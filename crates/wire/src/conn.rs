//! 長さ区切りの JSON フレームで型付きメッセージをやりとりする接続。

use std::collections::VecDeque;
use std::future::Future;
use std::marker::PhantomData;

use futures::channel::{mpsc, oneshot};
use futures::stream::{SplitSink, SplitStream};
use futures::{FutureExt, SinkExt, StreamExt};
use mw_mpc::net::{LocalDelivery, NetError, WireMsg, run_parties};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::bytes::Bytes;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use mw_mpc::round_based::MpcParty;

/// aux info のメッセージには ZK 証明が入るので大きめにとる
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("connection I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("connection closed")]
    Closed,
    #[error("malformed frame: {0}")]
    Malformed(String),
    #[error("unexpected message: {0}")]
    Unexpected(String),
    #[error("MPC: {0}")]
    Net(#[from] NetError),
}

pub struct Connection<S, Out, In> {
    sink: SplitSink<Framed<S, LengthDelimitedCodec>, Bytes>,
    stream: SplitStream<Framed<S, LengthDelimitedCodec>>,
    /// MPC の途中で先に届いた、MPC 以外のメッセージ
    pending: VecDeque<In>,
    /// 前の段階の MPC の途中で先に届いた、次の段階の MPC メッセージ
    early: VecDeque<WireMsg>,
    _out: PhantomData<fn(Out)>,
}

impl<S, Out, In> Connection<S, Out, In>
where
    S: AsyncRead + AsyncWrite + Unpin,
    Out: Serialize,
    In: DeserializeOwned + std::fmt::Debug,
{
    pub fn new(io: S) -> Self {
        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(MAX_FRAME_BYTES)
            .new_codec();
        let (sink, stream) = Framed::new(io, codec).split();
        Self {
            sink,
            stream,
            pending: VecDeque::new(),
            early: VecDeque::new(),
            _out: PhantomData,
        }
    }

    pub async fn send(&mut self, msg: &Out) -> Result<(), WireError> {
        send_on(&mut self.sink, msg).await
    }

    /// 送信側を閉じる(TLS なら close_notify を送る)。使い終わった接続は落とす前にこれを呼ぶ。
    pub async fn close(mut self) -> Result<(), WireError> {
        self.sink.close().await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<In, WireError> {
        if let Some(msg) = self.pending.pop_front() {
            return Ok(msg);
        }
        recv_on(&mut self.stream).await
    }

    /// この接続の上でローカルのパーティを動かす。
    ///
    /// `phase` はこの段階の名前(keygen、aux など)で、両側で同じものを使う。
    /// `wrap` は送るメッセージの包み方、`unwrap` は受け取ったメッセージから MPC 部分を
    /// 取り出す関数。MPC 以外のメッセージが届いたら、以降の `recv` で返すために取っておく。
    ///
    /// 相手はこの段階を終えると、すぐ次の段階のメッセージを送ってくる。それを今の段階に
    /// 渡すと失われるので、次の `run_mpc` のために取っておき、ここでの受信は終える
    /// (相手のこの段階のメッセージは、接続の順序からすべて届いている)。
    #[allow(clippy::too_many_arguments)]
    pub async fn run_mpc<M, F, Fut, T>(
        &mut self,
        phase: &str,
        n: u16,
        local: &[u16],
        wrap: fn(WireMsg) -> Out,
        unwrap: fn(In) -> Result<WireMsg, In>,
        start: F,
    ) -> Result<Vec<T>, WireError>
    where
        M: Clone + Serialize + DeserializeOwned + Send + 'static,
        F: FnMut(u16, MpcParty<M, LocalDelivery<M>>) -> Fut,
        Fut: Future<Output = T>,
    {
        let (net_out, mut to_peer) = mpsc::unbounded::<WireMsg>();
        let (from_peer, net_in) = mpsc::unbounded::<WireMsg>();
        let (done_tx, mut done_rx) = oneshot::channel::<()>();

        let parties = async move {
            let result = run_parties(n, local, net_out, net_in, start).await;
            let _ = done_tx.send(());
            result
        };

        // 前の段階のときに先に届いていた、この段階のメッセージ
        let mut later = VecDeque::new();
        while let Some(wire) = self.early.pop_front() {
            if wire.phase == phase {
                let _ = from_peer.unbounded_send(wire);
            } else {
                later.push_back(wire);
            }
        }
        self.early = later;

        let sink = &mut self.sink;
        let writer = async move {
            // run_parties が終わると net_out が閉じ、残りを送り切ってから抜ける
            while let Some(mut msg) = to_peer.next().await {
                msg.phase = phase.to_owned();
                send_on(sink, &wrap(msg)).await?;
            }
            Ok::<_, WireError>(())
        };

        let stream = &mut self.stream;
        let pending = &mut self.pending;
        let early = &mut self.early;
        let reader = async move {
            loop {
                futures::select! {
                    _ = done_rx => return Ok(()),
                    frame = recv_on::<In, _>(stream).fuse() => match frame {
                        Ok(msg) => match unwrap(msg) {
                            Ok(wire) if wire.phase != phase => {
                                // 相手は次の段階に進んだ。この段階の残りはローカルで終えられる
                                early.push_back(wire);
                                return Ok(());
                            }
                            Ok(wire) => {
                                if from_peer.unbounded_send(wire).is_err() {
                                    return Ok(());
                                }
                            }
                            // 相手はプロトコルを終えている。以降のメッセージは後で読む
                            Err(other) => {
                                pending.push_back(other);
                                return Ok(());
                            }
                        },
                        Err(WireError::Closed) => return Ok(()),
                        Err(e) => return Err(e),
                    },
                }
            }
        };

        let (outputs, written, read) = futures::join!(parties, writer, reader);
        written?;
        read?;
        Ok(outputs?)
    }
}

async fn send_on<S, Out>(
    sink: &mut SplitSink<Framed<S, LengthDelimitedCodec>, Bytes>,
    msg: &Out,
) -> Result<(), WireError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    Out: Serialize,
{
    let bytes = serde_json::to_vec(msg).map_err(|e| WireError::Malformed(e.to_string()))?;
    sink.send(Bytes::from(bytes)).await?;
    Ok(())
}

async fn recv_on<In, S>(
    stream: &mut SplitStream<Framed<S, LengthDelimitedCodec>>,
) -> Result<In, WireError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    In: DeserializeOwned,
{
    match stream.next().await {
        Some(Ok(frame)) => {
            serde_json::from_slice(&frame).map_err(|e| WireError::Malformed(e.to_string()))
        }
        Some(Err(e)) => Err(e.into()),
        None => Err(WireError::Closed),
    }
}
