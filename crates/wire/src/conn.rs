//! A connection that exchanges typed messages as length-delimited JSON frames.

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

/// Aux info messages carry ZK proofs, so allow them to be large
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
    /// Non-MPC messages that arrived early, in the middle of an MPC run
    pending: VecDeque<In>,
    /// MPC messages for the next phase that arrived early, in the middle of the previous phase
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

    /// Close the sending side (sends close_notify over TLS). Call this before dropping a finished connection.
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

    /// Run the local parties over this connection.
    ///
    /// `phase` names this phase (keygen, aux, ...), and both sides use the same one.
    /// `wrap` wraps outgoing messages, and `unwrap` extracts the MPC part from incoming messages.
    /// Non-MPC messages that arrive are kept so that later calls to `recv` return them.
    ///
    /// When the peer finishes this phase, it immediately sends messages for the next one. Handing those to
    /// this phase would lose them, so they are kept for the next `run_mpc` and receiving stops here
    /// (the connection is ordered, so all of the peer's messages for this phase have arrived).
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

        // Messages for this phase that arrived early, during the previous phase
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
            // When run_parties finishes, net_out closes; send what is left and exit
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
                                // The peer moved on to the next phase. The rest of this phase can finish locally
                                early.push_back(wire);
                                return Ok(());
                            }
                            Ok(wire) => {
                                if from_peer.unbounded_send(wire).is_err() {
                                    return Ok(());
                                }
                            }
                            // The peer has finished the protocol. Later messages are read afterwards
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
