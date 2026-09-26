//! Delivering MPC messages across processes.
//!
//! Each process runs only the parties it is responsible for (`local`). Messages for a local party
//! go through an in-process channel; everything else goes out to `net_out` as a `WireMsg`.
//! Connect `net_out` / `net_in` to an authenticated, encrypted A↔B connection
//! (cggmp21 leaves message authentication and confidentiality to the channel).

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use futures::channel::mpsc;
use futures::task::{ArcWake, waker};
use futures::{FutureExt, Stream, StreamExt, stream};
use round_based::{Incoming, MessageDestination, MessageType, MpcParty, Outgoing};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use cggmp21::round_based;

/// One message on the connection. `to` of `None` means everyone (broadcast).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WireMsg {
    pub from: u16,
    pub to: Option<u16>,
    pub body: serde_json::Value,
    /// Which phase (keygen, aux, ...) the message belongs to. Set by the sending connection.
    /// Used to keep a peer's messages for the next phase out of the current one when the peer moves ahead
    #[serde(default)]
    pub phase: String,
}

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("connection closed during the protocol")]
    Closed,
    #[error("unexpected message from party {from} to {to:?}")]
    Unexpected { from: u16, to: Option<u16> },
    #[error("malformed protocol message: {0}")]
    Malformed(String),
}

pub type LocalDelivery<M> = (
    mpsc::UnboundedReceiver<Result<Incoming<M>, Infallible>>,
    mpsc::UnboundedSender<Outgoing<M>>,
);

struct Router<M> {
    n: u16,
    inboxes: BTreeMap<u16, mpsc::UnboundedSender<Result<Incoming<M>, Infallible>>>,
    net_out: mpsc::UnboundedSender<WireMsg>,
    next_id: u64,
}

impl<M: Clone + Serialize> Router<M> {
    fn is_local(&self, i: u16) -> bool {
        self.inboxes.contains_key(&i)
    }

    fn has_remote(&self) -> bool {
        (0..self.n).any(|i| !self.is_local(i))
    }

    fn deliver(&mut self, to: u16, sender: u16, msg_type: MessageType, msg: M) {
        self.next_id += 1;
        if let Some(inbox) = self.inboxes.get(&to) {
            // If the receiving protocol has already finished, it is fine if this never arrives
            let _ = inbox.unbounded_send(Ok(Incoming {
                id: self.next_id,
                sender,
                msg_type,
                msg,
            }));
        }
    }

    fn send_remote(&self, from: u16, to: Option<u16>, msg: &M) -> Result<(), NetError> {
        let body = serde_json::to_value(msg).map_err(|e| NetError::Malformed(e.to_string()))?;
        self.net_out
            .unbounded_send(WireMsg {
                from,
                to,
                body,
                phase: String::new(),
            })
            .map_err(|_| NetError::Closed)
    }

    fn route_local(&mut self, from: u16, out: Outgoing<M>) -> Result<(), NetError> {
        match out.recipient {
            MessageDestination::OneParty(to) if self.is_local(to) => {
                self.deliver(to, from, MessageType::P2P, out.msg);
                Ok(())
            }
            MessageDestination::OneParty(to) => self.send_remote(from, Some(to), &out.msg),
            MessageDestination::AllParties => {
                let locals: Vec<u16> = self
                    .inboxes
                    .keys()
                    .copied()
                    .filter(|&j| j != from)
                    .collect();
                for to in locals {
                    self.deliver(to, from, MessageType::Broadcast, out.msg.clone());
                }
                if self.has_remote() {
                    self.send_remote(from, None, &out.msg)?;
                }
                Ok(())
            }
        }
    }
}

impl<M: Clone + Serialize + DeserializeOwned> Router<M> {
    fn route_remote(&mut self, wire: WireMsg) -> Result<(), NetError> {
        let WireMsg { from, to, body, .. } = wire;
        // Accept only messages that claim to come from the peer's parties
        let valid = from < self.n && !self.is_local(from) && to.is_none_or(|t| self.is_local(t));
        if !valid {
            return Err(NetError::Unexpected { from, to });
        }
        let msg: M =
            serde_json::from_value(body).map_err(|e| NetError::Malformed(e.to_string()))?;
        match to {
            Some(t) => self.deliver(t, from, MessageType::P2P, msg),
            None => {
                let locals: Vec<u16> = self.inboxes.keys().copied().collect();
                for t in locals {
                    self.deliver(t, from, MessageType::Broadcast, msg.clone());
                }
            }
        }
        Ok(())
    }
}

/// Run the local parties and return every party's output.
///
/// Before returning, every message the local parties produced has been queued on `net_out`.
pub async fn run_parties<M, F, Fut, T>(
    n: u16,
    local: &[u16],
    net_out: mpsc::UnboundedSender<WireMsg>,
    mut net_in: mpsc::UnboundedReceiver<WireMsg>,
    mut start: F,
) -> Result<Vec<T>, NetError>
where
    M: Clone + Serialize + DeserializeOwned + Send + 'static,
    F: FnMut(u16, MpcParty<M, LocalDelivery<M>>) -> Fut,
    Fut: Future<Output = T>,
{
    let mut router = Router {
        n,
        inboxes: BTreeMap::new(),
        net_out,
        next_id: 0,
    };
    let mut outboxes = Vec::new();
    let mut protocols = Vec::new();
    for &i in local {
        let (in_tx, in_rx) = mpsc::unbounded();
        let (out_tx, out_rx) = mpsc::unbounded::<Outgoing<M>>();
        router.inboxes.insert(i, in_tx);
        outboxes.push(out_rx.map(move |out| (i, out)));
        protocols.push(start(i, MpcParty::connected((in_rx, out_tx))));
    }
    let mut outgoing = stream::select_all(outboxes);
    let mut protocols = futures::future::join_all(protocols).fuse();

    loop {
        futures::select! {
            outputs = protocols => {
                // Deliver messages sent right before finishing, too
                while let Some(Some((from, out))) = outgoing.next().now_or_never() {
                    router.route_local(from, out)?;
                }
                return Ok(outputs);
            }
            out = outgoing.next() => {
                if let Some((from, out)) = out {
                    router.route_local(from, out)?;
                }
            }
            wire = net_in.next() => match wire {
                Some(wire) => router.route_remote(wire)?,
                // The peer finished first. Finish if the messages that arrived are enough
                None => return finish_after_close(&mut protocols, &mut outgoing, &mut router),
            },
        }
    }
}

struct WokenFlag(AtomicBool);

impl ArcWake for WokenFlag {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.0.store(true, Ordering::SeqCst);
    }
}

/// After the connection closes, advance the protocol with local messages only.
///
/// If it does not finish although nothing wakes it up and there is nothing to deliver, it is treated as stuck.
fn finish_after_close<P, O, M>(
    protocols: &mut P,
    outgoing: &mut O,
    router: &mut Router<M>,
) -> Result<P::Output, NetError>
where
    P: Future + Unpin,
    O: Stream<Item = (u16, Outgoing<M>)> + Unpin,
    M: Clone + Serialize,
{
    let flag = Arc::new(WokenFlag(AtomicBool::new(false)));
    let waker = waker(flag.clone());
    let mut cx = Context::from_waker(&waker);
    loop {
        flag.0.store(false, Ordering::SeqCst);
        if let Poll::Ready(outputs) = Pin::new(&mut *protocols).poll(&mut cx) {
            return Ok(outputs);
        }
        let mut routed = false;
        while let Poll::Ready(Some((from, out))) = Pin::new(&mut *outgoing).poll_next(&mut cx) {
            router.route_local(from, out)?;
            routed = true;
        }
        if !routed && !flag.0.load(Ordering::SeqCst) {
            return Err(NetError::Closed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router(local: &[u16]) -> (Router<u32>, mpsc::UnboundedReceiver<WireMsg>) {
        let (net_out, net_rx) = mpsc::unbounded();
        let mut inboxes = BTreeMap::new();
        for &i in local {
            inboxes.insert(i, mpsc::unbounded().0);
        }
        (
            Router {
                n: 3,
                inboxes,
                net_out,
                next_id: 0,
            },
            net_rx,
        )
    }

    fn wire(from: u16, to: Option<u16>) -> WireMsg {
        WireMsg {
            from,
            to,
            body: serde_json::json!(7),
            phase: String::new(),
        }
    }

    #[test]
    fn rejects_spoofed_or_misrouted_remote_messages() {
        let (mut r, _net) = router(&[0, 2]);
        // Claims to be a local party
        assert!(r.route_remote(wire(0, None)).is_err());
        // From a party that does not exist
        assert!(r.route_remote(wire(5, None)).is_err());
        // Addressed to a remote party
        assert!(r.route_remote(wire(1, Some(1))).is_err());
        // A valid one
        assert!(r.route_remote(wire(1, Some(2))).is_ok());
        assert!(r.route_remote(wire(1, None)).is_ok());
    }

    #[test]
    fn broadcast_goes_to_remote_once() {
        let (mut r, mut net) = router(&[0, 2]);
        r.route_local(
            0,
            Outgoing {
                recipient: MessageDestination::AllParties,
                msg: 1,
            },
        )
        .unwrap();
        assert_eq!(net.try_recv().unwrap(), wire_body(0, None, 1));
        assert!(
            net.try_recv().is_err(),
            "only one frame for the remote side"
        );
    }

    fn wire_body(from: u16, to: Option<u16>, v: u32) -> WireMsg {
        WireMsg {
            from,
            to,
            body: serde_json::json!(v),
            phase: String::new(),
        }
    }
}
