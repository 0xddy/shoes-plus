//! Bound unprocessed network packets without dropping connection control events.
//!
//! The endpoint routes packets before the connection can decrypt or validate them.
//! A receive window therefore cannot bound this queue. Admission is deliberately
//! nonblocking: an overloaded connection drops packets while the shared endpoint
//! remains free to service other connections. QUIC recovers reliable data;
//! DATAGRAM payloads retain best-effort semantics.

use std::{
    sync::Arc,
    task::{Context, Poll},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

/// Matches quic-go's per-connection unprocessed packet budget.
const MAX_PENDING_PACKETS: usize = 256;

#[derive(Debug)]
struct QueuedEvent<T> {
    event: T,
    // Dropped when the event is dequeued, the send fails, or the receiver closes.
    _packet_permit: Option<OwnedSemaphorePermit>,
}

#[derive(Debug)]
pub(crate) struct EventSender<T> {
    sender: mpsc::UnboundedSender<QueuedEvent<T>>,
    packet_budget: Arc<Semaphore>,
}

#[derive(Debug)]
pub(crate) struct EventReceiver<T> {
    receiver: mpsc::UnboundedReceiver<QueuedEvent<T>>,
}

pub(crate) fn channel<T>() -> (EventSender<T>, EventReceiver<T>) {
    let (sender, receiver) = mpsc::unbounded_channel();
    (
        EventSender {
            sender,
            packet_budget: Arc::new(Semaphore::new(MAX_PENDING_PACKETS)),
        },
        EventReceiver { receiver },
    )
}

impl<T> EventSender<T> {
    /// Local control events must remain deliverable when packet admission is full.
    pub(crate) fn send(&self, event: T) -> Result<(), mpsc::error::SendError<T>> {
        self.sender
            .send(QueuedEvent {
                event,
                _packet_permit: None,
            })
            .map_err(|error| mpsc::error::SendError(error.0.event))
    }

    /// Returns false when the packet was dropped, without blocking the endpoint.
    pub(crate) fn send_packet(&self, event: T) -> bool {
        let Ok(permit) = Arc::clone(&self.packet_budget).try_acquire_owned() else {
            return false;
        };
        self.sender
            .send(QueuedEvent {
                event,
                _packet_permit: Some(permit),
            })
            .is_ok()
    }
}

impl<T> EventReceiver<T> {
    pub(crate) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.receiver
            .poll_recv(cx)
            .map(|event| event.map(|queued| queued.event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::poll_fn,
        sync::atomic::{AtomicUsize, Ordering},
    };

    #[derive(Debug, PartialEq)]
    enum Event {
        Packet,
        Close,
        Rebind,
        ProtocolControl,
    }

    #[tokio::test]
    async fn full_packet_queue_preserves_control_events_and_other_connections() {
        let (sender, mut receiver) = channel();
        let (other_sender, mut other_receiver) = channel();
        for _ in 0..MAX_PENDING_PACKETS {
            assert!(sender.send_packet(Event::Packet));
        }
        assert!(!sender.send_packet(Event::Packet));
        assert!(other_sender.send_packet(Event::Packet));

        sender.send(Event::Close).unwrap();
        sender.send(Event::Rebind).unwrap();
        sender.send(Event::ProtocolControl).unwrap();
        assert_eq!(sender.packet_budget.available_permits(), 0);

        assert_eq!(
            poll_fn(|cx| receiver.poll_recv(cx)).await,
            Some(Event::Packet)
        );
        assert_eq!(sender.packet_budget.available_permits(), 1);
        assert!(sender.send_packet(Event::Packet));
        assert!(!sender.send_packet(Event::Packet));
        for _ in 1..MAX_PENDING_PACKETS {
            assert_eq!(
                poll_fn(|cx| receiver.poll_recv(cx)).await,
                Some(Event::Packet)
            );
        }
        for event in [
            Event::Close,
            Event::Rebind,
            Event::ProtocolControl,
            Event::Packet,
        ] {
            assert_eq!(poll_fn(|cx| receiver.poll_recv(cx)).await, Some(event));
        }
        assert_eq!(
            sender.packet_budget.available_permits(),
            MAX_PENDING_PACKETS
        );
        assert_eq!(
            poll_fn(|cx| other_receiver.poll_recv(cx)).await,
            Some(Event::Packet)
        );
    }

    #[test]
    fn closing_receiver_releases_packets_and_failed_sends_return_permits() {
        #[derive(Debug)]
        struct DropCounter(Arc<AtomicUsize>);
        impl Drop for DropCounter {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let dropped = Arc::new(AtomicUsize::new(0));
        let (sender, receiver) = channel();
        for _ in 0..MAX_PENDING_PACKETS {
            assert!(sender.send_packet(DropCounter(Arc::clone(&dropped))));
        }
        assert!(!sender.send_packet(DropCounter(Arc::clone(&dropped))));
        assert_eq!(dropped.load(Ordering::Relaxed), 1);

        drop(receiver);
        assert_eq!(dropped.load(Ordering::Relaxed), MAX_PENDING_PACKETS + 1);
        assert_eq!(
            sender.packet_budget.available_permits(),
            MAX_PENDING_PACKETS
        );

        assert!(!sender.send_packet(DropCounter(Arc::clone(&dropped))));
        assert_eq!(dropped.load(Ordering::Relaxed), MAX_PENDING_PACKETS + 2);
        assert_eq!(
            sender.packet_budget.available_permits(),
            MAX_PENDING_PACKETS
        );
    }

    #[tokio::test]
    async fn dropping_sender_drains_existing_events_before_reporting_closed() {
        let (sender, mut receiver) = channel();
        let budget = Arc::clone(&sender.packet_budget);
        assert!(sender.send_packet(Event::Packet));
        sender.send(Event::Close).unwrap();
        drop(sender);
        assert_eq!(
            poll_fn(|cx| receiver.poll_recv(cx)).await,
            Some(Event::Packet)
        );
        assert_eq!(budget.available_permits(), MAX_PENDING_PACKETS);
        assert_eq!(
            poll_fn(|cx| receiver.poll_recv(cx)).await,
            Some(Event::Close)
        );
        assert_eq!(poll_fn(|cx| receiver.poll_recv(cx)).await, None);
    }
}
