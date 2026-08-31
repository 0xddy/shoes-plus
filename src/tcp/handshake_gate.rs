//! A ceiling on unauthenticated work admitted by one logical listener.
//!
//! # What this bounds, and what it deliberately does not
//!
//! Everything else in this crate that limits a client is charged to the user it
//! authenticated as. Before authentication there is no user to charge, and the
//! window is not short: a TCP connection gets up to 60 seconds in
//! [`process_stream`](super::tcp_server::process_stream) to complete a handshake,
//! while native QUIC protocols have a transport handshake before their application
//! authentication and generic QUIC performs another configured-protocol handshake
//! on every bidi stream. Without a gate, a listener would carry as many of those as
//! its transport would hand it. That is the resource an unauthenticated peer can
//! consume, so it is the one this bounds.
//!
//! Most gate instances bound only the handshake. A connection-authenticated protocol
//! releases its permit and then runs under the user's own ceiling. Generic QUIC is
//! the deliberate exception: its connection has no user identity because every
//! stream authenticates separately, so it uses one gate for connection-lifetime
//! permits and an independent gate for pending stream handshakes. Keeping those
//! budgets separate prevents either an idle transport or its multiplexed streams
//! from escaping accounting.
//!
//! # Refusing rather than queueing
//!
//! [`enter`](HandshakeGate::enter) fails immediately instead of waiting. Waiting is
//! what turns a slow-loris into a denial of service: the attacker's stalled
//! handshakes hold the permits, and every legitimate client queues behind them for
//! as long as the attacker cares to hold on. Refusing costs the honest client one
//! reconnect and costs the attacker their leverage.
//!
//! # Why the per-source map needs no eviction
//!
//! A map keyed by a remote address is normally a liability -- it is a structure
//! sized by whoever is attacking you, and it needs a cleanup policy that is itself
//! something to get wrong. This one does not, because an entry exists only while
//! that address has a handshake in flight, and the last permit to be dropped removes
//! it. The total is capped, so the map holds at most `max_total` entries by
//! construction. There is no timer, no eviction policy and nothing to tune.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// Handshakes one listener will carry at once.
///
/// Sized for the resource actually at stake: each pending handshake is a task and
/// whatever socket, QUIC connection/stream and protocol buffers it has allocated so
/// far. A thousand of those is a bad interval, not a dead host, and a listener that
/// legitimately has a thousand handshakes in flight at one instant is under a load
/// spike no ceiling would have helped with.
pub const MAX_PENDING_HANDSHAKES: usize = 1024;

/// Handshakes one source address may hold of that total.
///
/// Without this the global ceiling is reached by whoever gets there first, which is
/// the attacker. A handshake takes milliseconds, so 64 *simultaneously in flight*
/// from one address is already far past what a client opening connections in a burst
/// produces -- while capping any single address at a sixteenth of the listener.
pub const MAX_PENDING_PER_SOURCE: usize = 64;

/// Accepted camouflage/fallback connections get their own budget so a long-lived
/// decoy response cannot consume every slot needed by real protocol handshakes.
///
/// The values intentionally match the handshake budget: this keeps the total
/// resource ceiling explicit without coupling the two failure domains.
pub const MAX_ACTIVE_FALLBACKS: usize = 1024;
pub const MAX_ACTIVE_FALLBACKS_PER_SOURCE: usize = 64;

/// Maximum time a background protocol may wait for its first authenticated logical
/// request. Once authentication succeeds, normal connection and user accounting own
/// the task instead of this pre-authentication deadline.
pub const DEFERRED_AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Default)]
struct GateState {
    total: usize,
    /// Only ever holds addresses with a handshake in flight. See the module docs for
    /// why that is what keeps it bounded.
    per_source: HashMap<IpAddr, usize>,
}

/// One listener's pending-handshake budget.
pub struct HandshakeGate {
    max_total: usize,
    max_per_source: usize,
    state: Mutex<GateState>,
}

impl HandshakeGate {
    pub fn new(max_total: usize, max_per_source: usize) -> Arc<Self> {
        Arc::new(Self {
            max_total,
            max_per_source,
            state: Mutex::new(GateState::default()),
        })
    }

    /// Take a permit for one handshake, or `None` if the listener is full.
    ///
    /// `source` is `None` for a transport with no remote address to attribute to --
    /// a unix socket, whose peers are local and already past a filesystem
    /// permission check. Those are held to the total but not to a per-source share,
    /// since they have no source to share out.
    pub fn enter(self: &Arc<Self>, source: Option<IpAddr>) -> Option<HandshakePermit> {
        let mut state = self.lock();

        if state.total >= self.max_total {
            return None;
        }

        if let Some(address) = source {
            // Read before inserting rather than through `entry`, so a refusal cannot
            // leave a zero-count entry behind and quietly break the invariant that
            // keeps this map bounded.
            let pending = state.per_source.get(&address).copied().unwrap_or(0);
            if pending >= self.max_per_source {
                return None;
            }
            state.per_source.insert(address, pending + 1);
        }

        state.total += 1;
        Some(HandshakePermit {
            gate: Arc::clone(self),
            source,
        })
    }

    /// Handshakes in flight right now, across every source.
    #[cfg(test)]
    fn pending(&self) -> usize {
        self.lock().total
    }

    fn lock(&self) -> MutexGuard<'_, GateState> {
        // A panic while a permit is being released must not wedge the listener into
        // refusing every future connection. Every mutation here leaves the counts
        // consistent, so recovering the inner value is the safer failure mode -- the
        // same argument `UserContext` makes for its own lifecycle lock.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A handshake's place in the listener's budget, released on drop.
///
/// Usually dropped as soon as the handshake resolves: TCP drops it after handler
/// setup, connection-authenticated QUIC protocols after their one auth exchange,
/// and generic QUIC stream gates after each stream's setup. Generic QUIC's separate
/// connection gate intentionally keeps its permit until the transport ends because
/// the transport itself never belongs to one authenticated user.
pub struct HandshakePermit {
    gate: Arc<HandshakeGate>,
    source: Option<IpAddr>,
}

impl Drop for HandshakePermit {
    fn drop(&mut self) {
        let mut state = self.gate.lock();
        state.total = state.total.saturating_sub(1);

        let Some(address) = self.source else {
            return;
        };
        if let Some(pending) = state.per_source.get_mut(&address) {
            *pending = pending.saturating_sub(1);
            if *pending == 0 {
                // The line that makes the map self-cleaning.
                state.per_source.remove(&address);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> Option<IpAddr> {
        Some(IpAddr::from([127, 0, 0, last]))
    }

    #[test]
    fn permits_are_returned_when_the_handshake_ends() {
        let gate = HandshakeGate::new(2, 2);
        let first = gate.enter(ip(1)).expect("under the ceiling");
        let _second = gate.enter(ip(2)).expect("at the ceiling");
        assert_eq!(gate.pending(), 2);

        assert!(gate.enter(ip(3)).is_none(), "the listener is full");

        drop(first);
        assert_eq!(gate.pending(), 1);
        assert!(gate.enter(ip(3)).is_some(), "the freed permit is reusable");
    }

    #[test]
    fn one_source_cannot_take_the_whole_listener() {
        let gate = HandshakeGate::new(100, 2);
        let _first = gate.enter(ip(1)).expect("under the per-source share");
        let noisy = gate.enter(ip(1)).expect("at the per-source share");
        assert!(
            gate.enter(ip(1)).is_none(),
            "a third handshake from one address is refused"
        );

        // The point of the per-source share: the listener still has room for
        // everybody else while one address is at its limit.
        assert!(gate.enter(ip(2)).is_some());
        assert!(gate.enter(ip(3)).is_some());

        drop(noisy);
        assert!(
            gate.enter(ip(1)).is_some(),
            "the noisy source is not banned"
        );
    }

    #[test]
    fn the_per_source_map_holds_nothing_once_the_handshakes_end() {
        // This is the invariant that lets the map go without an eviction policy: it
        // is sized by handshakes in flight, not by addresses ever seen.
        let gate = HandshakeGate::new(1024, 64);
        for last in 0..=255u8 {
            let permit = gate.enter(Some(IpAddr::from([10, 0, 0, last])));
            assert!(permit.is_some());
        }
        assert_eq!(gate.pending(), 0);
        assert!(
            gate.lock().per_source.is_empty(),
            "256 distinct addresses left no residue"
        );
    }

    #[test]
    fn a_refusal_leaves_no_residue_either() {
        let gate = HandshakeGate::new(1024, 1);
        let held = gate.enter(ip(1)).expect("the first is admitted");
        assert!(gate.enter(ip(1)).is_none());
        assert_eq!(gate.pending(), 1, "the refusal did not consume a slot");
        drop(held);
        assert!(gate.lock().per_source.is_empty());
    }

    #[test]
    fn a_sourceless_peer_is_held_to_the_total_only() {
        // Unix sockets: no address to share out, but they still cost a slot.
        let gate = HandshakeGate::new(2, 1);
        let _first = gate.enter(None).expect("under the ceiling");
        let _second = gate.enter(None).expect("no per-source share applies");
        assert!(gate.enter(None).is_none(), "the total still bounds them");
        assert!(gate.lock().per_source.is_empty());
    }
}
