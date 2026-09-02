//! Per-user identity and traffic counters.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use super::rate::{RateLimiter, RatePermit, RateWaiter};

#[derive(Default)]
struct ActiveConnections {
    next_id: u64,
    revoked: bool,
    tokens: HashMap<u64, CancellationToken>,
}

/// A user's accounting record.
///
/// Exactly one of these exists per user. Every connection that authenticates as
/// that user shares the same `Arc`, so all of them accumulate into the same
/// counters, and a reader of the counters sees the sum across every inbound,
/// transport, and worker thread the user is currently using.
///
/// # Layout
///
/// The counters are placed first inside a 64 byte aligned type. `Arc` honours the
/// alignment of the value it stores, so each user's hot counters land on their own
/// cache line and two users being metered concurrently on different cores never
/// invalidate each other's line.
///
/// # Ordering
///
/// Byte and lifetime-authentication counters use `Relaxed`: they only need to avoid
/// lost increments, and stronger ordering on every I/O buffer would buy nothing.
/// The live-connection counter is different. Its final decrement is a release and a
/// zero observation is an acquire, making the completed connection's last relaxed
/// byte increments visible before removal returns its final snapshot.
#[repr(align(64))]
pub struct UserContext {
    tx: AtomicU64,
    rx: AtomicU64,
    /// Unix milliseconds of the latest non-zero byte increment. This is kept
    /// beside the counters so a later periodic drain reports when bytes flowed,
    /// not merely when the control plane happened to collect them.
    last_traffic_observed_at_unix_millis: AtomicU64,
    /// Connections currently open. Maintained by the traffic meter, which owns the
    /// only place that reliably observes a connection ending.
    conns: AtomicU64,
    /// Successful authentications since this record was created.
    total_conns: AtomicU64,
    /// Ceiling on simultaneously open connections, or `0` for no ceiling.
    ///
    /// This is the one limit that bounds every protocol at once. Each of them has
    /// its own per-connection costs -- a hysteria2 or TUIC connection can hold
    /// hundreds of UDP sessions, a NaiveProxy one hundreds of multiplexed tunnels --
    /// and all of those are per-connection multipliers, so capping connections caps
    /// the product. Without it, a single valid credential is unbounded, and on a
    /// shared inbound that is one user able to exhaust the box for all the others.
    ///
    /// Read once per authentication under the lifecycle lock, never on the byte
    /// path, so it sits with the cold control-plane state despite being an atomic.
    max_conns: AtomicU64,
    /// Stable identity chosen by whoever registered the user. Never a credential.
    id: Arc<str>,
    enabled: AtomicBool,
    /// Whether accepting this user without a [`ConnContext`](crate::dynamic::ConnContext)
    /// must fail closed. Dynamic registries set this so losing task-local state can
    /// never silently produce a connection that removal cannot cancel.
    connection_tracking_required: bool,
    /// One cancellation token per authenticated client connection. This is a cold
    /// control-plane structure: the data path never locks it, and a connection only
    /// touches it once when authentication succeeds and once when it ends.
    connections: Mutex<ActiveConnections>,
    /// Wakes `remove_user` after the last cancelled connection has released its
    /// [`ConnContext`](super::meter::ConnContext).
    no_connections: Notify,
    /// Bandwidth ceiling for bytes going to the client -- the user's *download*.
    ///
    /// Shared by every connection this user has open, which is what makes it a
    /// per-user limit rather than a per-connection one. Placed after the cold
    /// control-plane state so the hot counters keep the first cache line to
    /// themselves; an unlimited user never touches the bucket's lock.
    tx_limiter: RateLimiter,
    /// Bandwidth ceiling for bytes coming from the client -- their *upload*.
    rx_limiter: RateLimiter,
}

impl std::fmt::Debug for UserContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserContext")
            .field("id", &self.id)
            .field("enabled", &self.is_enabled())
            .field("tx", &self.tx())
            .field("rx", &self.rx())
            .finish()
    }
}

impl UserContext {
    /// Create a dynamic user whose admission requires a tracked
    /// [`ConnContext`](crate::dynamic::ConnContext).
    ///
    /// This fail-closed default is appropriate for mutable registries that promise
    /// active revocation. If a handler loses its connection context across a task
    /// boundary, [`bind_connection_user`](crate::dynamic::bind_connection_user)
    /// rejects the authentication instead of silently creating a session removal
    /// cannot cancel.
    pub fn new(id: impl Into<Arc<str>>) -> Arc<Self> {
        Self::new_inner(id.into(), true)
    }

    /// Create a config/static user whose authentication intentionally has no
    /// revocable connection.
    ///
    /// Use this only where the user lifetime is immutable and therefore cannot make
    /// an active-disconnect promise. Dynamic registries should use [`Self::new`].
    pub fn new_untracked(id: impl Into<Arc<str>>) -> Arc<Self> {
        Self::new_inner(id.into(), false)
    }

    fn new_inner(id: Arc<str>, connection_tracking_required: bool) -> Arc<Self> {
        Arc::new(Self {
            tx: AtomicU64::new(0),
            rx: AtomicU64::new(0),
            last_traffic_observed_at_unix_millis: AtomicU64::new(0),
            conns: AtomicU64::new(0),
            total_conns: AtomicU64::new(0),
            max_conns: AtomicU64::new(0),
            id,
            enabled: AtomicBool::new(true),
            connection_tracking_required,
            connections: Mutex::new(ActiveConnections::default()),
            no_connections: Notify::new(),
            tx_limiter: RateLimiter::new(),
            rx_limiter: RateLimiter::new(),
        })
    }

    fn connections(&self) -> MutexGuard<'_, ActiveConnections> {
        // A panic in connection teardown must not permanently prevent an operator
        // from revoking the user. Every mutation below leaves the map structurally
        // valid, so recovering the inner value is the safer failure mode.
        self.connections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[inline]
    pub fn id(&self) -> &Arc<str> {
        &self.id
    }

    /// Bytes sent to the client, counted as they go on the wire.
    #[inline]
    pub fn add_tx(&self, n: u64) {
        self.note_traffic(n);
        self.tx.fetch_add(n, Ordering::Relaxed);
    }

    /// Bytes received from the client, counted as they come off the wire.
    #[inline]
    pub fn add_rx(&self, n: u64) {
        self.note_traffic(n);
        self.rx.fetch_add(n, Ordering::Relaxed);
    }

    #[inline]
    fn note_traffic(&self, n: u64) {
        if n == 0 {
            return;
        }
        let observed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        self.last_traffic_observed_at_unix_millis
            .fetch_max(observed_at, Ordering::Relaxed);
    }

    #[inline]
    pub fn tx(&self) -> u64 {
        self.tx.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn rx(&self) -> u64 {
        self.rx.load(Ordering::Relaxed)
    }

    /// Unix milliseconds of the most recent non-zero byte increment, or zero
    /// when this user generation has never carried traffic.
    #[inline]
    pub fn last_traffic_observed_at_unix_millis(&self) -> u64 {
        self.last_traffic_observed_at_unix_millis
            .load(Ordering::Relaxed)
    }

    #[inline]
    pub fn conns(&self) -> u64 {
        // Acquire pairs with the final connection's release decrement, so a caller
        // that observes zero can also observe every relaxed byte increment that
        // happened before that connection was dropped.
        self.conns.load(Ordering::Acquire)
    }

    #[inline]
    pub fn total_conns(&self) -> u64 {
        self.total_conns.load(Ordering::Relaxed)
    }

    /// This user's simultaneous-connection ceiling, or `0` if they have none.
    #[inline]
    pub fn max_conns(&self) -> u64 {
        self.max_conns.load(Ordering::Relaxed)
    }

    /// Set the simultaneous-connection ceiling; `0` removes it.
    ///
    /// Lowering it below the live count is allowed and does not disconnect anybody.
    /// That matches [`set_enabled`](Self::set_enabled): a limit governs admission,
    /// and tearing down connections already carrying traffic is a separate decision
    /// an operator makes with [`revoke_connections`](Self::revoke_connections). The
    /// count drains to the new ceiling as those connections end.
    pub fn set_max_conns(&self, limit: u64) {
        self.max_conns.store(limit, Ordering::Relaxed);
    }

    /// This user's download ceiling in bits per second, or `0` for no limit.
    #[inline]
    pub fn download_limit_bps(&self) -> u64 {
        self.tx_limiter.rate_bps()
    }

    /// This user's upload ceiling in bits per second, or `0` for no limit.
    #[inline]
    pub fn upload_limit_bps(&self) -> u64 {
        self.rx_limiter.rate_bps()
    }

    /// Sets both bandwidth ceilings; `0` removes one.
    ///
    /// Directions are named from the *client's* point of view, matching what a
    /// control plane calls them: `upload` is the client sending to us, which is
    /// `rx` here, and `download` is us sending to the client, which is `tx`.
    /// Swapping the pair is a silent bug -- traffic still flows, just throttled
    /// in the wrong direction and only visible as a user complaint -- so the
    /// mapping is spelled out here rather than left to the caller to infer.
    ///
    /// Like [`set_max_conns`](Self::set_max_conns), lowering a limit governs
    /// what happens next and does not disturb connections already open.
    pub fn set_speed_limits(&self, upload_bps: u64, download_bps: u64) {
        self.rx_limiter.set_rate(upload_bps);
        self.tx_limiter.set_rate(download_bps);
    }

    /// Poll for download allowance shared by every connection of this user.
    #[inline]
    pub(super) fn poll_acquire_tx<'a>(
        &'a self,
        waiter: &mut RateWaiter,
        cx: &mut Context<'_>,
        max_bytes: u64,
    ) -> Poll<RatePermit<'a>> {
        self.tx_limiter.poll_acquire(waiter, cx, max_bytes)
    }

    /// Poll for upload allowance. See [`poll_acquire_tx`](Self::poll_acquire_tx).
    #[inline]
    pub(super) fn poll_acquire_rx<'a>(
        &'a self,
        waiter: &mut RateWaiter,
        cx: &mut Context<'_>,
        max_bytes: u64,
    ) -> Poll<RatePermit<'a>> {
        self.rx_limiter.poll_acquire(waiter, cx, max_bytes)
    }

    /// Whether one more connection would put this user over their ceiling.
    ///
    /// Counted from the token map rather than from `conns`, because both are
    /// maintained under this same lock and the map is the one the caller is about to
    /// insert into. Reading the atomic here would introduce a second source of truth
    /// for the same quantity, and with it the chance of the two disagreeing.
    fn at_connection_limit(&self, connections: &ActiveConnections) -> bool {
        match self.max_conns() {
            0 => false,
            limit => connections.tokens.len() as u64 >= limit,
        }
    }

    /// Record a successful authentication unless removal has already linearised.
    ///
    /// The lifecycle lock closes the race where protocol admission observes
    /// `enabled = true`, removal returns its final snapshot, and only then admission
    /// increments `total_conns`. Callers must reject authentication when this
    /// returns `false`.
    pub(crate) fn note_auth(&self) -> bool {
        let connections = self.connections();
        if connections.revoked || !self.is_enabled() {
            return false;
        }
        self.total_conns.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Admit an authentication that intentionally has no revocable connection.
    ///
    /// This is the explicit path for a classic config-file inbound. It returns
    /// `false` for tracked contexts created with [`Self::new`], as well as for a
    /// suspended or removed user; dynamic handlers must bind a
    /// [`ConnContext`](crate::dynamic::ConnContext) instead.
    pub fn admit_unmetered(&self) -> bool {
        !self.connection_tracking_required && self.note_auth()
    }

    #[inline]
    pub(crate) fn open_conn(&self) {
        self.conns.fetch_add(1, Ordering::AcqRel);
    }

    #[inline]
    pub(crate) fn close_conn(&self) {
        // Saturate rather than wrap. An unbalanced close would otherwise report
        // billions of open connections, which is worse than reporting zero.
        let previous = self
            .conns
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                Some(n.saturating_sub(1))
            })
            .unwrap_or(0);
        if previous == 1 {
            // `notify_one` retains a permit when the remover is between checking
            // the counter and beginning its await, so the zero transition cannot
            // be missed.
            self.no_connections.notify_one();
        }
    }

    /// Register one authenticated connection and return the id its owner must use
    /// to unregister it. A connection racing with removal is cancelled immediately
    /// and never enters the live count.
    pub(crate) fn register_connection(&self, token: CancellationToken) -> Option<u64> {
        self.register_connection_inner(token, false, true)
    }

    /// Atomically admit and register a connection after its protocol has proved the
    /// credential. Removal takes the same lifecycle lock, so exactly one wins: a
    /// successful admission is included in the drain, while a late one is rejected
    /// without incrementing `total_conns`.
    pub(crate) fn register_authenticated_connection(
        &self,
        token: CancellationToken,
    ) -> Option<u64> {
        self.register_connection_inner(token, true, true)
    }

    /// Attempt authentication for a protocol that can continue anonymously via a
    /// fallback or masquerade when admission loses a lifecycle race or hits a
    /// connection limit. The caller must immediately enter that unauthenticated
    /// path on `None`; unlike the ordinary fail-closed entry point, the physical
    /// connection token remains live so the camouflage can actually be served.
    pub(crate) fn register_authenticated_connection_for_fallback(
        &self,
        token: CancellationToken,
    ) -> Option<u64> {
        self.register_connection_inner(token, true, false)
    }

    fn register_connection_inner(
        &self,
        token: CancellationToken,
        authenticated: bool,
        cancel_on_failure: bool,
    ) -> Option<u64> {
        let id = {
            let mut connections = self.connections();
            if connections.revoked || (authenticated && !self.is_enabled()) {
                None
            } else if self.at_connection_limit(&connections) {
                // Refused, and deliberately not counted in `total_conns`: the
                // credential was good but the connection never existed, so counting
                // it would make the lifetime figure a count of attempts.
                log::debug!(
                    "refusing a connection for {}: at the {} connection limit",
                    self.id,
                    self.max_conns()
                );
                None
            } else {
                if authenticated {
                    self.total_conns.fetch_add(1, Ordering::Relaxed);
                }
                let mut id = connections.next_id;
                while connections.tokens.contains_key(&id) {
                    id = id.wrapping_add(1);
                }
                connections.next_id = id.wrapping_add(1);
                connections.tokens.insert(id, token.clone());
                self.open_conn();
                Some(id)
            }
        };

        if id.is_none() && cancel_on_failure {
            token.cancel();
        }
        id
    }

    /// Release the connection registered by [`Self::register_connection`].
    pub(crate) fn unregister_connection(&self, id: u64) {
        if self.connections().tokens.remove(&id).is_some() {
            self.close_conn();
        }
    }

    /// Permanently revoke this record and signal every connection authenticated as
    /// it. Re-adding the same external id creates a fresh `UserContext`, so a
    /// cancelled token can never leak into the replacement user.
    pub fn revoke_connections(&self) {
        self.enabled.store(false, Ordering::Release);
        let tokens: Vec<CancellationToken> = {
            let mut connections = self.connections();
            connections.revoked = true;
            connections.tokens.values().cloned().collect()
        };
        for token in tokens {
            token.cancel();
        }
    }

    /// Signal every connection that is open at this instant without revoking the
    /// user itself.
    ///
    /// Unlike [`revoke_connections`](Self::revoke_connections), this deliberately
    /// leaves both the credential and admission state alone. A connection that
    /// registers after the snapshot below is therefore allowed to stay open. This
    /// is the control-plane "kick" operation: terminate stale sessions (for example
    /// after rotating a credential) while allowing the still-authorized user to
    /// reconnect immediately with the current credential.
    ///
    /// Returns the number of live connection tokens that were signalled. They may
    /// take a short time to unwind, so the live `conns` counter can remain non-zero
    /// after this method returns.
    pub fn kick_connections(&self) -> u64 {
        let tokens: Vec<CancellationToken> = self.connections().tokens.values().cloned().collect();
        let signalled = tokens.len() as u64;
        for token in tokens {
            token.cancel();
        }
        signalled
    }

    /// Wait until every connection that registered before revocation has exited.
    /// Calling this without first calling [`Self::revoke_connections`] would allow
    /// new connections to keep extending the wait indefinitely.
    pub async fn wait_for_connections_closed(&self) {
        while self.conns() != 0 {
            self.no_connections.notified().await;
        }
    }

    /// Whether this exact record has been permanently removed. This is distinct
    /// from `enabled = false`, which is reversible and deliberately leaves existing
    /// connections running.
    pub fn is_revoked(&self) -> bool {
        self.connections().revoked
    }

    /// Whether the user may authenticate. Checked by registry lookups, so a
    /// disabled user is indistinguishable from an unknown one at the protocol
    /// level, including for probe-resistant fallbacks.
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    /// Suspend or resume the user without discarding their counters. Established
    /// connections are deliberately left alone; this only affects new ones. Taking
    /// the admission lock gives disable and authentication one linearization order:
    /// an authentication that wins first remains established, while every attempt
    /// beginning after this method returns observes the new state.
    pub fn set_enabled(&self, enabled: bool) {
        let connections = self.connections();
        self.enabled
            .store(enabled && !connections.revoked, Ordering::Release);
    }

    /// Zero the traffic counters, returning what they held. Used for billing
    /// periods; `conns` is left alone because it tracks live state, not a total.
    pub fn take_traffic(&self) -> (u64, u64) {
        (
            self.tx.swap(0, Ordering::Relaxed),
            self.rx.swap(0, Ordering::Relaxed),
        )
    }

    pub fn stats(&self) -> UserStats {
        UserStats {
            id: self.id.clone(),
            enabled: self.is_enabled(),
            tx: self.tx(),
            rx: self.rx(),
            last_traffic_observed_at_unix_millis: self.last_traffic_observed_at_unix_millis(),
            conns: self.conns(),
            total_conns: self.total_conns(),
            max_conns: self.max_conns(),
            upload_limit_bps: self.upload_limit_bps(),
            download_limit_bps: self.download_limit_bps(),
        }
    }
}

/// A point-in-time copy of a user's counters.
///
/// The counters are read one at a time, so a snapshot is not an atomic view of
/// the user. That is intentional: making it one would require a lock on the I/O
/// path. For reporting, slight skew between `tx` and `rx` is irrelevant.
#[derive(Debug, Clone)]
pub struct UserStats {
    pub id: Arc<str>,
    pub enabled: bool,
    pub tx: u64,
    pub rx: u64,
    /// Unix milliseconds of the latest non-zero byte increment, or zero.
    pub last_traffic_observed_at_unix_millis: u64,
    pub conns: u64,
    pub total_conns: u64,
    /// Simultaneous-connection ceiling, or `0` if the user has none.
    pub max_conns: u64,
    /// Client-upload ceiling in bits per second, or `0` if the user has none.
    pub upload_limit_bps: u64,
    /// Client-download ceiling in bits per second, or `0` if the user has none.
    pub download_limit_bps: u64,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn accumulates_traffic_in_both_directions() {
        let user = UserContext::new("alice");
        assert_eq!(user.last_traffic_observed_at_unix_millis(), 0);
        user.add_tx(10);
        user.add_tx(5);
        user.add_rx(7);
        assert_eq!((user.tx(), user.rx()), (15, 7));
        assert_ne!(user.last_traffic_observed_at_unix_millis(), 0);
    }

    #[test]
    fn take_traffic_returns_and_zeroes_only_the_byte_counters() {
        let user = UserContext::new("alice");
        user.add_tx(120);
        user.add_rx(340);
        user.open_conn();
        assert!(user.note_auth());

        assert_eq!(user.take_traffic(), (120, 340));
        assert_eq!((user.tx(), user.rx()), (0, 0));
        // Live and lifetime connection counts are not part of a billing period.
        assert_eq!((user.conns(), user.total_conns()), (1, 1));

        // A second take with nothing in between reports zero rather than repeating.
        assert_eq!(user.take_traffic(), (0, 0));
    }

    #[test]
    fn tracks_live_connections_and_saturates_at_zero() {
        let user = UserContext::new("alice");
        user.open_conn();
        user.open_conn();
        assert_eq!(user.conns(), 2);

        user.close_conn();
        assert_eq!(user.conns(), 1);
        user.close_conn();
        assert_eq!(user.conns(), 0);

        // An unbalanced close must not wrap to u64::MAX.
        user.close_conn();
        assert_eq!(user.conns(), 0);
    }

    #[test]
    fn stats_snapshot_reports_the_current_values() {
        let user = UserContext::new("alice");
        user.add_tx(1);
        user.add_rx(2);
        assert!(user.note_auth());
        user.open_conn();
        user.set_enabled(false);

        let stats = user.stats();
        assert_eq!(&*stats.id, "alice");
        assert!(!stats.enabled);
        assert_eq!((stats.tx, stats.rx), (1, 2));
        assert_eq!((stats.conns, stats.total_conns), (1, 1));
    }

    #[test]
    fn counters_are_shared_through_the_arc() {
        let user = UserContext::new("alice");
        let clone = user.clone();
        clone.add_tx(4);
        user.add_tx(6);
        assert_eq!(user.tx(), 10);
        assert_eq!(clone.tx(), 10);
    }

    #[test]
    fn counters_sit_on_their_own_cache_line() {
        // The alignment is what keeps two users metered on different cores from
        // invalidating each other's line, so it is worth asserting rather than
        // trusting a comment.
        assert_eq!(std::mem::align_of::<UserContext>(), 64);
        let user = UserContext::new("alice");
        assert_eq!(Arc::as_ptr(&user) as usize % 64, 0);
    }

    #[test]
    fn revocation_closes_the_late_authentication_counter_gate() {
        let user = UserContext::new("alice");
        assert!(user.note_auth());
        user.revoke_connections();

        assert!(!user.note_auth());
        assert_eq!(user.total_conns(), 1);
        assert!(user.is_revoked());
    }

    #[test]
    fn suspension_and_authentication_share_one_lifecycle_gate() {
        let user = UserContext::new("alice");
        let lifecycle = user.connections();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let suspended = Arc::clone(&user);
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            suspended.set_enabled(false);
            finished_tx.send(()).unwrap();
        });

        started_rx.recv().unwrap();
        assert!(
            finished_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "suspension must wait for the same lifecycle gate as admission"
        );
        drop(lifecycle);
        finished_rx.recv().unwrap();
        worker.join().unwrap();

        let late = CancellationToken::new();
        assert!(
            user.register_authenticated_connection(late.clone())
                .is_none(),
            "no authentication beginning after suspension returns may be admitted"
        );
        assert!(late.is_cancelled());
        assert_eq!(user.total_conns(), 0);
    }

    #[test]
    fn kick_cancels_only_the_connections_present_at_its_snapshot() {
        let user = UserContext::new("alice");
        let first = CancellationToken::new();
        let second = CancellationToken::new();
        let first_id = user
            .register_authenticated_connection(first.clone())
            .unwrap();
        let second_id = user
            .register_authenticated_connection(second.clone())
            .unwrap();

        assert_eq!(user.kick_connections(), 2);
        assert!(first.is_cancelled());
        assert!(second.is_cancelled());
        assert!(user.is_enabled());
        assert!(!user.is_revoked());

        // A kick is not a tombstone. A fresh session can register immediately,
        // even while the cancelled sessions are still unwinding.
        let replacement = CancellationToken::new();
        let replacement_id = user
            .register_authenticated_connection(replacement.clone())
            .unwrap();
        assert!(!replacement.is_cancelled());

        user.unregister_connection(first_id);
        user.unregister_connection(second_id);
        user.unregister_connection(replacement_id);
    }

    #[test]
    fn no_ceiling_is_the_default() {
        let user = UserContext::new("alice");
        assert_eq!(user.max_conns(), 0);
        for _ in 0..64 {
            assert!(
                user.register_authenticated_connection(CancellationToken::new())
                    .is_some()
            );
        }
        assert_eq!(user.conns(), 64);
    }

    #[test]
    fn the_ceiling_refuses_the_connection_that_would_exceed_it() {
        let user = UserContext::new("alice");
        user.set_max_conns(2);

        let first = user
            .register_authenticated_connection(CancellationToken::new())
            .expect("under the ceiling");
        let _second = user
            .register_authenticated_connection(CancellationToken::new())
            .expect("at the ceiling");

        let refused = CancellationToken::new();
        assert!(
            user.register_authenticated_connection(refused.clone())
                .is_none()
        );
        // The caller is told to reject, and the connection's own token is cancelled
        // so anything already wrapped around it stops even if the caller does not.
        assert!(refused.is_cancelled());
        assert_eq!(user.conns(), 2);
        // A refused connection never existed, so it is not an authentication in the
        // lifetime figure either.
        assert_eq!(user.total_conns(), 2);

        // Releasing one frees exactly one slot.
        user.unregister_connection(first);
        assert_eq!(user.conns(), 1);
        assert!(
            user.register_authenticated_connection(CancellationToken::new())
                .is_some()
        );
        assert_eq!(user.conns(), 2);
    }

    #[test]
    fn lowering_the_ceiling_below_the_live_count_disconnects_nobody() {
        let user = UserContext::new("alice");
        let ids: Vec<u64> = (0..4)
            .map(|_| {
                user.register_authenticated_connection(CancellationToken::new())
                    .expect("no ceiling yet")
            })
            .collect();

        user.set_max_conns(1);
        assert_eq!(user.conns(), 4, "an admission limit is not a teardown");
        assert!(
            user.register_authenticated_connection(CancellationToken::new())
                .is_none()
        );

        // The count drains past the new ceiling before another is admitted.
        for id in &ids[..3] {
            user.unregister_connection(*id);
        }
        assert_eq!(user.conns(), 1);
        assert!(
            user.register_authenticated_connection(CancellationToken::new())
                .is_none()
        );
        user.unregister_connection(ids[3]);
        assert!(
            user.register_authenticated_connection(CancellationToken::new())
                .is_some()
        );
    }

    #[test]
    fn clearing_the_ceiling_admits_again() {
        let user = UserContext::new("alice");
        user.set_max_conns(1);
        user.register_authenticated_connection(CancellationToken::new())
            .expect("at the ceiling");
        assert!(
            user.register_authenticated_connection(CancellationToken::new())
                .is_none()
        );

        user.set_max_conns(0);
        assert!(
            user.register_authenticated_connection(CancellationToken::new())
                .is_some()
        );
        assert_eq!(user.conns(), 2);
    }

    #[test]
    fn the_ceiling_reaches_the_stats_snapshot() {
        let user = UserContext::new("alice");
        assert_eq!(user.stats().max_conns, 0);
        user.set_max_conns(7);
        assert_eq!(user.stats().max_conns, 7);
    }
}
