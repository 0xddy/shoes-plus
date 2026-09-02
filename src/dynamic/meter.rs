//! Per-connection traffic accounting.
//!
//! # Where the bytes are counted
//!
//! For byte-stream transports, [`TrafficMeterStream`] wraps the client-facing
//! connection at the lowest layer the application owns. Bytes passing that layer
//! are counted exactly once, including visible protocol headers and padding.
//!
//! QUIC is the exception because Quinn owns the UDP socket and its packet framing.
//! Hysteria2 and TUIC wrap each accepted logical stream and account for QUIC
//! datagrams explicitly; those datagram counts include application headers but not
//! Quinn's framing or AEAD overhead. Stream-tunneled protocols such as VLESS UDP,
//! Trojan UDP, and XUDP need no separate path because they remain above the meter.
//!
//! Only client-facing traffic is metered. The stream this proxy opens to the target
//! is deliberately left alone: counting both sides would double every byte.
//!
//! # Why the user is bound late
//!
//! The meter has to be installed before the user is known -- the credential only
//! arrives partway into the handshake, and for TLS-wrapped protocols it arrives
//! after a handshake the meter is already counting. So a connection starts out
//! anonymous: bytes accumulate in the [`ConnContext`] itself, and the moment a
//! protocol handler authenticates, [`bind_connection_user`] hands over what has
//! accumulated so far and every subsequent byte goes straight to the user's
//! counters.
//!
//! # How the context reaches the handler: two shapes
//!
//! **Shape A -- task local.** The handler finds the context through
//! [`bind_connection_user`], which reads it from a task local rather than from a
//! parameter. Threading an `Arc<ConnContext>` from the accept loop down to the byte
//! offset where a uuid appears would mean touching every handler signature in
//! between, including the ones that have nothing to do with users. The task local
//! costs one thread-local read per connection, once, and leaves those signatures
//! untouched. VLESS, VMess, Trojan, Shadowsocks 2022 and AnyTLS all work this way:
//! each authenticates inline on the task that accepted the connection. A handler
//! that then detaches the physical connection uses
//! [`spawn_connection_until_cancelled`] to capture the same context first.
//!
//! **Shape B -- explicit parameter.** Task locals do not cross [`tokio::spawn`], so
//! Shape A works only where authentication is inline. Three protocols authenticate
//! somewhere else and must carry the context themselves, as
//! `type Meter = Option<Arc<ConnContext>>`. QUIC protocols construct it when the
//! connection authenticates; a protocol that crosses a spawn first captures it with
//! [`current_connection`]. They admit through [`ConnContext::bind_authenticated`] or,
//! for repeated request authentication, [`ConnContext::bind_or_matches`]:
//!
//! - **Hysteria2** authenticates once and then fans out into three loops, each its
//!   own task;
//! - **TUIC** does the same with four;
//! - **NaiveProxy** hands the task to hyper at `serve_connection`, and the
//!   credential is not read until a request arrives on it.
//!
//! Tracked dynamic users fail closed when this context is missing, so getting the
//! propagation wrong rejects authentication rather than silently creating a session
//! removal cannot cancel. Every acceptance suite still moves traffic on the path that
//! crosses the spawn, proving the explicit hand-off is present.
//!
//! # Hot path cost
//!
//! One relaxed `fetch_add` per completed read and per completed write, on a cache
//! line that belongs to one user (see [`UserContext`]'s layout), plus one relaxed
//! atomic load to find that user. Unlimited users take no limiter lock and allocate
//! nothing. A limited user additionally enters its shared token bucket and lazily
//! allocates per-stream wait state when the bucket is empty.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use crate::async_stream::{AsyncPing, AsyncStream};

use super::rate::{RatePermit, RateWaiter};
use super::user::UserContext;

tokio::task_local! {
    /// The connection being metered on this task, if it is metered at all.
    static METERED_CONNECTION: Arc<ConnContext>;
}

/// One metered connection's link to the user it turns out to belong to.
///
/// Shared between the [`TrafficMeterStream`] and the task local, so the count of
/// live connections falls only once both are gone -- which matters for handlers
/// that hand the stream to a spawned task and return.
pub struct ConnContext {
    /// Bytes seen before the user was known. Emptied into the user by [`bind`],
    /// and discarded if authentication never succeeds.
    ///
    /// [`bind`]: ConnContext::bind
    pending_tx: AtomicU64,
    pending_rx: AtomicU64,
    /// Serialises the one-time bind and NaiveProxy's concurrent H2 requests. It is
    /// touched only during authentication, never by the byte-counting path.
    binding: Mutex<()>,
    /// Published only after admission has registered the connection. Keeping the
    /// user and its registration id in one cell prevents fallback paths from ever
    /// observing a half-bound connection.
    registration: OnceLock<ConnectionRegistration>,
    cancellation: CancellationToken,
}

#[derive(Clone, Copy, Debug)]
enum DatagramDirection {
    Tx,
    Rx,
}

/// Allowance for one complete QUIC datagram.
///
/// TX obtains this before handing a datagram to Quinn; RX obtains it after Quinn
/// has received the datagram but before validation or forwarding. Dropping it
/// returns every token, while [`commit`](Self::commit) records and charges the
/// datagram once its direction-specific admission point succeeds.
#[must_use = "dropping an uncommitted datagram permit refunds its allowance"]
pub(crate) struct DatagramPermit<'a> {
    conn: &'a ConnContext,
    direction: DatagramDirection,
    bytes: u64,
    first: RatePermit<'a>,
    additional: Vec<RatePermit<'a>>,
}

struct ConnectionRegistration {
    user: Arc<UserContext>,
    id: u64,
}

impl std::fmt::Debug for ConnContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnContext")
            .field("user", &self.user().map(|u| u.id().clone()))
            .field("pending", &self.pending())
            .finish()
    }
}

impl ConnContext {
    pub fn new() -> Arc<Self> {
        Self::with_cancellation(CancellationToken::new())
    }

    /// Create a connection context under an inbound's hard-removal tree.
    ///
    /// Cancelling this child for user revocation does not affect sibling
    /// connections, while cancelling `parent` terminates every child connection.
    pub(crate) fn new_child(parent: &CancellationToken) -> Arc<Self> {
        Self::with_cancellation(parent.child_token())
    }

    fn with_cancellation(cancellation: CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            pending_tx: AtomicU64::new(0),
            pending_rx: AtomicU64::new(0),
            binding: Mutex::new(()),
            registration: OnceLock::new(),
            cancellation,
        })
    }

    /// The authenticated user, once a handler has bound one.
    #[inline]
    pub fn user(&self) -> Option<&Arc<UserContext>> {
        self.registration
            .get()
            .map(|registration| &registration.user)
    }

    /// Bytes counted so far that have not been attributed to anyone. Zero once the
    /// user is bound.
    pub fn pending(&self) -> (u64, u64) {
        (
            self.pending_tx.load(Ordering::Relaxed),
            self.pending_rx.load(Ordering::Relaxed),
        )
    }

    /// Attribute this connection, and everything it has already transferred, to
    /// `user`. Returns false if it was already bound.
    ///
    /// The handover is a `swap` to zero rather than a read, so a byte counted
    /// during the bind lands in the user's counters through exactly one of the two
    /// paths and never through both. It is still ordered rather than atomic: this
    /// is called from the handshake, on the same task that is doing the reads, so
    /// there is no concurrent metering to race with.
    #[cfg(test)]
    pub(crate) fn bind(&self, user: Arc<UserContext>) -> bool {
        let _binding = self.lock_binding();
        self.bind_locked(user, false, true)
    }

    /// Atomically count a proved authentication and bind its physical connection.
    /// The user's removal gate is held across both operations.
    ///
    /// Use this instead of [`bind_connection_user`] when a protocol carries its
    /// `ConnContext` explicitly across a task boundary. Returns `false` when removal
    /// or suspension won the admission race, or when this context was already bound.
    ///
    /// [`bind_connection_user`]: crate::dynamic::bind_connection_user
    pub fn bind_authenticated(&self, user: Arc<UserContext>) -> bool {
        let _binding = self.lock_binding();
        self.bind_locked(user, true, true)
    }

    /// As [`bind_authenticated`](Self::bind_authenticated), except an admission
    /// failure leaves the anonymous physical connection alive so the caller can
    /// serve the same fallback or masquerade as an unknown credential.
    pub fn bind_authenticated_for_fallback(&self, user: Arc<UserContext>) -> bool {
        let _binding = self.lock_binding();
        self.bind_locked(user, true, false)
    }

    fn bind_locked(
        &self,
        user: Arc<UserContext>,
        authenticated: bool,
        cancel_on_failure: bool,
    ) -> bool {
        if self.registration.get().is_some() {
            return false;
        }
        let id = if authenticated {
            if cancel_on_failure {
                user.register_authenticated_connection(self.cancellation.clone())
            } else {
                user.register_authenticated_connection_for_fallback(self.cancellation.clone())
            }
        } else {
            user.register_connection(self.cancellation.clone())
        };
        let Some(id) = id else {
            // Removal won the race after authentication returned this record but
            // before the connection could bind it. Ordinary admission cancels the
            // local token; fallback admission deliberately leaves it anonymous and
            // live so the camouflage response can still be served.
            return false;
        };

        let registration = ConnectionRegistration { user, id };
        if let Err(registration) = self.registration.set(registration) {
            // The binding mutex makes this unreachable in normal operation. Keep
            // the defensive rollback so an invariant violation cannot leak a live
            // entry in the user's revocation set.
            registration.user.unregister_connection(registration.id);
            return false;
        }
        let user = &self.registration.get().expect("just published").user;
        user.add_tx(self.pending_tx.swap(0, Ordering::Relaxed));
        user.add_rx(self.pending_rx.swap(0, Ordering::Relaxed));
        true
    }

    fn lock_binding(&self) -> MutexGuard<'_, ()> {
        self.binding
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Bind this connection to `user`, or confirm it already belongs to them.
    ///
    /// For a protocol that reads a credential more than once on one connection.
    /// NaiveProxy is the case that needs it: it multiplexes every CONNECT over a
    /// single HTTP/2 connection and each request carries its own
    /// `proxy-authorization`, so the same user re-presenting their credential is
    /// ordinary and must not be treated as a failure.
    ///
    /// Returns `false` when the connection is already bound to somebody *else*, or
    /// when this user is no longer eligible for a new authentication because they
    /// were suspended or revoked. A caller must refuse either case. There is one
    /// meter per connection and it cannot separate two users' bytes after the fact,
    /// so letting a second user through would bill everything they move to the first.
    /// One connection, one user.
    ///
    /// The comparison is `Arc` identity rather than id equality: exactly one
    /// [`UserContext`] exists per user, so two records for one user cannot exist to
    /// be confused, and two users can never share one.
    pub fn bind_or_matches(&self, user: &Arc<UserContext>) -> bool {
        let _binding = self.lock_binding();
        if let Some(bound) = self.user() {
            return Arc::ptr_eq(bound, user) && user.note_auth();
        }
        self.bind_locked(Arc::clone(user), true, true)
    }

    /// Admit and account for QUIC datagrams, which never pass through a
    /// [`TrafficMeterStream`].
    ///
    /// Hysteria2 and TUIC carry UDP over QUIC datagrams rather than over the stream
    /// the connection was accepted on, so there is nothing there to wrap: quinn owns
    /// the datagram, and the loop that builds one is the only place its size is
    /// known. The two directional methods below are that loop's way in.
    ///
    /// The figure is the datagram's own length, header and address included, but not
    /// the QUIC framing and AEAD tag quinn adds around it -- the same caveat every
    /// QUIC inbound's accounting carries.
    ///
    /// Obtain download allowance before submitting a datagram to Quinn.
    ///
    /// A successful `send_datagram` must be followed by
    /// [`DatagramPermit::commit`]. A send error, connection cancellation, or task
    /// drop instead drops the permit and refunds all allowance without counting
    /// bytes that never reached Quinn.
    pub(crate) async fn admit_datagram_tx(&self, len: usize) -> DatagramPermit<'_> {
        self.admit_datagram(len, DatagramDirection::Tx).await
    }

    /// Obtain upload allowance for a datagram Quinn has already received.
    ///
    /// Callers wait here before validating or forwarding it. If cancellation wins
    /// while waiting, the datagram is discarded and this permit is never returned,
    /// so it is deliberately neither charged nor counted. Once admitted, even a
    /// malformed datagram is committed because it consumed receive capacity.
    pub(crate) async fn admit_datagram_rx(&self, len: usize) -> DatagramPermit<'_> {
        self.admit_datagram(len, DatagramDirection::Rx).await
    }

    async fn admit_datagram(&self, len: usize, direction: DatagramDirection) -> DatagramPermit<'_> {
        let bytes = len as u64;
        let mut remaining = bytes;
        let mut waiter = RateWaiter::default();
        let first = std::future::poll_fn(|cx| match direction {
            DatagramDirection::Tx => self.poll_acquire_tx(&mut waiter, cx, remaining),
            DatagramDirection::Rx => self.poll_acquire_rx(&mut waiter, cx, remaining),
        })
        .await;
        remaining -= first.granted();

        // A QUIC datagram normally fits below the limiter's 4 KiB minimum burst,
        // so this vector never allocates on real paths. Keeping the general case
        // correct avoids undercharging if a future transport permits jumbo
        // application datagrams.
        let mut additional = Vec::new();
        while remaining != 0 {
            let permit = std::future::poll_fn(|cx| match direction {
                DatagramDirection::Tx => self.poll_acquire_tx(&mut waiter, cx, remaining),
                DatagramDirection::Rx => self.poll_acquire_rx(&mut waiter, cx, remaining),
            })
            .await;
            remaining -= permit.granted();
            additional.push(permit);
        }

        DatagramPermit {
            conn: self,
            direction,
            bytes,
            first,
            additional,
        }
    }

    /// Poll for download allowance. An unbound connection remains unlimited:
    /// pre-authentication bytes are handshake overhead and belong to no user.
    #[inline]
    fn poll_acquire_tx<'a>(
        &'a self,
        waiter: &mut RateWaiter,
        cx: &mut Context<'_>,
        max_bytes: u64,
    ) -> Poll<RatePermit<'a>> {
        match self.registration.get() {
            Some(registration) => registration.user.poll_acquire_tx(waiter, cx, max_bytes),
            None => Poll::Ready(RatePermit::unlimited(max_bytes)),
        }
    }

    /// Poll for upload allowance. See [`poll_acquire_tx`](Self::poll_acquire_tx).
    #[inline]
    fn poll_acquire_rx<'a>(
        &'a self,
        waiter: &mut RateWaiter,
        cx: &mut Context<'_>,
        max_bytes: u64,
    ) -> Poll<RatePermit<'a>> {
        match self.registration.get() {
            Some(registration) => registration.user.poll_acquire_rx(waiter, cx, max_bytes),
            None => Poll::Ready(RatePermit::unlimited(max_bytes)),
        }
    }

    /// Resolves when the user this connection authenticated as is removed.
    /// Before authentication the token remains pending; binding registers it with
    /// the user's revocation set, and a bind racing with removal cancels it at once.
    pub async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    #[inline]
    fn add_tx(&self, n: u64) {
        if n == 0 {
            return;
        }
        if let Some(registration) = self.registration.get() {
            registration.user.add_tx(n);
            return;
        }

        self.pending_tx.fetch_add(n, Ordering::Relaxed);
        // Authentication can publish the registration between the check and the
        // fetch_add above. Rechecking and draining closes that handover race; swaps
        // performed concurrently are harmless because exactly one observes bytes.
        if let Some(registration) = self.registration.get() {
            registration
                .user
                .add_tx(self.pending_tx.swap(0, Ordering::Relaxed));
        }
    }

    #[inline]
    fn add_rx(&self, n: u64) {
        if n == 0 {
            return;
        }
        if let Some(registration) = self.registration.get() {
            registration.user.add_rx(n);
            return;
        }

        self.pending_rx.fetch_add(n, Ordering::Relaxed);
        if let Some(registration) = self.registration.get() {
            registration
                .user
                .add_rx(self.pending_rx.swap(0, Ordering::Relaxed));
        }
    }
}

impl DatagramPermit<'_> {
    /// Mark the admitted datagram as accepted by Quinn (TX) or accepted for
    /// processing (RX), charging every granted token and updating accounting.
    pub(crate) fn commit(self) {
        let Self {
            conn,
            direction,
            bytes,
            first,
            additional,
        } = self;

        let first_bytes = first.granted();
        first.commit(first_bytes);
        for permit in additional {
            let granted = permit.granted();
            permit.commit(granted);
        }

        match direction {
            DatagramDirection::Tx => conn.add_tx(bytes),
            DatagramDirection::Rx => conn.add_rx(bytes),
        }
    }
}

impl Drop for ConnContext {
    fn drop(&mut self) {
        // Mirrors the live-count increment performed during registration, so a
        // connection that never authenticated is not counted down.
        if let Some(registration) = self.registration.get() {
            registration.user.unregister_connection(registration.id);
        }
    }
}

/// Run `future` with `conn` available to [`bind_connection_user`].
pub fn scope_connection<F: std::future::Future>(
    conn: Arc<ConnContext>,
    future: F,
) -> impl std::future::Future<Output = F::Output> {
    METERED_CONNECTION.scope(conn, future)
}

/// Run one ordinary connection until it finishes or its authenticated user is
/// removed. Unlike checking only the stream, this also interrupts time spent in
/// DNS resolution, outbound connect, or protocol setup where no client I/O is
/// currently being polled.
pub async fn scope_connection_until_cancelled<F>(
    conn: Arc<ConnContext>,
    future: F,
) -> std::io::Result<()>
where
    F: Future<Output = std::io::Result<()>>,
{
    let cancellation = Arc::clone(&conn);
    scope_connection(conn, async move {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(connection_removed_error()),
            result = future => result,
        }
    })
    .await
}

/// Admit an authenticated user and, when this task is metered, bind its connection.
///
/// Registry lookups only resolve credentials; they deliberately do not mutate
/// accounting. A protocol handler must call this exactly once after it has all of
/// the proof its protocol requires. On a metered connection, counting the
/// authentication and registering the connection happen under the same per-user
/// lifecycle lock, so removal either drains this connection or rejects it here. A
/// classic, unmetered config-file inbound has no connection to register and records
/// only the authentication. A dynamic context outside the task-local scope is
/// rejected rather than silently admitted without a revocation token.
pub fn bind_connection_user(user: &Arc<UserContext>) -> bool {
    METERED_CONNECTION
        .try_with(|conn| conn.bind_authenticated(Arc::clone(user)))
        .unwrap_or_else(|_| user.admit_unmetered())
}

/// Admit an authenticated user while preserving an anonymous connection for a
/// probe-resistant fallback when admission fails. The caller must not continue as
/// authenticated after `false`.
pub fn bind_connection_user_for_fallback(user: &Arc<UserContext>) -> bool {
    METERED_CONNECTION
        .try_with(|conn| conn.bind_authenticated_for_fallback(Arc::clone(user)))
        .unwrap_or_else(|_| user.admit_unmetered())
}

/// The connection being metered on this task, for code that has to carry the
/// context across a [`tokio::spawn`] boundary itself.
pub fn current_connection() -> Option<Arc<ConnContext>> {
    METERED_CONNECTION.try_with(Arc::clone).ok()
}

/// Spawn a future that takes ownership of the connection currently being handled.
///
/// Tokio task locals do not cross a [`tokio::spawn`] boundary. Protocol handlers
/// that return `AlreadyHandled`, an unauthenticated fallback hand-off, or deferred
/// authentication therefore must capture the context before they return to the
/// outer connection scope. This helper performs that capture synchronously, keeps
/// the same `ConnContext` alive in the child task, and interrupts work that is not
/// polling a metered stream when the inbound's hard-removal tree is cancelled.
///
/// Outside an accepted connection (for example, a standalone handler test), the
/// future is spawned unchanged.
pub fn spawn_connection_until_cancelled<F>(
    future: F,
) -> tokio::task::JoinHandle<std::io::Result<()>>
where
    F: Future<Output = std::io::Result<()>> + Send + 'static,
{
    let conn = current_connection();
    tokio::spawn(async move {
        match conn {
            Some(conn) => scope_connection_until_cancelled(conn, future).await,
            None => future.await,
        }
    })
}

/// A stream that counts every byte that actually crosses it.
///
/// Unlimited reads and writes are forwarded unchanged. A limited user first
/// obtains shared allowance, then the I/O poll is capped to that allowance.
/// Nothing is counted for `Poll::Pending` or an error, so totals still reflect
/// bytes that reached the socket rather than bytes that were merely offered.
pub struct TrafficMeterStream<T> {
    inner: T,
    conn: Arc<ConnContext>,
    cancellation: Pin<Box<WaitForCancellationFutureOwned>>,
    /// Per-stream timer/notification state. It owns no shared reservation, so
    /// dropping the stream while it waits cannot leave rate debt behind.
    read_waiter: RateWaiter,
    write_waiter: RateWaiter,
}

impl<T> TrafficMeterStream<T> {
    pub fn new(inner: T, conn: Arc<ConnContext>) -> Self {
        let cancellation = Box::pin(conn.cancellation_token().cancelled_owned());
        Self {
            inner,
            conn,
            cancellation,
            read_waiter: RateWaiter::default(),
            write_waiter: RateWaiter::default(),
        }
    }

    pub fn conn(&self) -> &Arc<ConnContext> {
        &self.conn
    }

    fn poll_cancelled(&mut self, cx: &mut Context<'_>) -> std::io::Result<()> {
        if self.cancellation.as_mut().poll(cx).is_ready() {
            Err(connection_removed_error())
        } else {
            Ok(())
        }
    }
}

fn connection_removed_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionAborted,
        "connection closed because its user was removed",
    )
}

impl<T: std::fmt::Debug> std::fmt::Debug for TrafficMeterStream<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrafficMeterStream")
            .field("inner", &self.inner)
            .field("conn", &self.conn)
            .finish()
    }
}

/// Poll a reader without letting it consume more than `limit` bytes. The
/// temporary `ReadBuf` must propagate both initialization and filled length back
/// to its parent; callers are allowed to provide uninitialized storage.
fn poll_read_limited<T: AsyncRead + Unpin>(
    inner: &mut T,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
    limit: usize,
) -> (Poll<std::io::Result<()>>, u64) {
    let remaining = buf.remaining();
    if limit >= remaining {
        let before = buf.filled().len();
        let result = Pin::new(inner).poll_read(cx, buf);
        let read = match result {
            Poll::Ready(Ok(())) => (buf.filled().len() - before) as u64,
            _ => 0,
        };
        return (result, read);
    }

    let (result, initialized, filled) = {
        let mut limited = buf.take(limit);
        let result = Pin::new(inner).poll_read(cx, &mut limited);
        (result, limited.initialized().len(), limited.filled().len())
    };
    // SAFETY: the inner AsyncRead reported this prefix initialized through the
    // child ReadBuf above.
    unsafe { buf.assume_init(initialized) };
    let read = if matches!(result, Poll::Ready(Ok(()))) {
        buf.advance(filled);
        filled as u64
    } else {
        0
    };
    (result, read)
}

impl<T: AsyncRead + Unpin> AsyncRead for TrafficMeterStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.poll_cancelled(cx) {
            return Poll::Ready(Err(error));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let Self {
            inner,
            conn,
            read_waiter,
            ..
        } = this;
        let permit =
            std::task::ready!(conn.poll_acquire_rx(read_waiter, cx, buf.remaining() as u64,));
        let limit = permit.granted() as usize;
        let (result, read) = poll_read_limited(inner, cx, buf, limit);
        if matches!(result, Poll::Ready(Ok(()))) {
            permit.commit(read);
            conn.add_rx(read);
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for TrafficMeterStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if let Err(error) = this.poll_cancelled(cx) {
            return Poll::Ready(Err(error));
        }
        if buf.is_empty() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        let Self {
            inner,
            conn,
            write_waiter,
            ..
        } = this;
        let permit = std::task::ready!(conn.poll_acquire_tx(write_waiter, cx, buf.len() as u64,));
        let limit = permit.granted() as usize;
        let result = Pin::new(inner).poll_write(cx, &buf[..limit]);
        if let Poll::Ready(Ok(n)) = result {
            permit.commit(n as u64);
            conn.add_tx(n as u64);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.poll_cancelled(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.poll_cancelled(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }

    // Forwarded rather than left to the default implementation, which would fall
    // back to writing a single buffer per poll and cost throughput on the TLS
    // record path.
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if let Err(error) = this.poll_cancelled(cx) {
            return Poll::Ready(Err(error));
        }
        let requested = bufs
            .iter()
            .fold(0usize, |total, buf| total.saturating_add(buf.len()));
        if requested == 0 {
            return Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        }

        let Self {
            inner,
            conn,
            write_waiter,
            ..
        } = this;
        let permit = std::task::ready!(conn.poll_acquire_tx(write_waiter, cx, requested as u64,));
        let limit = permit.granted() as usize;
        let result = if limit >= requested {
            Pin::new(inner).poll_write_vectored(cx, bufs)
        } else {
            let mut remaining = limit;
            let mut limited = Vec::with_capacity(bufs.len());
            for buf in bufs {
                if remaining == 0 {
                    break;
                }
                let len = remaining.min(buf.len());
                if len != 0 {
                    limited.push(std::io::IoSlice::new(&buf[..len]));
                    remaining -= len;
                }
            }
            Pin::new(inner).poll_write_vectored(cx, &limited)
        };
        if let Poll::Ready(Ok(n)) = result {
            permit.commit(n as u64);
            conn.add_tx(n as u64);
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl<T: AsyncPing + Unpin> AsyncPing for TrafficMeterStream<T> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        // Deliberately not counted. A ping is written by the stream underneath this
        // one, which meters it on the way out.
        let this = self.get_mut();
        if let Err(error) = this.poll_cancelled(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_write_ping(cx)
    }
}

impl<T: AsyncStream> AsyncStream for TrafficMeterStream<T> {}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;

    fn metered(conn: &Arc<ConnContext>) -> (DuplexStream, TrafficMeterStream<DuplexStream>) {
        let (peer, local) = tokio::io::duplex(4096);
        (peer, TrafficMeterStream::new(local, Arc::clone(conn)))
    }

    #[tokio::test]
    async fn counts_bytes_in_both_directions_against_the_bound_user() {
        let user = UserContext::new("alice");
        let conn = ConnContext::new();
        assert!(conn.bind(Arc::clone(&user)));

        let (mut peer, mut stream) = metered(&conn);
        peer.write_all(b"0123456789").await.unwrap();
        let mut buf = [0u8; 10];
        stream.read_exact(&mut buf).await.unwrap();
        stream.write_all(b"abc").await.unwrap();

        assert_eq!((user.rx(), user.tx()), (10, 3));
        assert_eq!(conn.pending(), (0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_pending_read_refunds_its_pre_io_allowance() {
        const RATE_BPS: u64 = 1_000_000;
        const BURST: usize = 125_000;

        let user = UserContext::new("alice");
        user.set_speed_limits(RATE_BPS, 0);
        let conn = ConnContext::new();
        assert!(conn.bind(Arc::clone(&user)));

        // The first stream has no data. Its read obtains allowance before
        // polling the duplex and must return that allowance when the duplex is
        // Pending.
        let (_empty_peer, empty_local) = tokio::io::duplex(BURST + 1);
        let mut empty_stream = TrafficMeterStream::new(empty_local, Arc::clone(&conn));
        let mut attempt = [0u8; 4096];
        {
            let mut read = Box::pin(empty_stream.read_exact(&mut attempt));
            assert!(futures::poll!(read.as_mut()).is_pending());
        }
        assert_eq!(user.rx(), 0, "a Pending read must not be charged");

        // A different stream can still spend the complete opening burst. If
        // the first permit leaked, this read would have to wait for its tail.
        let (mut peer, local) = tokio::io::duplex(BURST + 1);
        peer.write_all(&vec![0x5a; BURST]).await.unwrap();
        let mut stream = TrafficMeterStream::new(local, Arc::clone(&conn));
        let mut received = vec![0u8; BURST];
        let start = tokio::time::Instant::now();
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(tokio::time::Instant::now(), start);
        assert_eq!(user.rx(), BURST as u64);
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_an_upload_waiter_leaves_no_debt_for_another_stream() {
        const RATE_BPS: u64 = 1_000_000;
        const BURST: usize = 125_000;

        let user = UserContext::new("alice");
        user.set_speed_limits(RATE_BPS, 0);
        let conn = ConnContext::new();
        assert!(conn.bind(Arc::clone(&user)));

        let (mut opening_peer, opening_local) = tokio::io::duplex(BURST + 1);
        opening_peer.write_all(&vec![0x11; BURST]).await.unwrap();
        let mut opening_stream = TrafficMeterStream::new(opening_local, Arc::clone(&conn));
        let mut opening = vec![0u8; BURST];
        opening_stream.read_exact(&mut opening).await.unwrap();
        assert_eq!(user.rx(), BURST as u64);

        // Data is ready underneath, but the exhausted shared bucket prevents
        // the wrapper from reading it. Cancelling this future and dropping its
        // stream must not enqueue a 32 KiB reservation for the future.
        let (mut blocked_peer, blocked_local) = tokio::io::duplex(32 * 1024 + 1);
        blocked_peer
            .write_all(&vec![0x22; 32 * 1024])
            .await
            .unwrap();
        let mut blocked_stream = TrafficMeterStream::new(blocked_local, Arc::clone(&conn));
        let mut blocked_buf = vec![0u8; 32 * 1024];
        {
            let mut read = Box::pin(blocked_stream.read_exact(&mut blocked_buf));
            assert!(futures::poll!(read.as_mut()).is_pending());
        }
        assert_eq!(
            user.rx(),
            BURST as u64,
            "rate waiting must happen before bytes leave the socket"
        );
        drop(blocked_stream);

        let (mut probe_peer, probe_local) = tokio::io::duplex(1025);
        probe_peer.write_all(&vec![0x33; 1024]).await.unwrap();
        let mut probe_stream = TrafficMeterStream::new(probe_local, Arc::clone(&conn));
        let mut probe = [0u8; 1024];
        let start = tokio::time::Instant::now();
        probe_stream.read_exact(&mut probe).await.unwrap();
        let elapsed = tokio::time::Instant::now().duration_since(start);
        let ideal = Duration::from_micros(8192);
        assert!(
            (ideal..=ideal + Duration::from_millis(1)).contains(&elapsed),
            "the canceled stream delayed a 1 KiB probe by {elapsed:?}"
        );
        assert_eq!(user.rx(), BURST as u64 + 1024);
    }

    #[tokio::test(start_paused = true)]
    async fn datagram_permits_count_only_on_commit_and_refund_on_drop() {
        const RATE_BPS: u64 = 8 * 64 * 1024;
        const DATAGRAM: usize = 64 * 1024;

        let user = UserContext::new("alice");
        user.set_speed_limits(RATE_BPS, RATE_BPS);
        let conn = ConnContext::new();
        assert!(conn.bind(Arc::clone(&user)));

        let tx = conn.admit_datagram_tx(DATAGRAM).await;
        assert_eq!(user.tx(), 0, "admission alone is not a successful send");
        drop(tx);
        let tx = conn.admit_datagram_tx(DATAGRAM).await;
        tx.commit();
        assert_eq!(user.tx(), DATAGRAM as u64);

        let rx = conn.admit_datagram_rx(DATAGRAM).await;
        assert_eq!(user.rx(), 0, "admission alone is not accepted input");
        drop(rx);
        let rx = conn.admit_datagram_rx(DATAGRAM).await;
        rx.commit();
        assert_eq!(user.rx(), DATAGRAM as u64);
    }

    #[tokio::test]
    async fn hands_the_handshake_bytes_over_when_the_user_is_bound() {
        let conn = ConnContext::new();
        let (mut peer, mut stream) = metered(&conn);

        // Stand in for the handshake: counted before anyone knows who this is.
        peer.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        stream.write_all(b"ok").await.unwrap();
        assert_eq!(conn.pending(), (2, 5));

        let user = UserContext::new("alice");
        assert!(conn.bind(Arc::clone(&user)));
        assert_eq!((user.rx(), user.tx()), (5, 2));
        assert_eq!(conn.pending(), (0, 0), "the handover must not leave a copy");

        // And from here on the bytes go straight to the user.
        stream.write_all(b"more").await.unwrap();
        assert_eq!(user.tx(), 6);
    }

    #[tokio::test]
    async fn one_connection_belongs_to_one_user() {
        // The shape NaiveProxy needs: a credential is read once per request, many
        // requests ride one connection, and there is one meter for all of them.
        let alice = UserContext::new("alice");
        let bob = UserContext::new("bob");
        let conn = ConnContext::new();

        assert!(
            conn.bind_or_matches(&alice),
            "the first user names the connection"
        );
        assert!(
            conn.bind_or_matches(&alice),
            "and re-presenting the same credential is ordinary, not a failure"
        );
        assert!(
            !conn.bind_or_matches(&bob),
            "but a second user must be refused: their bytes would land on alice"
        );

        // The refusal changes nothing -- the connection is still alice's.
        assert_eq!(
            conn.user().map(|u| u.id().to_string()),
            Some("alice".into())
        );
        assert_eq!(bob.conns(), 0, "and bob was never opened against");
        assert_eq!(bob.total_conns(), 0);

        let (mut peer, mut stream) = metered(&conn);
        peer.write_all(b"payload").await.unwrap();
        let mut buf = [0u8; 7];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(alice.rx(), 7);
        assert_eq!(bob.rx(), 0);
    }

    #[tokio::test]
    async fn traffic_from_a_client_that_never_authenticates_belongs_to_nobody() {
        let conn = ConnContext::new();
        let (mut peer, mut stream) = metered(&conn);
        peer.write_all(b"garbage").await.unwrap();
        let mut buf = [0u8; 7];
        stream.read_exact(&mut buf).await.unwrap();

        assert_eq!(conn.pending(), (0, 7));
        assert!(conn.user().is_none());
        // Dropping an unbound context must not touch any user's live count.
        drop(stream);
        drop(conn);
    }

    #[tokio::test]
    async fn the_connection_stays_live_until_the_last_holder_drops_it() {
        let user = UserContext::new("alice");
        let conn = ConnContext::new();
        conn.bind(Arc::clone(&user));
        assert_eq!(user.conns(), 1);

        // The stream holds its own clone, standing in for a handler that moved it
        // into a spawned task.
        let (_peer, stream) = metered(&conn);
        drop(conn);
        assert_eq!(user.conns(), 1, "the stream is still open");

        drop(stream);
        assert_eq!(user.conns(), 0);
        assert_eq!(
            user.total_conns(),
            0,
            "plain bind registers an already-accounted/internal connection"
        );
    }

    #[tokio::test]
    async fn revoking_a_user_wakes_and_aborts_a_pending_stream() {
        let user = UserContext::new("alice");
        let conn = ConnContext::new();
        assert!(conn.bind(Arc::clone(&user)));

        let (_peer, mut stream) = metered(&conn);
        drop(conn);
        let read = tokio::spawn(async move {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await
        });
        tokio::task::yield_now().await;

        user.revoke_connections();
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), read)
            .await
            .expect("revocation must wake a pending read")
            .expect("the read task must not panic")
            .expect_err("the removed user's stream must be aborted");
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);

        user.wait_for_connections_closed().await;
        assert_eq!(user.conns(), 0);
    }

    #[tokio::test]
    async fn a_bind_that_loses_the_removal_race_fails_closed() {
        let user = UserContext::new("alice");
        user.revoke_connections();

        let conn = ConnContext::new();
        assert!(!conn.bind_authenticated(Arc::clone(&user)));
        assert!(conn.user().is_none());
        assert_eq!(user.conns(), 0);
        assert_eq!(user.total_conns(), 0);

        let (_peer, mut stream) = metered(&conn);
        let error = stream
            .write_all(b"must not leave")
            .await
            .expect_err("a late bind inherits the already-cancelled state");
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
    }

    #[tokio::test]
    async fn fallback_admission_failure_stays_anonymous_and_allows_another_user() {
        let alice = UserContext::new("alice");
        alice.set_max_conns(1);
        alice.set_speed_limits(8 * 1024 * 1024, 8 * 1024 * 1024);
        let occupied = alice
            .register_authenticated_connection(CancellationToken::new())
            .expect("the first connection occupies the only slot");
        let conn = ConnContext::new();

        assert!(!conn.bind_authenticated_for_fallback(Arc::clone(&alice)));
        assert!(
            conn.user().is_none(),
            "a credential that failed admission must not claim the connection"
        );
        assert_eq!(alice.conns(), 1);
        assert_eq!(alice.total_conns(), 1);
        assert!(conn.registration.get().is_none());
        assert!(!conn.cancellation.is_cancelled());
        let mut waiter = RateWaiter::default();
        let permit =
            std::future::poll_fn(|cx| conn.poll_acquire_rx(&mut waiter, cx, 4 * 1024 * 1024)).await;
        assert_eq!(
            permit.granted(),
            4 * 1024 * 1024,
            "anonymous fallback bytes must not consume alice's rate bucket"
        );
        permit.commit(4 * 1024 * 1024);

        // A metered fallback can still move bytes, but without attributing them to
        // the credential whose admission was refused.
        let (mut peer, mut stream) = metered(&conn);
        peer.write_all(b"fallback").await.unwrap();
        let mut received = [0u8; 8];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"fallback");
        assert_eq!(alice.rx(), 0);
        assert_eq!(conn.pending(), (0, 8));

        // Hysteria2 accepts another auth request on the same H3 connection after a
        // camouflaged refusal. A different eligible user must still be able to bind
        // it, and receives the anonymous bytes exactly once.
        let bob = UserContext::new("bob");
        assert!(conn.bind_authenticated_for_fallback(Arc::clone(&bob)));
        assert!(conn.user().is_some_and(|user| Arc::ptr_eq(user, &bob)));
        assert_eq!(bob.rx(), 8);
        assert_eq!(conn.pending(), (0, 0));
        assert_eq!(alice.rx(), 0);

        alice.unregister_connection(occupied);
    }

    #[tokio::test]
    async fn concurrent_naive_requests_share_the_first_bind_without_a_false_rejection() {
        let user = UserContext::new("alice");
        let conn = ConnContext::new();
        let barrier = Arc::new(tokio::sync::Barrier::new(3));

        let mut requests = Vec::new();
        for _ in 0..2 {
            let conn = Arc::clone(&conn);
            let user = Arc::clone(&user);
            let barrier = Arc::clone(&barrier);
            requests.push(tokio::spawn(async move {
                barrier.wait().await;
                conn.bind_or_matches(&user)
            }));
        }
        barrier.wait().await;

        for request in requests {
            assert!(request.await.unwrap());
        }
        assert_eq!(user.conns(), 1);
        assert_eq!(user.total_conns(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_bind_and_removal_have_one_linearized_winner() {
        for _ in 0..100 {
            let user = UserContext::new("alice");
            let conn = ConnContext::new();
            let barrier = Arc::new(tokio::sync::Barrier::new(3));

            let binder = {
                let user = Arc::clone(&user);
                let conn = Arc::clone(&conn);
                let barrier = Arc::clone(&barrier);
                tokio::spawn(async move {
                    barrier.wait().await;
                    conn.bind_authenticated(user)
                })
            };
            let remover = {
                let user = Arc::clone(&user);
                let barrier = Arc::clone(&barrier);
                tokio::spawn(async move {
                    barrier.wait().await;
                    user.revoke_connections();
                })
            };
            barrier.wait().await;

            let admitted = binder.await.unwrap();
            remover.await.unwrap();
            assert_eq!(user.total_conns(), u64::from(admitted));
            assert_eq!(user.conns(), u64::from(admitted));
            drop(conn);
            user.wait_for_connections_closed().await;
        }
    }

    #[tokio::test]
    async fn a_second_bind_is_refused_rather_than_double_counted() {
        let alice = UserContext::new("alice");
        let bob = UserContext::new("bob");
        let conn = ConnContext::new();

        assert!(conn.bind(Arc::clone(&alice)));
        assert!(!conn.bind(Arc::clone(&bob)));

        assert_eq!(alice.conns(), 1);
        assert_eq!(bob.conns(), 0);
        assert_eq!(&**conn.user().unwrap().id(), "alice");
    }

    #[tokio::test]
    async fn binding_reaches_a_context_installed_further_up_the_call_stack() {
        // Stands in for a protocol handler several layers below the accept loop.
        async fn deep_inside_a_handshake(user: &Arc<UserContext>) -> bool {
            bind_connection_user(user)
        }

        let user = UserContext::new("alice");
        let conn = ConnContext::new();
        let bound = scope_connection(Arc::clone(&conn), async {
            assert!(current_connection().is_some());
            deep_inside_a_handshake(&user).await
        })
        .await;

        assert!(bound);
        assert_eq!(&**conn.user().unwrap().id(), "alice");
        assert_eq!(user.conns(), 1);
        assert_eq!(user.total_conns(), 1);
    }

    #[tokio::test]
    #[allow(clippy::async_yields_async)]
    async fn detached_unmetered_work_keeps_its_context_and_observes_hard_stop() {
        let parent = CancellationToken::new();
        let conn = ConnContext::new_child(&parent);
        let weak = Arc::downgrade(&conn);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();

        // The outer future must deliberately yield the detached JoinHandle: awaiting
        // it inside the task-local scope would wait forever and defeat this test.
        let task = scope_connection(Arc::clone(&conn), async move {
            spawn_connection_until_cancelled(async move {
                let _ = started_tx.send(());
                std::future::pending::<std::io::Result<()>>().await
            })
        })
        .await;
        drop(conn);

        started_rx.await.expect("detached work started");
        assert!(
            weak.upgrade().is_some(),
            "the detached task must retain the otherwise-unmetered context"
        );

        parent.cancel();
        let error = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("hard stop must wake detached work")
            .expect("detached task must not panic")
            .expect_err("hard stop must cancel detached work");
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
        assert!(
            weak.upgrade().is_none(),
            "the task must release its connection context after cancellation"
        );
    }

    #[tokio::test]
    async fn admission_outside_a_metered_inbound_still_counts_authentication() {
        let user = UserContext::new_untracked("alice");
        assert!(current_connection().is_none());
        assert!(bind_connection_user(&user));
        assert_eq!(user.conns(), 0);
        assert_eq!(user.total_conns(), 1);
    }

    #[tokio::test]
    async fn a_tracked_user_outside_its_connection_scope_fails_closed() {
        let user = UserContext::new("alice");
        assert!(current_connection().is_none());
        assert!(!bind_connection_user(&user));
        assert_eq!(user.conns(), 0);
        assert_eq!(user.total_conns(), 0);
    }
}
