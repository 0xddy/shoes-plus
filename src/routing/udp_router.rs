//! UDP Router - Per-destination routing for multi-destination UDP streams.
//!
//! This implementation uses:
//! - IndexMap with FxHasher for fast session storage with stable iteration order
//! - Separate buffer pools for outbound/inbound to prevent starvation
//! - Zero-copy queuing: read directly into pool buffer, queue if write pending
//! - DelayQueue for O(1) session expiry (no iteration)
//! - Work queues for pending writes/flushes/responses (no iteration over all sessions)

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use indexmap::IndexMap;
use log::{debug, warn};
use lru::LruCache;
use rustc_hash::{FxBuildHasher, FxHashMap};
use tokio::io::ReadBuf;
use tokio::time::Instant;
use tokio_util::time::{DelayQueue, delay_queue};

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncReadSessionMessage,
    AsyncReadTargetedMessage, AsyncSessionMessageStream, AsyncShutdownMessage,
    AsyncShutdownMessageExt, AsyncTargetedMessageStream, AsyncWriteMessage,
    AsyncWriteSessionMessage, AsyncWriteSourcedMessage, SessionMessage, SessionMessageStatus,
    SessionMessageTarget,
};
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::resolver::{Resolver, resolve_addresses};
use crate::util::allocate_vec;

/// Timeout for inactive sessions
const SESSION_TIMEOUT_SECS: u64 = 200;

/// Maximum UDP packet size
const MAX_UDP_PACKET_SIZE: usize = 65535;

/// Maximum number of blocked destinations to remember (LRU eviction)
const MAX_BLOCKED_ENTRIES: usize = 80;

/// Buffer pool size for outbound (server → remote) - one per concurrent session
const REMOTE_WRITE_POOL_SIZE: usize = 8;

/// Buffer pool size for inbound (remote → server) - all go to same writer
const SERVER_WRITE_POOL_SIZE: usize = 8;

/// Max pending remote writes per session (prevents one slow session from starving others)
const MAX_PENDING_REMOTE_WRITES_PER_SESSION: usize = 4;

/// Max pending server writes per session (prevents one chatty session from starving others)
const MAX_PENDING_SERVER_WRITES_PER_SESSION: usize = 4;

/// Max concurrent session creation attempts (limits resource usage under burst)
const MAX_PENDING_CREATES: usize = 16;

/// Max active or connecting UDP destination subflows per inbound stream.
/// XUDP may put many destinations under one protocol session ID, so the limit
/// counts routed subflows rather than protocol IDs.
const MAX_UDP_FLOWS: usize = 512;

/// Retiring streams count against the flow cap and are force-dropped after a
/// bounded grace period if their shutdown never completes.
const REMOTE_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// DNS, routing and connection setup are one bounded per-flow operation.
const UDP_FLOW_CREATE_TIMEOUT: Duration = Duration::from_secs(15);

/// Bound work done by the reserved control reader in one poll. Data packets are
/// deliberately dropped on this overload path so they cannot hide End events.
const CONTROL_READ_BUDGET: usize = 32;

/// How often to check if pings are needed
const PING_CHECK_INTERVAL: Duration = Duration::from_secs(15);

/// Ping streams that haven't had writes for this long
const PING_IDLE_THRESHOLD: Duration = Duration::from_secs(30);

/// Session identifier - incrementing counter, never reused
type SessionKey = usize;

/// Lazy buffer pool for backpressure management.
///
/// Buffers are created on-demand up to max_count, then reused.
/// Acquired buffers are either released immediately (if write succeeds)
/// or moved into a queue (zero-copy).
struct BufferPool {
    buffers: Vec<Box<[u8]>>,
    max_count: usize,
    created_count: usize,
}

impl BufferPool {
    fn new(max_count: usize) -> Self {
        Self {
            buffers: Vec::with_capacity(max_count),
            max_count,
            created_count: 0,
        }
    }

    #[inline]
    fn acquire(&mut self) -> Option<Box<[u8]>> {
        // Try to reuse existing buffer
        if let Some(buf) = self.buffers.pop() {
            return Some(buf);
        }

        // Create new if under limit
        if self.created_count < self.max_count {
            self.created_count += 1;
            Some(allocate_vec(MAX_UDP_PACKET_SIZE).into_boxed_slice())
        } else {
            None
        }
    }

    #[inline]
    fn release(&mut self, buf: Box<[u8]>) {
        self.buffers.push(buf);
    }

    #[inline]
    fn deallocate(&mut self) {
        let buffers = std::mem::take(&mut self.buffers);
        self.created_count -= buffers.len();
    }
}

/// State of a session key in the lookup map
#[derive(Clone, Copy)]
enum KeyState {
    /// Session exists with this ID
    Active(SessionKey),
    /// Session creation in progress
    Pending,
}

/// How to look up the session for a packet
#[derive(Clone)]
enum LookupKey {
    /// For Targeted streams: use destination
    Destination(NetLocation),
    /// For SessionBased streams: one protocol session may concurrently carry
    /// multiple UDP destinations.
    ProtocolSession(ProtocolSessionKey),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProtocolSessionKey {
    session_id: u16,
    destination: NetLocation,
}

/// Session lookup strategy - determined by server stream type
enum SessionLookup {
    /// For Targeted: destination -> KeyState
    ByDestination(FxHashMap<NetLocation, KeyState>),
    /// For SessionBased: (protocol session_id, destination) -> KeyState
    ByProtocolSession(FxHashMap<ProtocolSessionKey, KeyState>),
}

/// A routing session (one per unique flow)
struct RoutingSession {
    /// The destination this session routes to
    destination: NetLocation,

    /// The session's session id if this is a session UDP stream
    session_id: u16,

    /// Resolved address for response source field
    resolved_addr: SocketAddr,

    /// The lookup key for this session (needed for removal from lookup map)
    lookup_key: LookupKey,

    /// The remote connection
    remote: Box<dyn AsyncMessageStream>,

    /// Count of pending writes in remote_write_queue for this session
    in_remote_write_queue: usize,

    /// Is there a pending flush?
    in_remote_flush_queue: bool,

    /// Count of pending responses in server_write_queue for this session
    in_server_write_queue: usize,

    /// Key for DelayQueue (to cancel/reset expiry timer)
    expiry_key: Option<delay_queue::Key>,

    /// Remote read returned EOF or error
    remote_read_eof: bool,

    /// Remote write returned error
    remote_write_eof: bool,

    /// Last time we wrote to the remote (for ping decisions)
    last_write: Instant,

    /// Last iteration when expiry was reset (to avoid redundant resets)
    last_expiry_iteration: usize,
}

impl RoutingSession {
    fn new(
        destination: NetLocation,
        session_id: u16,
        resolved_addr: SocketAddr,
        lookup_key: LookupKey,
        remote: Box<dyn AsyncMessageStream>,
    ) -> Self {
        Self {
            destination,
            session_id,
            resolved_addr,
            lookup_key,
            remote,
            in_remote_write_queue: 0,
            in_remote_flush_queue: false,
            in_server_write_queue: 0,
            expiry_key: None, // Set after insert when we have the SessionId
            remote_read_eof: false,
            remote_write_eof: false,
            last_write: Instant::now(),
            last_expiry_iteration: 0,
        }
    }

    /// Check if session should be removed.
    #[inline]
    fn should_remove(&self) -> bool {
        self.remote_read_eof && self.remote_write_eof
    }

    /// Reset session expiry timer (skips if already reset this iteration)
    #[inline]
    fn reset_expiry(
        &mut self,
        expiry_queue: &mut DelayQueue<SessionKey>,
        _id: SessionKey,
        iteration: usize,
    ) {
        if self.last_expiry_iteration == iteration {
            return; // Already reset this iteration
        }
        self.last_expiry_iteration = iteration;

        // Use reset() which is more efficient than remove() + insert()
        // as it reuses the same slab entry and key
        if let Some(ref key) = self.expiry_key {
            expiry_queue.reset(key, Duration::from_secs(SESSION_TIMEOUT_SECS));
        }
    }
}

/// A pending write waiting to be sent to remote
struct PendingWrite {
    id: SessionKey,
    buf: Box<[u8]>,
    len: usize,
}

struct RetiringStream {
    remote: Box<dyn AsyncMessageStream>,
    /// Polling the timer registers the router task's waker, so the hard grace
    /// is enforced even when the remote shutdown future never wakes us.
    deadline: Pin<Box<tokio::time::Sleep>>,
}

/// Server stream variants - unified via enum
pub enum ServerStream {
    /// SOCKS5 UDP, Shadowsocks UoT, etc.
    Targeted(Box<dyn AsyncTargetedMessageStream>),
    /// XUDP (VLESS/VMess)
    Session(Box<dyn AsyncSessionMessageStream>),
}

impl ServerStream {
    fn poll_read_message(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<InboundMessage>> {
        match self {
            ServerStream::Targeted(stream) => {
                match Pin::new(stream).poll_read_targeted_message(cx, buf) {
                    Poll::Ready(Ok(dest)) => {
                        Poll::Ready(Ok(InboundMessage::Packet(InboundPacket {
                            destination: dest.into(),
                            session_id: 0,
                            response_address: None,
                            status: None,
                        })))
                    }
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            }
            ServerStream::Session(stream) => {
                match Pin::new(stream).poll_read_session_message(cx, buf) {
                    Poll::Ready(Ok(SessionMessage::Data {
                        session_id,
                        status,
                        target,
                    })) => Poll::Ready(Ok(InboundMessage::Packet(InboundPacket {
                        response_address: target.response_address_opt(),
                        destination: target.into_destination(),
                        session_id,
                        status: Some(status),
                    }))),
                    Poll::Ready(Ok(SessionMessage::End { session_id })) => {
                        Poll::Ready(Ok(InboundMessage::SessionEnd(session_id)))
                    }
                    Poll::Ready(Ok(SessionMessage::UnknownKeep { session_id })) => {
                        Poll::Ready(Ok(InboundMessage::UnknownKeep(session_id)))
                    }
                    Poll::Ready(Ok(SessionMessage::Rejected { session_id })) => {
                        Poll::Ready(Ok(InboundMessage::Rejected(session_id)))
                    }
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn poll_write_message(
        &mut self,
        cx: &mut Context<'_>,
        data: &[u8],
        target: &SessionMessageTarget,
        session_id: u16,
    ) -> Poll<io::Result<()>> {
        match self {
            ServerStream::Targeted(stream) => {
                Pin::new(stream).poll_write_sourced_message(cx, data, &target.response_address())
            }
            ServerStream::Session(stream) => {
                Pin::new(stream).poll_write_session_message(cx, session_id, data, target)
            }
        }
    }

    fn poll_write_session_end(
        &mut self,
        cx: &mut Context<'_>,
        session_id: u16,
        has_error: bool,
    ) -> Poll<io::Result<()>> {
        match self {
            ServerStream::Session(stream) => {
                Pin::new(stream).poll_write_session_end(cx, session_id, has_error)
            }
            ServerStream::Targeted(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "targeted UDP streams do not support session End frames",
            ))),
        }
    }

    fn supports_ping(&self) -> bool {
        match self {
            ServerStream::Targeted(stream) => stream.supports_ping(),
            ServerStream::Session(stream) => stream.supports_ping(),
        }
    }

    fn poll_write_ping(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        match self {
            ServerStream::Targeted(stream) => Pin::new(stream).poll_write_ping(cx),
            ServerStream::Session(stream) => Pin::new(stream).poll_write_ping(cx),
        }
    }

    fn poll_flush_message(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            ServerStream::Targeted(stream) => Pin::new(stream).poll_flush_message(cx),
            ServerStream::Session(stream) => Pin::new(stream).poll_flush_message(cx),
        }
    }

    async fn shutdown_message(&mut self) -> io::Result<()> {
        match self {
            ServerStream::Targeted(stream) => stream.shutdown_message().await,
            ServerStream::Session(stream) => stream.shutdown_message().await,
        }
    }
}

impl std::fmt::Debug for ServerStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerStream::Targeted(_) => f.debug_struct("Targeted").finish_non_exhaustive(),
            ServerStream::Session(_) => f.debug_struct("Session").finish_non_exhaustive(),
        }
    }
}

/// Packet info extracted from server stream
struct InboundPacket {
    destination: ResolvedLocation,
    session_id: u16,
    response_address: Option<SocketAddr>,
    status: Option<SessionMessageStatus>,
}

enum InboundMessage {
    Packet(InboundPacket),
    SessionEnd(u16),
    UnknownKeep(u16),
    Rejected(u16),
}

enum InboundAction {
    Packet(InboundPacket),
    Continue,
    Stop,
}

/// Result of session creation
struct SessionCreateResult {
    remote: Box<dyn AsyncMessageStream>,
    resolved_addr: SocketAddr,
}

async fn prepare_udp_destination(
    resolver: &Arc<dyn Resolver>,
    mut destination: ResolvedLocation,
    response_address: Option<SocketAddr>,
) -> io::Result<(ResolvedLocation, SocketAddr)> {
    if destination.resolved_addrs().is_none() {
        let addresses = resolve_addresses(resolver, destination.location()).await?;
        destination.set_resolved_addrs(addresses);
    }
    let response_address = response_address
        .or_else(|| destination.resolved_addr())
        .expect("successful UDP resolution must retain an address");
    Ok((destination, response_address))
}

/// Type alias for the session creation future
type SessionCreateFuture = Pin<Box<dyn Future<Output = io::Result<SessionCreateResult>> + Send>>;

/// Pending session creation state
struct PendingSessionCreate {
    lookup_key: LookupKey,
    destination: NetLocation,
    session_id: u16,
    initial_data: Vec<u8>,
    future: SessionCreateFuture,
}

/// The unified UDP router
pub struct UdpRouter<'a> {
    server: &'a mut ServerStream,
    /// Lookup: maps flow key -> session state
    session_lookup: SessionLookup,

    sessions: IndexMap<SessionKey, RoutingSession, FxBuildHasher>,
    next_session_id: SessionKey,
    /// Round-robin position for fair session polling
    session_poll_position: usize,
    /// Blocked destinations (LRU-bounded)
    blocked: LruCache<NetLocation, ()>,

    pending_creates: Vec<PendingSessionCreate>,

    remote_write_queue: VecDeque<PendingWrite>,
    remote_flush_queue: VecDeque<SessionKey>,
    server_write_queue: VecDeque<PendingWrite>,
    pending_session_ends: VecDeque<(u16, bool)>,
    queued_session_ends: HashSet<u16>,
    /// An End frame was accepted by the session writer but has not completed
    /// its transport flush. Do not read a same-ID New before it is on the wire.
    session_end_flush_pending: bool,

    needs_server_flush: bool,

    server_read_eof: bool,
    server_write_eof: bool,

    sessions_to_remove: HashSet<SessionKey>,
    pending_shutdowns: VecDeque<RetiringStream>,

    remote_write_pool: BufferPool,
    /// A buffer reserved for reading session control events even when every
    /// ordinary outbound buffer is held by a pending remote write.
    control_read_buffer: Box<[u8]>,
    server_write_pool: BufferPool,

    expiry_queue: DelayQueue<SessionKey>,
    ping_timer: tokio::time::Interval,
    expiry_iteration: usize,

    last_server_write: Instant,

    selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
}

impl<'a> UdpRouter<'a> {
    /// Create a new UDP router.
    pub fn new(
        server: &'a mut ServerStream,
        selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        need_initial_flush: bool,
    ) -> Self {
        let session_lookup = match server {
            ServerStream::Targeted(_) => SessionLookup::ByDestination(FxHashMap::default()),
            ServerStream::Session(_) => SessionLookup::ByProtocolSession(FxHashMap::default()),
        };

        Self {
            server,
            session_lookup,
            sessions: IndexMap::with_hasher(FxBuildHasher),
            next_session_id: 0,
            session_poll_position: 0,
            blocked: LruCache::new(NonZeroUsize::new(MAX_BLOCKED_ENTRIES).unwrap()),
            pending_creates: Vec::new(),
            remote_write_queue: VecDeque::with_capacity(REMOTE_WRITE_POOL_SIZE),
            remote_flush_queue: VecDeque::with_capacity(REMOTE_WRITE_POOL_SIZE),
            server_write_queue: VecDeque::with_capacity(SERVER_WRITE_POOL_SIZE),
            pending_session_ends: VecDeque::new(),
            queued_session_ends: HashSet::new(),
            session_end_flush_pending: false,
            needs_server_flush: need_initial_flush,
            server_read_eof: false,
            server_write_eof: false,
            sessions_to_remove: HashSet::new(),
            pending_shutdowns: VecDeque::new(),
            remote_write_pool: BufferPool::new(REMOTE_WRITE_POOL_SIZE),
            control_read_buffer: allocate_vec(MAX_UDP_PACKET_SIZE).into_boxed_slice(),
            server_write_pool: BufferPool::new(SERVER_WRITE_POOL_SIZE),
            expiry_queue: DelayQueue::new(),
            ping_timer: tokio::time::interval(PING_CHECK_INTERVAL),
            expiry_iteration: 0,
            last_server_write: Instant::now(),
            selector,
            resolver,
        }
    }

    /// Set server read EOF and clean up pending session creates.
    /// Called when server read returns an error or zero-length read.
    #[inline]
    fn set_server_read_eof(&mut self) {
        if self.server_read_eof {
            return;
        }

        self.server_read_eof = true;
        // Clean up pending creates - remove lookup entries and drop futures
        // TODO: is this correct? what if the user wanted to send a single packet and closed their
        // connection?
        for pending in self.pending_creates.drain(..) {
            match (&mut self.session_lookup, pending.lookup_key) {
                (SessionLookup::ByDestination(map), LookupKey::Destination(dest)) => {
                    map.remove(&dest);
                }
                (SessionLookup::ByProtocolSession(map), LookupKey::ProtocolSession(key)) => {
                    map.remove(&key);
                }
                _ => unreachable!(),
            }
            // Future and initial_data are dropped
        }
    }

    /// Set server write EOF and clean up server write queue.
    /// Called when server write or flush returns an error.
    #[inline]
    fn set_server_write_eof(&mut self) {
        if self.server_write_eof {
            return;
        }

        self.server_write_eof = true;
        self.needs_server_flush = false;

        // Return buffers to pool and clear queue.
        // We don't update session.in_server_write_queue counters here because:
        // 1. We're in shutdown mode - no more server writes will happen
        // 2. Sessions will be cleaned up through expiry anyway
        // 3. Avoids borrow conflicts when called from contexts that hold session refs
        for pending in self.server_write_queue.drain(..) {
            self.server_write_pool.release(pending.buf);
        }
        self.pending_session_ends.clear();
        self.queued_session_ends.clear();
        self.session_end_flush_pending = false;
        self.server_write_pool.deallocate();
    }

    fn queue_session_end(&mut self, session_id: u16, has_error: bool) {
        if matches!(&*self.server, ServerStream::Session(_))
            && self.queued_session_ends.insert(session_id)
        {
            self.pending_session_ends.push_back((session_id, has_error));
        }
    }

    fn reject_fresh_protocol_new(&mut self, packet: &InboundPacket) -> bool {
        if packet.status != Some(SessionMessageStatus::New) {
            return false;
        }
        let SessionLookup::ByProtocolSession(map) = &self.session_lookup else {
            return false;
        };
        if map.keys().any(|key| key.session_id == packet.session_id) {
            return false;
        }
        self.queue_session_end(packet.session_id, true);
        true
    }

    /// Drain pending session shutdowns (best-effort, non-blocking)
    fn drain_remote_shutdowns(&mut self, cx: &mut Context<'_>) {
        let count = self.pending_shutdowns.len();
        for _ in 0..count {
            let mut retiring = self.pending_shutdowns.pop_front().unwrap();
            // Poll before the remote so a permanently-pending shutdown still
            // has an independent wakeup at the hard deadline.
            if retiring.deadline.as_mut().poll(cx).is_ready() {
                continue;
            }
            if Pin::new(&mut retiring.remote)
                .poll_shutdown_message(cx)
                .is_pending()
            {
                self.pending_shutdowns.push_back(retiring);
            }
            // If Ready (success or error), stream is dropped
        }
    }

    fn handle_inbound_message(&mut self, message: InboundMessage) -> InboundAction {
        match message {
            InboundMessage::Packet(packet) => InboundAction::Packet(packet),
            InboundMessage::SessionEnd(session_id) => {
                debug!("[UdpRouter] peer ended protocol session {session_id}");
                self.end_protocol_session(session_id);
                InboundAction::Continue
            }
            InboundMessage::UnknownKeep(session_id) => {
                debug!(
                    "[UdpRouter] rejecting Keep for codec-unknown protocol session {session_id}"
                );
                self.end_protocol_session(session_id);
                self.queue_session_end(session_id, true);
                // Do not consume a following same-ID New until the rejecting
                // End has been accepted and flushed to the peer.
                InboundAction::Stop
            }
            InboundMessage::Rejected(session_id) => {
                debug!("[UdpRouter] rejecting duplicate New for protocol session {session_id}");
                self.end_protocol_session(session_id);
                self.queue_session_end(session_id, true);
                InboundAction::Stop
            }
        }
    }

    /// Continue reading control events while ordinary outbound buffers are all
    /// held by pending remote writes. The reserved buffer is full-size to honor
    /// the message-read contract; ordinary UDP Data is dropped under this
    /// overload policy so it cannot permanently hide a following control event.
    fn poll_read_server_with_control_buffer(&mut self, cx: &mut Context<'_>) -> (bool, bool) {
        let mut made_progress = false;
        for _ in 0..CONTROL_READ_BUDGET {
            let (message, len) = {
                let mut read_buf = ReadBuf::new(&mut self.control_read_buffer);
                let message = match self.server.poll_read_message(cx, &mut read_buf) {
                    Poll::Ready(Ok(message)) => {
                        made_progress = true;
                        message
                    }
                    Poll::Ready(Err(error)) => {
                        debug!("UDP inbound peer read ended: {error}");
                        self.set_server_read_eof();
                        return (made_progress, false);
                    }
                    Poll::Pending => return (made_progress, false),
                };
                (message, read_buf.filled().len())
            };

            match self.handle_inbound_message(message) {
                InboundAction::Continue => continue,
                InboundAction::Stop => return (true, false),
                InboundAction::Packet(packet) => {
                    if len == 0 {
                        self.set_server_read_eof();
                        return (true, false);
                    }
                    if self.reject_fresh_protocol_new(&packet) {
                        return (true, false);
                    }
                    debug!("dropping UDP data while outbound buffer pool is exhausted");
                }
            }
        }
        cx.waker().wake_by_ref();
        (made_progress, false)
    }

    /// Read from server, route to sessions
    /// Returns (made_progress, exhausted) - exhausted only if read hit Pending, not pool exhaustion
    #[inline]
    fn poll_read_server(&mut self, cx: &mut Context<'_>) -> (bool, bool) {
        if !self.pending_session_ends.is_empty()
            || self.session_end_flush_pending
            || self.needs_server_flush
        {
            return (false, false);
        }

        // Acquire buffer from outbound pool. If all ordinary buffers are held by
        // pending writes, a reserved buffer can still surface End/UnknownKeep.
        let Some(mut buf) = self.remote_write_pool.acquire() else {
            debug!("outbound pool exhausted, reading with reserved control buffer");
            return self.poll_read_server_with_control_buffer(cx);
        };

        let mut server_read_progress = false;
        let mut remote_writes_progress = false;
        loop {
            let mut read_buf = ReadBuf::new(&mut buf);
            let message = match self.server.poll_read_message(cx, &mut read_buf) {
                Poll::Ready(Ok(message)) => {
                    server_read_progress = true;
                    message
                }
                Poll::Ready(Err(e)) => {
                    debug!("UDP inbound peer read ended: {e}");
                    self.set_server_read_eof();
                    break;
                }
                Poll::Pending => {
                    break;
                }
            };

            let packet = match self.handle_inbound_message(message) {
                InboundAction::Packet(packet) => packet,
                InboundAction::Continue => continue,
                InboundAction::Stop => break,
            };
            let len = read_buf.filled().len();

            debug!(
                "[UdpRouter] poll_read_server got packet: {} bytes to {} ({:?})",
                len, packet.destination, packet.status
            );

            if len == 0 {
                self.set_server_read_eof();
                break;
            }

            // Look up session
            let key_state = match &self.session_lookup {
                SessionLookup::ByDestination(map) => {
                    map.get(packet.destination.location()).copied()
                }
                SessionLookup::ByProtocolSession(map) => map
                    .get(&ProtocolSessionKey {
                        session_id: packet.session_id,
                        destination: packet.destination.location().clone(),
                    })
                    .copied(),
            };

            match key_state {
                Some(KeyState::Active(id)) => {
                    let Some(session) = self.sessions.get_mut(&id) else {
                        // session is gone, skip message
                        continue;
                    };

                    // Skip if remote write is EOF
                    if session.remote_write_eof {
                        continue;
                    }

                    // Skip if session has too many pending writes (backpressure)
                    if session.in_remote_write_queue >= MAX_PENDING_REMOTE_WRITES_PER_SESSION {
                        continue;
                    }

                    // Always try to write immediately
                    match Pin::new(&mut session.remote).poll_write_message(cx, &buf[..len]) {
                        Poll::Ready(Ok(())) => {
                            remote_writes_progress = true;

                            session.last_write = Instant::now();
                            session.reset_expiry(&mut self.expiry_queue, id, self.expiry_iteration);
                            if !session.in_remote_flush_queue {
                                session.in_remote_flush_queue = true;
                                self.remote_flush_queue.push_back(id);
                            }
                        }
                        Poll::Pending => {
                            session.in_remote_write_queue += 1;
                            self.remote_write_queue
                                .push_back(PendingWrite { id, buf, len });
                            let Some(new_buf) = self.remote_write_pool.acquire() else {
                                return (server_read_progress, remote_writes_progress);
                            };
                            buf = new_buf;
                        }
                        Poll::Ready(Err(e)) => {
                            warn!("remote write error: {}", e);
                            session.remote_write_eof = true;
                            if session.should_remove() {
                                self.sessions_to_remove.insert(id);
                            }
                        }
                    }
                }
                Some(KeyState::Pending) => {}
                None => {
                    // No session - check blocked before creating
                    if self.blocked.get(packet.destination.location()).is_some() {
                        debug!("UDP proxying blocked to {}", packet.destination);
                        if self.reject_fresh_protocol_new(&packet) {
                            break;
                        }
                        continue;
                    }

                    if self.sessions.len()
                        + self.pending_creates.len()
                        + self.pending_shutdowns.len()
                        >= MAX_UDP_FLOWS
                    {
                        debug!(
                            "UDP flow limit reached, dropping new flow for {}",
                            packet.destination
                        );
                        if self.reject_fresh_protocol_new(&packet) {
                            break;
                        }
                        continue;
                    }

                    if self.pending_creates.len() >= MAX_PENDING_CREATES {
                        debug!(
                            "Too many pending creates, dropping new session creation for {}",
                            packet.destination
                        );
                        if self.reject_fresh_protocol_new(&packet) {
                            break;
                        }
                        continue;
                    }

                    self.start_session_creation(cx, packet, &buf[..len]);
                    if !self.pending_session_ends.is_empty() {
                        break;
                    }
                }
            }
        }

        self.remote_write_pool.release(buf);
        (server_read_progress, remote_writes_progress)
    }

    /// Drain pending writes to remotes
    #[inline]
    fn drain_remote_writes(&mut self, cx: &mut Context<'_>) -> bool {
        let queue_len = self.remote_write_queue.len();

        for _ in 0..queue_len {
            let PendingWrite { id, buf, len } = self.remote_write_queue.pop_front().unwrap();

            let Some(session) = self.sessions.get_mut(&id) else {
                // Session gone, release buffer
                self.remote_write_pool.release(buf);
                continue;
            };

            // If remote_write_eof, can't write - release buffer
            if session.remote_write_eof {
                session.in_remote_write_queue -= 1;
                self.remote_write_pool.release(buf);
                if session.should_remove() {
                    self.sessions_to_remove.insert(id);
                }
                continue;
            }

            let data = &buf[..len];

            match Pin::new(&mut session.remote).poll_write_message(cx, data) {
                Poll::Ready(Ok(())) => {
                    session.in_remote_write_queue -= 1;
                    session.last_write = Instant::now();
                    session.reset_expiry(&mut self.expiry_queue, id, self.expiry_iteration);
                    if !session.in_remote_flush_queue {
                        session.in_remote_flush_queue = true;
                        self.remote_flush_queue.push_back(id);
                    }
                    self.remote_write_pool.release(buf);
                }
                Poll::Pending => {
                    self.remote_write_queue
                        .push_back(PendingWrite { id, buf, len });
                }
                Poll::Ready(Err(e)) => {
                    warn!("remote write error: {}", e);
                    session.in_remote_write_queue -= 1;
                    self.remote_write_pool.release(buf);
                    session.remote_write_eof = true;
                    if session.should_remove() {
                        self.sessions_to_remove.insert(id);
                    }
                }
            }
        }

        self.remote_write_queue.len() < queue_len
    }

    /// Drain pending flushes
    #[inline]
    fn drain_remote_flushes(&mut self, cx: &mut Context<'_>) -> bool {
        let queue_len = self.remote_flush_queue.len();

        for _ in 0..queue_len {
            let id = self.remote_flush_queue.pop_front().unwrap();

            let Some(session) = self.sessions.get_mut(&id) else {
                continue;
            };

            if !session.in_remote_flush_queue {
                continue;
            }

            match Pin::new(&mut session.remote).poll_flush_message(cx) {
                Poll::Ready(Ok(())) => {
                    session.in_remote_flush_queue = false;
                }
                Poll::Pending => {
                    self.remote_flush_queue.push_back(id);
                }
                Poll::Ready(Err(error)) => {
                    if !session.remote_write_eof {
                        warn!("remote flush error: {error}");
                    }
                    session.in_remote_flush_queue = false;
                    session.remote_write_eof = true;
                    if session.should_remove() {
                        self.sessions_to_remove.insert(id);
                    }
                }
            }
        }

        self.remote_flush_queue.len() < queue_len
    }

    /// Read from remotes, write to server
    /// Returns (made_progress, write_success, exhausted) - exhausted only if reads hit Pending, not pool exhaustion
    #[inline]
    fn poll_read_remotes(&mut self, cx: &mut Context<'_>) -> (bool, bool) {
        // Acquire one buffer upfront - reused across sessions
        let Some(mut buf) = self.server_write_pool.acquire() else {
            debug!("inbound pool exhausted, applying backpressure");
            return (false, false); // pool-limited, not exhausted
        };

        let mut remote_read_progress = false;
        let mut server_write_progress = false;

        // Read from sessions, using round-robin for fairness
        let session_count = self.sessions.len();

        for i in 0..session_count {
            let idx = (self.session_poll_position + i) % session_count;
            let Some((&id, session)) = self.sessions.get_index_mut(idx) else {
                continue;
            };

            if session.remote_read_eof
                || session.in_server_write_queue >= MAX_PENDING_SERVER_WRITES_PER_SESSION
            {
                continue;
            }

            for _ in session.in_server_write_queue..MAX_PENDING_SERVER_WRITES_PER_SESSION {
                let mut read_buf = ReadBuf::new(&mut buf);

                match Pin::new(&mut session.remote).poll_read_message(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let len = read_buf.filled().len();
                        debug!(
                            "[UdpRouter] Read {} bytes from session remote (session {})",
                            len, session.destination
                        );
                        if len == 0 {
                            session.remote_read_eof = true;
                            if session.should_remove() {
                                self.sessions_to_remove.insert(id);
                            }
                            break; // Stop bursting this session
                        }

                        remote_read_progress = true;
                        session.reset_expiry(&mut self.expiry_queue, id, self.expiry_iteration);

                        let response_target = SessionMessageTarget::new(
                            ResolvedLocation::with_resolved(
                                session.destination.clone(),
                                session.resolved_addr,
                            ),
                            session.resolved_addr,
                        );
                        match self.server.poll_write_message(
                            cx,
                            &buf[..len],
                            &response_target,
                            session.session_id,
                        ) {
                            Poll::Ready(Ok(())) => {
                                debug!(
                                    "[UdpRouter] Wrote {} bytes to server (to {})",
                                    len, session.resolved_addr
                                );
                                server_write_progress = true;
                                // Buffer consumed and free, reuse `buf` for next burst or session
                            }
                            Poll::Pending => {
                                debug!("[UdpRouter] Write to server pending");
                                session.in_server_write_queue += 1;
                                self.server_write_queue
                                    .push_back(PendingWrite { id, buf, len });

                                match self.server_write_pool.acquire() {
                                    Some(new_buf) => {
                                        buf = new_buf;
                                        // Queued a write, break burst to allow other sessions/draining
                                        break;
                                    }
                                    None => {
                                        // Pool exhausted, pool_limited = true but we return
                                        // immediately
                                        return (remote_read_progress, server_write_progress);
                                    }
                                }
                            }
                            Poll::Ready(Err(e)) => {
                                debug!("UDP inbound peer write ended: {e}");
                                self.server_write_pool.release(buf); // release in-hand buffer
                                self.set_server_write_eof();
                                return (remote_read_progress, server_write_progress);
                            }
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        debug!("remote read error: {}", e);
                        session.remote_read_eof = true;
                        if session.should_remove() {
                            self.sessions_to_remove.insert(id);
                        }
                        break;
                    }
                    Poll::Pending => {
                        break;
                    }
                }
            }
        }

        // Advance position for fairness across poll calls
        if session_count > 0 {
            self.session_poll_position = (self.session_poll_position + 1) % session_count;
        }

        self.server_write_pool.release(buf);

        // exhausted only if we made no progress (all reads returned Pending)
        (remote_read_progress, server_write_progress)
    }

    /// Drain pending responses to server
    #[inline]
    fn drain_server_writes(&mut self, cx: &mut Context<'_>) -> bool {
        let mut server_write_progress = false;

        while let Some(pending) = self.server_write_queue.pop_front() {
            let PendingWrite { id, buf, len } = pending;

            let Some(session) = self.sessions.get_mut(&id) else {
                // Session gone, release buffer
                self.server_write_pool.release(buf);
                continue;
            };

            let response_target = SessionMessageTarget::new(
                ResolvedLocation::with_resolved(session.destination.clone(), session.resolved_addr),
                session.resolved_addr,
            );
            match self.server.poll_write_message(
                cx,
                &buf[..len],
                &response_target,
                session.session_id,
            ) {
                Poll::Ready(Ok(())) => {
                    session.in_server_write_queue -= 1;
                    if session.should_remove() {
                        self.sessions_to_remove.insert(id);
                    }
                    server_write_progress = true;
                    self.server_write_pool.release(buf);
                }
                Poll::Pending => {
                    self.server_write_queue
                        .push_front(PendingWrite { id, buf, len });
                    break;
                }
                Poll::Ready(Err(e)) => {
                    debug!("UDP inbound peer write ended: {e}");
                    session.in_server_write_queue -= 1; // last use of session borrow
                    self.server_write_pool.release(buf); // release current buffer
                    self.set_server_write_eof(); // clears remaining queue
                    break;
                }
            }
        }

        server_write_progress
    }

    /// Drain per-session End responses without closing the multiplexed server.
    #[inline]
    fn drain_session_ends(&mut self, cx: &mut Context<'_>) -> bool {
        let mut server_write_progress = false;

        while let Some(&(session_id, has_error)) = self.pending_session_ends.front() {
            match self
                .server
                .poll_write_session_end(cx, session_id, has_error)
            {
                Poll::Ready(Ok(())) => {
                    self.pending_session_ends.pop_front();
                    self.queued_session_ends.remove(&session_id);
                    self.session_end_flush_pending = true;
                    server_write_progress = true;
                }
                Poll::Pending => break,
                Poll::Ready(Err(error)) => {
                    debug!("UDP inbound peer session End write ended: {error}");
                    self.set_server_write_eof();
                    break;
                }
            }
        }

        server_write_progress
    }

    /// Poll pending session creates
    #[inline]
    fn poll_pending_creates(&mut self, cx: &mut Context<'_>) -> bool {
        let mut made_progress = false;

        let mut i = 0;
        while i < self.pending_creates.len() {
            let before = self.pending_creates.len();
            made_progress |= self.poll_pending_create(cx, i);
            if self.pending_creates.len() == before {
                i += 1;
            }
        }

        made_progress
    }

    #[inline]
    fn poll_pending_create(&mut self, cx: &mut Context<'_>, i: usize) -> bool {
        let result = match self.pending_creates[i].future.as_mut().poll(cx) {
            Poll::Ready(result) => result,
            Poll::Pending => {
                return false;
            }
        };

        let pending = self.pending_creates.swap_remove(i);

        let PendingSessionCreate {
            lookup_key,
            destination,
            session_id,
            initial_data,
            future: _,
        } = pending;

        match result {
            Ok(SessionCreateResult {
                remote,
                resolved_addr,
            }) => {
                debug!(
                    "Session created for {} (resolved to {})",
                    destination, resolved_addr
                );

                let id = self.next_session_id;
                self.next_session_id += 1;

                // Update lookup map
                let pending_key_state = match (&mut self.session_lookup, &lookup_key) {
                    (SessionLookup::ByDestination(map), LookupKey::Destination(dest)) => {
                        map.insert(dest.clone(), KeyState::Active(id))
                    }
                    (SessionLookup::ByProtocolSession(map), LookupKey::ProtocolSession(key)) => {
                        map.insert(key.clone(), KeyState::Active(id))
                    }
                    _ => unreachable!(),
                };
                debug_assert!(matches!(pending_key_state.unwrap(), KeyState::Pending));

                let mut session =
                    RoutingSession::new(destination, session_id, resolved_addr, lookup_key, remote);

                // TODO: part of constructor, we now know the id in advance
                let expiry_key = self
                    .expiry_queue
                    .insert(id, Duration::from_secs(SESSION_TIMEOUT_SECS));
                session.expiry_key = Some(expiry_key);

                // Try to write immediately
                if !initial_data.is_empty() {
                    debug!(
                        "Writing initial_data ({} bytes) to session for {}",
                        initial_data.len(),
                        session.destination
                    );
                    match Pin::new(&mut session.remote).poll_write_message(cx, &initial_data) {
                        Poll::Ready(Ok(())) => {
                            debug!("Initial data write succeeded, queueing flush");
                            session.last_write = Instant::now();
                            // Note: expiry was just set above when inserting into expiry_queue
                            if !session.in_remote_flush_queue {
                                session.in_remote_flush_queue = true;
                                self.remote_flush_queue.push_back(id);
                            }
                        }
                        Poll::Pending => {
                            debug!("Initial data write pending, queueing for later");
                            if let Some(mut buf) = self.remote_write_pool.acquire() {
                                let len = initial_data.len();
                                buf[..len].copy_from_slice(&initial_data);
                                session.in_remote_write_queue += 1;
                                self.remote_write_queue
                                    .push_back(PendingWrite { id, buf, len });
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            warn!("remote write error: {}", e);
                            session.remote_write_eof = true;
                            if session.should_remove() {
                                self.sessions_to_remove.insert(id);
                            }
                        }
                    }
                }
                self.sessions.insert(id, session);
                true
            }
            Err(e) => {
                let rejected_protocol_session = match &lookup_key {
                    LookupKey::ProtocolSession(key) => Some(key.session_id),
                    LookupKey::Destination(_) => None,
                };
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    debug!("UDP routing blocked session for {destination}: {e}");
                    // Mark as blocked
                    self.blocked.put(destination.clone(), ());
                } else {
                    warn!("Failed to create UDP session for {destination}: {e}");
                }
                // Remove from pending in lookup
                match (&mut self.session_lookup, &lookup_key) {
                    (SessionLookup::ByDestination(map), LookupKey::Destination(dest)) => {
                        map.remove(dest);
                    }
                    (SessionLookup::ByProtocolSession(map), LookupKey::ProtocolSession(key)) => {
                        map.remove(key);
                    }
                    _ => unreachable!(),
                }
                if let Some(session_id) = rejected_protocol_session {
                    let has_other_subflow = match &self.session_lookup {
                        SessionLookup::ByProtocolSession(map) => {
                            map.keys().any(|key| key.session_id == session_id)
                        }
                        SessionLookup::ByDestination(_) => false,
                    };
                    if !has_other_subflow {
                        self.queue_session_end(session_id, true);
                    }
                }
                false
            }
        }
    }

    /// Start session creation
    #[inline]
    fn start_session_creation(&mut self, cx: &mut Context<'_>, packet: InboundPacket, data: &[u8]) {
        let InboundPacket {
            destination,
            session_id,
            response_address,
            status: _,
        } = packet;

        let original_destination = destination.location().clone();

        let lookup_key = match &mut self.session_lookup {
            SessionLookup::ByDestination(map) => {
                map.insert(original_destination.clone(), KeyState::Pending);
                LookupKey::Destination(original_destination.clone())
            }
            SessionLookup::ByProtocolSession(map) => {
                let key = ProtocolSessionKey {
                    session_id,
                    destination: original_destination.clone(),
                };
                map.insert(key.clone(), KeyState::Pending);
                LookupKey::ProtocolSession(key)
            }
        };

        debug!("Creating session for {}", original_destination);

        let initial_data = data.to_vec();
        let selector = Arc::clone(&self.selector);
        let resolver = Arc::clone(&self.resolver);
        let dest_for_future = destination;

        let future: SessionCreateFuture = Box::pin(async move {
            tokio::time::timeout(UDP_FLOW_CREATE_TIMEOUT, async move {
                let (resolved_location, _resolved_addr) =
                    prepare_udp_destination(&resolver, dest_for_future, response_address).await?;
                let decision = selector.judge_udp(resolved_location, &resolver).await?;

                match decision {
                    ConnectDecision::Allow {
                        chain_group,
                        remote_location,
                    } => {
                        let connection = chain_group
                            .connect_udp_bidirectional_with_peer(&resolver, remote_location)
                            .await?;

                        Ok(SessionCreateResult {
                            remote: connection.client_stream,
                            resolved_addr: connection.remote_addr,
                        })
                    }
                    ConnectDecision::Block => Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Destination blocked by routing rules",
                    )),
                }
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP flow creation timed out"))?
        });

        let index = self.pending_creates.len();
        self.pending_creates.push(PendingSessionCreate {
            lookup_key,
            destination: original_destination,
            session_id,
            initial_data,
            future,
        });
        let _ = self.poll_pending_create(cx, index);
    }

    /// Apply an explicit end event from a session-multiplexed inbound.
    ///
    /// One XUDP protocol session may own several destination subflows. End retires
    /// every active subflow and cancels every pending creation for that ID.
    fn end_protocol_session(&mut self, session_id: u16) {
        let mut active_ids = Vec::new();
        let found_lookup = match &mut self.session_lookup {
            SessionLookup::ByProtocolSession(map) => {
                let before = map.len();
                map.retain(|key, state| {
                    if key.session_id == session_id {
                        if let KeyState::Active(id) = state {
                            active_ids.push(*id);
                        }
                        false
                    } else {
                        true
                    }
                });
                map.len() != before
            }
            SessionLookup::ByDestination(_) => return,
        };

        let pending_before = self.pending_creates.len();
        self.pending_creates.retain(|pending| {
            !matches!(
                &pending.lookup_key,
                LookupKey::ProtocolSession(key) if key.session_id == session_id
            )
        });
        let found_pending = self.pending_creates.len() != pending_before;

        for id in active_ids {
            self.remove_session(id);
        }

        if !found_lookup && !found_pending {
            debug!("ignoring end for unknown UDP protocol session {session_id}");
        }
    }

    /// Remove a session (split-borrow friendly version)
    #[inline]
    fn remove_session(&mut self, id: SessionKey) {
        let Some(mut session) = self.sessions.swap_remove(&id) else {
            return;
        };

        debug!("Session removed: {}", session.destination);

        // Cancel expiry timer
        if let Some(key) = session.expiry_key.take() {
            self.expiry_queue.remove(&key);
        }

        // Remove from lookup map
        match (&mut self.session_lookup, session.lookup_key) {
            (SessionLookup::ByDestination(map), LookupKey::Destination(dest)) => {
                map.remove(&dest);
            }
            (SessionLookup::ByProtocolSession(map), LookupKey::ProtocolSession(key)) => {
                map.remove(&key);
            }
            _ => unreachable!(),
        }

        // Queue remote stream for graceful shutdown
        self.pending_shutdowns.push_back(RetiringStream {
            remote: session.remote,
            deadline: Box::pin(tokio::time::sleep(REMOTE_SHUTDOWN_GRACE)),
        });
    }

    /// Process expired sessions
    fn process_expired(&mut self, cx: &mut Context<'_>) {
        while let Poll::Ready(Some(expired)) = self.expiry_queue.poll_expired(cx) {
            let id = expired.into_inner();
            // Clear expiry_key since poll_expired already removed it from the queue
            if let Some(session) = self.sessions.get_mut(&id) {
                debug!("Session expired: {}", session.destination);
                session.expiry_key = None;
            }
            self.remove_session(id);
        }
    }

    /// Mark idle sessions for pinging
    fn write_server_ping(&mut self, cx: &mut Context<'_>) -> bool {
        let now = Instant::now();

        if self.server.supports_ping()
            && self.server_write_queue.is_empty()
            && self.pending_session_ends.is_empty()
            && !self.session_end_flush_pending
            && now.duration_since(self.last_server_write) >= PING_IDLE_THRESHOLD
        {
            match self.server.poll_write_ping(cx) {
                Poll::Ready(Ok(_wrote_ping)) => {
                    // Reset regardless of if ping was written, if false, it means that the
                    // stream was already busy and it's unnecessary
                    debug!("Sent ping to server stream");
                    return true;
                }
                Poll::Ready(Err(e)) => {
                    debug!("server ping error: {}", e);
                    self.set_server_write_eof();
                }
                Poll::Pending => {
                    // Skip and wait for next ping interval
                }
            }
        }

        false
    }

    fn write_remote_pings(&mut self, cx: &mut Context<'_>) -> bool {
        let now = Instant::now();
        let mut made_progress = false;

        // Mark idle sessions for pinging
        for (&id, session) in &mut self.sessions {
            if session.remote.supports_ping()
                && session.in_remote_write_queue == 0
                && now.duration_since(session.last_write) >= PING_IDLE_THRESHOLD
            {
                // Try to send ping immediately
                match Pin::new(&mut session.remote).poll_write_ping(cx) {
                    Poll::Ready(Ok(_wrote_ping)) => {
                        debug!("Sent ping to {}", session.destination);
                        made_progress = true;
                        session.last_write = now;
                        if !session.in_remote_flush_queue {
                            session.in_remote_flush_queue = true;
                            self.remote_flush_queue.push_back(id);
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        debug!("remote ping error: {}", e);
                        session.remote_write_eof = true;
                        if session.should_remove() {
                            self.sessions_to_remove.insert(id);
                        }
                    }
                    Poll::Pending => {
                        // Skip and wait for next ping interval
                    }
                }
            }
        }

        made_progress
    }
}

impl<'a> Future for UdpRouter<'a> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        this.expiry_iteration = this.expiry_iteration.wrapping_add(1);

        let ping_triggered = this.ping_timer.poll_tick(cx).is_ready();

        // Each direction runs independently to exhaustion.
        this.poll_outbound(cx, ping_triggered);
        this.poll_inbound(cx, ping_triggered);

        if !this.sessions_to_remove.is_empty() {
            let sessions_to_remove = std::mem::take(&mut this.sessions_to_remove);
            for id in sessions_to_remove {
                this.remove_session(id);
            }
        }
        this.process_expired(cx);

        this.drain_remote_shutdowns(cx);

        if this.server_read_eof && this.server_write_eof {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl UdpRouter<'_> {
    /// Poll outbound path: server -> remotes
    /// Runs until no progress (all operations pending or exhausted).
    #[inline]
    fn poll_outbound(&mut self, cx: &mut Context<'_>, ping_triggered: bool) {
        if !self.pending_creates.is_empty() {
            self.poll_pending_creates(cx);
        }

        loop {
            let mut server_read_progress = false;
            let mut remote_writes_progress = false;

            remote_writes_progress |= self.drain_remote_writes(cx);

            if ping_triggered {
                remote_writes_progress |= self.write_remote_pings(cx);
            }

            if !self.remote_flush_queue.is_empty() {
                remote_writes_progress |= self.drain_remote_flushes(cx);
            }

            // Read from server and route to remotes (if not EOF)
            if !self.server_read_eof
                && self.pending_session_ends.is_empty()
                && !self.session_end_flush_pending
            {
                let (new_server_read_progress, new_remote_writes_progress) =
                    self.poll_read_server(cx);
                server_read_progress |= new_server_read_progress;
                remote_writes_progress |= new_remote_writes_progress;
            }

            if !server_read_progress && !remote_writes_progress {
                break;
            }

            // Cooperative yielding to prevent task starvation
            match tokio::task::coop::poll_proceed(cx) {
                Poll::Ready(coop) => coop.made_progress(),
                Poll::Pending => break,
            }
        }
    }

    /// Poll inbound path: remotes -> server
    /// Runs until no progress (all operations pending or exhausted).
    #[inline]
    fn poll_inbound(&mut self, cx: &mut Context<'_>, ping_triggered: bool) {
        loop {
            // Early exit if server write is EOF
            if self.server_write_eof {
                break;
            }

            let mut server_write_progress = false;

            // Drain pending writes to server
            server_write_progress |= self.drain_server_writes(cx);

            // Preserve write-call identity under backpressure: finish queued data
            // before a per-session End, and finish that End before accepting more
            // remote responses.
            if self.server_write_queue.is_empty() {
                server_write_progress |= self.drain_session_ends(cx);
            }

            // Read from remotes only when no earlier message is waiting to be
            // accepted by the multiplexed writer.
            let (remote_read_progress, new_server_write_progress) =
                if self.server_write_queue.is_empty()
                    && self.pending_session_ends.is_empty()
                    && !self.session_end_flush_pending
                {
                    self.poll_read_remotes(cx)
                } else {
                    (false, false)
                };
            server_write_progress |= new_server_write_progress;

            // Don't bother pinging if we wrote.
            if !server_write_progress && ping_triggered {
                server_write_progress |= self.write_server_ping(cx);
            }

            if server_write_progress {
                self.needs_server_flush = true;
                self.last_server_write = Instant::now();
            }

            if self.needs_server_flush {
                match self.server.poll_flush_message(cx) {
                    Poll::Ready(Ok(())) => {
                        self.needs_server_flush = false;
                        let end_was_pending = std::mem::take(&mut self.session_end_flush_pending);
                        if !self.server_read_eof || end_was_pending {
                            // Future::poll runs outbound before inbound. Schedule
                            // another poll now that reading peer frames is safe.
                            cx.waker().wake_by_ref();
                        }
                        // this counts as server write progress since we can now retry writes
                        server_write_progress = true;
                    }
                    Poll::Ready(Err(e)) => {
                        debug!("UDP inbound peer flush ended: {e}");
                        self.set_server_write_eof();
                    }
                    Poll::Pending => {}
                }
            }

            if !server_write_progress && !remote_read_progress {
                break;
            }

            // Cooperative yielding to prevent task starvation
            match tokio::task::coop::poll_proceed(cx) {
                Poll::Ready(coop) => coop.made_progress(),
                Poll::Pending => break,
            }
        }
    }
}

/// Run per-destination routing for any server UDP stream type.
pub async fn run_udp_routing(
    mut server: ServerStream,
    selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    need_initial_flush: bool,
) -> io::Result<()> {
    let result = UdpRouter::new(&mut server, selector, resolver, need_initial_flush).await;
    let _ = server.shutdown_message().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::NetLocationMask;
    use crate::client_proxy_selector::{ConnectAction, ConnectRule};
    use crate::tcp::chain_builder::build_direct_chain_group;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct CountingWaker(AtomicUsize);

    impl futures::task::ArcWake for CountingWaker {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct EndServer {
        event: Option<SessionMessage>,
    }

    impl AsyncReadSessionMessage for EndServer {
        fn poll_read_session_message(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<SessionMessage>> {
            match self.event.take() {
                Some(event) => Poll::Ready(Ok(event)),
                None => Poll::Pending,
            }
        }
    }

    impl AsyncWriteSessionMessage for EndServer {
        fn poll_write_session_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _session_id: u16,
            _buf: &[u8],
            _target: &SessionMessageTarget,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_write_session_end(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _session_id: u16,
            _has_error: bool,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncFlushMessage for EndServer {
        fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncShutdownMessage for EndServer {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for EndServer {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncSessionMessageStream for EndServer {}

    type ServerWrite = (u16, Vec<u8>, NetLocation, SocketAddr);
    type ServerEnd = (u16, bool);

    struct PacketServer {
        events: VecDeque<(SessionMessage, Vec<u8>)>,
        writes: Arc<Mutex<Vec<ServerWrite>>>,
        ends: Arc<Mutex<Vec<ServerEnd>>>,
    }

    impl AsyncReadSessionMessage for PacketServer {
        fn poll_read_session_message(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<SessionMessage>> {
            let Some((event, data)) = self.events.pop_front() else {
                return Poll::Pending;
            };
            if data.len() > buf.remaining() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "test packet buffer too small",
                )));
            }
            buf.put_slice(&data);
            Poll::Ready(Ok(event))
        }
    }

    impl AsyncWriteSessionMessage for PacketServer {
        fn poll_write_session_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            session_id: u16,
            buf: &[u8],
            target: &SessionMessageTarget,
        ) -> Poll<io::Result<()>> {
            self.writes.lock().unwrap().push((
                session_id,
                buf.to_vec(),
                target.destination().location().clone(),
                target.response_address(),
            ));
            Poll::Ready(Ok(()))
        }

        fn poll_write_session_end(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            session_id: u16,
            has_error: bool,
        ) -> Poll<io::Result<()>> {
            self.ends.lock().unwrap().push((session_id, has_error));
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncFlushMessage for PacketServer {
        fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncShutdownMessage for PacketServer {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for PacketServer {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncSessionMessageStream for PacketServer {}

    struct FlushGatedServer {
        events: VecDeque<(SessionMessage, Vec<u8>)>,
        event_reads: Arc<AtomicUsize>,
        ends: Arc<Mutex<Vec<ServerEnd>>>,
        allow_flush: Arc<AtomicBool>,
    }

    impl AsyncReadSessionMessage for FlushGatedServer {
        fn poll_read_session_message(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<SessionMessage>> {
            let Some((event, data)) = self.events.pop_front() else {
                return Poll::Pending;
            };
            self.event_reads.fetch_add(1, Ordering::SeqCst);
            buf.put_slice(&data);
            Poll::Ready(Ok(event))
        }
    }

    impl AsyncWriteSessionMessage for FlushGatedServer {
        fn poll_write_session_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _session_id: u16,
            _buf: &[u8],
            _target: &SessionMessageTarget,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_write_session_end(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            session_id: u16,
            has_error: bool,
        ) -> Poll<io::Result<()>> {
            self.ends.lock().unwrap().push((session_id, has_error));
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncFlushMessage for FlushGatedServer {
        fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.allow_flush.load(Ordering::SeqCst) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }

    impl AsyncShutdownMessage for FlushGatedServer {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for FlushGatedServer {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncSessionMessageStream for FlushGatedServer {}

    #[derive(Debug, Default)]
    struct IdleRemote;

    impl AsyncReadMessage for IdleRemote {
        fn poll_read_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWriteMessage for IdleRemote {
        fn poll_write_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncFlushMessage for IdleRemote {
        fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncShutdownMessage for IdleRemote {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for IdleRemote {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncMessageStream for IdleRemote {}

    #[derive(Debug, Default)]
    struct NeverShutdownRemote;

    impl AsyncReadMessage for NeverShutdownRemote {
        fn poll_read_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWriteMessage for NeverShutdownRemote {
        fn poll_write_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncFlushMessage for NeverShutdownRemote {
        fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncShutdownMessage for NeverShutdownRemote {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncPing for NeverShutdownRemote {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncMessageStream for NeverShutdownRemote {}

    fn direct_udp_selector(resolver: Arc<dyn Resolver>) -> Arc<ClientProxySelector> {
        let chain_group = build_direct_chain_group(resolver);
        Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
            vec![NetLocationMask::ANY],
            ConnectAction::new_allow(None, chain_group),
        )]))
    }

    fn literal_destination(address: SocketAddr) -> NetLocation {
        NetLocation::new(
            match address.ip() {
                std::net::IpAddr::V4(ip) => crate::address::Address::Ipv4(ip),
                std::net::IpAddr::V6(ip) => crate::address::Address::Ipv6(ip),
            },
            address.port(),
        )
    }

    fn exhaust_remote_write_pool(
        router: &mut UdpRouter<'_>,
        protocol_session_id: u16,
    ) -> NetLocation {
        let mut first_destination = None;
        for id in 0..REMOTE_WRITE_POOL_SIZE {
            let address: SocketAddr = format!("127.0.0.1:{}", 20_000 + id).parse().unwrap();
            let destination = literal_destination(address);
            first_destination.get_or_insert_with(|| destination.clone());
            let protocol_key = ProtocolSessionKey {
                session_id: protocol_session_id,
                destination: destination.clone(),
            };
            let mut session = RoutingSession::new(
                destination,
                protocol_session_id,
                address,
                LookupKey::ProtocolSession(protocol_key.clone()),
                Box::new(IdleRemote),
            );
            session.in_remote_write_queue = 1;
            router.sessions.insert(id, session);
            let SessionLookup::ByProtocolSession(lookup) = &mut router.session_lookup else {
                unreachable!();
            };
            lookup.insert(protocol_key, KeyState::Active(id));

            let mut buf = router.remote_write_pool.acquire().unwrap();
            buf[0] = id as u8;
            router
                .remote_write_queue
                .push_back(PendingWrite { id, buf, len: 1 });
        }
        router.next_session_id = REMOTE_WRITE_POOL_SIZE;
        assert!(router.remote_write_pool.acquire().is_none());
        first_destination.unwrap()
    }

    #[derive(Debug)]
    struct OrderedResolver(Vec<SocketAddr>);

    impl Resolver for OrderedResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
            let addresses = self.0.clone();
            Box::pin(async move { Ok(addresses) })
        }
    }

    #[derive(Debug)]
    struct PendingHostnameResolver;

    impl Resolver for PendingHostnameResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
            Box::pin(std::future::pending())
        }
    }

    #[derive(Debug)]
    struct FailingHostnameResolver;

    impl Resolver for FailingHostnameResolver {
        fn resolve_location(
            &self,
            location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
            let location = location.clone();
            Box::pin(async move {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("NXDOMAIN for {location}"),
                ))
            })
        }
    }

    #[tokio::test]
    async fn protocol_end_is_read_when_all_remote_write_buffers_are_pending() {
        let session_id = 61;
        let mut server = ServerStream::Session(Box::new(EndServer {
            event: Some(SessionMessage::End { session_id }),
        }));
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(ClientProxySelector::new(Vec::new()));
        let mut router = UdpRouter::new(&mut server, selector, resolver, false);
        exhaust_remote_write_pool(&mut router, session_id);

        let waker = futures::task::noop_waker_ref();
        let mut context = Context::from_waker(waker);
        let (read_progress, write_progress) = router.poll_read_server(&mut context);

        assert!(read_progress);
        assert!(!write_progress);
        assert!(router.sessions.is_empty());
        let SessionLookup::ByProtocolSession(lookup) = &router.session_lookup else {
            unreachable!();
        };
        assert!(lookup.is_empty());
    }

    #[tokio::test]
    async fn unknown_keep_is_rejected_when_all_remote_write_buffers_are_pending() {
        let blocked_session_id = 62;
        let unknown_session_id = 63;
        let ends = Arc::new(Mutex::new(Vec::new()));
        let mut server = ServerStream::Session(Box::new(PacketServer {
            events: VecDeque::from([(
                SessionMessage::UnknownKeep {
                    session_id: unknown_session_id,
                },
                Vec::new(),
            )]),
            writes: Arc::new(Mutex::new(Vec::new())),
            ends: Arc::clone(&ends),
        }));
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(ClientProxySelector::new(Vec::new()));
        let mut router = UdpRouter::new(&mut server, selector, resolver, false);
        exhaust_remote_write_pool(&mut router, blocked_session_id);

        let waker = futures::task::noop_waker_ref();
        let mut context = Context::from_waker(waker);
        let (read_progress, write_progress) = router.poll_read_server(&mut context);
        assert!(read_progress);
        assert!(!write_progress);
        assert_eq!(router.pending_session_ends.len(), 1);

        router.poll_inbound(&mut context, false);
        assert_eq!(
            ends.lock().unwrap().as_slice(),
            &[(unknown_session_id, true)]
        );
        assert!(router.pending_session_ends.is_empty());
    }

    #[tokio::test]
    async fn data_before_end_is_dropped_so_control_advances_when_pool_is_full() {
        let session_id = 64;
        let address: SocketAddr = "127.0.0.1:20000".parse().unwrap();
        let destination = literal_destination(address);
        let data = SessionMessage::Data {
            session_id,
            status: SessionMessageStatus::Keep,
            target: SessionMessageTarget::new(
                ResolvedLocation::with_resolved(destination.clone(), address),
                address,
            ),
        };
        let mut server = ServerStream::Session(Box::new(PacketServer {
            events: VecDeque::from([
                (data, b"drop-under-overload".to_vec()),
                (SessionMessage::End { session_id }, Vec::new()),
            ]),
            writes: Arc::new(Mutex::new(Vec::new())),
            ends: Arc::new(Mutex::new(Vec::new())),
        }));
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(ClientProxySelector::new(Vec::new()));
        let mut router = UdpRouter::new(&mut server, selector, resolver, false);
        assert_eq!(
            exhaust_remote_write_pool(&mut router, session_id),
            destination
        );

        let waker = futures::task::noop_waker_ref();
        let mut context = Context::from_waker(waker);
        let (read_progress, _) = router.poll_read_server(&mut context);
        assert!(read_progress);
        assert!(router.sessions.is_empty());
        let SessionLookup::ByProtocolSession(lookup) = &router.session_lookup else {
            unreachable!();
        };
        assert!(lookup.is_empty());
    }

    #[tokio::test]
    async fn slow_hostname_subflow_does_not_block_following_literal_session() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_address = peer.local_addr().unwrap();
        let slow_target = NetLocation::new(
            crate::address::Address::Hostname("slow.invalid".to_string()),
            53,
        );
        let literal_target = literal_destination(peer_address);
        let mut server = ServerStream::Session(Box::new(PacketServer {
            events: VecDeque::from([
                (
                    SessionMessage::Data {
                        session_id: 80,
                        status: SessionMessageStatus::New,
                        target: SessionMessageTarget::unresolved(slow_target),
                    },
                    b"slow".to_vec(),
                ),
                (
                    SessionMessage::Data {
                        session_id: 81,
                        status: SessionMessageStatus::New,
                        target: SessionMessageTarget::unresolved(literal_target),
                    },
                    b"literal".to_vec(),
                ),
            ]),
            writes: Arc::new(Mutex::new(Vec::new())),
            ends: Arc::new(Mutex::new(Vec::new())),
        }));
        let resolver: Arc<dyn Resolver> = Arc::new(PendingHostnameResolver);
        let selector = direct_udp_selector(Arc::clone(&resolver));
        let mut router = UdpRouter::new(&mut server, selector, resolver, false);
        let mut received = [0_u8; 32];
        let (length, _) = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                futures::future::poll_fn(|cx| {
                    router.poll_outbound(cx, false);
                    router.poll_inbound(cx, false);
                    Poll::Ready(())
                })
                .await;
                match peer.try_recv_from(&mut received) {
                    Ok(received) => break received,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("literal peer receive failed: {error}"),
                }
            }
        })
        .await
        .expect("literal session must not wait for the hostname resolver");
        assert_eq!(&received[..length], b"literal");
        assert!(
            router
                .pending_creates
                .iter()
                .any(|pending| pending.session_id == 80)
        );
    }

    #[tokio::test]
    async fn nxdomain_rejects_only_that_session_and_literal_session_continues() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_address = peer.local_addr().unwrap();
        let ends = Arc::new(Mutex::new(Vec::new()));
        let mut server = ServerStream::Session(Box::new(PacketServer {
            events: VecDeque::from([
                (
                    SessionMessage::Data {
                        session_id: 82,
                        status: SessionMessageStatus::New,
                        target: SessionMessageTarget::unresolved(NetLocation::new(
                            crate::address::Address::Hostname("nxdomain.invalid".to_string()),
                            53,
                        )),
                    },
                    b"fail".to_vec(),
                ),
                (
                    SessionMessage::Data {
                        session_id: 83,
                        status: SessionMessageStatus::New,
                        target: SessionMessageTarget::unresolved(literal_destination(peer_address)),
                    },
                    b"survives".to_vec(),
                ),
            ]),
            writes: Arc::new(Mutex::new(Vec::new())),
            ends: Arc::clone(&ends),
        }));
        let resolver: Arc<dyn Resolver> = Arc::new(FailingHostnameResolver);
        let selector = direct_udp_selector(Arc::clone(&resolver));
        let mut router = UdpRouter::new(&mut server, selector, resolver, false);
        let mut received = [0_u8; 32];
        let (length, _) = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                futures::future::poll_fn(|cx| {
                    router.poll_outbound(cx, false);
                    router.poll_inbound(cx, false);
                    Poll::Ready(())
                })
                .await;
                match peer.try_recv_from(&mut received) {
                    Ok(received) => break received,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("literal peer receive failed: {error}"),
                }
            }
        })
        .await
        .expect("following literal session must survive NXDOMAIN");
        assert_eq!(ends.lock().unwrap().as_slice(), &[(82, true)]);
        assert_eq!(&received[..length], b"survives");
        assert!(!router.server_read_eof);
    }

    #[tokio::test]
    async fn xudp_one_session_keeps_multiple_destinations_and_labels_delayed_responses() {
        let peer_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address_a = peer_a.local_addr().unwrap();
        let peer_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address_b = peer_b.local_addr().unwrap();
        let session_id = 29;
        let destination_a = literal_destination(address_a);
        let destination_b = literal_destination(address_b);
        let writes = Arc::new(Mutex::new(Vec::new()));
        let event_a = SessionMessage::Data {
            session_id,
            status: SessionMessageStatus::New,
            target: SessionMessageTarget::new(
                ResolvedLocation::with_resolved(destination_a.clone(), address_a),
                address_a,
            ),
        };
        let event_b = SessionMessage::Data {
            session_id,
            status: SessionMessageStatus::Keep,
            target: SessionMessageTarget::new(
                ResolvedLocation::with_resolved(destination_b.clone(), address_b),
                address_b,
            ),
        };
        let mut server = ServerStream::Session(Box::new(PacketServer {
            events: VecDeque::from([(event_a, b"to-a".to_vec()), (event_b, b"to-b".to_vec())]),
            writes: Arc::clone(&writes),
            ends: Arc::new(Mutex::new(Vec::new())),
        }));
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = direct_udp_selector(Arc::clone(&resolver));
        let mut router = UdpRouter::new(&mut server, selector, resolver, false);

        let mut received_a = [0_u8; 64];
        let mut received_b = [0_u8; 64];
        let (router_address_a, router_address_b) =
            tokio::time::timeout(Duration::from_secs(2), async {
                let mut router_address_a = None;
                let mut router_address_b = None;
                loop {
                    futures::future::poll_fn(|cx| {
                        router.poll_outbound(cx, false);
                        Poll::Ready(())
                    })
                    .await;
                    if router_address_a.is_none() {
                        match peer_a.try_recv_from(&mut received_a) {
                            Ok((length, address)) => {
                                assert_eq!(&received_a[..length], b"to-a");
                                router_address_a = Some(address);
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                            Err(error) => panic!("failed to receive destination A: {error}"),
                        }
                    }
                    if router_address_b.is_none() {
                        match peer_b.try_recv_from(&mut received_b) {
                            Ok((length, address)) => {
                                assert_eq!(&received_b[..length], b"to-b");
                                router_address_b = Some(address);
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                            Err(error) => panic!("failed to receive destination B: {error}"),
                        }
                    }
                    if let (Some(address_a), Some(address_b)) = (router_address_a, router_address_b)
                    {
                        break (address_a, address_b);
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("both XUDP destination subflows must receive their datagrams");

        assert_eq!(router.sessions.len(), 2);
        assert!(
            router
                .sessions
                .values()
                .any(|session| session.destination == destination_a)
        );
        assert!(
            router
                .sessions
                .values()
                .any(|session| session.destination == destination_b)
        );

        // B responds first, then the older A subflow responds after B exists.
        // Each response must retain its own destination metadata.
        peer_b.send_to(b"from-b", router_address_b).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                futures::future::poll_fn(|cx| {
                    router.poll_inbound(cx, false);
                    Poll::Ready(())
                })
                .await;
                if !writes.lock().unwrap().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("destination B response was not written to XUDP");
        peer_a
            .send_to(b"from-a-delayed", router_address_a)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                futures::future::poll_fn(|cx| {
                    router.poll_inbound(cx, false);
                    Poll::Ready(())
                })
                .await;
                if writes.lock().unwrap().len() >= 2 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("delayed destination A response was not written to XUDP");
        assert_eq!(
            writes.lock().unwrap().as_slice(),
            &[
                (session_id, b"from-b".to_vec(), destination_b, address_b,),
                (
                    session_id,
                    b"from-a-delayed".to_vec(),
                    destination_a,
                    address_a,
                ),
            ]
        );
    }

    #[tokio::test]
    async fn xudp_keep_for_another_target_preserves_the_old_pending_subflow() {
        struct DropFlag(Arc<std::sync::atomic::AtomicBool>);

        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let old_address: SocketAddr = "127.0.0.1:53001".parse().unwrap();
        let old_destination = literal_destination(old_address);
        let new_peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let new_address = new_peer.local_addr().unwrap();
        let new_destination = literal_destination(new_address);
        let session_id = 30;
        let event = SessionMessage::Data {
            session_id,
            status: SessionMessageStatus::Keep,
            target: SessionMessageTarget::new(
                ResolvedLocation::with_resolved(new_destination.clone(), new_address),
                new_address,
            ),
        };
        let mut server = ServerStream::Session(Box::new(PacketServer {
            events: VecDeque::from([(event, b"replacement".to_vec())]),
            writes: Arc::new(Mutex::new(Vec::new())),
            ends: Arc::new(Mutex::new(Vec::new())),
        }));
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = direct_udp_selector(Arc::clone(&resolver));
        let mut router = UdpRouter::new(&mut server, selector, resolver, false);
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let guard = DropFlag(Arc::clone(&dropped));

        let old_key = ProtocolSessionKey {
            session_id,
            destination: old_destination.clone(),
        };
        let SessionLookup::ByProtocolSession(lookup) = &mut router.session_lookup else {
            panic!("session stream must use protocol IDs");
        };
        lookup.insert(old_key.clone(), KeyState::Pending);
        router.pending_creates.push(PendingSessionCreate {
            lookup_key: LookupKey::ProtocolSession(old_key.clone()),
            destination: old_destination.clone(),
            session_id,
            initial_data: b"stale".to_vec(),
            future: Box::pin(async move {
                let _guard = guard;
                std::future::pending::<io::Result<SessionCreateResult>>().await
            }),
        });

        let waker = futures::task::noop_waker_ref();
        let mut context = Context::from_waker(waker);
        router.poll_read_server(&mut context);

        assert!(!dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(router.pending_creates.iter().any(|pending| {
            matches!(&pending.lookup_key, LookupKey::ProtocolSession(key) if key == &old_key)
                && pending.destination == old_destination
        }));
        assert!(
            router.pending_creates.iter().any(|pending| {
                pending.session_id == session_id && pending.destination == new_destination
            }) || router.sessions.values().any(|session| {
                session.session_id == session_id && session.destination == new_destination
            })
        );
        let SessionLookup::ByProtocolSession(lookup) = &router.session_lookup else {
            unreachable!();
        };
        assert!(matches!(lookup.get(&old_key), Some(KeyState::Pending)));
        assert!(lookup.contains_key(&ProtocolSessionKey {
            session_id,
            destination: new_destination,
        }));
    }

    #[tokio::test]
    async fn failed_keep_subflow_does_not_end_an_existing_same_id_flow() {
        let session_id = 32;
        let address_a: SocketAddr = "127.0.0.1:53101".parse().unwrap();
        let address_b: SocketAddr = "127.0.0.1:53102".parse().unwrap();
        let destination_a = literal_destination(address_a);
        let destination_b = literal_destination(address_b);
        let ends = Arc::new(Mutex::new(Vec::new()));
        let mut server = ServerStream::Session(Box::new(PacketServer {
            events: VecDeque::new(),
            writes: Arc::new(Mutex::new(Vec::new())),
            ends: Arc::clone(&ends),
        }));
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(ClientProxySelector::new(Vec::new()));
        let mut router = UdpRouter::new(&mut server, selector, resolver, false);

        let key_a = ProtocolSessionKey {
            session_id,
            destination: destination_a.clone(),
        };
        router.sessions.insert(
            0,
            RoutingSession::new(
                destination_a,
                session_id,
                address_a,
                LookupKey::ProtocolSession(key_a.clone()),
                Box::new(IdleRemote),
            ),
        );
        let key_b = ProtocolSessionKey {
            session_id,
            destination: destination_b.clone(),
        };
        let SessionLookup::ByProtocolSession(lookup) = &mut router.session_lookup else {
            unreachable!();
        };
        lookup.insert(key_a.clone(), KeyState::Active(0));
        lookup.insert(key_b.clone(), KeyState::Pending);
        router.pending_creates.push(PendingSessionCreate {
            lookup_key: LookupKey::ProtocolSession(key_b),
            destination: destination_b,
            session_id,
            initial_data: b"failed-keep".to_vec(),
            future: Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "second destination failed",
                ))
            }),
        });
        let waker = futures::task::noop_waker_ref();
        let mut context = Context::from_waker(waker);

        router.poll_pending_creates(&mut context);

        assert_eq!(router.sessions.len(), 1);
        let SessionLookup::ByProtocolSession(lookup) = &router.session_lookup else {
            unreachable!();
        };
        assert!(matches!(lookup.get(&key_a), Some(KeyState::Active(0))));
        assert!(router.pending_session_ends.is_empty());
        assert!(ends.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn xudp_destination_subflows_are_bounded_per_inbound_stream() {
        let session_id = 31;
        let new_peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let new_address = new_peer.local_addr().unwrap();
        let new_destination = literal_destination(new_address);
        let event = SessionMessage::Data {
            session_id,
            status: SessionMessageStatus::Keep,
            target: SessionMessageTarget::new(
                ResolvedLocation::with_resolved(new_destination.clone(), new_address),
                new_address,
            ),
        };
        let ends = Arc::new(Mutex::new(Vec::new()));
        let mut server = ServerStream::Session(Box::new(PacketServer {
            events: VecDeque::from([(event, b"over-limit".to_vec())]),
            writes: Arc::new(Mutex::new(Vec::new())),
            ends: Arc::clone(&ends),
        }));
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = direct_udp_selector(Arc::clone(&resolver));
        let mut router = UdpRouter::new(&mut server, selector, resolver, false);

        for id in 0..MAX_UDP_FLOWS {
            let address: SocketAddr = format!("127.0.0.1:{}", 10_000 + id).parse().unwrap();
            let destination = literal_destination(address);
            let protocol_key = ProtocolSessionKey {
                session_id,
                destination: destination.clone(),
            };
            router.sessions.insert(
                id,
                RoutingSession::new(
                    destination,
                    session_id,
                    address,
                    LookupKey::ProtocolSession(protocol_key.clone()),
                    Box::new(IdleRemote),
                ),
            );
            let SessionLookup::ByProtocolSession(lookup) = &mut router.session_lookup else {
                unreachable!();
            };
            lookup.insert(protocol_key, KeyState::Active(id));
        }
        router.next_session_id = MAX_UDP_FLOWS;

        let waker = futures::task::noop_waker_ref();
        let mut context = Context::from_waker(waker);
        let (read_progress, _) = router.poll_read_server(&mut context);

        assert!(read_progress);
        assert_eq!(router.sessions.len(), MAX_UDP_FLOWS);
        assert!(router.pending_creates.is_empty());
        let SessionLookup::ByProtocolSession(lookup) = &router.session_lookup else {
            unreachable!();
        };
        assert!(!lookup.contains_key(&ProtocolSessionKey {
            session_id,
            destination: new_destination,
        }));
        assert!(ends.lock().unwrap().is_empty());
        let mut received = [0_u8; 32];
        assert!(matches!(
            new_peer.try_recv_from(&mut received),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
    }

    #[tokio::test]
    async fn codec_unknown_keep_gets_error_end_without_stopping_other_sessions() {
        let codec_unknown_session_id = 39;
        let valid_session_id = 41;
        let valid_peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let valid_address = valid_peer.local_addr().unwrap();
        let valid_target = literal_destination(valid_address);
        let valid_event = SessionMessage::Data {
            session_id: valid_session_id,
            status: SessionMessageStatus::New,
            target: SessionMessageTarget::new(
                ResolvedLocation::with_resolved(valid_target.clone(), valid_address),
                valid_address,
            ),
        };
        let ends = Arc::new(Mutex::new(Vec::new()));
        let mut server = ServerStream::Session(Box::new(PacketServer {
            events: VecDeque::from([
                (
                    SessionMessage::UnknownKeep {
                        session_id: codec_unknown_session_id,
                    },
                    Vec::new(),
                ),
                (valid_event, b"valid-new".to_vec()),
            ]),
            writes: Arc::new(Mutex::new(Vec::new())),
            ends: Arc::clone(&ends),
        }));
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = direct_udp_selector(Arc::clone(&resolver));
        let mut router = UdpRouter::new(&mut server, selector, resolver, false);

        let mut received = [0_u8; 64];
        let (received_len, _) = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                futures::future::poll_fn(|cx| {
                    router.poll_outbound(cx, false);
                    router.poll_inbound(cx, false);
                    Poll::Ready(())
                })
                .await;
                match valid_peer.try_recv_from(&mut received) {
                    Ok(result) => break result,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("failed to receive valid New datagram: {error}"),
                }
            }
        })
        .await
        .expect("an unknown Keep must not stop a following valid session");
        assert_eq!(&received[..received_len], b"valid-new");

        futures::future::poll_fn(|cx| {
            router.poll_inbound(cx, false);
            Poll::Ready(())
        })
        .await;

        assert_eq!(
            ends.lock().unwrap().as_slice(),
            &[(codec_unknown_session_id, true)]
        );
        assert!(!router.server_read_eof);
        assert!(router.pending_creates.iter().all(|pending| {
            !matches!(
                &pending.lookup_key,
                LookupKey::ProtocolSession(key)
                    if key.session_id == codec_unknown_session_id
            )
        }));
        assert!(
            router
                .sessions
                .values()
                .all(|session| session.session_id != codec_unknown_session_id)
        );
        let SessionLookup::ByProtocolSession(lookup) = &router.session_lookup else {
            unreachable!();
        };
        assert!(
            lookup
                .keys()
                .all(|key| key.session_id != codec_unknown_session_id)
        );
        assert!(lookup.keys().any(|key| key.session_id == valid_session_id));
    }

    #[tokio::test]
    async fn same_id_new_is_not_read_until_unknown_keep_end_is_flushed() {
        let session_id = 42;
        let destination_address: SocketAddr = "127.0.0.1:53003".parse().unwrap();
        let destination = literal_destination(destination_address);
        let event_reads = Arc::new(AtomicUsize::new(0));
        let ends = Arc::new(Mutex::new(Vec::new()));
        let allow_flush = Arc::new(AtomicBool::new(false));
        let mut server = ServerStream::Session(Box::new(FlushGatedServer {
            events: VecDeque::from([
                (SessionMessage::UnknownKeep { session_id }, Vec::new()),
                (
                    SessionMessage::Data {
                        session_id,
                        status: SessionMessageStatus::New,
                        target: SessionMessageTarget::new(
                            ResolvedLocation::with_resolved(destination, destination_address),
                            destination_address,
                        ),
                    },
                    b"new-after-end".to_vec(),
                ),
            ]),
            event_reads: Arc::clone(&event_reads),
            ends: Arc::clone(&ends),
            allow_flush: Arc::clone(&allow_flush),
        }));
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(ClientProxySelector::new(Vec::new()));
        let mut router = UdpRouter::new(&mut server, selector, resolver, false);
        let waker = futures::task::noop_waker_ref();
        let mut context = Context::from_waker(waker);

        router.poll_outbound(&mut context, false);
        assert_eq!(event_reads.load(Ordering::SeqCst), 1);
        assert_eq!(router.pending_session_ends.len(), 1);

        router.poll_inbound(&mut context, false);
        assert_eq!(ends.lock().unwrap().as_slice(), &[(session_id, true)]);
        assert!(router.pending_session_ends.is_empty());
        assert!(router.session_end_flush_pending);

        router.poll_outbound(&mut context, false);
        assert_eq!(
            event_reads.load(Ordering::SeqCst),
            1,
            "same-ID New must remain unread while the rejecting End is unflushed"
        );

        allow_flush.store(true, Ordering::SeqCst);
        router.poll_inbound(&mut context, false);
        assert!(!router.session_end_flush_pending);
        router.poll_outbound(&mut context, false);
        assert_eq!(event_reads.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn peer_end_and_same_id_new_wait_for_an_older_response_flush() {
        let session_id = 43;
        let event_reads = Arc::new(AtomicUsize::new(0));
        let allow_flush = Arc::new(AtomicBool::new(false));
        let destination_address: SocketAddr = "127.0.0.1:53004".parse().unwrap();
        let mut server = ServerStream::Session(Box::new(FlushGatedServer {
            events: VecDeque::from([
                (SessionMessage::End { session_id }, Vec::new()),
                (
                    SessionMessage::Data {
                        session_id,
                        status: SessionMessageStatus::New,
                        target: SessionMessageTarget::unresolved(literal_destination(
                            destination_address,
                        )),
                    },
                    b"new-generation".to_vec(),
                ),
            ]),
            event_reads: Arc::clone(&event_reads),
            ends: Arc::new(Mutex::new(Vec::new())),
            allow_flush: Arc::clone(&allow_flush),
        }));
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(ClientProxySelector::new(Vec::new()));
        let mut router = UdpRouter::new(&mut server, selector, resolver, false);
        router.needs_server_flush = true;
        let waker = futures::task::noop_waker_ref();
        let mut context = Context::from_waker(waker);

        router.poll_outbound(&mut context, false);
        assert_eq!(event_reads.load(Ordering::SeqCst), 0);
        router.poll_inbound(&mut context, false);
        assert_eq!(event_reads.load(Ordering::SeqCst), 0);

        allow_flush.store(true, Ordering::SeqCst);
        router.poll_inbound(&mut context, false);
        assert!(!router.needs_server_flush);
        router.poll_outbound(&mut context, false);
        assert_eq!(event_reads.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn rejected_duplicate_new_sends_error_end_then_reads_other_session() {
        let rejected_id = 44;
        let valid_id = 45;
        let event_reads = Arc::new(AtomicUsize::new(0));
        let ends = Arc::new(Mutex::new(Vec::new()));
        let allow_flush = Arc::new(AtomicBool::new(false));
        let destination_address: SocketAddr = "127.0.0.1:53005".parse().unwrap();
        let mut server = ServerStream::Session(Box::new(FlushGatedServer {
            events: VecDeque::from([
                (
                    SessionMessage::Rejected {
                        session_id: rejected_id,
                    },
                    Vec::new(),
                ),
                (
                    SessionMessage::Data {
                        session_id: valid_id,
                        status: SessionMessageStatus::New,
                        target: SessionMessageTarget::unresolved(literal_destination(
                            destination_address,
                        )),
                    },
                    b"valid".to_vec(),
                ),
            ]),
            event_reads: Arc::clone(&event_reads),
            ends: Arc::clone(&ends),
            allow_flush: Arc::clone(&allow_flush),
        }));
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(ClientProxySelector::new(Vec::new()));
        let mut router = UdpRouter::new(&mut server, selector, resolver, false);
        let waker = futures::task::noop_waker_ref();
        let mut context = Context::from_waker(waker);

        router.poll_outbound(&mut context, false);
        assert_eq!(event_reads.load(Ordering::SeqCst), 1);
        router.poll_inbound(&mut context, false);
        assert_eq!(ends.lock().unwrap().as_slice(), &[(rejected_id, true)]);
        assert_eq!(event_reads.load(Ordering::SeqCst), 1);

        allow_flush.store(true, Ordering::SeqCst);
        router.poll_inbound(&mut context, false);
        router.poll_outbound(&mut context, false);
        assert_eq!(event_reads.load(Ordering::SeqCst), 2);
        assert!(!router.server_read_eof);
    }

    #[tokio::test]
    async fn protocol_end_removes_all_active_destination_subflows_immediately() {
        let session_id = 27;
        let mut server = ServerStream::Session(Box::new(EndServer {
            event: Some(SessionMessage::End { session_id }),
        }));
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(ClientProxySelector::new(Vec::new()));
        let mut router = UdpRouter::new(&mut server, selector, resolver, false);

        let mut peers = Vec::new();
        for internal_id in 0..2 {
            let remote_peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let remote_address = remote_peer.local_addr().unwrap();
            let remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            remote.connect(remote_address).await.unwrap();
            let destination = literal_destination(remote_address);
            let protocol_key = ProtocolSessionKey {
                session_id,
                destination: destination.clone(),
            };
            router.sessions.insert(
                internal_id,
                RoutingSession::new(
                    destination,
                    session_id,
                    remote_address,
                    LookupKey::ProtocolSession(protocol_key.clone()),
                    Box::new(remote),
                ),
            );
            let SessionLookup::ByProtocolSession(lookup) = &mut router.session_lookup else {
                panic!("session stream must use protocol IDs");
            };
            lookup.insert(protocol_key, KeyState::Active(internal_id));
            peers.push(remote_peer);
        }

        let waker = futures::task::noop_waker_ref();
        let mut context = Context::from_waker(waker);
        let (read_progress, _) = router.poll_read_server(&mut context);

        assert!(read_progress);
        assert!(router.sessions.is_empty());
        let SessionLookup::ByProtocolSession(lookup) = &router.session_lookup else {
            unreachable!();
        };
        assert!(lookup.keys().all(|key| key.session_id != session_id));
        assert_eq!(
            router.pending_shutdowns.len(),
            2,
            "all ended destination sockets must be retired, not reused"
        );
        drop(peers);
    }

    #[tokio::test]
    async fn protocol_end_cancels_all_pending_destination_subflows() {
        let session_id = 28;
        let mut server = ServerStream::Session(Box::new(EndServer {
            event: Some(SessionMessage::End { session_id }),
        }));
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(ClientProxySelector::new(Vec::new()));
        let mut router = UdpRouter::new(&mut server, selector, resolver, false);
        for port in [53, 54] {
            let destination = NetLocation::new(
                crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                port,
            );
            let protocol_key = ProtocolSessionKey {
                session_id,
                destination: destination.clone(),
            };
            let SessionLookup::ByProtocolSession(lookup) = &mut router.session_lookup else {
                panic!("session stream must use protocol IDs");
            };
            lookup.insert(protocol_key.clone(), KeyState::Pending);
            router.pending_creates.push(PendingSessionCreate {
                lookup_key: LookupKey::ProtocolSession(protocol_key),
                destination,
                session_id,
                initial_data: b"stale".to_vec(),
                future: Box::pin(std::future::pending()),
            });
        }

        let waker = futures::task::noop_waker_ref();
        let mut context = Context::from_waker(waker);
        router.poll_read_server(&mut context);

        assert!(router.pending_creates.is_empty());
        let SessionLookup::ByProtocolSession(lookup) = &router.session_lookup else {
            unreachable!();
        };
        assert!(
            lookup.keys().all(|key| key.session_id != session_id),
            "a following New must see the protocol ID as vacant"
        );
    }

    #[tokio::test]
    async fn retiring_streams_keep_churn_within_the_flow_hard_limit() {
        let session_id = 90;
        let new_address: SocketAddr = "127.0.0.1:54000".parse().unwrap();
        let ends = Arc::new(Mutex::new(Vec::new()));
        let mut server = ServerStream::Session(Box::new(PacketServer {
            events: VecDeque::from([(
                SessionMessage::Data {
                    session_id: 91,
                    status: SessionMessageStatus::New,
                    target: SessionMessageTarget::unresolved(literal_destination(new_address)),
                },
                b"must-drop-at-cap".to_vec(),
            )]),
            writes: Arc::new(Mutex::new(Vec::new())),
            ends: Arc::clone(&ends),
        }));
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(ClientProxySelector::new(Vec::new()));
        let mut router = UdpRouter::new(&mut server, selector, resolver, false);

        for id in 0..MAX_UDP_FLOWS {
            let address: SocketAddr = format!("127.0.0.1:{}", 10_000 + id).parse().unwrap();
            let destination = literal_destination(address);
            let key = ProtocolSessionKey {
                session_id,
                destination: destination.clone(),
            };
            router.sessions.insert(
                id,
                RoutingSession::new(
                    destination,
                    session_id,
                    address,
                    LookupKey::ProtocolSession(key.clone()),
                    Box::new(NeverShutdownRemote),
                ),
            );
            let SessionLookup::ByProtocolSession(lookup) = &mut router.session_lookup else {
                unreachable!();
            };
            lookup.insert(key, KeyState::Active(id));
        }

        router.end_protocol_session(session_id);
        assert_eq!(router.pending_shutdowns.len(), MAX_UDP_FLOWS);
        router.end_protocol_session(session_id);
        assert_eq!(router.pending_shutdowns.len(), MAX_UDP_FLOWS);

        let waker = futures::task::noop_waker_ref();
        let mut context = Context::from_waker(waker);
        router.poll_read_server(&mut context);
        assert!(router.pending_creates.is_empty());
        assert!(router.sessions.is_empty());
        assert_eq!(router.pending_shutdowns.len(), MAX_UDP_FLOWS);
        assert_eq!(router.pending_session_ends.len(), 1);
        router.poll_inbound(&mut context, false);
        assert_eq!(ends.lock().unwrap().as_slice(), &[(91, true)]);
    }

    #[tokio::test(start_paused = true)]
    async fn retirement_deadline_wakes_and_releases_capacity_without_ping_tick() {
        let mut server = ServerStream::Session(Box::new(EndServer { event: None }));
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(ClientProxySelector::new(Vec::new()));
        let mut router = UdpRouter::new(&mut server, selector, resolver, false);

        for id in 0..MAX_UDP_FLOWS {
            let address: SocketAddr = format!("127.0.0.1:{}", 20_000 + id).parse().unwrap();
            let destination = literal_destination(address);
            let key = ProtocolSessionKey {
                session_id: id as u16,
                destination: destination.clone(),
            };
            router.sessions.insert(
                id,
                RoutingSession::new(
                    destination,
                    id as u16,
                    address,
                    LookupKey::ProtocolSession(key.clone()),
                    Box::new(NeverShutdownRemote),
                ),
            );
            let SessionLookup::ByProtocolSession(lookup) = &mut router.session_lookup else {
                unreachable!();
            };
            lookup.insert(key, KeyState::Active(id));
        }

        router.remove_session(0);
        assert_eq!(router.sessions.len(), MAX_UDP_FLOWS - 1);
        assert_eq!(router.pending_shutdowns.len(), 1);
        assert_eq!(
            router.sessions.len() + router.pending_creates.len() + router.pending_shutdowns.len(),
            MAX_UDP_FLOWS
        );

        let wake_counter = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let deadline_waker = futures::task::waker(Arc::clone(&wake_counter));
        let mut context = Context::from_waker(&deadline_waker);
        router.drain_remote_shutdowns(&mut context);
        let wakes_before_deadline = wake_counter.0.load(Ordering::SeqCst);

        // The router Future and its 15-second ping interval are deliberately
        // not polled. The retirement Sleep must wake this task by itself.
        tokio::time::advance(REMOTE_SHUTDOWN_GRACE).await;
        tokio::task::yield_now().await;
        assert!(wake_counter.0.load(Ordering::SeqCst) > wakes_before_deadline);

        router.drain_remote_shutdowns(&mut context);
        assert!(router.pending_shutdowns.is_empty());
        assert!(
            router.sessions.len() + router.pending_creates.len() + router.pending_shutdowns.len()
                < MAX_UDP_FLOWS,
            "expired retiring streams must release flow capacity without a ping tick"
        );
    }

    #[tokio::test]
    async fn udp_destination_keeps_every_ordered_candidate_for_routing_and_dialing() {
        let addresses = vec![
            "192.0.2.1:53".parse().unwrap(),
            "[2001:db8::1]:53".parse().unwrap(),
            "192.0.2.2:53".parse().unwrap(),
        ];
        let resolver: Arc<dyn Resolver> = Arc::new(OrderedResolver(addresses.clone()));
        let original = NetLocation::new(
            crate::address::Address::Hostname("ordered.example".to_string()),
            53,
        );

        let (destination, response_address) =
            prepare_udp_destination(&resolver, original.clone().into(), None)
                .await
                .unwrap();

        assert_eq!(destination.location(), &original);
        assert_eq!(destination.resolved_addrs(), Some(addresses.as_slice()));
        assert_eq!(response_address, addresses[0]);
    }

    #[tokio::test]
    async fn xudp_response_address_does_not_replace_original_destination_or_candidates() {
        let addresses = vec![
            "192.0.2.10:53".parse().unwrap(),
            "192.0.2.11:53".parse().unwrap(),
        ];
        let response_address = "192.0.2.11:53".parse().unwrap();
        let resolver: Arc<dyn Resolver> = Arc::new(OrderedResolver(Vec::new()));
        let original = NetLocation::new(
            crate::address::Address::Hostname("session.example".to_string()),
            53,
        );
        let mut destination = ResolvedLocation::from(original.clone());
        destination.set_resolved_addrs(addresses.clone());

        let (destination, recorded_response) =
            prepare_udp_destination(&resolver, destination, Some(response_address))
                .await
                .unwrap();

        assert_eq!(destination.location(), &original);
        assert_eq!(destination.resolved_addrs(), Some(addresses.as_slice()));
        assert_eq!(recorded_response, response_address);
    }
}
