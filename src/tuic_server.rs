use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::str;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use futures::future::poll_fn;
use log::{debug, warn};
use lru::LruCache;
use rustc_hash::FxHashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::address::{Address, NetLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::copy_bidirectional::copy_bidirectional_with_sizes;
use crate::dynamic::{
    ConnContext, SelectorSlot, TrafficMeterStream, UserRegistry, scope_connection_until_cancelled,
};
use crate::quic_server::{
    QUIC_PRE_AUTH_TIMEOUT, QUIC_TRANSPORT_HANDSHAKE_TIMEOUT, QuicConnectionLifecycle,
    require_validated_quic_address,
};
use crate::quic_stream::QuicStream;
use crate::resolver::Resolver;
use crate::routing::protocol::sniff_tcp;
use crate::stream_reader::StreamReader;
use crate::tcp::handshake_gate::{
    HandshakeGate, HandshakePermit, MAX_PENDING_HANDSHAKES, MAX_PENDING_PER_SOURCE,
};
use crate::tcp::tcp_server::{
    apply_client_early_data, client_stream_setup_error, client_stream_setup_timeout,
    prepare_client_tcp_stream_with_metadata,
};
use crate::util::{allocate_vec, write_all};

const COMMAND_TYPE_AUTHENTICATE: u8 = 0x00;
const COMMAND_TYPE_CONNECT: u8 = 0x01;
const COMMAND_TYPE_PACKET: u8 = 0x02;
const COMMAND_TYPE_DISSOCIATE: u8 = 0x03;
const COMMAND_TYPE_HEARTBEAT: u8 = 0x04;

// hostname case: type (1) + hostname length (1) + hostname bytes (255) + port (2)
const MAX_ADDRESS_BYTES_LEN: usize = 1 + 1 + 255 + 2;
// version (1) + command (1) + assoc id (2) + packet id (2) + fragment total (1)
// + fragment id (1) + payload size (2) + address
const MAX_HEADER_LEN: usize = 1 + 1 + 2 + 2 + 1 + 1 + 2 + MAX_ADDRESS_BYTES_LEN;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum number of fragmented packets to track per connection.
/// Old entries are automatically evicted when this limit is reached.
const MAX_FRAGMENT_CACHE_SIZE: usize = 256;

/// Incomplete datagrams must not survive long enough to collide with a wrapped
/// packet id from a later generation of the same association.
const UDP_FRAGMENT_TIMEOUT: Duration = Duration::from_secs(10);

/// Authentication timeout - close connection if client doesn't authenticate within this time.
/// Default is 3 seconds per sing-box reference implementation.
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum number of authenticated TCP logical flows one physical TUIC
/// connection may process concurrently. Quinn advertises the same ceiling, and
/// the application semaphore keeps DNS/connect/copy work inside it even after a
/// peer has finished its sending half of a stream.
const MAX_ACTIVE_TCP_LOGICAL_FLOWS: usize = 256;

/// Absolute time allowed to deliver one TUIC CONNECT header after its QUIC stream
/// is accepted. Incremental reads never renew it.
const TCP_REQUEST_HEADER_TIMEOUT: Duration = Duration::from_secs(15);

/// Application error code used when refusing an over-limit peer-opened TCP stream.
const TCP_FLOW_LIMIT_ERROR_CODE: u32 = 0x01;

/// Maximum number of concurrent UDP sessions one connection may hold open.
///
/// A session owns a client-side UDP socket, a spawned task, and that task's 64 KiB
/// receive buffer. TUIC's association id is a `u16`, so the map is inherently capped
/// at 65536 -- which is not a limit worth relying on: it is around 4 GiB of buffers
/// and 65536 descriptors for a *single* authenticated connection, enough to take a
/// shared inbound down for everybody on it.
///
/// The same 512 as hysteria2's, for the same reason: far above what a real client
/// reaches, and roughly 32 MiB and 512 descriptors per connection at the ceiling.
const MAX_UDP_SESSIONS: usize = 512;

/// Bound queued client packets per association while its proxy transport applies
/// backpressure. This replaces the implicit backpressure of the old `send_to`.
const UDP_SESSION_QUEUE_CAPACITY: usize = 64;

/// A slow fixed destination must apply backpressure only to its own packets.
/// The connection-wide byte budget remains the authoritative memory bound.
const UDP_TARGET_QUEUE_CAPACITY: usize = 64;

/// Keep response buffering deliberately tiny. Each target worker may additionally
/// hold one packet while waiting to publish it, so a large shared queue would
/// multiply memory by the number of associations without improving fairness.
const UDP_TARGET_RESPONSE_QUEUE_CAPACITY: usize = 1;

/// One TUIC association is full-cone and may carry several destinations, but its
/// fixed-target transports must remain bounded against authenticated fan-out DoS.
const MAX_UDP_TARGETS_PER_SESSION: usize = 64;

/// Bound fixed-target outbound transports across all associations on one QUIC
/// connection. Per-association caps alone still permit 512 * 64 sockets.
const MAX_UDP_TARGETS_PER_CONNECTION: usize = 1024;

/// Maximum payload represented by the protocol's u16 payload length.
const MAX_UDP_PACKET_SIZE: usize = u16::MAX as usize;

/// Bound queued plus currently-written UDP payload bytes across all associations
/// on one authenticated connection.
const MAX_UDP_QUEUED_BYTES_PER_CONNECTION: usize = 16 * 1024 * 1024;

/// Bound authenticated client-opened uni command tasks. Quinn may advertise 4096
/// streams, but allowing every stream to allocate a maximum UDP payload at once is
/// an avoidable per-connection memory spike.
const MAX_IN_FLIGHT_UNI_COMMANDS: usize = 256;

/// Heartbeat interval - server sends heartbeat datagrams to client at this interval.
/// Default is 10 seconds per sing-box reference implementation.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

type UdpFragmentMap = Arc<Mutex<LruCache<(u16, u64, u16), FragmentedPacket>>>;
type UdpSessionMap = Arc<UdpSessionRegistry>;

/// The accounting record for one authenticated QUIC connection, or `None` when the
/// inbound is not metered.
///
/// Same shape and same reason as hysteria2's: TUIC authenticates once, up front,
/// before any stream or datagram exists, and then fans the connection out into four
/// loops that each run in a task of their own. So one context is bound to its user
/// immediately and travels as an explicit parameter. Every logical TCP task
/// installs it with
/// [`scope_connection_until_cancelled`](crate::dynamic::scope_connection_until_cancelled),
/// so hard inbound removal also interrupts DNS and outbound setup.
type Meter = Option<Arc<ConnContext>>;

fn try_admit_tcp_logical_flow(gate: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    gate.clone().try_acquire_owned().ok()
}

async fn read_tcp_request_header_before_deadline<T, F>(
    deadline: Instant,
    future: F,
) -> std::io::Result<T>
where
    F: Future<Output = std::io::Result<T>>,
{
    match timeout_at(deadline, future).await {
        Ok(result) => result,
        Err(_elapsed) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "TUIC TCP request header timed out",
        )),
    }
}

/// The listener resources assigned to one validated but not yet authenticated TUIC
/// peer. Keeping the permit and its absolute deadline together makes it impossible
/// for a call site to admit a connection without also bounding its anonymous phase.
struct TuicPreAuthAdmission {
    permit: HandshakePermit,
    deadline: Instant,
}

/// One client-facing QUIC stream, metered if the inbound is.
///
/// TUIC uses three stream shapes and needs a different half of each: a bidirectional
/// stream carries a proxied TCP connection, a client-opened uni stream carries
/// inbound UDP packets, and a server-opened uni stream carries outbound ones. Boxing
/// gives the metered and unmetered cases one type, so the loops below stay concrete.
///
/// Wrapping the stream is what meters the UDP-over-uni-stream mode; the datagram
/// mode has no stream to wrap and is counted explicitly through
/// [`ConnContext::admit_datagram_tx`] and its receiving counterpart.
type ClientStream = Box<dyn AsyncStream>;
type ClientRecvStream = Box<dyn AsyncRead + Unpin + Send>;
type ClientSendStream = Box<dyn AsyncWrite + Unpin + Send>;

fn meter_stream(send: quinn::SendStream, recv: quinn::RecvStream, meter: &Meter) -> ClientStream {
    match meter {
        Some(meter) => Box::new(TrafficMeterStream::new(
            QuicStream::from(send, recv),
            meter.clone(),
        )),
        None => Box::new(QuicStream::from(send, recv)),
    }
}

fn meter_recv(recv: quinn::RecvStream, meter: &Meter) -> ClientRecvStream {
    match meter {
        Some(meter) => Box::new(TrafficMeterStream::new(recv, meter.clone())),
        None => Box::new(recv),
    }
}

fn meter_send(send: quinn::SendStream, meter: &Meter) -> ClientSendStream {
    match meter {
        Some(meter) => Box::new(TrafficMeterStream::new(send, meter.clone())),
        None => Box::new(send),
    }
}

async fn process_connection(
    selector: Arc<SelectorSlot>,
    users: Arc<dyn UserRegistry>,
    metered: bool,
    conn: quinn::Incoming,
    zero_rtt_handshake: bool,
    pre_auth: TuicPreAuthAdmission,
    connection_cancel: CancellationToken,
) -> std::io::Result<()> {
    let TuicPreAuthAdmission {
        permit: handshake_permit,
        deadline: pre_auth_deadline,
    } = pre_auth;
    // A transport-local child inherits the inbound hard stop and is cancelled by
    // its guard on natural QUIC exit. Logical tasks therefore cannot outlive either
    // their listener or their physical connection while DNS/outbound work is pending.
    let connection_lifecycle = QuicConnectionLifecycle::new(&connection_cancel);
    // Authentication binds this context only when accounting is enabled; unmetered
    // peers still install it on every logical TCP flow for lifecycle cancellation.
    let lifecycle = ConnContext::new_child(connection_lifecycle.token());
    // Accept the incoming connection. When 0-RTT is enabled, use into_0rtt() to
    // allow 0.5-RTT data transmission before the handshake fully completes.
    // This reduces latency at the cost of some security (0-RTT data is vulnerable
    // to replay attacks, though for incoming server connections it's 0.5-RTT which
    // is safer but still shouldn't be used for client-authenticated data).
    let transport_deadline = std::cmp::min(
        pre_auth_deadline,
        Instant::now() + QUIC_TRANSPORT_HANDSHAKE_TIMEOUT,
    );
    let transport_result = tokio::select! {
        biased;
        () = lifecycle.cancelled() => {
            return Err(connection_lifecycle_cancelled_error());
        }
        result = timeout_at(transport_deadline, async move {
            if zero_rtt_handshake {
                let connecting = conn
                    .accept()
                    .map_err(|e| std::io::Error::other(format!("QUIC accept failed: {e}")))?;
                // For incoming connections, into_0rtt() always succeeds per quinn docs
                let (connection, _zero_rtt_accepted) = connecting
                    .into_0rtt()
                    .map_err(|_| std::io::Error::other("failed to enable 0-RTT"))?;
                Ok::<_, std::io::Error>(connection)
            } else {
                Ok(conn.await?)
            }
        }) => result,
    };
    let connection = match transport_result {
        Ok(result) => result?,
        Err(_elapsed) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TUIC QUIC handshake exceeded the pre-auth deadline",
            ));
        }
    };

    // Preserve TUIC's three-second application-authentication window after the
    // transport handshake, bounded by the absolute outer deadline that started at
    // gate admission.
    let auth_deadline = std::cmp::min(pre_auth_deadline, Instant::now() + AUTH_TIMEOUT);
    let auth_result = tokio::select! {
        biased;
        () = lifecycle.cancelled() => {
            connection.close(0u32.into(), b"connection cancelled");
            return Err(connection_lifecycle_cancelled_error());
        }
        result = timeout_at(
            auth_deadline,
            auth_connection(&connection, users.as_ref(), metered, &lifecycle),
        ) => result,
    };
    let meter = match auth_result {
        Ok(Ok(meter)) => meter,
        Ok(Err(e)) => {
            connection.close(0u32.into(), b"auth failed");
            return Err(e);
        }
        Err(_elapsed) => {
            connection.close(0u32.into(), b"auth timeout");
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "authentication timeout",
            ));
        }
    };

    // TUIC's AUTHENTICATE command covers the whole multiplexed connection. Once
    // it succeeds, the dynamic user's own connection admission replaces the
    // anonymous listener budget. Authentication failures and dropped futures
    // release this permit through Drop on their way out.
    drop(handshake_permit);

    // The AUTHENTICATE stream itself goes uncounted. It is read before anyone knows
    // whose connection this is, so there is no user to bill it to at the time, and it
    // is 50 bytes once per connection -- the same argument that already applies to the
    // QUIC handshake that carried it.
    // Create a cancellation token for the entire connection lifecycle.
    // When cancelled, all spawned tasks (UDP sessions, cleanup task, heartbeat) will terminate gracefully.
    let cancel_token = connection_lifecycle.token().child_token();
    // `CancellationToken` does not cancel when its last handle is merely dropped.
    // Keep a guard on this stack so a panic (for example while decoding an
    // authenticated datagram) cannot strand child UDP tasks and their user meter.
    let _cancel_on_exit = cancel_token.drop_guard_ref();

    // this allows for:
    // 1. multiple threads can read different sessions concurrently
    // 2. multiple threads can modify different sessions concurrently
    // 3. the outer write lock is only needed for adding/removing sessions
    let udp_session_map = Arc::new(UdpSessionRegistry::new());
    let udp_fragments = Arc::new(Mutex::new(LruCache::new(
        NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE).unwrap(),
    )));

    // Clone what we need for each loop before creating async blocks
    let heartbeat_connection = connection.clone();
    let heartbeat_cancel_token = cancel_token.clone();
    let heartbeat_meter = meter.clone();

    let bi_connection = connection.clone();
    let bi_selector = selector.clone();
    let bi_meter = meter.clone();
    let bi_lifecycle = Arc::clone(&lifecycle);

    let uni_connection = connection.clone();
    let uni_selector = selector.clone();
    let uni_udp_session_map = udp_session_map.clone();
    let uni_udp_fragments = udp_fragments.clone();
    let uni_cancel_token = cancel_token.clone();
    let uni_meter = meter.clone();

    let datagram_connection = connection.clone();
    let datagram_udp_fragments = udp_fragments;
    let datagram_cancel_token = cancel_token.clone();

    // Use try_join! to run all loops concurrently within the same task, like Quinn's perf example.
    // This reduces task count and avoids spawning separate tasks for the main loops.
    let heartbeat_loop = run_heartbeat_loop(
        heartbeat_connection,
        heartbeat_meter,
        heartbeat_cancel_token,
    );

    let bi_loop = run_bidirectional_loop(bi_connection, bi_selector, bi_meter, bi_lifecycle);

    let uni_loop = run_unidirectional_loop(
        uni_connection,
        uni_selector,
        uni_udp_session_map,
        uni_udp_fragments,
        uni_meter,
        uni_cancel_token,
    );

    let datagram_loop = run_datagram_loop(
        datagram_connection,
        selector,
        udp_session_map,
        datagram_udp_fragments,
        meter,
        datagram_cancel_token,
    );

    let result = tokio::select! {
        biased;
        () = lifecycle.cancelled() => {
            cancel_token.cancel();
            connection.close(0u32.into(), b"connection cancelled");
            Err(connection_lifecycle_cancelled_error())
        }
        result = async { tokio::try_join!(heartbeat_loop, bi_loop, uni_loop, datagram_loop) } => result,
    };

    // Cancel all remaining tasks (UDP session loops, cleanup task, heartbeat)
    cancel_token.cancel();

    // Per sing-box reference (service.go:382-398), close connection on error
    if result.is_err() {
        connection.close(0u32.into(), b"");
    }

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

fn connection_lifecycle_cancelled_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionAborted,
        "connection closed because its user or inbound was removed",
    )
}

/// Sends periodic heartbeat datagrams to the client to maintain connection liveness.
/// Per sing-box reference implementation (service.go:366-380).
/// Returns an error if heartbeat fails, which will cause the connection to close.
async fn run_heartbeat_loop(
    connection: quinn::Connection,
    meter: Meter,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
    // Skip the first immediate tick
    interval.tick().await;

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                return Ok(());
            }
            _ = interval.tick() => {
                // Send heartbeat datagram: [version, command_heartbeat]
                let heartbeat = bytes::Bytes::from_static(&[5, COMMAND_TYPE_HEARTBEAT]);
                let heartbeat_len = heartbeat.len();
                let permit = if let Some(meter) = &meter {
                    Some(tokio::select! {
                        biased;
                        _ = cancel_token.cancelled() => return Ok(()),
                        permit = meter.admit_datagram_tx(heartbeat_len) => permit,
                    })
                } else {
                    None
                };
                if cancel_token.is_cancelled() {
                    return Ok(());
                }
                if let Err(e) = connection.send_datagram(heartbeat) {
                    // Per sing-box reference, heartbeat failure should close the connection
                    return Err(std::io::Error::other(format!("heartbeat failed: {e}")));
                }
                // Counted, small as it is, because the client's own heartbeats are
                // counted on the way in -- `run_datagram_loop` bills a datagram before
                // it looks at what kind it is. One rule for both directions is easier
                // to state, and to test, than an exemption for keepalives.
                if let Some(permit) = permit {
                    permit.commit();
                }
            }
        }
    }
}

/// Read the client's `AUTHENTICATE` command and hand back whose connection this is.
///
/// TUIC's credential is two values at once. The uuid arrives in cleartext and only
/// names the user; the 32 bytes beside it are the proof, and they are worth nothing
/// on their own either -- they are keyed with that user's password *and* with this
/// QUIC connection's exported keying material, so the same password produces a
/// different token on every connection. That is why the registry hands back a
/// password instead of a verdict: the expected token can only be derived here, once
/// the uuid has said which password to derive it from.
async fn auth_connection(
    connection: &quinn::Connection,
    users: &dyn UserRegistry,
    metered: bool,
    lifecycle: &Arc<ConnContext>,
) -> std::io::Result<Meter> {
    // Loop until we receive an AUTH command.
    // Other commands (like DISSOCIATE) may arrive on uni streams before AUTH.
    // We discard non-AUTH streams and wait for the next one.
    // The outer timeout in process_connection ensures we don't wait forever.
    loop {
        let mut recv_stream = connection.accept_uni().await?;
        let mut stream_reader = StreamReader::new_with_buffer_size(80);
        let tuic_version = stream_reader.read_u8(&mut recv_stream).await?;
        if tuic_version != 5 {
            return Err(std::io::Error::other(format!(
                "invalid tuic version: {tuic_version}"
            )));
        }
        let command_type = stream_reader.read_u8(&mut recv_stream).await?;

        if command_type != COMMAND_TYPE_AUTHENTICATE {
            // Not an AUTH command - discard this stream and wait for the next one.
            debug!("Received command type {command_type} before auth, waiting for auth command");
            continue;
        }

        let mut specified_uuid = [0u8; 16];
        specified_uuid.copy_from_slice(stream_reader.read_slice(&mut recv_stream, 16).await?);

        // Read the whole credential before looking anything up. An unknown uuid and a
        // suspended user must give the same answer and neither may give it early:
        // closing on the uuid alone, before the client has finished sending, would
        // tell an observer which uuids this inbound knows.
        //
        // Looking up *after* the read rather than before it is what keeps the answer
        // current. This read is a network read the client controls, so it can be held
        // open indefinitely; a lookup on the near side of it would let a client that
        // sent its uuid and then stalled authenticate on a password that was rotated,
        // or as a user who was suspended, in the meantime.
        let token_bytes = stream_reader.read_slice(&mut recv_stream, 32).await?;

        // The value is not echoed back into the error. With more than one user it is
        // somebody's live credential, or a guess at one, and neither belongs in a log.
        let Some(identity) = users.find_tuic_uuid(&specified_uuid) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "unrecognized uuid",
            ));
        };

        let mut expected_token_bytes = [0u8; 32];
        connection
            .export_keying_material(
                &mut expected_token_bytes,
                &specified_uuid,
                identity.password.as_bytes(),
            )
            .map_err(|e| {
                std::io::Error::other(format!("Failed to export keying material: {e:?}"))
            })?;

        // A plain comparison rather than a constant-time one, as upstream had it, and
        // it is sound here for a reason worth writing down: the expected token is
        // derived from this connection's keying material, so it is a fresh value every
        // time. There is no stored secret for a timing probe to walk a byte at a time,
        // because an attacker would have to re-derive its target for each attempt --
        // which is precisely the thing it cannot do.
        if token_bytes != expected_token_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "incorrect token",
            ));
        }

        // The lookup deliberately left this to us: only now is the client shown to
        // hold the password the token was keyed with. Admission and registration use
        // the same user lifecycle gate, so removal cannot slip between them.
        if metered {
            if !lifecycle.bind_authenticated(identity.user) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "user could not be admitted: removed, suspended, or at their connection limit",
                ));
            }
            return Ok(Some(Arc::clone(lifecycle)));
        }
        if !identity.user.admit_unmetered() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "user could not be admitted: removed, suspended, or at their connection limit",
            ));
        }
        return Ok(None);
    }
}

async fn run_bidirectional_loop(
    connection: quinn::Connection,
    selector: Arc<SelectorSlot>,
    meter: Meter,
    lifecycle: Arc<ConnContext>,
) -> std::io::Result<()> {
    let flow_gate = Arc::new(Semaphore::new(MAX_ACTIVE_TCP_LOGICAL_FLOWS));
    loop {
        let (mut send_stream, mut recv_stream) = match connection.accept_bi().await {
            Ok(s) => s,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                break;
            }
            Err(quinn::ConnectionError::ConnectionClosed(_)) => {
                break;
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to accept bidirectional stream: {e}"
                )));
            }
        };

        let Some(flow_permit) = try_admit_tcp_logical_flow(&flow_gate) else {
            debug!(
                "refusing TUIC TCP stream: {MAX_ACTIVE_TCP_LOGICAL_FLOWS} logical flows are already active"
            );
            let _ = send_stream.reset(TCP_FLOW_LIMIT_ERROR_CODE.into());
            let _ = recv_stream.stop(TCP_FLOW_LIMIT_ERROR_CODE.into());
            continue;
        };
        let request_header_deadline = Instant::now() + TCP_REQUEST_HEADER_TIMEOUT;

        let conn = connection.clone();
        // Each CONNECT stream is an independent logical flow. Take one atomic
        // selector/resolver generation after accepting it and let the task-owned
        // Arcs pin that generation for the flow's lifetime.
        let (client_proxy_selector, resolver) = selector.load();
        // Every stream on this connection shares the one context, so a user's counters
        // cover all of them at once and the live-connection count follows the QUIC
        // connection rather than the streams multiplexed over it.
        let meter = meter.clone();
        let lifecycle = Arc::clone(&lifecycle);
        tokio::spawn(async move {
            // Covers CONNECT parsing, DNS/outbound setup, and copying.
            let _flow_permit = flow_permit;
            let result = scope_connection_until_cancelled(
                lifecycle,
                process_tcp_stream(
                    client_proxy_selector,
                    resolver,
                    meter,
                    send_stream,
                    recv_stream,
                    request_header_deadline,
                ),
            )
            .await;
            match result {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                    // Per official TUIC reference (handle_stream.rs:127-135),
                    // header parsing errors close the connection
                    debug!("TUIC TCP stream header was rejected: {e}");
                    conn.close(0u32.into(), b"");
                }
                Err(e) => {
                    // TCP proxying errors are just logged (handle_task.rs:238-246)
                    debug!("TUIC TCP stream ended: {e}");
                }
            }
        });
    }
    Ok(())
}

/// Generic over the stream because every caller reads through a different one: the
/// TCP path through a whole [`ClientStream`], the uni-stream UDP path through a
/// [`ClientRecvStream`], and either of those may be a meter wrapping the real thing.
async fn read_address<T: AsyncReadExt + Unpin>(
    recv: &mut T,
    stream_reader: &mut StreamReader,
) -> std::io::Result<Option<NetLocation>> {
    let address_type = stream_reader.read_u8(recv).await?;
    let address = match address_type {
        0xff => {
            return Ok(None);
        }
        0x00 => {
            let address_len = stream_reader.read_u8(recv).await? as usize;
            let address_bytes = stream_reader.read_slice(recv, address_len).await?;
            let address_str = str::from_utf8(address_bytes).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid address: {e}"),
                )
            })?;
            // Although this is supposed to be a hostname, some clients will pass
            // ipv4 and ipv6 addresses as well, so parse it rather than directly
            // using Address:Hostname enum.
            Address::from(address_str)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?
        }
        0x01 => {
            let ipv4_bytes = stream_reader.read_slice(recv, 4).await?;
            let ipv4_addr =
                Ipv4Addr::new(ipv4_bytes[0], ipv4_bytes[1], ipv4_bytes[2], ipv4_bytes[3]);
            Address::Ipv4(ipv4_addr)
        }
        0x02 => {
            let ipv6_bytes = stream_reader.read_slice(recv, 16).await?;
            let ipv6_bytes: [u8; 16] = ipv6_bytes.try_into().unwrap();
            let ipv6_addr = Ipv6Addr::from(ipv6_bytes);
            Address::Ipv6(ipv6_addr)
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid address type: {address_type}"),
            ));
        }
    };

    let port = stream_reader.read_u16_be(recv).await?;

    Ok(Some(NetLocation::new(address, port)))
}

fn serialize_address(location: &NetLocation) -> Vec<u8> {
    let mut address_bytes = match location.address() {
        Address::Hostname(hostname) => {
            let mut res = Vec::with_capacity(1 + 1 + hostname.len() + 2);
            res.push(0x00); // address type
            let hostname_bytes = hostname.as_bytes();
            res.push(hostname_bytes.len() as u8);
            res.extend_from_slice(hostname_bytes);
            res
        }
        Address::Ipv4(ipv4) => {
            let mut res = Vec::with_capacity(1 + 4 + 2);
            res.push(0x01); // address type
            res.extend_from_slice(&ipv4.octets());
            res
        }
        Address::Ipv6(ipv6) => {
            let mut res = Vec::with_capacity(1 + 16 + 2);
            res.push(0x02); // address type
            res.extend_from_slice(&ipv6.octets());
            res
        }
    };

    address_bytes.extend_from_slice(&location.port().to_be_bytes());

    address_bytes
}

fn serialize_socket_addr(addr: &SocketAddr) -> Vec<u8> {
    let mut res = match addr {
        SocketAddr::V4(addr_v4) => {
            let mut res = Vec::with_capacity(1 + 4 + 2);
            res.push(0x01); // address type for IPv4
            res.extend_from_slice(&addr_v4.ip().octets());
            res
        }
        SocketAddr::V6(addr_v6) => {
            let mut res = Vec::with_capacity(1 + 16 + 2);
            res.push(0x02); // address type for IPv6
            res.extend_from_slice(&addr_v6.ip().octets());
            res
        }
    };

    res.extend_from_slice(&addr.port().to_be_bytes());
    res
}

async fn read_tuic_tcp_request_header(
    server_stream: &mut ClientStream,
) -> std::io::Result<(NetLocation, Vec<u8>)> {
    let mut stream_reader = StreamReader::new_with_buffer_size(1024);
    let tuic_version = stream_reader.read_u8(server_stream).await?;
    if tuic_version != 5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid tuic version: {tuic_version}"),
        ));
    }
    let command_type = stream_reader.read_u8(server_stream).await?;
    if command_type != COMMAND_TYPE_CONNECT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid command type: {command_type}"),
        ));
    }

    let remote_location = read_address(server_stream, &mut stream_reader)
        .await?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "empty address"))?;
    let replay = stream_reader
        .unparsed_data_owned()
        .map(Vec::from)
        .unwrap_or_default();
    Ok((remote_location, replay))
}

async fn process_tcp_stream(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    meter: Meter,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    request_header_deadline: Instant,
) -> std::io::Result<()> {
    // Wrapped before the request header is read rather than after, so the version
    // byte, the command and the address are billed along with the payload that
    // follows. They are bytes the client put on the wire.
    let mut server_stream: ClientStream = meter_stream(send, recv, &meter);

    let (remote_location, mut replay) = read_tcp_request_header_before_deadline(
        request_header_deadline,
        read_tuic_tcp_request_header(&mut server_stream),
    )
    .await?;
    let sniffed = if client_proxy_selector.needs_tcp_sniff() {
        sniff_tcp(&mut server_stream, &mut replay).await?
    } else {
        None
    };

    let setup_client_stream_future = timeout(
        Duration::from_secs(60),
        prepare_client_tcp_stream_with_metadata(
            client_proxy_selector,
            resolver,
            remote_location.clone(),
            sniffed,
        ),
    );

    let client_setup = match setup_client_stream_future.await {
        Ok(Ok(Some(s))) => s,
        Ok(Ok(None)) => {
            // Must have been blocked.
            let _ = server_stream.shutdown().await;
            return Ok(());
        }
        Ok(Err(e)) => {
            let _ = server_stream.shutdown().await;
            return Err(client_stream_setup_error(&remote_location, e));
        }
        Err(elapsed) => {
            let _ = server_stream.shutdown().await;
            return Err(client_stream_setup_timeout(&remote_location, elapsed));
        }
    };
    let mut client_stream = apply_client_early_data(&mut server_stream, client_setup).await?;

    let client_requires_flush = if replay.is_empty() {
        false
    } else {
        write_all(&mut client_stream, &replay).await?;
        true
    };

    // Use 32KB buffers to match reference implementations
    let copy_result = copy_bidirectional_with_sizes(
        &mut server_stream,
        &mut client_stream,
        false, // no need to flush since it's QUIC
        client_requires_flush,
        32768,
        32768,
    )
    .await;

    let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());

    copy_result?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpRelayMode {
    Stream,
    Datagram,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpSessionStatus {
    Pending,
    Ready,
}

struct UdpSession {
    outbound_tx: mpsc::Sender<UdpForwardCommand>,
    last_activity: std::time::Instant,
    cancel_token: CancellationToken,
    mode: UdpRelayMode,
    generation: u64,
    status: UdpSessionStatus,
    _permit: OwnedSemaphorePermit,
}

struct UdpForwardCommand {
    remote_location: NetLocation,
    payload: Bytes,
    _payload_permit: OwnedSemaphorePermit,
}

struct UdpTargetHandle {
    outbound_tx: mpsc::Sender<UdpForwardCommand>,
    last_used: u64,
    generation: u64,
    cancel_token: CancellationToken,
}

enum UdpTargetPermit {
    Ready(OwnedSemaphorePermit),
    Awaiting(Arc<Semaphore>),
}

impl Drop for UdpTargetHandle {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

enum UdpTargetEvent {
    Message {
        remote_location: NetLocation,
        generation: u64,
        payload: Bytes,
    },
    Stopped {
        remote_location: NetLocation,
        generation: u64,
        error: std::io::Error,
    },
}

enum UdpResponseTransport {
    Stream {
        connection: quinn::Connection,
        meter: Meter,
    },
    Datagram {
        connection: quinn::Connection,
        meter: Meter,
    },
}

struct UdpSessionRegistry {
    sessions: DashMap<u16, UdpSession>,
    /// Serializes association generation changes with fragment-cache cleanup.
    /// Without this, an old worker could remove generation N, pause, and then
    /// erase fragments inserted for a newly-created generation N+1.
    lifecycle_lock: Mutex<()>,
    pending_epochs: Mutex<FxHashMap<u16, PendingUdpEpoch>>,
    session_permits: Arc<Semaphore>,
    target_permits: Arc<Semaphore>,
    queued_payload_permits: Arc<Semaphore>,
    next_generation: AtomicU64,
}

#[derive(Clone, Copy)]
struct PendingUdpEpoch {
    generation: u64,
    mode: UdpRelayMode,
    last_update: std::time::Instant,
}

enum UdpSessionReservation {
    Existing {
        outbound_tx: mpsc::Sender<UdpForwardCommand>,
        generation: u64,
    },
    Created {
        outbound_tx: mpsc::Sender<UdpForwardCommand>,
        outbound_rx: mpsc::Receiver<UdpForwardCommand>,
        cancel_token: CancellationToken,
        generation: u64,
    },
}

impl UdpSessionRegistry {
    fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            lifecycle_lock: Mutex::new(()),
            pending_epochs: Mutex::new(FxHashMap::default()),
            session_permits: Arc::new(Semaphore::new(MAX_UDP_SESSIONS)),
            target_permits: Arc::new(Semaphore::new(MAX_UDP_TARGETS_PER_CONNECTION)),
            queued_payload_permits: Arc::new(Semaphore::new(MAX_UDP_QUEUED_BYTES_PER_CONNECTION)),
            next_generation: AtomicU64::new(1),
        }
    }

    fn reserve(
        &self,
        assoc_id: u16,
        mode: UdpRelayMode,
        allow_create: bool,
        parent_cancel_token: &CancellationToken,
    ) -> std::io::Result<UdpSessionReservation> {
        let _lifecycle_guard = self
            .lifecycle_lock
            .lock()
            .map_err(|_| std::io::Error::other("TUIC association lifecycle mutex poisoned"))?;
        self.reserve_locked(assoc_id, mode, allow_create, parent_cancel_token, None)
    }

    fn reserve_locked(
        &self,
        assoc_id: u16,
        mode: UdpRelayMode,
        allow_create: bool,
        parent_cancel_token: &CancellationToken,
        required_generation: Option<u64>,
    ) -> std::io::Result<UdpSessionReservation> {
        match self.sessions.entry(assoc_id) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                let session = entry.get_mut();
                if session.mode != mode {
                    return Err(std::io::Error::other(format!(
                        "TUIC association {assoc_id} changed relay mode"
                    )));
                }
                if required_generation.is_some_and(|generation| generation != session.generation) {
                    return Err(std::io::Error::other(format!(
                        "TUIC association {assoc_id} generation changed"
                    )));
                }
                if let Ok(mut pending_epochs) = self.pending_epochs.lock()
                    && pending_epochs
                        .get(&assoc_id)
                        .is_some_and(|pending| pending.generation == session.generation)
                {
                    pending_epochs.remove(&assoc_id);
                }
                session.last_activity = std::time::Instant::now();
                Ok(UdpSessionReservation::Existing {
                    outbound_tx: session.outbound_tx.clone(),
                    generation: session.generation,
                })
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                if !allow_create {
                    return Err(std::io::Error::other(
                        "Ignoring packet with unknown session and empty address",
                    ));
                }
                let permit = self
                    .session_permits
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| {
                        std::io::Error::other(format!(
                            "Refusing new UDP session {assoc_id}: at the {MAX_UDP_SESSIONS} session limit"
                        ))
                    })?;
                let generation = required_generation
                    .unwrap_or_else(|| self.next_generation.fetch_add(1, Ordering::Relaxed));
                let cancel_token = parent_cancel_token.child_token();
                let (outbound_tx, outbound_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
                entry.insert(UdpSession {
                    outbound_tx: outbound_tx.clone(),
                    last_activity: std::time::Instant::now(),
                    cancel_token: cancel_token.clone(),
                    mode,
                    generation,
                    status: UdpSessionStatus::Pending,
                    _permit: permit,
                });
                if let Ok(mut pending_epochs) = self.pending_epochs.lock()
                    && pending_epochs
                        .get(&assoc_id)
                        .is_some_and(|pending| pending.generation == generation)
                {
                    pending_epochs.remove(&assoc_id);
                }
                Ok(UdpSessionReservation::Created {
                    outbound_tx,
                    outbound_rx,
                    cancel_token,
                    generation,
                })
            }
        }
    }

    fn promote(&self, assoc_id: u16, generation: u64) -> bool {
        let Some(mut session) = self.sessions.get_mut(&assoc_id) else {
            return false;
        };
        if session.generation != generation || session.status != UdpSessionStatus::Pending {
            return false;
        }
        session.status = UdpSessionStatus::Ready;
        true
    }

    fn validate_mode(&self, assoc_id: u16, mode: UdpRelayMode) -> std::io::Result<()> {
        if let Some(session) = self.sessions.get(&assoc_id)
            && session.mode != mode
        {
            return Err(std::io::Error::other(format!(
                "TUIC association {assoc_id} changed relay mode"
            )));
        }
        Ok(())
    }

    fn claim_packet_epoch(&self, assoc_id: u16, mode: UdpRelayMode) -> std::io::Result<u64> {
        let _lifecycle_guard = self
            .lifecycle_lock
            .lock()
            .map_err(|_| std::io::Error::other("TUIC association lifecycle mutex poisoned"))?;
        self.claim_packet_epoch_locked(assoc_id, mode, std::time::Instant::now())
    }

    fn claim_packet_epoch_locked(
        &self,
        assoc_id: u16,
        mode: UdpRelayMode,
        now: std::time::Instant,
    ) -> std::io::Result<u64> {
        self.validate_mode(assoc_id, mode)?;
        if let Some(session) = self.sessions.get(&assoc_id) {
            return Ok(session.generation);
        }

        let mut pending_epochs = self
            .pending_epochs
            .lock()
            .map_err(|_| std::io::Error::other("TUIC pending epoch mutex poisoned"))?;
        pending_epochs.retain(|_, pending| {
            now.checked_duration_since(pending.last_update)
                .is_none_or(|age| age < UDP_FRAGMENT_TIMEOUT)
        });
        if let Some(pending) = pending_epochs.get(&assoc_id) {
            if pending.mode != mode {
                return Err(std::io::Error::other(format!(
                    "TUIC pending association {assoc_id} changed relay mode"
                )));
            }
            return Ok(pending.generation);
        }
        if pending_epochs.len() >= MAX_FRAGMENT_CACHE_SIZE
            && let Some(oldest_assoc_id) = pending_epochs
                .iter()
                .min_by_key(|(_, pending)| pending.last_update)
                .map(|(assoc_id, _)| *assoc_id)
        {
            pending_epochs.remove(&oldest_assoc_id);
        }
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        pending_epochs.insert(
            assoc_id,
            PendingUdpEpoch {
                generation,
                mode,
                last_update: now,
            },
        );
        Ok(generation)
    }

    fn validate_claimed_epoch_locked(
        &self,
        assoc_id: u16,
        mode: UdpRelayMode,
        generation: u64,
        now: std::time::Instant,
    ) -> std::io::Result<()> {
        self.validate_mode(assoc_id, mode)?;
        if let Some(session) = self.sessions.get(&assoc_id) {
            if session.generation == generation {
                return Ok(());
            }
            return Err(std::io::Error::other(format!(
                "TUIC association {assoc_id} generation changed"
            )));
        }
        let mut pending_epochs = self
            .pending_epochs
            .lock()
            .map_err(|_| std::io::Error::other("TUIC pending epoch mutex poisoned"))?;
        let Some(pending) = pending_epochs.get(&assoc_id).copied() else {
            return Err(std::io::Error::other(format!(
                "TUIC association {assoc_id} epoch was cancelled"
            )));
        };
        if pending.generation != generation || pending.mode != mode {
            return Err(std::io::Error::other(format!(
                "TUIC association {assoc_id} epoch changed"
            )));
        }
        if now
            .checked_duration_since(pending.last_update)
            .is_some_and(|age| age >= UDP_FRAGMENT_TIMEOUT)
        {
            pending_epochs.remove(&assoc_id);
            return Err(std::io::Error::other(format!(
                "TUIC association {assoc_id} epoch expired"
            )));
        }
        Ok(())
    }

    fn refresh_pending_epoch_locked(
        &self,
        assoc_id: u16,
        mode: UdpRelayMode,
        generation: u64,
        now: std::time::Instant,
    ) -> std::io::Result<()> {
        let mut pending_epochs = self
            .pending_epochs
            .lock()
            .map_err(|_| std::io::Error::other("TUIC pending epoch mutex poisoned"))?;
        if let Some(pending) = pending_epochs.get_mut(&assoc_id) {
            if pending.generation != generation || pending.mode != mode {
                return Err(std::io::Error::other(format!(
                    "TUIC association {assoc_id} epoch changed"
                )));
            }
            pending.last_update = now;
        }
        Ok(())
    }

    fn purge_pending_epochs_locked(&self, now: std::time::Instant) -> Vec<(u16, u64)> {
        let Ok(mut pending_epochs) = self.pending_epochs.lock() else {
            return Vec::new();
        };
        let expired: Vec<_> = pending_epochs
            .iter()
            .filter_map(|(assoc_id, pending)| {
                now.checked_duration_since(pending.last_update)
                    .is_some_and(|age| age >= UDP_FRAGMENT_TIMEOUT)
                    .then_some((*assoc_id, pending.generation))
            })
            .collect();
        for (assoc_id, _) in &expired {
            pending_epochs.remove(assoc_id);
        }
        expired
    }

    fn remove_generation_locked(&self, assoc_id: u16, generation: u64) -> bool {
        if let dashmap::mapref::entry::Entry::Occupied(entry) = self.sessions.entry(assoc_id)
            && entry.get().generation == generation
        {
            entry.remove();
            return true;
        }
        false
    }

    fn dissociate_locked(&self, assoc_id: u16) {
        if let Some((_, session)) = self.sessions.remove(&assoc_id) {
            session.cancel_token.cancel();
        }
        if let Ok(mut pending_epochs) = self.pending_epochs.lock() {
            pending_epochs.remove(&assoc_id);
        }
    }

    fn remove_inactive_locked(&self) -> Vec<u16> {
        let mut removed = Vec::new();
        self.sessions.retain(|assoc_id, session| {
            if session.last_activity.elapsed() > IDLE_TIMEOUT {
                session.cancel_token.cancel();
                debug!("Removing inactive UDP session {assoc_id}");
                removed.push(*assoc_id);
                false
            } else {
                true
            }
        });
        removed
    }

    fn touch_generation(&self, assoc_id: u16, generation: u64) -> bool {
        self.touch_generation_at(assoc_id, generation, std::time::Instant::now())
    }

    fn touch_generation_at(&self, assoc_id: u16, generation: u64, now: std::time::Instant) -> bool {
        let Some(mut session) = self.sessions.get_mut(&assoc_id) else {
            return false;
        };
        if session.generation != generation {
            return false;
        }
        session.last_activity = now;
        true
    }
}

impl Drop for UdpSession {
    /// Stop the remote-to-local task this session started.
    ///
    /// A `CancellationToken` does not fire when its last handle is dropped -- only
    /// an explicit `cancel` or a `DropGuard` does that, as the connection token at
    /// the top of `process_connection` already notes -- and the spawned loop holds
    /// its own clone of this one along with the client socket and a 64 KiB receive
    /// buffer.
    ///
    /// Two paths discard a session without going through the reaper, and both leaked
    /// before this: the `remove` after a failed forward, and the loser of the insert
    /// race in `process_udp_packet`, where an already-started session is dropped
    /// because a concurrent packet for the same association id got there first. The
    /// race loser is the worse of the two, because it is not in the map for the
    /// reaper to ever find, so its socket and task lived until the whole connection
    /// ended.
    ///
    /// Cancelling here rather than at each call site makes the release a property of
    /// the session's lifetime. The reaper's explicit `cancel` is left in place and is
    /// simply idempotent.
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

struct FragmentedPacket {
    mode: UdpRelayMode,
    fragment_count: u8,
    fragment_received: u8,
    packet_len: usize,
    received: Vec<Option<Bytes>>,
    remote_location: Option<NetLocation>,
    last_update: std::time::Instant,
}

fn purge_expired_fragments_at(
    fragments: &mut LruCache<(u16, u64, u16), FragmentedPacket>,
    now: std::time::Instant,
) {
    let keys: Vec<_> = fragments
        .iter()
        .filter_map(|(key, packet)| {
            now.checked_duration_since(packet.last_update)
                .is_some_and(|age| age >= UDP_FRAGMENT_TIMEOUT)
                .then_some(*key)
        })
        .collect();
    for key in keys {
        fragments.pop(&key);
    }
}

fn purge_expired_fragments(fragments: &UdpFragmentMap) {
    let Ok(mut fragments) = fragments.lock() else {
        return;
    };
    purge_expired_fragments_at(&mut fragments, std::time::Instant::now());
}

/// Record the destination carried by fragment zero, even when a continuation
/// fragment created the reassembly entry first. Returns false when fragment zero
/// itself omits the required address.
fn capture_first_fragment_location(
    cached: &mut Option<NetLocation>,
    fragment_id: u8,
    presented: Option<NetLocation>,
) -> bool {
    if fragment_id != 0 {
        return true;
    }
    let Some(presented) = presented else {
        return false;
    };
    *cached = Some(presented);
    true
}

fn checked_udp_packet_len(current: usize, fragment_len: usize) -> std::io::Result<usize> {
    current
        .checked_add(fragment_len)
        .filter(|length| *length <= MAX_UDP_PACKET_SIZE)
        .ok_or_else(|| std::io::Error::other("TUIC fragmented UDP packet is too large"))
}

fn try_reserve_payload_bytes(
    budget: &Arc<Semaphore>,
    payload_len: usize,
) -> Option<OwnedSemaphorePermit> {
    let permits = u32::try_from(payload_len.max(1)).ok()?;
    budget.clone().try_acquire_many_owned(permits).ok()
}

fn absorb_udp_activation_error(assoc_id: u16, result: std::io::Result<bool>) -> bool {
    match result {
        Ok(activated) => activated,
        Err(error) => {
            // Routing rejection, DNS failure, proxy connect failure, and resource
            // exhaustion affect this association, not TUIC framing or the QUIC
            // connection itself.
            debug!("TUIC UDP association {assoc_id} was not activated: {error}");
            false
        }
    }
}

fn absorb_udp_packet_error(assoc_id: u16, result: std::io::Result<()>) -> std::io::Result<()> {
    if let Err(error) = result {
        // The PACKET wire command was already decoded successfully. Defragmentation,
        // association, routing, and outbound failures drop this UDP packet without
        // turning a single logical flow failure into a QUIC connection failure.
        debug!("Dropping TUIC UDP packet for association {assoc_id}: {error}");
    }
    Ok(())
}

async fn await_udp_response_or_cancel<F>(
    cancel_token: &CancellationToken,
    response: F,
) -> std::io::Result<bool>
where
    F: Future<Output = std::io::Result<()>>,
{
    tokio::select! {
        biased;
        _ = cancel_token.cancelled() => Ok(false),
        result = response => {
            result?;
            Ok(true)
        }
    }
}

async fn connect_udp_target(
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    remote_location: NetLocation,
) -> std::io::Result<Box<dyn AsyncMessageStream>> {
    let requested_location = remote_location.clone();
    let decision = match client_proxy_selector
        .judge_udp(remote_location.into(), resolver)
        .await
    {
        Ok(decision) => decision,
        Err(error) => {
            warn!("TUIC UDP routing for {requested_location} failed: {error}");
            return Err(error);
        }
    };

    match decision {
        ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => {
            let outbound_location = remote_location.clone();
            chain_group
                .connect_udp_bidirectional(resolver, remote_location)
                .await
                .map_err(|error| {
                    warn!("TUIC UDP outbound setup to {outbound_location} failed: {error}");
                    error
                })
        }
        ConnectDecision::Block => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "UDP destination blocked by routing rules",
        )),
    }
}

fn evict_lru_udp_target(targets: &mut FxHashMap<NetLocation, UdpTargetHandle>) {
    let Some(remote_location) = targets
        .iter()
        .min_by_key(|(_, target)| target.last_used)
        .map(|(remote_location, _)| remote_location.clone())
    else {
        return;
    };
    targets.remove(&remote_location);
}

fn try_reserve_udp_target(
    targets: &mut FxHashMap<NetLocation, UdpTargetHandle>,
    target_permits: &Arc<Semaphore>,
) -> Option<UdpTargetPermit> {
    match target_permits.clone().try_acquire_owned() {
        Ok(permit) => {
            if targets.len() >= MAX_UDP_TARGETS_PER_SESSION {
                evict_lru_udp_target(targets);
            }
            Some(UdpTargetPermit::Ready(permit))
        }
        Err(_) if targets.len() >= MAX_UDP_TARGETS_PER_SESSION => {
            // Cancellation releases the old worker's permit asynchronously. The
            // replacement owns its first command and waits in its own task, so
            // healthy targets keep progressing and the first packet is not lost.
            evict_lru_udp_target(targets);
            Some(UdpTargetPermit::Awaiting(target_permits.clone()))
        }
        Err(_) => None,
    }
}

async fn acquire_udp_target_permits(
    permit: UdpTargetPermit,
    session_target_permits: Arc<Semaphore>,
    cancel_token: &CancellationToken,
) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
    let session_permit = tokio::select! {
        biased;
        _ = cancel_token.cancelled() => return None,
        permit = session_target_permits.acquire_owned() => permit.ok()?,
    };
    let global_permit = match permit {
        UdpTargetPermit::Ready(permit) => permit,
        UdpTargetPermit::Awaiting(permits) => tokio::select! {
            biased;
            _ = cancel_token.cancelled() => return None,
            permit = permits.acquire_owned() => permit.ok()?,
        },
    };
    Some((session_permit, global_permit))
}

fn publish_udp_target_event(
    event_tx: &mpsc::Sender<UdpTargetEvent>,
    cancel_token: &CancellationToken,
    event: UdpTargetEvent,
) -> bool {
    if cancel_token.is_cancelled() {
        return false;
    }
    match event_tx.try_send(event) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            // UDP replies are lossy by contract. Never let one slow association
            // leave every target task holding another 64 KiB payload while it
            // waits for the single-slot response handoff.
            debug!("Dropping TUIC UDP response for slow association");
            true
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

enum UdpTargetWork {
    Command(Option<UdpForwardCommand>),
    Read(std::io::Result<usize>),
}

enum UdpSessionWork {
    Command(Option<UdpForwardCommand>),
    Target(Option<UdpTargetEvent>),
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_target_worker(
    remote_location: NetLocation,
    generation: u64,
    initial_remote: Option<Box<dyn AsyncMessageStream>>,
    mut outbound_rx: mpsc::Receiver<UdpForwardCommand>,
    event_tx: mpsc::Sender<UdpTargetEvent>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    cancel_token: CancellationToken,
    permit: UdpTargetPermit,
    session_target_permits: Arc<Semaphore>,
) {
    let Some((_session_permit, _global_permit)) =
        acquire_udp_target_permits(permit, session_target_permits, &cancel_token).await
    else {
        return;
    };
    let mut remote = match initial_remote {
        Some(remote) => remote,
        None => {
            let connect =
                connect_udp_target(&client_proxy_selector, &resolver, remote_location.clone());
            let result = tokio::select! {
                biased;
                _ = cancel_token.cancelled() => return,
                result = connect => result,
            };
            match result {
                Ok(remote) => remote,
                Err(error) => {
                    let error = std::io::Error::other(format!(
                        "Failed to connect TUIC UDP target {remote_location}: {error}"
                    ));
                    let _ = publish_udp_target_event(
                        &event_tx,
                        &cancel_token,
                        UdpTargetEvent::Stopped {
                            remote_location,
                            generation,
                            error,
                        },
                    );
                    return;
                }
            }
        }
    };
    let mut remote_buf = allocate_vec(MAX_UDP_PACKET_SIZE);

    loop {
        // Cancellation has strict priority, while the inner unbiased selection
        // prevents either a sustained command stream or sustained replies from
        // starving the other direction for this target.
        let work = tokio::select! {
            biased;
            _ = cancel_token.cancelled() => return,
            work = async {
                tokio::select! {
                    command = outbound_rx.recv() => UdpTargetWork::Command(command),
                    result = async {
                        let mut read_buf = ReadBuf::new(&mut remote_buf);
                        poll_fn(|cx| Pin::new(&mut *remote).poll_read_message(cx, &mut read_buf))
                            .await
                            .map(|()| read_buf.filled().len())
                    } => UdpTargetWork::Read(result),
                }
            } => work,
        };

        match work {
            UdpTargetWork::Command(Some(command)) => {
                let write = async {
                    poll_fn(|cx| Pin::new(&mut *remote).poll_write_message(cx, &command.payload))
                        .await?;
                    poll_fn(|cx| Pin::new(&mut *remote).poll_flush_message(cx)).await
                };
                let result = tokio::select! {
                    biased;
                    _ = cancel_token.cancelled() => return,
                    result = write => result,
                };
                if let Err(error) = result {
                    let error = std::io::Error::other(format!(
                        "TUIC UDP target {remote_location} ended while forwarding: {error}"
                    ));
                    let _ = publish_udp_target_event(
                        &event_tx,
                        &cancel_token,
                        UdpTargetEvent::Stopped {
                            remote_location,
                            generation,
                            error,
                        },
                    );
                    return;
                }
                // `command`, including its connection-wide payload permit, remains
                // alive until both write and flush complete and is dropped here.
            }
            UdpTargetWork::Command(None) => return,
            UdpTargetWork::Read(Ok(payload_len)) => {
                let payload = Bytes::copy_from_slice(&remote_buf[..payload_len]);
                if !publish_udp_target_event(
                    &event_tx,
                    &cancel_token,
                    UdpTargetEvent::Message {
                        remote_location: remote_location.clone(),
                        generation,
                        payload,
                    },
                ) {
                    return;
                }
            }
            UdpTargetWork::Read(Err(error)) => {
                let _ = publish_udp_target_event(
                    &event_tx,
                    &cancel_token,
                    UdpTargetEvent::Stopped {
                        remote_location,
                        generation,
                        error,
                    },
                );
                return;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_udp_target_worker(
    remote_location: NetLocation,
    generation: u64,
    initial_remote: Option<Box<dyn AsyncMessageStream>>,
    outbound_rx: mpsc::Receiver<UdpForwardCommand>,
    event_tx: mpsc::Sender<UdpTargetEvent>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    cancel_token: CancellationToken,
    permit: UdpTargetPermit,
    session_target_permits: Arc<Semaphore>,
) {
    tokio::spawn(run_udp_target_worker(
        remote_location,
        generation,
        initial_remote,
        outbound_rx,
        event_tx,
        client_proxy_selector,
        resolver,
        cancel_token,
        permit,
        session_target_permits,
    ));
}

#[allow(clippy::too_many_arguments)]
fn dispatch_udp_target_command(
    targets: &mut FxHashMap<NetLocation, UdpTargetHandle>,
    use_counter: &mut u64,
    next_target_generation: &mut u64,
    command: UdpForwardCommand,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    target_permits: &Arc<Semaphore>,
    session_target_permits: &Arc<Semaphore>,
    event_tx: &mpsc::Sender<UdpTargetEvent>,
    cancel_token: &CancellationToken,
) {
    if cancel_token.is_cancelled() {
        return;
    }
    let remote_location = command.remote_location.clone();
    let mut command = Some(command);
    let mut closed = false;
    if let Some(target) = targets.get_mut(&remote_location) {
        *use_counter = use_counter.wrapping_add(1);
        target.last_used = *use_counter;
        match target
            .outbound_tx
            .try_send(command.take().expect("command is available"))
        {
            Ok(()) => return,
            Err(mpsc::error::TrySendError::Full(command)) => {
                debug!("Dropping TUIC UDP packet for slow target {remote_location}");
                drop(command);
                return;
            }
            Err(mpsc::error::TrySendError::Closed(returned)) => {
                command = Some(returned);
                closed = true;
            }
        }
    }
    if closed {
        targets.remove(&remote_location);
    }

    let Some(permit) = try_reserve_udp_target(targets, target_permits) else {
        debug!("Dropping TUIC UDP packet for {remote_location}: connection target limit reached");
        return;
    };
    if cancel_token.is_cancelled() {
        return;
    }

    *next_target_generation = next_target_generation.wrapping_add(1);
    let generation = *next_target_generation;
    *use_counter = use_counter.wrapping_add(1);
    let target_cancel_token = cancel_token.child_token();
    let (outbound_tx, outbound_rx) = mpsc::channel(UDP_TARGET_QUEUE_CAPACITY);
    if outbound_tx
        .try_send(command.expect("command was not sent to an existing target"))
        .is_err()
    {
        unreachable!("a newly-created target queue always has capacity");
    }
    targets.insert(
        remote_location.clone(),
        UdpTargetHandle {
            outbound_tx,
            last_used: *use_counter,
            generation,
            cancel_token: target_cancel_token.clone(),
        },
    );
    spawn_udp_target_worker(
        remote_location,
        generation,
        None,
        outbound_rx,
        event_tx.clone(),
        client_proxy_selector.clone(),
        resolver.clone(),
        target_cancel_token,
        permit,
        session_target_permits.clone(),
    );
}

async fn send_udp_to_local_stream(
    assoc_id: u16,
    connection: &quinn::Connection,
    meter: &Meter,
    packet_id: u16,
    source: &NetLocation,
    payload: &[u8],
) -> std::io::Result<()> {
    let payload_len = payload.len();
    if payload_len > MAX_UDP_PACKET_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TUIC UDP response exceeds the u16 payload limit",
        ));
    }
    let address_bytes: Bytes = serialize_address(source).into();
    let address_bytes_len = address_bytes.len();

    // version(1) + command(1) + assoc_id(2) + packet_id(2) + fragment total(1)
    // + fragment id(1) + payload size (2) + address bytes
    //
    // The two leading bytes were missing here, and here only: the datagram path
    // above writes them, and `process_uni_stream` reads them off every uni stream
    // a client sends. A TUIC client in `quic` UDP relay mode parses this stream
    // the same way, so without them it read the assoc id as a version and dropped
    // the packet -- which is why that mode never worked.
    let header_len = 1 + 1 + 2 + 2 + 1 + 1 + 2 + address_bytes_len;

    let start_offset = MAX_HEADER_LEN - header_len;
    let end_offset = MAX_HEADER_LEN + payload_len;
    let mut buf = allocate_vec(end_offset).into_boxed_slice();

    buf[start_offset] = 5;
    buf[start_offset + 1] = COMMAND_TYPE_PACKET;
    buf[start_offset + 2] = (assoc_id >> 8) as u8;
    buf[start_offset + 3] = assoc_id as u8;
    buf[start_offset + 4] = (packet_id >> 8) as u8;
    buf[start_offset + 5] = packet_id as u8;
    buf[start_offset + 6] = 1;
    buf[start_offset + 7] = 0;
    buf[start_offset + 8] = (payload_len >> 8) as u8;
    buf[start_offset + 9] = payload_len as u8;
    buf[start_offset + 10..start_offset + 10 + address_bytes_len].copy_from_slice(&address_bytes);

    buf[MAX_HEADER_LEN..end_offset].copy_from_slice(payload);

    // TUIC quic relay mode defines one PACKET command per unidirectional stream.
    // Opening and finishing here also prevents one stalled response from pinning a
    // shared stream used by later packets or associations.
    let mut send_stream = meter_send(connection.open_uni().await?, meter);
    write_all(&mut send_stream, &buf[start_offset..end_offset])
        .await
        .map_err(|e| std::io::Error::other(format!("TUIC stream write failed: {e}")))?;
    send_stream
        .shutdown()
        .await
        .map_err(|e| std::io::Error::other(format!("TUIC stream finish failed: {e}")))
}

async fn send_udp_to_local_datagram(
    assoc_id: u16,
    connection: &quinn::Connection,
    meter: &Meter,
    packet_id: u16,
    source: &NetLocation,
    payload: &[u8],
    cancel_token: &CancellationToken,
) -> std::io::Result<()> {
    let max_datagram_size = connection
        .max_datagram_size()
        .ok_or_else(|| std::io::Error::other("datagram not supported by remote endpoint"))?;
    send_udp_datagram_fragments_with(
        assoc_id,
        meter,
        packet_id,
        source,
        payload,
        max_datagram_size,
        cancel_token,
        |fragment_id, datagram| {
            connection.send_datagram(datagram).map_err(|error| {
                std::io::Error::other(format!(
                    "Failed to send datagram fragment {fragment_id}: {error}"
                ))
            })
        },
    )
    .await
}

#[inline]
fn udp_response_send_allowed(cancel_token: &CancellationToken) -> bool {
    !cancel_token.is_cancelled()
}

#[allow(clippy::too_many_arguments)]
async fn send_udp_datagram_fragments_with<S>(
    assoc_id: u16,
    meter: &Meter,
    packet_id: u16,
    source: &NetLocation,
    payload: &[u8],
    max_datagram_size: usize,
    cancel_token: &CancellationToken,
    mut send_datagram: S,
) -> std::io::Result<()>
where
    S: FnMut(u8, Bytes) -> std::io::Result<()>,
{
    use bytes::BufMut;

    let payload_len = payload.len();
    if payload_len > MAX_UDP_PACKET_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TUIC UDP response exceeds the u16 payload limit",
        ));
    }
    let address_bytes: Bytes = serialize_address(source).into();
    let address_bytes_len = address_bytes.len();

    // Header format:
    // tuic_version (1 byte) + command_type (1 byte)
    // + assoc_id (2 bytes) + packet_id (2 bytes)
    // + frag_total (1 byte) + frag_id (1 byte)
    // + payload_size (2 bytes) + address_bytes
    let header_overhead = 1 + 1 + 2 + 2 + 1 + 1 + 2 + address_bytes_len;

    // TUIC's own wire format length-prefixes a hostname with one byte, so a
    // client cannot name a destination whose echoed form outgrows a datagram --
    // 269 bytes at the very most, against a floor of `min_mtu`. The `else` branch
    // below still subtracts this from `max_datagram_size`, though, and an
    // unreachable underflow is one refactor away from a reachable one. Checked
    // here so the arithmetic below is guarded by something other than a comment.
    if max_datagram_size <= header_overhead {
        return Err(std::io::Error::other(format!(
            "the requested destination needs {header_overhead} header bytes, which does not \
                 fit a {max_datagram_size} byte datagram"
        )));
    }

    if header_overhead + payload_len <= max_datagram_size {
        let mut datagram = BytesMut::with_capacity(header_overhead + payload_len);
        datagram.put_u8(5); // tuic version
        datagram.put_u8(COMMAND_TYPE_PACKET); // command type
        datagram.extend_from_slice(&assoc_id.to_be_bytes());
        datagram.extend_from_slice(&packet_id.to_be_bytes());
        datagram.put_u8(1); // frag_total = 1
        datagram.put_u8(0); // frag_id = 0
        datagram.extend_from_slice(&(payload_len as u16).to_be_bytes());
        datagram.extend_from_slice(&address_bytes);
        datagram.extend_from_slice(payload);

        // Admission uses datagram length rather than payload length, so the
        // session and address headers are charged only if Quinn accepts them.
        let datagram = datagram.freeze();
        let datagram_len = datagram.len();
        if !udp_response_send_allowed(cancel_token) {
            return Ok(());
        }
        let permit = if let Some(meter) = meter {
            Some(tokio::select! {
                biased;
                _ = cancel_token.cancelled() => return Ok(()),
                permit = meter.admit_datagram_tx(datagram_len) => permit,
            })
        } else {
            None
        };
        if !udp_response_send_allowed(cancel_token) {
            return Ok(());
        }
        send_datagram(0, datagram)?;
        if let Some(permit) = permit {
            permit.commit();
        }
    } else {
        // Calculate header sizes for first fragment and subsequent fragments.
        let first_overhead = header_overhead; // full address included in the first fragment
        let other_overhead = 1 + 1 + 2 + 2 + 1 + 1 + 2 + 1; // 0xff marker instead of full address
        let first_capacity = max_datagram_size - first_overhead;
        let other_capacity = max_datagram_size - other_overhead;

        let remaining = payload_len.saturating_sub(first_capacity);
        let additional_fragments = remaining.div_ceil(other_capacity);
        let fragment_count = 1 + additional_fragments;
        if fragment_count > u8::MAX as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "TUIC UDP response needs {fragment_count} fragments, protocol limit is {}",
                    u8::MAX
                ),
            ));
        }
        let fragment_count = fragment_count as u8;

        let mut offset = 0;
        for fragment_id in 0..fragment_count {
            if fragment_id != 0 {
                // QUIC datagram sends and unmetered accounting are synchronous.
                // Without an explicit yield this whole loop can run in one poll,
                // preventing the task processing DISSOCIATE from cancelling this
                // generation before every remaining fragment is queued.
                tokio::task::yield_now().await;
            }
            // Metering the preceding fragment can also await. In either case,
            // recheck the generation-owned token immediately after the scheduling
            // boundary and before allocating or writing the next fragment.
            if !udp_response_send_allowed(cancel_token) {
                return Ok(());
            }
            let (fragment_payload_len, header_size) = if fragment_id == 0 {
                let len = std::cmp::min(first_capacity, payload_len);
                (len, first_overhead)
            } else {
                let len = std::cmp::min(other_capacity, payload_len - offset);
                (len, other_overhead)
            };

            let mut datagram = BytesMut::with_capacity(header_size + fragment_payload_len);
            datagram.extend_from_slice(&[5, COMMAND_TYPE_PACKET]);
            datagram.extend_from_slice(&assoc_id.to_be_bytes());
            datagram.extend_from_slice(&packet_id.to_be_bytes());
            datagram.extend_from_slice(&[fragment_count, fragment_id]);
            datagram.extend_from_slice(&(fragment_payload_len as u16).to_be_bytes());
            if fragment_id == 0 {
                datagram.extend_from_slice(&address_bytes);
            } else {
                datagram.put_u8(0xff);
            }
            datagram.extend_from_slice(&payload[offset..offset + fragment_payload_len]);
            let datagram = datagram.freeze();
            let datagram_len = datagram.len();
            let permit = if let Some(meter) = meter {
                Some(tokio::select! {
                    biased;
                    _ = cancel_token.cancelled() => return Ok(()),
                    permit = meter.admit_datagram_tx(datagram_len) => permit,
                })
            } else {
                None
            };
            if !udp_response_send_allowed(cancel_token) {
                return Ok(());
            }
            send_datagram(fragment_id, datagram)?;
            if let Some(permit) = permit {
                permit.commit();
            }
            offset += fragment_payload_len;
        }
    }
    Ok(())
}

impl UdpResponseTransport {
    async fn send_packet(
        &mut self,
        assoc_id: u16,
        packet_id: u16,
        source: &NetLocation,
        payload: &[u8],
        cancel_token: &CancellationToken,
    ) -> std::io::Result<()> {
        match self {
            Self::Stream { connection, meter } => {
                send_udp_to_local_stream(assoc_id, connection, meter, packet_id, source, payload)
                    .await
            }
            Self::Datagram { connection, meter } => {
                send_udp_to_local_datagram(
                    assoc_id,
                    connection,
                    meter,
                    packet_id,
                    source,
                    payload,
                    cancel_token,
                )
                .await
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_session_worker(
    assoc_id: u16,
    session_generation: u64,
    udp_session_map: UdpSessionMap,
    mut response: UdpResponseTransport,
    initial_location: NetLocation,
    initial_permit: OwnedSemaphorePermit,
    mut outbound_rx: mpsc::Receiver<UdpForwardCommand>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    target_permits: Arc<Semaphore>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut next_packet_id = 0u16;
    let mut targets: FxHashMap<NetLocation, UdpTargetHandle> = FxHashMap::default();
    let (target_event_tx, mut target_event_rx) = mpsc::channel(UDP_TARGET_RESPONSE_QUEUE_CAPACITY);
    let session_target_permits = Arc::new(Semaphore::new(MAX_UDP_TARGETS_PER_SESSION));
    let initial_target_generation = 1;
    let initial_cancel_token = cancel_token.child_token();
    let (initial_tx, initial_rx) = mpsc::channel(UDP_TARGET_QUEUE_CAPACITY);
    targets.insert(
        initial_location.clone(),
        UdpTargetHandle {
            outbound_tx: initial_tx,
            last_used: 1,
            generation: initial_target_generation,
            cancel_token: initial_cancel_token.clone(),
        },
    );
    spawn_udp_target_worker(
        initial_location,
        initial_target_generation,
        None,
        initial_rx,
        target_event_tx.clone(),
        client_proxy_selector.clone(),
        resolver.clone(),
        initial_cancel_token,
        UdpTargetPermit::Ready(initial_permit),
        session_target_permits.clone(),
    );
    let mut use_counter = 1u64;
    let mut next_target_generation = initial_target_generation;

    loop {
        // Cancellation is strict-priority. The inner unbiased selection keeps a
        // busy uplink from starving target replies (and vice versa).
        let work = tokio::select! {
            biased;
            _ = cancel_token.cancelled() => return Ok(()),
            work = async {
                tokio::select! {
                    command = outbound_rx.recv() => UdpSessionWork::Command(command),
                    event = target_event_rx.recv() => UdpSessionWork::Target(event),
                }
            } => work,
        };

        match work {
            UdpSessionWork::Command(Some(command)) => {
                dispatch_udp_target_command(
                    &mut targets,
                    &mut use_counter,
                    &mut next_target_generation,
                    command,
                    &client_proxy_selector,
                    &resolver,
                    &target_permits,
                    &session_target_permits,
                    &target_event_tx,
                    &cancel_token,
                );
            }
            UdpSessionWork::Command(None) => return Ok(()),
            UdpSessionWork::Target(Some(UdpTargetEvent::Stopped {
                remote_location,
                generation,
                error,
            })) => {
                let is_current = targets
                    .get(&remote_location)
                    .is_some_and(|target| target.generation == generation);
                if !is_current {
                    continue;
                }
                debug!("TUIC UDP target {remote_location} stopped: {error}");
                targets.remove(&remote_location);
            }
            UdpSessionWork::Target(Some(UdpTargetEvent::Message {
                remote_location,
                generation,
                payload,
            })) => {
                let Some(target) = targets.get_mut(&remote_location) else {
                    continue;
                };
                if target.generation != generation {
                    continue;
                }
                use_counter = use_counter.wrapping_add(1);
                target.last_used = use_counter;

                // Count the successfully-read remote datagram immediately. A
                // temporarily backpressured QUIC writer must not let the 60-second
                // reaper kill an otherwise active downlink-only association.
                // The association generation check prevents a stale target task
                // from touching a reused id.
                udp_session_map.touch_generation(assoc_id, session_generation);

                let packet_id = next_packet_id;
                next_packet_id = next_packet_id.wrapping_add(1);
                let send = response.send_packet(
                    assoc_id,
                    packet_id,
                    &remote_location,
                    &payload,
                    &cancel_token,
                );
                if !await_udp_response_or_cancel(&cancel_token, send).await? {
                    return Ok(());
                }
            }
            UdpSessionWork::Target(None) => return Ok(()),
        }
    }
}

async fn run_unidirectional_loop(
    connection: quinn::Connection,
    selector: Arc<SelectorSlot>,
    udp_session_map: UdpSessionMap,
    fragments: UdpFragmentMap,
    meter: Meter,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let uni_command_gate = Arc::new(Semaphore::new(MAX_IN_FLIGHT_UNI_COMMANDS));
    // Spawn a cleanup task for UDP sessions that terminates when connection closes
    let cleanup_session_map = udp_session_map.clone();
    let cleanup_fragments = fragments.clone();
    let cleanup_cancel_token = cancel_token.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            tokio::select! {
                _ = cleanup_cancel_token.cancelled() => {
                    break;
                }
                _ = interval.tick() => {
                    remove_inactive_udp_sessions(&cleanup_session_map, &cleanup_fragments);
                    purge_expired_pending_udp_epochs(&cleanup_session_map, &cleanup_fragments);
                    purge_expired_fragments(&cleanup_fragments);
                }
            }
        }
    });

    loop {
        let recv_stream = match connection.accept_uni().await {
            Ok(recv_stream) => recv_stream,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                break;
            }
            Err(quinn::ConnectionError::ConnectionClosed(_)) => {
                break;
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to accept unidirectional stream: {e}"
                )));
            }
        };

        let uni_command_permit = match uni_command_gate.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                debug!(
                    "Dropping TUIC unidirectional command: {MAX_IN_FLIGHT_UNI_COMMANDS} tasks are already in flight"
                );
                drop(recv_stream);
                continue;
            }
        };

        let connection = connection.clone();
        let selector = selector.clone();
        let udp_session_map = udp_session_map.clone();
        let fragments = fragments.clone();
        let cancel_token = cancel_token.clone();
        let task_cancel_token = cancel_token.clone();
        let meter = meter.clone();
        tokio::spawn(async move {
            let _uni_command_permit = uni_command_permit;
            // Per TUIC protocol, each uni stream carries exactly ONE command.
            // The reference implementation (handle_stream.rs) handles one task per stream.
            let work = process_uni_stream(
                &connection,
                selector,
                recv_stream,
                udp_session_map,
                fragments,
                meter,
                cancel_token,
            );
            let result = tokio::select! {
                biased;
                () = task_cancel_token.cancelled() => return,
                result = work => result,
            };
            match result {
                Ok(()) => {}
                Err(e) => {
                    // Per official TUIC reference (handle_stream.rs:70-78),
                    // uni stream errors close the connection
                    debug!("TUIC unidirectional stream ended: {e}");
                    connection.close(0u32.into(), b"");
                }
            }
        });
    }
    Ok(())
}

/// Process a single uni stream command. Per TUIC protocol, each uni stream
/// carries exactly one command (PACKET or DISSOCIATE on server side).
async fn process_uni_stream(
    connection: &quinn::Connection,
    selector: Arc<SelectorSlot>,
    recv_stream: quinn::RecvStream,
    udp_session_map: UdpSessionMap,
    fragments: UdpFragmentMap,
    meter: Meter,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    // Wrapped before the first byte is read, so a packet command is billed whole --
    // headers, address and payload -- and a malformed one is billed too. The datagram
    // loop counts before validating for the same reason: bytes the client sent are
    // bytes it sent, whatever it made of them.
    let mut recv_stream: ClientRecvStream = meter_recv(recv_stream, &meter);

    // The fixed header/address fits in MAX_HEADER_LEN. Allocate the client-declared
    // payload only after confirming this is a PACKET command; DISSOCIATE therefore
    // remains a small command even under the uni task gate.
    let mut stream_reader = StreamReader::new_with_buffer_size(MAX_HEADER_LEN);

    let tuic_version = stream_reader.read_u8(&mut recv_stream).await?;
    if tuic_version != 5 {
        return Err(std::io::Error::other(format!(
            "invalid tuic version: {tuic_version}"
        )));
    }
    let command_type = stream_reader.read_u8(&mut recv_stream).await?;

    if command_type == COMMAND_TYPE_DISSOCIATE {
        let assoc_id = stream_reader.read_u16_be(&mut recv_stream).await?;
        // Remove and cancel the session's background task.
        // Per official TUIC Rust reference (handle_task.rs:154-165).
        dissociate_udp_session(&udp_session_map, &fragments, assoc_id);
        // Session not found is normal - it may have already timed out or been closed
        return Ok(());
    }

    if command_type != COMMAND_TYPE_PACKET {
        return Err(std::io::Error::other(format!(
            "invalid uni stream command type: {command_type}"
        )));
    }

    // PACKET command - read the packet data
    let assoc_id = stream_reader.read_u16_be(&mut recv_stream).await?;
    // Bind this stream to the association generation as soon as its id is known.
    // A concurrent DISSOCIATE can then invalidate the claim while this task awaits
    // the rest of the command, instead of letting the stale task recreate the id.
    let packet_epoch = match udp_session_map.claim_packet_epoch(assoc_id, UdpRelayMode::Stream) {
        Ok(packet_epoch) => packet_epoch,
        Err(error) => {
            debug!("Dropping TUIC UDP stream packet for association {assoc_id}: {error}");
            return Ok(());
        }
    };
    let packet_id = stream_reader.read_u16_be(&mut recv_stream).await?;
    let frag_total = stream_reader.read_u8(&mut recv_stream).await?;
    let frag_id = stream_reader.read_u8(&mut recv_stream).await?;
    let payload_size = stream_reader.read_u16_be(&mut recv_stream).await?;
    let remote_location = read_address(&mut recv_stream, &mut stream_reader).await?;

    let payload_fragment =
        read_uni_payload(&mut recv_stream, &mut stream_reader, payload_size as usize).await?;

    let result = process_udp_packet_v2(
        connection,
        &selector,
        &udp_session_map,
        &fragments,
        assoc_id,
        packet_id,
        frag_total,
        frag_id,
        remote_location,
        &payload_fragment,
        true,
        packet_epoch,
        &meter,
        &cancel_token,
    )
    .await;
    absorb_udp_packet_error(assoc_id, result)
}

async fn read_uni_payload(
    recv_stream: &mut ClientRecvStream,
    stream_reader: &mut StreamReader,
    payload_size: usize,
) -> std::io::Result<Bytes> {
    let buffered_len = stream_reader.unparsed_data().len().min(payload_size);
    let mut payload = allocate_vec(payload_size);
    if buffered_len != 0 {
        payload[..buffered_len].copy_from_slice(stream_reader.unparsed_data());
        stream_reader.consume(buffered_len);
    }
    if buffered_len < payload_size {
        recv_stream.read_exact(&mut payload[buffered_len..]).await?;
    }
    Ok(payload.into())
}

#[allow(clippy::too_many_arguments)]
fn activate_udp_session(
    connection: &quinn::Connection,
    selector: &Arc<SelectorSlot>,
    udp_session_map: &UdpSessionMap,
    fragments: &UdpFragmentMap,
    assoc_id: u16,
    initial_location: NetLocation,
    mode: UdpRelayMode,
    meter: &Meter,
    outbound_rx: mpsc::Receiver<UdpForwardCommand>,
    session_cancel_token: CancellationToken,
    generation: u64,
    connection_cancel_token: &CancellationToken,
) -> std::io::Result<bool> {
    if connection_cancel_token.is_cancelled() || session_cancel_token.is_cancelled() {
        remove_udp_generation(udp_session_map, fragments, assoc_id, generation);
        return Ok(false);
    }
    // Capture the exact selector/resolver generation in the packet's current task.
    // The spawned association and all of its target workers retain these Arcs even
    // if a dynamic reload swaps the listener's selector immediately afterwards.
    let (session_selector, session_resolver) = selector.load();
    let initial_permit = match udp_session_map.target_permits.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            remove_udp_generation(udp_session_map, fragments, assoc_id, generation);
            return Err(std::io::Error::other(format!(
                "Refusing TUIC UDP association {assoc_id}: connection target limit reached"
            )));
        }
    };

    if !udp_session_map.promote(assoc_id, generation) {
        return Ok(false);
    }

    let response = match mode {
        UdpRelayMode::Stream => UdpResponseTransport::Stream {
            connection: connection.clone(),
            meter: meter.clone(),
        },
        UdpRelayMode::Datagram => UdpResponseTransport::Datagram {
            connection: connection.clone(),
            meter: meter.clone(),
        },
    };
    let target_permits = udp_session_map.target_permits.clone();
    let worker_map = udp_session_map.clone();
    let cleanup_map = udp_session_map.clone();
    let cleanup_fragments = fragments.clone();
    tokio::spawn(async move {
        let result = run_udp_session_worker(
            assoc_id,
            generation,
            worker_map,
            response,
            initial_location,
            initial_permit,
            outbound_rx,
            session_selector,
            session_resolver,
            target_permits,
            session_cancel_token,
        )
        .await;
        remove_udp_generation(&cleanup_map, &cleanup_fragments, assoc_id, generation);
        if let Err(error) = result {
            debug!("TUIC UDP association {assoc_id} ended: {error}");
        }
    });
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn assemble_udp_packet(
    fragments: &UdpFragmentMap,
    assoc_id: u16,
    packet_id: u16,
    mode: UdpRelayMode,
    frag_total: u8,
    frag_id: u8,
    remote_location: Option<NetLocation>,
    payload_fragment: &[u8],
) -> std::io::Result<Option<(NetLocation, Bytes)>> {
    assemble_udp_packet_for_epoch_at(
        fragments,
        assoc_id,
        0,
        packet_id,
        mode,
        frag_total,
        frag_id,
        remote_location,
        payload_fragment,
        std::time::Instant::now(),
    )
}

#[allow(clippy::too_many_arguments)]
fn assemble_udp_packet_at(
    fragments: &UdpFragmentMap,
    assoc_id: u16,
    packet_id: u16,
    mode: UdpRelayMode,
    frag_total: u8,
    frag_id: u8,
    remote_location: Option<NetLocation>,
    payload_fragment: &[u8],
    now: std::time::Instant,
) -> std::io::Result<Option<(NetLocation, Bytes)>> {
    assemble_udp_packet_for_epoch_at(
        fragments,
        assoc_id,
        0,
        packet_id,
        mode,
        frag_total,
        frag_id,
        remote_location,
        payload_fragment,
        now,
    )
}

#[allow(clippy::too_many_arguments)]
fn assemble_udp_packet_for_epoch_at(
    fragments: &UdpFragmentMap,
    assoc_id: u16,
    epoch: u64,
    packet_id: u16,
    mode: UdpRelayMode,
    frag_total: u8,
    frag_id: u8,
    remote_location: Option<NetLocation>,
    payload_fragment: &[u8],
    now: std::time::Instant,
) -> std::io::Result<Option<(NetLocation, Bytes)>> {
    if frag_total == 0 || frag_id >= frag_total {
        return Err(std::io::Error::other(format!(
            "Invalid fragment id {frag_id} for total {frag_total}"
        )));
    }
    if frag_total == 1 {
        let remote_location = remote_location.ok_or_else(|| {
            std::io::Error::other("Ignoring packet with single fragment and no address")
        })?;
        checked_udp_packet_len(0, payload_fragment.len())?;
        return Ok(Some((
            remote_location,
            Bytes::copy_from_slice(payload_fragment),
        )));
    }

    let key = (assoc_id, epoch, packet_id);
    let mut fragments = fragments
        .lock()
        .map_err(|_| std::io::Error::other("TUIC fragment cache mutex poisoned"))?;
    purge_expired_fragments_at(&mut fragments, now);
    if !fragments.contains(&key) {
        fragments.put(
            key,
            FragmentedPacket {
                mode,
                fragment_count: frag_total,
                fragment_received: 0,
                packet_len: 0,
                received: vec![None; frag_total as usize],
                remote_location: None,
                last_update: now,
            },
        );
    }

    let packet = fragments
        .peek(&key)
        .ok_or_else(|| std::io::Error::other("Fragment cache error"))?;
    if packet.mode != mode {
        fragments.pop(&key);
        return Err(std::io::Error::other(format!(
            "TUIC association {assoc_id} packet {packet_id} changed relay mode"
        )));
    }
    if frag_id == 0 && remote_location.is_none() {
        fragments.pop(&key);
        return Err(std::io::Error::other(format!(
            "Ignoring packet with empty first fragment address for session {assoc_id}"
        )));
    }
    if packet.fragment_count != frag_total {
        fragments.pop(&key);
        return Err(std::io::Error::other(format!(
            "Mismatched fragment count for session {assoc_id} packet {packet_id}"
        )));
    }
    if packet.received[frag_id as usize].is_some() {
        fragments.pop(&key);
        return Err(std::io::Error::other(format!(
            "Duplicate fragment for session {assoc_id} packet {packet_id}"
        )));
    }

    let packet_len = match checked_udp_packet_len(packet.packet_len, payload_fragment.len()) {
        Ok(packet_len) => packet_len,
        Err(error) => {
            fragments.pop(&key);
            return Err(error);
        }
    };
    let packet = fragments
        .get_mut(&key)
        .ok_or_else(|| std::io::Error::other("Fragment cache entry disappeared"))?;
    // Only a valid, previously-unseen fragment counts as progress. Invalid or
    // duplicate traffic must not pin either this TTL or the entry's LRU position.
    if !capture_first_fragment_location(&mut packet.remote_location, frag_id, remote_location) {
        unreachable!("fragment-zero address was validated before mutating the cache");
    }
    packet.fragment_received += 1;
    packet.packet_len = packet_len;
    packet.received[frag_id as usize] = Some(Bytes::copy_from_slice(payload_fragment));
    packet.last_update = now;
    if packet.fragment_received != packet.fragment_count {
        return Ok(None);
    }

    let FragmentedPacket {
        remote_location,
        received,
        packet_len,
        ..
    } = fragments
        .pop(&key)
        .ok_or_else(|| std::io::Error::other("Fragment cache entry disappeared"))?;
    let remote_location = remote_location.ok_or_else(|| {
        std::io::Error::other(format!(
            "Missing first fragment address for session {assoc_id} packet {packet_id}"
        ))
    })?;
    let mut payload = BytesMut::with_capacity(packet_len);
    for fragment in received {
        payload.extend_from_slice(
            fragment
                .as_ref()
                .expect("fragment count proves every slot is populated"),
        );
    }
    Ok(Some((remote_location, payload.freeze())))
}

struct PendingUdpActivation {
    initial_location: NetLocation,
    mode: UdpRelayMode,
    outbound_rx: mpsc::Receiver<UdpForwardCommand>,
    cancel_token: CancellationToken,
    generation: u64,
}

#[allow(clippy::too_many_arguments)]
fn assemble_reserve_and_enqueue_udp_packet(
    udp_session_map: &UdpSessionMap,
    fragments: &UdpFragmentMap,
    assoc_id: u16,
    packet_id: u16,
    mode: UdpRelayMode,
    frag_total: u8,
    frag_id: u8,
    remote_location: Option<NetLocation>,
    payload_fragment: &[u8],
    packet_epoch: u64,
    cancel_token: &CancellationToken,
) -> std::io::Result<Option<PendingUdpActivation>> {
    assemble_reserve_and_enqueue_udp_packet_at(
        udp_session_map,
        fragments,
        assoc_id,
        packet_id,
        mode,
        frag_total,
        frag_id,
        remote_location,
        payload_fragment,
        packet_epoch,
        cancel_token,
        std::time::Instant::now(),
    )
}

#[allow(clippy::too_many_arguments)]
fn assemble_reserve_and_enqueue_udp_packet_at(
    udp_session_map: &UdpSessionMap,
    fragments: &UdpFragmentMap,
    assoc_id: u16,
    packet_id: u16,
    mode: UdpRelayMode,
    frag_total: u8,
    frag_id: u8,
    remote_location: Option<NetLocation>,
    payload_fragment: &[u8],
    packet_epoch: u64,
    cancel_token: &CancellationToken,
    now: std::time::Instant,
) -> std::io::Result<Option<PendingUdpActivation>> {
    let _lifecycle_guard = udp_session_map
        .lifecycle_lock
        .lock()
        .map_err(|_| std::io::Error::other("TUIC association lifecycle mutex poisoned"))?;
    if cancel_token.is_cancelled() {
        return Ok(None);
    }

    udp_session_map.validate_claimed_epoch_locked(assoc_id, mode, packet_epoch, now)?;
    let assembled = assemble_udp_packet_for_epoch_at(
        fragments,
        assoc_id,
        packet_epoch,
        packet_id,
        mode,
        frag_total,
        frag_id,
        remote_location,
        payload_fragment,
        now,
    )?;
    // Claiming or validating an epoch is not activity: otherwise duplicates and
    // malformed fragments can keep fragment-only associations alive forever.
    // Reaching here proves this fragment was accepted as new, valid progress.
    udp_session_map.refresh_pending_epoch_locked(assoc_id, mode, packet_epoch, now)?;
    let Some((remote_location, payload)) = assembled else {
        return Ok(None);
    };

    let Some(payload_permit) =
        try_reserve_payload_bytes(&udp_session_map.queued_payload_permits, payload.len())
    else {
        debug!("Dropping TUIC UDP packet: connection queue byte budget exhausted");
        return Ok(None);
    };
    let reservation =
        udp_session_map.reserve_locked(assoc_id, mode, true, cancel_token, Some(packet_epoch))?;
    let command = UdpForwardCommand {
        remote_location: remote_location.clone(),
        payload,
        _payload_permit: payload_permit,
    };

    match reservation {
        UdpSessionReservation::Existing {
            outbound_tx,
            generation,
        } => {
            debug_assert_eq!(generation, packet_epoch);
            match outbound_tx.try_send(command) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    debug!("Dropping TUIC UDP packet for slow association {assoc_id}");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    debug!("TUIC UDP association worker {assoc_id} has stopped");
                    if udp_session_map.remove_generation_locked(assoc_id, generation) {
                        remove_assoc_fragments(fragments, assoc_id);
                    }
                }
            }
            Ok(None)
        }
        UdpSessionReservation::Created {
            outbound_tx,
            outbound_rx,
            cancel_token,
            generation,
        } => {
            if outbound_tx.try_send(command).is_err() {
                unreachable!("a newly-created association queue always has capacity");
            }
            Ok(Some(PendingUdpActivation {
                initial_location: remote_location,
                mode,
                outbound_rx,
                cancel_token,
                generation,
            }))
        }
    }
}

fn remove_assoc_fragments(fragments: &UdpFragmentMap, assoc_id: u16) {
    let Ok(mut fragments) = fragments.lock() else {
        return;
    };
    let keys: Vec<_> = fragments
        .iter()
        .filter_map(|(key, _)| (key.0 == assoc_id).then_some(*key))
        .collect();
    for key in keys {
        fragments.pop(&key);
    }
}

fn remove_assoc_epoch_fragments(fragments: &UdpFragmentMap, assoc_id: u16, generation: u64) {
    let Ok(mut fragments) = fragments.lock() else {
        return;
    };
    let keys: Vec<_> = fragments
        .iter()
        .filter_map(|(key, _)| (key.0 == assoc_id && key.1 == generation).then_some(*key))
        .collect();
    for key in keys {
        fragments.pop(&key);
    }
}

fn purge_expired_pending_udp_epochs(udp_session_map: &UdpSessionMap, fragments: &UdpFragmentMap) {
    let Ok(_lifecycle_guard) = udp_session_map.lifecycle_lock.lock() else {
        return;
    };
    for (assoc_id, generation) in
        udp_session_map.purge_pending_epochs_locked(std::time::Instant::now())
    {
        remove_assoc_epoch_fragments(fragments, assoc_id, generation);
    }
}

fn remove_udp_generation(
    udp_session_map: &UdpSessionMap,
    fragments: &UdpFragmentMap,
    assoc_id: u16,
    generation: u64,
) {
    let Ok(_lifecycle_guard) = udp_session_map.lifecycle_lock.lock() else {
        return;
    };
    if udp_session_map.remove_generation_locked(assoc_id, generation) {
        remove_assoc_fragments(fragments, assoc_id);
    }
}

fn dissociate_udp_session(
    udp_session_map: &UdpSessionMap,
    fragments: &UdpFragmentMap,
    assoc_id: u16,
) {
    let Ok(_lifecycle_guard) = udp_session_map.lifecycle_lock.lock() else {
        return;
    };
    udp_session_map.dissociate_locked(assoc_id);
    remove_assoc_fragments(fragments, assoc_id);
}

fn remove_inactive_udp_sessions(udp_session_map: &UdpSessionMap, fragments: &UdpFragmentMap) {
    let Ok(_lifecycle_guard) = udp_session_map.lifecycle_lock.lock() else {
        return;
    };
    for assoc_id in udp_session_map.remove_inactive_locked() {
        remove_assoc_fragments(fragments, assoc_id);
    }
}

#[cfg(test)]
fn try_enqueue_udp_packet(
    udp_session_map: &UdpSessionMap,
    fragments: &UdpFragmentMap,
    assoc_id: u16,
    generation: u64,
    outbound_tx: mpsc::Sender<UdpForwardCommand>,
    command: UdpForwardCommand,
) {
    match outbound_tx.try_send(command) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            debug!("Dropping TUIC UDP packet for slow association {assoc_id}");
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            debug!("TUIC UDP association worker {assoc_id} has stopped");
            remove_udp_generation(udp_session_map, fragments, assoc_id, generation);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_udp_packet_v2(
    connection: &quinn::Connection,
    selector: &Arc<SelectorSlot>,
    udp_session_map: &UdpSessionMap,
    fragments: &UdpFragmentMap,
    assoc_id: u16,
    packet_id: u16,
    frag_total: u8,
    frag_id: u8,
    remote_location: Option<NetLocation>,
    payload_fragment: &[u8],
    is_uni_stream: bool,
    packet_epoch: u64,
    meter: &Meter,
    cancel_token: &CancellationToken,
) -> std::io::Result<()> {
    if frag_total == 0 {
        return Err(std::io::Error::other(
            "Ignoring packet with empty fragment total",
        ));
    }
    if frag_id >= frag_total {
        return Err(std::io::Error::other(format!(
            "Invalid fragment id {frag_id} >= total {frag_total}"
        )));
    }

    let mode = if is_uni_stream {
        UdpRelayMode::Stream
    } else {
        UdpRelayMode::Datagram
    };
    let pending_activation = assemble_reserve_and_enqueue_udp_packet(
        udp_session_map,
        fragments,
        assoc_id,
        packet_id,
        mode,
        frag_total,
        frag_id,
        remote_location,
        payload_fragment,
        packet_epoch,
        cancel_token,
    )?;
    let Some(PendingUdpActivation {
        initial_location,
        mode,
        outbound_rx,
        cancel_token: session_cancel_token,
        generation,
    }) = pending_activation
    else {
        return Ok(());
    };
    let activated = activate_udp_session(
        connection,
        selector,
        udp_session_map,
        fragments,
        assoc_id,
        initial_location,
        mode,
        meter,
        outbound_rx,
        session_cancel_token,
        generation,
        cancel_token,
    );
    absorb_udp_activation_error(assoc_id, activated);
    Ok(())
}

fn checked_payload_end(
    data_len: usize,
    offset: usize,
    payload_size: usize,
) -> std::io::Result<usize> {
    let end = offset
        .checked_add(payload_size)
        .ok_or_else(|| std::io::Error::other("decode UDP message: payload length overflow"))?;
    if end != data_len {
        let detail = if end > data_len {
            "truncated payload"
        } else {
            "trailing bytes after payload"
        };
        return Err(std::io::Error::other(format!(
            "decode UDP message: {detail}"
        )));
    }
    Ok(end)
}

async fn run_datagram_loop(
    connection: quinn::Connection,
    selector: Arc<SelectorSlot>,
    udp_session_map: UdpSessionMap,
    fragments: UdpFragmentMap,
    meter: Meter,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut last_cleanup = std::time::Instant::now();

    loop {
        let now = std::time::Instant::now();
        if (now - last_cleanup) > CLEANUP_INTERVAL {
            remove_inactive_udp_sessions(&udp_session_map, &fragments);
            purge_expired_pending_udp_epochs(&udp_session_map, &fragments);
            purge_expired_fragments(&fragments);
            last_cleanup = now;
        }

        let data = connection
            .read_datagram()
            .await
            .map_err(|err| std::io::Error::other(format!("failed to read datagram: {err}")))?;

        // The datagram has left Quinn's receive queue, but waits for upload
        // allowance before validation or forwarding. Cancellation while waiting
        // deliberately discards it unbilled. Once admitted it is counted even if
        // validation below rejects it, so malformed traffic is not free.
        if let Some(meter) = &meter {
            let permit = tokio::select! {
                biased;
                _ = cancel_token.cancelled() => return Ok(()),
                permit = meter.admit_datagram_rx(data.len()) => permit,
            };
            if cancel_token.is_cancelled() {
                return Ok(());
            }
            permit.commit();
        }

        // Per official TUIC reference (handle_stream.rs:172-180), protocol errors close the connection
        if data.len() < 2 {
            return Err(std::io::Error::other("invalid message: too short"));
        }

        let tuic_version = data[0];
        if tuic_version != 5 {
            return Err(std::io::Error::other(format!(
                "unknown version: {tuic_version}"
            )));
        }

        let command_type = data[1];
        if command_type == COMMAND_TYPE_HEARTBEAT {
            continue;
        } else if command_type != COMMAND_TYPE_PACKET {
            return Err(std::io::Error::other(format!(
                "unknown command: {command_type}"
            )));
        }

        let data_len = data.len();
        if data_len < 11 {
            return Err(std::io::Error::other("decode UDP message: too short"));
        }

        let assoc_id = u16::from_be_bytes([data[2], data[3]]);
        let packet_id = u16::from_be_bytes([data[4], data[5]]);
        let frag_total = data[6];
        let frag_id = data[7];
        let payload_size = u16::from_be_bytes([data[8], data[9]]) as usize;

        let address_type = data[10];

        let (remote_location, offset) = match address_type {
            0xff => (None, 11),
            0x00 => {
                if data_len < 14 {
                    return Err(std::io::Error::other(
                        "decode UDP message: hostname too short",
                    ));
                }
                let address_len = data[11] as usize;
                let address_end = 12usize.checked_add(address_len).ok_or_else(|| {
                    std::io::Error::other("decode UDP message: hostname length overflow")
                })?;
                let offset = address_end.checked_add(2).ok_or_else(|| {
                    std::io::Error::other("decode UDP message: hostname length overflow")
                })?;
                if offset > data_len {
                    return Err(std::io::Error::other(
                        "decode UDP message: truncated hostname",
                    ));
                }
                let address_bytes = &data[12..address_end];
                let address_str = str::from_utf8(address_bytes).map_err(|e| {
                    std::io::Error::other(format!("decode UDP message: invalid UTF-8: {e}"))
                })?;
                // Although this is supposed to be a hostname, some clients will pass
                // ipv4 and ipv6 addresses as well, so parse it rather than directly
                // using Address:Hostname enum.
                let address = Address::from(address_str).map_err(|e| {
                    std::io::Error::other(format!("decode UDP message: invalid address: {e}"))
                })?;
                let port = u16::from_be_bytes([data[address_end], data[address_end + 1]]);
                (Some(NetLocation::new(address, port)), offset)
            }
            0x01 => {
                if data_len < 17 {
                    return Err(std::io::Error::other("decode UDP message: IPv4 too short"));
                }
                let ipv4_addr = Ipv4Addr::new(data[11], data[12], data[13], data[14]);
                let port = u16::from_be_bytes([data[15], data[16]]);
                (Some(NetLocation::new(Address::Ipv4(ipv4_addr), port)), 17)
            }
            0x02 => {
                if data_len < 29 {
                    return Err(std::io::Error::other("decode UDP message: IPv6 too short"));
                }
                let ipv6_bytes: [u8; 16] = data[11..27].try_into().unwrap();
                let ipv6_addr = Ipv6Addr::from(ipv6_bytes);
                let port = u16::from_be_bytes([data[27], data[28]]);
                (Some(NetLocation::new(Address::Ipv6(ipv6_addr), port)), 29)
            }
            _ => {
                return Err(std::io::Error::other(format!(
                    "decode UDP message: invalid address type: {address_type}"
                )));
            }
        };

        // One checked calculation covers every address variant, including 0xff
        // (address omitted on a continuation fragment). Previously that branch
        // could index past the datagram and unwind the whole connection task.
        let payload_end = checked_payload_end(data_len, offset, payload_size)?;
        let payload_fragment = &data[offset..payload_end];

        let packet_epoch =
            match udp_session_map.claim_packet_epoch(assoc_id, UdpRelayMode::Datagram) {
                Ok(packet_epoch) => packet_epoch,
                Err(error) => {
                    debug!("Dropping TUIC UDP datagram for association {assoc_id}: {error}");
                    continue;
                }
            };

        if let Err(e) = process_udp_packet_v2(
            &connection,
            &selector,
            &udp_session_map,
            &fragments,
            assoc_id,
            packet_id,
            frag_total,
            frag_id,
            remote_location,
            payload_fragment,
            false,
            packet_epoch,
            &meter,
            &cancel_token,
        )
        .await
        {
            debug!("TUIC UDP datagram was rejected: {e}");
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn start_tuic_server(
    bind_address: SocketAddr,
    quic_server_config: Arc<quinn::crypto::rustls::QuicServerConfig>,
    users: Arc<dyn UserRegistry>,
    metered: bool,
    // Retained for the lifetime of accepted connections, which load it once for
    // every new TCP flow or UDP association. Authentication and fixed listener
    // settings remain connection/listener scoped.
    selector: Arc<SelectorSlot>,
    num_endpoints: usize,
    zero_rtt_handshake: bool,
    shutdown: CancellationToken,
    connection_cancel: CancellationToken,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    // All SO_REUSEPORT endpoints below form one logical listener and therefore
    // share one pending-authentication budget.
    let handshake_gate = HandshakeGate::new(MAX_PENDING_HANDSHAKES, MAX_PENDING_PER_SOURCE);
    let endpoints = crate::quic_server::prepare_endpoint_batch(num_endpoints, || {
        let mut server_config = quinn::ServerConfig::with_crypto(quic_server_config.clone());

        Arc::get_mut(&mut server_config.transport)
            .unwrap()
            .max_concurrent_bidi_streams((MAX_ACTIVE_TCP_LOGICAL_FLOWS as u32).into())
            .max_concurrent_uni_streams(4096_u32.into())
            .max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()))
            .keep_alive_interval(Some(Duration::from_secs(15)))
            .send_window(16 * 1024 * 1024)
            .receive_window((20u32 * 1024 * 1024).into())
            .stream_receive_window((8u32 * 1024 * 1024).into())
            // MTU settings per official TUIC reference
            .initial_mtu(1200)
            .min_mtu(1200)
            // Enable MTU discovery for larger packets on capable networks
            .mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()))
            // Enable GSO (Generic Segmentation Offload) for better throughput
            .enable_segmentation_offload(true)
            // Lower initial RTT estimate for faster initial window growth
            .initial_rtt(Duration::from_millis(100));

        // Request the platform-specific high-throughput QUIC buffer target in
        // each direction; see socket_util for the OpenBSD exception.
        //
        // SO_REUSEPORT only when there is a second endpoint to share the port with:
        // platforms without it panic rather than fail.
        let socket2_socket = crate::socket_util::new_socket2_udp_socket_with_buffer_size(
            bind_address.is_ipv6(),
            None,
            Some(bind_address),
            num_endpoints > 1,
            Some(crate::socket_util::QUIC_UDP_SOCKET_BUFFER_TARGET),
        )?;

        quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket2_socket.into(),
            Arc::new(quinn::TokioRuntime),
        )
    })?;

    let mut join_handles = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        // No resolver clone: the accept loop takes it from the selector slot, so the
        // rules and the DNS a connection routes by are always one generation.
        let selector = selector.clone();
        let users = users.clone();
        let handshake_gate = handshake_gate.clone();
        let shutdown = shutdown.clone();
        let connection_cancel = connection_cancel.clone();

        let join_handle = tokio::spawn(async move {
            loop {
                let conn = tokio::select! {
                    biased;
                    () = connection_cancel.cancelled() => break,
                    () = shutdown.cancelled() => break,
                    incoming = endpoint.accept() => match incoming {
                        Some(conn) => conn,
                        None => break,
                    },
                };
                let Some(conn) = require_validated_quic_address(conn, "TUIC") else {
                    continue;
                };
                let remote_ip = conn.remote_address().ip();
                let Some(handshake_permit) = handshake_gate.enter(Some(remote_ip)) else {
                    debug!(
                        "refusing TUIC peer {remote_ip}: the listener is at its pending-handshake limit"
                    );
                    conn.refuse();
                    continue;
                };
                let pre_auth = TuicPreAuthAdmission {
                    permit: handshake_permit,
                    deadline: Instant::now() + QUIC_PRE_AUTH_TIMEOUT,
                };
                let selector = selector.clone();
                let cloned_users = users.clone();
                let connection_cancel = connection_cancel.clone();
                tokio::spawn(async move {
                    if let Err(e) = process_connection(
                        selector,
                        cloned_users,
                        metered,
                        conn,
                        zero_rtt_handshake,
                        pre_auth,
                        connection_cancel,
                    )
                    .await
                    {
                        debug!("TUIC connection from {remote_ip} ended: {e}");
                    }
                });
            }

            if connection_cancel.is_cancelled() {
                crate::quic_server::hard_close_endpoint(endpoint, bind_address).await;
            } else {
                // See `quic_server::drain_endpoint`: the port cannot come back before
                // the connections sharing its socket are done with it.
                crate::quic_server::drain_endpoint(endpoint, bind_address).await;
            }
        });
        join_handles.push(join_handle);
    }

    Ok(join_handles)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_ACTIVE_TCP_LOGICAL_FLOWS, MAX_FRAGMENT_CACHE_SIZE, MAX_IN_FLIGHT_UNI_COMMANDS,
        MAX_UDP_PACKET_SIZE, MAX_UDP_SESSIONS, MAX_UDP_TARGETS_PER_SESSION,
        TCP_REQUEST_HEADER_TIMEOUT, UdpForwardCommand, UdpRelayMode, UdpSessionRegistry,
        UdpSessionReservation, UdpTargetEvent, UdpTargetHandle, UdpTargetPermit,
        absorb_udp_activation_error, absorb_udp_packet_error, acquire_udp_target_permits,
        assemble_reserve_and_enqueue_udp_packet, assemble_reserve_and_enqueue_udp_packet_at,
        assemble_udp_packet, assemble_udp_packet_at, await_udp_response_or_cancel,
        checked_payload_end, checked_udp_packet_len, dispatch_udp_target_command,
        dissociate_udp_session, publish_udp_target_event, read_tcp_request_header_before_deadline,
        remove_assoc_fragments, remove_inactive_udp_sessions, remove_udp_generation,
        run_udp_target_worker, send_udp_datagram_fragments_with, spawn_udp_target_worker,
        try_admit_tcp_logical_flow, try_enqueue_udp_packet, try_reserve_payload_bytes,
        try_reserve_udp_target,
    };
    use crate::address::{Address, NetLocation};
    use crate::async_stream::{
        AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
        AsyncWriteMessage,
    };
    use crate::dynamic::{ConnContext, UserContext};
    use bytes::Bytes;
    use futures::future::{pending, poll_fn};
    use lru::LruCache;
    use rustc_hash::FxHashMap;
    use std::net::Ipv4Addr;
    use std::num::NonZeroUsize;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::ReadBuf;
    use tokio::sync::Semaphore;
    use tokio::time::{Instant, advance};
    use tokio_util::sync::CancellationToken;

    struct CountingWriteMessageStream(Arc<AtomicUsize>);

    impl AsyncReadMessage for CountingWriteMessageStream {
        fn poll_read_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWriteMessage for CountingWriteMessageStream {
        fn poll_write_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<()>> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncFlushMessage for CountingWriteMessageStream {
        fn poll_flush_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncShutdownMessage for CountingWriteMessageStream {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for CountingWriteMessageStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncMessageStream for CountingWriteMessageStream {}

    struct PendingWriteMessageStream;

    impl AsyncReadMessage for PendingWriteMessageStream {
        fn poll_read_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWriteMessage for PendingWriteMessageStream {
        fn poll_write_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncFlushMessage for PendingWriteMessageStream {
        fn poll_flush_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncShutdownMessage for PendingWriteMessageStream {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for PendingWriteMessageStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncMessageStream for PendingWriteMessageStream {}

    struct ReplyAfterWriteMessageStream {
        writes: Arc<AtomicUsize>,
        written: bool,
        reply_sent: bool,
        read_waker: Option<std::task::Waker>,
    }

    impl AsyncReadMessage for ReplyAfterWriteMessageStream {
        fn poll_read_message(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.written && !self.reply_sent {
                self.reply_sent = true;
                buf.put_slice(b"reply-a");
                Poll::Ready(Ok(()))
            } else {
                self.read_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    impl AsyncWriteMessage for ReplyAfterWriteMessageStream {
        fn poll_write_message(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<()>> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            self.written = true;
            if let Some(waker) = self.read_waker.take() {
                waker.wake();
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncFlushMessage for ReplyAfterWriteMessageStream {
        fn poll_flush_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncShutdownMessage for ReplyAfterWriteMessageStream {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for ReplyAfterWriteMessageStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncMessageStream for ReplyAfterWriteMessageStream {}

    fn location(port: u16) -> NetLocation {
        NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), port)
    }

    fn fragment_map() -> super::UdpFragmentMap {
        Arc::new(Mutex::new(LruCache::new(
            NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE).unwrap(),
        )))
    }

    #[tokio::test]
    async fn pending_target_does_not_block_healthy_target_write_or_reply() {
        let blocked = location(1001);
        let healthy = location(1002);
        let target_permits = Arc::new(Semaphore::new(2));
        let session_target_permits = Arc::new(Semaphore::new(MAX_UDP_TARGETS_PER_SESSION));
        let payload_budget = Arc::new(Semaphore::new(32));
        let selector = Arc::new(super::ClientProxySelector::new(Vec::new()));
        let resolver: Arc<dyn super::Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let cancel_token = CancellationToken::new();
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(1);
        let mut targets = FxHashMap::default();

        let blocked_cancel = cancel_token.child_token();
        let (blocked_tx, blocked_rx) = tokio::sync::mpsc::channel(1);
        targets.insert(
            blocked.clone(),
            UdpTargetHandle {
                outbound_tx: blocked_tx,
                last_used: 1,
                generation: 1,
                cancel_token: blocked_cancel.clone(),
            },
        );
        spawn_udp_target_worker(
            blocked.clone(),
            1,
            Some(Box::new(PendingWriteMessageStream)),
            blocked_rx,
            event_tx.clone(),
            selector.clone(),
            resolver.clone(),
            blocked_cancel,
            UdpTargetPermit::Ready(target_permits.clone().try_acquire_owned().unwrap()),
            session_target_permits.clone(),
        );

        let healthy_writes = Arc::new(AtomicUsize::new(0));
        let healthy_cancel = cancel_token.child_token();
        let (healthy_tx, healthy_rx) = tokio::sync::mpsc::channel(1);
        targets.insert(
            healthy.clone(),
            UdpTargetHandle {
                outbound_tx: healthy_tx,
                last_used: 2,
                generation: 2,
                cancel_token: healthy_cancel.clone(),
            },
        );
        spawn_udp_target_worker(
            healthy.clone(),
            2,
            Some(Box::new(ReplyAfterWriteMessageStream {
                writes: healthy_writes.clone(),
                written: false,
                reply_sent: false,
                read_waker: None,
            })),
            healthy_rx,
            event_tx.clone(),
            selector.clone(),
            resolver.clone(),
            healthy_cancel,
            UdpTargetPermit::Ready(target_permits.clone().try_acquire_owned().unwrap()),
            session_target_permits.clone(),
        );

        let mut use_counter = 2;
        let mut next_generation = 2;
        for (remote_location, payload) in [
            (blocked, Bytes::from_static(b"blocks forever")),
            (healthy.clone(), Bytes::from_static(b"still flows")),
        ] {
            let payload_permit = try_reserve_payload_bytes(&payload_budget, payload.len()).unwrap();
            dispatch_udp_target_command(
                &mut targets,
                &mut use_counter,
                &mut next_generation,
                UdpForwardCommand {
                    remote_location,
                    payload,
                    _payload_permit: payload_permit,
                },
                &selector,
                &resolver,
                &target_permits,
                &session_target_permits,
                &event_tx,
                &cancel_token,
            );
        }

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), event_rx.recv())
            .await
            .expect("healthy target reply must not wait for blocked target")
            .expect("target event channel remains open");
        let UdpTargetEvent::Message {
            remote_location,
            generation,
            payload,
        } = event
        else {
            panic!("healthy test target returns a message");
        };
        assert_eq!(remote_location, healthy);
        assert_eq!(generation, 2);
        assert_eq!(payload, Bytes::from_static(b"reply-a"));
        assert_eq!(healthy_writes.load(Ordering::Relaxed), 1);
        cancel_token.cancel();
    }

    #[tokio::test]
    async fn full_association_rotation_waits_for_permits_and_preserves_the_first_packet() {
        let permits = Arc::new(Semaphore::new(MAX_UDP_TARGETS_PER_SESSION));
        let session_permits = Arc::new(Semaphore::new(MAX_UDP_TARGETS_PER_SESSION));
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let mut targets = FxHashMap::default();
        let mut oldest_cancel = None;
        for port in 1..=MAX_UDP_TARGETS_PER_SESSION as u16 {
            let global_permit = permits.clone().try_acquire_owned().unwrap();
            let session_permit = session_permits.clone().try_acquire_owned().unwrap();
            let (outbound_tx, _outbound_rx) = tokio::sync::mpsc::channel(1);
            let cancel_token = CancellationToken::new();
            if port == 1 {
                oldest_cancel = Some(cancel_token.clone());
            }
            let task_cancel = cancel_token.clone();
            let task_active = active.clone();
            let current = active.fetch_add(1, Ordering::SeqCst) + 1;
            max_active.fetch_max(current, Ordering::SeqCst);
            tokio::spawn(async move {
                task_cancel.cancelled().await;
                task_active.fetch_sub(1, Ordering::SeqCst);
                drop(session_permit);
                drop(global_permit);
            });
            targets.insert(
                location(port),
                UdpTargetHandle {
                    outbound_tx,
                    last_used: port as u64,
                    generation: port as u64,
                    cancel_token,
                },
            );
        }

        let replacement = try_reserve_udp_target(&mut targets, &permits)
            .expect("a full association rotates its oldest target");
        assert!(matches!(&replacement, UdpTargetPermit::Awaiting(_)));
        assert_eq!(targets.len(), MAX_UDP_TARGETS_PER_SESSION - 1);
        assert!(oldest_cancel.unwrap().is_cancelled());

        let cancel = CancellationToken::new();
        let (session_permit, global_permit) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            acquire_udp_target_permits(replacement, session_permits.clone(), &cancel),
        )
        .await
        .unwrap()
        .expect("cancel token remains live");
        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
        max_active.fetch_max(current, Ordering::SeqCst);

        let queue_budget = Arc::new(Semaphore::new(32));
        let command = UdpForwardCommand {
            remote_location: location(5353),
            payload: Bytes::from_static(b"first-packet"),
            _payload_permit: try_reserve_payload_bytes(&queue_budget, 12).unwrap(),
        };
        let writes = Arc::new(AtomicUsize::new(0));
        let mut remote: Box<dyn AsyncMessageStream> =
            Box::new(CountingWriteMessageStream(writes.clone()));
        poll_fn(|cx| Pin::new(&mut *remote).poll_write_message(cx, &command.payload))
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut *remote).poll_flush_message(cx))
            .await
            .unwrap();
        drop(command);
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        assert_eq!(queue_budget.available_permits(), 32);
        assert_eq!(permits.available_permits(), 0);
        assert_eq!(session_permits.available_permits(), 0);
        assert_eq!(
            max_active.load(Ordering::SeqCst),
            MAX_UDP_TARGETS_PER_SESSION
        );

        active.fetch_sub(1, Ordering::SeqCst);
        drop(session_permit);
        drop(global_permit);
        drop(targets);
    }

    #[test]
    fn continuation_first_fragments_reassemble_across_uni_stream_tasks() {
        let fragments = fragment_map();
        let target = location(53);
        let non_authoritative_target = location(5353);
        assert!(
            assemble_udp_packet(
                &fragments,
                7,
                9,
                UdpRelayMode::Stream,
                2,
                1,
                Some(non_authoritative_target),
                b"world",
            )
            .unwrap()
            .is_none()
        );
        let completed = assemble_udp_packet(
            &fragments,
            7,
            9,
            UdpRelayMode::Stream,
            2,
            0,
            Some(target.clone()),
            b"hello ",
        )
        .unwrap()
        .unwrap();
        assert_eq!(completed.0, target);
        assert_eq!(completed.1, Bytes::from_static(b"hello world"));
    }

    #[test]
    fn fragment_ttl_prevents_packet_id_wraparound_mixing_and_refreshes_on_progress() {
        let started = std::time::Instant::now();
        let fragments = fragment_map();
        assert!(
            assemble_udp_packet_at(
                &fragments,
                7,
                9,
                UdpRelayMode::Stream,
                2,
                0,
                Some(location(1000)),
                b"old-head",
                started,
            )
            .unwrap()
            .is_none()
        );

        // The old fragment zero has expired. The wrapped packet's continuation
        // starts a new entry and cannot inherit the old destination or payload.
        assert!(
            assemble_udp_packet_at(
                &fragments,
                7,
                9,
                UdpRelayMode::Stream,
                2,
                1,
                Some(location(2000)),
                b"new-tail",
                started + super::UDP_FRAGMENT_TIMEOUT + std::time::Duration::from_millis(1),
            )
            .unwrap()
            .is_none()
        );
        let new_target = location(3000);
        let completed = assemble_udp_packet_at(
            &fragments,
            7,
            9,
            UdpRelayMode::Stream,
            2,
            0,
            Some(new_target.clone()),
            b"new-head",
            started + super::UDP_FRAGMENT_TIMEOUT + std::time::Duration::from_secs(1),
        )
        .unwrap()
        .unwrap();
        assert_eq!(completed.0, new_target);
        assert_eq!(completed.1, Bytes::from_static(b"new-headnew-tail"));

        // Update-on-progress semantics: each valid new continuation refreshes the TTL.
        let live = fragment_map();
        assemble_udp_packet_at(
            &live,
            8,
            10,
            UdpRelayMode::Datagram,
            3,
            1,
            None,
            b"b",
            started,
        )
        .unwrap();
        assemble_udp_packet_at(
            &live,
            8,
            10,
            UdpRelayMode::Datagram,
            3,
            2,
            None,
            b"c",
            started + std::time::Duration::from_secs(9),
        )
        .unwrap();
        let target = location(5000);
        let completed = assemble_udp_packet_at(
            &live,
            8,
            10,
            UdpRelayMode::Datagram,
            3,
            0,
            Some(target.clone()),
            b"a",
            started + std::time::Duration::from_secs(18),
        )
        .unwrap()
        .unwrap();
        assert_eq!(completed.0, target);
        assert_eq!(completed.1, Bytes::from_static(b"abc"));
    }

    #[test]
    fn invalid_and_duplicate_fragments_do_not_refresh_fragment_or_pending_ttl() {
        let started = std::time::Instant::now();
        let parent = CancellationToken::new();

        // An out-of-range continuation never mutates either lifetime.
        let invalid_registry = Arc::new(UdpSessionRegistry::new());
        let invalid_fragments = fragment_map();
        let invalid_epoch = {
            let _guard = invalid_registry.lifecycle_lock.lock().unwrap();
            invalid_registry
                .claim_packet_epoch_locked(60, UdpRelayMode::Datagram, started)
                .unwrap()
        };
        assert!(
            assemble_reserve_and_enqueue_udp_packet_at(
                &invalid_registry,
                &invalid_fragments,
                60,
                9,
                UdpRelayMode::Datagram,
                3,
                0,
                Some(location(53)),
                b"head",
                invalid_epoch,
                &parent,
                started,
            )
            .unwrap()
            .is_none()
        );
        let invalid_at = started + std::time::Duration::from_secs(9);
        assert!(
            assemble_reserve_and_enqueue_udp_packet_at(
                &invalid_registry,
                &invalid_fragments,
                60,
                9,
                UdpRelayMode::Datagram,
                3,
                3,
                None,
                b"invalid",
                invalid_epoch,
                &parent,
                invalid_at,
            )
            .is_err()
        );
        assert_eq!(
            invalid_registry
                .pending_epochs
                .lock()
                .unwrap()
                .get(&60)
                .unwrap()
                .last_update,
            started
        );
        assert_eq!(
            invalid_fragments
                .lock()
                .unwrap()
                .peek(&(60, invalid_epoch, 9))
                .unwrap()
                .last_update,
            started
        );

        let expired_at =
            started + super::UDP_FRAGMENT_TIMEOUT + std::time::Duration::from_millis(1);
        assert!(
            assemble_reserve_and_enqueue_udp_packet_at(
                &invalid_registry,
                &invalid_fragments,
                60,
                9,
                UdpRelayMode::Datagram,
                3,
                1,
                None,
                b"late",
                invalid_epoch,
                &parent,
                expired_at,
            )
            .is_err()
        );
        assert!(
            !invalid_registry
                .pending_epochs
                .lock()
                .unwrap()
                .contains_key(&60)
        );
        {
            let mut fragments = invalid_fragments.lock().unwrap();
            super::purge_expired_fragments_at(&mut fragments, expired_at);
            assert!(!fragments.contains(&(60, invalid_epoch, 9)));
        }

        // A duplicate follows the same rule. It is rejected and evicted, and it
        // cannot keep the fragment-only epoch alive by repeating before timeout.
        let duplicate_registry = Arc::new(UdpSessionRegistry::new());
        let duplicate_fragments = fragment_map();
        let duplicate_epoch = {
            let _guard = duplicate_registry.lifecycle_lock.lock().unwrap();
            duplicate_registry
                .claim_packet_epoch_locked(61, UdpRelayMode::Stream, started)
                .unwrap()
        };
        assert!(
            assemble_reserve_and_enqueue_udp_packet_at(
                &duplicate_registry,
                &duplicate_fragments,
                61,
                10,
                UdpRelayMode::Stream,
                3,
                0,
                Some(location(53)),
                b"head",
                duplicate_epoch,
                &parent,
                started,
            )
            .unwrap()
            .is_none()
        );
        assert!(
            assemble_reserve_and_enqueue_udp_packet_at(
                &duplicate_registry,
                &duplicate_fragments,
                61,
                10,
                UdpRelayMode::Stream,
                3,
                0,
                Some(location(53)),
                b"duplicate",
                duplicate_epoch,
                &parent,
                invalid_at,
            )
            .is_err()
        );
        assert!(
            !duplicate_fragments
                .lock()
                .unwrap()
                .contains(&(61, duplicate_epoch, 10))
        );
        assert_eq!(
            duplicate_registry
                .pending_epochs
                .lock()
                .unwrap()
                .get(&61)
                .unwrap()
                .last_update,
            started
        );
        assert!(
            assemble_reserve_and_enqueue_udp_packet_at(
                &duplicate_registry,
                &duplicate_fragments,
                61,
                10,
                UdpRelayMode::Stream,
                3,
                1,
                None,
                b"late",
                duplicate_epoch,
                &parent,
                expired_at,
            )
            .is_err()
        );
        assert!(
            !duplicate_registry
                .pending_epochs
                .lock()
                .unwrap()
                .contains_key(&61)
        );
    }

    #[test]
    fn legal_new_fragments_refresh_fragment_and_pending_ttl() {
        let started = std::time::Instant::now();
        let registry = Arc::new(UdpSessionRegistry::new());
        let fragments = fragment_map();
        let parent = CancellationToken::new();
        let epoch = {
            let _guard = registry.lifecycle_lock.lock().unwrap();
            registry
                .claim_packet_epoch_locked(62, UdpRelayMode::Datagram, started)
                .unwrap()
        };

        assert!(
            assemble_reserve_and_enqueue_udp_packet_at(
                &registry,
                &fragments,
                62,
                11,
                UdpRelayMode::Datagram,
                3,
                0,
                Some(location(53)),
                b"a",
                epoch,
                &parent,
                started,
            )
            .unwrap()
            .is_none()
        );
        let refreshed_at = started + std::time::Duration::from_secs(9);
        assert!(
            assemble_reserve_and_enqueue_udp_packet_at(
                &registry,
                &fragments,
                62,
                11,
                UdpRelayMode::Datagram,
                3,
                1,
                None,
                b"b",
                epoch,
                &parent,
                refreshed_at,
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(
            registry
                .pending_epochs
                .lock()
                .unwrap()
                .get(&62)
                .unwrap()
                .last_update,
            refreshed_at
        );
        assert_eq!(
            fragments
                .lock()
                .unwrap()
                .peek(&(62, epoch, 11))
                .unwrap()
                .last_update,
            refreshed_at
        );

        let completed_at = started + std::time::Duration::from_secs(18);
        let mut pending = assemble_reserve_and_enqueue_udp_packet_at(
            &registry,
            &fragments,
            62,
            11,
            UdpRelayMode::Datagram,
            3,
            2,
            None,
            b"c",
            epoch,
            &parent,
            completed_at,
        )
        .unwrap()
        .expect("valid progress at nine-second intervals keeps both TTLs alive");
        let command = pending.outbound_rx.try_recv().unwrap();
        assert_eq!(command.payload, Bytes::from_static(b"abc"));
        assert!(!registry.pending_epochs.lock().unwrap().contains_key(&62));
        dissociate_udp_session(&registry, &fragments, 62);
    }

    #[test]
    fn fragment_keys_include_association_and_mode_is_fixed() {
        let fragments = fragment_map();
        for assoc_id in [1, 2] {
            assert!(
                assemble_udp_packet(
                    &fragments,
                    assoc_id,
                    5,
                    UdpRelayMode::Datagram,
                    2,
                    0,
                    Some(location(assoc_id)),
                    &[assoc_id as u8],
                )
                .unwrap()
                .is_none()
            );
        }
        assert!(
            assemble_udp_packet(&fragments, 1, 5, UdpRelayMode::Stream, 2, 1, None, b"x",).is_err()
        );
        assert!(
            assemble_udp_packet(&fragments, 1, 5, UdpRelayMode::Datagram, 2, 1, None, b"a",)
                .unwrap()
                .is_none()
        );
        let first = assemble_udp_packet(
            &fragments,
            1,
            5,
            UdpRelayMode::Datagram,
            2,
            0,
            Some(location(1)),
            &[1],
        )
        .unwrap()
        .unwrap();
        let second =
            assemble_udp_packet(&fragments, 2, 5, UdpRelayMode::Datagram, 2, 1, None, b"b")
                .unwrap()
                .unwrap();
        assert_eq!(first.1, Bytes::from_static(&[1, b'a']));
        assert_eq!(second.1, Bytes::from_static(&[2, b'b']));
    }

    #[test]
    fn oversized_fragment_aggregate_is_rejected_and_evicted() {
        let fragments = fragment_map();
        let first = vec![0u8; 40_000];
        let second = vec![0u8; 30_000];
        assert!(
            assemble_udp_packet(
                &fragments,
                8,
                1,
                UdpRelayMode::Datagram,
                2,
                0,
                Some(location(53)),
                &first,
            )
            .unwrap()
            .is_none()
        );
        assert!(
            assemble_udp_packet(
                &fragments,
                8,
                1,
                UdpRelayMode::Datagram,
                2,
                1,
                None,
                &second,
            )
            .is_err()
        );
        assert!(!fragments.lock().unwrap().contains(&(8, 0, 1)));
        assert_eq!(
            checked_udp_packet_len(MAX_UDP_PACKET_SIZE - 1, 1).unwrap(),
            MAX_UDP_PACKET_SIZE
        );
        assert!(checked_udp_packet_len(MAX_UDP_PACKET_SIZE, 1).is_err());
    }

    #[test]
    fn pending_dissociate_cancels_and_cannot_resurrect_old_generation() {
        let registry = Arc::new(UdpSessionRegistry::new());
        let fragments = fragment_map();
        let parent = CancellationToken::new();
        let first = registry
            .reserve(12, UdpRelayMode::Stream, true, &parent)
            .unwrap();
        let UdpSessionReservation::Created {
            cancel_token,
            generation: old_generation,
            ..
        } = first
        else {
            panic!("first reservation must create");
        };
        dissociate_udp_session(&registry, &fragments, 12);
        assert!(cancel_token.is_cancelled());

        let second = registry
            .reserve(12, UdpRelayMode::Stream, true, &parent)
            .unwrap();
        let UdpSessionReservation::Created {
            generation: new_generation,
            ..
        } = second
        else {
            panic!("id reuse must create a new generation");
        };
        assert_ne!(old_generation, new_generation);
        assert!(!registry.promote(12, old_generation));
        assert!(registry.promote(12, new_generation));
    }

    #[test]
    fn stale_generation_cleanup_cannot_erase_reused_association_fragments() {
        let registry = Arc::new(UdpSessionRegistry::new());
        let fragments = fragment_map();
        let parent = CancellationToken::new();
        let old = registry
            .reserve(12, UdpRelayMode::Datagram, true, &parent)
            .unwrap();
        let UdpSessionReservation::Created {
            generation: old_generation,
            ..
        } = old
        else {
            panic!("first reservation must create");
        };
        assert!(
            assemble_udp_packet(
                &fragments,
                12,
                1,
                UdpRelayMode::Datagram,
                2,
                0,
                Some(location(53)),
                b"old",
            )
            .unwrap()
            .is_none()
        );
        dissociate_udp_session(&registry, &fragments, 12);

        let new = registry
            .reserve(12, UdpRelayMode::Datagram, true, &parent)
            .unwrap();
        let UdpSessionReservation::Created {
            generation: new_generation,
            ..
        } = new
        else {
            panic!("reused association id must create a new generation");
        };
        assert_ne!(old_generation, new_generation);
        assert!(
            assemble_udp_packet(
                &fragments,
                12,
                2,
                UdpRelayMode::Datagram,
                2,
                0,
                Some(location(5353)),
                b"new",
            )
            .unwrap()
            .is_none()
        );

        // This is the delayed completion callback from the old worker. The
        // generation check and lifecycle lock make it a no-op for generation N+1.
        remove_udp_generation(&registry, &fragments, 12, old_generation);
        assert!(fragments.lock().unwrap().contains(&(12, 0, 2)));
    }

    #[test]
    fn successful_downlink_touch_is_generation_safe_and_prevents_idle_reap() {
        let registry = Arc::new(UdpSessionRegistry::new());
        let fragments = fragment_map();
        let parent = CancellationToken::new();
        let reservation = registry
            .reserve(44, UdpRelayMode::Datagram, true, &parent)
            .unwrap();
        let generation = match reservation {
            UdpSessionReservation::Created { generation, .. } => generation,
            UdpSessionReservation::Existing { .. } => unreachable!(),
        };
        let old =
            std::time::Instant::now() - super::IDLE_TIMEOUT - std::time::Duration::from_secs(1);
        registry.sessions.get_mut(&44).unwrap().last_activity = old;

        assert!(!registry.touch_generation_at(
            44,
            generation.wrapping_add(1),
            std::time::Instant::now()
        ));
        assert_eq!(registry.sessions.get(&44).unwrap().last_activity, old);
        assert!(registry.touch_generation_at(44, generation, std::time::Instant::now()));

        remove_inactive_udp_sessions(&registry, &fragments);
        assert!(registry.sessions.contains_key(&44));
    }

    #[test]
    fn pending_and_ready_sessions_share_an_exact_512_budget() {
        let registry = UdpSessionRegistry::new();
        let parent = CancellationToken::new();
        let mut reservations = Vec::new();
        for assoc_id in 0..MAX_UDP_SESSIONS as u16 {
            reservations.push(
                registry
                    .reserve(assoc_id, UdpRelayMode::Datagram, true, &parent)
                    .unwrap(),
            );
        }
        assert!(
            registry
                .reserve(
                    MAX_UDP_SESSIONS as u16,
                    UdpRelayMode::Datagram,
                    true,
                    &parent
                )
                .is_err()
        );
        assert!(matches!(
            registry
                .reserve(0, UdpRelayMode::Datagram, true, &parent)
                .unwrap(),
            UdpSessionReservation::Existing { .. }
        ));
        drop(reservations);
    }

    #[test]
    fn association_relay_mode_cannot_change() {
        let registry = UdpSessionRegistry::new();
        let parent = CancellationToken::new();
        let _reservation = registry
            .reserve(3, UdpRelayMode::Stream, true, &parent)
            .unwrap();
        assert!(registry.validate_mode(3, UdpRelayMode::Datagram).is_err());
        assert!(
            registry
                .reserve(3, UdpRelayMode::Datagram, true, &parent)
                .is_err()
        );
    }

    #[test]
    fn dissociate_while_packet_task_is_paused_prevents_old_epoch_resurrection() {
        let registry = Arc::new(UdpSessionRegistry::new());
        let fragments = fragment_map();
        let parent = CancellationToken::new();
        let old_epoch = registry
            .claim_packet_epoch(30, UdpRelayMode::Datagram)
            .unwrap();

        // Model a packet task paused after parsing the association id, while a
        // concurrent DISSOCIATE invalidates the epoch it captured.
        dissociate_udp_session(&registry, &fragments, 30);
        assert!(
            assemble_reserve_and_enqueue_udp_packet(
                &registry,
                &fragments,
                30,
                1,
                UdpRelayMode::Datagram,
                1,
                0,
                Some(location(53)),
                b"old-packet",
                old_epoch,
                &parent,
            )
            .is_err()
        );
        assert!(!registry.sessions.contains_key(&30));
        assert!(!fragments.lock().unwrap().iter().any(|(key, _)| key.0 == 30));

        let new_epoch = registry
            .claim_packet_epoch(30, UdpRelayMode::Datagram)
            .unwrap();
        assert_ne!(old_epoch, new_epoch);
        let pending = assemble_reserve_and_enqueue_udp_packet(
            &registry,
            &fragments,
            30,
            1,
            UdpRelayMode::Datagram,
            1,
            0,
            Some(location(53)),
            b"new-packet",
            new_epoch,
            &parent,
        )
        .unwrap()
        .expect("a fresh epoch may create the reused association");
        assert_eq!(pending.generation, new_epoch);
        assert!(registry.sessions.contains_key(&30));
        drop(pending);
        dissociate_udp_session(&registry, &fragments, 30);
    }

    #[test]
    fn same_mode_continuations_cannot_cross_a_dissociate_epoch() {
        let registry = Arc::new(UdpSessionRegistry::new());
        let fragments = fragment_map();
        let parent = CancellationToken::new();
        let old_epoch = registry
            .claim_packet_epoch(31, UdpRelayMode::Datagram)
            .unwrap();

        assert!(
            assemble_reserve_and_enqueue_udp_packet(
                &registry,
                &fragments,
                31,
                7,
                UdpRelayMode::Datagram,
                2,
                1,
                Some(location(5353)),
                b"old-tail",
                old_epoch,
                &parent,
            )
            .unwrap()
            .is_none()
        );
        assert!(fragments.lock().unwrap().contains(&(31, old_epoch, 7)));
        dissociate_udp_session(&registry, &fragments, 31);
        assert!(!fragments.lock().unwrap().iter().any(|(key, _)| key.0 == 31));

        let new_epoch = registry
            .claim_packet_epoch(31, UdpRelayMode::Datagram)
            .unwrap();
        assert_ne!(old_epoch, new_epoch);

        assert!(
            assemble_reserve_and_enqueue_udp_packet(
                &registry,
                &fragments,
                31,
                7,
                UdpRelayMode::Datagram,
                2,
                0,
                Some(location(53)),
                b"new-head",
                new_epoch,
                &parent,
            )
            .unwrap()
            .is_none()
        );
        assert!(fragments.lock().unwrap().contains(&(31, new_epoch, 7)));

        // A continuation that was already in flight before DISSOCIATE keeps its
        // old epoch and cannot complete (or poison) the new partial packet.
        assert!(
            assemble_reserve_and_enqueue_udp_packet(
                &registry,
                &fragments,
                31,
                7,
                UdpRelayMode::Datagram,
                2,
                1,
                None,
                b"old-tail",
                old_epoch,
                &parent,
            )
            .is_err()
        );
        assert!(fragments.lock().unwrap().contains(&(31, new_epoch, 7)));

        let mut pending = assemble_reserve_and_enqueue_udp_packet(
            &registry,
            &fragments,
            31,
            7,
            UdpRelayMode::Datagram,
            2,
            1,
            Some(location(5353)),
            b"new-tail",
            new_epoch,
            &parent,
        )
        .unwrap()
        .expect("only fragments from the new epoch complete the packet");
        assert_eq!(pending.generation, new_epoch);
        let command = pending.outbound_rx.try_recv().unwrap();
        assert_eq!(command.remote_location, location(53));
        assert_eq!(command.payload, Bytes::from_static(b"new-headnew-tail"));
        dissociate_udp_session(&registry, &fragments, 31);
    }

    #[test]
    fn lifecycle_transaction_rejects_a_stale_other_mode_packet() {
        let registry = Arc::new(UdpSessionRegistry::new());
        let fragments = fragment_map();
        let parent = CancellationToken::new();
        let stale_epoch = registry
            .claim_packet_epoch(32, UdpRelayMode::Stream)
            .unwrap();
        registry
            .reserve(32, UdpRelayMode::Datagram, true, &parent)
            .unwrap();
        assert!(
            assemble_reserve_and_enqueue_udp_packet(
                &registry,
                &fragments,
                32,
                1,
                UdpRelayMode::Stream,
                2,
                0,
                Some(location(53)),
                b"stale",
                stale_epoch,
                &parent,
            )
            .is_err()
        );
        assert!(!fragments.lock().unwrap().iter().any(|(key, _)| key.0 == 32));
    }

    #[test]
    fn slow_association_queue_drops_instead_of_blocking() {
        let registry = Arc::new(UdpSessionRegistry::new());
        let fragments = fragment_map();
        let parent = CancellationToken::new();
        let reservation = registry
            .reserve(4, UdpRelayMode::Datagram, true, &parent)
            .unwrap();
        let UdpSessionReservation::Created {
            outbound_tx,
            outbound_rx,
            generation,
            ..
        } = reservation
        else {
            panic!("first reservation must create");
        };
        let payload_budget = registry.queued_payload_permits.clone();
        for _ in 0..super::UDP_SESSION_QUEUE_CAPACITY {
            outbound_tx
                .try_send(UdpForwardCommand {
                    remote_location: location(53),
                    payload: Bytes::from_static(b"x"),
                    _payload_permit: try_reserve_payload_bytes(&payload_budget, 1).unwrap(),
                })
                .unwrap();
        }
        try_enqueue_udp_packet(
            &registry,
            &fragments,
            4,
            generation,
            outbound_tx,
            UdpForwardCommand {
                remote_location: location(53),
                payload: Bytes::from_static(b"dropped"),
                _payload_permit: try_reserve_payload_bytes(&payload_budget, 7).unwrap(),
            },
        );
        assert_eq!(outbound_rx.len(), super::UDP_SESSION_QUEUE_CAPACITY);
    }

    #[test]
    fn slow_response_handoff_never_accumulates_one_payload_per_target() {
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(1);
        let cancel = CancellationToken::new();
        assert!(publish_udp_target_event(
            &event_tx,
            &cancel,
            UdpTargetEvent::Message {
                remote_location: location(53),
                generation: 1,
                payload: Bytes::from(vec![1; MAX_UDP_PACKET_SIZE]),
            },
        ));
        // A full handoff drops immediately; no target task awaits while retaining
        // this second maximum-sized payload.
        assert!(publish_udp_target_event(
            &event_tx,
            &cancel,
            UdpTargetEvent::Message {
                remote_location: location(5353),
                generation: 2,
                payload: Bytes::from(vec![2; MAX_UDP_PACKET_SIZE]),
            },
        ));
        assert_eq!(event_rx.len(), 1);
        let UdpTargetEvent::Message { payload, .. } = event_rx.try_recv().unwrap() else {
            panic!("the first event remains buffered");
        };
        assert_eq!(payload[0], 1);
    }

    #[test]
    fn queued_payload_budget_is_connection_wide_and_counts_zero_length() {
        let budget = Arc::new(Semaphore::new(3));
        let two = try_reserve_payload_bytes(&budget, 2).unwrap();
        let zero = try_reserve_payload_bytes(&budget, 0).unwrap();
        assert!(try_reserve_payload_bytes(&budget, 1).is_none());
        drop(two);
        assert!(try_reserve_payload_bytes(&budget, 2).is_some());
        drop(zero);
    }

    #[test]
    fn uni_command_gate_has_an_exact_in_flight_limit() {
        let gate = Arc::new(Semaphore::new(MAX_IN_FLIGHT_UNI_COMMANDS));
        let permits: Vec<_> = (0..MAX_IN_FLIGHT_UNI_COMMANDS)
            .map(|_| gate.clone().try_acquire_owned().unwrap())
            .collect();
        assert!(gate.clone().try_acquire_owned().is_err());
        drop(permits);
        assert_eq!(gate.available_permits(), MAX_IN_FLIGHT_UNI_COMMANDS);
    }

    #[test]
    fn association_operational_and_post_decode_errors_are_not_connection_fatal() {
        assert!(!absorb_udp_activation_error(
            7,
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "routing block",
            )),
        ));
        assert!(
            absorb_udp_packet_error(7, Err(std::io::Error::other("duplicate fragment"))).is_ok()
        );
    }

    #[tokio::test]
    async fn cancelled_prefilled_command_never_writes() {
        let queue_budget = Arc::new(Semaphore::new(16));
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(UdpForwardCommand {
            remote_location: location(53),
            payload: Bytes::from_static(b"queued"),
            _payload_permit: try_reserve_payload_bytes(&queue_budget, 6).unwrap(),
        })
        .unwrap();

        let writes = Arc::new(AtomicUsize::new(0));
        let target_budget = Arc::new(Semaphore::new(1));
        let selector = Arc::new(super::ClientProxySelector::new(Vec::new()));
        let resolver: Arc<dyn super::Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let cancel = CancellationToken::new();
        cancel.cancel();
        let (event_tx, _event_rx) = tokio::sync::mpsc::channel(1);
        run_udp_target_worker(
            location(53),
            1,
            Some(Box::new(CountingWriteMessageStream(writes.clone()))),
            rx,
            event_tx,
            selector,
            resolver,
            cancel,
            UdpTargetPermit::Ready(target_budget.clone().try_acquire_owned().unwrap()),
            Arc::new(Semaphore::new(MAX_UDP_TARGETS_PER_SESSION)),
        )
        .await;
        assert_eq!(writes.load(Ordering::Relaxed), 0);
        assert_eq!(queue_budget.available_permits(), 16);
    }

    #[tokio::test]
    async fn cancellation_interrupts_a_pending_quic_response() {
        let token = CancellationToken::new();
        let task_token = token.clone();
        let task = tokio::spawn(async move {
            await_udp_response_or_cancel(&task_token, pending::<std::io::Result<()>>()).await
        });
        token.cancel();
        assert!(!task.await.unwrap().unwrap());
    }

    #[test]
    fn dissociate_cleanup_removes_only_its_fragment_state() {
        let fragments = fragment_map();
        for assoc_id in [1, 2] {
            assert!(
                assemble_udp_packet(
                    &fragments,
                    assoc_id,
                    1,
                    UdpRelayMode::Datagram,
                    2,
                    0,
                    Some(location(53)),
                    b"x",
                )
                .unwrap()
                .is_none()
            );
        }
        remove_assoc_fragments(&fragments, 1);
        let fragments = fragments.lock().unwrap();
        assert!(!fragments.contains(&(1, 0, 1)));
        assert!(fragments.contains(&(2, 0, 1)));
    }

    #[test]
    fn rejects_truncated_payload_after_omitted_address() {
        let error = checked_payload_end(11, 11, 1).expect_err("payload is absent");
        assert!(error.to_string().contains("truncated payload"));
    }

    #[test]
    fn accepts_payload_that_exactly_fills_datagram() {
        assert_eq!(checked_payload_end(18, 11, 7).unwrap(), 18);
    }

    #[test]
    fn rejects_trailing_datagram_payload_bytes() {
        let error = checked_payload_end(19, 11, 7).expect_err("one trailing byte");
        assert!(error.to_string().contains("trailing bytes"));
    }

    #[test]
    fn rejects_payload_offset_overflow() {
        let error = checked_payload_end(usize::MAX, usize::MAX, 1)
            .expect_err("offset addition must be checked");
        assert!(error.to_string().contains("length overflow"));
    }

    #[test]
    fn tcp_logical_flow_gate_rejects_257th_and_reopens_after_release() {
        let gate = Arc::new(Semaphore::new(MAX_ACTIVE_TCP_LOGICAL_FLOWS));
        let mut permits: Vec<_> = (0..MAX_ACTIVE_TCP_LOGICAL_FLOWS)
            .map(|_| try_admit_tcp_logical_flow(&gate).expect("flow is within the limit"))
            .collect();

        assert!(try_admit_tcp_logical_flow(&gate).is_none());
        drop(permits.pop());
        assert!(try_admit_tcp_logical_flow(&gate).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn slow_tcp_header_progress_does_not_extend_absolute_deadline() {
        let deadline = Instant::now() + TCP_REQUEST_HEADER_TIMEOUT;
        let task = tokio::spawn(async move {
            read_tcp_request_header_before_deadline(deadline, async {
                for _ in 0..100 {
                    // Models a drip-fed CONNECT header: each individual read makes
                    // progress within a second, but the complete header never does.
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Ok::<(), std::io::Error>(())
            })
            .await
        });
        tokio::task::yield_now().await;

        for _ in 0..14 {
            advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
            assert!(!task.is_finished());
        }
        advance(Duration::from_secs(1)).await;
        let error = task
            .await
            .expect("header task must not panic")
            .expect_err("the absolute deadline must expire");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn fragmented_datagram_response_stops_after_dissociate_cancels_generation() {
        let cancel = CancellationToken::new();
        let cancel_from_other_task = cancel.clone();
        let (first_fragment_tx, first_fragment_rx) = tokio::sync::oneshot::channel();
        let cancel_task = tokio::spawn(async move {
            first_fragment_rx
                .await
                .expect("the first fragment callback notifies DISSOCIATE");
            cancel_from_other_task.cancel();
        });
        let mut first_fragment_tx = Some(first_fragment_tx);
        let mut sent = Vec::new();

        send_udp_datagram_fragments_with(
            7,
            &None,
            11,
            &location(53),
            &[0x5a; 64],
            24,
            &cancel,
            |_fragment_id, datagram| {
                sent.push(datagram);
                if let Some(first_fragment_tx) = first_fragment_tx.take() {
                    first_fragment_tx
                        .send(())
                        .expect("DISSOCIATE task is waiting for the first fragment");
                }
                Ok(())
            },
        )
        .await
        .unwrap();
        cancel_task.await.expect("DISSOCIATE task must not panic");

        assert_eq!(sent.len(), 1, "no stale-generation fragment follows cancel");
    }

    #[tokio::test]
    async fn cancelled_single_datagram_response_never_reaches_wire() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let mut writes = 0;

        send_udp_datagram_fragments_with(
            7,
            &None,
            12,
            &location(53),
            b"fits",
            1200,
            &cancel,
            |_fragment_id, _datagram| {
                writes += 1;
                Ok(())
            },
        )
        .await
        .unwrap();

        assert_eq!(writes, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn metered_datagram_send_failure_and_cancellation_are_not_charged() {
        const RATE_BPS: u64 = 8 * 64 * 1024;

        let user = UserContext::new("alice");
        user.set_speed_limits(0, RATE_BPS);
        let conn = ConnContext::new();
        assert!(conn.bind(Arc::clone(&user)));
        let meter = Some(conn);
        let source = location(53);
        let payload = vec![0x5a; 65_000];

        send_udp_datagram_fragments_with(
            7,
            &meter,
            13,
            &source,
            &payload,
            65_535,
            &CancellationToken::new(),
            |_fragment_id, _datagram| Err(std::io::Error::other("modeled send failure")),
        )
        .await
        .expect_err("the modeled Quinn send must fail");
        assert_eq!(user.tx(), 0);

        let start = Instant::now();
        let mut sent_len = 0;
        send_udp_datagram_fragments_with(
            7,
            &meter,
            14,
            &source,
            &payload,
            65_535,
            &CancellationToken::new(),
            |_fragment_id, datagram| {
                sent_len += datagram.len();
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(Instant::now(), start);
        assert_eq!(user.tx(), sent_len as u64);

        let cancel = CancellationToken::new();
        let mut writes = 0;
        {
            let pending = send_udp_datagram_fragments_with(
                7,
                &meter,
                15,
                &source,
                &payload,
                65_535,
                &cancel,
                |_fragment_id, _datagram| {
                    writes += 1;
                    Ok(())
                },
            );
            tokio::pin!(pending);
            assert!(futures::poll!(pending.as_mut()).is_pending());
            cancel.cancel();
            pending.await.unwrap();
        }
        assert_eq!(writes, 0);
        assert_eq!(user.tx(), sent_len as u64);
    }
}
