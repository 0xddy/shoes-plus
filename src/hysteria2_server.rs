use lru::LruCache;
use std::collections::hash_map::Entry;
use std::future::Future;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::str;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures::future::poll_fn;
use log::{debug, warn};
use rand::distr::Alphanumeric;
use rand::{Rng, RngExt};
use rustc_hash::FxHashMap;
use tokio::io::{AsyncWriteExt, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;

/// Maximum number of fragmented packets to track per connection.
/// Old entries are automatically evicted when this limit is reached.
const MAX_FRAGMENT_CACHE_SIZE: usize = 256;

/// Authentication timeout - close connection if client doesn't authenticate within this time.
/// Default is 3 seconds per sing-box reference implementation.
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum number of authenticated TCP logical flows one physical Hysteria2
/// connection may process concurrently.
///
/// Quinn enforces the same advertised stream ceiling, while the semaphore below
/// remains the application-owned backstop and covers work after the peer has
/// finished uploading its stream bytes but DNS, outbound setup, or copying is still
/// alive.
const MAX_ACTIVE_TCP_LOGICAL_FLOWS: usize = 256;

/// Absolute time allowed to deliver one Hysteria2 TCP request header after its QUIC
/// stream is accepted. Progress does not reset this deadline.
const TCP_REQUEST_HEADER_TIMEOUT: Duration = Duration::from_secs(15);

/// Application error code used to refuse a peer-opened TCP stream after the
/// connection-local logical-flow budget is exhausted.
const TCP_FLOW_LIMIT_ERROR_CODE: u32 = 0x01;

/// Maximum number of concurrent UDP sessions one connection may hold open.
///
/// A session is not free: it owns a client-side UDP socket, a spawned task, and
/// that task's 64 KiB receive buffer. The session id is a client-chosen `u32`, so
/// without a ceiling here an authenticated client can name four billion of them and
/// the only thing bounding the cost is how fast it can send datagrams. That is a
/// file-descriptor exhaustion long before it is a memory one, and on a shared
/// inbound it takes every other user's connections down with it.
///
/// 512 leaves the ceiling well above what a real client reaches -- each session is
/// one destination flow, and even a busy peer-to-peer workload sits far below it --
/// while capping one connection at roughly 32 MiB and 512 descriptors.
const MAX_UDP_SESSIONS: usize = 512;

/// Bound packets queued behind one outbound association. The old direct socket
/// path applied backpressure in `send_to`; a bounded channel preserves that
/// property when a proxy transport owns the write side in another task.
const UDP_SESSION_QUEUE_CAPACITY: usize = 64;

/// Commands for one fixed target are serialized by that target's owner task.
/// Keeping this much smaller than the association queue prevents one stalled
/// destination from absorbing the whole connection byte budget.
const UDP_TARGET_QUEUE_CAPACITY: usize = 8;

/// Remote replies are best-effort UDP. A single-slot handoff keeps target tasks
/// independent without multiplying 64 KiB response buffers by every target.
const UDP_TARGET_RESPONSE_CAPACITY: usize = 1;

/// Hysteria associations are full-cone: one id may legitimately talk to many
/// destinations. Keep enough fixed-target transports for normal DNS/P2P traffic,
/// while preventing one association from opening an unbounded proxy fan-out.
const MAX_UDP_TARGETS_PER_SESSION: usize = 64;

/// Bound fixed-target outbound transports across every association on one QUIC
/// connection. The per-association ceiling alone still permits 32768 sockets.
const MAX_UDP_TARGETS_PER_CONNECTION: usize = 1024;

/// Upper bound for one reassembled UDP payload.
const MAX_UDP_PACKET_SIZE: usize = u16::MAX as usize;

/// One connection's incomplete UDP fragments are bounded independently of the
/// number of client-chosen session ids.
const MAX_UDP_FRAGMENT_BYTES_PER_CONNECTION: usize = 8 * 1024 * 1024;

/// Incomplete datagrams must not survive long enough to collide with a wrapped
/// packet id from a later generation of the same association.
const UDP_FRAGMENT_TIMEOUT: Duration = Duration::from_secs(10);

const UDP_SESSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Bytes waiting in, or currently being written by, all association workers on
/// one authenticated connection.
const MAX_UDP_QUEUED_BYTES_PER_CONNECTION: usize = 16 * 1024 * 1024;

/// HTTP/3 error code for normal closure.
/// Per official hysteria reference: https://github.com/apernet/hysteria/blob/master/core/server/server.go#L20
const CLOSE_ERR_CODE_OK: u32 = 0x100; // HTTP3 ErrCodeNoError

use crate::address::NetLocation;
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::copy_bidirectional::copy_bidirectional_with_sizes;
use crate::dynamic::{
    ConnContext, SelectorSlot, TrafficMeterStream, UserContext, UserRegistry,
    scope_connection_until_cancelled,
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
use crate::util::allocate_vec;

/// The accounting record for one authenticated QUIC connection, or `None` when the
/// inbound is not metered.
///
/// Hysteria2 multiplexes every proxied stream and datagram over a single QUIC
/// connection, and it authenticates once, up front, before any of them exist. So
/// unlike the TCP path there is no anonymous phase to hand over: one context is
/// bound to its user immediately and then shared by every loop below.
///
/// It travels as an explicit parameter because each loop runs in a task of its own.
/// Every logical TCP task installs it with
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
            "Hysteria2 TCP request header timed out",
        )),
    }
}

/// Decode the QUIC-varint address length at byte 8 of a Hysteria UDP datagram.
///
/// The first nine bytes are fixed-width through the first varint byte. Returning
/// `None` for a truncated multi-byte varint lets the datagram loop discard hostile
/// input without ever constructing an out-of-bounds slice.
fn decode_udp_address_length(data: &[u8]) -> Option<(usize, usize)> {
    let first_byte = *data.get(8)?;
    let num_bytes = 1usize << (first_byte >> 6);
    let mut value = u64::from(first_byte & 0b0011_1111);
    let next_index = 8usize.checked_add(num_bytes)?;

    for byte in data.get(9..next_index)? {
        value = (value << 8) | u64::from(*byte);
    }

    Some((usize::try_from(value).ok()?, next_index))
}

#[inline]
fn valid_udp_fragment(fragment_id: u8, fragment_count: u8) -> bool {
    fragment_count != 0 && fragment_id < fragment_count
}

fn checked_udp_packet_len(current: usize, fragment_len: usize) -> Option<usize> {
    current
        .checked_add(fragment_len)
        .filter(|length| *length <= MAX_UDP_PACKET_SIZE)
}

fn try_reserve_payload_bytes(
    budget: &Arc<Semaphore>,
    payload_len: usize,
) -> Option<OwnedSemaphorePermit> {
    let permits = u32::try_from(payload_len.max(1)).ok()?;
    budget.clone().try_acquire_many_owned(permits).ok()
}

fn checked_response_fragment_count(
    payload_len: usize,
    available_payload: usize,
) -> std::io::Result<u8> {
    let fragment_count = payload_len.div_ceil(available_payload);
    u8::try_from(fragment_count).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Hysteria2 UDP response needs {fragment_count} fragments, protocol limit is {}",
                u8::MAX
            ),
        )
    })
}

#[inline]
fn udp_response_send_allowed(cancel_token: &CancellationToken) -> bool {
    !cancel_token.is_cancelled()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpResponseSendOutcome {
    Sent,
    Cancelled,
    DroppedTooLarge {
        planned_max_datagram_size: usize,
        current_max_datagram_size: Option<usize>,
        attempted_datagram_len: usize,
        fragment_id: u8,
        fragment_count: u8,
    },
}

#[allow(clippy::too_many_arguments)]
async fn send_udp_response_with<M, S>(
    session_id: u32,
    meter: &Meter,
    packet_id: u16,
    source: &NetLocation,
    payload: &[u8],
    cancel_token: &CancellationToken,
    mut max_datagram_size: M,
    mut send_datagram: S,
) -> std::io::Result<UdpResponseSendOutcome>
where
    M: FnMut() -> Option<usize>,
    S: FnMut(Bytes) -> Result<(), quinn::SendDatagramError>,
{
    // Quinn's application datagram limit can change with the path MTU. Take one
    // fresh snapshot for this logical packet so every fragment uses the same
    // boundaries and fragment count.
    let planned_max_datagram_size = max_datagram_size()
        .ok_or_else(|| std::io::Error::other("datagram not supported by remote endpoint"))?;
    let payload_len = payload.len();
    let address_bytes: Bytes = source.to_string().into_bytes().into();
    let address_len_bytes: Bytes = encode_varint(address_bytes.len() as u64)?.into();

    // session id (4) + packet id (2) + fragment id (1) + fragment count (1)
    // + address length varint + address bytes
    let header_overhead = 4 + 2 + 1 + 1 + address_len_bytes.len() + address_bytes.len();
    if planned_max_datagram_size <= header_overhead {
        return Err(std::io::Error::other(format!(
            "the requested destination needs {header_overhead} header bytes, which does not \
             fit a {planned_max_datagram_size} byte datagram"
        )));
    }

    let available_payload = planned_max_datagram_size - header_overhead;
    let fragment_count = if payload_len <= available_payload {
        1
    } else {
        checked_response_fragment_count(payload_len, available_payload)?
    };

    for fragment_id in 0..fragment_count {
        let start = (fragment_id as usize) * available_payload;
        let end = std::cmp::min(start + available_payload, payload_len);
        let mut datagram = BytesMut::with_capacity(header_overhead + (end - start));
        datagram.extend_from_slice(&session_id.to_be_bytes());
        datagram.extend_from_slice(&packet_id.to_be_bytes());
        datagram.extend_from_slice(&[fragment_id, fragment_count]);
        datagram.extend_from_slice(&address_len_bytes);
        datagram.extend_from_slice(&address_bytes);
        datagram.extend_from_slice(&payload[start..end]);

        if !udp_response_send_allowed(cancel_token) {
            return Ok(UdpResponseSendOutcome::Cancelled);
        }
        let datagram = datagram.freeze();
        let datagram_len = datagram.len();
        let permit = if let Some(meter) = meter {
            Some(tokio::select! {
                biased;
                _ = cancel_token.cancelled() => {
                    return Ok(UdpResponseSendOutcome::Cancelled);
                }
                permit = meter.admit_datagram_tx(datagram_len) => permit,
            })
        } else {
            None
        };
        // Cancellation can race with allowance becoming ready. Do not put the
        // datagram on the wire in that case; dropping `permit` refunds it.
        if !udp_response_send_allowed(cancel_token) {
            return Ok(UdpResponseSendOutcome::Cancelled);
        }
        match send_datagram(datagram) {
            Ok(()) => {}
            // A path-MTU change between the snapshot above and this write is a
            // loss of this UDP packet, not a failure of the association.
            Err(quinn::SendDatagramError::TooLarge) => {
                return Ok(UdpResponseSendOutcome::DroppedTooLarge {
                    planned_max_datagram_size,
                    current_max_datagram_size: max_datagram_size(),
                    attempted_datagram_len: datagram_len,
                    fragment_id,
                    fragment_count,
                });
            }
            Err(error) => {
                return Err(std::io::Error::other(format!(
                    "Failed to send datagram fragment {fragment_id}: {error}"
                )));
            }
        }
        if let Some(permit) = permit {
            permit.commit();
        }
    }

    Ok(UdpResponseSendOutcome::Sent)
}

#[derive(Clone)]
struct Hysteria2ConnectionSettings {
    users: Arc<dyn UserRegistry>,
    metered: bool,
    udp_enabled: bool,
    up_mbps: u64,
    down_mbps: u64,
    ignore_client_bandwidth: bool,
    masquerade: Arc<crate::hysteria2_masquerade::Hysteria2Masquerade>,
}

async fn process_connection(
    selector: Arc<SelectorSlot>,
    conn: quinn::Incoming,
    settings: Hysteria2ConnectionSettings,
    handshake_permit: HandshakePermit,
    pre_auth_deadline: Instant,
    connection_cancel: CancellationToken,
) -> std::io::Result<()> {
    // Each physical transport has its own child below the inbound hard-stop token.
    // The guard also cancels it when QUIC ends naturally, so logical TCP tasks that
    // are between client I/O operations cannot outlive their transport.
    let connection_lifecycle = QuicConnectionLifecycle::new(&connection_cancel);
    // Metered peers bind this record after authentication; unmetered peers leave it
    // anonymous, but still use it for hard-stop and natural-exit cancellation.
    let lifecycle = ConnContext::new_child(connection_lifecycle.token());
    let transport_deadline = std::cmp::min(
        pre_auth_deadline,
        Instant::now() + QUIC_TRANSPORT_HANDSHAKE_TIMEOUT,
    );
    let transport_result = tokio::select! {
        biased;
        () = lifecycle.cancelled() => {
            return Err(connection_lifecycle_cancelled_error());
        }
        result = timeout_at(transport_deadline, conn) => result,
    };
    let connection = match transport_result {
        Ok(result) => result?,
        Err(_elapsed) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Hysteria2 QUIC handshake exceeded the pre-auth deadline",
            ));
        }
    };

    // Create a cancellation token for the entire connection lifecycle.
    // When cancelled, all spawned tasks (UDP sessions) will terminate gracefully.
    let cancel_token = connection_lifecycle.token().child_token();
    // `process_connection` has several early returns and drives attacker-controlled
    // parsers. Keep cleanup exception-safe: unwinding or dropping this future must
    // cancel every child token even when control never reaches the normal epilogue.
    let _cancel_guard = cancel_token.clone().drop_guard();

    // we unfortunately need to keep the h3 connection around because it closes the underlying
    // connection on drop, see
    // https://github.com/hyperium/h3/blob/dbf2523d26e115f096b66cdd8a6f68127a17a156/h3/src/server/connection.rs#L427
    //
    // we keep this function waiting for the tcp and udp tasks both to finish before dropping,
    // instead of passing the connection to one of the two loops, incase one finishes first.
    let h3_quinn_connection = h3_quinn::Connection::new(connection.clone());

    let h3_setup_deadline = std::cmp::min(
        pre_auth_deadline,
        Instant::now() + QUIC_TRANSPORT_HANDSHAKE_TIMEOUT,
    );
    let h3_setup_result = tokio::select! {
        biased;
        () = lifecycle.cancelled() => {
            connection.close(CLOSE_ERR_CODE_OK.into(), b"connection cancelled");
            return Err(connection_lifecycle_cancelled_error());
        }
        result = timeout_at(
            h3_setup_deadline,
            h3::server::Connection::new(h3_quinn_connection),
        ) => result,
    };
    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
        match h3_setup_result {
            Ok(Ok(connection)) => connection,
            Ok(Err(e)) => {
                return Err(std::io::Error::other(format!(
                    "H3 connection setup failed: {e}"
                )));
            }
            Err(_elapsed) => {
                connection.close(CLOSE_ERR_CODE_OK.into(), b"pre-auth timeout");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Hysteria2 H3 setup exceeded the pre-auth deadline",
                ));
            }
        };

    // Preserve the sing-box-compatible three-second application-authentication
    // window after H3 setup, but never let it outlive the 60-second absolute outer
    // deadline that began at gate admission.
    let auth_deadline = std::cmp::min(pre_auth_deadline, Instant::now() + AUTH_TIMEOUT);
    let auth_result = tokio::select! {
        biased;
        () = lifecycle.cancelled() => {
            connection.close(CLOSE_ERR_CODE_OK.into(), b"connection cancelled");
            return Err(connection_lifecycle_cancelled_error());
        }
        result = timeout_at(
            auth_deadline,
            auth_connection(&mut h3_conn, &connection, &settings, &lifecycle),
        ) => result,
    };
    let meter = match auth_result {
        Ok(Ok(user)) => user,
        Ok(Err(e)) => {
            connection.close(CLOSE_ERR_CODE_OK.into(), b"auth failed");
            return Err(e);
        }
        Err(_elapsed) => {
            connection.close(CLOSE_ERR_CODE_OK.into(), b"auth timeout");
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "authentication timeout",
            ));
        }
    };

    // Hysteria2 authenticates once for the whole QUIC connection. From this point
    // on the connection is charged to its user (when metering is enabled), so it no
    // longer belongs in the anonymous-handshake budget. Every error above releases
    // the permit through normal drop as well.
    drop(handshake_permit);

    // The auth exchange itself goes uncounted: it rides h3's own streams, whose
    // framing and QPACK encoding quinn and h3 own between them. It is a few hundred
    // bytes once per connection, and the same argument already applies to the QUIC
    // handshake that carried it.
    let udp_connection = connection.clone();
    let udp_selector = selector.clone();
    let udp_cancel_token = cancel_token.clone();
    let udp_meter = meter.clone();

    let uni_connection = connection.clone();

    // Use try_join! to run all loops concurrently within the same task, like Quinn's perf example.
    // This reduces task count and avoids spawning separate tasks for the main loops.
    let udp_loop = async {
        if settings.udp_enabled {
            run_udp_local_to_remote_loop(udp_connection, udp_selector, udp_meter, udp_cancel_token)
                .await
        } else {
            Ok(())
        }
    };

    let uni_loop = async {
        // Depending on the client, unidirectional streams could still be sent, accept and drop.
        loop {
            match uni_connection.accept_uni().await {
                Ok(mut recv_stream) => {
                    let _ = recv_stream.stop(0u32.into());
                }
                Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
                Err(quinn::ConnectionError::ConnectionClosed(_)) => break,
                Err(e) => {
                    return Err(std::io::Error::other(format!(
                        "unidirectional loop error: {e}"
                    )));
                }
            }
        }
        Ok(())
    };

    let tcp_connection = connection.clone();
    let tcp_loop = run_tcp_loop(tcp_connection, selector, meter, Arc::clone(&lifecycle));

    let result = tokio::select! {
        biased;
        () = lifecycle.cancelled() => {
            cancel_token.cancel();
            connection.close(CLOSE_ERR_CODE_OK.into(), b"connection cancelled");
            Err(connection_lifecycle_cancelled_error())
        }
        result = async { tokio::try_join!(udp_loop, uni_loop, tcp_loop) } => result,
    };

    cancel_token.cancel();

    // Per sing-box reference (service.go:277-293), close connection on error
    if result.is_err() {
        connection.close(CLOSE_ERR_CODE_OK.into(), b"");
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

/// Check that this really is a hysteria2 auth request, and hand back whose it is.
///
/// The password arrives in cleartext in a header, so a registry lookup is the whole
/// of authentication here -- there is nothing derived and nothing to recompute. That
/// is also why the rejection message no longer echoes the value: with more than one
/// user it is somebody's live credential, or a guess at one, and neither belongs in
/// a log line.
fn validate_auth_request<T>(
    req: &http::Request<T>,
    users: &dyn UserRegistry,
) -> std::io::Result<Arc<UserContext>> {
    if req.uri() != "https://hysteria/auth" {
        return Err(std::io::Error::other(format!(
            "unexpected uri: {}",
            req.uri()
        )));
    }
    if req.method() != "POST" {
        return Err(std::io::Error::other(format!(
            "unexpected method: {}",
            req.method()
        )));
    }

    let headers = req.headers();
    let auth_value = match headers.get("hysteria-auth") {
        Some(h) => h,
        None => {
            return Err(std::io::Error::other("missing auth header"));
        }
    };
    let auth_str = auth_value
        .to_str()
        .map_err(|e| std::io::Error::other(format!("invalid auth header value: {e}")))?;

    users
        .find_password(auth_str)
        .ok_or_else(|| std::io::Error::other("unrecognized auth password"))
}

fn generate_ascii_string() -> String {
    let mut rng = rand::rng();
    let length = rng.random_range(1..80);
    rng.sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

async fn auth_connection(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, bytes::Bytes>,
    connection: &quinn::Connection,
    settings: &Hysteria2ConnectionSettings,
    lifecycle: &Arc<ConnContext>,
) -> std::io::Result<Meter> {
    loop {
        match h3_conn
            .accept()
            .await
            .map_err(|e| std::io::Error::other(format!("H3 accept failed: {e}")))?
        {
            Some(resolver) => {
                let (req, mut stream) = resolver.resolve_request().await.map_err(|err| {
                    std::io::Error::other(format!("Failed to resolve request: {err}"))
                })?;
                match validate_auth_request(&req, settings.users.as_ref()) {
                    Ok(user) => {
                        // Admission and connection registration are one lifecycle
                        // operation. Do it before sending success, so remove_user
                        // cannot return while this peer is being told it authenticated.
                        let admitted = if settings.metered {
                            lifecycle.bind_authenticated_for_fallback(user)
                        } else {
                            user.admit_unmetered()
                        };
                        if !admitted {
                            debug!(
                                "Serving Hysteria2 masquerade response: credential resolved but user admission was refused"
                            );
                            settings.masquerade.respond(req, stream).await?;
                            continue;
                        }
                        let meter = settings.metered.then(|| Arc::clone(lifecycle));

                        // Hysteria2's header is bytes per second despite the
                        // configuration being expressed in Mbps. Missing and
                        // malformed values are zero in sing-quic and select BBR.
                        let client_receive_bps = req
                            .headers()
                            .get("Hysteria-CC-RX")
                            .and_then(|value| value.to_str().ok())
                            .and_then(|value| value.parse::<u64>().ok())
                            .unwrap_or(0);
                        let bandwidth = crate::hysteria2::brutal::negotiate_server(
                            client_receive_bps,
                            settings.up_mbps,
                            settings.down_mbps,
                            settings.ignore_client_bandwidth,
                        );
                        if let Some(send_bps) = bandwidth.send_bps {
                            crate::hysteria2::brutal::activate(connection, send_bps)?;
                        }
                        let advertised_receive = bandwidth.advertised_receive.header_value();

                        let resp = http::Response::builder()
                            .status(http::status::StatusCode::from_u16(233).unwrap())
                            .header(
                                "Hysteria-UDP",
                                if settings.udp_enabled {
                                    "true"
                                } else {
                                    "false"
                                },
                            )
                            .header("Hysteria-CC-RX", advertised_receive)
                            .header("Hysteria-Padding", generate_ascii_string())
                            .body(())
                            .unwrap();

                        let respond = async {
                            stream.send_response(resp).await.map_err(|e| {
                                std::io::Error::other(format!("failed to send auth response: {e}"))
                            })?;
                            stream.finish().await.map_err(|e| {
                                std::io::Error::other(format!("failed to finish auth stream: {e}"))
                            })
                        };

                        if let Some(context) = &meter {
                            tokio::select! {
                                biased;
                                () = context.cancelled() => {
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::ConnectionAborted,
                                        "user removed",
                                    ));
                                }
                                result = respond => result?,
                            }
                        } else {
                            respond.await?;
                        }

                        return Ok(meter);
                    }
                    Err(e) => {
                        debug!("Serving Hysteria2 masquerade response: {e}");
                        settings.masquerade.respond(req, stream).await?;
                    }
                }
            }
            // indicating no more streams to be received
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "no streams",
                ));
            }
        }
    }
}

struct UdpSession {
    outbound_tx: mpsc::Sender<UdpForwardCommand>,
    last_activity: Arc<Mutex<std::time::Instant>>,
    cancel_token: CancellationToken,
}

struct UdpForwardCommand {
    remote_location: NetLocation,
    payload: Bytes,
    _payload_permit: OwnedSemaphorePermit,
}

struct UdpTargetWorker {
    outbound_tx: mpsc::Sender<UdpForwardCommand>,
    last_used: u64,
    generation: u64,
    cancel_token: CancellationToken,
}

enum UdpTargetPermit {
    Ready(OwnedSemaphorePermit),
    /// The association was full and its LRU worker has been cancelled. Waiting
    /// in the replacement worker preserves the first packet without letting the
    /// association router or healthy targets wait for permit handoff.
    Awaiting(Arc<Semaphore>),
}

impl Drop for UdpTargetWorker {
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
    Closed {
        remote_location: NetLocation,
        generation: u64,
        error: std::io::Error,
    },
}

impl Drop for UdpSession {
    /// Stop the remote-to-local task this session started.
    ///
    /// A `CancellationToken` does not fire when its last handle is dropped -- only
    /// an explicit `cancel` or a `DropGuard` does that -- and the spawned loop holds
    /// its own clone of this one along with every fixed-target stream and a 64 KiB
    /// receive buffer. Every path that discards a session must therefore wake the
    /// worker so its proxy transports are dropped promptly.
    ///
    /// Cancelling here rather than at each call site makes the release a property of
    /// the session's lifetime, so a future path that drops one is covered too. The
    /// reaper's explicit `cancel` is left in place and is simply idempotent.
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

struct FragmentedPacket {
    fragment_count: u8,
    fragment_received: u8,
    packet_len: usize,
    received: Vec<Option<Bytes>>,
    remote_location: Option<NetLocation>,
    last_update: std::time::Instant,
}

struct UdpFragmentCache {
    entries: LruCache<(u32, u16), FragmentedPacket>,
    total_bytes: usize,
}

impl UdpFragmentCache {
    fn new() -> Self {
        Self {
            entries: LruCache::new(NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE).unwrap()),
            total_bytes: 0,
        }
    }

    fn remove(&mut self, key: &(u32, u16)) -> Option<FragmentedPacket> {
        let packet = self.entries.pop(key)?;
        self.total_bytes = self.total_bytes.saturating_sub(packet.packet_len);
        Some(packet)
    }

    fn pop_lru(&mut self) -> Option<((u32, u16), FragmentedPacket)> {
        let (key, packet) = self.entries.pop_lru()?;
        self.total_bytes = self.total_bytes.saturating_sub(packet.packet_len);
        Some((key, packet))
    }

    fn clear_session(&mut self, session_id: u32) {
        let keys: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(key, _)| (key.0 == session_id).then_some(*key))
            .collect();
        for key in keys {
            self.remove(&key);
        }
    }

    fn purge_expired(&mut self, now: std::time::Instant) {
        let keys: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(key, packet)| {
                now.checked_duration_since(packet.last_update)
                    .is_some_and(|age| age >= UDP_FRAGMENT_TIMEOUT)
                    .then_some(*key)
            })
            .collect();
        for key in keys {
            self.remove(&key);
        }
    }

    fn accept_fragment(
        &mut self,
        session_id: u32,
        packet_id: u16,
        fragment_id: u8,
        fragment_count: u8,
        remote_location: NetLocation,
        payload: Bytes,
    ) -> std::io::Result<Option<(Bytes, NetLocation)>> {
        self.accept_fragment_at(
            session_id,
            packet_id,
            fragment_id,
            fragment_count,
            remote_location,
            payload,
            std::time::Instant::now(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn accept_fragment_at(
        &mut self,
        session_id: u32,
        packet_id: u16,
        fragment_id: u8,
        fragment_count: u8,
        remote_location: NetLocation,
        payload: Bytes,
        now: std::time::Instant,
    ) -> std::io::Result<Option<(Bytes, NetLocation)>> {
        if !valid_udp_fragment(fragment_id, fragment_count) {
            return Err(std::io::Error::other(
                "invalid Hysteria2 UDP fragment index",
            ));
        }
        self.purge_expired(now);
        let key = (session_id, packet_id);
        if !self.entries.contains(&key) {
            if self.entries.len() >= MAX_FRAGMENT_CACHE_SIZE {
                self.pop_lru();
            }
            self.entries.put(
                key,
                FragmentedPacket {
                    fragment_count,
                    fragment_received: 0,
                    packet_len: 0,
                    received: vec![None; fragment_count as usize],
                    // Only fragment zero is authoritative. Some clients repeat an
                    // address on continuation fragments; it must not win merely by
                    // arriving first.
                    remote_location: (fragment_id == 0).then_some(remote_location.clone()),
                    last_update: now,
                },
            );
        }

        let (cached_count, cached_len) = {
            let packet = self
                .entries
                .get(&key)
                .expect("fragment entry was just inserted or already present");
            (packet.fragment_count, packet.packet_len)
        };
        if cached_count != fragment_count {
            self.remove(&key);
            return Err(std::io::Error::other(format!(
                "Mismatched fragment count for session {session_id} packet {packet_id}"
            )));
        }
        let duplicate = self
            .entries
            .get(&key)
            .expect("fragment count match keeps the entry")
            .received[fragment_id as usize]
            .is_some();
        if duplicate {
            self.remove(&key);
            return Err(std::io::Error::other(format!(
                "Duplicate fragment for session {session_id} packet {packet_id}"
            )));
        }
        let Some(packet_len) = checked_udp_packet_len(cached_len, payload.len()) else {
            self.remove(&key);
            return Err(std::io::Error::other(format!(
                "Oversized fragmented UDP packet for session {session_id}"
            )));
        };

        while self
            .total_bytes
            .checked_add(payload.len())
            .is_none_or(|bytes| bytes > MAX_UDP_FRAGMENT_BYTES_PER_CONNECTION)
        {
            let Some((evicted_key, _)) = self.pop_lru() else {
                return Err(std::io::Error::other(
                    "Hysteria2 fragment byte budget exhausted",
                ));
            };
            if evicted_key == key {
                return Err(std::io::Error::other(
                    "Hysteria2 fragment byte budget exhausted",
                ));
            }
        }

        let complete = {
            let packet = self
                .entries
                .get_mut(&key)
                .expect("current fragment entry survives byte-budget eviction");
            if fragment_id == 0 {
                packet.remote_location = Some(remote_location);
            }
            packet.fragment_received += 1;
            packet.packet_len = packet_len;
            packet.received[fragment_id as usize] = Some(payload);
            packet.last_update = now;
            packet.fragment_received == packet.fragment_count
        };
        self.total_bytes += packet_len - cached_len;
        if !complete {
            return Ok(None);
        }

        let packet = self
            .remove(&key)
            .expect("complete fragment entry remains cached");
        let remote_location = packet.remote_location.ok_or_else(|| {
            std::io::Error::other(format!(
                "Missing fragment-zero destination for session {session_id} packet {packet_id}"
            ))
        })?;
        let mut complete_payload = BytesMut::with_capacity(packet.packet_len);
        for fragment in packet.received {
            complete_payload.extend_from_slice(
                fragment
                    .as_ref()
                    .expect("fragment count proves every slot is populated"),
            );
        }
        Ok(Some((complete_payload.freeze(), remote_location)))
    }
}

impl UdpSession {
    fn touch(&self, now: std::time::Instant) {
        if let Ok(mut last_activity) = self.last_activity.lock() {
            *last_activity = now;
        }
    }

    fn is_idle_at(&self, now: std::time::Instant, idle_timeout: Duration) -> bool {
        self.last_activity
            .lock()
            .ok()
            .and_then(|last_activity| now.checked_duration_since(*last_activity))
            .is_some_and(|idle| idle > idle_timeout)
    }

    #[allow(clippy::too_many_arguments)]
    fn start(
        session_id: u32,
        connection: quinn::Connection,
        client_proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        target_permits: Arc<Semaphore>,
        meter: Meter,
        parent_cancel_token: &CancellationToken,
    ) -> Self {
        let session_cancel_token = parent_cancel_token.child_token();
        let (outbound_tx, outbound_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let last_activity = Arc::new(Mutex::new(std::time::Instant::now()));

        let session = UdpSession {
            outbound_tx,
            last_activity: last_activity.clone(),
            cancel_token: session_cancel_token.clone(),
        };

        let remote_ip = connection.remote_address().ip();
        tokio::spawn(async move {
            let result = run_udp_session_worker(
                session_id,
                connection,
                outbound_rx,
                client_proxy_selector,
                resolver,
                target_permits,
                meter,
                last_activity,
                session_cancel_token,
            )
            .await;

            if let Err(e) = result {
                debug!("Hysteria2 UDP association {session_id} from {remote_ip} ended: {e}");
            }
        });

        session
    }
}

fn cleanup_udp_sessions(
    sessions: &mut FxHashMap<u32, UdpSession>,
    fragments: &mut UdpFragmentCache,
    now: std::time::Instant,
) {
    sessions.retain(|session_id, session| {
        if session.is_idle_at(now, UDP_SESSION_IDLE_TIMEOUT) {
            session.cancel_token.cancel();
            fragments.clear_session(*session_id);
            debug!("Removing inactive UDP session {session_id}");
            false
        } else {
            true
        }
    });
    // Packet ids are only 16 bits. Expire incomplete packets even while their
    // association remains active, so an old fragment cannot be combined with a
    // later packet after the id wraps.
    fragments.purge_expired(now);
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
            warn!("Hysteria2 UDP routing for {requested_location} failed: {error}");
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
                    warn!("Hysteria2 UDP outbound setup to {outbound_location} failed: {error}");
                    error
                })
        }
        ConnectDecision::Block => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "UDP destination blocked by routing rules",
        )),
    }
}

fn evict_lru_udp_target_worker(targets: &mut FxHashMap<NetLocation, UdpTargetWorker>) {
    let Some(remote_location) = targets
        .iter()
        .min_by_key(|(_, target)| target.last_used)
        .map(|(remote_location, _)| remote_location.clone())
    else {
        return;
    };
    targets.remove(&remote_location);
}

fn try_reserve_udp_target_worker(
    targets: &mut FxHashMap<NetLocation, UdpTargetWorker>,
    target_permits: &Arc<Semaphore>,
) -> Option<UdpTargetPermit> {
    match target_permits.clone().try_acquire_owned() {
        Ok(permit) => Some(UdpTargetPermit::Ready(permit)),
        Err(_) if targets.len() >= MAX_UDP_TARGETS_PER_SESSION => {
            evict_lru_udp_target_worker(targets);
            Some(UdpTargetPermit::Awaiting(target_permits.clone()))
        }
        Err(_) => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_udp_target_worker(
    remote_location: NetLocation,
    initial_command: UdpForwardCommand,
    generation: u64,
    permit: UdpTargetPermit,
    session_target_permits: Arc<Semaphore>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    response_tx: mpsc::Sender<UdpTargetEvent>,
    parent_cancel_token: &CancellationToken,
) -> UdpTargetWorker {
    let cancel_token = parent_cancel_token.child_token();
    let task_cancel_token = cancel_token.clone();
    let (outbound_tx, outbound_rx) = mpsc::channel(UDP_TARGET_QUEUE_CAPACITY);
    assert!(
        outbound_tx.try_send(initial_command).is_ok(),
        "a new target queue has room for its initial packet"
    );
    let task_location = remote_location.clone();
    tokio::spawn(async move {
        if let Err(error) = run_udp_target_worker(
            task_location.clone(),
            generation,
            permit,
            session_target_permits,
            outbound_rx,
            client_proxy_selector,
            resolver,
            response_tx.clone(),
            task_cancel_token,
        )
        .await
        {
            let _ = response_tx.try_send(UdpTargetEvent::Closed {
                remote_location: task_location,
                generation,
                error,
            });
        }
    });
    UdpTargetWorker {
        outbound_tx,
        last_used: generation,
        generation,
        cancel_token,
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_target_worker(
    remote_location: NetLocation,
    generation: u64,
    permit: UdpTargetPermit,
    session_target_permits: Arc<Semaphore>,
    outbound_rx: mpsc::Receiver<UdpForwardCommand>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    response_tx: mpsc::Sender<UdpTargetEvent>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let Some((_session_permit, permit)) =
        acquire_udp_target_permits(permit, session_target_permits, &cancel_token).await?
    else {
        return Ok(());
    };
    let connect = connect_udp_target(&client_proxy_selector, &resolver, remote_location.clone());
    let mut remote = tokio::select! {
        biased;
        _ = cancel_token.cancelled() => return Ok(()),
        result = connect => result?,
    };
    run_connected_udp_target_worker(
        remote_location,
        generation,
        permit,
        outbound_rx,
        &mut remote,
        response_tx,
        cancel_token,
    )
    .await
}

async fn acquire_udp_target_permits(
    permit: UdpTargetPermit,
    session_target_permits: Arc<Semaphore>,
    cancel_token: &CancellationToken,
) -> std::io::Result<Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)>> {
    let session_permit = tokio::select! {
        biased;
        _ = cancel_token.cancelled() => return Ok(None),
        permit = session_target_permits.acquire_owned() => permit.map_err(|_| {
            std::io::Error::other("Hysteria2 UDP association target budget closed")
        })?,
    };
    let permit = match permit {
        UdpTargetPermit::Ready(permit) => permit,
        UdpTargetPermit::Awaiting(permits) => tokio::select! {
            biased;
            _ = cancel_token.cancelled() => return Ok(None),
            permit = permits.acquire_owned() => permit.map_err(|_| {
                std::io::Error::other("Hysteria2 UDP target budget closed")
            })?,
        },
    };
    Ok(Some((session_permit, permit)))
}

#[allow(clippy::too_many_arguments)]
async fn run_connected_udp_target_worker(
    remote_location: NetLocation,
    generation: u64,
    _permit: OwnedSemaphorePermit,
    mut outbound_rx: mpsc::Receiver<UdpForwardCommand>,
    remote: &mut Box<dyn AsyncMessageStream>,
    response_tx: mpsc::Sender<UdpTargetEvent>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut read_storage = allocate_vec(MAX_UDP_PACKET_SIZE);
    let mut prefer_read = false;

    enum TargetAction {
        Command(Option<UdpForwardCommand>),
        Read(std::io::Result<usize>),
    }

    loop {
        if cancel_token.is_cancelled() {
            return Ok(());
        }
        // Explicitly alternate priority when both directions are ready. This keeps
        // cancellation strict while preventing a continuously full write queue
        // from starving remote replies on this target.
        let action = {
            let mut read_buf = ReadBuf::new(&mut read_storage);
            if prefer_read {
                tokio::select! {
                    biased;
                    _ = cancel_token.cancelled() => return Ok(()),
                    result = poll_fn(|cx| Pin::new(&mut **remote).poll_read_message(cx, &mut read_buf)) => {
                        TargetAction::Read(result.map(|()| read_buf.filled().len()))
                    }
                    command = outbound_rx.recv() => TargetAction::Command(command),
                }
            } else {
                tokio::select! {
                    biased;
                    _ = cancel_token.cancelled() => return Ok(()),
                    command = outbound_rx.recv() => TargetAction::Command(command),
                    result = poll_fn(|cx| Pin::new(&mut **remote).poll_read_message(cx, &mut read_buf)) => {
                        TargetAction::Read(result.map(|()| read_buf.filled().len()))
                    }
                }
            }
        };

        match action {
            TargetAction::Command(Some(command)) => {
                prefer_read = true;
                let write = async {
                    poll_fn(|cx| Pin::new(&mut **remote).poll_write_message(cx, &command.payload))
                        .await?;
                    poll_fn(|cx| Pin::new(&mut **remote).poll_flush_message(cx)).await
                };
                tokio::select! {
                    biased;
                    _ = cancel_token.cancelled() => return Ok(()),
                    result = write => result?,
                }
                // `command`, including its byte-budget permit, is held through the
                // successful write and flush and is released here.
                drop(command);
            }
            TargetAction::Command(None) => return Ok(()),
            TargetAction::Read(result) => {
                prefer_read = false;
                let payload_len = result?;
                let event = UdpTargetEvent::Message {
                    remote_location: remote_location.clone(),
                    generation,
                    payload: Bytes::copy_from_slice(&read_storage[..payload_len]),
                };
                if response_tx.try_send(event).is_err() {
                    debug!("Dropping Hysteria2 UDP response for slow association");
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_udp_target_command(
    targets: &mut FxHashMap<NetLocation, UdpTargetWorker>,
    use_counter: &mut u64,
    next_generation: &mut u64,
    command: UdpForwardCommand,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    target_permits: &Arc<Semaphore>,
    session_target_permits: &Arc<Semaphore>,
    response_tx: &mpsc::Sender<UdpTargetEvent>,
    cancel_token: &CancellationToken,
) {
    if cancel_token.is_cancelled() {
        return;
    }
    let remote_location = command.remote_location.clone();
    if let Some(target) = targets.get_mut(&remote_location) {
        *use_counter = use_counter.wrapping_add(1);
        target.last_used = *use_counter;
        match target.outbound_tx.try_send(command) {
            Ok(()) => return,
            Err(mpsc::error::TrySendError::Full(_)) => {
                debug!("Dropping Hysteria2 UDP packet for saturated target {remote_location}");
                return;
            }
            Err(mpsc::error::TrySendError::Closed(command)) => {
                targets.remove(&remote_location);
                return dispatch_udp_target_command(
                    targets,
                    use_counter,
                    next_generation,
                    command,
                    client_proxy_selector,
                    resolver,
                    target_permits,
                    session_target_permits,
                    response_tx,
                    cancel_token,
                );
            }
        }
    }

    let Some(permit) = try_reserve_udp_target_worker(targets, target_permits) else {
        debug!(
            "Dropping Hysteria2 UDP packet for {remote_location}: connection target limit reached"
        );
        return;
    };
    if targets.len() >= MAX_UDP_TARGETS_PER_SESSION {
        evict_lru_udp_target_worker(targets);
    }
    *use_counter = use_counter.wrapping_add(1);
    *next_generation = next_generation.wrapping_add(1);
    let generation = *next_generation;
    let mut target = spawn_udp_target_worker(
        remote_location.clone(),
        command,
        generation,
        permit,
        session_target_permits.clone(),
        client_proxy_selector.clone(),
        resolver.clone(),
        response_tx.clone(),
        cancel_token,
    );
    target.last_used = *use_counter;
    targets.insert(remote_location, target);
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_session_worker(
    session_id: u32,
    connection: quinn::Connection,
    mut outbound_rx: mpsc::Receiver<UdpForwardCommand>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    target_permits: Arc<Semaphore>,
    meter: Meter,
    last_activity: Arc<Mutex<std::time::Instant>>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut next_packet_id: u16 = 0;
    let mut targets: FxHashMap<NetLocation, UdpTargetWorker> = FxHashMap::default();
    let mut use_counter = 0u64;
    let mut next_target_generation = 0u64;
    let (response_tx, mut response_rx) = mpsc::channel(UDP_TARGET_RESPONSE_CAPACITY);
    let session_target_permits = Arc::new(Semaphore::new(MAX_UDP_TARGETS_PER_SESSION));

    loop {
        if cancel_token.is_cancelled() {
            return Ok(());
        }
        let event = tokio::select! {
            _ = cancel_token.cancelled() => return Ok(()),
            command = outbound_rx.recv() => {
                let Some(command) = command else {
                    return Ok(());
                };
                dispatch_udp_target_command(
                    &mut targets,
                    &mut use_counter,
                    &mut next_target_generation,
                    command,
                    &client_proxy_selector,
                    &resolver,
                    &target_permits,
                    &session_target_permits,
                    &response_tx,
                    &cancel_token,
                );
                continue;
            }
            event = response_rx.recv() => {
                let Some(event) = event else {
                    return Ok(());
                };
                event
            },
        };

        let (remote_location, payload) = match event {
            UdpTargetEvent::Message {
                remote_location,
                generation,
                payload,
            } => {
                let Some(target) = targets.get_mut(&remote_location) else {
                    continue;
                };
                if target.generation != generation {
                    continue;
                }
                use_counter = use_counter.wrapping_add(1);
                target.last_used = use_counter;
                if let Ok(mut activity) = last_activity.lock() {
                    *activity = std::time::Instant::now();
                }
                (remote_location, payload)
            }
            UdpTargetEvent::Closed {
                remote_location,
                generation,
                error,
            } => {
                debug!(
                    "Hysteria2 UDP target {remote_location} for association {session_id} from {} ended: {error}",
                    connection.remote_address().ip()
                );
                if targets
                    .get(&remote_location)
                    .is_some_and(|target| target.generation == generation)
                {
                    targets.remove(&remote_location);
                }
                continue;
            }
        };
        if cancel_token.is_cancelled() {
            return Ok(());
        }
        let packet_id = next_packet_id;
        next_packet_id = next_packet_id.wrapping_add(1);

        // A fixed-destination AsyncMessageStream does not expose the final source
        // (for a proxy its transport peer is the proxy). Echo the address the HY2
        // client associated with this stream, which is also what preserves a
        // hostname or a routing rewrite on replies.
        match send_udp_response_with(
            session_id,
            &meter,
            packet_id,
            &remote_location,
            &payload,
            &cancel_token,
            || connection.max_datagram_size(),
            |datagram| connection.send_datagram(datagram),
        )
        .await?
        {
            UdpResponseSendOutcome::Sent => {}
            UdpResponseSendOutcome::Cancelled => return Ok(()),
            UdpResponseSendOutcome::DroppedTooLarge {
                planned_max_datagram_size,
                current_max_datagram_size,
                attempted_datagram_len,
                fragment_id,
                fragment_count,
            } => {
                debug!(
                    "Hysteria2 UDP response dropped after the QUIC datagram size changed: \
                     peer={}, association={session_id}, target={remote_location}, \
                     payload_len={}, planned_max_datagram_size={planned_max_datagram_size}, \
                     current_max_datagram_size={current_max_datagram_size:?}, \
                     attempted_datagram_len={attempted_datagram_len}, \
                     fragment_id={fragment_id}, fragment_count={fragment_count}",
                    connection.remote_address().ip(),
                    payload.len()
                );
            }
        }
    }
}

async fn run_udp_local_to_remote_loop(
    connection: quinn::Connection,
    selector: Arc<SelectorSlot>,
    meter: Meter,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut sessions: FxHashMap<u32, UdpSession> = FxHashMap::default();
    let target_permits = Arc::new(Semaphore::new(MAX_UDP_TARGETS_PER_CONNECTION));
    let queued_payload_budget = Arc::new(Semaphore::new(MAX_UDP_QUEUED_BYTES_PER_CONNECTION));
    let mut fragments = UdpFragmentCache::new();
    let mut cleanup_interval = tokio::time::interval(UDP_SESSION_CLEANUP_INTERVAL);
    cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // `interval` ticks immediately once. Consume that tick so the select below is
    // driven by the first real cleanup deadline.
    cleanup_interval.tick().await;

    loop {
        let data = tokio::select! {
            biased;
            _ = cancel_token.cancelled() => return Ok(()),
            _ = cleanup_interval.tick() => {
                cleanup_udp_sessions(
                    &mut sessions,
                    &mut fragments,
                    std::time::Instant::now(),
                );
                continue;
            }
            result = connection.read_datagram() => {
                result.map_err(|err| {
                    std::io::Error::other(format!("failed to read datagram: {err}"))
                })?
            }
        };

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

        // Per official hysteria reference (server.go:332-353), parse errors are ignored
        // and we continue waiting for the next message. Only connection errors are fatal.
        if data.len() < 9 {
            debug!("Ignoring short datagram (len={})", data.len());
            continue;
        }
        let session_id = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let packet_id = u16::from_be_bytes(data[4..6].try_into().unwrap());
        let fragment_id = data[6];
        let fragment_count = data[7];

        if !valid_udp_fragment(fragment_id, fragment_count) {
            debug!("Ignoring datagram with invalid fragment {fragment_id}/{fragment_count}");
            continue;
        }

        let Some((address_len, next_index)) = decode_udp_address_length(&data) else {
            debug!("Ignoring datagram with truncated address length");
            continue;
        };

        if address_len == 0 {
            debug!("Ignoring packet with empty address");
            continue;
        }

        if address_len > 2048 {
            debug!("Ignoring packet with address length {address_len}");
            continue;
        }

        if data.len() < next_index + address_len {
            debug!("Ignoring datagram with truncated address");
            continue;
        }
        let address_bytes = &data[next_index..next_index + address_len];
        let payload_fragment = data.slice(next_index + address_len..);

        let addr_str = match str::from_utf8(address_bytes) {
            Ok(s) => s,
            Err(e) => {
                debug!("Invalid UTF-8 in address: {e}");
                continue;
            }
        };

        let remote_location = match NetLocation::from_str(addr_str, None) {
            Ok(loc) => loc,
            Err(e) => {
                debug!("Failed to parse address '{addr_str}': {e}");
                continue;
            }
        };

        if let Some(session) = sessions.get_mut(&session_id) {
            session.touch(std::time::Instant::now());
        }

        let (complete_payload, remote_location) = if fragment_count == 1 {
            (payload_fragment, remote_location)
        } else {
            match fragments.accept_fragment(
                session_id,
                packet_id,
                fragment_id,
                fragment_count,
                remote_location,
                payload_fragment,
            ) {
                Ok(Some(packet)) => packet,
                Ok(None) => continue,
                Err(error) => {
                    debug!("Ignoring Hysteria2 UDP fragment: {error}");
                    continue;
                }
            }
        };

        let Some(payload_permit) =
            try_reserve_payload_bytes(&queued_payload_budget, complete_payload.len())
        else {
            debug!("Dropping Hysteria2 UDP packet: connection queue byte budget exhausted");
            continue;
        };
        if cancel_token.is_cancelled() {
            return Ok(());
        }

        let session_count = sessions.len();
        let session = match sessions.entry(session_id) {
            Entry::Vacant(entry) => {
                if session_count >= MAX_UDP_SESSIONS {
                    debug!(
                        "Refusing new UDP session {session_id}: at the {MAX_UDP_SESSIONS} session limit"
                    );
                    continue;
                }
                let (session_selector, session_resolver) = selector.load();
                entry.insert(UdpSession::start(
                    session_id,
                    connection.clone(),
                    session_selector,
                    session_resolver,
                    target_permits.clone(),
                    meter.clone(),
                    &cancel_token,
                ))
            }
            Entry::Occupied(entry) => entry.into_mut(),
        };
        session.touch(std::time::Instant::now());

        match session.outbound_tx.try_send(UdpForwardCommand {
            remote_location,
            payload: complete_payload,
            _payload_permit: payload_permit,
        }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                debug!("Dropping Hysteria2 UDP packet for saturated session {session_id}");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                debug!("Hysteria2 UDP association worker {session_id} has stopped");
                sessions.remove(&session_id);
                fragments.clear_session(session_id);
            }
        }
    }
}

async fn run_tcp_loop(
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
                "refusing Hysteria2 TCP stream: {MAX_ACTIVE_TCP_LOGICAL_FLOWS} logical flows are already active"
            );
            let _ = send_stream.reset(TCP_FLOW_LIMIT_ERROR_CODE.into());
            let _ = recv_stream.stop(TCP_FLOW_LIMIT_ERROR_CODE.into());
            continue;
        };
        let request_header_deadline = Instant::now() + TCP_REQUEST_HEADER_TIMEOUT;

        // TCP requests are independent Hysteria2 logical flows. Load the current
        // policy only after accepting the stream; the spawned task owns the Arcs
        // and therefore remains pinned if another reload happens meanwhile.
        let (client_proxy_selector, resolver) = selector.load();
        // Every stream on this connection shares the one context, so a user's
        // counters cover all of them at once and the live-connection count follows
        // the QUIC connection rather than the streams multiplexed over it.
        let meter = meter.clone();
        let lifecycle = Arc::clone(&lifecycle);
        tokio::spawn(async move {
            // Covers header parsing, DNS/outbound setup, and bidirectional copying.
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
            if let Err(e) = result {
                debug!("Hysteria2 TCP stream ended: {e}");
            }
        });
    }
    Ok(())
}

/// TCP request frame type constant from Hysteria2 protocol.
/// See: https://github.com/apernet/hysteria/blob/master/core/internal/protocol/proxy.go#L15
const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// Maximum error message length carried by a Hysteria2 TCP response.
///
/// This is the protocol limit used by the reference implementation. Keep the
/// bound here even though all of our current errors are much shorter: resolver
/// and proxy-chain errors can include attacker-controlled destination text.
const MAX_TCP_RESPONSE_MESSAGE_LENGTH: usize = 2048;

async fn handle_tcp_header(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<(NetLocation, StreamReader)> {
    let mut stream_reader = StreamReader::new_with_buffer_size(8192);

    // Read the TCP request frame type as a QUIC varint per protocol spec.
    // The value 0x401 can be encoded in multiple valid ways (e.g., [0x44, 0x01] as 2-byte form).
    let tcp_request_id = read_varint(stream, &mut stream_reader).await?;
    if tcp_request_id != FRAME_TYPE_TCP_REQUEST {
        return Err(std::io::Error::other(format!(
            "invalid tcp request id: expected {:#x}, got {:#x}",
            FRAME_TYPE_TCP_REQUEST, tcp_request_id
        )));
    }

    // max lengths from https://github.com/apernet/hysteria/blob/5520bcc405ee11a47c164c75bae5c40fc2b1d99d/core/internal/protocol/proxy.go#L19
    let address_len = read_varint(stream, &mut stream_reader).await?;
    if address_len > 2048 {
        return Err(std::io::Error::other("invalid address length"));
    }
    let address_bytes = stream_reader
        .read_slice(stream, address_len as usize)
        .await?;
    let address = std::str::from_utf8(address_bytes)
        .map_err(|e| std::io::Error::other(format!("invalid address encoding: {e}")))?;
    let remote_location = NetLocation::from_str(address, None)?;

    let padding_len = read_varint(stream, &mut stream_reader).await?;
    if padding_len > 4096 {
        return Err(std::io::Error::other("invalid padding length"));
    }
    stream_reader
        .read_slice(stream, padding_len as usize)
        .await?;

    Ok((remote_location, stream_reader))
}

fn encode_tcp_response(ok: bool, message: &str) -> std::io::Result<Vec<u8>> {
    // Keep truncation on a UTF-8 boundary. The wire field is bytes, but preserving
    // valid UTF-8 makes the diagnostic useful to clients that display it directly.
    let mut message_len = message.len().min(MAX_TCP_RESPONSE_MESSAGE_LENGTH);
    while !message.is_char_boundary(message_len) {
        message_len -= 1;
    }
    let message = &message.as_bytes()[..message_len];
    let message_len = encode_varint(message.len() as u64)?;

    // Keeping this at most 63 makes the padding length itself a one-byte varint,
    // matching the response shape previously emitted here and sing-quic's bounded
    // random padding.
    let mut rng = rand::rng();
    let padding_len = rng.random_range(0usize..=63);
    let encoded_padding_len = encode_varint(padding_len as u64)?;

    let mut response = Vec::with_capacity(
        1 + message_len.len() + message.len() + encoded_padding_len.len() + padding_len,
    );
    response.push(if ok { 0 } else { 1 });
    response.extend_from_slice(&message_len);
    response.extend_from_slice(message);
    response.extend_from_slice(&encoded_padding_len);
    let padding_start = response.len();
    response.resize(padding_start + padding_len, 0);
    rng.fill_bytes(&mut response[padding_start..]);
    Ok(response)
}

async fn write_tcp_response<W>(stream: &mut W, ok: bool, message: &str) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin + ?Sized,
{
    let response = encode_tcp_response(ok, message)?;
    stream.write_all(&response).await.map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("Hysteria2 TCP response write failed: {error}"),
        )
    })
}

async fn write_tcp_fast_open_replay<W>(stream: &mut W, replay: &[u8]) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin + ?Sized,
{
    stream.write_all(replay).await.map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("Hysteria2 TCP fast-open replay write failed: {error}"),
        )
    })
}

/// Best-effort protocol rejection followed by a FIN on this logical stream.
///
/// The original routing/setup error remains the task result. Failing to report it
/// to a peer that has already gone away must not be allowed to affect the other
/// streams multiplexed over the same QUIC connection.
async fn reject_tcp_stream(stream: &mut Box<dyn AsyncStream>, error: &std::io::Error) {
    if let Err(response_error) = write_tcp_response(stream, false, &error.to_string()).await {
        debug!("failed to report Hysteria2 TCP request failure: {response_error}");
    }
    let _ = stream.shutdown().await;
}

async fn process_tcp_stream(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    meter: Meter,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    request_header_deadline: Instant,
) -> std::io::Result<()> {
    // Metered before the request header is read, rather than after, so the address,
    // the padding, and the status response this proxy writes back are all billed --
    // they are bytes the client put on the wire and had put back to it. Reading the
    // header through the wrapper is also what makes `handle_tcp_header` take one
    // stream instead of quinn's send and recv halves.
    let mut server_stream: Box<dyn AsyncStream> = match meter {
        Some(meter) => Box::new(TrafficMeterStream::new(QuicStream::from(send, recv), meter)),
        None => Box::new(QuicStream::from(send, recv)),
    };

    let header = read_tcp_request_header_before_deadline(
        request_header_deadline,
        handle_tcp_header(&mut server_stream),
    )
    .await;
    let (remote_location, stream_reader) = match header {
        Ok(res) => res,
        Err(e) => {
            let _ = server_stream.shutdown().await;
            return Err(e);
        }
    };

    let mut replay = stream_reader
        .unparsed_data_owned()
        .map(Vec::from)
        .unwrap_or_default();
    drop(stream_reader);
    let sniffed = if client_proxy_selector.needs_tcp_sniff() {
        match sniff_tcp(&mut server_stream, &mut replay).await {
            Ok(sniffed) => sniffed,
            Err(error) => {
                reject_tcp_stream(&mut server_stream, &error).await;
                return Err(error);
            }
        }
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
            let error = std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("TCP destination {remote_location} blocked by routing rules"),
            );
            reject_tcp_stream(&mut server_stream, &error).await;
            return Ok(());
        }
        Ok(Err(e)) => {
            let error = client_stream_setup_error(&remote_location, e);
            reject_tcp_stream(&mut server_stream, &error).await;
            return Err(error);
        }
        Err(elapsed) => {
            let error = client_stream_setup_timeout(&remote_location, elapsed);
            reject_tcp_stream(&mut server_stream, &error).await;
            return Err(error);
        }
    };

    // Match sing-box: a successful TCP response reports that routing, DNS and the
    // outbound dial have all completed, not merely that the request parsed.
    write_tcp_response(&mut server_stream, true, "").await?;
    let mut client_stream = apply_client_early_data(&mut server_stream, client_setup).await?;

    let client_requires_flush = if replay.is_empty() {
        false
    } else {
        write_tcp_fast_open_replay(&mut client_stream, &replay).await?;
        true
    };

    // Use 32KB buffers to match hysteria2/sing-box reference implementations
    let copy_result = copy_bidirectional_with_sizes(
        &mut server_stream,
        &mut client_stream,
        // no need to flush even through we wrote this response since it's quic
        false,
        client_requires_flush,
        32768,
        32768,
    )
    .await;

    let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());

    copy_result?;
    Ok(())
}

#[inline]
fn encode_varint(value: u64) -> std::io::Result<Box<[u8]>> {
    if value <= 0b00111111 {
        Ok(Box::new([value as u8]))
    } else if value < (1 << 14) {
        let mut bytes = (value as u16).to_be_bytes();
        bytes[0] |= 0b01000000;
        Ok(Box::new(bytes))
    } else if value < (1 << 30) {
        let mut bytes = (value as u32).to_be_bytes();
        bytes[0] |= 0b10000000;
        Ok(Box::new(bytes))
    } else if value < (1 << 62) {
        let mut bytes = value.to_be_bytes();
        bytes[0] |= 0b11000000;
        Ok(Box::new(bytes))
    } else {
        Err(std::io::Error::other("value too large to encode as varint"))
    }
}

async fn read_varint(
    stream: &mut Box<dyn AsyncStream>,
    stream_reader: &mut StreamReader,
) -> std::io::Result<u64> {
    let first_byte = stream_reader.read_u8(stream).await?;

    let length = first_byte >> 6;
    let mut value: u64 = (first_byte & 0b00111111) as u64;

    let num_bytes = match length {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => {
            // impossible since we only have 2 bits
            panic!("invalid num bytes value");
        }
    };

    if num_bytes > 1 {
        let remaining_bytes = stream_reader.read_slice(stream, num_bytes - 1).await?;
        for byte in remaining_bytes {
            value <<= 8; // Shift left by 8 bits for each subsequent byte
            value |= *byte as u64; // Add the next byte
        }
    }

    Ok(value)
}

#[allow(clippy::too_many_arguments)]
pub async fn start_hysteria2_server(
    bind_address: SocketAddr,
    quic_server_config: Arc<quinn::crypto::rustls::QuicServerConfig>,
    users: Arc<dyn UserRegistry>,
    metered: bool,
    // Retained for the lifetime of accepted connections, which load it once for
    // every new logical TCP flow or UDP session. Authentication and the fixed QUIC
    // listener settings remain connection/listener scoped.
    selector: Arc<SelectorSlot>,
    num_endpoints: usize,
    udp_enabled: bool,
    up_mbps: u64,
    down_mbps: u64,
    ignore_client_bandwidth: bool,
    // Salamander obfuscation, or `None` for plain QUIC.
    obfs: Option<crate::hysteria2_obfs::Salamander>,
    masquerade: Arc<crate::hysteria2_masquerade::Hysteria2Masquerade>,
    shutdown: CancellationToken,
    connection_cancel: CancellationToken,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    // `num_endpoints` is an SO_REUSEPORT fan-out for one logical listener, not a
    // multiplier for its unauthenticated-connection budget.
    let handshake_gate = HandshakeGate::new(MAX_PENDING_HANDSHAKES, MAX_PENDING_PER_SOURCE);
    let endpoints = crate::quic_server::prepare_endpoint_batch(num_endpoints, || {
        let mut server_config = quinn::ServerConfig::with_crypto(quic_server_config.clone());

        // values estimated from https://github.com/apernet/hysteria/blob/5520bcc405ee11a47c164c75bae5c40fc2b1d99d/core/server/config.go#L16
        Arc::get_mut(&mut server_config.transport)
            .unwrap()
            .max_concurrent_bidi_streams((MAX_ACTIVE_TCP_LOGICAL_FLOWS as u32).into())
            // required for HTTP/3 QPACK updates
            .max_concurrent_uni_streams(1024_u32.into())
            .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()))
            .keep_alive_interval(Some(Duration::from_secs(10)))
            .send_window(16 * 1024 * 1024)
            .receive_window((20u32 * 1024 * 1024).into())
            // Quinn closes the connection when receive-buffer compaction still
            // leaves more than 1024 chunks in one stream. A larger per-stream
            // flow-control window lets a sustained upload retain more chunks
            // behind missing data, increasing the chance of hitting that limit.
            // Use Quinn's 1_250_000-byte default here as an empirical mitigation,
            // not a proven safety bound. The 20 MiB connection window remains
            // available to parallel streams.
            .stream_receive_window(1_250_000u32.into())
            // MTU settings per official TUIC reference
            .initial_mtu(1200)
            .min_mtu(1200)
            // Enable MTU discovery for larger packets on capable networks
            .mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()))
            // QUIC exists before the HTTP/3 auth request carrying
            // Hysteria-CC-RX. This factory starts each connection on BBR and
            // exposes a connection-local switch that auth flips to Brutal.
            .congestion_controller_factory(Arc::new(crate::hysteria2::brutal::BrutalConfig))
            // Enable GSO (Generic Segmentation Offload) for better throughput.
            // Salamander gives every datagram its own salt, so a coalesced
            // batch cannot be obfuscated as one buffer -- the offload has to
            // go when obfuscation is on.
            .enable_segmentation_offload(obfs.is_none())
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

        // `wrap_udp_socket` lives on the Runtime trait.
        use quinn::Runtime as _;
        let runtime = Arc::new(quinn::TokioRuntime);
        match obfs.clone() {
            // Obfuscation is a transformation of the bytes leaving and
            // entering the socket, so it wraps quinn's own socket rather
            // than replacing it: everything platform-specific about the UDP
            // path stays where quinn maintains it.
            Some(salamander) => {
                let inner = runtime.wrap_udp_socket(socket2_socket.into())?;
                quinn::Endpoint::new_with_abstract_socket(
                    quinn::EndpointConfig::default(),
                    Some(server_config),
                    Arc::new(crate::hysteria2_obfs::ObfuscatedUdpSocket::new(
                        inner, salamander,
                    )),
                    runtime,
                )
            }
            None => quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(server_config),
                socket2_socket.into(),
                runtime,
            ),
        }
    })?;

    let connection_settings = Hysteria2ConnectionSettings {
        users,
        metered,
        udp_enabled,
        up_mbps,
        down_mbps,
        ignore_client_bandwidth,
        masquerade,
    };
    let mut join_handles = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        // No resolver clone: the accept loop takes it from the selector slot, so the
        // rules and the DNS a connection routes by are always one generation.
        let selector = selector.clone();
        let handshake_gate = handshake_gate.clone();
        let shutdown = shutdown.clone();
        let connection_cancel = connection_cancel.clone();
        let connection_settings = connection_settings.clone();

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
                let Some(conn) = require_validated_quic_address(conn, "Hysteria2") else {
                    continue;
                };
                let remote_ip = conn.remote_address().ip();
                let Some(handshake_permit) = handshake_gate.enter(Some(remote_ip)) else {
                    debug!(
                        "refusing Hysteria2 peer {remote_ip}: the listener is at its pending-handshake limit"
                    );
                    conn.refuse();
                    continue;
                };
                let pre_auth_deadline = Instant::now() + QUIC_PRE_AUTH_TIMEOUT;
                let selector = selector.clone();
                let connection_settings = connection_settings.clone();
                let connection_cancel = connection_cancel.clone();
                tokio::spawn(async move {
                    if let Err(e) = process_connection(
                        selector,
                        conn,
                        connection_settings,
                        handshake_permit,
                        pre_auth_deadline,
                        connection_cancel,
                    )
                    .await
                    {
                        debug!("Hysteria2 connection from {remote_ip} ended: {e}");
                    }
                });
            }

            if connection_cancel.is_cancelled() {
                crate::quic_server::hard_close_endpoint(endpoint, bind_address).await;
            } else {
                // The connections are multiplexed over this endpoint's socket, so
                // letting them finish and giving the port back are the same act.
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
        MAX_ACTIVE_TCP_LOGICAL_FLOWS, MAX_FRAGMENT_CACHE_SIZE, MAX_TCP_RESPONSE_MESSAGE_LENGTH,
        MAX_UDP_FRAGMENT_BYTES_PER_CONNECTION, MAX_UDP_PACKET_SIZE, MAX_UDP_TARGETS_PER_SESSION,
        TCP_REQUEST_HEADER_TIMEOUT, UdpForwardCommand, UdpFragmentCache, UdpResponseSendOutcome,
        UdpSession, UdpTargetEvent, UdpTargetPermit, UdpTargetWorker, acquire_udp_target_permits,
        checked_response_fragment_count, checked_udp_packet_len, cleanup_udp_sessions,
        connect_udp_target, decode_udp_address_length, dispatch_udp_target_command,
        encode_tcp_response, read_tcp_request_header_before_deadline,
        run_connected_udp_target_worker, send_udp_response_with, try_admit_tcp_logical_flow,
        try_reserve_payload_bytes, try_reserve_udp_target_worker, udp_response_send_allowed,
        valid_udp_fragment, write_tcp_fast_open_replay, write_tcp_response,
    };
    use crate::address::{Address, NetLocation, NetLocationMask};
    use crate::async_stream::{
        AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
        AsyncWriteMessage,
    };
    use crate::client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule};
    use crate::config::{
        ClientConfig, ClientProxyConfig, ClientQuicConfig, ConfigSelection, Transport,
    };
    use crate::dynamic::{ConnContext, SelectorSlot, StaticUserRegistry, UserContext};
    use crate::hysteria2_masquerade::Hysteria2Masquerade;
    use crate::option_util::{NoneOrOne, NoneOrSome, OneOrSome};
    use crate::resolver::{NativeResolver, Resolver};
    use crate::tcp::chain_builder::{
        build_client_chain_group, build_client_proxy_chain, build_direct_chain_group,
    };
    use bytes::Bytes;
    use futures::future::poll_fn;
    use rustc_hash::FxHashMap;
    use std::future::Future;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
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

    struct ReplyAndCountingWriteMessageStream {
        reply: Option<Vec<u8>>,
        writes: Arc<AtomicUsize>,
    }

    impl AsyncReadMessage for ReplyAndCountingWriteMessageStream {
        fn poll_read_message(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            match self.reply.take() {
                Some(reply) => {
                    buf.put_slice(&reply);
                    Poll::Ready(Ok(()))
                }
                None => Poll::Pending,
            }
        }
    }

    impl AsyncWriteMessage for ReplyAndCountingWriteMessageStream {
        fn poll_write_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<()>> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncFlushMessage for ReplyAndCountingWriteMessageStream {
        fn poll_flush_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncShutdownMessage for ReplyAndCountingWriteMessageStream {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for ReplyAndCountingWriteMessageStream {
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

    impl AsyncMessageStream for ReplyAndCountingWriteMessageStream {}

    fn location(port: u16) -> NetLocation {
        NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), port)
    }

    #[tokio::test]
    async fn pending_target_does_not_block_a_healthy_target_write_or_reply() {
        let global_permits = Arc::new(Semaphore::new(2));
        let session_permits = Arc::new(Semaphore::new(MAX_UDP_TARGETS_PER_SESSION));
        let queue_budget = Arc::new(Semaphore::new(32));
        let cancel = CancellationToken::new();
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let chain = build_client_chain_group(NoneOrSome::None, resolver.clone());
        let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
            vec![NetLocationMask::from("0.0.0.0/0").unwrap()],
            ConnectAction::new_allow(None, chain),
        )]));
        let (response_tx, mut response_rx) = tokio::sync::mpsc::channel(1);
        let mut targets = FxHashMap::default();

        let healthy = location(1001);
        let writes = Arc::new(AtomicUsize::new(0));
        let (healthy_tx, healthy_rx) = tokio::sync::mpsc::channel(8);
        let healthy_cancel = cancel.child_token();
        let mut healthy_remote: Box<dyn AsyncMessageStream> =
            Box::new(ReplyAndCountingWriteMessageStream {
                reply: Some(b"reply".to_vec()),
                writes: writes.clone(),
            });
        let healthy_task_cancel = healthy_cancel.clone();
        let healthy_response_tx = response_tx.clone();
        let healthy_permit = global_permits.clone().try_acquire_owned().unwrap();
        let healthy_location = healthy.clone();
        tokio::spawn(async move {
            run_connected_udp_target_worker(
                healthy_location,
                1,
                healthy_permit,
                healthy_rx,
                &mut healthy_remote,
                healthy_response_tx,
                healthy_task_cancel,
            )
            .await
            .unwrap();
        });
        targets.insert(
            healthy.clone(),
            UdpTargetWorker {
                outbound_tx: healthy_tx,
                last_used: 1,
                generation: 1,
                cancel_token: healthy_cancel,
            },
        );

        // Holding this receiver without polling models a second target whose
        // DNS/proxy connect is pending forever.
        let pending_target = location(1002);
        let (pending_tx, pending_rx) = tokio::sync::mpsc::channel(8);
        let _pending_rx = pending_rx;
        let _pending_permit = global_permits.clone().try_acquire_owned().unwrap();
        targets.insert(
            pending_target.clone(),
            UdpTargetWorker {
                outbound_tx: pending_tx,
                last_used: 2,
                generation: 2,
                cancel_token: cancel.child_token(),
            },
        );

        let mut use_counter = 2;
        let mut next_generation = 2;
        for (remote_location, payload) in [
            (pending_target, Bytes::from_static(b"blocked")),
            (healthy.clone(), Bytes::from_static(b"healthy")),
        ] {
            dispatch_udp_target_command(
                &mut targets,
                &mut use_counter,
                &mut next_generation,
                UdpForwardCommand {
                    remote_location,
                    payload: payload.clone(),
                    _payload_permit: try_reserve_payload_bytes(&queue_budget, payload.len())
                        .unwrap(),
                },
                &selector,
                &resolver,
                &global_permits,
                &session_permits,
                &response_tx,
                &cancel,
            );
        }

        tokio::time::timeout(Duration::from_secs(1), async {
            while writes.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let UdpTargetEvent::Message {
            remote_location,
            payload,
            ..
        } = tokio::time::timeout(Duration::from_secs(1), response_rx.recv())
            .await
            .unwrap()
            .unwrap()
        else {
            panic!("healthy target unexpectedly closed");
        };
        assert_eq!(remote_location, healthy);
        assert_eq!(payload, Bytes::from_static(b"reply"));
        cancel.cancel();
    }

    #[tokio::test]
    async fn exhausted_global_budget_rotates_without_losing_the_first_packet() {
        let permits = Arc::new(Semaphore::new(MAX_UDP_TARGETS_PER_SESSION));
        let session_permits = Arc::new(Semaphore::new(MAX_UDP_TARGETS_PER_SESSION));
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let mut targets = FxHashMap::default();
        for port in 1..=MAX_UDP_TARGETS_PER_SESSION as u16 {
            let global_permit = permits.clone().try_acquire_owned().unwrap();
            let session_permit = session_permits.clone().try_acquire_owned().unwrap();
            let cancel = CancellationToken::new();
            let task_cancel = cancel.clone();
            let task_active = active.clone();
            let task_max_active = max_active.clone();
            let current = active.fetch_add(1, Ordering::SeqCst) + 1;
            task_max_active.fetch_max(current, Ordering::SeqCst);
            tokio::spawn(async move {
                task_cancel.cancelled().await;
                task_active.fetch_sub(1, Ordering::SeqCst);
                drop(session_permit);
                drop(global_permit);
            });
            let (outbound_tx, _outbound_rx) = tokio::sync::mpsc::channel(1);
            targets.insert(
                location(port),
                UdpTargetWorker {
                    outbound_tx,
                    last_used: port as u64,
                    generation: port as u64,
                    cancel_token: cancel,
                },
            );
        }
        assert_eq!(permits.available_permits(), 0);
        assert_eq!(session_permits.available_permits(), 0);
        assert_eq!(active.load(Ordering::SeqCst), MAX_UDP_TARGETS_PER_SESSION);

        let replacement = try_reserve_udp_target_worker(&mut targets, &permits)
            .expect("a full association rotates its LRU target");
        assert!(matches!(&replacement, UdpTargetPermit::Awaiting(_)));
        assert_eq!(targets.len(), MAX_UDP_TARGETS_PER_SESSION - 1);

        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = peer.local_addr().unwrap();
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let chain = build_client_chain_group(NoneOrSome::None, resolver.clone());
        let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
            vec![NetLocationMask::from("0.0.0.0/0").unwrap()],
            ConnectAction::new_allow(None, chain),
        )]));
        let queue_budget = Arc::new(Semaphore::new(32));
        let cancel = CancellationToken::new();
        let remote_location =
            NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), destination.port());
        let command = UdpForwardCommand {
            remote_location: remote_location.clone(),
            payload: Bytes::from_static(b"replacement"),
            _payload_permit: try_reserve_payload_bytes(&queue_budget, 11).unwrap(),
        };
        let (session_permit, global_permit) = tokio::time::timeout(
            Duration::from_secs(1),
            acquire_udp_target_permits(replacement, session_permits.clone(), &cancel),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
        max_active.fetch_max(current, Ordering::SeqCst);
        let mut stream = connect_udp_target(&selector, &resolver, remote_location)
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, &command.payload))
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx))
            .await
            .unwrap();
        drop(command);

        let mut received = [0u8; 32];
        let (len, _) = tokio::time::timeout(Duration::from_secs(1), peer.recv_from(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received[..len], b"replacement");
        assert_eq!(permits.available_permits(), 0);
        assert_eq!(session_permits.available_permits(), 0);
        assert_eq!(
            max_active.load(Ordering::SeqCst),
            MAX_UDP_TARGETS_PER_SESSION
        );
        active.fetch_sub(1, Ordering::SeqCst);
        drop(session_permit);
        drop(global_permit);
        cancel.cancel();
        drop(targets);
    }

    #[test]
    fn fragmented_payload_and_response_counts_are_bounded() {
        assert_eq!(
            checked_udp_packet_len(MAX_UDP_PACKET_SIZE - 1, 1),
            Some(MAX_UDP_PACKET_SIZE)
        );
        assert_eq!(checked_udp_packet_len(MAX_UDP_PACKET_SIZE, 1), None);
        assert_eq!(checked_response_fragment_count(2550, 10).unwrap(), 255);
        assert!(checked_response_fragment_count(2560, 10).is_err());
    }

    #[tokio::test]
    async fn datagram_too_large_drops_only_current_response_and_next_uses_new_limit() {
        let meter = None;
        let cancel = CancellationToken::new();
        let source = location(53);
        let payload = vec![0x5a; 1300];

        let mut first_limit_queries = 0;
        let first = send_udp_response_with(
            7,
            &meter,
            11,
            &source,
            &payload,
            &cancel,
            || {
                first_limit_queries += 1;
                if first_limit_queries == 1 {
                    Some(1400)
                } else {
                    Some(1200)
                }
            },
            |datagram| {
                assert!(datagram.len() > 1200);
                Err(quinn::SendDatagramError::TooLarge)
            },
        )
        .await
        .unwrap();
        assert_eq!(
            first,
            UdpResponseSendOutcome::DroppedTooLarge {
                planned_max_datagram_size: 1400,
                current_max_datagram_size: Some(1200),
                attempted_datagram_len: 1321,
                fragment_id: 0,
                fragment_count: 1,
            }
        );
        assert_eq!(first_limit_queries, 2);

        let mut second_limit_queries = 0;
        let mut sent = Vec::new();
        let second = send_udp_response_with(
            7,
            &meter,
            12,
            &source,
            &payload,
            &cancel,
            || {
                second_limit_queries += 1;
                Some(1200)
            },
            |datagram| {
                assert!(datagram.len() <= 1200);
                sent.push(datagram);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(second, UdpResponseSendOutcome::Sent);
        assert_eq!(second_limit_queries, 1);
        assert_eq!(sent.len(), 2);

        let mut reassembled = Vec::new();
        for (fragment_id, datagram) in sent.iter().enumerate() {
            assert_eq!(&datagram[..4], &7u32.to_be_bytes());
            assert_eq!(&datagram[4..6], &12u16.to_be_bytes());
            assert_eq!(datagram[6], fragment_id as u8);
            assert_eq!(datagram[7], 2);
            let (address_len, address_start) = decode_udp_address_length(datagram).unwrap();
            let payload_start = address_start + address_len;
            reassembled.extend_from_slice(&datagram[payload_start..]);
        }
        assert_eq!(reassembled, payload);
    }

    #[tokio::test]
    async fn non_size_datagram_send_errors_remain_fatal() {
        let error = send_udp_response_with(
            7,
            &None,
            13,
            &location(53),
            b"payload",
            &CancellationToken::new(),
            || Some(1200),
            |_datagram| Err(quinn::SendDatagramError::UnsupportedByPeer),
        )
        .await
        .expect_err("unsupported datagrams are a connection-level failure");
        assert!(
            error
                .to_string()
                .contains("datagrams not supported by peer")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn datagram_send_failure_and_cancellation_refund_admission() {
        const RATE_BPS: u64 = 8 * 64 * 1024;

        let user = UserContext::new("alice");
        user.set_speed_limits(0, RATE_BPS);
        let conn = ConnContext::new();
        assert!(conn.bind(Arc::clone(&user)));
        let meter = Some(conn);
        let source = location(53);
        let payload = vec![0x5a; 65_000];

        send_udp_response_with(
            7,
            &meter,
            14,
            &source,
            &payload,
            &CancellationToken::new(),
            || Some(65_535),
            |_datagram| Err(quinn::SendDatagramError::UnsupportedByPeer),
        )
        .await
        .expect_err("the modeled Quinn send must fail");
        assert_eq!(user.tx(), 0, "a failed send is not traffic");

        // The failure returned its nearly full-burst permit, so retrying the
        // same datagram does not wait for another second of credit.
        let start = Instant::now();
        let mut sent_len = 0;
        let outcome = send_udp_response_with(
            7,
            &meter,
            15,
            &source,
            &payload,
            &CancellationToken::new(),
            || Some(65_535),
            |datagram| {
                sent_len = datagram.len();
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(outcome, UdpResponseSendOutcome::Sent);
        assert_eq!(Instant::now(), start);
        assert_eq!(user.tx(), sent_len as u64);

        // With the bucket now exhausted, cancellation wins while admission is
        // pending. No closure call and no byte count may escape it.
        let cancel = CancellationToken::new();
        let mut writes = 0;
        {
            let pending = send_udp_response_with(
                7,
                &meter,
                16,
                &source,
                &payload,
                &cancel,
                || Some(65_535),
                |_datagram| {
                    writes += 1;
                    Ok(())
                },
            );
            tokio::pin!(pending);
            assert!(futures::poll!(pending.as_mut()).is_pending());
            cancel.cancel();
            assert_eq!(pending.await.unwrap(), UdpResponseSendOutcome::Cancelled);
        }
        assert_eq!(writes, 0);
        assert_eq!(user.tx(), sent_len as u64);
    }

    #[test]
    fn fragmented_response_stops_before_the_next_write_after_cancellation() {
        let cancel = CancellationToken::new();
        let mut writes = 0;
        for fragment_id in 0..3 {
            if !udp_response_send_allowed(&cancel) {
                break;
            }
            writes += 1;
            if fragment_id == 0 {
                // Models cancellation while the first fragment's asynchronous
                // metering operation is pending.
                cancel.cancel();
            }
        }
        assert_eq!(writes, 1, "no fragment after cancellation reaches the wire");
    }

    #[test]
    fn connection_fragment_cache_bounds_512_sessions_and_total_bytes() {
        let mut cache = UdpFragmentCache::new();
        for session_id in 0..512 {
            cache
                .accept_fragment(
                    session_id,
                    1,
                    0,
                    2,
                    location(53),
                    Bytes::from(vec![0u8; 40_000]),
                )
                .unwrap();
        }
        assert!(cache.entries.len() <= MAX_FRAGMENT_CACHE_SIZE);
        assert!(cache.total_bytes <= MAX_UDP_FRAGMENT_BYTES_PER_CONNECTION);
        assert!(cache.entries.len() < 512);
    }

    #[test]
    fn fragment_zero_destination_wins_and_accounting_is_released() {
        let mut cache = UdpFragmentCache::new();
        let continuation_target = location(2000);
        let first_target = location(1000);
        assert!(
            cache
                .accept_fragment(7, 9, 1, 2, continuation_target, Bytes::from_static(b"tail"),)
                .unwrap()
                .is_none()
        );
        let (payload, target) = cache
            .accept_fragment(
                7,
                9,
                0,
                2,
                first_target.clone(),
                Bytes::from_static(b"head"),
            )
            .unwrap()
            .unwrap();
        assert_eq!(target, first_target);
        assert_eq!(payload, Bytes::from_static(b"headtail"));
        assert_eq!(cache.total_bytes, 0);
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn fragment_ttl_prevents_packet_id_wraparound_mixing_and_refreshes_on_progress() {
        let started = std::time::Instant::now();
        let mut cache = UdpFragmentCache::new();
        cache
            .accept_fragment_at(
                7,
                9,
                0,
                2,
                location(1000),
                Bytes::from_static(b"old-head"),
                started,
            )
            .unwrap();

        // The old fragment zero expires. A continuation with the wrapped packet
        // id starts a fresh entry and must not complete with the old payload or
        // destination.
        assert!(
            cache
                .accept_fragment_at(
                    7,
                    9,
                    1,
                    2,
                    location(2000),
                    Bytes::from_static(b"new-tail"),
                    started + super::UDP_FRAGMENT_TIMEOUT + Duration::from_millis(1),
                )
                .unwrap()
                .is_none()
        );
        let new_target = location(3000);
        let (payload, target) = cache
            .accept_fragment_at(
                7,
                9,
                0,
                2,
                new_target.clone(),
                Bytes::from_static(b"new-head"),
                started + super::UDP_FRAGMENT_TIMEOUT + Duration::from_secs(1),
            )
            .unwrap()
            .unwrap();
        assert_eq!(target, new_target);
        assert_eq!(payload, Bytes::from_static(b"new-headnew-tail"));

        // A continuation inside the age window still completes normally and its
        // access refreshes the entry rather than expiring it early.
        let mut live = UdpFragmentCache::new();
        live.accept_fragment_at(
            8,
            10,
            1,
            3,
            location(4000),
            Bytes::from_static(b"b"),
            started,
        )
        .unwrap();
        live.accept_fragment_at(
            8,
            10,
            2,
            3,
            location(4000),
            Bytes::from_static(b"c"),
            started + Duration::from_secs(9),
        )
        .unwrap();
        let completed = live
            .accept_fragment_at(
                8,
                10,
                0,
                3,
                location(5000),
                Bytes::from_static(b"a"),
                started + Duration::from_secs(18),
            )
            .unwrap()
            .unwrap();
        assert_eq!(completed.0, Bytes::from_static(b"abc"));
        assert_eq!(completed.1, location(5000));
    }

    #[test]
    fn fragment_error_and_session_cleanup_release_accounting() {
        let mut cache = UdpFragmentCache::new();
        cache
            .accept_fragment(1, 1, 0, 2, location(53), Bytes::from_static(b"one"))
            .unwrap();
        assert!(
            cache
                .accept_fragment(1, 1, 0, 2, location(53), Bytes::from_static(b"duplicate"),)
                .is_err()
        );
        assert_eq!(cache.total_bytes, 0);

        for packet_id in [2, 3] {
            cache
                .accept_fragment(
                    1,
                    packet_id,
                    0,
                    2,
                    location(53),
                    Bytes::from_static(b"pending"),
                )
                .unwrap();
        }
        cache.clear_session(1);
        assert_eq!(cache.total_bytes, 0);
        assert!(cache.entries.is_empty());
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
        let mut remote: Box<dyn AsyncMessageStream> =
            Box::new(CountingWriteMessageStream(writes.clone()));
        let (response_tx, _response_rx) = tokio::sync::mpsc::channel(1);
        let cancel = CancellationToken::new();
        cancel.cancel();
        run_connected_udp_target_worker(
            location(53),
            1,
            target_budget.try_acquire_owned().unwrap(),
            rx,
            &mut remote,
            response_tx,
            cancel,
        )
        .await
        .unwrap();
        assert_eq!(writes.load(Ordering::Relaxed), 0);
        assert_eq!(queue_budget.available_permits(), 16);
    }

    #[tokio::test]
    async fn routed_udp_connect_uses_allow_rule_chain() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = peer.local_addr().unwrap();
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let chain = build_client_chain_group(NoneOrSome::None, resolver.clone());
        let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
            vec![NetLocationMask::from("0.0.0.0/0").unwrap()],
            ConnectAction::new_allow(None, chain),
        )]));
        let mut stream = connect_udp_target(
            &selector,
            &resolver,
            NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), destination.port()),
        )
        .await
        .unwrap();

        poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, b"via-chain"))
            .await
            .unwrap();
        let mut received = [0u8; 32];
        let (len, _) = tokio::time::timeout(Duration::from_secs(1), peer.recv_from(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received[..len], b"via-chain");
    }

    #[tokio::test]
    async fn dropping_a_session_cancels_its_background_task() {
        let parent = CancellationToken::new();
        let token = parent.child_token();
        let (outbound_tx, _outbound_rx) = tokio::sync::mpsc::channel(1);
        let session = UdpSession {
            outbound_tx,
            last_activity: Arc::new(Mutex::new(std::time::Instant::now())),
            cancel_token: token.clone(),
        };

        drop(session);
        assert!(token.is_cancelled());
        assert!(!parent.is_cancelled());
    }

    #[test]
    fn periodic_cleanup_runs_without_datagrams_and_downlink_touch_prevents_reaping() {
        let started = std::time::Instant::now();
        let token = CancellationToken::new();
        let (outbound_tx, _outbound_rx) = tokio::sync::mpsc::channel(1);
        let session = UdpSession {
            outbound_tx,
            last_activity: Arc::new(Mutex::new(started)),
            cancel_token: token.clone(),
        };
        // The response path calls the same touch after a generation-valid remote read.
        session.touch(started + Duration::from_secs(59));
        let mut sessions = FxHashMap::default();
        sessions.insert(7, session);
        let mut fragments = UdpFragmentCache::new();

        cleanup_udp_sessions(
            &mut sessions,
            &mut fragments,
            started + Duration::from_secs(61),
        );
        assert!(sessions.contains_key(&7));
        assert!(!token.is_cancelled());

        cleanup_udp_sessions(
            &mut sessions,
            &mut fragments,
            started + Duration::from_secs(120),
        );
        assert!(!sessions.contains_key(&7));
        assert!(token.is_cancelled());
    }

    #[test]
    fn changed_fragment_count_is_rejected_before_indexing_and_releases_accounting() {
        let mut cache = UdpFragmentCache::new();
        cache
            .accept_fragment(1, 7, 0, 2, location(53), Bytes::from_static(b"head"))
            .unwrap();
        let error = cache
            .accept_fragment(1, 7, 254, 255, location(53), Bytes::from_static(b"tail"))
            .expect_err("fragment count mismatch must be an ordinary packet error");
        assert!(error.to_string().contains("Mismatched fragment count"));
        assert_eq!(cache.total_bytes, 0);
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn udp_address_length_rejects_truncated_multibyte_varints() {
        for first_byte in [0x40, 0x80, 0xc0] {
            let mut datagram = [0u8; 9];
            datagram[8] = first_byte;
            assert_eq!(decode_udp_address_length(&datagram), None);
        }
    }

    #[test]
    fn udp_address_length_accepts_complete_varints() {
        let mut one_byte = [0u8; 9];
        one_byte[8] = 7;
        assert_eq!(decode_udp_address_length(&one_byte), Some((7, 9)));

        let mut eight_byte = [0u8; 16];
        eight_byte[8] = 0xc0;
        eight_byte[15] = 1;
        assert_eq!(decode_udp_address_length(&eight_byte), Some((1, 16)));
    }

    #[test]
    fn udp_fragment_indices_must_be_within_the_declared_count() {
        assert!(!valid_udp_fragment(0, 0));
        assert!(!valid_udp_fragment(1, 1));
        assert!(!valid_udp_fragment(2, 2));
        assert!(valid_udp_fragment(0, 1));
        assert!(valid_udp_fragment(1, 2));
    }

    fn decode_test_varint(bytes: &[u8]) -> (u64, usize) {
        let width = 1usize << (bytes[0] >> 6);
        let mut value = u64::from(bytes[0] & 0x3f);
        for byte in &bytes[1..width] {
            value = (value << 8) | u64::from(*byte);
        }
        (value, width)
    }

    fn assert_tcp_response_shape(response: &[u8], expected_status: u8) -> &[u8] {
        assert_eq!(response[0], expected_status);
        let (message_len, message_width) = decode_test_varint(&response[1..]);
        let message_start = 1 + message_width;
        let message_end = message_start + message_len as usize;
        let (padding_len, padding_width) = decode_test_varint(&response[message_end..]);
        assert_eq!(
            response.len(),
            message_end + padding_width + padding_len as usize
        );
        &response[message_start..message_end]
    }

    #[test]
    fn tcp_response_status_and_error_message_match_the_wire_contract() {
        let success = encode_tcp_response(true, "").unwrap();
        assert!(assert_tcp_response_shape(&success, 0).is_empty());

        // 2048 is not a character boundary for this three-byte scalar. The encoder
        // must stay within the protocol byte limit without creating invalid UTF-8.
        let oversized = "错".repeat(MAX_TCP_RESPONSE_MESSAGE_LENGTH);
        let failure = encode_tcp_response(false, &oversized).unwrap();
        let message = assert_tcp_response_shape(&failure, 1);
        assert!(message.len() <= MAX_TCP_RESPONSE_MESSAGE_LENGTH);
        assert!(message.len() > MAX_TCP_RESPONSE_MESSAGE_LENGTH - '错'.len_utf8());
        assert!(std::str::from_utf8(message).is_ok());
    }

    struct ZeroWriter;

    impl AsyncWrite for ZeroWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            assert!(!buffer.is_empty());
            Poll::Ready(Ok(0))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn tcp_response_and_fast_open_replay_report_write_zero() {
        let response_error = write_tcp_response(&mut ZeroWriter, false, "DNS failed")
            .await
            .expect_err("a zero-length response write must not spin");
        assert_eq!(response_error.kind(), std::io::ErrorKind::WriteZero);

        let replay_error = write_tcp_fast_open_replay(&mut ZeroWriter, b"early payload")
            .await
            .expect_err("a zero-length replay write must not spin");
        assert_eq!(replay_error.kind(), std::io::ErrorKind::WriteZero);
    }

    #[derive(Debug)]
    struct RejectHostnameResolver;

    impl Resolver for RejectHostnameResolver {
        fn resolve_location(
            &self,
            location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
            if let Some(address) = location.to_socket_addr_nonblocking() {
                return Box::pin(std::future::ready(Ok(vec![address])));
            }
            let location = location.clone();
            Box::pin(async move {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("test DNS failure for {location}"),
                ))
            })
        }
    }

    #[tokio::test]
    async fn dns_failure_is_reported_and_the_next_hysteria_stream_still_works() {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate test certificate");
        let server_tls = Arc::new(crate::rustls_config_util::create_server_config(
            certificate.cert.pem().as_bytes(),
            certificate.signing_key.serialize_pem().as_bytes(),
            Vec::new(),
            &["h3".to_string()],
            &[],
        ));
        let server_quic: quinn::crypto::rustls::QuicServerConfig =
            server_tls.try_into().expect("convert test QUIC server TLS");

        let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_address = reservation.local_addr().unwrap();
        drop(reservation);

        let resolver: Arc<dyn Resolver> = Arc::new(RejectHostnameResolver);
        let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
            vec![NetLocationMask::ANY],
            ConnectAction::new_allow(None, build_direct_chain_group(Arc::clone(&resolver))),
        )]));
        let selector = SelectorSlot::new(selector, Arc::clone(&resolver));
        let shutdown = CancellationToken::new();
        let server_tasks = super::start_hysteria2_server(
            server_address,
            Arc::new(server_quic),
            StaticUserRegistry::single_password("test-password"),
            false,
            selector,
            1,
            false,
            0,
            0,
            false,
            None,
            Arc::new(Hysteria2Masquerade::new(None).unwrap()),
            shutdown.clone(),
            CancellationToken::new(),
        )
        .await
        .expect("start Hysteria2 test server");

        let tcp_echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_echo_address = tcp_echo.local_addr().unwrap();
        let tcp_echo_task = tokio::spawn(async move {
            let (mut stream, _) = tcp_echo.accept().await.unwrap();
            let mut data = [0_u8; 11];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(25)).await;
        let chain = build_client_proxy_chain(
            OneOrSome::One(crate::config::ClientChainHop::Single(
                ConfigSelection::Config(ClientConfig {
                    address: NetLocation::from_ip_addr(server_address.ip(), server_address.port()),
                    protocol: ClientProxyConfig::Hysteria2 {
                        password: "test-password".to_string(),
                        udp_enabled: false,
                        up_mbps: 0,
                        down_mbps: 0,
                        obfs: None,
                        server_ports: NoneOrSome::None,
                        hop_interval: None,
                    },
                    transport: Transport::Quic,
                    quic_settings: Some(ClientQuicConfig {
                        verify: false,
                        sni_hostname: NoneOrOne::One("localhost".to_string()),
                        ..ClientQuicConfig::default()
                    }),
                    ..ClientConfig::default()
                }),
            )),
            Arc::clone(&resolver),
        );

        let failed_target = NetLocation::new(Address::Hostname("upload.invalid".into()), 8080);
        let failed = tokio::time::timeout(
            Duration::from_secs(3),
            chain.connect_tcp(failed_target.into(), &resolver),
        )
        .await
        .expect("the server must report DNS failure without waiting for stream EOF");
        let error = match failed {
            Ok(_) => panic!("DNS failure was incorrectly reported as TCP handshake success"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("test DNS failure"), "{error}");

        let mut proxied = chain
            .connect_tcp(
                NetLocation::from_ip_addr(tcp_echo_address.ip(), tcp_echo_address.port()).into(),
                &resolver,
            )
            .await
            .expect("a DNS failure on one stream must not close the Hysteria2 connection")
            .client_stream;
        proxied.write_all(b"still-alive").await.unwrap();
        proxied.flush().await.unwrap();
        let mut reply = [0_u8; 11];
        tokio::time::timeout(Duration::from_secs(3), proxied.read_exact(&mut reply))
            .await
            .expect("echo after failed stream timed out")
            .unwrap();
        assert_eq!(&reply, b"still-alive");

        drop(proxied);
        drop(chain);
        shutdown.cancel();
        tcp_echo_task.await.unwrap();
        for task in server_tasks {
            let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
        }
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
                    // Models a peer that supplies another header byte often enough
                    // to defeat a per-read timeout but never completes the header.
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
}
