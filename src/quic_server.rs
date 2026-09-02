use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use log::{debug, warn};
use quinn::EndpointConfig;
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until, timeout, timeout_at};
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ConnectDecision;
use crate::config::{
    BindLocation, ConfigSelection, ServerConfig, ServerProxyConfig, ServerQuicConfig,
};
use crate::copy_bidirectional::copy_bidirectional;
use crate::dynamic::{
    ConnContext, HandlerSlot, InboundReplayScope, ServerHandle, StaticUserRegistry,
    TrafficMeterStream, UserRegistry, scope_connection_until_cancelled,
};
use crate::quic_stream::QuicStream;
use crate::resolver::Resolver;
use crate::routing::{ServerStream, run_udp_routing};
use crate::rustls_config_util::create_server_config;
use crate::socket_util::new_socket2_udp_socket;
use crate::tcp::handshake_gate::{
    DEFERRED_AUTHENTICATION_TIMEOUT, HandshakeGate, HandshakePermit, MAX_ACTIVE_FALLBACKS,
    MAX_ACTIVE_FALLBACKS_PER_SOURCE, MAX_PENDING_HANDSHAKES, MAX_PENDING_PER_SOURCE,
};
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector_with_sniff_policy;
use crate::tcp::tcp_handler::{
    DeferredAuthenticationCompletion, DeferredAuthenticationOutcome, TcpServerHandler,
    TcpServerSetupResult, UnauthenticatedFallbackCompletion,
};
use crate::tcp::tcp_server::{
    ResolvedBind, apply_client_early_data, client_stream_setup_error, client_stream_setup_timeout,
    prepare_client_tcp_stream_with_metadata, run_udp_copy, sniff_tcp_after_success_response,
};
use crate::tcp::tcp_server_handler_factory::create_tcp_server_handler_with_replay_state;

/// How long a cancelled QUIC endpoint waits for its live connections before it
/// drops the socket.
///
/// A QUIC connection is multiplexed over the endpoint's UDP socket, so unlike TCP
/// the port cannot be released while connections are still using it -- letting them
/// finish and freeing the port are the same act. The wait has to be bounded anyway:
/// a client holding a connection open must not be able to keep the port claimed
/// indefinitely and block whatever wants to listen there next.
pub(crate) const QUIC_DRAIN_TIMEOUT: Duration = Duration::from_secs(3);

/// The absolute lifetime of an application-layer-unauthenticated QUIC peer.
///
/// This outer deadline starts when a Retry-validated Incoming is charged to a gate
/// and covers the transport handshake plus H3/application setup. Native protocols
/// retain their shorter application-authentication timer inside this ceiling. QUIC
/// activity, including PING frames, cannot reset either deadline.
pub(crate) const QUIC_PRE_AUTH_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum time spent on the QUIC transport handshake after Retry has validated
/// the peer's address.
///
/// Application protocols keep their own authentication window inside the outer
/// pre-auth deadline. A shorter transport-only window prevents a real but silent
/// peer from holding one listener admission for the transport's 30-60 second idle
/// timeout without ever reaching application authentication.
pub(crate) const QUIC_TRANSPORT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Live generic-QUIC transports admitted by one listener.
///
/// Unlike the stream gate, this is deliberately an active-connection quota rather
/// than a pending-handshake quota. Generic QUIC has no connection-level identity:
/// every bidi stream can authenticate independently (or use an unauthenticated
/// protocol), so releasing this quota after one cheap stream would allow unlimited
/// empty transports kept alive with QUIC PING frames. These names stay separate from
/// the handshake constants so their different lifetime and sizing are explicit.
const MAX_ACTIVE_GENERIC_QUIC_CONNECTIONS: usize = 1024;
const MAX_ACTIVE_GENERIC_QUIC_CONNECTIONS_PER_SOURCE: usize = 64;

/// Cancellation root for one physical QUIC connection.
///
/// The token inherits a hard inbound removal from `parent`. Its owned guard also
/// cancels the token on every natural or error return from the connection task, so
/// detached logical work cannot outlive the transport that created it.
pub(crate) struct QuicConnectionLifecycle {
    token: CancellationToken,
    _cancel_on_drop: DropGuard,
}

impl QuicConnectionLifecycle {
    pub(crate) fn new(parent: &CancellationToken) -> Self {
        let token = parent.child_token();
        let cancel_on_drop = token.clone().drop_guard();
        Self {
            token,
            _cancel_on_drop: cancel_on_drop,
        }
    }

    pub(crate) fn token(&self) -> &CancellationToken {
        &self.token
    }
}

/// Error codes used only by the generic QUIC transport.
///
/// Zero means success/application shutdown in a number of protocols. Refusing work
/// because a resource or authentication deadline was exceeded must be observable as
/// an error by the peer rather than looking like a clean end of stream.
const QUIC_ERR_PRE_AUTH_TIMEOUT: u32 = 1;
const QUIC_ERR_HANDSHAKE_LIMIT: u32 = 2;
const QUIC_ERR_INBOUND_HARD_CLOSE: u32 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IncomingAddressAction {
    Accept,
    Retry,
    Refuse,
}

fn incoming_address_action(validated: bool, may_retry: bool) -> IncomingAddressAction {
    if validated {
        IncomingAddressAction::Accept
    } else if may_retry {
        IncomingAddressAction::Retry
    } else {
        // Quinn currently guarantees that an unvalidated Incoming may be retried.
        // Keep this branch defensive: accepting here after an API/implementation
        // change would charge a spoofable source address to the listener gate.
        IncomingAddressAction::Refuse
    }
}

/// Require QUIC address validation before allocating a connection or gate permit.
///
/// A successful Retry consumes `incoming`; the client's token-bearing Initial will
/// arrive through `Endpoint::accept` as a new, validated Incoming. A theoretically
/// impossible Retry failure returns the original Incoming, which is explicitly
/// refused rather than accidentally accepted without validation.
pub(crate) fn require_validated_quic_address(
    incoming: quinn::Incoming,
    protocol: &str,
) -> Option<quinn::Incoming> {
    let remote = incoming.remote_address();
    match incoming_address_action(incoming.remote_address_validated(), incoming.may_retry()) {
        IncomingAddressAction::Accept => Some(incoming),
        IncomingAddressAction::Retry => {
            debug!("requiring QUIC address validation from {remote} before {protocol} admission");
            if let Err(error) = incoming.retry() {
                debug!(
                    "QUIC Retry unexpectedly unavailable for {remote}; refusing {protocol} peer"
                );
                error.into_incoming().refuse();
            }
            None
        }
        IncomingAddressAction::Refuse => {
            debug!("refusing unvalidated {protocol} peer {remote}: QUIC Retry is unavailable");
            incoming.refuse();
            None
        }
    }
}

/// Pending protocol handshakes carried by one generic QUIC connection.
///
/// Generic QUIC differs from Hysteria2 and TUIC: the QUIC connection itself has no
/// application authentication, and every bidi stream performs an independent
/// configured-protocol handshake. Its connection-lifetime permit is therefore kept
/// separately by `process_connection`, while every pending stream takes a permit
/// from this state. Keeping the two gates separate matters: a source legitimately at
/// its connection ceiling must still be able to authenticate a stream on those
/// connections rather than deadlocking against its own connection permits.
struct QuicHandshakeState {
    stream_gate: Arc<HandshakeGate>,
    fallback_gate: Arc<HandshakeGate>,
    source: IpAddr,
    first_handshake_completed: AtomicBool,
    first_handshake_notify: Notify,
}

impl QuicHandshakeState {
    fn new(
        stream_gate: Arc<HandshakeGate>,
        fallback_gate: Arc<HandshakeGate>,
        source: IpAddr,
    ) -> Arc<Self> {
        Arc::new(Self {
            stream_gate,
            fallback_gate,
            source,
            first_handshake_completed: AtomicBool::new(false),
            first_handshake_notify: Notify::new(),
        })
    }

    fn enter_stream(self: &Arc<Self>) -> Option<QuicStreamHandshakePermit> {
        self.stream_gate
            .enter(Some(self.source))
            .map(|permit| QuicStreamHandshakePermit {
                state: self.clone(),
                _permit: permit,
            })
    }

    fn first_handshake_completed(&self) -> bool {
        self.first_handshake_completed.load(Ordering::Acquire)
    }

    fn enter_fallback(&self) -> Option<HandshakePermit> {
        self.fallback_gate.enter(Some(self.source))
    }
}

async fn first_handshake_completed_before_deadline(
    state: Arc<QuicHandshakeState>,
    deadline: Instant,
) -> bool {
    loop {
        // `notify_one` stores a permit when it races this future before polling, so
        // constructing the waiter before the acquire-load cannot lose completion.
        let completed = state.first_handshake_notify.notified();
        if state.first_handshake_completed() {
            return true;
        }
        tokio::select! {
            () = completed => {}
            () = sleep_until(deadline) => return state.first_handshake_completed(),
        }
    }
}

/// One generic QUIC stream's place in the pending-handshake budget.
///
/// `complete` is deliberately explicit. Dropping before it means the configured
/// protocol handshake failed or was cancelled, so only a real successful setup can
/// disarm the connection's absolute pre-auth deadline.
struct QuicStreamHandshakePermit {
    state: Arc<QuicHandshakeState>,
    _permit: HandshakePermit,
}

impl QuicStreamHandshakePermit {
    fn complete(self) {
        let was_complete = self
            .state
            .first_handshake_completed
            .swap(true, Ordering::AcqRel);
        if !was_complete {
            self.state.first_handshake_notify.notify_one();
        }
        // `self` then drops the independent stream permit. The connection permit is
        // owned by `process_connection`, whose completion waiter releases it.
    }
}

/// Prepare a complete endpoint batch before any accept task is spawned.
///
/// This is deliberately generic so the native QUIC protocols use the same
/// all-or-nothing boundary. If `prepare` fails partway through, dropping the local
/// vector closes every socket prepared earlier in the batch.
pub(crate) fn prepare_endpoint_batch<T>(
    count: usize,
    mut prepare: impl FnMut() -> std::io::Result<T>,
) -> std::io::Result<Vec<T>> {
    let mut endpoints = Vec::with_capacity(count);
    for _ in 0..count {
        endpoints.push(prepare()?);
    }
    Ok(endpoints)
}

async fn start_quic_server(
    bind_address: SocketAddr,
    quic_server_config: Arc<quinn::crypto::rustls::QuicServerConfig>,
    // No resolver: this loop takes it from the slot, with the handler, so a
    // connection cannot mix one generation's rules with another's DNS.
    handler_slot: Arc<HandlerSlot>,
    num_endpoints: usize,
    metered: bool,
    cancel: CancellationToken,
    connection_cancel: CancellationToken,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    // Connections and stream handshakes are different resources and need independent
    // shares. Sharing each gate across the endpoint fan-out prevents `num_endpoints`
    // from multiplying either ceiling.
    let connection_gate = HandshakeGate::new(
        MAX_ACTIVE_GENERIC_QUIC_CONNECTIONS,
        MAX_ACTIVE_GENERIC_QUIC_CONNECTIONS_PER_SOURCE,
    );
    let stream_gate = HandshakeGate::new(MAX_PENDING_HANDSHAKES, MAX_PENDING_PER_SOURCE);
    let fallback_gate = HandshakeGate::new(MAX_ACTIVE_FALLBACKS, MAX_ACTIVE_FALLBACKS_PER_SOURCE);
    let endpoints = prepare_endpoint_batch(num_endpoints, || {
        let mut server_config = quinn::ServerConfig::with_crypto(quic_server_config.clone());
        // A peer cannot create more simultaneous bidi streams on one connection than
        // one source is allowed to hold in the listener-wide stream-handshake gate.
        // Generic QUIC has no use for peer-opened unidirectional streams.
        Arc::get_mut(&mut server_config.transport)
            .unwrap()
            .max_concurrent_bidi_streams((MAX_PENDING_PER_SOURCE as u32).into())
            .max_concurrent_uni_streams(0_u8.into());

        // Only ask for SO_REUSEPORT when there is actually a second endpoint to share
        // the port with; a single endpoint does not need it, and platforms that lack
        // it panic rather than fail.
        let socket2_socket = new_socket2_udp_socket(
            bind_address.is_ipv6(),
            None,
            Some(bind_address),
            num_endpoints > 1,
        )?;

        quinn::Endpoint::new(
            EndpointConfig::default(),
            Some(server_config),
            socket2_socket.into(),
            Arc::new(quinn::TokioRuntime),
        )
    })?;

    let mut join_handles = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let handler_slot = handler_slot.clone();
        let connection_gate = connection_gate.clone();
        let stream_gate = stream_gate.clone();
        let fallback_gate = fallback_gate.clone();
        let cancel = cancel.clone();
        let connection_cancel = connection_cancel.clone();
        let join_handle = tokio::spawn(async move {
            loop {
                let conn = tokio::select! {
                    biased;
                    () = connection_cancel.cancelled() => break,
                    () = cancel.cancelled() => break,
                    incoming = endpoint.accept() => match incoming {
                        Some(conn) => conn,
                        // The endpoint closed on its own.
                        None => break,
                    },
                };
                let Some(conn) = require_validated_quic_address(conn, "generic QUIC") else {
                    continue;
                };
                let remote_ip = conn.remote_address().ip();
                let Some(connection_permit) = connection_gate.enter(Some(remote_ip)) else {
                    debug!(
                        "refusing QUIC peer {remote_ip}: the listener is at its connection limit"
                    );
                    conn.refuse();
                    continue;
                };
                let pre_auth_deadline = Instant::now() + QUIC_PRE_AUTH_TIMEOUT;
                let handshake_state =
                    QuicHandshakeState::new(stream_gate.clone(), fallback_gate.clone(), remote_ip);
                // Generic QUIC authenticates and routes each bidirectional stream
                // independently. Keep the slot on the transport so every newly
                // accepted logical flow observes the current handler and its paired
                // resolver, while an already-running stream retains its loaded Arc.
                let handler_slot = handler_slot.clone();
                let stream_connection_cancel = connection_cancel.clone();
                tokio::spawn(async move {
                    if let Err(e) = process_connection(
                        handler_slot,
                        conn,
                        metered,
                        handshake_state,
                        connection_permit,
                        pre_auth_deadline,
                        stream_connection_cancel,
                    )
                    .await
                    {
                        debug!("QUIC connection from {remote_ip} ended: {e}");
                    }
                });
            }

            if connection_cancel.is_cancelled() {
                hard_close_endpoint(endpoint, bind_address).await;
            } else {
                drain_endpoint(endpoint, bind_address).await;
            }
        });

        join_handles.push(join_handle);
    }

    Ok(join_handles)
}

/// Stop taking new QUIC connections on `endpoint` and let the live ones finish.
///
/// Bounded by [`QUIC_DRAIN_TIMEOUT`]; see its documentation for why the port cannot
/// simply be released the way a TCP listener's is.
pub(crate) async fn drain_endpoint(endpoint: quinn::Endpoint, bind_address: SocketAddr) {
    // quinn refuses an incoming handshake when the endpoint has no server config,
    // which is how it spells "stop accepting" -- it is documented to affect new
    // connections only, so the live ones are untouched.
    endpoint.set_server_config(None);
    if tokio::time::timeout(QUIC_DRAIN_TIMEOUT, endpoint.wait_idle())
        .await
        .is_err()
    {
        debug!(
            "quic endpoint on {bind_address} still had {} live connection(s) after \
             {QUIC_DRAIN_TIMEOUT:?}; closing anyway",
            endpoint.open_connections()
        );
    }
}

/// Immediately close every connection on an endpoint, then wait only for quinn to
/// finish processing that forced close and release the socket.
///
/// This is intentionally distinct from [`drain_endpoint`]: the close signal is sent
/// before waiting, so a peer cannot extend a hard inbound removal by keeping a QUIC
/// stream alive.
pub(crate) async fn hard_close_endpoint(endpoint: quinn::Endpoint, bind_address: SocketAddr) {
    let open_connections = endpoint.open_connections();
    endpoint.close(QUIC_ERR_INBOUND_HARD_CLOSE.into(), b"inbound hard close");
    if tokio::time::timeout(QUIC_DRAIN_TIMEOUT, endpoint.wait_idle())
        .await
        .is_err()
    {
        debug!(
            "quic endpoint on {bind_address} still had work after hard-closing \
             {open_connections} connection(s); dropping it"
        );
    }
}

async fn process_connection(
    handler_slot: Arc<HandlerSlot>,
    conn: quinn::Incoming,
    metered: bool,
    handshake_state: Arc<QuicHandshakeState>,
    connection_permit: HandshakePermit,
    pre_auth_deadline: Instant,
    connection_cancel: CancellationToken,
) -> std::io::Result<()> {
    // Generic QUIC has no connection-level user identity: every stream performs an
    // independent configured-protocol handshake. Keep the separate active-transport
    // quota until the connection ends so one cheap successful stream cannot leave an
    // unlimited pool of empty, PING-kept-alive transports.
    let _connection_permit = connection_permit;
    // Streams need a transport-local cancellation parent, not a clone of the
    // inbound-wide token. It inherits hard removal, while this guard additionally
    // cancels detached logical work when the physical QUIC connection ends normally.
    let connection_lifecycle = QuicConnectionLifecycle::new(&connection_cancel);
    let transport_deadline = std::cmp::min(
        pre_auth_deadline,
        Instant::now() + QUIC_TRANSPORT_HANDSHAKE_TIMEOUT,
    );
    let connection = tokio::select! {
        biased;
        () = connection_lifecycle.token().cancelled() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "generic QUIC inbound was hard-stopped during transport handshake",
            ));
        }
        result = timeout_at(transport_deadline, conn) => match result {
            Ok(result) => result?,
            Err(_elapsed) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "generic QUIC transport handshake exceeded the pre-auth deadline",
                ));
            }
        }
    };

    let mut pre_auth_completion = Box::pin(first_handshake_completed_before_deadline(
        handshake_state.clone(),
        pre_auth_deadline,
    ));
    let mut pre_auth_pending = true;

    loop {
        if pre_auth_pending && handshake_state.first_handshake_completed() {
            pre_auth_pending = false;
        }

        let accepted = tokio::select! {
            biased;
            () = connection_lifecycle.token().cancelled() => {
                connection.close(QUIC_ERR_INBOUND_HARD_CLOSE.into(), b"inbound hard close");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "generic QUIC inbound was hard-stopped",
                ));
            }
            completed = &mut pre_auth_completion, if pre_auth_pending => {
                // A stream can complete without opening another stream to wake
                // `accept_bi`; Notify releases the admission immediately rather
                // than retaining it until the absolute deadline.
                if completed {
                    pre_auth_pending = false;
                    continue;
                }
                connection.close(QUIC_ERR_PRE_AUTH_TIMEOUT.into(), b"pre-auth timeout");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "generic QUIC first protocol handshake exceeded the pre-auth deadline",
                ));
            }
            accepted = connection.accept_bi() => accepted,
        };

        let (mut send, mut recv) = match accepted {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                debug!("Connection closed");
                break;
            }
            Err(e) => {
                return Err(std::io::Error::other(format!("quic connection error: {e}")));
            }
            Ok(s) => s,
        };
        let Some(handshake_permit) = handshake_state.enter_stream() else {
            debug!(
                "refusing a stream from {}: the listener is at its pending-handshake limit",
                connection.remote_address().ip()
            );
            let _ = send.reset(QUIC_ERR_HANDSHAKE_LIMIT.into());
            let _ = recv.stop(QUIC_ERR_HANDSHAKE_LIMIT.into());
            continue;
        };
        // Load after accepting the stream and before spawning its task. The pair is
        // one atomic slot generation, and the task-owned Arcs pin that generation
        // for this flow even if a reload happens while its handshake is in flight.
        let (cloned_handler, cloned_resolver) = handler_slot.load();
        let stream_connection_cancel = connection_lifecycle.token().clone();
        tokio::spawn(async move {
            if let Err(e) = process_streams(
                cloned_resolver,
                cloned_handler,
                (send, recv),
                metered,
                handshake_permit,
                stream_connection_cancel,
            )
            .await
            {
                debug!("QUIC stream ended: {e}");
            }
        });
    }

    Ok(())
}

/// Handle one QUIC bidirectional stream, counting its traffic if the inbound is
/// metered.
///
/// Each bidi stream carries its own protocol handshake, so each one authenticates
/// separately and is counted as its own connection even when several share a QUIC
/// connection.
///
/// What gets counted here is stream bytes, not datagram bytes: quinn owns the
/// framing, the packet encryption and the UDP socket, and a datagram on that socket
/// can carry frames belonging to several streams or to no stream at all. So a QUIC
/// inbound's figures exclude QUIC's own per-packet overhead, where a TCP inbound's
/// include TLS's.
async fn process_streams(
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
    (send, recv): (quinn::SendStream, quinn::RecvStream),
    metered: bool,
    handshake_permit: QuicStreamHandshakePermit,
    connection_cancel: CancellationToken,
) -> std::io::Result<()> {
    let quic_stream = QuicStream::from(send, recv);

    scope_generic_quic_stream_until_cancelled(&connection_cancel, move |conn| async move {
        let quic_stream: Box<dyn AsyncStream> = if metered {
            Box::new(TrafficMeterStream::new(quic_stream, conn))
        } else {
            Box::new(quic_stream)
        };
        serve_stream(resolver, server_handler, quic_stream, handshake_permit).await
    })
    .await
}

/// Run one independently authenticated generic-QUIC stream under its physical
/// connection's lifecycle (which itself inherits the inbound hard-removal tree).
/// A context exists even when byte accounting is disabled so a handler that
/// detaches a fallback or mux session can carry the same cancellation token across
/// its own `tokio::spawn` boundary.
async fn scope_generic_quic_stream_until_cancelled<F, Fut>(
    connection_cancel: &CancellationToken,
    build: F,
) -> std::io::Result<()>
where
    F: FnOnce(Arc<ConnContext>) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<()>>,
{
    let conn = ConnContext::new_child(connection_cancel);
    let future = build(Arc::clone(&conn));
    scope_connection_until_cancelled(conn, future).await
}

async fn serve_stream(
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
    quic_stream: Box<dyn AsyncStream>,
    handshake_permit: QuicStreamHandshakePermit,
) -> std::io::Result<()> {
    let setup_server_stream_future = timeout(
        Duration::from_secs(60),
        server_handler.setup_server_stream(quic_stream),
    );

    let setup_result = match setup_server_stream_future.await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            return Err(std::io::Error::new(
                e.kind(),
                format!("failed to setup server stream: {e}"),
            ));
        }
        Err(elapsed) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("server setup timed out: {elapsed}"),
            ));
        }
    };

    let admission = finish_stream_handshake(&setup_result, handshake_permit)?;

    match setup_result {
        TcpServerSetupResult::TcpForward {
            remote_location,
            stream: mut server_stream,
            need_initial_flush: server_need_initial_flush,
            proxy_selector,
            mut connection_success_response,
            initial_remote_data,
        } => {
            let mut replay = initial_remote_data.map(Vec::from).unwrap_or_default();
            let sniffed = sniff_tcp_after_success_response(
                &mut server_stream,
                proxy_selector.needs_tcp_sniff(),
                &mut connection_success_response,
                &mut replay,
            )
            .await?;
            let setup_client_stream_future = timeout(
                Duration::from_secs(60),
                prepare_client_tcp_stream_with_metadata(
                    proxy_selector,
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
            let mut client_stream =
                apply_client_early_data(&mut server_stream, client_setup).await?;

            if let Some(data) = connection_success_response {
                server_stream.write_all(&data).await?;
                // server_need_initial_flush should be set to true by the handler if
                // it's needed.
            }

            let client_need_initial_flush = if replay.is_empty() {
                false
            } else {
                client_stream.write_all(&replay).await?;
                true
            };

            let copy_result = copy_bidirectional(
                &mut server_stream,
                &mut client_stream,
                server_need_initial_flush,
                client_need_initial_flush,
            )
            .await;

            let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());

            copy_result?;
            Ok(())
        }
        TcpServerSetupResult::BidirectionalUdp {
            remote_location,
            stream: server_stream,
            need_initial_flush: server_need_initial_flush,
            proxy_selector,
        } => {
            let requested_location = remote_location.clone();
            let action = match proxy_selector
                .judge_udp(remote_location.into(), &resolver)
                .await
            {
                Ok(action) => action,
                Err(error) => {
                    warn!("UDP routing for {requested_location} failed: {error}");
                    return Err(error);
                }
            };
            match action {
                ConnectDecision::Allow {
                    chain_group,
                    remote_location,
                } => {
                    let outbound_location = remote_location.clone();
                    let client_stream = chain_group
                        .connect_udp_bidirectional(&resolver, remote_location)
                        .await
                        .map_err(|error| {
                            warn!("UDP outbound setup to {outbound_location} failed: {error}");
                            error
                        })?;

                    run_udp_copy(
                        server_stream,
                        client_stream,
                        server_need_initial_flush,
                        false,
                    )
                    .await
                }
                ConnectDecision::Block => Ok(()),
            }
        }
        TcpServerSetupResult::MultiDirectionalUdp {
            stream: server_stream,
            need_initial_flush,
            proxy_selector,
        } => {
            // Routes each packet based on its destination
            run_udp_routing(
                ServerStream::Targeted(server_stream),
                proxy_selector,
                resolver,
                need_initial_flush,
            )
            .await
        }
        TcpServerSetupResult::SessionBasedUdp {
            stream: server_stream,
            need_initial_flush,
            proxy_selector,
        } => {
            // Routes each session based on its destination
            run_udp_routing(
                ServerStream::Session(server_stream),
                proxy_selector,
                resolver,
                need_initial_flush,
            )
            .await
        }
        TcpServerSetupResult::AlreadyHandled => Ok(()),
        TcpServerSetupResult::UnauthenticatedFallbackHandled(completion) => {
            wait_for_quic_fallback(
                completion,
                match admission {
                    StreamSetupAdmission::Fallback(permit) => permit,
                    _ => unreachable!("fallback setup transfers to fallback admission"),
                },
            )
            .await
        }
        TcpServerSetupResult::DeferredAuthenticationHandled(completion) => {
            wait_for_quic_deferred_authentication(
                completion,
                match admission {
                    StreamSetupAdmission::Deferred(permit) => permit,
                    _ => unreachable!("deferred setup retains its stream admission"),
                },
            )
            .await
        }
    }
}

enum StreamSetupAdmission {
    Complete,
    Fallback(HandshakePermit),
    Deferred(QuicStreamHandshakePermit),
}

fn finish_stream_handshake(
    setup_result: &TcpServerSetupResult,
    handshake_permit: QuicStreamHandshakePermit,
) -> std::io::Result<StreamSetupAdmission> {
    match setup_result {
        TcpServerSetupResult::UnauthenticatedFallbackHandled(_) => {
            // A fallback is still bounded, but it must not keep a scarce protocol
            // handshake slot for its whole camouflage lifetime. Transfer to the
            // independent fallback gate without marking this QUIC connection as
            // authenticated.
            let fallback = handshake_permit.state.enter_fallback().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "generic QUIC listener is at its unauthenticated fallback limit",
                )
            })?;
            drop(handshake_permit);
            Ok(StreamSetupAdmission::Fallback(fallback))
        }
        TcpServerSetupResult::DeferredAuthenticationHandled(_) => {
            Ok(StreamSetupAdmission::Deferred(handshake_permit))
        }
        _ => {
            // This stream completed its configured protocol handshake. Release the
            // stream permit and notify the connection admission waiter immediately.
            handshake_permit.complete();
            Ok(StreamSetupAdmission::Complete)
        }
    }
}

async fn wait_for_quic_fallback(
    completion: UnauthenticatedFallbackCompletion,
    _permit: HandshakePermit,
) -> std::io::Result<()> {
    completion.wait().await
}

async fn wait_for_quic_deferred_authentication(
    completion: DeferredAuthenticationCompletion,
    permit: QuicStreamHandshakePermit,
) -> std::io::Result<()> {
    match timeout(DEFERRED_AUTHENTICATION_TIMEOUT, completion.wait()).await {
        Ok(DeferredAuthenticationOutcome::Authenticated) => {
            permit.complete();
            Ok(())
        }
        Ok(DeferredAuthenticationOutcome::Completed(result)) => {
            drop(permit);
            result
        }
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "deferred QUIC authentication exceeded its absolute deadline",
        )),
    }
}

/// Start QUIC listeners using the bind location carried by the config.
///
/// Kept as the compatibility entry point for existing shoes callers; dynamic
/// embedders that already resolved the listen set use the sibling helper below.
#[allow(dead_code)]
pub async fn start_quic_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
    users: Option<Arc<dyn UserRegistry>>,
    replay_scope: InboundReplayScope,
) -> std::io::Result<ServerHandle> {
    let resolved_bind = ResolvedBind::resolve(&config.bind_location)?;
    start_quic_servers_with_resolved_bind(config, resolver, users, replay_scope, resolved_bind)
        .await
}

pub(crate) async fn start_quic_servers_with_resolved_bind(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
    users: Option<Arc<dyn UserRegistry>>,
    replay_scope: InboundReplayScope,
    resolved_bind: ResolvedBind,
) -> std::io::Result<ServerHandle> {
    // One token for the whole inbound: every accept loop started below selects on
    // it, so the embedder stops all of them together.
    let cancel = CancellationToken::new();

    // Created here, before the config is taken apart, so it can record what the
    // endpoint below is about to bake in -- the certificate and the ALPN list, which
    // a reload cannot rebuild. `check_reload` compares against these.
    let mut handle =
        ServerHandle::new_with_replay_scope(config.transport.clone(), cancel.clone(), replay_scope);
    handle.record_listener_settings(&config);
    let replay_scope = handle.replay_scope();

    let ServerConfig {
        bind_location,
        quic_settings,
        protocol,
        sniff,
        rules,
        ..
    } = config;

    println!("Starting {} QUIC server at {}", &protocol, &bind_location);

    // See `start_tcp_servers`: only an inbound whose users the caller manages has
    // counters anyone can read.
    let metered = users.is_some();

    let rules = rules.map(ConfigSelection::unwrap_config).into_vec();
    // A direct entry must always exist
    assert!(!rules.is_empty());

    let bind_addresses = match (bind_location, resolved_bind) {
        (BindLocation::Address(_), ResolvedBind::Addresses(addresses)) if addresses.is_empty() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "resolved bind contains no addresses",
            ));
        }
        (BindLocation::Address(_), ResolvedBind::Addresses(addresses)) => addresses,
        (BindLocation::Path(_), ResolvedBind::Path(_)) => {
            return Err(std::io::Error::other(
                "Cannot listen on path, QUIC does not have unix domain socket support",
            ));
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "resolved bind kind does not match configured bind location",
            ));
        }
    };

    let ServerQuicConfig {
        cert,
        key,
        client_ca_certs,
        alpn_protocols,
        client_fingerprints,
        num_endpoints,
    } = quic_settings.unwrap();

    // Certificates are already embedded as PEM data during config validation
    let cert_bytes = cert.as_bytes().to_vec();
    let key_bytes = key.as_bytes().to_vec();

    let mut processed_ca_certs = Vec::with_capacity(client_ca_certs.len());
    for cert in client_ca_certs.into_iter() {
        processed_ca_certs.push(cert.as_bytes().to_vec());
    }

    let server_config = Arc::new(create_server_config(
        &cert_bytes,
        &key_bytes,
        processed_ca_certs,
        &alpn_protocols.into_vec(),
        &client_fingerprints.into_vec(),
    ));

    let quic_server_config: quinn::crypto::rustls::QuicServerConfig = server_config
        .try_into()
        .map_err(|e| std::io::Error::other(format!("invalid QUIC server config: {e}")))?;

    let quic_server_config = Arc::new(quic_server_config);

    let client_proxy_selector = Arc::new(create_tcp_client_proxy_selector_with_sniff_policy(
        rules.clone(),
        resolver.clone(),
        sniff,
    ));

    // Kept for the two arms below, which record what their accept loops bake in so
    // that a later reload can refuse to change it. The `match` consumes `protocol`.
    let started_protocol = protocol.clone();

    match protocol {
        ServerProxyConfig::Hysteria2 {
            password,
            udp_enabled,
            up_mbps,
            down_mbps,
            ignore_client_bandwidth,
            obfs,
            masquerade,
        } => {
            let obfs = obfs.map(|obfs| match obfs {
                crate::config::Hysteria2ObfsConfig::Salamander { password } => {
                    crate::hysteria2_obfs::Salamander::new(&password)
                }
            });
            // Hysteria2 sends its password in cleartext in a header, so the whole of
            // authentication is one registry lookup. An injected registry takes it
            // over; without one, the config's own password becomes a one-user
            // registry, which is the same comparison this used to do inline.
            let hysteria2_users = match users.as_ref() {
                Some(users) => users.clone(),
                None => StaticUserRegistry::single_password(&password),
            };
            let masquerade = Arc::new(crate::hysteria2_masquerade::Hysteria2Masquerade::new(
                masquerade.as_ref(),
            )?);

            for bind_address in bind_addresses.into_iter() {
                // A rule slot rather than a handler slot: hysteria2 authenticates in
                // its own accept loop rather than through a `TcpServerHandler`, so
                // the rules are the only thing above the socket a reload can reach.
                let selector_slot = handle.push_selector(
                    client_proxy_selector.clone(),
                    &resolver,
                    &started_protocol,
                    users.is_some(),
                );
                let hysteria2_handles = match crate::hysteria2_server::start_hysteria2_server(
                    bind_address,
                    quic_server_config.clone(),
                    hysteria2_users.clone(),
                    metered,
                    selector_slot,
                    num_endpoints,
                    udp_enabled,
                    up_mbps,
                    down_mbps,
                    ignore_client_bandwidth,
                    obfs.clone(),
                    masquerade.clone(),
                    cancel.clone(),
                    handle.connection_token(),
                )
                .await
                {
                    Ok(handles) => handles,
                    Err(error) => {
                        // A prior bind address may already have spawned accept
                        // loops. Revoke and join them before returning an error for
                        // this later endpoint batch.
                        handle.hard_shutdown(QUIC_DRAIN_TIMEOUT).await;
                        return Err(error);
                    }
                };
                for listener in hysteria2_handles {
                    handle.push_listener(listener);
                }
                handle.push_address(bind_address);
            }
        }
        ServerProxyConfig::TuicV5 {
            uuid,
            password,
            zero_rtt_handshake,
        } => {
            // TUIC's credential is two values at once: the uuid names the user in
            // cleartext and the password keys the token beside it. An injected registry
            // answers for both; without one, the config's own pair becomes a one-user
            // registry, which is the same comparison this used to do inline.
            let tuic_users = match users.as_ref() {
                Some(users) => users.clone(),
                None => StaticUserRegistry::single_tuic(&uuid, &password)?,
            };

            for bind_address in bind_addresses.into_iter() {
                // As above: rules only.
                let selector_slot = handle.push_selector(
                    client_proxy_selector.clone(),
                    &resolver,
                    &started_protocol,
                    users.is_some(),
                );
                let tuic_handles = match crate::tuic_server::start_tuic_server(
                    bind_address,
                    quic_server_config.clone(),
                    tuic_users.clone(),
                    metered,
                    selector_slot,
                    num_endpoints,
                    zero_rtt_handshake,
                    cancel.clone(),
                    handle.connection_token(),
                )
                .await
                {
                    Ok(handles) => handles,
                    Err(error) => {
                        handle.hard_shutdown(QUIC_DRAIN_TIMEOUT).await;
                        return Err(error);
                    }
                };
                for listener in tuic_handles {
                    handle.push_listener(listener);
                }
                handle.push_address(bind_address);
            }
        }
        tcp_protocol => {
            for bind_address in bind_addresses.into_iter() {
                // Shares protocol state across ports without reusing an interface-specific UDP bind IP.
                let handler_slot = handle.slot_for_ip(bind_address.ip(), &resolver, || {
                    create_tcp_server_handler_with_replay_state(
                        tcp_protocol.clone(),
                        &client_proxy_selector,
                        &resolver,
                        Some(bind_address.ip()),
                        users.as_ref(),
                        &replay_scope,
                    )
                    .into()
                });
                let quic_handles = match start_quic_server(
                    bind_address,
                    quic_server_config.clone(),
                    handler_slot,
                    num_endpoints,
                    metered,
                    cancel.clone(),
                    handle.connection_token(),
                )
                .await
                {
                    Ok(handles) => handles,
                    Err(error) => {
                        handle.hard_shutdown(QUIC_DRAIN_TIMEOUT).await;
                        return Err(error);
                    }
                };

                for listener in quic_handles {
                    handle.push_listener(listener);
                }
                handle.push_address(bind_address);
            }
        }
    }

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::{
        IncomingAddressAction, QUIC_ERR_HANDSHAKE_LIMIT, QUIC_ERR_PRE_AUTH_TIMEOUT,
        QUIC_PRE_AUTH_TIMEOUT, QUIC_TRANSPORT_HANDSHAKE_TIMEOUT, QuicConnectionLifecycle,
        QuicHandshakeState, finish_stream_handshake, first_handshake_completed_before_deadline,
        incoming_address_action, prepare_endpoint_batch, scope_generic_quic_stream_until_cancelled,
        wait_for_quic_fallback,
    };
    use crate::tcp::handshake_gate::{HandshakeGate, MAX_PENDING_PER_SOURCE};
    use crate::tcp::tcp_handler::{TcpServerSetupResult, UnauthenticatedFallbackCompletion};
    use std::cell::Cell;
    use std::net::{IpAddr, Ipv4Addr};
    use std::rc::Rc;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::{Instant, advance};
    use tokio_util::sync::CancellationToken;

    fn source(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    fn handshake_state(stream_gate: Arc<HandshakeGate>, source: IpAddr) -> Arc<QuicHandshakeState> {
        QuicHandshakeState::new(stream_gate, HandshakeGate::new(1, 1), source)
    }

    #[tokio::test]
    async fn nonmetered_generic_quic_work_observes_the_hard_stop_tree() {
        let hard_stop = CancellationToken::new();
        let task_token = hard_stop.clone();
        let (weak_tx, weak_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            scope_generic_quic_stream_until_cancelled(&task_token, |conn| {
                let _ = weak_tx.send(Arc::downgrade(&conn));
                async { std::future::pending::<std::io::Result<()>>().await }
            })
            .await
        });

        let weak = weak_rx.await.expect("logical stream context was created");
        assert!(weak.upgrade().is_some());
        hard_stop.cancel();

        let error = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("hard stop must wake nonmetered logical work")
            .expect("logical stream task must not panic")
            .expect_err("hard-stopped logical work must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
        assert!(weak.upgrade().is_none());
    }

    #[tokio::test]
    async fn natural_quic_exit_cancels_detached_logical_work_only_for_that_connection() {
        let inbound = CancellationToken::new();
        let connection = QuicConnectionLifecycle::new(&inbound);
        let task_token = connection.token().clone();
        let (weak_tx, weak_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            scope_generic_quic_stream_until_cancelled(&task_token, |conn| {
                let _ = weak_tx.send(Arc::downgrade(&conn));
                async { std::future::pending::<std::io::Result<()>>().await }
            })
            .await
        });

        let weak = weak_rx.await.expect("logical stream context was created");
        assert!(weak.upgrade().is_some());
        drop(connection);

        let error = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("natural transport exit must wake detached logical work")
            .expect("logical stream task must not panic")
            .expect_err("connection-scoped logical work must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
        assert!(weak.upgrade().is_none());
        assert!(
            !inbound.is_cancelled(),
            "one transport ending must not cancel the whole inbound"
        );
    }

    #[test]
    fn failed_endpoint_batch_drops_every_prepared_endpoint() {
        #[derive(Debug)]
        struct DropSpy(Rc<Cell<usize>>);

        impl Drop for DropSpy {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }

        let attempts = Cell::new(0);
        let drops = Rc::new(Cell::new(0));
        let error = prepare_endpoint_batch(3, || {
            let attempt = attempts.get();
            attempts.set(attempt + 1);
            if attempt == 1 {
                Err(std::io::Error::other("injected second-endpoint failure"))
            } else {
                Ok(DropSpy(Rc::clone(&drops)))
            }
        })
        .expect_err("the injected second endpoint fails");

        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert_eq!(attempts.get(), 2, "preparation stops at the first error");
        assert_eq!(
            drops.get(),
            1,
            "the first prepared endpoint is rolled back before Err escapes"
        );
    }

    #[test]
    fn unvalidated_incoming_is_retried_before_admission() {
        assert_eq!(
            incoming_address_action(false, true),
            IncomingAddressAction::Retry
        );
        assert_eq!(
            incoming_address_action(false, false),
            IncomingAddressAction::Refuse,
            "an API change that makes Retry unavailable must fail closed"
        );
        assert_eq!(
            incoming_address_action(true, false),
            IncomingAddressAction::Accept
        );
        assert_eq!(
            incoming_address_action(true, true),
            IncomingAddressAction::Accept,
            "a token already validated the address even when another Retry is legal"
        );
    }

    #[tokio::test]
    async fn stream_success_disarms_deadline_but_keeps_active_connection_quota() {
        let connection_gate = HandshakeGate::new(1, 1);
        let stream_gate = HandshakeGate::new(1, 1);
        let ip = source(1);
        let connection_permit = connection_gate
            .enter(Some(ip))
            .expect("admit the QUIC connection");
        let state = handshake_state(stream_gate.clone(), ip);
        let completion_state = state.clone();
        let completion = tokio::spawn(first_handshake_completed_before_deadline(
            completion_state,
            Instant::now() + Duration::from_secs(60),
        ));

        state
            .enter_stream()
            .expect("the independent stream gate is available")
            .complete();
        assert!(
            state.first_handshake_completed(),
            "success disarms only the absolute pre-auth deadline"
        );
        assert!(
            stream_gate.enter(Some(source(2))).is_some(),
            "completing a stream returns its stream-handshake permit"
        );
        assert!(completion.await.unwrap());
        assert!(
            connection_gate.enter(Some(source(2))).is_none(),
            "a stream cannot release the independent active-transport quota"
        );

        drop(connection_permit);
        assert!(connection_gate.enter(Some(source(2))).is_some());
    }

    #[test]
    fn a_failed_stream_releases_only_its_stream_permit() {
        let stream_gate = HandshakeGate::new(1, 1);
        let ip = source(1);
        let state = handshake_state(stream_gate.clone(), ip);

        let failed = state.enter_stream().expect("first stream");
        assert!(stream_gate.enter(Some(source(2))).is_none());
        drop(failed);
        assert!(
            !state.first_handshake_completed(),
            "failure must not disarm the connection deadline"
        );
        assert!(stream_gate.enter(Some(source(2))).is_some());
    }

    #[test]
    fn every_concurrent_stream_has_a_per_source_handshake_charge() {
        let stream_gate = HandshakeGate::new(8, 2);
        let ip = source(1);
        let state = handshake_state(stream_gate.clone(), ip);

        let first = state.enter_stream().expect("first stream");
        let second = state.enter_stream().expect("second stream");
        assert!(
            state.enter_stream().is_none(),
            "multiplexing cannot exceed the source's handshake share"
        );
        assert!(
            stream_gate.enter(Some(source(2))).is_some(),
            "one noisy QUIC peer does not consume another source's share"
        );

        second.complete();
        assert!(state.enter_stream().is_some());
        drop(first);
    }

    #[tokio::test(start_paused = true)]
    async fn absolute_deadline_fires_without_a_successful_stream() {
        let state = handshake_state(HandshakeGate::new(1, 1), source(1));
        let deadline = Instant::now() + Duration::from_secs(60);
        let waiter = tokio::spawn(first_handshake_completed_before_deadline(state, deadline));
        tokio::task::yield_now().await;

        advance(Duration::from_secs(60)).await;
        assert!(!waiter.await.unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn first_success_disarms_the_absolute_deadline() {
        let state = handshake_state(HandshakeGate::new(1, 1), source(1));
        let deadline = Instant::now() + Duration::from_secs(60);
        let waiter = tokio::spawn(first_handshake_completed_before_deadline(
            state.clone(),
            deadline,
        ));
        tokio::task::yield_now().await;

        state.enter_stream().expect("stream permit").complete();
        tokio::task::yield_now().await;
        assert!(
            waiter.is_finished(),
            "completion must wake admission immediately rather than at the deadline"
        );
        assert!(waiter.await.unwrap());
    }

    #[tokio::test]
    async fn unauthenticated_fallback_transfers_to_an_independent_admission() {
        let stream_gate = HandshakeGate::new(1, 1);
        let fallback_gate = HandshakeGate::new(1, 1);
        let state = QuicHandshakeState::new(stream_gate.clone(), fallback_gate.clone(), source(1));
        let permit = state.enter_stream().expect("fallback stream permit");
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        let setup_result = TcpServerSetupResult::UnauthenticatedFallbackHandled(
            UnauthenticatedFallbackCompletion::new(tokio::spawn(async move {
                finish_rx.await.map_err(std::io::Error::other)?;
                Ok(())
            })),
        );

        let retained_permit = match finish_stream_handshake(&setup_result, permit)
            .expect("unauthenticated fallback must transfer admission")
        {
            super::StreamSetupAdmission::Fallback(permit) => permit,
            _ => panic!("fallback setup returned the wrong admission kind"),
        };
        let TcpServerSetupResult::UnauthenticatedFallbackHandled(completion) = setup_result else {
            unreachable!()
        };
        let waiter = tokio::spawn(wait_for_quic_fallback(completion, retained_permit));
        tokio::task::yield_now().await;

        assert!(!state.first_handshake_completed());
        assert!(
            stream_gate.enter(Some(source(2))).is_some(),
            "fallback work must release the protocol-handshake slot"
        );
        assert!(
            fallback_gate.enter(Some(source(2))).is_none(),
            "the handed-off unauthenticated stream remains independently bounded"
        );

        finish_tx.send(()).expect("finish fallback");
        waiter
            .await
            .expect("fallback waiter must not panic")
            .expect("fallback completion must succeed");
        assert!(
            !state.first_handshake_completed(),
            "fallback completion is not protocol authentication"
        );
        assert!(
            fallback_gate.enter(Some(source(2))).is_some(),
            "fallback completion must release its fallback slot"
        );
    }

    #[test]
    fn authenticated_background_handoff_completes_the_connection_handshake() {
        let stream_gate = HandshakeGate::new(1, 1);
        let state = handshake_state(stream_gate.clone(), source(1));
        let permit = state.enter_stream().expect("authenticated stream permit");

        assert!(matches!(
            finish_stream_handshake(&TcpServerSetupResult::AlreadyHandled, permit),
            Ok(super::StreamSetupAdmission::Complete)
        ));

        assert!(state.first_handshake_completed());
        assert!(stream_gate.enter(Some(source(2))).is_some());
    }

    #[test]
    fn generic_transport_limits_use_error_codes_and_match_the_stream_share() {
        assert_ne!(QUIC_ERR_PRE_AUTH_TIMEOUT, 0);
        assert_ne!(QUIC_ERR_HANDSHAKE_LIMIT, 0);
        assert_eq!(MAX_PENDING_PER_SOURCE as u32, 64);
        assert!(QUIC_TRANSPORT_HANDSHAKE_TIMEOUT < QUIC_PRE_AUTH_TIMEOUT);
    }
}
