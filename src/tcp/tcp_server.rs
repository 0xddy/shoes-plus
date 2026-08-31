use std::net::{IpAddr, SocketAddr};
// NOTE(shoes-engine): only `run_unix_server` names this type, and that is
// unix-only, so an unconditional import is unused everywhere else.
#[cfg(target_family = "unix")]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error, warn};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use super::handshake_gate::{
    DEFERRED_AUTHENTICATION_TIMEOUT, HandshakeGate, HandshakePermit, MAX_ACTIVE_FALLBACKS,
    MAX_ACTIVE_FALLBACKS_PER_SOURCE, MAX_PENDING_HANDSHAKES, MAX_PENDING_PER_SOURCE,
};
use super::tcp_client_handler_factory::create_tcp_client_proxy_selector_with_sniff_policy;
use super::tcp_server_handler_factory::create_tcp_server_handler_with_replay_state;

use crate::address::NetLocation;
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::{AsyncShutdownMessageExt, AsyncStream};
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::config::{BindLocation, Config, ConfigSelection, ServerConfig, TcpConfig, Transport};
use crate::copy_bidirectional::copy_bidirectional;
use crate::copy_bidirectional_message::copy_bidirectional_message;
use crate::dynamic::{
    ConnContext, HandlerSlot, InboundReplayScope, InboundReplayState, ServerHandle,
    TrafficMeterStream, UserRegistry, scope_connection_until_cancelled,
};
use crate::quic_server::start_quic_servers_with_resolved_bind;
use crate::resolver::Resolver;
use crate::routing::protocol::{
    SniffedTcpMetadata, TcpPrefixClassification, classify_tcp_prefix, sniff_tcp,
};
use crate::routing::{ServerStream, run_udp_routing};
use crate::socket_util::{new_tcp_listener, set_tcp_keepalive};
use crate::tcp::tcp_handler::{
    DeferredAuthenticationCompletion, DeferredAuthenticationOutcome, TcpClientSetupResult,
    TcpServerHandler, TcpServerSetupResult, UnauthenticatedFallbackCompletion,
};
#[cfg(unix)]
use crate::tun::start_tun_server;
use crate::util::write_all;

async fn run_tcp_server(
    listener: tokio::net::TcpListener,
    bind_address: SocketAddr,
    tcp_config: TcpConfig,
    handler_slot: Arc<HandlerSlot>,
    metered: bool,
    cancel: CancellationToken,
    connection_cancel: CancellationToken,
) -> std::io::Result<()> {
    let TcpConfig { no_delay } = tcp_config;

    // One budget per listener, so a flood against this bind cannot starve another.
    let handshake_gate = HandshakeGate::new(MAX_PENDING_HANDSHAKES, MAX_PENDING_PER_SOURCE);
    let fallback_gate = HandshakeGate::new(MAX_ACTIVE_FALLBACKS, MAX_ACTIVE_FALLBACKS_PER_SOURCE);

    loop {
        // Returning here drops the listener, which is what frees the port. The
        // connections accepted so far were spawned off this loop and keep running:
        // they hold their own handler, so they finish under the rules they started
        // with. That is the smooth handover.
        let (stream, addr) = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                debug!("no longer accepting on {bind_address}");
                return Ok(());
            }
            accepted = listener.accept() => match accepted {
                Ok(v) => v,
                Err(e) => {
                    error!("Accept failed: {e}");
                    continue;
                }
            },
        };

        // Taken before anything is spent on this connection, and released again the
        // moment its handshake resolves. Dropping `stream` here is the refusal: the
        // peer sees a closed connection and this listener spends nothing further on
        // an address that is already holding as much of the budget as it may.
        let Some(permit) = handshake_gate.enter(Some(addr.ip())) else {
            debug!(
                "refusing {}: the listener is at its pending-handshake limit",
                addr.ip()
            );
            continue;
        };

        if let Err(e) = set_tcp_keepalive(
            &stream,
            std::time::Duration::from_secs(300),
            std::time::Duration::from_secs(60),
        ) {
            error!("Failed to set TCP keepalive: {e}");
        }

        if no_delay && let Err(e) = stream.set_nodelay(true) {
            error!("Failed to set TCP nodelay: {e}");
        }

        // Read once, here: this connection is pinned to the generation of rules,
        // protocol settings *and DNS* that were current when it was accepted. The
        // resolver comes out of the slot rather than from this loop's own capture,
        // because a reload can hand the rebuilt handler a different one.
        let (cloned_handler, cloned_resolver) = handler_slot.load();
        let connection_cancel = connection_cancel.clone();
        let fallback_gate = fallback_gate.clone();
        tokio::spawn(async move {
            if let Err(e) = process_metered_stream(
                stream,
                metered,
                cloned_handler,
                cloned_resolver,
                AcceptedConnectionAdmission {
                    handshake: permit,
                    fallback_gate,
                    source: Some(addr.ip()),
                    connection_cancel,
                },
            )
            .await
            {
                debug!("{}:{} finished with error: {:?}", addr.ip(), addr.port(), e);
            } else {
                debug!("{}:{} finished successfully", addr.ip(), addr.port());
            }
        });
    }
}

/// Bind a complete TCP listen set before any accept task is spawned.
///
/// `Vec`'s ordinary drop is the rollback: if a later bind fails, every listener
/// prepared earlier in the batch is closed before the error reaches the caller.
fn prepare_tcp_listeners(
    bind_addresses: Vec<SocketAddr>,
) -> std::io::Result<Vec<(SocketAddr, tokio::net::TcpListener)>> {
    bind_addresses
        .into_iter()
        .map(|address| {
            let listener = new_tcp_listener(address, 4096, None)?;
            Ok((address, listener))
        })
        .collect()
}

#[cfg(target_family = "unix")]
async fn run_unix_server(
    path_buf: PathBuf,
    handler_slot: Arc<HandlerSlot>,
    metered: bool,
    cancel: CancellationToken,
    connection_cancel: CancellationToken,
) -> std::io::Result<()> {
    if tokio::fs::symlink_metadata(&path_buf).await.is_ok() {
        println!(
            "WARNING: replacing file at socket path {}",
            path_buf.display()
        );
        let _ = tokio::fs::remove_file(&path_buf).await;
    }

    let listener = crate::socket_util::new_unix_listener(path_buf, 4096)?;
    // See `run_tcp_server`. A unix peer has no address to hold a share of, so only
    // the total applies here.
    let handshake_gate = HandshakeGate::new(MAX_PENDING_HANDSHAKES, MAX_PENDING_PER_SOURCE);
    let fallback_gate = HandshakeGate::new(MAX_ACTIVE_FALLBACKS, MAX_ACTIVE_FALLBACKS_PER_SOURCE);

    loop {
        // See `run_tcp_server`.
        let (stream, addr) = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                debug!("no longer accepting on the unix socket");
                return Ok(());
            }
            accepted = listener.accept() => match accepted {
                Ok(v) => v,
                Err(e) => {
                    error!("Accept failed: {e:?}");
                    continue;
                }
            },
        };

        // See `run_tcp_server`.
        let Some(permit) = handshake_gate.enter(None) else {
            debug!("refusing a unix peer: at the pending-handshake limit");
            continue;
        };

        // See `run_tcp_server`.
        let (cloned_handler, cloned_resolver) = handler_slot.load();
        let connection_cancel = connection_cancel.clone();
        let fallback_gate = fallback_gate.clone();
        tokio::spawn(async move {
            if let Err(e) = process_metered_stream(
                stream,
                metered,
                cloned_handler,
                cloned_resolver,
                AcceptedConnectionAdmission {
                    handshake: permit,
                    fallback_gate,
                    source: None,
                    connection_cancel,
                },
            )
            .await
            {
                debug!("{addr:?} finished with error: {e:?}");
            } else {
                debug!("{addr:?} finished successfully");
            }
        });
    }
}

struct AcceptedConnectionAdmission {
    handshake: HandshakePermit,
    fallback_gate: Arc<HandshakeGate>,
    source: Option<IpAddr>,
    connection_cancel: CancellationToken,
}

/// Handle one accepted connection, counting its traffic if the inbound is metered.
///
/// The meter goes on before any protocol touches the stream, so it sees the bytes
/// as they are on the wire. It cannot know whose they are yet -- the credential is
/// still several reads away -- so the connection stays anonymous until a handler
/// calls `bind_connection_user`, which finds this connection through the task local
/// scope installed here.
async fn process_metered_stream<AS>(
    stream: AS,
    metered: bool,
    server_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    admission: AcceptedConnectionAdmission,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    let AcceptedConnectionAdmission {
        handshake,
        fallback_gate,
        source,
        connection_cancel,
    } = admission;
    // This child remains live across ordinary listener removal, but a hard inbound
    // removal reaches it before or after authentication. It also covers classic
    // non-metered inbounds: a handler that detaches ownership captures this task-
    // local context through `spawn_connection_until_cancelled` before returning.
    let conn = ConnContext::new_child(&connection_cancel);
    if metered {
        let stream = TrafficMeterStream::new(stream, Arc::clone(&conn));
        scope_connection_until_cancelled(
            conn,
            process_stream(
                stream,
                server_handler,
                resolver,
                handshake,
                fallback_gate,
                source,
            ),
        )
        .await
    } else {
        scope_connection_until_cancelled(
            conn,
            process_stream(
                stream,
                server_handler,
                resolver,
                handshake,
                fallback_gate,
                source,
            ),
        )
        .await
    }
}

async fn setup_server_stream<AS>(
    stream: AS,
    server_handler: Arc<dyn TcpServerHandler>,
) -> std::io::Result<TcpServerSetupResult>
where
    AS: AsyncStream + 'static,
{
    let server_stream = Box::new(stream);
    server_handler.setup_server_stream(server_stream).await
}

/// Run one accepted connection to completion.
///
/// `permit` is this connection's place in the listener's pending-handshake budget.
/// It is taken as a value rather than borrowed because the point is to release it
/// early: it is dropped as soon as the handshake below resolves, not when the
/// connection ends. See [`handshake_gate`](super::handshake_gate).
pub async fn process_stream<AS>(
    stream: AS,
    server_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    permit: HandshakePermit,
    fallback_gate: Arc<HandshakeGate>,
    source: Option<IpAddr>,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    let setup_server_stream_future = timeout(
        Duration::from_secs(60),
        setup_server_stream(stream, server_handler),
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

    // Authenticated and authentication-free protocols no longer belong in the
    // pending-handshake budget once setup succeeds. An unauthenticated camouflage
    // fallback is different: setup only detached the same untrusted connection, so
    // retain its charge until that background connection ends. The early error
    // returns above release the charge on their way out.
    let mut handshake_permit = Some(permit);
    let fallback_permit = if matches!(
        setup_result,
        TcpServerSetupResult::UnauthenticatedFallbackHandled(_)
    ) {
        // A completed protocol parser must not let a camouflage connection retain
        // the scarce handshake budget. Transfer it to an independent, still-bounded
        // fallback gate; refusing the transfer drops the completion and aborts its
        // background task.
        drop(handshake_permit.take());
        Some(fallback_gate.enter(source).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "listener is at its unauthenticated fallback limit",
            )
        })?)
    } else if matches!(
        setup_result,
        TcpServerSetupResult::DeferredAuthenticationHandled(_)
    ) {
        None
    } else {
        drop(handshake_permit.take());
        None
    };

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
                write_all(&mut server_stream, &data).await?;
                // server_need_initial_flush should be set to true by the handler if
                // it's needed.
            }

            let client_need_initial_flush = if replay.is_empty() {
                false
            } else {
                write_all(&mut client_stream, &replay).await?;
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
                ConnectDecision::Block => Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "Blocked bidirectional udp forward",
                )),
            }
        }
        TcpServerSetupResult::MultiDirectionalUdp {
            stream: server_stream,
            need_initial_flush,
            proxy_selector,
        } => {
            // Per-destination routing: each packet is routed based on its destination
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
            // Per-destination routing: each session is routed based on its destination
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
            wait_for_tcp_fallback(
                completion,
                fallback_permit.expect("fallback setup transfers to fallback admission"),
            )
            .await
        }
        TcpServerSetupResult::DeferredAuthenticationHandled(completion) => {
            wait_for_tcp_deferred_authentication(
                completion,
                handshake_permit.expect("deferred authentication retains its handshake permit"),
            )
            .await
        }
    }
}

async fn wait_for_tcp_fallback(
    completion: UnauthenticatedFallbackCompletion,
    _permit: HandshakePermit,
) -> std::io::Result<()> {
    // Reality/VLESS/AnyTLS/ShadowTLS camouflage is a real proxied connection and
    // may legitimately be long-lived. Its independent fallback gate bounds
    // concurrency; normal EOF or hard inbound cancellation bounds its lifetime.
    completion.wait().await
}

async fn wait_for_tcp_deferred_authentication(
    completion: DeferredAuthenticationCompletion,
    _permit: HandshakePermit,
) -> std::io::Result<()> {
    match timeout(DEFERRED_AUTHENTICATION_TIMEOUT, completion.wait()).await {
        Ok(DeferredAuthenticationOutcome::Authenticated) => Ok(()),
        Ok(DeferredAuthenticationOutcome::Completed(result)) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "deferred TCP authentication exceeded its absolute deadline",
        )),
    }
}

/// Sniff application bytes without deadlocking response-gated inbound protocols.
///
/// SOCKS5, HTTP CONNECT and Snell clients do not send application data until the
/// inbound acknowledges their tunnel request. When a protocol rule needs sniffed
/// metadata, that acknowledgement therefore has to be written *and flushed* before
/// [`sniff_tcp`] is allowed to read. Taking the response here also prevents the
/// normal post-connect path from sending it twice. Protocols without a response and
/// handshakes which already supplied early data retain the same replay-safe sniffer.
pub(crate) async fn sniff_tcp_after_success_response(
    server_stream: &mut Box<dyn AsyncStream>,
    should_sniff: bool,
    connection_success_response: &mut Option<Box<[u8]>>,
    replay: &mut Vec<u8>,
) -> std::io::Result<Option<SniffedTcpMetadata>> {
    if !should_sniff {
        return Ok(None);
    }

    // A complete handshake-carried payload can be classified without client I/O,
    // so preserve the usual "success after outbound connect" timing in that case.
    // Only the NeedMore branch can block on a response-gated client.
    match classify_tcp_prefix(replay) {
        TcpPrefixClassification::Matched(metadata) => return Ok(Some(metadata)),
        TcpPrefixClassification::NoMatch => return Ok(None),
        TcpPrefixClassification::NeedMore => {}
    }

    if let Some(response) = connection_success_response.take() {
        write_all(server_stream, &response).await?;
        // This flush cannot be deferred to copy_bidirectional: the client may be
        // waiting for these bytes before it produces anything for the sniffer.
        server_stream.flush().await?;
    }

    sniff_tcp(server_stream, replay).await
}

pub async fn setup_client_tcp_stream(
    server_stream: &mut Box<dyn AsyncStream>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    remote_location: NetLocation,
) -> std::io::Result<Option<Box<dyn AsyncStream>>> {
    let Some(setup) = prepare_client_tcp_stream_with_metadata(
        client_proxy_selector,
        resolver,
        remote_location,
        None,
    )
    .await?
    else {
        return Ok(None);
    };

    apply_client_early_data(server_stream, setup)
        .await
        .map(Some)
}

/// Preserve the original kind while adding the destination to the error returned
/// to the debug-only connection boundary. The actual routing or dial failure is
/// logged at its source below, before peer-side writes can become involved.
pub(crate) fn client_stream_setup_error(
    remote_location: &NetLocation,
    error: std::io::Error,
) -> std::io::Error {
    std::io::Error::new(
        error.kind(),
        format!("failed to setup client stream to {remote_location}: {error}"),
    )
}

pub(crate) fn client_stream_setup_timeout(
    remote_location: &NetLocation,
    elapsed: tokio::time::error::Elapsed,
) -> std::io::Error {
    warn!("TCP outbound setup to {remote_location} timed out: {elapsed}");
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("client setup to {remote_location} timed out: {elapsed}"),
    )
}

/// Resolve policy and establish the outbound side only. Keeping peer-side early
/// data delivery out of this future lets callers put a precise timeout around DNS,
/// routing and dialing without misreporting a stalled inbound write as an outbound
/// setup timeout.
pub(crate) async fn prepare_client_tcp_stream_with_metadata(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    remote_location: NetLocation,
    metadata: Option<SniffedTcpMetadata>,
) -> std::io::Result<Option<TcpClientSetupResult>> {
    let requested_location = remote_location.clone();
    let action_result = match metadata {
        Some(metadata) => {
            client_proxy_selector
                .judge_sniffed_tcp(
                    remote_location.into(),
                    &resolver,
                    metadata.protocol,
                    metadata.domain,
                )
                .await
        }
        None => {
            client_proxy_selector
                .judge_tcp(remote_location.into(), &resolver)
                .await
        }
    };

    let action = match action_result {
        Ok(action) => action,
        Err(error) => {
            warn!("TCP outbound routing for {requested_location} failed: {error}");
            return Err(error);
        }
    };

    match action {
        ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => {
            let outbound_location = remote_location.clone();
            let setup = chain_group
                .connect_tcp(remote_location, &resolver)
                .await
                .map_err(|error| {
                    warn!("TCP outbound setup to {outbound_location} failed: {error}");
                    error
                })?;
            Ok(Some(setup))
        }
        ConnectDecision::Block => Ok(None),
    }
}

pub(crate) async fn apply_client_early_data(
    server_stream: &mut Box<dyn AsyncStream>,
    setup: TcpClientSetupResult,
) -> std::io::Result<Box<dyn AsyncStream>> {
    let TcpClientSetupResult {
        client_stream,
        early_data,
    } = setup;
    if let Some(data) = early_data {
        // This is a write back to the inbound peer, not part of outbound setup.
        // Keep its resource bound separate so a stalled peer is not reported as
        // a routing or dial failure at production log levels.
        timeout(Duration::from_secs(60), async {
            server_stream.write_all(&data).await?;
            server_stream.flush().await
        })
        .await
        .map_err(|elapsed| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("writing proxy early data to inbound peer timed out: {elapsed}"),
            )
        })??;
    }
    Ok(client_stream)
}

/// Unified function to run the appropriate UDP copy based on the setup result.
/// Copy messages bidirectionally between server and client message streams.
///
/// After the copy completes (whether successfully or with an error), both streams
/// are shut down to ensure proper cleanup and FIN frames are sent.
#[inline]
pub async fn run_udp_copy(
    mut server_stream: Box<dyn AsyncMessageStream>,
    mut client_stream: Box<dyn AsyncMessageStream>,
    server_need_initial_flush: bool,
    client_need_initial_flush: bool,
) -> std::io::Result<()> {
    let copy_result = copy_bidirectional_message(
        &mut server_stream,
        &mut client_stream,
        server_need_initial_flush,
        client_need_initial_flush,
    )
    .await;

    let (_, _) = futures::join!(
        server_stream.shutdown_message(),
        client_stream.shutdown_message()
    );

    copy_result
}

/// The exact listen targets selected for one expanded server config.
///
/// Hostname resolution is deliberately separated from listener startup so an
/// embedder can resolve before entering a control-plane critical section, then
/// use the same immutable result for conflict accounting and the real bind. The
/// ordinary [`start_servers_with_users_and_replay_scope`] entry point still
/// resolves for config-file callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedBind {
    Addresses(Vec<SocketAddr>),
    Path(std::path::PathBuf),
}

impl ResolvedBind {
    /// Resolve a config's complete listen set using the platform name service.
    /// Callers that need lock-free resolution should invoke this before taking
    /// their own mutation lock and pass the result to the resolved start API.
    pub fn resolve(bind_location: &BindLocation) -> std::io::Result<Self> {
        match bind_location {
            BindLocation::Address(addresses) => {
                let mut resolved = Vec::new();
                for address in addresses.iter() {
                    resolved.extend(address.to_socket_addrs()?);
                }
                if resolved.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "bind location resolved to no addresses",
                    ));
                }
                Ok(Self::Addresses(resolved))
            }
            BindLocation::Path(path) => Ok(Self::Path(path.clone())),
        }
    }

    fn check_matches(&self, bind_location: &BindLocation) -> std::io::Result<()> {
        match (self, bind_location) {
            (Self::Addresses(addresses), BindLocation::Address(_)) if addresses.is_empty() => {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "resolved bind contains no addresses",
                ))
            }
            (Self::Addresses(_), BindLocation::Address(_)) => Ok(()),
            (Self::Path(resolved), BindLocation::Path(configured)) if resolved == configured => {
                Ok(())
            }
            (Self::Path(resolved), BindLocation::Path(configured)) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "resolved unix bind {} does not match configured path {}",
                    resolved.display(),
                    configured.display()
                ),
            )),
            (Self::Addresses(_), BindLocation::Path(_))
            | (Self::Path(_), BindLocation::Address(_)) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "resolved bind kind does not match configured bind location",
            )),
        }
    }
}

pub async fn start_servers(
    config: Config,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    start_servers_with_users(config, resolver, None)
        .await
        .map(ServerHandle::into_listeners)
}

/// Start one inbound, authenticating against a caller-supplied user registry.
///
/// This is the entry point for an embedder that manages users itself. When `users`
/// is `Some`, it is the sole authority for this inbound and the credentials in the
/// protocol config are not consulted, so an inbound whose registry is empty rejects
/// every client until users are added to it. When `users` is `None` each protocol
/// handler builds a `StaticUserRegistry` from its own config section instead, which
/// is what [`start_servers`] does and what a config file expects.
///
/// The returned [`ServerHandle`] is what makes the inbound manageable afterwards:
/// `reload` swaps its rules and protocol settings without rebinding, `shutdown`
/// stops accepting while established connections finish. Dropping it stops
/// nothing.
///
/// Hysteria2 and TUIC are not covered by the registry yet: both authenticate
/// inside `quic_server.rs` rather than through a `TcpServerHandler`, so they keep
/// using their config credential even when a registry is supplied, and their
/// handle has nothing to reload.
pub async fn start_servers_with_users(
    config: Config,
    resolver: Arc<dyn Resolver>,
    users: Option<Arc<dyn UserRegistry>>,
) -> std::io::Result<ServerHandle> {
    start_servers_with_users_and_replay_state(
        config,
        resolver,
        users,
        InboundReplayState::default(),
    )
    .await
}

/// Start one inbound while retaining an embedder-owned replay namespace.
///
/// A control plane uses this only when it intentionally rebuilds the listener for
/// the same logical inbound. The new listener then still rejects VMess auth ids and
/// Shadowsocks salts already seen by the retired listener.
pub async fn start_servers_with_users_and_replay_state(
    config: Config,
    resolver: Arc<dyn Resolver>,
    users: Option<Arc<dyn UserRegistry>>,
    replay_state: InboundReplayState,
) -> std::io::Result<ServerHandle> {
    start_servers_with_users_and_replay_scope(
        config,
        resolver,
        users,
        InboundReplayScope::new(replay_state),
    )
    .await
}

/// Start one expanded listener group under an embedder-owned live replay scope.
/// Cloning the scope across all groups lets the engine observe old handlers that
/// outlive their registered inbound slot without retaining dead tags itself.
pub async fn start_servers_with_users_and_replay_scope(
    config: Config,
    resolver: Arc<dyn Resolver>,
    users: Option<Arc<dyn UserRegistry>>,
    replay_scope: InboundReplayScope,
) -> std::io::Result<ServerHandle> {
    match config {
        #[cfg(unix)]
        Config::TunServer(tun_config) => {
            let mut handle = ServerHandle::new_with_replay_scope(
                Transport::Tcp,
                CancellationToken::new(),
                replay_scope,
            );
            handle.push_listener(start_tun_server(tun_config, resolver).await?);
            Ok(handle)
        }
        #[cfg(not(unix))]
        Config::TunServer(_) => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN server is not supported on this platform",
        )),
        Config::Server(server_config) => {
            start_tcp_or_quic_servers(server_config, resolver, users, replay_scope, None).await
        }
        _ => unreachable!("create_server_configs only returns Server and TunServer"),
    }
}

/// Start one expanded server config using an already-resolved listen set.
///
/// The listener never consults the configured hostname on this path. This makes
/// the supplied [`ResolvedBind`] the single source of truth for both the caller's
/// address ownership records and the sockets that are actually opened.
// The standalone binary includes these modules directly, while this entry point
// is consumed through the library by shoes-engine.
#[allow(dead_code)]
pub async fn start_servers_with_users_and_replay_scope_resolved(
    config: Config,
    resolver: Arc<dyn Resolver>,
    users: Option<Arc<dyn UserRegistry>>,
    replay_scope: InboundReplayScope,
    resolved_bind: ResolvedBind,
) -> std::io::Result<ServerHandle> {
    match config {
        Config::Server(server_config) => {
            start_tcp_or_quic_servers(
                server_config,
                resolver,
                users,
                replay_scope,
                Some(resolved_bind),
            )
            .await
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "an explicit resolved bind can only start a server config",
        )),
    }
}

async fn start_tcp_or_quic_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
    users: Option<Arc<dyn UserRegistry>>,
    replay_scope: InboundReplayScope,
    resolved_bind: Option<ResolvedBind>,
) -> std::io::Result<ServerHandle> {
    let resolved_bind = match resolved_bind {
        Some(resolved) => {
            resolved.check_matches(&config.bind_location)?;
            resolved
        }
        None => ResolvedBind::resolve(&config.bind_location)?,
    };
    let handle = match config.transport {
        Transport::Tcp => {
            start_tcp_servers(config.clone(), resolver, users, replay_scope, resolved_bind).await?
        }
        Transport::Quic => {
            start_quic_servers_with_resolved_bind(
                config.clone(),
                resolver,
                users,
                replay_scope,
                resolved_bind,
            )
            .await?
        }
        Transport::Udp => todo!(),
    };

    if handle.listener_count() == 0 {
        return Err(std::io::Error::other(format!(
            "failed to start servers at {}",
            &config.bind_location
        )));
    }

    Ok(handle)
}

async fn start_tcp_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
    users: Option<Arc<dyn UserRegistry>>,
    replay_scope: InboundReplayScope,
    resolved_bind: ResolvedBind,
) -> std::io::Result<ServerHandle> {
    // Recorded before the config is taken apart. These are the settings the accept
    // loop is about to bake in, and `check_reload` compares against them so that a
    // later update changing one is refused rather than silently ignored.
    let mut handle =
        ServerHandle::new_with_replay_scope(Transport::Tcp, CancellationToken::new(), replay_scope);
    handle.record_listener_settings(&config);
    let replay_scope = handle.replay_scope();

    let ServerConfig {
        bind_location,
        tcp_settings,
        protocol,
        sniff,
        rules,
        ..
    } = config;

    println!("Starting {} TCP server at {}", &protocol, &bind_location);

    // Traffic is only counted for an inbound whose users the caller manages: those
    // are the only `UserContext`s anyone can read the counters off. A config-file
    // inbound gets the stream unwrapped, exactly as before.
    let metered = users.is_some();

    let rules = rules.map(ConfigSelection::unwrap_config).into_vec();
    // We should always have a direct entry.
    assert!(!rules.is_empty());

    let tcp_config = tcp_settings.unwrap_or_else(TcpConfig::default);

    let client_proxy_selector = Arc::new(create_tcp_client_proxy_selector_with_sniff_policy(
        rules.clone(),
        resolver.clone(),
        sniff,
    ));

    // Bind every selected socket before spawning the first accept loop. Otherwise
    // a failure binding a later address would return `Err` after an earlier task
    // had escaped with no `ServerHandle` left for the caller to stop.
    match (bind_location, resolved_bind) {
        (BindLocation::Address(_), ResolvedBind::Addresses(bind_addresses)) => {
            for (socket_addr, tcp_listener) in prepare_tcp_listeners(bind_addresses)? {
                // Shares protocol state across ports without reusing an
                // interface-specific UDP bind IP.
                let handler_slot = handle.slot_for_ip(socket_addr.ip(), &resolver, || {
                    create_tcp_server_handler_with_replay_state(
                        protocol.clone(),
                        &client_proxy_selector,
                        &resolver,
                        Some(socket_addr.ip()),
                        users.as_ref(),
                        &replay_scope,
                    )
                    .into()
                });
                debug!("TCP handler for {}: {handler_slot:?}", socket_addr.ip());

                let tcp_config = tcp_config.clone();
                let cancel = handle.cancel_token();
                let connection_cancel = handle.connection_token();
                let listener = tokio::spawn(async move {
                    // No resolver here: the loop takes it from the slot, with the
                    // handler, so both come from one generation.
                    run_tcp_server(
                        tcp_listener,
                        socket_addr,
                        tcp_config,
                        handler_slot,
                        metered,
                        cancel,
                        connection_cancel,
                    )
                    .await
                    .unwrap();
                });
                handle.push_listener(listener);
                handle.push_address(socket_addr);
            }
        }
        (BindLocation::Path(_), ResolvedBind::Path(_path_buf)) => {
            #[cfg(target_family = "unix")]
            {
                let handler_slot = handle.slot_for_path(
                    create_tcp_server_handler_with_replay_state(
                        protocol,
                        &client_proxy_selector,
                        &resolver,
                        None,
                        users.as_ref(),
                        &replay_scope,
                    )
                    .into(),
                    &resolver,
                );
                debug!("TCP handler: {handler_slot:?}");
                let cancel = handle.cancel_token();
                let connection_cancel = handle.connection_token();
                let listener = tokio::spawn(async move {
                    run_unix_server(_path_buf, handler_slot, metered, cancel, connection_cancel)
                        .await
                        .unwrap();
                });
                handle.push_listener(listener);
            }
            #[cfg(not(target_family = "unix"))]
            {
                return Err(std::io::Error::other(
                    "Unix sockets are not supported on this platform",
                ));
            }
        }
        _ => unreachable!("resolved bind shape was checked before listener startup"),
    }

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

    use super::{
        ResolvedBind, prepare_tcp_listeners, sniff_tcp_after_success_response,
        start_servers_with_users_and_replay_scope_resolved, wait_for_tcp_fallback,
    };
    use crate::async_stream::{AsyncPing, AsyncStream};
    use crate::config::{Config, ServerConfig};
    use crate::dns::DnsRegistry;
    use crate::dynamic::{InboundReplayScope, InboundReplayState};
    use crate::routing::predicate::RouteProtocol;
    use crate::tcp::handshake_gate::HandshakeGate;
    use crate::tcp::tcp_handler::UnauthenticatedFallbackCompletion;

    #[tokio::test]
    async fn resolved_start_and_reload_never_consult_the_configured_hostname() {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);

        let config: ServerConfig = serde_yaml::from_str(&format!(
            r#"
address: bind-resolution-must-not-run.invalid:{}
protocol:
  type: socks
  udp_enabled: false
rules:
  - masks: 0.0.0.0/0
    action: allow
"#,
            address.port()
        ))
        .expect("hostname syntax is valid even though it must never be resolved");
        let resolved = ResolvedBind::Addresses(vec![address]);
        let mut dns = DnsRegistry::new();
        let resolver = dns.get_or_create_default();

        let handle = start_servers_with_users_and_replay_scope_resolved(
            Config::Server(config.clone()),
            resolver.clone(),
            None,
            InboundReplayScope::new(InboundReplayState::default()),
            resolved.clone(),
        )
        .await
        .expect("the supplied literal address, not the .invalid hostname, drives the bind");

        assert_eq!(handle.addresses(), &[address]);
        let occupied = std::net::TcpListener::bind(address)
            .expect_err("the resolved address must be held by the live listener");
        assert!(matches!(
            occupied.kind(),
            std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
        ));

        let generation = handle
            .reload_resolved(config, &resolver, None, &resolved)
            .expect("the resolved reload path must not retry the .invalid hostname");
        assert_eq!(generation, 1);

        handle
            .hard_shutdown(std::time::Duration::from_secs(1))
            .await;
        std::net::TcpListener::bind(address)
            .expect("shutdown releases the exact address supplied in ResolvedBind");
    }

    #[tokio::test]
    async fn unauthenticated_tcp_fallback_holds_its_independent_admission_until_completion() {
        let gate = HandshakeGate::new(1, 1);
        let permit = gate.enter(None).expect("admit fallback handshake");
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        let completion = UnauthenticatedFallbackCompletion::new(tokio::spawn(async move {
            finish_rx.await.map_err(std::io::Error::other)?;
            Ok(())
        }));
        let waiter = tokio::spawn(wait_for_tcp_fallback(completion, permit));
        tokio::task::yield_now().await;

        assert!(
            gate.enter(None).is_none(),
            "a detached unauthenticated connection must retain its fallback admission"
        );

        finish_tx.send(()).expect("finish fallback");
        waiter
            .await
            .expect("fallback waiter must not panic")
            .expect("fallback completion must succeed");
        assert!(
            gate.enter(None).is_some(),
            "completion must release the independent fallback admission"
        );
    }

    #[tokio::test]
    async fn cancelling_tcp_fallback_wait_releases_admission() {
        struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

        impl Drop for DropSignal {
            fn drop(&mut self) {
                if let Some(signal) = self.0.take() {
                    let _ = signal.send(());
                }
            }
        }

        let gate = HandshakeGate::new(1, 1);
        let permit = gate.enter(None).expect("admit fallback handshake");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let completion = UnauthenticatedFallbackCompletion::new(tokio::spawn(async move {
            let _drop_signal = DropSignal(Some(dropped_tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
            Ok(())
        }));
        let waiter = tokio::spawn(wait_for_tcp_fallback(completion, permit));
        started_rx.await.expect("fallback task started");

        assert!(
            gate.enter(None).is_none(),
            "the live fallback must retain its admission before cancellation"
        );

        waiter.abort();
        waiter
            .await
            .expect_err("hard cancellation aborts the waiter");
        tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
            .await
            .expect("hard cancellation must abort fallback work")
            .expect("fallback drop signal must be delivered");
        assert!(
            gate.enter(None).is_some(),
            "hard cancellation must release the fallback admission"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn long_lived_tcp_fallback_is_not_cut_off_by_the_authentication_deadline() {
        let gate = HandshakeGate::new(1, 1);
        let permit = gate.enter(None).expect("admit fallback");
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        let completion = UnauthenticatedFallbackCompletion::new(tokio::spawn(async move {
            finish_rx.await.map_err(std::io::Error::other)?;
            Ok(())
        }));
        let waiter = tokio::spawn(wait_for_tcp_fallback(completion, permit));
        tokio::task::yield_now().await;

        tokio::time::advance(super::DEFERRED_AUTHENTICATION_TIMEOUT * 2).await;
        tokio::task::yield_now().await;
        assert!(
            !waiter.is_finished(),
            "a camouflage connection must not inherit the deferred-auth deadline"
        );
        assert!(
            gate.enter(None).is_none(),
            "live fallback retains its quota"
        );

        finish_tx.send(()).expect("finish fallback");
        waiter
            .await
            .expect("fallback waiter must not panic")
            .expect("fallback completion must succeed");
        assert!(
            gate.enter(None).is_some(),
            "completion returns fallback capacity"
        );
    }

    #[tokio::test]
    async fn failed_tcp_listen_batch_releases_earlier_sockets() {
        let first_reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let first = first_reservation.local_addr().unwrap();
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let occupied_address = occupied.local_addr().unwrap();
        assert_ne!(first, occupied_address);
        drop(first_reservation);

        let error = prepare_tcp_listeners(vec![first, occupied_address])
            .expect_err("the second address is already occupied");
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
            ),
            "the occupied address must reject the second bind: {error}"
        );

        // The first bind succeeded before the second failed. Returning `Err` must
        // have dropped that prepared listener rather than leaking its port.
        std::net::TcpListener::bind(first)
            .expect("the earlier listener in the failed batch must be closed");
    }

    struct TestDuplexStream(tokio::io::DuplexStream);

    impl AsyncRead for TestDuplexStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestDuplexStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestDuplexStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            unreachable!("test stream does not support ping")
        }
    }

    impl AsyncStream for TestDuplexStream {}

    #[tokio::test]
    async fn tunnel_success_response_is_flushed_before_sniff_reads_payload() {
        const RESPONSE: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
        const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: sniff.example\r\n\r\n";

        let (server, mut client) = tokio::io::duplex(1024);
        let client_task = tokio::spawn(async move {
            let mut response = vec![0; RESPONSE.len()];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(response, RESPONSE);
            client.write_all(REQUEST).await.unwrap();
        });

        let mut stream: Box<dyn AsyncStream> = Box::new(TestDuplexStream(server));
        let mut response = Some(RESPONSE.to_vec().into_boxed_slice());
        let mut replay = Vec::new();
        let metadata = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            sniff_tcp_after_success_response(&mut stream, true, &mut response, &mut replay),
        )
        .await
        .expect("the response-gated client must not wait for the 300 ms sniff timeout")
        .unwrap()
        .expect("HTTP request should be classified");

        client_task.await.unwrap();
        assert!(response.is_none(), "the normal path must not send it twice");
        assert_eq!(replay, REQUEST);
        assert_eq!(metadata.protocol, RouteProtocol::Http);
        assert_eq!(metadata.domain.as_deref(), Some("sniff.example"));
    }

    #[tokio::test]
    async fn existing_early_data_is_classified_without_touching_the_stream() {
        const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: early.example\r\n\r\n";
        let (server, _client) = tokio::io::duplex(64);
        let mut stream: Box<dyn AsyncStream> = Box::new(TestDuplexStream(server));
        let mut response = Some(Box::from(&b"ok"[..]));
        let mut replay = REQUEST.to_vec();

        let metadata = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            sniff_tcp_after_success_response(&mut stream, true, &mut response, &mut replay),
        )
        .await
        .expect("complete early data must not wait for a read")
        .unwrap()
        .unwrap();

        assert_eq!(metadata.domain.as_deref(), Some("early.example"));
        assert_eq!(replay, REQUEST);
        assert_eq!(
            response.as_deref(),
            Some(&b"ok"[..]),
            "classification without a read keeps the normal post-connect response timing"
        );
    }

    #[tokio::test]
    async fn selector_without_protocol_rules_leaves_deferred_response_untouched() {
        let (server, _client) = tokio::io::duplex(64);
        let mut stream: Box<dyn AsyncStream> = Box::new(TestDuplexStream(server));
        let mut response = Some(Box::from(&b"ok"[..]));
        let mut replay = b"early".to_vec();

        let metadata =
            sniff_tcp_after_success_response(&mut stream, false, &mut response, &mut replay)
                .await
                .unwrap();

        assert!(metadata.is_none());
        assert_eq!(response.as_deref(), Some(&b"ok"[..]));
        assert_eq!(replay, b"early");
    }
}
