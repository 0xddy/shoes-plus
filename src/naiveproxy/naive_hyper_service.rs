//! Hyper-based NaiveProxy service
//!
//! This module provides a hyper-based HTTP/2 server for NaiveProxy connections.
//! It handles CONNECT requests with padding support and built-in static file fallback.

use std::convert::Infallible;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use log::debug;
use rand::RngExt;
use tokio::io::AsyncWriteExt;

use crate::address::{Address, NetLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::client_proxy_selector::ClientProxySelector;
use crate::copy_bidirectional::copy_bidirectional_with_sizes;
use crate::crypto::CryptoTlsStream;
use crate::dynamic::{
    ConnContext, UserContext, UserRegistry, current_connection, spawn_connection_until_cancelled,
};
use crate::resolver::Resolver;
use crate::routing::{ServerStream, run_udp_routing};
use crate::socks_handler::read_location_direct;
use crate::tcp::tcp_handler::{
    DeferredAuthenticationCompletion, DeferredAuthenticationSignal, TcpServerSetupResult,
    UnauthenticatedFallbackCompletion,
};
use crate::tcp::tcp_server::run_udp_copy;
use crate::tls_server_handler::NaiveConfig;
use crate::uot::{UOT_V1_MAGIC_ADDRESS, UOT_V2_MAGIC_ADDRESS, UotV1ServerStream, UotV2Stream};

use tokio::io::AsyncReadExt;

use super::naive_padding_stream::{
    NaivePaddingStream, PaddingDirection, PaddingType, generate_padding_header,
    parse_padding_type_request,
};

/// Wrapper for hyper's upgraded stream that implements AsyncStream.
///
/// This is needed because `TokioIo<Upgraded>` doesn't implement `AsyncStream`
/// (which requires `Sync`), but we need `AsyncStream` for UoT stream wrappers.
struct HyperUpgradedStream(TokioIo<hyper::upgrade::Upgraded>);

impl tokio::io::AsyncRead for HyperUpgradedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for HyperUpgradedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl crate::async_stream::AsyncPing for HyperUpgradedStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<bool>> {
        std::task::Poll::Ready(Ok(false))
    }
}

// SAFETY: The underlying hyper Upgraded stream is used only from async contexts
// in a single-threaded manner per connection. The Sync bound is required by
// AsyncStream but the stream is never actually shared across threads.
unsafe impl Sync for HyperUpgradedStream {}

impl AsyncStream for HyperUpgradedStream {}

/// Service configuration for hyper NaiveProxy handler
struct NaiveServiceConfig {
    users: Arc<dyn UserRegistry>,
    fallback_path: Option<PathBuf>,
    resolver: Arc<dyn Resolver>,
    proxy_selector: Arc<ClientProxySelector>,
    udp_enabled: bool,
    padding_enabled: bool,
    /// Naive HTTP/2 authenticates on its first CONNECT request, after Hyper owns the
    /// physical stream. Notify the accepting transport at that exact boundary so it
    /// can release the pre-auth permit without treating an idle H2 connection as an
    /// authenticated proxy.
    authentication: Option<DeferredAuthenticationSignal>,
    /// The connection's accounting record, captured before the spawn below.
    ///
    /// Every other TCP protocol finds this through a task local, because it
    /// authenticates inline on the task that accepted the connection. NaiveProxy
    /// does not: hyper owns the task from `serve_connection` onward, and the
    /// credential is not read until a request arrives on it. A task local does not
    /// cross `tokio::spawn`, so without this the user's counters would sit at zero
    /// while every byte still flowed correctly -- a silent failure.
    meter: Option<Arc<ConnContext>>,
}

/// Resolve a `proxy-authorization` header to the user it belongs to.
///
/// The header value is compared as it arrived, never decoded: it is attacker
/// controlled, and the registry indexes on the encoded form for that reason. A value
/// that is not valid UTF-8, or does not start with `Basic `, is simply not anyone's
/// credential.
fn authenticate(
    header: &http::HeaderValue,
    config: &NaiveServiceConfig,
) -> Option<Arc<UserContext>> {
    let encoded = header.to_str().ok()?.strip_prefix("Basic ")?;
    config.users.find_naive_basic(encoded.as_bytes())
}

fn empty_body() -> BoxBody<Bytes, io::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full_body(data: Bytes) -> BoxBody<Bytes, io::Error> {
    Full::new(data).map_err(|never| match never {}).boxed()
}

/// Run the hyper-based NaiveProxy service
///
/// This is an internal function called by `setup_naive_server_stream` after
/// determining the HTTP version to use.
pub(super) async fn run_naive_hyper_service<IO: AsyncStream + 'static>(
    tls_stream: CryptoTlsStream<IO>,
    naive_cfg: &NaiveConfig,
    effective_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    use_h2: bool,
) -> io::Result<TcpServerSetupResult> {
    let io = TokioIo::new(tls_stream);

    let (authentication, authentication_waiter) = if use_h2 {
        let (signal, waiter) = DeferredAuthenticationSignal::channel();
        (Some(signal), Some(waiter))
    } else {
        (None, None)
    };

    let service_config = Arc::new(NaiveServiceConfig {
        users: naive_cfg.users.clone(),
        fallback_path: naive_cfg.fallback_path.clone(),
        resolver,
        proxy_selector: effective_selector,
        udp_enabled: naive_cfg.udp_enabled,
        padding_enabled: naive_cfg.padding_enabled,
        authentication,
        // Read here, on the accepting task, which is the last point at which the
        // task local is still reachable. Ordinary TCP accepts install a context
        // even when byte accounting is disabled, so hard inbound removal can still
        // terminate the detached Hyper connection.
        meter: current_connection(),
    });

    let completion = if use_h2 {
        // HTTP/2 for NaiveProxy clients
        tokio::spawn(async move {
            let removal_meter = service_config.meter.clone();
            let service = hyper::service::service_fn(move |req| {
                let config = service_config.clone();
                async move { naive_service(req, config).await }
            });

            // H2 settings tuned for reasonable throughput without excessive memory
            // Reference naiveproxy uses ~64KB default, we use 256 KB for better throughput
            const WINDOW_SIZE: u32 = 256 * 1024; // 256 KB (was 16 MB)
            // `max_frame_size` is advertised *to the peer*: it is the largest single frame they
            // may send us, and therefore what our HTTP/2 layer must be prepared to buffer
            // before a byte of it can be handed on. The old value was the protocol maximum,
            // which is not a throughput setting so much as an absence of one -- the framing
            // overhead it saves over 64 KiB is 9 bytes in 65536. sing-mux advertises 32 KiB
            // here for the same reason.
            const MAX_FRAME_SIZE: u32 = 64 * 1024; // 64 KiB, matching COPY_BUF_SIZE

            let connection = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .auto_date_header(false)
                .initial_stream_window_size(WINDOW_SIZE)
                .initial_connection_window_size(WINDOW_SIZE)
                .max_frame_size(MAX_FRAME_SIZE)
                // Each concurrent stream is a live CONNECT tunnel holding a pair of
                // `COPY_BUF_SIZE` buffers, so this number is the multiplier on this
                // connection's memory ceiling -- see `handle_naive_stream`. 256 is
                // still far more simultaneous tunnels than a client driving a browser
                // opens, and a client that does hit it has its extra streams queued by
                // its own HTTP/2 layer rather than refused.
                .max_concurrent_streams(256)
                .serve_connection(io, service);

            let result = if let Some(meter) = removal_meter {
                tokio::select! {
                    biased;
                    () = meter.cancelled() => return Ok(()),
                    result = connection => result,
                }
            } else {
                connection.await
            };

            if let Err(e) = result {
                debug!("Naive HTTP/2 connection error: {}", e);
            }
            Ok(())
        })
    } else {
        // HTTP/1.1 for browsers and censors - serve static files only, no proxy
        let fallback_path = naive_cfg.fallback_path.clone();
        spawn_connection_until_cancelled(async move {
            let service = hyper::service::service_fn(move |req| {
                let path = fallback_path.clone();
                async move { http1_fallback_service(req, path).await }
            });

            let result = hyper::server::conn::http1::Builder::new()
                .auto_date_header(false)
                .serve_connection(io, service)
                .await;

            if let Err(e) = result {
                debug!("Naive HTTP/1.1 fallback error: {}", e);
            }
            Ok(())
        })
    };

    // Hyper owns the stream now. HTTP/1.1 is camouflage only and remains an
    // unauthenticated fallback. HTTP/2 is the real proxy data plane, but its Basic
    // credential arrives on the first CONNECT request; keep the transport's pre-auth
    // admission until `naive_service` signals that exact boundary.
    if let Some(authentication_waiter) = authentication_waiter {
        Ok(TcpServerSetupResult::DeferredAuthenticationHandled(
            DeferredAuthenticationCompletion::new(completion, authentication_waiter),
        ))
    } else {
        Ok(TcpServerSetupResult::UnauthenticatedFallbackHandled(
            UnauthenticatedFallbackCompletion::new(completion),
        ))
    }
}

/// HTTP/1.1 fallback service - only serves static files, no proxy functionality
async fn http1_fallback_service(
    req: Request<Incoming>,
    fallback_path: Option<PathBuf>,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Infallible> {
    match *req.method() {
        Method::GET | Method::HEAD => {
            let path = req.uri().path();
            let is_head = req.method() == Method::HEAD;
            debug!("NaiveProxy HTTP/1.1: serving fallback for {}", path);
            serve_fallback(path, &fallback_path, is_head).await
        }
        Method::OPTIONS => Ok(Response::builder()
            .status(StatusCode::OK)
            .header("allow", "GET, HEAD, OPTIONS")
            .body(empty_body())
            .unwrap()),
        _ => Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(empty_body())
            .unwrap()),
    }
}

/// Main NaiveProxy service handler for HTTP/2 (hyper)
async fn naive_service(
    mut req: Request<Incoming>,
    config: Arc<NaiveServiceConfig>,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Infallible> {
    match *req.method() {
        Method::CONNECT => {}
        Method::GET | Method::HEAD => {
            let is_head = req.method() == Method::HEAD;
            debug!(
                "NaiveProxy HTTP/2: serving fallback for {}",
                req.uri().path()
            );
            return serve_fallback(req.uri().path(), &config.fallback_path, is_head).await;
        }
        Method::OPTIONS => {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("allow", "GET, HEAD, OPTIONS")
                .body(empty_body())
                .unwrap());
        }
        _ => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(empty_body())
                .unwrap());
        }
    }

    // Return 400 for anything that might reveal proxy support
    let has_padding = req.headers().get("padding").is_some();
    if !has_padding && config.padding_enabled {
        debug!("NaiveProxy: missing padding header, returning 400");
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(empty_body())
            .unwrap());
    }

    let username = match req.headers().get("proxy-authorization") {
        Some(auth) => match authenticate(auth, &config) {
            Some(user) => {
                // Binds the whole connection, not this request: NaiveProxy
                // multiplexes every CONNECT over one H2 connection, so the first
                // request to authenticate is the one that names it, and a second
                // bind is refused rather than double counted.
                //
                // Which makes *whose* connection it is a question that has to be
                // answered, not ignored. A refused bind is fine when it is the same
                // user asking again -- the common case, one request per CONNECT --
                // but a second, different user on the same connection cannot be let
                // through: every byte they move would be billed to whoever bound it
                // first, and the meter has no way to separate them afterwards. One
                // connection, one user; a client wanting to be somebody else opens
                // another.
                if let Some(meter) = &config.meter {
                    if !meter.bind_or_matches(&user) {
                        debug!(
                            "NaiveProxy: a second user on a connection already bound to \
                             another, returning 400"
                        );
                        return Ok(Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(empty_body())
                            .unwrap());
                    }
                } else if !user.admit_unmetered() {
                    debug!(
                        "NaiveProxy: user could not be admitted: removed, suspended, or at their connection limit"
                    );
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(empty_body())
                        .unwrap());
                }
                if let Some(authentication) = &config.authentication {
                    authentication.complete();
                }
                user.id().to_string()
            }
            None => {
                debug!("NaiveProxy: invalid credentials, returning 400");
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(empty_body())
                    .unwrap());
            }
        },
        None => {
            debug!("NaiveProxy: missing auth header, returning 400");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(empty_body())
                .unwrap());
        }
    };

    let destination = match parse_connect_destination(&req) {
        Some(dest) => dest,
        None => {
            log::debug!("NaiveProxy: rejecting invalid CONNECT destination");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(empty_body())
                .unwrap());
        }
    };

    debug!("[{}] NaiveProxy CONNECT to {}", username, destination);

    let padding_type = if config.padding_enabled && has_padding {
        if let Some(types) = req.headers().get("padding-type-request") {
            let types_str = types.to_str().unwrap_or("1");
            parse_padding_type_request(types_str)
                .into_iter()
                .find(|&t| t == PaddingType::Variant1)
                .unwrap_or(PaddingType::Variant1)
        } else {
            PaddingType::Variant1
        }
    } else {
        PaddingType::None
    };

    // Get upgrade future before moving the request
    let on_upgrade = hyper::upgrade::on(&mut req);
    let resolver = config.resolver.clone();
    let proxy_selector = config.proxy_selector.clone();
    let udp_enabled = config.udp_enabled;
    let removal_meter = config.meter.clone();

    tokio::spawn(async move {
        let tunnel = async move {
            match on_upgrade.await {
                Ok(upgraded) => {
                    let io = HyperUpgradedStream(TokioIo::new(upgraded));

                    if padding_type != PaddingType::None {
                        let stream =
                            NaivePaddingStream::new(io, PaddingDirection::Server, padding_type);
                        if let Err(e) = handle_naive_stream(
                            stream,
                            destination,
                            resolver,
                            proxy_selector,
                            udp_enabled,
                            &username,
                        )
                        .await
                        {
                            debug!("NaiveProxy tunnel error: {}", e);
                        }
                    } else if let Err(e) = handle_naive_stream(
                        io,
                        destination,
                        resolver,
                        proxy_selector,
                        udp_enabled,
                        &username,
                    )
                    .await
                    {
                        debug!("NaiveProxy tunnel error: {}", e);
                    }
                }
                Err(e) => {
                    debug!("NaiveProxy upgrade failed: {}", e);
                }
            }
        };

        if let Some(meter) = removal_meter {
            tokio::select! {
                biased;
                () = meter.cancelled() => {}
                () = tunnel => {}
            }
        } else {
            tunnel.await;
        }
    });

    let mut response = Response::builder().status(StatusCode::OK);

    if padding_type != PaddingType::None {
        let padding_len = rand::rng().random_range(30..=62);
        response = response.header("padding", generate_padding_header(padding_len));
        response = response.header("padding-type-reply", (padding_type as u8).to_string());
    }

    Ok(response.body(empty_body()).unwrap())
}

fn parse_connect_destination(req: &Request<Incoming>) -> Option<NetLocation> {
    let authority = req.uri().authority()?;
    parse_authority(authority.as_str()).ok()
}

/// Parse authority string (host:port) into NetLocation
fn parse_authority(authority: &str) -> io::Result<NetLocation> {
    // Handle IPv6: [::1]:443
    if authority.starts_with('[') {
        let end_bracket = authority
            .find(']')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid IPv6 address"))?;

        let host = &authority[1..end_bracket];

        let port =
            if authority.len() > end_bracket + 1 && authority.as_bytes()[end_bracket + 1] == b':' {
                authority[end_bracket + 2..].parse::<u16>().map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid port: {}", e))
                })?
            } else {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "Missing port"));
            };

        let addr = host.parse().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid IPv6: {}", e))
        })?;

        return Ok(NetLocation::new(Address::Ipv6(addr), port));
    }

    // Handle host:port
    let colon = authority
        .rfind(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing port"))?;

    let host = &authority[..colon];
    let port = authority[colon + 1..]
        .parse::<u16>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid port: {}", e)))?;

    let address = Address::from(host)?;
    Ok(NetLocation::new(address, port))
}

/// Serve static files or return 401 Unauthorized
async fn serve_fallback(
    uri_path: &str,
    fallback_path: &Option<PathBuf>,
    is_head: bool,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Infallible> {
    let Some(base_path) = fallback_path else {
        // Return 401 instead of 407 to avoid revealing proxy
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(empty_body())
            .unwrap());
    };

    // Sanitize path to prevent directory traversal
    let request_path = uri_path.trim_start_matches('/');
    let mut file_path = base_path.clone();

    for component in std::path::Path::new(request_path).components() {
        match component {
            std::path::Component::Normal(c) => file_path.push(c),
            std::path::Component::ParentDir => {
                return Ok(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(empty_body())
                    .unwrap());
            }
            _ => {}
        }
    }

    if file_path.is_dir() {
        file_path.push("index.html");
    }

    match tokio::fs::read(&file_path).await {
        Ok(contents) => {
            let mime = mime_guess::from_path(&file_path)
                .first_or_octet_stream()
                .to_string();

            let body = if is_head {
                empty_body()
            } else {
                full_body(Bytes::from(contents.clone()))
            };

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", mime)
                .header("content-length", contents.len())
                .body(body)
                .unwrap())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(empty_body())
            .unwrap()),
        Err(_) => Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(empty_body())
            .unwrap()),
    }
}

/// Handle a single NaiveProxy stream after setup
///
/// This handles both TCP and UDP-over-TCP (UoT) connections.
async fn handle_naive_stream<S: AsyncStream + 'static>(
    mut stream: S,
    remote_location: NetLocation,
    resolver: Arc<dyn Resolver>,
    proxy_selector: Arc<ClientProxySelector>,
    udp_enabled: bool,
    user_name: &str,
) -> io::Result<()> {
    use crate::client_proxy_selector::ConnectDecision;

    if let Address::Hostname(host) = remote_location.address() {
        if host == UOT_V1_MAGIC_ADDRESS {
            if !udp_enabled {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "UDP-over-TCP not enabled",
                ));
            }

            debug!("NaiveProxy stream (user: {}): UoT V1 mode", user_name);
            let uot_stream = UotV1ServerStream::new_uot(stream);

            return run_udp_routing(
                ServerStream::Targeted(Box::new(uot_stream)),
                proxy_selector,
                resolver,
                false,
            )
            .await;
        } else if host == UOT_V2_MAGIC_ADDRESS {
            if !udp_enabled {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "UDP-over-TCP not enabled",
                ));
            }

            // UoT V2 header: destination uses SOCKS5 address format
            let is_connect = stream.read_u8().await?;
            let destination = read_location_direct(&mut stream).await?;

            debug!(
                "NaiveProxy stream (user: {}): UoT V2 connect={} -> {}",
                user_name, is_connect, destination
            );

            if is_connect == 1 {
                let uot_v2_stream = UotV2Stream::new(stream);

                let action = proxy_selector
                    .judge_udp(destination.clone().into(), &resolver)
                    .await?;

                match action {
                    ConnectDecision::Allow {
                        chain_group,
                        remote_location,
                    } => {
                        let client_stream = chain_group
                            .connect_udp_bidirectional(&resolver, remote_location)
                            .await?;

                        return run_udp_copy(
                            Box::new(uot_v2_stream) as Box<dyn AsyncMessageStream>,
                            client_stream,
                            false,
                            false,
                        )
                        .await;
                    }
                    ConnectDecision::Block => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "UDP blocked by rules",
                        ));
                    }
                }
            } else {
                // V2 non-connect mode (same as V1)
                let uot_stream = UotV1ServerStream::new_uot(stream);

                return run_udp_routing(
                    ServerStream::Targeted(Box::new(uot_stream)),
                    proxy_selector,
                    resolver,
                    false,
                )
                .await;
            }
        }
    }

    debug!(
        "NaiveProxy stream (user: {}): TCP -> {}",
        user_name, remote_location
    );

    let action = proxy_selector
        .judge_tcp(remote_location.clone().into(), &resolver)
        .await?;

    let mut client_stream: Box<dyn AsyncStream> = match action {
        ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => {
            let result = chain_group.connect_tcp(remote_location, &resolver).await?;
            result.client_stream
        }
        ConnectDecision::Block => {
            debug!("NaiveProxy: connection blocked by rules");
            return Ok(());
        }
    };

    // Larger than the 16 KiB default, because a single CONNECT tunnel here carries a
    // whole client connection and the default costs syscalls on a fast link.
    //
    // But not as large as it wants to be. This pair of buffers is charged per
    // *stream*, not per connection, and NaiveProxy multiplexes every CONNECT over one
    // HTTP/2 connection -- so the real figure is this number, doubled for the two
    // directions, times `max_concurrent_streams`. At the 256 KiB it used to be that
    // came to half a gigabyte for one authenticated client, which is a resource
    // exhaustion an ordinary user reaches by accident and a malicious one reaches on
    // purpose. 64 KiB is what the reference implementation uses, and keeps the
    // ceiling in tens of megabytes.
    const COPY_BUF_SIZE: usize = 64 * 1024;
    let result = copy_bidirectional_with_sizes(
        &mut stream,
        &mut client_stream,
        false,
        false,
        COPY_BUF_SIZE,
        COPY_BUF_SIZE,
    )
    .await;

    let _ = stream.shutdown().await;
    let _ = client_stream.shutdown().await;

    match result {
        Ok(()) => {
            debug!("NaiveProxy stream (user: {}): done", user_name);
            Ok(())
        }
        Err(e) => {
            debug!("NaiveProxy stream (user: {}): error: {}", user_name, e);
            Err(e)
        }
    }
}
