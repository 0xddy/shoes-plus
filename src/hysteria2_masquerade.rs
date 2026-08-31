//! HTTP/3 camouflage for unauthenticated Hysteria2 connections.
//!
//! Hysteria2 authenticates with one special HTTP/3 request. Everything else on
//! the connection is deliberately ordinary HTTP: either a fixed page or a
//! reverse proxy. Keeping this bridge separate from the proxy data path makes it
//! much harder for a probe request to accidentally acquire a user/accounting
//! context.

use std::sync::{Arc, OnceLock};

use bytes::{Buf, Bytes};
use http::header::{HOST, HeaderMap, HeaderValue};
use http::{Request, Response, StatusCode, Uri, Version};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, StreamBody};
use hyper::body::Frame;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use log::{debug, warn};
use tokio::net::TcpStream;
use url::Url;

use crate::async_stream::AsyncStream;
use crate::config::Hysteria2MasqueradeConfig;
use crate::crypto::{CryptoConnection, CryptoTlsStream, perform_crypto_handshake};

type H3RequestStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type H3RecvStream = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;
type H3SendStream = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type ProxyRequestBody = UnsyncBoxBody<Bytes, std::io::Error>;

/// Parsed, listener-ready masquerade configuration.
#[derive(Debug, Clone)]
pub(crate) enum Hysteria2Masquerade {
    NotFound,
    String {
        content: Bytes,
        content_type: HeaderValue,
    },
    Proxy {
        target: Url,
        rewrite_host: bool,
        use_native_roots: bool,
    },
}

impl Hysteria2Masquerade {
    pub(crate) fn new(config: Option<&Hysteria2MasqueradeConfig>) -> std::io::Result<Self> {
        match config {
            None => Ok(Self::NotFound),
            Some(Hysteria2MasqueradeConfig::String {
                content,
                content_type,
            }) => {
                let content_type = HeaderValue::from_str(content_type).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid Hysteria2 masquerade content type: {e}"),
                    )
                })?;
                Ok(Self::String {
                    content: Bytes::copy_from_slice(content.as_bytes()),
                    content_type,
                })
            }
            Some(Hysteria2MasqueradeConfig::Proxy {
                url,
                rewrite_host,
                use_native_roots,
            }) => {
                let target = parse_proxy_url(url)?;
                Ok(Self::Proxy {
                    target,
                    rewrite_host: *rewrite_host,
                    use_native_roots: *use_native_roots,
                })
            }
        }
    }

    /// Answer one request that did not authenticate the connection.
    pub(crate) async fn respond(
        &self,
        request: Request<()>,
        mut stream: H3RequestStream,
    ) -> std::io::Result<()> {
        match self {
            Self::NotFound => {
                send_bytes(
                    &mut stream,
                    Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(())
                        .expect("a 404 response is valid"),
                    Bytes::new(),
                )
                .await
            }
            Self::String {
                content,
                content_type,
            } => {
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header(http::header::CONTENT_TYPE, content_type)
                    .header(http::header::CONTENT_LENGTH, content.len())
                    .body(())
                    .expect("validated fixed masquerade headers are valid");
                let body = if request.method() == http::Method::HEAD {
                    Bytes::new()
                } else {
                    content.clone()
                };
                send_bytes(&mut stream, response, body).await
            }
            Self::Proxy {
                target,
                rewrite_host,
                use_native_roots,
            } => {
                let (mut send, recv) = stream.split();
                if let Err(error) = proxy(
                    request,
                    &mut send,
                    recv,
                    target,
                    *rewrite_host,
                    *use_native_roots,
                )
                .await
                {
                    warn!("Hysteria2 masquerade upstream failed: {error}");
                    // Match sing-box's ErrorHandler: a failure before response
                    // headers becomes a plain 502. `proxy` only returns after
                    // sending headers for h3-side failures, which cannot be
                    // replaced at that point and will make this send fail too.
                    send_bytes(
                        &mut send,
                        Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(())
                            .expect("a 502 response is valid"),
                        Bytes::new(),
                    )
                    .await?;
                }
                Ok(())
            }
        }
    }
}

pub(crate) fn validate_config(config: &Hysteria2MasqueradeConfig) -> std::io::Result<()> {
    Hysteria2Masquerade::new(Some(config)).map(|_| ())
}

fn parse_proxy_url(raw: &str) -> std::io::Result<Url> {
    let url = Url::parse(raw).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid Hysteria2 proxy masquerade URL: {e}"),
        )
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Hysteria2 proxy masquerade URL must be an absolute HTTP or HTTPS URL without user info",
        ));
    }
    Ok(url)
}

async fn send_bytes<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    response: Response<()>,
    body: Bytes,
) -> std::io::Result<()>
where
    S: h3::quic::SendStream<Bytes>,
{
    stream
        .send_response(response)
        .await
        .map_err(|e| std::io::Error::other(format!("failed to send masquerade response: {e}")))?;
    if !body.is_empty() {
        stream
            .send_data(body)
            .await
            .map_err(|e| std::io::Error::other(format!("failed to send masquerade body: {e}")))?;
    }
    stream
        .finish()
        .await
        .map_err(|e| std::io::Error::other(format!("failed to finish masquerade response: {e}")))
}

async fn proxy(
    request: Request<()>,
    send: &mut H3SendStream,
    recv: H3RecvStream,
    target: &Url,
    rewrite_host: bool,
    use_native_roots: bool,
) -> std::io::Result<()> {
    let body = request_body(recv);
    let upstream_request = rewrite_request(request, target, rewrite_host, body)?;
    let (upstream, protocol) = connect_upstream(target, use_native_roots).await?;
    let io = TokioIo::new(upstream);
    let response = match protocol {
        UpstreamProtocol::Http1 => {
            let (mut sender, connection) = http1::handshake::<_, ProxyRequestBody>(io)
                .await
                .map_err(|e| {
                    std::io::Error::other(format!("upstream HTTP/1 handshake failed: {e}"))
                })?;
            tokio::spawn(async move {
                if let Err(error) = connection.await {
                    debug!("Hysteria2 masquerade HTTP/1 connection ended: {error}");
                }
            });
            sender
                .send_request(upstream_request)
                .await
                .map_err(|e| std::io::Error::other(format!("upstream request failed: {e}")))?
        }
        UpstreamProtocol::Http2 => {
            let (mut sender, connection) =
                http2::handshake::<_, _, ProxyRequestBody>(TokioExecutor::new(), io)
                    .await
                    .map_err(|e| {
                        std::io::Error::other(format!("upstream HTTP/2 handshake failed: {e}"))
                    })?;
            tokio::spawn(async move {
                if let Err(error) = connection.await {
                    debug!("Hysteria2 masquerade HTTP/2 connection ended: {error}");
                }
            });
            sender
                .send_request(upstream_request)
                .await
                .map_err(|e| std::io::Error::other(format!("upstream request failed: {e}")))?
        }
    };
    forward_response(send, response).await
}

fn request_body(recv: H3RecvStream) -> ProxyRequestBody {
    let frames =
        futures::stream::try_unfold((recv, false), |(mut recv, trailers_sent)| async move {
            if trailers_sent {
                return Ok(None);
            }
            match recv.recv_data().await.map_err(|e| {
                std::io::Error::other(format!("failed to read masquerade request body: {e}"))
            })? {
                Some(mut data) => {
                    let remaining = data.remaining();
                    Ok(Some((
                        Frame::data(data.copy_to_bytes(remaining)),
                        (recv, false),
                    )))
                }
                None => match recv.recv_trailers().await.map_err(|e| {
                    std::io::Error::other(format!(
                        "failed to read masquerade request trailers: {e}"
                    ))
                })? {
                    Some(trailers) => Ok(Some((Frame::trailers(trailers), (recv, true)))),
                    None => Ok(None),
                },
            }
        });
    StreamBody::new(frames).boxed_unsync()
}

fn rewrite_request<B>(
    request: Request<()>,
    target: &Url,
    rewrite_host: bool,
    body: B,
) -> std::io::Result<Request<B>> {
    let original_authority = request
        .uri()
        .authority()
        .map(|authority| authority.as_str().to_owned())
        .or_else(|| {
            request
                .headers()
                .get(HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        });
    let path_and_query = joined_path_and_query(target, request.uri());
    let uri: Uri = path_and_query.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid rewritten masquerade URI: {e}"),
        )
    })?;

    let (parts, ()) = request.into_parts();
    let mut headers = parts.headers;
    remove_hop_by_hop_headers(&mut headers);
    remove_hysteria2_protocol_headers(&mut headers);
    let host = if rewrite_host {
        target_authority(target)
    } else {
        original_authority.unwrap_or_else(|| target_authority(target))
    };
    headers.insert(HOST, HeaderValue::from_str(&host).map_err(invalid_host)?);

    let mut upstream = Request::new(body);
    *upstream.method_mut() = parts.method;
    *upstream.uri_mut() = uri;
    *upstream.version_mut() = Version::HTTP_11;
    *upstream.headers_mut() = headers;
    Ok(upstream)
}

fn joined_path_and_query(target: &Url, incoming: &Uri) -> String {
    let base = target.path();
    let incoming_path = incoming.path();
    let mut path = match (base.ends_with('/'), incoming_path.starts_with('/')) {
        (true, true) => format!("{}{}", base, &incoming_path[1..]),
        (false, false) => format!("{base}/{incoming_path}"),
        _ => format!("{base}{incoming_path}"),
    };
    if path.is_empty() {
        path.push('/');
    }

    match (target.query(), incoming.query()) {
        (Some(base_query), Some(incoming_query)) => {
            path.push('?');
            path.push_str(base_query);
            path.push('&');
            path.push_str(incoming_query);
        }
        (Some(query), None) | (None, Some(query)) => {
            path.push('?');
            path.push_str(query);
        }
        (None, None) => {}
    }
    path
}

fn target_authority(target: &Url) -> String {
    use url::Position::{AfterPort, BeforeHost};
    target[BeforeHost..AfterPort].to_string()
}

fn invalid_host(error: http::header::InvalidHeaderValue) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("invalid masquerade Host header: {error}"),
    )
}

fn remove_hop_by_hop_headers(headers: &mut HeaderMap) {
    // RFC 9110 section 7.6.1. HTTP/3 rejects these connection-specific fields,
    // and an HTTP/1 origin may legitimately send them back.
    let nominated: Vec<_> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| http::header::HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    const NAMES: [&str; 8] = [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];
    for name in NAMES {
        headers.remove(name);
    }
}

fn remove_hysteria2_protocol_headers(headers: &mut HeaderMap) {
    // An auth request can reach the cover proxy both for an unknown password and
    // for a valid password whose admission was refused. Never forward the cleartext
    // credential -- or any of the surrounding protocol-only metadata -- to an
    // operator-controlled camouflage origin. Header names are normalized to lower
    // case by `http`, so the prefix check is case-insensitive in practice and also
    // covers future Hysteria2 request headers without another deny-list update.
    let protocol_headers: Vec<_> = headers
        .keys()
        .filter(|name| name.as_str().starts_with("hysteria-"))
        .cloned()
        .collect();
    for name in protocol_headers {
        headers.remove(name);
    }
}

async fn forward_response(
    stream: &mut H3SendStream,
    response: Response<hyper::body::Incoming>,
) -> std::io::Result<()> {
    let (mut parts, mut body) = response.into_parts();
    remove_hop_by_hop_headers(&mut parts.headers);
    let mut h3_response = Response::builder()
        .status(parts.status)
        .version(Version::HTTP_3)
        .body(())
        .expect("upstream response status is valid");
    *h3_response.headers_mut() = parts.headers;
    stream
        .send_response(h3_response)
        .await
        .map_err(|e| std::io::Error::other(format!("failed to send proxied headers: {e}")))?;

    while let Some(frame) = body.frame().await {
        let frame = frame
            .map_err(|e| std::io::Error::other(format!("failed to read upstream response: {e}")))?;
        match frame.into_data() {
            Ok(data) => stream.send_data(data).await.map_err(|e| {
                std::io::Error::other(format!("failed to send proxied response body: {e}"))
            })?,
            Err(frame) => {
                if let Ok(mut trailers) = frame.into_trailers() {
                    remove_hop_by_hop_headers(&mut trailers);
                    stream.send_trailers(trailers).await.map_err(|e| {
                        std::io::Error::other(format!("failed to send proxied trailers: {e}"))
                    })?;
                }
            }
        }
    }
    stream
        .finish()
        .await
        .map_err(|e| std::io::Error::other(format!("failed to finish proxied response: {e}")))
}

#[derive(Clone, Copy)]
enum UpstreamProtocol {
    Http1,
    Http2,
}

async fn connect_upstream(
    target: &Url,
    use_native_roots: bool,
) -> std::io::Result<(Box<dyn AsyncStream>, UpstreamProtocol)> {
    let host = target.host_str().expect("validated proxy URL has a host");
    let port = target
        .port_or_known_default()
        .expect("HTTP and HTTPS have known default ports");
    let tcp = TcpStream::connect((host, port)).await?;
    tcp.set_nodelay(true)?;
    let mut stream: Box<dyn AsyncStream> = Box::new(tcp);
    let mut protocol = UpstreamProtocol::Http1;

    if target.scheme() == "https" {
        static BUNDLED_TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
        static NATIVE_TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
        let config = if use_native_roots {
            &NATIVE_TLS_CONFIG
        } else {
            &BUNDLED_TLS_CONFIG
        }
        .get_or_init(|| {
            Arc::new(crate::rustls_config_util::create_client_config(
                true,
                vec![],
                vec!["h2".to_string(), "http/1.1".to_string()],
                true,
                None,
                false,
                use_native_roots,
            ))
        })
        .clone();
        let server_name =
            rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid masquerade TLS server name: {e}"),
                )
            })?;
        let client = rustls::ClientConnection::new(config, server_name).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("could not create masquerade TLS client: {e}"),
            )
        })?;
        let mut connection = CryptoConnection::new_rustls_client(client);
        perform_crypto_handshake(&mut connection, &mut stream, 16_384).await?;
        if connection.alpn_protocol() == Some(b"h2") {
            protocol = UpstreamProtocol::Http2;
        }
        stream = Box::new(CryptoTlsStream::new(stream, connection));
    }

    Ok((stream, protocol))
}

#[cfg(test)]
mod tests {
    use super::{joined_path_and_query, parse_proxy_url, rewrite_request, target_authority};

    #[test]
    fn reverse_proxy_joins_base_path_and_queries_like_go() {
        let target = parse_proxy_url("https://origin.example/base?fixed=1").unwrap();
        let incoming = "https://cover.example/asset?q=two".parse().unwrap();
        assert_eq!(
            joined_path_and_query(&target, &incoming),
            "/base/asset?fixed=1&q=two"
        );
        assert_eq!(target_authority(&target), "origin.example");
    }

    #[test]
    fn proxy_url_is_absolute_http_without_credentials() {
        for invalid in [
            "/relative",
            "ftp://example.com/",
            "https:///",
            "https://user:pass@example.com/",
        ] {
            assert!(parse_proxy_url(invalid).is_err(), "accepted {invalid}");
        }
        assert!(parse_proxy_url("http://127.0.0.1:8080/base").is_ok());
    }

    #[test]
    fn proxy_never_forwards_hysteria_credentials_or_protocol_headers() {
        let target = parse_proxy_url("http://127.0.0.1:8080/cover").unwrap();
        let request = http::Request::post("https://hysteria/auth")
            .header("hysteria-auth", "live-user-password")
            .header("Hysteria-CC-RX", "1048576")
            .header("Hysteria-Padding", "camouflage-padding")
            .header("x-cover-probe", "preserved")
            .body(())
            .unwrap();

        let upstream = rewrite_request(request, &target, true, ()).unwrap();

        assert!(
            upstream
                .headers()
                .keys()
                .all(|name| !name.as_str().starts_with("hysteria-")),
            "no Hysteria2-only header may escape to the camouflage origin"
        );
        assert_eq!(upstream.headers()["x-cover-probe"], "preserved");
    }
}
