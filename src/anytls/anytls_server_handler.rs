//! AnyTLS Server Handler
//!
//! Implements TcpServerHandler for AnyTLS protocol.
//! This handler:
//! 1. Authenticates clients via SHA256(password)
//! 2. Creates an AnyTlsSession with all routing dependencies
//! 3. Runs the session which handles streams internally

use async_trait::async_trait;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::address::NetLocation;
use crate::anytls::anytls_padding::PaddingFactory;
use crate::anytls::anytls_server_session::AnyTlsSession;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::copy_bidirectional::copy_bidirectional;
use crate::dynamic::{
    UserRegistry, bind_connection_user_for_fallback, current_connection,
    spawn_connection_until_cancelled,
};
use crate::resolver::Resolver;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{
    TcpServerHandler, TcpServerSetupResult, UnauthenticatedFallbackCompletion,
};
use crate::util::write_all;

/// AnyTLS server handler implementing TcpServerHandler
///
/// This handler receives a post-TLS stream and handles AnyTLS protocol.
/// It authenticates the client, creates a session with routing dependencies,
/// and runs the session which handles all streams internally.
#[derive(Debug)]
pub struct AnyTlsServerHandler {
    /// Who a password hash belongs to, and the 8-byte-prefix probe that decides
    /// whether to keep reading one. Both questions go to the same registry: an
    /// injected one for a multi-user inbound, or a one-user registry built from this
    /// inbound's own config credential.
    users: Arc<dyn UserRegistry>,
    /// Padding factory for traffic obfuscation
    padding: Arc<PaddingFactory>,
    /// Resolver for destination addresses
    resolver: Arc<dyn Resolver>,
    /// Proxy provider for routing decisions
    proxy_provider: Arc<ClientProxySelector>,
    /// UDP enabled for UoT support
    udp_enabled: bool,
    /// Fallback destination for failed authentication
    fallback: Option<NetLocation>,
}

impl AnyTlsServerHandler {
    /// Create a new AnyTLS server handler.
    ///
    /// # Arguments
    /// * `users` - The registry this inbound authenticates against
    /// * `padding` - Padding factory for traffic obfuscation
    /// * `resolver` - DNS resolver for destination addresses
    /// * `proxy_provider` - Proxy selector for routing decisions
    /// * `udp_enabled` - Whether UDP-over-TCP is enabled
    /// * `fallback` - Optional fallback destination for failed auth
    pub fn new(
        users: Arc<dyn UserRegistry>,
        padding: Arc<PaddingFactory>,
        resolver: Arc<dyn Resolver>,
        proxy_provider: Arc<ClientProxySelector>,
        udp_enabled: bool,
        fallback: Option<NetLocation>,
    ) -> Self {
        Self {
            users,
            padding,
            resolver,
            proxy_provider,
            udp_enabled,
            fallback,
        }
    }
}

#[async_trait]
impl TcpServerHandler for AnyTlsServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        // Use StreamReader to peek at auth header without consuming
        let mut reader = StreamReader::new();

        // First, peek at the 8-byte prefix for quick fallback.
        // This allows us to reject non-AnyTLS traffic (e.g., small HTTP requests)
        // without hanging waiting for the full 32-byte hash.
        //
        // Timing side-channel note: This creates a timing difference between prefix
        // match and mismatch, but is not exploitable since enumerating 2^64 prefixes
        // is infeasible, and discovering a valid prefix doesn't help recover the
        // password or the remaining 24 bytes of the SHA256 hash.
        let prefix_data = reader.peek_slice(&mut server_stream, 8).await?;
        let prefix: [u8; 8] = prefix_data.try_into().expect("peek_slice returned 8 bytes");

        if !self.users.has_password_sha256_prefix(&prefix) {
            log::debug!("AnyTLS quick fallback: 8-byte prefix doesn't match any user");
            if let Some(ref fallback) = self.fallback {
                return self.fallback_to_dest(server_stream, reader, fallback).await;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "authentication failed (prefix mismatch)",
            ));
        }

        // Prefix matches - now read the full 32-byte hash
        let auth_data = reader.peek_slice(&mut server_stream, 32).await?;
        let hash: [u8; 32] = auth_data.try_into().expect("peek_slice returned 32 bytes");

        let meter = current_connection();
        let user_name = match self.users.find_password_sha256(&hash) {
            Some(user) => {
                log::debug!("AnyTLS user authenticated: {}", user.id());
                // The stream is metered from the moment it was accepted, so this hands
                // the TLS handshake already counted against nobody over to whoever
                // just proved they own it. Inline on the accepting task, before the
                // session is spawned, which is what lets the task local reach it.
                if !bind_connection_user_for_fallback(&user) {
                    log::debug!("AnyTLS password resolved but the user could not be admitted");
                    if let Some(ref fallback) = self.fallback {
                        return self.fallback_to_dest(server_stream, reader, fallback).await;
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "authentication failed",
                    ));
                }
                // Consume only after admission succeeds. A rejected but valid hash
                // must reach the fallback byte-for-byte like an unknown credential.
                reader.consume(32);
                user.id().to_string()
            }
            None => {
                log::debug!("AnyTLS authentication failed: unknown password");
                // If fallback is configured, forward the connection there. A disabled
                // user lands here too, deliberately: the registry reports them absent
                // so that a suspension is not observable from outside.
                if let Some(ref fallback) = self.fallback {
                    return self.fallback_to_dest(server_stream, reader, fallback).await;
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "authentication failed",
                ));
            }
        };

        let padding_len = reader.read_u16_be(&mut server_stream).await?;

        // Skip padding bytes (consume them from the reader)
        if padding_len > 0 {
            let _ = reader
                .read_slice(&mut *server_stream, padding_len as usize)
                .await?;
        }

        // Get any remaining unparsed data that may have been buffered
        let initial_data = reader.unparsed_data_owned();

        // Create session with all dependencies for internal stream handling
        let session = AnyTlsSession::new_server_with_initial_data(
            server_stream,
            Arc::clone(&self.padding),
            Arc::clone(&self.resolver),
            Arc::clone(&self.proxy_provider),
            self.udp_enabled,
            user_name,
            initial_data,
        );

        // Hyper-style session ownership outlives this setup future. Carry the
        // connection context across that spawn so removing the user can close the
        // whole multiplexed session, including child streams waiting on routing.
        tokio::spawn(async move {
            let result = if let Some(meter) = meter {
                tokio::select! {
                    result = session.run_core() => result,
                    () = meter.cancelled() => {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionAborted,
                            "user removed",
                        ))
                    }
                }
            } else {
                session.run_core().await
            };
            // The selected core future is now gone, so this is the sole cleanup
            // owner and cannot be cancelled by the select above.
            session.close().await;

            if let Err(e) = result {
                log::debug!("AnyTLS session ended: {}", e);
            }
        });

        Ok(TcpServerSetupResult::AlreadyHandled)
    }
}

impl AnyTlsServerHandler {
    /// Forward the connection to a fallback destination when authentication fails.
    ///
    /// This makes the server indistinguishable from a legitimate server by transparently
    /// proxying failed auth attempts to the configured fallback destination.
    async fn fallback_to_dest(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        reader: StreamReader,
        fallback: &NetLocation,
    ) -> std::io::Result<TcpServerSetupResult> {
        log::debug!("AnyTLS FALLBACK: Connecting to fallback: {}", fallback);

        // Get the unconsumed data from the reader (includes auth header)
        let unconsumed_data = reader.unparsed_data();

        // Resolve and connect to the fallback destination
        let dest_addr = crate::resolver::resolve_single_address(&self.resolver, fallback).await?;

        log::debug!("AnyTLS FALLBACK: Resolved {} to {}", fallback, dest_addr);

        let mut dest_stream: Box<dyn AsyncStream> = Box::new(TcpStream::connect(dest_addr).await?);

        log::debug!(
            "AnyTLS FALLBACK: Connected to fallback, forwarding {} bytes",
            unconsumed_data.len()
        );

        // Forward the unconsumed data (auth header that the client sent)
        if !unconsumed_data.is_empty() {
            write_all(&mut dest_stream, unconsumed_data).await?;
            dest_stream.flush().await?;
        }

        log::debug!("AnyTLS FALLBACK: Spawning bidirectional copy");

        // Spawn the long-running bidirectional copy as a background task.
        // This allows the setup to complete within the timeout while the actual
        // data transfer runs indefinitely.
        let completion = spawn_connection_until_cancelled(async move {
            let result = copy_bidirectional(
                &mut *client_stream,
                &mut *dest_stream,
                false, // client doesn't need initial flush
                false, // dest doesn't need initial flush
            )
            .await;

            let _ = client_stream.shutdown().await;
            let _ = dest_stream.shutdown().await;

            if let Err(e) = result {
                log::debug!("AnyTLS FALLBACK: Connection ended: {}", e);
            } else {
                log::debug!("AnyTLS FALLBACK: Connection completed");
            }
            Ok(())
        });

        Ok(TcpServerSetupResult::UnauthenticatedFallbackHandled(
            UnauthenticatedFallbackCompletion::new(completion),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    use super::*;

    use crate::address::Address;
    use crate::dynamic::credential::{password_sha256, password_sha256_prefix};
    use crate::dynamic::{ConnContext, StaticUserRegistry, UserContext, scope_connection};
    use crate::resolver::NativeResolver;

    struct TestStream(tokio::io::DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl crate::async_stream::AsyncPing for TestStream {
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

    impl AsyncStream for TestStream {}

    #[derive(Debug)]
    struct OnePasswordRegistry {
        hash: [u8; 32],
        user: Arc<UserContext>,
    }

    impl UserRegistry for OnePasswordRegistry {
        fn find_password_sha256(&self, hash: &[u8; 32]) -> Option<Arc<UserContext>> {
            (hash == &self.hash).then(|| Arc::clone(&self.user))
        }

        fn has_password_sha256_prefix(&self, _prefix: &[u8; 8]) -> bool {
            true
        }

        fn user_count(&self) -> usize {
            1
        }
    }

    async fn fallback_round_trip(
        users: Arc<dyn UserRegistry>,
        hash: [u8; 32],
    ) -> ([u8; 32], [u8; 5]) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let fallback_address = listener.local_addr().unwrap();
        let fallback = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0u8; 32];
            stream.read_exact(&mut header).await.unwrap();
            stream.write_all(b"cover").await.unwrap();
            stream.shutdown().await.unwrap();
            header
        });
        let handler = AnyTlsServerHandler::new(
            users,
            PaddingFactory::default_factory(),
            Arc::new(NativeResolver::new()),
            Arc::new(ClientProxySelector::new(Vec::new())),
            false,
            Some(NetLocation::new(
                Address::Ipv4(Ipv4Addr::LOCALHOST),
                fallback_address.port(),
            )),
        );
        let (mut client, server) = tokio::io::duplex(128);
        client.write_all(&hash).await.unwrap();
        let conn = ConnContext::new();
        let result = scope_connection(
            Arc::clone(&conn),
            handler.setup_server_stream(Box::new(TestStream(server))),
        )
        .await
        .unwrap();
        let TcpServerSetupResult::UnauthenticatedFallbackHandled(completion) = result else {
            panic!("credential rejection did not enter the AnyTLS fallback");
        };
        let mut cover = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut cover))
            .await
            .unwrap()
            .unwrap();
        client.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), completion.wait())
            .await
            .unwrap()
            .unwrap();
        (fallback.await.unwrap(), cover)
    }

    #[test]
    fn the_wire_credential_is_the_raw_sha256_of_the_password() {
        // The handler compares what the client sends against this derivation, so if
        // it ever drifted every AnyTLS client in the world would stop connecting.
        let hash = password_sha256("secret123");
        let expected = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"secret123");
        assert_eq!(&hash[..], expected.as_ref());
        assert_ne!(password_sha256("pass1"), password_sha256("pass2"));
    }

    #[test]
    fn a_config_built_registry_answers_both_questions_the_handler_asks() {
        // The handler asks twice: an 8-byte prefix probe before it has read the whole
        // credential, then the full 32 bytes. Both go to the registry.
        let registry = StaticUserRegistry::single_anytls_password("alice", "password1");
        let hash = password_sha256("password1");

        assert!(registry.has_password_sha256_prefix(&password_sha256_prefix(&hash)));
        assert_eq!(
            registry
                .find_password_sha256(&hash)
                .map(|user| user.id().to_string()),
            Some("alice".to_string())
        );
    }

    #[test]
    fn a_probe_that_is_not_a_credential_is_turned_away_at_the_prefix() {
        // What actually shows up on a public port: an HTTP request. It must be sent
        // to the fallback after 8 bytes rather than hang the handler waiting for 32.
        let registry = StaticUserRegistry::single_anytls_password("alice", "password1");
        let http: [u8; 8] = *b"GET / HT";
        assert!(!registry.has_password_sha256_prefix(&http));
    }

    #[test]
    fn two_users_are_told_apart_by_the_full_hash() {
        let mut registry = StaticUserRegistry::new();
        registry.add_anytls_password("alice", "password1");
        registry.add_anytls_password("bob", "password2");
        let registry: Arc<dyn UserRegistry> = Arc::new(registry);

        assert_eq!(
            registry
                .find_password_sha256(&password_sha256("password1"))
                .map(|u| u.id().to_string()),
            Some("alice".to_string())
        );
        assert_eq!(
            registry
                .find_password_sha256(&password_sha256("password2"))
                .map(|u| u.id().to_string()),
            Some("bob".to_string())
        );
        assert_eq!(registry.user_count(), 2);
    }

    #[tokio::test]
    async fn a_valid_password_at_its_connection_limit_looks_like_an_unknown_password() {
        let hash = password_sha256("password1");
        let user = UserContext::new("alice");
        user.set_max_conns(1);
        let occupied = user
            .register_authenticated_connection(CancellationToken::new())
            .unwrap();
        let users: Arc<dyn UserRegistry> = Arc::new(OnePasswordRegistry {
            hash,
            user: Arc::clone(&user),
        });

        let (limited_header, limited_cover) = fallback_round_trip(users.clone(), hash).await;
        let unknown_hash = password_sha256("unknown");
        let (unknown_header, unknown_cover) = fallback_round_trip(users, unknown_hash).await;
        assert_eq!(limited_header, hash);
        assert_eq!(unknown_header, unknown_hash);
        assert_eq!(limited_cover, unknown_cover);
        assert_eq!(&limited_cover, b"cover");
        assert_eq!(user.conns(), 1);
        assert_eq!(user.total_conns(), 1);
        user.unregister_connection(occupied);
    }
}
