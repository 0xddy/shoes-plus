use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Instant, timeout_at};

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_chain::ClientProxyChain;
use crate::client_proxy_selector::ClientProxySelector;
use crate::crypto::{CryptoConnection, CryptoTlsStream, perform_crypto_handshake};
use crate::dynamic::spawn_connection_until_cancelled;
use crate::resolver::Resolver;
use crate::shadow_tls::{ParsedClientHello, parse_server_hello};
use crate::tcp::tcp_handler::{
    TcpClientSetupResult, TcpServerSetupResult, UnauthenticatedFallbackCompletion,
};
use crate::tls_server_handler::InnerProtocol;
use crate::util::{allocate_vec, write_all};
use crate::vless::tls_deframer::TlsDeframer;

use super::{RealityServerConfig, RealityServerConnection};

#[derive(Debug)]
pub struct RealityServerTarget {
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    pub dest: NetLocation,
    pub max_time_diff: Option<u64>, // in milliseconds
    pub min_client_version: Option<[u8; 3]>,
    pub max_client_version: Option<[u8; 3]>,
    pub cipher_suites: Vec<super::CipherSuite>,
    /// The effective proxy selector for this REALITY target.
    /// For Vision mode, this is passed to the VLESS setup function.
    /// Inner handler already has this selector from construction.
    pub effective_selector: Arc<ClientProxySelector>,
    /// What to do after Reality termination - normal handler, Vision VLESS, or Naive
    pub inner_protocol: InnerProtocol,
    /// Client chain for connecting to dest server (for fallback connections).
    pub dest_client_chain: ClientProxyChain,
}

/// Set up REALITY server stream with real-time mirroring for anti-probing.
///
/// Connect to dest IMMEDIATELY before auth processing, making timing
/// indistinguishable from a real reverse proxy. This defeats active probing.
///
/// Flow:
/// - Connect to dest immediately
/// - Forward ClientHello immediately (starts dest's handshake)
/// - Validate auth (fast, ~1ms, while dest is processing)
/// - Read dest's response (it's been processing in parallel)
/// - Branch based on auth:
///   - Auth failed: forward dest's response, continue bidirectional copy
///   - Auth succeeded: build REALITY response matching dest's structure
#[inline]
pub async fn setup_reality_server_stream(
    mut server_stream: Box<dyn AsyncStream>,
    target: &RealityServerTarget,
    parsed_client_hello: ParsedClientHello,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<TcpServerSetupResult> {
    let client_hello_frame = &parsed_client_hello.client_hello_frame;
    log::debug!(
        "REALITY ClientHello frame length: {}",
        client_hello_frame.len()
    );

    // Connect to dest before auth processing to minimize timing differences
    let TcpClientSetupResult {
        client_stream: mut dest_stream,
        early_data,
    } = target
        .dest_client_chain
        .connect_tcp(target.dest.clone().into(), resolver)
        .await
        .map_err(|e| {
            log::warn!("REALITY: Failed to connect to dest {}: {}", target.dest, e);
            std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("REALITY: Failed to connect to dest {}: {}", target.dest, e),
            )
        })?;

    debug_assert!(
        early_data.is_none(),
        "unexpected early_data from dest connection"
    );

    log::debug!(
        "REALITY: Connected to dest {}, forwarding ClientHello ({} bytes)",
        target.dest,
        client_hello_frame.len()
    );

    write_all(&mut dest_stream, client_hello_frame)
        .await
        .map_err(|error| {
            log::warn!(
                "REALITY: Failed to send ClientHello to dest {}: {}",
                target.dest,
                error
            );
            error
        })?;
    dest_stream.flush().await.map_err(|error| {
        log::warn!(
            "REALITY: Failed to flush ClientHello to dest {}: {}",
            target.dest,
            error
        );
        error
    })?;

    if !parsed_client_hello.supports_tls13 {
        log::debug!("REALITY: Client does not support TLS 1.3, falling back to dest");
        let completion = start_forward_to_dest(server_stream, dest_stream, vec![], Bytes::new());
        return Ok(TcpServerSetupResult::UnauthenticatedFallbackHandled(
            completion,
        ));
    }

    let reality_config = RealityServerConfig {
        private_key: target.private_key,
        short_ids: target.short_ids.clone(),
        dest: target.dest.clone(),
        max_time_diff: target.max_time_diff,
        min_client_version: target.min_client_version,
        max_client_version: target.max_client_version,
        cipher_suites: target.cipher_suites.clone(),
    };

    let mut reality_conn = RealityServerConnection::new(reality_config)?;

    let auth_result = reality_conn.validate_client_hello(client_hello_frame);

    // Read dest response until we have enough records. Use 512-byte heuristic like XTLS/REALITY:
    // first encrypted record > 512 bytes = combined mode, <= 512 bytes = separate mode
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut deframer = TlsDeframer::new();
    let mut dest_records: Vec<Bytes> = Vec::new();
    let mut buf = allocate_vec(8192).into_boxed_slice();
    let mut dest_handshake_success = false;
    let mut dest_record_parse_error = None;

    loop {
        let new_records = match timeout_at(deadline, dest_stream.read(&mut buf)).await {
            Ok(Ok(0)) => {
                log::warn!(
                    "REALITY: Dest {} closed during the TLS handshake",
                    target.dest
                );
                return Err(std::io::Error::other(
                    "REALITY: Dest connection closed during TLS handshake",
                ));
            }
            Ok(Ok(n)) => {
                deframer.feed(&buf[..n]);
                match deframer.next_records() {
                    Ok(records) => records,
                    Err(e) => {
                        dest_record_parse_error = Some(e.to_string());
                        break;
                    }
                }
            }
            Ok(Err(e)) => {
                log::warn!(
                    "REALITY: Failed to read TLS handshake from dest {}: {}",
                    target.dest,
                    e
                );
                return Err(std::io::Error::other(format!(
                    "REALITY: Error reading from dest: {}",
                    e
                )));
            }
            Err(_) => {
                log::debug!("REALITY: Timeout reading from dest");
                break;
            }
        };

        // When we get the first record (ServerHello), check if dest supports TLS 1.3
        if dest_records.is_empty() && !new_records.is_empty() {
            match parse_server_hello(&new_records[0]) {
                Ok(parsed) => {
                    if !parsed.is_tls13 {
                        log::warn!(
                            "REALITY: Dest {} is TLS 1.2, falling back to transparent forward",
                            target.dest
                        );
                        let completion = start_forward_to_dest(
                            server_stream,
                            dest_stream,
                            new_records,
                            deframer.into_remaining_data(),
                        );
                        return Ok(TcpServerSetupResult::UnauthenticatedFallbackHandled(
                            completion,
                        ));
                    }
                    log::debug!("REALITY: Dest confirmed TLS 1.3");
                }
                Err(e) => {
                    log::warn!("REALITY: Failed to parse dest ServerHello: {}", e);
                    let completion = start_forward_to_dest(
                        server_stream,
                        dest_stream,
                        new_records,
                        deframer.into_remaining_data(),
                    );
                    return Ok(TcpServerSetupResult::UnauthenticatedFallbackHandled(
                        completion,
                    ));
                }
            }
        }

        dest_records.extend(new_records);

        // Separate mode: first encrypted record is small, need more records
        // Keep reading until we have 6 records (SH + CCS + 4 encrypted) or timeout
        // Note: Some servers send NewSessionTicket as a 7th record, but we don't need it
        if dest_records.len() >= 6 {
            log::debug!(
                "REALITY: Separate mode detected, got {} records",
                dest_records.len()
            );
            dest_handshake_success = true;
            break;
        } else if dest_records.len() >= 3 {
            // Check if we have enough records using the 512-byte heuristic
            // Records: [0]=ServerHello, [1]=CCS, [2..]=encrypted handshake
            let first_encrypted = &dest_records[2];
            if first_encrypted.len() > 512 {
                // Combined mode: first encrypted record > 512 bytes contains all messages
                log::debug!(
                    "REALITY: Combined mode detected (first encrypted record {} bytes > 512)",
                    first_encrypted.len()
                );
                dest_handshake_success = true;
                break;
            }
        }
    }

    let remaining_data = deframer.into_remaining_data();

    if !dest_handshake_success {
        if let Some(error) = dest_record_parse_error {
            log::warn!(
                "REALITY: Failed to parse TLS records from dest {}: {}; falling back to transparent forward",
                target.dest,
                error
            );
        } else {
            log::warn!(
                "REALITY: Dest handshake failed (got {} records), falling back to transparent forward",
                dest_records.len()
            );
        }
        let completion =
            start_forward_to_dest(server_stream, dest_stream, dest_records, remaining_data);
        return Ok(TcpServerSetupResult::UnauthenticatedFallbackHandled(
            completion,
        ));
    }

    log::debug!(
        "REALITY: Read {} records from dest ({} bytes remaining)",
        dest_records.len(),
        remaining_data.len()
    );

    // Branch based on auth result. Permission failures and malformed authentication
    // material are both peer-controlled probe outcomes, so forward them to the
    // configured destination without raising a production error.
    match auth_result {
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::InvalidData
            ) =>
        {
            log::debug!(
                "REALITY: Auth failed ({}), forwarding to dest transparently",
                e
            );
            let completion =
                start_forward_to_dest(server_stream, dest_stream, dest_records, remaining_data);
            return Ok(TcpServerSetupResult::UnauthenticatedFallbackHandled(
                completion,
            ));
        }

        Err(e) => {
            log::error!("REALITY: Unexpected error during auth: {}", e);
            return Err(e);
        }

        Ok(()) => {}
    }

    log::debug!("REALITY: Auth succeeded, building response matching dest structure");

    drop(dest_stream);
    reality_conn.build_server_response(dest_records)?;

    let mut connection = CryptoConnection::new_reality_server(reality_conn);
    perform_crypto_handshake(&mut connection, &mut server_stream, 16384).await?;

    let tls_stream = CryptoTlsStream::new(server_stream, connection);
    log::debug!("REALITY: TLS 1.3 handshake completed successfully");

    match &target.inner_protocol {
        InnerProtocol::Normal(handler) => handler.setup_server_stream(Box::new(tls_stream)).await,
        InnerProtocol::VisionVless(vision_cfg) => {
            crate::vless::vless_server_handler::setup_custom_tls_vision_vless_server_stream(
                tls_stream,
                &vision_cfg.users,
                vision_cfg.udp_enabled,
                target.effective_selector.clone(),
                resolver,
                vision_cfg.fallback.clone(),
            )
            .await
        }
        InnerProtocol::Naive(naive_cfg) => {
            crate::naiveproxy::setup_naive_server_stream(
                tls_stream,
                naive_cfg,
                target.effective_selector.clone(),
                resolver.clone(),
            )
            .await
        }
    }
}

/// Forward dest records to client and spawn bidirectional copy.
///
/// Used when Reality auth fails or client doesn't support TLS 1.3.
/// Forwards any already-read dest records to the client, then spawns
/// bidirectional copy for the rest of the connection.
fn start_forward_to_dest(
    mut client_stream: Box<dyn AsyncStream>,
    mut dest_stream: Box<dyn AsyncStream>,
    dest_records: Vec<Bytes>,
    remaining_data: Bytes,
) -> UnauthenticatedFallbackCompletion {
    let task = spawn_connection_until_cancelled(async move {
        for record in &dest_records {
            if let Err(e) = write_all(&mut client_stream, record).await {
                log::debug!("REALITY FALLBACK: Error forwarding record: {}", e);
                let _ = futures::join!(client_stream.shutdown(), dest_stream.shutdown());
                return Ok(());
            }
            if let Err(e) = client_stream.flush().await {
                log::debug!("REALITY FALLBACK: Error flushing record: {}", e);
                let _ = futures::join!(client_stream.shutdown(), dest_stream.shutdown());
                return Ok(());
            }
        }

        if !remaining_data.is_empty()
            && let Err(e) = write_all(&mut client_stream, &remaining_data).await
        {
            log::debug!("REALITY FALLBACK: Error forwarding remaining data: {}", e);
            let _ = futures::join!(client_stream.shutdown(), dest_stream.shutdown());
            return Ok(());
        }

        log::debug!(
            "REALITY FALLBACK: Forwarded {} records + {} remaining bytes, starting bidirectional copy",
            dest_records.len(),
            remaining_data.len()
        );

        let result = crate::copy_bidirectional::copy_bidirectional(
            &mut *client_stream,
            &mut dest_stream,
            !remaining_data.is_empty(), // flush the client if we wrote remaining data
            false,
        )
        .await;

        let _ = futures::join!(client_stream.shutdown(), dest_stream.shutdown());

        if let Err(e) = result {
            log::debug!("REALITY FALLBACK: Connection ended with error: {}", e);
        }
        Ok(())
    });
    UnauthenticatedFallbackCompletion::new(task)
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use bytes::Bytes;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio_util::sync::CancellationToken;

    use super::start_forward_to_dest;
    use crate::async_stream::{AsyncPing, AsyncStream};
    use crate::dynamic::{ConnContext, scope_connection};

    struct TestDuplexStream(tokio::io::DuplexStream);

    impl AsyncRead for TestDuplexStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestDuplexStream {
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

    impl AsyncPing for TestDuplexStream {
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

    impl AsyncStream for TestDuplexStream {}

    #[tokio::test]
    async fn hard_stop_terminates_the_detached_reality_fallback() {
        let (client, _client_peer) = tokio::io::duplex(4096);
        let (destination, _destination_peer) = tokio::io::duplex(4096);
        let parent = CancellationToken::new();
        let conn = ConnContext::new_child(&parent);
        let weak = Arc::downgrade(&conn);

        let completion = scope_connection(Arc::clone(&conn), async move {
            start_forward_to_dest(
                Box::new(TestDuplexStream(client)),
                Box::new(TestDuplexStream(destination)),
                Vec::new(),
                Bytes::new(),
            )
        })
        .await;
        drop(conn);
        assert!(weak.upgrade().is_some());

        parent.cancel();
        let error = tokio::time::timeout(Duration::from_secs(1), completion.wait())
            .await
            .expect("hard stop must finish the detached fallback")
            .expect_err("hard stop must cancel the detached fallback");
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
        assert!(weak.upgrade().is_none());
    }
}
