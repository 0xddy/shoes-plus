use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream, AsyncTargetedMessageStream};
use crate::client_proxy_selector::ClientProxySelector;

/// Completion of an unauthenticated camouflage/fallback connection that was
/// handed to a background task.
///
/// Keeping this handle in [`TcpServerSetupResult`] lets the transport retain its
/// pre-authentication admission permit until the handed-off connection actually
/// ends. Tokio normally detaches a dropped [`JoinHandle`]; this wrapper instead
/// aborts on drop so hard-cancelling the transport cannot leave fallback work
/// running without its admission charge. Normal completion uses
/// [`wait`](Self::wait).
pub struct UnauthenticatedFallbackCompletion {
    task: Option<JoinHandle<std::io::Result<()>>>,
}

impl UnauthenticatedFallbackCompletion {
    pub fn new(task: JoinHandle<std::io::Result<()>>) -> Self {
        Self { task: Some(task) }
    }

    /// Wait for the background fallback, converting task cancellation or panic to
    /// an ordinary I/O error rather than propagating a Tokio join failure.
    pub async fn wait(mut self) -> std::io::Result<()> {
        // Poll through a mutable reference so `self` continues to own the handle
        // while this future is pending. If the waiter is cancelled, `Drop` can
        // still abort the fallback instead of accidentally detaching it.
        let result = self
            .task
            .as_mut()
            .expect("fallback completion can only be awaited once")
            .await;
        self.task.take();
        match result {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("unauthenticated fallback task was cancelled: {error}"),
            )),
            Err(error) => Err(std::io::Error::other(format!(
                "unauthenticated fallback task failed: {error}"
            ))),
        }
    }
}

impl Drop for UnauthenticatedFallbackCompletion {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            // A transport hard-cancel drops its setup future. Tokio normally
            // detaches a dropped JoinHandle, which would let the unauthenticated
            // fallback outlive both its gate permit and connection scope.
            task.abort();
        }
    }
}

/// One deferred-authentication handoff's terminal state as observed by the
/// accepting transport.
pub enum DeferredAuthenticationOutcome {
    /// The background protocol task authenticated a user and may now continue
    /// independently under that user's connection accounting.
    Authenticated,
    /// The background task ended before any request authenticated.
    Completed(std::io::Result<()>),
}

/// A cloneable edge-trigger for a protocol whose authentication happens after its
/// physical connection has been handed to a background task.
///
/// NaiveProxy HTTP/2 is the motivating case: Hyper owns the connection before the
/// first CONNECT request carries Basic credentials. A watch channel makes the edge
/// race-free even when that first request authenticates before the transport starts
/// waiting for it.
#[derive(Clone)]
pub struct DeferredAuthenticationSignal {
    authenticated: watch::Sender<bool>,
}

impl DeferredAuthenticationSignal {
    pub fn channel() -> (Self, watch::Receiver<bool>) {
        let (authenticated, receiver) = watch::channel(false);
        (Self { authenticated }, receiver)
    }

    pub fn complete(&self) {
        self.authenticated.send_replace(true);
    }
}

/// Completion of a background protocol task whose user authentication is deferred
/// until after the handler has returned.
///
/// Until [`wait`](Self::wait) observes authentication, dropping this value aborts
/// the task just like [`UnauthenticatedFallbackCompletion`]. Once authentication is
/// observed the join handle is deliberately detached: the task is then owned by the
/// connection cancellation tree and user accounting rather than the pre-auth gate.
pub struct DeferredAuthenticationCompletion {
    task: Option<JoinHandle<std::io::Result<()>>>,
    authenticated: watch::Receiver<bool>,
}

impl DeferredAuthenticationCompletion {
    pub fn new(
        task: JoinHandle<std::io::Result<()>>,
        authenticated: watch::Receiver<bool>,
    ) -> Self {
        Self {
            task: Some(task),
            authenticated,
        }
    }

    pub async fn wait(mut self) -> DeferredAuthenticationOutcome {
        enum Wake {
            Authenticated(Result<(), watch::error::RecvError>),
            Task(Result<std::io::Result<()>, tokio::task::JoinError>),
        }

        if *self.authenticated.borrow() {
            // Taking and dropping a JoinHandle detaches it. `self` no longer owns a
            // handle for Drop to abort, which is intentional after authentication.
            self.task.take();
            return DeferredAuthenticationOutcome::Authenticated;
        }

        let wake = {
            let task = self
                .task
                .as_mut()
                .expect("deferred authentication completion can only be awaited once");
            tokio::select! {
                biased;
                signal = self.authenticated.changed() => Wake::Authenticated(signal),
                result = task => Wake::Task(result),
            }
        };

        match wake {
            Wake::Authenticated(Ok(())) if *self.authenticated.borrow() => {
                self.task.take();
                DeferredAuthenticationOutcome::Authenticated
            }
            Wake::Authenticated(_) => {
                // Every sender disappeared without authenticating. The task owns
                // those senders, so wait for its concrete result rather than turn a
                // normal connection close into a synthetic channel error.
                let result = self
                    .task
                    .as_mut()
                    .expect("deferred task remains owned until it completes")
                    .await;
                self.task.take();
                DeferredAuthenticationOutcome::Completed(map_background_result(
                    result,
                    "deferred authentication task",
                ))
            }
            Wake::Task(result) => {
                self.task.take();
                DeferredAuthenticationOutcome::Completed(map_background_result(
                    result,
                    "deferred authentication task",
                ))
            }
        }
    }
}

impl Drop for DeferredAuthenticationCompletion {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn map_background_result(
    result: Result<std::io::Result<()>, tokio::task::JoinError>,
    task_name: &str,
) -> std::io::Result<()> {
    match result {
        Ok(result) => result,
        Err(error) if error.is_cancelled() => Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            format!("{task_name} was cancelled: {error}"),
        )),
        Err(error) => Err(std::io::Error::other(format!(
            "{task_name} failed: {error}"
        ))),
    }
}

pub enum TcpServerSetupResult {
    TcpForward {
        remote_location: NetLocation,
        stream: Box<dyn AsyncStream>,
        need_initial_flush: bool,
        /// Response normally written after the remote connection succeeds. A caller
        /// that needs application-protocol sniffing must send and flush it first,
        /// because response-gated clients cannot provide sniffable bytes otherwise.
        connection_success_response: Option<Box<[u8]>>,
        /// Initial data to send to the remote location
        initial_remote_data: Option<Box<[u8]>>,
        /// The proxy selector to use for routing this connection
        proxy_selector: Arc<ClientProxySelector>,
    },
    BidirectionalUdp {
        need_initial_flush: bool,
        remote_location: NetLocation,
        stream: Box<dyn AsyncMessageStream>,
        /// The proxy selector to use for routing this connection
        proxy_selector: Arc<ClientProxySelector>,
    },
    MultiDirectionalUdp {
        need_initial_flush: bool,
        stream: Box<dyn AsyncTargetedMessageStream>,
        /// The proxy selector to use for routing this connection
        proxy_selector: Arc<ClientProxySelector>,
    },
    SessionBasedUdp {
        need_initial_flush: bool,
        stream: Box<dyn crate::async_stream::AsyncSessionMessageStream>,
        /// The proxy selector to use for routing this connection
        proxy_selector: Arc<ClientProxySelector>,
    },
    /// Connection has been fully handled (e.g., spawned as a background task).
    /// No further processing needed by the caller.
    AlreadyHandled,
    /// The stream was handed to a probing-resistance or camouflage fallback after
    /// proxy authentication failed (or before deferred authentication completed).
    ///
    /// Transport callers must stop processing this stream, but must not count it as
    /// a successful proxy handshake for a multiplexed connection-wide auth gate.
    UnauthenticatedFallbackHandled(UnauthenticatedFallbackCompletion),
    /// A background protocol connection is live, but authentication will happen on
    /// its first logical request. The transport must keep the pre-auth permit until
    /// that signal arrives, then detach the background task without aborting it.
    DeferredAuthenticationHandled(DeferredAuthenticationCompletion),
}

impl TcpServerSetupResult {
    pub(crate) fn is_already_handled(&self) -> bool {
        matches!(
            self,
            Self::AlreadyHandled
                | Self::UnauthenticatedFallbackHandled(_)
                | Self::DeferredAuthenticationHandled(_)
        )
    }

    pub fn set_need_initial_flush(&mut self, need_initial_flush: bool) {
        match self {
            TcpServerSetupResult::TcpForward {
                need_initial_flush: flush,
                ..
            }
            | TcpServerSetupResult::BidirectionalUdp {
                need_initial_flush: flush,
                ..
            }
            | TcpServerSetupResult::MultiDirectionalUdp {
                need_initial_flush: flush,
                ..
            }
            | TcpServerSetupResult::SessionBasedUdp {
                need_initial_flush: flush,
                ..
            } => {
                *flush = need_initial_flush;
            }
            TcpServerSetupResult::AlreadyHandled
            | TcpServerSetupResult::UnauthenticatedFallbackHandled(_)
            | TcpServerSetupResult::DeferredAuthenticationHandled(_) => {}
        }
    }
}

#[async_trait]
pub trait TcpServerHandler: Send + Sync + Debug {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult>;
}

pub struct TcpClientSetupResult {
    pub client_stream: Box<dyn AsyncStream>,
    /// Early application data that was buffered during protocol handshake.
    /// Only expected from the final destination - intermediate hops should not
    /// return early data (all proxy protocols are client-initiated).
    pub early_data: Option<Vec<u8>>,
}

#[async_trait]
pub trait TcpClientHandler: Send + Sync + Debug {
    /// Setup a client connection through this proxy.
    ///
    /// # Arguments
    /// * `client_stream` - The transport stream to the proxy server
    /// * `remote_location` - The destination to connect to through the proxy.
    ///                       May include pre-resolved address to avoid duplicate DNS lookups.
    ///
    /// # Returns
    /// * `client_stream` - The wrapped stream ready for application data
    /// * `early_data` - Any application data received during handshake (from final destination)
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult>;

    /// Whether this handler returns a connection whose protocol request is
    /// conceptually performed by the first application write in sing-box.
    ///
    /// Shoes performs these handshakes eagerly.  The marker lets URLTest place
    /// its latency boundary at the equivalent point without delaying ordinary
    /// connection setup.
    fn needs_handshake_for_write(&self) -> bool {
        false
    }

    /// Returns true if this handler supports UDP-over-TCP tunneling.
    fn supports_udp_over_tcp(&self) -> bool {
        false
    }

    /// Returns true when this protocol carries UDP as native datagrams to the
    /// proxy server instead of tunnelling messages over a byte stream.
    fn supports_native_udp(&self) -> bool {
        false
    }

    /// Setup a bidirectional UDP message stream over a TCP connection.
    /// Only called if `supports_udp_over_tcp()` returns true.
    ///
    /// # Arguments
    /// * `client_stream` - The transport stream to the proxy server
    /// * `target` - The destination for UDP packets.
    ///              May include pre-resolved address to avoid duplicate DNS lookups.
    ///
    /// # Returns
    /// A message stream for sending/receiving UDP packets to the target.
    async fn setup_client_udp_bidirectional(
        &self,
        _client_stream: Box<dyn AsyncStream>,
        _target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "UDP-over-TCP not supported by this protocol",
        ))
    }

    /// Wrap a native UDP socket connected to the proxy server.
    ///
    /// Protocols such as Shadowsocks SIP003 encrypt each datagram independently,
    /// so forcing them through `setup_client_udp_bidirectional` would incorrectly
    /// turn native UDP into UDP-over-TCP.
    async fn setup_client_native_udp(
        &self,
        _client_stream: Box<dyn AsyncMessageStream>,
        _target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "native UDP not supported by this protocol",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DeferredAuthenticationCompletion, DeferredAuthenticationOutcome,
        DeferredAuthenticationSignal, UnauthenticatedFallbackCompletion,
    };

    #[tokio::test]
    async fn fallback_task_panic_becomes_an_io_error() {
        let completion = UnauthenticatedFallbackCompletion::new(tokio::spawn(async move {
            panic!("injected fallback panic");
            #[allow(unreachable_code)]
            Ok(())
        }));

        let error = completion
            .wait()
            .await
            .expect_err("join failure must not escape as a panic");
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert!(error.to_string().contains("fallback task failed"));
    }

    #[tokio::test]
    async fn deferred_authentication_detaches_live_work_only_after_the_signal() {
        let (signal, receiver) = DeferredAuthenticationSignal::channel();
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let completion = DeferredAuthenticationCompletion::new(
            tokio::spawn(async move {
                finish_rx.await.map_err(std::io::Error::other)?;
                let _ = done_tx.send(());
                Ok(())
            }),
            receiver,
        );

        signal.complete();
        assert!(matches!(
            completion.wait().await,
            DeferredAuthenticationOutcome::Authenticated
        ));

        finish_tx
            .send(())
            .expect("the authenticated background task remains live");
        tokio::time::timeout(std::time::Duration::from_secs(1), done_rx)
            .await
            .expect("the detached task must still run")
            .expect("the detached task must report completion");
    }

    #[tokio::test]
    async fn deferred_task_end_before_authentication_is_reported() {
        let (_signal, receiver) = DeferredAuthenticationSignal::channel();
        let completion = DeferredAuthenticationCompletion::new(
            tokio::spawn(async { Err(std::io::Error::other("ended before auth")) }),
            receiver,
        );

        match completion.wait().await {
            DeferredAuthenticationOutcome::Completed(Err(error)) => {
                assert!(error.to_string().contains("ended before auth"));
            }
            _ => panic!("task completion must not be mistaken for authentication"),
        }
    }
}
