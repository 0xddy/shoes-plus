//! Fail local socket operations after a normal loopback handshake. No malformed
//! packets or traffic outside the loopback interface are generated.

use super::*;
use crate::runtime::Runtime as _;
use crate::{AsyncUdpSocket, UdpPoller};
use std::{future::poll_fn, io::IoSliceMut, pin::Pin};

#[derive(Debug)]
struct FailingSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    // 1 fails try_send, 2 fails poll_writable; each fault fires only once.
    fault: AtomicUsize,
    failures: AtomicUsize,
}

impl FailingSocket {
    fn fail(&self, operation: usize) -> io::Result<()> {
        if self
            .fault
            .compare_exchange(operation, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.failures.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected local UDP failure",
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct FailingPoller {
    socket: Arc<FailingSocket>,
    inner: Pin<Box<dyn UdpPoller>>,
}

impl UdpPoller for FailingPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.socket.fail(2)?;
        self.inner.as_mut().poll_writable(cx)
    }
}

impl AsyncUdpSocket for FailingSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(FailingPoller {
            inner: self.inner.clone().create_io_poller(),
            socket: self,
        })
    }
    fn try_send(&self, transmit: &crate::udp::Transmit) -> io::Result<()> {
        self.fail(1)?;
        self.inner.try_send(transmit)
    }
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [crate::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

fn assert_local_io_error(error: &crate::ConnectionError) {
    let crate::ConnectionError::TransportError(error) = error else {
        panic!("unexpected error: {error:?}");
    };
    assert_eq!(error.code, proto::TransportErrorCode::INTERNAL_ERROR);
    assert!(error.reason.contains("local UDP"), "{error}");
    assert!(error.reason.contains("PermissionDenied"), "{error}");
    assert!(
        error.reason.contains("injected local UDP failure"),
        "{error}"
    );
}

async fn run_fault(operation: usize, close_first: bool) {
    let factory = EndpointFactory::new();
    let server_endpoint = factory.endpoint();
    let socket = Arc::new(FailingSocket {
        inner: TokioRuntime
            .wrap_udp_socket(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
            .unwrap(),
        fault: AtomicUsize::new(0),
        failures: AtomicUsize::new(0),
    });
    let mut client_endpoint = Endpoint::new_with_abstract_socket(
        Default::default(),
        None,
        socket.clone(),
        Arc::new(TokioRuntime),
    )
    .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(factory.cert.cert.der().clone()).unwrap();
    let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    let mut transport = TransportConfig::default();
    transport.send_window(1);
    client_config.transport_config(Arc::new(transport));
    client_endpoint.set_default_client_config(client_config);

    let client_connecting = client_endpoint
        .connect(server_endpoint.local_addr().unwrap(), "localhost")
        .unwrap();
    let (client, server) = timeout(Duration::from_secs(2), async {
        tokio::join!(client_connecting, async {
            server_endpoint.accept().await.unwrap().await
        })
    })
    .await
    .unwrap();
    let client = client.unwrap();
    let server = server.unwrap();
    let (mut send, mut recv) = client.open_bi().await.unwrap();
    send.write_all(b"x").await.unwrap();

    // This current-thread test does not yield to the driver between buffering
    // one byte and registering all waiters, so the local send window stays full.
    let mut buffer = [0; 1];
    {
        let mut read = Box::pin(recv.read(&mut buffer));
        let mut write = Box::pin(send.write(b"y"));
        let mut closed = Box::pin(client.closed());
        poll_fn(|cx| {
            assert!(read.as_mut().poll(cx).is_pending());
            assert!(write.as_mut().poll(cx).is_pending());
            assert!(closed.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        socket.fault.store(operation, Ordering::SeqCst);
        if close_first {
            client.close(42u32.into(), b"existing application closure");
            timeout(Duration::from_secs(1), async {
                while socket.failures.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the driver must encounter the armed socket fault");
        }
        let (read, write, closed) = timeout(Duration::from_secs(1), async {
            tokio::join!(read, write, closed)
        })
        .await
        .expect("fatal socket failure must wake every connection waiter");
        let assert_reason = |error: &crate::ConnectionError| {
            if close_first {
                assert!(
                    matches!(error, crate::ConnectionError::LocallyClosed),
                    "{error:?}"
                );
            } else {
                assert_local_io_error(error);
            }
        };
        assert_reason(&closed);
        match read {
            Err(crate::ReadError::ConnectionLost(error)) => assert_reason(&error),
            other => panic!("read result: {other:?}"),
        }
        match write {
            Err(crate::WriteError::ConnectionLost(error)) => assert_reason(&error),
            other => panic!("write result: {other:?}"),
        }
        assert_reason(&client.close_reason().unwrap());
    }
    assert_eq!(socket.failures.load(Ordering::SeqCst), 1);
    timeout(Duration::from_secs(1), client_endpoint.wait_idle())
        .await
        .expect("endpoint must release a failed connection while application handles remain alive");
    assert_eq!(client_endpoint.open_connections(), 0);

    // Reuse the same endpoint/socket after the one-shot failure. Releasing the
    // old handles must not send a duplicate Drained event for a reused slab ID.
    let reconnecting = client_endpoint
        .connect(server_endpoint.local_addr().unwrap(), "localhost")
        .unwrap();
    let (fresh, fresh_peer) = timeout(Duration::from_secs(2), async {
        tokio::join!(reconnecting, async {
            server_endpoint.accept().await.unwrap().await
        })
    })
    .await
    .unwrap();
    let fresh = fresh.unwrap();
    let fresh_peer = fresh_peer.unwrap();
    drop(send);
    drop(recv);
    drop(client);
    tokio::task::yield_now().await;
    assert_eq!(client_endpoint.open_connections(), 1);
    assert!(fresh.close_reason().is_none());
    fresh.close(0u32.into(), b"test complete");
    fresh_peer.close(0u32.into(), b"test complete");
    server.close(0u32.into(), b"test complete");
    client_endpoint.close(0u32.into(), b"test complete");
    server_endpoint.close(0u32.into(), b"test complete");
}

#[tokio::test]
async fn fatal_udp_send_error_wakes_waiters_and_releases_endpoint() {
    run_fault(1, false).await;
}

#[tokio::test]
async fn fatal_udp_writable_error_wakes_waiters_and_releases_endpoint() {
    run_fault(2, false).await;
}

#[tokio::test]
async fn fatal_udp_error_preserves_existing_close_reason() {
    run_fault(1, true).await;
}
