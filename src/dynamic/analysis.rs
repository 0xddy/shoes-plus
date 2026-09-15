//! Optional, payload-level analytics hooks. No transport, aggregation or storage
//! policy belongs in the proxy core. The observer is sampled once per routed flow.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use arc_swap::ArcSwapOption;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::address::NetLocation;
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};
use crate::routing::protocol::SniffedTcpMetadata;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AnalysisTarget {
    pub host: String,
    pub port: u16,
}

impl From<&NetLocation> for AnalysisTarget {
    fn from(value: &NetLocation) -> Self {
        Self {
            host: value.address().to_string(),
            port: value.port(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AnalysisMetadata {
    pub generation: u64,
    pub inbound_tag: String,
    pub user_id: String,
    pub network: &'static str,
    /// Only an actually sniffed hostname; the destination hostname is separate.
    pub domain: Option<String>,
    pub app_protocol: Option<&'static str>,
    pub destination: Option<AnalysisTarget>,
    pub sniff_destination: Option<AnalysisTarget>,
}

pub trait AnalysisObserver: Send + Sync {
    fn enabled(&self) -> bool {
        true
    }
    fn generation(&self) -> u64 {
        u64::from(self.enabled())
    }
    fn register(&self, metadata: AnalysisMetadata) -> Option<Arc<dyn AnalysisFlow>>;
}

pub trait AnalysisFlow: Send + Sync {
    /// Capture the active collection generation before starting an I/O operation.
    /// Zero means inactive. Tokens must be finished or cancelled exactly once.
    fn begin(&self) -> u64;
    fn finish(&self, token: u64, upload: u64, download: u64, target: Option<&AnalysisTarget>);
    /// The wrapper has a terminal Web result for this exact target. Even if
    /// detail storage is full, the observer can retain user/unknown totals.
    fn finish_web(&self, token: u64, upload: u64, download: u64, target: Option<&AnalysisTarget>) {
        self.finish(token, upload, download, target);
    }
    fn cancel(&self, token: u64);
    fn close(&self);
    /// True only when this generation accepts the classification, including
    /// Web traffic whose detail entry overflows. False fences stale I/O results.
    fn classify_target(
        &self,
        _token: u64,
        _target: &AnalysisTarget,
        _domain: Option<&str>,
        _app_protocol: &str,
    ) -> bool {
        true
    }
    /// Stop an unclassified target in this generation without retaining a
    /// tombstone. Its wrapper will issue no further analysis callbacks.
    fn discard_target(&self, _token: u64, _target: &AnalysisTarget) {}
    fn try_reserve_sniff(&self, _bytes: usize) -> bool {
        true
    }
    fn release_sniff(&self, _bytes: usize) {}
    /// Reserve wrapper storage for an already registered flow. Unlike temporary
    /// sniff reservations, a paused flow remains eligible so new UDP targets can
    /// participate after the control session resumes.
    fn try_reserve_storage(&self, _bytes: usize) -> bool {
        true
    }
    fn release_storage(&self, _bytes: usize) {}
    fn try_reserve_pending_storage(&self, bytes: usize) -> bool {
        self.try_reserve_storage(bytes)
    }
    fn release_pending_storage(&self, bytes: usize) {
        self.release_storage(bytes);
    }
    /// Move existing wrapper storage out of the pending sub-budget without
    /// releasing its actual memory reservation.
    fn promote_pending_storage(&self, _bytes: usize) {}
}

struct ObserverHolder(Arc<dyn AnalysisObserver>);

/// One pointer shared by every user/listener in an engine. Replacing it affects
/// new flows only; an observer owns the generation fence for its existing flows.
#[derive(Default)]
pub struct AnalysisSlot(ArcSwapOption<ObserverHolder>);

impl AnalysisSlot {
    pub fn set(&self, observer: Option<Arc<dyn AnalysisObserver>>) {
        self.0
            .store(observer.map(|observer| Arc::new(ObserverHolder(observer))));
    }
}

pub struct AnalysisUserContext {
    pub slot: Arc<AnalysisSlot>,
    pub inbound_tag: String,
}

impl AnalysisUserContext {
    fn register(
        &self,
        user_id: &str,
        network: &'static str,
        destination: Option<&NetLocation>,
        sniffed: Option<&SniffedTcpMetadata>,
        expected_generation: Option<u64>,
    ) -> Option<Arc<FlowHandle>> {
        let observer = self.slot.0.load();
        let observer = observer.as_ref()?;
        if !observer.0.enabled() {
            return None;
        }
        let generation = observer.0.generation();
        if generation == 0 || expected_generation.is_some_and(|expected| expected != generation) {
            return None;
        }
        let target = destination.map(AnalysisTarget::from);
        let metadata = AnalysisMetadata {
            generation,
            inbound_tag: self.inbound_tag.clone(),
            user_id: user_id.to_owned(),
            network,
            domain: sniffed.and_then(|metadata| metadata.analysis_domain.clone()),
            app_protocol: sniffed.map(|metadata| match metadata.protocol {
                crate::routing::predicate::RouteProtocol::Http => "http",
                crate::routing::predicate::RouteProtocol::Tls => "tls",
            }),
            sniff_destination: sniffed.and(target.clone()),
            destination: target,
        };
        observer
            .0
            .register(metadata)
            .map(|flow| Arc::new(FlowHandle(flow)))
    }
}

pub(crate) struct FlowHandle(Arc<dyn AnalysisFlow>);
impl Drop for FlowHandle {
    fn drop(&mut self) {
        self.0.close();
    }
}

fn current_user() -> Option<Arc<super::UserContext>> {
    super::current_connection().and_then(|connection| connection.user().cloned())
}

pub(crate) fn wrap_tcp(
    stream: Box<dyn AsyncStream>,
    destination: &NetLocation,
    sniffed: Option<&SniffedTcpMetadata>,
    initial_download: usize,
) -> Box<dyn AsyncStream> {
    let flow = current_user().and_then(|user| {
        user.analysis_context()?
            .register(user.id(), "tcp", Some(destination), sniffed, None)
    });
    match flow {
        Some(flow) => match AnalysisStream::try_new(stream, flow, None) {
            Ok(stream) => {
                if initial_download != 0 {
                    let token = stream.flow.0.begin();
                    stream
                        .flow
                        .0
                        .finish(token, 0, initial_download as u64, None);
                }
                Box::new(stream)
            }
            Err(stream) => stream,
        },
        None => stream,
    }
}

/// A UDP association retains its eligibility when created. Enabling collection
/// later cannot retrospectively register this association. Its first allowed
/// target registers it, and all target workers share the resulting flow.
pub(crate) struct UdpAnalysis {
    user: Option<Arc<super::UserContext>>,
    generation: u64,
    targets: Arc<std::sync::atomic::AtomicUsize>,
    flow: OnceLock<Option<Arc<FlowHandle>>>,
}

tokio::task_local! {
    static UDP_ANALYSIS: Arc<UdpAnalysis>;
}

pub(crate) fn current_udp() -> Option<Arc<UdpAnalysis>> {
    UDP_ANALYSIS.try_with(Arc::clone).ok()
}

pub(crate) async fn scope_udp<F: std::future::Future>(
    analysis: Option<Arc<UdpAnalysis>>,
    work: F,
) -> F::Output {
    match analysis {
        Some(analysis) => UDP_ANALYSIS.scope(analysis, work).await,
        None => work.await,
    }
}

pub(crate) fn wrap_udp(
    stream: Box<dyn AsyncMessageStream>,
    destination: &NetLocation,
) -> Box<dyn AsyncMessageStream> {
    match current_udp() {
        Some(analysis) => analysis.wrap(stream, destination),
        None => stream,
    }
}

impl UdpAnalysis {
    pub(crate) fn new() -> Arc<Self> {
        Self::for_user(current_user())
    }

    pub(crate) fn for_user(user: Option<Arc<super::UserContext>>) -> Arc<Self> {
        let generation = user
            .as_ref()
            .and_then(|user| user.analysis_context())
            .and_then(|context| {
                context.slot.0.load().as_ref().map(|observer| {
                    if observer.0.enabled() {
                        observer.0.generation()
                    } else {
                        0
                    }
                })
            })
            .unwrap_or(0);
        Arc::new(Self {
            user,
            generation,
            targets: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            flow: OnceLock::new(),
        })
    }

    pub(crate) fn wrap(
        &self,
        stream: Box<dyn AsyncMessageStream>,
        destination: &NetLocation,
    ) -> Box<dyn AsyncMessageStream> {
        let flow = self.flow.get_or_init(|| {
            if self.generation == 0 {
                return None;
            }
            let user = self.user.as_ref()?;
            let context = user.analysis_context()?;
            let observer = context.slot.0.load();
            if observer.as_ref()?.0.generation() != self.generation {
                return None;
            }
            context.register(user.id(), "udp", None, None, Some(self.generation))
        });
        match flow {
            Some(flow) => {
                if self
                    .targets
                    .fetch_update(
                        std::sync::atomic::Ordering::Relaxed,
                        std::sync::atomic::Ordering::Relaxed,
                        |count| (count < 64).then_some(count + 1),
                    )
                    .is_err()
                {
                    return stream;
                }
                let slot = SniffSlot(self.targets.clone());
                match AnalysisStream::try_new(stream, flow.clone(), Some(destination)) {
                    Ok(mut stream) => {
                        stream.sniff_slot = Some(slot);
                        Box::new(stream)
                    }
                    Err(stream) => stream,
                }
            }
            None => stream,
        }
    }
}

/// Wrap the already decoded outbound side. This naturally covers vectored TCP
/// writes and all protocol-specific datagram batching without counting framing.
struct AnalysisStream<T> {
    inner: T,
    flow: Arc<FlowHandle>,
    target: Option<AnalysisTarget>,
    read_token: Option<u64>,
    write_token: Option<u64>,
    sniff: Option<(
        crate::routing::udp_sniff::UdpSniffer,
        Pin<Box<tokio::time::Sleep>>,
    )>,
    sniff_started: bool,
    sniff_epoch: u64,
    sniff_slot: Option<SniffSlot>,
    excluded: bool,
    web: bool,
    _storage: StorageReservation,
}

struct StorageReservation {
    flow: Arc<dyn AnalysisFlow>,
    bytes: usize,
    pending: bool,
}

impl Drop for StorageReservation {
    fn drop(&mut self) {
        if self.pending {
            self.flow.release_pending_storage(self.bytes);
        } else {
            self.flow.release_storage(self.bytes);
        }
    }
}

struct SniffSlot(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for SniffSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl<T> AnalysisStream<T> {
    fn try_new(
        inner: T,
        flow: Arc<FlowHandle>,
        destination: Option<&NetLocation>,
    ) -> Result<Self, T> {
        let host_bytes = destination.map_or(0, |target| match target.address() {
            crate::address::Address::Hostname(host) => host.len(),
            _ => 45, // Longest textual IPv6 address, including an IPv4 suffix.
        });
        // The wrapper contains the inline sniffer. Reserve its optional timer
        // too, plus room for allocator rounding and Display's String capacity.
        // This remains a one-time operation for each target, never per packet.
        let bytes = std::mem::size_of::<Self>()
            .saturating_add(std::mem::size_of::<tokio::time::Sleep>())
            .saturating_add(512)
            .saturating_add(host_bytes.saturating_mul(2));
        let pending = destination.is_some();
        if !(if pending {
            flow.0.try_reserve_pending_storage(bytes)
        } else {
            flow.0.try_reserve_storage(bytes)
        }) {
            return Err(inner);
        }
        let storage = StorageReservation {
            flow: flow.0.clone(),
            bytes,
            pending,
        };
        Ok(Self {
            inner,
            flow,
            target: destination.map(AnalysisTarget::from),
            read_token: None,
            write_token: None,
            sniff: None,
            sniff_started: false,
            sniff_epoch: 0,
            sniff_slot: None,
            excluded: false,
            web: false,
            _storage: storage,
        })
    }
    fn read_begin(&mut self) {
        if !self.excluded && self.read_token.is_none() {
            self.read_token = Some(self.flow.0.begin());
        }
    }
    fn write_begin(&mut self) {
        if !self.excluded && self.write_token.is_none() {
            self.write_token = Some(self.flow.0.begin());
        }
    }
    fn read_done(&mut self, count: u64) {
        if let Some(token) = self.read_token.take() {
            if self.web {
                self.flow
                    .0
                    .finish_web(token, 0, count, self.target.as_ref());
            } else {
                self.flow.0.finish(token, 0, count, self.target.as_ref());
            }
        }
    }
    fn write_done(&mut self, count: u64) {
        if let Some(token) = self.write_token.take() {
            if self.web {
                self.flow
                    .0
                    .finish_web(token, count, 0, self.target.as_ref());
            } else {
                self.flow.0.finish(token, count, 0, self.target.as_ref());
            }
        }
    }
    fn sniff_expiry(&mut self, cx: &mut Context<'_>) {
        use std::future::Future;
        if self
            .sniff
            .as_mut()
            .is_some_and(|(sniff, timer)| sniff.expired() || timer.as_mut().poll(cx).is_ready())
        {
            self.exclude_target();
        }
    }
    fn exclude_target(&mut self) {
        self.excluded = true;
        self.sniff = None;
        self.sniff_slot = None;
        if let Some(target) = &self.target {
            self.flow.0.discard_target(self.sniff_epoch, target);
        }
        if let Some(token) = self.read_token.take() {
            self.flow.0.cancel(token);
        }
        if let Some(token) = self.write_token.take() {
            self.flow.0.cancel(token);
        }
        // The small wrapper remains alive around the business stream, so its
        // storage reservation remains charged until Drop.
    }
    fn sniff_packet(&mut self, bytes: &[u8]) {
        let token = self.write_token.unwrap_or(0);
        if token == 0 {
            return;
        }
        if !self.sniff_started {
            self.sniff_started = true;
            self.sniff_epoch = token;
            self.sniff = Some((
                crate::routing::udp_sniff::UdpSniffer::new(self.flow.0.clone()),
                Box::pin(tokio::time::sleep(std::time::Duration::from_millis(300))),
            ));
        }
        if self.sniff.is_some() && token != self.sniff_epoch {
            self.exclude_target();
            return;
        }
        if let Some((sniff, _)) = &mut self.sniff {
            if let Some((protocol, domain)) = sniff.observe(bytes) {
                self.apply_classification(token, protocol, domain.as_deref());
                return;
            }
            if sniff.expired() {
                self.exclude_target();
            }
        }
    }

    fn apply_classification(&mut self, token: u64, protocol: &str, domain: Option<&str>) {
        let accepted = self
            .target
            .as_ref()
            .is_some_and(|target| self.flow.0.classify_target(token, target, domain, protocol));
        if accepted && matches!(protocol, "http" | "tls" | "quic") {
            self.web = true;
            self.sniff = None;
            self.sniff_slot = None;
            if self._storage.pending {
                self._storage
                    .flow
                    .promote_pending_storage(self._storage.bytes);
                self._storage.pending = false;
            }
        } else {
            self.exclude_target();
        }
    }
}

impl<T> Drop for AnalysisStream<T> {
    fn drop(&mut self) {
        if let Some(token) = self.read_token.take() {
            self.flow.0.cancel(token);
        }
        if let Some(token) = self.write_token.take() {
            self.flow.0.cancel(token);
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for AnalysisStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.read_begin();
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if result.is_ready() {
            self.read_done((buf.filled().len() - before) as u64);
        }
        result
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for AnalysisStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_begin();
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(ref result) = result {
            self.write_done(result.as_ref().copied().unwrap_or(0) as u64);
        }
        result
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.write_begin();
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(ref result) = result {
            self.write_done(result.as_ref().copied().unwrap_or(0) as u64);
        }
        result
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
impl<T: AsyncPing + Unpin> AsyncPing for AnalysisStream<T> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }
    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}
impl<T: AsyncStream> AsyncStream for AnalysisStream<T> {}
impl<T: AsyncReadMessage + Unpin> AsyncReadMessage for AnalysisStream<T> {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.sniff_expiry(cx);
        self.read_begin();
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read_message(cx, buf);
        if result.is_ready() {
            self.read_done((buf.filled().len() - before) as u64);
        }
        result
    }
}
impl<T: AsyncWriteMessage + Unpin> AsyncWriteMessage for AnalysisStream<T> {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<()>> {
        self.sniff_expiry(cx);
        self.write_begin();
        let result = Pin::new(&mut self.inner).poll_write_message(cx, buf);
        if let Poll::Ready(ref result) = result {
            if result.is_ok() {
                self.sniff_packet(buf);
            }
            self.write_done(if result.is_ok() { buf.len() as u64 } else { 0 });
        }
        result
    }
}
impl<T: AsyncFlushMessage + Unpin> AsyncFlushMessage for AnalysisStream<T> {
    fn poll_flush_message(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush_message(cx)
    }
}
impl<T: AsyncShutdownMessage + Unpin> AsyncShutdownMessage for AnalysisStream<T> {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown_message(cx)
    }
}
impl<T: AsyncMessageStream> AsyncMessageStream for AnalysisStream<T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Default)]
    struct BudgetFlow {
        allowed: AtomicBool,
        reserved: AtomicUsize,
        releases: AtomicUsize,
        cancelled: AtomicUsize,
        closed: AtomicUsize,
        begins: AtomicUsize,
        discarded: AtomicUsize,
        epoch: AtomicUsize,
    }

    impl AnalysisFlow for BudgetFlow {
        fn begin(&self) -> u64 {
            self.begins.fetch_add(1, Ordering::Relaxed);
            self.epoch.load(Ordering::Relaxed).max(1) as u64
        }
        fn finish(&self, _: u64, _: u64, _: u64, _: Option<&AnalysisTarget>) {}
        fn cancel(&self, _: u64) {
            self.cancelled.fetch_add(1, Ordering::Relaxed);
        }
        fn close(&self) {
            self.closed.fetch_add(1, Ordering::Relaxed);
        }
        fn discard_target(&self, _: u64, _: &AnalysisTarget) {
            self.discarded.fetch_add(1, Ordering::Relaxed);
        }
        fn classify_target(
            &self,
            token: u64,
            _: &AnalysisTarget,
            _: Option<&str>,
            _: &str,
        ) -> bool {
            token == self.epoch.load(Ordering::Relaxed).max(1) as u64
        }
        fn try_reserve_storage(&self, bytes: usize) -> bool {
            if !self.allowed.load(Ordering::Relaxed) {
                return false;
            }
            self.reserved.fetch_add(bytes, Ordering::Relaxed);
            true
        }
        fn release_storage(&self, bytes: usize) {
            self.reserved.fetch_sub(bytes, Ordering::Relaxed);
            self.releases.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn storage_lease_is_released_once_with_a_pending_read() {
        let budget = Arc::new(BudgetFlow::default());
        budget.allowed.store(true, Ordering::Relaxed);
        let (inner, _peer) = tokio::io::duplex(64);
        let mut stream =
            match AnalysisStream::try_new(inner, Arc::new(FlowHandle(budget.clone())), None) {
                Ok(stream) => stream,
                Err(_) => panic!("available budget should reserve wrapper storage"),
            };
        assert!(budget.reserved.load(Ordering::Relaxed) > 0);
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut bytes = [0; 16];
        assert!(
            Pin::new(&mut stream)
                .poll_read(&mut cx, &mut ReadBuf::new(&mut bytes))
                .is_pending()
        );
        drop(stream);
        assert_eq!(budget.reserved.load(Ordering::Relaxed), 0);
        assert_eq!(budget.releases.load(Ordering::Relaxed), 1);
        assert_eq!(budget.cancelled.load(Ordering::Relaxed), 1);
        assert_eq!(budget.closed.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn refusing_tcp_storage_keeps_the_original_stream_usable() {
        let budget = Arc::new(BudgetFlow::default());
        let (inner, mut peer) = tokio::io::duplex(64);
        let mut stream =
            match AnalysisStream::try_new(inner, Arc::new(FlowHandle(budget.clone())), None) {
                Err(stream) => stream,
                Ok(_) => panic!("exhausted budget must decline the wrapper"),
            };
        stream.write_all(b"upload").await.unwrap();
        let mut upload = [0; 6];
        peer.read_exact(&mut upload).await.unwrap();
        assert_eq!(&upload, b"upload");
        peer.write_all(b"reply").await.unwrap();
        let mut reply = [0; 5];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        assert_eq!(budget.reserved.load(Ordering::Relaxed), 0);
        assert_eq!(budget.releases.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn refusing_udp_target_storage_preserves_datagram_forwarding() {
        let budget = Arc::new(BudgetFlow::default());
        let analysis = UdpAnalysis {
            user: None,
            generation: 1,
            targets: Arc::new(AtomicUsize::new(0)),
            flow: OnceLock::from(Some(Arc::new(FlowHandle(budget.clone())))),
        };
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let inner = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        inner.connect(peer.local_addr().unwrap()).await.unwrap();
        let destination =
            NetLocation::from_str(&peer.local_addr().unwrap().to_string(), None).unwrap();
        let mut stream = analysis.wrap(Box::new(inner), &destination);
        futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, b"datagram"))
            .await
            .unwrap();
        let mut received = [0; 32];
        let (count, sender) = peer.recv_from(&mut received).await.unwrap();
        assert_eq!(&received[..count], b"datagram");
        peer.send_to(b"reply", sender).await.unwrap();
        let mut reply = ReadBuf::new(&mut received);
        futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut reply))
            .await
            .unwrap();
        assert_eq!(reply.filled(), b"reply");
        drop(stream);
        drop(analysis);
        assert_eq!(budget.reserved.load(Ordering::Relaxed), 0);
        assert_eq!(budget.releases.load(Ordering::Relaxed), 0);
        assert_eq!(budget.closed.load(Ordering::Relaxed), 1);
    }
    #[tokio::test]
    async fn terminal_non_web_wrappers_stop_callbacks_and_return_sniff_slots() {
        let budget = Arc::new(BudgetFlow::default());
        budget.allowed.store(true, Ordering::Relaxed);
        let analysis = UdpAnalysis {
            user: None,
            generation: 1,
            targets: Arc::new(AtomicUsize::new(0)),
            flow: OnceLock::from(Some(Arc::new(FlowHandle(budget.clone())))),
        };
        let mut question = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        question.extend_from_slice(b"\x03www\x07youtube\x03com\x00\x00\x01\x00\x01");
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination =
            NetLocation::from_str(&peer.local_addr().unwrap().to_string(), None).unwrap();
        let mut streams = Vec::new();
        // More than the old lifetime 64-target cap, while every rejected
        // wrapper remains alive and its actual storage remains reserved.
        for _ in 0..80 {
            let inner = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            inner.connect(peer.local_addr().unwrap()).await.unwrap();
            let mut stream = analysis.wrap(Box::new(inner), &destination);
            for _ in 0..2 {
                futures::future::poll_fn(|cx| {
                    Pin::new(&mut stream).poll_write_message(cx, &question)
                })
                .await
                .unwrap();
                let mut received = [0; 512];
                let (count, sender) = peer.recv_from(&mut received).await.unwrap();
                assert_eq!(&received[..count], question);
                peer.send_to(b"reply", sender).await.unwrap();
                let mut reply = ReadBuf::new(&mut received);
                futures::future::poll_fn(|cx| {
                    Pin::new(&mut stream).poll_read_message(cx, &mut reply)
                })
                .await
                .unwrap();
                assert_eq!(reply.filled(), b"reply");
            }
            assert_eq!(analysis.targets.load(Ordering::Relaxed), 0);
            streams.push(stream);
        }
        assert_eq!(budget.begins.load(Ordering::Relaxed), 80);
        assert_eq!(budget.discarded.load(Ordering::Relaxed), 80);
        assert_eq!(budget.cancelled.load(Ordering::Relaxed), 80);
        assert!(budget.reserved.load(Ordering::Relaxed) > 0);
        drop(streams);
        assert_eq!(budget.reserved.load(Ordering::Relaxed), 0);
        assert_eq!(budget.releases.load(Ordering::Relaxed), 80);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_sniff_timeout_discards_target_without_another_packet() {
        let budget = Arc::new(BudgetFlow::default());
        budget.allowed.store(true, Ordering::Relaxed);
        let (inner, _peer) = tokio::io::duplex(64);
        let destination = NetLocation::from_str("192.0.2.1:443", None).unwrap();
        let mut stream = match AnalysisStream::try_new(
            inner,
            Arc::new(FlowHandle(budget.clone())),
            Some(&destination),
        ) {
            Ok(stream) => stream,
            Err(_) => panic!("available budget"),
        };
        stream.sniff_epoch = 1;
        stream.sniff_started = true;
        stream.sniff = Some((
            crate::routing::udp_sniff::UdpSniffer::new(budget.clone()),
            Box::pin(tokio::time::sleep(std::time::Duration::from_millis(300))),
        ));
        let slots = Arc::new(AtomicUsize::new(1));
        stream.sniff_slot = Some(SniffSlot(slots.clone()));
        stream.read_begin();
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        stream.sniff_expiry(&mut cx);
        tokio::time::advance(std::time::Duration::from_millis(301)).await;
        stream.sniff_expiry(&mut cx);
        assert!(stream.excluded);
        assert_eq!(slots.load(Ordering::Relaxed), 0);
        assert_eq!(budget.discarded.load(Ordering::Relaxed), 1);
        assert_eq!(budget.cancelled.load(Ordering::Relaxed), 1);
        stream.read_begin();
        stream.write_begin();
        assert_eq!(budget.begins.load(Ordering::Relaxed), 1);
        assert!(budget.reserved.load(Ordering::Relaxed) > 0);
        drop(stream);
        assert_eq!(budget.reserved.load(Ordering::Relaxed), 0);
    }
    #[tokio::test]
    async fn stale_first_classification_cannot_enable_web_callbacks_in_the_new_epoch() {
        let budget = Arc::new(BudgetFlow::default());
        budget.allowed.store(true, Ordering::Relaxed);
        let (inner, _peer) = tokio::io::duplex(64);
        let destination = NetLocation::from_str("192.0.2.1:443", None).unwrap();
        let mut stream = match AnalysisStream::try_new(
            inner,
            Arc::new(FlowHandle(budget.clone())),
            Some(&destination),
        ) {
            Ok(stream) => stream,
            Err(_) => panic!("available budget"),
        };
        stream.write_begin();
        assert_eq!(stream.write_token, Some(1));
        // The first write returns after pause/reconfigure. A valid QUIC parse
        // is still stale and must not install the wrapper's persistent Web flag.
        budget.epoch.store(2, Ordering::Relaxed);
        stream.sniff_epoch = 1;
        stream.apply_classification(1, "quic", Some("youtube.com"));
        assert!(stream.excluded);
        assert!(!stream.web);
        assert!(stream._storage.pending);
        assert_eq!(budget.cancelled.load(Ordering::Relaxed), 1);
        assert_eq!(budget.discarded.load(Ordering::Relaxed), 1);
        stream.write_begin();
        stream.read_begin();
        assert_eq!(budget.begins.load(Ordering::Relaxed), 1);
        assert!(budget.reserved.load(Ordering::Relaxed) > 0);
        drop(stream);
        assert_eq!(budget.reserved.load(Ordering::Relaxed), 0);
    }
}
