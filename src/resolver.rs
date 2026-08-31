use std::fmt::Debug;
use std::future::Future;
use std::hash::Hash;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, OnceLock, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::future::FutureExt;
use log::debug;
use lru::LruCache;
use parking_lot::Mutex;
use tokio::sync::{Mutex as AsyncMutex, RwLock};

// Resolver is a public embedding API, so its public input types must be
// reachable by crates such as shoes-engine as well.
use crate::address::ResolvedLocation;
// `Address` is part of the embedding API used by shoes-engine; the standalone
// binary's duplicate module graph does not reference it directly.
#[allow(unused_imports)]
pub use crate::address::{Address, NetLocation};

type ResolveFuture = Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>;

const CACHING_NATIVE_RESOLVER_CACHE_CAPACITY: usize = 10_000;
const RESOLVER_CACHE_CAPACITY: usize = 1_024;

/// Constructs a bounded LRU without eagerly reserving storage for every entry.
fn bounded_lru<K: Hash + Eq, V>(capacity: usize) -> LruCache<K, V> {
    let mut cache = LruCache::unbounded();
    cache.resize(NonZeroUsize::new(capacity).unwrap());
    cache
}

pub trait Resolver: Send + Sync + Debug {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture;

    /// Maximum lifetime for an address result cached outside this resolver.
    /// `None` disables outer result caching. Implementations with
    /// location-dependent policy override [`Self::result_cache_ttl_for`].
    fn result_cache_ttl(&self) -> Option<Duration> {
        Some(Duration::from_secs(
            ResolverCache::DEFAULT_RESULT_TIMEOUT_SECS,
        ))
    }

    fn result_cache_ttl_for(&self, _location: &NetLocation) -> Option<Duration> {
        self.result_cache_ttl()
    }

    /// Resolve through one explicitly named upstream exposed by a composite
    /// resolver. Ordinary resolvers deliberately reject a non-empty tag rather
    /// than silently falling back to their default path.
    ///
    /// This is the narrow primitive needed by per-outbound dialers: routing
    /// policy still uses [`Self::resolve_location`], while a proxy-server lookup
    /// can select the exact DNS transport requested by its own configuration.
    fn resolve_location_via(&self, upstream_tag: &str, location: &NetLocation) -> ResolveFuture {
        if upstream_tag.is_empty() {
            return self.resolve_location(location);
        }
        let upstream_tag = upstream_tag.to_string();
        Box::pin(async move {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("resolver does not expose named upstream {upstream_tag:?}"),
            ))
        })
    }
}

/// A resolver reference that can be connected after the graph containing it
/// has been built.
///
/// DNS transports may themselves use a proxy chain, while a proxy hop in that
/// chain can request one of the DNS policy's named upstreams. Building that
/// graph requires a late back-reference to the finished policy resolver. The
/// stored reference is deliberately weak so the finished resolver does not
/// retain itself through `policy -> upstream -> client chain -> resolver`.
#[derive(Default)]
pub struct LateBoundResolver {
    inner: OnceLock<Weak<dyn Resolver>>,
}

impl LateBoundResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Connect this handle exactly once to its finished resolver graph.
    pub fn bind(&self, resolver: &Arc<dyn Resolver>) -> std::io::Result<()> {
        self.inner.set(Arc::downgrade(resolver)).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "late-bound resolver is already connected",
            )
        })
    }

    fn target(&self) -> std::io::Result<Arc<dyn Resolver>> {
        self.inner.get().and_then(Weak::upgrade).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "late-bound resolver is not connected",
            )
        })
    }
}

impl Debug for LateBoundResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LateBoundResolver")
            .field("connected", &self.inner.get().is_some())
            .finish()
    }
}

impl Resolver for LateBoundResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        match self.target() {
            Ok(target) => target.resolve_location(location),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn resolve_location_via(&self, upstream_tag: &str, location: &NetLocation) -> ResolveFuture {
        match self.target() {
            Ok(target) => target.resolve_location_via(upstream_tag, location),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn result_cache_ttl(&self) -> Option<Duration> {
        self.target()
            .ok()
            .and_then(|target| target.result_cache_ttl())
    }

    fn result_cache_ttl_for(&self, location: &NetLocation) -> Option<Duration> {
        self.target()
            .ok()
            .and_then(|target| target.result_cache_ttl_for(location))
    }
}

/// Resolver wrapper that enforces a timeout on DNS resolution.
/// Wraps any inner Resolver and fails with TimedOut if resolution takes too long.
pub struct TimeoutResolver<T> {
    inner: T,
    timeout: Duration,
}

impl<T: Resolver> TimeoutResolver<T> {
    #[allow(dead_code)]
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

    #[allow(dead_code)]
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(inner: T, timeout: Duration) -> Self {
        Self { inner, timeout }
    }
}

impl<T: Resolver> Debug for TimeoutResolver<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimeoutResolver")
            .field("inner", &self.inner)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl<T: Resolver> Resolver for TimeoutResolver<T> {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        // Fast path: if already an IP address, no resolution needed
        if location.to_socket_addr_nonblocking().is_some() {
            let loc = location.clone();
            return Box::pin(async move { Ok(vec![loc.to_socket_addr_nonblocking().unwrap()]) });
        }

        let inner_future = self.inner.resolve_location(location);
        let timeout_duration = self.timeout;
        let location_str = location.to_string();

        Box::pin(async move {
            match tokio::time::timeout(timeout_duration, inner_future).await {
                Ok(result) => result,
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "DNS resolution for {} timed out after {:?}",
                        location_str, timeout_duration
                    ),
                )),
            }
        })
    }

    fn resolve_location_via(&self, upstream_tag: &str, location: &NetLocation) -> ResolveFuture {
        if location.to_socket_addr_nonblocking().is_some() {
            let location = location.clone();
            return Box::pin(
                async move { Ok(vec![location.to_socket_addr_nonblocking().unwrap()]) },
            );
        }

        let inner_future = self.inner.resolve_location_via(upstream_tag, location);
        let timeout_duration = self.timeout;
        let location_string = location.to_string();
        let upstream_tag = upstream_tag.to_string();
        Box::pin(async move {
            tokio::time::timeout(timeout_duration, inner_future)
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "DNS resolution for {location_string} via {upstream_tag:?} timed out after {timeout_duration:?}"
                        ),
                    )
                })?
        })
    }

    fn result_cache_ttl(&self) -> Option<Duration> {
        self.inner.result_cache_ttl()
    }

    fn result_cache_ttl_for(&self, location: &NetLocation) -> Option<Duration> {
        self.inner.result_cache_ttl_for(location)
    }
}

type ResolverFactoryFuture =
    Pin<Box<dyn Future<Output = std::io::Result<Arc<dyn Resolver>>> + Send>>;

pub type ResolverFactory = Arc<dyn Fn() -> ResolverFactoryFuture + Send + Sync>;

/// Socket/connectivity failures which can become healthy after rebuilding a
/// connection pool or trying another transport. DNS semantic errors and data
/// validation failures are intentionally excluded.
pub(crate) fn is_connection_error_kind(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::AddrNotAvailable
            | std::io::ErrorKind::WouldBlock
    )
}

/// Policy controlling when a RefreshingResolver rebuilds its inner resolver.
#[derive(Debug, Clone, Copy)]
pub struct RefreshPolicy {
    /// Rebuild the inner resolver if it has been idle longer than this.
    pub max_idle: Duration,
    /// Rebuild the inner resolver once it reaches this age, even while queries
    /// keep it continuously active. `None` preserves the historical idle-only
    /// refresh behaviour.
    pub max_age: Option<Duration>,
    /// After a refreshable error, rebuild and retry the lookup once.
    pub retry_once_after_refresh: bool,
}

/// Resolver wrapper that rebuilds its inner resolver on idle timeout or
/// connection-related errors. Targets stale pooled connection state in
/// hickory-backed resolvers.
pub struct RefreshingResolver {
    factory: ResolverFactory,
    inner: Arc<RwLock<Arc<dyn Resolver>>>,
    refresh_lock: Arc<AsyncMutex<()>>,
    refresh_state: Arc<Mutex<RefreshState>>,
    policy: RefreshPolicy,
    description: String,
    result_cache_ttl: Option<Duration>,
}

struct RefreshState {
    last_activity_at: Option<Instant>,
    last_refresh_attempt_at: Instant,
    last_error_refresh_attempt_at: Option<Instant>,
    generation: u64,
}

impl Debug for RefreshingResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshingResolver")
            .field("description", &self.description)
            .field("max_idle", &self.policy.max_idle)
            .field("max_age", &self.policy.max_age)
            .finish()
    }
}

impl RefreshingResolver {
    pub async fn new(
        factory: ResolverFactory,
        policy: RefreshPolicy,
        description: String,
    ) -> std::io::Result<Self> {
        let inner = factory().await?;
        let result_cache_ttl = inner.result_cache_ttl();
        Ok(Self {
            factory,
            inner: Arc::new(RwLock::new(inner)),
            refresh_lock: Arc::new(AsyncMutex::new(())),
            refresh_state: Arc::new(Mutex::new(RefreshState {
                last_activity_at: None,
                last_refresh_attempt_at: Instant::now(),
                last_error_refresh_attempt_at: None,
                generation: 0,
            })),
            policy,
            description,
            result_cache_ttl,
        })
    }

    fn should_refresh_for_error(err: &std::io::Error) -> bool {
        is_connection_error_kind(err.kind())
    }

    fn scheduled_refresh_reason(
        state: &RefreshState,
        policy: RefreshPolicy,
    ) -> Option<&'static str> {
        if policy
            .max_age
            .is_some_and(|max_age| state.last_refresh_attempt_at.elapsed() >= max_age)
        {
            return Some("maximum age");
        }
        if matches!(state.last_activity_at, Some(last) if last.elapsed() > policy.max_idle) {
            return Some("idle timeout");
        }
        None
    }

    fn error_refresh_is_rate_limited(state: &RefreshState, policy: RefreshPolicy) -> bool {
        policy.max_age.is_some_and(|minimum_interval| {
            state
                .last_error_refresh_attempt_at
                .is_some_and(|last_attempt| last_attempt.elapsed() < minimum_interval)
        })
    }
}

impl Resolver for RefreshingResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
            return Box::pin(async move { Ok(vec![socket_addr]) });
        }

        let location = location.clone();
        let inner = self.inner.clone();
        let refresh_lock = self.refresh_lock.clone();
        let factory = self.factory.clone();
        let refresh_state = self.refresh_state.clone();
        let policy = self.policy;
        let description = self.description.clone();

        Box::pin(async move {
            // Refreshes after an idle period or a configured maximum instance
            // age. The latter keeps system DNS configuration current even under
            // continuous traffic. Double-checked locking coalesces concurrent
            // refresh attempts.
            let refresh_reason = {
                let state = refresh_state.lock();
                RefreshingResolver::scheduled_refresh_reason(&state, policy)
            };
            if refresh_reason.is_some() {
                let _guard = refresh_lock.lock().await;
                let refresh_reason = {
                    let state = refresh_state.lock();
                    RefreshingResolver::scheduled_refresh_reason(&state, policy)
                };
                if let Some(refresh_reason) = refresh_reason {
                    match factory().await {
                        Ok(fresh) => {
                            let unchanged = {
                                let current = inner.read().await;
                                Arc::ptr_eq(&current, &fresh)
                            };
                            if !unchanged {
                                *inner.write().await = fresh;
                                log::info!(
                                    "RefreshingResolver ({}): rebuilt after {}",
                                    description,
                                    refresh_reason
                                );
                            } else {
                                log::debug!(
                                    "RefreshingResolver ({}): {} check found no resolver change",
                                    description,
                                    refresh_reason
                                );
                            }
                            let mut state = refresh_state.lock();
                            let now = Instant::now();
                            state.last_activity_at = Some(now);
                            state.last_refresh_attempt_at = now;
                            state.last_error_refresh_attempt_at = Some(now);
                            state.generation = state.generation.wrapping_add(1);
                        }
                        Err(e) => {
                            // Rate-limit repeated scheduled rebuild failures to
                            // the configured idle/age interval instead of trying
                            // to re-read system state on every lookup.
                            let now = Instant::now();
                            let mut state = refresh_state.lock();
                            state.last_activity_at = Some(now);
                            state.last_refresh_attempt_at = now;
                            state.last_error_refresh_attempt_at = Some(now);
                            log::warn!(
                                "RefreshingResolver ({}): scheduled refresh failed: {}",
                                description,
                                e
                            );
                        }
                    }
                }
            }

            let current_generation = refresh_state.lock().generation;
            let current = inner.read().await.clone();
            match current.resolve_location(&location).await {
                Ok(addrs) => {
                    refresh_state.lock().last_activity_at = Some(Instant::now());
                    Ok(addrs)
                }
                Err(err)
                    if policy.retry_once_after_refresh
                        && RefreshingResolver::should_refresh_for_error(&err) =>
                {
                    let _guard = refresh_lock.lock().await;
                    if refresh_state.lock().generation != current_generation {
                        let current = inner.read().await.clone();
                        let addrs = current.resolve_location(&location).await?;
                        refresh_state.lock().last_activity_at = Some(Instant::now());
                        return Ok(addrs);
                    }
                    let error_refresh_is_rate_limited = {
                        let state = refresh_state.lock();
                        RefreshingResolver::error_refresh_is_rate_limited(&state, policy)
                    };
                    if error_refresh_is_rate_limited {
                        return Err(err);
                    }
                    match factory().await {
                        Ok(fresh) => {
                            let unchanged = {
                                let current = inner.read().await;
                                Arc::ptr_eq(&current, &fresh)
                            };
                            if !unchanged {
                                *inner.write().await = fresh.clone();
                                log::info!(
                                    "RefreshingResolver ({}): rebuilt on {} error for {}",
                                    description,
                                    err.kind(),
                                    location
                                );
                            } else {
                                log::debug!(
                                    "RefreshingResolver ({}): {} error check for {} found no resolver change",
                                    description,
                                    err.kind(),
                                    location
                                );
                            }
                            {
                                let mut state = refresh_state.lock();
                                let now = Instant::now();
                                state.last_refresh_attempt_at = now;
                                state.last_error_refresh_attempt_at = Some(now);
                                state.generation = state.generation.wrapping_add(1);
                            }
                            let addrs = fresh.resolve_location(&location).await?;
                            refresh_state.lock().last_activity_at = Some(Instant::now());
                            Ok(addrs)
                        }
                        Err(factory_err) => {
                            let now = Instant::now();
                            let mut state = refresh_state.lock();
                            state.last_refresh_attempt_at = now;
                            state.last_error_refresh_attempt_at = Some(now);
                            log::warn!(
                                "RefreshingResolver ({}): error-refresh factory failed: {}",
                                description,
                                factory_err
                            );
                            Err(err)
                        }
                    }
                }
                Err(err) => Err(err),
            }
        })
    }

    fn result_cache_ttl(&self) -> Option<Duration> {
        self.result_cache_ttl
    }
}

#[derive(Debug, Default)]
pub struct NativeResolver;

impl NativeResolver {
    pub fn new() -> Self {
        NativeResolver {}
    }
}

impl Resolver for NativeResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        let address = location.address().clone();
        let port = location.port();
        Box::pin(
            tokio::net::lookup_host((address.to_string(), port)).map(move |result| {
                let ret = result.map(|r| {
                    r.filter(|addr| !addr.ip().is_unspecified())
                        .collect::<Vec<_>>()
                });
                debug!("NativeResolver resolved {address}:{port} -> {ret:?}");
                ret
            }),
        )
    }
}

pub async fn resolve_single_address(
    resolver: &Arc<dyn Resolver>,
    location: &NetLocation,
) -> std::io::Result<SocketAddr> {
    if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
        return Ok(socket_addr);
    }
    let resolve_results = resolver.resolve_location(location).await?;
    if resolve_results.is_empty() {
        return Err(std::io::Error::other(format!(
            "could not resolve location: {location}"
        )));
    }
    Ok(resolve_results[0])
}

/// Resolve all addresses for a location. Returns a single-element vec
/// for IP literals, or the full set from the resolver.
pub async fn resolve_addresses(
    resolver: &Arc<dyn Resolver>,
    location: &NetLocation,
) -> std::io::Result<Vec<SocketAddr>> {
    resolve_addresses_via(resolver, None, location).await
}

/// Resolve all addresses through an optional exact named upstream.
pub async fn resolve_addresses_via(
    resolver: &Arc<dyn Resolver>,
    upstream_tag: Option<&str>,
    location: &NetLocation,
) -> std::io::Result<Vec<SocketAddr>> {
    if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
        return Ok(vec![socket_addr]);
    }

    let addrs = match upstream_tag {
        Some(tag) => resolver.resolve_location_via(tag, location).await?,
        None => resolver.resolve_location(location).await?,
    };
    if addrs.is_empty() {
        return Err(std::io::Error::other(format!(
            "could not resolve location: {location}"
        )));
    }
    Ok(addrs)
}

/// Resolve a ResolvedLocation lazily. If already resolved, returns the first
/// cached address. Otherwise resolves and retains the complete ordered result
/// so a later socket connector can retry every candidate.
pub async fn resolve_location(
    location: &mut ResolvedLocation,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<SocketAddr> {
    resolve_location_via(location, resolver, None).await
}

/// Resolve and cache a location through an optional exact named upstream.
pub async fn resolve_location_via(
    location: &mut ResolvedLocation,
    resolver: &Arc<dyn Resolver>,
    upstream_tag: Option<&str>,
) -> std::io::Result<SocketAddr> {
    if let Some(addr) = location.resolved_addr() {
        return Ok(addr);
    }
    let addrs = resolve_addresses_via(resolver, upstream_tag, location.location()).await?;
    let addr = addrs.first().copied().ok_or_else(|| {
        std::io::Error::other(format!(
            "could not resolve location: {}",
            location.location()
        ))
    })?;
    location.set_resolved_addrs(addrs);
    Ok(addr)
}

/// Native resolver with application-level caching.
/// Uses tokio::net::lookup_host (OS resolver) with TTL-based cache.
/// This is used as the default resolver when no DNS config is specified.
pub struct CachingNativeResolver {
    cache: Arc<parking_lot::Mutex<LruCache<NetLocation, CachedResolveResult>>>,
    result_timeout_secs: u64,
}

struct CachedResolveResult {
    timestamp: Instant,
    addr: SocketAddr,
}

impl std::fmt::Debug for CachingNativeResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachingNativeResolver")
            .field("result_timeout_secs", &self.result_timeout_secs)
            .finish()
    }
}

impl CachingNativeResolver {
    pub const DEFAULT_RESULT_TIMEOUT_SECS: u64 = 60 * 60; // 1 hour

    pub fn new() -> Self {
        Self::with_timeout(Self::DEFAULT_RESULT_TIMEOUT_SECS)
    }

    pub fn with_timeout(result_timeout_secs: u64) -> Self {
        Self {
            cache: Arc::new(parking_lot::Mutex::new(bounded_lru(
                CACHING_NATIVE_RESOLVER_CACHE_CAPACITY,
            ))),
            result_timeout_secs,
        }
    }
}

impl Default for CachingNativeResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver for CachingNativeResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        // Check cache first
        {
            let mut cache = self.cache.lock();
            if let Some(cached) = cache.get(location)
                && Instant::now().duration_since(cached.timestamp)
                    <= Duration::from_secs(self.result_timeout_secs)
            {
                let addr = cached.addr;
                return Box::pin(async move { Ok(vec![addr]) });
            }
            cache.pop(location);
        }

        let location = location.clone();
        let cache = self.cache.clone();

        Box::pin(async move {
            let address = location.address().to_string();
            let port = location.port();

            let result = tokio::net::lookup_host((address.clone(), port)).await?;
            let addrs: Vec<SocketAddr> =
                result.filter(|addr| !addr.ip().is_unspecified()).collect();

            if addrs.is_empty() {
                return Err(std::io::Error::other(format!(
                    "DNS lookup returned no addresses for {address}"
                )));
            }

            // Cache the first result
            cache.lock().put(
                location,
                CachedResolveResult {
                    timestamp: Instant::now(),
                    addr: addrs[0],
                },
            );

            debug!("CachingNativeResolver resolved {address}:{port} -> {addrs:?}");
            Ok(addrs)
        })
    }
}

/// Poll-based resolver cache for use in Future/Stream implementations.
/// Wraps any Resolver and provides poll_resolve_location for manual polling.
pub struct ResolverCache {
    resolver: Arc<dyn Resolver>,
    /// Completed resolution results with timestamps
    cache: LruCache<NetLocation, (Instant, Vec<SocketAddr>)>,
    /// The latest poll-based lookup. A changed target cancels the abandoned lookup.
    pending: Option<(NetLocation, ResolveFuture)>,
    result_timeout_secs: u64,
}

impl ResolverCache {
    pub const DEFAULT_RESULT_TIMEOUT_SECS: u64 = 60 * 60;

    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        Self::new_with_timeout(resolver, Self::DEFAULT_RESULT_TIMEOUT_SECS)
    }

    pub fn new_with_timeout(resolver: Arc<dyn Resolver>, result_timeout_secs: u64) -> Self {
        Self {
            resolver,
            cache: bounded_lru(RESOLVER_CACHE_CAPACITY),
            pending: None,
            result_timeout_secs,
        }
    }

    fn result_cache_ttl(&self, target: &NetLocation) -> Option<Duration> {
        self.resolver
            .result_cache_ttl_for(target)
            .map(|ttl| ttl.min(Duration::from_secs(self.result_timeout_secs)))
    }

    /// Async resolve method for convenience.
    pub async fn resolve_location(&mut self, target: &NetLocation) -> std::io::Result<SocketAddr> {
        self.resolve_addresses(target)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| {
                std::io::Error::other(format!("DNS lookup returned no addresses for {target}"))
            })
    }

    /// Resolve and retain every address in resolver preference order.
    pub async fn resolve_addresses(
        &mut self,
        target: &NetLocation,
    ) -> std::io::Result<Vec<SocketAddr>> {
        self.pending = None;

        // Fast path: IP address
        if let Some(socket_addr) = target.to_socket_addr_nonblocking() {
            return Ok(vec![socket_addr]);
        }

        let result_cache_ttl = self.result_cache_ttl(target);
        // Check cache
        if let (Some(ttl), Some((ts, addrs))) = (result_cache_ttl, self.cache.get(target)) {
            if !ttl.is_zero() && Instant::now().duration_since(*ts) <= ttl {
                return Ok(addrs.clone());
            }
            self.cache.pop(target);
        } else if result_cache_ttl.is_none() {
            self.cache.pop(target);
        }

        // Resolve
        let addrs = self.resolver.resolve_location(target).await?;
        if addrs.is_empty() {
            return Err(std::io::Error::other(format!(
                "DNS lookup returned no addresses for {target}"
            )));
        }
        if result_cache_ttl.is_some_and(|ttl| !ttl.is_zero()) {
            self.cache
                .put(target.clone(), (Instant::now(), addrs.clone()));
        }
        Ok(addrs)
    }

    /// Poll-based resolve for use in Future/Stream poll methods.
    pub fn poll_resolve_location(
        &mut self,
        cx: &mut Context<'_>,
        target: &NetLocation,
    ) -> Poll<std::io::Result<SocketAddr>> {
        match self.poll_resolve_addresses(cx, target) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(addrs)) => Poll::Ready(addrs.into_iter().next().ok_or_else(|| {
                std::io::Error::other(format!("DNS lookup returned no addresses for {target}"))
            })),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        }
    }

    /// Poll-based resolution that preserves every address in resolver order.
    pub fn poll_resolve_addresses(
        &mut self,
        cx: &mut Context<'_>,
        target: &NetLocation,
    ) -> Poll<std::io::Result<Vec<SocketAddr>>> {
        if self
            .pending
            .as_ref()
            .is_some_and(|(pending_target, _)| pending_target != target)
        {
            self.pending = None;
        }

        // Fast path: IP address
        if let Some(socket_addr) = target.to_socket_addr_nonblocking() {
            return Poll::Ready(Ok(vec![socket_addr]));
        }

        let result_cache_ttl = self.result_cache_ttl(target);
        // Check completed cache
        if let (Some(ttl), Some((ts, addrs))) = (result_cache_ttl, self.cache.get(target)) {
            if !ttl.is_zero() && Instant::now().duration_since(*ts) <= ttl {
                return Poll::Ready(Ok(addrs.clone()));
            }
            self.cache.pop(target);
        } else if result_cache_ttl.is_none() {
            self.cache.pop(target);
        }

        if self.pending.is_none() {
            self.pending = Some((target.clone(), self.resolver.resolve_location(target)));
        }

        let result = self.pending.as_mut().unwrap().1.as_mut().poll(cx);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(addrs)) => {
                self.pending = None;
                if addrs.is_empty() {
                    return Poll::Ready(Err(std::io::Error::other(format!(
                        "DNS lookup returned no addresses for {target}"
                    ))));
                }
                if result_cache_ttl.is_some_and(|ttl| !ttl.is_zero()) {
                    self.cache
                        .put(target.clone(), (Instant::now(), addrs.clone()));
                }
                Poll::Ready(Ok(addrs))
            }
            Poll::Ready(Err(e)) => {
                self.pending = None;
                Poll::Ready(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Barrier;

    /// A mock resolver that returns configurable results, tracking call count.
    #[derive(Debug)]
    struct MockResolver {
        addrs: Vec<SocketAddr>,
        call_count: AtomicUsize,
        error_kind: Option<std::io::ErrorKind>,
        result_cache_ttl: Option<Duration>,
    }

    impl MockResolver {
        fn with_addrs(addrs: Vec<SocketAddr>) -> Self {
            Self {
                addrs,
                call_count: AtomicUsize::new(0),
                error_kind: None,
                result_cache_ttl: Some(Duration::from_secs(60 * 60)),
            }
        }

        fn with_error(kind: std::io::ErrorKind) -> Self {
            Self {
                addrs: vec![],
                call_count: AtomicUsize::new(0),
                error_kind: Some(kind),
                result_cache_ttl: Some(Duration::from_secs(60 * 60)),
            }
        }

        fn with_cache_ttl(addrs: Vec<SocketAddr>, result_cache_ttl: Option<Duration>) -> Self {
            Self {
                addrs,
                call_count: AtomicUsize::new(0),
                error_kind: None,
                result_cache_ttl,
            }
        }

        fn count(&self) -> usize {
            self.call_count.load(Ordering::Relaxed)
        }
    }

    impl Resolver for MockResolver {
        fn resolve_location(&self, _location: &NetLocation) -> ResolveFuture {
            self.call_count.fetch_add(1, Ordering::Relaxed);
            let addrs = self.addrs.clone();
            let error_kind = self.error_kind;
            Box::pin(async move {
                if let Some(kind) = error_kind {
                    Err(std::io::Error::new(kind, "mock error"))
                } else {
                    Ok(addrs)
                }
            })
        }

        fn result_cache_ttl(&self) -> Option<Duration> {
            self.result_cache_ttl
        }
    }

    /// A mock resolver that fails the first N calls then succeeds.
    #[derive(Debug)]
    struct FlakyResolver {
        fail_count: AtomicUsize,
        fails_remaining: AtomicUsize,
        error_kind: std::io::ErrorKind,
        success_addrs: Vec<SocketAddr>,
    }

    impl FlakyResolver {
        fn new(
            fail_first_n: usize,
            error_kind: std::io::ErrorKind,
            success_addrs: Vec<SocketAddr>,
        ) -> Self {
            Self {
                fail_count: AtomicUsize::new(0),
                fails_remaining: AtomicUsize::new(fail_first_n),
                error_kind,
                success_addrs,
            }
        }
    }

    impl Resolver for FlakyResolver {
        fn resolve_location(&self, _location: &NetLocation) -> ResolveFuture {
            let remaining = self.fails_remaining.fetch_sub(1, Ordering::Relaxed);
            if remaining > 0 {
                self.fail_count.fetch_add(1, Ordering::Relaxed);
                let kind = self.error_kind;
                Box::pin(async move { Err(std::io::Error::new(kind, "flaky error")) })
            } else {
                let addrs = self.success_addrs.clone();
                Box::pin(async move { Ok(addrs) })
            }
        }
    }

    #[derive(Debug, Default)]
    struct PendingResolver {
        active: Arc<AtomicUsize>,
        calls: AtomicUsize,
    }

    struct PendingFuture {
        active: Arc<AtomicUsize>,
    }

    impl Future for PendingFuture {
        type Output = std::io::Result<Vec<SocketAddr>>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for PendingFuture {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::Relaxed);
        }
    }

    impl Resolver for PendingResolver {
        fn resolve_location(&self, _location: &NetLocation) -> ResolveFuture {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.active.fetch_add(1, Ordering::Relaxed);
            Box::pin(PendingFuture {
                active: self.active.clone(),
            })
        }
    }

    fn test_location() -> NetLocation {
        NetLocation::new(Address::Hostname("example.com".to_string()), 80)
    }

    fn test_addrs() -> Vec<SocketAddr> {
        vec!["127.0.0.1:80".parse().unwrap()]
    }

    fn unique_location(index: usize) -> NetLocation {
        NetLocation::new(Address::Hostname(format!("host-{index}.example")), 443)
    }

    #[test]
    fn connectivity_classifier_covers_immediate_route_and_bind_failures() {
        for kind in [
            std::io::ErrorKind::TimedOut,
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::HostUnreachable,
            std::io::ErrorKind::NetworkUnreachable,
            std::io::ErrorKind::AddrNotAvailable,
        ] {
            assert!(is_connection_error_kind(kind), "missing {kind:?}");
        }
        assert!(!is_connection_error_kind(std::io::ErrorKind::NotFound));
        assert!(!is_connection_error_kind(std::io::ErrorKind::InvalidData));
    }

    #[tokio::test]
    async fn late_bound_resolver_delegates_without_retaining_target() {
        let handle = LateBoundResolver::new();
        let error = handle.resolve_location(&test_location()).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotConnected);

        let concrete = Arc::new(MockResolver::with_addrs(test_addrs()));
        let target: Arc<dyn Resolver> = concrete.clone();
        handle.bind(&target).unwrap();
        assert_eq!(
            handle.resolve_location(&test_location()).await.unwrap(),
            test_addrs()
        );
        assert_eq!(concrete.count(), 1);
        assert_eq!(
            handle.bind(&target).unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );

        drop(target);
        drop(concrete);
        let error = handle.resolve_location(&test_location()).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotConnected);
    }

    #[test]
    fn test_caching_native_resolver_cache_is_bounded() {
        let resolver = CachingNativeResolver::new();
        let mut cache = resolver.cache.lock();

        for index in 0..CACHING_NATIVE_RESOLVER_CACHE_CAPACITY + 1 {
            cache.put(
                unique_location(index),
                CachedResolveResult {
                    timestamp: Instant::now(),
                    addr: "127.0.0.1:443".parse().unwrap(),
                },
            );
        }

        assert_eq!(cache.len(), CACHING_NATIVE_RESOLVER_CACHE_CAPACITY);
        assert!(cache.peek(&unique_location(0)).is_none());
    }

    #[tokio::test]
    async fn test_resolver_cache_is_bounded() {
        let resolver: Arc<dyn Resolver> = Arc::new(MockResolver::with_addrs(test_addrs()));
        let mut cache = ResolverCache::new(resolver);

        for index in 0..RESOLVER_CACHE_CAPACITY + 1 {
            cache
                .resolve_location(&unique_location(index))
                .await
                .unwrap();
        }

        assert_eq!(cache.cache.len(), RESOLVER_CACHE_CAPACITY);
        assert!(cache.cache.peek(&unique_location(0)).is_none());
    }

    #[tokio::test]
    async fn resolver_cache_honors_bypass_zero_and_positive_ttl_hints() {
        for ttl in [None, Some(Duration::ZERO)] {
            let concrete = Arc::new(MockResolver::with_cache_ttl(test_addrs(), ttl));
            let resolver: Arc<dyn Resolver> = concrete.clone();
            let mut cache = ResolverCache::new(resolver);
            cache.resolve_location(&test_location()).await.unwrap();
            cache.resolve_location(&test_location()).await.unwrap();
            assert_eq!(concrete.count(), 2, "TTL {ttl:?} must bypass outer cache");
            assert!(cache.cache.is_empty());
        }

        let concrete = Arc::new(MockResolver::with_cache_ttl(
            test_addrs(),
            Some(Duration::from_secs(30)),
        ));
        let resolver: Arc<dyn Resolver> = concrete.clone();
        let mut cache = ResolverCache::new(resolver);
        cache.resolve_location(&test_location()).await.unwrap();
        cache.resolve_location(&test_location()).await.unwrap();
        assert_eq!(concrete.count(), 1);
        assert_eq!(cache.cache.len(), 1);
    }

    #[test]
    fn test_resolver_cache_cancels_abandoned_pending_result() {
        let resolver = Arc::new(PendingResolver::default());
        let mut cache = ResolverCache::new(resolver.clone());
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let first = unique_location(0);
        let second = unique_location(1);

        assert!(matches!(
            cache.poll_resolve_location(&mut cx, &first),
            Poll::Pending
        ));
        assert_eq!(resolver.active.load(Ordering::Relaxed), 1);

        assert!(matches!(
            cache.poll_resolve_location(&mut cx, &second),
            Poll::Pending
        ));
        assert_eq!(resolver.active.load(Ordering::Relaxed), 1);
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 2);

        assert!(matches!(
            cache.poll_resolve_location(&mut cx, &second),
            Poll::Pending
        ));
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 2);

        let literal = NetLocation::new(Address::Ipv4(std::net::Ipv4Addr::LOCALHOST), 443);
        assert!(matches!(
            cache.poll_resolve_location(&mut cx, &literal),
            Poll::Ready(Ok(_))
        ));
        assert_eq!(resolver.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_refreshing_resolver_retries_after_timeout() {
        let success_addrs = test_addrs();
        let call_count = Arc::new(AtomicUsize::new(0));

        let call_count_clone = call_count.clone();
        let addrs = success_addrs.clone();
        let factory: ResolverFactory = Arc::new(move || {
            let n = call_count_clone.fetch_add(1, Ordering::Relaxed);
            let addrs = addrs.clone();
            Box::pin(async move {
                if n == 0 {
                    // First build: return a resolver that times out
                    Ok(
                        Arc::new(MockResolver::with_error(std::io::ErrorKind::TimedOut))
                            as Arc<dyn Resolver>,
                    )
                } else {
                    // Refresh build: return a resolver that succeeds
                    Ok(Arc::new(MockResolver::with_addrs(addrs)) as Arc<dyn Resolver>)
                }
            })
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_secs(60),
            max_age: None,
            retry_once_after_refresh: true,
        };

        let resolver = RefreshingResolver::new(factory, policy, "test".to_string())
            .await
            .unwrap();

        let result = resolver.resolve_location(&test_location()).await.unwrap();
        assert_eq!(result, success_addrs);
        // Factory called twice: initial build + refresh-on-error
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_refreshing_resolver_no_retry_on_non_refreshable_error() {
        let call_count = Arc::new(AtomicUsize::new(0));

        let call_count_clone = call_count.clone();
        let factory: ResolverFactory = Arc::new(move || {
            call_count_clone.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move {
                // Return a resolver that returns a non-refreshable error
                Ok(
                    Arc::new(MockResolver::with_error(std::io::ErrorKind::Other))
                        as Arc<dyn Resolver>,
                )
            })
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_secs(60),
            max_age: None,
            retry_once_after_refresh: true,
        };

        let resolver = RefreshingResolver::new(factory, policy, "test".to_string())
            .await
            .unwrap();

        let result = resolver.resolve_location(&test_location()).await;
        assert!(result.is_err());
        // Factory called only once (initial build, no refresh for non-refreshable errors)
        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn refreshing_resolver_rate_limits_system_style_error_refreshes() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let factory_count = call_count.clone();
        let factory: ResolverFactory = Arc::new(move || {
            factory_count.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move {
                Ok(
                    Arc::new(MockResolver::with_error(std::io::ErrorKind::TimedOut))
                        as Arc<dyn Resolver>,
                )
            })
        });
        let interval = Duration::from_millis(20);
        let resolver = RefreshingResolver::new(
            factory,
            RefreshPolicy {
                max_idle: Duration::from_secs(60),
                max_age: Some(interval),
                retry_once_after_refresh: true,
            },
            "system-style-test".to_string(),
        )
        .await
        .unwrap();

        assert!(resolver.resolve_location(&test_location()).await.is_err());
        assert_eq!(call_count.load(Ordering::Relaxed), 2);

        // A hot failing upstream must not run its refresh factory again on
        // every query during the platform configuration cooldown.
        assert!(resolver.resolve_location(&test_location()).await.is_err());
        assert_eq!(call_count.load(Ordering::Relaxed), 2);

        tokio::time::sleep(interval + Duration::from_millis(10)).await;
        assert!(resolver.resolve_location(&test_location()).await.is_err());
        assert_eq!(
            call_count.load(Ordering::Relaxed),
            3,
            "the scheduled age check must also suppress a duplicate error refresh"
        );
    }

    #[tokio::test]
    async fn test_refreshing_resolver_idle_refresh() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let addrs = test_addrs();

        let call_count_clone = call_count.clone();
        let addrs_clone = addrs.clone();
        let factory: ResolverFactory = Arc::new(move || {
            call_count_clone.fetch_add(1, Ordering::Relaxed);
            let addrs = addrs_clone.clone();
            Box::pin(
                async move { Ok(Arc::new(MockResolver::with_addrs(addrs)) as Arc<dyn Resolver>) },
            )
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_millis(50),
            max_age: None,
            retry_once_after_refresh: true,
        };

        let resolver = RefreshingResolver::new(factory, policy, "test".to_string())
            .await
            .unwrap();

        // First resolve records activity.
        let result = resolver.resolve_location(&test_location()).await.unwrap();
        assert_eq!(result, addrs);
        assert_eq!(call_count.load(Ordering::Relaxed), 1);

        // Wait for idle timeout
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Second resolve triggers idle refresh
        let result = resolver.resolve_location(&test_location()).await.unwrap();
        assert_eq!(result, addrs);
        // Factory called twice: initial + idle refresh
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_refreshing_resolver_max_age_refreshes_while_active() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let addrs = test_addrs();

        let call_count_clone = call_count.clone();
        let addrs_clone = addrs.clone();
        let factory: ResolverFactory = Arc::new(move || {
            call_count_clone.fetch_add(1, Ordering::Relaxed);
            let addrs = addrs_clone.clone();
            Box::pin(
                async move { Ok(Arc::new(MockResolver::with_addrs(addrs)) as Arc<dyn Resolver>) },
            )
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_secs(60),
            max_age: Some(Duration::from_millis(20)),
            retry_once_after_refresh: true,
        };
        let resolver = RefreshingResolver::new(factory, policy, "max-age-test".to_string())
            .await
            .unwrap();

        // Activity well inside max_idle must not suppress the independent
        // maximum-age rebuild.
        assert_eq!(
            resolver.resolve_location(&test_location()).await.unwrap(),
            addrs
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            resolver.resolve_location(&test_location()).await.unwrap(),
            addrs
        );
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_refreshing_resolver_coalesces_concurrent_idle_refresh() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let addrs = test_addrs();

        let call_count_clone = call_count.clone();
        let addrs_clone = addrs.clone();
        let factory: ResolverFactory = Arc::new(move || {
            call_count_clone.fetch_add(1, Ordering::Relaxed);
            let addrs = addrs_clone.clone();
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(Arc::new(MockResolver::with_addrs(addrs)) as Arc<dyn Resolver>)
            })
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_millis(20),
            max_age: None,
            retry_once_after_refresh: true,
        };

        let resolver = Arc::new(
            RefreshingResolver::new(factory, policy, "test".to_string())
                .await
                .unwrap(),
        );

        let result = resolver.resolve_location(&test_location()).await.unwrap();
        assert_eq!(result, addrs);
        assert_eq!(call_count.load(Ordering::Relaxed), 1);

        tokio::time::sleep(Duration::from_millis(50)).await;

        let concurrency = 32;
        let barrier = Arc::new(Barrier::new(concurrency));
        let tasks = (0..concurrency).map(|_| {
            let resolver = resolver.clone();
            let barrier = barrier.clone();
            let location = test_location();
            tokio::spawn(async move {
                barrier.wait().await;
                resolver.resolve_location(&location).await
            })
        });

        for result in futures::future::join_all(tasks).await {
            assert_eq!(result.unwrap().unwrap(), addrs);
        }
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_resolve_addresses_returns_all() {
        let addrs: Vec<SocketAddr> = vec![
            "1.1.1.1:80".parse().unwrap(),
            "2.2.2.2:80".parse().unwrap(),
            "3.3.3.3:80".parse().unwrap(),
        ];
        let inner: Arc<dyn Resolver> = Arc::new(MockResolver::with_addrs(addrs.clone()));
        let loc = test_location();

        let result = resolve_addresses(&inner, &loc).await.unwrap();
        assert_eq!(result, addrs);
    }

    #[tokio::test]
    async fn test_resolve_addresses_ip_literal() {
        let inner: Arc<dyn Resolver> = Arc::new(MockResolver::with_addrs(vec![]));
        let loc = NetLocation::new(Address::Ipv4("1.2.3.4".parse().unwrap()), 443);

        let result = resolve_addresses(&inner, &loc).await.unwrap();
        assert_eq!(result, vec!["1.2.3.4:443".parse::<SocketAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn test_timeout_resolver_ip_bypass() {
        let inner = MockResolver::with_addrs(test_addrs());
        let resolver = TimeoutResolver::with_timeout(inner, Duration::from_millis(1));

        // IP literals should return immediately without timeout
        let loc = NetLocation::new(Address::Ipv4("1.2.3.4".parse().unwrap()), 80);
        let result = resolver.resolve_location(&loc).await.unwrap();
        assert_eq!(result[0], "1.2.3.4:80".parse::<SocketAddr>().unwrap());
    }
}
