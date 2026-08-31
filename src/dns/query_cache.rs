//! Process-client DNS question cache matching sing-box's default
//! `independent_cache=false` behaviour.
//!
//! Entries are keyed only by the DNS question. The selected policy graph,
//! upstream tag, and transport deliberately do not participate in the key.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use hickory_resolver::net::NetError;
use hickory_resolver::proto::rr::Name;
use lru::LruCache;
use parking_lot::Mutex;
use tokio::sync::watch;

use crate::address::NetLocation;
use crate::dns::parsed::IpStrategy;
use crate::resolver::Resolver;

/// sing-box's default cache capacity when the panel does not override it.
pub const DNS_QUERY_CACHE_CAPACITY: usize = 1024;

/// Address record types observable through Shoes' `Resolver` API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsQuestionType {
    A,
    Aaaa,
}

/// A DNS cache key. This intentionally contains no transport or resolver tag.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsQuestion {
    /// FQDN wire spelling with original ASCII case retained. Hickory `Name`
    /// compares case-insensitively, while Go's comparable `dns.Question`
    /// string key does not.
    pub name: Arc<str>,
    pub record_type: DnsQuestionType,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DnsInflightKey {
    generation: u64,
    question: DnsQuestion,
    transport: Arc<str>,
}

#[derive(Debug)]
struct DnsInflightSignal {
    completed: watch::Receiver<bool>,
}

impl DnsInflightSignal {
    async fn wait(&self) {
        let mut completed = self.completed.clone();
        if *completed.borrow() {
            return;
        }
        let _ = completed.changed().await;
    }
}

enum DnsQuestionFlight {
    Leader(DnsQuestionLeader),
    Follower(Arc<DnsInflightSignal>),
}

impl DnsQuestion {
    pub fn new(name: impl Into<Arc<str>>, record_type: DnsQuestionType) -> Self {
        Self {
            name: name.into(),
            record_type,
        }
    }
}

/// Cacheable outcomes from sing-box's address lookup path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsCachedOutcome {
    /// `NOERROR`, including a cacheable empty/NODATA response.
    Success(Arc<[IpAddr]>),
    /// `NXDOMAIN` is the only failure RCODE cached by Go's `Client.Exchange`.
    NxDomain,
}

/// Per-query controls applied in the same order as sing-box `Client.Lookup`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DnsCachePolicy {
    pub disable_cache: bool,
    pub rewrite_ttl: Option<u32>,
    pub client_subnet: bool,
}

/// A transport response reduced to the address lookup surface while retaining
/// the effective DNS lifetime and a cold-path semantic error, if any.
pub struct DnsExchangeResponse {
    outcome: DnsCachedOutcome,
    ttl: Duration,
    response_error: Option<io::Error>,
}

impl DnsExchangeResponse {
    pub fn success(addresses: impl Into<Arc<[IpAddr]>>, ttl: Duration) -> Self {
        Self {
            outcome: DnsCachedOutcome::Success(addresses.into()),
            ttl,
            response_error: None,
        }
    }

    pub fn nx_domain(ttl: Duration, error: io::Error) -> Self {
        Self {
            outcome: DnsCachedOutcome::NxDomain,
            ttl,
            response_error: Some(error),
        }
    }

    pub(crate) fn into_result(self) -> io::Result<Arc<[IpAddr]>> {
        match self.outcome {
            DnsCachedOutcome::Success(addresses) => Ok(addresses),
            DnsCachedOutcome::NxDomain => Err(self.response_error.unwrap_or_else(nx_domain_error)),
        }
    }

    #[cfg(test)]
    pub(crate) fn ttl_for_test(&self) -> Duration {
        self.ttl
    }
}

#[derive(Debug)]
struct CachedNxDomain;

impl std::fmt::Display for CachedNxDomain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("cached DNS response code NXDOMAIN")
    }
}

impl std::error::Error for CachedNxDomain {}

fn nx_domain_error() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, CachedNxDomain)
}

/// Classify both a cold Hickory NXDOMAIN and its warm shared-cache replay as
/// the same terminal DNS outcome.
pub fn is_dns_nx_domain_error(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|source| {
        source.is::<CachedNxDomain>()
            || source
                .downcast_ref::<NetError>()
                .is_some_and(NetError::is_nx_domain)
    })
}

fn cached_outcome_result(outcome: DnsCachedOutcome) -> io::Result<Arc<[IpAddr]>> {
    match outcome {
        DnsCachedOutcome::Success(addresses) => Ok(addresses),
        DnsCachedOutcome::NxDomain => Err(nx_domain_error()),
    }
}

#[derive(Debug, Clone)]
struct DnsCacheEntry {
    outcome: DnsCachedOutcome,
    expires_at: Instant,
}

#[derive(Debug)]
struct DnsQueryCacheInner {
    generation: u64,
    entries: LruCache<DnsQuestion, DnsCacheEntry>,
}

/// Shared cache for one committed DNS client generation.
///
/// `clear_generation` rotates the logical Go DNS-client generation without
/// replacing resolver graphs. This lets no-drop policy state survive reloads
/// while cached DNS answers do not.
#[derive(Debug)]
pub struct DnsQueryCache {
    inner: Mutex<DnsQueryCacheInner>,
    inflight: DashMap<DnsInflightKey, Arc<DnsInflightSignal>>,
}

impl Default for DnsQueryCache {
    fn default() -> Self {
        Self::with_capacity(DNS_QUERY_CACHE_CAPACITY)
    }
}

impl DnsQueryCache {
    fn with_capacity(capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity).expect("DNS cache capacity must be non-zero");
        Self {
            inner: Mutex::new(DnsQueryCacheInner {
                generation: 0,
                entries: LruCache::new(capacity),
            }),
            inflight: DashMap::new(),
        }
    }

    /// Load a live cache entry and refresh its LRU position.
    pub fn load(&self, question: &DnsQuestion) -> Option<DnsCachedOutcome> {
        let generation = self.generation();
        self.load_if_generation(question, generation)
    }

    fn load_if_generation(
        &self,
        question: &DnsQuestion,
        expected_generation: u64,
    ) -> Option<DnsCachedOutcome> {
        let now = Instant::now();
        let mut inner = self.inner.lock();
        if inner.generation != expected_generation {
            return None;
        }
        let expired = inner
            .entries
            .peek(question)
            .is_some_and(|entry| now >= entry.expires_at);
        if expired {
            inner.entries.pop(question);
            return None;
        }
        inner
            .entries
            .get(question)
            .map(|entry| entry.outcome.clone())
    }

    /// Store a response for its effective TTL. Go deliberately skips TTL zero.
    pub fn store(&self, question: DnsQuestion, outcome: DnsCachedOutcome, ttl: Duration) {
        let generation = self.generation();
        self.store_if_generation(question, outcome, ttl, generation);
    }

    fn store_if_generation(
        &self,
        question: DnsQuestion,
        outcome: DnsCachedOutcome,
        ttl: Duration,
        expected_generation: u64,
    ) {
        if ttl.is_zero() {
            return;
        }
        let Some(expires_at) = Instant::now().checked_add(ttl) else {
            return;
        };
        let mut inner = self.inner.lock();
        if inner.generation != expected_generation {
            return;
        }
        inner.entries.put(
            question,
            DnsCacheEntry {
                outcome,
                expires_at,
            },
        );
    }

    /// Join Go's per-question single-flight condition. Only the map inserter is
    /// the leader. Followers wait for that leader, re-check the shared cache,
    /// and, if it is still empty, continue without creating another serialized
    /// flight around their own exchange.
    fn begin_question(self: &Arc<Self>, key: DnsInflightKey) -> DnsQuestionFlight {
        match self.inflight.entry(key.clone()) {
            Entry::Occupied(entry) => DnsQuestionFlight::Follower(entry.get().clone()),
            Entry::Vacant(entry) => {
                let (completed, receiver) = watch::channel(false);
                let signal = Arc::new(DnsInflightSignal {
                    completed: receiver,
                });
                entry.insert(signal.clone());
                DnsQuestionFlight::Leader(DnsQuestionLeader {
                    cache: self.clone(),
                    key,
                    signal,
                    completed,
                })
            }
        }
    }

    /// Clear answers only. Policy rule state is intentionally owned elsewhere.
    pub fn clear_generation(&self) -> u64 {
        let mut inner = self.inner.lock();
        inner.entries.clear();
        inner.generation = inner.generation.wrapping_add(1);
        // New-generation misses must not wait on an old DNS client's
        // transport-scoped condition variable.
        self.inflight.clear();
        inner.generation
    }

    pub fn generation(&self) -> u64 {
        self.inner.lock().generation
    }

    /// Resolve one A/AAAA question with Go-compatible read/write ordering.
    ///
    /// `disable_cache` bypasses the entire cache. ECS still reads a warm
    /// ordinary question entry, but a cold ECS exchange never writes one.
    pub async fn resolve<F, Fut>(
        self: &Arc<Self>,
        question: DnsQuestion,
        transport: impl Into<Arc<str>>,
        policy: DnsCachePolicy,
        exchange: F,
    ) -> io::Result<Arc<[IpAddr]>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<DnsExchangeResponse>>,
    {
        let generation = self.generation();
        if policy.disable_cache {
            return exchange().await?.into_result();
        }

        if let Some(hit) = self.load_if_generation(&question, generation) {
            return cached_outcome_result(hit);
        }

        // ECS is non-simple only inside Exchange: Lookup's preceding question
        // cache read still happened, but a miss neither locks nor stores.
        if policy.client_subnet {
            return exchange().await?.into_result();
        }

        let key = DnsInflightKey {
            generation,
            question: question.clone(),
            transport: transport.into(),
        };
        let _leader = match self.begin_question(key) {
            DnsQuestionFlight::Leader(leader) => Some(leader),
            DnsQuestionFlight::Follower(signal) => {
                signal.wait().await;
                None
            }
        };
        if let Some(hit) = self.load_if_generation(&question, generation) {
            return cached_outcome_result(hit);
        }

        let response = exchange().await?;
        let ttl = policy
            .rewrite_ttl
            .map_or(response.ttl, |ttl| Duration::from_secs(u64::from(ttl)));
        self.store_if_generation(question, response.outcome.clone(), ttl, generation);
        response.into_result()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().entries.len()
    }

    #[cfg(test)]
    fn expire(&self, question: &DnsQuestion) {
        if let Some(entry) = self.inner.lock().entries.get_mut(question) {
            entry.expires_at = Instant::now();
        }
    }
}

/// RAII completion signal for the one leader which inserted an inflight key.
/// Dropping the resolve future still wakes every follower.
struct DnsQuestionLeader {
    cache: Arc<DnsQueryCache>,
    key: DnsInflightKey,
    signal: Arc<DnsInflightSignal>,
    completed: watch::Sender<bool>,
}

impl Drop for DnsQuestionLeader {
    fn drop(&mut self) {
        if let Entry::Occupied(entry) = self.cache.inflight.entry(self.key.clone())
            && Arc::ptr_eq(entry.get(), &self.signal)
        {
            entry.remove();
        }
        self.completed.send_replace(true);
    }
}

/// Shared-cache adapter for the platform resolver. The OS API exposes neither
/// wire records nor TTLs. It may consume a warm A/AAAA entry produced by a raw
/// DNS transport, but a cold OS lookup deliberately does not synthesize a TTL
/// or write back. Configured `system` entries use wire-aware transports on
/// supported platforms; this adapter remains only for the implicit default and
/// targets where raw platform DNS discovery is unavailable.
pub(crate) struct SharedNativeResolver {
    cache: Arc<DnsQueryCache>,
    ip_strategy: IpStrategy,
    transport_tag: Arc<str>,
}

impl std::fmt::Debug for SharedNativeResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SharedNativeResolver")
            .field("ip_strategy", &self.ip_strategy)
            .field("transport_tag", &self.transport_tag)
            .finish()
    }
}

impl SharedNativeResolver {
    pub(crate) fn new(
        cache: Arc<DnsQueryCache>,
        ip_strategy: IpStrategy,
        transport_tag: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            cache,
            ip_strategy,
            transport_tag: transport_tag.into(),
        }
    }
}

async fn resolve_native_question(
    cache: Arc<DnsQueryCache>,
    name: Name,
    question_name: Arc<str>,
    question_type: DnsQuestionType,
    transport_tag: Arc<str>,
) -> io::Result<Arc<[IpAddr]>> {
    let question = DnsQuestion::new(question_name, question_type);
    if let Some(hit) = cache.load(&question) {
        return cached_outcome_result(hit);
    }
    let _ = transport_tag;
    Ok(tokio::net::lookup_host((name.to_utf8(), 0))
        .await?
        .map(|address| address.ip())
        .filter(|address| match question_type {
            DnsQuestionType::A => address.is_ipv4(),
            DnsQuestionType::Aaaa => address.is_ipv6(),
        })
        .collect::<Vec<_>>()
        .into())
}

impl Resolver for SharedNativeResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
        if let Some(address) = location.to_socket_addr_nonblocking() {
            return Box::pin(std::future::ready(Ok(vec![address])));
        }
        let name_string = location.address().to_string();
        let question_name: Arc<str> = if name_string.ends_with('.') {
            Arc::from(name_string.as_str())
        } else {
            Arc::from(format!("{name_string}."))
        };
        let mut name = match Name::from_utf8(&name_string) {
            Ok(name) => name,
            Err(error) => {
                return Box::pin(std::future::ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    error,
                ))));
            }
        };
        name.set_fqdn(true);
        let port = location.port();
        let cache = self.cache.clone();
        let transport_tag = self.transport_tag.clone();
        let strategy = self.ip_strategy;

        Box::pin(async move {
            let query = |question_type| {
                resolve_native_question(
                    cache.clone(),
                    name.clone(),
                    question_name.clone(),
                    question_type,
                    transport_tag.clone(),
                )
            };
            let mut addresses = match strategy {
                IpStrategy::Ipv4Only => query(DnsQuestionType::A).await?.to_vec(),
                IpStrategy::Ipv6Only => query(DnsQuestionType::Aaaa).await?.to_vec(),
                IpStrategy::Ipv4AndIpv6 | IpStrategy::Ipv6AndIpv4 => {
                    let (ipv4, ipv6) =
                        tokio::join!(query(DnsQuestionType::A), query(DnsQuestionType::Aaaa));
                    let mut addresses = Vec::new();
                    let mut first_error = None;
                    let mut append = |result: io::Result<Arc<[IpAddr]>>| match result {
                        Ok(result) => addresses.extend_from_slice(&result),
                        Err(error) => {
                            first_error.get_or_insert(error);
                        }
                    };
                    if matches!(strategy, IpStrategy::Ipv6AndIpv4) {
                        append(ipv6);
                        append(ipv4);
                    } else {
                        append(ipv4);
                        append(ipv6);
                    }
                    if addresses.is_empty()
                        && let Some(error) = first_error
                    {
                        return Err(error);
                    }
                    addresses
                }
                IpStrategy::Ipv4ThenIpv6 | IpStrategy::Ipv6ThenIpv4 => {
                    let (first, second) = if matches!(strategy, IpStrategy::Ipv6ThenIpv4) {
                        (DnsQuestionType::Aaaa, DnsQuestionType::A)
                    } else {
                        (DnsQuestionType::A, DnsQuestionType::Aaaa)
                    };
                    match query(first).await {
                        Ok(addresses) if !addresses.is_empty() => addresses.to_vec(),
                        first_result => match query(second).await {
                            Ok(addresses) if !addresses.is_empty() => addresses.to_vec(),
                            Ok(_) => first_result?.to_vec(),
                            Err(error) => match first_result {
                                Ok(_) => return Err(error),
                                Err(first_error) => return Err(first_error),
                            },
                        },
                    }
                }
            };
            addresses.retain(|address| !address.is_unspecified());
            if addresses.is_empty() {
                return Err(io::Error::other(format!(
                    "native DNS lookup returned no addresses for {name_string}"
                )));
            }
            Ok(addresses
                .into_iter()
                .map(|address| SocketAddr::new(address, port))
                .collect())
        })
    }

    fn result_cache_ttl(&self) -> Option<Duration> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::net::{DnsError, NoRecords};
    use hickory_resolver::proto::op::{Query, ResponseCode};
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn question(index: usize) -> DnsQuestion {
        DnsQuestion::new(format!("host-{index}.example."), DnsQuestionType::A)
    }

    #[test]
    fn cache_is_question_only_bounded_and_generation_scoped() {
        let cache = DnsQueryCache::with_capacity(2);
        cache.store(
            question(1),
            DnsCachedOutcome::Success(Arc::from([IpAddr::from([192, 0, 2, 1])])),
            Duration::from_secs(60),
        );
        cache.store(
            question(2),
            DnsCachedOutcome::NxDomain,
            Duration::from_secs(60),
        );
        assert!(cache.load(&question(1)).is_some());
        cache.store(
            question(3),
            DnsCachedOutcome::Success(Arc::from([IpAddr::from([192, 0, 2, 3])])),
            Duration::from_secs(60),
        );
        assert_eq!(cache.len(), 2);
        assert!(cache.load(&question(2)).is_none(), "LRU entry was evicted");

        assert_eq!(cache.clear_generation(), 1);
        assert_eq!(cache.generation(), 1);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn zero_ttl_is_not_cached() {
        let cache = DnsQueryCache::default();
        cache.store(question(1), DnsCachedOutcome::NxDomain, Duration::ZERO);
        assert!(cache.load(&question(1)).is_none());
    }

    #[test]
    fn question_cache_preserves_go_case_sensitive_name_identity() {
        let cache = DnsQueryCache::default();
        let upper = DnsQuestion::new("Example.COM.", DnsQuestionType::A);
        let lower = DnsQuestion::new("example.com.", DnsQuestionType::A);
        assert_ne!(upper, lower);
        cache.store(upper, DnsCachedOutcome::NxDomain, Duration::from_secs(60));
        assert!(cache.load(&lower).is_none());
    }

    #[tokio::test]
    async fn question_flight_leader_notifies_followers_then_is_pruned() {
        let cache = Arc::new(DnsQueryCache::default());
        let key = DnsInflightKey {
            generation: cache.generation(),
            question: question(1),
            transport: Arc::from("transport-a"),
        };
        let DnsQuestionFlight::Leader(leader) = cache.begin_question(key.clone()) else {
            panic!("the first caller must lead the flight");
        };
        let DnsQuestionFlight::Follower(follower) = cache.begin_question(key) else {
            panic!("the second caller must follow the existing flight");
        };
        assert_eq!(cache.inflight.len(), 1);
        let waiter = tokio::spawn(async move { follower.wait().await });
        drop(leader);
        tokio::time::timeout(Duration::from_millis(100), waiter)
            .await
            .expect("leader completion wakes the follower")
            .unwrap();
        assert!(cache.inflight.is_empty());
    }

    #[test]
    fn singleflight_is_transport_scoped_while_answers_are_not() {
        let cache = Arc::new(DnsQueryCache::default());
        let question = question(1);
        let generation = cache.generation();
        let first = cache.begin_question(DnsInflightKey {
            generation,
            question: question.clone(),
            transport: Arc::from("transport-a"),
        });
        let second = cache.begin_question(DnsInflightKey {
            generation,
            question,
            transport: Arc::from("transport-b"),
        });
        assert!(matches!(&first, DnsQuestionFlight::Leader(_)));
        assert!(matches!(&second, DnsQuestionFlight::Leader(_)));
        assert_eq!(cache.inflight.len(), 2);
        drop((first, second));
        assert!(cache.inflight.is_empty());
    }

    #[tokio::test]
    async fn followers_with_no_cached_leader_result_exchange_concurrently() {
        let cache = Arc::new(DnsQueryCache::default());
        let question = question(1);
        let inflight_key = DnsInflightKey {
            generation: cache.generation(),
            question: question.clone(),
            transport: Arc::from("transport-a"),
        };
        let (leader_started_tx, leader_started_rx) = tokio::sync::oneshot::channel();
        let (release_leader_tx, release_leader_rx) = tokio::sync::oneshot::channel();
        let leader_cache = cache.clone();
        let leader_question = question.clone();
        let leader = tokio::spawn(async move {
            leader_cache
                .resolve(
                    leader_question,
                    "transport-a",
                    DnsCachePolicy::default(),
                    || async move {
                        let _ = leader_started_tx.send(());
                        let _ = release_leader_rx.await;
                        Ok(DnsExchangeResponse::success(
                            [IpAddr::from([192, 0, 2, 1])],
                            Duration::ZERO,
                        ))
                    },
                )
                .await
        });
        leader_started_rx.await.unwrap();

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let mut followers = Vec::new();
        for octet in [2, 3] {
            let follower_cache = cache.clone();
            let follower_question = question.clone();
            let barrier = barrier.clone();
            followers.push(tokio::spawn(async move {
                follower_cache
                    .resolve(
                        follower_question,
                        "transport-a",
                        DnsCachePolicy::default(),
                        || async move {
                            barrier.wait().await;
                            Ok(DnsExchangeResponse::success(
                                [IpAddr::from([192, 0, 2, octet])],
                                Duration::ZERO,
                            ))
                        },
                    )
                    .await
            }));
        }

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let participants = cache
                    .inflight
                    .get(&inflight_key)
                    .map_or(0, |signal| Arc::strong_count(signal.value()));
                if participants >= 4 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both callers must join the leader before it is released");

        release_leader_tx.send(()).unwrap();
        leader.await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            for follower in followers {
                follower.await.unwrap().unwrap();
            }
        })
        .await
        .expect("cache-missing followers must exchange outside the completed flight");
        assert!(cache.inflight.is_empty());
    }

    #[tokio::test]
    async fn answer_cache_hits_across_resolver_graphs_and_transports() {
        let cache = Arc::new(DnsQueryCache::default());
        let key = question(1);
        let calls = AtomicUsize::new(0);
        let expected = IpAddr::from([192, 0, 2, 1]);
        cache
            .resolve(
                key.clone(),
                "source-a",
                DnsCachePolicy::default(),
                || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(DnsExchangeResponse::success(
                        [expected],
                        Duration::from_secs(60),
                    ))
                },
            )
            .await
            .unwrap();
        let hit = cache
            .resolve(
                key,
                "different-source-and-graph",
                DnsCachePolicy::default(),
                || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(DnsExchangeResponse::success(
                        [IpAddr::from([203, 0, 113, 9])],
                        Duration::from_secs(60),
                    ))
                },
            )
            .await
            .unwrap();
        assert_eq!(&*hit, &[expected]);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn native_cold_lookup_does_not_synthesize_ttl_or_write_cache() {
        let cache = Arc::new(DnsQueryCache::default());
        let question_name: Arc<str> = Arc::from("localhost.");
        let question = DnsQuestion::new(question_name.clone(), DnsQuestionType::A);

        let result = resolve_native_question(
            cache.clone(),
            // Keep the cache key canonical, but exercise the OS hosts lookup with
            // the non-FQDN spelling present in every platform's hosts file. A
            // trailing dot deliberately bypasses `/etc/hosts` on some libc/NSS
            // configurations and would make this cache test depend on external DNS.
            Name::from_str("localhost").unwrap(),
            question_name,
            DnsQuestionType::A,
            Arc::from("system"),
        )
        .await
        .unwrap();

        assert!(
            !result.is_empty(),
            "localhost must have an IPv4 hosts entry"
        );
        assert!(
            cache.load(&question).is_none(),
            "getaddrinfo exposes no wire TTL and must not populate the shared cache"
        );
    }

    #[tokio::test]
    async fn pre_reload_exchange_cannot_store_into_the_new_generation() {
        let cache = Arc::new(DnsQueryCache::default());
        let key = question(1);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let task_cache = cache.clone();
        let task_key = key.clone();
        let task = tokio::spawn(async move {
            task_cache
                .resolve(
                    task_key,
                    "transport-a",
                    DnsCachePolicy::default(),
                    || async move {
                        let _ = started_tx.send(());
                        let _ = release_rx.await;
                        Ok(DnsExchangeResponse::success(
                            [IpAddr::from([192, 0, 2, 1])],
                            Duration::from_secs(60),
                        ))
                    },
                )
                .await
        });
        started_rx.await.unwrap();
        assert_eq!(cache.clear_generation(), 1);
        release_tx.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert!(cache.load(&key).is_none());
    }

    #[tokio::test]
    async fn ecs_reads_warm_cache_but_cold_exchange_does_not_store() {
        let cache = Arc::new(DnsQueryCache::default());
        let key = question(1);
        let warm = IpAddr::from([192, 0, 2, 1]);
        cache.store(
            key.clone(),
            DnsCachedOutcome::Success(Arc::from([warm])),
            Duration::from_secs(60),
        );
        let calls = AtomicUsize::new(0);
        let hit = cache
            .resolve(
                key.clone(),
                "transport-a",
                DnsCachePolicy {
                    client_subnet: true,
                    ..DnsCachePolicy::default()
                },
                || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(DnsExchangeResponse::success(
                        [IpAddr::from([203, 0, 113, 1])],
                        Duration::from_secs(60),
                    ))
                },
            )
            .await
            .unwrap();
        assert_eq!(&*hit, &[warm]);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let cold_key = question(2);
        cache
            .resolve(
                cold_key.clone(),
                "transport-a",
                DnsCachePolicy {
                    client_subnet: true,
                    ..DnsCachePolicy::default()
                },
                || async {
                    Ok(DnsExchangeResponse::success(
                        [IpAddr::from([203, 0, 113, 2])],
                        Duration::from_secs(60),
                    ))
                },
            )
            .await
            .unwrap();
        assert!(cache.load(&cold_key).is_none());
    }

    #[tokio::test]
    async fn disable_cache_bypasses_reads_and_writes() {
        let cache = Arc::new(DnsQueryCache::default());
        let key = question(1);
        cache.store(
            key.clone(),
            DnsCachedOutcome::Success(Arc::from([IpAddr::from([192, 0, 2, 1])])),
            Duration::from_secs(60),
        );
        let fresh = IpAddr::from([203, 0, 113, 1]);
        let result = cache
            .resolve(
                key.clone(),
                "transport-a",
                DnsCachePolicy {
                    disable_cache: true,
                    ..DnsCachePolicy::default()
                },
                || async {
                    Ok(DnsExchangeResponse::success(
                        [fresh],
                        Duration::from_secs(60),
                    ))
                },
            )
            .await
            .unwrap();
        assert_eq!(&*result, &[fresh]);
        assert_eq!(
            cache.load(&key),
            Some(DnsCachedOutcome::Success(Arc::from([IpAddr::from([
                192, 0, 2, 1
            ])])))
        );
    }

    #[tokio::test]
    async fn rewrite_ttl_caches_nxdomain_but_other_rcodes_are_not_responses() {
        let cache = Arc::new(DnsQueryCache::default());
        let nx_key = question(1);
        let policy = DnsCachePolicy {
            rewrite_ttl: Some(60),
            ..DnsCachePolicy::default()
        };
        assert_eq!(
            cache
                .resolve(nx_key.clone(), "transport-a", policy, || async {
                    Ok(DnsExchangeResponse::nx_domain(
                        Duration::ZERO,
                        io::Error::new(io::ErrorKind::NotFound, "NXDOMAIN"),
                    ))
                })
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(cache.load(&nx_key), Some(DnsCachedOutcome::NxDomain));

        for index in 2..=4 {
            let key = question(index);
            let error = cache
                .resolve(key.clone(), "transport-a", policy, || async {
                    Err(io::Error::other("SERVFAIL/REFUSED/FORMERR"))
                })
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Other);
            assert!(cache.load(&key).is_none());
        }
    }

    #[tokio::test]
    async fn rewrite_ttl_controls_cold_store_but_does_not_rewrite_a_warm_hit() {
        let cache = Arc::new(DnsQueryCache::default());
        let key = question(1);
        let calls = AtomicUsize::new(0);
        cache
            .resolve(
                key.clone(),
                "source-a",
                DnsCachePolicy {
                    rewrite_ttl: Some(60),
                    ..DnsCachePolicy::default()
                },
                || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(DnsExchangeResponse::success(
                        [IpAddr::from([192, 0, 2, 1])],
                        Duration::ZERO,
                    ))
                },
            )
            .await
            .unwrap();
        assert!(
            cache.load(&key).is_some(),
            "rewrite TTL made a zero-TTL response cacheable"
        );

        cache
            .resolve(
                key.clone(),
                "source-a",
                DnsCachePolicy {
                    rewrite_ttl: Some(0),
                    ..DnsCachePolicy::default()
                },
                || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(DnsExchangeResponse::success(
                        [IpAddr::from([203, 0, 113, 1])],
                        Duration::ZERO,
                    ))
                },
            )
            .await
            .unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "warm reads precede RewriteTTL"
        );

        cache.expire(&key);
        cache
            .resolve(
                key.clone(),
                "source-a",
                DnsCachePolicy {
                    rewrite_ttl: Some(0),
                    ..DnsCachePolicy::default()
                },
                || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(DnsExchangeResponse::success(
                        [IpAddr::from([203, 0, 113, 1])],
                        Duration::from_secs(600),
                    ))
                },
            )
            .await
            .unwrap();
        assert!(
            cache.load(&key).is_none(),
            "cold RewriteTTL=0 must skip store"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn cold_and_warm_nxdomain_are_both_classifiable_terminal_outcomes() {
        let query = Query::query(
            Name::from_str("missing.example.").unwrap(),
            hickory_resolver::proto::rr::RecordType::A,
        );
        let cold = io::Error::new(
            io::ErrorKind::NotFound,
            NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(
                query,
                ResponseCode::NXDomain,
            ))),
        );
        assert!(is_dns_nx_domain_error(&cold));

        let warm = cached_outcome_result(DnsCachedOutcome::NxDomain).unwrap_err();
        assert!(is_dns_nx_domain_error(&warm));
        assert_eq!(cold.kind(), warm.kind());
    }
}
