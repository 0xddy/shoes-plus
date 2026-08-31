//! Policy-aware DNS resolution.
//!
//! [`PolicyResolver`] selects an upstream resolver (or a local terminal action)
//! from the first hostname rule that matches. The implementation is deliberately
//! independent from configuration parsing so callers can resolve DNS server tags
//! first and then construct an immutable, cheaply shared resolver.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use regex::{Regex, RegexBuilder};

use crate::address::NetLocation;
use crate::dns::query_cache::DnsQueryCache;
use crate::resolver::Resolver;
use crate::routing::predicate::{
    RouteContext, RouteMatchConfig, RoutePredicate, RouteRuleSetConfig,
};

/// Engine-owned mutable state shared by DNS policy graphs.
///
/// Rule windows and the question cache are strongly retained for one committed
/// Go DNS-client generation. This preserves the reject flood window across an
/// inbound remove/add gap. A full DNS-client rotation clears both kinds of
/// state before the replacement policy graph is built.
#[derive(Debug)]
pub struct PolicyStateRegistry {
    reject_flood: Mutex<HashMap<PolicyRuleStateIdentity, Arc<RejectFloodState>>>,
    /// The Arc itself is generation-scoped. Old resolver graphs retain their
    /// old cache exactly like a retiring Go Box retains its Client/LRU, while
    /// replacement graphs clone the newly published empty cache.
    query_cache: Mutex<Arc<DnsQueryCache>>,
    generation: AtomicU64,
}

impl Default for PolicyStateRegistry {
    fn default() -> Self {
        Self {
            reject_flood: Mutex::new(HashMap::new()),
            query_cache: Mutex::new(Arc::new(DnsQueryCache::default())),
            generation: AtomicU64::new(0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PolicyRuleStateIdentity {
    /// Stable identity supplied by the trusted topology compiler.
    stable_key: String,
    /// Canonical compiled matcher bytes. Including these prevents an arbitrary
    /// Shoes config from making a different rule collide merely by copying an
    /// internal stable key.
    matcher: Vec<u8>,
}

#[derive(Debug, Default)]
struct RejectFloodState {
    attempts: Mutex<VecDeque<Instant>>,
}

impl PolicyStateRegistry {
    pub(crate) fn query_cache(&self) -> Arc<DnsQueryCache> {
        self.query_cache.lock().clone()
    }

    /// Rotate the Go DNS-client generation. Full Box/DNS-client rebuilds create
    /// fresh rule actions in Go, so both cached answers and reject flood windows
    /// are reset at this boundary.
    pub fn rotate_dns_client_generation(&self) -> u64 {
        self.reject_flood.lock().clear();
        *self.query_cache.lock() = Arc::new(DnsQueryCache::default());
        self.generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1)
    }

    pub fn query_cache_generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn reject_flood_state(&self, stable_key: &str, matcher: Vec<u8>) -> Arc<RejectFloodState> {
        let identity = PolicyRuleStateIdentity {
            stable_key: stable_key.to_string(),
            matcher,
        };
        let mut states = self.reject_flood.lock();
        if let Some(state) = states.get(&identity) {
            return state.clone();
        }
        let state = Arc::new(RejectFloodState::default());
        states.insert(identity, state.clone());
        state
    }

    #[cfg(test)]
    fn retained_identity_count(&self) -> usize {
        self.reject_flood.lock().len()
    }

    #[cfg(test)]
    fn live_state_count(&self) -> usize {
        self.reject_flood
            .lock()
            .values()
            .filter(|state| Arc::strong_count(state) > 1)
            .count()
    }
}

/// DNS response codes accepted by miekg/dns for sing-box's predefined action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRcode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    YxDomain,
    YxRrset,
    NxRrset,
    NotAuth,
    NotZone,
    DsoTypeNi,
    BadSig,
    BadKey,
    BadTime,
    BadMode,
    BadName,
    BadAlg,
    BadTrunc,
    BadCookie,
}

impl DnsRcode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            // An omitted field deserializes to the empty string and means the
            // DNS success code in both ACP compilers.
            "" | "NOERROR" => Some(Self::NoError),
            "FORMERR" => Some(Self::FormErr),
            "SERVFAIL" => Some(Self::ServFail),
            "NXDOMAIN" => Some(Self::NxDomain),
            "NOTIMP" | "NOTIMPL" => Some(Self::NotImp),
            "REFUSED" => Some(Self::Refused),
            "YXDOMAIN" => Some(Self::YxDomain),
            "YXRRSET" => Some(Self::YxRrset),
            "NXRRSET" => Some(Self::NxRrset),
            "NOTAUTH" => Some(Self::NotAuth),
            "NOTZONE" => Some(Self::NotZone),
            "DSOTYPENI" => Some(Self::DsoTypeNi),
            "BADSIG" => Some(Self::BadSig),
            "BADKEY" => Some(Self::BadKey),
            "BADTIME" => Some(Self::BadTime),
            "BADMODE" => Some(Self::BadMode),
            "BADNAME" => Some(Self::BadName),
            "BADALG" => Some(Self::BadAlg),
            "BADTRUNC" => Some(Self::BadTrunc),
            "BADCOOKIE" => Some(Self::BadCookie),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoError => "NOERROR",
            Self::FormErr => "FORMERR",
            Self::ServFail => "SERVFAIL",
            Self::NxDomain => "NXDOMAIN",
            Self::NotImp => "NOTIMP",
            Self::Refused => "REFUSED",
            Self::YxDomain => "YXDOMAIN",
            Self::YxRrset => "YXRRSET",
            Self::NxRrset => "NXRRSET",
            Self::NotAuth => "NOTAUTH",
            Self::NotZone => "NOTZONE",
            Self::DsoTypeNi => "DSOTYPENI",
            Self::BadSig => "BADSIG",
            Self::BadKey => "BADKEY",
            Self::BadTime => "BADTIME",
            Self::BadMode => "BADMODE",
            Self::BadName => "BADNAME",
            Self::BadAlg => "BADALG",
            Self::BadTrunc => "BADTRUNC",
            Self::BadCookie => "BADCOOKIE",
        }
    }
}

impl fmt::Display for DnsRcode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Reject behavior supported by sing-box's DNS lookup path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRejectMethod {
    Default,
    Drop,
}

impl DnsRejectMethod {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "default" => Some(Self::Default),
            "drop" => Some(Self::Drop),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Drop => "drop",
        }
    }
}

impl fmt::Display for DnsRejectMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The typed terminal failure selected by a DNS policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPolicyFailure {
    ResponseCode(DnsRcode),
    Rejected(DnsRejectMethod),
}

/// An address-resolver error that preserves DNS policy semantics for callers
/// which need to distinguish the original RCODE and an explicit drop.
#[derive(Debug)]
pub struct DnsPolicyError {
    hostname: String,
    failure: DnsPolicyFailure,
}

impl DnsPolicyError {
    pub fn failure(&self) -> DnsPolicyFailure {
        self.failure
    }

    fn response_code(hostname: String, rcode: DnsRcode) -> Self {
        debug_assert_ne!(rcode, DnsRcode::NoError);
        Self {
            hostname,
            failure: DnsPolicyFailure::ResponseCode(rcode),
        }
    }

    fn rejected(hostname: String, method: DnsRejectMethod) -> Self {
        Self {
            hostname,
            failure: DnsPolicyFailure::Rejected(method),
        }
    }

    fn into_io_error(self) -> io::Error {
        let kind = match self.failure {
            DnsPolicyFailure::ResponseCode(DnsRcode::NoError) => {
                unreachable!("NOERROR is not a DNS policy failure")
            }
            DnsPolicyFailure::ResponseCode(DnsRcode::NxDomain) => io::ErrorKind::NotFound,
            DnsPolicyFailure::ResponseCode(DnsRcode::Refused) | DnsPolicyFailure::Rejected(_) => {
                io::ErrorKind::PermissionDenied
            }
            DnsPolicyFailure::ResponseCode(_) => io::ErrorKind::Other,
        };
        io::Error::new(kind, self)
    }
}

impl fmt::Display for DnsPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.failure {
            DnsPolicyFailure::ResponseCode(rcode) => {
                write!(
                    formatter,
                    "DNS policy returned {rcode} for {}",
                    self.hostname
                )
            }
            DnsPolicyFailure::Rejected(DnsRejectMethod::Default) => {
                write!(formatter, "DNS policy rejected {}", self.hostname)
            }
            DnsPolicyFailure::Rejected(DnsRejectMethod::Drop) => {
                write!(formatter, "DNS policy dropped lookup for {}", self.hostname)
            }
        }
    }
}

impl std::error::Error for DnsPolicyError {}

/// Validated predefined response projected onto the address-only lookup path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPredefinedResponse {
    pub rcode: DnsRcode,
    pub addresses: Vec<IpAddr>,
}

impl DnsPredefinedResponse {
    pub fn new(rcode: DnsRcode, addresses: Vec<IpAddr>) -> Self {
        Self { rcode, addresses }
    }

    pub fn no_error(addresses: Vec<IpAddr>) -> Self {
        Self::new(DnsRcode::NoError, addresses)
    }
}

/// Conservative defaults for panel-provided DNS policy.
///
/// Rust's regex engine has linear-time matching, while its compiled programs can
/// still consume meaningful memory. These limits bound both the number of
/// programs and their individual compiled size before a policy becomes live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyLimits {
    pub max_rules: usize,
    pub max_patterns_per_rule: usize,
    pub max_total_patterns: usize,
    pub max_regex_patterns: usize,
    pub max_pattern_bytes: usize,
    pub max_total_pattern_bytes: usize,
    pub max_predefined_addresses_per_rule: usize,
    pub regex_size_limit: usize,
    pub regex_dfa_size_limit: usize,
}

impl Default for PolicyLimits {
    fn default() -> Self {
        Self {
            max_rules: 4_096,
            max_patterns_per_rule: 256,
            max_total_patterns: 16_384,
            max_regex_patterns: 512,
            max_pattern_bytes: 4_096,
            max_total_pattern_bytes: 4 * 1_024 * 1_024,
            max_predefined_addresses_per_rule: 256,
            regex_size_limit: 1_024 * 1_024,
            regex_dfa_size_limit: 2 * 1_024 * 1_024,
        }
    }
}

impl PolicyLimits {
    fn validate(self) -> io::Result<Self> {
        let non_zero = [
            ("max_rules", self.max_rules),
            ("max_patterns_per_rule", self.max_patterns_per_rule),
            ("max_total_patterns", self.max_total_patterns),
            ("max_regex_patterns", self.max_regex_patterns),
            ("max_pattern_bytes", self.max_pattern_bytes),
            ("max_total_pattern_bytes", self.max_total_pattern_bytes),
            (
                "max_predefined_addresses_per_rule",
                self.max_predefined_addresses_per_rule,
            ),
            ("regex_size_limit", self.regex_size_limit),
            ("regex_dfa_size_limit", self.regex_dfa_size_limit),
        ];
        if let Some((name, _)) = non_zero.into_iter().find(|(_, value)| *value == 0) {
            return Err(invalid_policy(format!(
                "policy limit {name} must be non-zero"
            )));
        }
        if self.max_patterns_per_rule > self.max_total_patterns {
            return Err(invalid_policy(
                "max_patterns_per_rule must not exceed max_total_patterns",
            ));
        }
        Ok(self)
    }
}

/// Terminal action selected by a DNS policy rule.
#[derive(Clone)]
pub enum PolicyAction {
    /// Resolve through the referenced upstream.
    Route(Arc<dyn Resolver>),
    /// Refuse the lookup without contacting an upstream.
    Reject(DnsRejectMethod),
    /// Return the configured A/AAAA address subset without contacting an upstream.
    /// An empty set is a successful NOERROR-style empty response.
    Predefined(DnsPredefinedResponse),
}

impl fmt::Debug for PolicyAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Route(resolver) => formatter.debug_tuple("Route").field(resolver).finish(),
            Self::Reject(method) => formatter.debug_tuple("Reject").field(method).finish(),
            Self::Predefined(response) => {
                formatter.debug_tuple("Predefined").field(response).finish()
            }
        }
    }
}

/// Uncompiled rule accepted by [`PolicyResolver::new`].
///
/// Pattern categories are ORed, matching sing-box's destination-domain group.
/// An empty pattern set is a catch-all rule. Rules are evaluated in input order.
#[derive(Debug, Clone)]
pub struct PolicyRuleSpec {
    pub exact: Vec<String>,
    pub suffix: Vec<String>,
    pub keyword: Vec<String>,
    pub regex: Vec<String>,
    /// Prevalidated local rule-set references. RoutePredicate evaluates these
    /// together with the direct hostname category using sing-box match-state
    /// merging (including nested invert semantics).
    pub rule_set: Vec<RouteRuleSetConfig>,
    /// Prevent the default reject action from degrading to drop after more
    /// than 50 matching lookups in sing-box's rolling 30-second window.
    pub no_drop: bool,
    pub action: PolicyAction,
    /// Optional timeout applied only to a matched route resolver call.
    pub timeout: Option<Duration>,
}

impl PolicyRuleSpec {
    pub fn new(action: PolicyAction) -> Self {
        Self {
            exact: Vec::new(),
            suffix: Vec::new(),
            keyword: Vec::new(),
            regex: Vec::new(),
            rule_set: Vec::new(),
            no_drop: false,
            action,
            timeout: None,
        }
    }

    pub fn exact(mut self, values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.exact.extend(values.into_iter().map(Into::into));
        self
    }

    pub fn suffix(mut self, values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.suffix.extend(values.into_iter().map(Into::into));
        self
    }

    pub fn keyword(mut self, values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.keyword.extend(values.into_iter().map(Into::into));
        self
    }

    pub fn regex(mut self, values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.regex.extend(values.into_iter().map(Into::into));
        self
    }

    pub fn rule_set(mut self, values: impl IntoIterator<Item = RouteRuleSetConfig>) -> Self {
        self.rule_set.extend(values);
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = (!timeout.is_zero()).then_some(timeout);
        self
    }

    pub fn no_drop(mut self, no_drop: bool) -> Self {
        self.no_drop = no_drop;
        self
    }
}

/// Immutable resolver that applies ordered hostname policy before its final
/// resolver.
#[derive(Debug)]
pub struct PolicyResolver {
    final_resolver: Arc<dyn Resolver>,
    named_upstreams: HashMap<String, Arc<dyn Resolver>>,
    rules: Box<[PolicyRule]>,
}

impl PolicyResolver {
    pub fn new(final_resolver: Arc<dyn Resolver>, rules: Vec<PolicyRuleSpec>) -> io::Result<Self> {
        Self::with_limits(final_resolver, rules, PolicyLimits::default())
    }

    /// Construct a policy resolver that also exposes its tagged transports for
    /// exact per-dialer resolution. Named lookups bypass hostname policy and do
    /// not mutate the final resolver used by ordinary consumers.
    pub fn with_named_upstreams(
        final_resolver: Arc<dyn Resolver>,
        rules: Vec<PolicyRuleSpec>,
        named_upstreams: impl IntoIterator<Item = (String, Arc<dyn Resolver>)>,
    ) -> io::Result<Self> {
        Self::with_limits_and_named_upstreams(
            final_resolver,
            rules,
            PolicyLimits::default(),
            named_upstreams,
            Vec::new(),
            None,
        )
    }

    /// Construct a policy whose compiler-issued rule identities share mutable
    /// state through an engine-owned registry. The key vector is positional and
    /// must contain one entry per rule; `None` retains the ordinary resolver-local
    /// behavior for that rule.
    pub(crate) fn with_named_upstreams_and_state_registry(
        final_resolver: Arc<dyn Resolver>,
        rules: Vec<PolicyRuleSpec>,
        named_upstreams: impl IntoIterator<Item = (String, Arc<dyn Resolver>)>,
        rule_state_keys: Vec<Option<String>>,
        state_registry: &PolicyStateRegistry,
    ) -> io::Result<Self> {
        Self::with_limits_and_named_upstreams(
            final_resolver,
            rules,
            PolicyLimits::default(),
            named_upstreams,
            rule_state_keys,
            Some(state_registry),
        )
    }

    pub fn with_limits(
        final_resolver: Arc<dyn Resolver>,
        rules: Vec<PolicyRuleSpec>,
        limits: PolicyLimits,
    ) -> io::Result<Self> {
        Self::with_limits_and_named_upstreams(
            final_resolver,
            rules,
            limits,
            std::iter::empty(),
            Vec::new(),
            None,
        )
    }

    fn with_limits_and_named_upstreams(
        final_resolver: Arc<dyn Resolver>,
        rules: Vec<PolicyRuleSpec>,
        limits: PolicyLimits,
        named_upstreams: impl IntoIterator<Item = (String, Arc<dyn Resolver>)>,
        rule_state_keys: Vec<Option<String>>,
        state_registry: Option<&PolicyStateRegistry>,
    ) -> io::Result<Self> {
        let limits = limits.validate()?;
        if rules.len() > limits.max_rules {
            return Err(invalid_policy(format!(
                "DNS policy has {} rules, limit is {}",
                rules.len(),
                limits.max_rules
            )));
        }
        let rule_state_keys = if rule_state_keys.is_empty() {
            vec![None; rules.len()]
        } else if rule_state_keys.len() == rules.len() {
            rule_state_keys
        } else {
            return Err(invalid_policy(format!(
                "DNS policy has {} rules but {} shared-state identities",
                rules.len(),
                rule_state_keys.len()
            )));
        };

        let mut budget = CompileBudget::default();
        let rules = rules
            .into_iter()
            .zip(rule_state_keys)
            .enumerate()
            .map(|(index, (spec, state_key))| {
                PolicyRule::compile(
                    index,
                    spec,
                    limits,
                    &mut budget,
                    state_key.as_deref().zip(state_registry),
                )
            })
            .collect::<io::Result<Vec<_>>>()?;

        let mut named = HashMap::new();
        for (tag, resolver) in named_upstreams {
            if tag.trim().is_empty() || tag.trim() != tag {
                return Err(invalid_policy(
                    "DNS named upstream tags must be non-empty trimmed strings",
                ));
            }
            if named.insert(tag.clone(), resolver).is_some() {
                return Err(invalid_policy(format!(
                    "DNS policy has duplicate named upstream tag {tag:?}"
                )));
            }
        }

        Ok(Self {
            final_resolver,
            named_upstreams: named,
            rules: rules.into_boxed_slice(),
        })
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Resolver for PolicyResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
        if let Some(address) = location.to_socket_addr_nonblocking() {
            return Box::pin(async move { Ok(vec![address]) });
        }

        let hostname = location
            .address()
            .hostname()
            .expect("a non-IP NetLocation must contain a hostname");
        let normalized_hostname = normalize_hostname(hostname);
        let selected = self
            .rules
            .iter()
            .find(|rule| rule.matches(&normalized_hostname, location))
            .map(|rule| (rule.selected_action(), rule.timeout));
        let final_resolver = self.final_resolver.clone();
        let location = location.clone();
        let port = location.port();

        Box::pin(async move {
            match selected {
                Some((PolicyAction::Route(resolver), timeout)) => {
                    let resolve = resolver.resolve_location(&location);
                    let addresses = match timeout {
                        Some(timeout) => tokio::time::timeout(timeout, resolve)
                            .await
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    format!(
                                        "DNS policy route for {normalized_hostname} timed out after {timeout:?}"
                                    ),
                                )
                            })??,
                        None => resolve.await?,
                    };
                    Ok(normalize_result_ports(addresses, port))
                }
                Some((PolicyAction::Reject(method), _)) => {
                    Err(DnsPolicyError::rejected(normalized_hostname, method).into_io_error())
                }
                Some((PolicyAction::Predefined(response), _)) => {
                    match response.rcode {
                        DnsRcode::NoError => Ok(response
                            .addresses
                            .into_iter()
                            .map(|address| SocketAddr::new(address, port))
                            .collect()),
                        rcode => Err(DnsPolicyError::response_code(normalized_hostname, rcode)
                            .into_io_error()),
                    }
                }
                None => Ok(normalize_result_ports(
                    final_resolver.resolve_location(&location).await?,
                    port,
                )),
            }
        })
    }

    fn resolve_location_via(
        &self,
        upstream_tag: &str,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
        if upstream_tag.is_empty() {
            return self.resolve_location(location);
        }
        if let Some(address) = location.to_socket_addr_nonblocking() {
            return Box::pin(async move { Ok(vec![address]) });
        }

        let resolver = self.named_upstreams.get(upstream_tag).cloned();
        let requested_tag = upstream_tag.to_string();
        let location = location.clone();
        let port = location.port();
        Box::pin(async move {
            let resolver = resolver.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("DNS policy references unknown named upstream {requested_tag:?}"),
                )
            })?;
            Ok(normalize_result_ports(
                resolver.resolve_location(&location).await?,
                port,
            ))
        })
    }

    fn result_cache_ttl(&self) -> Option<Duration> {
        let mut effective = self.final_resolver.result_cache_ttl();
        for rule in &self.rules {
            if let PolicyAction::Route(resolver) = &rule.action {
                let ttl = resolver.result_cache_ttl()?;
                effective = Some(effective?.min(ttl));
            }
        }
        effective
    }

    fn result_cache_ttl_for(&self, location: &NetLocation) -> Option<Duration> {
        if location.to_socket_addr_nonblocking().is_some() {
            return Some(Duration::from_secs(60 * 60));
        }
        let hostname = location.address().hostname()?;
        let normalized_hostname = normalize_hostname(hostname);
        match self
            .rules
            .iter()
            .find(|rule| rule.matches(&normalized_hostname, location))
            .map(|rule| &rule.action)
        {
            Some(PolicyAction::Route(resolver)) => resolver.result_cache_ttl_for(location),
            Some(PolicyAction::Reject(_)) => None,
            Some(PolicyAction::Predefined(_)) => Some(Duration::from_secs(60 * 60)),
            None => self.final_resolver.result_cache_ttl_for(location),
        }
    }
}

#[derive(Debug)]
struct PolicyRule {
    exact: Box<[String]>,
    suffix: Box<[String]>,
    keyword: Box<[String]>,
    regex: Box<[Regex]>,
    mixed_rule_set_matcher: Option<RoutePredicate>,
    action: PolicyAction,
    reject_flood: Option<Arc<RejectFloodState>>,
    timeout: Option<Duration>,
}

impl PolicyRule {
    fn compile(
        index: usize,
        spec: PolicyRuleSpec,
        limits: PolicyLimits,
        budget: &mut CompileBudget,
        shared_state: Option<(&str, &PolicyStateRegistry)>,
    ) -> io::Result<Self> {
        let pattern_count = spec
            .exact
            .len()
            .checked_add(spec.suffix.len())
            .and_then(|count| count.checked_add(spec.keyword.len()))
            .and_then(|count| count.checked_add(spec.regex.len()))
            .ok_or_else(|| invalid_policy(format!("dns.rules[{index}] pattern count overflow")))?;
        if pattern_count > limits.max_patterns_per_rule {
            return Err(invalid_policy(format!(
                "dns.rules[{index}] has {pattern_count} patterns, per-rule limit is {}",
                limits.max_patterns_per_rule
            )));
        }
        budget.patterns = budget.patterns.checked_add(pattern_count).ok_or_else(|| {
            invalid_policy(format!("dns.rules[{index}] total pattern count overflow"))
        })?;
        if budget.patterns > limits.max_total_patterns {
            return Err(invalid_policy(format!(
                "DNS policy has {} patterns, total limit is {}",
                budget.patterns, limits.max_total_patterns
            )));
        }

        budget.regex_patterns = budget
            .regex_patterns
            .checked_add(spec.regex.len())
            .ok_or_else(|| invalid_policy("DNS policy regex count overflow"))?;
        if budget.regex_patterns > limits.max_regex_patterns {
            return Err(invalid_policy(format!(
                "DNS policy has {} regex patterns, limit is {}",
                budget.regex_patterns, limits.max_regex_patterns
            )));
        }

        validate_action(index, &spec.action, limits)?;
        if spec.no_drop && !matches!(&spec.action, PolicyAction::Reject(DnsRejectMethod::Default)) {
            return Err(invalid_policy(format!(
                "dns.rules[{index}] no_drop is only valid for the default reject method"
            )));
        }
        if spec.timeout.is_some() && !matches!(&spec.action, PolicyAction::Route(_)) {
            return Err(invalid_policy(format!(
                "dns.rules[{index}] timeout is only valid for route actions"
            )));
        }
        let reject_flood =
            matches!(&spec.action, PolicyAction::Reject(DnsRejectMethod::Default)) && !spec.no_drop;
        if shared_state.is_some() && !reject_flood {
            return Err(invalid_policy(format!(
                "dns.rules[{index}] shared reject state is only valid for default reject without no_drop"
            )));
        }
        let exact = compile_literals(index, "domain", spec.exact, limits, budget, |value| {
            normalize_domain_literal(value, true)
        })?;
        let suffix = compile_literals(
            index,
            "domain_suffix",
            spec.suffix,
            limits,
            budget,
            |value| normalize_domain_literal(value, false),
        )?;
        let keyword = compile_literals(
            index,
            "domain_keyword",
            spec.keyword,
            limits,
            budget,
            str::to_owned,
        )?;
        let matcher_regex = spec.regex.clone();
        let mut regex = Vec::with_capacity(spec.regex.len());
        for (regex_index, pattern) in spec.regex.into_iter().enumerate() {
            account_pattern_bytes(index, "domain_regex", &pattern, limits, budget)?;
            if pattern.is_empty() {
                return Err(invalid_policy(format!(
                    "dns.rules[{index}].domain_regex[{regex_index}] must not be empty"
                )));
            }
            let compiled = RegexBuilder::new(&pattern)
                .size_limit(limits.regex_size_limit)
                .dfa_size_limit(limits.regex_dfa_size_limit)
                .build()
                .map_err(|error| {
                    invalid_policy(format!(
                        "invalid dns.rules[{index}].domain_regex[{regex_index}] {pattern:?}: {error}"
                    ))
                })?;
            regex.push(compiled);
        }
        let shared_matcher = shared_state.map(|_| {
            serde_json::to_vec(&(&exact, &suffix, &keyword, &matcher_regex, &spec.rule_set))
                .expect("validated DNS policy matchers serialize to JSON")
        });
        let mixed_rule_set_matcher = if spec.rule_set.is_empty() {
            None
        } else {
            let matcher = RoutePredicate::compile(&RouteMatchConfig {
                domain: exact.clone(),
                domain_suffix: suffix.clone(),
                domain_keyword: keyword.clone(),
                domain_regex: matcher_regex,
                rule_set: spec.rule_set,
                ..RouteMatchConfig::default()
            })
            .map_err(|error| {
                invalid_policy(format!("invalid dns.rules[{index}].rule_set: {error}"))
            })?;
            if matcher.requires_ip() || matcher.uses_context() || matcher.uses_destination_port() {
                return Err(invalid_policy(format!(
                    "dns.rules[{index}].rule_set requires IP, port, network, or protocol metadata unavailable to DNS hostname lookup"
                )));
            }
            Some(matcher)
        };

        let reject_flood = reject_flood.then(|| {
            if let Some((stable_key, registry)) = shared_state {
                let matcher =
                    shared_matcher.expect("shared state always precomputes a matcher identity");
                registry.reject_flood_state(stable_key, matcher)
            } else {
                Arc::new(RejectFloodState::default())
            }
        });

        Ok(Self {
            exact: exact.into_boxed_slice(),
            suffix: suffix.into_boxed_slice(),
            keyword: keyword.into_boxed_slice(),
            regex: regex.into_boxed_slice(),
            mixed_rule_set_matcher,
            action: spec.action,
            reject_flood,
            timeout: spec.timeout.filter(|timeout| !timeout.is_zero()),
        })
    }

    fn selected_action(&self) -> PolicyAction {
        self.selected_action_at(Instant::now())
    }

    fn selected_action_at(&self, now: Instant) -> PolicyAction {
        let Some(reject_flood) = &self.reject_flood else {
            return self.action.clone();
        };

        let mut attempts = reject_flood.attempts.lock();
        while attempts.front().is_some_and(|attempt| {
            now.saturating_duration_since(*attempt) > Duration::from_secs(30)
        }) {
            attempts.pop_front();
        }
        attempts.push_back(now);
        let should_drop = attempts.len() > 50;
        // Once the threshold is crossed, older retained hits cannot affect any
        // future decision: they expire no later than the newest 51 entries.
        // Keeping only that suffix preserves the rolling-window semantics while
        // bounding memory under a sustained reject flood.
        while attempts.len() > 51 {
            attempts.pop_front();
        }
        if should_drop {
            PolicyAction::Reject(DnsRejectMethod::Drop)
        } else {
            self.action.clone()
        }
    }

    fn matches(&self, hostname: &str, location: &NetLocation) -> bool {
        let catch_all = self.exact.is_empty()
            && self.suffix.is_empty()
            && self.keyword.is_empty()
            && self.regex.is_empty()
            && self.mixed_rule_set_matcher.is_none();
        if let Some(matcher) = &self.mixed_rule_set_matcher {
            matcher.matches(location, None, &RouteContext::default())
        } else {
            catch_all
                || self.exact.iter().any(|pattern| pattern == hostname)
                || self
                    .suffix
                    .iter()
                    .any(|pattern| domain_has_suffix(hostname, pattern))
                || self
                    .keyword
                    .iter()
                    .any(|pattern| hostname.contains(pattern))
                || self.regex.iter().any(|pattern| pattern.is_match(hostname))
        }
    }
}

#[derive(Default)]
struct CompileBudget {
    patterns: usize,
    regex_patterns: usize,
    pattern_bytes: usize,
}

fn compile_literals(
    rule_index: usize,
    field: &str,
    values: Vec<String>,
    limits: PolicyLimits,
    budget: &mut CompileBudget,
    normalize: impl Fn(&str) -> String,
) -> io::Result<Vec<String>> {
    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            account_pattern_bytes(rule_index, field, &value, limits, budget)?;
            let normalized = normalize(&value);
            if normalized.is_empty() {
                return Err(invalid_policy(format!(
                    "dns.rules[{rule_index}].{field}[{index}] must not be empty"
                )));
            }
            Ok(normalized)
        })
        .collect()
}

fn account_pattern_bytes(
    rule_index: usize,
    field: &str,
    value: &str,
    limits: PolicyLimits,
    budget: &mut CompileBudget,
) -> io::Result<()> {
    if value.len() > limits.max_pattern_bytes {
        return Err(invalid_policy(format!(
            "dns.rules[{rule_index}].{field} pattern is {} bytes, limit is {}",
            value.len(),
            limits.max_pattern_bytes
        )));
    }
    budget.pattern_bytes = budget
        .pattern_bytes
        .checked_add(value.len())
        .ok_or_else(|| invalid_policy("DNS policy pattern byte count overflow"))?;
    if budget.pattern_bytes > limits.max_total_pattern_bytes {
        return Err(invalid_policy(format!(
            "DNS policy patterns total {} bytes, limit is {}",
            budget.pattern_bytes, limits.max_total_pattern_bytes
        )));
    }
    Ok(())
}

fn validate_action(index: usize, action: &PolicyAction, limits: PolicyLimits) -> io::Result<()> {
    let PolicyAction::Predefined(response) = action else {
        return Ok(());
    };
    if response.addresses.len() > limits.max_predefined_addresses_per_rule {
        return Err(invalid_policy(format!(
            "dns.rules[{index}] has {} predefined addresses, limit is {}",
            response.addresses.len(),
            limits.max_predefined_addresses_per_rule
        )));
    }
    Ok(())
}

fn normalize_hostname(value: &str) -> String {
    value.trim_end_matches('.').to_lowercase()
}

fn normalize_domain_literal(value: &str, exact: bool) -> String {
    let value = normalize_hostname(value);
    if exact {
        value
    } else {
        value.trim_start_matches('.').to_string()
    }
}

fn domain_has_suffix(hostname: &str, suffix: &str) -> bool {
    hostname == suffix
        || hostname
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn normalize_result_ports(mut addresses: Vec<SocketAddr>, port: u16) -> Vec<SocketAddr> {
    addresses
        .iter_mut()
        .for_each(|address| address.set_port(port));
    addresses
}

fn invalid_policy(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tempfile::NamedTempFile;

    use crate::address::Address;

    use super::*;

    fn source_rule_set(contents: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    #[derive(Debug)]
    struct StaticResolver {
        addresses: Vec<SocketAddr>,
        calls: AtomicUsize,
        result_cache_ttl: Option<Duration>,
    }

    impl StaticResolver {
        fn new(address: IpAddr, returned_port: u16) -> Arc<Self> {
            Arc::new(Self {
                addresses: vec![SocketAddr::new(address, returned_port)],
                calls: AtomicUsize::new(0),
                result_cache_ttl: Some(Duration::from_secs(60 * 60)),
            })
        }

        fn new_with_cache_ttl(
            address: IpAddr,
            returned_port: u16,
            result_cache_ttl: Option<Duration>,
        ) -> Arc<Self> {
            Arc::new(Self {
                addresses: vec![SocketAddr::new(address, returned_port)],
                calls: AtomicUsize::new(0),
                result_cache_ttl,
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl Resolver for StaticResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let addresses = self.addresses.clone();
            Box::pin(async move { Ok(addresses) })
        }

        fn result_cache_ttl(&self) -> Option<Duration> {
            self.result_cache_ttl
        }
    }

    #[derive(Debug)]
    struct SlowResolver {
        delay: Duration,
        address: SocketAddr,
        calls: AtomicUsize,
    }

    impl SlowResolver {
        fn new(delay: Duration, address: SocketAddr) -> Arc<Self> {
            Arc::new(Self {
                delay,
                address,
                calls: AtomicUsize::new(0),
            })
        }
    }

    impl Resolver for SlowResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let delay = self.delay;
            let address = self.address;
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                Ok(vec![address])
            })
        }
    }

    fn location(hostname: &str, port: u16) -> NetLocation {
        NetLocation::new(Address::Hostname(hostname.to_string()), port)
    }

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    #[tokio::test]
    async fn ordered_rules_normalize_hostnames_before_matching() {
        let final_resolver = StaticResolver::new(v4(99), 1);
        let exact = StaticResolver::new(v4(1), 1);
        let suffix = StaticResolver::new(v4(2), 1);
        let keyword = StaticResolver::new(v4(3), 1);
        let regex = StaticResolver::new(v4(4), 1);
        let policy = PolicyResolver::new(
            final_resolver.clone(),
            vec![
                PolicyRuleSpec::new(PolicyAction::Route(exact.clone())).exact(["Exact.Example"]),
                PolicyRuleSpec::new(PolicyAction::Route(suffix.clone())).suffix([".Example.NET"]),
                PolicyRuleSpec::new(PolicyAction::Route(keyword.clone())).keyword(["needle"]),
                PolicyRuleSpec::new(PolicyAction::Route(regex.clone()))
                    .regex([r"^api[0-9]+\.example\.org$"]),
            ],
        )
        .unwrap();

        for (hostname, expected) in [
            ("EXACT.EXAMPLE.", v4(1)),
            ("deep.Example.Net", v4(2)),
            ("has-NEEDLE-here.test", v4(3)),
            ("API42.EXAMPLE.ORG", v4(4)),
            ("unmatched.example", v4(99)),
        ] {
            let resolved = policy
                .resolve_location(&location(hostname, 8443))
                .await
                .unwrap();
            assert_eq!(resolved, vec![SocketAddr::new(expected, 8443)]);
        }
        assert_eq!(exact.calls(), 1);
        assert_eq!(suffix.calls(), 1);
        assert_eq!(keyword.calls(), 1);
        assert_eq!(regex.calls(), 1);
        assert_eq!(final_resolver.calls(), 1);
    }

    #[tokio::test]
    async fn keyword_and_regex_patterns_keep_sing_box_case_semantics() {
        let rule_set =
            source_rule_set(r#"{"version":4,"rules":[{"domain_suffix":["other.example"]}]}"#);
        let final_resolver = StaticResolver::new(v4(99), 0);
        let direct = StaticResolver::new(v4(1), 0);
        let mixed = StaticResolver::new(v4(2), 0);
        let policy = PolicyResolver::new(
            final_resolver.clone(),
            vec![
                PolicyRuleSpec::new(PolicyAction::Route(direct.clone()))
                    .keyword(["NeEdLe"])
                    .regex([r"^API[0-9]+\.example$"]),
                PolicyRuleSpec::new(PolicyAction::Route(mixed.clone()))
                    .keyword(["MiXeD"])
                    .regex([r"^MIXED\.example$"])
                    .rule_set([RouteRuleSetConfig {
                        format: "source".to_string(),
                        path: rule_set.path().to_path_buf(),
                    }]),
            ],
        )
        .unwrap();

        for hostname in [
            "has-needle.example",
            "api42.example",
            "has-mixed.example",
            "mixed.example",
        ] {
            assert_eq!(
                policy
                    .resolve_location(&location(hostname, 53))
                    .await
                    .unwrap(),
                [SocketAddr::new(v4(99), 53)],
                "configured pattern case must remain significant for {hostname}"
            );
        }
        assert_eq!(direct.calls(), 0);
        assert_eq!(mixed.calls(), 0);
        assert_eq!(final_resolver.calls(), 4);
    }

    #[tokio::test]
    async fn named_upstream_bypasses_policy_without_changing_default_resolution() {
        let final_resolver = StaticResolver::new(v4(99), 1);
        let routed = StaticResolver::new(v4(1), 1);
        let named = StaticResolver::new(v4(7), 1);
        let policy = PolicyResolver::with_named_upstreams(
            final_resolver.clone(),
            vec![PolicyRuleSpec::new(PolicyAction::Route(routed.clone())).suffix(["example.com"])],
            [(
                "outbound-dns".to_string(),
                named.clone() as Arc<dyn Resolver>,
            )],
        )
        .unwrap();

        let target = location("api.example.com", 8443);
        assert_eq!(
            policy
                .resolve_location_via("outbound-dns", &target)
                .await
                .unwrap(),
            [SocketAddr::new(v4(7), 8443)]
        );
        assert_eq!(named.calls(), 1);
        assert_eq!(routed.calls(), 0);
        assert_eq!(final_resolver.calls(), 0);

        assert_eq!(
            policy.resolve_location(&target).await.unwrap(),
            [SocketAddr::new(v4(1), 8443)]
        );
        assert_eq!(routed.calls(), 1);

        let error = policy
            .resolve_location_via("missing", &target)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn first_match_wins_and_suffix_requires_a_label_boundary() {
        let final_resolver = StaticResolver::new(v4(99), 53);
        let first = StaticResolver::new(v4(1), 53);
        let second = StaticResolver::new(v4(2), 53);
        let policy = PolicyResolver::new(
            final_resolver.clone(),
            vec![
                PolicyRuleSpec::new(PolicyAction::Route(first.clone())).suffix(["example.com"]),
                PolicyRuleSpec::new(PolicyAction::Route(second.clone())).keyword(["example.com"]),
            ],
        )
        .unwrap();

        let matched = policy
            .resolve_location(&location("www.example.com", 443))
            .await
            .unwrap();
        assert_eq!(matched[0].ip(), v4(1));
        let boundary_miss = policy
            .resolve_location(&location("notexample.com", 443))
            .await
            .unwrap();
        assert_eq!(boundary_miss[0].ip(), v4(2));
        assert_eq!(first.calls(), 1);
        assert_eq!(second.calls(), 1);
        assert_eq!(final_resolver.calls(), 0);
    }

    #[tokio::test]
    async fn matched_route_timeout_is_per_rule_and_reports_timed_out() {
        let final_resolver = StaticResolver::new(v4(99), 1);
        let slow = SlowResolver::new(Duration::from_millis(200), SocketAddr::new(v4(1), 1));
        let policy = PolicyResolver::new(
            final_resolver.clone(),
            vec![
                PolicyRuleSpec::new(PolicyAction::Route(slow.clone()))
                    .exact(["slow.example"])
                    .timeout(Duration::from_millis(10)),
            ],
        )
        .unwrap();

        let error = policy
            .resolve_location(&location("slow.example", 53))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(slow.calls.load(Ordering::Relaxed), 1);
        assert_eq!(final_resolver.calls(), 0);

        // An unmatched query still follows the unwrapped final resolver.
        let resolved = policy
            .resolve_location(&location("fast.example", 5353))
            .await
            .unwrap();
        assert_eq!(resolved, [SocketAddr::new(v4(99), 5353)]);
    }

    #[tokio::test]
    async fn zero_route_timeout_preserves_existing_resolver_behavior() {
        let slow = SlowResolver::new(Duration::from_millis(5), SocketAddr::new(v4(7), 1));
        let policy = PolicyResolver::new(
            StaticResolver::new(v4(99), 1),
            vec![
                PolicyRuleSpec::new(PolicyAction::Route(slow))
                    .exact(["slow.example"])
                    .timeout(Duration::ZERO),
            ],
        )
        .unwrap();
        assert_eq!(
            policy
                .resolve_location(&location("slow.example", 53))
                .await
                .unwrap(),
            [SocketAddr::new(v4(7), 53)]
        );
    }

    #[tokio::test]
    async fn reject_and_catch_all_rules_do_not_contact_an_upstream() {
        let final_resolver = StaticResolver::new(v4(99), 53);
        let policy = PolicyResolver::new(
            final_resolver.clone(),
            vec![
                PolicyRuleSpec::new(PolicyAction::Reject(DnsRejectMethod::Default))
                    .suffix(["blocked.example"]),
            ],
        )
        .unwrap();
        let error = policy
            .resolve_location(&location("BLOCKED.EXAMPLE", 53))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(final_resolver.calls(), 0);

        let catch_all = PolicyResolver::new(
            final_resolver.clone(),
            vec![PolicyRuleSpec::new(PolicyAction::Reject(
                DnsRejectMethod::Default,
            ))],
        )
        .unwrap();
        assert!(
            catch_all
                .resolve_location(&location("anything.example", 53))
                .await
                .is_err()
        );
        assert_eq!(final_resolver.calls(), 0);
    }

    #[tokio::test]
    async fn reject_drop_is_an_immediate_typed_terminal_failure() {
        let final_resolver = StaticResolver::new(v4(99), 53);
        let policy = PolicyResolver::new(
            final_resolver.clone(),
            vec![
                PolicyRuleSpec::new(PolicyAction::Reject(DnsRejectMethod::Drop))
                    .exact(["drop.example"]),
            ],
        )
        .unwrap();

        let error = tokio::time::timeout(
            Duration::from_millis(50),
            policy.resolve_location(&location("drop.example", 53)),
        )
        .await
        .expect("drop must not leave an address lookup pending")
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let typed = error
            .get_ref()
            .and_then(|source| source.downcast_ref::<DnsPolicyError>())
            .expect("DNS policy error must preserve its typed failure");
        assert_eq!(
            typed.failure(),
            DnsPolicyFailure::Rejected(DnsRejectMethod::Drop)
        );
        assert_eq!(final_resolver.calls(), 0);
    }

    #[tokio::test]
    async fn default_reject_degrades_after_fifty_hits_unless_no_drop_is_set() {
        let failure = |error: &io::Error| {
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<DnsPolicyError>())
                .expect("typed DNS policy failure")
                .failure()
        };
        let target = location("flood.example", 53);
        let policy = PolicyResolver::new(
            StaticResolver::new(v4(99), 53),
            vec![PolicyRuleSpec::new(PolicyAction::Reject(
                DnsRejectMethod::Default,
            ))],
        )
        .unwrap();
        for _ in 0..50 {
            let error = policy.resolve_location(&target).await.unwrap_err();
            assert_eq!(
                failure(&error),
                DnsPolicyFailure::Rejected(DnsRejectMethod::Default)
            );
        }
        let error = policy.resolve_location(&target).await.unwrap_err();
        assert_eq!(
            failure(&error),
            DnsPolicyFailure::Rejected(DnsRejectMethod::Drop)
        );
        for _ in 0..10_000 {
            let error = policy.resolve_location(&target).await.unwrap_err();
            assert_eq!(
                failure(&error),
                DnsPolicyFailure::Rejected(DnsRejectMethod::Drop)
            );
        }
        assert_eq!(
            policy.rules[0]
                .reject_flood
                .as_ref()
                .expect("default reject has a flood window")
                .attempts
                .lock()
                .len(),
            51,
            "sustained floods must not grow the rolling-window allocation"
        );
        let no_drop = PolicyResolver::new(
            StaticResolver::new(v4(99), 53),
            vec![PolicyRuleSpec::new(PolicyAction::Reject(DnsRejectMethod::Default)).no_drop(true)],
        )
        .unwrap();
        for _ in 0..60 {
            let error = no_drop.resolve_location(&target).await.unwrap_err();
            assert_eq!(
                failure(&error),
                DnsPolicyFailure::Rejected(DnsRejectMethod::Default)
            );
        }
    }

    #[tokio::test]
    async fn shared_rule_state_crosses_resolver_boundaries_and_rejects_forged_collisions() {
        fn failure(error: &io::Error) -> DnsPolicyFailure {
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<DnsPolicyError>())
                .expect("typed DNS policy failure")
                .failure()
        }

        let state = PolicyStateRegistry::default();
        let key =
            "__acp_dns_reject_v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let build = |matcher: &str| {
            PolicyResolver::with_named_upstreams_and_state_registry(
                StaticResolver::new(v4(99), 53),
                vec![
                    PolicyRuleSpec::new(PolicyAction::Reject(DnsRejectMethod::Default))
                        .exact([matcher]),
                ],
                std::iter::empty::<(String, Arc<dyn Resolver>)>(),
                vec![Some(key.to_string())],
                &state,
            )
            .unwrap()
        };

        let first = build("flood.example");
        let reloaded = build("flood.example");
        assert!(Arc::ptr_eq(
            first.rules[0].reject_flood.as_ref().unwrap(),
            reloaded.rules[0].reject_flood.as_ref().unwrap()
        ));

        let target = location("flood.example", 53);
        for _ in 0..50 {
            let error = first.resolve_location(&target).await.unwrap_err();
            assert_eq!(
                failure(&error),
                DnsPolicyFailure::Rejected(DnsRejectMethod::Default)
            );
        }
        let error = reloaded.resolve_location(&target).await.unwrap_err();
        assert_eq!(
            failure(&error),
            DnsPolicyFailure::Rejected(DnsRejectMethod::Drop)
        );

        // A hand-written config may copy an internal-looking key, but a
        // different compiled matcher is deliberately part of the registry
        // identity and therefore cannot inherit the first rule's flood window.
        let forged = PolicyResolver::with_named_upstreams_and_state_registry(
            StaticResolver::new(v4(99), 53),
            vec![
                PolicyRuleSpec::new(PolicyAction::Reject(DnsRejectMethod::Default))
                    .keyword(["flood"]),
            ],
            std::iter::empty::<(String, Arc<dyn Resolver>)>(),
            vec![Some(key.to_string())],
            &state,
        )
        .unwrap();
        assert!(!Arc::ptr_eq(
            first.rules[0].reject_flood.as_ref().unwrap(),
            forged.rules[0].reject_flood.as_ref().unwrap()
        ));
        let error = forged.resolve_location(&target).await.unwrap_err();
        assert_eq!(
            failure(&error),
            DnsPolicyFailure::Rejected(DnsRejectMethod::Default)
        );
        assert_eq!(state.live_state_count(), 2);

        drop(first);
        drop(reloaded);
        drop(forged);
        assert_eq!(state.live_state_count(), 0);
        assert_eq!(state.retained_identity_count(), 2);

        // An inbound-only update can remove the last graph before adding its
        // replacement. The generation-owned registry must preserve the flood
        // window across that gap, just as Go keeps the same DNS rule action.
        let resumed = build("flood.example");
        let error = resumed.resolve_location(&target).await.unwrap_err();
        assert_eq!(
            failure(&error),
            DnsPolicyFailure::Rejected(DnsRejectMethod::Drop)
        );
        drop(resumed);

        let replacement = PolicyResolver::with_named_upstreams_and_state_registry(
            StaticResolver::new(v4(99), 53),
            vec![PolicyRuleSpec::new(PolicyAction::Reject(
                DnsRejectMethod::Default,
            ))],
            std::iter::empty::<(String, Arc<dyn Resolver>)>(),
            vec![Some(format!("__acp_dns_reject_v1_{}", "b".repeat(64)))],
            &state,
        )
        .unwrap();
        assert_eq!(state.live_state_count(), 1);
        assert_eq!(state.retained_identity_count(), 3);
        drop(replacement);
    }

    #[test]
    fn rotating_dns_client_clears_question_cache_and_reject_flood_state() {
        use crate::dns::{DnsCachedOutcome, DnsQuestion, DnsQuestionType};

        let registry = PolicyStateRegistry::default();
        let matcher = b"same compiled matcher".to_vec();
        let flood = registry.reject_flood_state("stable-rule", matcher.clone());
        let question = DnsQuestion::new("cached.example.", DnsQuestionType::A);
        let first_cache = registry.query_cache();
        first_cache.store(
            question.clone(),
            DnsCachedOutcome::NxDomain,
            Duration::from_secs(60),
        );
        assert!(first_cache.load(&question).is_some());

        assert_eq!(registry.rotate_dns_client_generation(), 1);
        let second_cache = registry.query_cache();
        assert!(!Arc::ptr_eq(&first_cache, &second_cache));
        assert!(second_cache.load(&question).is_none());
        assert!(
            first_cache.load(&question).is_some(),
            "a retiring resolver graph keeps its physically separate Go-client cache"
        );
        assert!(!Arc::ptr_eq(
            &flood,
            &registry.reject_flood_state("stable-rule", matcher)
        ));
    }

    #[test]
    fn default_reject_rolling_window_keeps_the_exact_thirty_second_boundary() {
        let policy = PolicyResolver::new(
            StaticResolver::new(v4(99), 53),
            vec![PolicyRuleSpec::new(PolicyAction::Reject(
                DnsRejectMethod::Default,
            ))],
        )
        .unwrap();
        let rule = &policy.rules[0];
        let started_at = Instant::now();

        for _ in 0..50 {
            assert!(matches!(
                rule.selected_action_at(started_at),
                PolicyAction::Reject(DnsRejectMethod::Default)
            ));
        }
        assert!(matches!(
            rule.selected_action_at(started_at),
            PolicyAction::Reject(DnsRejectMethod::Drop)
        ));
        assert!(matches!(
            rule.selected_action_at(started_at + Duration::from_secs(30)),
            PolicyAction::Reject(DnsRejectMethod::Drop)
        ));
        assert!(matches!(
            rule.selected_action_at(started_at + Duration::from_secs(30) + Duration::from_nanos(1)),
            PolicyAction::Reject(DnsRejectMethod::Default)
        ));
    }

    #[test]
    fn no_drop_is_rejected_outside_default_reject() {
        let final_resolver = StaticResolver::new(v4(99), 53);
        for action in [
            PolicyAction::Reject(DnsRejectMethod::Drop),
            PolicyAction::Route(StaticResolver::new(v4(1), 53)),
            PolicyAction::Predefined(DnsPredefinedResponse::no_error(Vec::new())),
        ] {
            let error = PolicyResolver::new(
                final_resolver.clone(),
                vec![PolicyRuleSpec::new(action).no_drop(true)],
            )
            .unwrap_err();
            assert!(error.to_string().contains("no_drop"));
        }
    }

    #[test]
    fn policy_cache_hint_follows_the_selected_route_profile() {
        let final_resolver =
            StaticResolver::new_with_cache_ttl(v4(99), 53, Some(Duration::from_secs(90)));
        let uncached = StaticResolver::new_with_cache_ttl(v4(1), 53, None);
        let short = StaticResolver::new_with_cache_ttl(v4(2), 53, Some(Duration::from_secs(5)));
        let policy = PolicyResolver::new(
            final_resolver,
            vec![
                PolicyRuleSpec::new(PolicyAction::Route(uncached)).exact(["uncached.example"]),
                PolicyRuleSpec::new(PolicyAction::Route(short)).exact(["short.example"]),
            ],
        )
        .unwrap();

        assert_eq!(
            policy.result_cache_ttl_for(&location("uncached.example", 53)),
            None
        );
        assert_eq!(
            policy.result_cache_ttl_for(&location("short.example", 53)),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            policy.result_cache_ttl_for(&location("other.example", 53)),
            Some(Duration::from_secs(90))
        );
    }

    #[test]
    fn predefined_rcode_parser_matches_miekg_names_strictly() {
        for (name, rcode, canonical) in [
            ("NOERROR", DnsRcode::NoError, "NOERROR"),
            ("FORMERR", DnsRcode::FormErr, "FORMERR"),
            ("SERVFAIL", DnsRcode::ServFail, "SERVFAIL"),
            ("NXDOMAIN", DnsRcode::NxDomain, "NXDOMAIN"),
            ("NOTIMP", DnsRcode::NotImp, "NOTIMP"),
            ("NOTIMPL", DnsRcode::NotImp, "NOTIMP"),
            ("REFUSED", DnsRcode::Refused, "REFUSED"),
            ("YXDOMAIN", DnsRcode::YxDomain, "YXDOMAIN"),
            ("YXRRSET", DnsRcode::YxRrset, "YXRRSET"),
            ("NXRRSET", DnsRcode::NxRrset, "NXRRSET"),
            ("NOTAUTH", DnsRcode::NotAuth, "NOTAUTH"),
            ("NOTZONE", DnsRcode::NotZone, "NOTZONE"),
            ("DSOTYPENI", DnsRcode::DsoTypeNi, "DSOTYPENI"),
            ("BADSIG", DnsRcode::BadSig, "BADSIG"),
            ("BADKEY", DnsRcode::BadKey, "BADKEY"),
            ("BADTIME", DnsRcode::BadTime, "BADTIME"),
            ("BADMODE", DnsRcode::BadMode, "BADMODE"),
            ("BADNAME", DnsRcode::BadName, "BADNAME"),
            ("BADALG", DnsRcode::BadAlg, "BADALG"),
            ("BADTRUNC", DnsRcode::BadTrunc, "BADTRUNC"),
            ("BADCOOKIE", DnsRcode::BadCookie, "BADCOOKIE"),
        ] {
            let parsed = DnsRcode::parse(name).unwrap_or_else(|| panic!("missing {name}"));
            assert_eq!(parsed, rcode, "{name}");
            assert_eq!(parsed.as_str(), canonical, "{name}");
        }
        assert_eq!(DnsRcode::parse(""), Some(DnsRcode::NoError));
        for invalid in ["SUCCESS", "noerror", " NOERROR", "NOERROR "] {
            assert_eq!(DnsRcode::parse(invalid), None, "{invalid:?}");
        }
    }

    #[tokio::test]
    async fn predefined_response_codes_are_typed_terminal_outcomes() {
        for (rcode, kind) in [
            (DnsRcode::NxDomain, io::ErrorKind::NotFound),
            (DnsRcode::Refused, io::ErrorKind::PermissionDenied),
            (DnsRcode::ServFail, io::ErrorKind::Other),
            (DnsRcode::FormErr, io::ErrorKind::Other),
            (DnsRcode::BadCookie, io::ErrorKind::Other),
        ] {
            let final_resolver = StaticResolver::new(v4(99), 53);
            let policy = PolicyResolver::new(
                final_resolver.clone(),
                vec![
                    PolicyRuleSpec::new(PolicyAction::Predefined(DnsPredefinedResponse::new(
                        rcode,
                        vec![v4(7)],
                    )))
                    .exact(["rcode.example"]),
                ],
            )
            .unwrap();

            let error = policy
                .resolve_location(&location("rcode.example", 53))
                .await
                .unwrap_err();
            assert_eq!(error.kind(), kind);
            let typed = error
                .get_ref()
                .and_then(|source| source.downcast_ref::<DnsPolicyError>())
                .expect("DNS policy error must preserve its response code");
            assert_eq!(typed.failure(), DnsPolicyFailure::ResponseCode(rcode));
            assert_eq!(final_resolver.calls(), 0);
        }
    }

    #[tokio::test]
    async fn predefined_answers_preserve_a_and_aaaa_and_target_port() {
        let final_resolver = StaticResolver::new(v4(99), 1);
        let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let policy = PolicyResolver::new(
            final_resolver.clone(),
            vec![
                PolicyRuleSpec::new(PolicyAction::Predefined(DnsPredefinedResponse::no_error(
                    vec![v4(7), ipv6],
                )))
                .exact(["static.example"]),
            ],
        )
        .unwrap();
        let resolved = policy
            .resolve_location(&location("static.example", 5353))
            .await
            .unwrap();
        assert_eq!(
            resolved,
            vec![SocketAddr::new(v4(7), 5353), SocketAddr::new(ipv6, 5353)]
        );
        assert_eq!(final_resolver.calls(), 0);
    }

    #[tokio::test]
    async fn empty_predefined_answer_is_a_successful_terminal_response() {
        let final_resolver = StaticResolver::new(v4(99), 1);
        let policy = PolicyResolver::new(
            final_resolver.clone(),
            vec![
                PolicyRuleSpec::new(PolicyAction::Predefined(DnsPredefinedResponse::no_error(
                    Vec::new(),
                )))
                .exact(["empty.example"]),
            ],
        )
        .unwrap();

        let resolved = policy
            .resolve_location(&location("empty.example", 53))
            .await
            .unwrap();
        assert!(resolved.is_empty());
        assert_eq!(final_resolver.calls(), 0);
    }

    #[tokio::test]
    async fn direct_and_rule_set_domains_share_one_or_category() {
        let rule_set =
            source_rule_set(r#"{"version":4,"rules":[{"domain_suffix":["ads.example"]}]}"#);
        let final_resolver = StaticResolver::new(v4(1), 0);
        let resolver = PolicyResolver::new(
            final_resolver.clone(),
            vec![
                PolicyRuleSpec::new(PolicyAction::Predefined(DnsPredefinedResponse::no_error(
                    vec![v4(9)],
                )))
                .exact(["direct.example"])
                .rule_set([RouteRuleSetConfig {
                    format: "source".to_string(),
                    path: rule_set.path().to_path_buf(),
                }]),
            ],
        )
        .unwrap();

        let result = resolver
            .resolve_location(&location("track.ads.example", 5353))
            .await
            .unwrap();
        assert_eq!(result, [SocketAddr::new(v4(9), 5353)]);
        let direct = resolver
            .resolve_location(&location("direct.example", 5353))
            .await
            .unwrap();
        assert_eq!(direct, [SocketAddr::new(v4(9), 5353)]);
        let unrelated = resolver
            .resolve_location(&location("unrelated.example", 5353))
            .await
            .unwrap();
        assert_eq!(unrelated, [SocketAddr::new(v4(1), 5353)]);
        assert_eq!(final_resolver.calls(), 1);
    }

    #[tokio::test]
    async fn literal_ip_bypasses_policy_and_upstream() {
        let final_resolver = StaticResolver::new(v4(99), 1);
        let policy = PolicyResolver::new(
            final_resolver.clone(),
            vec![PolicyRuleSpec::new(PolicyAction::Reject(
                DnsRejectMethod::Default,
            ))],
        )
        .unwrap();
        let literal = NetLocation::new(Address::Ipv4(Ipv4Addr::new(198, 51, 100, 3)), 8080);
        assert_eq!(
            policy.resolve_location(&literal).await.unwrap(),
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3)),
                8080
            )]
        );
        assert_eq!(final_resolver.calls(), 0);
    }

    #[test]
    fn constructor_rejects_invalid_and_oversized_policy() {
        let final_resolver = StaticResolver::new(v4(99), 53);
        let invalid_regex = PolicyResolver::new(
            final_resolver.clone(),
            vec![PolicyRuleSpec::new(PolicyAction::Reject(DnsRejectMethod::Default)).regex(["("])],
        )
        .unwrap_err();
        assert_eq!(invalid_regex.kind(), io::ErrorKind::InvalidInput);

        assert!(
            PolicyResolver::new(
                final_resolver.clone(),
                vec![
                    PolicyRuleSpec::new(PolicyAction::Reject(DnsRejectMethod::Default,))
                        .exact([""])
                ]
            )
            .is_err()
        );
        assert!(
            PolicyResolver::new(
                final_resolver.clone(),
                vec![
                    PolicyRuleSpec::new(PolicyAction::Reject(DnsRejectMethod::Default,))
                        .timeout(Duration::from_millis(1))
                ]
            )
            .is_err()
        );
        let limits = PolicyLimits {
            max_rules: 1,
            max_patterns_per_rule: 1,
            max_total_patterns: 1,
            max_regex_patterns: 1,
            max_pattern_bytes: 4,
            max_total_pattern_bytes: 4,
            max_predefined_addresses_per_rule: 1,
            regex_size_limit: 1_024,
            regex_dfa_size_limit: 1_024,
        };
        assert!(
            PolicyResolver::with_limits(
                final_resolver.clone(),
                vec![
                    PolicyRuleSpec::new(PolicyAction::Reject(DnsRejectMethod::Default)),
                    PolicyRuleSpec::new(PolicyAction::Reject(DnsRejectMethod::Default)),
                ],
                limits,
            )
            .is_err()
        );
        assert!(
            PolicyResolver::with_limits(
                final_resolver,
                vec![
                    PolicyRuleSpec::new(PolicyAction::Reject(DnsRejectMethod::Default,))
                        .exact(["12345"])
                ],
                limits,
            )
            .is_err()
        );
    }
}
