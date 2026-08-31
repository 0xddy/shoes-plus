//! DNS configuration types.

use serde::{Deserialize, Serialize};

use crate::config::types::rules::{ClientChain, ClientChainSelectionConfig};
use crate::config::types::selection::ConfigSelection;
use crate::dns::{DnsClientSubnet, DnsPredefinedResponse, DnsRejectMethod, IpStrategy};
use crate::option_util::NoneOrSome;
use crate::routing::predicate::RouteRuleSetConfig;

use super::common::is_false;

/// Default timeout for DNS resolution in seconds.
fn default_timeout_secs() -> u32 {
    5
}

/// Default connect timeout for DNS upstream connections in seconds.
fn default_connect_timeout_secs() -> u32 {
    5
}

/// Default number of retry attempts for custom DNS groups.
/// Lower than hickory's default to avoid turning transient failures into slow successes.
fn default_attempts() -> usize {
    1
}

/// A DNS server specification in config.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum DnsServerSpec {
    /// Simple URL string: "system", "udp://8.8.8.8", etc.
    /// Must be IP-based (no hostnames). Cannot have bootstrap_url.
    Simple(String),
    /// Object with URL and optional client_chain, bootstrap_url, server_name, ip_strategy.
    WithOptions {
        /// Stable name used by DNS policy `final` and `route` actions.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tag: Option<String>,
        /// Original DNS transport tag retained by compiler-generated query
        /// profiles. The shared answer cache is question-only, while Go's
        /// single-flight lock is scoped to this source transport.
        #[serde(
            default,
            rename = "__acp_source_tag",
            skip_serializing_if = "Option::is_none"
        )]
        source_tag: Option<String>,
        url: String,
        #[serde(default)]
        client_chain: NoneOrSome<ConfigSelection<ClientChain>>,
        /// Selection policy when `client_chain` expands to multiple chains.
        #[serde(default, skip_serializing_if = "is_round_robin_selection")]
        client_chain_selection: ClientChainSelectionConfig,
        /// Bootstrap resolver for hostname resolution.
        /// Can be a URL string (e.g., "udp://8.8.8.8") or a dns_group name.
        #[serde(default)]
        bootstrap_url: Option<String>,
        /// SNI server name override for TLS/HTTPS. Defaults to hostname from URL.
        #[serde(default)]
        server_name: Option<String>,
        /// Use the operating system's TLS trust policy for encrypted upstreams.
        /// Omitted/false preserves historical shoes configurations.
        #[serde(default, skip_serializing_if = "is_false")]
        use_native_roots: bool,
        /// IP lookup strategy for DNS resolution. Defaults to ipv4_then_ipv6.
        #[serde(default)]
        ip_strategy: IpStrategy,
        /// Disable the Hickory response cache for this private upstream profile.
        #[serde(default, skip_serializing_if = "is_false")]
        disable_cache: bool,
        /// Force positive and negative response cache lifetime to this TTL.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rewrite_ttl: Option<u32>,
        /// EDNS Client Subnet attached to every query through this profile.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        client_subnet: String,
        /// Timeout for DNS resolution in seconds. Defaults to 5. Set to 0 to disable.
        /// Advanced `system` profiles retain the platform resolver timeout instead,
        /// because this field cannot distinguish an omitted value from the serde default.
        #[serde(default = "default_timeout_secs")]
        timeout_secs: u32,
        /// Timeout for establishing connections to DNS upstreams in seconds.
        /// Defaults to 5. Separate from timeout_secs which covers the full request.
        /// For plain `tcp://` upstreams, hickory also passes the request timeout
        /// into `connect_tcp`, so the runtime uses the shorter of that value and
        /// this connect timeout.
        #[serde(default = "default_connect_timeout_secs")]
        connect_timeout_secs: u32,
        /// Number of retry attempts for failed queries. Defaults to 1. Advanced
        /// `system` profiles retain the platform resolver attempt count.
        #[serde(default = "default_attempts")]
        attempts: usize,
    },
}

impl DnsServerSpec {
    /// Check if a string looks like a DNS URL (has known scheme) vs a group reference.
    fn is_url_string(s: &str) -> bool {
        s == "system" || s.contains("://")
    }

    /// Get the group name if this is a group reference.
    pub fn as_group_ref(&self) -> Option<&str> {
        if let Self::Simple(s) = self
            && !Self::is_url_string(s)
        {
            return Some(s);
        }
        None
    }

    /// Get the URL string from this spec.
    /// Panics if called on a group reference - use as_group_ref() to check first.
    pub fn url(&self) -> &str {
        match self {
            Self::Simple(s) => {
                debug_assert!(Self::is_url_string(s), "called url() on group reference");
                s
            }
            Self::WithOptions { url, .. } => url,
        }
    }

    /// Get the policy tag, if this upstream participates in tagged DNS policy.
    pub fn tag(&self) -> Option<&str> {
        if let Self::WithOptions { tag, .. } = self {
            tag.as_deref()
        } else {
            None
        }
    }

    /// Get the client_chain.
    pub fn client_chains(&self) -> &NoneOrSome<ConfigSelection<ClientChain>> {
        static NONE: NoneOrSome<ConfigSelection<ClientChain>> = NoneOrSome::None;
        if let Self::WithOptions { client_chain, .. } = self {
            client_chain
        } else {
            &NONE
        }
    }

    pub fn client_chain_selection(&self) -> ClientChainSelectionConfig {
        if let Self::WithOptions {
            client_chain_selection,
            ..
        } = self
        {
            client_chain_selection.clone()
        } else {
            ClientChainSelectionConfig::RoundRobin
        }
    }

    /// Get the bootstrap_url if present.
    pub fn bootstrap_url(&self) -> Option<&str> {
        if let Self::WithOptions { bootstrap_url, .. } = self {
            bootstrap_url.as_deref()
        } else {
            None
        }
    }

    /// Get the server_name override if present.
    pub fn server_name(&self) -> Option<&str> {
        if let Self::WithOptions { server_name, .. } = self {
            server_name.as_deref()
        } else {
            None
        }
    }

    pub fn use_native_roots(&self) -> bool {
        if let Self::WithOptions {
            use_native_roots, ..
        } = self
        {
            *use_native_roots
        } else {
            false
        }
    }

    /// Get the ip_strategy (defaults to Ipv4ThenIpv6 for Simple variant).
    pub fn ip_strategy(&self) -> IpStrategy {
        if let Self::WithOptions { ip_strategy, .. } = self {
            *ip_strategy
        } else {
            IpStrategy::default()
        }
    }

    /// Get the compiler-retained original transport tag for a private query
    /// profile. Ordinary upstreams use their own policy tag instead.
    pub fn source_tag(&self) -> Option<&str> {
        if let Self::WithOptions { source_tag, .. } = self {
            source_tag.as_deref()
        } else {
            None
        }
    }

    pub fn disable_cache(&self) -> bool {
        if let Self::WithOptions { disable_cache, .. } = self {
            *disable_cache
        } else {
            false
        }
    }

    pub fn rewrite_ttl(&self) -> Option<u32> {
        if let Self::WithOptions { rewrite_ttl, .. } = self {
            *rewrite_ttl
        } else {
            None
        }
    }

    pub fn client_subnet(&self) -> Option<&str> {
        if let Self::WithOptions { client_subnet, .. } = self
            && !client_subnet.is_empty()
        {
            Some(client_subnet)
        } else {
            None
        }
    }

    /// Get the timeout in seconds (defaults to 5 for Simple variant).
    /// Returns 0 if timeout is disabled.
    pub fn timeout_secs(&self) -> u32 {
        if let Self::WithOptions { timeout_secs, .. } = self {
            *timeout_secs
        } else {
            default_timeout_secs()
        }
    }

    /// Get the connect timeout in seconds (defaults to 5 for Simple variant).
    pub fn connect_timeout_secs(&self) -> u32 {
        if let Self::WithOptions {
            connect_timeout_secs,
            ..
        } = self
        {
            *connect_timeout_secs
        } else {
            default_connect_timeout_secs()
        }
    }

    /// Get the number of retry attempts (defaults to 1 for Simple variant).
    pub fn attempts(&self) -> usize {
        if let Self::WithOptions { attempts, .. } = self {
            *attempts
        } else {
            default_attempts()
        }
    }
}

/// Action for an ordered DNS policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsPolicyActionConfig {
    /// Resolve through the upstream named by `server`.
    Route,
    /// Terminate the lookup with a rejection.
    Reject,
    /// Return configured DNS resource records (an empty list is allowed).
    Predefined,
}

/// A first-match DNS policy rule.
///
/// The address-only lookup path preserves DNS response codes and reject method
/// as typed terminal failures.  All predefined sections are validated, while
/// only answer-section A/AAAA records are projected into lookup addresses.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsPolicyRuleConfig {
    /// Internal ACP compiler identity for sharing the rolling default-reject
    /// flood window across per-inbound projections. Hand-written Shoes configs
    /// should omit this field.
    #[serde(
        default,
        rename = "__acp_reject_flood_key",
        skip_serializing_if = "String::is_empty"
    )]
    pub reject_flood_state_key: String,
    /// Exact hostname matches. `exact` is accepted as a concise alias.
    #[serde(default, alias = "exact", skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(default, alias = "suffix", skip_serializing_if = "Vec::is_empty")]
    pub domain_suffix: Vec<String>,
    #[serde(default, alias = "keyword", skip_serializing_if = "Vec::is_empty")]
    pub domain_keyword: Vec<String>,
    #[serde(default, alias = "regex", skip_serializing_if = "Vec::is_empty")]
    pub domain_regex: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_set: Vec<RouteRuleSetConfig>,
    pub action: DnsPolicyActionConfig,
    /// Upstream tag for `route`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// DNS response code for `predefined`; omission means NOERROR.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rcode: String,
    /// Reject method (`default` or `drop`) for `reject`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    /// Keep the default reject method from degrading to drop after sing-box's
    /// rolling flood threshold is exceeded.
    #[serde(default, skip_serializing_if = "is_false")]
    pub no_drop: bool,
    /// Answer-section resource records for `predefined`, as RR text or base64
    /// standalone wire RRs. Bare IPs remain accepted for local compatibility.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub answer: Vec<String>,
    /// Authority-section resource records for `predefined`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ns: Vec<String>,
    /// Additional-section resource records for `predefined`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra: Vec<String>,
    /// Per-rule timeout for a matched `route` action, in milliseconds. Zero or
    /// omission preserves the upstream resolver's existing timeout behaviour.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub timeout_millis: u64,
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

/// DNS group configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfigGroup {
    pub dns_group: String,
    #[serde(alias = "dns_server")]
    pub dns_servers: NoneOrSome<DnsServerSpec>,
    #[serde(default, rename = "final", skip_serializing_if = "Option::is_none")]
    pub final_server: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<DnsPolicyRuleConfig>,
}

/// DNS configuration for servers.
/// The `servers` field can be a group name, inline specs, or None (use default).
/// After validation, `servers` is mutated to a single group name reference.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default, alias = "server")]
    pub servers: NoneOrSome<DnsServerSpec>,
    #[serde(default, rename = "final", skip_serializing_if = "Option::is_none")]
    pub final_server: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<DnsPolicyRuleConfig>,
}

impl DnsConfig {
    /// Get the resolved group name after validation.
    /// Returns None if servers was None/Unspecified (use default system resolver).
    /// Panics if called before validation or if servers wasn't resolved properly.
    pub fn resolved_group(&self) -> Option<&str> {
        match &self.servers {
            NoneOrSome::Unspecified | NoneOrSome::None => None,
            NoneOrSome::One(spec) => Some(
                spec.as_group_ref()
                    .expect("DnsConfig.servers should be a single group name after validation"),
            ),
            NoneOrSome::Some(_) => {
                panic!("DnsConfig.servers should be a single group name after validation")
            }
        }
    }
}

/// A DNS server spec with all group references expanded.
/// Client chains contain actual ClientConfig objects, not group names.
#[derive(Debug, Clone)]
pub struct ExpandedDnsSpec {
    pub tag: Option<String>,
    pub source_tag: Option<String>,
    pub url: String,
    pub server_name: Option<String>,
    pub use_native_roots: bool,
    /// Client chains with all group refs resolved to configs.
    pub client_chains: Vec<ClientChain>,
    pub client_chain_selection: ClientChainSelectionConfig,
    /// Bootstrap resolver URL or group name. Groups are resolved at runtime.
    pub bootstrap_url: Option<String>,
    pub ip_strategy: IpStrategy,
    pub disable_cache: bool,
    pub rewrite_ttl: Option<u32>,
    pub client_subnet: Option<DnsClientSubnet>,
    /// Timeout for DNS resolution in seconds. 0 means no timeout.
    pub timeout_secs: u32,
    /// Timeout for establishing connections to DNS upstreams in seconds.
    pub connect_timeout_secs: u32,
    /// Number of retry attempts for failed queries.
    pub attempts: usize,
}

fn is_round_robin_selection(selection: &ClientChainSelectionConfig) -> bool {
    matches!(selection, ClientChainSelectionConfig::RoundRobin)
}

/// Validated action for a DNS policy rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpandedDnsPolicyAction {
    Route(String),
    Reject(DnsRejectMethod),
    Predefined(DnsPredefinedResponse),
}

/// DNS policy rule after action references and predefined answers are validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedDnsPolicyRule {
    pub reject_flood_state_key: Option<String>,
    pub exact: Vec<String>,
    pub suffix: Vec<String>,
    pub keyword: Vec<String>,
    pub regex: Vec<String>,
    pub rule_set: Vec<RouteRuleSetConfig>,
    pub action: ExpandedDnsPolicyAction,
    pub no_drop: bool,
    /// Zero means no rule-level timeout wrapper.
    pub timeout_millis: u64,
}

/// A DNS group with all specs expanded.
#[derive(Debug, Clone)]
pub struct ExpandedDnsGroup {
    pub name: String,
    pub specs: Vec<ExpandedDnsSpec>,
    /// Resolved final upstream tag. `None` denotes a legacy composite group.
    pub final_server: Option<String>,
    pub rules: Vec<ExpandedDnsPolicyRule>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_server_spec_simple() {
        let yaml = r#"system"#;
        let spec: DnsServerSpec = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(spec, DnsServerSpec::Simple(ref s) if s == "system"));
        assert_eq!(spec.url(), "system");
        assert!(spec.client_chains().is_empty());
    }

    #[test]
    fn test_dns_server_spec_url() {
        let yaml = r#"udp://8.8.8.8"#;
        let spec: DnsServerSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.url(), "udp://8.8.8.8");
    }

    #[test]
    fn test_dns_server_spec_with_chain() {
        let yaml = r#"
url: https://1.1.1.1/dns-query
client_chain: my-proxy
"#;
        let spec: DnsServerSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.url(), "https://1.1.1.1/dns-query");
        assert!(!spec.client_chains().is_empty());
        assert!(spec.bootstrap_url().is_none());
        assert!(spec.server_name().is_none());
    }

    #[test]
    fn dns_server_urltest_chain_selection_roundtrips() {
        let yaml = r#"
url: https://1.1.1.1/dns-query
client_chain:
  - direct
  - backup
client_chain_selection:
  type: urltest
  url: https://www.gstatic.com/generate_204
  use_native_roots: true
  interval_millis: 30000
  tolerance_millis: 50
  idle_timeout_millis: 1800000
"#;
        let spec: DnsServerSpec = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(
            spec.client_chain_selection(),
            ClientChainSelectionConfig::UrlTest {
                use_native_roots: true,
                interval_millis: 30_000,
                tolerance_millis: 50,
                idle_timeout_millis: 1_800_000,
                ..
            }
        ));
        let serialized = serde_yaml::to_string(&spec).unwrap();
        assert!(serialized.contains("client_chain_selection:"));
        assert!(serialized.contains("type: urltest"));
        assert!(serialized.contains("use_native_roots: true"));
        let roundtrip: DnsServerSpec = serde_yaml::from_str(&serialized).unwrap();
        assert!(matches!(
            roundtrip.client_chain_selection(),
            ClientChainSelectionConfig::UrlTest { .. }
        ));
    }

    #[test]
    fn dns_server_options_reject_unknown_plural_client_chains() {
        let yaml = r#"
url: https://1.1.1.1/dns-query
client_chains: direct
"#;
        let error = serde_yaml::from_str::<DnsServerSpec>(yaml).unwrap_err();
        assert!(error.to_string().contains("did not match any variant"));
    }

    #[test]
    fn test_dns_server_spec_with_bootstrap() {
        let yaml = r#"
url: tls://dns.google
bootstrap_url: udp://8.8.8.8
server_name: dns.google
use_native_roots: true
"#;
        let spec: DnsServerSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.url(), "tls://dns.google");
        assert!(spec.client_chains().is_empty());
        assert_eq!(spec.bootstrap_url(), Some("udp://8.8.8.8"));
        assert_eq!(spec.server_name(), Some("dns.google"));
        assert!(spec.use_native_roots());
    }

    #[test]
    fn test_dns_server_spec_with_bootstrap_group_ref() {
        let yaml = r#"
url: https://cloudflare-dns.com/dns-query
client_chain: privacy-proxy
bootstrap_url: fast-dns
"#;
        let spec: DnsServerSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.url(), "https://cloudflare-dns.com/dns-query");
        assert!(!spec.client_chains().is_empty());
        assert_eq!(spec.bootstrap_url(), Some("fast-dns"));
    }

    #[test]
    fn test_dns_config_group() {
        let yaml = r#"
dns_group: my-dns
dns_servers:
  - system
  - udp://8.8.8.8
  - url: https://1.1.1.1/dns-query
    client_chain: proxy-group
"#;
        let group: DnsConfigGroup = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(group.dns_group, "my-dns");
        let servers = group.dns_servers.into_vec();
        assert_eq!(servers.len(), 3);
    }

    #[test]
    fn test_dns_config_bare_group_name_rejected() {
        // Bare group names are not allowed - must use servers field
        let yaml = r#"my-dns-group"#;
        let result: Result<DnsConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "bare group name should be rejected");
    }

    #[test]
    fn test_dns_config_with_servers() {
        let yaml = r#"
servers:
  - system
  - udp://8.8.8.8
"#;
        let config: DnsConfig = serde_yaml::from_str(yaml).unwrap();
        let servers = config.servers.into_vec();
        assert_eq!(servers.len(), 2);
    }

    #[test]
    fn test_dns_config_with_servers_group_ref() {
        // Group reference inside servers field is allowed
        let yaml = r#"
servers: my-dns-group
"#;
        let config: DnsConfig = serde_yaml::from_str(yaml).unwrap();
        let servers = config.servers.into_vec();
        assert_eq!(servers.len(), 1);
        assert!(servers[0].as_group_ref().is_some());
        assert_eq!(servers[0].as_group_ref(), Some("my-dns-group"));
    }

    #[test]
    fn test_dns_config_resolved_group() {
        // After validation, servers should be a single group name
        let config = DnsConfig {
            servers: NoneOrSome::One(DnsServerSpec::Simple("my-resolved-group".to_string())),
            final_server: None,
            rules: Vec::new(),
        };
        assert_eq!(config.resolved_group(), Some("my-resolved-group"));
    }

    #[test]
    fn test_dns_server_spec_group_ref() {
        // Group reference (no URL scheme)
        let yaml = r#"base-dns"#;
        let spec: DnsServerSpec = serde_yaml::from_str(yaml).unwrap();
        assert!(spec.as_group_ref().is_some());
        assert_eq!(spec.as_group_ref(), Some("base-dns"));
    }

    #[test]
    fn test_dns_server_spec_url_not_group_ref() {
        // URLs should not be detected as group refs
        for url in [
            "system",
            "udp://8.8.8.8",
            "tcp://1.1.1.1",
            "tls://dns.google",
            "quic://dns.adguard-dns.com",
            "https://cloudflare.com/dns-query",
            "h3://cloudflare.com/dns-query",
        ] {
            let spec = DnsServerSpec::Simple(url.to_string());
            assert!(
                !spec.as_group_ref().is_some(),
                "{} should not be a group ref",
                url
            );
            assert!(spec.as_group_ref().is_none());
        }
    }

    #[test]
    fn test_dns_server_spec_with_options_not_group_ref() {
        // WithOptions is never a group ref
        let spec = DnsServerSpec::WithOptions {
            tag: None,
            source_tag: None,
            client_chain_selection: ClientChainSelectionConfig::RoundRobin,
            url: "tls://dns.google".to_string(),
            client_chain: NoneOrSome::None,
            bootstrap_url: None,
            server_name: None,
            use_native_roots: false,
            ip_strategy: IpStrategy::default(),
            disable_cache: false,
            rewrite_ttl: None,
            client_subnet: String::new(),
            timeout_secs: default_timeout_secs(),
            connect_timeout_secs: default_connect_timeout_secs(),
            attempts: default_attempts(),
        };
        assert!(!spec.as_group_ref().is_some());
        assert!(spec.as_group_ref().is_none());
    }

    #[test]
    fn test_dns_group_with_composition() {
        let yaml = r#"
dns_group: full-dns
dns_servers:
  - base-dns
  - fast-dns
  - tls://1.1.1.1
"#;
        let group: DnsConfigGroup = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(group.dns_group, "full-dns");
        let servers = group.dns_servers.into_vec();
        assert_eq!(servers.len(), 3);
        assert!(servers[0].as_group_ref().is_some());
        assert_eq!(servers[0].as_group_ref(), Some("base-dns"));
        assert!(servers[1].as_group_ref().is_some());
        assert_eq!(servers[1].as_group_ref(), Some("fast-dns"));
        assert!(!servers[2].as_group_ref().is_some());
    }

    #[test]
    fn test_dns_server_spec_attempts_default() {
        let yaml = r#"udp://8.8.8.8"#;
        let spec: DnsServerSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.attempts(), 1);
    }

    #[test]
    fn test_dns_server_spec_attempts_custom() {
        let yaml = r#"
url: tls://8.8.8.8
server_name: dns.google
attempts: 3
"#;
        let spec: DnsServerSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.attempts(), 3);
    }

    #[test]
    fn test_dns_server_spec_connect_timeout_default() {
        let yaml = r#"udp://8.8.8.8"#;
        let spec: DnsServerSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.connect_timeout_secs(), 5);
    }

    #[test]
    fn test_dns_server_spec_connect_timeout_custom() {
        let yaml = r#"
url: tls://8.8.8.8
connect_timeout_secs: 2
"#;
        let spec: DnsServerSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.connect_timeout_secs(), 2);
    }

    #[test]
    fn test_dns_server_spec_timeout_secs_default() {
        let yaml = r#"udp://8.8.8.8"#;
        let spec: DnsServerSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.timeout_secs(), 5);
    }

    #[test]
    fn test_dns_server_spec_full_options() {
        let yaml = r#"
url: https://1.1.1.1/dns-query
server_name: cloudflare-dns.com
timeout_secs: 3
connect_timeout_secs: 1
attempts: 1
ip_strategy: ipv4_only
disable_cache: true
rewrite_ttl: 0
client_subnet: 192.0.2.7/24
"#;
        let spec: DnsServerSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.timeout_secs(), 3);
        assert_eq!(spec.connect_timeout_secs(), 1);
        assert_eq!(spec.attempts(), 1);
        assert_eq!(spec.ip_strategy(), IpStrategy::Ipv4Only);
        assert_eq!(spec.server_name(), Some("cloudflare-dns.com"));
        assert!(spec.disable_cache());
        assert_eq!(spec.rewrite_ttl(), Some(0));
        assert_eq!(spec.client_subnet(), Some("192.0.2.7/24"));
    }

    #[test]
    fn test_dns_policy_config_and_aliases() {
        let yaml = r#"
servers:
  - tag: cloudflare
    url: https://1.1.1.1/dns-query
  - tag: google
    url: tls://8.8.8.8
final: cloudflare
rules:
  - exact: [exact.example]
    suffix: [example.net]
    keyword: [api]
    regex: ['^edge[0-9]+\.example$']
    action: route
    server: google
    timeout_millis: 1250
  - domain: [empty.example]
    action: predefined
    rcode: NXDOMAIN
    answer: []
    ns: ['example. 60 IN NS ns.example.']
    extra: ['ns.example. 60 IN A 192.0.2.53']
  - domain_suffix: [blocked.example]
    action: reject
    no_drop: true
"#;
        let config: DnsConfig = serde_yaml::from_str(yaml).unwrap();
        let servers = config.servers.into_vec();
        assert_eq!(servers[0].tag(), Some("cloudflare"));
        assert_eq!(servers[1].tag(), Some("google"));
        assert_eq!(config.final_server.as_deref(), Some("cloudflare"));
        assert_eq!(config.rules[0].domain, ["exact.example"]);
        assert_eq!(config.rules[0].domain_suffix, ["example.net"]);
        assert_eq!(config.rules[0].domain_keyword, ["api"]);
        assert_eq!(config.rules[0].domain_regex, [r"^edge[0-9]+\.example$"]);
        assert_eq!(config.rules[0].action, DnsPolicyActionConfig::Route);
        assert_eq!(config.rules[0].server.as_deref(), Some("google"));
        assert_eq!(config.rules[0].timeout_millis, 1250);
        assert_eq!(config.rules[1].timeout_millis, 0);
        assert_eq!(config.rules[1].rcode, "NXDOMAIN");
        assert!(config.rules[1].answer.is_empty());
        assert_eq!(config.rules[1].ns.len(), 1);
        assert_eq!(config.rules[1].extra.len(), 1);
        assert!(config.rules[2].no_drop);
    }

    #[test]
    fn test_dns_policy_rejects_unrepresentable_response_fields() {
        for unsupported in ["rewrite_ttl: '60'", "client_subnet: 192.0.2.0/24"] {
            let yaml = format!(
                "servers: system\nrules:\n  - action: reject\n    {}\n",
                unsupported
            );
            let result = serde_yaml::from_str::<DnsConfig>(&yaml);
            assert!(
                result.is_err(),
                "unsupported DNS response field was accepted: {unsupported}"
            );
        }
    }
}
