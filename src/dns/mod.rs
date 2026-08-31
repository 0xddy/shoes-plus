//! DNS resolver module with configurable DNS servers.
//!
//! Supports:
//! - System resolver (NativeResolver)
//! - UDP DNS
//! - TCP DNS
//! - DNS-over-TLS (DoT) - requires `hickory-tls` feature
//! - DNS-over-HTTPS (DoH) - requires `hickory-https` feature
//!
//! TCP-based protocols (tcp://, tls://, https://) support routing through
//! proxy chains via the ProxyRuntimeProvider.

mod builder;
mod client_subnet;
mod composite_resolver;
mod hickory_resolver;
mod parsed;
mod policy;
mod predefined;
mod proxy_runtime;
mod query_cache;
mod system_config;
mod system_resolver;

#[allow(unused_imports)]
pub use builder::{DnsRegistry, build_dns_registry, build_dns_registry_with_policy_state};
pub use client_subnet::DnsClientSubnet;
pub use parsed::{IpStrategy, ParsedDnsUrl};
#[allow(unused_imports)]
pub use policy::{
    DnsPolicyError, DnsPolicyFailure, DnsPredefinedResponse, DnsRcode, DnsRejectMethod,
    PolicyAction, PolicyLimits, PolicyResolver, PolicyRuleSpec, PolicyStateRegistry,
};
pub use predefined::parse_predefined_lookup_addresses;
// The Shoes binary mirrors the library modules directly, so embedding-only public
// exports appear unused in that duplicate crate even though shoes-engine consumes them.
#[allow(unused_imports)]
pub use query_cache::{
    DNS_QUERY_CACHE_CAPACITY, DnsCachePolicy, DnsCachedOutcome, DnsExchangeResponse, DnsQueryCache,
    DnsQuestion, DnsQuestionType, is_dns_nx_domain_error,
};
