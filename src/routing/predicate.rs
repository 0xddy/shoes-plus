//! Optional, context-aware predicates for routing rules.
//!
//! The original shoes destination-mask matcher remains the first stage. This module is an
//! optional second stage, keeping richer control-plane policy fields out of the proxy core.

use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;

use crate::address::{Address, NetLocation};
use crate::routing::srs::{
    self, SrsDefaultRule, SrsLogicalMode, SrsLogicalRule, SrsRule, SrsRuleSet,
};

/// Transport metadata available while making a routing decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteNetwork {
    Tcp,
    Udp,
}

/// Application protocols exposed by the panel's TCP protocol matcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteProtocol {
    Http,
    Tls,
}

/// Metadata which is not part of a destination address but may affect routing.
///
/// `network` is optional so the long-standing selector API can continue to be used. A rule
/// which explicitly filters by network does not match when the caller supplies no context.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct RouteContext {
    pub network: Option<RouteNetwork>,
    pub protocol: Option<RouteProtocol>,
    /// HTTP Host or TLS SNI. Like sing-box, this takes precedence over the proxy
    /// request's original hostname while evaluating domain fields.
    pub sniffed_domain: Option<String>,
}

impl RouteContext {
    pub const fn new(network: RouteNetwork) -> Self {
        Self {
            network: Some(network),
            protocol: None,
            sniffed_domain: None,
        }
    }

    pub const fn tcp() -> Self {
        Self::new(RouteNetwork::Tcp)
    }

    pub const fn udp() -> Self {
        Self::new(RouteNetwork::Udp)
    }

    pub fn sniffed_tcp(protocol: RouteProtocol, domain: Option<String>) -> Self {
        Self {
            network: Some(RouteNetwork::Tcp),
            protocol: Some(protocol),
            sniffed_domain: domain,
        }
    }
}

/// Serializable second-stage matcher attached to a shoes routing rule.
///
/// The four domain fields and `ip_cidr` form one destination-address OR category;
/// `port` and `port_range` form one destination-port OR category. Address, port,
/// network and logical categories are ANDed. `any` and `all` retain explicit logical
/// structure, and `invert` negates the complete node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RouteMatchConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_suffix: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_keyword: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_regex: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_cidr: Vec<String>,
    /// Literal destination address families accepted by this rule (`4` and/or `6`).
    ///
    /// sing-box's route `IPVersionItem` does not inspect DNS-resolved destination
    /// candidates. Consequently a hostname does not match this field merely because
    /// one of its A/AAAA answers has the requested family.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_version: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_range: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<RouteNetwork>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocol: Vec<RouteProtocol>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_set: Vec<RouteRuleSetConfig>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub invert: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any: Vec<RouteMatchConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all: Vec<RouteMatchConfig>,
}

/// A local sing-box rule-set loaded and compiled with its enclosing route matcher.
///
/// Remote fetching and refresh are intentionally outside shoes; the node agent atomically
/// replaces the local file before rebuilding the selector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRuleSetConfig {
    /// `source`/`json` or `binary`/`srs`.
    pub format: String,
    pub path: PathBuf,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouteMatchConfig {
    #[serde(default, deserialize_with = "one_or_many")]
    domain: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    domain_suffix: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    domain_keyword: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    domain_regex: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    ip_cidr: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    ip_version: Vec<u8>,
    #[serde(default, deserialize_with = "one_or_many")]
    port: Vec<u16>,
    #[serde(default, deserialize_with = "one_or_many")]
    port_range: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    network: Vec<RouteNetwork>,
    #[serde(default, deserialize_with = "one_or_many")]
    protocol: Vec<RouteProtocol>,
    #[serde(default, deserialize_with = "one_or_many")]
    rule_set: Vec<RouteRuleSetConfig>,
    #[serde(default)]
    invert: bool,
    #[serde(default, deserialize_with = "one_or_many")]
    any: Vec<RouteMatchConfig>,
    #[serde(default, deserialize_with = "one_or_many")]
    all: Vec<RouteMatchConfig>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

fn one_or_many<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(value) => vec![value],
        OneOrMany::Many(values) => values,
    })
}

impl<'de> Deserialize<'de> for RouteMatchConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouteMatchConfig::deserialize(deserializer)?;
        let config = Self {
            domain: raw.domain,
            domain_suffix: raw.domain_suffix,
            domain_keyword: raw.domain_keyword,
            domain_regex: raw.domain_regex,
            ip_cidr: raw.ip_cidr,
            ip_version: raw.ip_version,
            port: raw.port,
            port_range: raw.port_range,
            network: raw.network,
            protocol: raw.protocol,
            rule_set: raw.rule_set,
            invert: raw.invert,
            any: raw.any,
            all: raw.all,
        };
        validate_match_config(&config).map_err(serde::de::Error::custom)?;
        Ok(config)
    }
}

/// Error returned when a serializable route matcher cannot be compiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePredicateError(String);

impl RoutePredicateError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for RoutePredicateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RoutePredicateError {}

fn validate_match_config(config: &RouteMatchConfig) -> Result<(), RoutePredicateError> {
    for value in &config.domain_regex {
        Regex::new(value).map_err(|error| {
            RoutePredicateError::new(format!("invalid domain_regex '{value}': {error}"))
        })?;
    }
    for value in &config.ip_cidr {
        IpRange::parse_cidr(value)?;
    }
    for value in &config.ip_version {
        if !matches!(value, 4 | 6) {
            return Err(RoutePredicateError::new(format!(
                "invalid ip_version '{value}': expected 4 or 6"
            )));
        }
    }
    for value in &config.port_range {
        PortRange::parse(value)?;
    }
    for configured in &config.rule_set {
        configured
            .format
            .parse::<srs::SrsFormat>()
            .map_err(|error| RoutePredicateError::new(error.to_string()))?;
        if configured.path.as_os_str().is_empty() {
            return Err(RoutePredicateError::new(
                "route rule-set path cannot be empty",
            ));
        }
    }
    for child in config.any.iter().chain(&config.all) {
        validate_match_config(child)?;
    }
    Ok(())
}

fn describe_unsupported(rule_set: &SrsRuleSet) -> Vec<String> {
    let mut found = rule_set
        .unsupported_fields
        .iter()
        .map(|field| format!("top-level.{field}"))
        .collect::<Vec<_>>();
    for (index, rule) in rule_set.rules.iter().enumerate() {
        describe_unsupported_rule(rule, &format!("rules[{index}]"), &mut found);
    }
    if found.is_empty() {
        found.push("unknown unsupported rule content".into());
    }
    found
}

fn describe_unsupported_rule(rule: &SrsRule, path: &str, found: &mut Vec<String>) {
    match rule {
        SrsRule::Default(rule) => found.extend(
            rule.unsupported_fields
                .iter()
                .map(|field| format!("{path}.{field}")),
        ),
        SrsRule::Logical(rule) => {
            found.extend(
                rule.unsupported_fields
                    .iter()
                    .map(|field| format!("{path}.{field}")),
            );
            for (index, child) in rule.rules.iter().enumerate() {
                describe_unsupported_rule(child, &format!("{path}.rules[{index}]"), found);
            }
        }
        SrsRule::Unsupported(rule) => {
            found.push(format!("{path}.type={}", rule.rule_type));
            found.extend(rule.fields.iter().map(|field| format!("{path}.{field}")));
        }
    }
}

/// A validated, reusable routing predicate.
#[derive(Debug, Default)]
pub struct RoutePredicate {
    domain: HashSet<String>,
    domain_suffix: HashSet<String>,
    domain_keyword: Vec<String>,
    domain_regex: Vec<Regex>,
    ip_cidr: IpRanges,
    ip_version: Vec<u8>,
    port: Vec<u16>,
    port_range: Vec<PortRange>,
    network: Vec<RouteNetwork>,
    protocol: Vec<RouteProtocol>,
    invert: bool,
    any: Vec<RoutePredicate>,
    all: Vec<RoutePredicate>,
    rule_set_rules: Option<Vec<RoutePredicate>>,
    logical: Option<LogicalPredicate>,
    requires_ip: bool,
    uses_destination_port: bool,
    uses_context: bool,
    uses_protocol: bool,
}

#[derive(Debug)]
struct LogicalPredicate {
    mode: SrsLogicalMode,
    rules: Vec<RoutePredicate>,
}

impl RoutePredicate {
    /// Validate and compile a serializable matcher. Regex and CIDR parsing happens once.
    pub fn compile(config: &RouteMatchConfig) -> Result<Self, RoutePredicateError> {
        validate_match_config(config)?;
        let domain_regex = config
            .domain_regex
            .iter()
            .map(|value| {
                Regex::new(value).map_err(|error| {
                    RoutePredicateError(format!("invalid domain_regex '{value}': {error}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let ip_cidr = IpRanges::new(
            config
                .ip_cidr
                .iter()
                .map(|value| IpRange::parse_cidr(value))
                .collect::<Result<Vec<_>, _>>()?,
        );
        let port_range = config
            .port_range
            .iter()
            .map(|value| PortRange::parse(value))
            .collect::<Result<Vec<_>, _>>()?;
        let any = config
            .any
            .iter()
            .map(Self::compile)
            .collect::<Result<Vec<_>, _>>()?;
        let all = config
            .all
            .iter()
            .map(Self::compile)
            .collect::<Result<Vec<_>, _>>()?;
        let rule_set_rules = if config.rule_set.is_empty() {
            None
        } else {
            let mut rules = Vec::new();
            for configured in &config.rule_set {
                rules.extend(Self::compile_rule_set(configured)?);
            }
            Some(rules)
        };

        let requires_ip = !ip_cidr.is_empty()
            || any.iter().any(Self::requires_ip)
            || all.iter().any(Self::requires_ip)
            || rule_set_rules
                .as_ref()
                .is_some_and(|rules| rules.iter().any(Self::requires_ip));
        let uses_protocol = !config.protocol.is_empty()
            || any.iter().any(Self::uses_protocol)
            || all.iter().any(Self::uses_protocol)
            || rule_set_rules
                .as_ref()
                .is_some_and(|rules| rules.iter().any(Self::uses_protocol));
        let uses_destination_port = !config.port.is_empty()
            || !config.port_range.is_empty()
            || any.iter().any(Self::uses_destination_port)
            || all.iter().any(Self::uses_destination_port)
            || rule_set_rules
                .as_ref()
                .is_some_and(|rules| rules.iter().any(Self::uses_destination_port));
        let uses_context = !config.network.is_empty()
            || uses_protocol
            || any.iter().any(Self::uses_context)
            || all.iter().any(Self::uses_context)
            || rule_set_rules
                .as_ref()
                .is_some_and(|rules| rules.iter().any(Self::uses_context));

        Ok(Self {
            domain: config.domain.iter().map(|v| normalize_domain(v)).collect(),
            domain_suffix: config
                .domain_suffix
                .iter()
                .map(|v| normalize_domain(v).trim_start_matches('.').to_string())
                .collect(),
            domain_keyword: config.domain_keyword.clone(),
            domain_regex,
            ip_cidr,
            ip_version: config.ip_version.clone(),
            port: config.port.clone(),
            port_range,
            network: config.network.clone(),
            protocol: config.protocol.clone(),
            invert: config.invert,
            any,
            all,
            rule_set_rules,
            logical: None,
            requires_ip,
            uses_destination_port,
            uses_context,
            uses_protocol,
        })
    }

    fn compile_rule_set(
        configured: &RouteRuleSetConfig,
    ) -> Result<Vec<RoutePredicate>, RoutePredicateError> {
        let parsed =
            srs::parse_file_named(&configured.format, &configured.path).map_err(|error| {
                RoutePredicateError(format!(
                    "parse route rule-set '{}' as {}: {error}",
                    configured.path.display(),
                    configured.format
                ))
            })?;
        if parsed.rules.is_empty() {
            return Err(RoutePredicateError(format!(
                "route rule-set '{}' is empty; refusing a fail-open policy",
                configured.path.display()
            )));
        }
        if !parsed.is_fully_supported() {
            return Err(RoutePredicateError(format!(
                "route rule-set '{}' contains unsupported fields: {}",
                configured.path.display(),
                describe_unsupported(&parsed).join(", ")
            )));
        }
        parsed
            .rules
            .into_iter()
            .map(Self::compile_srs_rule)
            .collect()
    }

    fn compile_srs_rule(rule: SrsRule) -> Result<Self, RoutePredicateError> {
        match rule {
            SrsRule::Default(rule) => Self::compile_srs_default(rule),
            SrsRule::Logical(rule) => Self::compile_srs_logical(rule),
            SrsRule::Unsupported(rule) => Err(RoutePredicateError(format!(
                "unsupported SRS rule type '{}' ({})",
                rule.rule_type,
                rule.fields.join(", ")
            ))),
        }
    }

    fn compile_srs_default(rule: SrsDefaultRule) -> Result<Self, RoutePredicateError> {
        if !rule.unsupported_fields.is_empty() {
            return Err(RoutePredicateError(format!(
                "unsupported SRS default-rule fields: {}",
                rule.unsupported_fields.join(", ")
            )));
        }
        if rule.network.is_empty()
            && rule.domain.is_empty()
            && rule.domain_suffix.is_empty()
            && rule.domain_keyword.is_empty()
            && rule.domain_regex.is_empty()
            && rule.ip_cidr.is_empty()
            && rule.port.is_empty()
            && rule.port_range.is_empty()
        {
            return Err(RoutePredicateError::new(
                "empty SRS default rule is invalid",
            ));
        }
        let network = rule
            .network
            .iter()
            .map(|value| match value.trim().to_ascii_lowercase().as_str() {
                "tcp" => Ok(RouteNetwork::Tcp),
                "udp" => Ok(RouteNetwork::Udp),
                _ => Err(RoutePredicateError(format!(
                    "unsupported SRS network value '{value}'"
                ))),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let ip_ranges = rule
            .ip_cidr
            .iter()
            .map(|range| IpRange::from_bounds(range.start, range.end))
            .collect::<Result<Vec<_>, _>>()?;
        let port_range = rule
            .port_range
            .iter()
            .map(|range| format!("{}:{}", range.start, range.end))
            .collect();
        let mut predicate = Self::compile(&RouteMatchConfig {
            domain: rule.domain,
            domain_suffix: rule.domain_suffix,
            domain_keyword: rule.domain_keyword,
            domain_regex: rule.domain_regex,
            port: rule.port,
            port_range,
            network,
            invert: rule.invert,
            ..Default::default()
        })?;
        predicate.ip_cidr = IpRanges::new(ip_ranges);
        predicate.requires_ip = !predicate.ip_cidr.is_empty()
            || predicate.any.iter().any(Self::requires_ip)
            || predicate.all.iter().any(Self::requires_ip);
        Ok(predicate)
    }

    fn compile_srs_logical(rule: SrsLogicalRule) -> Result<Self, RoutePredicateError> {
        if !rule.unsupported_fields.is_empty() {
            return Err(RoutePredicateError(format!(
                "unsupported SRS logical-rule fields: {}",
                rule.unsupported_fields.join(", ")
            )));
        }
        if rule.rules.is_empty() {
            return Err(RoutePredicateError::new(
                "empty SRS logical rule is invalid",
            ));
        }
        let rules = rule
            .rules
            .into_iter()
            .map(Self::compile_srs_rule)
            .collect::<Result<Vec<_>, _>>()?;
        let requires_ip = rules.iter().any(Self::requires_ip);
        let uses_destination_port = rules.iter().any(Self::uses_destination_port);
        let uses_context = rules.iter().any(Self::uses_context);
        let uses_protocol = rules.iter().any(Self::uses_protocol);
        Ok(Self {
            invert: rule.invert,
            logical: Some(LogicalPredicate {
                mode: rule.mode,
                rules,
            }),
            requires_ip,
            uses_destination_port,
            uses_context,
            uses_protocol,
            ..Default::default()
        })
    }

    pub fn requires_ip(&self) -> bool {
        self.requires_ip
    }

    pub fn has_rule_set(config: &RouteMatchConfig) -> bool {
        !config.rule_set.is_empty() || config.any.iter().chain(&config.all).any(Self::has_rule_set)
    }

    pub fn uses_context(&self) -> bool {
        self.uses_context
    }

    pub fn uses_destination_port(&self) -> bool {
        self.uses_destination_port
    }

    pub fn uses_protocol(&self) -> bool {
        self.uses_protocol
    }

    /// Whether evaluating this particular destination needs a DNS result before its
    /// address category can be decided. A domain branch in the same OR group can make
    /// the result final without resolving the CIDR branch.
    pub fn needs_resolved_ip(
        &self,
        location: &NetLocation,
        resolved_ip: Option<IpAddr>,
        context: &RouteContext,
    ) -> bool {
        self.needs_resolved_ips(location, resolved_ip.as_slice(), context)
    }

    /// Slice-aware form of [`Self::needs_resolved_ip`]. Destination CIDR items
    /// use sing-box's any-address semantics across the complete ordered DNS result.
    pub fn needs_resolved_ips(
        &self,
        location: &NetLocation,
        resolved_ips: &[IpAddr],
        context: &RouteContext,
    ) -> bool {
        self.evaluate(location, resolved_ips, context) == MatchState::NeedsIp
    }

    /// Evaluate against a destination and any already-resolved IP address.
    pub fn matches(
        &self,
        location: &NetLocation,
        resolved_ip: Option<IpAddr>,
        context: &RouteContext,
    ) -> bool {
        self.matches_resolved_ips(location, resolved_ip.as_slice(), context)
    }

    /// Slice-aware form of [`Self::matches`]. Only destination IP predicates
    /// consume the resolved candidates; literal-only fields such as `ip_version`
    /// retain their sing-box route semantics.
    pub fn matches_resolved_ips(
        &self,
        location: &NetLocation,
        resolved_ips: &[IpAddr],
        context: &RouteContext,
    ) -> bool {
        self.evaluate(location, resolved_ips, context) == MatchState::Matches
    }

    fn evaluate(
        &self,
        location: &NetLocation,
        resolved_ips: &[IpAddr],
        context: &RouteContext,
    ) -> MatchState {
        self.evaluate_states_with_base(location, resolved_ips, context, 0)
            .outcome()
    }

    /// Evaluate a rule while retaining sing-box's address/port category state.
    ///
    /// A rule-set is not a plain boolean child: a direct matcher and a
    /// rule-set matcher may satisfy different members of the same category.
    /// Carrying the inherited bits into every rule-set branch reproduces that
    /// behavior without coupling the node-agent's topology model to shoes.
    fn evaluate_states_with_base(
        &self,
        location: &NetLocation,
        resolved_ips: &[IpAddr],
        context: &RouteContext,
        inherited_base: u8,
    ) -> RuleMatchStateSet {
        if let Some(logical) = &self.logical {
            return self.evaluate_logical_states(
                logical,
                location,
                resolved_ips,
                context,
                inherited_base,
            );
        }

        let hostname = context
            .sniffed_domain
            .as_deref()
            .map(normalize_domain)
            .or_else(|| match location.address() {
                Address::Hostname(value) => Some(normalize_domain(value)),
                _ => None,
            });
        let literal_destination_ip = match location.address() {
            Address::Ipv4(value) => Some(IpAddr::V4(*value)),
            Address::Ipv6(value) => Some(IpAddr::V6(*value)),
            Address::Hostname(_) => None,
        };

        let has_address_items = !self.domain.is_empty()
            || !self.domain_suffix.is_empty()
            || !self.domain_keyword.is_empty()
            || !self.domain_regex.is_empty()
            || !self.ip_cidr.is_empty();
        let has_port_items = !self.port.is_empty() || !self.port_range.is_empty();
        let evaluation_base = if self.invert { 0 } else { inherited_base };
        let mut states = RuleMatchStateSet::single(evaluation_base);
        if has_address_items {
            // sing-box destinationAddressItems semantics: every domain matcher and IP CIDR
            // belongs to one OR group. The DNS-dependent arm remains unknown until it is
            // actually needed; an already-matching domain arm avoids a needless lookup.
            let domain_match = hostname.as_ref().is_some_and(|host| {
                self.domain.contains(host)
                    || matches_any_domain_suffix(&self.domain_suffix, host)
                    || self
                        .domain_keyword
                        .iter()
                        .any(|keyword| host.contains(keyword))
                    || self
                        .domain_regex
                        .iter()
                        .any(|pattern| pattern.is_match(host))
            });
            let address_match = if domain_match {
                MatchState::Matches
            } else if self.ip_cidr.is_empty() {
                MatchState::DoesNotMatch
            } else if let Some(ip) = literal_destination_ip {
                MatchState::from_bool(self.ip_cidr.contains(ip))
            } else if !resolved_ips.is_empty() {
                MatchState::from_bool(
                    resolved_ips
                        .iter()
                        .copied()
                        .any(|ip| self.ip_cidr.contains(ip)),
                )
            } else {
                MatchState::NeedsIp
            };
            states = states.mark_category(RULE_MATCH_DESTINATION_ADDRESS, address_match);
        }

        let mut independent = MatchState::Matches;
        if !self.ip_version.is_empty() {
            let version_match = match literal_destination_ip {
                Some(IpAddr::V4(_)) => MatchState::from_bool(self.ip_version.contains(&4)),
                Some(IpAddr::V6(_)) => MatchState::from_bool(self.ip_version.contains(&6)),
                None => MatchState::DoesNotMatch,
            };
            independent = independent.and(version_match);
        }

        if has_port_items {
            // Exact ports and ranges are one destination-port OR group.
            states = states.mark_category(
                RULE_MATCH_DESTINATION_PORT,
                MatchState::from_bool(
                    self.port.contains(&location.port())
                        || self
                            .port_range
                            .iter()
                            .any(|range| range.contains(location.port())),
                ),
            );
        }
        if !self.network.is_empty() {
            independent = independent.and(MatchState::from_bool(
                context
                    .network
                    .is_some_and(|network| self.network.contains(&network)),
            ));
        }
        if !self.protocol.is_empty() {
            independent = independent.and(MatchState::from_bool(
                context
                    .protocol
                    .is_some_and(|protocol| self.protocol.contains(&protocol)),
            ));
        }
        if !self.any.is_empty() {
            let any_match = self
                .any
                .iter()
                .fold(MatchState::DoesNotMatch, |state, child| {
                    state.or(child.evaluate(location, resolved_ips, context))
                });
            independent = independent.and(any_match);
        }
        if !self.all.is_empty() {
            let all_match = self.all.iter().fold(MatchState::Matches, |state, child| {
                state.and(child.evaluate(location, resolved_ips, context))
            });
            independent = independent.and(all_match);
        }

        match independent {
            MatchState::DoesNotMatch => {
                return RuleMatchStateSet::inverted_failure(self.invert, inherited_base);
            }
            MatchState::NeedsIp => states = states.only_possible(),
            MatchState::Matches => {}
        }

        if let Some(rules) = &self.rule_set_rules {
            states = Self::evaluate_rule_set_states(rules, states, location, resolved_ips, context);
        }

        let mut required = 0;
        if has_address_items {
            required |= RULE_MATCH_DESTINATION_ADDRESS;
        }
        if has_port_items {
            required |= RULE_MATCH_DESTINATION_PORT;
        }
        states = states.filter_required(required);
        states.finish_invert(self.invert, inherited_base)
    }

    fn evaluate_rule_set_states(
        rules: &[RoutePredicate],
        bases: RuleMatchStateSet,
        location: &NetLocation,
        resolved_ips: &[IpAddr],
        context: &RouteContext,
    ) -> RuleMatchStateSet {
        let mut result = RuleMatchStateSet::empty();
        for base in RuleMatchStateSet::states(bases.possible) {
            let child = rules
                .iter()
                .fold(RuleMatchStateSet::empty(), |states, rule| {
                    states.merge(rule.evaluate_states_with_base(
                        location,
                        resolved_ips,
                        context,
                        base,
                    ))
                });
            if RuleMatchStateSet::contains(bases.definite, base) {
                result.definite |= child.definite;
                result.possible |= child.possible;
            } else {
                result.possible |= child.possible;
            }
        }
        result.possible |= result.definite;
        result
    }

    fn evaluate_logical_states(
        &self,
        logical: &LogicalPredicate,
        location: &NetLocation,
        resolved_ips: &[IpAddr],
        context: &RouteContext,
        inherited_base: u8,
    ) -> RuleMatchStateSet {
        let evaluation_base = if self.invert { 0 } else { inherited_base };
        let states = match logical.mode {
            SrsLogicalMode::And => logical.rules.iter().fold(
                RuleMatchStateSet::single(evaluation_base),
                |states, rule| {
                    states.combine(rule.evaluate_states_with_base(
                        location,
                        resolved_ips,
                        context,
                        evaluation_base,
                    ))
                },
            ),
            SrsLogicalMode::Or => {
                logical
                    .rules
                    .iter()
                    .fold(RuleMatchStateSet::empty(), |states, rule| {
                        states.merge(rule.evaluate_states_with_base(
                            location,
                            resolved_ips,
                            context,
                            evaluation_base,
                        ))
                    })
            }
        };
        states.finish_invert(self.invert, inherited_base)
    }
}

const RULE_MATCH_DESTINATION_ADDRESS: u8 = 1 << 0;
const RULE_MATCH_DESTINATION_PORT: u8 = 1 << 1;

/// Definite and IP-dependent possible sing-box category-state alternatives.
/// Bit `1 << state` represents one address/port category bitset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuleMatchStateSet {
    definite: u16,
    possible: u16,
}

impl RuleMatchStateSet {
    const fn empty() -> Self {
        Self {
            definite: 0,
            possible: 0,
        }
    }

    fn single(state: u8) -> Self {
        let bit = Self::state_bit(state);
        Self {
            definite: bit,
            possible: bit,
        }
    }

    fn possible(state: u8) -> Self {
        Self {
            definite: 0,
            possible: Self::state_bit(state),
        }
    }

    const fn state_bit(state: u8) -> u16 {
        1_u16 << state
    }

    fn contains(set: u16, state: u8) -> bool {
        set & Self::state_bit(state) != 0
    }

    fn states(set: u16) -> impl Iterator<Item = u8> {
        (0..4).filter(move |state| Self::contains(set, *state))
    }

    fn merge(self, other: Self) -> Self {
        Self {
            definite: self.definite | other.definite,
            possible: self.possible | other.possible,
        }
    }

    fn combine(self, other: Self) -> Self {
        Self {
            definite: Self::combine_sets(self.definite, other.definite),
            possible: Self::combine_sets(self.possible, other.possible),
        }
    }

    fn combine_sets(left: u16, right: u16) -> u16 {
        let mut combined = 0;
        for left_state in Self::states(left) {
            for right_state in Self::states(right) {
                combined |= Self::state_bit(left_state | right_state);
            }
        }
        combined
    }

    fn mark_category(self, category: u8, matched: MatchState) -> Self {
        match matched {
            MatchState::Matches => Self {
                definite: Self::mark_set(self.definite, category),
                possible: Self::mark_set(self.possible, category),
            },
            MatchState::DoesNotMatch => self,
            MatchState::NeedsIp => Self {
                // Retaining the unmarked path lets a rule-set branch fill the
                // category without forcing an otherwise unnecessary lookup.
                definite: self.definite,
                possible: self.possible | Self::mark_set(self.possible, category),
            },
        }
    }

    fn mark_set(set: u16, category: u8) -> u16 {
        Self::states(set).fold(0, |marked, state| {
            marked | Self::state_bit(state | category)
        })
    }

    fn filter_required(self, required: u8) -> Self {
        let filter = |set| {
            Self::states(set).fold(0, |filtered, state| {
                if state & required == required {
                    filtered | Self::state_bit(state)
                } else {
                    filtered
                }
            })
        };
        Self {
            definite: filter(self.definite),
            possible: filter(self.possible),
        }
    }

    fn only_possible(self) -> Self {
        Self {
            definite: 0,
            possible: self.possible,
        }
    }

    fn inverted_failure(invert: bool, inherited_base: u8) -> Self {
        if invert {
            Self::single(inherited_base)
        } else {
            Self::empty()
        }
    }

    fn finish_invert(self, invert: bool, inherited_base: u8) -> Self {
        if !invert {
            return self;
        }
        if self.definite != 0 {
            Self::empty()
        } else if self.possible != 0 {
            Self::possible(inherited_base)
        } else {
            Self::single(inherited_base)
        }
    }

    fn outcome(self) -> MatchState {
        if self.definite != 0 {
            MatchState::Matches
        } else if self.possible != 0 {
            MatchState::NeedsIp
        } else {
            MatchState::DoesNotMatch
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchState {
    Matches,
    DoesNotMatch,
    NeedsIp,
}

impl MatchState {
    fn from_bool(value: bool) -> Self {
        if value {
            Self::Matches
        } else {
            Self::DoesNotMatch
        }
    }

    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::DoesNotMatch, _) | (_, Self::DoesNotMatch) => Self::DoesNotMatch,
            (Self::NeedsIp, _) | (_, Self::NeedsIp) => Self::NeedsIp,
            (Self::Matches, Self::Matches) => Self::Matches,
        }
    }

    fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Matches, _) | (_, Self::Matches) => Self::Matches,
            (Self::NeedsIp, _) | (_, Self::NeedsIp) => Self::NeedsIp,
            (Self::DoesNotMatch, Self::DoesNotMatch) => Self::DoesNotMatch,
        }
    }
}

fn normalize_domain(value: &str) -> String {
    value.trim().trim_end_matches('.').to_lowercase()
}

fn matches_any_domain_suffix(suffixes: &HashSet<String>, hostname: &str) -> bool {
    if suffixes.contains(hostname) {
        return true;
    }
    hostname
        .match_indices('.')
        .any(|(separator, _)| suffixes.contains(&hostname[separator + 1..]))
}

#[derive(Debug)]
enum IpRange {
    V4 { start: u32, end: u32 },
    V6 { start: u128, end: u128 },
}

/// Sorted, coalesced IP intervals. GeoIP SRS files commonly contain hundreds of
/// thousands of ranges, so per-request linear scans are not acceptable here.
#[derive(Debug, Default)]
struct IpRanges {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl IpRanges {
    fn new(ranges: Vec<IpRange>) -> Self {
        let mut result = Self::default();
        for range in ranges {
            match range {
                IpRange::V4 { start, end } => result.v4.push((start, end)),
                IpRange::V6 { start, end } => result.v6.push((start, end)),
            }
        }
        result.v4 = merge_v4_ranges(result.v4);
        result.v6 = merge_v6_ranges(result.v6);
        result
    }

    fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    fn contains(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(address) => {
                let value = u32::from(address);
                let index = self.v4.partition_point(|(start, _)| *start <= value);
                index > 0 && value <= self.v4[index - 1].1
            }
            IpAddr::V6(address) => {
                let value = u128::from(address);
                let index = self.v6.partition_point(|(start, _)| *start <= value);
                index > 0 && value <= self.v6[index - 1].1
            }
        }
    }
}

fn merge_v4_ranges(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    ranges.sort_unstable_by_key(|range| range.0);
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(previous) = merged.last_mut()
            && start <= previous.1.saturating_add(1)
        {
            previous.1 = previous.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
}

fn merge_v6_ranges(mut ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    ranges.sort_unstable_by_key(|range| range.0);
    let mut merged: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(previous) = merged.last_mut()
            && start <= previous.1.saturating_add(1)
        {
            previous.1 = previous.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
}

impl IpRange {
    fn parse_cidr(value: &str) -> Result<Self, RoutePredicateError> {
        let (address, prefix) = match value.trim().split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (value.trim(), None),
        };
        let address = address
            .parse::<IpAddr>()
            .map_err(|error| RoutePredicateError(format!("invalid ip_cidr '{value}': {error}")))?;
        match address {
            IpAddr::V4(address) => {
                let prefix = parse_prefix(value, prefix, 32)?;
                let mask = prefix_mask_v4(prefix);
                Ok(Self::V4 {
                    start: u32::from(address) & mask,
                    end: (u32::from(address) & mask) | !mask,
                })
            }
            IpAddr::V6(address) => {
                let prefix = parse_prefix(value, prefix, 128)?;
                let mask = prefix_mask_v6(prefix);
                Ok(Self::V6 {
                    start: u128::from(address) & mask,
                    end: (u128::from(address) & mask) | !mask,
                })
            }
        }
    }

    fn from_bounds(start: IpAddr, end: IpAddr) -> Result<Self, RoutePredicateError> {
        match (start, end) {
            (IpAddr::V4(start), IpAddr::V4(end)) if start <= end => Ok(Self::V4 {
                start: u32::from(start),
                end: u32::from(end),
            }),
            (IpAddr::V6(start), IpAddr::V6(end)) if start <= end => Ok(Self::V6 {
                start: u128::from(start),
                end: u128::from(end),
            }),
            (start, end) => Err(RoutePredicateError(format!(
                "invalid SRS IP range {start}..={end}"
            ))),
        }
    }
}

fn parse_prefix(
    original: &str,
    prefix: Option<&str>,
    maximum: u8,
) -> Result<u8, RoutePredicateError> {
    let prefix = match prefix {
        Some(value) => value.parse::<u8>().map_err(|error| {
            RoutePredicateError(format!("invalid ip_cidr '{original}': {error}"))
        })?,
        None => maximum,
    };
    if prefix > maximum {
        return Err(RoutePredicateError(format!(
            "invalid ip_cidr '{original}': prefix must be <= {maximum}"
        )));
    }
    Ok(prefix)
}

fn prefix_mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn prefix_mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[derive(Debug)]
struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    fn parse(value: &str) -> Result<Self, RoutePredicateError> {
        let value = value.trim();
        let components = value.split_once(':').or_else(|| value.split_once('-'));
        let (start, end) = match components {
            Some((start, end)) => (parse_port(value, start)?, parse_port(value, end)?),
            None => {
                let port = parse_port(value, value)?;
                (port, port)
            }
        };
        if start > end {
            return Err(RoutePredicateError(format!(
                "invalid port_range '{value}': start exceeds end"
            )));
        }
        Ok(Self { start, end })
    }

    fn contains(&self, port: u16) -> bool {
        (self.start..=self.end).contains(&port)
    }
}

fn parse_port(original: &str, value: &str) -> Result<u16, RoutePredicateError> {
    value
        .trim()
        .parse::<u16>()
        .map_err(|error| RoutePredicateError(format!("invalid port_range '{original}': {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn location(host: &str, port: u16) -> NetLocation {
        NetLocation::new(Address::from(host).unwrap(), port)
    }

    fn source_rule_set(contents: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    #[test]
    fn deserializes_scalar_or_list_and_validates_input() {
        let config: RouteMatchConfig = serde_yaml::from_str(
            r#"
domain: Example.COM.
port: [80, 443]
network: tcp
ip_version: 4
protocol: [http, tls]
"#,
        )
        .unwrap();
        assert_eq!(config.domain, vec!["Example.COM."]);
        assert_eq!(config.port, vec![80, 443]);
        assert_eq!(config.network, vec![RouteNetwork::Tcp]);
        assert_eq!(config.ip_version, vec![4]);
        assert_eq!(
            config.protocol,
            vec![RouteProtocol::Http, RouteProtocol::Tls]
        );

        assert!(serde_yaml::from_str::<RouteMatchConfig>("domain_regex: '[a-'\n").is_err());
        assert!(serde_yaml::from_str::<RouteMatchConfig>("ip_cidr: 10.0.0.0/40\n").is_err());
        assert!(serde_yaml::from_str::<RouteMatchConfig>("port_range: 9000:8000\n").is_err());
        assert!(serde_yaml::from_str::<RouteMatchConfig>("ip_version: 5\n").is_err());
        assert!(serde_yaml::from_str::<RouteMatchConfig>("protocol: quic\n").is_err());
    }

    #[test]
    fn ip_version_matches_only_literal_destination_family() {
        let ipv6 = RoutePredicate::compile(&RouteMatchConfig {
            ip_version: vec![6],
            ..Default::default()
        })
        .unwrap();
        let context = RouteContext::default();

        assert!(ipv6.matches(&location("2001:db8::1", 443), None, &context));
        assert!(!ipv6.matches(&location("192.0.2.1", 443), None, &context));
        assert!(!ipv6.needs_resolved_ip(&location("example.com", 443), None, &context));
        assert!(!ipv6.matches(
            &location("example.com", 443),
            Some("2001:db8::2".parse().unwrap()),
            &context
        ));
        assert!(!ipv6.matches(
            &location("example.com", 443),
            Some("192.0.2.2".parse().unwrap()),
            &context
        ));
    }

    #[test]
    fn cidr_uses_any_resolved_candidate_before_applying_invert() {
        let config = RouteMatchConfig {
            ip_cidr: vec!["10.0.0.0/8".into()],
            ..Default::default()
        };
        let predicate = RoutePredicate::compile(&config).unwrap();
        let inverted = RoutePredicate::compile(&RouteMatchConfig {
            invert: true,
            ..config
        })
        .unwrap();
        let destination = location("multi.example", 443);
        let candidates = ["192.0.2.1".parse().unwrap(), "10.1.2.3".parse().unwrap()];

        assert!(predicate.matches_resolved_ips(&destination, &candidates, &RouteContext::tcp()));
        assert!(!inverted.matches_resolved_ips(&destination, &candidates, &RouteContext::tcp()));
    }

    #[test]
    fn different_destination_categories_use_and_semantics() {
        let config: RouteMatchConfig = serde_yaml::from_str(
            r#"
domain_suffix: example.com
domain_keyword: api
domain_regex: '^api\.'
port_range: 8000:9000
network: [tcp]
"#,
        )
        .unwrap();
        let predicate = RoutePredicate::compile(&config).unwrap();
        assert!(predicate.matches(
            &location("API.Example.COM.", 8443),
            None,
            &RouteContext::tcp()
        ));
        assert!(!predicate.matches(
            &location("www.other.test", 8443),
            None,
            &RouteContext::tcp()
        ));
        assert!(!predicate.matches(
            &location("api.example.com", 443),
            None,
            &RouteContext::tcp()
        ));
        assert!(!predicate.matches(
            &location("api.example.com", 8443),
            None,
            &RouteContext::udp()
        ));
    }

    #[test]
    fn domain_keyword_and_regex_keep_configured_case() {
        let predicate = RoutePredicate::compile(&RouteMatchConfig {
            domain_keyword: vec!["NeEdLe".into()],
            domain_regex: vec![r"^API[0-9]+\.example$".into()],
            ..Default::default()
        })
        .unwrap();
        let context = RouteContext::tcp();

        for destination in ["has-needle.example", "api42.example", "API42.EXAMPLE"] {
            assert!(!predicate.matches(&location(destination, 443), None, &context));
        }

        let lowercase = RoutePredicate::compile(&RouteMatchConfig {
            domain_keyword: vec!["needle".into()],
            domain_regex: vec![r"^api[0-9]+\.example$".into()],
            ..Default::default()
        })
        .unwrap();
        assert!(lowercase.matches(&location("HAS-NEEDLE.EXAMPLE", 443), None, &context));
        assert!(lowercase.matches(&location("API42.EXAMPLE", 443), None, &context));
    }

    #[test]
    fn address_items_are_one_or_group() {
        let predicate = RoutePredicate::compile(&RouteMatchConfig {
            domain: vec!["exact.example".into()],
            domain_suffix: vec!["suffix.example".into()],
            domain_keyword: vec!["keyword".into()],
            domain_regex: vec![r"^regex\d+\.example$".into()],
            ip_cidr: vec!["10.0.0.0/8".into()],
            ..Default::default()
        })
        .unwrap();
        let context = RouteContext::default();

        for destination in [
            "exact.example",
            "api.suffix.example",
            "has-keyword.example",
            "regex42.example",
            "10.1.2.3",
        ] {
            assert!(
                predicate.matches(&location(destination, 443), None, &context),
                "{destination} should match one address item"
            );
        }
        assert!(!predicate.matches(&location("unrelated.example", 443), None, &context));
        assert!(predicate.needs_resolved_ip(&location("unrelated.example", 443), None, &context));
        assert!(!predicate.needs_resolved_ip(&location("exact.example", 443), None, &context));
    }

    #[test]
    fn exact_ports_and_ranges_are_one_or_group() {
        let predicate = RoutePredicate::compile(&RouteMatchConfig {
            port: vec![53, 443],
            port_range: vec!["8000:9000".into()],
            ..Default::default()
        })
        .unwrap();
        let context = RouteContext::default();
        assert!(predicate.matches(&location("example.com", 443), None, &context));
        assert!(predicate.matches(&location("example.com", 8443), None, &context));
        assert!(!predicate.matches(&location("example.com", 808), None, &context));
    }

    #[test]
    fn exact_domain_is_not_suffix_and_cidr_respects_address_family() {
        let exact = RoutePredicate::compile(&RouteMatchConfig {
            domain: vec!["example.com".into()],
            ..Default::default()
        })
        .unwrap();
        assert!(exact.matches(
            &location("example.com", 443),
            None,
            &RouteContext::default()
        ));
        assert!(!exact.matches(
            &location("www.example.com", 443),
            None,
            &RouteContext::default()
        ));

        let cidr = RoutePredicate::compile(&RouteMatchConfig {
            ip_cidr: vec!["10.0.0.0/8".into(), "2001:db8::/32".into()],
            ..Default::default()
        })
        .unwrap();
        assert!(cidr.matches(&location("10.1.2.3", 443), None, &RouteContext::default()));
        assert!(cidr.matches(
            &location("host.invalid", 443),
            Some("2001:db8::1".parse().unwrap()),
            &RouteContext::default()
        ));
        assert!(!cidr.matches(&location("192.0.2.1", 443), None, &RouteContext::default()));
    }

    #[test]
    fn ip_ranges_are_sorted_coalesced_and_binary_searched() {
        let ranges = IpRanges::new(vec![
            IpRange::parse_cidr("10.128.0.0/9").unwrap(),
            IpRange::parse_cidr("2001:db8:1::/48").unwrap(),
            IpRange::parse_cidr("10.0.0.0/9").unwrap(),
            IpRange::parse_cidr("10.64.0.0/10").unwrap(),
            IpRange::parse_cidr("2001:db8::/48").unwrap(),
        ]);
        assert_eq!(ranges.v4.len(), 1);
        assert_eq!(ranges.v6.len(), 1);
        assert!(ranges.contains("10.255.255.255".parse().unwrap()));
        assert!(!ranges.contains("11.0.0.0".parse().unwrap()));
        assert!(ranges.contains("2001:db8:1::1".parse().unwrap()));
    }

    #[test]
    fn supports_nested_any_all_and_invert() {
        let config: RouteMatchConfig = serde_yaml::from_str(
            r#"
all:
  - any:
      - domain_suffix: example.com
      - ip_cidr: 10.0.0.0/8
  - port: [443, 8443]
invert: true
"#,
        )
        .unwrap();
        let predicate = RoutePredicate::compile(&config).unwrap();
        assert!(!predicate.matches(
            &location("api.example.com", 443),
            None,
            &RouteContext::default()
        ));
        assert!(predicate.matches(
            &location("api.example.com", 80),
            None,
            &RouteContext::default()
        ));
    }

    #[test]
    fn network_predicate_reports_context_dependency() {
        let predicate = RoutePredicate::compile(&RouteMatchConfig {
            network: vec![RouteNetwork::Udp],
            ..Default::default()
        })
        .unwrap();
        assert!(predicate.uses_context());
        assert!(!predicate.matches(&location("example.com", 53), None, &RouteContext::default()));
        assert!(predicate.matches(&location("example.com", 53), None, &RouteContext::udp()));
    }

    #[test]
    fn loads_local_source_rule_set_and_ors_top_level_rules() {
        let file = source_rule_set(
            r#"{
  "version": 4,
  "rules": [
    {
      "domain_suffix": "ads.example",
      "port": 443,
      "network": "tcp"
    },
    { "ip_cidr": "10.0.0.0/8" }
  ]
}"#,
        );
        let predicate = RoutePredicate::compile(&RouteMatchConfig {
            rule_set: vec![RouteRuleSetConfig {
                format: "source".into(),
                path: file.path().into(),
            }],
            ..Default::default()
        })
        .unwrap();

        assert!(predicate.matches(
            &location("track.ads.example", 443),
            None,
            &RouteContext::tcp()
        ));
        assert!(!predicate.matches(
            &location("track.ads.example", 80),
            None,
            &RouteContext::tcp()
        ));
        assert!(predicate.matches(&location("10.2.3.4", 80), None, &RouteContext::udp()));
        assert!(!predicate.matches(
            &location("unrelated.example", 443),
            Some("192.0.2.1".parse().unwrap()),
            &RouteContext::tcp()
        ));
    }

    #[test]
    fn merges_direct_and_multiple_rule_sets_by_match_category() {
        let primary =
            source_rule_set(r#"{"version":4,"rules":[{"domain":"set.example","port":443}]}"#);
        let secondary = source_rule_set(
            r#"{"version":4,"rules":[{"domain":"other-set.example","port":8443}]}"#,
        );
        let config = RouteMatchConfig {
            domain: vec!["direct.example".into()],
            port: vec![80],
            rule_set: vec![
                RouteRuleSetConfig {
                    format: "source".into(),
                    path: primary.path().into(),
                },
                RouteRuleSetConfig {
                    format: "source".into(),
                    path: secondary.path().into(),
                },
            ],
            ..Default::default()
        };
        let predicate = RoutePredicate::compile(&config).unwrap();

        // Direct and rule-set arms can fill different address/port categories.
        for (host, port) in [
            ("direct.example", 443),
            ("set.example", 80),
            ("other-set.example", 80),
            ("direct.example", 80),
        ] {
            assert!(
                predicate.matches(&location(host, port), None, &RouteContext::tcp()),
                "{host}:{port} should match the merged category state"
            );
        }
        assert!(!predicate.matches(
            &location("unrelated.example", 80),
            None,
            &RouteContext::tcp()
        ));
        assert!(!predicate.matches(&location("direct.example", 22), None, &RouteContext::tcp()));

        let inverted = RoutePredicate::compile(&RouteMatchConfig {
            invert: true,
            ..config
        })
        .unwrap();
        assert!(!inverted.matches(&location("direct.example", 443), None, &RouteContext::tcp()));
        assert!(inverted.matches(
            &location("unrelated.example", 80),
            None,
            &RouteContext::tcp()
        ));
    }

    #[test]
    fn multi_address_cidr_preserves_rule_set_category_and_logical_semantics() {
        let category_set =
            source_rule_set(r#"{"version":4,"rules":[{"ip_cidr":"10.0.0.0/8","port":443}]}"#);
        let category = RoutePredicate::compile(&RouteMatchConfig {
            ip_cidr: vec!["203.0.113.0/24".into()],
            port: vec![80],
            rule_set: vec![RouteRuleSetConfig {
                format: "source".into(),
                path: category_set.path().into(),
            }],
            ..Default::default()
        })
        .unwrap();
        let candidates = ["198.51.100.7".parse().unwrap(), "10.2.3.4".parse().unwrap()];

        // The direct port category and the rule-set's destination-address
        // category may be filled by different arms. The matching CIDR is on
        // the second DNS candidate and must still fill the shared category.
        assert!(category.matches_resolved_ips(
            &location("category.example", 80),
            &candidates,
            &RouteContext::tcp()
        ));

        let logical_set = source_rule_set(
            r#"{
  "version": 4,
  "rules": [{
    "type": "logical",
    "mode": "and",
    "rules": [
      { "ip_cidr": "10.0.0.0/8", "invert": true },
      { "port": 443 }
    ]
  }]
}"#,
        );
        let logical = RoutePredicate::compile(&RouteMatchConfig {
            rule_set: vec![RouteRuleSetConfig {
                format: "source".into(),
                path: logical_set.path().into(),
            }],
            ..Default::default()
        })
        .unwrap();

        // Inversion applies after the CIDR item checks the entire candidate
        // set. It cannot be implemented by evaluating the whole logical rule
        // once per address and ORing those booleans.
        assert!(!logical.matches_resolved_ips(
            &location("logical.example", 443),
            &candidates,
            &RouteContext::tcp()
        ));
        assert!(logical.matches_resolved_ips(
            &location("logical.example", 443),
            &["198.51.100.7".parse().unwrap()],
            &RouteContext::tcp()
        ));
    }

    #[test]
    fn mixed_rule_set_avoids_lookup_when_its_domain_fills_unknown_ip_category() {
        let set = source_rule_set(r#"{"version":4,"rules":[{"domain":"known.example"}]}"#);
        let predicate = RoutePredicate::compile(&RouteMatchConfig {
            ip_cidr: vec!["10.0.0.0/8".into()],
            rule_set: vec![RouteRuleSetConfig {
                format: "source".into(),
                path: set.path().into(),
            }],
            ..Default::default()
        })
        .unwrap();

        assert!(predicate.matches(
            &location("known.example", 443),
            None,
            &RouteContext::default()
        ));
        assert!(!predicate.needs_resolved_ip(
            &location("known.example", 443),
            None,
            &RouteContext::default()
        ));
        assert!(predicate.needs_resolved_ip(
            &location("unknown.example", 443),
            None,
            &RouteContext::default()
        ));
        assert!(predicate.matches(
            &location("unknown.example", 443),
            Some("10.1.2.3".parse().unwrap()),
            &RouteContext::default()
        ));
        assert!(!predicate.matches(
            &location("unknown.example", 443),
            Some("192.0.2.1".parse().unwrap()),
            &RouteContext::default()
        ));
    }

    #[test]
    fn preserves_srs_logical_rules_and_rejects_empty_sets() {
        let logical = source_rule_set(
            r#"{
  "version": 4,
  "rules": [{
    "type": "logical",
    "mode": "and",
    "rules": [
      { "domain_suffix": "internal.example" },
      { "port_range": "8000:9000" }
    ]
  }]
}"#,
        );
        let logical = RoutePredicate::compile(&RouteMatchConfig {
            rule_set: vec![RouteRuleSetConfig {
                format: "json".into(),
                path: logical.path().into(),
            }],
            ..Default::default()
        })
        .unwrap();
        assert!(logical.matches(
            &location("api.internal.example", 8443),
            None,
            &RouteContext::default()
        ));
        assert!(!logical.matches(
            &location("api.internal.example", 443),
            None,
            &RouteContext::default()
        ));

        let empty = source_rule_set(r#"{"version":4,"rules":[]}"#);
        let empty = RoutePredicate::compile(&RouteMatchConfig {
            rule_set: vec![RouteRuleSetConfig {
                format: "source".into(),
                path: empty.path().into(),
            }],
            ..Default::default()
        })
        .unwrap_err();
        assert!(empty.to_string().contains("empty"));
        assert!(empty.to_string().contains("fail-open"));
    }

    #[test]
    fn rejects_unsupported_or_empty_rule_set_semantics() {
        let unsupported = source_rule_set(r#"{"version":4,"rules":[{"process_name":"browser"}]}"#);
        let error = RoutePredicate::compile(&RouteMatchConfig {
            rule_set: vec![RouteRuleSetConfig {
                format: "source".into(),
                path: unsupported.path().into(),
            }],
            ..Default::default()
        })
        .unwrap_err();
        assert!(error.to_string().contains("unsupported"));
        assert!(error.to_string().contains("process_name"));

        for (name, contents) in [
            ("default", r#"{"version":4,"rules":[{}]}"#),
            (
                "logical",
                r#"{"version":4,"rules":[{"type":"logical","mode":"or","rules":[]}]}"#,
            ),
        ] {
            let empty_rule = source_rule_set(contents);
            let error = RoutePredicate::compile(&RouteMatchConfig {
                rule_set: vec![RouteRuleSetConfig {
                    format: "source".into(),
                    path: empty_rule.path().into(),
                }],
                ..Default::default()
            })
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("empty SRS {name} rule")),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn protocol_and_sniffed_domain_are_anded_like_sing_box_metadata() {
        let predicate = RoutePredicate::compile(&RouteMatchConfig {
            domain_suffix: vec!["example.com".into()],
            protocol: vec![RouteProtocol::Tls],
            ..Default::default()
        })
        .unwrap();
        let destination = location("192.0.2.10", 443);

        assert!(!predicate.matches(&destination, None, &RouteContext::tcp()));
        assert!(predicate.matches(
            &destination,
            None,
            &RouteContext::sniffed_tcp(RouteProtocol::Tls, Some("api.example.com".into()))
        ));
        assert!(!predicate.matches(
            &destination,
            None,
            &RouteContext::sniffed_tcp(RouteProtocol::Http, Some("api.example.com".into()))
        ));
        assert!(!predicate.matches(
            &destination,
            None,
            &RouteContext::sniffed_tcp(RouteProtocol::Tls, Some("other.test".into()))
        ));
    }
}
