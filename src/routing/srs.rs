//! Strict, dependency-light parser for sing-box source and binary rule-sets.
//!
//! This module intentionally stops at an intermediate representation.  Loading,
//! refreshing and evaluating a rule-set belong to higher layers, which keeps SRS
//! support from coupling shoes' existing selector to sing-box's configuration
//! model.
//!
//! Binary fields that this intermediate representation cannot evaluate are still
//! consumed and recorded in `unsupported_fields`.  Callers must only compile a
//! rule when [`SrsRule::is_fully_supported`] returns `true`; silently discarding
//! such a field would turn a conjunction into a broader (and potentially
//! unconditional) match.

use std::{
    collections::BTreeSet,
    fmt,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    str::FromStr,
};

use flate2::read::ZlibDecoder;
use serde_json::{Map, Value};

const MAGIC: &[u8; 3] = b"SRS";
const MIN_VERSION: u8 = 1;
const MAX_VERSION: u8 = 4;

// These limits are deliberately generous enough for public GeoIP/geosite sets,
// while bounding allocations when a remote rule-set is corrupt or hostile.
const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES: usize = 256 * 1024 * 1024;
const MAX_RULES: usize = 1_000_000;
const MAX_LIST_ENTRIES: usize = 2_000_000;
const MAX_STRING_BYTES: usize = 1024 * 1024;
const MAX_RECOVERED_STRING_BYTES: usize = 128 * 1024 * 1024;
const MAX_LOGICAL_DEPTH: usize = 64;
const MAX_ITEMS_PER_RULE: usize = 256;

/// The representation used by a configured sing-box rule-set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrsFormat {
    /// JSON source rule-set (`source` in sing-box configuration).
    Source,
    /// Compiled, zlib-compressed `SRS` rule-set.
    Binary,
}

impl FromStr for SrsFormat {
    type Err = SrsParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "source" | "json" => Ok(Self::Source),
            "binary" | "srs" => Ok(Self::Binary),
            other => Err(SrsParseError::new(format!(
                "unsupported rule-set format `{other}`"
            ))),
        }
    }
}

/// A parsed sing-box rule-set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrsRuleSet {
    pub version: u8,
    pub rules: Vec<SrsRule>,
    /// Unknown source-level fields.  Binary rule-sets have none at this level.
    pub unsupported_fields: Vec<String>,
}

impl SrsRuleSet {
    /// Whether every field in the set can be represented by this module.
    pub fn is_fully_supported(&self) -> bool {
        self.unsupported_fields.is_empty() && self.rules.iter().all(SrsRule::is_fully_supported)
    }
}

/// A headless rule inside an SRS rule-set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrsRule {
    Default(SrsDefaultRule),
    Logical(SrsLogicalRule),
    /// A source JSON rule with a rule type whose shape is unknown to this parser.
    /// Binary unknown rule types are rejected because their payload length cannot
    /// be consumed safely.
    Unsupported(SrsUnsupportedRule),
}

impl SrsRule {
    /// Whether evaluating this rule while ignoring any predicate is impossible.
    pub fn is_fully_supported(&self) -> bool {
        match self {
            Self::Default(rule) => rule.unsupported_fields.is_empty(),
            Self::Logical(rule) => {
                rule.unsupported_fields.is_empty()
                    && rule.rules.iter().all(Self::is_fully_supported)
            }
            Self::Unsupported(_) => false,
        }
    }
}

/// A normal headless rule. Destination-address items are one OR category,
/// destination-port items are another; populated categories are ANDed by evaluators.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SrsDefaultRule {
    pub network: Vec<String>,
    pub domain: Vec<String>,
    pub domain_suffix: Vec<String>,
    pub domain_keyword: Vec<String>,
    pub domain_regex: Vec<String>,
    /// Destination IP ranges recovered from source CIDRs or an SRS IPSet.
    pub ip_cidr: Vec<SrsIpRange>,
    pub port: Vec<u16>,
    pub port_range: Vec<SrsPortRange>,
    pub invert: bool,
    /// Predicates that were consumed but cannot be evaluated by this model.
    pub unsupported_fields: Vec<String>,
}

/// An inclusive IP range.  sing-box binary IPSet entries are ranges rather than
/// necessarily being single CIDR prefixes, so retaining the range is lossless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SrsIpRange {
    pub start: IpAddr,
    pub end: IpAddr,
}

/// An inclusive destination-port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SrsPortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrsLogicalMode {
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrsLogicalRule {
    pub mode: SrsLogicalMode,
    pub rules: Vec<SrsRule>,
    pub invert: bool,
    pub unsupported_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrsUnsupportedRule {
    pub rule_type: String,
    pub fields: Vec<String>,
}

/// A bounded parse failure.  The error owns no input bytes and is safe to retain
/// in a remote rule-set loader's diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrsParseError {
    message: String,
}

impl SrsParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for SrsParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SrsParseError {}

/// Parse source JSON or compiled SRS bytes into the independent rule model.
pub fn parse_bytes(format: SrsFormat, bytes: &[u8]) -> Result<SrsRuleSet, SrsParseError> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(limit_error("input bytes", MAX_INPUT_BYTES));
    }
    match format {
        SrsFormat::Source => parse_source(bytes),
        SrsFormat::Binary => parse_binary(bytes),
    }
}

/// Convenience entry point for configuration values such as `source` and
/// `binary`.
pub fn parse_bytes_named(format: &str, bytes: &[u8]) -> Result<SrsRuleSet, SrsParseError> {
    parse_bytes(format.parse()?, bytes)
}

/// Open and parse a local rule-set without ever allocating more than the input limit.
///
/// Checking metadata alone would be subject to a path replacement race and would not
/// protect pseudo-files whose reported length is zero. Opening first and reading through
/// `take` makes the cap apply to the actual file handle consumed by the parser.
pub fn parse_file_named(format: &str, path: &Path) -> Result<SrsRuleSet, SrsParseError> {
    let file = std::fs::File::open(path)
        .map_err(|error| SrsParseError::new(format!("open rule-set: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| SrsParseError::new(format!("read rule-set metadata: {error}")))?;
    if metadata.len() > MAX_INPUT_BYTES as u64 {
        return Err(limit_error("input bytes", MAX_INPUT_BYTES));
    }

    let mut bytes = Vec::with_capacity(metadata.len().min(MAX_INPUT_BYTES as u64) as usize);
    file.take(MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| SrsParseError::new(format!("read rule-set: {error}")))?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(limit_error("input bytes", MAX_INPUT_BYTES));
    }
    parse_bytes_named(format, &bytes)
}

fn limit_error(name: &str, limit: usize) -> SrsParseError {
    SrsParseError::new(format!("{name} exceeds safety limit {limit}"))
}

#[derive(Default)]
struct ParseBudget {
    rules: usize,
    list_entries: usize,
    recovered_string_bytes: usize,
}

impl ParseBudget {
    fn add_rule(&mut self) -> Result<(), SrsParseError> {
        self.rules = self
            .rules
            .checked_add(1)
            .ok_or_else(|| limit_error("rules", MAX_RULES))?;
        if self.rules > MAX_RULES {
            return Err(limit_error("rules", MAX_RULES));
        }
        Ok(())
    }

    fn add_entries(&mut self, count: usize) -> Result<(), SrsParseError> {
        self.list_entries = self
            .list_entries
            .checked_add(count)
            .ok_or_else(|| limit_error("list entries", MAX_LIST_ENTRIES))?;
        if self.list_entries > MAX_LIST_ENTRIES {
            return Err(limit_error("list entries", MAX_LIST_ENTRIES));
        }
        Ok(())
    }

    fn add_recovered_string(&mut self, length: usize) -> Result<(), SrsParseError> {
        if length > MAX_STRING_BYTES {
            return Err(limit_error("string bytes", MAX_STRING_BYTES));
        }
        self.recovered_string_bytes = self
            .recovered_string_bytes
            .checked_add(length)
            .ok_or_else(|| limit_error("recovered string bytes", MAX_RECOVERED_STRING_BYTES))?;
        if self.recovered_string_bytes > MAX_RECOVERED_STRING_BYTES {
            return Err(limit_error(
                "recovered string bytes",
                MAX_RECOVERED_STRING_BYTES,
            ));
        }
        Ok(())
    }
}

fn parse_source(bytes: &[u8]) -> Result<SrsRuleSet, SrsParseError> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| SrsParseError::new(format!("invalid source rule-set JSON: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| SrsParseError::new("source rule-set must be a JSON object"))?;

    let raw_version = object
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| SrsParseError::new("source rule-set version must be an integer"))?;
    let version = u8::try_from(raw_version)
        .map_err(|_| SrsParseError::new(format!("unsupported rule-set version {raw_version}")))?;
    validate_version(version)?;

    let raw_rules = object
        .get("rules")
        .and_then(Value::as_array)
        .ok_or_else(|| SrsParseError::new("source rule-set rules must be an array"))?;
    if raw_rules.len() > MAX_RULES {
        return Err(limit_error("rules", MAX_RULES));
    }

    let mut budget = ParseBudget::default();
    let mut rules = Vec::with_capacity(raw_rules.len());
    for (index, value) in raw_rules.iter().enumerate() {
        rules.push(
            parse_source_rule(value, 0, &mut budget)
                .map_err(|error| error.context(format!("rule[{index}]")))?,
        );
    }

    let unsupported_fields = object
        .keys()
        .filter(|key| key.as_str() != "version" && key.as_str() != "rules")
        .cloned()
        .collect();

    Ok(SrsRuleSet {
        version,
        rules,
        unsupported_fields,
    })
}

impl SrsParseError {
    fn context(self, context: impl fmt::Display) -> Self {
        Self::new(format!("{context}: {}", self.message))
    }
}

fn parse_source_rule(
    value: &Value,
    depth: usize,
    budget: &mut ParseBudget,
) -> Result<SrsRule, SrsParseError> {
    if depth > MAX_LOGICAL_DEPTH {
        return Err(limit_error("logical rule depth", MAX_LOGICAL_DEPTH));
    }
    budget.add_rule()?;
    let object = value
        .as_object()
        .ok_or_else(|| SrsParseError::new("rule must be a JSON object"))?;
    let rule_type = match object.get("type") {
        None => "default",
        Some(Value::String(value)) => value.as_str(),
        Some(_) => return Err(SrsParseError::new("rule type must be a string")),
    };

    match rule_type {
        "" | "default" => Ok(SrsRule::Default(parse_source_default(object, budget)?)),
        "logical" => Ok(SrsRule::Logical(parse_source_logical(
            object, depth, budget,
        )?)),
        other => Ok(SrsRule::Unsupported(SrsUnsupportedRule {
            rule_type: other.to_owned(),
            fields: object.keys().cloned().collect(),
        })),
    }
}

fn parse_source_default(
    object: &Map<String, Value>,
    budget: &mut ParseBudget,
) -> Result<SrsDefaultRule, SrsParseError> {
    const SUPPORTED: &[&str] = &[
        "type",
        "network",
        "domain",
        "domain_suffix",
        "domain_keyword",
        "domain_regex",
        "ip_cidr",
        "port",
        "port_range",
        "invert",
    ];

    let mut rule = SrsDefaultRule {
        network: parse_optional_string_list(object, "network", budget)?,
        domain: parse_optional_string_list(object, "domain", budget)?,
        domain_suffix: parse_optional_string_list(object, "domain_suffix", budget)?,
        domain_keyword: parse_optional_string_list(object, "domain_keyword", budget)?,
        domain_regex: parse_optional_string_list(object, "domain_regex", budget)?,
        ip_cidr: parse_source_ip_ranges(object.get("ip_cidr"), budget)?,
        port: parse_source_ports(object.get("port"), budget)?,
        port_range: parse_source_port_ranges(object.get("port_range"), budget)?,
        invert: parse_optional_bool(object, "invert")?,
        unsupported_fields: object
            .keys()
            .filter(|key| !SUPPORTED.contains(&key.as_str()))
            .cloned()
            .collect(),
    };

    for network in &rule.network {
        if network != "tcp" && network != "udp" {
            mark_unsupported(&mut rule.unsupported_fields, format!("network={network}"));
        }
    }
    Ok(rule)
}

fn parse_source_logical(
    object: &Map<String, Value>,
    depth: usize,
    budget: &mut ParseBudget,
) -> Result<SrsLogicalRule, SrsParseError> {
    let mode = match object.get("mode").and_then(Value::as_str) {
        Some("and") => SrsLogicalMode::And,
        Some("or") => SrsLogicalMode::Or,
        Some(other) => {
            return Err(SrsParseError::new(format!(
                "unknown logical mode `{other}`"
            )));
        }
        None => return Err(SrsParseError::new("logical rule mode is required")),
    };
    let raw_rules = object
        .get("rules")
        .and_then(Value::as_array)
        .ok_or_else(|| SrsParseError::new("logical rule rules must be an array"))?;
    budget.add_entries(raw_rules.len())?;
    let mut rules = Vec::with_capacity(raw_rules.len());
    for (index, value) in raw_rules.iter().enumerate() {
        rules.push(
            parse_source_rule(value, depth + 1, budget)
                .map_err(|error| error.context(format!("logical rule[{index}]")))?,
        );
    }
    Ok(SrsLogicalRule {
        mode,
        rules,
        invert: parse_optional_bool(object, "invert")?,
        unsupported_fields: object
            .keys()
            .filter(|key| !matches!(key.as_str(), "type" | "mode" | "rules" | "invert"))
            .cloned()
            .collect(),
    })
}

fn parse_optional_bool(object: &Map<String, Value>, field: &str) -> Result<bool, SrsParseError> {
    match object.get(field) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(SrsParseError::new(format!(
            "field `{field}` must be a boolean"
        ))),
    }
}

fn parse_optional_string_list(
    object: &Map<String, Value>,
    field: &str,
    budget: &mut ParseBudget,
) -> Result<Vec<String>, SrsParseError> {
    match object.get(field) {
        None => Ok(Vec::new()),
        Some(value) => parse_string_list(value, field, budget),
    }
}

fn parse_string_list(
    value: &Value,
    field: &str,
    budget: &mut ParseBudget,
) -> Result<Vec<String>, SrsParseError> {
    let mut result = Vec::new();
    match value {
        Value::String(value) => {
            budget.add_entries(1)?;
            budget.add_recovered_string(value.len())?;
            result.push(value.clone());
        }
        Value::Array(values) => {
            budget.add_entries(values.len())?;
            result.reserve(values.len());
            for value in values {
                let value = value.as_str().ok_or_else(|| {
                    SrsParseError::new(format!("field `{field}` must contain only strings"))
                })?;
                budget.add_recovered_string(value.len())?;
                result.push(value.to_owned());
            }
        }
        _ => {
            return Err(SrsParseError::new(format!(
                "field `{field}` must be a string or string array"
            )));
        }
    }
    Ok(result)
}

fn parse_source_ports(
    value: Option<&Value>,
    budget: &mut ParseBudget,
) -> Result<Vec<u16>, SrsParseError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values: Vec<&Value> = match value {
        Value::Array(values) => values.iter().collect(),
        other => vec![other],
    };
    budget.add_entries(values.len())?;
    values
        .into_iter()
        .map(|value| {
            let port = value
                .as_u64()
                .ok_or_else(|| SrsParseError::new("field `port` must contain integers"))?;
            u16::try_from(port)
                .map_err(|_| SrsParseError::new(format!("port {port} is out of range")))
        })
        .collect()
}

fn parse_source_port_ranges(
    value: Option<&Value>,
    budget: &mut ParseBudget,
) -> Result<Vec<SrsPortRange>, SrsParseError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    parse_string_list(value, "port_range", budget)?
        .into_iter()
        .map(|value| parse_port_range(&value))
        .collect()
}

fn parse_port_range(value: &str) -> Result<SrsPortRange, SrsParseError> {
    let (start, end) = value
        .split_once(':')
        .ok_or_else(|| SrsParseError::new(format!("invalid port range `{value}`")))?;
    if end.contains(':') {
        return Err(SrsParseError::new(format!("invalid port range `{value}`")));
    }
    let start = if start.is_empty() {
        0
    } else {
        start
            .parse::<u16>()
            .map_err(|_| SrsParseError::new(format!("invalid port range `{value}`")))?
    };
    let end = if end.is_empty() {
        u16::MAX
    } else {
        end.parse::<u16>()
            .map_err(|_| SrsParseError::new(format!("invalid port range `{value}`")))?
    };
    if start > end {
        return Err(SrsParseError::new(format!(
            "port range `{value}` starts after it ends"
        )));
    }
    Ok(SrsPortRange { start, end })
}

fn parse_source_ip_ranges(
    value: Option<&Value>,
    budget: &mut ParseBudget,
) -> Result<Vec<SrsIpRange>, SrsParseError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    parse_string_list(value, "ip_cidr", budget)?
        .into_iter()
        .map(|value| parse_ip_range(&value))
        .collect()
}

fn parse_ip_range(value: &str) -> Result<SrsIpRange, SrsParseError> {
    if let Some((address, prefix)) = value.split_once('/') {
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| SrsParseError::new(format!("invalid IP CIDR `{value}`")))?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| SrsParseError::new(format!("invalid IP CIDR `{value}`")))?;
        return match address {
            IpAddr::V4(address) if prefix <= 32 => {
                let raw = u32::from(address);
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(prefix))
                };
                Ok(SrsIpRange {
                    start: IpAddr::V4(Ipv4Addr::from(raw & mask)),
                    end: IpAddr::V4(Ipv4Addr::from((raw & mask) | !mask)),
                })
            }
            IpAddr::V6(address) if prefix <= 128 => {
                let raw = u128::from(address);
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(prefix))
                };
                Ok(SrsIpRange {
                    start: IpAddr::V6(Ipv6Addr::from(raw & mask)),
                    end: IpAddr::V6(Ipv6Addr::from((raw & mask) | !mask)),
                })
            }
            _ => Err(SrsParseError::new(format!("invalid IP CIDR `{value}`"))),
        };
    }

    let address = value
        .parse::<IpAddr>()
        .map_err(|_| SrsParseError::new(format!("invalid IP address `{value}`")))?;
    Ok(SrsIpRange {
        start: address,
        end: address,
    })
}

fn parse_binary(bytes: &[u8]) -> Result<SrsRuleSet, SrsParseError> {
    if bytes.len() < MAGIC.len() + 1 || &bytes[..MAGIC.len()] != MAGIC {
        return Err(SrsParseError::new("invalid sing-box rule-set magic"));
    }
    let version = bytes[MAGIC.len()];
    validate_version(version)?;

    let decoder = ZlibDecoder::new(&bytes[MAGIC.len() + 1..]);
    let mut decompressed = Vec::new();
    decoder
        .take((MAX_DECOMPRESSED_BYTES + 1) as u64)
        .read_to_end(&mut decompressed)
        .map_err(|error| SrsParseError::new(format!("invalid SRS zlib body: {error}")))?;
    if decompressed.len() > MAX_DECOMPRESSED_BYTES {
        return Err(limit_error("decompressed bytes", MAX_DECOMPRESSED_BYTES));
    }

    let mut reader = BinaryReader::new(&decompressed);
    let count = reader.read_count("rules", MAX_RULES)?;
    let mut budget = ParseBudget::default();
    let mut rules = Vec::with_capacity(count);
    for index in 0..count {
        rules.push(
            parse_binary_rule(&mut reader, version, 0, &mut budget)
                .map_err(|error| error.context(format!("rule[{index}]")))?,
        );
    }
    if !reader.is_empty() {
        return Err(SrsParseError::new(format!(
            "SRS body contains {} trailing bytes",
            reader.remaining()
        )));
    }
    Ok(SrsRuleSet {
        version,
        rules,
        unsupported_fields: Vec::new(),
    })
}

fn validate_version(version: u8) -> Result<(), SrsParseError> {
    if !(MIN_VERSION..=MAX_VERSION).contains(&version) {
        return Err(SrsParseError::new(format!(
            "unsupported rule-set version {version}; expected {MIN_VERSION}..={MAX_VERSION}"
        )));
    }
    Ok(())
}

fn parse_binary_rule(
    reader: &mut BinaryReader<'_>,
    version: u8,
    depth: usize,
    budget: &mut ParseBudget,
) -> Result<SrsRule, SrsParseError> {
    if depth > MAX_LOGICAL_DEPTH {
        return Err(limit_error("logical rule depth", MAX_LOGICAL_DEPTH));
    }
    budget.add_rule()?;
    match reader.read_u8()? {
        0 => Ok(SrsRule::Default(parse_binary_default(
            reader, version, budget,
        )?)),
        1 => Ok(SrsRule::Logical(parse_binary_logical(
            reader, version, depth, budget,
        )?)),
        rule_type => Err(SrsParseError::new(format!(
            "unknown binary rule type {rule_type}"
        ))),
    }
}

fn parse_binary_default(
    reader: &mut BinaryReader<'_>,
    version: u8,
    budget: &mut ParseBudget,
) -> Result<SrsDefaultRule, SrsParseError> {
    let mut rule = SrsDefaultRule::default();
    let mut seen = BTreeSet::new();

    for _ in 0..MAX_ITEMS_PER_RULE {
        let item = reader.read_u8()?;
        if item == 0xff {
            rule.invert = reader.read_bool()?;
            return Ok(rule);
        }
        if !seen.insert(item) {
            return Err(SrsParseError::new(format!(
                "duplicate binary rule item {item}"
            )));
        }
        match item {
            // query_type
            0 => {
                reader.read_u16_vec(budget)?;
                mark_unsupported(&mut rule.unsupported_fields, "query_type");
            }
            // network
            1 => {
                rule.network = reader.read_string_vec(budget)?;
                for network in &rule.network {
                    if network != "tcp" && network != "udp" {
                        mark_unsupported(
                            &mut rule.unsupported_fields,
                            format!("network={network}"),
                        );
                    }
                }
            }
            // Combined exact/suffix domain succinct matcher.
            2 => {
                let (domain, suffix) = read_domain_matcher(reader, budget)?;
                rule.domain = domain;
                rule.domain_suffix = suffix;
            }
            3 => rule.domain_keyword = reader.read_string_vec(budget)?,
            4 => rule.domain_regex = reader.read_string_vec(budget)?,
            // source_ip_cidr
            5 => {
                read_ip_set(reader, budget)?;
                mark_unsupported(&mut rule.unsupported_fields, "source_ip_cidr");
            }
            // ip_cidr
            6 => rule.ip_cidr = read_ip_set(reader, budget)?,
            // source_port
            7 => {
                reader.read_u16_vec(budget)?;
                mark_unsupported(&mut rule.unsupported_fields, "source_port");
            }
            // source_port_range
            8 => {
                reader.read_string_vec(budget)?;
                mark_unsupported(&mut rule.unsupported_fields, "source_port_range");
            }
            // port
            9 => rule.port = reader.read_u16_vec(budget)?,
            // port_range
            10 => {
                rule.port_range = reader
                    .read_string_vec(budget)?
                    .into_iter()
                    .map(|value| parse_port_range(&value))
                    .collect::<Result<_, _>>()?;
            }
            // process_name, process_path, package_name, wifi_ssid, wifi_bssid
            11..=15 => {
                reader.read_string_vec(budget)?;
                mark_unsupported(
                    &mut rule.unsupported_fields,
                    match item {
                        11 => "process_name",
                        12 => "process_path",
                        13 => "package_name",
                        14 => "wifi_ssid",
                        _ => "wifi_bssid",
                    },
                );
            }
            // AdGuard matcher, introduced in SRS v2.
            16 => {
                require_version(version, 2, "adguard_domain")?;
                read_succinct_keys(reader, budget)?;
                mark_unsupported(&mut rule.unsupported_fields, "adguard_domain");
            }
            // process_path_regex
            17 => {
                reader.read_string_vec(budget)?;
                mark_unsupported(&mut rule.unsupported_fields, "process_path_regex");
            }
            // network_type, introduced in SRS v3
            18 => {
                require_version(version, 3, "network_type")?;
                reader.read_u8_vec(budget)?;
                mark_unsupported(&mut rule.unsupported_fields, "network_type");
            }
            // Boolean predicates have no payload in the binary format.
            19 | 20 => {
                require_version(version, 3, "network cost predicate")?;
                mark_unsupported(
                    &mut rule.unsupported_fields,
                    if item == 19 {
                        "network_is_expensive"
                    } else {
                        "network_is_constrained"
                    },
                );
            }
            // network_interface_address map, introduced in SRS v4
            21 => {
                require_version(version, 4, "network_interface_address")?;
                consume_interface_address_map(reader, budget)?;
                mark_unsupported(&mut rule.unsupported_fields, "network_interface_address");
            }
            // default_interface_address, introduced in SRS v4
            22 => {
                require_version(version, 4, "default_interface_address")?;
                consume_prefix_list(reader, budget)?;
                mark_unsupported(&mut rule.unsupported_fields, "default_interface_address");
            }
            // package_name_regex is version 5 and deliberately outside this API.
            23 => {
                return Err(SrsParseError::new(
                    "package_name_regex requires unsupported SRS version 5",
                ));
            }
            other => {
                return Err(SrsParseError::new(format!(
                    "unknown binary rule item {other}"
                )));
            }
        }
    }
    Err(limit_error("items per rule", MAX_ITEMS_PER_RULE))
}

fn parse_binary_logical(
    reader: &mut BinaryReader<'_>,
    version: u8,
    depth: usize,
    budget: &mut ParseBudget,
) -> Result<SrsLogicalRule, SrsParseError> {
    let mode = match reader.read_u8()? {
        0 => SrsLogicalMode::And,
        1 => SrsLogicalMode::Or,
        value => {
            return Err(SrsParseError::new(format!("unknown logical mode {value}")));
        }
    };
    let count = reader.read_count("logical rules", MAX_RULES)?;
    budget.add_entries(count)?;
    let mut rules = Vec::with_capacity(count);
    for index in 0..count {
        rules.push(
            parse_binary_rule(reader, version, depth + 1, budget)
                .map_err(|error| error.context(format!("logical rule[{index}]")))?,
        );
    }
    Ok(SrsLogicalRule {
        mode,
        rules,
        invert: reader.read_bool()?,
        unsupported_fields: Vec::new(),
    })
}

fn require_version(version: u8, minimum: u8, field: &str) -> Result<(), SrsParseError> {
    if version < minimum {
        return Err(SrsParseError::new(format!(
            "binary item `{field}` requires SRS version {minimum} or later"
        )));
    }
    Ok(())
}

fn consume_interface_address_map(
    reader: &mut BinaryReader<'_>,
    budget: &mut ParseBudget,
) -> Result<(), SrsParseError> {
    let count = reader.read_count("interface address entries", MAX_LIST_ENTRIES)?;
    budget.add_entries(count)?;
    for _ in 0..count {
        reader.read_u8()?; // interface type
        consume_prefix_list(reader, budget)?;
    }
    Ok(())
}

fn consume_prefix_list(
    reader: &mut BinaryReader<'_>,
    budget: &mut ParseBudget,
) -> Result<(), SrsParseError> {
    let count = reader.read_count("prefixes", MAX_LIST_ENTRIES)?;
    budget.add_entries(count)?;
    for _ in 0..count {
        let length = reader.read_count("IP address bytes", 16)?;
        if length != 4 && length != 16 {
            return Err(SrsParseError::new(format!(
                "invalid binary IP address length {length}"
            )));
        }
        reader.read_exact(length)?;
        let bits = reader.read_u8()?;
        if (length == 4 && bits > 32) || (length == 16 && bits > 128) {
            return Err(SrsParseError::new(format!(
                "invalid prefix length {bits} for {length}-byte address"
            )));
        }
    }
    Ok(())
}

fn read_ip_set(
    reader: &mut BinaryReader<'_>,
    budget: &mut ParseBudget,
) -> Result<Vec<SrsIpRange>, SrsParseError> {
    let version = reader.read_u8()?;
    if version != 1 {
        return Err(SrsParseError::new(format!(
            "unsupported binary IPSet version {version}"
        )));
    }
    // sing-box intentionally writes this count as a fixed-width big-endian u64.
    let count = reader.read_u64_be()?;
    let count = usize::try_from(count).map_err(|_| limit_error("IP ranges", MAX_LIST_ENTRIES))?;
    if count > MAX_LIST_ENTRIES {
        return Err(limit_error("IP ranges", MAX_LIST_ENTRIES));
    }
    budget.add_entries(count)?;
    let mut ranges = Vec::with_capacity(count);
    for _ in 0..count {
        let start = reader.read_ip_addr()?;
        let end = reader.read_ip_addr()?;
        if !ip_range_is_valid(start, end) {
            return Err(SrsParseError::new(format!(
                "invalid binary IP range {start}..={end}"
            )));
        }
        ranges.push(SrsIpRange { start, end });
    }
    Ok(ranges)
}

fn ip_range_is_valid(start: IpAddr, end: IpAddr) -> bool {
    match (start, end) {
        (IpAddr::V4(start), IpAddr::V4(end)) => u32::from(start) <= u32::from(end),
        (IpAddr::V6(start), IpAddr::V6(end)) => u128::from(start) <= u128::from(end),
        _ => false,
    }
}

fn read_domain_matcher(
    reader: &mut BinaryReader<'_>,
    budget: &mut ParseBudget,
) -> Result<(Vec<String>, Vec<String>), SrsParseError> {
    let keys = read_succinct_keys(reader, budget)?;
    let mut domains = BTreeSet::new();
    let mut suffixes = BTreeSet::new();
    let mut legacy_prefixes = BTreeSet::new();

    for key in keys {
        let key = reverse_unicode(&key);
        let Some(first) = key.chars().next() else {
            return Err(SrsParseError::new(
                "domain succinct matcher contains an empty key",
            ));
        };
        match first {
            '\r' => {
                legacy_prefixes.insert(key[first.len_utf8()..].to_owned());
            }
            '\n' => {
                let suffix = &key[first.len_utf8()..];
                if suffix.is_empty() {
                    return Err(SrsParseError::new(
                        "domain succinct matcher contains an empty suffix",
                    ));
                }
                suffixes.insert(suffix.to_owned());
            }
            _ => {
                domains.insert(key);
            }
        }
    }

    // Version 1 encoded a normal suffix as two keys: an exact root and a `\r`
    // marker for `.root`.  Later versions use `\nroot` directly.
    for prefix in legacy_prefixes {
        if let Some(root) = prefix.strip_prefix('.')
            && domains.remove(root)
        {
            suffixes.insert(root.to_owned());
            continue;
        }
        if prefix.is_empty() {
            return Err(SrsParseError::new(
                "domain succinct matcher contains an empty prefix",
            ));
        }
        suffixes.insert(prefix);
    }

    Ok((
        domains.into_iter().collect(),
        suffixes.into_iter().collect(),
    ))
}

fn reverse_unicode(value: &str) -> String {
    value.chars().rev().collect()
}

fn read_succinct_keys(
    reader: &mut BinaryReader<'_>,
    budget: &mut ParseBudget,
) -> Result<Vec<String>, SrsParseError> {
    let version = reader.read_u8()?;
    if version != 0 {
        return Err(SrsParseError::new(format!(
            "unsupported succinct matcher version {version}"
        )));
    }
    let leaves = reader.read_u64_vec()?;
    let bitmap = reader.read_u64_vec()?;
    let labels = reader.read_byte_vec()?;

    let Some(last_one) = bitmap
        .iter()
        .enumerate()
        .rev()
        .find_map(|(word_index, word)| {
            (*word != 0).then(|| word_index * 64 + (63 - word.leading_zeros() as usize))
        })
    else {
        return Err(SrsParseError::new(
            "domain succinct matcher has no root terminator",
        ));
    };

    let ones = (0..=last_one)
        .filter(|index| get_bit(&bitmap, *index))
        .count();
    let zeros = last_one + 1 - ones;
    if ones != zeros + 1 || labels.len() != zeros {
        return Err(SrsParseError::new(
            "malformed domain succinct matcher shape",
        ));
    }
    if ones > MAX_LIST_ENTRIES {
        return Err(limit_error("succinct matcher nodes", MAX_LIST_ENTRIES));
    }

    // A leaf bit beyond the represented node set is malformed rather than
    // padding: accepting it would make recovery implementation-dependent.
    for (word_index, word) in leaves.iter().enumerate() {
        let first_bit = word_index * 64;
        if first_bit >= ones {
            if *word != 0 {
                return Err(SrsParseError::new(
                    "domain succinct matcher has out-of-range leaf bits",
                ));
            }
        } else if first_bit + 64 > ones {
            let valid = ones - first_bit;
            let mask = if valid == 64 {
                u64::MAX
            } else {
                (1_u64 << valid) - 1
            };
            if word & !mask != 0 {
                return Err(SrsParseError::new(
                    "domain succinct matcher has out-of-range leaf bits",
                ));
            }
        }
    }

    // Decode LOUDS child ranges.  The nth zero describes edge n and therefore
    // child node n+1; the nth one terminates a node's child list.
    let mut first_edge = Vec::with_capacity(ones);
    let mut edge_count = Vec::with_capacity(ones);
    let mut edge = 0_usize;
    let mut group_start = 0_usize;
    for index in 0..=last_one {
        if get_bit(&bitmap, index) {
            first_edge.push(group_start);
            edge_count.push(edge - group_start);
            group_start = edge;
        } else {
            edge += 1;
        }
    }
    if first_edge.len() != ones || edge != labels.len() {
        return Err(SrsParseError::new(
            "malformed domain succinct matcher topology",
        ));
    }

    let is_leaf = |node: usize| get_bit(&leaves, node);
    let mut keys = Vec::new();
    let mut current = Vec::new();
    let mut stack = vec![(0_usize, 0_usize)];
    if is_leaf(0) {
        keys.push(String::new());
    }
    while let Some((node, child_offset)) = stack.last_mut() {
        if *child_offset < edge_count[*node] {
            let edge_index = first_edge[*node] + *child_offset;
            *child_offset += 1;
            let child = edge_index + 1;
            if child >= ones {
                return Err(SrsParseError::new(
                    "domain succinct matcher child is out of range",
                ));
            }
            current.push(labels[edge_index]);
            if current.len() > MAX_STRING_BYTES {
                return Err(limit_error("domain key bytes", MAX_STRING_BYTES));
            }
            if is_leaf(child) {
                budget.add_recovered_string(current.len())?;
                keys.push(
                    String::from_utf8(current.clone()).map_err(|_| {
                        SrsParseError::new("domain succinct matcher key is not UTF-8")
                    })?,
                );
            }
            stack.push((child, 0));
        } else {
            stack.pop();
            if !stack.is_empty() {
                current.pop();
            }
        }
    }
    budget.add_entries(keys.len())?;
    Ok(keys)
}

fn get_bit(words: &[u64], index: usize) -> bool {
    words
        .get(index >> 6)
        .is_some_and(|word| word & (1_u64 << (index & 63)) != 0)
}

fn mark_unsupported(fields: &mut Vec<String>, field: impl Into<String>) {
    let field = field.into();
    if !fields.contains(&field) {
        fields.push(field);
    }
}

struct BinaryReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BinaryReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    fn read_exact(&mut self, count: usize) -> Result<&'a [u8], SrsParseError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or_else(|| SrsParseError::new("binary offset overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| SrsParseError::new("unexpected end of SRS body"))?;
        self.position = end;
        Ok(value)
    }

    fn read_u8(&mut self) -> Result<u8, SrsParseError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_bool(&mut self) -> Result<bool, SrsParseError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(SrsParseError::new(format!(
                "invalid binary boolean {value}"
            ))),
        }
    }

    fn read_u16_be(&mut self) -> Result<u16, SrsParseError> {
        let bytes: [u8; 2] = self.read_exact(2)?.try_into().expect("two-byte slice");
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u64_be(&mut self) -> Result<u64, SrsParseError> {
        let bytes: [u8; 8] = self.read_exact(8)?.try_into().expect("eight-byte slice");
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_uvarint(&mut self) -> Result<u64, SrsParseError> {
        let mut value = 0_u64;
        for index in 0..10 {
            let byte = self.read_u8()?;
            if index == 9 && byte > 1 {
                return Err(SrsParseError::new("binary varint overflows u64"));
            }
            value |= u64::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(SrsParseError::new("binary varint is too long"))
    }

    fn read_count(&mut self, name: &str, limit: usize) -> Result<usize, SrsParseError> {
        let value = self.read_uvarint()?;
        let value = usize::try_from(value).map_err(|_| limit_error(name, limit))?;
        if value > limit {
            return Err(limit_error(name, limit));
        }
        Ok(value)
    }

    fn read_string_vec(&mut self, budget: &mut ParseBudget) -> Result<Vec<String>, SrsParseError> {
        let count = self.read_count("string list entries", MAX_LIST_ENTRIES)?;
        budget.add_entries(count)?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let length = self.read_count("string bytes", MAX_STRING_BYTES)?;
            budget.add_recovered_string(length)?;
            let bytes = self.read_exact(length)?;
            values.push(
                std::str::from_utf8(bytes)
                    .map_err(|_| SrsParseError::new("binary string is not UTF-8"))?
                    .to_owned(),
            );
        }
        Ok(values)
    }

    fn read_u8_vec(&mut self, budget: &mut ParseBudget) -> Result<Vec<u8>, SrsParseError> {
        let count = self.read_count("byte list entries", MAX_LIST_ENTRIES)?;
        budget.add_entries(count)?;
        Ok(self.read_exact(count)?.to_vec())
    }

    fn read_byte_vec(&mut self) -> Result<Vec<u8>, SrsParseError> {
        let count = self.read_count("byte slice bytes", MAX_RECOVERED_STRING_BYTES)?;
        Ok(self.read_exact(count)?.to_vec())
    }

    fn read_u16_vec(&mut self, budget: &mut ParseBudget) -> Result<Vec<u16>, SrsParseError> {
        let count = self.read_count("u16 list entries", MAX_LIST_ENTRIES)?;
        budget.add_entries(count)?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.read_u16_be()?);
        }
        Ok(values)
    }

    fn read_u64_vec(&mut self) -> Result<Vec<u64>, SrsParseError> {
        let count = self.read_count("u64 slice entries", MAX_DECOMPRESSED_BYTES / 8)?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.read_u64_be()?);
        }
        Ok(values)
    }

    fn read_ip_addr(&mut self) -> Result<IpAddr, SrsParseError> {
        let length = self.read_count("IP address bytes", 16)?;
        match length {
            4 => {
                let bytes: [u8; 4] = self.read_exact(4)?.try_into().expect("four-byte slice");
                Ok(IpAddr::V4(Ipv4Addr::from(bytes)))
            }
            16 => {
                let bytes: [u8; 16] = self.read_exact(16)?.try_into().expect("sixteen-byte slice");
                Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
            }
            other => Err(SrsParseError::new(format!(
                "invalid binary IP address length {other}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{Compression, write::ZlibEncoder};
    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn file_loader_rejects_oversized_input_before_reading_it_all() {
        let file = NamedTempFile::new().unwrap();
        file.as_file().set_len(MAX_INPUT_BYTES as u64 + 1).unwrap();
        let error = parse_file_named("source", file.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("input bytes exceeds safety limit")
        );
    }

    #[test]
    fn parses_supported_source_versions_without_degradation() {
        for version in 1..=4 {
            let source = format!(
                r#"{{
                    "version": {version},
                    "rules": [{{
                        "domain": ["exact.example"],
                        "domain_suffix": "example.com",
                        "domain_keyword": ["cdn"],
                        "domain_regex": ["^api\\d+\\.example$"],
                        "ip_cidr": ["192.0.2.7/24", "2001:db8::/126"],
                        "port": [53, 443],
                        "port_range": [":1024", "8000:"],
                        "network": ["tcp", "udp"],
                        "invert": true
                    }}]
                }}"#
            );
            let parsed = parse_bytes(SrsFormat::Source, source.as_bytes()).unwrap();
            assert_eq!(parsed.version, version);
            assert!(parsed.is_fully_supported());
            let SrsRule::Default(rule) = &parsed.rules[0] else {
                panic!("expected default rule");
            };
            assert_eq!(rule.domain, ["exact.example"]);
            assert_eq!(rule.domain_suffix, ["example.com"]);
            assert_eq!(rule.network, ["tcp", "udp"]);
            assert_eq!(rule.port, [53, 443]);
            assert_eq!(
                rule.port_range,
                [
                    SrsPortRange {
                        start: 0,
                        end: 1024
                    },
                    SrsPortRange {
                        start: 8000,
                        end: u16::MAX
                    }
                ]
            );
            assert_eq!(
                rule.ip_cidr[0],
                SrsIpRange {
                    start: "192.0.2.0".parse().unwrap(),
                    end: "192.0.2.255".parse().unwrap(),
                }
            );
            assert!(rule.invert);
        }
    }

    #[test]
    fn source_unsupported_predicate_is_never_silently_dropped() {
        let parsed = parse_bytes_named(
            "source",
            br#"{
                "version": 4,
                "rules": [{
                    "type": "logical",
                    "mode": "or",
                    "rules": [
                        {"domain_suffix": ["example.com"]},
                        {"process_name": ["browser"]}
                    ]
                }]
            }"#,
        )
        .unwrap();
        assert!(!parsed.is_fully_supported());
        let SrsRule::Logical(logical) = &parsed.rules[0] else {
            panic!("expected logical rule");
        };
        let SrsRule::Default(unsupported) = &logical.rules[1] else {
            panic!("expected default child");
        };
        assert_eq!(unsupported.unsupported_fields, ["process_name"]);
        assert!(unsupported.domain.is_empty());
    }

    #[test]
    fn parses_v4_binary_domain_ipset_ports_and_logical_rules() {
        let mut supported = vec![0]; // default rule
        supported.push(1); // network
        write_string_vec(&mut supported, &["tcp", "udp"]);
        supported.push(2); // domain matcher
        let keys = [
            reverse_unicode("exact.example"),
            reverse_unicode("\nexample.com"),
        ];
        write_succinct(&mut supported, &keys);
        supported.push(3);
        write_string_vec(&mut supported, &["cdn"]);
        supported.push(4);
        write_string_vec(&mut supported, &[r"^api\d+\.example$"]);
        supported.push(6); // destination IPSet
        write_ip_set(
            &mut supported,
            &[(
                "198.51.100.0".parse().unwrap(),
                "198.51.100.255".parse().unwrap(),
            )],
        );
        supported.push(9);
        write_u16_vec(&mut supported, &[53, 443]);
        supported.push(10);
        write_string_vec(&mut supported, &["1000:2000"]);
        supported.extend_from_slice(&[0xff, 0]);

        let mut unsupported_child = vec![0]; // default
        unsupported_child.push(7); // source_port
        write_u16_vec(&mut unsupported_child, &[12345]);
        unsupported_child.push(2);
        write_succinct(&mut unsupported_child, &[reverse_unicode("guard.example")]);
        unsupported_child.extend_from_slice(&[0xff, 0]);

        let mut logical = vec![1, 1]; // logical, OR
        write_uvarint(&mut logical, 1);
        logical.extend_from_slice(&unsupported_child);
        logical.push(0); // invert

        let binary = make_binary(4, &[supported, logical]);
        let parsed = parse_bytes(SrsFormat::Binary, &binary).unwrap();
        assert_eq!(parsed.version, 4);
        assert_eq!(parsed.rules.len(), 2);
        assert!(!parsed.is_fully_supported());

        let SrsRule::Default(rule) = &parsed.rules[0] else {
            panic!("expected default rule");
        };
        assert!(rule.unsupported_fields.is_empty());
        assert_eq!(rule.domain, ["exact.example"]);
        assert_eq!(rule.domain_suffix, ["example.com"]);
        assert_eq!(rule.domain_keyword, ["cdn"]);
        assert_eq!(rule.port, [53, 443]);
        assert_eq!(
            rule.ip_cidr,
            [SrsIpRange {
                start: "198.51.100.0".parse().unwrap(),
                end: "198.51.100.255".parse().unwrap(),
            }]
        );

        let SrsRule::Logical(logical) = &parsed.rules[1] else {
            panic!("expected logical rule");
        };
        let SrsRule::Default(child) = &logical.rules[0] else {
            panic!("expected default child");
        };
        assert_eq!(child.domain, ["guard.example"]);
        assert_eq!(child.unsupported_fields, ["source_port"]);
    }

    #[test]
    fn parses_fixture_written_by_sing_box_v1_13_19() {
        // Generated with common/srs.Write(..., RuleSetVersion4) from the exact
        // sing-box version currently used by the Go node-agent.  Keeping this
        // fixture static makes the Rust suite an actual cross-language format
        // check instead of only round-tripping our test encoder.
        const FIXTURE: &[u8] = &[
            0x53, 0x52, 0x53, 0x04, 0x78, 0xda, 0x5c, 0x8e, 0xb1, 0xaa, 0xc2, 0x30, 0x18, 0x85,
            0xcf, 0x9f, 0x94, 0x96, 0x16, 0x0a, 0xf7, 0x8e, 0x77, 0xeb, 0x70, 0x37, 0x21, 0x44,
            0xc5, 0x41, 0x9f, 0x43, 0xb7, 0x22, 0x84, 0xe4, 0x47, 0x84, 0x44, 0x83, 0xb4, 0x90,
            0x67, 0xea, 0x13, 0x08, 0xee, 0xbe, 0x56, 0xa5, 0xea, 0x20, 0x7e, 0xc3, 0xe1, 0x70,
            0x86, 0xc3, 0x27, 0x40, 0x42, 0x76, 0x36, 0xca, 0xde, 0x45, 0x01, 0x02, 0x00, 0x09,
            0x80, 0x50, 0xec, 0x26, 0xb6, 0x7f, 0x1c, 0xfc, 0x39, 0xda, 0xa0, 0x0c, 0x27, 0xcf,
            0x51, 0x85, 0xce, 0xd8, 0x64, 0x38, 0x55, 0x2c, 0x49, 0x5a, 0x77, 0xca, 0xe8, 0x77,
            0x6f, 0xe2, 0xb1, 0x75, 0xb3, 0x56, 0x71, 0x32, 0x21, 0x7a, 0xfe, 0xcf, 0x9f, 0x37,
            0x00, 0x44, 0x76, 0x5f, 0x3a, 0x4c, 0x31, 0xfe, 0x34, 0x54, 0x5f, 0xf1, 0xc1, 0xf7,
            0x20, 0x4b, 0x81, 0x15, 0xdd, 0x2a, 0x2a, 0xe7, 0x5a, 0xeb, 0xcd, 0x42, 0x6b, 0x3d,
            0x82, 0x88, 0xf0, 0xb6, 0x02, 0x9a, 0x57, 0xc9, 0x87, 0x61, 0xa8, 0xd9, 0xc7, 0x60,
            0x12, 0x2b, 0x77, 0x31, 0xfd, 0xa1, 0x20, 0xbd, 0x1e, 0x81, 0x47, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xa5, 0x32, 0x28, 0x1b,
        ];

        let parsed = parse_bytes(SrsFormat::Binary, FIXTURE).unwrap();
        assert_eq!(parsed.version, 4);
        assert_eq!(parsed.rules.len(), 2);
        let SrsRule::Default(rule) = &parsed.rules[0] else {
            panic!("expected default rule");
        };
        assert_eq!(rule.domain, ["exact.example"]);
        assert_eq!(rule.domain_suffix, ["example.com"]);
        assert_eq!(rule.domain_keyword, ["cdn"]);
        assert_eq!(rule.port, [53, 443]);
        assert_eq!(rule.ip_cidr.len(), 2);
        assert!(rule.unsupported_fields.is_empty());

        let SrsRule::Logical(logical) = &parsed.rules[1] else {
            panic!("expected logical rule");
        };
        let SrsRule::Default(child) = &logical.rules[0] else {
            panic!("expected default child");
        };
        assert_eq!(child.domain, ["guard.example"]);
        assert_eq!(child.unsupported_fields, ["source_port"]);
        assert!(!parsed.is_fully_supported());
    }

    #[test]
    fn recovers_v1_legacy_suffix_encoding() {
        let mut rule = vec![0, 2];
        write_succinct(
            &mut rule,
            &[
                reverse_unicode("example.com"),
                reverse_unicode("\r.example.com"),
            ],
        );
        rule.extend_from_slice(&[0xff, 0]);
        let parsed = parse_bytes(SrsFormat::Binary, &make_binary(1, &[rule])).unwrap();
        let SrsRule::Default(rule) = &parsed.rules[0] else {
            panic!("expected default rule");
        };
        assert!(rule.domain.is_empty());
        assert_eq!(rule.domain_suffix, ["example.com"]);
        assert!(parsed.is_fully_supported());
    }

    #[test]
    fn v4_interface_predicates_are_consumed_and_marked_unsupported() {
        let mut rule = vec![0, 21]; // default, network_interface_address
        write_uvarint(&mut rule, 1); // map entries
        rule.push(2); // interface type
        write_uvarint(&mut rule, 1); // prefixes
        write_prefix(&mut rule, "10.0.0.0".parse().unwrap(), 8);
        rule.push(22); // default_interface_address
        write_uvarint(&mut rule, 1);
        write_prefix(&mut rule, "2001:db8::".parse().unwrap(), 32);
        rule.push(9); // ensure parsing resumes at the correct byte
        write_u16_vec(&mut rule, &[443]);
        rule.extend_from_slice(&[0xff, 0]);

        let parsed = parse_bytes(SrsFormat::Binary, &make_binary(4, &[rule])).unwrap();
        let SrsRule::Default(rule) = &parsed.rules[0] else {
            panic!("expected default rule");
        };
        assert_eq!(rule.port, [443]);
        assert_eq!(
            rule.unsupported_fields,
            ["network_interface_address", "default_interface_address"]
        );
        assert!(!parsed.is_fully_supported());
    }

    #[test]
    fn rejects_malformed_and_future_inputs() {
        assert!(parse_bytes_named("source", br#"{"version":5,"rules":[]}"#).is_err());
        assert!(
            parse_bytes_named("source", br#"{"version":4,"rules":[{"port_range":"9:1"}]}"#)
                .is_err()
        );

        let future = make_binary(5, &[]);
        assert!(parse_bytes(SrsFormat::Binary, &future).is_err());

        let mut bad_bool = vec![0, 0xff, 2];
        let bad_bool = make_binary(4, &[std::mem::take(&mut bad_bool)]);
        assert!(parse_bytes(SrsFormat::Binary, &bad_bool).is_err());
    }

    fn make_binary(version: u8, rules: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        write_uvarint(&mut body, rules.len() as u64);
        for rule in rules {
            body.extend_from_slice(rule);
        }
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&body).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut output = b"SRS".to_vec();
        output.push(version);
        output.extend_from_slice(&compressed);
        output
    }

    fn write_uvarint(output: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            output.push((value as u8) | 0x80);
            value >>= 7;
        }
        output.push(value as u8);
    }

    fn write_string_vec(output: &mut Vec<u8>, values: &[&str]) {
        write_uvarint(output, values.len() as u64);
        for value in values {
            write_uvarint(output, value.len() as u64);
            output.extend_from_slice(value.as_bytes());
        }
    }

    fn write_u16_vec(output: &mut Vec<u8>, values: &[u16]) {
        write_uvarint(output, values.len() as u64);
        for value in values {
            output.extend_from_slice(&value.to_be_bytes());
        }
    }

    fn write_ip_set(output: &mut Vec<u8>, ranges: &[(IpAddr, IpAddr)]) {
        output.push(1); // IPSet version
        output.extend_from_slice(&(ranges.len() as u64).to_be_bytes());
        for (start, end) in ranges {
            write_ip(output, *start);
            write_ip(output, *end);
        }
    }

    fn write_ip(output: &mut Vec<u8>, address: IpAddr) {
        match address {
            IpAddr::V4(address) => {
                write_uvarint(output, 4);
                output.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                write_uvarint(output, 16);
                output.extend_from_slice(&address.octets());
            }
        }
    }

    fn write_prefix(output: &mut Vec<u8>, address: IpAddr, bits: u8) {
        write_ip(output, address);
        output.push(bits);
    }

    fn write_succinct(output: &mut Vec<u8>, keys: &[String]) {
        let mut keys: Vec<Vec<u8>> = keys.iter().map(|key| key.as_bytes().to_vec()).collect();
        keys.sort();
        keys.dedup();

        #[derive(Clone, Copy)]
        struct QueueItem {
            start: usize,
            end: usize,
            column: usize,
        }

        let mut leaves = Vec::new();
        let mut bitmap = Vec::new();
        let mut labels = Vec::new();
        let mut queue = vec![QueueItem {
            start: 0,
            end: keys.len(),
            column: 0,
        }];
        let mut bitmap_index = 0;
        let mut index = 0;
        while index < queue.len() {
            let mut item = queue[index];
            if item.start < item.end && item.column == keys[item.start].len() {
                item.start += 1;
                set_bit(&mut leaves, index);
            }
            let mut cursor = item.start;
            while cursor < item.end {
                let group_start = cursor;
                let label = keys[group_start][item.column];
                while cursor < item.end && keys[cursor][item.column] == label {
                    cursor += 1;
                }
                queue.push(QueueItem {
                    start: group_start,
                    end: cursor,
                    column: item.column + 1,
                });
                labels.push(label);
                bitmap_index += 1; // zero bits are already clear
            }
            set_bit(&mut bitmap, bitmap_index);
            bitmap_index += 1;
            index += 1;
        }

        output.push(0); // succinct matcher version
        write_u64_slice(output, &leaves);
        write_u64_slice(output, &bitmap);
        write_uvarint(output, labels.len() as u64);
        output.extend_from_slice(&labels);
    }

    fn set_bit(words: &mut Vec<u64>, index: usize) {
        while words.len() <= index / 64 {
            words.push(0);
        }
        words[index / 64] |= 1_u64 << (index % 64);
    }

    fn write_u64_slice(output: &mut Vec<u8>, values: &[u64]) {
        write_uvarint(output, values.len() as u64);
        for value in values {
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}
