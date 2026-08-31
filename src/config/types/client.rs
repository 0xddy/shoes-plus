//! Client configuration types.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::address::NetLocation;
use crate::h2mux::{H2MuxOptions, MuxProtocol};
use crate::option_util::{NoneOrOne, NoneOrSome};

use super::common::{
    default_reality_client_short_id, default_true, is_false, is_true, unspecified_address,
};
use super::server::WebsocketPingType;
use super::shadowsocks::ShadowsocksConfig;
use super::transport::{ClientQuicConfig, TcpConfig, Transport};

const NANOS_PER_SECOND: u128 = 1_000_000_000;

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

/// Parse Go's `time.ParseDuration` syntax into a bounded positive/zero Rust
/// duration. This is shared by panel adapters so duration strings are not
/// interpreted differently at the glue and data-plane layers.
pub fn parse_go_duration(value: &str) -> Result<Duration, String> {
    parse_go_duration_field(value, "duration")
}

fn parse_go_duration_field(value: &str, field: &str) -> Result<Duration, String> {
    let original = value;
    let mut value = value;
    if let Some(rest) = value.strip_prefix('+') {
        value = rest;
    } else if value.starts_with('-') {
        return Err(format!("negative {field} '{original}' is not supported"));
    }
    if value == "0" {
        return Ok(Duration::ZERO);
    }
    if value.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }

    let mut total_nanos = 0_u128;
    while !value.is_empty() {
        let bytes = value.as_bytes();
        let mut number_end = 0;
        while number_end < bytes.len() && bytes[number_end].is_ascii_digit() {
            number_end += 1;
        }
        let integer_end = number_end;
        let mut fraction = None;
        if number_end < bytes.len() && bytes[number_end] == b'.' {
            number_end += 1;
            let fraction_start = number_end;
            while number_end < bytes.len() && bytes[number_end].is_ascii_digit() {
                number_end += 1;
            }
            if number_end > fraction_start {
                fraction = Some(&value[fraction_start..number_end]);
            }
        }
        if integer_end == 0 && fraction.is_none() {
            return Err(format!("invalid {field} '{original}'"));
        }

        let unit_end = value[number_end..]
            .char_indices()
            .find_map(|(index, character)| {
                (character == '.' || character.is_ascii_digit()).then_some(number_end + index)
            })
            .unwrap_or(value.len());
        if unit_end == number_end {
            return Err(format!("missing unit in {field} '{original}'"));
        }
        let unit = &value[number_end..unit_end];
        let unit_nanos = match unit {
            "ns" => 1_u128,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => NANOS_PER_SECOND,
            "m" => 60 * NANOS_PER_SECOND,
            "h" => 60 * 60 * NANOS_PER_SECOND,
            _ => {
                return Err(format!("unknown unit '{unit}' in {field} '{original}'"));
            }
        };

        let integer = if integer_end == 0 {
            0
        } else {
            value[..integer_end]
                .parse::<u128>()
                .map_err(|_| format!("{field} '{original}' is too large"))?
        };
        let integer_nanos = integer
            .checked_mul(unit_nanos)
            .ok_or_else(|| format!("{field} '{original}' is too large"))?;
        let fraction_nanos = fraction.map_or(0, |digits| {
            // Match Go's time.ParseDuration behavior: fractional units are converted
            // through floating point, then truncated to whole nanoseconds.
            format!("0.{digits}")
                .parse::<f64>()
                .map(|fraction| (fraction * unit_nanos as f64) as u128)
                .unwrap_or(u128::MAX)
        });
        total_nanos = total_nanos
            .checked_add(integer_nanos)
            .and_then(|total| total.checked_add(fraction_nanos))
            .ok_or_else(|| format!("{field} '{original}' is too large"))?;
        if total_nanos > i64::MAX as u128 {
            return Err(format!("{field} '{original}' is too large"));
        }
        value = &value[unit_end..];
    }

    Ok(Duration::new(
        (total_nanos / NANOS_PER_SECOND) as u64,
        (total_nanos % NANOS_PER_SECOND) as u32,
    ))
}

fn format_go_duration(value: Duration) -> String {
    let nanos = value.as_nanos();
    if nanos == 0 {
        return "0s".into();
    }
    let seconds = nanos / NANOS_PER_SECOND;
    let subsecond = nanos % NANOS_PER_SECOND;
    if subsecond == 0 {
        return format!("{seconds}s");
    }
    let fraction = format!("{subsecond:09}").trim_end_matches('0').to_string();
    format!("{seconds}.{fraction}s")
}

fn deserialize_connect_timeout<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .map(|value| {
            parse_go_duration_field(&value, "connect_timeout").map_err(serde::de::Error::custom)
        })
        .transpose()
}

fn serialize_connect_timeout<S>(value: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(value) => serializer.serialize_some(&format_go_duration(*value)),
        None => serializer.serialize_none(),
    }
}

/// Configuration for h2mux (HTTP/2 multiplexing) on protocols that support it.
///
/// H2MUX multiplexes multiple proxy streams over a single HTTP/2 connection,
/// reducing connection overhead and improving performance for many concurrent streams.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct H2MuxConfig {
    /// Maximum number of connections to maintain
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,

    /// Minimum number of streams before opening a new connection
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_streams: Option<u32>,

    /// Maximum number of streams per connection (0 = unlimited)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_streams: Option<u32>,

    /// Enable padding for traffic obfuscation
    #[serde(default, skip_serializing_if = "is_false")]
    pub padding: bool,
}

impl H2MuxConfig {
    /// Converts this config to H2MuxOptions for the client handler.
    pub fn to_options(&self) -> H2MuxOptions {
        H2MuxOptions {
            protocol: MuxProtocol::H2Mux,
            max_connections: self.max_connections.unwrap_or(4),
            min_streams: self.min_streams.unwrap_or(4),
            max_streams: self.max_streams.unwrap_or(0),
            padding: self.padding,
        }
    }
}

/// Custom deserializer for ClientProxyConfig::Shadowsocks
fn deserialize_shadowsocks_client<'de, D>(
    deserializer: D,
) -> Result<(ShadowsocksConfig, ShadowsocksUdpMode), D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ShadowsocksClientTemp {
        cipher: String,
        password: String,
        #[serde(default = "default_true")]
        udp_enabled: bool,
        #[serde(default)]
        udp_mode: Option<ShadowsocksUdpMode>,
    }

    let temp = ShadowsocksClientTemp::deserialize(deserializer)?;
    let config =
        ShadowsocksConfig::from_fields(&temp.cipher, &temp.password).map_err(Error::custom)?;

    let udp_mode = match (temp.udp_enabled, temp.udp_mode) {
        (false, Some(ShadowsocksUdpMode::Uot | ShadowsocksUdpMode::Native)) => {
            return Err(Error::custom(
                "shadowsocks udp_enabled=false conflicts with an enabled udp_mode",
            ));
        }
        (true, Some(ShadowsocksUdpMode::Disabled)) => {
            return Err(Error::custom(
                "shadowsocks udp_enabled=true conflicts with udp_mode=disabled",
            ));
        }
        (false, _) => ShadowsocksUdpMode::Disabled,
        (true, Some(mode)) => mode,
        (true, None) => ShadowsocksUdpMode::Uot,
    };

    Ok((config, udp_mode))
}

/// Custom serializer for ClientProxyConfig::Shadowsocks - flattens config fields
fn serialize_shadowsocks_client<S>(
    config: &ShadowsocksConfig,
    udp_mode: &ShadowsocksUdpMode,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeStruct;

    // Preserve the historical spelling for disabled/UoT. Native UDP is an
    // explicit mode because it uses SIP003 datagrams rather than a TCP tunnel.
    let field_count = if *udp_mode == ShadowsocksUdpMode::Uot {
        2
    } else {
        3
    };
    let mut state = serializer.serialize_struct("Shadowsocks", field_count)?;
    config.serialize_fields(&mut state)?;
    match udp_mode {
        ShadowsocksUdpMode::Disabled => state.serialize_field("udp_enabled", &false)?,
        ShadowsocksUdpMode::Uot => {}
        ShadowsocksUdpMode::Native => state.serialize_field("udp_mode", udp_mode)?,
    }
    state.end()
}

/// Custom deserializer for ClientProxyConfig::Snell - flattens config fields
fn deserialize_snell_client<'de, D>(deserializer: D) -> Result<(ShadowsocksConfig, bool), D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SnellClientTemp {
        cipher: String,
        password: String,
        #[serde(default = "default_true")]
        udp_enabled: bool,
    }

    let temp = SnellClientTemp::deserialize(deserializer)?;
    let config =
        ShadowsocksConfig::from_fields(&temp.cipher, &temp.password).map_err(Error::custom)?;

    Ok((config, temp.udp_enabled))
}

/// Custom serializer for ClientProxyConfig::Snell - flattens config fields
fn serialize_snell_client<S>(
    config: &ShadowsocksConfig,
    udp_enabled: &bool,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeStruct;

    // Only serialize udp_enabled if it's not the default (true)
    let field_count = if *udp_enabled { 2 } else { 3 };
    let mut state = serializer.serialize_struct("Snell", field_count)?;
    config.serialize_fields(&mut state)?;
    if !*udp_enabled {
        state.serialize_field("udp_enabled", udp_enabled)?;
    }
    state.end()
}

/// Custom deserializer for ClientProxyConfig::Vmess that validates legacy aead field
fn deserialize_vmess_client<'de, D>(
    deserializer: D,
) -> Result<(String, String, bool, Option<H2MuxConfig>), D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct VmessClientTemp {
        cipher: String,
        user_id: String,
        #[serde(default, alias = "force_aead")]
        aead: Option<bool>,
        #[serde(default = "default_true")]
        udp_enabled: bool,
        #[serde(default)]
        h2mux: Option<H2MuxConfig>,
    }

    let temp = VmessClientTemp::deserialize(deserializer)?;

    // Check if aead/force_aead was explicitly set
    if let Some(aead_value) = temp.aead {
        if !aead_value {
            return Err(Error::custom(
                "Non-AEAD VMess mode (aead=false or force_aead=false) is no longer supported. \
                 Please remove the aead/force_aead field from your configuration, or set it to true.",
            ));
        }
        // Warn about deprecated field
        log::warn!(
            "The 'aead'/'force_aead' field in VMess client configuration is deprecated and will be removed in a future version. \
             AEAD mode is now always enabled. Please remove this field from your configuration."
        );
    }

    Ok((temp.cipher, temp.user_id, temp.udp_enabled, temp.h2mux))
}

/// Custom deserializer for TlsClientConfig that handles deprecated shadowtls_password field
fn deserialize_tls_client_config<'de, D>(deserializer: D) -> Result<TlsClientConfig, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TlsClientConfigTemp {
        #[serde(default = "default_true")]
        verify: bool,
        #[serde(default)]
        use_native_roots: bool,
        #[serde(alias = "server_fingerprint", default)]
        server_fingerprints: NoneOrSome<String>,
        #[serde(default)]
        sni_hostname: NoneOrOne<String>,
        #[serde(alias = "alpn_protocol", default)]
        alpn_protocols: NoneOrSome<String>,
        #[serde(default)]
        tls_buffer_size: Option<usize>,
        #[serde(default)]
        key: Option<String>,
        #[serde(default)]
        cert: Option<String>,
        #[serde(default)]
        shadowtls_password: Option<String>,
        #[serde(default)]
        vision: bool,
        protocol: Box<ClientProxyConfig>,
    }

    let temp = TlsClientConfigTemp::deserialize(deserializer)?;

    // Check for mutually exclusive fields
    if temp.vision && temp.shadowtls_password.is_some() {
        return Err(Error::custom(
            "TLS client config cannot have both vision=true and shadowtls_password set. \
             Vision and ShadowTLS are incompatible. \
             Use either 'vision: true' with regular TLS, or 'type: shadowtls' for ShadowTLS.",
        ));
    }

    // Check if deprecated shadowtls_password was used
    if let Some(password) = temp.shadowtls_password {
        log::warn!(
            "The 'shadowtls_password' field in TLS client configuration is deprecated. \
             Please use 'type: shadowtls' with 'password' field instead. \
             This field will be removed in a future version."
        );

        // Transform to ShadowTLS variant internally by wrapping protocol
        return Ok(TlsClientConfig {
            verify: temp.verify,
            use_native_roots: temp.use_native_roots,
            server_fingerprints: temp.server_fingerprints,
            sni_hostname: temp.sni_hostname.clone(),
            alpn_protocols: temp.alpn_protocols,
            tls_buffer_size: temp.tls_buffer_size,
            key: temp.key,
            cert: temp.cert,
            vision: false,
            protocol: Box::new(ClientProxyConfig::ShadowTls {
                password,
                sni_hostname: temp.sni_hostname.into_option(),
                protocol: temp.protocol,
            }),
        });
    }

    // Normal case - no shadowtls_password
    Ok(TlsClientConfig {
        verify: temp.verify,
        use_native_roots: temp.use_native_roots,
        server_fingerprints: temp.server_fingerprints,
        sni_hostname: temp.sni_hostname,
        alpn_protocols: temp.alpn_protocols,
        tls_buffer_size: temp.tls_buffer_size,
        key: temp.key,
        cert: temp.cert,
        vision: temp.vision,
        protocol: temp.protocol,
    })
}

/// Variant deserializer for Tls in ClientProxyConfig enum
fn deserialize_tls_variant<'de, D>(deserializer: D) -> Result<TlsClientConfig, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_tls_client_config(deserializer)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    #[serde(default, skip_serializing_if = "NoneOrOne::is_unspecified")]
    pub bind_interface: NoneOrOne<String>,
    /// IPv4 source address used for IPv4 TCP and direct UDP destinations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inet4_bind_address: Option<Ipv4Addr>,
    /// IPv6 source address used for IPv6 TCP and direct UDP destinations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inet6_bind_address: Option<Ipv6Addr>,
    /// Linux netfilter socket mark (`SO_MARK`). Zero means unset.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub routing_mark: u32,
    /// Per-address TCP connect timeout, encoded in Go duration syntax.
    #[serde(
        default,
        deserialize_with = "deserialize_connect_timeout",
        serialize_with = "serialize_connect_timeout",
        skip_serializing_if = "Option::is_none"
    )]
    pub connect_timeout: Option<Duration>,
    /// Linux `IP_BIND_ADDRESS_NO_PORT` for TCP source binds.
    #[serde(default, skip_serializing_if = "is_false")]
    pub bind_address_no_port: bool,
    /// Optional exact upstream tag exposed by the active DNS policy resolver.
    /// Only this connector's socket lookup uses it; route matching and all
    /// unrelated DNS consumers retain the group's normal policy/final server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_resolver: Option<String>,
    #[serde(
        default = "unspecified_address",
        skip_serializing_if = "NetLocation::is_unspecified"
    )]
    pub address: NetLocation,
    pub protocol: ClientProxyConfig,
    #[serde(default, skip_serializing_if = "Transport::is_default")]
    pub transport: Transport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_settings: Option<TcpConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_settings: Option<ClientQuicConfig>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            bind_interface: NoneOrOne::None,
            inet4_bind_address: None,
            inet6_bind_address: None,
            routing_mark: 0,
            connect_timeout: None,
            bind_address_no_port: false,
            dns_resolver: None,
            address: unspecified_address(),
            protocol: ClientProxyConfig::Direct,
            transport: Transport::default(),
            tcp_settings: None,
            quic_settings: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ClientProxyConfig {
    Direct,
    Http {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        /// When true, resolve hostnames to IP addresses before passing to HTTP CONNECT.
        /// Used when the upstream proxy blocks by hostname.
        #[serde(default, skip_serializing_if = "is_false")]
        resolve_hostname: bool,
    },
    #[serde(alias = "socks5")]
    Socks {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
    #[serde(
        alias = "ss",
        deserialize_with = "deserialize_shadowsocks_client",
        serialize_with = "serialize_shadowsocks_client"
    )]
    Shadowsocks {
        config: ShadowsocksConfig,
        udp_mode: ShadowsocksUdpMode,
    },
    #[serde(
        deserialize_with = "deserialize_snell_client",
        serialize_with = "serialize_snell_client"
    )]
    Snell {
        config: ShadowsocksConfig,
        udp_enabled: bool,
    },
    Vless {
        user_id: String,
        #[serde(default = "default_true", skip_serializing_if = "is_true")]
        udp_enabled: bool,
        /// Per-packet encoding used for UDP over the VLESS byte stream.
        ///
        /// Omitting this field preserves shoes' historical single-destination
        /// `CommandUdp` framing.  XUDP and packetaddr must be selected
        /// explicitly by configuration adapters.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        packet_encoding: Option<VlessPacketEncoding>,
        /// H2MUX multiplexing configuration
        #[serde(default, skip_serializing_if = "Option::is_none")]
        h2mux: Option<H2MuxConfig>,
    },
    Trojan {
        password: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shadowsocks: Option<ShadowsocksConfig>,
        /// Native Trojan UDP-over-TCP association support.
        #[serde(default = "default_true", skip_serializing_if = "is_true")]
        udp_enabled: bool,
        /// H2MUX multiplexing configuration
        #[serde(default, skip_serializing_if = "Option::is_none")]
        h2mux: Option<H2MuxConfig>,
    },
    /// Hysteria2's QUIC-native outbound protocol.
    ///
    /// TLS and the proxy server address use [`ClientConfig::quic_settings`] and
    /// [`ClientConfig::address`] respectively.  Unlike ordinary stream wrappers,
    /// this protocol must be the first hop because it creates and owns its UDP/
    /// QUIC transport.
    Hysteria2 {
        password: String,
        #[serde(default = "default_true", skip_serializing_if = "is_true")]
        udp_enabled: bool,
        #[serde(default, skip_serializing_if = "is_zero_u64")]
        up_mbps: u64,
        #[serde(default, skip_serializing_if = "is_zero_u64")]
        down_mbps: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        obfs: Option<Hysteria2ClientObfs>,
        /// sing-box expert option.  Parsed so unsupported use is rejected during
        /// validation instead of being mistaken for the ordinary `server_port`.
        #[serde(default, skip_serializing_if = "NoneOrSome::is_unspecified")]
        server_ports: NoneOrSome<String>,
        /// sing-box expert option, in Go duration syntax.  Port hopping is not yet
        /// available in shoes and validation rejects any supplied value.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hop_interval: Option<String>,
    },
    Reality {
        public_key: String,
        #[serde(default = "default_reality_client_short_id")]
        short_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sni_hostname: Option<String>,

        /// TLS 1.3 cipher suites to use (optional)
        /// Valid values: "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"
        /// If empty or not specified, all three cipher suites are offered.
        #[serde(
            alias = "cipher_suite",
            default,
            skip_serializing_if = "NoneOrSome::is_unspecified"
        )]
        cipher_suites: NoneOrSome<crate::reality::CipherSuite>,

        /// Enable XTLS-Vision protocol for TLS-in-TLS optimization.
        /// When enabled, the inner protocol MUST be VLESS.
        #[serde(default, skip_serializing_if = "is_false")]
        vision: bool,

        protocol: Box<ClientProxyConfig>,
    },
    #[serde(alias = "shadowtls")]
    ShadowTls {
        /// ShadowTLS password for authentication
        password: String,

        /// Optional SNI hostname override
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sni_hostname: Option<String>,

        /// Inner protocol (typically VLESS, Trojan, etc.)
        protocol: Box<ClientProxyConfig>,
    },
    #[serde(deserialize_with = "deserialize_tls_variant")]
    Tls(TlsClientConfig),
    #[serde(deserialize_with = "deserialize_vmess_client")]
    Vmess {
        cipher: String,
        user_id: String,
        #[serde(default = "default_true", skip_serializing_if = "is_true")]
        udp_enabled: bool,
        /// H2MUX multiplexing configuration
        #[serde(default, skip_serializing_if = "Option::is_none")]
        h2mux: Option<H2MuxConfig>,
    },
    #[serde(alias = "ws")]
    Websocket(WebsocketClientConfig),
    #[serde(alias = "noop")]
    PortForward,
    /// AnyTLS outbound protocol
    Anytls {
        /// Authentication password
        password: String,
        /// UDP over TCP support (default: true)
        #[serde(default = "default_true", skip_serializing_if = "is_true")]
        udp_enabled: bool,
        /// Custom padding scheme (optional, uses default if not specified)
        /// Each line is a key=value pair like "stop=8" or "0=30-30"
        #[serde(default, skip_serializing_if = "Option::is_none")]
        padding_scheme: Option<Vec<String>>,
    },
    /// NaiveProxy client protocol (HTTP/2 CONNECT with padding)
    #[serde(alias = "naive")]
    Naiveproxy {
        /// Username for Basic Auth
        username: String,
        /// Password for Basic Auth
        password: String,
        /// Enable padding protocol (default: true)
        #[serde(default = "default_true", skip_serializing_if = "is_true")]
        padding: bool,
    },
}

/// VLESS UDP packet encodings that differ from the legacy length-prefixed mode.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VlessPacketEncoding {
    Xudp,
    Packetaddr,
}

/// UDP obfuscation accepted by a Hysteria2 outbound.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Hysteria2ClientObfs {
    Salamander { password: String },
}

/// UDP transport selected by a Shadowsocks client.
///
/// Existing shoes configurations map `udp_enabled: true` (or omission) to
/// `uot`, preserving the historical UDP-over-TCP behavior. `native` selects
/// the SIP003 Shadowsocks UDP packet format instead.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShadowsocksUdpMode {
    Disabled,
    #[default]
    Uot,
    Native,
}

impl ClientProxyConfig {
    pub fn is_direct(&self) -> bool {
        matches!(self, ClientProxyConfig::Direct)
    }

    /// Returns the protocol name for display/error messages
    pub fn protocol_name(&self) -> &str {
        match self {
            ClientProxyConfig::Direct => "Direct",
            ClientProxyConfig::Http { .. } => "HTTP",
            ClientProxyConfig::Socks { .. } => "SOCKS5",
            ClientProxyConfig::Shadowsocks { .. } => "Shadowsocks",
            ClientProxyConfig::Snell { .. } => "Snell",
            ClientProxyConfig::Vless { .. } => "VLESS",
            ClientProxyConfig::Trojan { .. } => "Trojan",
            ClientProxyConfig::Hysteria2 { .. } => "Hysteria2",
            ClientProxyConfig::Reality { .. } => "Reality",
            ClientProxyConfig::Tls(..) => "TLS",
            ClientProxyConfig::ShadowTls { .. } => "ShadowTLS",
            ClientProxyConfig::Vmess { .. } => "VMess",
            ClientProxyConfig::Websocket(..) => "WebSocket",
            ClientProxyConfig::PortForward => "PortForward",
            ClientProxyConfig::Anytls { .. } => "AnyTLS",
            ClientProxyConfig::Naiveproxy { .. } => "NaiveProxy",
        }
    }

    pub fn is_hysteria2(&self) -> bool {
        matches!(self, ClientProxyConfig::Hysteria2 { .. })
    }

    /// Whether this protocol can carry fixed-destination UDP messages over
    /// the byte stream established for the proxy hop.
    ///
    /// Keep this in step with the handlers constructed by
    /// `create_tcp_client_handler`; configuration validation uses it to reject
    /// unusable datagram chains before a runtime is reported as applied.
    pub fn supports_udp_over_tcp(&self) -> bool {
        match self {
            ClientProxyConfig::Shadowsocks { udp_mode, .. } => {
                matches!(udp_mode, ShadowsocksUdpMode::Uot)
            }
            ClientProxyConfig::Snell { udp_enabled, .. }
            | ClientProxyConfig::Anytls { udp_enabled, .. } => *udp_enabled,
            ClientProxyConfig::Vless {
                udp_enabled, h2mux, ..
            }
            | ClientProxyConfig::Trojan {
                udp_enabled, h2mux, ..
            }
            | ClientProxyConfig::Vmess {
                udp_enabled, h2mux, ..
            } => *udp_enabled || h2mux.is_some(),
            ClientProxyConfig::Reality {
                vision, protocol, ..
            } => {
                if *vision {
                    matches!(
                        protocol.as_ref(),
                        ClientProxyConfig::Vless {
                            udp_enabled: true,
                            ..
                        }
                    )
                } else {
                    protocol.supports_udp_over_tcp()
                }
            }
            ClientProxyConfig::Tls(config) => {
                if config.vision {
                    matches!(
                        config.protocol.as_ref(),
                        ClientProxyConfig::Vless {
                            udp_enabled: true,
                            ..
                        }
                    )
                } else {
                    config.protocol.supports_udp_over_tcp()
                }
            }
            ClientProxyConfig::ShadowTls { protocol, .. } => protocol.supports_udp_over_tcp(),
            ClientProxyConfig::Websocket(config) => config.protocol.supports_udp_over_tcp(),
            ClientProxyConfig::Direct
            | ClientProxyConfig::Http { .. }
            | ClientProxyConfig::Socks { .. }
            | ClientProxyConfig::Hysteria2 { .. }
            | ClientProxyConfig::PortForward
            | ClientProxyConfig::Naiveproxy { .. } => false,
        }
    }

    /// Whether this protocol owns a native datagram transport. Native UDP is
    /// usable only when the protocol is in the first and final chain hop.
    pub fn supports_native_udp(&self) -> bool {
        match self {
            ClientProxyConfig::Shadowsocks { udp_mode, .. } => {
                matches!(udp_mode, ShadowsocksUdpMode::Native)
            }
            ClientProxyConfig::Hysteria2 { udp_enabled, .. } => *udp_enabled,
            _ => false,
        }
    }

    /// Whether the final UDP protocol can only encode a literal IP target.
    ///
    /// Most proxy protocols deliberately retain the original hostname and let
    /// the upstream resolve it. VLESS packetaddr is the exception: its packet
    /// address format has only IPv4 and IPv6 variants. H2MUX carries the final
    /// target itself, so an inner packetaddr setting does not apply there.
    pub fn requires_literal_udp_target(&self) -> bool {
        match self {
            ClientProxyConfig::Vless {
                packet_encoding,
                h2mux,
                ..
            } => {
                h2mux.is_none() && matches!(packet_encoding, Some(VlessPacketEncoding::Packetaddr))
            }
            ClientProxyConfig::Reality { protocol, .. }
            | ClientProxyConfig::ShadowTls { protocol, .. } => {
                protocol.requires_literal_udp_target()
            }
            ClientProxyConfig::Tls(config) => config.protocol.requires_literal_udp_target(),
            ClientProxyConfig::Websocket(config) => config.protocol.requires_literal_udp_target(),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsClientConfig {
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub verify: bool,
    /// Use the operating system's trust policy instead of shoes' bundled
    /// Mozilla/WebPKI roots. Omitted/false preserves historical shoes YAML.
    #[serde(default, skip_serializing_if = "is_false")]
    pub use_native_roots: bool,
    #[serde(
        alias = "server_fingerprint",
        default,
        skip_serializing_if = "NoneOrSome::is_unspecified"
    )]
    pub server_fingerprints: NoneOrSome<String>,
    #[serde(default, skip_serializing_if = "NoneOrOne::is_unspecified")]
    pub sni_hostname: NoneOrOne<String>,
    #[serde(
        alias = "alpn_protocol",
        default,
        skip_serializing_if = "NoneOrSome::is_unspecified"
    )]
    pub alpn_protocols: NoneOrSome<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_buffer_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,

    /// Enable XTLS-Vision protocol for TLS-in-TLS optimization.
    /// When enabled, the inner protocol MUST be VLESS.
    /// Requires TLS 1.3.
    #[serde(default, skip_serializing_if = "is_false")]
    pub vision: bool,

    pub protocol: Box<ClientProxyConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebsocketClientConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matching_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matching_headers: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "WebsocketPingType::is_default")]
    pub ping_type: WebsocketPingType,
    pub protocol: Box<ClientProxyConfig>,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn vless_packet_encoding_is_explicit_and_legacy_default_is_omitted() {
        let legacy: ClientProxyConfig =
            serde_yaml::from_str("type: vless\nuser_id: 00000000-0000-0000-0000-000000000000\n")
                .unwrap();
        assert!(matches!(
            legacy,
            ClientProxyConfig::Vless {
                packet_encoding: None,
                ..
            }
        ));

        let xudp: ClientProxyConfig = serde_yaml::from_str(
            "type: vless\nuser_id: 00000000-0000-0000-0000-000000000000\npacket_encoding: xudp\n",
        )
        .unwrap();
        assert!(matches!(
            xudp,
            ClientProxyConfig::Vless {
                packet_encoding: Some(VlessPacketEncoding::Xudp),
                ..
            }
        ));
    }

    #[test]
    fn hysteria2_client_shape_matches_panel_adapter_fields() {
        let config: ClientConfig = serde_yaml::from_str(
            r#"
address: hy2.example.com:443
transport: quic
quic_settings:
  verify: false
  sni_hostname: edge.example.com
  alpn_protocols: [h3]
protocol:
  type: hysteria2
  password: secret
  up_mbps: 100
  down_mbps: 200
  obfs:
    type: salamander
    password: obfs-secret
"#,
        )
        .unwrap();
        assert!(config.protocol.is_hysteria2());
        assert!(!config.quic_settings.as_ref().unwrap().use_native_roots);
        assert!(matches!(
            config.protocol,
            ClientProxyConfig::Hysteria2 {
                udp_enabled: true,
                up_mbps: 100,
                down_mbps: 200,
                obfs: Some(Hysteria2ClientObfs::Salamander { .. }),
                ..
            }
        ));

        let serialized = serde_yaml::to_string(&config).unwrap();
        assert!(serialized.contains("type: hysteria2"));
        assert!(serialized.contains("type: salamander"));
        assert!(!serialized.contains("server_ports"));
        assert!(!serialized.contains("hop_interval"));

        let native: ClientConfig = serde_yaml::from_str(
            r#"
address: hy2.example.com:443
transport: quic
quic_settings:
  use_native_roots: true
protocol:
  type: hysteria2
  password: secret
"#,
        )
        .unwrap();
        assert!(native.quic_settings.unwrap().use_native_roots);
    }

    #[test]
    fn tls_native_roots_are_opt_in_and_roundtrip() {
        let legacy: ClientProxyConfig =
            serde_yaml::from_str("type: tls\nprotocol:\n  type: direct\n").unwrap();
        assert!(matches!(
            legacy,
            ClientProxyConfig::Tls(TlsClientConfig {
                use_native_roots: false,
                ..
            })
        ));

        let native: ClientProxyConfig =
            serde_yaml::from_str("type: tls\nuse_native_roots: true\nprotocol:\n  type: direct\n")
                .unwrap();
        assert!(matches!(
            &native,
            ClientProxyConfig::Tls(TlsClientConfig {
                use_native_roots: true,
                ..
            })
        ));
        assert!(
            serde_yaml::to_string(&native)
                .unwrap()
                .contains("use_native_roots: true")
        );
    }

    #[test]
    fn shadowsocks_udp_mode_preserves_uot_compatibility_and_selects_native_explicitly() {
        let legacy: ClientProxyConfig = serde_yaml::from_str(
            "type: shadowsocks\ncipher: aes-128-gcm\npassword: test-password\n",
        )
        .unwrap();
        assert!(matches!(
            legacy,
            ClientProxyConfig::Shadowsocks {
                udp_mode: ShadowsocksUdpMode::Uot,
                ..
            }
        ));

        let native: ClientProxyConfig = serde_yaml::from_str(
            "type: shadowsocks\ncipher: aes-128-gcm\npassword: test-password\nudp_mode: native\n",
        )
        .unwrap();
        assert!(matches!(
            &native,
            ClientProxyConfig::Shadowsocks {
                udp_mode: ShadowsocksUdpMode::Native,
                ..
            }
        ));
        let encoded = serde_yaml::to_string(&native).unwrap();
        assert!(encoded.contains("udp_mode: native"), "{encoded}");
        assert!(!encoded.contains("udp_enabled"), "{encoded}");

        let disabled: ClientProxyConfig = serde_yaml::from_str(
            "type: shadowsocks\ncipher: aes-128-gcm\npassword: test-password\nudp_enabled: false\n",
        )
        .unwrap();
        assert!(matches!(
            disabled,
            ClientProxyConfig::Shadowsocks {
                udp_mode: ShadowsocksUdpMode::Disabled,
                ..
            }
        ));

        let conflict: Result<ClientProxyConfig, _> = serde_yaml::from_str(
            "type: shadowsocks\ncipher: aes-128-gcm\npassword: test-password\nudp_enabled: false\nudp_mode: native\n",
        );
        assert!(conflict.is_err());

        let inverse_conflict: Result<ClientProxyConfig, _> = serde_yaml::from_str(
            "type: shadowsocks\ncipher: aes-128-gcm\npassword: test-password\nudp_enabled: true\nudp_mode: disabled\n",
        );
        assert!(inverse_conflict.is_err());
    }

    fn create_test_client_config() -> ClientConfig {
        ClientConfig {
            bind_interface: NoneOrOne::One("eth0".to_string()),
            inet4_bind_address: Some(Ipv4Addr::new(192, 0, 2, 10)),
            inet6_bind_address: Some("2001:db8::10".parse().unwrap()),
            routing_mark: 100,
            connect_timeout: Some(Duration::from_millis(8_500)),
            bind_address_no_port: true,
            dns_resolver: Some("proxy-dns".to_string()),
            address: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 1080),
            protocol: ClientProxyConfig::Socks {
                username: Some("client_user".to_string()),
                password: Some("client_pass".to_string()),
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
        }
    }

    #[test]
    fn test_client_config_serialization() {
        let original = create_test_client_config();
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        println!("Client config YAML:\n{yaml_str}");
        let deserialized: ClientConfig =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
        assert!(matches!(
            deserialized.protocol,
            ClientProxyConfig::Socks { .. }
        ));
        assert_eq!(deserialized.inet4_bind_address, original.inet4_bind_address);
        assert_eq!(deserialized.inet6_bind_address, original.inet6_bind_address);
        assert_eq!(deserialized.routing_mark, 100);
        assert_eq!(deserialized.connect_timeout, original.connect_timeout);
        assert!(deserialized.bind_address_no_port);
    }

    #[test]
    fn test_default_client_config_keeps_legacy_serialization_shape() {
        let yaml = serde_yaml::to_string(&ClientConfig::default()).unwrap();
        for field in [
            "inet4_bind_address",
            "inet6_bind_address",
            "routing_mark",
            "connect_timeout",
            "bind_address_no_port",
        ] {
            assert!(
                !yaml.contains(field),
                "unexpected default field {field}: {yaml}"
            );
        }
    }

    #[test]
    fn test_connect_timeout_uses_go_duration_syntax() {
        for (value, expected) in [
            ("300ms", Duration::from_millis(300)),
            ("1.5s", Duration::from_millis(1_500)),
            ("2h45m", Duration::from_secs(9_900)),
            ("250µs", Duration::from_micros(250)),
        ] {
            assert_eq!(parse_go_duration(value).unwrap(), expected);
        }
        for value in ["", "5", "1fortnight", "-1s", "1s trailing"] {
            assert!(parse_go_duration(value).is_err(), "accepted {value:?}");
        }

        let parsed: ClientConfig =
            serde_yaml::from_str("protocol:\n  type: direct\nconnect_timeout: 2h45m\n").unwrap();
        assert_eq!(parsed.connect_timeout, Some(Duration::from_secs(9_900)));
        let encoded = serde_yaml::to_string(&parsed).unwrap();
        assert!(encoded.contains("connect_timeout: 9900s"));
    }

    #[test]
    fn test_rejects_unknown_field_in_vmess_client() {
        // Test ClientProxyConfig::Vmess directly
        let yaml = r#"
type: vmess
cipher: aes-128-gcm
user_id: "b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4"
unknown_option: true
"#;
        let result: Result<ClientProxyConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field `unknown_option`"),
            "Error should mention unknown field: {err}"
        );
    }

    #[test]
    fn test_rejects_unknown_field_in_tls_client_config() {
        // Test ClientProxyConfig::Tls directly
        let yaml = r#"
type: tls
verify: true
wrong_field: "oops"
protocol:
  type: socks
"#;
        let result: Result<ClientProxyConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field `wrong_field`"),
            "Error should mention unknown field: {err}"
        );
    }

    #[test]
    fn test_rejects_unknown_field_in_client_config() {
        // Test ClientConfig directly
        let yaml = r#"
address: "127.0.0.1:9090"
protocol:
  type: socks
invalid_client_field: "bad"
"#;
        let result: Result<ClientConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field `invalid_client_field`"),
            "Error should mention unknown field: {err}"
        );
    }

    #[test]
    fn test_client_proxy_config_direct() {
        let yaml = r#"
type: direct
"#;
        let result: Result<ClientProxyConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert!(result.unwrap().is_direct());
    }

    #[test]
    fn test_client_proxy_config_socks() {
        let yaml = r#"
type: socks
username: "user"
password: "pass"
"#;
        let result: Result<ClientProxyConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ClientProxyConfig::Socks { .. }));
    }

    #[test]
    fn test_client_proxy_config_http() {
        let yaml = r#"
type: http
"#;
        let result: Result<ClientProxyConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ClientProxyConfig::Http { .. }));
    }

    #[test]
    fn test_websocket_client_config() {
        let yaml = r#"
type: websocket
matching_path: "/ws"
protocol:
  type: direct
"#;
        let result: Result<ClientProxyConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ClientProxyConfig::Websocket(_)));
    }
}
