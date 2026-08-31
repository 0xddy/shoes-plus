//! Configuration types for the proxy server.
//!
//! This module contains all the configuration types used by the proxy server,
//! organized into submodules by functionality:
//!
//! - [`common`]: Shared helpers and constants
//! - [`transport`]: Transport layer types (TCP, QUIC, UDP)
//! - [`shadowsocks`]: Shadowsocks protocol configuration
//! - [`selection`]: ConfigSelection for referencing groups or inline configs
//! - [`server`]: Server-side protocol configurations
//! - [`client`]: Client-side protocol configurations
//! - [`rules`]: Rule configurations for traffic routing
//! - [`groups`]: Top-level configuration groups and the Config enum
//! - [`dns`]: DNS server configuration

pub mod client;
pub mod common;
pub mod dns;
pub mod groups;
pub mod rules;
pub mod selection;
pub mod server;
pub mod shadowsocks;
pub mod transport;
pub mod tun;

// Re-export all public types for convenience
#[allow(unused_imports)]
pub use client::{
    ClientConfig, ClientProxyConfig, H2MuxConfig, Hysteria2ClientObfs, ShadowsocksUdpMode,
    TlsClientConfig, VlessPacketEncoding, WebsocketClientConfig, parse_go_duration,
};
pub use common::DEFAULT_REALITY_SHORT_ID;
#[allow(unused_imports)]
pub use dns::{
    DnsConfig, DnsConfigGroup, DnsPolicyActionConfig, DnsPolicyRuleConfig, DnsServerSpec,
    ExpandedDnsGroup, ExpandedDnsPolicyAction, ExpandedDnsPolicyRule, ExpandedDnsSpec,
};
pub use groups::{ClientConfigGroup, Config, NamedPem, PemSource};
#[allow(unused_imports)]
pub use rules::{
    ClientChain, ClientChainHop, ClientChainSelectionConfig, DEFAULT_URLTEST_IDLE_TIMEOUT_MILLIS,
    RouteMatchConfig, RouteNetwork, RouteRuleSetConfig, RuleActionConfig, RuleConfig,
};
pub use selection::ConfigSelection;
pub use server::{
    Hysteria2MasqueradeConfig, Hysteria2ObfsConfig, RealityServerConfig, ServerConfig,
    ServerProxyConfig, ShadowTlsServerConfig, ShadowTlsServerHandshakeConfig, TlsServerConfig,
    WebsocketPingType, WebsocketServerConfig, direct_allow_rule,
};
pub use shadowsocks::ShadowsocksConfig;
pub use transport::{BindLocation, ClientQuicConfig, ServerQuicConfig, TcpConfig, Transport};
pub use tun::TunConfig;
