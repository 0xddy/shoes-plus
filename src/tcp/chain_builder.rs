//! Builder functions for creating ClientProxyChain from config.

use std::fmt::Write as _;
use std::sync::Arc;

use sha2::{Digest as _, Sha256};

use crate::client_proxy_chain::{
    ClientChainGroup, ClientProxyChain, InitialHopEntry, current_client_chain_group_registry,
};
use crate::config::ConfigSelection;
use crate::config::{ClientChainHop, ClientChainSelectionConfig, ClientConfig};
use crate::hysteria2_client::Hysteria2SocketConnector;
use crate::resolver::Resolver;
use crate::tcp::proxy_connector::ProxyConnector;
use crate::tcp::proxy_connector_impl::ProxyConnectorImpl;
use crate::tcp::socket_connector::SocketConnector;
use crate::tcp::socket_connector_impl::SocketConnectorImpl;

/// Build a ClientProxyChain from a client_chain configuration.
///
/// Creates InitialHopEntry (socket + optional proxy paired) from hop 0.
/// Creates ProxyConnectors for subsequent hops (1+).
/// `protocol: direct` at hop 0 creates InitialHopEntry::Direct.
pub fn build_client_proxy_chain(
    client_chain: crate::option_util::OneOrSome<ClientChainHop>,
    resolver: Arc<dyn Resolver>,
) -> ClientProxyChain {
    let hops: Vec<Vec<ClientConfig>> = client_chain
        .into_vec()
        .into_iter()
        .map(|hop| match hop {
            ClientChainHop::Single(selection) => match selection {
                ConfigSelection::Config(config) => vec![config],
                ConfigSelection::GroupName(group_name) => {
                    panic!(
                        "Group reference '{}' was not resolved during config validation.",
                        group_name
                    );
                }
            },
            ClientChainHop::Pool(selections) => selections
                .into_vec()
                .into_iter()
                .flat_map(|selection| match selection {
                    ConfigSelection::Config(config) => vec![config],
                    ConfigSelection::GroupName(group_name) => {
                        panic!(
                            "Group reference '{}' was not resolved during config validation.",
                            group_name
                        );
                    }
                })
                .collect(),
        })
        .collect();

    if hops.is_empty() {
        panic!("Client chain must have at least one hop");
    }

    // Build initial hop entries from hop 0.
    // Each entry pairs socket + optional proxy together to ensure atomic selection.
    let initial_hop: Vec<InitialHopEntry> = hops[0]
        .iter()
        .map(|config| {
            // Find the first proxy address for QUIC socket configuration
            let target_address = find_first_proxy_address(&hops, config);

            let socket: Box<dyn SocketConnector> = if config.protocol.is_hysteria2() {
                Box::new(
                    Hysteria2SocketConnector::from_client_config(config)
                        .expect("Hysteria2 client config was validated before chain construction"),
                )
            } else {
                SocketConnectorImpl::from_config(config, target_address)
                    .map(|s| Box::new(s) as Box<dyn SocketConnector>)
                    .expect("Failed to create SocketConnector")
            };

            if config.protocol.is_direct() {
                // Direct: socket only, no proxy
                InitialHopEntry::Direct(socket)
            } else {
                // Proxy: socket + proxy paired
                let proxy = ProxyConnectorImpl::from_config(config.clone(), resolver.clone())
                    .map(|p| Box::new(p) as Box<dyn ProxyConnector>)
                    .expect("Failed to create ProxyConnector for non-direct config");
                InitialHopEntry::Proxy { socket, proxy }
            }
        })
        .collect();

    // Build proxy connectors for subsequent hops (1+)
    let subsequent_hops: Vec<Vec<Box<dyn ProxyConnector>>> = hops
        .into_iter()
        .skip(1) // Skip hop 0, already processed as initial_hop
        .enumerate()
        .map(|(hop_offset, hop_configs)| {
            let hop_index = hop_offset + 1; // Actual hop index for error messages
            hop_configs
                .into_iter()
                .map(|config| {
                    // Subsequent hops MUST NOT have direct protocol
                    if config.protocol.is_direct() {
                        panic!(
                            "protocol: direct is only valid at hop 0. Found direct at hop {} with address {}",
                            hop_index,
                            config.address
                        );
                    }
                    if config.protocol.is_hysteria2() {
                        panic!(
                            "protocol: hysteria2 is only valid at hop 0 because it creates its own QUIC transport. Found hysteria2 at hop {} with address {}",
                            hop_index, config.address
                        );
                    }

                    ProxyConnectorImpl::from_config(config, resolver.clone())
                        .map(|p| Box::new(p) as Box<dyn ProxyConnector>)
                        .expect("Failed to create ProxyConnector for subsequent hop")
                })
                .collect()
        })
        .collect();

    ClientProxyChain::new(initial_hop, subsequent_hops)
}

/// Find the first proxy address in the chain (for socket connector target).
fn find_first_proxy_address<'a>(
    hops: &'a [Vec<ClientConfig>],
    current_config: &'a ClientConfig,
) -> Option<&'a crate::address::NetLocation> {
    // If current config is a proxy, use its address
    if !current_config.protocol.is_direct() {
        return Some(&current_config.address);
    }

    // Otherwise, look at subsequent hops
    for hop in hops.iter().skip(1) {
        for config in hop {
            if !config.protocol.is_direct() {
                return Some(&config.address);
            }
        }
    }

    None
}

/// Build a "direct" ClientChainGroup (no proxy, just socket connection).
/// Uses the same pattern as build_client_chain_group with no chains configured.
pub fn build_direct_chain_group(resolver: Arc<dyn Resolver>) -> ClientChainGroup {
    build_client_chain_group(crate::option_util::NoneOrSome::None, resolver)
}

/// Build a single direct chain whose TCP and UDP sockets are bound to one
/// interface. Advanced systemd-resolved DNS uses this to match the default-link
/// dialer semantics and to make scoped IPv6 link-local upstreams routable
/// without leaking an interface choice into Hickory's IpAddr-only config.
pub(crate) fn build_bound_direct_chain_group(
    interface: String,
    resolver: Arc<dyn Resolver>,
) -> ClientChainGroup {
    let config = ClientConfig {
        bind_interface: crate::option_util::NoneOrOne::One(interface),
        ..ClientConfig::default()
    };
    let chain = build_client_proxy_chain(
        crate::option_util::OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(config))),
        resolver.clone(),
    );
    ClientChainGroup::new_with_selection(
        vec![chain],
        ClientChainSelectionConfig::RoundRobin,
        resolver,
    )
}

/// Build a ClientChainGroup from config chains.
pub fn build_client_chain_group(
    client_chains: crate::option_util::NoneOrSome<crate::config::ClientChain>,
    resolver: Arc<dyn Resolver>,
) -> ClientChainGroup {
    build_client_chain_group_with_selection(
        client_chains,
        ClientChainSelectionConfig::RoundRobin,
        resolver,
    )
}

/// Build a ClientChainGroup with an explicit cross-chain selection policy.
pub fn build_client_chain_group_with_selection(
    client_chains: crate::option_util::NoneOrSome<crate::config::ClientChain>,
    selection: ClientChainSelectionConfig,
    resolver: Arc<dyn Resolver>,
) -> ClientChainGroup {
    let shared_key = match &selection {
        ClientChainSelectionConfig::UrlTest {
            shared_id: Some(shared_id),
            ..
        } => current_client_chain_group_registry().map(|registry| {
            let encoded = serde_json::to_vec(&(&client_chains, &selection))
                .expect("validated client chains always serialize");
            let mut digest = Sha256::new();
            digest.update(b"shoes/client-chain-group/v1\0");
            digest.update(shared_id.as_bytes());
            digest.update(b"\0");
            digest.update(encoded);
            let mut key = String::with_capacity(shared_id.len() + 1 + 64);
            key.push_str(shared_id);
            key.push(':');
            for byte in digest.finalize() {
                write!(&mut key, "{byte:02x}").expect("writing to a String cannot fail");
            }
            (registry, key)
        }),
        _ => None,
    };
    let defer_urltest_start = shared_key.is_some();
    let shared_probe_resolver = shared_key
        .as_ref()
        .map(|(registry, _)| registry.probe_resolver());
    let shared_history_store = shared_key
        .as_ref()
        .map(|(registry, _)| registry.history_store());
    let shared_probe_permits = shared_key
        .as_ref()
        .map(|(registry, _)| registry.probe_permits());

    let build = || {
        let chains: Vec<ClientProxyChain> = if client_chains.is_empty() {
            vec![build_client_proxy_chain(
                crate::option_util::OneOrSome::One(ClientChainHop::Single(
                    ConfigSelection::Config(ClientConfig::default()),
                )),
                resolver.clone(),
            )]
        } else {
            client_chains
                .into_vec()
                .into_iter()
                .map(|chain| build_client_proxy_chain(chain.hops, resolver.clone()))
                .collect()
        };

        if defer_urltest_start {
            ClientChainGroup::new_with_deferred_selection(
                chains,
                selection,
                shared_probe_resolver.expect("shared URLTest has a probe resolver"),
                shared_history_store.expect("shared URLTest has a history store"),
                shared_probe_permits.expect("shared URLTest has a probe semaphore"),
            )
        } else {
            ClientChainGroup::new_with_selection(chains, selection, resolver)
        }
    };

    match shared_key {
        Some((registry, key)) => registry.get_or_insert_with(key, build),
        None => build(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::NetLocation;
    use crate::config::{ClientChain, ClientProxyConfig};
    use crate::option_util::{NoneOrSome, OneOrSome};
    use crate::resolver::NativeResolver;
    use std::net::{IpAddr, Ipv4Addr};

    fn mock_resolver() -> Arc<dyn Resolver> {
        Arc::new(NativeResolver::new())
    }

    fn socks_config(port: u16) -> ClientConfig {
        ClientConfig {
            address: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
            protocol: ClientProxyConfig::Socks {
                username: None,
                password: None,
            },
            ..Default::default()
        }
    }

    fn direct_config() -> ClientConfig {
        ClientConfig::default()
    }

    #[test]
    fn test_build_single_direct_hop() {
        let chain = build_client_proxy_chain(
            OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                direct_config(),
            ))),
            mock_resolver(),
        );

        // Direct creates 1 socket connector, 0 proxy connectors
        assert_eq!(chain.num_hops(), 1);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_build_single_proxy_hop() {
        let chain = build_client_proxy_chain(
            OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                socks_config(1080),
            ))),
            mock_resolver(),
        );

        // Single proxy creates 1 socket connector, 1 proxy connector
        assert_eq!(chain.num_hops(), 1);
    }

    #[test]
    fn test_build_direct_then_proxy_chain() {
        let chain = build_client_proxy_chain(
            OneOrSome::Some(vec![
                ClientChainHop::Single(ConfigSelection::Config(direct_config())),
                ClientChainHop::Single(ConfigSelection::Config(socks_config(1080))),
            ]),
            mock_resolver(),
        );

        // direct (hop 0) -> socks (hop 1)
        // InitialHopEntry::Direct + 1 subsequent hop = 2 hops total
        assert_eq!(chain.num_hops(), 2);
    }

    #[test]
    fn test_build_two_proxy_hops() {
        let chain = build_client_proxy_chain(
            OneOrSome::Some(vec![
                ClientChainHop::Single(ConfigSelection::Config(socks_config(1080))),
                ClientChainHop::Single(ConfigSelection::Config(socks_config(1081))),
            ]),
            mock_resolver(),
        );

        // socks1 (hop 0) -> socks2 (hop 1)
        assert_eq!(chain.num_hops(), 2);
    }

    #[test]
    fn test_build_pool_at_hop0() {
        let chain = build_client_proxy_chain(
            OneOrSome::One(ClientChainHop::Pool(OneOrSome::Some(vec![
                ConfigSelection::Config(socks_config(1080)),
                ConfigSelection::Config(socks_config(1081)),
            ]))),
            mock_resolver(),
        );

        // Pool of 2 proxies at hop 0
        assert_eq!(chain.num_hops(), 1);
    }

    #[test]
    fn test_build_empty_client_chains_creates_default() {
        let group = build_client_chain_group(NoneOrSome::None, mock_resolver());
        // Default is a single direct chain
        assert!(group.supports_udp());
    }

    #[test]
    fn bound_direct_group_exposes_the_default_link_to_all_dns_sockets() {
        let group = build_bound_direct_chain_group("eth-test0".to_string(), mock_resolver());
        assert!(group.is_direct_only());
        assert!(group.supports_udp());
        assert_eq!(group.get_bind_interface(), Some("eth-test0"));
    }

    #[test]
    fn test_build_client_chain_group_with_chains() {
        let chains = NoneOrSome::Some(vec![
            ClientChain {
                hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                    socks_config(1080),
                ))),
            },
            ClientChain {
                hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                    direct_config(),
                ))),
            },
        ]);
        let group = build_client_chain_group(chains, mock_resolver());
        // 2 chains in group
        assert!(group.supports_udp()); // direct chain supports UDP
    }

    #[test]
    #[should_panic(expected = "protocol: direct is only valid at hop 0")]
    fn test_direct_at_hop1_panics() {
        build_client_proxy_chain(
            OneOrSome::Some(vec![
                ClientChainHop::Single(ConfigSelection::Config(socks_config(1080))),
                ClientChainHop::Single(ConfigSelection::Config(direct_config())),
            ]),
            mock_resolver(),
        );
    }

    #[test]
    #[should_panic(expected = "protocol: direct is only valid at hop 0")]
    fn test_direct_in_pool_at_hop1_panics() {
        build_client_proxy_chain(
            OneOrSome::Some(vec![
                ClientChainHop::Single(ConfigSelection::Config(socks_config(1080))),
                ClientChainHop::Pool(OneOrSome::Some(vec![
                    ConfigSelection::Config(socks_config(1081)),
                    ConfigSelection::Config(direct_config()),
                ])),
            ]),
            mock_resolver(),
        );
    }

    #[test]
    #[should_panic(expected = "was not resolved during config validation")]
    fn test_unresolved_group_reference_panics() {
        build_client_proxy_chain(
            OneOrSome::One(ClientChainHop::Single(ConfigSelection::GroupName(
                "unresolved_group".to_string(),
            ))),
            mock_resolver(),
        );
    }

    #[test]
    fn test_find_first_proxy_address_direct_only() {
        let direct = direct_config();
        let hops = vec![vec![direct.clone()]];
        assert!(find_first_proxy_address(&hops, &direct).is_none());
    }

    #[test]
    fn test_find_first_proxy_address_proxy_at_hop0() {
        let proxy = socks_config(1080);
        let hops = vec![vec![proxy.clone()]];
        let addr = find_first_proxy_address(&hops, &proxy);
        assert!(addr.is_some());
        assert_eq!(addr.unwrap().port(), 1080);
    }

    #[test]
    fn test_find_first_proxy_address_proxy_at_hop1() {
        let direct = direct_config();
        let proxy = socks_config(1080);
        let hops = vec![vec![direct.clone()], vec![proxy.clone()]];
        let addr = find_first_proxy_address(&hops, &direct);
        assert!(addr.is_some());
        assert_eq!(addr.unwrap().port(), 1080);
    }
}
