//! EDNS Client Subnet validation shared by configuration and DNS transports.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// A validated ECS address and source prefix length.
///
/// ACP/sing-box accept either CIDR notation or a bare address. Bare IPv4 and
/// IPv6 addresses are normalized to `/32` and `/128` respectively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DnsClientSubnet {
    address: IpAddr,
    prefix_len: u8,
}

impl DnsClientSubnet {
    pub fn to_hickory(self) -> hickory_resolver::proto::rr::rdata::opt::ClientSubnet {
        // Hickory serializes the significant bytes but does not clear unused
        // low bits in a non-octet-aligned prefix. miekg/dns (used by Go
        // sing-box) applies the CIDR mask before encoding, as RFC 7871 requires.
        let address = match self.address {
            IpAddr::V4(address) => {
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix_len)
                };
                IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
            }
            IpAddr::V6(address) => {
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix_len)
                };
                IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
            }
        };
        hickory_resolver::proto::rr::rdata::opt::ClientSubnet::new(address, self.prefix_len, 0)
    }
}

impl std::fmt::Display for DnsClientSubnet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.address, self.prefix_len)
    }
}

impl FromStr for DnsClientSubnet {
    type Err = std::io::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() || value.trim() != value {
            return Err(invalid_subnet(
                "client_subnet must be a non-empty trimmed IP or prefix",
            ));
        }

        let (address, prefix_len) = match value.split_once('/') {
            Some((address, prefix)) => {
                if address.is_empty() || prefix.is_empty() || prefix.contains('/') {
                    return Err(invalid_subnet(format!("invalid client_subnet {value:?}")));
                }
                let address = address.parse::<IpAddr>().map_err(|error| {
                    invalid_subnet(format!(
                        "invalid client_subnet address {address:?}: {error}"
                    ))
                })?;
                if !prefix.bytes().all(|byte| byte.is_ascii_digit())
                    || (prefix.len() > 1 && prefix.starts_with('0'))
                {
                    return Err(invalid_subnet(format!(
                        "invalid client_subnet prefix length {prefix:?}"
                    )));
                }
                let prefix_len = prefix.parse::<u8>().map_err(|error| {
                    invalid_subnet(format!(
                        "invalid client_subnet prefix length {prefix:?}: {error}"
                    ))
                })?;
                (address, prefix_len)
            }
            None => {
                let address = value.parse::<IpAddr>().map_err(|error| {
                    invalid_subnet(format!("invalid client_subnet address {value:?}: {error}"))
                })?;
                let prefix_len = if address.is_ipv4() { 32 } else { 128 };
                (address, prefix_len)
            }
        };

        let max_prefix = if address.is_ipv4() { 32 } else { 128 };
        if prefix_len > max_prefix {
            return Err(invalid_subnet(format!(
                "client_subnet prefix length {prefix_len} exceeds {max_prefix} for {address}"
            )));
        }

        Ok(Self {
            address,
            prefix_len,
        })
    }
}

fn invalid_subnet(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes_bare_addresses_and_prefixes() {
        let ipv4 = "192.0.2.1".parse::<DnsClientSubnet>().unwrap();
        let ecs = ipv4.to_hickory();
        assert_eq!(ecs.addr(), "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(ecs.source_prefix(), 32);
        assert_eq!(ipv4.to_string(), "192.0.2.1/32");
        assert_eq!(
            "2001:db8::1"
                .parse::<DnsClientSubnet>()
                .unwrap()
                .to_string(),
            "2001:db8::1/128"
        );
        assert_eq!(
            "192.0.2.129/24"
                .parse::<DnsClientSubnet>()
                .unwrap()
                .to_string(),
            "192.0.2.129/24"
        );
    }

    #[test]
    fn rejects_invalid_prefixes() {
        for value in [
            "",
            " 192.0.2.1/24",
            "192.0.2.1/024",
            "192.0.2.1/33",
            "2001:db8::/129",
        ] {
            assert!(value.parse::<DnsClientSubnet>().is_err(), "{value}");
        }
    }

    #[test]
    fn masks_host_bits_before_hickory_encodes_non_octet_prefixes() {
        let ipv4 = "192.0.2.255/25"
            .parse::<DnsClientSubnet>()
            .unwrap()
            .to_hickory();
        assert_eq!(ipv4.addr(), "192.0.2.128".parse::<IpAddr>().unwrap());
        assert_eq!(ipv4.source_prefix(), 25);

        let ipv6 = "2001:db8:0:0:ffff:ffff:ffff:ffff/65"
            .parse::<DnsClientSubnet>()
            .unwrap()
            .to_hickory();
        assert_eq!(
            ipv6.addr(),
            "2001:db8:0:0:8000::".parse::<IpAddr>().unwrap()
        );
        assert_eq!(ipv6.source_prefix(), 65);
    }
}
