//! Refuses proxy targets that point at non-public addresses.
//!
//! Every target this proxy fetches comes from the caller, and on a Screenly
//! player the caller is web content rendered by the viewer. Without a check,
//! any page can ask the proxy to fetch a loopback service — the identity proxy
//! hands out the device's credentials — or sweep the network the player sits
//! on, and read the answer, because the response comes back with the caller's
//! origin allowed and credentials exposed.
//!
//! The blocked ranges mirror the SSRF filter the screenshoter uses, so both
//! services agree on what "not public" means. Set `BLOCK_PRIVATE_ADDRESSES` to
//! `false` where the proxy is meant to reach internal hosts, such as a test
//! world serving its own origin.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::OnceLock;

const BLOCK_PRIVATE_ADDRESSES_VAR: &str = "BLOCK_PRIVATE_ADDRESSES";

/// Port used only to turn a hostname into something resolvable; the address is
/// what matters, never the port.
const RESOLVE_PORT: u16 = 80;

/// IPv4 ranges a proxied request must never reach.
const BLOCKED_IPV4_CIDRS: &[(Ipv4Addr, u32)] = &[
    (Ipv4Addr::new(0, 0, 0, 0), 8),       // this host / this network
    (Ipv4Addr::new(10, 0, 0, 0), 8),      // private
    (Ipv4Addr::new(100, 64, 0, 0), 10),   // carrier-grade NAT
    (Ipv4Addr::new(127, 0, 0, 0), 8),     // loopback
    (Ipv4Addr::new(169, 254, 0, 0), 16),  // link-local + cloud metadata
    (Ipv4Addr::new(172, 16, 0, 0), 12),   // private
    (Ipv4Addr::new(192, 0, 0, 0), 24),    // IETF protocol assignments
    (Ipv4Addr::new(192, 0, 2, 0), 24),    // TEST-NET-1
    (Ipv4Addr::new(192, 88, 99, 0), 24),  // former 6to4 relay
    (Ipv4Addr::new(192, 168, 0, 0), 16),  // private
    (Ipv4Addr::new(198, 18, 0, 0), 15),   // benchmarking
    (Ipv4Addr::new(198, 51, 100, 0), 24), // TEST-NET-2
    (Ipv4Addr::new(203, 0, 113, 0), 24),  // TEST-NET-3
    (Ipv4Addr::new(224, 0, 0, 0), 4),     // multicast and broadcast
    (Ipv4Addr::new(240, 0, 0, 0), 4),     // reserved
];

/// IPv6 ranges a proxied request must never reach.
const BLOCKED_IPV6_CIDRS: &[(Ipv6Addr, u32)] = &[
    (Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0), 64), // discard prefix
    (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 32), // Teredo tunneling
    (Ipv6Addr::new(0x2001, 0x20, 0, 0, 0, 0, 0, 0), 28), // ORCHIDv2
    (Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32), // documentation
    (Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16), // 6to4 (deprecated)
    (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20), // documentation
    (Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0), 16), // SRv6
    (Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96), // NAT64
    (Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0), 48), // NAT64
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7), // unique local
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10), // link-local
    (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8), // multicast
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 128),    // unspecified
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 128),    // loopback
];

fn matches_prefix(address: &[u8], network: &[u8], prefix_length: u32) -> bool {
    let full_bytes = (prefix_length / 8) as usize;
    if address[..full_bytes] != network[..full_bytes] {
        return false;
    }

    let remaining_bits = prefix_length % 8;
    if remaining_bits == 0 {
        return true;
    }

    let mask = 0xffu8 << (8 - remaining_bits);
    address[full_bytes] & mask == network[full_bytes] & mask
}

fn is_blocked_ipv4(address: Ipv4Addr) -> bool {
    BLOCKED_IPV4_CIDRS.iter().any(|(network, prefix_length)| {
        matches_prefix(&address.octets(), &network.octets(), *prefix_length)
    })
}

fn is_blocked_ipv6(address: Ipv6Addr) -> bool {
    // An IPv4-mapped ::ffff:a.b.c.d or the deprecated IPv4-compatible ::a.b.c.d
    // both carry in their low 32 bits the address that is actually connected to.
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_blocked_ipv4(mapped);
    }
    if let Some(compatible) = address.to_ipv4() {
        return is_blocked_ipv4(compatible);
    }

    BLOCKED_IPV6_CIDRS.iter().any(|(network, prefix_length)| {
        matches_prefix(&address.octets(), &network.octets(), *prefix_length)
    })
}

/// True when an address points somewhere a proxied request must never reach.
pub(crate) fn is_blocked_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_blocked_ipv4(address),
        IpAddr::V6(address) => is_blocked_ipv6(address),
    }
}

/// Read once: the setting cannot change under a running proxy, and the check
/// runs on every request and every redirect hop.
fn blocking_private_addresses() -> bool {
    static BLOCKING: OnceLock<bool> = OnceLock::new();
    *BLOCKING.get_or_init(|| {
        std::env::var(BLOCK_PRIVATE_ADDRESSES_VAR)
            .map(|value| value != "false")
            .unwrap_or(true)
    })
}

/// Returns the reason a URL must not be fetched, or `None` when it may be.
///
/// A literal address is decided without a lookup; a hostname is resolved and
/// every address it answers with has to be public, so a name pointing at
/// loopback is refused as well. A hostname that does not resolve is refused,
/// because it cannot be vetted. The reason names the class of refusal and the
/// URL, never the resolved address.
///
/// This resolves names with the blocking resolver, so callers on an async
/// runtime should reach for [`blocked_url_reason_async`].
pub(crate) fn blocked_url_reason(url: &url::Url) -> Option<String> {
    blocked_url_reason_when(url, blocking_private_addresses())
}

fn blocked_url_reason_when(url: &url::Url, blocking: bool) -> Option<String> {
    if !matches!(url.scheme(), "http" | "https") {
        return Some(format!("Target scheme is not allowed: {url}"));
    }

    if !blocking {
        return None;
    }

    let host = url.host()?;

    let addresses: Vec<IpAddr> = match host {
        url::Host::Ipv4(address) => vec![IpAddr::V4(address)],
        url::Host::Ipv6(address) => vec![IpAddr::V6(address)],
        url::Host::Domain(domain) => match (domain, RESOLVE_PORT).to_socket_addrs() {
            Ok(resolved) => resolved.map(|address| address.ip()).collect(),
            Err(_) => return Some(format!("Target host does not resolve: {url}")),
        },
    };

    if addresses.is_empty() {
        return Some(format!("Target host does not resolve: {url}"));
    }

    if addresses.iter().copied().any(is_blocked_address) {
        return Some(format!("Target resolves to a non-public address: {url}"));
    }

    None
}

/// [`blocked_url_reason`] moved off the async runtime, since resolving a name
/// blocks the thread it runs on.
pub(crate) async fn blocked_url_reason_async(url: url::Url) -> Option<String> {
    match tokio::task::spawn_blocking(move || blocked_url_reason(&url)).await {
        Ok(reason) => reason,
        Err(_) => Some(String::from("Target could not be checked")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(url: &str) -> url::Url {
        url.parse().expect("test URL should parse")
    }

    #[test]
    fn is_blocked_address_when_loopback_should_block() {
        assert!(is_blocked_address("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_loopback_outside_the_first_octet_should_block() {
        assert!(is_blocked_address("127.13.37.1".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_private_class_a_should_block() {
        assert!(is_blocked_address("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_private_class_b_should_block() {
        assert!(is_blocked_address("172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_just_below_private_class_b_should_allow() {
        assert!(!is_blocked_address("172.15.255.255".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_just_above_private_class_b_should_allow() {
        assert!(!is_blocked_address("172.32.0.1".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_private_class_c_should_block() {
        assert!(is_blocked_address("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_link_local_metadata_should_block() {
        assert!(is_blocked_address("169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_carrier_grade_nat_should_block() {
        assert!(is_blocked_address("100.64.0.1".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_unspecified_should_block() {
        assert!(is_blocked_address("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_broadcast_should_block() {
        assert!(is_blocked_address("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_public_should_allow() {
        assert!(!is_blocked_address("93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_ipv6_loopback_should_block() {
        assert!(is_blocked_address("::1".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_ipv6_unique_local_should_block() {
        assert!(is_blocked_address("fd00::1".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_ipv6_link_local_should_block() {
        assert!(is_blocked_address("fe80::1".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_ipv4_mapped_loopback_should_block() {
        assert!(is_blocked_address("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_ipv6_public_should_allow() {
        assert!(!is_blocked_address(
            "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()
        ));
    }

    #[test]
    fn blocked_url_reason_when_loopback_literal_should_refuse() {
        let reason = blocked_url_reason_when(&parse("http://127.0.0.1:4040/api/v3/screens/"), true);

        assert_eq!(
            reason,
            Some(String::from(
                "Target resolves to a non-public address: http://127.0.0.1:4040/api/v3/screens/"
            ))
        );
    }

    #[test]
    fn blocked_url_reason_when_private_literal_should_refuse() {
        let reason = blocked_url_reason_when(&parse("http://192.168.1.10/"), true);

        assert_eq!(
            reason,
            Some(String::from(
                "Target resolves to a non-public address: http://192.168.1.10/"
            ))
        );
    }

    #[test]
    fn blocked_url_reason_when_ipv6_loopback_literal_should_refuse() {
        let reason = blocked_url_reason_when(&parse("http://[::1]:3030/"), true);

        assert_eq!(
            reason,
            Some(String::from(
                "Target resolves to a non-public address: http://[::1]:3030/"
            ))
        );
    }

    #[test]
    fn blocked_url_reason_when_scheme_is_not_http_should_refuse() {
        let reason = blocked_url_reason_when(&parse("file:///etc/passwd"), true);

        assert_eq!(
            reason,
            Some(String::from(
                "Target scheme is not allowed: file:///etc/passwd"
            ))
        );
    }

    #[test]
    fn blocked_url_reason_when_not_blocking_should_allow_loopback() {
        let reason = blocked_url_reason_when(&parse("http://127.0.0.1:4040/"), false);

        assert_eq!(reason, None);
    }

    #[test]
    fn blocked_url_reason_when_not_blocking_should_still_refuse_a_bad_scheme() {
        let reason = blocked_url_reason_when(&parse("file:///etc/passwd"), false);

        assert_eq!(
            reason,
            Some(String::from(
                "Target scheme is not allowed: file:///etc/passwd"
            ))
        );
    }

    #[test]
    fn blocked_url_reason_when_public_literal_should_allow() {
        let reason = blocked_url_reason_when(&parse("https://93.184.216.34/index.html"), true);

        assert_eq!(reason, None);
    }
}
