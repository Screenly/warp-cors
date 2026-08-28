//! Refuses proxy targets that point back at the device running the proxy.
//!
//! Every target this proxy fetches comes from the caller, and on a Screenly
//! player the caller is web content rendered by the viewer. A page that names a
//! loopback target reaches services meant for the device alone — the identity
//! proxy answers with the device's credentials — and it can read the answer,
//! because the response comes back with the caller's origin allowed and every
//! header exposed.
//!
//! Reaching the rest of the network stays allowed: a player sits on a customer
//! network and content legitimately fetches hosts there. Only the device itself
//! is out of bounds, which means loopback and every address the device answers
//! on — a service bound to `0.0.0.0` is reachable through the device's own LAN
//! address just as well as through `127.0.0.1`.
//!
//! Set `BLOCK_LOCAL_ADDRESSES` to `false` where the proxy is meant to reach the
//! device, such as a test world serving its own origin.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::OnceLock;

use log::error;

const BLOCK_LOCAL_ADDRESSES_VAR: &str = "BLOCK_LOCAL_ADDRESSES";

/// Port used only to turn a hostname into something resolvable, and to probe
/// whether an address belongs to the device; the address is what matters.
const PROBE_PORT: u16 = 0;

/// Port paired with a hostname for resolution. Any port resolves the same name.
const RESOLVE_PORT: u16 = 80;

/// Ranges that always name this host, whatever interfaces it has.
const BLOCKED_IPV4_CIDRS: &[(Ipv4Addr, u32)] = &[
    (Ipv4Addr::new(0, 0, 0, 0), 8),   // this host / this network
    (Ipv4Addr::new(127, 0, 0, 0), 8), // loopback
];

/// IPv6 counterparts of the ranges above.
const BLOCKED_IPV6_CIDRS: &[(Ipv6Addr, u32)] = &[
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 128), // unspecified
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 128), // loopback
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

fn is_loopback_ipv4(address: Ipv4Addr) -> bool {
    BLOCKED_IPV4_CIDRS.iter().any(|(network, prefix_length)| {
        matches_prefix(&address.octets(), &network.octets(), *prefix_length)
    })
}

fn is_loopback_ipv6(address: Ipv6Addr) -> bool {
    // An IPv4-mapped ::ffff:a.b.c.d or the deprecated IPv4-compatible ::a.b.c.d
    // both carry in their low 32 bits the address that is actually connected to.
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_loopback_ipv4(mapped);
    }
    if let Some(compatible) = address.to_ipv4() {
        return is_loopback_ipv4(compatible);
    }

    BLOCKED_IPV6_CIDRS.iter().any(|(network, prefix_length)| {
        matches_prefix(&address.octets(), &network.octets(), *prefix_length)
    })
}

/// True when an address names this host outright, before any interface is
/// considered.
fn is_loopback_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_loopback_ipv4(address),
        IpAddr::V6(address) => is_loopback_ipv6(address),
    }
}

/// True when the device answers on this address.
///
/// Binding a socket to an address only succeeds when the address belongs to one
/// of the local interfaces, which answers the question without enumerating them
/// and without going stale when a lease changes. A kernel configured with
/// `ip_nonlocal_bind` would let any address bind and make this always true, so
/// the loopback ranges are checked separately rather than relying on this alone.
fn is_device_address(address: IpAddr) -> bool {
    let mapped = match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address => address,
    };

    UdpSocket::bind(SocketAddr::new(mapped, PROBE_PORT)).is_ok()
}

/// True when a proxied request must not reach this address: it is loopback, or
/// it is one the device itself answers on.
pub(crate) fn is_blocked_address(address: IpAddr) -> bool {
    is_loopback_address(address) || is_device_address(address)
}

/// Read once: the setting cannot change under a running proxy, and the check
/// runs on every request and every name the client resolves.
fn blocking_local_addresses() -> bool {
    static BLOCKING: OnceLock<bool> = OnceLock::new();
    *BLOCKING.get_or_init(|| {
        std::env::var(BLOCK_LOCAL_ADDRESSES_VAR)
            .map(|value| value != "false")
            .unwrap_or(true)
    })
}

/// Returns the reason a URL must not be fetched, or `None` when it may be.
///
/// A literal address is decided without a lookup; a hostname is resolved and no
/// address it answers with may name the device, so a name pointing at loopback
/// is refused as well. A hostname that does not resolve is refused, because it
/// cannot be vetted. The reason names the class of refusal and the URL, never
/// the resolved address.
///
/// This resolves names with the blocking resolver, so callers on an async
/// runtime should reach for [`blocked_url_reason_async`].
pub(crate) fn blocked_url_reason(url: &url::Url) -> Option<String> {
    blocked_url_reason_when(url, blocking_local_addresses())
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
        return Some(format!("Target is an address of this device: {url}"));
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

/// The resolver the HTTP client connects through, which refuses to hand back an
/// address of this device.
///
/// Vetting a URL and then letting the client look the name up again leaves a
/// window where the second answer differs from the checked one, which is all a
/// rebinding host needs. Resolving here means the addresses that were vetted
/// are exactly the addresses connected to, and it covers redirect hops too,
/// since every connection the client makes comes through this resolver.
pub(crate) struct PublicAddressResolver;

impl reqwest::dns::Resolve for PublicAddressResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();

        Box::pin(async move {
            let blocking = blocking_local_addresses();
            let resolved = tokio::task::spawn_blocking(move || {
                (host.as_str(), RESOLVE_PORT)
                    .to_socket_addrs()
                    .map(|addresses| addresses.collect::<Vec<_>>())
            })
            .await??;

            if blocking
                && resolved
                    .iter()
                    .any(|address| is_blocked_address(address.ip()))
            {
                error!("Refusing to resolve a host that names this device");
                return Err(Box::new(DeviceAddress) as Box<dyn std::error::Error + Send + Sync>);
            }

            Ok(Box::new(resolved.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Returned when a name resolves to an address of this device. The message
/// deliberately names no address.
#[derive(Debug)]
struct DeviceAddress;

impl fmt::Display for DeviceAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Target is an address of this device")
    }
}

impl std::error::Error for DeviceAddress {}

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
    fn is_blocked_address_when_unspecified_should_block() {
        assert!(is_blocked_address("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_ipv6_loopback_should_block() {
        assert!(is_blocked_address("::1".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_ipv6_unspecified_should_block() {
        assert!(is_blocked_address("::".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_ipv4_mapped_loopback_should_block() {
        assert!(is_blocked_address("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_an_address_of_this_device_should_block() {
        let device_address = UdpSocket::bind("127.0.0.1:0")
            .expect("binding loopback should work")
            .local_addr()
            .expect("a bound socket has an address")
            .ip();

        assert!(is_blocked_address(device_address));
    }

    #[test]
    fn is_blocked_address_when_public_should_allow() {
        assert!(!is_blocked_address("93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_ipv6_public_should_allow() {
        assert!(!is_blocked_address(
            "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()
        ));
    }

    // A player sits on a customer network and content there is fair game, so the
    // private ranges must stay reachable.
    #[test]
    fn is_blocked_address_when_private_class_a_should_allow() {
        assert!(!is_blocked_address("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn is_blocked_address_when_private_class_c_should_allow() {
        assert!(!is_blocked_address("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn blocked_url_reason_when_loopback_literal_should_refuse() {
        let reason = blocked_url_reason_when(&parse("http://127.0.0.1:4040/api/v3/screens/"), true);

        assert_eq!(
            reason,
            Some(String::from(
                "Target is an address of this device: http://127.0.0.1:4040/api/v3/screens/"
            ))
        );
    }

    #[test]
    fn blocked_url_reason_when_ipv6_loopback_literal_should_refuse() {
        let reason = blocked_url_reason_when(&parse("http://[::1]:3030/"), true);

        assert_eq!(
            reason,
            Some(String::from(
                "Target is an address of this device: http://[::1]:3030/"
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
