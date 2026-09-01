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

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};

use log::error;

/// Only the address matters here, never the port: it pairs with a hostname to
/// resolve it, and with an address to probe whether the device owns it. It has
/// to stay zero in what the resolver hands back, because that is the value the
/// HTTP client replaces with the port the scheme calls for - hand back 80 and
/// an https request connects to port 80.
const ANY_PORT: u16 = 0;

/// Unwraps ::ffff:a.b.c.d to the v4 address actually connected to, so the
/// std predicates below see it.
fn unmapped(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        address => address,
    }
}

/// True when the device answers on this address.
///
/// Binding a socket to an address only succeeds when the address belongs to one
/// of the local interfaces, which answers the question without enumerating them
/// and without going stale when a lease changes. A kernel configured with
/// `ip_nonlocal_bind` would let any address bind and make this always true, so
/// loopback is checked separately rather than relying on this alone.
fn is_device_address(address: IpAddr) -> bool {
    probe_says_device(UdpSocket::bind(SocketAddr::new(address, ANY_PORT)).map(|_| ()))
}

/// `EAFNOSUPPORT`, which std gives no named `ErrorKind`. A kernel that will not
/// make a socket of this family will not connect one either, so an address in
/// that family is already out of reach and needs no refusing.
#[cfg(any(target_os = "linux", target_os = "android"))]
const FAMILY_UNSUPPORTED: i32 = 97;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const FAMILY_UNSUPPORTED: i32 = 47;

/// Reads the outcome of that bind.
///
/// Two failures mean the address is not one to refuse: `AddrNotAvailable`, which
/// is the kernel saying no interface holds it, and a family it will not give us
/// a socket for at all. Anything else answers nothing — a descriptor limit
/// reached under a burst of concurrent requests, a sandbox refusing the syscall
/// — and a check that cannot answer must not hand back "safe", or the block
/// quietly stops applying exactly when the proxy is busiest.
fn probe_says_device(outcome: io::Result<()>) -> bool {
    match outcome {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => false,
        Err(error) if error.raw_os_error() == Some(FAMILY_UNSUPPORTED) => false,
        Err(error) => {
            error!("Cannot tell whether an address is this device's, refusing it: {error}");
            true
        }
    }
}

/// True when a proxied request must not reach this address: it is loopback, or
/// it is one the device itself answers on.
pub(crate) fn is_blocked_address(address: IpAddr) -> bool {
    let address = unmapped(address);
    // All of 0.0.0.0/8 means this host, but only 0.0.0.0 itself is unspecified.
    address.is_loopback()
        || address.is_unspecified()
        || matches!(address, IpAddr::V4(v4) if v4.octets()[0] == 0)
        || is_device_address(address)
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
    if !matches!(url.scheme(), "http" | "https") {
        return Some(format!("Target scheme is not allowed: {url}"));
    }

    let host = url.host()?;

    let addresses: Vec<IpAddr> = match host {
        url::Host::Ipv4(address) => vec![IpAddr::V4(address)],
        url::Host::Ipv6(address) => vec![IpAddr::V6(address)],
        url::Host::Domain(domain) => match (domain, ANY_PORT).to_socket_addrs() {
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
            let resolved = tokio::task::spawn_blocking(move || {
                (host.as_str(), ANY_PORT)
                    .to_socket_addrs()
                    .map(|addresses| addresses.collect::<Vec<_>>())
            })
            .await??;

            if resolved
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
    fn is_blocked_address_when_in_this_host_range_should_block() {
        assert!(is_blocked_address("0.1.2.3".parse().unwrap()));
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
    fn probe_says_device_when_bound_should_be_true() {
        assert!(probe_says_device(Ok(())));
    }

    #[test]
    fn probe_says_device_when_address_is_not_available_should_be_false() {
        let outcome = Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "not here"));

        assert!(!probe_says_device(outcome));
    }

    // Hosts with IPv6 turned off answer every v6 bind this way, including the
    // wildcard, and nothing can reach a v6 target there in the first place.
    #[test]
    fn probe_says_device_when_the_family_is_unsupported_should_be_false() {
        let outcome = Err(io::Error::from_raw_os_error(FAMILY_UNSUPPORTED));

        assert!(!probe_says_device(outcome));
    }

    // The probe failing for its own reasons says nothing about the address, so it
    // must not be read as permission to fetch it.
    #[test]
    fn probe_says_device_when_the_probe_itself_fails_should_be_true() {
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::Other,
            io::ErrorKind::OutOfMemory,
        ] {
            assert!(probe_says_device(Err(io::Error::new(kind, "probe failed"))));
        }
    }

    // The loopback assertion above passes on the is_loopback() short-circuit, so
    // the bind probe itself is only covered by an address that is not loopback.
    // Connecting a UDP socket sends nothing; it just makes the kernel pick the
    // outbound interface and tell us which address it would use.
    #[test]
    fn is_device_address_when_a_non_loopback_local_address_should_be_true() {
        let socket = UdpSocket::bind("0.0.0.0:0").expect("binding the wildcard should work");
        if socket.connect("192.0.2.1:80").is_err() {
            return; // No route off this machine, so there is no address to check.
        }
        let local = socket
            .local_addr()
            .expect("a connected socket has an address")
            .ip();
        if local.is_loopback() || local.is_unspecified() {
            return;
        }

        assert!(is_device_address(local));
        assert!(is_blocked_address(local));
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
        let reason = blocked_url_reason(&parse("http://127.0.0.1:4040/api/v3/screens/"));

        assert_eq!(
            reason,
            Some(String::from(
                "Target is an address of this device: http://127.0.0.1:4040/api/v3/screens/"
            ))
        );
    }

    #[test]
    fn blocked_url_reason_when_ipv6_loopback_literal_should_refuse() {
        let reason = blocked_url_reason(&parse("http://[::1]:3030/"));

        assert_eq!(
            reason,
            Some(String::from(
                "Target is an address of this device: http://[::1]:3030/"
            ))
        );
    }

    #[test]
    fn blocked_url_reason_when_scheme_is_not_http_should_refuse() {
        let reason = blocked_url_reason(&parse("file:///etc/passwd"));

        assert_eq!(
            reason,
            Some(String::from(
                "Target scheme is not allowed: file:///etc/passwd"
            ))
        );
    }

    #[test]
    fn blocked_url_reason_when_public_literal_should_allow() {
        let reason = blocked_url_reason(&parse("https://93.184.216.34/index.html"));

        assert_eq!(reason, None);
    }
}
