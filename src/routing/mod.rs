//! Platform-independent routing/NAT boundary (v0.8 server-side
//! forwarding/NAT; v0.8.5 client-side routing).
//!
//! Turning the v0.7 encrypted point-to-point tunnel into an actual
//! gateway needs the host OS to forward VPN-subnet traffic toward the
//! wider network and translate its source address (NAT/masquerade) so
//! replies find their way back. Both of those are OS mechanisms, not
//! something this project implements itself (no userspace router, no
//! userspace connection tracker) -- this module defines what the VPN
//! server needs from the OS ([`RoutingConfig`]) and exposes a single
//! entrypoint ([`apply`]) that configures it and hands back an RAII
//! [`RoutingGuard`] that undoes exactly what it did when dropped.
//!
//! v0.8.5 adds the client-side counterpart: routing selected traffic (or,
//! in full-tunnel mode, all IPv4 traffic) into the client's TUN device,
//! while always protecting the VPN server's own endpoint so its traffic
//! keeps using the client's normal physical route (see
//! [`ClientRoutingMode`], [`build_client_routing_plan`]).
//!
//! Nothing in `client.rs`, `server.rs`, `transport.rs`, `protocol.rs`, or
//! `crypto.rs` ever runs an `ip`/`iptables` command, touches `/proc/sys`,
//! or knows anything else OS-specific about routing -- all of that lives
//! behind this module's platform backend (`src/routing/linux.rs` today).
//! This mirrors `src/tun/`'s split between the platform-independent
//! `PacketDevice` shape and its Linux backend exactly: only Linux is
//! implemented, and compiling for any other target fails at compile time
//! with a clear message rather than linking in a fake/nonfunctional stub.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
use linux::{Guard as PlatformGuard, ClientRouteGuard as PlatformClientRouteGuard};

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
use windows::{Guard as PlatformGuard, ClientRouteGuard as PlatformClientRouteGuard};

#[cfg(target_os = "android")]
pub mod android;
#[cfg(target_os = "android")]
use android::{Guard as PlatformGuard, ClientRouteGuard as PlatformClientRouteGuard};

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
mod unsupported;

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
use unsupported::{Guard as PlatformGuard, ClientRouteGuard as PlatformClientRouteGuard};

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
pub fn install_shutdown_handler() {
    unsupported::install_shutdown_handler()
}
#[cfg(target_os = "android")]
pub fn install_shutdown_handler() {
    android::install_shutdown_handler()
}
#[cfg(target_os = "windows")]
pub fn install_shutdown_handler() {
    windows::install_shutdown_handler()
}
#[cfg(target_os = "linux")]
pub fn install_shutdown_handler() {
    linux::install_shutdown_handler()
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
pub fn shutdown_requested() -> bool {
    unsupported::shutdown_requested()
}
#[cfg(target_os = "android")]
pub fn shutdown_requested() -> bool {
    android::shutdown_requested()
}
#[cfg(target_os = "windows")]
pub fn shutdown_requested() -> bool {
    windows::shutdown_requested()
}
#[cfg(target_os = "linux")]
pub fn shutdown_requested() -> bool {
    linux::shutdown_requested()
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
pub fn current_route_to(endpoint: &str) -> io::Result<RouteVia> {
    unsupported::current_route_to(endpoint)
}
#[cfg(target_os = "android")]
pub fn current_route_to(endpoint: &str) -> io::Result<RouteVia> {
    android::current_route_to(endpoint)
}
#[cfg(target_os = "linux")]
pub fn current_route_to(endpoint: &str) -> io::Result<RouteVia> {
    linux::current_route_to(endpoint)
}
#[cfg(target_os = "windows")]
pub fn current_route_to(endpoint: &str) -> io::Result<RouteVia> {
    windows::current_route_to(endpoint)
}

use std::fmt;
use std::io;
use std::net::Ipv4Addr;

/// What the VPN server needs from the host's networking stack to act as
/// a gateway for the VPN subnet.
pub struct RoutingConfig {
    /// VPN subnet in CIDR form, e.g. `"10.13.13.0/24"`.
    pub vpn_subnet: String,
    /// Name of the server's TUN interface, e.g. `"tiny-tun-server"`.
    pub tun_interface: String,
    /// Outbound interface to forward/NAT through. `None` means
    /// "auto-detect from the host's default route".
    pub outbound_interface: Option<String>,
    /// Address topology for VPN Tunnel Endpoints
    pub address_plan: crate::tun::TunnelAddressPlan,
}

/// RAII handle for "forwarding/NAT is currently configured for this VPN
/// session". Dropping it restores the host's previous state (the IP
/// forwarding sysctl and any iptables rules this module added) -- see
/// `src/routing/linux.rs`'s `Guard` for exactly what that means on Linux.
pub struct RoutingGuard {
    #[allow(dead_code)] // held only for its Drop side effect
    inner: PlatformGuard,
}

/// Configure the host to forward and NAT traffic from `config.vpn_subnet`
/// out through the detected/configured outbound interface, returning a
/// guard that restores the previous state when dropped (including on
/// early return via `?` -- Rust drops locals during unwinding/early
/// return the same as at the end of a block).
///
/// If any step fails partway through, everything already configured by
/// this call is rolled back before the error is returned -- callers never
/// need to guess what state the host was left in after a failed `apply`.
#[cfg(target_os = "linux")]
pub fn apply(config: &RoutingConfig) -> io::Result<RoutingGuard> {
    let inner = linux::apply(config)?;
    Ok(RoutingGuard { inner })
}

#[cfg(target_os = "windows")]
pub fn apply(config: &RoutingConfig) -> io::Result<RoutingGuard> {
    let inner = windows::apply(config)?;
    Ok(RoutingGuard { inner })
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
pub fn apply(config: &RoutingConfig) -> io::Result<RoutingGuard> {
    let inner = unsupported::apply(config)?;
    Ok(RoutingGuard { inner })
}

#[cfg(target_os = "android")]
pub fn apply(config: &RoutingConfig) -> io::Result<RoutingGuard> {
    let inner = android::apply(config)?;
    Ok(RoutingGuard { inner })
}

/// Compute the VPN subnet in CIDR form (e.g. `"10.13.13.0/24"`) from an
/// address/netmask pair, such as `tun::SERVER_TUN_ADDRESS`/
/// `tun::VPN_TUN_NETMASK`. Pure and platform-independent -- no I/O.
pub fn cidr_from_address_and_netmask(
    address: (u8, u8, u8, u8),
    netmask: (u8, u8, u8, u8),
) -> String {
    let address_bits = u32::from_be_bytes([address.0, address.1, address.2, address.3]);
    let mask_bits = u32::from_be_bytes([netmask.0, netmask.1, netmask.2, netmask.3]);
    let network_bits = address_bits & mask_bits;
    let prefix_len = mask_bits.count_ones();
    let octets = network_bits.to_be_bytes();
    format!(
        "{}.{}.{}.{}/{prefix_len}",
        octets[0], octets[1], octets[2], octets[3]
    )
}

// ============================================================================
// v0.8.5: client-side routing.
//
// The client's job is simpler than the server's in one sense (no NAT, no
// forwarding sysctl) and trickier in another: it must never let its own
// new routes cut off the very UDP socket the tunnel depends on. See
// `build_client_routing_plan` for how that's guaranteed structurally
// (the server-endpoint exception is always part of the plan, computed
// from the host's *pre-VPN* route to that endpoint) rather than merely
// documented as something callers must remember to do.
// ============================================================================

/// How the client should route traffic once its VPN session is
/// established. Loaded from config (`config::RoutingMode` +
/// `config::ClientRoutingSettings`) and converted into this type by
/// `client.rs` -- this type itself doesn't know about config file syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientRoutingMode {
    /// No client-side route changes. The TUN device's own connected
    /// route for the VPN subnet (added automatically when the interface
    /// is configured) is the only route touching it -- exactly the v0.7/
    /// v0.8 behavior. This is the default: installing v0.8.5 must not
    /// silently change an existing client's routing behavior.
    ///
    /// `client.rs` short-circuits on this variant before it would ever
    /// be constructed in production code (so `configure_client_routing`
    /// performs zero routing-related work at all -- not even resolving
    /// the server's pre-VPN route -- when routing is disabled); it's
    /// exercised directly by this module's own tests instead, hence
    /// `#[allow(dead_code)]` rather than removing a meaningful, documented
    /// part of this public enum's contract.
    #[allow(dead_code)]
    Disabled,
    /// Route only these CIDRs (e.g. `"10.20.0.0/24"`) through the VPN TUN
    /// device; everything else keeps using the client's normal route(s).
    Split(Vec<String>),
    /// Route all IPv4 traffic through the VPN TUN device, except the VPN
    /// server's own endpoint (see `build_client_routing_plan`).
    Full,
}

/// How to reach a destination: either through a named interface with no
/// explicit gateway (appropriate for a point-to-point TUN link, or for a
/// destination on a directly-connected/local network), or via a specific
/// gateway on a specific device (the common case for a real remote
/// destination like a VPN server on the far side of a router).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteVia {
    Device(String),
    Gateway { gateway: String, device: String },
}

/// One route the client should add.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRoute {
    /// Destination in CIDR form, e.g. `"10.20.0.0/24"` or
    /// `"203.0.113.10/32"`.
    pub destination: String,
    pub via: RouteVia,
}

/// A fully-resolved, platform-independent plan of routes to add for the
/// client. Building one (`build_client_routing_plan`) is pure -- no I/O,
/// no `ip` command -- so the logic that decides *what* to route is fully
/// unit-testable without touching a real routing table; only *applying*
/// the plan (`apply_client_routes`) touches the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRoutingPlan {
    pub routes: Vec<ClientRoute>,
}

/// An invalid input to [`build_client_routing_plan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingPlanError {
    InvalidCidr(String),
}

impl fmt::Display for RoutingPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoutingPlanError::InvalidCidr(cidr) => write!(f, "invalid IPv4 CIDR: {cidr:?}"),
        }
    }
}

impl std::error::Error for RoutingPlanError {}

/// Whether `s` is a syntactically valid IPv4 CIDR (`a.b.c.d/n`, all
/// octets 0-255, prefix length 0-32). Pure, no I/O.
pub fn is_valid_ipv4_cidr(s: &str) -> bool {
    let Some((address, prefix)) = s.split_once('/') else {
        return false;
    };
    let Ok(prefix_len) = prefix.parse::<u8>() else {
        return false;
    };
    if prefix_len > 32 {
        return false;
    }
    address.parse::<Ipv4Addr>().is_ok()
}

/// Compute what routes the client should add for `mode`.
///
/// `tun_interface` is the client's TUN device name. `server_endpoint_ip`
/// is the VPN server's resolved IPv4 address (as a plain dotted-quad
/// string, no port). `server_route` is the route the host would use to
/// reach `server_endpoint_ip` *before* any VPN routes are added (see
/// `routing::current_route_to`, which must be called before this
/// function for `Full` mode to be meaningful).
///
/// - `Disabled` produces an empty plan.
/// - `Split` produces one route per configured CIDR, deduplicated, each
///   via the TUN device. It never touches the default route.
/// - `Full` produces the VPN server's own endpoint pinned to
///   `server_route` (so the tunnel's own traffic never loops back into
///   itself), plus `0.0.0.0/1` and `128.0.0.0/1` via the TUN device.
///   Those two halves together cover the entire IPv4 address space and
///   win over the existing `0.0.0.0/0` default route by longest-prefix
///   match, without ever modifying, deleting, or needing to back up that
///   default route -- removing them on shutdown transparently restores
///   the original default-route behavior. This is the same technique
///   established VPN clients (OpenVPN's `redirect-gateway`, WireGuard's
///   `wg-quick`) use for exactly this reason.
pub fn build_client_routing_plan(
    mode: &ClientRoutingMode,
    tun_interface: &str,
    server_endpoint_ip: &str,
    server_route: &RouteVia,
) -> Result<ClientRoutingPlan, RoutingPlanError> {
    match mode {
        ClientRoutingMode::Disabled => Ok(ClientRoutingPlan { routes: vec![] }),

        ClientRoutingMode::Split(cidrs) => {
            let mut seen = Vec::new();
            let mut routes = Vec::new();
            for cidr in cidrs {
                if !is_valid_ipv4_cidr(cidr) {
                    return Err(RoutingPlanError::InvalidCidr(cidr.clone()));
                }
                if seen.contains(cidr) {
                    continue; // no accidental duplicate routes
                }
                seen.push(cidr.clone());
                routes.push(ClientRoute {
                    destination: cidr.clone(),
                    via: RouteVia::Device(tun_interface.to_string()),
                });
            }
            Ok(ClientRoutingPlan { routes })
        }

        ClientRoutingMode::Full => {
            let server_exception = ClientRoute {
                destination: format!("{server_endpoint_ip}/32"),
                via: server_route.clone(),
            };
            let lower_half = ClientRoute {
                destination: "0.0.0.0/1".to_string(),
                via: RouteVia::Device(tun_interface.to_string()),
            };
            let upper_half = ClientRoute {
                destination: "128.0.0.0/1".to_string(),
                via: RouteVia::Device(tun_interface.to_string()),
            };
            Ok(ClientRoutingPlan {
                routes: vec![server_exception, lower_half, upper_half],
            })
        }
    }
}

/// RAII handle for "these client routes are currently installed".
/// Dropping it removes exactly the routes the corresponding
/// `apply_client_routes` call added (in reverse order) -- see
/// `src/routing/linux.rs`'s `ClientRouteGuard`.
pub struct ClientRouteGuard {
    #[allow(dead_code)] // held only for its Drop side effect
    inner: PlatformClientRouteGuard,
}

/// Apply `plan`'s routes on the host, returning a guard that removes them
/// when dropped. If any route fails to add, every route already added by
/// this call is removed before the error is returned.
#[cfg(target_os = "linux")]
pub fn apply_client_routes(plan: &ClientRoutingPlan) -> io::Result<ClientRouteGuard> {
    let inner = linux::apply_client_routes(plan)?;
    Ok(ClientRouteGuard { inner })
}

#[cfg(target_os = "windows")]
pub fn apply_client_routes(plan: &ClientRoutingPlan) -> io::Result<ClientRouteGuard> {
    let inner = windows::apply_client_routes(plan)?;
    Ok(ClientRouteGuard { inner })
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
pub fn apply_client_routes(plan: &ClientRoutingPlan) -> io::Result<ClientRouteGuard> {
    let inner = unsupported::apply_client_routes(plan)?;
    Ok(ClientRouteGuard { inner })
}

#[cfg(target_os = "android")]
pub fn apply_client_routes(plan: &ClientRoutingPlan) -> io::Result<ClientRouteGuard> {
    let inner = android::apply_client_routes(plan)?;
    Ok(ClientRouteGuard { inner })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_from_address_and_netmask_computes_network_address() {
        assert_eq!(
            cidr_from_address_and_netmask((10, 13, 13, 2), (255, 255, 255, 0)),
            "10.13.13.0/24"
        );
    }

    #[test]
    fn cidr_from_address_and_netmask_masks_off_host_bits() {
        // Even if given a "dirty" address with host bits set, the network
        // address in the result should have them masked off.
        assert_eq!(
            cidr_from_address_and_netmask((192, 168, 1, 200), (255, 255, 255, 128)),
            "192.168.1.128/25"
        );
    }

    #[test]
    fn cidr_from_address_and_netmask_handles_slash_16() {
        assert_eq!(
            cidr_from_address_and_netmask((172, 16, 5, 9), (255, 255, 0, 0)),
            "172.16.0.0/16"
        );
    }

    // ------------------------------------------------------------------
    // v0.8.5 client routing plan tests
    // ------------------------------------------------------------------

    fn dummy_server_route() -> RouteVia {
        RouteVia::Gateway {
            gateway: "192.0.2.1".to_string(),
            device: "eth0".to_string(),
        }
    }

    #[test]
    fn cidr_validation_accepts_valid_cidrs() {
        assert!(is_valid_ipv4_cidr("10.20.0.0/24"));
        assert!(is_valid_ipv4_cidr("0.0.0.0/0"));
        assert!(is_valid_ipv4_cidr("255.255.255.255/32"));
    }

    #[test]
    fn cidr_validation_rejects_invalid_cidrs() {
        assert!(!is_valid_ipv4_cidr("10.20.0.0")); // no prefix
        assert!(!is_valid_ipv4_cidr("10.20.0.0/33")); // prefix too large
        assert!(!is_valid_ipv4_cidr("10.20.0.0/-1")); // negative
        assert!(!is_valid_ipv4_cidr("not.an.ip.addr/24"));
        assert!(!is_valid_ipv4_cidr("10.20.0/24")); // too few octets
        assert!(!is_valid_ipv4_cidr("10.20.0.0.1/24")); // too many octets
        assert!(!is_valid_ipv4_cidr(""));
    }

    #[test]
    fn disabled_mode_produces_an_empty_plan() {
        let plan = build_client_routing_plan(
            &ClientRoutingMode::Disabled,
            "tiny-tun-client",
            "203.0.113.10",
            &dummy_server_route(),
        )
        .unwrap();
        assert!(plan.routes.is_empty());
    }

    #[test]
    fn split_mode_does_not_replace_the_default_route() {
        let plan = build_client_routing_plan(
            &ClientRoutingMode::Split(vec!["10.20.0.0/24".to_string()]),
            "tiny-tun-client",
            "203.0.113.10",
            &dummy_server_route(),
        )
        .unwrap();
        assert!(!plan.routes.iter().any(|r| r.destination == "0.0.0.0/0"));
        assert!(!plan.routes.iter().any(|r| r.destination == "0.0.0.0/1"));
        assert_eq!(plan.routes.len(), 1);
        assert_eq!(plan.routes[0].destination, "10.20.0.0/24");
        assert_eq!(
            plan.routes[0].via,
            RouteVia::Device("tiny-tun-client".to_string())
        );
    }

    #[test]
    fn split_mode_handles_empty_route_list() {
        let plan = build_client_routing_plan(
            &ClientRoutingMode::Split(vec![]),
            "tiny-tun-client",
            "203.0.113.10",
            &dummy_server_route(),
        )
        .unwrap();
        assert!(plan.routes.is_empty());
    }

    #[test]
    fn split_mode_deduplicates_routes() {
        let plan = build_client_routing_plan(
            &ClientRoutingMode::Split(vec![
                "10.20.0.0/24".to_string(),
                "10.20.0.0/24".to_string(),
                "10.30.0.0/16".to_string(),
            ]),
            "tiny-tun-client",
            "203.0.113.10",
            &dummy_server_route(),
        )
        .unwrap();
        assert_eq!(plan.routes.len(), 2);
    }

    #[test]
    fn split_mode_rejects_invalid_cidr() {
        let result = build_client_routing_plan(
            &ClientRoutingMode::Split(vec!["not-a-cidr".to_string()]),
            "tiny-tun-client",
            "203.0.113.10",
            &dummy_server_route(),
        );
        assert!(matches!(result, Err(RoutingPlanError::InvalidCidr(_))));
    }

    #[test]
    fn full_mode_contains_server_endpoint_exception() {
        let plan = build_client_routing_plan(
            &ClientRoutingMode::Full,
            "tiny-tun-client",
            "203.0.113.10",
            &dummy_server_route(),
        )
        .unwrap();
        let exception = plan
            .routes
            .iter()
            .find(|r| r.destination == "203.0.113.10/32")
            .expect("server endpoint exception must be present");
        // And it must use the pre-VPN route, NOT the TUN device -- this
        // is the whole point of the exception.
        assert_eq!(exception.via, dummy_server_route());
        assert_ne!(exception.via, RouteVia::Device("tiny-tun-client".to_string()));
    }

    #[test]
    fn full_mode_contains_default_vpn_route_as_two_halves() {
        let plan = build_client_routing_plan(
            &ClientRoutingMode::Full,
            "tiny-tun-client",
            "203.0.113.10",
            &dummy_server_route(),
        )
        .unwrap();
        // 0.0.0.0/1 + 128.0.0.0/1 together cover all of IPv4 without
        // ever touching the real 0.0.0.0/0 default route.
        assert!(plan.routes.iter().any(|r| r.destination == "0.0.0.0/1"
            && r.via == RouteVia::Device("tiny-tun-client".to_string())));
        assert!(plan.routes.iter().any(|r| r.destination == "128.0.0.0/1"
            && r.via == RouteVia::Device("tiny-tun-client".to_string())));
        // Never a literal 0.0.0.0/0 -- we don't touch/replace it.
        assert!(!plan.routes.iter().any(|r| r.destination == "0.0.0.0/0"));
    }

    #[test]
    fn full_mode_plan_has_exactly_three_routes() {
        let plan = build_client_routing_plan(
            &ClientRoutingMode::Full,
            "tiny-tun-client",
            "203.0.113.10",
            &dummy_server_route(),
        )
        .unwrap();
        assert_eq!(plan.routes.len(), 3);
    }
}