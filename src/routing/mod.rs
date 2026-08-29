//! Platform-independent routing/NAT boundary (v0.8).
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
//! Nothing in `client.rs`, `server.rs`, `transport.rs`, `protocol.rs`, or
//! `crypto.rs` ever runs an `iptables` command, touches `/proc/sys`, or
//! knows anything else OS-specific about routing -- all of that lives
//! behind this module's platform backend (`src/routing/linux.rs` today).
//! This mirrors `src/tun/`'s split between the platform-independent
//! `PacketDevice` shape and its Linux backend exactly: only Linux is
//! implemented, and compiling for any other target fails at compile time
//! with a clear message rather than linking in a fake/nonfunctional stub.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
use linux::Guard as PlatformGuard;

#[cfg(target_os = "linux")]
pub use linux::{install_shutdown_handler, shutdown_requested};

#[cfg(not(target_os = "linux"))]
compile_error!(
    "tiny-vpn's routing/NAT gateway backend is currently implemented for \
     Linux only (see src/routing/mod.rs and src/routing/linux.rs). Add a \
     new module under src/routing/ that implements `apply` for this \
     target and wire it into the #[cfg]s here, rather than compiling a \
     fake/nonfunctional stub for this target."
);

use std::io;

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
}