//! DNS integration (v0.9).
//!
//! This module configures the OS resolver to point out to the VPN DNS endpoint.
//! It does not implement a DNS server or affect transport protocols directly.

use std::io;
use std::net::IpAddr;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(not(target_os = "linux"))]
mod unsupported;

#[cfg(target_os = "linux")]
use linux::Guard as PlatformDnsGuard;

#[cfg(not(target_os = "linux"))]
use unsupported::Guard as PlatformDnsGuard;

/// The portable intent for OS-level DNS configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    pub enabled: bool,
    pub servers: Vec<IpAddr>,
}

/// An RAII guard that restores the OS DNS configuration when dropped.
pub struct DnsGuard {
    _inner: PlatformDnsGuard,
}

#[cfg(target_os = "linux")]
pub fn apply(config: &DnsConfig, tun_interface: &str) -> io::Result<Option<DnsGuard>> {
    if !config.enabled {
        return Ok(None);
    }
    let _inner = linux::apply(config, tun_interface)?;
    Ok(Some(DnsGuard { _inner }))
}

#[cfg(not(target_os = "linux"))]
pub fn apply(config: &DnsConfig, tun_interface: &str) -> io::Result<Option<DnsGuard>> {
    if !config.enabled {
        return Ok(None);
    }
    let _inner = unsupported::apply(config, tun_interface)?;
    Ok(Some(DnsGuard { _inner }))
}
