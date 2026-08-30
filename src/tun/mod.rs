//! Platform-independent virtual network interface boundary (v0.6.5).
//!
//! Everything in the VPN core -- `client.rs`, `server.rs`, `transport.rs`,
//! `protocol.rs`, `crypto.rs` -- talks to a virtual network interface only
//! through the types exported from this module: [`PacketDevice`],
//! [`PacketReader`], [`PacketWriter`], and [`TunError`]. None of those
//! files import the Linux `tun` crate, or any other platform crate,
//! directly. Adding a new operating system's backend means adding a file
//! under `src/tun/` and wiring it into the `#[cfg]`s below -- the rest of
//! the codebase does not change.
//!
//! # Why this shape and not a custom trait
//!
//! The Linux `tun` crate's own `Device::split() -> (Reader, Writer)`
//! model -- two independent halves, each implementing `std::io::{Read,
//! Write}`, safe to move to separate threads -- is *already* exactly the
//! right shape for this project: `client.rs`/`server.rs` have always run
//! "TUN -> network" and "network -> TUN" concurrently on two threads (see
//! v0.3+). So instead of inventing a new `TunDevice` trait with
//! `read_packet`/`write_packet` methods, this module just re-exposes that
//! same split-reader/writer shape as its own types, so a Linux-crate type
//! never leaks outside `src/tun/`. Any future backend (Android
//! `VpnService`, Windows Wintun, macOS `utun`) only needs to be able to
//! produce something splittable into a `Read` half and a `Write` half --
//! which every one of those mechanisms can do -- so this abstraction
//! doesn't need to change shape to accommodate them.
//!
//! # Platform selection
//!
//! Only Linux is implemented right now. Compiling for any other target
//! fails at compile time with a clear message (see below) rather than
//! silently linking in a nonfunctional stub -- there is no fake Android,
//! Windows, or macOS backend pretending to exist.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
use linux::{Device as PlatformDevice, Reader as PlatformReader, Writer as PlatformWriter};

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "windows")]
use windows::{Device as PlatformDevice, Reader as PlatformReader, Writer as PlatformWriter};

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod unsupported;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
use unsupported::{Device as PlatformDevice, Reader as PlatformReader, Writer as PlatformWriter};

use std::io::{self, Read, Write};

/// Name/address for the VPN client's TUN interface (used by `vpn-client`
/// and `udp-client`). Not platform-specific -- this is this project's own
/// test network layout, not an OS concept.
pub const CLIENT_TUN_NAME: &str = "tiny-tun-client";
pub const CLIENT_TUN_ADDRESS: (u8, u8, u8, u8) = (10, 13, 13, 1);

/// Name/address for the VPN server's TUN interface (used by `vpn-server`
/// and `udp-server`).
pub const SERVER_TUN_NAME: &str = "tiny-tun-server";
pub const SERVER_TUN_ADDRESS: (u8, u8, u8, u8) = (10, 13, 13, 2);

/// Shared netmask for the client/server test network.
pub const VPN_TUN_NETMASK: (u8, u8, u8, u8) = (255, 255, 255, 0);

/// An error from the platform-specific virtual network interface backend.
///
/// Kept distinct from `protocol::ProtocolError`, `crypto::CryptoError`,
/// and `config::ConfigError` so it's obvious at a glance whether a
/// failure came from talking to the OS's virtual-interface mechanism
/// (this type) or from the platform-independent VPN protocol/crypto/
/// config layers (their own types). Converts to `io::Error` at the
/// `tun` module boundary so the rest of the codebase -- which already
/// uses `io::Result` throughout -- doesn't need a second error type
/// threaded through every function signature.
#[derive(Debug)]
pub struct TunError(String);

impl std::fmt::Display for TunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "virtual network interface error: {}", self.0)
    }
}

impl std::error::Error for TunError {}

impl From<TunError> for io::Error {
    fn from(e: TunError) -> Self {
        io::Error::new(io::ErrorKind::Other, e.to_string())
    }
}

/// An open virtual network interface, ready to be split into a reader and
/// writer for concurrent relaying.
///
/// This type's *shape* is platform-independent; what it actually wraps is
/// selected by the `#[cfg]`s above. Nothing outside `src/tun/` ever names
/// `PlatformDevice` or any Linux-crate type.
pub struct PacketDevice {
    inner: PlatformDevice,
}

/// The read half of a split [`PacketDevice`]. Implements [`Read`], same
/// as before this module existed -- only the type name changed, not the
/// I/O interface `transport.rs` and `tun`'s own relay helpers use.
pub struct PacketReader {
    inner: PlatformReader,
}

/// The write half of a split [`PacketDevice`]. Implements [`Write`].
pub struct PacketWriter {
    inner: PlatformWriter,
}

impl PacketDevice {
    /// Split into independent reader/writer halves so "TUN -> network"
    /// and "network -> TUN" can run concurrently on separate threads, as
    /// `client.rs`/`server.rs` have always done.
    pub fn split(self) -> (PacketReader, PacketWriter) {
        let (reader, writer) = self.inner.split();
        (PacketReader { inner: reader }, PacketWriter { inner: writer })
    }
}

impl PacketReader {
    pub fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read_packet(buf)
    }
}

impl PacketWriter {
    pub fn write_packet(&mut self, buf: &[u8]) -> io::Result<()> {
        self.inner.write_packet(buf)
    }
}

/// Create and bring up a virtual network interface with the given
/// name/address/netmask, using whichever backend is compiled in for the
/// current target.
#[cfg(target_os = "linux")]
pub fn create_device(
    name: &str,
    address: (u8, u8, u8, u8),
    netmask: (u8, u8, u8, u8),
) -> io::Result<PacketDevice> {
    let inner = linux::create_raw_device(name, address, netmask)?;
    Ok(PacketDevice { inner })
}

#[cfg(target_os = "windows")]
pub fn create_device(
    name: &str,
    address: (u8, u8, u8, u8),
    netmask: (u8, u8, u8, u8),
) -> io::Result<PacketDevice> {
    let inner = windows::create_raw_device(name, address, netmask)?;
    Ok(PacketDevice { inner })
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn create_device(
    name: &str,
    address: (u8, u8, u8, u8),
    netmask: (u8, u8, u8, u8),
) -> io::Result<PacketDevice> {
    let inner = unsupported::create_raw_device(name, address, netmask)?;
    Ok(PacketDevice { inner })
}

/// Standalone virtual-interface smoke test (the `tiny-vpn tun` command,
/// unchanged since v0.2): creates one device and prints every packet read
/// from it. This is a diagnostic tool for whichever backend is compiled
/// in, so it's provided directly by that backend rather than abstracted
/// -- there's nothing platform-independent to factor out of "dump
/// whatever this OS's virtual interface gives you".
#[cfg(target_os = "linux")]
pub use linux::run;

#[cfg(target_os = "windows")]
pub use windows::run;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub use unsupported::run;

/// Relay raw packets from a device reader out to `sink`, one device read
/// per write, logging each one as `"{role}: TUN -> TCP: N bytes"`.
///
/// TEMPORARY (since v0.3, unchanged here): each read becomes exactly one
/// `write_all` call. This is NOT a framing protocol -- TCP is a byte
/// stream, so the receiving side's `read()` calls are not guaranteed to
/// line up with these writes. Only `vpn-client`/`vpn-server` (the plain
/// TCP VPN mode) use this; `udp-client`/`udp-server` use v0.5's proper
/// framing instead. Generic over `PacketReader` and any `Write` sink, so
/// this has no platform-specific code despite living in the `tun` module
/// -- it's here because it's a TUN-adjacent relay helper, not because it
/// touches any OS-specific type.
pub fn relay_tun_to_writer<W: Write>(
    mut tun_reader: PacketReader,
    mut sink: W,
    role: &str,
) -> io::Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        let n = tun_reader.read_packet(&mut buf)?;
        if n == 0 {
            continue;
        }
        println!("{role}: TUN -> TCP: {n} bytes");
        sink.write_all(&buf[..n])?;
    }
}

/// Relay bytes read from `source` into a device writer, one read per
/// device write, logging each one as `"{role}: TCP -> TUN: N bytes"`.
///
/// Subject to the same TEMPORARY caveat as [`relay_tun_to_writer`].
pub fn relay_reader_to_tun<R: Read>(
    mut source: R,
    mut tun_writer: PacketWriter,
    role: &str,
) -> io::Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        let n = source.read(&mut buf)?;
        if n == 0 {
            // Peer closed the TCP connection.
            return Ok(());
        }
        println!("{role}: TCP -> TUN: {n} bytes");
        tun_writer.write_packet(&buf[..n])?;
    }
}