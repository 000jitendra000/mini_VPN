//! TUN interface creation/configuration and packet I/O (v0.2, extended in v0.3).
//!
//! v0.2 added `run()`: a standalone TUN smoke test that creates one device
//! and prints every packet read from it.
//!
//! v0.3 adds `create_device()` plus `relay_tun_to_writer()` /
//! `relay_reader_to_tun()`: reusable building blocks that `client.rs` and
//! `server.rs` use to bridge a TUN device to a TCP connection. This module
//! stays transport-agnostic -- it knows how to talk to a TUN device, not
//! about TCP -- so the relay helpers are generic over `Read`/`Write`.

use std::io::{self, Read, Write};

/// Name requested for the standalone `tiny-vpn tun` (v0.2) test interface.
const TEST_TUN_NAME: &str = "tiny-tun0";
const TEST_TUN_ADDRESS: (u8, u8, u8, u8) = (10, 13, 13, 1);
const TEST_TUN_NETMASK: (u8, u8, u8, u8) = (255, 255, 255, 0);

/// Name/address for the v0.3 VPN client's TUN interface.
pub const CLIENT_TUN_NAME: &str = "tiny-tun-client";
pub const CLIENT_TUN_ADDRESS: (u8, u8, u8, u8) = (10, 13, 13, 1);

/// Name/address for the v0.3 VPN server's TUN interface.
pub const SERVER_TUN_NAME: &str = "tiny-tun-server";
pub const SERVER_TUN_ADDRESS: (u8, u8, u8, u8) = (10, 13, 13, 2);

/// Shared netmask for the v0.3 client/server test network.
pub const VPN_TUN_NETMASK: (u8, u8, u8, u8) = (255, 255, 255, 0);

/// Create and bring up a TUN device with the given name/address/netmask.
pub fn create_device(
    name: &str,
    address: (u8, u8, u8, u8),
    netmask: (u8, u8, u8, u8),
) -> io::Result<tun::Device> {
    let mut config = tun::Configuration::default();
    config.tun_name(name).address(address).netmask(netmask).up();

    #[cfg(target_os = "linux")]
    config.platform_config(|platform_config| {
        // Creating/configuring a TUN device requires root or CAP_NET_ADMIN.
        platform_config.ensure_root_privileges(true);
    });

    tun::create(&config).map_err(to_io_error)
}

/// Create a TUN interface and print info about every packet read from it.
///
/// Set the `TINY_VPN_TUN_ECHO=1` environment variable to also write each
/// packet straight back into the device, unmodified, as a simple way to
/// exercise the write-back path during manual testing (requirement 7).
pub fn run() -> io::Result<()> {
    let echo_back = std::env::var("TINY_VPN_TUN_ECHO").as_deref() == Ok("1");

    let mut dev = create_device(TEST_TUN_NAME, TEST_TUN_ADDRESS, TEST_TUN_NETMASK)?;

    let (a, b, c, d) = TEST_TUN_ADDRESS;
    println!("TUN interface '{TEST_TUN_NAME}' is up at {a}.{b}.{c}.{d}/24");
    if echo_back {
        println!("Echo mode enabled: packets read will be written straight back to the device.");
    }
    println!("Reading packets. Press Ctrl+C to stop.\n");

    let mut buf = [0u8; 4096];
    loop {
        let n = dev.read(&mut buf)?;
        print_packet(&buf[..n]);

        if echo_back {
            dev.write_all(&buf[..n])?;
        }
    }
}

/// Relay raw packets from a TUN reader out to `sink`, one TUN read per
/// write, logging each one as `"{role}: TUN -> TCP: N bytes"`.
///
/// TEMPORARY (v0.3): each TUN read becomes exactly one `write_all` call.
/// This is NOT a framing protocol -- TCP is a byte stream, so the receiving
/// side's `read()` calls are not guaranteed to line up with these writes
/// (they can be split or coalesced). This naive one-read-one-write approach
/// only *tends* to work for small, infrequent packets on an otherwise idle
/// loopback connection; proper message framing that fixes this arrives in
/// v0.5. Do not rely on this preserving packet boundaries.
pub fn relay_tun_to_writer<W: Write>(
    mut tun_reader: tun::Reader,
    mut sink: W,
    role: &str,
) -> io::Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        let n = tun_reader.read(&mut buf)?;
        if n == 0 {
            continue;
        }
        println!("{role}: TUN -> TCP: {n} bytes");
        sink.write_all(&buf[..n])?;
    }
}

/// Relay bytes read from `source` into a TUN writer, one read per TUN
/// write, logging each one as `"{role}: TCP -> TUN: N bytes"`.
///
/// Subject to the same TEMPORARY caveat as [`relay_tun_to_writer`]: a
/// `read()` here may not contain exactly one original packet.
pub fn relay_reader_to_tun<R: Read>(
    mut source: R,
    mut tun_writer: tun::Writer,
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
        tun_writer.write_all(&buf[..n])?;
    }
}

/// Print the length, a hex preview, and a best-effort IP version guess for
/// a raw packet. This is deliberately not a real IP parser -- packets stay
/// raw and unparsed through v0.3; real parsing is a later version.
fn print_packet(data: &[u8]) {
    println!("Received packet: {} bytes", data.len());

    let preview_len = data.len().min(32);
    let hex: Vec<String> = data[..preview_len]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    println!("  {}", hex.join(" "));

    if let Some(&first_byte) = data.first() {
        match first_byte >> 4 {
            4 => println!("  (IP version nibble indicates IPv4)"),
            6 => println!("  (IP version nibble indicates IPv6)"),
            other => println!("  (unrecognized IP version nibble: {other})"),
        }
    }
    println!();
}

fn to_io_error(e: tun::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}