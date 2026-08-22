//! TUN interface experimentation (v0.2).
//!
//! Creates a TUN device, brings it up with a test IPv4 address, and reads
//! raw IP packets from it, printing enough information about each packet
//! to verify that real IP traffic from the kernel is reaching this Rust
//! program.
//!
//! This module intentionally does NOT parse IP packets, forward them
//! anywhere, or connect to the v0.1 TCP tunnel -- that wiring is v0.3+.

use std::io::{self, Read, Write};

/// Name requested for the TUN interface. The kernel may adjust it.
const TUN_NAME: &str = "tiny-tun0";
/// Address assigned to the TUN interface for this test.
const TUN_ADDRESS: (u8, u8, u8, u8) = (10, 13, 13, 1);
const TUN_NETMASK: (u8, u8, u8, u8) = (255, 255, 255, 0);

/// Create a TUN interface and print info about every packet read from it.
///
/// Set the `TINY_VPN_TUN_ECHO=1` environment variable to also write each
/// packet straight back into the device, unmodified, as a simple way to
/// exercise the write-back path during manual testing (requirement 7).
pub fn run() -> io::Result<()> {
    let echo_back = std::env::var("TINY_VPN_TUN_ECHO").as_deref() == Ok("1");

    let mut config = tun::Configuration::default();
    config
        .tun_name(TUN_NAME)
        .address(TUN_ADDRESS)
        .netmask(TUN_NETMASK)
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|platform_config| {
        // Creating/configuring a TUN device requires root or CAP_NET_ADMIN.
        platform_config.ensure_root_privileges(true);
    });

    let mut dev = tun::create(&config).map_err(to_io_error)?;

    let (a, b, c, d) = TUN_ADDRESS;
    println!("TUN interface '{TUN_NAME}' is up at {a}.{b}.{c}.{d}/24");
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

/// Print the length, a hex preview, and a best-effort IP version guess for
/// a raw packet. This is deliberately not a real IP parser (that's v0.3).
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