//! Linux virtual network interface backend (v0.2, split out as the Linux
//! backend in v0.6.5).
//!
//! This is the **only** file in the project that references the `tun`
//! crate (or any Linux-specific networking API). Everything it exposes to
//! `super` (`src/tun/mod.rs`) is either a type alias that already matches
//! the shape `mod.rs` expects (`Device`, `Reader`, `Writer`), or a plain
//! function (`create_raw_device`, `run`) -- `mod.rs` wraps the former and
//! re-exports the latter directly. No other file in the codebase imports
//! `tun::*` at all.

use std::io::{self, Read, Write};

/// The `tun` crate's device/reader/writer types already have exactly the
/// shape `super::PacketDevice`/`PacketReader`/`PacketWriter` want to wrap,
/// but since we want to expose explicit packet-based methods, we wrap them.
pub struct Device(tun::Device);
pub struct Reader(tun::Reader);
pub struct Writer(tun::Writer);

impl Device {
    pub fn split(self) -> (Reader, Writer) {
        let (reader, writer) = self.0.split();
        (Reader(reader), Writer(writer))
    }
}

impl Reader {
    pub fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::fd::AsRawFd;
        let fd = self.0.as_raw_fd();
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };

        let res = unsafe { libc::poll(&mut pfd, 1, 250) };
        if res < 0 {
            return Err(io::Error::last_os_error());
        } else if res == 0 {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "timeout"));
        } else if (pfd.revents & libc::POLLIN) == 0 {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "not ready"));
        }

        self.0.read(buf)
    }
}

impl Writer {
    pub fn write_packet(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.write_all(buf)
    }
}

/// Name requested for the standalone `tiny-vpn tun` (v0.2) test interface.
const TEST_TUN_NAME: &str = "tiny-tun0";
const TEST_TUN_ADDRESS: (u8, u8, u8, u8) = (10, 13, 13, 1);
const TEST_TUN_NETMASK: (u8, u8, u8, u8) = (255, 255, 255, 0);

/// Create and bring up a Linux TUN device with the given
/// name/address/netmask. Called by `super::create_device`, which wraps
/// the result in the platform-independent `PacketDevice`.
pub fn create_raw_device(
    name: &str,
    address: (u8, u8, u8, u8),
    netmask: (u8, u8, u8, u8),
) -> io::Result<Device> {
    let mut config = tun::Configuration::default();
    config.tun_name(name).address(address).netmask(netmask).up();

    config.platform_config(|platform_config| {
        // Creating/configuring a TUN device requires root or CAP_NET_ADMIN.
        platform_config.ensure_root_privileges(true);
    });

    tun::create(&config).map_err(to_tun_error).map_err(io::Error::from).map(Device)
}

/// Create a TUN interface and print info about every packet read from it.
///
/// Set the `TINY_VPN_TUN_ECHO=1` environment variable to also write each
/// packet straight back into the device, unmodified, as a simple way to
/// exercise the write-back path during manual testing (requirement 7 from
/// v0.2). This is a Linux-specific diagnostic tool, not something that
/// needs to be abstracted across platforms -- it exists to answer "is
/// this backend actually receiving raw IP packets", which is inherently
/// backend-specific.
pub fn run() -> io::Result<()> {
    let echo_back = std::env::var("TINY_VPN_TUN_ECHO").as_deref() == Ok("1");

    let dev = create_raw_device(TEST_TUN_NAME, TEST_TUN_ADDRESS, TEST_TUN_NETMASK)?;
    let (mut reader, mut writer) = dev.split();

    let (a, b, c, d) = TEST_TUN_ADDRESS;
    println!("TUN interface '{TEST_TUN_NAME}' is up at {a}.{b}.{c}.{d}/24");
    if echo_back {
        println!("Echo mode enabled: packets read will be written straight back to the device.");
    }
    println!("Reading packets. Press Ctrl+C to stop.\n");

    let mut buf = [0u8; 4096];
    loop {
        let n = reader.read_packet(&mut buf)?;
        print_packet(&buf[..n]);

        if echo_back {
            writer.write_packet(&buf[..n])?;
        }
    }
}

/// Print the length, a hex preview, and a best-effort IP version guess for
/// a raw packet. Deliberately not a real IP parser -- packets stay raw
/// and unparsed; real parsing is out of scope for this project so far.
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

fn to_tun_error(e: tun::Error) -> super::TunError {
    super::TunError(e.to_string())
}