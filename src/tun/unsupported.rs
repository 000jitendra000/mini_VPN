//! Unsupported platform fallback.
//!
//! Provides the required type shapes for `PacketDevice`, `PacketReader`, and
//! `PacketWriter` so the cross-platform VPN core can compile cleanly on targets
//! without a configured backend, failing only at runtime if this functionality
//! is actually invoked (e.g. `create_raw_device`).

use std::io;

pub struct Device;
pub struct Reader;
pub struct Writer;

impl Device {
    pub fn split(self) -> (Reader, Writer) {
        unreachable!("virtual network interface backend not implemented for this platform")
    }
}

impl Reader {
    pub fn read_packet(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "virtual network interface backend not implemented for this platform"))
    }
}

impl Writer {
    pub fn write_packet(&mut self, _buf: &[u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "virtual network interface backend not implemented for this platform"))
    }
}

pub fn create_raw_device(
    _name: &str,
    _address: (u8, u8, u8, u8),
    _netmask: (u8, u8, u8, u8),
) -> io::Result<Device> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "virtual network interface backend not implemented for this platform"))
}

pub fn run() -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "virtual network interface backend not implemented for this platform"))
}
