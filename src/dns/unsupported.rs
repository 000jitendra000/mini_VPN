use std::io;

pub struct Guard;

pub fn apply(_config: &super::DnsConfig, _tun_interface: &str) -> io::Result<Guard> {
    eprintln!("DNS: configuration is completely unsupported for this target OS in this milestone. Returning explicitly unsupported error without applying configuration modifications.");
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "DNS configuration is not supported on this platform.",
    ))
}
