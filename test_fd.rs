use std::os::unix::io::AsRawFd;
fn check(reader: &tun::Reader) -> std::os::unix::io::RawFd {
    reader.as_raw_fd()
}
