use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

pub struct Device {
    fd: OwnedFd,
}

pub struct Reader {
    file: File,
}

pub struct Writer {
    file: File,
}

pub fn create_device_from_fd(fd: RawFd) -> Device {
    // Safety: Transfer of ownership is guaranteed by Kotlin Android FFI boundaries returning a detached fd.
    // The native Rust side now assumes complete responsibility for dropping this descriptor.
    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
    Device { fd: owned_fd }
}

impl Device {
    pub fn split(self) -> (Reader, Writer) {
        // dup() is used so that the read and write threads can effectively use isolated File streams.
        // Dropping both halves organically closes the original file descriptor.
        let file1 = File::from(self.fd);
        let file2 = file1.try_clone().expect("Failed to dup Android VPN descriptor");
        (Reader { file: file1 }, Writer { file: file2 })
    }
}

impl Reader {
    pub fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Writer {
    pub fn write_packet(&mut self, buf: &[u8]) -> io::Result<()> {
        self.file.write_all(buf)
    }
}

pub fn run() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Standalone tun test not implemented for Android",
    ))
}
