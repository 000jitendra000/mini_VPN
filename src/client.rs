//! TCP byte-tunnel client (v0.1) and VPN client (v0.3).
//!
//! `run()` is the original v0.1 mode: it relays stdin -> socket and
//! socket -> stdout, so the raw byte tunnel can be exercised interactively
//! or with piped input.
//!
//! `run_vpn()` is new in v0.3: it creates a TUN interface, connects to a
//! VPN server, and relays raw IP packets between the two, in both
//! directions, concurrently.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::thread;

use crate::tun;

/// Connect to `address` and relay bytes between stdio and the connection.
pub fn run(address: &str) -> io::Result<()> {
    let stream = TcpStream::connect(address)?;
    println!("Connected to {address}");

    let mut writer = stream.try_clone()?;
    let mut reader = stream;

    // Thread 1: read from stdin, write to the TCP connection.
    let stdin_thread = thread::spawn(move || -> io::Result<()> {
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        let mut buf = [0u8; 4096];
        loop {
            let n = handle.read(&mut buf)?;
            if n == 0 {
                // stdin closed (e.g. EOF from a pipe). Stop sending.
                return Ok(());
            }
            writer.write_all(&buf[..n])?;
        }
    });

    // Thread 2 (main thread): read from the TCP connection, write to stdout.
    let stdout_result: io::Result<()> = (|| {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        let mut buf = [0u8; 4096];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                // Server closed the connection.
                return Ok(());
            }
            handle.write_all(&buf[..n])?;
            handle.flush()?;
        }
    })();

    // Don't propagate a stdin-thread panic as a hard error; just report it.
    match stdin_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("stdin/send error: {e}"),
        Err(_) => eprintln!("stdin thread panicked"),
    }

    stdout_result
}

/// Create the client TUN interface, connect to `address`, and relay raw IP
/// packets between the TUN device and the TCP connection in both
/// directions, concurrently.
///
/// See `tun::relay_tun_to_writer` / `tun::relay_reader_to_tun` for the
/// important caveat that v0.3 does not yet frame packets on the wire.
pub fn run_vpn(address: &str) -> io::Result<()> {
    let tun_device = tun::create_device(
        tun::CLIENT_TUN_NAME,
        tun::CLIENT_TUN_ADDRESS,
        tun::VPN_TUN_NETMASK,
    )?;
    let (a, b, c, d) = tun::CLIENT_TUN_ADDRESS;
    println!(
        "Client TUN '{}' is up at {a}.{b}.{c}.{d}/24",
        tun::CLIENT_TUN_NAME
    );

    let stream = TcpStream::connect(address)?;
    println!("Connected to server at {address}");

    let (tun_reader, tun_writer) = tun_device.split();
    let tcp_upload = stream.try_clone()?;
    let tcp_download = stream;

    // Thread: TUN -> TCP (packets captured from the local TUN device are
    // sent to the server).
    let upload_thread = thread::spawn(move || {
        tun::relay_tun_to_writer(tun_reader, tcp_upload, "Client")
    });

    // Main thread: TCP -> TUN (packets arriving from the server are
    // written into the local TUN device).
    let download_result = tun::relay_reader_to_tun(tcp_download, tun_writer, "Client");

    match upload_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("Client TUN->TCP error: {e}"),
        Err(_) => eprintln!("Client TUN->TCP thread panicked"),
    }

    download_result
}