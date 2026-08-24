//! TCP byte-tunnel client (v0.1) and VPN client (v0.3, extended in v0.4
//! with UDP transport and in v0.6 with encryption).
//!
//! `run()` is the original v0.1 mode: it relays stdin -> socket and
//! socket -> stdout, so the raw byte tunnel can be exercised interactively
//! or with piped input.
//!
//! `run_vpn()` is v0.3: it creates a TUN interface, connects to a VPN
//! server over TCP, and relays raw IP packets between the two, in both
//! directions, concurrently.
//!
//! `run_udp_vpn()` is v0.4/v0.6: same idea as `run_vpn()`, but the
//! transport is a UDP socket instead of a TCP stream, and (as of v0.6)
//! every datagram is ChaCha20-Poly1305 encrypted using a pre-shared key
//! loaded from a config file.

use std::io::{self, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::Arc;
use std::thread;

use crate::config;
use crate::crypto::{self, Cipher, Direction};
use crate::transport;
use crate::tun;

/// Load the pre-shared key from `config_path` and build a `Cipher` from
/// it. Wraps config/key errors as `io::Error` so callers can use `?`
/// alongside the rest of this module's I/O.
fn load_cipher(config_path: &str) -> io::Result<Cipher> {
    let key_hex = config::load_crypto_key_hex(config_path)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let key = crypto::parse_key_hex(&key_hex)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    Ok(Cipher::new(key))
}

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

/// Create the client TUN interface, load the pre-shared key from
/// `config_path`, bind a UDP socket, connect it to the server's UDP
/// address, and relay raw IP packets between the TUN device and the
/// socket in both directions, concurrently.
///
/// Every datagram sent is a ChaCha20-Poly1305-encrypted, framed IP packet
/// (see `transport.rs` and `crypto.rs`); every datagram received is
/// decrypted and authenticated before its payload is written to the TUN
/// device. A packet that fails authentication (wrong key on one side,
/// tampering, or corruption) is dropped and logged -- never written to
/// TUN, and never treated as valid data.
pub fn run_udp_vpn(server_address: &str, config_path: &str) -> io::Result<()> {
    let cipher = Arc::new(load_cipher(config_path)?);

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

    // Bind to an OS-assigned local port; we only ever talk to one server.
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(server_address)?;
    println!(
        "UDP socket bound to {} and connected to server at {server_address}",
        socket.local_addr()?
    );

    let (tun_reader, tun_writer) = tun_device.split();
    let upload_socket = socket.try_clone()?;
    let upload_cipher = Arc::clone(&cipher);

    // Thread: TUN -> UDP (packets captured from the local TUN device are
    // framed, encrypted as Client->Server, and sent to the server).
    let upload_thread = thread::spawn(move || {
        transport::relay_tun_to_udp(
            tun_reader,
            &upload_socket,
            "Client",
            &upload_cipher,
            Direction::ClientToServer,
        )
    });

    // Main thread: UDP -> TUN (datagrams arriving from the server are
    // decrypted as Server->Client, authenticated, and written into the
    // local TUN device).
    let download_result = transport::relay_udp_to_tun(
        &socket,
        tun_writer,
        "Client",
        &cipher,
        Direction::ServerToClient,
    );

    match upload_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("Client TUN->UDP error: {e}"),
        Err(_) => eprintln!("Client TUN->UDP thread panicked"),
    }

    download_result
}