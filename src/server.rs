//! TCP byte-tunnel server (v0.1) and VPN server (v0.3, extended in v0.4).
//!
//! `run()` is the original v0.1 mode: it accepts one client connection at
//! a time and relays raw bytes between the tunnel and the client itself,
//! since there's no second endpoint yet in v0.1.
//!
//! `run_vpn()` is v0.3: it accepts one client, creates a TUN interface,
//! and relays raw IP packets between the TUN device and a TCP connection,
//! in both directions, concurrently.
//!
//! `run_udp_vpn()` is new in v0.4: same idea, but over UDP. Since UDP is
//! connectionless, the server doesn't "accept" a client -- it just
//! remembers the address of whichever peer most recently sent it a
//! datagram, and sends replies there. No client table, no authentication.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::transport;
use crate::tun;

/// Bind to `address` and serve one client connection at a time, forever.
pub fn run(address: &str) -> io::Result<()> {
    let listener = TcpListener::bind(address)?;
    println!("Listening on {address}");

    loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                println!("Client connected: {peer}");
                if let Err(e) = handle_client(stream) {
                    eprintln!("Connection error ({peer}): {e}");
                }
                println!("Client disconnected: {peer}");
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {e}");
                // Keep the server alive; try to accept the next connection.
            }
        }
    }
}

/// Relay bytes read from `stream` back to the same `stream`.
fn handle_client(mut stream: TcpStream) -> io::Result<()> {
    let mut read_stream = stream.try_clone()?;
    let mut buf = [0u8; 4096];

    loop {
        let n = read_stream.read(&mut buf)?;
        if n == 0 {
            // Client closed the connection.
            return Ok(());
        }
        stream.write_all(&buf[..n])?;
    }
}

/// Listen on `address`, accept a single VPN client, create the server TUN
/// interface, and relay raw IP packets between the TUN device and the TCP
/// connection in both directions, concurrently.
///
/// See `tun::relay_tun_to_writer` / `tun::relay_reader_to_tun` for the
/// important caveat that v0.3 does not yet frame packets on the wire.
pub fn run_vpn(address: &str) -> io::Result<()> {
    let listener = TcpListener::bind(address)?;
    println!("VPN server listening on {address}");

    let (stream, peer) = listener.accept()?;
    println!("Client connected: {peer}");

    let tun_device = tun::create_device(
        tun::SERVER_TUN_NAME,
        tun::SERVER_TUN_ADDRESS,
        tun::VPN_TUN_NETMASK,
    )?;
    let (a, b, c, d) = tun::SERVER_TUN_ADDRESS;
    println!(
        "Server TUN '{}' is up at {a}.{b}.{c}.{d}/24",
        tun::SERVER_TUN_NAME
    );

    let (tun_reader, tun_writer) = tun_device.split();
    let tcp_upload = stream.try_clone()?;
    let tcp_download = stream;

    // Thread: TUN -> TCP (packets captured from the server's TUN device
    // are sent to the client).
    let upload_thread = thread::spawn(move || {
        tun::relay_tun_to_writer(tun_reader, tcp_upload, "Server")
    });

    // Main thread: TCP -> TUN (packets arriving from the client are
    // written into the server's TUN device).
    let download_result = tun::relay_reader_to_tun(tcp_download, tun_writer, "Server");

    match upload_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("Server TUN->TCP error: {e}"),
        Err(_) => eprintln!("Server TUN->TCP thread panicked"),
    }

    download_result
}

/// Bind a UDP socket on `bind_address`, create the server TUN interface,
/// and relay raw IP packets between the TUN device and the socket in both
/// directions, concurrently.
///
/// UDP is connectionless, so there's no "accept" step: the server just
/// remembers the address of whichever peer most recently sent it a
/// datagram (see `transport::relay_udp_to_tun_learn_peer`) and sends TUN
/// packets there. Only one client is supported.
pub fn run_udp_vpn(bind_address: &str) -> io::Result<()> {
    let socket = UdpSocket::bind(bind_address)?;
    println!("VPN UDP server listening on {bind_address}");

    let tun_device = tun::create_device(
        tun::SERVER_TUN_NAME,
        tun::SERVER_TUN_ADDRESS,
        tun::VPN_TUN_NETMASK,
    )?;
    let (a, b, c, d) = tun::SERVER_TUN_ADDRESS;
    println!(
        "Server TUN '{}' is up at {a}.{b}.{c}.{d}/24",
        tun::SERVER_TUN_NAME
    );

    let (tun_reader, tun_writer) = tun_device.split();
    let download_socket = socket.try_clone()?;

    // Shared with both threads: the most recent client address seen. None
    // until the client's first datagram arrives.
    let peer_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let upload_peer_addr = Arc::clone(&peer_addr);

    // Thread: TUN -> UDP (packets captured from the server's TUN device
    // are sent to whichever client address is currently known).
    let upload_thread = thread::spawn(move || {
        transport::relay_tun_to_udp_to_peer(tun_reader, &socket, "Server", upload_peer_addr)
    });

    // Main thread: UDP -> TUN (datagrams arriving from the client are
    // written into the server's TUN device; this also learns/updates the
    // client's address for the upload thread to use).
    let download_result =
        transport::relay_udp_to_tun_learn_peer(&download_socket, tun_writer, "Server", peer_addr);

    match upload_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("Server TUN->UDP error: {e}"),
        Err(_) => eprintln!("Server TUN->UDP thread panicked"),
    }

    download_result
}