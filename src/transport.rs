//! UDP transport (v0.4).
//!
//! Bridges a TUN device to a `std::net::UdpSocket`. Unlike the v0.3 TCP
//! relay, UDP already preserves datagram boundaries: one TUN read becomes
//! exactly one `send`/`send_to` call, and one `recv`/`recv_from` call
//! yields exactly one TUN write. No framing, headers, sequence numbers, or
//! acknowledgements are added -- the UDP payload IS the raw IP packet.
//!
//! This module intentionally knows nothing about how the TUN device was
//! created (that stays in `tun.rs`); it only relays between a TUN
//! reader/writer and a socket.
//!
//! Two relay styles are provided:
//! - "connected" (`relay_tun_to_udp` / `relay_udp_to_tun`): for a socket
//!   that already has a fixed peer, e.g. the client, which knows the
//!   server's address up front and can call `UdpSocket::connect()`.
//! - "dynamic peer" (`relay_tun_to_udp_to_peer` / `relay_udp_to_tun_learn_peer`):
//!   for the server, which doesn't know the client's address until the
//!   first datagram arrives. The server remembers only the single most
//!   recent sender -- there is no client table, ID, or authentication.
//!
//! UDP gives us datagram boundaries and nothing else: no reliability,
//! ordering, encryption, or authentication. Those remain later versions.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};

/// Maximum UDP payload this module will send/receive in one call.
///
/// Assumption: the TUN devices in this project use the `tun` crate's
/// default MTU of 1500 bytes (see `tun::DEFAULT_MTU`). This buffer is sized
/// comfortably above that so a full-MTU IP packet always fits in one
/// `recv`/`recv_from` without truncation. Packets that somehow exceed this
/// buffer are not fragmented or reassembled at v0.4 -- that's out of scope.
const MAX_PACKET_SIZE: usize = 2048;

/// Relay raw packets: TUN read -> `socket.send()`, one TUN read per
/// datagram, logging each as `"{role}: TUN -> UDP: N bytes"`.
///
/// Assumes `socket` already has a fixed peer (e.g. via `UdpSocket::connect`).
pub fn relay_tun_to_udp(mut tun_reader: tun::Reader, socket: &UdpSocket, role: &str) -> io::Result<()> {
    let mut buf = [0u8; MAX_PACKET_SIZE];
    loop {
        let n = tun_reader.read(&mut buf)?;
        if n == 0 {
            continue;
        }
        println!("{role}: TUN -> UDP: {n} bytes");
        socket.send(&buf[..n])?;
    }
}

/// Relay raw packets: `socket.recv()` -> TUN write, one datagram per TUN
/// write, logging each as `"{role}: UDP -> TUN: N bytes"`.
///
/// Assumes `socket` already has a fixed peer (e.g. via `UdpSocket::connect`).
pub fn relay_udp_to_tun(socket: &UdpSocket, mut tun_writer: tun::Writer, role: &str) -> io::Result<()> {
    let mut buf = [0u8; MAX_PACKET_SIZE];
    loop {
        let n = socket.recv(&mut buf)?;
        if n == 0 {
            continue;
        }
        println!("{role}: UDP -> TUN: {n} bytes");
        tun_writer.write_all(&buf[..n])?;
    }
}

/// Relay raw packets: TUN read -> `socket.send_to(known_peer)`, one TUN
/// read per datagram, logging each as `"{role}: TUN -> UDP: N bytes"`.
///
/// For use on the server, where the peer isn't known until a datagram has
/// been received at least once. If no peer is known yet, the packet is
/// dropped (logged), since there is nowhere to send it -- there is no
/// client table or queueing at v0.4.
pub fn relay_tun_to_udp_to_peer(
    mut tun_reader: tun::Reader,
    socket: &UdpSocket,
    role: &str,
    peer_addr: Arc<Mutex<Option<SocketAddr>>>,
) -> io::Result<()> {
    let mut buf = [0u8; MAX_PACKET_SIZE];
    loop {
        let n = tun_reader.read(&mut buf)?;
        if n == 0 {
            continue;
        }

        let peer = *peer_addr.lock().unwrap();
        match peer {
            Some(peer) => {
                println!("{role}: TUN -> UDP: {n} bytes");
                socket.send_to(&buf[..n], peer)?;
            }
            None => {
                println!("{role}: TUN -> UDP: dropped {n} bytes (no client known yet)");
            }
        }
    }
}

/// Relay raw packets: `socket.recv_from()` -> TUN write, one datagram per
/// TUN write, logging each as `"{role}: UDP -> TUN: N bytes"`.
///
/// For use on the server: remembers only the single most recent sender
/// address in `peer_addr`, so `relay_tun_to_udp_to_peer` knows where to
/// send outbound packets. This is deliberately not a client table -- v0.4
/// supports exactly one client.
pub fn relay_udp_to_tun_learn_peer(
    socket: &UdpSocket,
    mut tun_writer: tun::Writer,
    role: &str,
    peer_addr: Arc<Mutex<Option<SocketAddr>>>,
) -> io::Result<()> {
    let mut buf = [0u8; MAX_PACKET_SIZE];
    loop {
        let (n, sender) = socket.recv_from(&mut buf)?;
        if n == 0 {
            continue;
        }

        {
            let mut guard = peer_addr.lock().unwrap();
            if *guard != Some(sender) {
                println!("{role}: client address is now {sender}");
                *guard = Some(sender);
            }
        }

        println!("{role}: UDP -> TUN: {n} bytes");
        tun_writer.write_all(&buf[..n])?;
    }
}