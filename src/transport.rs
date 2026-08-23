//! UDP transport (v0.4, extended with packet framing in v0.5).
//!
//! Bridges a TUN device to a `std::net::UdpSocket`, wrapping each raw IP
//! packet in a `protocol::Frame` before it goes out over UDP, and
//! unwrapping it back out on the way in:
//!
//! ```text
//! TUN read -> Frame::data() -> encode() -> UDP send
//! UDP recv -> decode() -> frame.payload -> TUN write
//! ```
//!
//! One TUN read still becomes exactly one UDP datagram -- UDP's own
//! datagram boundary is what makes that reliable. Framing adds a small,
//! explicit, versioned header around that payload so the wire format is
//! no longer "just whatever bytes the TUN device happened to produce".
//! The TUN side of this module still only ever sees raw, unframed IP
//! packets; only the UDP side is framed.
//!
//! This module knows nothing about how the TUN device was created
//! (`tun.rs`), and (via `protocol.rs`) nothing about what's inside the IP
//! packet -- the payload is opaque bytes. UDP gives us datagram
//! boundaries; framing gives us an explicit wire format. Neither gives us
//! reliability, ordering, encryption, or authentication -- those remain
//! later versions.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};

use crate::protocol::{self, Frame};

/// Buffer size for one TUN read: large enough for a full-MTU IP packet
/// (see `protocol::MAX_PAYLOAD_SIZE`).
const TUN_READ_BUFFER_SIZE: usize = protocol::MAX_PAYLOAD_SIZE;

/// Buffer size for one UDP datagram: large enough for one fully encoded
/// frame (see `protocol::MAX_FRAME_SIZE`). A well-behaved sender never
/// encodes a frame bigger than that, so a datagram never needs more.
const UDP_RECV_BUFFER_SIZE: usize = protocol::MAX_FRAME_SIZE;

/// Relay raw packets: TUN read -> frame -> `socket.send()`, one TUN read
/// per datagram, logging both the raw payload size and the encoded frame
/// size so it's obvious the two differ.
///
/// Assumes `socket` already has a fixed peer (e.g. via `UdpSocket::connect`).
pub fn relay_tun_to_udp(mut tun_reader: tun::Reader, socket: &UdpSocket, role: &str) -> io::Result<()> {
    let mut buf = [0u8; TUN_READ_BUFFER_SIZE];
    loop {
        let n = tun_reader.read(&mut buf)?;
        if n == 0 {
            continue;
        }

        let frame = match Frame::data(buf[..n].to_vec()) {
            Ok(frame) => frame,
            Err(e) => {
                eprintln!("{role}: dropping oversized TUN packet ({n} bytes): {e}");
                continue;
            }
        };
        let encoded = frame.encode();
        println!(
            "{role}: TUN -> FRAME: {n} byte payload, {} byte frame",
            encoded.len()
        );
        println!("{role}: FRAME -> UDP: {} bytes", encoded.len());
        socket.send(&encoded)?;
    }
}

/// Relay raw packets: `socket.recv()` -> decode frame -> TUN write, one
/// datagram per TUN write, logging both the datagram size and the
/// unwrapped payload size.
///
/// Assumes `socket` already has a fixed peer (e.g. via `UdpSocket::connect`).
pub fn relay_udp_to_tun(socket: &UdpSocket, mut tun_writer: tun::Writer, role: &str) -> io::Result<()> {
    let mut buf = [0u8; UDP_RECV_BUFFER_SIZE];
    loop {
        let n = socket.recv(&mut buf)?;
        if n == 0 {
            continue;
        }

        println!("{role}: UDP -> FRAME: {n} bytes");
        let frame = match Frame::decode(&buf[..n]) {
            Ok(frame) => frame,
            Err(e) => {
                eprintln!("{role}: dropping malformed frame ({n} bytes): {e}");
                continue;
            }
        };
        println!("{role}: FRAME -> TUN: {} byte payload", frame.payload.len());
        tun_writer.write_all(&frame.payload)?;
    }
}

/// Relay raw packets: TUN read -> frame -> `socket.send_to(known_peer)`,
/// one TUN read per datagram, logging both the raw payload size and the
/// encoded frame size.
///
/// For use on the server, where the peer isn't known until a datagram has
/// been received at least once. If no peer is known yet, the packet is
/// dropped (logged), since there is nowhere to send it -- there is no
/// client table or queueing at v0.4/v0.5.
pub fn relay_tun_to_udp_to_peer(
    mut tun_reader: tun::Reader,
    socket: &UdpSocket,
    role: &str,
    peer_addr: Arc<Mutex<Option<SocketAddr>>>,
) -> io::Result<()> {
    let mut buf = [0u8; TUN_READ_BUFFER_SIZE];
    loop {
        let n = tun_reader.read(&mut buf)?;
        if n == 0 {
            continue;
        }

        let peer = *peer_addr.lock().unwrap();
        let peer = match peer {
            Some(peer) => peer,
            None => {
                println!("{role}: TUN -> FRAME: dropped {n} bytes (no client known yet)");
                continue;
            }
        };

        let frame = match Frame::data(buf[..n].to_vec()) {
            Ok(frame) => frame,
            Err(e) => {
                eprintln!("{role}: dropping oversized TUN packet ({n} bytes): {e}");
                continue;
            }
        };
        let encoded = frame.encode();
        println!(
            "{role}: TUN -> FRAME: {n} byte payload, {} byte frame",
            encoded.len()
        );
        println!("{role}: FRAME -> UDP: {} bytes", encoded.len());
        socket.send_to(&encoded, peer)?;
    }
}

/// Relay raw packets: `socket.recv_from()` -> decode frame -> TUN write,
/// one datagram per TUN write, logging both the datagram size and the
/// unwrapped payload size.
///
/// For use on the server: remembers only the single most recent sender
/// address in `peer_addr`, so `relay_tun_to_udp_to_peer` knows where to
/// send outbound packets. This is deliberately not a client table -- v0.4
/// supports exactly one client, and v0.5 doesn't change that.
pub fn relay_udp_to_tun_learn_peer(
    socket: &UdpSocket,
    mut tun_writer: tun::Writer,
    role: &str,
    peer_addr: Arc<Mutex<Option<SocketAddr>>>,
) -> io::Result<()> {
    let mut buf = [0u8; UDP_RECV_BUFFER_SIZE];
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

        println!("{role}: UDP -> FRAME: {n} bytes");
        let frame = match Frame::decode(&buf[..n]) {
            Ok(frame) => frame,
            Err(e) => {
                eprintln!("{role}: dropping malformed frame ({n} bytes): {e}");
                continue;
            }
        };
        println!("{role}: FRAME -> TUN: {} byte payload", frame.payload.len());
        tun_writer.write_all(&frame.payload)?;
    }
}