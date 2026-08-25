//! UDP transport (v0.4), extended with packet framing (v0.5) and AEAD
//! encryption (v0.6).
//!
//! Bridges a TUN device to a `std::net::UdpSocket`. Each raw IP packet
//! travels through three steps before it hits the wire, and the same
//! three steps in reverse on the way back in:
//!
//! ```text
//! TUN read -> Frame::data()+encode() -> Cipher::encrypt() -> UDP send
//! UDP recv -> Cipher::decrypt() -> Frame::decode() -> TUN write
//! ```
//!
//! One TUN read still becomes exactly one UDP datagram -- UDP's own
//! datagram boundary is what makes that reliable. Framing adds a small,
//! explicit, versioned header around the raw packet; encryption then
//! wraps the *entire* encoded frame (header included) in a
//! ChaCha20-Poly1305 AEAD envelope, so nothing about the frame -- not
//! even its type or declared length -- is visible on the wire. The TUN
//! side of this module still only ever sees raw, unframed, unencrypted IP
//! packets; only the UDP side is framed and encrypted.
//!
//! This module knows nothing about how the virtual network interface was
//! created (`src/tun/`; this module only ever names `tun::PacketReader`/
//! `tun::PacketWriter`, never a platform-specific type), nothing about
//! what's inside the IP packet (`protocol.rs` treats the payload as
//! opaque bytes), and nothing about how encryption actually works
//! (`crypto.rs` owns the cipher, nonce, and key handling entirely -- this
//! module just calls `encrypt`/`decrypt`). Encryption gives us
//! confidentiality and authenticity for what's on the wire; it does not
//! give us peer authentication, key exchange, or replay protection --
//! those remain later versions.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};

use crate::crypto::{self, Cipher, Direction};
use crate::protocol::{self, Frame};
use crate::tun::{PacketReader, PacketWriter};

/// Buffer size for one TUN read: large enough for a full-MTU IP packet
/// (see `protocol::MAX_PAYLOAD_SIZE`).
const TUN_READ_BUFFER_SIZE: usize = protocol::MAX_PAYLOAD_SIZE;

/// Buffer size for one UDP datagram: large enough for one fully encoded
/// frame, plus the encryption envelope's counter prefix and auth tag (see
/// `protocol::MAX_FRAME_SIZE`, `crypto::COUNTER_SIZE`, `crypto::TAG_SIZE`).
/// A well-behaved sender never produces anything bigger than this, so a
/// datagram never needs more.
const UDP_RECV_BUFFER_SIZE: usize = crypto::COUNTER_SIZE + protocol::MAX_FRAME_SIZE + crypto::TAG_SIZE;

/// Relay raw packets: TUN read -> frame -> encrypt -> `socket.send()`, one
/// TUN read per datagram, logging the size at each step so it's obvious
/// how framing and encryption each change the size on the wire.
///
/// Assumes `socket` already has a fixed peer (e.g. via `UdpSocket::connect`).
/// Encrypts as `direction` -- the direction this function's traffic is
/// travelling.
pub fn relay_tun_to_udp(
    mut tun_reader: PacketReader,
    socket: &UdpSocket,
    role: &str,
    cipher: &Cipher,
    direction: Direction,
) -> io::Result<()> {
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

        let envelope = cipher.encrypt(direction, &encoded);
        println!("{role}: FRAME -> ENCRYPT: {} bytes", encoded.len());
        println!("{role}: ENCRYPT -> UDP: {} bytes", envelope.len());
        socket.send(&envelope)?;
    }
}

/// Relay raw packets: `socket.recv()` -> decrypt -> decode frame -> TUN
/// write, one datagram per TUN write, logging the size at each step.
///
/// Assumes `socket` already has a fixed peer (e.g. via `UdpSocket::connect`).
/// Decrypts assuming the sender used `direction`.
pub fn relay_udp_to_tun(
    socket: &UdpSocket,
    mut tun_writer: PacketWriter,
    role: &str,
    cipher: &Cipher,
    direction: Direction,
) -> io::Result<()> {
    let mut buf = [0u8; UDP_RECV_BUFFER_SIZE];
    loop {
        let n = socket.recv(&mut buf)?;
        if n == 0 {
            continue;
        }

        println!("{role}: UDP -> DECRYPT: {n} bytes");
        let plaintext = match cipher.decrypt(direction, &buf[..n]) {
            Ok(plaintext) => plaintext,
            Err(e) => {
                // Never log the packet contents or key material here --
                // only that a packet was rejected, and why at a high
                // level (see crypto::CryptoError for what detail is and
                // isn't exposed).
                println!("{role}: dropped packet: {e}");
                continue;
            }
        };
        println!("{role}: DECRYPT -> FRAME: {} bytes", plaintext.len());

        let frame = match Frame::decode(&plaintext) {
            Ok(frame) => frame,
            Err(e) => {
                eprintln!("{role}: dropping malformed frame ({} bytes): {e}", plaintext.len());
                continue;
            }
        };
        println!("{role}: FRAME -> TUN: {} byte payload", frame.payload.len());
        tun_writer.write_all(&frame.payload)?;
    }
}

/// Relay raw packets: TUN read -> frame -> encrypt ->
/// `socket.send_to(known_peer)`, one TUN read per datagram, logging the
/// size at each step.
///
/// For use on the server, where the peer isn't known until a datagram has
/// been received at least once. If no peer is known yet, the packet is
/// dropped (logged), since there is nowhere to send it -- there is no
/// client table or queueing at v0.4/v0.5/v0.6. Encrypts as `direction`.
pub fn relay_tun_to_udp_to_peer(
    mut tun_reader: PacketReader,
    socket: &UdpSocket,
    role: &str,
    peer_addr: Arc<Mutex<Option<SocketAddr>>>,
    cipher: &Cipher,
    direction: Direction,
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

        let envelope = cipher.encrypt(direction, &encoded);
        println!("{role}: FRAME -> ENCRYPT: {} bytes", encoded.len());
        println!("{role}: ENCRYPT -> UDP: {} bytes", envelope.len());
        socket.send_to(&envelope, peer)?;
    }
}

/// Relay raw packets: `socket.recv_from()` -> decrypt -> decode frame ->
/// TUN write, one datagram per TUN write, logging the size at each step.
///
/// For use on the server: remembers only the single most recent sender
/// address in `peer_addr`, so `relay_tun_to_udp_to_peer` knows where to
/// send outbound packets. This is deliberately not a client table -- v0.4
/// supports exactly one client, and that hasn't changed. Decrypts
/// assuming the sender used `direction`.
///
/// A packet that fails authentication (wrong key, tampered ciphertext, or
/// tampered counter) is dropped and logged, and is NEVER written to the
/// TUN device and NEVER used to update the learned peer address --
/// forged/garbled UDP traffic cannot make the server treat an attacker as
/// the client.
pub fn relay_udp_to_tun_learn_peer(
    socket: &UdpSocket,
    mut tun_writer: PacketWriter,
    role: &str,
    peer_addr: Arc<Mutex<Option<SocketAddr>>>,
    cipher: &Cipher,
    direction: Direction,
) -> io::Result<()> {
    let mut buf = [0u8; UDP_RECV_BUFFER_SIZE];
    loop {
        let (n, sender) = socket.recv_from(&mut buf)?;
        if n == 0 {
            continue;
        }

        println!("{role}: UDP -> DECRYPT: {n} bytes");
        let plaintext = match cipher.decrypt(direction, &buf[..n]) {
            Ok(plaintext) => plaintext,
            Err(e) => {
                println!("{role}: dropped packet from {sender}: {e}");
                continue;
            }
        };
        println!("{role}: DECRYPT -> FRAME: {} bytes", plaintext.len());

        {
            let mut guard = peer_addr.lock().unwrap();
            if *guard != Some(sender) {
                println!("{role}: client address is now {sender}");
                *guard = Some(sender);
            }
        }

        let frame = match Frame::decode(&plaintext) {
            Ok(frame) => frame,
            Err(e) => {
                eprintln!("{role}: dropping malformed frame ({} bytes): {e}", plaintext.len());
                continue;
            }
        };
        println!("{role}: FRAME -> TUN: {} byte payload", frame.payload.len());
        tun_writer.write_all(&frame.payload)?;
    }
}