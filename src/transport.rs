//! UDP transport (v0.4), extended with packet framing (v0.5), AEAD
//! encryption (v0.6), and handshake-derived session encryption (v0.7).
//!
//! Bridges a TUN device to a `std::net::UdpSocket`. Each raw IP packet
//! travels through three steps before it hits the wire, and the same
//! three steps in reverse on the way back in:
//!
//! ```text
//! TUN read -> Frame::data()+encode() -> Cipher::encrypt() -> wrap as EncryptedData -> UDP send
//! UDP recv -> unwrap EncryptedData -> Cipher::decrypt() -> Frame::decode() -> TUN write
//! ```
//!
//! One TUN read still becomes exactly one UDP datagram -- UDP's own
//! datagram boundary is what makes that reliable. Framing adds a small,
//! explicit, versioned header around the raw packet; encryption then
//! wraps the *entire* encoded frame (header included) in a
//! ChaCha20-Poly1305 AEAD envelope, so nothing about the frame -- not
//! even its type or declared length -- is visible on the wire. As of
//! v0.7, that envelope is itself wrapped in one more byte (see
//! `protocol::encode_encrypted_data`) so a receiver can tell encrypted
//! VPN data apart from handshake traffic on the same socket. The TUN side
//! of this module still only ever sees raw, unframed, unencrypted IP
//! packets; only the UDP side is framed, encrypted, and tagged.
//!
//! **What moved to v0.7 and what didn't:** the functions here now only
//! handle the *established-session data path* -- encrypting/decrypting
//! with a per-session `Cipher` and a shared "is there a session yet"
//! cell. The v0.7 handshake state machine itself (who's allowed to
//! establish a session, when, and how) is NOT here: the server's
//! handshake responder logic lives in `server.rs` (see
//! `server::handle_incoming_datagram`), and the client's handshake
//! sequence lives in `client.rs` (see `client::perform_handshake`), per
//! this project's file responsibilities. This module deliberately does no
//! cryptographic work of its own -- it only calls `crypto::Cipher::
//! encrypt`/`decrypt` and `protocol::Frame`/`UdpMessage` encode/decode.
//!
//! This module still knows nothing about how the virtual network
//! interface was created (`src/tun/`; only `tun::PacketReader`/
//! `PacketWriter` are named here, never a platform-specific type), and
//! nothing about what's inside the IP packet (`protocol.rs` treats the
//! payload as opaque bytes). Session encryption gives us confidentiality,
//! authenticity, and (via fresh per-session keys) safety against the v0.6
//! restart/nonce-reuse problem; it does not give us replay protection
//! against messages replayed *within* a session, multi-client support, or
//! forward secrecy beyond one session's lifetime -- see `crypto.rs` and
//! the v0.7 final report for exactly what is and isn't guaranteed.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};

use crate::crypto::{self, Cipher, Direction};
use crate::protocol::{self, Frame};
use crate::tun::{PacketReader, PacketWriter};

/// Buffer size for one TUN read: large enough for a full-MTU IP packet
/// (see `protocol::MAX_PAYLOAD_SIZE`).
const TUN_READ_BUFFER_SIZE: usize = protocol::MAX_PAYLOAD_SIZE;

/// Buffer size for one UDP datagram: large enough for the largest possible
/// `EncryptedData` message -- one leading message-type byte, plus one
/// fully encoded frame, plus the encryption envelope's counter prefix and
/// auth tag (see `protocol::MAX_FRAME_SIZE`, `crypto::COUNTER_SIZE`,
/// `crypto::TAG_SIZE`). Handshake messages are much smaller than this, so
/// the same buffer covers both. A well-behaved sender never produces
/// anything bigger than this, so a datagram never needs more.
pub const UDP_RECV_BUFFER_SIZE: usize =
    1 + crypto::COUNTER_SIZE + protocol::MAX_FRAME_SIZE + crypto::TAG_SIZE;

/// The server's currently-established (peer address, send cipher), shared
/// between its receive loop (which learns/updates this once a handshake
/// completes) and its TUN-reading upload thread (which polls it before
/// every send). `None` means "no established session yet" -- see
/// `relay_tun_to_udp_established`.
pub type EstablishedPeer = Option<(SocketAddr, Arc<Cipher>)>;

/// Relay raw packets over an established v0.7 session, for the CLIENT:
/// TUN read -> frame -> encrypt -> wrap as `EncryptedData` ->
/// `socket.send()`. One TUN read per datagram, logging the size at each
/// step.
///
/// The client only ever calls this after `client::perform_handshake` has
/// already completed, so `cipher` and the connected `socket` are fixed
/// for the rest of the process's life -- there's no "session not
/// established yet" case to handle here (contrast with the server's
/// `relay_tun_to_udp_established`, which starts before any session
/// exists).
pub fn relay_tun_to_udp_session(
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
        let datagram = protocol::encode_encrypted_data(&envelope);
        println!("{role}: ENCRYPT -> UDP: {} bytes", datagram.len());
        socket.send(&datagram)?;
    }
}

/// Relay raw packets over an established v0.7 session, for the CLIENT:
/// `socket.recv()` -> unwrap `EncryptedData` -> decrypt -> decode frame ->
/// TUN write. One datagram per TUN write, logging the size at each step.
///
/// By the time this runs, the client has already completed its handshake,
/// so any *handshake* message that arrives here is unexpected (e.g. a
/// retransmitted `HandshakeResponse` after the client already moved on).
/// It's logged and dropped, not treated as a hard error.
pub fn relay_udp_to_tun_session(
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
        let message = match protocol::UdpMessage::decode(&buf[..n]) {
            Ok(message) => message,
            Err(e) => {
                eprintln!("{role}: dropping malformed datagram ({n} bytes): {e}");
                continue;
            }
        };
        let body = match message {
            protocol::UdpMessage::EncryptedData(body) => body,
            protocol::UdpMessage::Handshake(_) => {
                println!("{role}: dropping unexpected handshake message after session establishment");
                continue;
            }
        };

        let plaintext = match cipher.decrypt(direction, body) {
            Ok(plaintext) => plaintext,
            Err(e) => {
                // Never log packet contents or key material -- only that
                // a packet was rejected, and why at a high level (see
                // crypto::CryptoError for what detail is/isn't exposed).
                println!("{role}: dropped packet: {e}");
                continue;
            }
        };
        println!("{role}: DECRYPT -> FRAME: {} bytes", plaintext.len());

        let frame = match Frame::decode(&plaintext) {
            Ok(frame) => frame,
            Err(e) => {
                eprintln!(
                    "{role}: dropping malformed frame ({} bytes): {e}",
                    plaintext.len()
                );
                continue;
            }
        };
        println!("{role}: FRAME -> TUN: {} byte payload", frame.payload.len());
        tun_writer.write_all(&frame.payload)?;
    }
}

/// Relay raw packets over an established v0.7 session, for the SERVER:
/// TUN read -> frame -> encrypt -> wrap as `EncryptedData` ->
/// `socket.send_to(established_peer)`.
///
/// Unlike the client's `relay_tun_to_udp_session`, the server starts this
/// loop before any session exists, so `established` (shared with the
/// server's receive loop -- see `server::run_udp_vpn`) is checked fresh
/// before every send. If no session is established yet, the packet is
/// dropped and logged, matching the v0.4-v0.6 "no client known yet"
/// behavior, now generalized to "no *authenticated* session yet".
pub fn relay_tun_to_udp_established(
    mut tun_reader: PacketReader,
    socket: &UdpSocket,
    role: &str,
    established: Arc<Mutex<EstablishedPeer>>,
    direction: Direction,
) -> io::Result<()> {
    let mut buf = [0u8; TUN_READ_BUFFER_SIZE];
    loop {
        let n = tun_reader.read(&mut buf)?;
        if n == 0 {
            continue;
        }

        let current = established.lock().unwrap().clone();
        let (peer, cipher) = match current {
            Some((peer, cipher)) => (peer, cipher),
            None => {
                println!("{role}: TUN -> FRAME: dropped {n} bytes (no established session yet)");
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
        let datagram = protocol::encode_encrypted_data(&envelope);
        println!("{role}: ENCRYPT -> UDP: {} bytes", datagram.len());
        socket.send_to(&datagram, peer)?;
    }
}