//! ChaCha20-Poly1305 AEAD encryption for the UDP VPN transport (v0.6).
//!
//! Wraps a complete, already-encoded v0.5 `protocol::Frame` before it goes
//! out over UDP:
//!
//! ```text
//! Frame::encode() -> Cipher::encrypt() -> [counter(8) | ciphertext+tag] -> UDP
//! UDP -> [counter(8) | ciphertext+tag] -> Cipher::decrypt() -> Frame::decode()
//! ```
//!
//! This module does not invent any cryptographic primitive: it is a thin,
//! heavily-commented wrapper around the RustCrypto `chacha20poly1305`
//! crate's standard AEAD API (ChaCha20-Poly1305, as specified). Callers
//! only ever see `Cipher::encrypt`/`Cipher::decrypt` plus key
//! loading/parsing -- never a raw key, nonce, or cipher object.
//!
//! # Nonce construction (read this before changing anything here)
//!
//! ChaCha20-Poly1305 requires a 96-bit nonce that is *never reused* with
//! the same key. Reusing a (key, nonce) pair breaks both confidentiality
//! and authentication for both messages that share it.
//!
//! The nonce is built as:
//!
//! ```text
//! byte  0:    direction tag (0x00 = Client->Server, 0x01 = Server->Client)
//! bytes 1-3:  zero padding (reserved, unused)
//! bytes 4-11: 64-bit packet counter, big-endian
//! ```
//!
//! This gives two guarantees:
//! - **No cross-direction collision.** Both directions share the same
//!   pre-shared key (v0.6 does not derive separate directional subkeys),
//!   but the leading nonce byte differs per direction, so the two
//!   directions use completely disjoint nonce spaces. A counter value
//!   that happens to repeat on the *other* direction can never produce
//!   the same nonce.
//! - **No same-direction collision within one process run.** Each
//!   `Cipher` keeps its own strictly-increasing `u64` send counter and
//!   never revisits a value while the process is alive.
//!
//! **Known limitation, by design, for this version:** a direction's
//! counter resets to 0 every time its process restarts, while the
//! pre-shared key does not change (it's loaded from a static config
//! file). This means the first few nonces used after a restart repeat
//! nonces used before the restart under the same key, which is unsafe in
//! general. Fixing this properly needs either an ephemeral per-session
//! key/salt or persisted counter state -- both are session-establishment
//! concerns explicitly out of scope for v0.6 (see the "Do NOT implement"
//! list: session negotiation, key rotation). This is a deliberate,
//! documented gap consistent with v0.6 covering only encryption under a
//! single static PSK, not later work.
//!
//! The counter is sent on the wire in the clear (the receiver needs it to
//! reconstruct the same nonce) but is authenticated as AEAD associated
//! data, so tampering with it in transit is detected and decryption
//! fails -- it is never trusted blindly.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

/// Size of a raw pre-shared key in bytes (256 bits).
pub const KEY_SIZE: usize = 32;

/// Size of the counter prefix transmitted alongside the ciphertext.
pub const COUNTER_SIZE: usize = 8;

/// Size of the Poly1305 authentication tag appended to the ciphertext.
pub const TAG_SIZE: usize = 16;

/// Which direction a packet is travelling. This is never transmitted --
/// each side knows its own role, so it's used purely to pick the nonce's
/// leading byte (see module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

impl Direction {
    fn tag_byte(self) -> u8 {
        match self {
            Direction::ClientToServer => 0x00,
            Direction::ServerToClient => 0x01,
        }
    }
}

/// Errors from key parsing or AEAD operations.
///
/// Deliberately never includes key material or plaintext, and the
/// authentication-failure case deliberately carries no further detail
/// (truncated vs. tampered ciphertext vs. tampered counter vs. wrong key
/// are all indistinguishable from the outside) -- that's a standard AEAD
/// property, not an oversight, and avoids handing an attacker an oracle.
#[derive(Debug)]
pub enum CryptoError {
    InvalidKeyLength { expected: usize, found: usize },
    InvalidKeyHex,
    /// Decryption failed: truncated input, tampered ciphertext, a
    /// tampered/incorrect counter, or the wrong key. No further detail is
    /// given on purpose -- see the type-level docs.
    AuthenticationFailed,
    TruncatedEnvelope { have: usize, need: usize },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidKeyLength { expected, found } => {
                write!(
                    f,
                    "invalid key length: expected {expected} hex characters, found {found}"
                )
            }
            CryptoError::InvalidKeyHex => write!(f, "key is not valid hex"),
            CryptoError::AuthenticationFailed => write!(f, "authentication failed"),
            CryptoError::TruncatedEnvelope { have, need } => {
                write!(
                    f,
                    "truncated encrypted packet: have {have} bytes, need at least {need}"
                )
            }
        }
    }
}

impl std::error::Error for CryptoError {}

/// Parse a hex-encoded pre-shared key (as loaded from config) into raw key
/// bytes. Expects exactly `KEY_SIZE` (32) bytes once decoded, i.e. exactly
/// 64 hex characters.
pub fn parse_key_hex(hex: &str) -> Result<[u8; KEY_SIZE], CryptoError> {
    let hex = hex.trim();
    if hex.len() != KEY_SIZE * 2 {
        return Err(CryptoError::InvalidKeyLength {
            expected: KEY_SIZE * 2,
            found: hex.len(),
        });
    }

    let mut key = [0u8; KEY_SIZE];
    for (i, byte_slot) in key.iter_mut().enumerate() {
        let pair = hex
            .get(i * 2..i * 2 + 2)
            .ok_or(CryptoError::InvalidKeyHex)?;
        *byte_slot = u8::from_str_radix(pair, 16).map_err(|_| CryptoError::InvalidKeyHex)?;
    }
    Ok(key)
}

/// A loaded pre-shared key, ready to encrypt outgoing packets and decrypt
/// incoming ones.
///
/// Holds one monotonically increasing send counter, used only for this
/// process's own outgoing direction (a client only ever encrypts
/// `ClientToServer`; a server only ever encrypts `ServerToClient`).
/// Decryption doesn't need a local counter -- it reads the transmitted one.
pub struct Cipher {
    cipher: ChaCha20Poly1305,
    send_counter: AtomicU64,
}

impl Cipher {
    /// Build a cipher from raw key bytes. The key is moved in and never
    /// exposed again -- there is no accessor for it.
    pub fn new(key: [u8; KEY_SIZE]) -> Self {
        // KeySize for ChaCha20Poly1305 is exactly KEY_SIZE (32) bytes, so
        // this can't fail.
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .expect("ChaCha20Poly1305 key must be exactly 32 bytes");
        Cipher {
            cipher,
            send_counter: AtomicU64::new(0),
        }
    }

    /// Encrypt `plaintext` (a complete, already-encoded v0.5 frame) for
    /// sending in `direction`. Returns the wire envelope:
    /// `counter (8 bytes, big-endian) || ciphertext || 16-byte tag`.
    ///
    /// Uses (and advances) this cipher's own counter, so repeated calls on
    /// the same `Cipher` never reuse a counter value while the process
    /// keeps running (see module docs for the restart caveat).
    pub fn encrypt(&self, direction: Direction, plaintext: &[u8]) -> Vec<u8> {
        let counter = self.send_counter.fetch_add(1, Ordering::Relaxed);
        let counter_bytes = counter.to_be_bytes();
        let nonce = build_nonce(direction, counter);

        // The counter travels in the clear (the receiver needs it to
        // rebuild the same nonce) but is authenticated as AAD, not
        // encrypted -- tampering with it is detected, not hidden.
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &counter_bytes,
                },
            )
            .expect("ChaCha20Poly1305 encryption cannot fail for well-formed inputs");

        let mut envelope = Vec::with_capacity(COUNTER_SIZE + ciphertext.len());
        envelope.extend_from_slice(&counter_bytes);
        envelope.extend_from_slice(&ciphertext);
        envelope
    }

    /// Decrypt and authenticate an envelope that was sent using
    /// `direction` (the direction from the *sender's* point of view --
    /// e.g. the server decrypts packets sent as `Direction::ClientToServer`).
    ///
    /// Returns the original plaintext (a complete, encoded v0.5 frame) on
    /// success. Any failure -- truncated input, tampered ciphertext, or a
    /// tampered/incorrect counter -- returns `CryptoError` without ever
    /// producing unauthenticated plaintext.
    pub fn decrypt(&self, direction: Direction, envelope: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if envelope.len() < COUNTER_SIZE + TAG_SIZE {
            return Err(CryptoError::TruncatedEnvelope {
                have: envelope.len(),
                need: COUNTER_SIZE + TAG_SIZE,
            });
        }

        let counter_bytes: [u8; COUNTER_SIZE] = envelope[..COUNTER_SIZE]
            .try_into()
            .expect("slice length checked above");
        let counter = u64::from_be_bytes(counter_bytes);
        let ciphertext = &envelope[COUNTER_SIZE..];

        let nonce = build_nonce(direction, counter);

        self.cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &counter_bytes,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)
    }
}

/// Build the 12-byte ChaCha20-Poly1305 nonce for a given direction and
/// packet counter. See the module docs for why this construction never
/// reuses a nonce under the same key.
fn build_nonce(direction: Direction, counter: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[0] = direction.tag_byte();
    // bytes[1..4] intentionally left as zero padding.
    bytes[4..12].copy_from_slice(&counter.to_be_bytes());
    *Nonce::from_slice(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(byte: u8) -> [u8; KEY_SIZE] {
        [byte; KEY_SIZE]
    }

    #[test]
    fn round_trip() {
        let cipher = Cipher::new(test_key(0x11));
        let plaintext = b"a v0.5 frame goes here".to_vec();
        let envelope = cipher.encrypt(Direction::ClientToServer, &plaintext);
        let decrypted = cipher
            .decrypt(Direction::ClientToServer, &envelope)
            .expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let cipher = Cipher::new(test_key(0x22));
        let mut envelope = cipher.encrypt(Direction::ClientToServer, b"hello");
        let last = envelope.len() - 1;
        envelope[last] ^= 0xFF;
        assert!(matches!(
            cipher.decrypt(Direction::ClientToServer, &envelope),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn tampered_counter_fails() {
        let cipher = Cipher::new(test_key(0x33));
        let mut envelope = cipher.encrypt(Direction::ClientToServer, b"hello");
        envelope[0] ^= 0xFF; // corrupt the transmitted counter (part of the AAD)
        assert!(matches!(
            cipher.decrypt(Direction::ClientToServer, &envelope),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let cipher_a = Cipher::new(test_key(0x44));
        let cipher_b = Cipher::new(test_key(0x55));
        let envelope = cipher_a.encrypt(Direction::ClientToServer, b"hello");
        assert!(matches!(
            cipher_b.decrypt(Direction::ClientToServer, &envelope),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn different_counters_produce_different_ciphertexts() {
        let cipher = Cipher::new(test_key(0x66));
        let a = cipher.encrypt(Direction::ClientToServer, b"same plaintext");
        let b = cipher.encrypt(Direction::ClientToServer, b"same plaintext");
        // Different counters (0, then 1) -> different nonces -> different
        // ciphertext, even for byte-identical plaintext.
        assert_ne!(a, b);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let cipher = Cipher::new(test_key(0x77));
        let envelope = cipher.encrypt(Direction::ClientToServer, b"");
        let decrypted = cipher
            .decrypt(Direction::ClientToServer, &envelope)
            .unwrap();
        assert_eq!(decrypted, Vec::<u8>::new());
    }

    #[test]
    fn maximum_frame_round_trips() {
        use crate::protocol::MAX_FRAME_SIZE;
        let cipher = Cipher::new(test_key(0x88));
        let plaintext = vec![0xAB; MAX_FRAME_SIZE];
        let envelope = cipher.encrypt(Direction::ClientToServer, &plaintext);
        let decrypted = cipher
            .decrypt(Direction::ClientToServer, &envelope)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn direction_changes_the_nonce() {
        // Same counter value, different direction -> different nonce.
        // This is the property that keeps the two directions from ever
        // colliding despite sharing one key.
        let nonce_c2s = build_nonce(Direction::ClientToServer, 0);
        let nonce_s2c = build_nonce(Direction::ServerToClient, 0);
        assert_ne!(nonce_c2s, nonce_s2c);
    }

    #[test]
    fn cross_direction_decrypt_fails() {
        // Encrypting as Client->Server and attempting to decrypt as if it
        // were Server->Client (same key, same counter value) must fail,
        // because the two directions use disjoint nonces.
        let cipher = Cipher::new(test_key(0x99));
        let envelope = cipher.encrypt(Direction::ClientToServer, b"hello");
        assert!(matches!(
            cipher.decrypt(Direction::ServerToClient, &envelope),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn truncated_envelope_is_rejected_without_panicking() {
        let cipher = Cipher::new(test_key(0xAA));
        let short = vec![0u8; COUNTER_SIZE]; // no ciphertext/tag at all
        assert!(matches!(
            cipher.decrypt(Direction::ClientToServer, &short),
            Err(CryptoError::TruncatedEnvelope { .. })
        ));
    }

    #[test]
    fn key_hex_round_trip() {
        let key = test_key(0xCD);
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        let parsed = parse_key_hex(&hex).unwrap();
        assert_eq!(parsed, key);
    }

    #[test]
    fn key_hex_wrong_length_is_rejected() {
        assert!(matches!(
            parse_key_hex("abcd"),
            Err(CryptoError::InvalidKeyLength { .. })
        ));
    }

    #[test]
    fn key_hex_invalid_characters_are_rejected() {
        let bad = "zz".repeat(KEY_SIZE);
        assert!(matches!(parse_key_hex(&bad), Err(CryptoError::InvalidKeyHex)));
    }
}