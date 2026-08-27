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
//!
//! # v0.7 addendum: session keys replace direct PSK use
//!
//! Everything above this point is the unmodified v0.6 `Cipher`. As of
//! v0.7, `Cipher::new` is no longer ever called with the raw pre-shared
//! key directly -- it's called with a *session key* produced by
//! [`derive_session_ciphers`] after a successful handshake. Each new
//! session derives fresh, independent `client_to_server`/
//! `server_to_client` keys from `(PSK, client_random, server_random)` via
//! HKDF-SHA256, so a freshly-restarted process gets a **different** key
//! for the same PSK, which is what actually fixes the v0.6 restart/nonce-
//! reuse problem documented above -- not a change to the nonce
//! construction itself (which is unchanged and still correct on its own
//! terms). A `Cipher`'s counter is still allowed to start at 0 for a new
//! session precisely because it now pairs with a key that has never been
//! used before.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

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

impl std::fmt::Debug for Cipher {
    /// Deliberately prints nothing about the key or counter state --
    /// this exists only so `Cipher`/`Arc<Cipher>` can appear inside
    /// `#[derive(Debug)]` types elsewhere (e.g. `server::ServerAction`)
    /// without ever risking exposing secret material through a derived
    /// or manual `{:?}` format.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cipher").finish_non_exhaustive()
    }
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

// ============================================================================
// v0.7: handshake authentication and session key derivation.
//
// Everything below is new. It does not change `Cipher`, `Direction`,
// `build_nonce`, or the v0.6 envelope format above -- it only adds what's
// needed to (a) authenticate a handshake using the PSK, and (b) derive
// fresh session keys from the PSK plus both sides' handshake randomness,
// so a restarted process gets a new key instead of reusing the old one
// under the same key (see the module-level "v0.7 addendum" docs above).
//
// # Construction
//
// Both the handshake authentication tags and the session keys are
// produced by the same primitive: HKDF-SHA256 (RustCrypto `hkdf` crate),
// keyed by the PSK, with domain separation via the `info` parameter:
//
// ```text
// PRK = HKDF-Extract(salt = None, ikm = PSK)      [Hkdf::new(None, psk)]
//
// handshake tag  = HKDF-Expand(PRK, info = "tiny-vpn-v0.7" || message_type
//                                          || version || client_random
//                                          || server_random,           32 bytes)
//
// session key    = HKDF-Expand(PRK, info = "tiny-vpn-v0.7-session-"    32 bytes)
//                                          || direction_label
//                                          || client_random || server_random,
// ```
//
// Using HKDF-Expand output as an authentication tag (recompute and
// compare) rather than a general-purpose MAC avoids adding a second
// primitive (e.g. a separate `hmac` crate) beyond the one KDF the spec
// asks for: HKDF-Expand is a PRF keyed by the PSK-derived PRK, so nobody
// without the PSK can predict its output for a given `info`, which is
// exactly the property an authentication tag needs.
//
// `message_type` and `version` are included in every handshake tag's
// `info` so a tag computed for one message type/version can never be
// replayed as valid for another. `client_random`/`server_random` bind
// the tag to this specific handshake attempt.
// ============================================================================

/// Size of the random value each side contributes to a handshake.
pub const RANDOM_SIZE: usize = 32;

/// Size of a handshake authentication tag (an HKDF-Expand output).
pub const HANDSHAKE_TAG_SIZE: usize = 32;

const HKDF_CONTEXT_PREFIX: &[u8] = b"tiny-vpn-v0.7";

/// Generate a fresh, cryptographically secure random value for use as a
/// handshake's `client_random`/`server_random`. Backed by the OS CSPRNG
/// (`OsRng`, via `chacha20poly1305`'s existing `getrandom`-based
/// re-export -- no separate RNG dependency is needed). Never a timestamp,
/// counter, PID, or any other non-CSPRNG source.
pub fn generate_random() -> [u8; RANDOM_SIZE] {
    let mut bytes = [0u8; RANDOM_SIZE];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Derive one 32-byte HKDF-Expand output from `psk` and `info`. Private:
/// every public use of this (tags, session keys) goes through the
/// functions below so the `info` construction stays consistent and
/// documented in one place.
fn hkdf_expand_32(psk: &[u8; KEY_SIZE], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, psk);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .expect("32-byte output is always valid for HKDF-SHA256 (max is 255*32 bytes)");
    out
}

/// Compute the authentication tag for a handshake message, binding
/// `message_type`, `version`, `client_random`, and `server_random` --
/// exactly the values the v0.7 spec requires a handshake tag to cover.
/// Used for both the server's `Response` tag and the client's `Confirm`
/// tag; `message_type` (the two are different constants -- see
/// `protocol::MSG_TYPE_HANDSHAKE_RESPONSE`/`MSG_TYPE_HANDSHAKE_CONFIRM`)
/// keeps the two tags from ever being valid for each other's purpose.
pub fn handshake_tag(
    message_type: u8,
    version: u8,
    psk: &[u8; KEY_SIZE],
    client_random: &[u8; RANDOM_SIZE],
    server_random: &[u8; RANDOM_SIZE],
) -> [u8; HANDSHAKE_TAG_SIZE] {
    let mut info = Vec::with_capacity(HKDF_CONTEXT_PREFIX.len() + 2 + RANDOM_SIZE * 2);
    info.extend_from_slice(HKDF_CONTEXT_PREFIX);
    info.push(message_type);
    info.push(version);
    info.extend_from_slice(client_random);
    info.extend_from_slice(server_random);
    hkdf_expand_32(psk, &info)
}

/// Constant-time comparison of a received tag against the expected one.
/// Always use this (never `==`) to compare handshake tags, so a mismatch
/// can't be distinguished by timing.
pub fn verify_tag(
    expected: &[u8; HANDSHAKE_TAG_SIZE],
    received: &[u8; HANDSHAKE_TAG_SIZE],
) -> bool {
    expected.ct_eq(received).into()
}

/// The two independent, freshly-derived ciphers for one session, plus
/// non-secret fingerprints of each key safe to log for debugging/testing
/// (see [`key_fingerprint`]).
pub struct SessionCiphers {
    pub client_to_server: Cipher,
    pub server_to_client: Cipher,
    pub client_to_server_fingerprint: String,
    pub server_to_client_fingerprint: String,
}

/// Derive fresh, independent session keys for both directions from `psk`,
/// `client_random`, and `server_random`, and build a `Cipher` for each.
///
/// Called once per successfully authenticated handshake. Because
/// `client_random`/`server_random` are freshly generated for every
/// session (see `generate_random`), every session's keys differ from
/// every other session's, even under the same static PSK -- this is what
/// makes it safe for each new session's `Cipher` to start its counter at
/// 0 (see the module-level "v0.7 addendum" docs).
pub fn derive_session_ciphers(
    psk: &[u8; KEY_SIZE],
    client_random: &[u8; RANDOM_SIZE],
    server_random: &[u8; RANDOM_SIZE],
) -> SessionCiphers {
    let c2s_key = hkdf_expand_32(
        psk,
        &session_info(b"client-to-server", client_random, server_random),
    );
    let s2c_key = hkdf_expand_32(
        psk,
        &session_info(b"server-to-client", client_random, server_random),
    );

    SessionCiphers {
        client_to_server_fingerprint: key_fingerprint(&c2s_key),
        server_to_client_fingerprint: key_fingerprint(&s2c_key),
        client_to_server: Cipher::new(c2s_key),
        server_to_client: Cipher::new(s2c_key),
    }
}

fn session_info(
    direction_label: &[u8],
    client_random: &[u8; RANDOM_SIZE],
    server_random: &[u8; RANDOM_SIZE],
) -> Vec<u8> {
    let mut info = Vec::with_capacity(
        HKDF_CONTEXT_PREFIX.len() + 9 + direction_label.len() + RANDOM_SIZE * 2,
    );
    info.extend_from_slice(HKDF_CONTEXT_PREFIX);
    info.extend_from_slice(b"-session-");
    info.extend_from_slice(direction_label);
    info.extend_from_slice(client_random);
    info.extend_from_slice(server_random);
    info
}

/// A short, non-secret fingerprint of a session key, safe to log or
/// compare across runs -- e.g. to demonstrate that two sessions derived
/// different key material without ever printing an actual key. This is
/// NOT a security mechanism (it's a one-way hash truncated for
/// readability, not a commitment scheme); it exists purely for
/// observability and testing (see the v0.7 restart test).
fn key_fingerprint(key: &[u8; KEY_SIZE]) -> String {
    let hash = Sha256::digest(key);
    hash[..8].iter().map(|b| format!("{b:02x}")).collect()
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

    // ------------------------------------------------------------------
    // v0.7 handshake authentication / session key derivation tests
    // ------------------------------------------------------------------

    fn test_psk(byte: u8) -> [u8; KEY_SIZE] {
        [byte; KEY_SIZE]
    }

    fn test_random(byte: u8) -> [u8; RANDOM_SIZE] {
        [byte; RANDOM_SIZE]
    }

    #[test]
    fn generated_randoms_differ() {
        // Not a proof of CSPRNG quality, just a sanity check that we're
        // not accidentally returning a constant or predictable value.
        let a = generate_random();
        let b = generate_random();
        assert_ne!(a, b);
    }

    #[test]
    fn handshake_tag_round_trip_with_matching_psk() {
        let psk = test_psk(0x01);
        let client_random = test_random(0xAA);
        let server_random = test_random(0xBB);
        let tag = handshake_tag(2, 1, &psk, &client_random, &server_random);
        let recomputed = handshake_tag(2, 1, &psk, &client_random, &server_random);
        assert!(verify_tag(&tag, &recomputed));
    }

    #[test]
    fn handshake_tag_wrong_psk_fails() {
        let client_random = test_random(0xAA);
        let server_random = test_random(0xBB);
        let tag_a = handshake_tag(2, 1, &test_psk(0x01), &client_random, &server_random);
        let tag_b = handshake_tag(2, 1, &test_psk(0x02), &client_random, &server_random);
        assert!(!verify_tag(&tag_a, &tag_b));
    }

    #[test]
    fn handshake_tag_modified_client_random_fails() {
        let psk = test_psk(0x01);
        let server_random = test_random(0xBB);
        let tag = handshake_tag(2, 1, &psk, &test_random(0xAA), &server_random);
        let recomputed = handshake_tag(2, 1, &psk, &test_random(0xAC), &server_random);
        assert!(!verify_tag(&tag, &recomputed));
    }

    #[test]
    fn handshake_tag_modified_server_random_fails() {
        let psk = test_psk(0x01);
        let client_random = test_random(0xAA);
        let tag = handshake_tag(2, 1, &psk, &client_random, &test_random(0xBB));
        let recomputed = handshake_tag(2, 1, &psk, &client_random, &test_random(0xBC));
        assert!(!verify_tag(&tag, &recomputed));
    }

    #[test]
    fn handshake_tag_modified_message_type_fails() {
        let psk = test_psk(0x01);
        let client_random = test_random(0xAA);
        let server_random = test_random(0xBB);
        // Response tag (type 2) must not validate as a Confirm tag (type 3).
        let response_tag = handshake_tag(2, 1, &psk, &client_random, &server_random);
        let confirm_tag = handshake_tag(3, 1, &psk, &client_random, &server_random);
        assert!(!verify_tag(&response_tag, &confirm_tag));
    }

    #[test]
    fn handshake_tag_modified_version_fails() {
        let psk = test_psk(0x01);
        let client_random = test_random(0xAA);
        let server_random = test_random(0xBB);
        let tag_v1 = handshake_tag(2, 1, &psk, &client_random, &server_random);
        let tag_v2 = handshake_tag(2, 2, &psk, &client_random, &server_random);
        assert!(!verify_tag(&tag_v1, &tag_v2));
    }

    #[test]
    fn different_client_randoms_produce_different_session_material() {
        let psk = test_psk(0x10);
        let server_random = test_random(0x20);
        let session_a = derive_session_ciphers(&psk, &test_random(0x01), &server_random);
        let session_b = derive_session_ciphers(&psk, &test_random(0x02), &server_random);
        assert_ne!(
            session_a.client_to_server_fingerprint,
            session_b.client_to_server_fingerprint
        );
        assert_ne!(
            session_a.server_to_client_fingerprint,
            session_b.server_to_client_fingerprint
        );
    }

    #[test]
    fn different_server_randoms_produce_different_session_material() {
        let psk = test_psk(0x10);
        let client_random = test_random(0x20);
        let session_a = derive_session_ciphers(&psk, &client_random, &test_random(0x01));
        let session_b = derive_session_ciphers(&psk, &client_random, &test_random(0x02));
        assert_ne!(
            session_a.client_to_server_fingerprint,
            session_b.client_to_server_fingerprint
        );
        assert_ne!(
            session_a.server_to_client_fingerprint,
            session_b.server_to_client_fingerprint
        );
    }

    #[test]
    fn two_complete_handshakes_produce_different_session_keys() {
        // Simulates the v0.7 restart scenario: same PSK, but a fresh
        // handshake (fresh randoms) each time -- session A and session B
        // must not share key material.
        let psk = test_psk(0x42);

        let session_a = derive_session_ciphers(&psk, &generate_random(), &generate_random());
        let session_b = derive_session_ciphers(&psk, &generate_random(), &generate_random());

        assert_ne!(
            session_a.client_to_server_fingerprint,
            session_b.client_to_server_fingerprint
        );
        assert_ne!(
            session_a.server_to_client_fingerprint,
            session_b.server_to_client_fingerprint
        );
    }

    #[test]
    fn directional_session_keys_differ() {
        let psk = test_psk(0x55);
        let client_random = test_random(0x01);
        let server_random = test_random(0x02);
        let session = derive_session_ciphers(&psk, &client_random, &server_random);
        assert_ne!(
            session.client_to_server_fingerprint,
            session.server_to_client_fingerprint
        );
    }

    #[test]
    fn session_cross_direction_key_cannot_decrypt() {
        // A client->server encrypted packet must not be decryptable with
        // the server->client key from the same session.
        let psk = test_psk(0x66);
        let client_random = test_random(0x01);
        let server_random = test_random(0x02);
        let session = derive_session_ciphers(&psk, &client_random, &server_random);

        let envelope = session
            .client_to_server
            .encrypt(Direction::ClientToServer, b"secret payload");

        assert!(matches!(
            session
                .server_to_client
                .decrypt(Direction::ClientToServer, &envelope),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn session_from_old_handshake_cannot_be_decrypted_by_new_session() {
        // Session A encrypts a packet; session B (a later, independent
        // handshake under the same PSK) must not be able to decrypt it,
        // even though both use the same Direction tag.
        let psk = test_psk(0x77);
        let session_a = derive_session_ciphers(&psk, &test_random(0x01), &test_random(0x02));
        let session_b = derive_session_ciphers(&psk, &test_random(0x03), &test_random(0x04));

        let envelope_from_a = session_a
            .client_to_server
            .encrypt(Direction::ClientToServer, b"session A data");

        assert!(matches!(
            session_b
                .client_to_server
                .decrypt(Direction::ClientToServer, &envelope_from_a),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn fresh_session_counter_at_zero_does_not_reuse_old_session_nonce() {
        // The core v0.7 fix: session A's Cipher and session B's Cipher
        // both start their counter at 0, but because their keys differ,
        // the (key, nonce) pairs never collide -- so encrypting the same
        // plaintext under counter 0 in both sessions produces different,
        // safe ciphertexts.
        let psk = test_psk(0x88);
        let session_a = derive_session_ciphers(&psk, &test_random(0x01), &test_random(0x02));
        let session_b = derive_session_ciphers(&psk, &test_random(0x03), &test_random(0x04));

        let plaintext = b"identical plaintext, counter 0 in both sessions";
        let envelope_a = session_a
            .client_to_server
            .encrypt(Direction::ClientToServer, plaintext);
        let envelope_b = session_b
            .client_to_server
            .encrypt(Direction::ClientToServer, plaintext);

        // Same counter (0) is visible in both envelopes' first 8 bytes...
        assert_eq!(&envelope_a[..COUNTER_SIZE], &envelope_b[..COUNTER_SIZE]);
        // ...but the ciphertexts differ, because the keys differ.
        assert_ne!(envelope_a, envelope_b);
    }
}