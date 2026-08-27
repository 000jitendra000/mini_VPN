//! VPN wire protocol / packet framing (v0.5).
//!
//! Defines a small, plaintext, inspectable frame format that wraps a raw
//! IP packet before it goes out over UDP:
//!
//! ```text
//! +------------+---------+------------+--------------+-------------+
//! | Magic      | Version | Type       | Payload Len  | Payload     |
//! | 2 bytes    | 1 byte  | 1 byte     | 2 bytes (BE) | N bytes     |
//! +------------+---------+------------+--------------+-------------+
//! ```
//!
//! This module only knows about frames, not about IP packets: the payload
//! is treated as opaque bytes (`Vec<u8>` / `&[u8]`). It does not parse
//! source/destination addresses, protocol numbers, or anything else about
//! the IP packet carried inside -- that's out of scope through at least
//! v0.5. No encryption or authentication is applied here either: every
//! byte of a frame is plaintext and unauthenticated (see v0.6 / v0.7).

use std::fmt;

/// "TV" -- identifies the start of a tiny-vpn frame.
pub const MAGIC: [u8; 2] = [0x54, 0x56];

/// The only wire format version that currently exists.
pub const VERSION: u8 = 0x01;

/// Size of the fixed frame header: magic (2) + version (1) + type (1) +
/// payload length (2).
pub const HEADER_SIZE: usize = 6;

/// Maximum payload this protocol will encode/accept.
///
/// Assumption: the TUN devices in this project use the `tun` crate's
/// default MTU of 1500 bytes (`tun::DEFAULT_MTU`), so a raw IP packet
/// never exceeds that. This is not IP fragmentation/reassembly -- a
/// payload larger than this is simply rejected as an error, not split.
pub const MAX_PAYLOAD_SIZE: usize = 1500;

/// Maximum size of a fully encoded frame (header + maximum payload).
/// 6-byte header + 1500-byte payload = 1506 bytes.
pub const MAX_FRAME_SIZE: usize = HEADER_SIZE + MAX_PAYLOAD_SIZE;

/// The kind of frame. Only `Data` exists at v0.5; more variants (control
/// messages, handshake, etc.) belong to later versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data = 1,
}

impl FrameType {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(FrameType::Data),
            _ => None,
        }
    }

    fn to_byte(self) -> u8 {
        self as u8
    }
}

/// A decoded (or to-be-encoded) VPN frame.
///
/// `payload` is always opaque bytes -- for a `Data` frame this is a raw IP
/// packet, but `Frame` itself never parses or interprets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub version: u8,
    pub frame_type: FrameType,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Build a `Data` frame wrapping `payload` (e.g. a raw IP packet just
    /// read from a TUN device). Fails if `payload` exceeds
    /// `MAX_PAYLOAD_SIZE` -- this protocol does not fragment.
    pub fn data(payload: Vec<u8>) -> Result<Self, ProtocolError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                len: payload.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }
        Ok(Frame {
            version: VERSION,
            frame_type: FrameType::Data,
            payload,
        })
    }

    /// Total size this frame occupies once encoded (header + payload).
    pub fn encoded_len(&self) -> usize {
        HEADER_SIZE + self.payload.len()
    }

    /// Serialize this frame to bytes: `MAGIC | VERSION | TYPE | LEN | PAYLOAD`.
    ///
    /// Note: this assumes `self.payload.len() <= MAX_PAYLOAD_SIZE`, which
    /// `Frame::data` enforces at construction time.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        buf.extend_from_slice(&MAGIC);
        buf.push(self.version);
        buf.push(self.frame_type.to_byte());
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Parse exactly one frame from `bytes`.
    ///
    /// This is a strict decoder: `bytes` must contain exactly one complete
    /// frame (header + declared payload length) with nothing left over.
    /// That matches how frames are used at v0.5 -- one frame per UDP
    /// datagram -- so trailing bytes after a well-formed frame are treated
    /// as corruption rather than "the start of the next frame".
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < HEADER_SIZE {
            return Err(ProtocolError::TruncatedFrame {
                have: bytes.len(),
                need: HEADER_SIZE,
            });
        }

        if !bytes.starts_with(&MAGIC) {
            return Err(ProtocolError::InvalidMagic {
                found: [bytes[0], bytes[1]],
            });
        }

        let version = bytes[2];
        if version != VERSION {
            return Err(ProtocolError::UnsupportedVersion { found: version });
        }

        let frame_type = FrameType::from_byte(bytes[3])
            .ok_or(ProtocolError::UnsupportedFrameType { found: bytes[3] })?;

        let payload_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::InvalidPayloadLength {
                declared: payload_len,
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let expected_total = HEADER_SIZE + payload_len;
        if bytes.len() < expected_total {
            return Err(ProtocolError::TruncatedFrame {
                have: bytes.len(),
                need: expected_total,
            });
        }
        if bytes.len() > expected_total {
            return Err(ProtocolError::ExtraBytes {
                have: bytes.len(),
                expected: expected_total,
            });
        }

        let payload = bytes[HEADER_SIZE..expected_total].to_vec();

        Ok(Frame {
            version,
            frame_type,
            payload,
        })
    }
}

/// Errors returned while decoding (or building) a frame.
///
/// Malformed input always produces one of these variants -- never a
/// panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// The first two bytes weren't `MAGIC`.
    InvalidMagic { found: [u8; 2] },
    /// The version byte isn't one this implementation understands.
    UnsupportedVersion { found: u8 },
    /// The type byte isn't a known `FrameType`.
    UnsupportedFrameType { found: u8 },
    /// Fewer bytes were supplied than the frame (header, or header +
    /// declared payload) requires.
    TruncatedFrame { have: usize, need: usize },
    /// The declared payload length exceeds `MAX_PAYLOAD_SIZE`.
    InvalidPayloadLength { declared: usize, max: usize },
    /// More bytes were supplied than one complete frame accounts for.
    ExtraBytes { have: usize, expected: usize },
    /// A payload passed to `Frame::data` exceeds `MAX_PAYLOAD_SIZE`.
    PayloadTooLarge { len: usize, max: usize },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::InvalidMagic { found } => {
                write!(f, "invalid magic bytes: {found:02x?}")
            }
            ProtocolError::UnsupportedVersion { found } => {
                write!(f, "unsupported protocol version: {found}")
            }
            ProtocolError::UnsupportedFrameType { found } => {
                write!(f, "unsupported frame type: {found}")
            }
            ProtocolError::TruncatedFrame { have, need } => {
                write!(f, "truncated frame: have {have} bytes, need at least {need}")
            }
            ProtocolError::InvalidPayloadLength { declared, max } => {
                write!(f, "invalid payload length {declared} (max {max})")
            }
            ProtocolError::ExtraBytes { have, expected } => {
                write!(
                    f,
                    "extra bytes after frame: have {have}, expected exactly {expected}"
                )
            }
            ProtocolError::PayloadTooLarge { len, max } => {
                write!(f, "payload too large: {len} bytes (max {max})")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

// ============================================================================
// v0.7: handshake protocol message types.
//
// This is a SEPARATE, sibling wire format to the `Frame` format above --
// handshake messages are never wrapped in a `Frame`, and a decrypted
// `Frame` never appears anywhere outside an `EncryptedData` message's
// body. The two protocols share this file because both are "the VPN wire
// protocol", but they don't share types, constants, or codecs.
//
// Every UDP datagram sent by the v0.7 transport begins with one message-
// type byte, so a receiver can tell handshake traffic apart from
// encrypted VPN data without guessing:
//
// ```text
// byte 0: message type
//   0x01 = HandshakeInit      (Client -> Server)
//   0x02 = HandshakeResponse  (Server -> Client)
//   0x03 = HandshakeConfirm   (Client -> Server)
//   0x04 = EncryptedData      (either direction)
// bytes 1..: message-type-specific body
// ```
//
// `EncryptedData`'s body is the existing, completely unmodified v0.6
// encryption envelope (`counter(8) || ciphertext || tag`) -- this module
// does not touch it beyond slicing off the leading type byte; encryption
// itself is `crypto.rs`'s job.
// ============================================================================

/// Size of the random value each side contributes to a handshake.
///
/// `crypto::RANDOM_SIZE` produces exactly this many bytes; the two
/// constants are defined independently (in different modules, each with
/// no dependency on the other) rather than one importing the other, to
/// keep `protocol.rs` free of any dependency on `crypto.rs`. Keep them in
/// sync if either changes.
pub const HANDSHAKE_RANDOM_SIZE: usize = 32;

/// Size of the authentication tag attached to `Response`/`Confirm`
/// messages. `crypto::HANDSHAKE_TAG_SIZE` produces exactly this many
/// bytes (currently via HKDF-SHA256); this module only ever treats a tag
/// as an opaque, fixed-size byte array to encode/decode -- it never
/// computes or verifies one itself.
pub const HANDSHAKE_TAG_SIZE: usize = 32;

/// The only handshake protocol version that currently exists.
pub const HANDSHAKE_VERSION: u8 = 1;

/// Leading message-type byte for each kind of v0.7 UDP datagram.
pub const MSG_TYPE_HANDSHAKE_INIT: u8 = 1;
pub const MSG_TYPE_HANDSHAKE_RESPONSE: u8 = 2;
pub const MSG_TYPE_HANDSHAKE_CONFIRM: u8 = 3;
pub const MSG_TYPE_ENCRYPTED_DATA: u8 = 4;

/// A handshake message. Does not include `EncryptedData` -- see
/// [`UdpMessage`] for the outer type that also distinguishes encrypted
/// data from handshake traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeMessage {
    /// Client -> Server: "let's start a session; here's my randomness."
    Init {
        version: u8,
        client_random: [u8; HANDSHAKE_RANDOM_SIZE],
    },
    /// Server -> Client: "here's my randomness, and proof I know the PSK
    /// (a tag over version + client_random + server_random)."
    Response {
        version: u8,
        server_random: [u8; HANDSHAKE_RANDOM_SIZE],
        tag: [u8; HANDSHAKE_TAG_SIZE],
    },
    /// Client -> Server: "proof I also know the PSK (a tag over the same
    /// values, with a different message-type domain separator)."
    Confirm { tag: [u8; HANDSHAKE_TAG_SIZE] },
}

impl HandshakeMessage {
    /// The leading wire byte for this message's variant.
    pub fn message_type(&self) -> u8 {
        match self {
            HandshakeMessage::Init { .. } => MSG_TYPE_HANDSHAKE_INIT,
            HandshakeMessage::Response { .. } => MSG_TYPE_HANDSHAKE_RESPONSE,
            HandshakeMessage::Confirm { .. } => MSG_TYPE_HANDSHAKE_CONFIRM,
        }
    }

    /// Serialize this message to bytes, including the leading type byte.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![self.message_type()];
        match self {
            HandshakeMessage::Init {
                version,
                client_random,
            } => {
                buf.push(*version);
                buf.extend_from_slice(client_random);
            }
            HandshakeMessage::Response {
                version,
                server_random,
                tag,
            } => {
                buf.push(*version);
                buf.extend_from_slice(server_random);
                buf.extend_from_slice(tag);
            }
            HandshakeMessage::Confirm { tag } => {
                buf.extend_from_slice(tag);
            }
        }
        buf
    }

    /// Parse exactly one handshake message from `bytes` (including its
    /// leading type byte). Every field is fixed-size, so this is a
    /// strict, exact-length decoder: too few or too many bytes for the
    /// indicated message type is an error, never a panic.
    pub fn decode(bytes: &[u8]) -> Result<Self, HandshakeError> {
        let (&message_type, rest) = bytes
            .split_first()
            .ok_or(HandshakeError::TooShort { have: 0, need: 1 })?;

        match message_type {
            MSG_TYPE_HANDSHAKE_INIT => {
                let need = 1 + HANDSHAKE_RANDOM_SIZE;
                if rest.len() != need {
                    return Err(HandshakeError::WrongLength {
                        message_type,
                        have: rest.len(),
                        need,
                    });
                }
                let version = rest[0];
                let mut client_random = [0u8; HANDSHAKE_RANDOM_SIZE];
                client_random.copy_from_slice(&rest[1..1 + HANDSHAKE_RANDOM_SIZE]);
                Ok(HandshakeMessage::Init {
                    version,
                    client_random,
                })
            }
            MSG_TYPE_HANDSHAKE_RESPONSE => {
                let need = 1 + HANDSHAKE_RANDOM_SIZE + HANDSHAKE_TAG_SIZE;
                if rest.len() != need {
                    return Err(HandshakeError::WrongLength {
                        message_type,
                        have: rest.len(),
                        need,
                    });
                }
                let version = rest[0];
                let mut server_random = [0u8; HANDSHAKE_RANDOM_SIZE];
                server_random.copy_from_slice(&rest[1..1 + HANDSHAKE_RANDOM_SIZE]);
                let mut tag = [0u8; HANDSHAKE_TAG_SIZE];
                tag.copy_from_slice(&rest[1 + HANDSHAKE_RANDOM_SIZE..]);
                Ok(HandshakeMessage::Response {
                    version,
                    server_random,
                    tag,
                })
            }
            MSG_TYPE_HANDSHAKE_CONFIRM => {
                let need = HANDSHAKE_TAG_SIZE;
                if rest.len() != need {
                    return Err(HandshakeError::WrongLength {
                        message_type,
                        have: rest.len(),
                        need,
                    });
                }
                let mut tag = [0u8; HANDSHAKE_TAG_SIZE];
                tag.copy_from_slice(rest);
                Ok(HandshakeMessage::Confirm { tag })
            }
            other => Err(HandshakeError::UnknownMessageType { found: other }),
        }
    }
}

/// The outermost dispatch point for a v0.7 UDP datagram: is this
/// handshake traffic, or encrypted VPN data? `EncryptedData`'s payload is
/// borrowed straight out of the input slice (minus the leading type
/// byte) -- this type does not decrypt it or look inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpMessage<'a> {
    Handshake(HandshakeMessage),
    EncryptedData(&'a [u8]),
}

impl<'a> UdpMessage<'a> {
    /// Look at the leading message-type byte of `bytes` and dispatch to
    /// either a decoded [`HandshakeMessage`] or a borrowed `EncryptedData`
    /// body. Never panics on malformed/truncated/unknown input.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, HandshakeError> {
        let &message_type = bytes
            .first()
            .ok_or(HandshakeError::TooShort { have: 0, need: 1 })?;
        if message_type == MSG_TYPE_ENCRYPTED_DATA {
            Ok(UdpMessage::EncryptedData(&bytes[1..]))
        } else {
            HandshakeMessage::decode(bytes).map(UdpMessage::Handshake)
        }
    }
}

/// Wrap an already-encrypted v0.6 envelope (`counter || ciphertext ||
/// tag`, produced by `crypto::Cipher::encrypt`, untouched) in the v0.7
/// outer `EncryptedData` message so it can be told apart from handshake
/// traffic on the wire.
pub fn encode_encrypted_data(envelope: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + envelope.len());
    buf.push(MSG_TYPE_ENCRYPTED_DATA);
    buf.extend_from_slice(envelope);
    buf
}

/// Errors from decoding a [`HandshakeMessage`] or [`UdpMessage`].
///
/// Like `ProtocolError`, malformed input always produces one of these --
/// never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// Fewer bytes were supplied than even a message-type byte.
    TooShort { have: usize, need: usize },
    /// The leading byte isn't a message type this implementation knows.
    UnknownMessageType { found: u8 },
    /// The body wasn't exactly the length that `message_type` requires.
    WrongLength {
        message_type: u8,
        have: usize,
        need: usize,
    },
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::TooShort { have, need } => {
                write!(f, "handshake message too short: have {have} bytes, need at least {need}")
            }
            HandshakeError::UnknownMessageType { found } => {
                write!(f, "unknown message type: {found}")
            }
            HandshakeError::WrongLength {
                message_type,
                have,
                need,
            } => {
                write!(
                    f,
                    "wrong length for message type {message_type}: have {have} bytes, need exactly {need}"
                )
            }
        }
    }
}

impl std::error::Error for HandshakeError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small, realistic-looking IPv4 header (20 bytes, no options, no
    /// payload beyond the header). Not meant to be a valid, routable
    /// packet -- just plausible bytes to prove framing doesn't touch
    /// packet contents.
    fn sample_ipv4_packet() -> Vec<u8> {
        vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0a, 0x0d,
            0x0d, 0x01, 0x0a, 0x0d, 0x0d, 0x02,
        ]
    }

    #[test]
    fn round_trip() {
        let original = Frame::data(vec![1, 2, 3, 4, 5]).unwrap();
        let encoded = original.encode();
        let decoded = Frame::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn empty_payload_is_accepted() {
        // An empty DATA payload is well-formed at the framing layer: the
        // format places no lower bound on payload length. Whether an
        // empty IP packet is meaningful is a question for a higher layer,
        // not for the frame decoder.
        let frame = Frame::data(vec![]).unwrap();
        let encoded = frame.encode();
        assert_eq!(encoded.len(), HEADER_SIZE);
        let decoded = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.payload, Vec::<u8>::new());
    }

    #[test]
    fn invalid_magic_is_rejected() {
        let mut bytes = Frame::data(vec![1, 2, 3]).unwrap().encode();
        bytes[0] = 0x00;
        match Frame::decode(&bytes) {
            Err(ProtocolError::InvalidMagic { .. }) => {}
            other => panic!("expected InvalidMagic, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let mut bytes = Frame::data(vec![1, 2, 3]).unwrap().encode();
        bytes[2] = 0x02;
        match Frame::decode(&bytes) {
            Err(ProtocolError::UnsupportedVersion { found: 0x02 }) => {}
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_frame_type_is_rejected() {
        let mut bytes = Frame::data(vec![1, 2, 3]).unwrap().encode();
        bytes[3] = 0xff;
        match Frame::decode(&bytes) {
            Err(ProtocolError::UnsupportedFrameType { found: 0xff }) => {}
            other => panic!("expected UnsupportedFrameType, got {other:?}"),
        }
    }

    #[test]
    fn truncated_header_is_rejected() {
        let full = Frame::data(vec![1, 2, 3]).unwrap().encode();
        let bytes = &full[..HEADER_SIZE - 1];
        match Frame::decode(bytes) {
            Err(ProtocolError::TruncatedFrame { .. }) => {}
            other => panic!("expected TruncatedFrame, got {other:?}"),
        }
    }

    #[test]
    fn truncated_payload_is_rejected() {
        // Header declares an 84-byte payload; only supply 40 of them.
        let full = Frame::data(vec![0xAB; 84]).unwrap().encode();
        let truncated = &full[..HEADER_SIZE + 40];
        match Frame::decode(truncated) {
            Err(ProtocolError::TruncatedFrame { .. }) => {}
            other => panic!("expected TruncatedFrame, got {other:?}"),
        }
    }

    #[test]
    fn extra_bytes_are_rejected() {
        let mut bytes = Frame::data(vec![1, 2, 3]).unwrap().encode();
        bytes.push(0xFF); // one byte more than the declared payload length
        match Frame::decode(&bytes) {
            Err(ProtocolError::ExtraBytes { .. }) => {}
            other => panic!("expected ExtraBytes, got {other:?}"),
        }
    }

    #[test]
    fn maximum_payload_round_trips() {
        let payload = vec![0x42; MAX_PAYLOAD_SIZE];
        let frame = Frame::data(payload.clone()).unwrap();
        assert_eq!(frame.encoded_len(), MAX_FRAME_SIZE);
        let encoded = frame.encode();
        assert_eq!(encoded.len(), MAX_FRAME_SIZE);
        let decoded = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn over_maximum_payload_is_rejected_when_building() {
        let payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        match Frame::data(payload) {
            Err(ProtocolError::PayloadTooLarge { .. }) => {}
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn real_ipv4_packet_round_trips_unchanged() {
        let packet = sample_ipv4_packet();
        let frame = Frame::data(packet.clone()).unwrap();
        let encoded = frame.encode();

        // Sanity-check the wire layout by hand, matching the spec exactly.
        assert_eq!(&encoded[0..2], &MAGIC);
        assert_eq!(encoded[2], VERSION);
        assert_eq!(encoded[3], FrameType::Data.to_byte());
        assert_eq!(
            u16::from_be_bytes([encoded[4], encoded[5]]),
            packet.len() as u16
        );
        assert_eq!(encoded.len(), HEADER_SIZE + packet.len());

        let decoded = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.payload, packet);
    }

    // ------------------------------------------------------------------
    // v0.7 handshake message tests
    // ------------------------------------------------------------------

    fn sample_random(byte: u8) -> [u8; HANDSHAKE_RANDOM_SIZE] {
        [byte; HANDSHAKE_RANDOM_SIZE]
    }

    fn sample_tag(byte: u8) -> [u8; HANDSHAKE_TAG_SIZE] {
        [byte; HANDSHAKE_TAG_SIZE]
    }

    #[test]
    fn handshake_init_round_trips() {
        let message = HandshakeMessage::Init {
            version: HANDSHAKE_VERSION,
            client_random: sample_random(0xAA),
        };
        let encoded = message.encode();
        assert_eq!(encoded[0], MSG_TYPE_HANDSHAKE_INIT);
        assert_eq!(encoded.len(), 1 + 1 + HANDSHAKE_RANDOM_SIZE);
        assert_eq!(HandshakeMessage::decode(&encoded).unwrap(), message);
    }

    #[test]
    fn handshake_response_round_trips() {
        let message = HandshakeMessage::Response {
            version: HANDSHAKE_VERSION,
            server_random: sample_random(0xBB),
            tag: sample_tag(0xCC),
        };
        let encoded = message.encode();
        assert_eq!(encoded[0], MSG_TYPE_HANDSHAKE_RESPONSE);
        assert_eq!(
            encoded.len(),
            1 + 1 + HANDSHAKE_RANDOM_SIZE + HANDSHAKE_TAG_SIZE
        );
        assert_eq!(HandshakeMessage::decode(&encoded).unwrap(), message);
    }

    #[test]
    fn handshake_confirm_round_trips() {
        let message = HandshakeMessage::Confirm {
            tag: sample_tag(0xDD),
        };
        let encoded = message.encode();
        assert_eq!(encoded[0], MSG_TYPE_HANDSHAKE_CONFIRM);
        assert_eq!(encoded.len(), 1 + HANDSHAKE_TAG_SIZE);
        assert_eq!(HandshakeMessage::decode(&encoded).unwrap(), message);
    }

    #[test]
    fn handshake_empty_input_is_rejected() {
        assert!(matches!(
            HandshakeMessage::decode(&[]),
            Err(HandshakeError::TooShort { .. })
        ));
    }

    #[test]
    fn handshake_unknown_message_type_is_rejected() {
        assert!(matches!(
            HandshakeMessage::decode(&[0xFF]),
            Err(HandshakeError::UnknownMessageType { found: 0xFF })
        ));
    }

    #[test]
    fn handshake_truncated_init_is_rejected() {
        let full = HandshakeMessage::Init {
            version: HANDSHAKE_VERSION,
            client_random: sample_random(0x11),
        }
        .encode();
        let truncated = &full[..full.len() - 1];
        assert!(matches!(
            HandshakeMessage::decode(truncated),
            Err(HandshakeError::WrongLength { .. })
        ));
    }

    #[test]
    fn handshake_extra_bytes_on_confirm_are_rejected() {
        let mut bytes = HandshakeMessage::Confirm {
            tag: sample_tag(0x22),
        }
        .encode();
        bytes.push(0x00);
        assert!(matches!(
            HandshakeMessage::decode(&bytes),
            Err(HandshakeError::WrongLength { .. })
        ));
    }

    #[test]
    fn udp_message_dispatches_encrypted_data() {
        let envelope = vec![1, 2, 3, 4, 5];
        let datagram = encode_encrypted_data(&envelope);
        match UdpMessage::decode(&datagram) {
            Ok(UdpMessage::EncryptedData(body)) => assert_eq!(body, envelope.as_slice()),
            other => panic!("expected EncryptedData, got {other:?}"),
        }
    }

    #[test]
    fn udp_message_dispatches_handshake() {
        let message = HandshakeMessage::Init {
            version: HANDSHAKE_VERSION,
            client_random: sample_random(0x33),
        };
        let datagram = message.encode();
        match UdpMessage::decode(&datagram) {
            Ok(UdpMessage::Handshake(decoded)) => assert_eq!(decoded, message),
            other => panic!("expected Handshake, got {other:?}"),
        }
    }

    #[test]
    fn udp_message_empty_input_is_rejected() {
        assert!(matches!(
            UdpMessage::decode(&[]),
            Err(HandshakeError::TooShort { .. })
        ));
    }
}