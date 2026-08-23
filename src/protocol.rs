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
}