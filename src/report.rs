// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `ReportData` is the 64-byte `runtime_data` payload bound into a TDX attestation.
//!
//! Wire layout, all big-endian:
//! - `0..32`: payload hash
//! - `32..40`: build ID
//! - `40..44`: version code
//! - `44..48`: build number
//! - `48..56`: application nonce
//! - `56..64`: reserved zeroes
//!
//! Verifiers typically parse these 64 bytes, recompute the expected payload
//! hash, then check `build_id` and `nonce` against their own policy.

use crate::error::BuildIdError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema version embedded in every `ReportData`.
///
/// Increment this when the wire layout or hashing rules change.
pub const REPORT_DATA_VERSION: u32 = 1;

/// Structured 64-byte `runtime_data` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportData {
    /// `[00..32]` SHA-256 of the domain-specific inputs for this attestation.
    pub payload_hash: [u8; 32],
    /// `[32..40]` First 8 bytes of SHA-256(server binary) — short build fingerprint.
    pub build_id: [u8; 8],
    /// `[40..44]` Schema / protocol version.
    pub version_code: u32,
    /// `[44..48]` CI build number.
    pub build_number: u32,
    /// `[48..56]` Monotonic ingestion counter — replay protection.
    pub nonce: u64,
    // [56..64] reserved — always zero on the wire, not stored in this struct.
}

impl ReportData {
    /// Construct a new [`ReportData`].
    pub fn new(
        payload_hash: [u8; 32],
        build_id: [u8; 8],
        version_code: u32,
        build_number: u32,
        nonce: u64,
    ) -> Self {
        Self {
            payload_hash,
            build_id,
            version_code,
            build_number,
            nonce,
        }
    }

    /// Serialise to the canonical 64-byte wire format.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[0..32].copy_from_slice(&self.payload_hash);
        out[32..40].copy_from_slice(&self.build_id);
        out[40..44].copy_from_slice(&self.version_code.to_be_bytes());
        out[44..48].copy_from_slice(&self.build_number.to_be_bytes());
        out[48..56].copy_from_slice(&self.nonce.to_be_bytes());
        // out[56..64] stays zero — reserved
        out
    }

    /// Deserialise from the canonical 64-byte wire format.
    pub fn from_bytes(b: &[u8; 64]) -> Self {
        let mut payload_hash = [0u8; 32];
        payload_hash.copy_from_slice(&b[0..32]);

        let mut build_id = [0u8; 8];
        build_id.copy_from_slice(&b[32..40]);

        let version_code = u32::from_be_bytes([b[40], b[41], b[42], b[43]]);
        let build_number = u32::from_be_bytes([b[44], b[45], b[46], b[47]]);
        let nonce = u64::from_be_bytes([b[48], b[49], b[50], b[51], b[52], b[53], b[54], b[55]]);

        Self {
            payload_hash,
            build_id,
            version_code,
            build_number,
            nonce,
        }
    }

    /// Hex-encode the full 64 bytes (128 hex characters).
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Return `true` if the embedded `payload_hash` matches `expected`.
    pub fn verify_payload(&self, expected: &[u8; 32]) -> bool {
        self.payload_hash == *expected
    }
}

/// Derive a `build_id` from raw binary bytes.
///
/// Computes `SHA-256(binary_bytes)` and returns the first 8 bytes.
pub fn build_id_from_binary(binary_bytes: &[u8]) -> [u8; 8] {
    let hash = Sha256::digest(binary_bytes);
    let mut id = [0u8; 8];
    id.copy_from_slice(&hash[0..8]);
    id
}

/// Derive a `build_id` from an already-computed SHA-256 hex string.
///
/// Decodes the first 16 hex characters, which is equivalent to
/// [`build_id_from_binary`] on the same binary. Use this when you already have
/// the full hash, for example from [`crate::binary_hash`].
pub fn build_id_from_hash_hex(hex_hash: &str) -> Result<[u8; 8], BuildIdError> {
    let prefix = hex_hash
        .get(..16)
        .ok_or(BuildIdError::TooShort(hex_hash.len()))?;
    let bytes = hex::decode(prefix).map_err(|e| BuildIdError::InvalidHex(e.to_string()))?;
    let mut id = [0u8; 8];
    id.copy_from_slice(&bytes[..8]);
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ReportData {
        ReportData::new([1u8; 32], [2u8; 8], REPORT_DATA_VERSION, 7, 42)
    }

    #[test]
    fn to_bytes_is_64() {
        assert_eq!(sample().to_bytes().len(), 64);
    }

    #[test]
    fn roundtrip() {
        let rd = sample();
        assert_eq!(rd, ReportData::from_bytes(&rd.to_bytes()));
    }

    #[test]
    fn to_hex_is_128_chars() {
        assert_eq!(sample().to_hex().len(), 128);
    }

    #[test]
    fn reserved_bytes_are_zero() {
        assert_eq!(&sample().to_bytes()[56..64], &[0u8; 8]);
    }

    #[test]
    fn fields_survive_roundtrip() {
        let rd = sample();
        let rt = ReportData::from_bytes(&rd.to_bytes());
        assert_eq!(rt.version_code, REPORT_DATA_VERSION);
        assert_eq!(rt.build_number, 7);
        assert_eq!(rt.nonce, 42);
        assert_eq!(rt.build_id, [2u8; 8]);
        assert_eq!(rt.payload_hash, [1u8; 32]);
    }

    #[test]
    fn verify_payload_passes_and_rejects() {
        let hash = [5u8; 32];
        let rd = ReportData::new(hash, [0u8; 8], 1, 0, 1);
        assert!(rd.verify_payload(&hash));
        assert!(!rd.verify_payload(&[6u8; 32]));
    }

    #[test]
    fn build_id_from_binary_is_first_8_bytes_of_sha256() {
        let bin = b"some binary bytes";
        let id = build_id_from_binary(bin);
        let full = Sha256::digest(bin);
        assert_eq!(id, full[0..8]);
    }

    #[test]
    fn build_id_from_hash_hex_matches_build_id_from_binary() {
        let bin = b"some binary bytes";
        let hex = hex::encode(Sha256::digest(bin));
        assert_eq!(
            build_id_from_hash_hex(&hex).expect("known-good SHA-256 hex"),
            build_id_from_binary(bin)
        );
    }

    #[test]
    fn build_id_from_hash_hex_rejects_short_input() {
        assert_eq!(
            build_id_from_hash_hex("abcd"),
            Err(BuildIdError::TooShort(4))
        );
    }

    #[test]
    fn build_id_from_hash_hex_rejects_invalid_hex() {
        let err = build_id_from_hash_hex("zzzzzzzzzzzzzzzz").unwrap_err();
        assert!(matches!(err, BuildIdError::InvalidHex(_)));
    }

    #[test]
    fn build_id_from_hash_hex_uses_first_16_chars_only() {
        let hex = "0011223344556677deadbeefcafebabe";
        assert_eq!(
            build_id_from_hash_hex(hex).expect("known-good prefix"),
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
        );
    }
}
