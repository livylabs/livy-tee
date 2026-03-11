// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! REPORTDATA — the 64-byte field embedded in every TDX quote.
//!
//! This structure is domain-agnostic: the `payload_hash` carries the
//! business-logic-specific inputs (computed by the caller); the remaining
//! fields are common to every use case and give verifiers a shared language
//! for checking build identity, version, and replay protection.
//!
//! ## Wire layout (all multi-byte integers are big-endian)
//!
//! ```text
//!  Bytes    Size  Field         Description
//!  ─────    ────  ─────         ───────────
//!  00..32    32   payload_hash  SHA-256 of the caller-supplied inputs.
//!                               · Content ingestion: SHA-256(content_hash ‖ "|" ‖
//!                                 identity_pubkey ‖ "|" ‖ timestamp_ms_le).
//!                               · Replace with any deterministic, collision-resistant
//!                                 encoding of your own inputs when reusing this crate
//!                                 for a different use case — the struct has no opinion
//!                                 on what these 32 bytes represent.
//!
//!  32..40     8   build_id      First 8 bytes of SHA-256(server binary on disk).
//!                               A short, human-verifiable build fingerprint.
//!
//!                               If the source code is open or the vendor publishes a
//!                               release checksum, any third party can:
//!                                 1. Obtain the exact source at the tagged commit.
//!                                 2. Reproduce the binary (reproducible build).
//!                                 3. Compute SHA-256(binary) independently.
//!                                 4. Compare the first 8 bytes to this field.
//!
//!                               This binds every attestation to a specific, auditable
//!                               build without storing the full 32-byte hash inline.
//!                               The full hash is available as `tee_binary_hash` in the
//!                               provenance record and, in a real TDX quote, as the
//!                               48-byte MRTD in the TD report body.
//!
//!  40..44     4   version_code  u32 BE — schema / protocol version.
//!                               Increment this — and only this — constant whenever the
//!                               REPORTDATA layout or any hashing scheme changes, so
//!                               old and new verifiers can unambiguously identify the
//!                               format of a record. See [`REPORT_DATA_VERSION`].
//!
//!  44..48     4   build_number  u32 BE — CI build number / patch counter.
//!                               Together with `version_code` this uniquely identifies
//!                               the software revision that produced the attestation.
//!                               Set to 0 in development; set from CI in production.
//!
//!  48..56     8   nonce         u64 BE — monotonically increasing ingestion counter.
//!                               The server increments a persistent counter on every
//!                               ingest call and embeds the next value here.
//!
//!                               Replay protection: a verifier confirms the nonce in the
//!                               quote matches the value stored in the provenance record.
//!                               Because the counter only moves forward, a quote cannot
//!                               be replayed for a different record and the same content
//!                               cannot be submitted twice with a recycled attestation.
//!
//!  56..64     8   reserved      Zero-filled. Reserved for future fields.
//!                               Verifiers that only read [0..56] remain correct when
//!                               new fields are added here in a future version_code.
//! ```
//!
//! ## Verification recipe (independent — no Livy infrastructure required)
//!
//! ```text
//! 1. Fetch the provenance record for a content_hash.
//! 2. Decode the base64 `tdx_quote` field.
//! 3. Extract bytes [0..64] from the quote's TD report body (REPORTDATA field).
//! 4. Parse into ReportData::from_bytes(&bytes).
//! 5. Recompute the expected payload_hash from the record's fields using the
//!    domain-specific hash function (e.g. `content_payload_hash` in tee-server).
//! 6. Assert rd.verify_payload(&expected_hash) == true.
//! 7. Assert rd.build_id == build_id_from_hash_hex(&record.tee_binary_hash).
//! 8. Assert rd.nonce == record.nonce.
//! 9. (Real TDX only) verify the quote signature chain against Intel PCS.
//! ```

use sha2::{Digest, Sha256};

/// Schema version embedded in every REPORTDATA.
///
/// Increment when the wire layout or any hashing scheme changes.
pub const REPORT_DATA_VERSION: u32 = 1;

/// The 64-byte REPORTDATA field embedded in every TDX quote.
///
/// See the [module-level documentation](self) for the full wire layout and the
/// step-by-step verification recipe.
#[derive(Debug, Clone, PartialEq, Eq)]
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
        Self { payload_hash, build_id, version_code, build_number, nonce }
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
        let nonce =
            u64::from_be_bytes([b[48], b[49], b[50], b[51], b[52], b[53], b[54], b[55]]);

        Self { payload_hash, build_id, version_code, build_number, nonce }
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
/// Decodes the first 16 hex characters (= 8 bytes) of the hash.
///
/// # Errors
///
/// Returns an error if the hex string is shorter than 16 characters or
/// contains invalid hex.
pub fn build_id_from_hash_hex(hex_hash: &str) -> Result<[u8; 8], String> {
    let prefix = hex_hash.get(..16).ok_or_else(|| {
        format!("hex hash too short: {} chars (need at least 16)", hex_hash.len())
    })?;
    let bytes = hex::decode(prefix).map_err(|e| format!("invalid hex in build_id: {e}"))?;
    let mut id = [0u8; 8];
    id.copy_from_slice(&bytes);
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
        assert_eq!(build_id_from_hash_hex(&hex).unwrap(), build_id_from_binary(bin));
    }

    #[test]
    fn build_id_from_hash_hex_rejects_short_input() {
        assert!(build_id_from_hash_hex("abcd").is_err());
    }

    #[test]
    fn build_id_from_hash_hex_rejects_invalid_hex() {
        assert!(build_id_from_hash_hex("zzzzzzzzzzzzzzzz").is_err());
    }
}
