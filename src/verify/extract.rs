// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Local extraction of fields from a raw TDX DCAP quote.
//!
//! TDX DCAP v4 quote layout (byte offsets):
//!
//! ```text
//!  [0..2]     version      u16 LE — must be 4
//!  [2..4]     att_key_type u16 LE
//!  [4..8]     tee_type     u32 LE — 0x81 = TDX
//!  [8..48]    header rest
//!  ── TD Report Body (520 bytes @ 48) ──
//!  [48..184]  various TD fields (TEETCBSVN, MRSEAM, …)
//!  [184..232] MRTD         48 bytes — measurement of the TD binary
//!  [232..568] more TD fields (RTMR0..3, etc.)
//!  [568..632] REPORTDATA   64 bytes — our embedded user_data
//! ```

use crate::evidence::{Evidence, QUOTE_MIN_LEN};
use thiserror::Error;

const OFFSET_VERSION: usize = 0;
const OFFSET_TEE_TYPE: usize = 4;
const OFFSET_MRTD: usize = 184;
const OFFSET_REPORT_DATA: usize = 568;

const TEE_TYPE_TDX: u32 = 0x81;

/// Errors returned by [`extract_report_data`] and [`extract_mrtd`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExtractError {
    /// Base64 decoding failed while parsing a textual quote/runtime input.
    #[error("base64 decode failed: {0}")]
    Base64(String),
    /// Runtime data did not decode to exactly 64 bytes.
    #[error("runtime_data must decode to exactly 64 bytes, got {0}")]
    InvalidRuntimeDataLength(usize),
    /// Quote buffer is too short to contain the required DCAP fields.
    #[error("quote too short: need at least {QUOTE_MIN_LEN} bytes, got {0}")]
    TooShort(usize),
    /// Quote version is not 4 (the only supported TDX DCAP version).
    #[error("unsupported quote version {0}: expected 4")]
    UnsupportedVersion(u16),
    /// TEE type field is not `0x81` (TDX).
    #[error("unsupported TEE type 0x{0:08x}: expected 0x81 (TDX)")]
    UnsupportedTeeType(u32),
}

fn parse_header(evidence: &Evidence) -> Result<(), ExtractError> {
    let raw = evidence.raw();
    if raw.len() < QUOTE_MIN_LEN {
        return Err(ExtractError::TooShort(raw.len()));
    }
    let version = u16::from_le_bytes([raw[OFFSET_VERSION], raw[OFFSET_VERSION + 1]]);
    if version != 4 {
        return Err(ExtractError::UnsupportedVersion(version));
    }
    let tee_type = u32::from_le_bytes([
        raw[OFFSET_TEE_TYPE],
        raw[OFFSET_TEE_TYPE + 1],
        raw[OFFSET_TEE_TYPE + 2],
        raw[OFFSET_TEE_TYPE + 3],
    ]);
    if tee_type != TEE_TYPE_TDX {
        return Err(ExtractError::UnsupportedTeeType(tee_type));
    }
    Ok(())
}

/// Extract the 64-byte REPORTDATA field from a raw TDX DCAP quote.
///
/// This is a local, network-free operation. No signature verification is
/// performed — use the `ita-verify` feature for full chain verification.
pub fn extract_report_data(evidence: &Evidence) -> Result<[u8; 64], ExtractError> {
    parse_header(evidence)?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&evidence.raw()[OFFSET_REPORT_DATA..OFFSET_REPORT_DATA + 64]);
    Ok(out)
}

/// Extract the 48-byte MRTD (TD binary measurement) from a raw TDX DCAP quote.
///
/// In real quotes this equals SHA-384 of the TD image as measured by the TDX
/// module at launch.  In mock quotes this is all zeros.
pub fn extract_mrtd(evidence: &Evidence) -> Result<[u8; 48], ExtractError> {
    parse_header(evidence)?;
    let mut out = [0u8; 48];
    out.copy_from_slice(&evidence.raw()[OFFSET_MRTD..OFFSET_MRTD + 48]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "mock-tee")]
    use crate::generate::generate_evidence;
    #[cfg(feature = "mock-tee")]
    use crate::report::ReportData;

    #[cfg(feature = "mock-tee")]
    #[test]
    fn extract_roundtrip_mock() {
        let user_data = ReportData::new([1u8; 32], [2u8; 8], 1, 0, 99).to_bytes();
        let evidence = generate_evidence(&user_data).unwrap();
        let extracted = extract_report_data(&evidence).unwrap();
        assert_eq!(extracted, user_data);
    }

    #[cfg(feature = "mock-tee")]
    #[test]
    fn extract_mrtd_is_zeros_in_mock() {
        let evidence = generate_evidence(&[0u8; 64]).unwrap();
        let mrtd = extract_mrtd(&evidence).unwrap();
        assert_eq!(mrtd, [0u8; 48]);
    }

    #[test]
    fn too_short_returns_error() {
        use crate::evidence::EvidenceError;
        let result = Evidence::from_bytes(vec![0u8; 100]);
        assert!(matches!(result, Err(EvidenceError::TooShort(100))));
    }

    #[test]
    fn wrong_version_returns_error() {
        let mut buf = vec![0u8; 632];
        buf[0] = 3; // version = 3
        buf[4] = 0x81; // tee_type = TDX
        let evidence = Evidence::from_bytes(buf).unwrap();
        assert!(matches!(
            extract_report_data(&evidence),
            Err(ExtractError::UnsupportedVersion(3))
        ));
    }

    #[test]
    fn wrong_tee_type_returns_error() {
        let mut buf = vec![0u8; 632];
        buf[0] = 4; // version = 4
        buf[4] = 0x00; // tee_type = 0 (SGX, not TDX)
        let evidence = Evidence::from_bytes(buf).unwrap();
        assert!(matches!(
            extract_report_data(&evidence),
            Err(ExtractError::UnsupportedTeeType(0))
        ));
    }
}
