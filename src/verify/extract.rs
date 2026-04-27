// SPDX-License-Identifier: MIT
//! Local extraction of fields from a raw TDX DCAP quote.
//!
//! This module parses fixed offsets from the quote body. It does not verify the
//! quote signature chain.

use crate::evidence::{Evidence, QUOTE_MIN_LEN};
const OFFSET_VERSION: usize = 0;
const OFFSET_TEE_TYPE: usize = 4;
const OFFSET_MRTD: usize = 184;
const OFFSET_REPORT_DATA: usize = 568;

const TEE_TYPE_TDX: u32 = 0x81;
use crate::error::ExtractError;

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

/// Extract the 64-byte `REPORTDATA` field from a raw TDX quote.
pub fn extract_report_data(evidence: &Evidence) -> Result<[u8; 64], ExtractError> {
    parse_header(evidence)?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&evidence.raw()[OFFSET_REPORT_DATA..OFFSET_REPORT_DATA + 64]);
    Ok(out)
}

/// Extract the 48-byte MRTD from a raw TDX quote.
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
        use crate::error::EvidenceError;
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
