// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Local quote/public-values binding helpers.

use crate::{
    evidence::Evidence,
    public_values::PublicValues,
    report::ReportData,
    verify::extract::{extract_report_data, ExtractError},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

pub(crate) fn verify_quote_report_data_binding(
    raw_quote_b64: &str,
    expected_report_data: &[u8; 64],
) -> Result<bool, ExtractError> {
    let raw = BASE64
        .decode(raw_quote_b64.trim())
        .map_err(|err| ExtractError::Base64(err.to_string()))?;
    let raw_len = raw.len();
    let evidence = Evidence::from_bytes(raw).map_err(|_| ExtractError::TooShort(raw_len))?;
    let quote_rd_bytes = extract_report_data(&evidence)?;

    Ok(quote_rd_bytes == *expected_report_data)
}

/// Verify a raw DCAP quote's ITA nonce binding and an expected `payload_hash`.
///
/// **No TDX hardware. No network.** Pure software — anyone can call this.
///
/// Checks:
/// 1. `SHA-512(nonce_val ‖ nonce_iat ‖ runtime_data) == REPORTDATA` in the quote.
/// 2. `ReportData.payload_hash == expected_payload_hash`.
///
/// Use this when you built the `payload_hash` yourself with the low-level API
/// (e.g. `SHA-256(your_inputs)`) rather than through a [`PublicValues`] buffer.
/// For the high-level commit/read model, use [`verify_quote_with_public_values`]
/// or [`crate::bind::Attestation::verify`] instead.
pub fn verify_quote(
    raw_quote_b64: &str,
    runtime_data_b64: &str,
    nonce_val_b64: &str,
    nonce_iat_b64: &str,
    expected_payload_hash: &[u8; 32],
) -> Result<bool, ExtractError> {
    let raw = BASE64
        .decode(raw_quote_b64.trim())
        .map_err(|err| ExtractError::Base64(err.to_string()))?;
    let raw_len = raw.len();
    let evidence = Evidence::from_bytes(raw).map_err(|_| ExtractError::TooShort(raw_len))?;
    let quote_rd_bytes = extract_report_data(&evidence)?;

    let runtime_data_bytes = BASE64
        .decode(runtime_data_b64.trim())
        .map_err(|err| ExtractError::Base64(err.to_string()))?;
    let runtime_data: [u8; 64] = runtime_data_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ExtractError::InvalidRuntimeDataLength(runtime_data_bytes.len()))?;
    let nonce_val = BASE64
        .decode(nonce_val_b64.trim())
        .map_err(|err| ExtractError::Base64(err.to_string()))?;
    let nonce_iat = BASE64
        .decode(nonce_iat_b64.trim())
        .map_err(|err| ExtractError::Base64(err.to_string()))?;
    let expected_report_data = nonce_and_runtime_hash(&nonce_val, &nonce_iat, &runtime_data);

    if quote_rd_bytes != expected_report_data {
        return Ok(false);
    }

    let rd = ReportData::from_bytes(&runtime_data);
    Ok(rd.verify_payload(expected_payload_hash))
}

/// Verify a raw DCAP quote against a [`PublicValues`] buffer.
///
/// **No TDX hardware. No network.** Pure software — anyone can call this.
///
/// Checks:
/// 1. `SHA-512(nonce_val ‖ nonce_iat ‖ runtime_data) == REPORTDATA` in the quote.
/// 2. `SHA-256(public_values.buffer) == ReportData.payload_hash` in runtime_data.
///
/// This is the high-level counterpart to [`verify_quote`]: it computes the
/// `payload_hash` automatically from the `PublicValues` buffer rather than
/// requiring you to supply it directly.
pub fn verify_quote_with_public_values(
    raw_quote_b64: &str,
    runtime_data_b64: &str,
    nonce_val_b64: &str,
    nonce_iat_b64: &str,
    public_values: &PublicValues,
) -> Result<bool, ExtractError> {
    let hash = public_values.commitment_hash();
    verify_quote(
        raw_quote_b64,
        runtime_data_b64,
        nonce_val_b64,
        nonce_iat_b64,
        &hash,
    )
}

pub(super) fn nonce_and_runtime_hash(
    nonce_val: &[u8],
    nonce_iat: &[u8],
    runtime_data: &[u8; 64],
) -> [u8; 64] {
    use sha2::{Digest, Sha512};

    let mut h = Sha512::new();
    h.update(nonce_val);
    h.update(nonce_iat);
    h.update(runtime_data);
    h.finalize().into()
}

#[cfg(all(test, feature = "mock-tee"))]
mod tests {
    use super::*;
    use crate::generate::generate_evidence;
    use base64::engine::general_purpose::STANDARD as BASE64;

    fn mock_binding_inputs() -> (String, String, String, String, PublicValues) {
        let mut public_values = PublicValues::new();
        public_values.commit(&"binding-value").unwrap();

        let nonce_val = b"nonce-val".to_vec();
        let nonce_iat = b"nonce-iat".to_vec();
        let runtime_data = ReportData::new(public_values.commitment_hash(), [0u8; 8], 7, 0, 1);
        let quote = generate_evidence(&nonce_and_runtime_hash(
            &nonce_val,
            &nonce_iat,
            &runtime_data.to_bytes(),
        ))
        .expect("mock evidence should build");

        (
            BASE64.encode(quote.raw()),
            BASE64.encode(runtime_data.to_bytes()),
            BASE64.encode(&nonce_val),
            BASE64.encode(&nonce_iat),
            public_values,
        )
    }

    #[test]
    fn verify_quote_with_public_values_returns_false_for_mismatched_public_values() {
        let (quote_b64, runtime_data_b64, nonce_val_b64, nonce_iat_b64, _) = mock_binding_inputs();
        let mut tampered = PublicValues::new();
        tampered.commit(&"tampered-value").unwrap();

        let ok = verify_quote_with_public_values(
            &quote_b64,
            &runtime_data_b64,
            &nonce_val_b64,
            &nonce_iat_b64,
            &tampered,
        )
        .expect("structurally valid quote should verify cleanly");

        assert!(!ok);
    }

    #[test]
    fn verify_quote_report_data_binding_rejects_truncated_quotes_with_diagnostic() {
        let (_, runtime_data_b64, nonce_val_b64, nonce_iat_b64, _) = mock_binding_inputs();
        let runtime_data: [u8; 64] = BASE64
            .decode(runtime_data_b64)
            .expect("runtime data should decode")
            .as_slice()
            .try_into()
            .expect("runtime data should be 64 bytes");
        let nonce_val = BASE64
            .decode(nonce_val_b64)
            .expect("nonce value should decode");
        let nonce_iat = BASE64
            .decode(nonce_iat_b64)
            .expect("nonce iat should decode");
        let expected_report_data = nonce_and_runtime_hash(&nonce_val, &nonce_iat, &runtime_data);

        assert!(matches!(
            verify_quote_report_data_binding("", &expected_report_data),
            Err(ExtractError::TooShort(0))
        ));
    }
}
