// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Local quote/public-values binding helpers.

use crate::{
    evidence::Evidence,
    public_values::PublicValues,
    report::ReportData,
    verify::extract::{extract_report_data, ExtractError},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

#[derive(Debug)]
pub(crate) enum QuoteBindingDecodeError {
    Base64(base64::DecodeError),
}

pub(crate) fn verify_quote_report_data_binding(
    raw_quote_b64: &str,
    runtime_data: &[u8; 64],
    nonce_val: &[u8],
    nonce_iat: &[u8],
) -> Result<bool, QuoteBindingDecodeError> {
    let raw = BASE64
        .decode(raw_quote_b64.trim())
        .map_err(QuoteBindingDecodeError::Base64)?;
    let evidence = match Evidence::from_bytes(raw) {
        Ok(evidence) => evidence,
        Err(_) => return Ok(false),
    };
    let quote_rd_bytes = match extract_report_data(&evidence) {
        Ok(report_data) => report_data,
        Err(_) => return Ok(false),
    };

    Ok(quote_rd_bytes == nonce_and_runtime_hash(nonce_val, nonce_iat, runtime_data))
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
        .map_err(|_| ExtractError::TooShort(0))?;
    let raw_len = raw.len();
    let evidence = Evidence::from_bytes(raw).map_err(|_| ExtractError::TooShort(raw_len))?;
    let quote_rd_bytes = extract_report_data(&evidence)?;

    let runtime_data_bytes = BASE64
        .decode(runtime_data_b64.trim())
        .map_err(|_| ExtractError::TooShort(0))?;
    let runtime_data: [u8; 64] = runtime_data_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ExtractError::TooShort(runtime_data_bytes.len()))?;
    let nonce_val = BASE64
        .decode(nonce_val_b64.trim())
        .map_err(|_| ExtractError::TooShort(0))?;
    let nonce_iat = BASE64
        .decode(nonce_iat_b64.trim())
        .map_err(|_| ExtractError::TooShort(0))?;

    if quote_rd_bytes != nonce_and_runtime_hash(&nonce_val, &nonce_iat, &runtime_data) {
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
