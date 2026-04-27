// SPDX-License-Identifier: MIT
//! Internal helpers for decoding fixed-size verification payloads.

use base64::{
    engine::general_purpose::STANDARD as BASE64,
    engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine,
};

pub(crate) fn decode_standard_base64(name: &str, value: &str) -> Result<Vec<u8>, String> {
    BASE64
        .decode(value.trim())
        .map_err(|e| format!("{name} base64: {e}"))
}

pub(crate) fn decode_standard_base64_array_64(name: &str, value: &str) -> Result<[u8; 64], String> {
    let bytes = decode_standard_base64(name, value)?;
    to_array_64(name, bytes)
}

pub(crate) fn decode_claim_array_64(name: &str, value: &str) -> Result<[u8; 64], String> {
    if value.len() == 128 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        let bytes = hex::decode(value).map_err(|_| format!("{name}: invalid hex"))?;
        return to_array_64(name, bytes);
    }

    let bytes = BASE64URL
        .decode(value)
        .or_else(|_| BASE64.decode(value))
        .map_err(|_| format!("{name}: could not decode as base64url/base64"))?;
    to_array_64(name, bytes)
}

fn to_array_64(name: &str, bytes: Vec<u8>) -> Result<[u8; 64], String> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        format!(
            "{name} has unexpected length: {} bytes (expected 64)",
            bytes.len()
        )
    })
}
