// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `Evidence` — raw TDX quote bytes with base64 helpers.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use thiserror::Error;

/// Errors returned when constructing or decoding [`Evidence`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EvidenceError {
    /// Quote bytes could not be decoded from base64.
    #[error("base64 decode failed: {0}")]
    Base64(String),
    /// Quote is shorter than the minimum valid DCAP quote size (632 bytes).
    #[error("quote too short: {0} bytes (minimum 632)")]
    TooShort(usize),
}

/// Minimum valid DCAP quote size in bytes (matches the mock stub size).
pub const QUOTE_MIN_LEN: usize = 632;

/// Raw TDX quote bytes.
///
/// Wraps the binary DCAP quote (or a correctly-shaped mock stub) and provides
/// base64 helpers for transport/storage.
///
/// **Invariant:** `raw.len() >= QUOTE_MIN_LEN` (632 bytes) — enforced at construction.
#[derive(Debug, Clone)]
pub struct Evidence {
    raw: Vec<u8>,
}

impl Evidence {
    /// Wrap raw quote bytes.
    ///
    /// Returns an error if `raw.len() < 632`.
    pub fn from_bytes(raw: Vec<u8>) -> Result<Self, EvidenceError> {
        if raw.len() < QUOTE_MIN_LEN {
            return Err(EvidenceError::TooShort(raw.len()));
        }
        Ok(Self { raw })
    }

    /// Access the raw quote bytes.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Encode the raw quote bytes as standard base64.
    #[must_use]
    pub fn to_base64(&self) -> String {
        BASE64.encode(&self.raw)
    }

    /// Decode a standard base64 string into raw quote bytes.
    pub fn from_base64(s: &str) -> Result<Self, EvidenceError> {
        let raw = BASE64.decode(s).map_err(|e| EvidenceError::Base64(e.to_string()))?;
        Self::from_bytes(raw)
    }
}
