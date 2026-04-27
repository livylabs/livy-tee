// SPDX-License-Identifier: MIT
//! `Evidence` — raw TDX quote bytes with base64 helpers.

use crate::error::EvidenceError;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};

/// Minimum valid DCAP quote size in bytes (matches the mock stub size).
pub const QUOTE_MIN_LEN: usize = 632;

/// Portable low-level evidence envelope for transport and storage.
///
/// `quote` always contains standard base64-encoded raw quote bytes. Azure
/// evidence also carries `azure_runtime_data`, which preserves the runtime JSON
/// required for Intel Trust Authority's `/attest/azure` flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableEvidence {
    /// Standard base64-encoded raw quote bytes.
    pub quote: String,
    /// Optional standard base64-encoded Azure runtime JSON bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure_runtime_data: Option<String>,
}

/// Raw TDX quote bytes.
///
/// Wraps the binary DCAP quote (or a correctly-shaped mock stub) and provides
/// base64 helpers for transport/storage. For a portable low-level envelope that
/// also preserves Azure runtime JSON, use [`PortableEvidence`] or
/// [`Evidence::to_transport_string`].
///
/// **Invariant:** `raw.len() >= QUOTE_MIN_LEN` (632 bytes) — enforced at construction.
#[derive(Debug, Clone)]
pub struct Evidence {
    raw: Vec<u8>,
    azure_runtime_data: Option<Vec<u8>>,
}

impl Evidence {
    /// Wrap raw quote bytes.
    ///
    /// Returns an error if `raw.len() < 632`.
    pub fn from_bytes(raw: Vec<u8>) -> Result<Self, EvidenceError> {
        if raw.len() < QUOTE_MIN_LEN {
            return Err(EvidenceError::TooShort(raw.len()));
        }
        Ok(Self {
            raw,
            azure_runtime_data: None,
        })
    }

    /// Wrap raw quote bytes plus Azure runtime JSON bytes.
    ///
    /// This is used by the Azure quote adapter so ITA `/attest/azure` can be
    /// called with the expected Azure runtime payload format. It is also the
    /// public constructor for rebuilding Azure evidence after transport.
    pub fn from_bytes_with_azure_runtime(
        raw: Vec<u8>,
        azure_runtime_data: Vec<u8>,
    ) -> Result<Self, EvidenceError> {
        if raw.len() < QUOTE_MIN_LEN {
            return Err(EvidenceError::TooShort(raw.len()));
        }
        Ok(Self {
            raw,
            azure_runtime_data: Some(azure_runtime_data),
        })
    }

    /// Access the raw quote bytes.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Optional Azure runtime JSON bytes captured during quote collection.
    #[must_use]
    pub fn azure_runtime_data(&self) -> Option<&[u8]> {
        self.azure_runtime_data.as_deref()
    }

    /// Convert this evidence into a portable transport envelope.
    #[must_use]
    pub fn to_portable(&self) -> PortableEvidence {
        PortableEvidence {
            quote: self.to_base64(),
            azure_runtime_data: self
                .azure_runtime_data
                .as_ref()
                .map(|bytes| BASE64.encode(bytes)),
        }
    }

    /// Rebuild evidence from a portable transport envelope.
    pub fn from_portable(portable: PortableEvidence) -> Result<Self, EvidenceError> {
        let raw = decode_base64_field("quote", &portable.quote)?;
        let azure_runtime_data = portable
            .azure_runtime_data
            .as_deref()
            .map(|value| decode_base64_field("azure_runtime_data", value))
            .transpose()?;

        match azure_runtime_data {
            Some(runtime_json) => Self::from_bytes_with_azure_runtime(raw, runtime_json),
            None => Self::from_bytes(raw),
        }
    }

    /// Serialize this evidence into a portable JSON string.
    ///
    /// Unlike [`Evidence::to_base64`], this preserves Azure runtime JSON when
    /// present so the value can be parsed back and re-verified on Azure.
    #[must_use]
    pub fn to_transport_string(&self) -> String {
        serde_json::to_string(&self.to_portable())
            .expect("portable evidence serialization should not fail")
    }

    /// Parse evidence from either a portable JSON envelope or a raw quote base64 string.
    pub fn from_transport_string(s: &str) -> Result<Self, EvidenceError> {
        if s.trim_start().starts_with('{') {
            let portable: PortableEvidence = serde_json::from_str(s)
                .map_err(|e| EvidenceError::PortableFormat(e.to_string()))?;
            Self::from_portable(portable)
        } else {
            Self::from_base64(s)
        }
    }

    /// Encode the raw quote bytes as standard base64.
    ///
    /// This only covers the raw quote bytes. Azure callers that need to keep
    /// runtime JSON must use [`Evidence::to_portable`] or
    /// [`Evidence::to_transport_string`].
    #[must_use]
    pub fn to_base64(&self) -> String {
        BASE64.encode(&self.raw)
    }

    /// Decode a standard base64 string into raw quote bytes.
    ///
    /// This only reconstructs the raw quote bytes. Azure callers that need to
    /// restore runtime JSON must use [`Evidence::from_portable`] or
    /// [`Evidence::from_transport_string`].
    pub fn from_base64(s: &str) -> Result<Self, EvidenceError> {
        let raw = decode_base64_field("quote", s)?;
        Self::from_bytes(raw)
    }
}

fn decode_base64_field(field: &str, value: &str) -> Result<Vec<u8>, EvidenceError> {
    BASE64
        .decode(value)
        .map_err(|e| EvidenceError::Base64(format!("{field}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::Evidence;

    #[test]
    fn azure_transport_roundtrip_preserves_runtime_json() {
        let quote = vec![0xabu8; 632];
        let runtime_json =
            br#"{"user-data":"deadbeef","vm-configuration":{"console-enabled":false}}"#.to_vec();
        let evidence =
            Evidence::from_bytes_with_azure_runtime(quote.clone(), runtime_json.clone()).unwrap();

        let encoded = evidence.to_transport_string();
        let decoded = Evidence::from_transport_string(&encoded).unwrap();

        assert_eq!(decoded.raw(), quote.as_slice());
        assert_eq!(decoded.azure_runtime_data(), Some(runtime_json.as_slice()));
    }

    #[test]
    fn raw_quote_transport_stays_compatible_with_legacy_base64() {
        let quote = vec![0x42u8; 632];
        let encoded = Evidence::from_bytes(quote.clone()).unwrap().to_base64();

        let decoded = Evidence::from_transport_string(&encoded).unwrap();

        assert_eq!(decoded.raw(), quote.as_slice());
        assert_eq!(decoded.azure_runtime_data(), None);
    }
}
