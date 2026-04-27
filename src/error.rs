// SPDX-License-Identifier: MIT
//! Shared public error types for the crate.

use crate::evidence::QUOTE_MIN_LEN;
#[cfg(feature = "ita-verify")]
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors returned when constructing or decoding [`crate::Evidence`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EvidenceError {
    /// Quote bytes could not be decoded from base64.
    #[error("base64 decode failed: {0}")]
    Base64(String),
    /// Quote is shorter than the minimum valid DCAP quote size (632 bytes).
    #[error("quote too short: {0} bytes (minimum 632)")]
    TooShort(usize),
    /// Portable evidence JSON could not be parsed.
    #[error("portable evidence format error: {0}")]
    PortableFormat(String),
}

/// Errors returned by [`crate::generate_evidence`] and [`crate::binary_hash`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GenerateError {
    /// TSM configfs mount is not present; TDX hardware or kernel driver required.
    #[error("TSM configfs not available at /sys/kernel/config/tsm/report")]
    TsmNotAvailable,
    /// I/O error during configfs read/write.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Failed to read the current executable binary from disk.
    #[error("failed to read binary for hash: {0}")]
    BinaryRead(std::io::Error),
    /// Azure adapter prerequisites are missing.
    #[error("Azure quote adapter prerequisite missing: {0}")]
    AzurePrerequisite(String),
    /// Azure quote adapter command failed.
    #[error("Azure quote adapter command failed: {0}")]
    AzureCommand(String),
    /// Azure vTPM returned a TPM response code.
    #[error("Azure vTPM command failed with response code 0x{0:08x}")]
    AzureTpmResponseCode(u32),
    /// Azure runtime data returned by vTPM is malformed.
    #[error("Azure runtime data is invalid: {0}")]
    AzureRuntime(String),
    /// Azure local quote endpoint returned an invalid response.
    #[error("Azure quote endpoint response is invalid: {0}")]
    AzureQuoteResponse(String),
}

impl GenerateError {
    /// Stable machine-readable error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::TsmNotAvailable => "tsm_not_available",
            Self::Io(_) => "io",
            Self::BinaryRead(_) => "binary_read",
            Self::AzurePrerequisite(_) => "azure_prerequisite",
            Self::AzureCommand(_) => "azure_command",
            Self::AzureTpmResponseCode(_) => "azure_tpm_response_code",
            Self::AzureRuntime(_) => "azure_runtime",
            Self::AzureQuoteResponse(_) => "azure_quote_response",
        }
    }
}

/// Errors returned by [`crate::extract_report_data`] and [`crate::extract_mrtd`].
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

/// Errors when reading from [`crate::PublicValues`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PublicValuesError {
    /// Base64 decoding failed.
    #[error("failed to decode public values base64: {0}")]
    Base64(String),
    /// Serializing a committed value failed.
    #[error("failed to serialize public value: {0}")]
    Serialize(String),
    /// A committed payload is too large for the 32-bit wire-format length prefix.
    #[error("public value is too large for the wire format: {0} bytes")]
    EntryTooLarge(usize),
    /// The buffer has no more complete entries to read.
    #[error("public values buffer exhausted — no more entries to read")]
    BufferExhausted,
    /// A trailing fragment does not contain a full 4-byte length prefix.
    #[error(
        "public values buffer has {remaining} trailing byte(s) at offset {offset}; expected a 4-byte length prefix"
    )]
    TruncatedLengthPrefix {
        /// Byte offset where the incomplete length prefix starts.
        offset: usize,
        /// Number of bytes remaining from that offset to the end of the buffer.
        remaining: usize,
    },
    /// An entry declares more payload bytes than remain in the buffer.
    #[error(
        "public values entry at offset {offset} declares {declared_len} payload byte(s), but only {remaining} remain"
    )]
    TruncatedEntryPayload {
        /// Byte offset where the entry's 4-byte length prefix starts.
        offset: usize,
        /// Payload length declared by the entry's length prefix.
        declared_len: usize,
        /// Payload bytes still available after the 4-byte length prefix.
        remaining: usize,
    },
    /// A value could not be deserialized from the buffer.
    #[error("failed to deserialize public value: {0}")]
    Deserialize(String),
}

/// Errors returned by [`crate::build_id_from_hash_hex`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum BuildIdError {
    /// The provided hash was shorter than the required 16 hex characters.
    #[error("hash hex too short: need at least 16 hex chars, got {0}")]
    TooShort(usize),
    /// The first 16 characters were not valid hex.
    #[error("hash hex is not valid: {0}")]
    InvalidHex(String),
}

/// Errors returned by Intel Trust Authority verification calls.
#[cfg(feature = "ita-verify")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// Network error during communication with Intel Trust Authority.
    #[error("network error: {0}")]
    Network(String),
    /// Local verifier configuration is invalid.
    #[error("invalid verifier configuration: {0}")]
    InvalidConfiguration(String),
    /// Intel Trust Authority API returned an error response.
    #[error("ITA API error: {0}")]
    ItaApi(String),
    /// The high-level [`crate::Attestation`] artifact itself is malformed.
    ///
    /// This variant is emitted by the high-level attestation verification flow
    /// when locally stored fields such as `raw_quote`, `runtime_data`, or the
    /// verifier nonce encodings cannot be decoded or do not have the expected
    /// shape. Low-level ITA appraisal helpers do not construct this variant.
    #[error("invalid attestation: {0}")]
    InvalidAttestation(String),
    /// The stored low-level evidence artifact is malformed or incomplete.
    ///
    /// This variant is emitted by the high-level [`crate::Attestation`] flow
    /// when replaying or reappraising bundled evidence. Low-level ITA network
    /// calls do not construct this variant unless they are explicitly given a
    /// malformed transport artifact from the caller.
    #[error("invalid stored evidence: {0}")]
    InvalidStoredEvidence(String),
    /// The ITA token or JWKS validation step failed.
    #[error("invalid ITA token: {0}")]
    InvalidToken(String),
    /// The ITA token claims are present but semantically invalid.
    #[error("invalid ITA token claims: {0}")]
    InvalidTokenClaims(String),
}

#[cfg(feature = "ita-verify")]
impl VerifyError {
    /// Stable machine-readable error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Network(_) => "network",
            Self::InvalidConfiguration(_) => "invalid_configuration",
            Self::ItaApi(_) => "ita_api",
            Self::InvalidAttestation(_) => "invalid_attestation",
            Self::InvalidStoredEvidence(_) => "invalid_stored_evidence",
            Self::InvalidToken(_) => "invalid_token",
            Self::InvalidTokenClaims(_) => "invalid_token_claims",
        }
    }
}

/// Error type for [`crate::generate_and_attest`].
#[cfg(feature = "ita-verify")]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AttestError {
    /// Preparing committed public values failed.
    #[error("public values commit failed: {0}")]
    PublicValues(#[from] PublicValuesError),
    /// Quote generation failed.
    #[error("quote generation failed: {0}")]
    Generate(#[from] GenerateError),
    /// Deriving the REPORTDATA build ID failed.
    #[error("failed to derive build ID: {0}")]
    BuildId(#[from] BuildIdError),
    /// ITA verification call failed.
    #[error("ITA verification failed: {0}")]
    Verify(#[from] VerifyError),
}

#[cfg(feature = "ita-verify")]
impl AttestError {
    /// Stable machine-readable error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::PublicValues(_) => "public_values",
            Self::Generate(err) => err.code(),
            Self::BuildId(_) => "build_id",
            Self::Verify(err) => err.code(),
        }
    }
}

/// Errors returned by [`crate::Livy::from_env`].
#[cfg(feature = "ita-verify")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[non_exhaustive]
pub enum LivyEnvError {
    /// `ITA_API_KEY` is not present in the environment.
    #[error("ITA_API_KEY environment variable is not set")]
    MissingApiKey,
    /// `ITA_API_KEY` is present but empty after trimming whitespace.
    #[error("ITA_API_KEY is empty")]
    EmptyApiKey,
}
