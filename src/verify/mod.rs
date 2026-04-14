// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! TDX evidence verification.
//!
//! Two levels:
//!   - **Local** (`extract`): parse raw quote bytes to extract fields.
//!     Always available, no network required.
//!   - **ITA** (`ita`, feature = `ita-verify`): POST to Intel Trust Authority
//!     for server-side appraisal. Public helpers that only parse the returned
//!     JWT are explicitly named `*_unauthenticated`; stored-token verification
//!     validates the JWT first.

pub(crate) mod extract;

#[cfg(feature = "ita-verify")]
pub(crate) mod codec;

#[cfg(feature = "ita-verify")]
pub(crate) mod ita;

#[cfg(feature = "ita-verify")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "ita-verify")]
use thiserror::Error;

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
