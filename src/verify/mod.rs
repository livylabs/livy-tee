// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! TDX evidence verification.
//!
//! Two levels:
//!   - **Local** (`extract`): parse raw quote bytes to extract fields.
//!     Always available, no network required.
//!   - **ITA** (`ita`, feature = `ita-verify`): POST to Intel Trust Authority
//!     for full hardware chain verification.

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
    /// The attestation object itself is malformed.
    #[error("invalid attestation: {0}")]
    InvalidAttestation(String),
    /// The stored low-level evidence artifact is malformed or incomplete.
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
