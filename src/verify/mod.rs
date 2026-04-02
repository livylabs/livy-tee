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
pub(crate) mod ita;

#[cfg(feature = "ita-verify")]
use thiserror::Error;

/// Errors returned by Intel Trust Authority verification calls.
#[cfg(feature = "ita-verify")]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// Network error during communication with Intel Trust Authority.
    #[error("network error: {0}")]
    Network(String),
    /// Intel Trust Authority API returned an error response.
    #[error("ITA API error: {0}")]
    ItaApi(String),
    /// Failed to parse the ITA attestation token (JWT).
    #[error("JWT parse error: {0}")]
    JwtParse(String),
}
