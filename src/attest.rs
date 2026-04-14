// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Combined evidence generation + Intel Trust Authority attestation.
//!
//! # Why two steps?
//!
//! TDX attestation is fundamentally a two-phase operation:
//!
//! 1. **Generate** — write REPORTDATA to `/sys/kernel/config/tsm/report/`; the
//!    kernel's TDX guest driver asks the hardware to produce a DCAP quote and
//!    writes the raw bytes back.  This is entirely local; no network required.
//!
//! 2. **Verify** — send the raw quote to Intel Trust Authority (ITA), which
//!    checks the full DCAP certificate chain (PCK → Intermediate CA → Intel CA)
//!    and returns a short, signed JWT (the "attestation token").  The JWT
//!    contains the MRTD, REPORTDATA, and TCB status, signed by Intel's key.
//!
//! # Intel CLI-compatible nonce flow
//!
//! Before generating the quote, a verifier nonce is fetched from ITA to prevent
//! quote relay attacks.  The actual bytes written to TSM configfs are:
//! `SHA-512(nonce.val ‖ nonce.iat ‖ user_data)`
//!
//! The original `user_data` (our structured 64-byte ReportData) is sent to ITA
//! as `runtime_data`.  ITA verifies the binding server-side.
//!
//! # `mock-tee` mode
//!
//! When compiled with `--features mock-tee`, the hardware step is replaced by
//! a correctly-shaped 632-byte stub.  ITA would reject this stub, so
//! `generate_and_attest` skips the ITA call and returns an empty `ita_token`.
//! The nonce fields are zeroed (no network call).

use crate::{
    evidence::Evidence,
    generate::{generate_evidence, GenerateError},
    report::BuildIdError,
    verify::{ita::ItaConfig, VerifyError},
};

#[cfg(not(feature = "mock-tee"))]
use crate::verify::ita::{appraise_evidence_unauthenticated, get_nonce};
use thiserror::Error;

/// Output of a combined TDX quote generation + ITA attestation call.
///
/// In `mock-tee` mode, `ita_token`, `mrtd`, and `tcb_status` are empty,
/// and nonce fields are zeroed.
#[derive(Debug)]
pub struct AttestedEvidence {
    /// Raw DCAP quote bytes (from TSM configfs or mock).
    pub evidence: Evidence,
    /// ITA-signed JWT. Empty in `mock-tee` mode.
    pub ita_token: String,
    /// MRTD extracted from the ITA JWT. Empty in `mock-tee` mode.
    pub mrtd: String,
    /// TCB evaluation status. Empty in `mock-tee` mode.
    pub tcb_status: String,
    /// Optional TCB evaluation date (RFC3339 date-time from ITA token claims).
    pub tcb_date: Option<String>,
    /// Advisory IDs reported by Intel Trust Authority. Empty in `mock-tee` mode.
    pub advisory_ids: Vec<String>,
    /// The original 64-byte runtime_data (our ReportData struct).
    pub runtime_data: [u8; 64],
    /// Decoded verifier nonce value bytes. Zeroed in `mock-tee` mode.
    pub nonce_val: Vec<u8>,
    /// Decoded verifier nonce issued-at bytes. Zeroed in `mock-tee` mode.
    pub nonce_iat: Vec<u8>,
    /// Decoded verifier nonce signature bytes. Zeroed in `mock-tee` mode.
    pub nonce_signature: Vec<u8>,
}

/// Error type for [`generate_and_attest`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AttestError {
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

impl AttestError {
    /// Stable machine-readable error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Generate(err) => err.code(),
            Self::BuildId(_) => "build_id",
            Self::Verify(err) => err.code(),
        }
    }
}

/// Generate a TDX quote and verify it with Intel Trust Authority (Intel CLI-compatible).
///
/// In production (no `mock-tee` feature):
/// 1. Fetches a verifier nonce from ITA.
/// 2. Computes `reportdata_for_quote = SHA-512(nonce.val ‖ nonce.iat ‖ user_data)`.
/// 3. Writes to TSM configfs — hardware produces a DCAP quote.
/// 4. POSTs quote + runtime_data + nonce to ITA.
/// 5. Returns both the raw evidence and the ITA-signed JWT.
///
/// In `mock-tee` mode: uses zeroed nonces, produces a stub quote, skips ITA.
pub async fn generate_and_attest(
    user_data: &[u8; 64],
    #[cfg_attr(feature = "mock-tee", allow(unused_variables))] config: &ItaConfig,
) -> Result<AttestedEvidence, AttestError> {
    use sha2::{Digest, Sha512};

    #[cfg(feature = "mock-tee")]
    let (nonce_val, nonce_iat, nonce_signature) = (vec![0u8; 32], vec![0u8; 32], vec![]);

    #[cfg(not(feature = "mock-tee"))]
    let nonce = get_nonce(config).await?;
    #[cfg(not(feature = "mock-tee"))]
    let (nonce_val, nonce_iat, nonce_signature) = (
        nonce.val.clone(),
        nonce.iat.clone(),
        nonce.signature.clone(),
    );

    let reportdata_for_quote: [u8; 64] = {
        let mut h = Sha512::new();
        h.update(&nonce_val);
        h.update(&nonce_iat);
        h.update(user_data);
        h.finalize().into()
    };

    let evidence = generate_evidence(&reportdata_for_quote)?;

    #[cfg(feature = "mock-tee")]
    {
        Ok(AttestedEvidence {
            evidence,
            ita_token: String::new(),
            mrtd: String::new(),
            tcb_status: String::new(),
            tcb_date: None,
            advisory_ids: Vec::new(),
            runtime_data: *user_data,
            nonce_val,
            nonce_iat,
            nonce_signature,
        })
    }

    #[cfg(not(feature = "mock-tee"))]
    {
        let claims =
            appraise_evidence_unauthenticated(&evidence, config, user_data, &nonce).await?;
        Ok(AttestedEvidence {
            evidence,
            ita_token: claims.raw_token,
            mrtd: claims.mrtd,
            tcb_status: claims.tcb_status,
            tcb_date: claims.tcb_date,
            advisory_ids: claims.advisory_ids,
            runtime_data: *user_data,
            nonce_val,
            nonce_iat,
            nonce_signature,
        })
    }
}
