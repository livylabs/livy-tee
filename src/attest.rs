// SPDX-License-Identifier: MIT
//! Combined evidence generation and ITA appraisal.
//!
//! Most applications use [`crate::Livy`] and [`crate::AttestBuilder`]. This is
//! the lower-level helper behind that flow.
//!
//! In hardware mode it fetches a verifier nonce, hashes it into the quote
//! binding value, generates evidence, and appraises that evidence with ITA. In
//! `mock-tee` mode it returns stub evidence and skips the ITA call.

use crate::{
    error::AttestError, evidence::Evidence, generate::generate_evidence, verify::ita::ItaConfig,
};

#[cfg(not(feature = "mock-tee"))]
use crate::verify::ita::{appraise_evidence_authenticated, get_nonce};

/// Output of a combined quote generation and ITA appraisal call.
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

/// Generate evidence and appraise it with Intel Trust Authority.
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
        let (raw_token, claims) = appraise_evidence_authenticated(
            &evidence,
            config,
            user_data,
            &nonce,
            &config.default_jwks_url(),
            config.expected_token_issuer(),
            config.expected_token_audience.clone(),
        )
        .await?;
        Ok(AttestedEvidence {
            evidence,
            ita_token: raw_token,
            mrtd: claims.mrtd().to_string(),
            tcb_status: claims.tcb_status().to_string(),
            tcb_date: claims.tcb_date().map(str::to_string),
            advisory_ids: claims.advisory_ids().to_vec(),
            runtime_data: *user_data,
            nonce_val,
            nonce_iat,
            nonce_signature,
        })
    }
}
