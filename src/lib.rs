// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#![warn(missing_docs, missing_debug_implementations, unreachable_pub)]
#![deny(unsafe_code)]
//! Intel TDX attestation primitives and the Livy high-level API.
//!
//! Most applications use [`Livy`], [`AttestBuilder`], and [`Attestation`].
//! Lower-level modules stay public for
//! custom generation, parsing, and verification flows.
//!
//! # Features
//!
//! | Feature      | Default | Description |
//! |--------------|---------|-------------|
//! | *(none)*     | yes     | Runtime provider auto-detection: TSM configfs or Azure vTPM/paravisor |
//! | `mock-tee`   | no      | Correctly-shaped 632-byte stub — no hardware required |
//! | `ita-verify` | no      | Intel Trust Authority REST API verification |

mod cloud;
mod evidence;
mod generate;
mod parser;
mod public_values;
mod report;
mod types;
mod verify;

#[cfg(feature = "ita-verify")]
mod attest;
#[cfg(feature = "ita-verify")]
mod bind;

// ── Core types ─────────────────────────────────────────────────────────────
pub use cloud::{detect_cloud_provider, CloudProvider};
pub use evidence::{Evidence, EvidenceError, PortableEvidence, QUOTE_MIN_LEN};
pub use parser::parse;
pub use public_values::{entry_hash, PublicValues, PublicValuesError};
pub use report::{
    build_id_from_binary, build_id_from_hash_hex, BuildIdError, ReportData, REPORT_DATA_VERSION,
};
pub use types::Config;

// ── Generation ─────────────────────────────────────────────────────────────
pub use generate::{binary_hash, generate_evidence, GenerateError};

// ── Verification — local (always available) ────────────────────────────────
pub use verify::extract::{extract_mrtd, extract_report_data, ExtractError};

#[cfg(feature = "ita-verify")]
pub use verify::ita::{
    appraise_evidence_unauthenticated, default_issuer_for_jwks_url, default_jwks_url_for_api_url,
    get_nonce, ItaConfig, UnauthenticatedAppraisalClaims, VerifierNonce,
};
#[cfg(feature = "ita-verify")]
pub use verify::VerifyError;

#[cfg(feature = "ita-verify")]
pub use attest::{generate_and_attest, AttestError, AttestedEvidence};

#[cfg(feature = "ita-verify")]
pub use bind::{
    verify_quote, verify_quote_with_public_values, AttestBuilder, Attestation,
    AttestationVerification, AttestationVerificationPolicy, Livy, LivyEnvError,
};

#[cfg(feature = "ita-verify")]
pub use verify::ita::unauthenticated_report_data_hash_from_token;
