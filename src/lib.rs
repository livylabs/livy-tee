// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#![warn(missing_docs, missing_debug_implementations, unreachable_pub)]
#![deny(unsafe_code)]
//! Intel TDX quote generation and verification.
//!
//! A TDX quote cryptographically binds:
//!   { MRTD (TEE binary hash), RTMRs, report_data (our payload hash) }
//!
//! Anyone can verify the quote against Intel's Trust Authority to confirm that
//! specific code ran inside a genuine TDX Trust Domain.  This is the hardware
//! root of trust for all Livy provenance claims.
//!
//! # Feature flags
//!
//! | Feature      | Default | Description |
//! |--------------|---------|-------------|
//! | *(none)*     | yes     | TSM configfs generation — requires TDX hardware (kernel ≥ 6.7) |
//! | `mock-tee`   | no      | Correctly-shaped 632-byte stub — no hardware required |
//! | `ita-verify` | no      | Intel Trust Authority REST API verification |

pub mod evidence;
pub mod generate;
mod parser;
pub mod public_values;
pub mod report;
mod types;
pub mod verify;

#[cfg(feature = "ita-verify")]
mod attest;
#[cfg(feature = "ita-verify")]
mod bind;

// ── Core types ─────────────────────────────────────────────────────────────
pub use evidence::{Evidence, EvidenceError};
pub use parser::parse;
pub use public_values::{entry_hash, PublicValues, PublicValuesError};
pub use report::{
    build_id_from_binary, build_id_from_hash_hex, ReportData, REPORT_DATA_VERSION,
};
pub use types::Config;

// ── Generation ─────────────────────────────────────────────────────────────
pub use generate::{binary_hash, generate_evidence, GenerateError};

// ── Verification — local (always available) ────────────────────────────────
pub use verify::extract::{extract_mrtd, extract_report_data, ExtractError};

#[cfg(feature = "ita-verify")]
pub use verify::ita::{get_nonce, verify_evidence, ItaConfig, VerifiedClaims, VerifierNonce};
#[cfg(feature = "ita-verify")]
pub use verify::VerifyError;

#[cfg(feature = "ita-verify")]
pub use attest::{generate_and_attest, AttestedEvidence, AttestError};

#[cfg(feature = "ita-verify")]
pub use bind::{verify_quote, verify_quote_with_public_values, Attestation, AttestBuilder, Livy};

#[cfg(feature = "ita-verify")]
pub use verify::ita::report_data_from_token;
