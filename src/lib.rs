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
pub mod public_values;
pub mod report;
pub mod verify;

#[cfg(feature = "ita-verify")]
pub mod attest;
#[cfg(feature = "ita-verify")]
pub mod bind;

pub use evidence::Evidence;
pub use evidence::EvidenceError;
pub use public_values::{entry_hash, PublicValues, PublicValuesError};
pub use report::{build_id_from_binary, build_id_from_hash_hex, ReportData, REPORT_DATA_VERSION};
pub use generate::{binary_hash, generate_evidence, GenerateError};

pub use verify::extract::{extract_mrtd, extract_report_data, ExtractError};

#[cfg(feature = "ita-verify")]
pub use verify::ita::{get_nonce, verify_evidence, ItaConfig, VerifiedClaims, VerifierNonce};
#[cfg(feature = "ita-verify")]
pub use verify::VerifyError;

#[cfg(feature = "ita-verify")]
pub use attest::{generate_and_attest, AttestedEvidence, AttestError};

#[cfg(feature = "ita-verify")]
pub use bind::{payload_hash_for, verify_quote, verify_token, AttestBuilder, Livy, Proof};

#[cfg(feature = "ita-verify")]
pub use verify::ita::report_data_from_token;
