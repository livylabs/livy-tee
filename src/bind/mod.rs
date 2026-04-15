// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! High-level attestation API.
//!
//! Most applications use [`Livy`], [`AttestBuilder`], and [`Attestation`].
//! Commit public values, finalize the attestation, then verify it with
//! [`Attestation::verify`] or [`Attestation::verify_fresh`].
//!
//! Committed values are public. Use [`AttestBuilder::commit_hashed`] when a
//! value should be bound by hash rather than stored in plain text.

mod attestation;
mod local;

pub use attestation::{
    AttestBuilder, Attestation, AttestationVerification, AttestationVerificationPolicy, Livy,
    LivyEnvError,
};
pub use local::{verify_quote, verify_quote_with_public_values};
