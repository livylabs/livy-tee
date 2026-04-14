// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! High-level API for binding arbitrary public values to a TDX attestation.
//!
//! This is the primary integration point for application developers.
//! The primitives in [`generate`], [`report`], and [`verify`] are still
//! accessible directly, but most programs need only this module.
//!
//! # Commit / read model
//!
//! Inspired by zkVM journal semantics (e.g. SP1's `env::commit`), the API
//! lets TEE code commit arbitrary typed values as public outputs.  Verifiers
//! read them back in order and constrain each one independently.
//!
//! ```rust,ignore
//! // ── TEE side ──────────────────────────────────────────
//! let livy = Livy::from_env()?;
//! let mut builder = livy.attest();
//!
//! // Only commit data that is intended to be public — values are stored in
//! // plain text and are readable by anyone who receives the attestation.
//! // For sensitive inputs, commit a hash: builder.commit_hashed(&sensitive_value)
//! builder.commit(&content_hash);
//! builder.commit(&identity_pubkey);
//! builder.commit(&device_binding);
//! builder.nonce(counter);
//!
//! let attestation = builder.finalize().await?;
//!
//! // ── Verifier side (anyone, anywhere) ──────────────────
//! let hash: [u8; 32]  = attestation.public_values.read()?;
//! let pubkey: String   = attestation.public_values.read()?;
//! let binding: [u8;32] = attestation.public_values.read()?;
//!
//! assert_eq!(hash, sha256(&original_photo));
//! // Strict attestation check: JWT/JWKS, TCB policy, public-value binding,
//! // and fresh ITA appraisal of the bundled evidence artifact.
//! let report = attestation.verify_fresh(&config).await?;
//! assert!(report.all_passed());
//! ```
//!
//! # REPORTDATA binding
//!
//! `REPORTDATA[0..32]` = `SHA-256(public_values buffer)`.  The full buffer
//! travels alongside the attestation so verifiers can reconstruct the commitment.
//!
//! # Note on terminology
//!
//! This is a hardware **attestation**, not a cryptographic proof.  Security
//! relies on trusting Intel TDX hardware and its signing keys — not on
//! mathematical hardness assumptions.  The commit/read API borrows from zkVM
//! ergonomics but the trust model is fundamentally different.
//!
//! # Replay protection
//!
//! Pass a monotonically increasing counter via [`AttestBuilder::nonce`].
//! The nonce is embedded in REPORTDATA bytes `[48..56]`.

mod attestation;
mod local;

pub use attestation::{
    AttestBuilder, Attestation, AttestationVerification, AttestationVerificationPolicy, Livy,
    LivyEnvError,
};
pub use local::{verify_quote, verify_quote_with_public_values};
