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
//! let hash: [u8; 32]  = attestation.public_values.read();
//! let pubkey: String   = attestation.public_values.read();
//! let binding: [u8;32] = attestation.public_values.read();
//!
//! assert_eq!(hash, sha256(&original_photo));
//! // Full chain: verifies the public values are bound to the TDX hardware quote.
//! assert!(attestation.verify().unwrap());
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

use serde::Serialize;

use crate::{
    attest::AttestError,
    generate::binary_hash,
    public_values::PublicValues,
    report::{build_id_from_hash_hex, ReportData, REPORT_DATA_VERSION},
    verify::ita::ItaConfig,
};

/// Verify a raw DCAP quote's ITA nonce binding and an expected `payload_hash`.
///
/// **No TDX hardware. No network.** Pure software — anyone can call this.
///
/// Checks:
/// 1. `SHA-512(nonce_val ‖ nonce_iat ‖ runtime_data) == REPORTDATA` in the quote.
/// 2. `ReportData.payload_hash == expected_payload_hash`.
///
/// Use this when you built the `payload_hash` yourself with the low-level API
/// (e.g. `SHA-256(your_inputs)`) rather than through a [`PublicValues`] buffer.
/// For the high-level commit/read model, use [`verify_quote_with_public_values`]
/// or [`Attestation::verify`] instead.
pub fn verify_quote(
    raw_quote_b64: &str,
    runtime_data_b64: &str,
    nonce_val_b64: &str,
    nonce_iat_b64: &str,
    expected_payload_hash: &[u8; 32],
) -> Result<bool, crate::verify::extract::ExtractError> {
    use crate::evidence::Evidence;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use sha2::{Digest, Sha512};

    let raw = BASE64
        .decode(raw_quote_b64.trim())
        .map_err(|_| crate::verify::extract::ExtractError::TooShort(0))?;
    let raw_len = raw.len();
    let evidence = Evidence::from_bytes(raw)
        .map_err(|_| crate::verify::extract::ExtractError::TooShort(raw_len))?;
    let quote_rd_bytes = crate::verify::extract::extract_report_data(&evidence)?;

    let runtime_data_bytes = BASE64
        .decode(runtime_data_b64.trim())
        .map_err(|_| crate::verify::extract::ExtractError::TooShort(0))?;
    if runtime_data_bytes.len() < 64 {
        return Err(crate::verify::extract::ExtractError::TooShort(
            runtime_data_bytes.len(),
        ));
    }
    let nonce_val = BASE64
        .decode(nonce_val_b64.trim())
        .map_err(|_| crate::verify::extract::ExtractError::TooShort(0))?;
    let nonce_iat = BASE64
        .decode(nonce_iat_b64.trim())
        .map_err(|_| crate::verify::extract::ExtractError::TooShort(0))?;

    let expected_rd: [u8; 64] = {
        let mut h = Sha512::new();
        h.update(&nonce_val);
        h.update(&nonce_iat);
        h.update(&runtime_data_bytes[..64]);
        let hash = h.finalize();
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&hash);
        arr
    };
    if quote_rd_bytes != expected_rd {
        return Ok(false);
    }

    let mut rd_arr = [0u8; 64];
    rd_arr.copy_from_slice(&runtime_data_bytes[..64]);
    let rd = ReportData::from_bytes(&rd_arr);
    Ok(rd.verify_payload(expected_payload_hash))
}

/// Verify a raw DCAP quote against a [`PublicValues`] buffer.
///
/// **No TDX hardware. No network.** Pure software — anyone can call this.
///
/// Checks:
/// 1. `SHA-512(nonce_val ‖ nonce_iat ‖ runtime_data) == REPORTDATA` in the quote.
/// 2. `SHA-256(public_values.buffer) == ReportData.payload_hash` in runtime_data.
///
/// This is the high-level counterpart to [`verify_quote`]: it computes the
/// `payload_hash` automatically from the `PublicValues` buffer rather than
/// requiring you to supply it directly.
pub fn verify_quote_with_public_values(
    raw_quote_b64: &str,
    runtime_data_b64: &str,
    nonce_val_b64: &str,
    nonce_iat_b64: &str,
    public_values: &PublicValues,
) -> Result<bool, crate::verify::extract::ExtractError> {
    let hash = public_values.commitment_hash();
    verify_quote(
        raw_quote_b64,
        runtime_data_b64,
        nonce_val_b64,
        nonce_iat_b64,
        &hash,
    )
}

/// Livy client — the entry point for TDX-backed attestation.
///
/// Create with [`Livy::from_env`] (reads `ITA_API_KEY`) or [`Livy::new`]
/// (explicit key). Then call [`Livy::attest`] to start committing values.
#[derive(Debug, Clone)]
pub struct Livy {
    config: ItaConfig,
}

impl Livy {
    /// Create a Livy client from an explicit API key.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            config: ItaConfig {
                api_key: api_key.into(),
                ..ItaConfig::default()
            },
        }
    }

    /// Create a Livy client from an explicit [`ItaConfig`].
    pub fn with_config(config: ItaConfig) -> Self {
        Self { config }
    }

    /// Create a Livy client by reading `ITA_API_KEY` from the environment.
    pub fn from_env() -> Result<Self, String> {
        let key = std::env::var("ITA_API_KEY")
            .map_err(|_| "ITA_API_KEY environment variable is not set".to_string())?;
        if key.is_empty() {
            return Err("ITA_API_KEY is empty".to_string());
        }
        Ok(Self::new(key))
    }

    /// Start building an attestation.
    ///
    /// Use `.commit(...)` to add public values, `.nonce(...)` for replay
    /// protection, then `.finalize().await` to generate the attestation.
    pub fn attest(&self) -> AttestBuilder<'_> {
        AttestBuilder {
            config: &self.config,
            public_values: PublicValues::new(),
            nonce: 0,
        }
    }
}

/// Builder for a single TDX attestation.
///
/// Obtained from [`Livy::attest`].
#[derive(Debug, Clone)]
pub struct AttestBuilder<'a> {
    config: &'a ItaConfig,
    public_values: PublicValues,
    nonce: u64,
}

impl<'a> AttestBuilder<'a> {
    /// Commit a typed value as a public output.
    ///
    /// Values are read back in commit order by the verifier via
    /// `attestation.public_values.read::<T>()`.
    ///
    /// **Privacy notice:** the committed value is stored in plain text and is
    /// readable by any party who receives the attestation. Only commit data that
    /// is intended to be public. For sensitive values, use
    /// [`commit_hashed`](Self::commit_hashed) to store a SHA-256 hash instead.
    pub fn commit<T: Serialize>(&mut self, value: &T) -> &mut Self {
        self.public_values.commit(value);
        self
    }

    /// Commit the SHA-256 hash of a serialized value instead of the value itself.
    ///
    /// Use this for sensitive data that must be bound to the attestation without
    /// revealing the raw content. The 32-byte hash is stored in the public values
    /// buffer; the original value is never included.
    ///
    /// To verify: the verifier independently serializes the same value with
    /// `serde_json` and checks that `SHA-256(serialized)` matches what is read
    /// back from `public_values`.
    pub fn commit_hashed<T: Serialize>(&mut self, value: &T) -> &mut Self {
        use sha2::{Digest, Sha256};
        let encoded =
            serde_json::to_vec(value).expect("commit_hashed: serialization should not fail");
        let hash: [u8; 32] = Sha256::digest(&encoded).into();
        self.public_values.commit_raw(&hash);
        self
    }

    /// Commit raw bytes as a public output (no serialization wrapper).
    pub fn commit_raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.public_values.commit_raw(bytes);
        self
    }

    /// Set a monotonically increasing nonce for replay protection.
    ///
    /// Defaults to `0`. The nonce is stored at bytes `[48..56]` of ReportData.
    pub fn nonce(&mut self, n: u64) -> &mut Self {
        self.nonce = n;
        self
    }

    /// Generate a TDX quote and obtain an ITA attestation token.
    ///
    /// The attestation's `public_values` contains all committed values in plain
    /// text. Any party with the attestation can read them. Commit only public
    /// data or pre-hash sensitive values with [`commit_hashed`](Self::commit_hashed).
    ///
    /// `REPORTDATA[0..32]` = `SHA-256(public_values buffer)`.
    pub async fn finalize(self) -> Result<Attestation, AttestError> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let payload_hash = self.public_values.commitment_hash();

        let binary_hash_hex = binary_hash().map_err(AttestError::Generate)?;
        let build_id = build_id_from_hash_hex(&binary_hash_hex);
        let rd = ReportData::new(payload_hash, build_id, REPORT_DATA_VERSION, 0, self.nonce);
        let rd_bytes = rd.to_bytes();

        let attested = crate::attest::generate_and_attest(&rd_bytes, self.config).await?;

        Ok(Attestation {
            ita_token: attested.ita_token,
            mrtd: attested.mrtd,
            tcb_status: attested.tcb_status,
            tcb_date: attested.tcb_date,
            raw_quote: BASE64.encode(attested.evidence.raw()),
            runtime_data: BASE64.encode(attested.runtime_data),
            verifier_nonce_val: BASE64.encode(&attested.nonce_val),
            verifier_nonce_iat: BASE64.encode(&attested.nonce_iat),
            report_data: rd,
            public_values: self.public_values,
        })
    }
}

/// A TDX hardware attestation with inspectable public values.
///
/// This is a hardware attestation backed by Intel TDX — not a cryptographic
/// proof.  Security relies on trusting the TDX hardware and Intel's signing
/// keys.  The public values buffer is committed into `REPORTDATA[0..32]`
/// via `SHA-256(buffer)` and can be verified by anyone with the raw quote.
///
/// **Privacy:** all committed values are stored in plain text inside
/// `public_values`. Do not commit sensitive data — use
/// [`AttestBuilder::commit_hashed`] to bind a value by its hash instead.
///
/// # Verification (no Livy infrastructure)
///
/// ```rust,ignore
/// // 1. Read and constrain individual values.
/// let hash: [u8; 32] = attestation.public_values.read();
/// assert_eq!(hash, expected);
///
/// // 2. Full chain: verify the public values are bound to the TDX quote.
/// //    Checks SHA-512(nonces ‖ runtime_data) == quote REPORTDATA AND
/// //    SHA-256(public_values) == report_data.payload_hash.
/// assert!(attestation.verify().unwrap());
/// ```
///
/// # Cross-language verification
///
/// The `public_values` buffer uses `serde_json` for entry serialization
/// (length-prefixed JSON).  Verifiers in other languages must use the raw
/// buffer bytes to recompute `SHA-256(buffer)` — they do NOT need to
/// re-serialize values.  The buffer travels alongside the attestation as
/// an opaque byte sequence.
#[derive(Debug, Clone)]
pub struct Attestation {
    /// ITA-signed JWT.
    pub ita_token: String,
    /// Hex-encoded MRTD (96 chars = 48 bytes).
    pub mrtd: String,
    /// TCB status from Intel Trust Authority.
    pub tcb_status: String,
    /// Optional TCB assessment date from Intel Trust Authority claims.
    pub tcb_date: Option<String>,
    /// Base64-encoded raw DCAP quote.
    pub raw_quote: String,
    /// Base64-encoded original 64-byte ReportData struct.
    pub runtime_data: String,
    /// Base64-encoded verifier nonce value bytes.
    pub verifier_nonce_val: String,
    /// Base64-encoded verifier nonce issued-at bytes.
    pub verifier_nonce_iat: String,
    /// Structured REPORTDATA parsed from `runtime_data`.
    pub report_data: ReportData,
    /// The committed public values — read with `.public_values.read::<T>()`.
    pub public_values: PublicValues,
}

impl Attestation {
    /// Hex-encoded 32-byte commitment hash.
    #[must_use]
    pub fn payload_hash_hex(&self) -> String {
        hex::encode(self.report_data.payload_hash)
    }

    /// Verify the full attestation chain.
    ///
    /// Performs two checks in sequence:
    /// 1. `SHA-512(nonce_val ‖ nonce_iat ‖ runtime_data) == REPORTDATA` in the TDX quote.
    /// 2. `SHA-256(public_values buffer) == ReportData.payload_hash` in runtime_data.
    ///
    /// Both checks must pass. This confirms the public values are cryptographically
    /// bound to the hardware-signed quote — not merely locally self-consistent.
    ///
    /// This is the correct verification step for callers. For the narrow
    /// self-consistency check only (no quote binding), see
    /// [`verify_public_values_commitment`](Self::verify_public_values_commitment).
    pub fn verify(&self) -> Result<bool, crate::verify::extract::ExtractError> {
        verify_quote_with_public_values(
            &self.raw_quote,
            &self.runtime_data,
            &self.verifier_nonce_val,
            &self.verifier_nonce_iat,
            &self.public_values,
        )
    }

    /// Check that `SHA-256(public_values)` matches `report_data.payload_hash`.
    ///
    /// This is a **local self-consistency** check only. It confirms the public
    /// values buffer has not been tampered with relative to the `payload_hash`
    /// stored in `report_data`, but it does **not** verify that `report_data`
    /// is bound to the raw TDX quote via the verifier nonces.
    ///
    /// A forged `Attestation` where both `public_values` and `report_data` were
    /// replaced together will pass this check while the TDX quote attests to
    /// something else entirely.
    ///
    /// Use [`verify`](Self::verify) for full chain verification.
    #[must_use]
    pub fn verify_public_values_commitment(&self) -> bool {
        self.public_values
            .verify_commitment(&self.report_data.payload_hash)
    }
}
