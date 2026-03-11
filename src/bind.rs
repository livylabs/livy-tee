// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! High-level API for binding program inputs/outputs to a TDX attestation.
//!
//! This is the primary integration point for application developers.
//! The primitives in [`generate`], [`report`], and [`verify`] are still
//! accessible directly, but most programs need only this module.
//!
//! # Minimal example
//!
//! ```rust,no_run
//! use livy_tee::Livy;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let livy = Livy::from_env()?;
//!
//!     let input  = b"user request";
//!     let output = b"computed result";
//!
//!     let proof = livy.attest()
//!         .input(input)
//!         .output(output)
//!         .commit()
//!         .await?;
//!
//!     println!("ita_token:    {}", proof.ita_token);
//!     println!("mrtd:         {}", proof.mrtd);
//!     println!("tcb_status:   {}", proof.tcb_status);
//!     println!("payload_hash: {}", proof.payload_hash_hex());
//!
//!     assert!(proof.verify_binding(input, output));
//!     Ok(())
//! }
//! ```
//!
//! # Payload hash construction
//!
//! The 32-byte `payload_hash` embedded in our 64-byte ReportData struct is:
//! ```text
//! SHA-256( SHA-256(input) ‖ SHA-256(output) )
//! ```
//!
//! If no input or output is bound, the corresponding slot is `[0u8; 32]`.
//!
//! # Intel CLI-compatible nonce flow
//!
//! The actual REPORTDATA embedded in the DCAP quote is:
//! ```text
//! REPORTDATA = SHA-512(nonce.val ‖ nonce.iat ‖ our_64_byte_ReportData_struct)
//! ```
//!
//! The original 64-byte struct is stored in `Proof.runtime_data` (base64) and
//! sent to ITA as `runtime_data`.  ITA verifies the binding server-side.
//! External verifiers use `verify_quote` which re-checks both levels.
//!
//! # Replay protection
//!
//! For programs that process multiple requests, pass a monotonically increasing
//! counter via [`.nonce()`](AttestBuilder::nonce). The nonce is embedded in
//! REPORTDATA bytes `[48..56]` and can be checked against stored records.

use sha2::{Digest, Sha256};

use crate::{
    attest::AttestError,
    generate::binary_hash,
    report::{build_id_from_hash_hex, ReportData, REPORT_DATA_VERSION},
    verify::ita::ItaConfig,
};

/// Compute the 32-byte `payload_hash` for the given input and output bytes.
///
/// ```text
/// payload_hash = SHA-256( SHA-256(input) ‖ SHA-256(output) )
/// ```
#[must_use]
pub fn payload_hash_for(input: impl AsRef<[u8]>, output: impl AsRef<[u8]>) -> [u8; 32] {
    let ih: [u8; 32] = Sha256::digest(input.as_ref()).into();
    let oh: [u8; 32] = Sha256::digest(output.as_ref()).into();
    let mut h = Sha256::new();
    h.update(ih);
    h.update(oh);
    h.finalize().into()
}

/// Verify a raw DCAP quote (base64-encoded) against known inputs and outputs.
///
/// **No TDX hardware. No network.** Pure software — anyone can call this.
///
/// Steps performed:
/// 1. Base64-decode the quote.
/// 2. Extract REPORTDATA bytes `[568..632]` from the quote (= SHA-512 hash).
/// 3. Base64-decode `runtime_data_b64` (our 64-byte ReportData struct).
/// 4. Base64-decode `nonce_val_b64` and `nonce_iat_b64`.
/// 5. Recompute `SHA-512(nonce_val ‖ nonce_iat ‖ runtime_data)` and assert it matches step 2.
/// 6. Parse `runtime_data` bytes as [`ReportData`].
/// 7. Recompute `SHA-256(SHA-256(input) ‖ SHA-256(output))`.
/// 8. Assert the embedded `payload_hash` matches.
///
/// Returns `Ok(false)` if any binding check fails (SHA-512 mismatch, payload
/// hash mismatch).
///
/// # Errors
///
/// Returns an error if the raw quote is structurally invalid (too short,
/// wrong version, etc.) or if any base64 field cannot be decoded.
pub fn verify_quote(
    raw_quote_b64: &str,
    runtime_data_b64: &str,
    nonce_val_b64: &str,
    nonce_iat_b64: &str,
    input: impl AsRef<[u8]>,
    output: impl AsRef<[u8]>,
) -> Result<bool, crate::verify::extract::ExtractError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use sha2::Sha512;
    use crate::evidence::Evidence;

    let raw = BASE64
        .decode(raw_quote_b64.trim())
        .map_err(|_| crate::verify::extract::ExtractError::TooShort(0))?;
    let evidence = match Evidence::from_bytes(raw) {
        Ok(e) => e,
        Err(_) => return Ok(false),
    };
    let quote_rd_bytes = crate::verify::extract::extract_report_data(&evidence)?;

    let runtime_data_bytes = match BASE64.decode(runtime_data_b64.trim()) {
        Ok(b) if b.len() >= 64 => b,
        _ => return Ok(false),
    };
    let nonce_val = match BASE64.decode(nonce_val_b64.trim()) {
        Ok(b) => b,
        Err(_) => return Ok(false),
    };
    let nonce_iat = match BASE64.decode(nonce_iat_b64.trim()) {
        Ok(b) => b,
        Err(_) => return Ok(false),
    };

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
    let expected_payload = payload_hash_for(input, output);
    Ok(rd.verify_payload(&expected_payload))
}

/// Verify an ITA attestation token (JWT) against known inputs and outputs.
///
/// **No TDX hardware. No network.**
///
/// **Note:** After nonce integration, the JWT's `tdx_report_data` field contains
/// `SHA-512(nonce.val ‖ nonce.iat ‖ runtime_data)`, not the raw ReportData struct.
/// Use [`verify_quote`] with the raw quote and nonce fields for full verification.
///
/// Returns `Ok(None)` if the ITA token did not include `tdx_report_data`.
pub fn verify_token(
    ita_token: &str,
    input: impl AsRef<[u8]>,
    output: impl AsRef<[u8]>,
) -> Result<Option<bool>, crate::verify::VerifyError> {
    use crate::verify::ita::report_data_from_token;

    match report_data_from_token(ita_token)? {
        None => Ok(None),
        Some(rd) => {
            let expected = payload_hash_for(input, output);
            Ok(Some(rd.verify_payload(&expected)))
        }
    }
}

/// Livy client — the entry point for TDX-backed provenance.
///
/// Create with [`Livy::from_env`] (reads `ITA_API_KEY`) or [`Livy::new`]
/// (explicit key). Then call [`Livy::attest`] to start binding data.
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
    ///
    /// # Errors
    ///
    /// Returns an error string if the variable is missing or empty.
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
    /// Chain `.input(...)`, `.output(...)`, and `.nonce(...)` then call
    /// `.commit().await` to generate the TDX quote and ITA token.
    pub fn attest(&self) -> AttestBuilder<'_> {
        AttestBuilder {
            config: &self.config,
            input_hash: [0u8; 32],
            output_hash: [0u8; 32],
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
    input_hash: [u8; 32],
    output_hash: [u8; 32],
    nonce: u64,
}

impl<'a> AttestBuilder<'a> {
    /// Bind the program's **input** bytes.
    ///
    /// SHA-256 is computed automatically. Calling this multiple times replaces
    /// the previous input.
    pub fn input(mut self, data: impl AsRef<[u8]>) -> Self {
        self.input_hash = Sha256::digest(data.as_ref()).into();
        self
    }

    /// Bind a pre-computed SHA-256 hash of the input.
    pub fn input_hash(mut self, hash: [u8; 32]) -> Self {
        self.input_hash = hash;
        self
    }

    /// Bind the program's **output** bytes.
    ///
    /// SHA-256 is computed automatically. Calling this multiple times replaces
    /// the previous output.
    pub fn output(mut self, data: impl AsRef<[u8]>) -> Self {
        self.output_hash = Sha256::digest(data.as_ref()).into();
        self
    }

    /// Bind a pre-computed SHA-256 hash of the output.
    pub fn output_hash(mut self, hash: [u8; 32]) -> Self {
        self.output_hash = hash;
        self
    }

    /// Set a monotonically increasing nonce for replay protection.
    ///
    /// Defaults to `0`. The nonce is stored at bytes `[48..56]` of ReportData.
    pub fn nonce(mut self, n: u64) -> Self {
        self.nonce = n;
        self
    }

    /// Generate a TDX quote and obtain an ITA attestation token.
    ///
    /// # Errors
    ///
    /// Returns [`AttestError`] if quote generation fails or if the ITA call fails.
    pub async fn commit(self) -> Result<Proof, AttestError> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let payload_hash: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(self.input_hash);
            h.update(self.output_hash);
            h.finalize().into()
        };

        let binary_hash_hex = binary_hash().map_err(AttestError::Generate)?;
        let build_id = build_id_from_hash_hex(&binary_hash_hex)
            .map_err(|e| AttestError::Generate(crate::generate::GenerateError::Io(
                std::io::Error::new(std::io::ErrorKind::InvalidData, e),
            )))?;
        let rd = ReportData::new(payload_hash, build_id, REPORT_DATA_VERSION, 0, self.nonce);
        let rd_bytes = rd.to_bytes();

        let attested = crate::attest::generate_and_attest(&rd_bytes, self.config).await?;

        Ok(Proof {
            ita_token: attested.ita_token,
            mrtd: attested.mrtd,
            tcb_status: attested.tcb_status,
            raw_quote: BASE64.encode(attested.evidence.raw()),
            runtime_data: BASE64.encode(attested.runtime_data),
            verifier_nonce_val: BASE64.encode(&attested.nonce_val),
            verifier_nonce_iat: BASE64.encode(&attested.nonce_iat),
            report_data: rd,
            input_hash: self.input_hash,
            output_hash: self.output_hash,
        })
    }
}

/// A TDX attestation proof that cryptographically binds inputs + outputs to a
/// specific TEE binary execution.
///
/// # Independent verification (no Livy infrastructure)
///
/// 1. Call [`verify_quote`] with `raw_quote`, `runtime_data`, `verifier_nonce_val`,
///    `verifier_nonce_iat`, and the original input/output bytes.
/// 2. Verify the ITA JWT signature against Intel's JWKS endpoint.
#[derive(Debug, Clone)]
pub struct Proof {
    /// ITA-signed JWT.
    pub ita_token: String,
    /// Hex-encoded MRTD (96 chars = 48 bytes).
    pub mrtd: String,
    /// TCB status from Intel Trust Authority (`"UpToDate"`, `"OutOfDate"`, `"Revoked"`).
    pub tcb_status: String,
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
    /// SHA-256 of the input bytes (or `[0u8; 32]` if no input was bound).
    pub input_hash: [u8; 32],
    /// SHA-256 of the output bytes (or `[0u8; 32]` if no output was bound).
    pub output_hash: [u8; 32],
}

impl Proof {
    /// Hex-encoded 32-byte `payload_hash`.
    #[must_use]
    pub fn payload_hash_hex(&self) -> String {
        hex::encode(self.report_data.payload_hash)
    }

    /// Re-verify that the payload hash covers the given input and output.
    #[must_use]
    pub fn verify_binding(&self, input: impl AsRef<[u8]>, output: impl AsRef<[u8]>) -> bool {
        let ih: [u8; 32] = Sha256::digest(input.as_ref()).into();
        let oh: [u8; 32] = Sha256::digest(output.as_ref()).into();
        let expected: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(ih);
            h.update(oh);
            h.finalize().into()
        };
        self.report_data.verify_payload(&expected)
    }
}
