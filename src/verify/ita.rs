// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Intel Trust Authority (ITA) REST API verification.
//!
//! Sends the raw quote to ITA's appraisal endpoint and parses the returned JWT
//! to extract TDX claims.  ITA performs the full DCAP chain verification
//! server-side; we parse the JWT without re-verifying the signature (ITA is
//! the authoritative verifier).
//!
//! ## Attestation flow (Intel CLI-compatible)
//!
//! 1. GET  `{api_url}/appraisal/v2/nonce`  — fetch anti-replay verifier nonce
//! 2. Compute `REPORTDATA = SHA-512(nonce.val ‖ nonce.iat ‖ our_64_byte_struct)` — 64 bytes
//! 3. Generate DCAP quote with the new REPORTDATA via TSM configfs
//! 4. POST `{api_url}/appraisal/v2/attest`:
//!    ```json
//!    {
//!      "tdx": {
//!        "quote":          "<base64url-DCAP-quote>",
//!        "runtime_data":   "<base64 of our 64-byte ReportData struct>",
//!        "verifier_nonce": { "val": "...", "iat": "...", "signature": "..." }
//!      }
//!    }
//!    ```
//! 5. ITA verifies server-side: `SHA-512(nonce.val ‖ nonce.iat ‖ runtime_data) == REPORTDATA in quote`
//!
//! ITA v2 JWT payload structure (TDX-specific claims nested under "tdx"):
//! ```json
//! {
//!   "tdx": {
//!     "tdx_mrtd": "<96-hex-char MRTD>",
//!     "tdx_report_data": "<base64-encoded 64-byte REPORTDATA (= SHA-512 hash)>",
//!     "attester_tcb_status": "UpToDate",
//!     "attester_advisory_ids": [...],
//!     ...
//!   },
//!   "verifier_instance_ids": [...],
//!   "exp": ..., "iat": ..., ...
//! }
//! ```

use crate::evidence::Evidence;
use crate::verify::VerifyError;
use serde::Deserialize;

/// Configuration for the Intel Trust Authority API.
#[derive(Debug, Clone)]
pub struct ItaConfig {
    /// Intel Trust Authority API key (`x-api-key` request header).
    pub api_key: String,
    /// ITA endpoint base URL (default: `https://api.trustauthority.intel.com`).
    pub api_url: String,
    /// Timeout in seconds for ITA HTTP requests (default: 30).
    pub request_timeout_secs: u64,
}

impl Default for ItaConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            api_url: "https://api.trustauthority.intel.com".to_string(),
            request_timeout_secs: 30,
        }
    }
}

/// ITA verifier nonce — anti-replay token fetched from GET /appraisal/v2/nonce.
///
/// Used to compute `REPORTDATA = SHA-512(nonce.val ‖ nonce.iat ‖ runtime_data)`.
#[derive(Debug, Clone)]
pub struct VerifierNonce {
    /// Decoded nonce value bytes (used in SHA-512 computation).
    pub val: Vec<u8>,
    /// Decoded nonce issued-at bytes (used in SHA-512 computation).
    pub iat: Vec<u8>,
    /// Decoded nonce signature bytes.
    pub signature: Vec<u8>,
    /// Original base64 string for the val field (for request body).
    pub val_b64: String,
    /// Original base64 string for the iat field (for request body).
    pub iat_b64: String,
    /// Original base64 string for the signature field (for request body).
    pub signature_b64: String,
}

#[derive(Debug, Deserialize)]
struct NonceApiResponse {
    val: String,
    iat: String,
    #[serde(default)]
    signature: String,
}

/// Claims extracted from an ITA attestation token (JWT).
#[derive(Debug, Clone)]
pub struct VerifiedClaims {
    /// MRTD as a hex string (48 bytes = 96 hex chars).
    pub mrtd: String,
    /// Raw 64-byte REPORTDATA extracted from the JWT.
    pub report_data: [u8; 64],
    /// The original 64-byte `runtime_data` (our ReportData struct).
    pub runtime_data: [u8; 64],
    /// TCB status string from ITA.
    pub tcb_status: String,
    /// The full raw JWT for storage or further inspection.
    pub raw_token: String,
}

#[derive(Debug, Deserialize, Default)]
struct TdxNestedClaims {
    #[serde(default)]
    tdx_mrtd: String,
    #[serde(default)]
    tdx_report_data: String,
    #[serde(default)]
    attester_tcb_status: String,
}

#[derive(Debug, Deserialize)]
struct ItaClaims {
    #[serde(default)]
    tdx: TdxNestedClaims,
}

/// Fetch an anti-replay verifier nonce from Intel Trust Authority.
///
/// This must be called before generating the DCAP quote so that the nonce
/// bytes can be incorporated into REPORTDATA.
pub async fn get_nonce(config: &ItaConfig) -> Result<VerifierNonce, VerifyError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    if config.api_key.is_empty() {
        return Err(VerifyError::ItaApi("ITA API key is empty".to_string()));
    }

    let url = format!("{}/appraisal/v2/nonce", config.api_url);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.request_timeout_secs))
        .build()
        .map_err(|e| VerifyError::Network(e.to_string()))?;
    let response = client
        .get(&url)
        .header("x-api-key", &config.api_key)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| VerifyError::Network(e.to_string()))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| VerifyError::Network(e.to_string()))?;

    if !status.is_success() {
        return Err(VerifyError::ItaApi(format!(
            "ITA nonce endpoint returned HTTP {status}: {body}"
        )));
    }

    let nonce_resp: NonceApiResponse = serde_json::from_str(&body)
        .map_err(|e| VerifyError::JwtParse(format!("nonce response JSON: {e}")))?;

    let val = BASE64
        .decode(&nonce_resp.val)
        .map_err(|e| VerifyError::JwtParse(format!("nonce.val base64: {e}")))?;
    let iat = BASE64
        .decode(&nonce_resp.iat)
        .map_err(|e| VerifyError::JwtParse(format!("nonce.iat base64: {e}")))?;
    let signature = if nonce_resp.signature.is_empty() {
        vec![]
    } else {
        BASE64
            .decode(&nonce_resp.signature)
            .map_err(|e| VerifyError::JwtParse(format!("nonce.signature base64: {e}")))?
    };

    Ok(VerifierNonce {
        val_b64: nonce_resp.val,
        iat_b64: nonce_resp.iat,
        signature_b64: nonce_resp.signature,
        val,
        iat,
        signature,
    })
}

/// Verify TDX evidence via Intel Trust Authority (Intel CLI-compatible flow).
///
/// Sends the raw quote along with `runtime_data` and `verifier_nonce` so that
/// ITA can verify: `SHA-512(nonce.val ‖ nonce.iat ‖ runtime_data) == REPORTDATA in quote`.
pub async fn verify_evidence(
    evidence: &Evidence,
    config: &ItaConfig,
    runtime_data: &[u8; 64],
    nonce: &VerifierNonce,
) -> Result<VerifiedClaims, VerifyError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;

    if config.api_key.is_empty() {
        return Err(VerifyError::ItaApi("ITA API key is empty".to_string()));
    }

    let quote_b64url = BASE64URL.encode(evidence.raw());
    let runtime_data_b64 = BASE64.encode(runtime_data);

    let body = serde_json::json!({
        "tdx": {
            "quote": quote_b64url,
            "runtime_data": runtime_data_b64,
            "verifier_nonce": {
                "val": nonce.val_b64,
                "iat": nonce.iat_b64,
                "signature": nonce.signature_b64,
            }
        }
    });

    let url = format!("{}/appraisal/v2/attest", config.api_url);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.request_timeout_secs))
        .build()
        .map_err(|e| VerifyError::Network(e.to_string()))?;
    let response = client
        .post(&url)
        .header("x-api-key", &config.api_key)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| VerifyError::Network(e.to_string()))?;

    let status = response.status();
    let raw_token = response
        .text()
        .await
        .map_err(|e| VerifyError::Network(e.to_string()))?;

    if !status.is_success() {
        return Err(VerifyError::ItaApi(format!(
            "ITA returned HTTP {status}: {raw_token}"
        )));
    }

    // ITA v2 returns a JSON envelope: { "token": "<JWT>" }.
    // Fall back to treating the body as a raw JWT string for forward-compat.
    let jwt = if let Ok(envelope) = serde_json::from_str::<serde_json::Value>(&raw_token) {
        envelope
            .get("token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| raw_token.trim().trim_matches('"').to_string())
    } else {
        raw_token.trim().trim_matches('"').to_string()
    };

    let claims = decode_jwt_claims(&jwt)?;

    if claims.tdx.tdx_mrtd.len() != 96 {
        return Err(VerifyError::ItaApi(format!(
            "MRTD has unexpected length: {} chars (expected 96)",
            claims.tdx.tdx_mrtd.len()
        )));
    }
    hex::decode(&claims.tdx.tdx_mrtd)
        .map_err(|_| VerifyError::ItaApi("MRTD is not valid hex".to_string()))?;

    let mut report_data = [0u8; 64];
    if !claims.tdx.tdx_report_data.is_empty() {
        let rd_bytes = BASE64URL
            .decode(&claims.tdx.tdx_report_data)
            .map_err(|_| VerifyError::JwtParse(
                "tdx_report_data: could not decode as base64url".to_string()
            ))?;
        if rd_bytes.len() != 64 {
            return Err(VerifyError::JwtParse(format!(
                "tdx_report_data has unexpected length: {} bytes (expected 64)",
                rd_bytes.len()
            )));
        }
        report_data.copy_from_slice(&rd_bytes);
    }

    Ok(VerifiedClaims {
        mrtd: claims.tdx.tdx_mrtd,
        report_data,
        runtime_data: *runtime_data,
        tcb_status: claims.tdx.attester_tcb_status,
        raw_token: jwt,
    })
}

/// Extract and parse the REPORTDATA embedded in an ITA v2 JWT.
///
/// **Note:** After nonce integration, the JWT's `tdx_report_data` field contains
/// `SHA-512(nonce.val ‖ nonce.iat ‖ runtime_data)`, not the raw ReportData struct.
pub fn report_data_from_token(jwt: &str) -> Result<Option<crate::report::ReportData>, VerifyError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};

    let claims = decode_jwt_claims(jwt)?;

    if claims.tdx.tdx_report_data.is_empty() {
        return Ok(None);
    }

    let rd_bytes = BASE64URL
        .decode(&claims.tdx.tdx_report_data)
        .map_err(|_| VerifyError::JwtParse(
            "tdx_report_data: could not decode as base64url".to_string()
        ))?;

    if rd_bytes.len() != 64 {
        return Err(VerifyError::JwtParse(format!(
            "tdx_report_data has unexpected length: {} bytes (expected 64)",
            rd_bytes.len()
        )));
    }

    let mut arr = [0u8; 64];
    arr.copy_from_slice(&rd_bytes);
    Ok(Some(crate::report::ReportData::from_bytes(&arr)))
}

fn decode_jwt_claims(jwt: &str) -> Result<ItaClaims, VerifyError> {
    let parts: Vec<&str> = jwt.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(VerifyError::JwtParse("JWT must have 3 parts".to_string()));
    }

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};
    let payload_bytes = BASE64URL
        .decode(parts[1])
        .map_err(|e| VerifyError::JwtParse(format!("JWT payload base64: {e}")))?;

    serde_json::from_slice::<ItaClaims>(&payload_bytes)
        .map_err(|e| VerifyError::JwtParse(format!("JWT claims JSON: {e}")))
}
