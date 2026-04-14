// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Intel Trust Authority (ITA) REST API verification.
//!
//! Sends the raw quote to ITA's appraisal endpoint and parses the returned JWT
//! to extract TDX claims.  ITA performs the full DCAP chain verification
//! server-side.  For stored attestations, verify the returned JWT against
//! ITA's JWKS before trusting its claims.
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
//!     "tdx_report_data": "<base64 or hex-encoded 64-byte REPORTDATA>",
//!     "attester_tcb_status": "UpToDate",
//!     "attester_advisory_ids": [...],
//!     ...
//!   },
//!   "verifier_instance_ids": [...],
//!   "exp": ..., "iat": ..., ...
//! }
//! ```

use crate::evidence::Evidence;
use crate::verify::codec::{decode_claim_array_64, decode_standard_base64_array_64};
use crate::verify::VerifyError;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Default Intel Trust Authority token-signing JWKS endpoint.
pub(crate) const DEFAULT_JWKS_URL: &str = "https://portal.trustauthority.intel.com/certs";

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

impl ItaConfig {
    /// Derive the default Intel Trust Authority JWKS URL for this API region.
    #[must_use]
    pub fn default_jwks_url(&self) -> String {
        default_jwks_url_for_api_url(&self.api_url)
    }
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

/// Derive the default Intel Trust Authority JWKS URL from an ITA API base URL.
///
/// Official regional hosts map `api...trustauthority.intel.com` to the matching
/// `portal...trustauthority.intel.com/certs` endpoint. Unknown hosts fall back
/// to the global default.
#[must_use]
pub fn default_jwks_url_for_api_url(api_url: &str) -> String {
    reqwest::Url::parse(api_url)
        .ok()
        .and_then(default_jwks_url_from_api_url)
        .unwrap_or_else(|| DEFAULT_JWKS_URL.to_string())
}

fn default_jwks_url_from_api_url(api_url: reqwest::Url) -> Option<String> {
    let host = api_url.host_str()?;
    let portal_host = if let Some(rest) = host.strip_prefix("api.") {
        if rest.ends_with(".trustauthority.intel.com") {
            format!("portal.{rest}")
        } else {
            return None;
        }
    } else if host.starts_with("portal.") && host.ends_with(".trustauthority.intel.com") {
        host.to_string()
    } else {
        return None;
    };

    let mut portal_url = api_url;
    portal_url.set_host(Some(&portal_host)).ok()?;
    portal_url.set_path("/certs");
    portal_url.set_query(None);
    portal_url.set_fragment(None);
    Some(portal_url.to_string())
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

/// Claims parsed from an ITA appraisal token without authenticating its JWT signature.
///
/// This is only suitable for the immediate appraisal response returned by
/// Intel Trust Authority. For stored attestations, use
/// [`crate::Attestation::verify_with_policy`] to authenticate the token before
/// trusting these values.
#[derive(Debug, Clone)]
pub struct UnauthenticatedAppraisalClaims {
    /// MRTD as a hex string (48 bytes = 96 hex chars).
    pub mrtd: String,
    /// Raw 64-byte REPORTDATA extracted from the JWT.
    pub report_data: [u8; 64],
    /// The 64-byte `runtime_data` submitted in the appraisal request.
    pub runtime_data: [u8; 64],
    /// TCB status string from ITA.
    pub tcb_status: String,
    /// Optional TCB assessment date from ITA token claims.
    pub tcb_date: Option<String>,
    /// Advisory IDs reported by Intel Trust Authority for this appraisal.
    pub advisory_ids: Vec<String>,
    /// The raw JWT returned by ITA, without local signature verification.
    pub raw_token: String,
}

#[derive(Debug, Clone)]
struct AppraisalClaimsCore {
    mrtd: String,
    report_data: [u8; 64],
    tcb_status: String,
    tcb_date: Option<String>,
    advisory_ids: Vec<String>,
}

impl AppraisalClaimsCore {
    fn into_unauthenticated_appraisal(
        self,
        runtime_data: [u8; 64],
        raw_token: String,
    ) -> UnauthenticatedAppraisalClaims {
        UnauthenticatedAppraisalClaims {
            mrtd: self.mrtd,
            report_data: self.report_data,
            runtime_data,
            tcb_status: self.tcb_status,
            tcb_date: self.tcb_date,
            advisory_ids: self.advisory_ids,
            raw_token,
        }
    }
}

/// Claims extracted from an ITA token after JWT signature and expiry validation.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedTokenClaims {
    claims: AppraisalClaimsCore,
    /// Token binding material used to prove this token belongs to the attestation.
    pub binding: VerifiedTokenBinding,
}

impl VerifiedTokenClaims {
    pub(crate) fn mrtd(&self) -> &str {
        &self.claims.mrtd
    }

    pub(crate) fn tcb_status(&self) -> &str {
        &self.claims.tcb_status
    }

    pub(crate) fn tcb_date(&self) -> Option<&str> {
        self.claims.tcb_date.as_deref()
    }

    pub(crate) fn advisory_ids(&self) -> &[String] {
        &self.claims.advisory_ids
    }

    pub(crate) fn binding_matches(
        &self,
        runtime_data: &[u8; 64],
        expected_runtime_hash: &[u8; 64],
    ) -> bool {
        match &self.binding {
            VerifiedTokenBinding::StandardReportData => {
                self.claims.report_data == *expected_runtime_hash
            }
            VerifiedTokenBinding::AzureRuntime {
                held_data,
                user_data_hash,
            } => held_data == runtime_data && user_data_hash == expected_runtime_hash,
        }
    }

    pub(crate) fn supports_offline_quote_report_data_binding(&self) -> bool {
        matches!(self.binding, VerifiedTokenBinding::StandardReportData)
    }

    fn into_unauthenticated_appraisal(
        self,
        runtime_data: [u8; 64],
        raw_token: String,
    ) -> UnauthenticatedAppraisalClaims {
        self.claims
            .into_unauthenticated_appraisal(runtime_data, raw_token)
    }
}

#[derive(Debug, Clone)]
pub(crate) enum VerifiedTokenBinding {
    StandardReportData,
    AzureRuntime {
        held_data: [u8; 64],
        user_data_hash: [u8; 64],
    },
}

#[derive(Debug, Deserialize, Default, Clone)]
struct TdxClaimFields {
    #[serde(default)]
    tdx_mrtd: String,
    #[serde(default)]
    tdx_report_data: String,
    #[serde(default)]
    attester_tcb_status: String,
    #[serde(default)]
    attester_tcb_date: String,
    #[serde(default)]
    attester_advisory_ids: Vec<String>,
    #[serde(default)]
    attester_held_data: String,
    #[serde(default)]
    attester_runtime_data: serde_json::Value,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct AppraisalClaims {
    #[serde(default)]
    method: String,
}

#[derive(Debug, Deserialize, Clone)]
struct ItaClaims {
    #[serde(default)]
    appraisal: AppraisalClaims,
    #[serde(default)]
    tdx: TdxClaimFields,
    #[serde(flatten)]
    flat_tdx: TdxClaimFields,
    #[serde(default)]
    #[allow(dead_code)]
    exp: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    nbf: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    iat: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppraisalBindingKind {
    Standard,
    Azure,
}

impl ItaClaims {
    fn trimmed(value: &str) -> &str {
        value.trim()
    }

    fn appraisal_method(&self) -> &str {
        Self::trimmed(&self.appraisal.method)
    }

    fn nested_or_flat_fields<'a, T, F>(&'a self, get: F) -> &'a T
    where
        T: Default + PartialEq,
        F: Fn(&'a TdxClaimFields) -> &'a T,
    {
        let nested = get(&self.tdx);
        if nested != &T::default() {
            nested
        } else {
            get(&self.flat_tdx)
        }
    }

    fn tdx_mrtd(&self) -> &str {
        Self::trimmed(self.nested_or_flat_fields(|claims| &claims.tdx_mrtd))
    }

    fn tdx_report_data(&self) -> &str {
        Self::trimmed(self.nested_or_flat_fields(|claims| &claims.tdx_report_data))
    }

    fn attester_tcb_status(&self) -> &str {
        Self::trimmed(self.nested_or_flat_fields(|claims| &claims.attester_tcb_status))
    }

    fn attester_tcb_date(&self) -> Option<&str> {
        let v = Self::trimmed(self.nested_or_flat_fields(|claims| &claims.attester_tcb_date));
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    }

    fn attester_advisory_ids(&self) -> &[String] {
        self.nested_or_flat_fields(|claims| &claims.attester_advisory_ids)
    }

    fn attester_held_data(&self) -> &str {
        Self::trimmed(self.nested_or_flat_fields(|claims| &claims.attester_held_data))
    }

    fn attester_runtime_user_data(&self) -> Option<&str> {
        self.tdx
            .attester_runtime_data
            .get("user-data")
            .and_then(serde_json::Value::as_str)
            .or_else(|| {
                self.flat_tdx
                    .attester_runtime_data
                    .get("user-data")
                    .and_then(serde_json::Value::as_str)
            })
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    /// Determine whether the token uses Azure's separate held-data/runtime-hash binding.
    ///
    /// We trust an explicit `appraisal.method = "azure"` marker. For payloads
    /// that omit `appraisal.method`, we only accept the Azure binding when both
    /// Azure-only claims are present. Partial Azure-only data is rejected as
    /// ambiguous instead of silently falling back to the standard binding.
    fn binding_kind(&self) -> Result<AppraisalBindingKind, VerifyError> {
        let method = self.appraisal_method();
        let has_held_data = !self.attester_held_data().is_empty();
        let has_runtime_user_data = self.attester_runtime_user_data().is_some();

        if method.eq_ignore_ascii_case("azure") {
            if !has_held_data {
                return Err(VerifyError::InvalidTokenClaims(
                    "Azure ITA token is missing attester_held_data".to_string(),
                ));
            }
            if !has_runtime_user_data {
                return Err(VerifyError::InvalidTokenClaims(
                    "Azure ITA token is missing attester_runtime_data.user-data".to_string(),
                ));
            }
            return Ok(AppraisalBindingKind::Azure);
        }

        match (method.is_empty(), has_held_data, has_runtime_user_data) {
            (_, false, false) => Ok(AppraisalBindingKind::Standard),
            (true, true, true) => Ok(AppraisalBindingKind::Azure),
            (true, true, false) => Err(VerifyError::InvalidTokenClaims(
                "ITA token has Azure-specific attester_held_data without attester_runtime_data.user-data"
                    .to_string(),
            )),
            (true, false, true) => Err(VerifyError::InvalidTokenClaims(
                "ITA token has Azure-specific attester_runtime_data.user-data without attester_held_data"
                    .to_string(),
            )),
            (false, _, _) => Err(VerifyError::InvalidTokenClaims(format!(
                "ITA token appraisal.method={method:?} conflicts with Azure-specific attester_* claims"
            ))),
        }
    }
}

fn http_client(request_timeout_secs: u64) -> Result<reqwest::Client, VerifyError> {
    static CLIENTS: OnceLock<Mutex<HashMap<u64, reqwest::Client>>> = OnceLock::new();

    let clients = CLIENTS.get_or_init(|| Mutex::new(HashMap::new()));
    // The cache is only an optimization. If another thread panicked while
    // holding the lock, recover the inner map rather than failing or aborting.
    let mut clients = match clients.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(client) = clients.get(&request_timeout_secs).cloned() {
        return Ok(client);
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(request_timeout_secs))
        .build()
        .map_err(|e| VerifyError::Network(e.to_string()))?;

    clients.insert(request_timeout_secs, client.clone());

    Ok(client)
}

/// Verify an ITA attestation token against Intel Trust Authority's JWKS.
///
/// The token header's `kid` selects the signing key from `jwks_url`; the token
/// `jku` header, if present, is intentionally ignored.
pub(crate) async fn verify_attestation_token(
    jwt: &str,
    jwks_url: &str,
    request_timeout_secs: u64,
) -> Result<VerifiedTokenClaims, VerifyError> {
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

    let jwt = normalized_jwt(jwt)?;

    let header =
        decode_header(jwt).map_err(|e| VerifyError::InvalidToken(format!("JWT header: {e}")))?;
    let algorithm = match header.alg {
        Algorithm::PS384 | Algorithm::RS256 => header.alg,
        other => {
            return Err(VerifyError::InvalidToken(format!(
                "unsupported ITA token signing algorithm: {other:?}"
            )))
        }
    };
    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| VerifyError::InvalidToken("JWT header missing kid".to_string()))?;

    let client = http_client(request_timeout_secs)?;
    let response = client
        .get(jwks_url)
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
            "ITA JWKS endpoint returned HTTP {status}: {body}"
        )));
    }

    let jwks: JwkSet = serde_json::from_str(&body)
        .map_err(|e| VerifyError::InvalidToken(format!("JWKS JSON: {e}")))?;
    let jwk = jwks
        .keys
        .iter()
        .find(|jwk| jwk.common.key_id.as_deref() == Some(kid))
        .ok_or_else(|| VerifyError::InvalidToken(format!("JWKS has no key for kid {kid}")))?;
    let key = DecodingKey::from_jwk(jwk)
        .map_err(|e| VerifyError::InvalidToken(format!("JWKS key for kid {kid}: {e}")))?;

    let mut validation = Validation::new(algorithm);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.validate_aud = false;

    let token = decode::<ItaClaims>(jwt, &key, &validation)
        .map_err(|e| VerifyError::InvalidToken(format!("JWT validation: {e}")))?;
    let claims = token.claims;
    parse_verified_claims(claims)
}

fn attest_path_for_evidence(evidence: &Evidence) -> &'static str {
    if evidence.azure_runtime_data().is_some() {
        "/appraisal/v2/attest/azure"
    } else {
        "/appraisal/v2/attest"
    }
}

/// Fetch an anti-replay verifier nonce from Intel Trust Authority.
///
/// This must be called before generating the DCAP quote so that the nonce
/// bytes can be incorporated into REPORTDATA.
pub async fn get_nonce(config: &ItaConfig) -> Result<VerifierNonce, VerifyError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    if config.api_key.is_empty() {
        return Err(VerifyError::InvalidConfiguration(
            "ITA API key is empty".to_string(),
        ));
    }

    let url = format!("{}/appraisal/v2/nonce", config.api_url);

    let client = http_client(config.request_timeout_secs)?;
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
        .map_err(|e| VerifyError::ItaApi(format!("nonce response JSON: {e}")))?;

    let val = BASE64
        .decode(&nonce_resp.val)
        .map_err(|e| VerifyError::ItaApi(format!("nonce.val base64: {e}")))?;
    let iat = BASE64
        .decode(&nonce_resp.iat)
        .map_err(|e| VerifyError::ItaApi(format!("nonce.iat base64: {e}")))?;
    let signature = if nonce_resp.signature.is_empty() {
        vec![]
    } else {
        BASE64
            .decode(&nonce_resp.signature)
            .map_err(|e| VerifyError::ItaApi(format!("nonce.signature base64: {e}")))?
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

/// Submit evidence to Intel Trust Authority for server-side appraisal and parse
/// the returned token without authenticating its JWT signature.
///
/// Sends the raw quote along with `runtime_data` and `verifier_nonce`.
/// For standard TDX attesters, ITA verifies
/// `SHA-512(nonce.val ‖ nonce.iat ‖ runtime_data) == REPORTDATA in quote`.
/// Azure TDX VMs use Intel Trust Authority's `/attest/azure` flow, which binds
/// the caller's `user_data` separately from the Azure runtime JSON.
///
/// This is suitable for the immediate ITA response on the same request. For
/// stored attestations, use [`crate::Attestation::verify_with_policy`] to
/// authenticate the token before trusting any claims.
pub async fn appraise_evidence_unauthenticated(
    evidence: &Evidence,
    config: &ItaConfig,
    runtime_data: &[u8; 64],
    nonce: &VerifierNonce,
) -> Result<UnauthenticatedAppraisalClaims, VerifyError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    if config.api_key.is_empty() {
        return Err(VerifyError::InvalidConfiguration(
            "ITA API key is empty".to_string(),
        ));
    }

    let path = attest_path_for_evidence(evidence);
    let body = if path.ends_with("/azure") {
        let runtime_json = evidence.azure_runtime_data().ok_or_else(|| {
            VerifyError::InvalidStoredEvidence(
                "Azure provider selected but evidence has no Azure runtime_data".to_string(),
            )
        })?;
        let quote_b64 = BASE64.encode(evidence.raw());
        let runtime_json_b64 = BASE64.encode(runtime_json);
        let user_data_b64 = BASE64.encode(runtime_data);
        serde_json::json!({
            "tdx": {
                "quote": quote_b64,
                "runtime_data": runtime_json_b64,
                "user_data": user_data_b64,
                "verifier_nonce": {
                    "val": nonce.val_b64,
                    "iat": nonce.iat_b64,
                    "signature": nonce.signature_b64,
                }
            }
        })
    } else {
        let quote_b64url = BASE64URL.encode(evidence.raw());
        let runtime_data_b64 = BASE64.encode(runtime_data);
        serde_json::json!({
            "tdx": {
                "quote": quote_b64url,
                "runtime_data": runtime_data_b64,
                "verifier_nonce": {
                    "val": nonce.val_b64,
                    "iat": nonce.iat_b64,
                    "signature": nonce.signature_b64,
                }
            }
        })
    };

    let url = format!("{}{}", config.api_url, path);

    let client = http_client(config.request_timeout_secs)?;
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
    let jwt = match serde_json::from_str::<serde_json::Value>(&raw_token) {
        Ok(serde_json::Value::Object(envelope)) => envelope
            .get("token")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .ok_or_else(|| VerifyError::ItaApi("ITA JSON response missing token".to_string()))?,
        Ok(serde_json::Value::String(token)) => token,
        Ok(_) => {
            return Err(VerifyError::ItaApi(
                "ITA JSON response is not a token envelope".to_string(),
            ))
        }
        Err(_) => raw_token.trim().to_string(),
    };
    let jwt = jwt.trim().to_string();
    if jwt.is_empty() {
        return Err(VerifyError::ItaApi(
            "ITA JSON response token is empty".to_string(),
        ));
    }

    let claims = decode_jwt_claims(&jwt)?;
    let verified = parse_verified_claims(claims)?;

    Ok(verified.into_unauthenticated_appraisal(*runtime_data, jwt))
}

/// Crate-internal compatibility wrapper for existing fresh-appraisal flows.
///
/// This parses the appraisal token without authenticating its signature because
/// the token has just been returned by ITA on this request.
#[allow(dead_code)]
pub(crate) async fn verify_evidence(
    evidence: &Evidence,
    config: &ItaConfig,
    runtime_data: &[u8; 64],
    nonce: &VerifierNonce,
) -> Result<UnauthenticatedAppraisalClaims, VerifyError> {
    appraise_evidence_unauthenticated(evidence, config, runtime_data, nonce).await
}

fn parse_verified_claims(claims: ItaClaims) -> Result<VerifiedTokenClaims, VerifyError> {
    if claims.tdx_mrtd().len() != 96 {
        return Err(VerifyError::InvalidTokenClaims(format!(
            "MRTD has unexpected length: {} chars (expected 96)",
            claims.tdx_mrtd().len()
        )));
    }
    hex::decode(claims.tdx_mrtd())
        .map_err(|_| VerifyError::InvalidTokenClaims("MRTD is not valid hex".to_string()))?;

    if claims.tdx_report_data().is_empty() {
        return Err(VerifyError::InvalidTokenClaims(
            "ITA token is missing tdx_report_data".to_string(),
        ));
    }
    let report_data = decode_claim_array_64("tdx_report_data", claims.tdx_report_data())
        .map_err(VerifyError::InvalidTokenClaims)?;

    let binding = match claims.binding_kind()? {
        AppraisalBindingKind::Standard => VerifiedTokenBinding::StandardReportData,
        AppraisalBindingKind::Azure => {
            let held_data =
                decode_standard_base64_array_64("attester_held_data", claims.attester_held_data())
                    .map_err(VerifyError::InvalidTokenClaims)?;
            let user_data_hash = decode_claim_array_64(
                "attester_runtime_data.user-data",
                claims.attester_runtime_user_data().ok_or_else(|| {
                    VerifyError::InvalidTokenClaims(
                        "Azure ITA token is missing attester_runtime_data.user-data".to_string(),
                    )
                })?,
            )
            .map_err(VerifyError::InvalidTokenClaims)?;
            VerifiedTokenBinding::AzureRuntime {
                held_data,
                user_data_hash,
            }
        }
    };

    Ok(VerifiedTokenClaims {
        claims: AppraisalClaimsCore {
            mrtd: claims.tdx_mrtd().to_string(),
            report_data,
            tcb_status: claims.attester_tcb_status().to_string(),
            tcb_date: claims.attester_tcb_date().map(ToOwned::to_owned),
            advisory_ids: claims.attester_advisory_ids().to_vec(),
        },
        binding,
    })
}

/// Extract the raw `tdx_report_data` claim embedded in an ITA v2 JWT without
/// authenticating the token.
///
/// **Note:** After nonce integration, the JWT's `tdx_report_data` field contains
/// the token's 64-byte binding value, not the raw [`crate::report::ReportData`]
/// struct. For standard TDX attesters this is
/// `SHA-512(nonce.val ‖ nonce.iat ‖ runtime_data)`.
pub fn unauthenticated_report_data_hash_from_token(
    jwt: &str,
) -> Result<Option<[u8; 64]>, VerifyError> {
    let claims = decode_jwt_claims(jwt)?;

    if claims.tdx_report_data().is_empty() {
        return Ok(None);
    }

    decode_claim_array_64("tdx_report_data", claims.tdx_report_data())
        .map(Some)
        .map_err(VerifyError::InvalidTokenClaims)
}

fn decode_jwt_claims(jwt: &str) -> Result<ItaClaims, VerifyError> {
    let jwt = normalized_jwt(jwt)?;
    let parts: Vec<&str> = jwt.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(VerifyError::InvalidToken(
            "JWT must have 3 parts".to_string(),
        ));
    }

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};
    let payload_bytes = BASE64URL
        .decode(parts[1])
        .map_err(|e| VerifyError::InvalidToken(format!("JWT payload base64: {e}")))?;

    serde_json::from_slice::<ItaClaims>(&payload_bytes)
        .map_err(|e| VerifyError::InvalidToken(format!("JWT claims JSON: {e}")))
}

fn normalized_jwt(jwt: &str) -> Result<&str, VerifyError> {
    let jwt = jwt.trim();
    if jwt.is_empty() {
        return Err(VerifyError::InvalidToken("JWT is empty".to_string()));
    }
    Ok(jwt)
}

#[cfg(test)]
mod tests {
    use super::{
        default_jwks_url_for_api_url, parse_verified_claims,
        unauthenticated_report_data_hash_from_token, ItaConfig, VerifiedTokenBinding,
        DEFAULT_JWKS_URL,
    };
    use crate::verify::VerifyError;
    use base64::Engine;
    use serde_json::json;
    use sha2::{Digest, Sha512};

    fn sample_mrtd() -> String {
        "11".repeat(48)
    }

    fn fake_jwt(payload: &str) -> String {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
        format!("e30.{payload}.sig")
    }

    #[test]
    fn parse_verified_claims_azure_uses_held_data_and_runtime_hash_binding() {
        let runtime_data = [0x5au8; 64];
        let nonce_val = [0x11u8; 32];
        let nonce_iat = [0x22u8; 32];
        let user_data_hash: [u8; 64] = {
            let mut h = Sha512::new();
            h.update(nonce_val);
            h.update(nonce_iat);
            h.update(runtime_data);
            h.finalize().into()
        };

        let claims = serde_json::from_value(json!({
            "appraisal": { "method": "azure" },
            "tdx": {
                "tdx_mrtd": sample_mrtd(),
                "tdx_report_data": format!("{}{}", "aa".repeat(32), "00".repeat(32)),
                "attester_tcb_status": "UpToDate",
                "attester_tcb_date": "2026-02-11T00:00:00Z",
                "attester_held_data": base64::engine::general_purpose::STANDARD.encode(runtime_data),
                "attester_runtime_data": {
                    "user-data": hex::encode(user_data_hash),
                }
            }
        }))
        .expect("claims JSON should deserialize");

        let verified = parse_verified_claims(claims).expect("Azure claims should parse");
        match verified.binding {
            VerifiedTokenBinding::AzureRuntime {
                held_data,
                user_data_hash: actual_hash,
            } => {
                assert_eq!(held_data, runtime_data);
                assert_eq!(actual_hash, user_data_hash);
                assert!(verified.binding_matches(&runtime_data, &user_data_hash));
            }
            VerifiedTokenBinding::StandardReportData => {
                panic!("expected Azure runtime binding")
            }
        }
    }

    #[test]
    fn parse_verified_claims_rejects_missing_azure_runtime_hash() {
        let claims = serde_json::from_value(json!({
            "appraisal": { "method": "azure" },
            "tdx": {
                "tdx_mrtd": sample_mrtd(),
                "tdx_report_data": "00".repeat(64),
                "attester_tcb_status": "UpToDate",
                "attester_held_data": base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
                "attester_runtime_data": {}
            }
        }))
        .expect("claims JSON should deserialize");

        let err = parse_verified_claims(claims).unwrap_err();
        assert!(
            matches!(err, VerifyError::InvalidTokenClaims(ref message) if message.contains("attester_runtime_data.user-data")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_verified_claims_accepts_azure_shape_without_method() {
        let claims = serde_json::from_value(json!({
            "tdx": {
                "tdx_mrtd": sample_mrtd(),
                "tdx_report_data": "00".repeat(64),
                "attester_tcb_status": "UpToDate",
                "attester_held_data": base64::engine::general_purpose::STANDARD.encode([0x12u8; 64]),
                "attester_runtime_data": {
                    "user-data": "34".repeat(64),
                }
            }
        }))
        .expect("claims JSON should deserialize");

        let verified = parse_verified_claims(claims).expect("Azure-shaped claims should parse");
        assert!(matches!(
            verified.binding,
            VerifiedTokenBinding::AzureRuntime { .. }
        ));
    }

    #[test]
    fn parse_verified_claims_rejects_partial_azure_shape_without_method() {
        let claims = serde_json::from_value(json!({
            "tdx": {
                "tdx_mrtd": sample_mrtd(),
                "tdx_report_data": "00".repeat(64),
                "attester_tcb_status": "UpToDate",
                "attester_held_data": base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
            }
        }))
        .expect("claims JSON should deserialize");

        let err = parse_verified_claims(claims).unwrap_err();
        assert!(
            matches!(err, VerifyError::InvalidTokenClaims(ref message) if message.contains("Azure-specific attester_held_data")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_verified_claims_rejects_non_azure_method_with_azure_claims() {
        let claims = serde_json::from_value(json!({
            "appraisal": { "method": "tdx" },
            "tdx": {
                "tdx_mrtd": sample_mrtd(),
                "tdx_report_data": "00".repeat(64),
                "attester_tcb_status": "UpToDate",
                "attester_held_data": base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
                "attester_runtime_data": {
                    "user-data": "11".repeat(64),
                }
            }
        }))
        .expect("claims JSON should deserialize");

        let err = parse_verified_claims(claims).unwrap_err();
        assert!(
            matches!(err, VerifyError::InvalidTokenClaims(ref message) if message.contains("conflicts with Azure-specific")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_verified_claims_trims_wrapping_whitespace() {
        let claims = serde_json::from_value(json!({
            "tdx": {
                "tdx_mrtd": format!("  {}  ", sample_mrtd()),
                "tdx_report_data": format!("  {}  ", "ab".repeat(64)),
                "attester_tcb_status": "  UpToDate\t",
                "attester_tcb_date": " 2026-02-11T00:00:00Z ",
            }
        }))
        .expect("claims JSON should deserialize");

        let verified = parse_verified_claims(claims).expect("whitespace should be trimmed");
        assert_eq!(verified.mrtd(), sample_mrtd());
        assert!(
            matches!(verified.binding, VerifiedTokenBinding::StandardReportData),
            "expected standard token binding"
        );
        assert_eq!(verified.tcb_status(), "UpToDate");
        assert_eq!(verified.tcb_date(), Some("2026-02-11T00:00:00Z"));
    }

    #[test]
    fn unauthenticated_report_data_hash_from_token_trims_input() {
        let jwt = fake_jwt(&format!(
            r#"{{"tdx":{{"tdx_report_data":" {} "}}}}"#,
            "aa".repeat(64)
        ));
        let jwt = format!("  {jwt}  ");

        let claim =
            unauthenticated_report_data_hash_from_token(&jwt).expect("trimmed JWT should parse");

        assert_eq!(claim, Some([0xaau8; 64]));
    }

    #[test]
    fn default_jwks_url_maps_us_and_eu_regions() {
        assert_eq!(
            default_jwks_url_for_api_url("https://api.trustauthority.intel.com"),
            DEFAULT_JWKS_URL
        );
        assert_eq!(
            default_jwks_url_for_api_url("https://api.eu.trustauthority.intel.com/appraisal/v2"),
            "https://portal.eu.trustauthority.intel.com/certs"
        );
    }

    #[test]
    fn ita_config_default_jwks_url_falls_back_for_unknown_hosts() {
        let config = ItaConfig {
            api_key: String::new(),
            api_url: "http://127.0.0.1:8080".to_string(),
            request_timeout_secs: 30,
        };

        assert_eq!(config.default_jwks_url(), DEFAULT_JWKS_URL);
    }
}
