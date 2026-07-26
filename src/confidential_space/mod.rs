// SPDX-License-Identifier: MIT
//! Google Confidential Space launcher integration and token verification.

use crate::verify::oidc::{discover_jwks_url, verify_jwt_with_jwks};
use crate::PublicValues;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine as _};
use jsonwebtoken::Algorithm;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Confidential Space launcher Unix socket.
const CONFIDENTIAL_SPACE_LAUNCHER_SOCKET: &str = "/run/container_launcher/teeserver.sock";
/// Trusted Google Cloud Attestation issuer.
pub const CONFIDENTIAL_SPACE_GOOGLE_ISSUER: &str = "https://confidentialcomputing.googleapis.com";
/// Trusted Intel Trust Authority Confidential Space issuer.
pub const CONFIDENTIAL_SPACE_INTEL_ISSUER: &str = "https://portal.trustauthority.intel.com";
/// The only supported serialized Confidential Space artifact schema version.
pub const CONFIDENTIAL_SPACE_ATTESTATION_SCHEMA_VERSION: u32 = 2;

const GOOGLE_DISCOVERY_URL: &str =
    "https://confidentialcomputing.googleapis.com/.well-known/openid-configuration";
const INTEL_DISCOVERY_URL: &str =
    "https://portal.trustauthority.intel.com/.well-known/openid-configuration";
const MAX_AUDIENCE_BYTES: usize = 512;
const DEFAULT_MAX_TOKEN_AGE_SECS: u64 = 300;
const TOKEN_CLOCK_SKEW_SECS: u64 = 60;

/// Which Confidential Space attestation service must mint the artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialSpaceAttesterMode {
    /// Require a Google Cloud Attestation token.
    Google,
    /// Require an Intel Trust Authority token.
    Intel,
    /// Require independently valid Google and Intel tokens with matching claims.
    Dual,
}

/// Confidential Space token-generation configuration.
#[derive(Debug, Clone)]
pub struct ConfidentialSpaceConfig {
    /// Exact audience placed in each launcher request.
    pub audience: String,
    /// Required attestation service or services.
    pub attester_mode: ConfidentialSpaceAttesterMode,
    /// Launcher Unix socket path.
    pub launcher_socket: PathBuf,
    /// Launcher request timeout in seconds.
    pub request_timeout_secs: u64,
}

impl ConfidentialSpaceConfig {
    /// Create a configuration using the production launcher socket.
    #[must_use]
    pub fn new(audience: impl Into<String>, attester_mode: ConfidentialSpaceAttesterMode) -> Self {
        Self {
            audience: audience.into(),
            attester_mode,
            launcher_socket: PathBuf::from(CONFIDENTIAL_SPACE_LAUNCHER_SOCKET),
            request_timeout_secs: 30,
        }
    }

    fn validate(&self) -> Result<(), ConfidentialSpaceError> {
        validate_audience(&self.audience)?;
        if self.request_timeout_secs == 0 {
            return Err(ConfidentialSpaceError::InvalidConfiguration(
                "request_timeout_secs must be greater than zero".to_string(),
            ));
        }
        if self.launcher_socket.as_os_str().is_empty() {
            return Err(ConfidentialSpaceError::InvalidConfiguration(
                "launcher_socket must not be empty".to_string(),
            ));
        }
        Ok(())
    }
}

/// Errors from Confidential Space generation and verification setup.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ConfidentialSpaceError {
    /// A local generation or verification setting is invalid.
    #[error("invalid Confidential Space configuration: {0}")]
    InvalidConfiguration(String),
    /// The launcher could not be reached or timed out.
    #[error("Confidential Space launcher request failed: {0}")]
    Launcher(String),
    /// A launcher endpoint returned a non-success status.
    #[error("{issuer:?} launcher endpoint returned HTTP {status}: {body}")]
    LauncherStatus {
        /// Attestation service whose endpoint failed.
        issuer: ConfidentialSpaceIssuer,
        /// HTTP response status.
        status: u16,
        /// HTTP response body.
        body: String,
    },
    /// A successful launcher response did not contain a usable token.
    #[error("invalid {issuer:?} launcher response: {message}")]
    LauncherResponse {
        /// Attestation service whose response was malformed.
        issuer: ConfidentialSpaceIssuer,
        /// Diagnostic message.
        message: String,
    },
    /// The serialized artifact is not schema version 2.
    #[error(
        "unsupported Confidential Space attestation schema version {0}; only version 2 is supported"
    )]
    UnsupportedArtifactVersion(u32),
}

/// Token issuer used in diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialSpaceIssuer {
    /// Google Cloud Attestation.
    Google,
    /// Intel Trust Authority.
    Intel,
}

impl ConfidentialSpaceIssuer {
    fn launcher_path(self) -> &'static str {
        match self {
            Self::Google => "/v1/token",
            Self::Intel => "/v1/intel/token",
        }
    }

    fn expected_issuer(self) -> &'static str {
        match self {
            Self::Google => CONFIDENTIAL_SPACE_GOOGLE_ISSUER,
            Self::Intel => CONFIDENTIAL_SPACE_INTEL_ISSUER,
        }
    }

    fn discovery_url(self) -> &'static str {
        match self {
            Self::Google => GOOGLE_DISCOVERY_URL,
            Self::Intel => INTEL_DISCOVERY_URL,
        }
    }

    fn accepted_algorithms(self) -> &'static [Algorithm] {
        match self {
            Self::Google => &[Algorithm::RS256],
            Self::Intel => &[Algorithm::PS384, Algorithm::RS256],
        }
    }
}

/// Type-safe launcher tokens. A dual artifact cannot be mistaken for a
/// single-issuer artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "attester", rename_all = "snake_case")]
pub enum ConfidentialSpaceTokens {
    /// Google Cloud Attestation token.
    Google {
        /// Signed OIDC token.
        token: String,
    },
    /// Intel Trust Authority token.
    Intel {
        /// Signed OIDC token.
        token: String,
    },
    /// Independent Google and Intel OIDC tokens.
    Dual {
        /// Google Cloud Attestation token.
        google: String,
        /// Intel Trust Authority token.
        intel: String,
    },
}

impl ConfidentialSpaceTokens {
    /// Return the token-generation mode represented by this value.
    #[must_use]
    pub fn attester_mode(&self) -> ConfidentialSpaceAttesterMode {
        match self {
            Self::Google { .. } => ConfidentialSpaceAttesterMode::Google,
            Self::Intel { .. } => ConfidentialSpaceAttesterMode::Intel,
            Self::Dual { .. } => ConfidentialSpaceAttesterMode::Dual,
        }
    }

    /// Return the Google token, if present.
    #[must_use]
    pub fn google(&self) -> Option<&str> {
        match self {
            Self::Google { token } => Some(token),
            Self::Dual { google, .. } => Some(google),
            Self::Intel { .. } => None,
        }
    }

    /// Return the Intel token, if present.
    #[must_use]
    pub fn intel(&self) -> Option<&str> {
        match self {
            Self::Intel { token } => Some(token),
            Self::Dual { intel, .. } => Some(intel),
            Self::Google { .. } => None,
        }
    }
}

/// Confidential Space attestation client.
#[derive(Debug, Clone)]
pub struct ConfidentialSpace {
    config: ConfidentialSpaceConfig,
}

impl ConfidentialSpace {
    /// Create a client from an explicit configuration.
    #[must_use]
    pub fn new(config: ConfidentialSpaceConfig) -> Self {
        Self { config }
    }

    /// Access this client's configuration.
    #[must_use]
    pub fn config(&self) -> &ConfidentialSpaceConfig {
        &self.config
    }

    /// Request typed launcher tokens for an already-computed commitment.
    pub async fn request_tokens(
        &self,
        commitment: &[u8; 32],
    ) -> Result<ConfidentialSpaceTokens, ConfidentialSpaceError> {
        self.config.validate()?;

        match self.config.attester_mode {
            ConfidentialSpaceAttesterMode::Google => {
                let token = self
                    .request_token(ConfidentialSpaceIssuer::Google, commitment)
                    .await?;
                Ok(ConfidentialSpaceTokens::Google { token })
            }
            ConfidentialSpaceAttesterMode::Intel => {
                let token = self
                    .request_token(ConfidentialSpaceIssuer::Intel, commitment)
                    .await?;
                Ok(ConfidentialSpaceTokens::Intel { token })
            }
            ConfidentialSpaceAttesterMode::Dual => {
                let google = self
                    .request_token(ConfidentialSpaceIssuer::Google, commitment)
                    .await?;
                let intel = self
                    .request_token(ConfidentialSpaceIssuer::Intel, commitment)
                    .await?;
                Ok(ConfidentialSpaceTokens::Dual { google, intel })
            }
        }
    }

    /// Request launcher tokens bound to `SHA-256(public_values)` and build a
    /// version-2 portable artifact.
    pub async fn attest<P>(
        &self,
        public_values: P,
    ) -> Result<ConfidentialSpaceAttestation, ConfidentialSpaceError>
    where
        P: Borrow<PublicValues>,
    {
        let public_values = public_values.borrow().clone();
        let tokens = self
            .request_tokens(&public_values.commitment_hash())
            .await?;
        Ok(ConfidentialSpaceAttestation {
            schema_version: CONFIDENTIAL_SPACE_ATTESTATION_SCHEMA_VERSION,
            tokens,
            public_values,
        })
    }

    async fn request_token(
        &self,
        issuer: ConfidentialSpaceIssuer,
        commitment: &[u8; 32],
    ) -> Result<String, ConfidentialSpaceError> {
        #[cfg(not(unix))]
        {
            let _ = issuer;
            let _ = commitment;
            return Err(ConfidentialSpaceError::Launcher(
                "Unix domain sockets are unsupported on this platform".to_string(),
            ));
        }

        #[cfg(unix)]
        {
            #[derive(Serialize)]
            struct TokenRequest<'a> {
                audience: &'a str,
                token_type: &'static str,
                nonces: [String; 1],
            }

            let client = reqwest::Client::builder()
                .unix_socket(self.config.launcher_socket.clone())
                .timeout(std::time::Duration::from_secs(
                    self.config.request_timeout_secs,
                ))
                .build()
                .map_err(|error| ConfidentialSpaceError::Launcher(error.to_string()))?;
            let request = TokenRequest {
                audience: &self.config.audience,
                token_type: "OIDC",
                nonces: [BASE64URL.encode(commitment)],
            };
            let response = client
                .post(format!("http://localhost{}", issuer.launcher_path()))
                .header("Accept", "application/json")
                .json(&request)
                .send()
                .await
                .map_err(|error| ConfidentialSpaceError::Launcher(error.to_string()))?;
            let status = response.status();
            let body = response
                .text()
                .await
                .map_err(|error| ConfidentialSpaceError::Launcher(error.to_string()))?;
            if !status.is_success() {
                return Err(ConfidentialSpaceError::LauncherStatus {
                    issuer,
                    status: status.as_u16(),
                    body,
                });
            }
            normalize_launcher_token(issuer, &body)
        }
    }
}

fn normalize_launcher_token(
    issuer: ConfidentialSpaceIssuer,
    body: &str,
) -> Result<String, ConfidentialSpaceError> {
    let token = match serde_json::from_str::<serde_json::Value>(body) {
        Ok(serde_json::Value::String(token)) => Some(token),
        Ok(serde_json::Value::Object(envelope)) => envelope
            .get("token")
            .or_else(|| envelope.get("attestation_token"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        Ok(_) => None,
        Err(_) => Some(body.to_string()),
    }
    .map(|token| token.trim().to_string())
    .filter(|token| !token.is_empty())
    .ok_or_else(|| ConfidentialSpaceError::LauncherResponse {
        issuer,
        message: "response is missing a non-empty token".to_string(),
    })?;

    if token.split('.').count() != 3 {
        return Err(ConfidentialSpaceError::LauncherResponse {
            issuer,
            message: "token is not a three-part JWT".to_string(),
        });
    }
    Ok(token)
}

fn validate_audience(audience: &str) -> Result<(), ConfidentialSpaceError> {
    if audience.trim().is_empty() {
        return Err(ConfidentialSpaceError::InvalidConfiguration(
            "audience must not be empty".to_string(),
        ));
    }
    if audience.len() > MAX_AUDIENCE_BYTES {
        return Err(ConfidentialSpaceError::InvalidConfiguration(format!(
            "audience is {} bytes; maximum is {MAX_AUDIENCE_BYTES}",
            audience.len()
        )));
    }
    Ok(())
}

/// Portable Confidential Space attestation artifact.
#[derive(Debug, Clone, Serialize)]
pub struct ConfidentialSpaceAttestation {
    /// Required artifact schema version.
    pub schema_version: u32,
    /// Issuer-specific signed tokens.
    pub tokens: ConfidentialSpaceTokens,
    /// Values whose SHA-256 commitment is carried as the sole `eat_nonce`.
    pub public_values: PublicValues,
}

#[derive(Deserialize)]
struct ConfidentialSpaceAttestationWire {
    #[serde(default)]
    schema_version: Option<u32>,
    tokens: ConfidentialSpaceTokens,
    public_values: PublicValues,
}

impl<'de> Deserialize<'de> for ConfidentialSpaceAttestation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ConfidentialSpaceAttestationWire::deserialize(deserializer)?;
        let version = wire.schema_version.ok_or_else(|| {
            D::Error::custom(
                "unsupported legacy Confidential Space artifact: schema_version is required; only version 2 is supported",
            )
        })?;
        if version != CONFIDENTIAL_SPACE_ATTESTATION_SCHEMA_VERSION {
            return Err(D::Error::custom(format!(
                "unsupported Confidential Space attestation schema version {version}; only version 2 is supported"
            )));
        }
        Ok(Self {
            schema_version: version,
            tokens: wire.tokens,
            public_values: wire.public_values,
        })
    }
}

impl ConfidentialSpaceAttestation {
    /// Return `SHA-256(public_values)`.
    #[must_use]
    pub fn commitment_hash(&self) -> [u8; 32] {
        self.public_values.commitment_hash()
    }

    /// Verify issuer tokens and strict Confidential Space workload policy.
    pub async fn verify(
        &self,
        policy: &ConfidentialSpaceVerificationPolicy,
    ) -> Result<ConfidentialSpaceVerification, ConfidentialSpaceError> {
        if self.schema_version != CONFIDENTIAL_SPACE_ATTESTATION_SCHEMA_VERSION {
            return Err(ConfidentialSpaceError::UnsupportedArtifactVersion(
                self.schema_version,
            ));
        }
        policy.validate()?;

        let expected_nonce = BASE64URL.encode(self.commitment_hash());
        let mode = self.tokens.attester_mode();
        let (google, google_claims) = match self.tokens.google() {
            Some(token) => {
                let (result, claims) = verify_issuer_token(
                    ConfidentialSpaceIssuer::Google,
                    token,
                    &expected_nonce,
                    policy,
                )
                .await;
                (Some(result), claims)
            }
            None => (None, None),
        };
        let (intel, intel_claims) = match self.tokens.intel() {
            Some(token) => {
                let (result, claims) = verify_issuer_token(
                    ConfidentialSpaceIssuer::Intel,
                    token,
                    &expected_nonce,
                    policy,
                )
                .await;
                (Some(result), claims)
            }
            None => (None, None),
        };

        let dual_claims_match = if mode == ConfidentialSpaceAttesterMode::Dual {
            Some(matches!(
                (google_claims, intel_claims),
                (Some(google), Some(intel)) if google == intel
            ))
        } else {
            None
        };

        Ok(ConfidentialSpaceVerification {
            attester_mode: mode,
            google,
            intel,
            dual_claims_match,
        })
    }
}

/// Relying-party Confidential Space verification policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialSpaceVerificationPolicy {
    /// Exact required OIDC audience.
    pub expected_audience: String,
    /// Exact required canonical `sha256:…` container image digest.
    pub expected_image_digest: String,
    /// Accepted signed TDX TCB status values.
    #[serde(default = "default_accepted_tcb_statuses")]
    pub accepted_tcb_statuses: Vec<String>,
    /// Optional minimum signed TDX TCB date in canonical UTC form.
    #[serde(default)]
    pub minimum_tcb_date: Option<String>,
    /// Optional minimum Confidential Space image version (`YYMM##` or `YYYYMM##`).
    #[serde(default)]
    pub minimum_confidential_space_version: Option<String>,
    /// Maximum age of the signed `iat` claim, allowing 60 seconds of clock skew.
    #[serde(default = "default_max_token_age_secs")]
    pub max_token_age_secs: u64,
    /// OIDC discovery/JWKS timeout in seconds.
    pub request_timeout_secs: u64,
    /// Optional trusted Google JWKS mirror or test endpoint.
    ///
    /// The signed token issuer remains fixed to
    /// [`CONFIDENTIAL_SPACE_GOOGLE_ISSUER`].
    pub google_jwks_url: Option<String>,
    /// Optional trusted Intel JWKS mirror or test endpoint.
    ///
    /// The signed token issuer remains fixed to
    /// [`CONFIDENTIAL_SPACE_INTEL_ISSUER`].
    pub intel_jwks_url: Option<String>,
}

impl ConfidentialSpaceVerificationPolicy {
    /// Create the required relying-party policy.
    #[must_use]
    pub fn new(
        expected_audience: impl Into<String>,
        expected_image_digest: impl Into<String>,
    ) -> Self {
        Self {
            expected_audience: expected_audience.into(),
            expected_image_digest: expected_image_digest.into(),
            accepted_tcb_statuses: default_accepted_tcb_statuses(),
            minimum_tcb_date: None,
            minimum_confidential_space_version: None,
            max_token_age_secs: default_max_token_age_secs(),
            request_timeout_secs: 30,
            google_jwks_url: None,
            intel_jwks_url: None,
        }
    }

    fn validate(&self) -> Result<(), ConfidentialSpaceError> {
        validate_audience(&self.expected_audience)?;
        let digest = self.expected_image_digest.as_bytes();
        if digest.len() != 71
            || !self.expected_image_digest.starts_with("sha256:")
            || !digest[7..]
                .iter()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ConfidentialSpaceError::InvalidConfiguration(
                "expected_image_digest must be canonical lowercase sha256:<64 hex chars>"
                    .to_string(),
            ));
        }
        if self.request_timeout_secs == 0 {
            return Err(ConfidentialSpaceError::InvalidConfiguration(
                "request_timeout_secs must be greater than zero".to_string(),
            ));
        }
        if self.max_token_age_secs == 0 {
            return Err(ConfidentialSpaceError::InvalidConfiguration(
                "max_token_age_secs must be greater than zero".to_string(),
            ));
        }
        if self.accepted_tcb_statuses.is_empty()
            || self
                .accepted_tcb_statuses
                .iter()
                .any(|status| status.trim().is_empty())
        {
            return Err(ConfidentialSpaceError::InvalidConfiguration(
                "accepted_tcb_statuses must contain at least one non-empty value".to_string(),
            ));
        }
        if self
            .minimum_tcb_date
            .as_deref()
            .is_some_and(|date| parse_tcb_date(date).is_none())
        {
            return Err(ConfidentialSpaceError::InvalidConfiguration(
                "minimum_tcb_date must use canonical YYYY-MM-DDThh:mm:ssZ UTC form".to_string(),
            ));
        }
        if self
            .minimum_confidential_space_version
            .as_deref()
            .is_some_and(|version| parse_confidential_space_version(version).is_none())
        {
            return Err(ConfidentialSpaceError::InvalidConfiguration(
                "minimum_confidential_space_version must use YYMM## or YYYYMM## form".to_string(),
            ));
        }
        Ok(())
    }

    async fn jwks_url(&self, issuer: ConfidentialSpaceIssuer) -> Result<String, String> {
        let configured = match issuer {
            ConfidentialSpaceIssuer::Google => self.google_jwks_url.as_ref(),
            ConfidentialSpaceIssuer::Intel => self.intel_jwks_url.as_ref(),
        };
        if let Some(url) = configured {
            if url.trim().is_empty() {
                return Err("configured JWKS URL is empty".to_string());
            }
            return Ok(url.clone());
        }

        discover_jwks_url(
            issuer.discovery_url(),
            issuer.expected_issuer(),
            self.request_timeout_secs,
        )
        .await
        .map_err(|error| error.to_string())
    }
}

/// Issuer-specific Confidential Space verification diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use = "issuer verification is diagnostic until all_passed() is checked"]
pub struct ConfidentialSpaceIssuerVerification {
    /// Token issuer represented by this report.
    pub issuer: ConfidentialSpaceIssuer,
    /// A non-empty token was supplied.
    pub token_present: bool,
    /// JWT signature, expiry, and not-before checks passed.
    pub jwt_signature_and_time_valid: bool,
    /// Signed `iat` is present, not materially in the future, and recent enough.
    pub token_fresh: bool,
    /// Token `iss` exactly matches the fixed trusted issuer.
    pub issuer_matches: bool,
    /// Token `aud` exactly matches the relying-party policy.
    pub audience_matches: bool,
    /// Exactly one `eat_nonce` equals the encoded 32-byte commitment.
    pub commitment_nonce_matches: bool,
    /// Container image digest exactly matches policy.
    pub image_digest_matches: bool,
    /// `swname` identifies Confidential Space.
    pub confidential_space_image: bool,
    /// Debugging has remained disabled since boot.
    pub production_image: bool,
    /// Secure Boot is enabled.
    pub secure_boot_enabled: bool,
    /// Hardware model is Google Cloud Intel TDX.
    pub intel_tdx: bool,
    /// The signed TCB root identifies Intel.
    pub intel_tcb_attester: bool,
    /// The signed TDX TCB status is accepted by policy.
    pub tcb_status_allowed: bool,
    /// The signed TDX TCB date is canonical and meets the optional policy minimum.
    pub tcb_date_allowed: bool,
    /// The signed Confidential Space version is canonical and meets the optional minimum.
    pub confidential_space_version_allowed: bool,
    /// Confidential Space image carries the `STABLE` support attribute.
    pub stable_support: bool,
    /// Memory monitoring is explicitly disabled.
    pub memory_monitoring_disabled: bool,
    /// No operator command override is present.
    pub cmd_override_empty: bool,
    /// No operator environment override is present.
    pub env_override_empty: bool,
    /// Signed TDX TCB status, if unambiguously present.
    pub tcb_status: String,
    /// Signed TDX TCB date, if unambiguously present.
    pub tcb_date: Option<String>,
    /// Signed Confidential Space image version, if unambiguously present.
    pub confidential_space_version: Option<String>,
    /// Signature/JWKS/claim parsing failure, if one occurred.
    pub verification_error: Option<String>,
}

impl ConfidentialSpaceIssuerVerification {
    fn failed(issuer: ConfidentialSpaceIssuer, token_present: bool, message: String) -> Self {
        Self {
            issuer,
            token_present,
            jwt_signature_and_time_valid: false,
            token_fresh: false,
            issuer_matches: false,
            audience_matches: false,
            commitment_nonce_matches: false,
            image_digest_matches: false,
            confidential_space_image: false,
            production_image: false,
            secure_boot_enabled: false,
            intel_tdx: false,
            intel_tcb_attester: false,
            tcb_status_allowed: false,
            tcb_date_allowed: false,
            confidential_space_version_allowed: false,
            stable_support: false,
            memory_monitoring_disabled: false,
            cmd_override_empty: false,
            env_override_empty: false,
            tcb_status: String::new(),
            tcb_date: None,
            confidential_space_version: None,
            verification_error: Some(message),
        }
    }

    /// Return `true` only when every issuer-specific check passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.token_present
            && self.jwt_signature_and_time_valid
            && self.token_fresh
            && self.issuer_matches
            && self.audience_matches
            && self.commitment_nonce_matches
            && self.image_digest_matches
            && self.confidential_space_image
            && self.production_image
            && self.secure_boot_enabled
            && self.intel_tdx
            && self.intel_tcb_attester
            && self.tcb_status_allowed
            && self.tcb_date_allowed
            && self.confidential_space_version_allowed
            && self.stable_support
            && self.memory_monitoring_disabled
            && self.cmd_override_empty
            && self.env_override_empty
            && self.verification_error.is_none()
    }
}

/// Combined single- or dual-issuer verification diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use = "verification is diagnostic until all_passed() is checked"]
pub struct ConfidentialSpaceVerification {
    /// Required issuer mode encoded by the artifact.
    pub attester_mode: ConfidentialSpaceAttesterMode,
    /// Google issuer diagnostics, if a Google token was required.
    pub google: Option<ConfidentialSpaceIssuerVerification>,
    /// Intel issuer diagnostics, if an Intel token was required.
    pub intel: Option<ConfidentialSpaceIssuerVerification>,
    /// Equality of common signed workload/posture claims in dual mode.
    pub dual_claims_match: Option<bool>,
}

impl ConfidentialSpaceVerification {
    /// Return `true` only when every required issuer and cross-issuer check passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        match self.attester_mode {
            ConfidentialSpaceAttesterMode::Google => self
                .google
                .as_ref()
                .is_some_and(ConfidentialSpaceIssuerVerification::all_passed),
            ConfidentialSpaceAttesterMode::Intel => self
                .intel
                .as_ref()
                .is_some_and(ConfidentialSpaceIssuerVerification::all_passed),
            ConfidentialSpaceAttesterMode::Dual => {
                self.google
                    .as_ref()
                    .is_some_and(ConfidentialSpaceIssuerVerification::all_passed)
                    && self
                        .intel
                        .as_ref()
                        .is_some_and(ConfidentialSpaceIssuerVerification::all_passed)
                    && self.dual_claims_match == Some(true)
            }
        }
    }

    /// Enforce the strict verdict while retaining this diagnostic report.
    pub fn require_success(&self) -> Result<(), &Self> {
        if self.all_passed() {
            Ok(())
        } else {
            Err(self)
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ConfidentialSpaceClaims {
    #[serde(default)]
    iss: String,
    #[serde(default)]
    aud: serde_json::Value,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    attester_tcb: Vec<String>,
    #[serde(default)]
    eat_nonce: serde_json::Value,
    #[serde(default)]
    dbgstat: String,
    #[serde(default)]
    hwmodel: String,
    #[serde(default)]
    secboot: Option<bool>,
    #[serde(default)]
    sub: String,
    #[serde(default)]
    swname: String,
    #[serde(default)]
    swversion: Vec<String>,
    #[serde(default)]
    tdx: serde_json::Value,
    #[serde(default)]
    submods: SubmodsClaims,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct TdxClaims {
    #[serde(default)]
    gcp_attester_tcb_status: String,
    #[serde(default)]
    gcp_attester_tcb_date: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct SubmodsClaims {
    #[serde(default)]
    confidential_space: ConfidentialSpacePostureClaims,
    #[serde(default)]
    container: ContainerClaims,
    #[serde(default)]
    gce: serde_json::Value,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ConfidentialSpacePostureClaims {
    #[serde(default)]
    support_attributes: Vec<String>,
    #[serde(default)]
    monitoring_enabled: MonitoringClaims,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct MonitoringClaims {
    #[serde(default)]
    memory: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ContainerClaims {
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    cmd_override: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    env_override: BTreeMap<String, String>,
    #[serde(default)]
    image_digest: String,
    #[serde(default)]
    image_id: String,
    #[serde(default)]
    image_reference: String,
    #[serde(default)]
    image_signatures: serde_json::Value,
    #[serde(default)]
    restart_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommonWorkloadClaims {
    commitment_nonce: String,
    subject: String,
    hwmodel: String,
    dbgstat: String,
    secboot: Option<bool>,
    swname: String,
    swversion: Vec<String>,
    support_attributes: BTreeSet<String>,
    memory_monitoring: Option<bool>,
    args: Vec<String>,
    cmd_override: Vec<String>,
    env: BTreeMap<String, String>,
    env_override: BTreeMap<String, String>,
    image_digest: String,
    image_id: String,
    image_reference: String,
    image_signatures: serde_json::Value,
    restart_policy: String,
    gce: serde_json::Value,
}

async fn verify_issuer_token(
    issuer: ConfidentialSpaceIssuer,
    token: &str,
    expected_nonce: &str,
    policy: &ConfidentialSpaceVerificationPolicy,
) -> (
    ConfidentialSpaceIssuerVerification,
    Option<CommonWorkloadClaims>,
) {
    if token.trim().is_empty() {
        return (
            ConfidentialSpaceIssuerVerification::failed(
                issuer,
                false,
                "required token is missing".to_string(),
            ),
            None,
        );
    }

    let jwks_url = match policy.jwks_url(issuer).await {
        Ok(url) => url,
        Err(message) => {
            return (
                ConfidentialSpaceIssuerVerification::failed(issuer, true, message),
                None,
            )
        }
    };
    let claims = match verify_jwt_with_jwks::<ConfidentialSpaceClaims>(
        token,
        &jwks_url,
        policy.request_timeout_secs,
        issuer.accepted_algorithms(),
    )
    .await
    {
        Ok(claims) => claims,
        Err(error) => {
            return (
                ConfidentialSpaceIssuerVerification::failed(issuer, true, error.to_string()),
                None,
            )
        }
    };

    let nonce = exactly_one_nonce(&claims.eat_nonce);
    let support_attributes: BTreeSet<String> = claims
        .submods
        .confidential_space
        .support_attributes
        .iter()
        .cloned()
        .collect();
    let tdx = exactly_one_tdx_claim(&claims.tdx);
    let tcb_status = tdx
        .as_ref()
        .map(|claims| claims.gcp_attester_tcb_status.trim())
        .filter(|status| !status.is_empty())
        .map(str::to_string);
    let tcb_date = tdx
        .as_ref()
        .map(|claims| claims.gcp_attester_tcb_date.trim())
        .filter(|date| !date.is_empty())
        .map(str::to_string);
    let confidential_space_version = exactly_one_confidential_space_version(&claims.swversion);
    let token_fresh = claims
        .iat
        .is_some_and(|issued_at| token_is_fresh(issued_at, policy.max_token_age_secs));
    let tcb_status_allowed = tcb_status.as_deref().is_some_and(|status| {
        policy
            .accepted_tcb_statuses
            .iter()
            .any(|accepted| accepted.trim().eq_ignore_ascii_case(status))
    });
    let tcb_date_allowed = tcb_date.as_deref().is_some_and(|date| {
        parse_tcb_date(date).is_some_and(|actual| {
            policy
                .minimum_tcb_date
                .as_deref()
                .and_then(parse_tcb_date)
                .map_or(true, |minimum| actual >= minimum)
        })
    });
    let confidential_space_version_allowed =
        confidential_space_version
            .as_deref()
            .is_some_and(|version| {
                parse_confidential_space_version(version).is_some_and(|actual| {
                    policy
                        .minimum_confidential_space_version
                        .as_deref()
                        .and_then(parse_confidential_space_version)
                        .map_or(true, |minimum| actual >= minimum)
                })
            });
    let result = ConfidentialSpaceIssuerVerification {
        issuer,
        token_present: true,
        jwt_signature_and_time_valid: true,
        token_fresh,
        issuer_matches: claims.iss == issuer.expected_issuer(),
        audience_matches: claims.aud.as_str() == Some(policy.expected_audience.as_str()),
        commitment_nonce_matches: nonce.as_deref() == Some(expected_nonce),
        image_digest_matches: claims.submods.container.image_digest == policy.expected_image_digest,
        confidential_space_image: claims.swname == "CONFIDENTIAL_SPACE",
        production_image: claims.dbgstat == "disabled-since-boot",
        secure_boot_enabled: claims.secboot == Some(true),
        intel_tdx: claims.hwmodel == "GCP_INTEL_TDX",
        intel_tcb_attester: claims.attester_tcb.as_slice() == ["INTEL"],
        tcb_status_allowed,
        tcb_date_allowed,
        confidential_space_version_allowed,
        stable_support: support_attributes.contains("STABLE"),
        memory_monitoring_disabled: claims.submods.confidential_space.monitoring_enabled.memory
            == Some(false),
        cmd_override_empty: claims.submods.container.cmd_override.is_empty(),
        env_override_empty: claims.submods.container.env_override.is_empty(),
        tcb_status: tcb_status.unwrap_or_default(),
        tcb_date,
        confidential_space_version,
        verification_error: None,
    };
    let common = nonce.map(|commitment_nonce| CommonWorkloadClaims {
        commitment_nonce,
        subject: claims.sub,
        hwmodel: claims.hwmodel,
        dbgstat: claims.dbgstat,
        secboot: claims.secboot,
        swname: claims.swname,
        swversion: claims.swversion,
        support_attributes,
        memory_monitoring: claims.submods.confidential_space.monitoring_enabled.memory,
        args: claims.submods.container.args,
        cmd_override: claims.submods.container.cmd_override,
        env: claims.submods.container.env,
        env_override: claims.submods.container.env_override,
        image_digest: claims.submods.container.image_digest,
        image_id: claims.submods.container.image_id,
        image_reference: claims.submods.container.image_reference,
        image_signatures: claims.submods.container.image_signatures,
        restart_policy: claims.submods.container.restart_policy,
        gce: claims.submods.gce,
    });

    (result, common)
}

fn exactly_one_nonce(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(nonce) if !nonce.is_empty() => Some(nonce.clone()),
        serde_json::Value::Array(nonces) if nonces.len() == 1 => nonces[0]
            .as_str()
            .filter(|nonce| !nonce.is_empty())
            .map(str::to_string),
        _ => None,
    }
}

fn default_accepted_tcb_statuses() -> Vec<String> {
    vec!["UpToDate".to_string()]
}

const fn default_max_token_age_secs() -> u64 {
    DEFAULT_MAX_TOKEN_AGE_SECS
}

fn token_is_fresh(issued_at: u64, max_age_secs: u64) -> bool {
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return false;
    };
    let now = now.as_secs();
    issued_at <= now.saturating_add(TOKEN_CLOCK_SKEW_SECS)
        && now
            <= issued_at
                .saturating_add(max_age_secs)
                .saturating_add(TOKEN_CLOCK_SKEW_SECS)
}

fn exactly_one_tdx_claim(value: &serde_json::Value) -> Option<TdxClaims> {
    match value {
        serde_json::Value::Object(_) => serde_json::from_value(value.clone()).ok(),
        serde_json::Value::Array(claims) if claims.len() == 1 => {
            serde_json::from_value(claims[0].clone()).ok()
        }
        _ => None,
    }
}

fn exactly_one_confidential_space_version(versions: &[String]) -> Option<String> {
    if versions.len() != 1 {
        return None;
    }
    let version = versions[0].trim();
    (!version.is_empty()).then(|| version.to_string())
}

fn parse_confidential_space_version(version: &str) -> Option<(u16, u8, u8)> {
    let bytes = version.as_bytes();
    if !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let (year, month, revision) = match bytes.len() {
        6 => (
            2_000 + parse_ascii_number::<u16>(&bytes[0..2])?,
            parse_ascii_number::<u8>(&bytes[2..4])?,
            parse_ascii_number::<u8>(&bytes[4..6])?,
        ),
        8 => (
            parse_ascii_number::<u16>(&bytes[0..4])?,
            parse_ascii_number::<u8>(&bytes[4..6])?,
            parse_ascii_number::<u8>(&bytes[6..8])?,
        ),
        _ => return None,
    };
    (year > 0 && (1..=12).contains(&month)).then_some((year, month, revision))
}

fn parse_tcb_date(date: &str) -> Option<(u16, u8, u8, u8, u8, u8)> {
    let bytes = date.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return None;
    }
    let year = parse_ascii_number::<u16>(&bytes[0..4])?;
    let month = parse_ascii_number::<u8>(&bytes[5..7])?;
    let day = parse_ascii_number::<u8>(&bytes[8..10])?;
    let hour = parse_ascii_number::<u8>(&bytes[11..13])?;
    let minute = parse_ascii_number::<u8>(&bytes[14..16])?;
    let second = parse_ascii_number::<u8>(&bytes[17..19])?;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return None,
    };
    (year > 0 && (1..=days_in_month).contains(&day) && hour <= 23 && minute <= 59 && second <= 59)
        .then_some((year, month, day, hour, minute, second))
}

fn parse_ascii_number<T>(bytes: &[u8]) -> Option<T>
where
    T: std::str::FromStr,
{
    if !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

const fn is_leap_year(year: u16) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}
