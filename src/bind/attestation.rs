// SPDX-License-Identifier: MIT
//! High-level instance attestation builder and verifier API.

use super::local::{
    nonce_and_commitment_hash, verify_quote_report_data_binding, verify_quote_with_public_values,
};
use crate::{
    error::{AttestError, LivyEnvError, PublicValuesError, VerifyError},
    evidence::Evidence,
    public_values::PublicValues,
    verify::{
        codec::decode_standard_base64,
        ita::{
            appraise_evidence_authenticated, default_issuer_for_jwks_url, verify_attestation_token,
            ItaConfig, VerifierNonce, DEFAULT_JWKS_URL,
        },
    },
};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;

/// The only supported serialized [`Attestation`] schema version.
pub const ATTESTATION_SCHEMA_VERSION: u32 = 2;

/// Policy for [`Attestation::verify_with_policy`] and
/// [`Attestation::verify_fresh_with_policy`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AttestationVerificationPolicy {
    /// Intel Trust Authority JWKS endpoint used to verify the token signature.
    pub jwks_url: String,
    /// Optional expected token issuer (`iss`).
    ///
    /// If this is `None`, verification derives the issuer from `jwks_url`.
    pub expected_token_issuer: Option<String>,
    /// Optional expected token audience (`aud`).
    ///
    /// If this is `None`, audience is not enforced.
    pub expected_token_audience: Option<String>,
    /// Timeout in seconds for JWKS HTTP requests.
    pub request_timeout_secs: u64,
    /// Accepted ITA TCB status values. Defaults to only `"UpToDate"`.
    pub accepted_tcb_statuses: Vec<String>,
    /// Optional exact advisory-ID set expected from the signed ITA token.
    ///
    /// Matching is case-insensitive and order-insensitive.
    pub expected_advisory_ids: Option<Vec<String>>,
    /// Optional expected MRTD, as a 96-character hex string.
    ///
    /// MRTD is a platform launch measurement. It is not, by itself, a
    /// measurement of the application running in the VM.
    pub expected_mrtd: Option<String>,
}

impl Default for AttestationVerificationPolicy {
    fn default() -> Self {
        Self {
            jwks_url: DEFAULT_JWKS_URL.to_string(),
            expected_token_issuer: None,
            expected_token_audience: None,
            request_timeout_secs: 30,
            accepted_tcb_statuses: vec!["UpToDate".to_string()],
            expected_advisory_ids: None,
            expected_mrtd: None,
        }
    }
}

/// Diagnostic report returned by instance attestation verification.
///
/// `Ok(report)` is still diagnostic. Use [`require_success`](Self::require_success)
/// or [`all_passed`](Self::all_passed) for a strict verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use = "verification is diagnostic until you check all_passed() or require_success()"]
#[non_exhaustive]
pub struct AttestationVerification {
    /// `true` when the ITA JWT passed signature and registered time validation.
    pub jwt_signature_and_expiry_valid: bool,
    /// Why token validation failed, when it failed non-fatally.
    pub token_verification_error: Option<VerifyError>,
    /// `true` when the signed token binding matches the verifier nonce and
    /// `SHA-256(public_values)` commitment.
    pub token_report_data_matches: bool,
    /// Local raw-quote binding result, when this attestation format exposes it.
    ///
    /// `None` is the normal Azure case because its stored quote does not expose
    /// the same portable binding surface.
    pub quote_report_data_matches: Option<bool>,
    /// `true` when the public `mrtd` field matches the verified token claim.
    pub mrtd_matches_token: bool,
    /// `true` when the public `tcb_status` field matches the verified token claim.
    pub tcb_status_matches_token: bool,
    /// `true` when the public `tcb_date` field matches the verified token claim.
    pub tcb_date_matches_token: bool,
    /// `true` when the public advisory-ID list matches the verified token claim.
    pub advisory_ids_match_token: bool,
    /// `true` when the token TCB status is accepted by the verification policy.
    pub tcb_status_allowed: bool,
    /// TCB status extracted from the verified token.
    pub tcb_status: String,
    /// Optional TCB date extracted from the verified token.
    pub tcb_date: Option<String>,
    /// Advisory IDs extracted from the verified token.
    pub advisory_ids: Vec<String>,
    /// MRTD extracted from the verified token.
    pub mrtd: String,
    /// Result of comparing token advisory IDs to the policy's expected set.
    pub expected_advisory_ids_matches: Option<bool>,
    /// Result of comparing token MRTD to the policy's expected MRTD.
    pub expected_mrtd_matches: Option<bool>,
    /// Result of fresh ITA appraisal of the bundled evidence, when performed.
    pub bundled_evidence_authenticated: Option<bool>,
}

impl AttestationVerification {
    /// Return `true` when every required verification check passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.jwt_signature_and_expiry_valid
            && self.token_report_data_matches
            && self.quote_report_data_matches.unwrap_or(true)
            && self.mrtd_matches_token
            && self.tcb_status_matches_token
            && self.tcb_date_matches_token
            && self.advisory_ids_match_token
            && self.tcb_status_allowed
            && self.expected_advisory_ids_matches.unwrap_or(true)
            && self.expected_mrtd_matches.unwrap_or(true)
            && self.bundled_evidence_authenticated.unwrap_or(true)
    }

    /// Enforce the strict verification contract while preserving diagnostics.
    pub fn require_success(&self) -> Result<(), &Self> {
        if self.all_passed() {
            Ok(())
        } else {
            Err(self)
        }
    }
}

/// Client entry point for instance-based TDX attestation.
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
    pub fn from_env() -> Result<Self, LivyEnvError> {
        let key = std::env::var("ITA_API_KEY").map_err(|_| LivyEnvError::MissingApiKey)?;
        if key.trim().is_empty() {
            return Err(LivyEnvError::EmptyApiKey);
        }
        Ok(Self::new(key))
    }

    /// Start building an attestation.
    pub fn attest(&self) -> AttestBuilder<'_> {
        AttestBuilder {
            config: &self.config,
            public_values: PublicValues::new(),
            pending_public_values_error: None,
        }
    }
}

/// Builder for a single instance-based TDX attestation.
#[derive(Debug, Clone)]
pub struct AttestBuilder<'a> {
    config: &'a ItaConfig,
    public_values: PublicValues,
    pending_public_values_error: Option<PublicValuesError>,
}

impl<'a> AttestBuilder<'a> {
    /// Commit a typed value as a public output.
    pub fn commit<T: Serialize>(&mut self, value: &T) -> &mut Self {
        let result = self.public_values.commit(value).map(|_| ());
        self.record_public_values_result(result);
        self
    }

    /// Commit the SHA-256 hash of a serialized value instead of the value itself.
    pub fn commit_hashed<T: Serialize>(&mut self, value: &T) -> &mut Self {
        use sha2::{Digest, Sha256};
        let result = serde_json::to_vec(value)
            .map_err(|e| PublicValuesError::Serialize(e.to_string()))
            .and_then(|encoded| {
                let hash: [u8; 32] = Sha256::digest(&encoded).into();
                self.public_values.commit_raw(&hash).map(|_| ())
            });
        self.record_public_values_result(result);
        self
    }

    /// Commit raw bytes as a public output (no serialization wrapper).
    pub fn commit_raw(&mut self, bytes: &[u8]) -> &mut Self {
        let result = self.public_values.commit_raw(bytes).map(|_| ());
        self.record_public_values_result(result);
        self
    }

    /// Generate a TDX quote and obtain an ITA attestation token.
    pub async fn finalize(self) -> Result<Attestation, AttestError> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        if let Some(err) = self.pending_public_values_error {
            return Err(AttestError::PublicValues(err));
        }

        let commitment = self.public_values.commitment_hash();
        let attested = crate::attest::generate_and_attest(&commitment, self.config).await?;

        Ok(Attestation {
            schema_version: ATTESTATION_SCHEMA_VERSION,
            ita_token: attested.ita_token,
            jwks_url: self.config.default_jwks_url(),
            mrtd: attested.mrtd,
            tcb_status: attested.tcb_status,
            tcb_date: attested.tcb_date,
            advisory_ids: attested.advisory_ids,
            evidence: attested.evidence.to_transport_string(),
            raw_quote: BASE64.encode(attested.evidence.raw()),
            verifier_nonce_val: BASE64.encode(&attested.nonce_val),
            verifier_nonce_iat: BASE64.encode(&attested.nonce_iat),
            verifier_nonce_signature: BASE64.encode(&attested.nonce_signature),
            public_values: self.public_values,
        })
    }

    fn record_public_values_result(&mut self, result: Result<(), PublicValuesError>) {
        if self.pending_public_values_error.is_none() {
            if let Err(err) = result {
                self.pending_public_values_error = Some(err);
            }
        }
    }
}

/// A version-2 instance TDX attestation plus its committed public values.
///
/// The only application-controlled quote input is
/// `SHA-256(public_values)`. MRTD describes the VM launch measurement and does
/// not independently identify the application running inside the instance.
#[derive(Debug, Clone, Serialize)]
pub struct Attestation {
    /// Required artifact schema version. Must equal [`ATTESTATION_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// ITA-signed JWT.
    pub ita_token: String,
    /// JWKS endpoint that matches the ITA region used to mint `ita_token`.
    pub jwks_url: String,
    /// Hex-encoded platform launch MRTD (96 chars = 48 bytes).
    pub mrtd: String,
    /// TCB status from Intel Trust Authority.
    pub tcb_status: String,
    /// Optional TCB assessment date from Intel Trust Authority claims.
    pub tcb_date: Option<String>,
    /// Advisory IDs reported by Intel Trust Authority.
    pub advisory_ids: Vec<String>,
    /// Portable low-level evidence artifact.
    pub evidence: String,
    /// Base64-encoded raw DCAP quote.
    pub raw_quote: String,
    /// Base64-encoded verifier nonce value bytes.
    pub verifier_nonce_val: String,
    /// Base64-encoded verifier nonce issued-at bytes.
    pub verifier_nonce_iat: String,
    /// Base64-encoded verifier nonce signature bytes.
    pub verifier_nonce_signature: String,
    /// The committed public values.
    pub public_values: PublicValues,
}

#[derive(Deserialize)]
struct AttestationWire {
    #[serde(default)]
    schema_version: Option<u32>,
    ita_token: String,
    jwks_url: String,
    mrtd: String,
    tcb_status: String,
    tcb_date: Option<String>,
    #[serde(default)]
    advisory_ids: Vec<String>,
    evidence: String,
    raw_quote: String,
    verifier_nonce_val: String,
    verifier_nonce_iat: String,
    verifier_nonce_signature: String,
    public_values: PublicValues,
}

impl<'de> Deserialize<'de> for Attestation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AttestationWire::deserialize(deserializer)?;
        let version = wire.schema_version.ok_or_else(|| {
            D::Error::custom(
                "unsupported legacy attestation artifact: schema_version is required; only version 2 is supported",
            )
        })?;
        if version != ATTESTATION_SCHEMA_VERSION {
            return Err(D::Error::custom(format!(
                "unsupported attestation schema version {version}; only version 2 is supported"
            )));
        }

        Ok(Self {
            schema_version: version,
            ita_token: wire.ita_token,
            jwks_url: wire.jwks_url,
            mrtd: wire.mrtd,
            tcb_status: wire.tcb_status,
            tcb_date: wire.tcb_date,
            advisory_ids: wire.advisory_ids,
            evidence: wire.evidence,
            raw_quote: wire.raw_quote,
            verifier_nonce_val: wire.verifier_nonce_val,
            verifier_nonce_iat: wire.verifier_nonce_iat,
            verifier_nonce_signature: wire.verifier_nonce_signature,
            public_values: wire.public_values,
        })
    }
}

impl Attestation {
    /// Hex-encoded 32-byte public-values commitment.
    #[must_use]
    pub fn payload_hash_hex(&self) -> String {
        hex::encode(self.public_values.commitment_hash())
    }

    /// Return the 32-byte public-values commitment bound by this artifact.
    #[must_use]
    pub fn commitment_hash(&self) -> [u8; 32] {
        self.public_values.commitment_hash()
    }

    /// Verify that `public_values` are bound to the raw quote bytes.
    pub fn verify_binding(&self) -> Result<bool, crate::ExtractError> {
        verify_quote_with_public_values(
            &self.raw_quote,
            &self.verifier_nonce_val,
            &self.verifier_nonce_iat,
            &self.public_values,
        )
    }

    /// Verify the ITA token and local bindings against the default policy.
    pub async fn verify(&self) -> Result<AttestationVerification, VerifyError> {
        let policy = self.default_policy();
        self.verify_with_policy(&policy).await
    }

    /// Verify the attestation and reappraise the bundled evidence via ITA.
    pub async fn verify_fresh(
        &self,
        config: &ItaConfig,
    ) -> Result<AttestationVerification, VerifyError> {
        let policy = self.default_policy();
        self.verify_fresh_with_policy(config, &policy).await
    }

    /// Verify the ITA token and local bindings against an explicit policy.
    pub async fn verify_with_policy(
        &self,
        policy: &AttestationVerificationPolicy,
    ) -> Result<AttestationVerification, VerifyError> {
        Ok(self.verify_with_policy_context(policy).await?.report)
    }

    async fn verify_with_policy_context(
        &self,
        policy: &AttestationVerificationPolicy,
    ) -> Result<VerificationContext, VerifyError> {
        self.require_schema_v2()?;

        let expected_token_issuer = resolved_expected_token_issuer(policy);
        let (token, token_verification_error) = match verify_attestation_token(
            &self.ita_token,
            &policy.jwks_url,
            policy.request_timeout_secs,
            expected_token_issuer.as_deref(),
            policy.expected_token_audience.as_deref(),
        )
        .await
        {
            Ok(token) => (Some(token), None),
            Err(err) => (None, Some(err)),
        };
        let jwt_valid = token.is_some();

        let nonce_val = decode_standard_base64("verifier_nonce_val", &self.verifier_nonce_val)
            .map_err(VerifyError::InvalidAttestation)?;
        let nonce_iat = decode_standard_base64("verifier_nonce_iat", &self.verifier_nonce_iat)
            .map_err(VerifyError::InvalidAttestation)?;
        let commitment = self.public_values.commitment_hash();
        let expected_token_report_data =
            nonce_and_commitment_hash(&nonce_val, &nonce_iat, &commitment);
        let offline_quote_report_data_matches =
            verify_quote_report_data_binding(&self.raw_quote, &expected_token_report_data)
                .map_err(|err| VerifyError::InvalidAttestation(format!("raw_quote: {err}")))?;

        let tcb_status_allowed = token.as_ref().is_some_and(|token| {
            policy
                .accepted_tcb_statuses
                .iter()
                .any(|status| status.eq_ignore_ascii_case(token.tcb_status()))
        });

        let quote_report_data_matches = match token.as_ref() {
            None if self.supports_offline_quote_report_data_binding_hint() => {
                Some(offline_quote_report_data_matches)
            }
            None => None,
            Some(token) if token.supports_offline_quote_report_data_binding() => {
                Some(offline_quote_report_data_matches)
            }
            Some(_) => None,
        };

        let report = AttestationVerification {
            jwt_signature_and_expiry_valid: jwt_valid,
            token_verification_error,
            token_report_data_matches: token.as_ref().is_some_and(|token| {
                token.binding_matches(&commitment, &expected_token_report_data)
            }),
            quote_report_data_matches,
            mrtd_matches_token: token
                .as_ref()
                .is_some_and(|token| self.mrtd.eq_ignore_ascii_case(token.mrtd())),
            tcb_status_matches_token: token
                .as_ref()
                .is_some_and(|token| self.tcb_status == token.tcb_status()),
            tcb_date_matches_token: token
                .as_ref()
                .is_some_and(|token| self.tcb_date.as_deref() == token.tcb_date()),
            advisory_ids_match_token: token.as_ref().is_some_and(|token| {
                advisory_id_sets_match(&self.advisory_ids, token.advisory_ids())
            }),
            tcb_status_allowed,
            tcb_status: token
                .as_ref()
                .map_or_else(String::new, |token| token.tcb_status().to_string()),
            tcb_date: token
                .as_ref()
                .and_then(|token| token.tcb_date().map(str::to_string)),
            advisory_ids: token
                .as_ref()
                .map_or_else(Vec::new, |token| token.advisory_ids().to_vec()),
            mrtd: token
                .as_ref()
                .map_or_else(String::new, |token| token.mrtd().to_string()),
            expected_advisory_ids_matches: policy.expected_advisory_ids.as_ref().map(|expected| {
                token
                    .as_ref()
                    .is_some_and(|token| advisory_id_sets_match(expected, token.advisory_ids()))
            }),
            expected_mrtd_matches: policy.expected_mrtd.as_ref().map(|expected| {
                token
                    .as_ref()
                    .is_some_and(|token| expected.eq_ignore_ascii_case(token.mrtd()))
            }),
            bundled_evidence_authenticated: None,
        };

        Ok(VerificationContext {
            report,
            commitment,
            nonce: StoredVerifierNonce {
                val: nonce_val,
                iat: nonce_iat,
            },
            token_requires_azure_runtime_evidence: token
                .as_ref()
                .is_some_and(|token| !token.supports_offline_quote_report_data_binding()),
        })
    }

    /// Verify with an explicit policy and reappraise the bundled evidence via ITA.
    pub async fn verify_fresh_with_policy(
        &self,
        config: &ItaConfig,
        policy: &AttestationVerificationPolicy,
    ) -> Result<AttestationVerification, VerifyError> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let VerificationContext {
            mut report,
            commitment,
            nonce,
            token_requires_azure_runtime_evidence,
        } = self.verify_with_policy_context(policy).await?;
        let evidence = self.stored_evidence()?;
        if token_requires_azure_runtime_evidence && evidence.azure_runtime_data().is_none() {
            return Err(VerifyError::InvalidStoredEvidence(
                "stored Azure evidence is missing runtime_data required for verify_fresh"
                    .to_string(),
            ));
        }
        let nonce = self.stored_nonce_with_parts(nonce)?;
        let expected_token_issuer = resolved_expected_token_issuer(policy);
        let (_fresh_token, fresh) = appraise_evidence_authenticated(
            &evidence,
            config,
            &commitment,
            &nonce,
            &policy.jwks_url,
            expected_token_issuer,
            policy.expected_token_audience.clone(),
        )
        .await?;
        let raw_quote_matches_evidence = BASE64.encode(evidence.raw()) == self.raw_quote.trim();

        report.bundled_evidence_authenticated = Some(
            raw_quote_matches_evidence
                && fresh.mrtd().eq_ignore_ascii_case(&self.mrtd)
                && fresh.tcb_status() == self.tcb_status
                && fresh.tcb_date().map(str::to_string) == self.tcb_date
                && advisory_id_sets_match(fresh.advisory_ids(), &self.advisory_ids),
        );

        Ok(report)
    }

    fn require_schema_v2(&self) -> Result<(), VerifyError> {
        if self.schema_version == ATTESTATION_SCHEMA_VERSION {
            Ok(())
        } else {
            Err(VerifyError::InvalidAttestation(format!(
                "unsupported attestation schema version {}; only version 2 is supported",
                self.schema_version
            )))
        }
    }

    fn stored_evidence(&self) -> Result<Evidence, VerifyError> {
        let encoded = if self.evidence.trim().is_empty() {
            self.raw_quote.as_str()
        } else {
            self.evidence.as_str()
        };

        Evidence::from_transport_string(encoded)
            .map_err(|err| VerifyError::InvalidStoredEvidence(format!("stored evidence: {err}")))
    }

    fn default_policy(&self) -> AttestationVerificationPolicy {
        let mut policy = AttestationVerificationPolicy::default();
        if !self.jwks_url.is_empty() {
            policy.jwks_url = self.jwks_url.clone();
        }
        policy
    }

    fn supports_offline_quote_report_data_binding_hint(&self) -> bool {
        let encoded = if self.evidence.trim().is_empty() {
            self.raw_quote.as_str()
        } else {
            self.evidence.as_str()
        };

        Evidence::from_transport_string(encoded)
            .map(|evidence| evidence.azure_runtime_data().is_none())
            .unwrap_or(true)
    }

    fn stored_nonce_with_parts(
        &self,
        decoded: StoredVerifierNonce,
    ) -> Result<VerifierNonce, VerifyError> {
        let signature =
            decode_standard_base64("verifier_nonce_signature", &self.verifier_nonce_signature)
                .map_err(VerifyError::InvalidAttestation)?;

        Ok(VerifierNonce {
            val: decoded.val,
            iat: decoded.iat,
            signature,
            val_b64: self.verifier_nonce_val.clone(),
            iat_b64: self.verifier_nonce_iat.clone(),
            signature_b64: self.verifier_nonce_signature.clone(),
        })
    }
}

struct VerificationContext {
    report: AttestationVerification,
    commitment: [u8; 32],
    nonce: StoredVerifierNonce,
    token_requires_azure_runtime_evidence: bool,
}

struct StoredVerifierNonce {
    val: Vec<u8>,
    iat: Vec<u8>,
}

fn advisory_id_sets_match(left: &[String], right: &[String]) -> bool {
    normalize_advisory_ids(left) == normalize_advisory_ids(right)
}

fn resolved_expected_token_issuer(policy: &AttestationVerificationPolicy) -> Option<String> {
    policy
        .expected_token_issuer
        .clone()
        .or_else(|| default_issuer_for_jwks_url(&policy.jwks_url))
}

fn normalize_advisory_ids(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| value.trim().to_ascii_uppercase())
        .filter(|value| !value.is_empty())
        .collect()
}
