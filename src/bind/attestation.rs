// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! High-level attestation builder and verifier API.

use super::local::{
    nonce_and_runtime_hash, verify_quote_report_data_binding, verify_quote_with_public_values,
};
use crate::{
    error::{AttestError, LivyEnvError, PublicValuesError, VerifyError},
    evidence::Evidence,
    generate::binary_hash,
    public_values::PublicValues,
    report::{build_id_from_hash_hex, ReportData, REPORT_DATA_VERSION},
    verify::{
        codec::{decode_standard_base64, decode_standard_base64_array_64},
        ita::{
            appraise_evidence_authenticated, default_issuer_for_jwks_url, verify_attestation_token,
            ItaConfig, VerifierNonce, DEFAULT_JWKS_URL,
        },
    },
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Policy for [`Attestation::verify_with_policy`] and [`Attestation::verify_fresh_with_policy`].
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
    pub expected_mrtd: Option<String>,
    /// Optional expected build ID from [`ReportData::build_id`].
    pub expected_build_id: Option<[u8; 8]>,
    /// Optional expected application nonce from [`ReportData::nonce`].
    pub expected_nonce: Option<u64>,
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
            expected_build_id: None,
            expected_nonce: None,
        }
    }
}

/// Diagnostic report returned by attestation verification.
///
/// Read this in three groups:
/// - token trust: `jwt_signature_and_expiry_valid`, `token_verification_error`
/// - binding checks: `token_report_data_matches`, `quote_report_data_matches`,
///   `runtime_data_matches_report`, `public_values_bound`
/// - policy / identity checks: `*_matches_token`, `tcb_status_allowed`,
///   `expected_*`
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
    ///
    /// When this is `Some(_)`, the report still describes local checks, but the
    /// token-derived checks should be treated as untrusted.
    pub token_verification_error: Option<VerifyError>,
    /// `true` when the signed token binding matches this attestation's nonce and runtime data.
    pub token_report_data_matches: bool,
    /// Local raw-quote binding result, when this attestation format exposes it portably.
    ///
    /// `None` means this check is not available for the stored artifact format,
    /// which is the normal Azure case.
    pub quote_report_data_matches: Option<bool>,
    /// `true` when the stored `runtime_data` decodes to the stored `report_data`.
    pub runtime_data_matches_report: bool,
    /// `true` when `SHA-256(public_values)` matches `report_data.payload_hash`.
    pub public_values_bound: bool,
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
    /// Result of comparing the token advisory IDs to the policy's expected set.
    ///
    /// `None` means the policy did not pin advisory IDs.
    pub expected_advisory_ids_matches: Option<bool>,
    /// Result of comparing the token MRTD to the policy's expected MRTD.
    ///
    /// `None` means the policy did not pin MRTD.
    pub expected_mrtd_matches: Option<bool>,
    /// Result of comparing the report build ID to the policy's expected build ID.
    ///
    /// `None` means the policy did not pin build ID.
    pub expected_build_id_matches: Option<bool>,
    /// Result of comparing the report nonce to the policy's expected nonce.
    ///
    /// `None` means the policy did not pin an application nonce.
    pub expected_nonce_matches: Option<bool>,
    /// Result of fresh ITA appraisal of the bundled evidence, when performed.
    ///
    /// `None` means verification was run without a fresh ITA reappraisal.
    pub bundled_evidence_authenticated: Option<bool>,
}

impl AttestationVerification {
    /// Return `true` when every required verification check passed.
    ///
    /// Fields that are `None` because the check was not requested or not
    /// applicable are treated as pass-through.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.jwt_signature_and_expiry_valid
            && self.token_report_data_matches
            && self.quote_report_data_matches.unwrap_or(true)
            && self.runtime_data_matches_report
            && self.public_values_bound
            && self.mrtd_matches_token
            && self.tcb_status_matches_token
            && self.tcb_date_matches_token
            && self.advisory_ids_match_token
            && self.tcb_status_allowed
            && self.expected_advisory_ids_matches.unwrap_or(true)
            && self.expected_mrtd_matches.unwrap_or(true)
            && self.expected_build_id_matches.unwrap_or(true)
            && self.expected_nonce_matches.unwrap_or(true)
            && self.bundled_evidence_authenticated.unwrap_or(true)
    }

    /// Enforce the strict verification contract while preserving diagnostics.
    ///
    /// Returns `Ok(())` only when [`all_passed`](Self::all_passed) is `true`.
    pub fn require_success(&self) -> Result<(), &Self> {
        if self.all_passed() {
            Ok(())
        } else {
            Err(self)
        }
    }
}

/// Client entry point for TDX-backed attestation.
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
            nonce: 0,
            pending_public_values_error: None,
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
    pending_public_values_error: Option<PublicValuesError>,
}

impl<'a> AttestBuilder<'a> {
    /// Commit a typed value as a public output.
    ///
    /// Values are stored in plain text. Use [`commit_hashed`](Self::commit_hashed)
    /// when a value should be bound by hash only.
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

    /// Set the application nonce stored in [`ReportData::nonce`].
    pub fn nonce(&mut self, n: u64) -> &mut Self {
        self.nonce = n;
        self
    }

    /// Generate a TDX quote and obtain an ITA attestation token.
    pub async fn finalize(self) -> Result<Attestation, AttestError> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        if let Some(err) = self.pending_public_values_error {
            return Err(AttestError::PublicValues(err));
        }

        let payload_hash = self.public_values.commitment_hash();

        let binary_hash_hex = binary_hash().map_err(AttestError::Generate)?;
        let build_id = build_id_from_hash_hex(&binary_hash_hex)?;
        let rd = ReportData::new(payload_hash, build_id, REPORT_DATA_VERSION, 0, self.nonce);
        let rd_bytes = rd.to_bytes();

        let attested = crate::attest::generate_and_attest(&rd_bytes, self.config).await?;

        Ok(Attestation {
            ita_token: attested.ita_token,
            jwks_url: self.config.default_jwks_url(),
            mrtd: attested.mrtd,
            tcb_status: attested.tcb_status,
            tcb_date: attested.tcb_date,
            advisory_ids: attested.advisory_ids,
            evidence: attested.evidence.to_transport_string(),
            raw_quote: BASE64.encode(attested.evidence.raw()),
            runtime_data: BASE64.encode(attested.runtime_data),
            verifier_nonce_val: BASE64.encode(&attested.nonce_val),
            verifier_nonce_iat: BASE64.encode(&attested.nonce_iat),
            verifier_nonce_signature: BASE64.encode(&attested.nonce_signature),
            report_data: rd,
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

/// A TDX attestation plus its committed public values.
///
/// `public_values` are public. Use [`AttestBuilder::commit_hashed`] for values
/// that should be bound by hash rather than stored in plain text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// ITA-signed JWT.
    pub ita_token: String,
    /// JWKS endpoint that matches the ITA region used to mint `ita_token`.
    pub jwks_url: String,
    /// Hex-encoded MRTD (96 chars = 48 bytes).
    pub mrtd: String,
    /// TCB status from Intel Trust Authority.
    pub tcb_status: String,
    /// Optional TCB assessment date from Intel Trust Authority claims.
    pub tcb_date: Option<String>,
    /// Advisory IDs reported by Intel Trust Authority.
    #[serde(default)]
    pub advisory_ids: Vec<String>,
    /// Portable low-level evidence artifact.
    ///
    /// This is the self-contained evidence transport string produced by
    /// `Evidence::to_transport_string()`. On Azure it includes the runtime JSON
    /// needed to reappraise the bundled evidence with ITA.
    pub evidence: String,
    /// Base64-encoded raw DCAP quote.
    pub raw_quote: String,
    /// Base64-encoded original 64-byte ReportData struct.
    pub runtime_data: String,
    /// Base64-encoded verifier nonce value bytes.
    pub verifier_nonce_val: String,
    /// Base64-encoded verifier nonce issued-at bytes.
    pub verifier_nonce_iat: String,
    /// Base64-encoded verifier nonce signature bytes.
    pub verifier_nonce_signature: String,
    /// Structured REPORTDATA parsed from `runtime_data`.
    pub report_data: ReportData,
    /// The committed public values — read with `.public_values.read::<T>()?`.
    pub public_values: PublicValues,
}

impl Attestation {
    /// Hex-encoded 32-byte commitment hash.
    #[must_use]
    pub fn payload_hash_hex(&self) -> String {
        hex::encode(self.report_data.payload_hash)
    }

    /// Verify that `public_values` are bound to the raw quote bytes.
    ///
    /// This is a local check. It does not verify the ITA token or policy.
    pub fn verify_binding(&self) -> Result<bool, crate::ExtractError> {
        verify_quote_with_public_values(
            &self.raw_quote,
            &self.runtime_data,
            &self.verifier_nonce_val,
            &self.verifier_nonce_iat,
            &self.public_values,
        )
    }

    /// Verify the ITA token and local bindings against the default policy.
    ///
    /// This does not reappraise the bundled evidence. Use [`verify_fresh`](Self::verify_fresh)
    /// when that stronger check is required.
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
    ///
    /// `Ok(report)` is still diagnostic. Call
    /// [`AttestationVerification::require_success`] or check [`AttestationVerification::all_passed`].
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

        let runtime_data = decode_standard_base64_array_64("runtime_data", &self.runtime_data)
            .map_err(VerifyError::InvalidAttestation)?;
        let nonce_val = decode_standard_base64("verifier_nonce_val", &self.verifier_nonce_val)
            .map_err(VerifyError::InvalidAttestation)?;
        let nonce_iat = decode_standard_base64("verifier_nonce_iat", &self.verifier_nonce_iat)
            .map_err(VerifyError::InvalidAttestation)?;
        let expected_token_report_data =
            nonce_and_runtime_hash(&nonce_val, &nonce_iat, &runtime_data);
        let offline_quote_report_data_matches =
            verify_quote_report_data_binding(&self.raw_quote, &expected_token_report_data)
                .map_err(|err| VerifyError::InvalidAttestation(format!("raw_quote: {err}")))?;

        let parsed_report = ReportData::from_bytes(&runtime_data);
        let tcb_status_allowed = token.as_ref().is_some_and(|t| {
            policy
                .accepted_tcb_statuses
                .iter()
                .any(|status| status.eq_ignore_ascii_case(t.tcb_status()))
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
            token_report_data_matches: token
                .as_ref()
                .is_some_and(|t| t.binding_matches(&runtime_data, &expected_token_report_data)),
            quote_report_data_matches,
            runtime_data_matches_report: parsed_report == self.report_data,
            public_values_bound: self
                .public_values
                .verify_commitment(&parsed_report.payload_hash),
            mrtd_matches_token: token
                .as_ref()
                .is_some_and(|t| self.mrtd.eq_ignore_ascii_case(t.mrtd())),
            tcb_status_matches_token: token
                .as_ref()
                .is_some_and(|t| self.tcb_status == t.tcb_status()),
            tcb_date_matches_token: token
                .as_ref()
                .is_some_and(|t| self.tcb_date.as_deref() == t.tcb_date()),
            advisory_ids_match_token: token
                .as_ref()
                .is_some_and(|t| advisory_id_sets_match(&self.advisory_ids, t.advisory_ids())),
            tcb_status_allowed,
            tcb_status: token
                .as_ref()
                .map_or_else(String::new, |t| t.tcb_status().to_string()),
            tcb_date: token
                .as_ref()
                .and_then(|t| t.tcb_date().map(str::to_string)),
            advisory_ids: token
                .as_ref()
                .map_or_else(Vec::new, |t| t.advisory_ids().to_vec()),
            mrtd: token
                .as_ref()
                .map_or_else(String::new, |t| t.mrtd().to_string()),
            expected_advisory_ids_matches: policy.expected_advisory_ids.as_ref().map(|expected| {
                token
                    .as_ref()
                    .is_some_and(|t| advisory_id_sets_match(expected, t.advisory_ids()))
            }),
            expected_mrtd_matches: policy.expected_mrtd.as_ref().map(|expected| {
                token
                    .as_ref()
                    .is_some_and(|t| expected.eq_ignore_ascii_case(t.mrtd()))
            }),
            expected_build_id_matches: policy
                .expected_build_id
                .map(|expected| parsed_report.build_id == expected),
            expected_nonce_matches: policy
                .expected_nonce
                .map(|expected| parsed_report.nonce == expected),
            bundled_evidence_authenticated: None,
        };

        Ok(VerificationContext {
            report,
            runtime_data,
            nonce: StoredVerifierNonce {
                val: nonce_val,
                iat: nonce_iat,
            },
            token_requires_azure_runtime_evidence: token
                .as_ref()
                .is_some_and(|t| !t.supports_offline_quote_report_data_binding()),
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
            runtime_data,
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
            &runtime_data,
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

    /// Check that `SHA-256(public_values)` matches `report_data.payload_hash`.
    ///
    /// This is a self-consistency check only. It does not prove the quote
    /// itself matches the stored `report_data`.
    #[must_use]
    pub fn verify_public_values_commitment(&self) -> bool {
        self.public_values
            .verify_commitment(&self.report_data.payload_hash)
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
    runtime_data: [u8; 64],
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
