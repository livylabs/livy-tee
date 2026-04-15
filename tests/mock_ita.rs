// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests that require both `mock-tee` and `ita-verify` features.
//!
//! Run with: cargo test --features mock-tee,ita-verify
#![cfg(all(feature = "mock-tee", feature = "ita-verify"))]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use livy_tee::{
    binary_hash, build_id_from_hash_hex, extract_report_data, generate_and_attest,
    generate_evidence, unauthenticated_report_data_hash_from_token,
    verify_quote_with_public_values, Attestation, AttestationVerificationPolicy, ExtractError,
    ItaConfig, Livy, PublicValues, ReportData, VerifyError, REPORT_DATA_VERSION,
};
use serde::ser::Error as _;
use sha2::{Digest, Sha512};

// ------------------------------------------------------------------------// Helpers
// ------------------------------------------------------------------------
fn sample_build_id() -> [u8; 8] {
    build_id_from_hash_hex(&binary_hash().unwrap()).expect("binary_hash returns valid SHA-256 hex")
}

fn default_config() -> ItaConfig {
    ItaConfig {
        api_key: "test-key".to_string(),
        ..ItaConfig::default()
    }
}

async fn build_mock_attestation(
    configure: impl FnOnce(&mut livy_tee::AttestBuilder<'_>),
) -> Attestation {
    let livy = Livy::new("mock-key");
    let mut builder = livy.attest();
    configure(&mut builder);
    builder.finalize().await.unwrap()
}

/// Build a minimal unsigned JWT: base64url(header).base64url(payload).fakesig
fn fake_jwt(payload_json: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    let header = B64URL.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload = B64URL.encode(payload_json);
    format!("{header}.{payload}.fakesig")
}

struct FailingSerialize;

impl serde::Serialize for FailingSerialize {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Err(S::Error::custom("intentional serialization failure"))
    }
}

// ===========================================================================
// PublicValues commitment
// ===========================================================================

#[test]
fn commitment_hash_is_deterministic() {
    let mut a = PublicValues::new();
    a.commit(&"input").unwrap();
    a.commit(&"output").unwrap();

    let mut b = PublicValues::new();
    b.commit(&"input").unwrap();
    b.commit(&"output").unwrap();

    assert_eq!(a.commitment_hash(), b.commitment_hash());
}

#[test]
fn commitment_hash_changes_with_values() {
    let mut a = PublicValues::new();
    a.commit(&"input-a").unwrap();

    let mut b = PublicValues::new();
    b.commit(&"input-b").unwrap();

    assert_ne!(a.commitment_hash(), b.commitment_hash());
}

#[test]
fn commitment_hash_changes_with_order() {
    let mut a = PublicValues::new();
    a.commit(&1u32).unwrap();
    a.commit(&2u32).unwrap();

    let mut b = PublicValues::new();
    b.commit(&2u32).unwrap();
    b.commit(&1u32).unwrap();

    assert_ne!(a.commitment_hash(), b.commitment_hash());
}

// ===========================================================================
// verify_quote_with_public_values (mock mode — local binding chain)
// ===========================================================================

/// Construct the same chain that generate_and_attest builds internally.
fn mock_chain(pv: &PublicValues) -> (String, String, String, String) {
    let ph = pv.commitment_hash();
    let rd = ReportData::new(ph, sample_build_id(), REPORT_DATA_VERSION, 0, 0);
    let rd_bytes = rd.to_bytes();

    // Mock mode uses zeroed nonces.
    let nonce_val = vec![0u8; 32];
    let nonce_iat = vec![0u8; 32];

    // REPORTDATA = SHA-512(nonce_val ‖ nonce_iat ‖ rd_bytes)
    let reportdata_for_quote: [u8; 64] = {
        let mut h = Sha512::new();
        h.update(&nonce_val);
        h.update(&nonce_iat);
        h.update(rd_bytes);
        h.finalize().into()
    };

    let evidence = generate_evidence(&reportdata_for_quote).unwrap();

    (
        BASE64.encode(evidence.raw()),
        BASE64.encode(rd_bytes),
        BASE64.encode(&nonce_val),
        BASE64.encode(&nonce_iat),
    )
}

#[test]
fn verify_quote_accepts_correct_mock_binding() {
    let mut pv = PublicValues::new();
    pv.commit(&"hello").unwrap();
    pv.commit(&"world").unwrap();
    let (quote_b64, rd_b64, nonce_val_b64, nonce_iat_b64) = mock_chain(&pv);

    let ok =
        verify_quote_with_public_values(&quote_b64, &rd_b64, &nonce_val_b64, &nonce_iat_b64, &pv)
            .expect("verify should not error");
    assert!(ok, "should accept correct mock binding");
}

#[test]
fn verify_quote_rejects_tampered_values_mock() {
    let mut pv = PublicValues::new();
    pv.commit(&"hello").unwrap();
    pv.commit(&"world").unwrap();
    let (quote_b64, rd_b64, nonce_val_b64, nonce_iat_b64) = mock_chain(&pv);

    let mut tampered = PublicValues::new();
    tampered.commit(&"TAMPERED").unwrap();
    tampered.commit(&"world").unwrap();

    let ok = verify_quote_with_public_values(
        &quote_b64,
        &rd_b64,
        &nonce_val_b64,
        &nonce_iat_b64,
        &tampered,
    )
    .expect("should not error");
    assert!(!ok, "tampered values should be rejected");
}

#[test]
fn verify_quote_rejects_wrong_nonce_mock() {
    let mut pv = PublicValues::new();
    pv.commit(&"hello").unwrap();
    let (quote_b64, rd_b64, _nonce_val_b64, nonce_iat_b64) = mock_chain(&pv);

    let wrong_nonce_val = BASE64.encode([0xffu8; 32]);
    let ok =
        verify_quote_with_public_values(&quote_b64, &rd_b64, &wrong_nonce_val, &nonce_iat_b64, &pv)
            .expect("should not error");
    assert!(!ok, "wrong nonce should be rejected");
}

#[test]
fn verify_quote_rejects_invalid_base64() {
    let pv = PublicValues::new();
    let result = verify_quote_with_public_values("!!!invalid!!!", "AAAA", "AAAA", "AAAA", &pv);
    assert!(result.is_err());
}

#[test]
fn verify_quote_rejects_runtime_data_with_trailing_bytes() {
    let mut pv = PublicValues::new();
    pv.commit(&"hello").unwrap();
    let (quote_b64, rd_b64, nonce_val_b64, nonce_iat_b64) = mock_chain(&pv);
    let runtime_with_trailing = format!("{rd_b64}AA==");

    let result = verify_quote_with_public_values(
        &quote_b64,
        &runtime_with_trailing,
        &nonce_val_b64,
        &nonce_iat_b64,
        &pv,
    );
    assert!(result.is_err());
}

// ===========================================================================
// generate_and_attest (mock path)
// ===========================================================================

#[tokio::test]
async fn generate_and_attest_mock_returns_empty_token() {
    let rd = ReportData::new([0u8; 32], sample_build_id(), REPORT_DATA_VERSION, 0, 0);
    let attested = generate_and_attest(&rd.to_bytes(), &default_config())
        .await
        .unwrap();
    assert!(attested.ita_token.is_empty());
    assert!(attested.mrtd.is_empty());
    assert!(attested.tcb_status.is_empty());
}

#[tokio::test]
async fn generate_and_attest_mock_returns_valid_evidence() {
    let mut pv = PublicValues::new();
    pv.commit(&"in").unwrap();
    pv.commit(&"out").unwrap();
    let ph = pv.commitment_hash();

    let rd = ReportData::new(ph, sample_build_id(), REPORT_DATA_VERSION, 0, 0);
    let rd_bytes = rd.to_bytes();
    let attested = generate_and_attest(&rd_bytes, &default_config())
        .await
        .unwrap();

    assert_eq!(attested.runtime_data, rd_bytes);

    let extracted_rd = extract_report_data(&attested.evidence).unwrap();
    let expected_rd: [u8; 64] = {
        let mut h = Sha512::new();
        h.update(&attested.nonce_val);
        h.update(&attested.nonce_iat);
        h.update(rd_bytes);
        h.finalize().into()
    };
    assert_eq!(extracted_rd, expected_rd);
}

#[tokio::test]
async fn generate_and_attest_mock_zeroes_nonces() {
    let rd = ReportData::new([0u8; 32], sample_build_id(), REPORT_DATA_VERSION, 0, 0);
    let attested = generate_and_attest(&rd.to_bytes(), &default_config())
        .await
        .unwrap();
    assert_eq!(attested.nonce_val, vec![0u8; 32]);
    assert_eq!(attested.nonce_iat, vec![0u8; 32]);
}

// ===========================================================================
// unauthenticated_report_data_hash_from_token
// ===========================================================================

#[test]
fn unauthenticated_report_data_hash_from_token_invalid_jwt() {
    let result = unauthenticated_report_data_hash_from_token("not-a-jwt");
    assert!(result.is_err());
}

#[test]
fn unauthenticated_report_data_hash_from_token_empty_report_data() {
    let jwt = fake_jwt(r#"{"tdx":{}}"#);
    let result = unauthenticated_report_data_hash_from_token(&jwt).unwrap();
    assert!(result.is_none());
}

#[test]
fn unauthenticated_report_data_hash_from_token_decodes_hex_claim() {
    let expected = [0xabu8; 64];
    let jwt = fake_jwt(&format!(
        r#"{{"tdx":{{"tdx_report_data":"{}"}}}}"#,
        hex::encode(expected)
    ));
    let result = unauthenticated_report_data_hash_from_token(&jwt).unwrap();
    assert_eq!(result, Some(expected));
}

// ===========================================================================
// Proof via AttestBuilder (mock) — new commit/public_values API
// ===========================================================================

#[tokio::test]
async fn proof_via_attest_builder_mock() {
    let att = build_mock_attestation(|builder| {
        builder.commit(&"test-input");
        builder.commit(&"test-output");
        builder.nonce(42);
    })
    .await;

    assert!(att.ita_token.is_empty());
    assert_eq!(att.report_data.nonce, 42);

    // Read back values.
    let v1: String = att.public_values.read().unwrap();
    let v2: String = att.public_values.read().unwrap();
    assert_eq!(v1, "test-input");
    assert_eq!(v2, "test-output");
}

#[tokio::test]
async fn proof_verify_binding_mock() {
    let att = build_mock_attestation(|builder| {
        builder.commit(&"correct-data");
    })
    .await;

    assert!(
        att.verify_binding().expect("verify should not error"),
        "att.verify_binding() should pass for matching public values"
    );
}

#[tokio::test]
async fn proof_verify_binding_rejects_invalid_raw_quote_base64() {
    let mut att = build_mock_attestation(|builder| {
        builder.commit(&"correct-data");
    })
    .await;
    att.raw_quote = "not-base64".to_string();

    let err = att
        .verify_binding()
        .expect_err("invalid raw_quote should be a hard error");

    assert!(matches!(err, ExtractError::Base64(_)));
}

#[tokio::test]
async fn proof_verify_binding_rejects_invalid_runtime_data_base64() {
    let mut att = build_mock_attestation(|builder| {
        builder.commit(&"correct-data");
    })
    .await;
    att.runtime_data = "not-base64".to_string();

    let err = att
        .verify_binding()
        .expect_err("invalid runtime_data should be a hard error");

    assert!(matches!(err, ExtractError::Base64(_)));
}

#[tokio::test]
async fn proof_verify_binding_rejects_truncated_raw_quote() {
    let mut att = build_mock_attestation(|builder| {
        builder.commit(&"correct-data");
    })
    .await;
    att.raw_quote = BASE64.encode(vec![0u8; 32]);

    let err = att
        .verify_binding()
        .expect_err("truncated raw_quote should be a hard error");

    assert!(matches!(err, ExtractError::TooShort(32)));
}

#[tokio::test]
async fn attest_builder_finalize_surfaces_public_values_errors() {
    let livy = Livy::new("mock-key");
    let mut builder = livy.attest();
    builder.commit(&FailingSerialize);

    let err = builder
        .finalize()
        .await
        .expect_err("finalize should surface commit serialization failures");

    assert_eq!(err.code(), "public_values");
    assert!(matches!(err, livy_tee::AttestError::PublicValues(_)));
}

#[tokio::test]
async fn proof_verify_mock_reports_jwt_failure() {
    let att = build_mock_attestation(|builder| {
        builder.commit(&"correct-data");
    })
    .await;

    let report = att
        .verify()
        .await
        .expect("verify should return a report, not Err");
    assert!(
        !report.jwt_signature_and_expiry_valid,
        "mock has no real JWT"
    );
    assert!(matches!(
        report.token_verification_error,
        Some(VerifyError::InvalidToken(_))
    ));
    assert_eq!(report.quote_report_data_matches, Some(true));
    assert!(
        !report.all_passed(),
        "all_passed should be false without valid JWT"
    );
    // Local checks that don't depend on the token should still pass.
    assert!(report.runtime_data_matches_report);
    assert!(report.public_values_bound);
    assert!(report.require_success().is_err());
}

#[tokio::test]
async fn proof_verify_with_policy_reports_token_failures_but_keeps_local_checks() {
    let att = build_mock_attestation(|builder| {
        builder.commit(&"correct-data");
        builder.nonce(42);
    })
    .await;

    let report = att
        .verify_with_policy(&{
            let mut policy = AttestationVerificationPolicy::default();
            policy.expected_mrtd = Some("00".repeat(48));
            policy.expected_build_id = Some(att.report_data.build_id);
            policy.expected_nonce = Some(att.report_data.nonce);
            policy
        })
        .await
        .expect("verify_with_policy should return a report, not Err");

    assert!(
        !report.jwt_signature_and_expiry_valid,
        "mock has no real JWT"
    );
    assert!(matches!(
        report.token_verification_error,
        Some(VerifyError::InvalidToken(_))
    ));
    assert!(!report.token_report_data_matches);
    assert_eq!(report.quote_report_data_matches, Some(true));
    assert!(!report.mrtd_matches_token);
    assert!(!report.tcb_status_matches_token);
    assert!(!report.tcb_date_matches_token);
    assert!(!report.tcb_status_allowed);
    assert_eq!(report.expected_mrtd_matches, Some(false));

    assert!(report.runtime_data_matches_report);
    assert!(report.public_values_bound);
    assert_eq!(report.expected_build_id_matches, Some(true));
    assert_eq!(report.expected_nonce_matches, Some(true));
    assert!(
        !report.all_passed(),
        "all_passed should be false without valid JWT"
    );
    assert!(report.require_success().is_err());
}

#[tokio::test]
async fn proof_verify_rejects_empty_raw_quote_as_structurally_invalid() {
    let mut att = build_mock_attestation(|builder| {
        builder.commit(&"correct-data");
    })
    .await;
    att.raw_quote.clear();

    let err = att
        .verify()
        .await
        .expect_err("empty raw quote should surface a structural error");

    assert!(
        matches!(err, VerifyError::InvalidAttestation(message) if message.contains("raw_quote"))
    );
}

#[tokio::test]
async fn proof_verify_reports_tampered_raw_quote_as_quote_binding_failure() {
    let mut att = build_mock_attestation(|builder| {
        builder.commit(&"correct-data");
    })
    .await;

    let mut quote = BASE64
        .decode(att.raw_quote.as_bytes())
        .expect("mock raw quote should be valid base64");
    quote[568] ^= 0xff;
    att.raw_quote = BASE64.encode(quote);

    let report = att
        .verify()
        .await
        .expect("verify should return a report, not Err");

    assert!(!report.jwt_signature_and_expiry_valid);
    assert!(matches!(
        report.token_verification_error,
        Some(VerifyError::InvalidToken(_))
    ));
    assert!(!report.token_report_data_matches);
    assert_eq!(report.quote_report_data_matches, Some(false));
    assert!(report.runtime_data_matches_report);
    assert!(report.public_values_bound);
    assert!(report.require_success().is_err());
    assert!(!report.all_passed());
}

#[tokio::test]
async fn proof_payload_hash_hex_mock() {
    let att = build_mock_attestation(|builder| {
        builder.commit(&"in");
        builder.commit(&"out");
    })
    .await;

    let hex_str = att.payload_hash_hex();
    assert_eq!(hex_str.len(), 64);

    // Should match PublicValues commitment hash.
    let mut pv = PublicValues::new();
    pv.commit(&"in").unwrap();
    pv.commit(&"out").unwrap();
    assert_eq!(hex_str, hex::encode(pv.commitment_hash()));
}

#[test]
fn verify_quote_reports_invalid_base64_input() {
    let err = livy_tee::verify_quote("not-base64", "", "", "", &[0u8; 32]).unwrap_err();
    assert!(matches!(err, ExtractError::Base64(_)));
}

#[tokio::test]
async fn verify_rejects_malformed_attestation_runtime_data_as_hard_error() {
    let mut att = build_mock_attestation(|builder| {
        builder.commit(&"correct-data");
    })
    .await;
    att.runtime_data = "not-base64".to_string();

    let err = att
        .verify()
        .await
        .expect_err("malformed attestation fields should be hard errors");

    assert!(matches!(err, VerifyError::InvalidAttestation(_)));
}

#[tokio::test]
async fn verify_quote_binding_chain_mock() {
    let att = build_mock_attestation(|builder| {
        builder.commit(&"chain-input");
        builder.commit(&"chain-output");
    })
    .await;

    let ok = verify_quote_with_public_values(
        &att.raw_quote,
        &att.runtime_data,
        &att.verifier_nonce_val,
        &att.verifier_nonce_iat,
        &att.public_values,
    )
    .expect("verify should not error");
    assert!(ok, "binding verification should pass");

    // Tampered public values should fail.
    let mut tampered = PublicValues::new();
    tampered.commit(&"tampered").unwrap();
    let ok2 = verify_quote_with_public_values(
        &att.raw_quote,
        &att.runtime_data,
        &att.verifier_nonce_val,
        &att.verifier_nonce_iat,
        &tampered,
    )
    .expect("should not error");
    assert!(!ok2, "tampered values should fail binding verification");
}

#[tokio::test]
async fn attestation_json_roundtrip_preserves_public_artifact_and_resets_cursor() {
    let att = build_mock_attestation(|builder| {
        builder.commit(&"serde-input");
        builder.commit_hashed(&vec![1u8, 2, 3, 4]);
        builder.nonce(42);
    })
    .await;

    let first_value: String = att.public_values.read().unwrap();
    assert_eq!(first_value, "serde-input");

    let encoded = serde_json::to_string(&att).expect("attestation should serialize");
    let decoded: Attestation =
        serde_json::from_str(&encoded).expect("attestation should deserialize");

    assert_eq!(decoded.ita_token, att.ita_token);
    assert_eq!(decoded.jwks_url, att.jwks_url);
    assert_eq!(decoded.mrtd, att.mrtd);
    assert_eq!(decoded.tcb_status, att.tcb_status);
    assert_eq!(decoded.tcb_date, att.tcb_date);
    assert_eq!(decoded.advisory_ids, att.advisory_ids);
    assert_eq!(decoded.evidence, att.evidence);
    assert_eq!(decoded.raw_quote, att.raw_quote);
    assert_eq!(decoded.runtime_data, att.runtime_data);
    assert_eq!(decoded.verifier_nonce_val, att.verifier_nonce_val);
    assert_eq!(decoded.verifier_nonce_iat, att.verifier_nonce_iat);
    assert_eq!(
        decoded.verifier_nonce_signature,
        att.verifier_nonce_signature
    );
    assert_eq!(decoded.report_data, att.report_data);

    let roundtrip_first: String = decoded.public_values.read().unwrap();
    assert_eq!(roundtrip_first, "serde-input");
    let roundtrip_hashed = decoded.public_values.read_raw().unwrap();
    assert_eq!(roundtrip_hashed.len(), 32);
    assert_eq!(
        decoded.public_values.entries_raw(),
        att.public_values.entries_raw()
    );
}
