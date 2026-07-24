// SPDX-License-Identifier: MIT
//! Mock high-level ITA and 32-byte commitment-binding tests.

#![cfg(all(feature = "mock-tee", feature = "ita-verify"))]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use livy_tee::{
    extract_report_data, generate_and_attest, generate_evidence,
    unauthenticated_report_data_hash_from_token, verify_quote, verify_quote_with_public_values,
    Attestation, AttestationVerificationPolicy, ExtractError, ItaConfig, Livy, PublicValues,
    VerifyError, ATTESTATION_SCHEMA_VERSION,
};
use serde::ser::Error as _;
use sha2::{Digest, Sha512};

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

fn mock_chain(public_values: &PublicValues) -> (String, String, String) {
    let nonce_val = vec![0u8; 32];
    let nonce_iat = vec![0u8; 32];
    let report_data: [u8; 64] = {
        let mut hash = Sha512::new();
        hash.update(&nonce_val);
        hash.update(&nonce_iat);
        hash.update(public_values.commitment_hash());
        hash.finalize().into()
    };
    let evidence = generate_evidence(&report_data).unwrap();
    (
        BASE64.encode(evidence.raw()),
        BASE64.encode(nonce_val),
        BASE64.encode(nonce_iat),
    )
}

#[test]
fn commitment_hash_is_deterministic_and_ordered() {
    let mut first = PublicValues::new();
    first.commit(&"input").unwrap().commit(&"output").unwrap();
    let mut same = PublicValues::new();
    same.commit(&"input").unwrap().commit(&"output").unwrap();
    let mut reversed = PublicValues::new();
    reversed
        .commit(&"output")
        .unwrap()
        .commit(&"input")
        .unwrap();

    assert_eq!(first.commitment_hash(), same.commitment_hash());
    assert_ne!(first.commitment_hash(), reversed.commitment_hash());
}

#[test]
fn quote_binding_uses_only_commitment_and_verifier_nonce() {
    let mut values = PublicValues::new();
    values.commit(&"hello").unwrap().commit(&"world").unwrap();
    let (quote, nonce_val, nonce_iat) = mock_chain(&values);

    assert!(verify_quote_with_public_values(&quote, &nonce_val, &nonce_iat, &values).unwrap());
    assert!(verify_quote(&quote, &nonce_val, &nonce_iat, &values.commitment_hash()).unwrap());
}

#[test]
fn quote_binding_rejects_tampered_values_or_nonce() {
    let mut values = PublicValues::new();
    values.commit(&"hello").unwrap();
    let (quote, nonce_val, nonce_iat) = mock_chain(&values);

    let mut tampered = PublicValues::new();
    tampered.commit(&"tampered").unwrap();
    assert!(!verify_quote_with_public_values(&quote, &nonce_val, &nonce_iat, &tampered).unwrap());

    let wrong_nonce = BASE64.encode([0xffu8; 32]);
    assert!(!verify_quote_with_public_values(&quote, &wrong_nonce, &nonce_iat, &values).unwrap());
}

#[test]
fn quote_binding_reports_malformed_inputs() {
    let values = PublicValues::new();
    assert!(verify_quote_with_public_values("not-base64", "", "", &values).is_err());
    assert!(matches!(
        verify_quote("", "", "", &[0u8; 32]),
        Err(ExtractError::TooShort(0))
    ));
}

#[tokio::test]
async fn generate_and_attest_accepts_32_byte_commitment() {
    let commitment = [0x42u8; 32];
    let attested = generate_and_attest(&commitment, &default_config())
        .await
        .unwrap();

    assert!(attested.ita_token.is_empty());
    assert_eq!(attested.nonce_val, vec![0u8; 32]);
    assert_eq!(attested.nonce_iat, vec![0u8; 32]);

    let expected: [u8; 64] = {
        let mut hash = Sha512::new();
        hash.update(&attested.nonce_val);
        hash.update(&attested.nonce_iat);
        hash.update(commitment);
        hash.finalize().into()
    };
    assert_eq!(extract_report_data(&attested.evidence).unwrap(), expected);
}

#[tokio::test]
async fn builder_artifact_has_schema_v2_and_no_legacy_binding_fields() {
    let attestation = build_mock_attestation(|builder| {
        builder.commit(&123u64).commit(&369u64);
    })
    .await;

    assert_eq!(attestation.schema_version, ATTESTATION_SCHEMA_VERSION);
    assert!(attestation.verify_binding().unwrap());
    assert_eq!(
        attestation.payload_hash_hex(),
        hex::encode(attestation.public_values.commitment_hash())
    );

    let json = serde_json::to_value(&attestation).unwrap();
    assert_eq!(json["schema_version"], 2);
    assert!(json.get("runtime_data").is_none());
    assert!(json.get("report_data").is_none());
    assert!(json.get("build_id").is_none());
    assert!(json.get("nonce").is_none());
}

#[tokio::test]
async fn builder_surfaces_public_value_serialization_errors() {
    let livy = Livy::new("mock-key");
    let mut builder = livy.attest();
    builder.commit(&FailingSerialize);
    let error = builder.finalize().await.unwrap_err();
    assert_eq!(error.code(), "public_values");
}

#[tokio::test]
async fn mock_verification_keeps_local_binding_diagnostics() {
    let attestation = build_mock_attestation(|builder| {
        builder.commit(&"input").commit(&"output");
    })
    .await;
    let mut policy = AttestationVerificationPolicy::default();
    policy.jwks_url = "http://127.0.0.1:9/jwks".to_string();
    policy.request_timeout_secs = 1;

    let report = attestation.verify_with_policy(&policy).await.unwrap();
    assert!(!report.jwt_signature_and_expiry_valid);
    assert!(!report.token_report_data_matches);
    assert_eq!(report.quote_report_data_matches, Some(true));
    assert!(!report.all_passed());
}

#[tokio::test]
async fn tampered_public_values_invalidate_local_binding() {
    let mut attestation = build_mock_attestation(|builder| {
        builder.commit(&"input").commit(&"output");
    })
    .await;
    let mut tampered = PublicValues::new();
    tampered
        .commit(&"input")
        .unwrap()
        .commit(&"tampered")
        .unwrap();
    attestation.public_values = tampered;

    assert!(!attestation.verify_binding().unwrap());
}

#[tokio::test]
async fn raw_quote_tampering_is_detected() {
    let mut attestation = build_mock_attestation(|builder| {
        builder.commit(&"input");
    })
    .await;
    let mut quote = BASE64.decode(&attestation.raw_quote).unwrap();
    quote[568] ^= 1;
    attestation.raw_quote = BASE64.encode(quote);
    assert!(!attestation.verify_binding().unwrap());
}

#[tokio::test]
async fn artifact_v2_roundtrip_resets_public_values_cursor() {
    let attestation = build_mock_attestation(|builder| {
        builder.commit(&"first").commit(&"second");
    })
    .await;
    let _: String = attestation.public_values.read().unwrap();

    let encoded = serde_json::to_string(&attestation).unwrap();
    let decoded: Attestation = serde_json::from_str(&encoded).unwrap();
    let first: String = decoded.public_values.read().unwrap();
    let second: String = decoded.public_values.read().unwrap();
    assert_eq!((first.as_str(), second.as_str()), ("first", "second"));
    assert_eq!(decoded.schema_version, 2);
}

#[tokio::test]
async fn legacy_or_unknown_artifact_versions_are_rejected() {
    let attestation = build_mock_attestation(|builder| {
        builder.commit(&"value");
    })
    .await;
    let mut value = serde_json::to_value(&attestation).unwrap();

    value["schema_version"] = serde_json::json!(1);
    let error = serde_json::from_value::<Attestation>(value.clone())
        .unwrap_err()
        .to_string();
    assert!(error.contains("unsupported attestation schema version 1"));

    value.as_object_mut().unwrap().remove("schema_version");
    let error = serde_json::from_value::<Attestation>(value)
        .unwrap_err()
        .to_string();
    assert!(error.contains("unsupported legacy attestation artifact"));
}

#[tokio::test]
async fn directly_tampered_schema_version_is_rejected_by_verifier() {
    let mut attestation = build_mock_attestation(|builder| {
        builder.commit(&"value");
    })
    .await;
    attestation.schema_version = 1;
    let error = attestation.verify().await.unwrap_err();
    assert!(
        matches!(error, VerifyError::InvalidAttestation(message) if message.contains("schema version 1"))
    );
}

#[test]
fn unauthenticated_report_data_inspection_remains_a_64_byte_low_level_helper() {
    let expected = [0xabu8; 64];
    let jwt = fake_jwt(&format!(
        r#"{{"tdx":{{"tdx_report_data":"{}"}}}}"#,
        hex::encode(expected)
    ));
    assert_eq!(
        unauthenticated_report_data_hash_from_token(&jwt).unwrap(),
        Some(expected)
    );
    assert!(unauthenticated_report_data_hash_from_token("not-a-jwt").is_err());
}
