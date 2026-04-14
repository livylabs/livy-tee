// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests that require both `mock-tee` and `ita-verify` features.
//!
//! Run with: cargo test --features mock-tee,ita-verify
#![cfg(all(feature = "mock-tee", feature = "ita-verify"))]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use livy_tee::{
    binary_hash, build_id_from_hash_hex, extract_report_data, generate_and_attest,
    generate_evidence, report_data_from_token, verify_quote_with_public_values, ItaConfig, Livy,
    PublicValues, ReportData, REPORT_DATA_VERSION,
};
use sha2::{Digest, Sha512};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_build_id() -> [u8; 8] {
    build_id_from_hash_hex(&binary_hash().unwrap())
}

fn default_config() -> ItaConfig {
    ItaConfig {
        api_key: "test-key".to_string(),
        ..ItaConfig::default()
    }
}

/// Build a minimal unsigned JWT: base64url(header).base64url(payload).fakesig
fn fake_jwt(payload_json: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    let header = B64URL.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload = B64URL.encode(payload_json);
    format!("{header}.{payload}.fakesig")
}

// ===========================================================================
// PublicValues commitment
// ===========================================================================

#[test]
fn commitment_hash_is_deterministic() {
    let mut a = PublicValues::new();
    a.commit(&"input");
    a.commit(&"output");

    let mut b = PublicValues::new();
    b.commit(&"input");
    b.commit(&"output");

    assert_eq!(a.commitment_hash(), b.commitment_hash());
}

#[test]
fn commitment_hash_changes_with_values() {
    let mut a = PublicValues::new();
    a.commit(&"input-a");

    let mut b = PublicValues::new();
    b.commit(&"input-b");

    assert_ne!(a.commitment_hash(), b.commitment_hash());
}

#[test]
fn commitment_hash_changes_with_order() {
    let mut a = PublicValues::new();
    a.commit(&1u32);
    a.commit(&2u32);

    let mut b = PublicValues::new();
    b.commit(&2u32);
    b.commit(&1u32);

    assert_ne!(a.commitment_hash(), b.commitment_hash());
}

// ===========================================================================
// verify_quote_with_public_values (mock mode — full chain)
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
        h.update(&rd_bytes);
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
    pv.commit(&"hello");
    pv.commit(&"world");
    let (quote_b64, rd_b64, nonce_val_b64, nonce_iat_b64) = mock_chain(&pv);

    let ok =
        verify_quote_with_public_values(&quote_b64, &rd_b64, &nonce_val_b64, &nonce_iat_b64, &pv)
            .expect("verify should not error");
    assert!(ok, "should accept correct mock binding");
}

#[test]
fn verify_quote_rejects_tampered_values_mock() {
    let mut pv = PublicValues::new();
    pv.commit(&"hello");
    pv.commit(&"world");
    let (quote_b64, rd_b64, nonce_val_b64, nonce_iat_b64) = mock_chain(&pv);

    let mut tampered = PublicValues::new();
    tampered.commit(&"TAMPERED");
    tampered.commit(&"world");

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
    pv.commit(&"hello");
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
    pv.commit(&"in");
    pv.commit(&"out");
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
        h.update(&rd_bytes);
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
// report_data_from_token
// ===========================================================================

#[test]
fn report_data_from_token_invalid_jwt() {
    let result = report_data_from_token("not-a-jwt");
    assert!(result.is_err());
}

#[test]
fn report_data_from_token_empty_report_data() {
    let jwt = fake_jwt(r#"{"tdx":{}}"#);
    let result = report_data_from_token(&jwt).unwrap();
    assert!(result.is_none());
}

// ===========================================================================
// Proof via AttestBuilder (mock) — new commit/public_values API
// ===========================================================================

#[tokio::test]
async fn proof_via_attest_builder_mock() {
    let livy = Livy::new("mock-key");
    let mut builder = livy.attest();
    builder.commit(&"test-input");
    builder.commit(&"test-output");
    builder.nonce(42);
    let att = builder.finalize().await.unwrap();

    assert!(att.ita_token.is_empty());
    assert_eq!(att.report_data.nonce, 42);

    // Read back values.
    let v1: String = att.public_values.read();
    let v2: String = att.public_values.read();
    assert_eq!(v1, "test-input");
    assert_eq!(v2, "test-output");
}

#[tokio::test]
async fn proof_verify_mock() {
    let livy = Livy::new("mock-key");
    let mut builder = livy.attest();
    builder.commit(&"correct-data");
    let att = builder.finalize().await.unwrap();

    assert!(
        att.verify().expect("verify should not error"),
        "att.verify() should pass for matching public values"
    );
}

#[tokio::test]
async fn proof_payload_hash_hex_mock() {
    let livy = Livy::new("mock-key");
    let mut builder = livy.attest();
    builder.commit(&"in");
    builder.commit(&"out");
    let att = builder.finalize().await.unwrap();

    let hex_str = att.payload_hash_hex();
    assert_eq!(hex_str.len(), 64);

    // Should match PublicValues commitment hash.
    let mut pv = PublicValues::new();
    pv.commit(&"in");
    pv.commit(&"out");
    assert_eq!(hex_str, hex::encode(pv.commitment_hash()));
}

#[tokio::test]
async fn verify_quote_full_chain_mock() {
    let livy = Livy::new("mock-key");
    let mut builder = livy.attest();
    builder.commit(&"chain-input");
    builder.commit(&"chain-output");
    let att = builder.finalize().await.unwrap();

    let ok = verify_quote_with_public_values(
        &att.raw_quote,
        &att.runtime_data,
        &att.verifier_nonce_val,
        &att.verifier_nonce_iat,
        &att.public_values,
    )
    .expect("verify should not error");
    assert!(ok, "full chain verification should pass");

    // Tampered public values should fail.
    let mut tampered = PublicValues::new();
    tampered.commit(&"tampered");
    let ok2 = verify_quote_with_public_values(
        &att.raw_quote,
        &att.runtime_data,
        &att.verifier_nonce_val,
        &att.verifier_nonce_iat,
        &tampered,
    )
    .expect("should not error");
    assert!(!ok2, "tampered values should fail full chain");
}
