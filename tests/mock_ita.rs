// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests that require both `mock-tee` and `ita-verify` features.
//!
//! Run with: cargo test --features mock-tee,ita-verify
#![cfg(all(feature = "mock-tee", feature = "ita-verify"))]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use livy_tee::{
    binary_hash, extract_report_data, generate_and_attest, generate_evidence,
    payload_hash_for, report_data_from_token, verify_quote, verify_token,
    report::{build_id_from_hash_hex, ReportData, REPORT_DATA_VERSION},
    ItaConfig, Livy,
};
use sha2::{Digest, Sha256, Sha512};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_build_id() -> [u8; 8] {
    build_id_from_hash_hex(&binary_hash().unwrap()).unwrap()
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
// payload_hash_for
// ===========================================================================

#[test]
fn payload_hash_for_is_deterministic() {
    let h1 = payload_hash_for(b"input", b"output");
    let h2 = payload_hash_for(b"input", b"output");
    assert_eq!(h1, h2);
}

#[test]
fn payload_hash_for_changes_with_input() {
    let h1 = payload_hash_for(b"input-a", b"output");
    let h2 = payload_hash_for(b"input-b", b"output");
    assert_ne!(h1, h2);
}

#[test]
fn payload_hash_for_changes_with_output() {
    let h1 = payload_hash_for(b"input", b"output-a");
    let h2 = payload_hash_for(b"input", b"output-b");
    assert_ne!(h1, h2);
}

#[test]
fn payload_hash_for_empty_inputs() {
    // Empty byte slices should not panic and should produce a valid 32-byte hash.
    let h = payload_hash_for(b"", b"");
    assert_eq!(h.len(), 32);
    // Different from a non-empty input.
    assert_ne!(h, payload_hash_for(b"x", b""));
}

// ===========================================================================
// verify_quote (mock mode — full chain)
// ===========================================================================

/// Construct the same chain that generate_and_attest builds internally.
fn mock_chain(input: &[u8], output: &[u8]) -> (String, String, String, String) {
    let ph = payload_hash_for(input, output);
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
    let input = b"hello";
    let output = b"world";
    let (quote_b64, rd_b64, nonce_val_b64, nonce_iat_b64) = mock_chain(input, output);

    let ok = verify_quote(&quote_b64, &rd_b64, &nonce_val_b64, &nonce_iat_b64, input, output)
        .expect("verify_quote should not error");
    assert!(ok, "verify_quote should accept correct mock binding");
}

#[test]
fn verify_quote_rejects_tampered_input_mock() {
    let input = b"hello";
    let output = b"world";
    let (quote_b64, rd_b64, nonce_val_b64, nonce_iat_b64) = mock_chain(input, output);

    let ok = verify_quote(
        &quote_b64, &rd_b64, &nonce_val_b64, &nonce_iat_b64,
        b"TAMPERED", output,
    )
    .expect("should not error");
    assert!(!ok, "tampered input should be rejected");
}

#[test]
fn verify_quote_rejects_tampered_output_mock() {
    let input = b"hello";
    let output = b"world";
    let (quote_b64, rd_b64, nonce_val_b64, nonce_iat_b64) = mock_chain(input, output);

    let ok = verify_quote(
        &quote_b64, &rd_b64, &nonce_val_b64, &nonce_iat_b64,
        input, b"TAMPERED",
    )
    .expect("should not error");
    assert!(!ok, "tampered output should be rejected");
}

#[test]
fn verify_quote_rejects_wrong_nonce_mock() {
    let input = b"hello";
    let output = b"world";
    let (quote_b64, rd_b64, _nonce_val_b64, nonce_iat_b64) = mock_chain(input, output);

    // Use wrong nonce val bytes.
    let wrong_nonce_val = BASE64.encode([0xffu8; 32]);
    let ok = verify_quote(
        &quote_b64, &rd_b64, &wrong_nonce_val, &nonce_iat_b64,
        input, output,
    )
    .expect("should not error");
    assert!(!ok, "wrong nonce should be rejected");
}

#[test]
fn verify_quote_rejects_invalid_base64() {
    let result = verify_quote("!!!invalid!!!", "AAAA", "AAAA", "AAAA", b"x", b"y");
    // Should error (invalid base64 for the quote).
    assert!(result.is_err());
}

// ===========================================================================
// verify_token
// ===========================================================================

#[test]
fn verify_token_returns_none_for_missing_report_data() {
    // JWT with no tdx_report_data field.
    let jwt = fake_jwt(r#"{"tdx":{}}"#);
    let result = verify_token(&jwt, b"input", b"output").unwrap();
    assert!(result.is_none());
}

#[test]
fn verify_token_rejects_malformed_jwt() {
    let result = verify_token("not-a-jwt", b"input", b"output");
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
    let ph = payload_hash_for(b"in", b"out");
    let rd = ReportData::new(ph, sample_build_id(), REPORT_DATA_VERSION, 0, 0);
    let rd_bytes = rd.to_bytes();
    let attested = generate_and_attest(&rd_bytes, &default_config())
        .await
        .unwrap();

    // The runtime_data should be exactly our original rd_bytes.
    assert_eq!(attested.runtime_data, rd_bytes);

    // The evidence should have a valid REPORTDATA = SHA-512(nonce_val ‖ nonce_iat ‖ rd_bytes).
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
// Proof via AttestBuilder (mock)
// ===========================================================================

#[tokio::test]
async fn proof_via_attest_builder_mock() {
    let livy = Livy::new("mock-key");
    let proof = livy
        .attest()
        .input(b"test-input")
        .output(b"test-output")
        .nonce(42)
        .commit()
        .await
        .unwrap();

    // In mock mode, ita_token is empty.
    assert!(proof.ita_token.is_empty());
    // report_data should have nonce 42.
    assert_eq!(proof.report_data.nonce, 42);
    // input_hash and output_hash should be correct SHA-256 digests.
    assert_eq!(proof.input_hash, <[u8; 32]>::from(Sha256::digest(b"test-input")));
    assert_eq!(proof.output_hash, <[u8; 32]>::from(Sha256::digest(b"test-output")));
}

#[tokio::test]
async fn proof_verify_binding_mock() {
    let livy = Livy::new("mock-key");
    let proof = livy
        .attest()
        .input(b"correct-input")
        .output(b"correct-output")
        .commit()
        .await
        .unwrap();

    assert!(proof.verify_binding(b"correct-input", b"correct-output"));
    assert!(!proof.verify_binding(b"wrong-input", b"correct-output"));
    assert!(!proof.verify_binding(b"correct-input", b"wrong-output"));
}

#[tokio::test]
async fn proof_payload_hash_hex_mock() {
    let livy = Livy::new("mock-key");
    let proof = livy
        .attest()
        .input(b"in")
        .output(b"out")
        .commit()
        .await
        .unwrap();

    let hex_str = proof.payload_hash_hex();
    // Should be 64 hex characters (32 bytes).
    assert_eq!(hex_str.len(), 64);
    // Should match payload_hash_for.
    assert_eq!(hex_str, hex::encode(payload_hash_for(b"in", b"out")));
}

#[tokio::test]
async fn verify_quote_full_chain_mock() {
    let livy = Livy::new("mock-key");
    let input = b"chain-input";
    let output = b"chain-output";
    let proof = livy
        .attest()
        .input(input)
        .output(output)
        .commit()
        .await
        .unwrap();

    let ok = verify_quote(
        &proof.raw_quote,
        &proof.runtime_data,
        &proof.verifier_nonce_val,
        &proof.verifier_nonce_iat,
        input,
        output,
    )
    .expect("verify_quote should not error");
    assert!(ok, "full chain verification should pass");

    // Tampered input should fail.
    let ok2 = verify_quote(
        &proof.raw_quote,
        &proof.runtime_data,
        &proof.verifier_nonce_val,
        &proof.verifier_nonce_iat,
        b"tampered",
        output,
    )
    .expect("should not error");
    assert!(!ok2, "tampered input should fail full chain");
}
