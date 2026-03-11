// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Real TDX hardware integration tests.
//!
//! # Prerequisites
//!   - TDX-capable hardware with Linux kernel ≥ 6.7
//!   - `ITA_API_KEY` environment variable set
//!
//! # Running
//! ```bash
//! ITA_API_KEY=<key> cargo test --test tdx_integration \
//!     --no-default-features --features ita-verify -p livy-tee \
//!     -- --nocapture --test-threads=1
//! ```

#![cfg(feature = "ita-verify")]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use livy_tee::{
    binary_hash, build_id_from_hash_hex, extract_report_data, generate_and_attest,
    generate_evidence, get_nonce, payload_hash_for, verify_quote, ItaConfig, Livy, ReportData,
    REPORT_DATA_VERSION,
};
use sha2::{Digest, Sha256, Sha512};

fn api_key() -> String {
    let key = std::env::var("ITA_API_KEY")
        .expect("ITA_API_KEY must be set to run TDX integration tests");
    assert!(!key.is_empty(), "ITA_API_KEY is set but empty");
    key
}

fn ita_config() -> ItaConfig {
    ItaConfig {
        api_key: api_key(),
        ..ItaConfig::default()
    }
}

fn assert_real_tdx_evidence(quote_len: usize) {
    assert!(
        quote_len > 4000,
        "quote is only {quote_len} bytes — this is the mock-tee stub, not real TDX hardware"
    );
}

#[test]
fn tdx_quote_is_real_hardware() {
    let rd = ReportData::new([1u8; 32], [0u8; 8], REPORT_DATA_VERSION, 0, 0);
    let evidence = generate_evidence(&rd.to_bytes()).expect(
        "generate_evidence failed — TDX hardware or kernel TDX guest driver required",
    );
    assert_real_tdx_evidence(evidence.raw().len());
}

#[tokio::test]
async fn ita_nonce_is_valid() {
    let nonce = get_nonce(&ita_config())
        .await
        .expect("get_nonce failed — check ITA_API_KEY and network connectivity");
    assert!(!nonce.val.is_empty());
    assert!(!nonce.iat.is_empty());
}

#[tokio::test]
async fn consecutive_nonces_are_distinct() {
    let cfg = ita_config();
    let n1 = get_nonce(&cfg).await.expect("get_nonce #1 failed");
    let n2 = get_nonce(&cfg).await.expect("get_nonce #2 failed");
    assert_ne!(n1.val, n2.val, "two consecutive nonces have the same val");
}

#[tokio::test]
async fn sha512_reportdata_matches_nonce_plus_runtime_data() {
    let cfg = ita_config();

    let payload: [u8; 32] = Sha256::digest(b"tdx-integration-sha512-test").into();
    let bin_hash = binary_hash().unwrap();
    let rd = ReportData::new(
        payload,
        build_id_from_hash_hex(&bin_hash).unwrap(),
        REPORT_DATA_VERSION,
        0,
        1001,
    );
    let rd_bytes = rd.to_bytes();

    let nonce = get_nonce(&cfg).await.expect("get_nonce failed");

    let expected_rd: [u8; 64] = {
        let mut h = Sha512::new();
        h.update(&nonce.val);
        h.update(&nonce.iat);
        h.update(&rd_bytes);
        h.finalize().into()
    };

    let evidence = generate_evidence(&expected_rd).expect("generate_evidence failed");
    assert_real_tdx_evidence(evidence.raw().len());

    let extracted = extract_report_data(&evidence).expect("extract_report_data failed");
    assert_eq!(extracted, expected_rd);
}

#[tokio::test]
async fn generate_and_attest_returns_valid_jwt() {
    let cfg = ita_config();
    let payload: [u8; 32] = Sha256::digest(b"generate-and-attest-test").into();
    let rd = ReportData::new(payload, [0u8; 8], REPORT_DATA_VERSION, 0, 0);

    let attested = generate_and_attest(&rd.to_bytes(), &cfg)
        .await
        .expect("generate_and_attest failed");

    assert_real_tdx_evidence(attested.evidence.raw().len());
    assert!(!attested.ita_token.is_empty());
    assert_eq!(attested.ita_token.splitn(4, '.').count(), 3);
    assert_eq!(attested.mrtd.len(), 96);
    let mrtd_bytes = hex::decode(&attested.mrtd).expect("MRTD is not valid hex");
    assert_ne!(mrtd_bytes, vec![0u8; 48]);
    assert_ne!(attested.tcb_status, "Revoked");
    assert_eq!(attested.runtime_data, rd.to_bytes());
    assert!(!attested.nonce_val.is_empty());
}

#[tokio::test]
async fn verify_quote_accepts_correct_binding() {
    let livy = Livy::new(api_key());
    let input = b"integration-test-input";
    let output = b"integration-test-output";

    let proof = livy
        .attest()
        .input(input)
        .output(output)
        .commit()
        .await
        .expect("attest.commit() failed");

    let raw = BASE64.decode(proof.raw_quote.trim()).expect("raw_quote is not valid base64");
    assert_real_tdx_evidence(raw.len());

    let ok = verify_quote(
        &proof.raw_quote,
        &proof.runtime_data,
        &proof.verifier_nonce_val,
        &proof.verifier_nonce_iat,
        input,
        output,
    )
    .expect("verify_quote returned an error");

    assert!(ok, "verify_quote returned false on valid proof");
}

#[tokio::test]
async fn verify_quote_rejects_tampered_input() {
    let livy = Livy::new(api_key());
    let input = b"real input";
    let output = b"real output";

    let proof = livy
        .attest()
        .input(input)
        .output(output)
        .commit()
        .await
        .expect("attest.commit() failed");

    let ok = verify_quote(
        &proof.raw_quote,
        &proof.runtime_data,
        &proof.verifier_nonce_val,
        &proof.verifier_nonce_iat,
        b"TAMPERED input",
        output,
    )
    .expect("verify_quote errored unexpectedly");

    assert!(!ok, "verify_quote accepted tampered input");
}

#[tokio::test]
async fn verify_quote_rejects_tampered_output() {
    let livy = Livy::new(api_key());
    let input = b"real input for output test";
    let output = b"real output";

    let proof = livy
        .attest()
        .input(input)
        .output(output)
        .commit()
        .await
        .expect("attest.commit() failed");

    let ok = verify_quote(
        &proof.raw_quote,
        &proof.runtime_data,
        &proof.verifier_nonce_val,
        &proof.verifier_nonce_iat,
        input,
        b"TAMPERED output",
    )
    .expect("verify_quote errored unexpectedly");

    assert!(!ok, "verify_quote accepted tampered output");
}

#[tokio::test]
async fn verify_quote_rejects_wrong_nonce() {
    let livy = Livy::new(api_key());
    let input = b"nonce-mismatch-test-input";
    let output = b"nonce-mismatch-test-output";

    let proof = livy
        .attest()
        .input(input)
        .output(output)
        .commit()
        .await
        .expect("attest.commit() failed");

    let zeroed = BASE64.encode([0u8; 32]);
    let ok = verify_quote(
        &proof.raw_quote,
        &proof.runtime_data,
        &zeroed,
        &zeroed,
        input,
        output,
    )
    .expect("verify_quote errored unexpectedly");

    assert!(!ok, "verify_quote accepted wrong nonce");
}

#[tokio::test]
async fn verify_binding_correct_and_incorrect() {
    let livy = Livy::new(api_key());
    let input = b"verify-binding-input";
    let output = b"verify-binding-output";

    let proof = livy
        .attest()
        .input(input)
        .output(output)
        .commit()
        .await
        .expect("attest.commit() failed");

    assert!(proof.verify_binding(input, output));
    assert!(!proof.verify_binding(b"wrong input", output));
    assert!(!proof.verify_binding(input, b"wrong output"));

    let expected = payload_hash_for(input, output);
    assert_eq!(proof.report_data.payload_hash, expected);
}

#[tokio::test]
async fn custom_nonce_is_embedded_in_report_data() {
    let livy = Livy::new(api_key());

    let proof = livy
        .attest()
        .input(b"nonce-embedding-test")
        .output(b"out")
        .nonce(99_999)
        .commit()
        .await
        .expect("attest.commit() failed");

    assert_eq!(proof.report_data.nonce, 99_999);
}

#[tokio::test]
async fn external_verifier_reconstructs_report_data_from_raw_inputs() {
    let livy = Livy::new(api_key());
    let input  = b"provenance: user request payload";
    let output = b"provenance: tee computed result";

    let proof = livy
        .attest()
        .input(input)
        .output(output)
        .commit()
        .await
        .expect("attest.commit() failed");

    let runtime_data_bytes: [u8; 64] = {
        let raw = BASE64.decode(&proof.runtime_data).expect("runtime_data is not valid base64");
        assert_eq!(raw.len(), 64);
        raw.try_into().unwrap()
    };

    let nonce_val = BASE64.decode(&proof.verifier_nonce_val).expect("nonce_val decode failed");
    let nonce_iat = BASE64.decode(&proof.verifier_nonce_iat).expect("nonce_iat decode failed");
    let raw_quote = BASE64.decode(&proof.raw_quote).expect("raw_quote decode failed");
    assert!(raw_quote.len() >= 632);

    // Check 1: payload_hash
    let expected_payload_hash: [u8; 32] = {
        let ih: [u8; 32] = Sha256::digest(input.as_ref()).into();
        let oh: [u8; 32] = Sha256::digest(output.as_ref()).into();
        let mut h = Sha256::new();
        h.update(ih);
        h.update(oh);
        h.finalize().into()
    };
    let embedded_payload_hash: [u8; 32] = runtime_data_bytes[0..32].try_into().unwrap();
    assert_eq!(embedded_payload_hash, expected_payload_hash);

    // Check 2: SHA-512 binding
    let quote_reportdata: &[u8; 64] = raw_quote[568..632].try_into().unwrap();
    let expected_reportdata: [u8; 64] = {
        let mut h = Sha512::new();
        h.update(&nonce_val);
        h.update(&nonce_iat);
        h.update(&runtime_data_bytes);
        h.finalize().into()
    };
    assert_eq!(quote_reportdata, &expected_reportdata);
}

#[tokio::test]
async fn runtime_data_is_64_bytes_base64() {
    let livy = Livy::new(api_key());

    let proof = livy
        .attest()
        .input(b"runtime-data-size-test")
        .output(b"out")
        .commit()
        .await
        .expect("attest.commit() failed");

    let raw = BASE64.decode(&proof.runtime_data).expect("runtime_data is not valid base64");
    assert_eq!(raw.len(), 64);
    assert_eq!(proof.runtime_data.len(), 88);
}
