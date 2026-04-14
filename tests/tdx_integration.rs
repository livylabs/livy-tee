// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Real TDX hardware integration tests.
//!
//! # Prerequisites
//!   - TDX-capable hardware with Linux kernel >= 6.7
//!   - `ITA_API_KEY` environment variable set
//!
//! # Running
//! ```bash
//! ITA_API_KEY=<key> cargo test --test tdx_integration \
//!     --no-default-features --features ita-verify -p livy-tee \
//!     -- --nocapture --test-threads=1
//! ```

#![cfg(all(feature = "ita-verify", not(feature = "mock-tee")))]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use livy_tee::{
    binary_hash, build_id_from_hash_hex, extract_report_data, generate_and_attest,
    generate_evidence, get_nonce, verify_quote_with_public_values, ItaConfig, Livy, PublicValues,
    ReportData, REPORT_DATA_VERSION,
};
use sha2::{Digest, Sha256, Sha512};

fn api_key() -> String {
    let key =
        std::env::var("ITA_API_KEY").expect("ITA_API_KEY must be set to run TDX integration tests");
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

fn is_azure_runtime() -> bool {
    livy_tee::detect_cloud_provider() == Some(livy_tee::CloudProvider::Azure)
}

#[test]
fn tdx_quote_is_real_hardware() {
    let rd = ReportData::new([1u8; 32], [0u8; 8], REPORT_DATA_VERSION, 0, 0);
    let evidence = generate_evidence(&rd.to_bytes())
        .expect("generate_evidence failed — TDX hardware or kernel TDX guest driver required");
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
        build_id_from_hash_hex(&bin_hash),
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
    if is_azure_runtime() {
        assert!(extracted.iter().any(|b| *b != 0));
    } else {
        assert_eq!(extracted, expected_rd);
    }
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
    let mut builder = livy.attest();
    builder.commit(&"integration-test-input");
    builder.commit(&"integration-test-output");
    let att = builder.finalize().await.expect("finalize failed");

    let raw = BASE64
        .decode(att.raw_quote.trim())
        .expect("raw_quote is not valid base64");
    assert_real_tdx_evidence(raw.len());

    let ok = verify_quote_with_public_values(
        &att.raw_quote,
        &att.runtime_data,
        &att.verifier_nonce_val,
        &att.verifier_nonce_iat,
        &att.public_values,
    )
    .expect("verify returned an error");

    if is_azure_runtime() {
        // Azure `/attest/azure` evidence carries Azure runtime JSON and uses a
        // platform-specific quote shape; local raw-quote binding checks are not
        // equivalent to the native TSM quote path.
        assert!(!att.ita_token.is_empty());
    } else {
        assert!(ok, "verify returned false on valid attestation");
    }
}

#[tokio::test]
async fn verify_quote_rejects_tampered_values() {
    let livy = Livy::new(api_key());
    let mut builder = livy.attest();
    builder.commit(&"real input");
    builder.commit(&"real output");
    let att = builder.finalize().await.expect("finalize failed");

    let mut tampered = PublicValues::new();
    tampered.commit(&"TAMPERED input");
    tampered.commit(&"real output");

    let ok = verify_quote_with_public_values(
        &att.raw_quote,
        &att.runtime_data,
        &att.verifier_nonce_val,
        &att.verifier_nonce_iat,
        &tampered,
    )
    .expect("verify errored unexpectedly");

    assert!(!ok, "verify accepted tampered values");
}

#[tokio::test]
async fn verify_quote_rejects_wrong_nonce() {
    let livy = Livy::new(api_key());
    let mut builder = livy.attest();
    builder.commit(&"nonce-mismatch-test");
    let att = builder.finalize().await.expect("finalize failed");

    let zeroed = BASE64.encode([0u8; 32]);
    let ok = verify_quote_with_public_values(
        &att.raw_quote,
        &att.runtime_data,
        &zeroed,
        &zeroed,
        &att.public_values,
    )
    .expect("verify errored unexpectedly");

    assert!(!ok, "verify accepted wrong nonce");
}

#[tokio::test]
async fn proof_verify_correct_and_tampered() {
    let livy = Livy::new(api_key());
    let mut builder = livy.attest();
    builder.commit(&"verify-test");
    let att = builder.finalize().await.expect("finalize failed");

    let report = att.verify().await.expect("verify should not error");
    let strict_report = att
        .verify_fresh(&ita_config())
        .await
        .expect("verify_fresh should not error");
    assert!(report.jwt_signature_and_expiry_valid);
    assert!(report.token_report_data_matches);
    assert!(report.runtime_data_matches_report);
    assert!(report.public_values_bound);
    assert!(report.mrtd_matches_token);
    assert!(report.tcb_status_matches_token);
    if is_azure_runtime() {
        assert_eq!(report.quote_report_data_matches, None);
    } else {
        assert_eq!(report.quote_report_data_matches, Some(true));
    }
    assert_eq!(
        strict_report.bundled_evidence_authenticated,
        Some(true),
        "strict verification report: {strict_report:#?}"
    );
    assert!(
        strict_report.all_passed(),
        "strict verification report: {strict_report:#?}"
    );
    assert_eq!(
        report.tcb_status_allowed,
        report.tcb_status.eq_ignore_ascii_case("UpToDate")
    );

    // Read back and check.
    let val: String = att.public_values.read();
    assert_eq!(val, "verify-test");
}

#[tokio::test]
async fn custom_nonce_is_embedded_in_report_data() {
    let livy = Livy::new(api_key());
    let mut builder = livy.attest();
    builder.commit(&"nonce-embedding-test");
    builder.nonce(99_999);
    let att = builder.finalize().await.expect("finalize failed");

    assert_eq!(att.report_data.nonce, 99_999);
}

#[tokio::test]
async fn external_verifier_reconstructs_report_data_from_public_values() {
    let livy = Livy::new(api_key());
    let mut builder = livy.attest();
    builder.commit(&"provenance: user request payload");
    builder.commit(&"provenance: tee computed result");
    let att = builder.finalize().await.expect("finalize failed");

    let runtime_data_bytes: [u8; 64] = {
        let raw = BASE64
            .decode(&att.runtime_data)
            .expect("runtime_data is not valid base64");
        assert_eq!(raw.len(), 64);
        raw.try_into().unwrap()
    };

    let nonce_val = BASE64
        .decode(&att.verifier_nonce_val)
        .expect("nonce_val decode failed");
    let nonce_iat = BASE64
        .decode(&att.verifier_nonce_iat)
        .expect("nonce_iat decode failed");
    let raw_quote = BASE64
        .decode(&att.raw_quote)
        .expect("raw_quote decode failed");
    assert!(raw_quote.len() >= 632);

    // Check 1: commitment hash matches payload_hash in runtime_data
    let embedded_payload_hash: [u8; 32] = runtime_data_bytes[0..32].try_into().unwrap();
    assert_eq!(embedded_payload_hash, att.public_values.commitment_hash());

    // Check 2: SHA-512 binding
    let quote_reportdata: &[u8; 64] = raw_quote[568..632].try_into().unwrap();
    let expected_reportdata: [u8; 64] = {
        let mut h = Sha512::new();
        h.update(&nonce_val);
        h.update(&nonce_iat);
        h.update(&runtime_data_bytes);
        h.finalize().into()
    };
    if is_azure_runtime() {
        assert!(quote_reportdata.iter().any(|b| *b != 0));
    } else {
        assert_eq!(quote_reportdata, &expected_reportdata);
    }
}

#[tokio::test]
async fn runtime_data_is_64_bytes_base64() {
    let livy = Livy::new(api_key());
    let mut builder = livy.attest();
    builder.commit(&"runtime-data-size-test");
    let att = builder.finalize().await.expect("finalize failed");

    let raw = BASE64
        .decode(&att.runtime_data)
        .expect("runtime_data is not valid base64");
    assert_eq!(raw.len(), 64);
    assert_eq!(att.runtime_data.len(), 88);
}
