// SPDX-License-Identifier: MIT
//! Real TDX hardware integration tests.
//!
//! These tests are ignored by default because they require TDX hardware and,
//! except for the low-level quote test, an `ITA_API_KEY`. Run them on a
//! provisioned guest with:
//!
//! ```text
//! cargo test --features ita-verify --test tdx_integration -- --ignored --test-threads=1
//! ```

#![cfg(all(feature = "ita-verify", not(feature = "mock-tee")))]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use livy_tee::{
    extract_report_data, generate_and_attest, generate_evidence, get_nonce,
    verify_quote_with_public_values, ItaConfig, Livy, PublicValues,
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
        "quote is only {quote_len} bytes — this is not real TDX hardware"
    );
}

fn is_azure_runtime() -> bool {
    livy_tee::detect_cloud_provider() == Some(livy_tee::CloudProvider::Azure)
}

#[test]
#[ignore = "requires a real TDX guest"]
fn low_level_quote_api_still_accepts_64_byte_hardware_reportdata() {
    let evidence = generate_evidence(&[0x5au8; 64])
        .expect("generate_evidence failed — TDX hardware or guest driver required");
    assert_real_tdx_evidence(evidence.raw().len());
}

#[tokio::test]
#[ignore = "requires a real TDX guest and ITA_API_KEY"]
async fn ita_nonces_are_nonempty_and_distinct() {
    let config = ita_config();
    let first = get_nonce(&config).await.expect("first get_nonce failed");
    let second = get_nonce(&config).await.expect("second get_nonce failed");
    assert!(!first.val.is_empty());
    assert!(!first.iat.is_empty());
    assert_ne!(first.val, second.val);
}

#[tokio::test]
#[ignore = "requires a real TDX guest and ITA_API_KEY"]
async fn hardware_reportdata_is_sha512_of_nonce_and_32_byte_commitment() {
    let config = ita_config();
    let commitment: [u8; 32] = Sha256::digest(b"tdx-integration-commitment").into();
    let nonce = get_nonce(&config).await.expect("get_nonce failed");
    let expected: [u8; 64] = {
        let mut hash = Sha512::new();
        hash.update(&nonce.val);
        hash.update(&nonce.iat);
        hash.update(commitment);
        hash.finalize().into()
    };
    let evidence = generate_evidence(&expected).expect("generate_evidence failed");
    assert_real_tdx_evidence(evidence.raw().len());

    let extracted = extract_report_data(&evidence).expect("extract_report_data failed");
    if is_azure_runtime() {
        assert!(extracted.iter().any(|byte| *byte != 0));
    } else {
        assert_eq!(extracted, expected);
    }
}

#[tokio::test]
#[ignore = "requires a real TDX guest and ITA_API_KEY"]
async fn generate_and_attest_accepts_a_32_byte_commitment() {
    let commitment: [u8; 32] = Sha256::digest(b"generate-and-attest-test").into();
    let attested = generate_and_attest(&commitment, &ita_config())
        .await
        .expect("generate_and_attest failed");

    assert_real_tdx_evidence(attested.evidence.raw().len());
    assert_eq!(attested.ita_token.split('.').count(), 3);
    assert_eq!(attested.mrtd.len(), 96);
    assert!(!attested.nonce_val.is_empty());
}

#[tokio::test]
#[ignore = "requires a real TDX guest and ITA_API_KEY"]
async fn high_level_quote_binding_rejects_tampered_public_values() {
    let livy = Livy::new(api_key());
    let mut builder = livy.attest();
    builder.commit(&"real input").commit(&"real output");
    let attestation = builder.finalize().await.expect("finalize failed");
    let raw = BASE64.decode(&attestation.raw_quote).unwrap();
    assert_real_tdx_evidence(raw.len());

    let valid = verify_quote_with_public_values(
        &attestation.raw_quote,
        &attestation.verifier_nonce_val,
        &attestation.verifier_nonce_iat,
        &attestation.public_values,
    )
    .unwrap();
    if !is_azure_runtime() {
        assert!(valid);
    }

    let mut tampered = PublicValues::new();
    tampered.commit(&"tampered input").unwrap();
    tampered.commit(&"real output").unwrap();
    assert!(!verify_quote_with_public_values(
        &attestation.raw_quote,
        &attestation.verifier_nonce_val,
        &attestation.verifier_nonce_iat,
        &tampered,
    )
    .unwrap());
}

#[tokio::test]
#[ignore = "requires a real TDX guest and ITA_API_KEY"]
async fn authenticated_token_and_fresh_evidence_verify() {
    let livy = Livy::new(api_key());
    let mut builder = livy.attest();
    builder.commit(&"verify-test");
    let attestation = builder.finalize().await.expect("finalize failed");

    let report = attestation.verify().await.expect("verify failed");
    let fresh = attestation
        .verify_fresh(&ita_config())
        .await
        .expect("verify_fresh failed");
    assert!(report.jwt_signature_and_expiry_valid);
    assert!(report.token_report_data_matches);
    assert_eq!(fresh.bundled_evidence_authenticated, Some(true));
    assert_eq!(
        report.tcb_status_allowed,
        report.tcb_status.eq_ignore_ascii_case("UpToDate")
    );
}
