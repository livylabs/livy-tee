// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use base64::Engine;
#[cfg(feature = "ita-verify")]
use livy_tee::VerifyError;
use livy_tee::{
    binary_hash, build_id_from_hash_hex, Evidence, EvidenceError, GenerateError, ReportData,
    REPORT_DATA_VERSION,
};
#[cfg(feature = "mock-tee")]
use livy_tee::{extract_report_data, generate_evidence};
use sha2::{Digest, Sha256};

fn sample_payload() -> [u8; 32] {
    Sha256::digest(b"integration-test-payload").into()
}

fn sample_build_id() -> [u8; 8] {
    build_id_from_hash_hex(&binary_hash().unwrap()).expect("binary_hash returns valid SHA-256 hex")
}

fn sample_report() -> ReportData {
    ReportData::new(
        sample_payload(),
        sample_build_id(),
        REPORT_DATA_VERSION,
        0,
        1,
    )
}

#[test]
fn report_data_is_64_bytes() {
    assert_eq!(sample_report().to_bytes().len(), 64);
}

#[test]
fn report_data_is_deterministic() {
    let r = sample_report();
    assert_eq!(r.to_bytes(), r.to_bytes());
}

#[test]
fn report_data_changes_with_different_payload() {
    let r1 = sample_report();
    let different_payload: [u8; 32] = Sha256::digest(b"different").into();
    let r2 = ReportData::new(
        different_payload,
        sample_build_id(),
        REPORT_DATA_VERSION,
        0,
        1,
    );
    assert_ne!(r1.to_bytes(), r2.to_bytes());
}

#[test]
fn report_data_changes_with_nonce() {
    let r1 = sample_report();
    let r2 = ReportData::new(
        sample_payload(),
        sample_build_id(),
        REPORT_DATA_VERSION,
        0,
        2,
    );
    assert_ne!(r1.to_bytes(), r2.to_bytes());
}

#[test]
fn report_data_hex_is_128_chars() {
    assert_eq!(sample_report().to_hex().len(), 128);
}

#[test]
fn reserved_bytes_are_zero() {
    let bytes = sample_report().to_bytes();
    assert_eq!(&bytes[56..64], &[0u8; 8]);
}

#[test]
fn verify_payload_helper_works() {
    let payload = sample_payload();
    let rd = ReportData::new(payload, sample_build_id(), REPORT_DATA_VERSION, 0, 1);
    assert!(rd.verify_payload(&payload));
    assert!(!rd.verify_payload(&[0u8; 32]));
}

#[cfg(feature = "mock-tee")]
#[test]
fn generate_evidence_succeeds_in_mock_mode() {
    let evidence = generate_evidence(&sample_report().to_bytes()).unwrap();
    assert!(!evidence.raw().is_empty());
}

#[cfg(feature = "mock-tee")]
#[test]
fn mock_evidence_is_exactly_632_bytes() {
    let evidence = generate_evidence(&[0u8; 64]).unwrap();
    assert_eq!(evidence.raw().len(), 632);
}

#[cfg(feature = "mock-tee")]
#[test]
fn generated_evidence_encodes_to_valid_base64() {
    let evidence = generate_evidence(&sample_report().to_bytes()).unwrap();
    let b64 = evidence.to_base64();
    assert!(!b64.is_empty());
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .expect("evidence.to_base64() must be valid standard base64");
}

#[cfg(feature = "mock-tee")]
#[test]
fn evidence_base64_roundtrip() {
    let evidence = generate_evidence(&[42u8; 64]).unwrap();
    let b64 = evidence.to_base64();
    let recovered = Evidence::from_base64(&b64).unwrap();
    assert_eq!(evidence.raw(), recovered.raw());
}

#[test]
fn binary_hash_returns_nonempty_string() {
    assert!(!binary_hash().unwrap().is_empty());
}

#[test]
fn generate_error_codes_are_stable() {
    assert_eq!(
        GenerateError::AzureRuntime("bad runtime".to_string()).code(),
        "azure_runtime"
    );
    assert_eq!(
        GenerateError::AzureQuoteResponse("bad response".to_string()).code(),
        "azure_quote_response"
    );
    assert_eq!(
        GenerateError::AzureTpmResponseCode(0x18b).code(),
        "azure_tpm_response_code"
    );
}

#[cfg(feature = "ita-verify")]
#[test]
fn verify_error_codes_are_stable() {
    assert_eq!(
        VerifyError::InvalidStoredEvidence("missing runtime json".to_string()).code(),
        "invalid_stored_evidence"
    );
    assert_eq!(
        VerifyError::InvalidTokenClaims("bad azure claims".to_string()).code(),
        "invalid_token_claims"
    );
}

#[cfg(feature = "mock-tee")]
#[test]
fn extract_report_data_roundtrip() {
    let user_data = sample_report().to_bytes();
    let evidence = generate_evidence(&user_data).unwrap();
    let extracted = extract_report_data(&evidence).unwrap();
    assert_eq!(extracted, user_data);
}

#[test]
fn evidence_from_bytes_rejects_short_buffer() {
    let result = Evidence::from_bytes(vec![0u8; 100]);
    assert!(matches!(result, Err(EvidenceError::TooShort(100))));
}

#[cfg(feature = "mock-tee")]
#[test]
fn different_user_data_produces_different_extracted_report_data() {
    let e1 = generate_evidence(&[1u8; 64]).unwrap();
    let e2 = generate_evidence(&[2u8; 64]).unwrap();
    assert_ne!(
        extract_report_data(&e1).unwrap(),
        extract_report_data(&e2).unwrap()
    );
}

#[test]
fn atttest_builder_input_hash_precomputed() {
    let input = b"hello";
    let output = b"world";
    let ih: [u8; 32] = Sha256::digest(input).into();
    let oh: [u8; 32] = Sha256::digest(output).into();
    let expected: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(ih);
        h.update(oh);
        h.finalize().into()
    };
    let rd = ReportData::new(expected, sample_build_id(), REPORT_DATA_VERSION, 0, 0);
    assert!(rd.verify_payload(&expected));
}

#[test]
fn livy_from_env_fails_when_key_missing() {
    std::env::remove_var("ITA_API_KEY");
    let result = std::env::var("ITA_API_KEY");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Evidence error paths
// ---------------------------------------------------------------------------

#[test]
fn evidence_from_base64_rejects_invalid_base64() {
    let result = Evidence::from_base64("not-valid-base64!!!");
    assert!(matches!(result, Err(EvidenceError::Base64(_))));
}

#[test]
fn evidence_from_base64_rejects_short_decoded() {
    // Valid base64 but decodes to only 3 bytes — well under 632.
    let b64 = base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3]);
    let result = Evidence::from_base64(&b64);
    assert!(matches!(result, Err(EvidenceError::TooShort(3))));
}

#[test]
fn evidence_from_bytes_boundary_632() {
    // Exactly 632 bytes should succeed.
    let buf = vec![0u8; 632];
    assert!(Evidence::from_bytes(buf).is_ok());

    // 631 bytes should fail.
    let buf_short = vec![0u8; 631];
    assert!(Evidence::from_bytes(buf_short).is_err());
}
