// SPDX-License-Identifier: MIT

#[cfg(feature = "mock-tee")]
use base64::Engine;
#[cfg(feature = "mock-tee")]
use livy_tee::{extract_report_data, generate_evidence};
use livy_tee::{Evidence, EvidenceError, GenerateError};
#[cfg(feature = "ita-verify")]
use livy_tee::{Livy, LivyEnvError, VerifyError};
#[cfg(feature = "ita-verify")]
use std::sync::{Mutex, OnceLock};

#[cfg(feature = "ita-verify")]
fn ita_api_key_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(feature = "ita-verify")]
struct ItaApiKeyEnvRestore(Option<String>);

#[cfg(feature = "ita-verify")]
impl Drop for ItaApiKeyEnvRestore {
    fn drop(&mut self) {
        match self.0.take() {
            Some(value) => std::env::set_var("ITA_API_KEY", value),
            None => std::env::remove_var("ITA_API_KEY"),
        }
    }
}

#[cfg(feature = "ita-verify")]
fn with_ita_api_key_env<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
    let _lock = ita_api_key_env_lock().lock().unwrap();
    let _restore = ItaApiKeyEnvRestore(std::env::var("ITA_API_KEY").ok());
    match value {
        Some(value) => std::env::set_var("ITA_API_KEY", value),
        None => std::env::remove_var("ITA_API_KEY"),
    }
    f()
}

#[cfg(feature = "mock-tee")]
#[test]
fn generate_evidence_keeps_the_low_level_64_byte_api() {
    let user_data = [0x5au8; 64];
    let evidence = generate_evidence(&user_data).unwrap();
    assert_eq!(evidence.raw().len(), 632);
    assert_eq!(extract_report_data(&evidence).unwrap(), user_data);
}

#[cfg(feature = "mock-tee")]
#[test]
fn different_user_data_produces_different_report_data() {
    let first = generate_evidence(&[1u8; 64]).unwrap();
    let second = generate_evidence(&[2u8; 64]).unwrap();
    assert_ne!(
        extract_report_data(&first).unwrap(),
        extract_report_data(&second).unwrap()
    );
}

#[cfg(feature = "mock-tee")]
#[test]
fn generated_evidence_roundtrips_through_base64() {
    let evidence = generate_evidence(&[42u8; 64]).unwrap();
    let encoded = evidence.to_base64();
    base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .expect("evidence must be standard base64");
    let recovered = Evidence::from_base64(&encoded).unwrap();
    assert_eq!(evidence.raw(), recovered.raw());
}

#[test]
fn evidence_rejects_short_or_invalid_input() {
    assert!(matches!(
        Evidence::from_bytes(vec![0u8; 100]),
        Err(EvidenceError::TooShort(100))
    ));
    assert!(matches!(
        Evidence::from_base64("not-base64"),
        Err(EvidenceError::Base64(_))
    ));
}

#[test]
fn evidence_accepts_the_632_byte_boundary() {
    let evidence = Evidence::from_bytes(vec![0u8; 632]).unwrap();
    assert_eq!(evidence.raw().len(), 632);
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

#[cfg(feature = "ita-verify")]
#[test]
fn livy_from_env_validates_and_reads_ita_api_key() {
    with_ita_api_key_env(None, || {
        assert_eq!(Livy::from_env().unwrap_err(), LivyEnvError::MissingApiKey);
    });
    with_ita_api_key_env(Some("  "), || {
        assert_eq!(Livy::from_env().unwrap_err(), LivyEnvError::EmptyApiKey);
    });
    with_ita_api_key_env(Some("test-key"), || {
        Livy::from_env().expect("non-empty API key should be accepted");
    });
}
