// SPDX-License-Identifier: MIT
//! Deterministic signed ITA token verification tests.

#![cfg(feature = "ita-verify")]

mod support;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use livy_tee::{
    appraise_evidence_unauthenticated, Attestation, AttestationVerificationPolicy, Evidence,
    ItaConfig, PublicValues, VerifierNonce, VerifyError, ATTESTATION_SCHEMA_VERSION,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};
use support::{TEST_JWK_E, TEST_JWK_KID, TEST_JWK_N, TEST_RSA_PRIVATE_KEY_PEM};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

const TEST_ISSUER: &str = "https://issuer.example.test";
const TEST_AUDIENCE: &str = "https://relying-party.example.test";
const TEST_TCB_DATE: &str = "2026-02-11T00:00:00Z";

#[derive(Debug)]
struct VerificationFixture {
    attestation: Attestation,
    commitment: [u8; 32],
    report_hash: [u8; 64],
    mrtd: String,
}

struct HttpServer {
    url: String,
    task: JoinHandle<Vec<String>>,
}

impl HttpServer {
    async fn jwks(requests: usize) -> Self {
        let body = json!({
            "keys": [{
                "kty": "RSA",
                "kid": TEST_JWK_KID,
                "use": "sig",
                "alg": "RS256",
                "n": TEST_JWK_N,
                "e": TEST_JWK_E,
            }]
        })
        .to_string();
        Self::responses(requests, move |_| (200, body.clone())).await
    }

    async fn token(token: String) -> Self {
        let body = json!({ "token": token }).to_string();
        Self::responses(1, move |_| (200, body.clone())).await
    }

    async fn responses(
        requests: usize,
        response: impl Fn(usize) -> (u16, String) + Send + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut observed = Vec::new();
            for index in 0..requests {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0u8; 65_536];
                let size = stream.read(&mut request).await.unwrap();
                observed.push(String::from_utf8_lossy(&request[..size]).to_string());
                let (status, body) = response(index);
                let reason = if status == 200 { "OK" } else { "ERROR" };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            observed
        });
        Self {
            url: format!("http://{addr}"),
            task,
        }
    }

    async fn finish(self) -> Vec<String> {
        self.task.await.unwrap()
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn report_hash(nonce_val: &[u8], nonce_iat: &[u8], commitment: &[u8; 32]) -> [u8; 64] {
    let mut hash = Sha512::new();
    hash.update(nonce_val);
    hash.update(nonce_iat);
    hash.update(commitment);
    hash.finalize().into()
}

fn quote_with_report_data(report_data: [u8; 64]) -> Vec<u8> {
    let mut quote = vec![0u8; 632];
    quote[0..2].copy_from_slice(&4u16.to_le_bytes());
    quote[4..8].copy_from_slice(&0x81u32.to_le_bytes());
    quote[568..632].copy_from_slice(&report_data);
    quote
}

fn verification_fixture(tcb_status: &str, azure: bool) -> VerificationFixture {
    let mut public_values = PublicValues::new();
    public_values.commit(&"input").unwrap();
    public_values.commit(&"output").unwrap();
    let commitment = public_values.commitment_hash();
    let nonce_val = [0x31u8; 32];
    let nonce_iat = [0x52u8; 32];
    let nonce_signature = [0x73u8; 32];
    let report_hash = report_hash(&nonce_val, &nonce_iat, &commitment);
    let quote = quote_with_report_data(report_hash);
    let raw_quote = BASE64.encode(&quote);
    let evidence = if azure {
        Evidence::from_bytes_with_azure_runtime(
            quote,
            format!(r#"{{"user-data":"{}"}}"#, hex::encode(report_hash)).into_bytes(),
        )
        .unwrap()
        .to_transport_string()
    } else {
        raw_quote.clone()
    };
    let mrtd = "11".repeat(48);

    VerificationFixture {
        commitment,
        report_hash,
        mrtd: mrtd.clone(),
        attestation: Attestation {
            schema_version: ATTESTATION_SCHEMA_VERSION,
            ita_token: String::new(),
            jwks_url: String::new(),
            mrtd,
            tcb_status: tcb_status.to_string(),
            tcb_date: Some(TEST_TCB_DATE.to_string()),
            advisory_ids: Vec::new(),
            evidence,
            raw_quote,
            verifier_nonce_val: BASE64.encode(nonce_val),
            verifier_nonce_iat: BASE64.encode(nonce_iat),
            verifier_nonce_signature: BASE64.encode(nonce_signature),
            public_values,
        },
    }
}

fn verifier_nonce(fixture: &VerificationFixture) -> VerifierNonce {
    VerifierNonce {
        val: BASE64
            .decode(&fixture.attestation.verifier_nonce_val)
            .unwrap(),
        iat: BASE64
            .decode(&fixture.attestation.verifier_nonce_iat)
            .unwrap(),
        signature: BASE64
            .decode(&fixture.attestation.verifier_nonce_signature)
            .unwrap(),
        val_b64: fixture.attestation.verifier_nonce_val.clone(),
        iat_b64: fixture.attestation.verifier_nonce_iat.clone(),
        signature_b64: fixture.attestation.verifier_nonce_signature.clone(),
    }
}

fn sign_token(claims: Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_JWK_KID.to_string());
    sign_token_with_header(claims, header)
}

fn sign_token_with_header(claims: Value, header: Header) -> String {
    jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes())
            .expect("repaired RSA private-key fixture must parse"),
    )
    .unwrap()
}

fn registered(mut claims: Value) -> Value {
    let now = now_unix_secs();
    let object = claims.as_object_mut().unwrap();
    object.insert("iat".to_string(), json!(now - 60));
    object.insert("nbf".to_string(), json!(now - 60));
    object.insert("exp".to_string(), json!(now + 3600));
    object.insert("iss".to_string(), json!(TEST_ISSUER));
    object.insert("aud".to_string(), json!(TEST_AUDIENCE));
    claims
}

fn standard_claims(
    fixture: &VerificationFixture,
    report_data_claim: [u8; 64],
    tcb_status: &str,
) -> Value {
    registered(json!({
        "tdx": {
            "tdx_mrtd": fixture.mrtd,
            "tdx_report_data": hex::encode(report_data_claim),
            "attester_tcb_status": tcb_status,
            "attester_tcb_date": TEST_TCB_DATE,
            "attester_advisory_ids": [],
        }
    }))
}

fn azure_claims(
    fixture: &VerificationFixture,
    held_data: [u8; 32],
    user_data_hash: [u8; 64],
    tcb_status: &str,
) -> Value {
    registered(json!({
        "appraisal": { "method": "azure" },
        "tdx": {
            "tdx_mrtd": fixture.mrtd,
            "tdx_report_data": hex::encode([0xa5u8; 64]),
            "attester_tcb_status": tcb_status,
            "attester_tcb_date": TEST_TCB_DATE,
            "attester_advisory_ids": [],
            "attester_held_data": BASE64.encode(held_data),
            "attester_runtime_data": {
                "user-data": hex::encode(user_data_hash),
            }
        }
    }))
}

fn policy(fixture: &VerificationFixture, jwks_url: String) -> AttestationVerificationPolicy {
    let mut policy = AttestationVerificationPolicy::default();
    policy.jwks_url = jwks_url;
    policy.expected_token_issuer = Some(TEST_ISSUER.to_string());
    policy.expected_token_audience = Some(TEST_AUDIENCE.to_string());
    policy.request_timeout_secs = 5;
    policy.accepted_tcb_statuses = vec!["UpToDate".to_string()];
    policy.expected_mrtd = Some(fixture.mrtd.clone());
    policy
}

#[test]
fn repaired_rsa_fixture_is_usable() {
    EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes())
        .expect("RSA private-key test fixture should remain valid");
}

#[tokio::test]
async fn signed_standard_token_and_quote_binding_pass() {
    let mut fixture = verification_fixture("UpToDate", false);
    fixture.attestation.ita_token =
        sign_token(standard_claims(&fixture, fixture.report_hash, "UpToDate"));
    let jwks = HttpServer::jwks(1).await;
    let report = fixture
        .attestation
        .verify_with_policy(&policy(&fixture, format!("{}/jwks", jwks.url)))
        .await
        .unwrap();

    assert!(report.all_passed(), "{report:#?}");
    assert_eq!(report.quote_report_data_matches, Some(true));
    jwks.finish().await;
}

#[tokio::test]
async fn tampered_public_values_break_token_and_quote_binding() {
    let mut fixture = verification_fixture("UpToDate", false);
    fixture.attestation.ita_token =
        sign_token(standard_claims(&fixture, fixture.report_hash, "UpToDate"));
    let mut tampered = PublicValues::new();
    tampered.commit(&"input").unwrap();
    tampered.commit(&"tampered-output").unwrap();
    fixture.attestation.public_values = tampered;

    let jwks = HttpServer::jwks(1).await;
    let report = fixture
        .attestation
        .verify_with_policy(&policy(&fixture, format!("{}/jwks", jwks.url)))
        .await
        .unwrap();
    assert!(!report.token_report_data_matches);
    assert_eq!(report.quote_report_data_matches, Some(false));
    assert!(!report.all_passed());
    jwks.finish().await;
}

#[tokio::test]
async fn signed_azure_token_uses_32_byte_held_data() {
    let mut fixture = verification_fixture("UpToDate", true);
    fixture.attestation.ita_token = sign_token(azure_claims(
        &fixture,
        fixture.commitment,
        fixture.report_hash,
        "UpToDate",
    ));
    let jwks = HttpServer::jwks(1).await;
    let report = fixture
        .attestation
        .verify_with_policy(&policy(&fixture, format!("{}/jwks", jwks.url)))
        .await
        .unwrap();

    assert!(report.all_passed(), "{report:#?}");
    assert_eq!(report.quote_report_data_matches, None);
    jwks.finish().await;
}

#[tokio::test]
async fn azure_held_data_or_runtime_hash_mismatch_is_rejected() {
    for claims in [
        azure_claims(
            &verification_fixture("UpToDate", true),
            [0x99; 32],
            verification_fixture("UpToDate", true).report_hash,
            "UpToDate",
        ),
        {
            let fixture = verification_fixture("UpToDate", true);
            azure_claims(&fixture, fixture.commitment, [0x88; 64], "UpToDate")
        },
    ] {
        let mut fixture = verification_fixture("UpToDate", true);
        fixture.attestation.ita_token = sign_token(claims);
        let jwks = HttpServer::jwks(1).await;
        let report = fixture
            .attestation
            .verify_with_policy(&policy(&fixture, format!("{}/jwks", jwks.url)))
            .await
            .unwrap();
        assert!(!report.token_report_data_matches);
        assert!(!report.all_passed());
        jwks.finish().await;
    }
}

#[tokio::test]
async fn token_registered_claim_failures_are_diagnostic() {
    enum Mutation {
        Expired,
        Future,
        Issuer,
        Audience,
    }

    for mutation in [
        Mutation::Expired,
        Mutation::Future,
        Mutation::Issuer,
        Mutation::Audience,
    ] {
        let mut fixture = verification_fixture("UpToDate", false);
        let mut claims = standard_claims(&fixture, fixture.report_hash, "UpToDate");
        let object = claims.as_object_mut().unwrap();
        match mutation {
            Mutation::Expired => {
                object.insert("exp".to_string(), json!(now_unix_secs() - 120));
            }
            Mutation::Future => {
                object.insert("nbf".to_string(), json!(now_unix_secs() + 3600));
            }
            Mutation::Issuer => {
                object.insert("iss".to_string(), json!("https://wrong.example"));
            }
            Mutation::Audience => {
                object.insert("aud".to_string(), json!("https://wrong.example"));
            }
        }
        fixture.attestation.ita_token = sign_token(claims);
        let jwks = HttpServer::jwks(1).await;
        let report = fixture
            .attestation
            .verify_with_policy(&policy(&fixture, format!("{}/jwks", jwks.url)))
            .await
            .unwrap();
        assert!(!report.jwt_signature_and_expiry_valid);
        assert!(report.token_verification_error.is_some());
        assert!(!report.all_passed());
        jwks.finish().await;
    }
}

#[tokio::test]
async fn wrong_key_id_and_algorithm_are_rejected() {
    let fixture = verification_fixture("UpToDate", false);
    let claims = standard_claims(&fixture, fixture.report_hash, "UpToDate");

    let mut unknown_kid = Header::new(Algorithm::RS256);
    unknown_kid.kid = Some("unknown".to_string());
    let tokens = [
        (sign_token_with_header(claims.clone(), unknown_kid), true),
        (
            jsonwebtoken::encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(b"not-rsa"),
            )
            .unwrap(),
            false,
        ),
    ];

    for (token, expects_jwks_request) in tokens {
        let mut fixture = verification_fixture("UpToDate", false);
        fixture.attestation.ita_token = token;
        let jwks = if expects_jwks_request {
            Some(HttpServer::jwks(1).await)
        } else {
            None
        };
        let jwks_url = jwks.as_ref().map_or_else(
            || "http://127.0.0.1:9/jwks".to_string(),
            |server| format!("{}/jwks", server.url),
        );
        let report = fixture
            .attestation
            .verify_with_policy(&policy(&fixture, jwks_url))
            .await
            .unwrap();
        assert!(!report.jwt_signature_and_expiry_valid);
        assert!(!report.all_passed());
        if let Some(server) = jwks {
            server.finish().await;
        }
    }
}

#[tokio::test]
async fn tcb_and_mrtd_policy_are_enforced() {
    let mut fixture = verification_fixture("OutOfDate", false);
    fixture.attestation.ita_token =
        sign_token(standard_claims(&fixture, fixture.report_hash, "OutOfDate"));
    let jwks = HttpServer::jwks(1).await;
    let mut verification_policy = policy(&fixture, format!("{}/jwks", jwks.url));
    verification_policy.expected_mrtd = Some("22".repeat(48));
    let report = fixture
        .attestation
        .verify_with_policy(&verification_policy)
        .await
        .unwrap();
    assert!(!report.tcb_status_allowed);
    assert_eq!(report.expected_mrtd_matches, Some(false));
    assert!(!report.all_passed());
    jwks.finish().await;
}

#[tokio::test]
async fn unauthenticated_appraisal_submits_a_32_byte_standard_runtime_value() {
    let fixture = verification_fixture("UpToDate", false);
    let token = sign_token(standard_claims(&fixture, fixture.report_hash, "UpToDate"));
    let server = HttpServer::token(token).await;
    let config = ItaConfig {
        api_key: "test-key".to_string(),
        api_url: server.url.clone(),
        expected_token_issuer: None,
        expected_token_audience: None,
        request_timeout_secs: 5,
    };
    let evidence = Evidence::from_base64(&fixture.attestation.raw_quote).unwrap();
    let claims = appraise_evidence_unauthenticated(
        &evidence,
        &config,
        &fixture.commitment,
        &verifier_nonce(&fixture),
    )
    .await
    .unwrap();
    assert_eq!(claims.user_data, fixture.commitment);

    let requests = server.finish().await;
    assert!(requests[0].contains("/appraisal/v2/attest"));
    assert!(requests[0].contains(&BASE64.encode(fixture.commitment)));
}

#[tokio::test]
async fn verify_fresh_reappraises_with_the_same_32_byte_commitment() {
    let mut fixture = verification_fixture("UpToDate", false);
    let token = sign_token(standard_claims(&fixture, fixture.report_hash, "UpToDate"));
    fixture.attestation.ita_token = token.clone();
    let jwks = HttpServer::jwks(2).await;
    let appraisal = HttpServer::token(token).await;
    let verification_policy = policy(&fixture, format!("{}/jwks", jwks.url));
    let config = ItaConfig {
        api_key: "test-key".to_string(),
        api_url: appraisal.url.clone(),
        expected_token_issuer: Some(TEST_ISSUER.to_string()),
        expected_token_audience: Some(TEST_AUDIENCE.to_string()),
        request_timeout_secs: 5,
    };

    let report = fixture
        .attestation
        .verify_fresh_with_policy(&config, &verification_policy)
        .await
        .unwrap();
    assert_eq!(report.bundled_evidence_authenticated, Some(true));
    assert!(report.all_passed(), "{report:#?}");

    let requests = appraisal.finish().await;
    assert!(requests[0].contains(&BASE64.encode(fixture.commitment)));
    jwks.finish().await;
}

#[tokio::test]
async fn malformed_attestation_fields_remain_hard_errors() {
    let mut fixture = verification_fixture("UpToDate", false);
    fixture.attestation.ita_token =
        sign_token(standard_claims(&fixture, fixture.report_hash, "UpToDate"));
    fixture.attestation.raw_quote = "not-base64".to_string();
    let jwks = HttpServer::jwks(1).await;
    let error = fixture
        .attestation
        .verify_with_policy(&policy(&fixture, format!("{}/jwks", jwks.url)))
        .await
        .unwrap_err();
    assert!(matches!(error, VerifyError::InvalidAttestation(_)));
    jwks.finish().await;
}
