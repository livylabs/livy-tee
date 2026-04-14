// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Deterministic signed-token verification tests.
//!
//! Run with: cargo test --test signed_verification --features ita-verify
#![cfg(feature = "ita-verify")]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use livy_tee::{
    appraise_evidence_unauthenticated, unauthenticated_report_data_hash_from_token, Attestation,
    AttestationVerification, AttestationVerificationPolicy, Evidence, ItaConfig, PublicValues,
    ReportData, VerifierNonce, VerifyError, REPORT_DATA_VERSION,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

const TEST_JWK_KID: &str = "livy-tee-test-rs256";
const TEST_JWK_N: &str = "vpr_cZm-XbZoRuKrCLn9zUf-auv6PZlQFKn80upja-ylEknyPRo4hnDbQL8DdijlQM4XtNMghWhHa0Xgl2--I_7oLlGMNnOUsbVcdIkTAF_Jf0y-0dLMtxLlfrZ45uxpAOxvGxvuoS4D7E_5AfX2iQwt7Zboh38XoR7vcmXCDqVPe5f7MybVM7BKkb9golLDTdtXBVhz-k1s1GNFA2zMKTVw3s9Ubn2--Dety9jiIieBCNyDES7quPQCtVTM2q5CPZKLkGQstXs0IezG4c5jObRE5uwT_wWo5qP1XjQYa6twFqgN5a1Pz7QJawEImOPfW_-bcogCsOzg_cdhYHBqsQ";
const TEST_JWK_E: &str = "AQAB";
const TEST_TCB_DATE: &str = "2026-02-11T00:00:00Z";
const TEST_GCP_ADVISORY_IDS: [&str; 4] = [
    "INTEL-SA-00828",
    "INTEL-SA-00950",
    "INTEL-SA-01046",
    "INTEL-SA-01073",
];
const TEST_RSA_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC+mv9xmb5dtmhG
4qsIuf3NR/5q6/o9mVAUqfzS6mNr7KUSSfI9GjiGcNtAvwN2KOVAzhe00yCFaEdr
ReCXb74j/uguUYw2c5SxtVx0iRMAX8l/TL7R0sy3EuV+tnjm7GkA7G8bG+6hLgPs
T/kB9faJDC3tluiHfxehHu9yZcIOpU97l/szJtUzsEqRv2CiUsNN21cFWHP6TWzU
Y0UDbMwpNXDez1Rufb74N63L2OIiJ4EI3IMRLuq49AK1VMzarkI9kouQZCy1ezQh
7MbhzmM5tETm7BP/Bajmo/VeNBhrq3AWqA3lrU/PtAlrAQiY499b/5tyiAKw7OD9
x2FgcGqxAgMBAAECggEAPYToeqF9PGDx4iMpwdzKCpY4iwkUEQqpOqos5GRrZ3uP
QcplKYyLfvTxB0I/m0USzWpXY3EbV4OzPW/lz+rsi1CsXrrKTw7aCMt5BlHxtJa2
AeTi1/U6RsKOGOpLNnlKYNZu++h1ikdAU+bx/0yEYHJyZnNlJMqD9Wh3L0yhqDjr
HZ4LTGM+XcbjLRRCHxliDkmYSjcAVB63qv0jIK8+5ylxbAiVhnJDlY4eqQLsYRoe
GOCLnt/xQfV/zN0nYvzogn8Rnb/+ZCmgso5vT7yOqeGaEEHDNtbMto1BsQWdYo5B
xXgCsCF1izFIfy8YFCnxM06VVCoLcW3sqURP9uJvuwKBgQDn8WhoyYqNXGb0/xBH
cN4Fio/WfG8nI3jaOt3D6A+3nmNDpOidbaO8drP5KL0YxcrIwf+15qvnebXfJYX+
uqQ82VkO/R/laPMqPNpJbudOlhgPWqPXzA+gC2FxMgmdaW5y9eQbJfWIQk0waCrr
DyRMuGi5SYqHVVbSGnnCpTOY+wKBgQDSX/z775LRwwYOegs9Ma4LjmYUFGuey+OZ
v/SkF3Giq43nqrWaElxMwep6aoKAp3iMHVGSwosxQySIYk8HcPi9FGam8UvjqyYy
bJVToFNEUWf8t0daHY0qP9Oflmq6bJst5IPsdC8RCZUbiInj3bpaKMZia5xCroCq
bZTmyCJTQwKBgQDP7wMcVfopSrpeTz/H3C6epx7WOY3od4uDkRx44dUdVxhEb1W+
tKkCbyRfbZ9A0yk9m3XkHBzmkp1ypJAg0jAlAPEvV8u9fb3pks5a4Nrq//In6alS
7/TeFPXRZftqrDdBRqGtmPUqp83NZMV9H4D6aqQv3/cZ5m7EQsn/rty3+wKBgEZz
RKot6ZH7aHzSnA7rIyjVkBOrXvr3tomXgdqtyy05nDT3swccnPJLgjVqk7d33eO2
McofAjQGEyblHSgVygav3UyMw+hDOXBrcnpl11yqklNMIUXpXYvHghwQaD9z/WeZ
/h/iLJzdA6ULzXmUmEJ3IzB0bwjZnVb1iYbbgLs3AoGAaVCxASKe3LnPHmOin7o2
KdX8KPUu0w6al1jRIsbolgQ+d1VfrVU1q22eVl5gJx/fCW/sNEFBbIzlluupPdwd
5RO9DBmqkDlJq8OWcMeKekKJaOBJj66L/3zTWcuUvNMOUrizl9zJ3++Z8025evxO
g+iQymSztLxy+1KadgJ/pwA=
-----END PRIVATE KEY-----"#;

#[derive(Debug)]
struct VerificationFixture {
    attestation: Attestation,
    runtime_data: [u8; 64],
    runtime_hash: [u8; 64],
    mrtd: String,
}

struct JwksServer {
    url: String,
    task: JoinHandle<()>,
}

impl JwksServer {
    async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local JWKS server");
        let addr = listener.local_addr().expect("JWKS listener address");
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
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept JWKS request");
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write JWKS response");
        });
        Self {
            url: format!("http://{addr}/jwks.json"),
            task,
        }
    }

    async fn finish(self) {
        self.task.await.expect("JWKS task should complete");
    }
}

struct AppraisalServer {
    url: String,
    task: JoinHandle<()>,
}

impl AppraisalServer {
    async fn spawn(expected_path: &'static str, token: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local appraisal server");
        let addr = listener
            .local_addr()
            .expect("local appraisal listener address");
        let body = json!({ "token": token }).to_string();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept appraisal request");
            let mut request = vec![0u8; 8192];
            let len = stream
                .read(&mut request)
                .await
                .expect("read appraisal request");
            let request = String::from_utf8_lossy(&request[..len]);
            assert!(
                request.contains(expected_path),
                "expected request path {expected_path}, got {request}"
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write appraisal response");
        });
        Self {
            url: format!("http://{addr}"),
            task,
        }
    }

    async fn finish(self) {
        self.task.await.expect("join appraisal server task");
    }
}

fn sample_mrtd() -> String {
    "11".repeat(48)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time should be after unix epoch")
        .as_secs()
}

fn runtime_hash(nonce_val: &[u8], nonce_iat: &[u8], runtime_data: &[u8; 64]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(nonce_val);
    h.update(nonce_iat);
    h.update(runtime_data);
    h.finalize().into()
}

fn quote_with_report_data(report_data: [u8; 64]) -> String {
    let mut quote = vec![0u8; 632];
    quote[0..2].copy_from_slice(&4u16.to_le_bytes());
    quote[4..8].copy_from_slice(&0x81u32.to_le_bytes());
    quote[568..632].copy_from_slice(&report_data);
    BASE64.encode(quote)
}

fn verification_fixture(tcb_status: &str) -> VerificationFixture {
    let mut public_values = PublicValues::new();
    public_values.commit(&"input");
    public_values.commit(&"output");

    let report_data = ReportData::new(
        public_values.commitment_hash(),
        [0x42; 8],
        REPORT_DATA_VERSION,
        0,
        7,
    );
    let runtime_data = report_data.to_bytes();
    let nonce_val = [0x31u8; 32];
    let nonce_iat = [0x52u8; 32];
    let nonce_signature = [0x73u8; 32];
    let mrtd = sample_mrtd();
    let raw_quote = quote_with_report_data(runtime_hash(&nonce_val, &nonce_iat, &runtime_data));

    VerificationFixture {
        runtime_hash: runtime_hash(&nonce_val, &nonce_iat, &runtime_data),
        runtime_data,
        mrtd: mrtd.clone(),
        attestation: Attestation {
            ita_token: String::new(),
            jwks_url: String::new(),
            mrtd,
            tcb_status: tcb_status.to_string(),
            tcb_date: Some(TEST_TCB_DATE.to_string()),
            advisory_ids: Vec::new(),
            evidence: raw_quote.clone(),
            raw_quote,
            runtime_data: BASE64.encode(runtime_data),
            verifier_nonce_val: BASE64.encode(nonce_val),
            verifier_nonce_iat: BASE64.encode(nonce_iat),
            verifier_nonce_signature: BASE64.encode(nonce_signature),
            report_data,
            public_values,
        },
    }
}

fn verifier_nonce(fixture: &VerificationFixture) -> VerifierNonce {
    VerifierNonce {
        val: BASE64
            .decode(fixture.attestation.verifier_nonce_val.as_bytes())
            .expect("fixture nonce value should decode"),
        iat: BASE64
            .decode(fixture.attestation.verifier_nonce_iat.as_bytes())
            .expect("fixture nonce iat should decode"),
        signature: BASE64
            .decode(fixture.attestation.verifier_nonce_signature.as_bytes())
            .expect("fixture nonce signature should decode"),
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
        &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes()).expect("load test RSA key"),
    )
    .expect("sign test JWT")
}

fn with_registered_claims(mut claims: Value) -> Value {
    let now = now_unix_secs();
    let object = claims
        .as_object_mut()
        .expect("test claims should be a JSON object");
    object.insert("iat".to_string(), json!(now - 60));
    object.insert("nbf".to_string(), json!(now - 60));
    object.insert("exp".to_string(), json!(now + 3600));
    claims
}

fn standard_claims(
    fixture: &VerificationFixture,
    report_data_claim: [u8; 64],
    tcb_status: &str,
) -> Value {
    with_registered_claims(json!({
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
    held_data: [u8; 64],
    user_data_hash: [u8; 64],
    tcb_status: &str,
) -> Value {
    with_registered_claims(json!({
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

fn default_policy(fixture: &VerificationFixture) -> AttestationVerificationPolicy {
    let mut policy = AttestationVerificationPolicy::default();
    policy.jwks_url = String::new();
    policy.request_timeout_secs = 5;
    policy.accepted_tcb_statuses = vec!["UpToDate".to_string()];
    policy.expected_advisory_ids = None;
    policy.expected_mrtd = Some(fixture.mrtd.clone());
    policy.expected_build_id = Some(fixture.attestation.report_data.build_id);
    policy.expected_nonce = Some(fixture.attestation.report_data.nonce);
    policy
}

fn verify_config(api_url: String) -> ItaConfig {
    ItaConfig {
        api_key: "test-key".to_string(),
        api_url,
        request_timeout_secs: 30,
    }
}

fn attach_azure_runtime_evidence(fixture: &mut VerificationFixture) {
    let raw_quote = BASE64
        .decode(fixture.attestation.raw_quote.as_bytes())
        .expect("fixture raw quote should decode");
    let evidence =
        Evidence::from_bytes_with_azure_runtime(raw_quote, br#"{"user-data":"cafebabe"}"#.to_vec())
            .expect("fixture Azure evidence should be valid");
    fixture.attestation.evidence = evidence.to_transport_string();
}

async fn verify_fixture(
    mut fixture: VerificationFixture,
    claims: Value,
    policy: AttestationVerificationPolicy,
) -> AttestationVerification {
    let server = JwksServer::spawn().await;
    let mut policy = policy;
    policy.jwks_url = server.url.clone();
    fixture.attestation.ita_token = sign_token(claims);
    let report = fixture
        .attestation
        .verify_with_policy(&policy)
        .await
        .expect("verification should return a report");
    server.finish().await;
    report
}

async fn verify_fresh_fixture(
    mut fixture: VerificationFixture,
    claims: Value,
    appraisal_path: &'static str,
    policy: AttestationVerificationPolicy,
) -> AttestationVerification {
    let stored_token = sign_token(claims.clone());
    let appraisal = AppraisalServer::spawn(appraisal_path, stored_token.clone()).await;
    let jwks = JwksServer::spawn().await;
    let mut policy = policy;
    policy.jwks_url = jwks.url.clone();
    fixture.attestation.ita_token = stored_token;

    let report = fixture
        .attestation
        .verify_fresh_with_policy(&verify_config(appraisal.url.clone()), &policy)
        .await
        .expect("fresh verification should succeed");

    appraisal.finish().await;
    jwks.finish().await;
    report
}

#[tokio::test]
async fn appraise_evidence_unauthenticated_returns_trimmed_token_claims() {
    let fixture = verification_fixture("UpToDate");
    let evidence = Evidence::from_transport_string(&fixture.attestation.evidence)
        .expect("fixture evidence should decode");
    let nonce = verifier_nonce(&fixture);
    let token = sign_token(standard_claims(&fixture, fixture.runtime_hash, "UpToDate"));
    let appraisal = AppraisalServer::spawn("/appraisal/v2/attest", format!(" \n{token}\t ")).await;

    let claims = appraise_evidence_unauthenticated(
        &evidence,
        &ItaConfig {
            api_key: "test-key".to_string(),
            api_url: appraisal.url.clone(),
            request_timeout_secs: 30,
        },
        &fixture.runtime_data,
        &nonce,
    )
    .await
    .expect("appraisal should return claims");

    appraisal.finish().await;

    assert_eq!(claims.raw_token, token);
    assert_eq!(claims.mrtd, fixture.mrtd);
    assert_eq!(claims.report_data, fixture.runtime_hash);
    assert_eq!(claims.runtime_data, fixture.runtime_data);
    assert_eq!(claims.tcb_status, "UpToDate");
}

#[tokio::test]
async fn verify_with_policy_accepts_signed_standard_token() {
    let fixture = verification_fixture("UpToDate");
    let claims = standard_claims(&fixture, fixture.runtime_hash, "UpToDate");
    let policy = default_policy(&fixture);
    let report = verify_fixture(fixture, claims, policy).await;

    assert!(report.jwt_signature_and_expiry_valid);
    assert_eq!(report.token_verification_error, None);
    assert!(report.token_report_data_matches);
    assert_eq!(report.quote_report_data_matches, Some(true));
    assert!(report.runtime_data_matches_report);
    assert!(report.public_values_bound);
    assert!(report.mrtd_matches_token);
    assert!(report.tcb_status_matches_token);
    assert!(report.tcb_date_matches_token);
    assert!(report.tcb_status_allowed);
    assert_eq!(report.expected_mrtd_matches, Some(true));
    assert_eq!(report.expected_build_id_matches, Some(true));
    assert_eq!(report.expected_nonce_matches, Some(true));
    assert!(report.require_success().is_ok());
    assert!(report.all_passed());
}

#[tokio::test]
async fn verify_with_policy_accepts_signed_azure_token() {
    let fixture = verification_fixture("UpToDate");
    let claims = azure_claims(
        &fixture,
        fixture.runtime_data,
        fixture.runtime_hash,
        "UpToDate",
    );
    let policy = default_policy(&fixture);
    let report = verify_fixture(fixture, claims, policy).await;

    assert!(report.jwt_signature_and_expiry_valid);
    assert_eq!(report.token_verification_error, None);
    assert!(report.token_report_data_matches);
    assert_eq!(report.quote_report_data_matches, None);
    assert!(report.runtime_data_matches_report);
    assert!(report.public_values_bound);
    assert!(report.mrtd_matches_token);
    assert!(report.tcb_status_matches_token);
    assert!(report.tcb_date_matches_token);
    assert!(report.tcb_status_allowed);
    assert!(report.all_passed());
}

#[tokio::test]
async fn verify_with_policy_reports_standard_report_data_mismatch() {
    let fixture = verification_fixture("UpToDate");
    let claims = standard_claims(&fixture, [0x99; 64], "UpToDate");
    let policy = default_policy(&fixture);
    let report = verify_fixture(fixture, claims, policy).await;

    assert!(report.jwt_signature_and_expiry_valid);
    assert_eq!(report.token_verification_error, None);
    assert!(!report.token_report_data_matches);
    assert_eq!(report.quote_report_data_matches, Some(true));
    assert!(report.runtime_data_matches_report);
    assert!(report.public_values_bound);
    assert!(report.mrtd_matches_token);
    assert!(report.tcb_status_allowed);
    assert!(report.require_success().is_err());
    assert!(!report.all_passed());
}

#[tokio::test]
async fn verify_with_policy_reports_azure_held_data_mismatch() {
    let fixture = verification_fixture("UpToDate");
    let claims = azure_claims(&fixture, [0x77; 64], fixture.runtime_hash, "UpToDate");
    let policy = default_policy(&fixture);
    let report = verify_fixture(fixture, claims, policy).await;

    assert!(report.jwt_signature_and_expiry_valid);
    assert_eq!(report.token_verification_error, None);
    assert!(!report.token_report_data_matches);
    assert_eq!(report.quote_report_data_matches, None);
    assert!(report.runtime_data_matches_report);
    assert!(report.public_values_bound);
    assert!(report.mrtd_matches_token);
    assert!(report.tcb_status_allowed);
    assert!(!report.all_passed());
}

#[tokio::test]
async fn verify_with_policy_reports_azure_user_data_hash_mismatch() {
    let fixture = verification_fixture("UpToDate");
    let claims = azure_claims(&fixture, fixture.runtime_data, [0x88; 64], "UpToDate");
    let policy = default_policy(&fixture);
    let report = verify_fixture(fixture, claims, policy).await;

    assert!(report.jwt_signature_and_expiry_valid);
    assert_eq!(report.token_verification_error, None);
    assert!(!report.token_report_data_matches);
    assert_eq!(report.quote_report_data_matches, None);
    assert!(report.runtime_data_matches_report);
    assert!(report.public_values_bound);
    assert!(report.mrtd_matches_token);
    assert!(report.tcb_status_allowed);
    assert!(!report.all_passed());
}

#[tokio::test]
async fn verify_with_policy_rejects_out_of_date_tcb_by_default() {
    let fixture = verification_fixture("OutOfDate");
    let claims = standard_claims(&fixture, fixture.runtime_hash, "OutOfDate");
    let policy = default_policy(&fixture);
    let report = verify_fixture(fixture, claims, policy).await;

    assert!(report.jwt_signature_and_expiry_valid);
    assert_eq!(report.token_verification_error, None);
    assert!(report.token_report_data_matches);
    assert_eq!(report.quote_report_data_matches, Some(true));
    assert!(report.tcb_status_matches_token);
    assert!(!report.tcb_status_allowed);
    assert_eq!(report.tcb_status, "OutOfDate");
    assert!(!report.all_passed());
}

#[tokio::test]
async fn verify_with_policy_can_allow_out_of_date_tcb() {
    let fixture = verification_fixture("OutOfDate");
    let claims = standard_claims(&fixture, fixture.runtime_hash, "OutOfDate");
    let mut policy = default_policy(&fixture);
    policy.accepted_tcb_statuses = vec!["OutOfDate".to_string()];
    let report = verify_fixture(fixture, claims, policy).await;

    assert!(report.jwt_signature_and_expiry_valid);
    assert_eq!(report.token_verification_error, None);
    assert!(report.token_report_data_matches);
    assert_eq!(report.quote_report_data_matches, Some(true));
    assert!(report.tcb_status_matches_token);
    assert!(report.tcb_status_allowed);
    assert!(report.all_passed());
}

#[tokio::test]
async fn verify_with_policy_accepts_any_configured_tcb_status_in_a_multi_entry_allowlist() {
    let fixture = verification_fixture("OutOfDate");
    let claims = standard_claims(&fixture, fixture.runtime_hash, "OutOfDate");
    let mut policy = default_policy(&fixture);
    policy.accepted_tcb_statuses = vec!["UpToDate".to_string(), "OutOfDate".to_string()];
    let report = verify_fixture(fixture, claims, policy).await;

    assert!(report.jwt_signature_and_expiry_valid);
    assert!(report.tcb_status_allowed);
    assert_eq!(report.tcb_status, "OutOfDate");
    assert!(report.all_passed());
}

#[tokio::test]
async fn verify_with_policy_can_allow_out_of_date_tcb_for_expected_advisory_set() {
    let mut fixture = verification_fixture("OutOfDate");
    fixture.attestation.advisory_ids = TEST_GCP_ADVISORY_IDS
        .iter()
        .map(|id| id.to_string())
        .collect();
    let mut claims = standard_claims(&fixture, fixture.runtime_hash, "OutOfDate");
    claims["tdx"]["attester_advisory_ids"] = json!(TEST_GCP_ADVISORY_IDS);
    let mut policy = default_policy(&fixture);
    policy.accepted_tcb_statuses = vec!["OutOfDate".to_string()];
    policy.expected_advisory_ids = Some(vec![
        "intel-sa-01073".to_string(),
        "INTEL-SA-00950".to_string(),
        "intel-sa-00828".to_string(),
        "INTEL-SA-01046".to_string(),
    ]);
    let report = verify_fixture(fixture, claims, policy).await;

    assert!(report.jwt_signature_and_expiry_valid);
    assert!(report.tcb_status_allowed);
    assert_eq!(
        report.advisory_ids,
        TEST_GCP_ADVISORY_IDS
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
    );
    assert_eq!(report.expected_advisory_ids_matches, Some(true));
    assert!(report.all_passed());
}

#[tokio::test]
async fn verify_with_policy_rejects_out_of_date_tcb_when_advisory_set_differs() {
    let mut fixture = verification_fixture("OutOfDate");
    fixture.attestation.advisory_ids = TEST_GCP_ADVISORY_IDS
        .iter()
        .map(|id| id.to_string())
        .collect();
    let mut claims = standard_claims(&fixture, fixture.runtime_hash, "OutOfDate");
    claims["tdx"]["attester_advisory_ids"] = json!(TEST_GCP_ADVISORY_IDS);
    let mut policy = default_policy(&fixture);
    policy.accepted_tcb_statuses = vec!["OutOfDate".to_string()];
    policy.expected_advisory_ids = Some(vec![
        "INTEL-SA-00828".to_string(),
        "INTEL-SA-00950".to_string(),
        "INTEL-SA-01046".to_string(),
    ]);
    let report = verify_fixture(fixture, claims, policy).await;

    assert!(report.jwt_signature_and_expiry_valid);
    assert!(report.advisory_ids_match_token);
    assert!(report.tcb_status_allowed);
    assert_eq!(report.expected_advisory_ids_matches, Some(false));
    assert!(!report.all_passed());
}

#[tokio::test]
async fn verify_with_policy_reports_expected_identity_mismatches() {
    let fixture = verification_fixture("UpToDate");
    let claims = standard_claims(&fixture, fixture.runtime_hash, "UpToDate");
    let mut policy = default_policy(&fixture);
    policy.expected_mrtd = Some("22".repeat(48));
    policy.expected_build_id = Some([0x24; 8]);
    policy.expected_nonce = Some(999);
    let report = verify_fixture(fixture, claims, policy).await;

    assert!(report.jwt_signature_and_expiry_valid);
    assert_eq!(report.token_verification_error, None);
    assert!(report.token_report_data_matches);
    assert_eq!(report.quote_report_data_matches, Some(true));
    assert_eq!(report.expected_mrtd_matches, Some(false));
    assert_eq!(report.expected_build_id_matches, Some(false));
    assert_eq!(report.expected_nonce_matches, Some(false));
    assert!(!report.all_passed());
}

#[tokio::test]
async fn verify_with_policy_leaves_expected_mrtd_unset_when_policy_does_not_pin_it() {
    let fixture = verification_fixture("UpToDate");
    let claims = standard_claims(&fixture, fixture.runtime_hash, "UpToDate");
    let mut policy = default_policy(&fixture);
    policy.expected_mrtd = None;
    let report = verify_fixture(fixture, claims, policy).await;

    assert!(report.jwt_signature_and_expiry_valid);
    assert_eq!(report.expected_mrtd_matches, None);
    assert!(report.all_passed());
}

#[tokio::test]
async fn verify_with_policy_reports_public_tcb_date_mismatch() {
    let mut fixture = verification_fixture("UpToDate");
    fixture.attestation.tcb_date = Some("2030-01-01T00:00:00Z".to_string());
    let claims = standard_claims(&fixture, fixture.runtime_hash, "UpToDate");
    let policy = default_policy(&fixture);
    let report = verify_fixture(fixture, claims, policy).await;

    assert!(report.jwt_signature_and_expiry_valid);
    assert!(!report.tcb_date_matches_token);
    assert!(!report.all_passed());
}

#[tokio::test]
async fn verify_with_policy_reports_public_advisory_id_mismatch() {
    let mut fixture = verification_fixture("UpToDate");
    fixture.attestation.advisory_ids = vec!["INTEL-SA-99999".to_string()];
    let claims = standard_claims(&fixture, fixture.runtime_hash, "UpToDate");
    let policy = default_policy(&fixture);
    let report = verify_fixture(fixture, claims, policy).await;

    assert!(report.jwt_signature_and_expiry_valid);
    assert!(!report.advisory_ids_match_token);
    assert!(!report.all_passed());
}

#[tokio::test]
async fn verify_with_policy_treats_malformed_signed_azure_claims_as_token_failure() {
    let fixture = verification_fixture("UpToDate");
    let claims = with_registered_claims(json!({
        "appraisal": { "method": "azure" },
        "tdx": {
            "tdx_mrtd": fixture.mrtd,
            "tdx_report_data": hex::encode([0xa5u8; 64]),
            "attester_tcb_status": "UpToDate",
            "attester_tcb_date": TEST_TCB_DATE,
            "attester_held_data": BASE64.encode([0u8; 63]),
            "attester_runtime_data": {
                "user-data": hex::encode(fixture.runtime_hash),
            }
        }
    }));
    let policy = default_policy(&fixture);
    let report = verify_fixture(fixture, claims, policy).await;

    assert!(!report.jwt_signature_and_expiry_valid);
    assert!(matches!(
        report.token_verification_error,
        Some(VerifyError::InvalidTokenClaims(_))
    ));
    assert!(!report.token_report_data_matches);
    assert_eq!(report.quote_report_data_matches, Some(true));
    assert!(!report.mrtd_matches_token);
    assert!(!report.tcb_status_matches_token);
    assert!(!report.tcb_date_matches_token);
    assert!(!report.tcb_status_allowed);
    assert!(report.runtime_data_matches_report);
    assert!(report.public_values_bound);
    assert_eq!(report.expected_mrtd_matches, Some(false));
    assert_eq!(report.expected_build_id_matches, Some(true));
    assert_eq!(report.expected_nonce_matches, Some(true));
    assert!(!report.all_passed());
}

#[tokio::test]
async fn verify_with_policy_reports_empty_raw_quote_without_full_pass() {
    let mut fixture = verification_fixture("UpToDate");
    fixture.attestation.raw_quote.clear();
    let claims = standard_claims(&fixture, fixture.runtime_hash, "UpToDate");
    let policy = default_policy(&fixture);
    let server = JwksServer::spawn().await;
    let mut policy = policy;
    policy.jwks_url = server.url.clone();
    fixture.attestation.ita_token = sign_token(claims);

    let err = fixture
        .attestation
        .verify_with_policy(&policy)
        .await
        .expect_err("empty raw quote should be rejected structurally");
    server.finish().await;

    assert!(
        matches!(err, VerifyError::InvalidAttestation(message) if message.contains("raw_quote"))
    );
}

#[tokio::test]
async fn verify_with_policy_reports_tampered_raw_quote_without_full_pass() {
    let mut fixture = verification_fixture("UpToDate");
    fixture.attestation.raw_quote = quote_with_report_data([0x77; 64]);
    let claims = standard_claims(&fixture, fixture.runtime_hash, "UpToDate");
    let policy = default_policy(&fixture);
    let report = verify_fixture(fixture, claims, policy).await;

    assert!(report.jwt_signature_and_expiry_valid);
    assert_eq!(report.token_verification_error, None);
    assert!(report.token_report_data_matches);
    assert_eq!(report.quote_report_data_matches, Some(false));
    assert!(report.runtime_data_matches_report);
    assert!(report.public_values_bound);
    assert!(report.require_success().is_err());
    assert!(!report.all_passed());
}

#[tokio::test]
async fn verify_with_policy_reports_empty_jwt_but_keeps_local_quote_checks() {
    let fixture = verification_fixture("UpToDate");
    let report = fixture
        .attestation
        .verify_with_policy(&default_policy(&fixture))
        .await
        .expect("verification should return a report");

    assert!(!report.jwt_signature_and_expiry_valid);
    assert!(matches!(
        report.token_verification_error,
        Some(VerifyError::InvalidToken(_))
    ));
    assert!(!report.token_report_data_matches);
    assert_eq!(report.quote_report_data_matches, Some(true));
    assert!(report.runtime_data_matches_report);
    assert!(report.public_values_bound);
    assert!(report.require_success().is_err());
    assert!(!report.all_passed());
}

#[tokio::test]
async fn verify_fresh_authenticates_stored_standard_evidence() {
    let fixture = verification_fixture("UpToDate");
    let claims = standard_claims(&fixture, fixture.runtime_hash, "UpToDate");
    let policy = default_policy(&fixture);
    let report = verify_fresh_fixture(fixture, claims, "/appraisal/v2/attest", policy).await;

    assert_eq!(report.quote_report_data_matches, Some(true));
    assert_eq!(report.bundled_evidence_authenticated, Some(true));
    assert!(report.all_passed());
}

#[tokio::test]
async fn verify_fresh_authenticates_stored_azure_evidence() {
    let mut fixture = verification_fixture("UpToDate");
    attach_azure_runtime_evidence(&mut fixture);
    let claims = azure_claims(
        &fixture,
        fixture.runtime_data,
        fixture.runtime_hash,
        "UpToDate",
    );
    let policy = default_policy(&fixture);
    let report = verify_fresh_fixture(fixture, claims, "/appraisal/v2/attest/azure", policy).await;

    assert_eq!(report.quote_report_data_matches, None);
    assert_eq!(report.bundled_evidence_authenticated, Some(true));
    assert!(report.all_passed());
}

#[tokio::test]
async fn verify_fresh_rejects_tampered_raw_quote_against_stored_azure_evidence() {
    let mut fixture = verification_fixture("UpToDate");
    attach_azure_runtime_evidence(&mut fixture);
    fixture.attestation.raw_quote = quote_with_report_data([0x44; 64]);

    let claims = azure_claims(
        &fixture,
        fixture.runtime_data,
        fixture.runtime_hash,
        "UpToDate",
    );
    let policy = default_policy(&fixture);
    let report = verify_fresh_fixture(fixture, claims, "/appraisal/v2/attest/azure", policy).await;

    assert_eq!(report.quote_report_data_matches, None);
    assert_eq!(report.bundled_evidence_authenticated, Some(false));
    assert!(!report.all_passed());
}

#[tokio::test]
async fn verify_with_policy_reports_expired_jwt() {
    let fixture = verification_fixture("UpToDate");
    let mut claims = standard_claims(&fixture, fixture.runtime_hash, "UpToDate");
    let now = now_unix_secs();
    let object = claims.as_object_mut().expect("claims object");
    object.insert("iat".to_string(), json!(now - 3600));
    object.insert("nbf".to_string(), json!(now - 3600));
    object.insert("exp".to_string(), json!(now - 3600));
    let policy = default_policy(&fixture);
    let report = verify_fixture(fixture, claims, policy).await;

    assert!(!report.jwt_signature_and_expiry_valid);
    assert!(matches!(
        report.token_verification_error,
        Some(VerifyError::InvalidToken(_))
    ));
    assert!(!report.token_report_data_matches);
    assert_eq!(report.quote_report_data_matches, Some(true));
    assert!(report.runtime_data_matches_report);
    assert!(report.public_values_bound);
    assert!(report.require_success().is_err());
}

#[tokio::test]
async fn verify_with_policy_reports_future_nbf_jwt() {
    let fixture = verification_fixture("UpToDate");
    let mut claims = standard_claims(&fixture, fixture.runtime_hash, "UpToDate");
    let now = now_unix_secs();
    let object = claims.as_object_mut().expect("claims object");
    object.insert("iat".to_string(), json!(now));
    object.insert("nbf".to_string(), json!(now + 3600));
    object.insert("exp".to_string(), json!(now + 7200));
    let policy = default_policy(&fixture);

    let report = verify_fixture(fixture, claims, policy).await;

    assert!(!report.jwt_signature_and_expiry_valid);
    assert!(matches!(
        report.token_verification_error,
        Some(VerifyError::InvalidToken(_))
    ));
    assert!(!report.token_report_data_matches);
    assert_eq!(report.quote_report_data_matches, Some(true));
    assert!(report.runtime_data_matches_report);
    assert!(report.public_values_bound);
    assert!(report.require_success().is_err());
}

#[tokio::test]
async fn verify_with_policy_reports_unknown_kid_jwt() {
    let mut fixture = verification_fixture("UpToDate");
    let claims = standard_claims(&fixture, fixture.runtime_hash, "UpToDate");
    let server = JwksServer::spawn().await;
    let mut policy = default_policy(&fixture);
    policy.jwks_url = server.url.clone();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("wrong-kid".to_string());
    fixture.attestation.ita_token = sign_token_with_header(claims, header);

    let report = fixture
        .attestation
        .verify_with_policy(&policy)
        .await
        .expect("verification should return a report");
    server.finish().await;

    assert!(!report.jwt_signature_and_expiry_valid);
    assert!(matches!(
        report.token_verification_error,
        Some(VerifyError::InvalidToken(_))
    ));
    assert!(!report.token_report_data_matches);
    assert_eq!(report.quote_report_data_matches, Some(true));
    assert!(report.runtime_data_matches_report);
    assert!(report.public_values_bound);
    assert!(report.require_success().is_err());
}

#[tokio::test]
async fn verify_with_policy_reports_unsupported_algorithm_jwt() {
    let mut fixture = verification_fixture("UpToDate");
    let claims = standard_claims(&fixture, fixture.runtime_hash, "UpToDate");
    let mut policy = default_policy(&fixture);
    policy.jwks_url = "http://127.0.0.1:1/jwks.json".to_string();
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(TEST_JWK_KID.to_string());
    fixture.attestation.ita_token = jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_secret(b"not-an-ita-rsa-key"),
    )
    .expect("sign HS256 JWT");

    let report = fixture
        .attestation
        .verify_with_policy(&policy)
        .await
        .expect("verification should return a report");

    assert!(!report.jwt_signature_and_expiry_valid);
    assert!(matches!(
        report.token_verification_error,
        Some(VerifyError::InvalidToken(_))
    ));
    assert!(!report.token_report_data_matches);
    assert_eq!(report.quote_report_data_matches, Some(true));
    assert!(report.runtime_data_matches_report);
    assert!(report.public_values_bound);
    assert!(report.require_success().is_err());
}

#[tokio::test]
async fn verify_with_policy_accepts_trimmed_jwt() {
    let mut fixture = verification_fixture("UpToDate");
    let claims = standard_claims(&fixture, fixture.runtime_hash, "UpToDate");
    let server = JwksServer::spawn().await;
    let mut policy = default_policy(&fixture);
    policy.jwks_url = server.url.clone();
    fixture.attestation.ita_token = format!("  {} \n", sign_token(claims));

    let report = fixture
        .attestation
        .verify_with_policy(&policy)
        .await
        .expect("verification should return a report");
    server.finish().await;

    assert!(report.jwt_signature_and_expiry_valid);
    assert_eq!(report.token_verification_error, None);
    assert!(report.all_passed());
}

#[test]
fn unauthenticated_report_data_hash_from_token_accepts_trimmed_input() {
    let claims = serde_json::json!({
        "tdx": {
            "tdx_report_data": hex::encode([0xabu8; 64]),
        }
    });
    let token = format!("  {} \n", sign_token(with_registered_claims(claims)));

    let hash = unauthenticated_report_data_hash_from_token(&token)
        .expect("trimmed JWT should decode")
        .expect("claim should be present");

    assert_eq!(hash, [0xabu8; 64]);
}

#[tokio::test]
async fn verify_fresh_rejects_missing_azure_runtime_json_as_invalid_stored_evidence() {
    let mut fixture = verification_fixture("UpToDate");
    let claims = azure_claims(
        &fixture,
        fixture.runtime_data,
        fixture.runtime_hash,
        "UpToDate",
    );
    let stored_token = sign_token(claims);
    let jwks = JwksServer::spawn().await;
    let mut policy = default_policy(&fixture);
    policy.jwks_url = jwks.url.clone();
    fixture.attestation.ita_token = stored_token;
    fixture.attestation.evidence = fixture.attestation.raw_quote.clone();

    let err = fixture
        .attestation
        .verify_fresh_with_policy(&verify_config("http://127.0.0.1:1".to_string()), &policy)
        .await
        .expect_err("missing Azure runtime JSON should be a hard error");
    jwks.finish().await;

    assert!(matches!(err, VerifyError::InvalidStoredEvidence(_)));
}
