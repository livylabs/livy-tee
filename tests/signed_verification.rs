// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Deterministic signed-token verification tests.
//!
//! Run with: cargo test --test signed_verification --features ita-verify
#![cfg(feature = "ita-verify")]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use livy_tee::{
    Attestation, AttestationVerification, AttestationVerificationPolicy, PublicValues, ReportData,
    REPORT_DATA_VERSION,
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

fn sample_mrtd() -> String {
    "11".repeat(48)
}

fn now_unix_secs() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time should be after unix epoch")
        .as_secs() as usize
}

fn runtime_hash(nonce_val: &[u8], nonce_iat: &[u8], runtime_data: &[u8; 64]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(nonce_val);
    h.update(nonce_iat);
    h.update(runtime_data);
    h.finalize().into()
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
    let mrtd = sample_mrtd();

    VerificationFixture {
        runtime_hash: runtime_hash(&nonce_val, &nonce_iat, &runtime_data),
        runtime_data,
        mrtd: mrtd.clone(),
        attestation: Attestation {
            ita_token: String::new(),
            mrtd,
            tcb_status: tcb_status.to_string(),
            tcb_date: Some(TEST_TCB_DATE.to_string()),
            raw_quote: String::new(),
            runtime_data: BASE64.encode(runtime_data),
            verifier_nonce_val: BASE64.encode(nonce_val),
            verifier_nonce_iat: BASE64.encode(nonce_iat),
            report_data,
            public_values,
        },
    }
}

fn sign_token(claims: Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_JWK_KID.to_string());
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
            "attester_held_data": BASE64.encode(held_data),
            "attester_runtime_data": {
                "user-data": hex::encode(user_data_hash),
            }
        }
    }))
}

fn default_policy(fixture: &VerificationFixture) -> AttestationVerificationPolicy {
    AttestationVerificationPolicy {
        jwks_url: String::new(),
        request_timeout_secs: 5,
        accepted_tcb_statuses: vec!["UpToDate".to_string()],
        expected_mrtd: Some(fixture.mrtd.clone()),
        expected_build_id: Some(fixture.attestation.report_data.build_id),
        expected_nonce: Some(fixture.attestation.report_data.nonce),
    }
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

#[tokio::test]
async fn verify_with_policy_accepts_signed_standard_token() {
    let fixture = verification_fixture("UpToDate");
    let claims = standard_claims(&fixture, fixture.runtime_hash, "UpToDate");
    let policy = default_policy(&fixture);
    let report = verify_fixture(fixture, claims, policy).await;

    assert!(report.jwt_signature_and_expiry_valid);
    assert!(report.token_report_data_matches);
    assert!(report.runtime_data_matches_report);
    assert!(report.public_values_bound);
    assert!(report.mrtd_matches_token);
    assert!(report.tcb_status_matches_token);
    assert!(report.tcb_date_matches_token);
    assert!(report.tcb_status_allowed);
    assert_eq!(report.expected_mrtd_matches, Some(true));
    assert_eq!(report.expected_build_id_matches, Some(true));
    assert_eq!(report.expected_nonce_matches, Some(true));
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
    assert!(report.token_report_data_matches);
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
    assert!(!report.token_report_data_matches);
    assert!(report.runtime_data_matches_report);
    assert!(report.public_values_bound);
    assert!(report.mrtd_matches_token);
    assert!(report.tcb_status_allowed);
    assert!(!report.all_passed());
}

#[tokio::test]
async fn verify_with_policy_reports_azure_held_data_mismatch() {
    let fixture = verification_fixture("UpToDate");
    let claims = azure_claims(&fixture, [0x77; 64], fixture.runtime_hash, "UpToDate");
    let policy = default_policy(&fixture);
    let report = verify_fixture(fixture, claims, policy).await;

    assert!(report.jwt_signature_and_expiry_valid);
    assert!(!report.token_report_data_matches);
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
    assert!(!report.token_report_data_matches);
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
    assert!(report.token_report_data_matches);
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
    assert!(report.token_report_data_matches);
    assert!(report.tcb_status_matches_token);
    assert!(report.tcb_status_allowed);
    assert!(report.all_passed());
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
    assert!(report.token_report_data_matches);
    assert_eq!(report.expected_mrtd_matches, Some(false));
    assert_eq!(report.expected_build_id_matches, Some(false));
    assert_eq!(report.expected_nonce_matches, Some(false));
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
    assert!(!report.token_report_data_matches);
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
