// SPDX-License-Identifier: MIT

#![cfg(feature = "confidential-space")]

mod support;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use livy_tee::{
    ConfidentialSpace, ConfidentialSpaceAttestation, ConfidentialSpaceAttesterMode,
    ConfidentialSpaceConfig, ConfidentialSpaceError, ConfidentialSpaceTokens,
    ConfidentialSpaceVerification, ConfidentialSpaceVerificationPolicy, PublicValues,
    CONFIDENTIAL_SPACE_ATTESTATION_SCHEMA_VERSION, CONFIDENTIAL_SPACE_GOOGLE_ISSUER,
    CONFIDENTIAL_SPACE_INTEL_ISSUER,
};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use support::{TEST_JWK_E, TEST_JWK_KID, TEST_JWK_N, TEST_RSA_PRIVATE_KEY_PEM};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::task::JoinHandle;

const AUDIENCE: &str = "https://relying-party.example.test";
const IMAGE_DIGEST: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn public_values() -> PublicValues {
    let mut values = PublicValues::new();
    values.commit(&"input").unwrap();
    values.commit(&"output").unwrap();
    values
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
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
        &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn valid_claims(issuer: &str, commitment: [u8; 32]) -> Value {
    let now = now_unix_secs();
    json!({
        "iss": issuer,
        "aud": AUDIENCE,
        "iat": now - 60,
        "nbf": now - 60,
        "exp": now + 3600,
        "eat_nonce": [BASE64URL.encode(commitment)],
        "dbgstat": "disabled-since-boot",
        "hwmodel": "GCP_INTEL_TDX",
        "secboot": true,
        "sub": "https://www.googleapis.com/compute/v1/projects/p/zones/z/instances/i",
        "swname": "CONFIDENTIAL_SPACE",
        "swversion": ["260700"],
        "submods": {
            "confidential_space": {
                "support_attributes": ["LATEST", "STABLE", "USABLE"],
                "monitoring_enabled": { "memory": false }
            },
            "container": {
                "args": ["/app"],
                "env": {"PATH":"/usr/bin", "HOSTNAME":"workload"},
                "image_digest": IMAGE_DIGEST,
                "image_id": IMAGE_DIGEST,
                "image_reference": "registry.example/app@sha256:0123",
                "image_signatures": [],
                "restart_policy": "Never"
            },
            "gce": {
                "instance_id": "123",
                "instance_name": "workload",
                "project_id": "project",
                "project_number": "456",
                "zone": "europe-west4-a"
            }
        }
    })
}

fn artifact(tokens: ConfidentialSpaceTokens) -> ConfidentialSpaceAttestation {
    ConfidentialSpaceAttestation {
        schema_version: CONFIDENTIAL_SPACE_ATTESTATION_SCHEMA_VERSION,
        tokens,
        public_values: public_values(),
    }
}

struct JwksServer {
    url: String,
    task: JoinHandle<()>,
}

impl JwksServer {
    async fn spawn(requests: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
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
            for _ in 0..requests {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        Self {
            url: format!("http://{addr}/jwks"),
            task,
        }
    }

    async fn finish(self) {
        self.task.await.unwrap();
    }
}

fn policy(jwks_url: &str) -> ConfidentialSpaceVerificationPolicy {
    let mut policy = ConfidentialSpaceVerificationPolicy::new(AUDIENCE, IMAGE_DIGEST);
    policy.request_timeout_secs = 5;
    policy.google_jwks_url = Some(jwks_url.to_string());
    policy.intel_jwks_url = Some(jwks_url.to_string());
    policy
}

async fn verify_google_claims(claims: Value) -> ConfidentialSpaceVerification {
    let server = JwksServer::spawn(1).await;
    let attestation = artifact(ConfidentialSpaceTokens::Google {
        token: sign_token(claims),
    });
    let report = attestation.verify(&policy(&server.url)).await.unwrap();
    server.finish().await;
    report
}

#[cfg(unix)]
struct LauncherServer {
    socket_path: PathBuf,
    task: JoinHandle<Vec<(String, Value)>>,
}

#[cfg(unix)]
impl LauncherServer {
    async fn spawn(responses: Vec<(u16, String, u64)>) -> Self {
        let short_id = uuid::Uuid::new_v4().simple().to_string();
        let socket_path = PathBuf::from(format!(
            "/tmp/livy-cs-{}-{}.sock",
            std::process::id(),
            &short_id[..8]
        ));
        let listener = UnixListener::bind(&socket_path).unwrap();
        let task = tokio::spawn(async move {
            let mut observed = Vec::new();
            for (status, body, delay_ms) in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_http_request(&mut stream).await;
                let (path, json) = parse_request(&request);
                observed.push((path, json));
                if delay_ms > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                }
                let reason = if status == 200 { "OK" } else { "ERROR" };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
            observed
        });
        Self { socket_path, task }
    }

    async fn finish(self) -> Vec<(String, Value)> {
        let observed = self.task.await.unwrap();
        let _ = std::fs::remove_file(&self.socket_path);
        observed
    }
}

#[cfg(unix)]
async fn read_http_request(stream: &mut tokio::net::UnixStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let size = stream.read(&mut chunk).await.unwrap();
        if size == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..size]);
        let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let header_end = header_end + 4;
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        if request.len() >= header_end + content_length {
            break;
        }
    }
    request
}

#[cfg(unix)]
fn parse_request(request: &[u8]) -> (String, Value) {
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let path = headers
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_string();
    let body = serde_json::from_slice(&request[header_end..]).unwrap();
    (path, body)
}

#[cfg(unix)]
fn launcher_client(socket_path: PathBuf, mode: ConfidentialSpaceAttesterMode) -> ConfidentialSpace {
    let mut config = ConfidentialSpaceConfig::new(AUDIENCE, mode);
    config.launcher_socket = socket_path;
    config.request_timeout_secs = 1;
    ConfidentialSpace::new(config)
}

#[cfg(unix)]
#[tokio::test]
async fn launcher_google_request_uses_expected_path_and_body() {
    let server = LauncherServer::spawn(vec![(200, json!({"token":"a.b.c"}).to_string(), 0)]).await;
    let client = launcher_client(
        server.socket_path.clone(),
        ConfidentialSpaceAttesterMode::Google,
    );
    let values = public_values();
    let attestation = client.attest(&values).await.unwrap();
    assert!(matches!(
        attestation.tokens,
        ConfidentialSpaceTokens::Google { ref token } if token == "a.b.c"
    ));

    let requests = server.finish().await;
    assert_eq!(requests[0].0, "/v1/token");
    assert_eq!(requests[0].1["audience"], AUDIENCE);
    assert_eq!(requests[0].1["token_type"], "OIDC");
    assert_eq!(
        requests[0].1["nonces"],
        json!([BASE64URL.encode(values.commitment_hash())])
    );
}

#[cfg(unix)]
#[tokio::test]
async fn launcher_intel_accepts_a_raw_token_response() {
    let server = LauncherServer::spawn(vec![(200, "a.b.c".to_string(), 0)]).await;
    let client = launcher_client(
        server.socket_path.clone(),
        ConfidentialSpaceAttesterMode::Intel,
    );
    let tokens = client
        .request_tokens(&public_values().commitment_hash())
        .await
        .unwrap();
    assert!(matches!(
        tokens,
        ConfidentialSpaceTokens::Intel { ref token } if token == "a.b.c"
    ));
    let requests = server.finish().await;
    assert_eq!(requests[0].0, "/v1/intel/token");
}

#[cfg(unix)]
#[tokio::test]
async fn launcher_dual_requires_both_successful_tokens() {
    let server = LauncherServer::spawn(vec![
        (200, json!({"token":"google.token.sig"}).to_string(), 0),
        (200, json!("intel.token.sig").to_string(), 0),
    ])
    .await;
    let client = launcher_client(
        server.socket_path.clone(),
        ConfidentialSpaceAttesterMode::Dual,
    );
    let tokens = client
        .request_tokens(&public_values().commitment_hash())
        .await
        .unwrap();
    assert!(matches!(
        tokens,
        ConfidentialSpaceTokens::Dual { ref google, ref intel }
            if google == "google.token.sig" && intel == "intel.token.sig"
    ));
    let requests = server.finish().await;
    assert_eq!(requests[0].0, "/v1/token");
    assert_eq!(requests[1].0, "/v1/intel/token");
}

#[cfg(unix)]
#[tokio::test]
async fn launcher_status_missing_token_and_timeout_are_errors() {
    let status_server = LauncherServer::spawn(vec![(503, "unavailable".to_string(), 0)]).await;
    let status_client = launcher_client(
        status_server.socket_path.clone(),
        ConfidentialSpaceAttesterMode::Google,
    );
    let error = status_client.request_tokens(&[0u8; 32]).await.unwrap_err();
    assert!(matches!(
        error,
        ConfidentialSpaceError::LauncherStatus { status: 503, .. }
    ));
    status_server.finish().await;

    let missing_server =
        LauncherServer::spawn(vec![(200, json!({"not_token":"x"}).to_string(), 0)]).await;
    let missing_client = launcher_client(
        missing_server.socket_path.clone(),
        ConfidentialSpaceAttesterMode::Google,
    );
    assert!(matches!(
        missing_client.request_tokens(&[0u8; 32]).await,
        Err(ConfidentialSpaceError::LauncherResponse { .. })
    ));
    missing_server.finish().await;

    let timeout_server =
        LauncherServer::spawn(vec![(200, json!({"token":"a.b.c"}).to_string(), 1_500)]).await;
    let timeout_client = launcher_client(
        timeout_server.socket_path.clone(),
        ConfidentialSpaceAttesterMode::Google,
    );
    assert!(matches!(
        timeout_client.request_tokens(&[0u8; 32]).await,
        Err(ConfidentialSpaceError::Launcher(_))
    ));
    timeout_server.finish().await;
}

#[tokio::test]
async fn launcher_rejects_empty_or_oversized_audience_before_connecting() {
    for audience in ["".to_string(), "x".repeat(513)] {
        let config = ConfidentialSpaceConfig::new(audience, ConfidentialSpaceAttesterMode::Google);
        let client = ConfidentialSpace::new(config);
        assert!(matches!(
            client.request_tokens(&[0u8; 32]).await,
            Err(ConfidentialSpaceError::InvalidConfiguration(_))
        ));
    }
}

#[tokio::test]
async fn valid_google_intel_and_dual_tokens_pass_strict_verification() {
    for mode in [
        ConfidentialSpaceAttesterMode::Google,
        ConfidentialSpaceAttesterMode::Intel,
        ConfidentialSpaceAttesterMode::Dual,
    ] {
        let values = public_values();
        let google = sign_token(valid_claims(
            CONFIDENTIAL_SPACE_GOOGLE_ISSUER,
            values.commitment_hash(),
        ));
        let intel = sign_token(valid_claims(
            CONFIDENTIAL_SPACE_INTEL_ISSUER,
            values.commitment_hash(),
        ));
        let tokens = match mode {
            ConfidentialSpaceAttesterMode::Google => {
                ConfidentialSpaceTokens::Google { token: google }
            }
            ConfidentialSpaceAttesterMode::Intel => ConfidentialSpaceTokens::Intel { token: intel },
            ConfidentialSpaceAttesterMode::Dual => ConfidentialSpaceTokens::Dual { google, intel },
        };
        let attestation = ConfidentialSpaceAttestation {
            schema_version: 2,
            tokens,
            public_values: values,
        };
        let requests = if mode == ConfidentialSpaceAttesterMode::Dual {
            2
        } else {
            1
        };
        let server = JwksServer::spawn(requests).await;
        let report = attestation.verify(&policy(&server.url)).await.unwrap();
        assert!(report.all_passed(), "{mode:?}: {report:#?}");
        assert_eq!(
            report.dual_claims_match,
            (mode == ConfidentialSpaceAttesterMode::Dual).then_some(true)
        );
        server.finish().await;
    }
}

#[tokio::test]
async fn wrong_commitment_audience_issuer_or_image_is_rejected() {
    enum Mutation {
        Nonce,
        NonceCardinality,
        Audience,
        Issuer,
        Image,
    }
    for mutation in [
        Mutation::Nonce,
        Mutation::NonceCardinality,
        Mutation::Audience,
        Mutation::Issuer,
        Mutation::Image,
    ] {
        let values = public_values();
        let mut claims = valid_claims(CONFIDENTIAL_SPACE_GOOGLE_ISSUER, values.commitment_hash());
        let object = claims.as_object_mut().unwrap();
        match mutation {
            Mutation::Nonce => {
                object.insert(
                    "eat_nonce".to_string(),
                    json!([BASE64URL.encode([9u8; 32])]),
                );
            }
            Mutation::NonceCardinality => {
                object.insert(
                    "eat_nonce".to_string(),
                    json!([
                        BASE64URL.encode(values.commitment_hash()),
                        BASE64URL.encode([9u8; 32])
                    ]),
                );
            }
            Mutation::Audience => {
                object.insert("aud".to_string(), json!("https://wrong.example"));
            }
            Mutation::Issuer => {
                object.insert("iss".to_string(), json!(CONFIDENTIAL_SPACE_INTEL_ISSUER));
            }
            Mutation::Image => {
                object
                    .get_mut("submods")
                    .unwrap()
                    .get_mut("container")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert(
                        "image_digest".to_string(),
                        json!("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                    );
            }
        }
        let report = verify_google_claims(claims).await;
        assert!(!report.all_passed(), "{report:#?}");
    }
}

#[tokio::test]
async fn signature_algorithm_key_and_time_failures_are_rejected() {
    let values = public_values();
    let claims = valid_claims(CONFIDENTIAL_SPACE_GOOGLE_ISSUER, values.commitment_hash());

    let mut unknown_header = Header::new(Algorithm::RS256);
    unknown_header.kid = Some("unknown-key".to_string());
    let unknown_key = sign_token_with_header(claims.clone(), unknown_header);
    let server = JwksServer::spawn(1).await;
    let report = artifact(ConfidentialSpaceTokens::Google { token: unknown_key })
        .verify(&policy(&server.url))
        .await
        .unwrap();
    assert!(!report.all_passed());
    server.finish().await;

    let valid_signature = sign_token(claims.clone());
    let mut parts: Vec<_> = valid_signature.split('.').map(str::to_string).collect();
    let replacement = if parts[2].starts_with('A') { "B" } else { "A" };
    parts[2].replace_range(..1, replacement);
    let invalid_signature = parts.join(".");
    let server = JwksServer::spawn(1).await;
    let report = artifact(ConfidentialSpaceTokens::Google {
        token: invalid_signature,
    })
    .verify(&policy(&server.url))
    .await
    .unwrap();
    assert!(!report.all_passed());
    assert!(!report.google.unwrap().jwt_signature_and_time_valid);
    server.finish().await;

    let unsupported = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(b"secret"),
    )
    .unwrap();
    let report = artifact(ConfidentialSpaceTokens::Google { token: unsupported })
        .verify(&policy("http://127.0.0.1:9/jwks"))
        .await
        .unwrap();
    assert!(!report.all_passed());

    for claim in ["exp", "nbf"] {
        let mut expired = claims.clone();
        expired.as_object_mut().unwrap().insert(
            claim.to_string(),
            if claim == "exp" {
                json!(now_unix_secs() - 120)
            } else {
                json!(now_unix_secs() + 3600)
            },
        );
        let report = verify_google_claims(expired).await;
        assert!(!report.all_passed());
        assert!(!report.google.unwrap().jwt_signature_and_time_valid);
    }
}

#[tokio::test]
async fn posture_and_override_failures_are_individually_rejected() {
    enum Mutation {
        Debug,
        Hardware,
        Stable,
        Monitoring,
        Command,
        EnvironmentOverride,
        SecureBoot,
        Software,
    }
    for mutation in [
        Mutation::Debug,
        Mutation::Hardware,
        Mutation::Stable,
        Mutation::Monitoring,
        Mutation::Command,
        Mutation::EnvironmentOverride,
        Mutation::SecureBoot,
        Mutation::Software,
    ] {
        let values = public_values();
        let mut claims = valid_claims(CONFIDENTIAL_SPACE_GOOGLE_ISSUER, values.commitment_hash());
        match mutation {
            Mutation::Debug => claims["dbgstat"] = json!("enabled"),
            Mutation::Hardware => claims["hwmodel"] = json!("GCP_AMD_SEV"),
            Mutation::Stable => {
                claims["submods"]["confidential_space"]["support_attributes"] =
                    json!(["LATEST", "USABLE"]);
            }
            Mutation::Monitoring => {
                claims["submods"]["confidential_space"]["monitoring_enabled"]["memory"] =
                    json!(true);
            }
            Mutation::Command => {
                claims["submods"]["container"]["cmd_override"] = json!(["--unsafe"]);
            }
            Mutation::EnvironmentOverride => {
                claims["submods"]["container"]["env_override"] = json!({"MODE":"unsafe"});
            }
            Mutation::SecureBoot => claims["secboot"] = json!(false),
            Mutation::Software => claims["swname"] = json!("GCE"),
        }
        let report = verify_google_claims(claims).await;
        assert!(!report.all_passed(), "{report:#?}");
    }
}

#[tokio::test]
async fn dual_mode_rejects_missing_or_disagreeing_tokens() {
    let values = public_values();
    let google_claims = valid_claims(CONFIDENTIAL_SPACE_GOOGLE_ISSUER, values.commitment_hash());
    let intel_claims = valid_claims(CONFIDENTIAL_SPACE_INTEL_ISSUER, values.commitment_hash());

    let missing = ConfidentialSpaceAttestation {
        schema_version: 2,
        tokens: ConfidentialSpaceTokens::Dual {
            google: sign_token(google_claims.clone()),
            intel: String::new(),
        },
        public_values: values.clone(),
    };
    let server = JwksServer::spawn(1).await;
    let report = missing.verify(&policy(&server.url)).await.unwrap();
    assert!(!report.all_passed());
    assert_eq!(report.dual_claims_match, Some(false));
    server.finish().await;

    let mut disagreeing = intel_claims;
    disagreeing["submods"]["container"]["args"] = json!(["/different-app"]);
    let dual = ConfidentialSpaceAttestation {
        schema_version: 2,
        tokens: ConfidentialSpaceTokens::Dual {
            google: sign_token(google_claims),
            intel: sign_token(disagreeing),
        },
        public_values: values,
    };
    let server = JwksServer::spawn(2).await;
    let report = dual.verify(&policy(&server.url)).await.unwrap();
    assert!(report.google.as_ref().unwrap().all_passed());
    assert!(report.intel.as_ref().unwrap().all_passed());
    assert_eq!(report.dual_claims_match, Some(false));
    assert!(!report.all_passed());
    server.finish().await;
}

#[tokio::test]
async fn dual_mode_compares_the_complete_image_environment() {
    let values = public_values();
    let google_claims = valid_claims(CONFIDENTIAL_SPACE_GOOGLE_ISSUER, values.commitment_hash());
    let mut intel_claims = valid_claims(CONFIDENTIAL_SPACE_INTEL_ISSUER, values.commitment_hash());
    intel_claims["submods"]["container"]["env"]["PATH"] = json!("/different");

    let dual = ConfidentialSpaceAttestation {
        schema_version: 2,
        tokens: ConfidentialSpaceTokens::Dual {
            google: sign_token(google_claims),
            intel: sign_token(intel_claims),
        },
        public_values: values,
    };
    let server = JwksServer::spawn(2).await;
    let report = dual.verify(&policy(&server.url)).await.unwrap();
    assert!(report.google.as_ref().unwrap().all_passed());
    assert!(report.intel.as_ref().unwrap().all_passed());
    assert_eq!(report.dual_claims_match, Some(false));
    assert!(!report.all_passed());
    server.finish().await;
}

#[test]
fn confidential_space_artifact_schema_v2_roundtrips_and_v1_is_rejected() {
    let artifact = artifact(ConfidentialSpaceTokens::Google {
        token: "a.b.c".to_string(),
    });
    let encoded = serde_json::to_value(&artifact).unwrap();
    let decoded: ConfidentialSpaceAttestation = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(decoded.schema_version, 2);
    assert_eq!(decoded.commitment_hash(), artifact.commitment_hash());

    let mut legacy = encoded;
    legacy["schema_version"] = json!(1);
    let error = serde_json::from_value::<ConfidentialSpaceAttestation>(legacy)
        .unwrap_err()
        .to_string();
    assert!(error.contains("only version 2 is supported"));
}

#[tokio::test]
async fn invalid_policy_inputs_are_rejected() {
    let attestation = artifact(ConfidentialSpaceTokens::Google {
        token: "a.b.c".to_string(),
    });
    for policy in [
        ConfidentialSpaceVerificationPolicy::new("", IMAGE_DIGEST),
        ConfidentialSpaceVerificationPolicy::new(AUDIENCE, "not-a-digest"),
    ] {
        assert!(matches!(
            attestation.verify(&policy).await,
            Err(ConfidentialSpaceError::InvalidConfiguration(_))
        ));
    }
}
