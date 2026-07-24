// SPDX-License-Identifier: MIT
//! Shared OIDC discovery, JWKS retrieval, and JWT signature/time validation.

use jsonwebtoken::Algorithm;
use serde::de::DeserializeOwned;
#[cfg(feature = "confidential-space")]
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum OidcError {
    #[error("network error: {0}")]
    Network(String),
    #[error("{endpoint} returned HTTP {status}: {body}")]
    Http {
        endpoint: &'static str,
        status: reqwest::StatusCode,
        body: String,
    },
    #[cfg(feature = "confidential-space")]
    #[error("invalid OIDC discovery document: {0}")]
    Discovery(String),
    #[error("invalid token: {0}")]
    Token(String),
}

#[cfg(feature = "confidential-space")]
#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

pub(crate) fn http_client(request_timeout_secs: u64) -> Result<reqwest::Client, OidcError> {
    static CLIENTS: OnceLock<Mutex<HashMap<u64, reqwest::Client>>> = OnceLock::new();

    let clients = CLIENTS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut clients = match clients.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(client) = clients.get(&request_timeout_secs).cloned() {
        return Ok(client);
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(request_timeout_secs))
        .build()
        .map_err(|error| OidcError::Network(error.to_string()))?;
    clients.insert(request_timeout_secs, client.clone());
    Ok(client)
}

#[cfg(feature = "confidential-space")]
pub(crate) async fn discover_jwks_url(
    discovery_url: &str,
    expected_issuer: &str,
    request_timeout_secs: u64,
) -> Result<String, OidcError> {
    let client = http_client(request_timeout_secs)?;
    let response = client
        .get(discovery_url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|error| OidcError::Network(error.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| OidcError::Network(error.to_string()))?;
    if !status.is_success() {
        return Err(OidcError::Http {
            endpoint: "OIDC discovery endpoint",
            status,
            body,
        });
    }

    let discovery: DiscoveryDocument = serde_json::from_str(&body)
        .map_err(|error| OidcError::Discovery(format!("JSON: {error}")))?;
    if discovery.issuer.trim() != expected_issuer {
        return Err(OidcError::Discovery(format!(
            "issuer mismatch: expected {expected_issuer}, got {}",
            discovery.issuer
        )));
    }
    let jwks_url = reqwest::Url::parse(discovery.jwks_uri.trim())
        .map_err(|error| OidcError::Discovery(format!("jwks_uri URL: {error}")))?;
    if jwks_url.scheme() != "https" {
        return Err(OidcError::Discovery("jwks_uri must use HTTPS".to_string()));
    }
    Ok(jwks_url.to_string())
}

pub(crate) async fn verify_jwt_with_jwks<T>(
    jwt: &str,
    jwks_url: &str,
    request_timeout_secs: u64,
    accepted_algorithms: &[Algorithm],
) -> Result<T, OidcError>
where
    T: DeserializeOwned,
{
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};

    let jwt = jwt.trim();
    if jwt.is_empty() {
        return Err(OidcError::Token("JWT is empty".to_string()));
    }

    let header =
        decode_header(jwt).map_err(|error| OidcError::Token(format!("JWT header: {error}")))?;
    if !accepted_algorithms.contains(&header.alg) {
        return Err(OidcError::Token(format!(
            "unsupported signing algorithm: {:?}",
            header.alg
        )));
    }
    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| OidcError::Token("JWT header missing kid".to_string()))?;

    let client = http_client(request_timeout_secs)?;
    let response = client
        .get(jwks_url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|error| OidcError::Network(error.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| OidcError::Network(error.to_string()))?;
    if !status.is_success() {
        return Err(OidcError::Http {
            endpoint: "JWKS endpoint",
            status,
            body,
        });
    }

    let jwks: JwkSet = serde_json::from_str(&body)
        .map_err(|error| OidcError::Token(format!("JWKS JSON: {error}")))?;
    let jwk = jwks
        .keys
        .iter()
        .find(|jwk| jwk.common.key_id.as_deref() == Some(kid))
        .ok_or_else(|| OidcError::Token(format!("JWKS has no key for kid {kid}")))?;
    let key = DecodingKey::from_jwk(jwk)
        .map_err(|error| OidcError::Token(format!("JWKS key for kid {kid}: {error}")))?;

    let mut validation = Validation::new(header.alg);
    validation.algorithms = accepted_algorithms.to_vec();
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.validate_aud = false;
    validation.required_spec_claims.insert("nbf".to_string());

    decode::<T>(jwt, &key, &validation)
        .map(|token| token.claims)
        .map_err(|error| OidcError::Token(format!("JWT validation: {error}")))
}
