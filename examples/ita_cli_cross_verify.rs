// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Generate an attestation with livy-tee and verify its ITA token with
//! Intel Trust Authority CLI.
//!
//! Run on a TDX VM:
//!   ITA_CLI_CONFIG_PATH=/home/livy/config.json cargo run --release \
//!     --no-default-features --features ita-verify --example ita_cli_cross_verify

use std::{
    error::Error,
    io::Write,
    path::PathBuf,
    process::{self, Command},
};

use base64::{
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL},
    Engine,
};
use serde_json::Value;

fn read_config_json() -> Result<String, Box<dyn Error>> {
    if let Ok(config_json) = std::env::var("ITA_CLI_CONFIG_JSON") {
        return Ok(config_json);
    }

    let path = std::env::var("ITA_CLI_CONFIG_PATH")
        .unwrap_or_else(|_| "/home/livy/config.json".to_string());
    Ok(std::fs::read_to_string(path)?)
}

fn api_key_from_config(config_json: &str) -> Result<String, Box<dyn Error>> {
    if let Ok(api_key) = std::env::var("ITA_API_KEY") {
        if !api_key.is_empty() {
            return Ok(api_key);
        }
    }

    let config: serde_json::Value = serde_json::from_str(config_json)?;
    config
        .get("trustauthority_api_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "trustauthority_api_key is missing from ITA CLI config".into())
}

fn cli_config_path(config_json: &str) -> Result<PathBuf, Box<dyn Error>> {
    let mut config: Value = serde_json::from_str(config_json)?;

    if config.get("trustauthority_url").is_none() {
        let api_url = config
            .get("trustauthority_api_url")
            .and_then(|v| v.as_str())
            .unwrap_or("https://api.trustauthority.intel.com");
        let trustauthority_url = if api_url.contains(".eu.") {
            "https://portal.eu.trustauthority.intel.com"
        } else {
            "https://portal.trustauthority.intel.com"
        };

        config
            .as_object_mut()
            .ok_or("ITA CLI config must be a JSON object")?
            .insert(
                "trustauthority_url".to_string(),
                Value::String(trustauthority_url.to_string()),
            );
    }

    let path = std::env::temp_dir().join(format!("livy-tee-ita-cli-config-{}.json", process::id()));

    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path)?
    };

    #[cfg(not(unix))]
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)?;

    file.write_all(serde_json::to_string(&config)?.as_bytes())?;
    Ok(path)
}

fn token_tdx_claims(token: &str) -> Result<Value, Box<dyn Error>> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or("ITA token must contain a JWT payload")?;
    let claims: Value = serde_json::from_slice(&BASE64URL.decode(payload)?)?;
    Ok(claims.get("tdx").cloned().unwrap_or(claims))
}

fn main() -> Result<(), Box<dyn Error>> {
    let config_json = read_config_json()?;
    let api_key = api_key_from_config(&config_json)?;
    let cli_config_path = cli_config_path(&config_json)?;
    let cli = std::env::var("ITA_CLI_BIN").unwrap_or_else(|_| "trustauthority-cli".to_string());

    let livy = livy_tee::Livy::new(api_key);
    let rt = tokio::runtime::Runtime::new()?;

    let mut builder = livy.attest();
    builder.commit(&"livy-tee ita-cli cross verification input");
    builder.commit(&"livy-tee ita-cli cross verification output");
    // Demo replay counter; production callers should supply a monotonic value.
    builder.nonce(20260413);

    let attestation = rt.block_on(builder.finalize())?;

    if !attestation.verify()? {
        return Err("livy-tee offline verification failed".into());
    }

    let raw_quote = BASE64.decode(&attestation.raw_quote)?;
    let runtime_data = BASE64.decode(&attestation.runtime_data)?;
    let tdx_claims = token_tdx_claims(&attestation.ita_token)?;
    println!("livy-tee attestation generated");
    println!("  quote_bytes: {}", raw_quote.len());
    println!("  runtime_data_bytes: {}", runtime_data.len());
    println!("  mrtd: {}", attestation.mrtd);
    println!("  tcb_status: {}", attestation.tcb_status);
    for key in [
        "attester_tcb_date",
        "attester_advisory_ids",
        "pce_svn",
        "sgx_tcb_comp_svn",
        "tdx_tee_tcb_svn",
        "tdx_seamsvn",
    ] {
        if let Some(value) = tdx_claims.get(key) {
            println!("  {key}: {value}");
        }
    }
    println!("  payload_hash: {}", attestation.payload_hash_hex());
    println!("  livy_tee_offline_verify: ok");

    let output = Command::new(&cli)
        .arg("verify")
        .arg("--config")
        .arg(&cli_config_path)
        .arg("--token")
        .arg(&attestation.ita_token)
        .output()?;
    let _ = std::fs::remove_file(&cli_config_path);

    if !output.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        eprintln!("{}", String::from_utf8_lossy(&output.stdout));
        return Err(format!("trustauthority-cli verify failed: {}", output.status).into());
    }

    println!("  trustauthority_cli_verify: ok");
    Ok(())
}
