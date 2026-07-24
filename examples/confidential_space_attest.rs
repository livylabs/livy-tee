// SPDX-License-Identifier: MIT
//! Request a Confidential Space token and emit a portable artifact.
//!
//! Run this executable inside the Confidential Space workload. Standard output
//! contains only the artifact JSON so it can be sent over an authenticated
//! channel to the relying party.

use livy_tee::{
    ConfidentialSpace, ConfidentialSpaceAttesterMode, ConfidentialSpaceConfig, PublicValues,
};
use std::error::Error;
use std::io::{self, Write as _};
use std::path::PathBuf;

const AUDIENCE_ENV: &str = "LIVY_TEE_CS_AUDIENCE";
const ATTESTER_ENV: &str = "LIVY_TEE_CS_ATTESTER";
const LAUNCHER_SOCKET_ENV: &str = "LIVY_TEE_CS_LAUNCHER_SOCKET";
const TIMEOUT_ENV: &str = "LIVY_TEE_CS_TIMEOUT_SECS";
const BUILT_AUDIENCE: Option<&str> = option_env!("LIVY_TEE_CS_AUDIENCE");
const BUILT_ATTESTER: Option<&str> = option_env!("LIVY_TEE_CS_ATTESTER");

fn configured_value(name: &str, built_value: Option<&str>) -> Result<String, io::Error> {
    std::env::var(name)
        .ok()
        .or_else(|| built_value.map(str::to_string))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} must be set to a non-empty value at build time or runtime"),
            )
        })
}

fn attester_mode() -> Result<ConfidentialSpaceAttesterMode, io::Error> {
    let value = std::env::var(ATTESTER_ENV)
        .ok()
        .or_else(|| BUILT_ATTESTER.map(str::to_string))
        .unwrap_or_else(|| "dual".to_string());
    match value.trim().to_ascii_lowercase().as_str() {
        "google" => Ok(ConfidentialSpaceAttesterMode::Google),
        "intel" => Ok(ConfidentialSpaceAttesterMode::Intel),
        "dual" => Ok(ConfidentialSpaceAttesterMode::Dual),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{ATTESTER_ENV} must be google, intel, or dual"),
        )),
    }
}

fn optional_timeout() -> Result<Option<u64>, io::Error> {
    let Ok(value) = std::env::var(TIMEOUT_ENV) else {
        return Ok(None);
    };
    let timeout = value.parse::<u64>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{TIMEOUT_ENV} must be a positive integer: {error}"),
        )
    })?;
    if timeout == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{TIMEOUT_ENV} must be greater than zero"),
        ));
    }
    Ok(Some(timeout))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let audience = configured_value(AUDIENCE_ENV, BUILT_AUDIENCE)?;
    let mode = attester_mode()?;
    let public_value = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "livy-tee Confidential Space smoke test".to_string());

    let mut public_values = PublicValues::new();
    public_values.commit(&public_value)?;

    let mut config = ConfidentialSpaceConfig::new(audience, mode);
    if let Ok(socket) = std::env::var(LAUNCHER_SOCKET_ENV) {
        config.launcher_socket = PathBuf::from(socket);
    }
    if let Some(timeout) = optional_timeout()? {
        config.request_timeout_secs = timeout;
    }
    if !config.launcher_socket.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Confidential Space launcher socket is missing at {}; run this executable inside the workload",
                config.launcher_socket.display()
            ),
        )
        .into());
    }

    let artifact = ConfidentialSpace::new(config).attest(public_values).await?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, &artifact)?;
    writeln!(output)?;
    Ok(())
}
