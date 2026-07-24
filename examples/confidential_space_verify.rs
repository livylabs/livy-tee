// SPDX-License-Identifier: MIT
//! Verify a portable Confidential Space artifact as the relying party.
//!
//! The artifact path is the first argument. Omit it, or pass `-`, to read JSON
//! from standard input. The audience and image digest always come from trusted
//! verifier environment variables rather than from the artifact.

use livy_tee::{ConfidentialSpaceAttestation, ConfidentialSpaceVerificationPolicy};
use std::error::Error;
use std::io::{self, Read as _, Write as _};

const AUDIENCE_ENV: &str = "LIVY_TEE_CS_AUDIENCE";
const IMAGE_DIGEST_ENV: &str = "LIVY_TEE_CS_IMAGE_DIGEST";
const TIMEOUT_ENV: &str = "LIVY_TEE_CS_TIMEOUT_SECS";

fn required_env(name: &str) -> Result<String, io::Error> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} must be set to a non-empty value"),
            )
        })
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

fn read_artifact() -> Result<Vec<u8>, io::Error> {
    match std::env::args().nth(1).as_deref() {
        None | Some("-") => {
            let mut encoded = Vec::new();
            io::stdin().read_to_end(&mut encoded)?;
            Ok(encoded)
        }
        Some(path) => std::fs::read(path),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let artifact: ConfidentialSpaceAttestation = serde_json::from_slice(&read_artifact()?)?;
    let mut policy = ConfidentialSpaceVerificationPolicy::new(
        required_env(AUDIENCE_ENV)?,
        required_env(IMAGE_DIGEST_ENV)?,
    );
    if let Some(timeout) = optional_timeout()? {
        policy.request_timeout_secs = timeout;
    }

    let report = artifact.verify(&policy).await?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, &report)?;
    writeln!(output)?;

    if !report.all_passed() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Confidential Space attestation policy failed",
        )
        .into());
    }
    Ok(())
}
