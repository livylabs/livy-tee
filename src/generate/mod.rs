// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! TDX evidence generation.
//!
//! Azure CVMs use the Azure vTPM/paravisor path. Other Linux TDX guests use
//! TSM configfs. Enable `mock-tee` to use a correctly-shaped stub instead.

#[cfg(not(feature = "mock-tee"))]
mod azure;
#[cfg(not(feature = "mock-tee"))]
mod tsm;

#[cfg(feature = "mock-tee")]
mod mock;

#[cfg(not(feature = "mock-tee"))]
use crate::cloud::{detect_cloud_provider, log_detected_provider, CloudProvider};
use crate::evidence::Evidence;
use thiserror::Error;

/// Errors returned by [`generate_evidence`] and [`binary_hash`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GenerateError {
    /// TSM configfs mount is not present; TDX hardware or kernel driver required.
    #[error("TSM configfs not available at /sys/kernel/config/tsm/report")]
    TsmNotAvailable,
    /// I/O error during configfs read/write.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Failed to read the current executable binary from disk.
    #[error("failed to read binary for hash: {0}")]
    BinaryRead(std::io::Error),
    /// Azure adapter prerequisites are missing.
    #[error("Azure quote adapter prerequisite missing: {0}")]
    AzurePrerequisite(String),
    /// Azure quote adapter command failed.
    #[error("Azure quote adapter command failed: {0}")]
    AzureCommand(String),
    /// Azure vTPM returned a TPM response code.
    #[error("Azure vTPM command failed with response code 0x{0:08x}")]
    AzureTpmResponseCode(u32),
    /// Azure runtime data returned by vTPM is malformed.
    #[error("Azure runtime data is invalid: {0}")]
    AzureRuntime(String),
    /// Azure local quote endpoint returned an invalid response.
    #[error("Azure quote endpoint response is invalid: {0}")]
    AzureQuoteResponse(String),
}

impl GenerateError {
    /// Stable machine-readable error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::TsmNotAvailable => "tsm_not_available",
            Self::Io(_) => "io",
            Self::BinaryRead(_) => "binary_read",
            Self::AzurePrerequisite(_) => "azure_prerequisite",
            Self::AzureCommand(_) => "azure_command",
            Self::AzureTpmResponseCode(_) => "azure_tpm_response_code",
            Self::AzureRuntime(_) => "azure_runtime",
            Self::AzureQuoteResponse(_) => "azure_quote_response",
        }
    }
}

/// Generate TDX evidence over 64 bytes of caller-supplied user data.
pub fn generate_evidence(user_data: &[u8; 64]) -> Result<Evidence, GenerateError> {
    #[cfg(not(feature = "mock-tee"))]
    {
        match detect_cloud_provider() {
            Some(CloudProvider::Azure) => {
                log_detected_provider(CloudProvider::Azure);
                azure::generate(user_data)
            }
            _ => tsm::generate(user_data),
        }
    }

    #[cfg(feature = "mock-tee")]
    {
        mock::generate(user_data)
    }
}

/// SHA-256 of the current binary on disk.
///
/// In `mock-tee` mode returns a stable placeholder string.
pub fn binary_hash() -> Result<String, GenerateError> {
    #[cfg(not(feature = "mock-tee"))]
    {
        use sha2::{Digest, Sha256};
        let exe = std::env::current_exe().map_err(GenerateError::BinaryRead)?;
        let bytes = std::fs::read(&exe).map_err(GenerateError::BinaryRead)?;
        Ok(hex::encode(Sha256::digest(&bytes)))
    }

    #[cfg(feature = "mock-tee")]
    {
        Ok("0000000000000000000000000000000000000000000000000000000000000000".to_string())
    }
}
