// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! TDX evidence generation.
//!
//! Default: TSM configfs (`/sys/kernel/config/tsm/report/`) — requires TDX hardware.
//! Add `--features mock-tee` to use a correctly-shaped stub without hardware.

#[cfg(not(feature = "mock-tee"))]
mod tsm;

#[cfg(feature = "mock-tee")]
mod mock;

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
}

/// Generate TDX evidence over 64 bytes of caller-supplied user data.
///
/// The `user_data` slice is embedded verbatim as the REPORTDATA field in the
/// resulting DCAP quote (bytes 568–632).
pub fn generate_evidence(user_data: &[u8; 64]) -> Result<Evidence, GenerateError> {
    #[cfg(not(feature = "mock-tee"))]
    {
        tsm::generate(user_data)
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
        Ok("0000000000000000000000000000000000000000000000000000000000000000"
            .to_string())
    }
}
