// SPDX-License-Identifier: MIT
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
use crate::error::GenerateError;
use crate::evidence::Evidence;

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
