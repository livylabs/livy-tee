// SPDX-License-Identifier: MIT
//! Public configuration types.

/// Parser configuration for [`crate::parse`].
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Accept surrounding ASCII whitespace in the base64 input.
    pub trim_input: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self { trim_input: true }
    }
}
