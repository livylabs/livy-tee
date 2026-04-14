// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Parsing helpers for quote input.

use crate::{Config, Evidence, EvidenceError};

/// Parse a standard base64-encoded quote into [`Evidence`].
///
/// This is a convenience wrapper around [`Evidence::from_base64`] with
/// optional input trimming controlled by [`Config`].
pub fn parse(input: &str, config: Config) -> Result<Evidence, EvidenceError> {
    let normalized = if config.trim_input {
        input.trim()
    } else {
        input
    };
    Evidence::from_base64(normalized)
}

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::{Config, Evidence};

    #[test]
    fn parse_accepts_trimmed_input_by_default() {
        let quote = vec![0xAB; 632];
        let encoded = format!(" \n{}\n ", Evidence::from_bytes(quote).unwrap().to_base64());

        let parsed = parse(&encoded, Config::default()).expect("parse should succeed");

        assert_eq!(parsed.raw().len(), 632);
    }
}
