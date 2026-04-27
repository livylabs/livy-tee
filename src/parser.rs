// SPDX-License-Identifier: MIT
//! Parsing helpers for quote input.

use crate::{error::EvidenceError, Config, Evidence};

/// Parse quote input into [`Evidence`].
///
/// Accepts either a standard base64-encoded raw quote or the portable JSON
/// envelope produced by [`Evidence::to_transport_string`]. Surrounding
/// whitespace is optionally trimmed according to [`Config`].
pub fn parse(input: &str, config: Config) -> Result<Evidence, EvidenceError> {
    let normalized = if config.trim_input {
        input.trim()
    } else {
        input
    };
    Evidence::from_transport_string(normalized)
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

    #[test]
    fn parse_accepts_portable_azure_evidence() {
        let quote = vec![0xCD; 632];
        let runtime_json = br#"{"user-data":"cafebabe"}"#.to_vec();
        let evidence =
            Evidence::from_bytes_with_azure_runtime(quote.clone(), runtime_json.clone()).unwrap();
        let encoded = format!(" \n{}\n ", evidence.to_transport_string());

        let parsed = parse(&encoded, Config::default()).expect("parse should succeed");

        assert_eq!(parsed.raw(), quote.as_slice());
        assert_eq!(parsed.azure_runtime_data(), Some(runtime_json.as_slice()));
    }
}
