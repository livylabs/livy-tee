// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Length-prefixed public values buffer.
//!
//! Each committed value is encoded as:
//! `[u32 little-endian payload length][serde_json payload bytes]`.
//! The buffer can be replayed sequentially with a read cursor or inspected
//! entry-by-entry without deserializing payloads.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// A serialized buffer of public values with a read cursor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublicValues {
    buffer: Vec<u8>,
    cursor: usize,
}

/// Errors returned by [`PublicValues`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PublicValuesError {
    /// Failed to decode the base64 buffer.
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
    /// Failed to encode or decode the JSON payload.
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    /// An entry payload exceeded the on-wire `u32` length prefix.
    #[error("entry payload too large to encode: {0} bytes")]
    EntryTooLarge(usize),
    /// The buffer ended before a full 4-byte length prefix was available.
    #[error("buffer ended while reading length prefix at offset {offset}")]
    TruncatedLength {
        /// The byte offset where the incomplete length prefix begins.
        offset: usize,
    },
    /// The buffer ended before a full payload was available.
    #[error(
        "buffer ended while reading entry at offset {offset}: payload length {length}, buffer size {buffer_len}"
    )]
    TruncatedEntry {
        /// The byte offset where the entry length prefix begins.
        offset: usize,
        /// The decoded payload length from the entry prefix.
        length: usize,
        /// The total buffer size that failed validation.
        buffer_len: usize,
    },
    /// The read cursor is already at the end of the buffer.
    #[error("no more entries available at cursor {offset}")]
    EndOfBuffer {
        /// The cursor position that attempted to read past the end.
        offset: usize,
    },
}

impl PublicValues {
    /// Create an empty public values buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a validated public values buffer from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer does not contain a complete sequence of
    /// length-prefixed entries.
    pub fn from_bytes(buffer: Vec<u8>) -> Result<Self, PublicValuesError> {
        validate_buffer(&buffer)?;
        Ok(Self { buffer, cursor: 0 })
    }

    /// Decode a validated public values buffer from base64.
    ///
    /// # Errors
    ///
    /// Returns an error if the base64 is invalid or if the decoded bytes do not
    /// contain a complete sequence of length-prefixed entries.
    pub fn from_base64(encoded: &str) -> Result<Self, PublicValuesError> {
        let buffer = BASE64.decode(encoded.trim())?;
        Self::from_bytes(buffer)
    }

    /// Encode the buffer as standard base64.
    #[must_use]
    pub fn to_base64(&self) -> String {
        BASE64.encode(&self.buffer)
    }

    /// Borrow the raw on-wire bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Reset the sequential read cursor to the start of the buffer.
    pub fn reset_cursor(&mut self) {
        self.cursor = 0;
    }

    /// Append a new JSON-serialized value to the buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be serialized or the encoded
    /// payload would exceed the `u32` length prefix.
    pub fn commit<T: Serialize>(&mut self, value: &T) -> Result<(), PublicValuesError> {
        let payload = serde_json::to_vec(value)?;
        let len = u32::try_from(payload.len())
            .map_err(|_| PublicValuesError::EntryTooLarge(payload.len()))?;
        self.buffer.extend_from_slice(&len.to_le_bytes());
        self.buffer.extend_from_slice(&payload);
        Ok(())
    }

    /// Read the next value from the buffer and advance the cursor.
    ///
    /// # Errors
    ///
    /// Returns an error if the cursor is at the end of the buffer, the next
    /// entry is truncated, or the JSON payload cannot be decoded as `T`.
    pub fn read<T: DeserializeOwned>(&mut self) -> Result<T, PublicValuesError> {
        if self.cursor >= self.buffer.len() {
            return Err(PublicValuesError::EndOfBuffer {
                offset: self.cursor,
            });
        }

        let (entry_start, entry_len) = parse_entry_header(&self.buffer, self.cursor)?;
        let payload_start = entry_start + 4;
        let payload_end = payload_start + entry_len;
        let value = serde_json::from_slice(&self.buffer[payload_start..payload_end])?;
        self.cursor = payload_end;
        Ok(value)
    }

    /// Return each raw on-wire entry as `(field_index, wire_bytes)`.
    ///
    /// `wire_bytes` includes both the 4-byte little-endian length prefix and
    /// the JSON payload bytes. This helper does not consult or advance the
    /// sequential read cursor.
    #[must_use]
    pub fn entries_raw(&self) -> Vec<(u32, Vec<u8>)> {
        let mut entries = Vec::new();
        let mut offset = 0usize;
        let mut index = 0u32;

        while offset < self.buffer.len() {
            let (entry_start, entry_len) = parse_entry_header(&self.buffer, offset)
                .expect("PublicValues buffers are validated on construction");
            let entry_end = entry_start + 4 + entry_len;
            entries.push((index, self.buffer[entry_start..entry_end].to_vec()));
            offset = entry_end;
            index += 1;
        }

        entries
    }

    /// Count the number of committed entries in the buffer.
    #[must_use]
    pub fn entry_count(&self) -> u32 {
        let mut count = 0u32;
        let mut offset = 0usize;

        while offset < self.buffer.len() {
            let (entry_start, entry_len) = parse_entry_header(&self.buffer, offset)
                .expect("PublicValues buffers are validated on construction");
            offset = entry_start + 4 + entry_len;
            count += 1;
        }

        count
    }
}

/// Compute the SHA-256 hash of a raw entry wire payload.
#[must_use]
pub fn entry_hash(wire_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(wire_bytes).into()
}

fn validate_buffer(buffer: &[u8]) -> Result<(), PublicValuesError> {
    let mut offset = 0usize;
    while offset < buffer.len() {
        let (entry_start, entry_len) = parse_entry_header(buffer, offset)?;
        offset = entry_start + 4 + entry_len;
    }
    Ok(())
}

fn parse_entry_header(buffer: &[u8], offset: usize) -> Result<(usize, usize), PublicValuesError> {
    let len_bytes = buffer
        .get(offset..offset + 4)
        .ok_or(PublicValuesError::TruncatedLength { offset })?;

    let mut prefix = [0u8; 4];
    prefix.copy_from_slice(len_bytes);
    let entry_len = u32::from_le_bytes(prefix) as usize;
    let payload_start = offset + 4;
    let payload_end = payload_start + entry_len;

    if payload_end > buffer.len() {
        return Err(PublicValuesError::TruncatedEntry {
            offset,
            length: entry_len,
            buffer_len: buffer.len(),
        });
    }

    Ok((offset, entry_len))
}

#[cfg(test)]
mod tests {
    use super::{entry_hash, PublicValues, PublicValuesError};

    #[test]
    fn entries_raw_returns_entry_boundaries_and_indices() {
        let mut values = PublicValues::new();
        values.commit(&"alpha").unwrap();
        values.commit(&42u32).unwrap();
        values.commit(&vec!["x", "y"]).unwrap();

        let entries = values.entries_raw();
        assert_eq!(entries.len(), 3);

        let expected_payloads = [
            serde_json::to_vec("alpha").unwrap(),
            serde_json::to_vec(&42u32).unwrap(),
            serde_json::to_vec(&vec!["x", "y"]).unwrap(),
        ];

        for (expected_index, (index, wire_bytes)) in entries.into_iter().enumerate() {
            assert_eq!(index as usize, expected_index);
            let payload_len = u32::from_le_bytes(wire_bytes[..4].try_into().unwrap()) as usize;
            assert_eq!(payload_len, expected_payloads[index as usize].len());
            assert_eq!(
                &wire_bytes[4..],
                expected_payloads[index as usize].as_slice()
            );
        }
    }

    #[test]
    fn entry_hash_is_stable_for_identical_values_and_changes_for_different_values() {
        let mut values = PublicValues::new();
        values.commit(&"same").unwrap();
        values.commit(&"same").unwrap();
        values.commit(&"different").unwrap();

        let entries = values.entries_raw();
        let first = entry_hash(&entries[0].1);
        let second = entry_hash(&entries[1].1);
        let third = entry_hash(&entries[2].1);

        assert_eq!(first, second);
        assert_ne!(first, third);
    }

    #[test]
    fn entry_count_matches_number_of_commits() {
        let mut values = PublicValues::new();
        assert_eq!(values.entry_count(), 0);

        values.commit(&"one").unwrap();
        values.commit(&"two").unwrap();
        values.commit(&3u8).unwrap();

        assert_eq!(values.entry_count(), 3);
    }

    #[test]
    fn entry_count_survives_from_bytes_and_from_base64() {
        let mut values = PublicValues::new();
        values.commit(&"one").unwrap();
        values.commit(&"two").unwrap();
        values.commit(&3u8).unwrap();

        let from_bytes = PublicValues::from_bytes(values.as_bytes().to_vec()).unwrap();
        let from_base64 = PublicValues::from_base64(&values.to_base64()).unwrap();

        assert_eq!(from_bytes.entry_count(), 3);
        assert_eq!(from_base64.entry_count(), 3);
        assert_eq!(from_bytes.entries_raw(), values.entries_raw());
        assert_eq!(from_base64.entries_raw(), values.entries_raw());
    }

    #[test]
    fn entries_raw_does_not_advance_the_read_cursor() {
        let mut values = PublicValues::new();
        values.commit(&"first").unwrap();
        values.commit(&"second").unwrap();

        let _ = values.entries_raw();
        let first: String = values.read().unwrap();
        let second: String = values.read().unwrap();

        assert_eq!(first, "first");
        assert_eq!(second, "second");
    }

    #[test]
    fn base64_roundtrip_preserves_entries() {
        let mut values = PublicValues::new();
        values.commit(&"alpha").unwrap();
        values.commit(&7u32).unwrap();

        let encoded = values.to_base64();
        let decoded = PublicValues::from_base64(&encoded).unwrap();

        assert_eq!(decoded.as_bytes(), values.as_bytes());
        assert_eq!(decoded.entries_raw(), values.entries_raw());
    }

    #[test]
    fn truncated_buffer_is_rejected() {
        let err = PublicValues::from_bytes(vec![5, 0, 0, 0, b'a'])
            .expect_err("incomplete payload should fail validation");

        assert!(matches!(
            err,
            PublicValuesError::TruncatedEntry {
                offset: 0,
                length: 5,
                buffer_len: 5,
            }
        ));
    }
}
