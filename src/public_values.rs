// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Ordered, typed public values committed by TEE code and read by verifiers.
//!
//! The on-wire format is a sequence of entries encoded as:
//! `[u32 little-endian payload length][serde_json payload bytes]`.
//! The full buffer is public and can be independently parsed and hashed.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::cell::Cell;

/// Ordered collection of public values committed during a TEE attestation.
#[derive(Debug, Clone)]
pub struct PublicValues {
    buffer: Vec<u8>,
    /// Read cursor with interior mutability so reads work on `&self`.
    read_cursor: Cell<usize>,
}

impl Serialize for PublicValues {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for PublicValues {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        Self::from_base64(&encoded).map_err(serde::de::Error::custom)
    }
}

impl PublicValues {
    /// Create an empty `PublicValues` for committing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            read_cursor: Cell::new(0),
        }
    }

    /// Reconstruct from a raw byte buffer.
    ///
    /// This constructor preserves the bytes exactly as provided and does not
    /// validate that the buffer is a complete sequence of
    /// `[u32 little-endian length][payload]` entries. Use this for buffers
    /// created locally via [`commit`](Self::commit) / [`commit_raw`](Self::commit_raw).
    ///
    /// For malformed or otherwise untrusted input, prefer
    /// [`try_from_bytes`](Self::try_from_bytes) or call [`validate`](Self::validate)
    /// before consuming entries.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            buffer: bytes,
            read_cursor: Cell::new(0),
        }
    }

    /// Reconstruct from raw bytes after validating the full entry framing.
    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, PublicValuesError> {
        let values = Self::from_bytes(bytes);
        values.validate()?;
        Ok(values)
    }

    /// Reconstruct from a base64-encoded buffer after validating entry framing.
    ///
    /// This is the validating transport constructor and matches the behavior of
    /// `serde` deserialization. For unchecked local reconstruction from raw
    /// bytes, use [`from_bytes`](Self::from_bytes).
    pub fn from_base64(b64: &str) -> Result<Self, PublicValuesError> {
        let bytes = BASE64
            .decode(b64.trim())
            .map_err(|e| PublicValuesError::Base64(e.to_string()))?;
        Self::try_from_bytes(bytes)
    }

    /// Commit a value as a public output.
    ///
    /// Values are serialized with `serde_json` and appended to the on-wire
    /// buffer. Use [`commit_raw`](Self::commit_raw) when the payload is already
    /// pre-serialized (for example a precomputed hash).
    pub fn commit<T: Serialize>(&mut self, value: &T) {
        let encoded =
            serde_json::to_vec(value).expect("PublicValues::commit: serialization should not fail");
        self.commit_raw(&encoded);
    }

    /// Commit raw bytes directly (no serialization wrapper).
    pub fn commit_raw(&mut self, bytes: &[u8]) {
        let len: u32 = bytes
            .len()
            .try_into()
            .expect("PublicValues entry too large for wire format");
        self.buffer.extend_from_slice(&len.to_le_bytes());
        self.buffer.extend_from_slice(bytes);
    }

    /// Read the next JSON-serialized entry.
    ///
    /// Use this for entries created with [`commit`](Self::commit). Raw entries
    /// created with [`commit_raw`](Self::commit_raw) are not deserialized and
    /// should be consumed with [`read_raw`](Self::read_raw).
    pub fn read<T: DeserializeOwned>(&self) -> Result<T, PublicValuesError> {
        let (start, end) = self.next_entry_bounds()?;
        let value = serde_json::from_slice(&self.buffer[start..end])
            .map_err(|e| PublicValuesError::Deserialize(e.to_string()))?;
        self.read_cursor.set(end);
        Ok(value)
    }

    /// Backward-compatible alias for [`read`](Self::read).
    pub fn try_read<T: DeserializeOwned>(&self) -> Result<T, PublicValuesError> {
        self.read()
    }

    /// Read the exact payload bytes for the next entry without deserializing.
    ///
    /// Use this for raw entries, including hash bytes stored by higher-level
    /// helpers such as `commit_hashed`.
    pub fn read_raw(&self) -> Result<Vec<u8>, PublicValuesError> {
        let (start, end) = self.next_entry_bounds()?;
        let bytes = self.buffer[start..end].to_vec();
        self.read_cursor.set(end);
        Ok(bytes)
    }

    /// Validate that the buffer is a complete sequence of framed entries.
    ///
    /// This checks entry framing only: every entry must have a full 4-byte
    /// length prefix and enough payload bytes to satisfy that prefix. It does
    /// not deserialize payloads, so raw/hash entries remain valid.
    pub fn validate(&self) -> Result<(), PublicValuesError> {
        let mut offset = 0usize;
        while let Some(end) = checked_entry_end(&self.buffer, offset)? {
            offset = end;
        }
        Ok(())
    }

    /// Reset the read cursor to the beginning.
    pub fn reset_cursor(&self) {
        self.read_cursor.set(0);
    }

    /// Return each entry as `(field_index, wire_bytes)`.
    ///
    /// `wire_bytes` includes both the 4-byte length prefix and payload bytes.
    /// This helper does not advance the sequential read cursor.
    ///
    /// This method enumerates only the valid prefix of the buffer. Call
    /// [`validate`](Self::validate) first when a trailing malformed tail should
    /// be treated as an error.
    #[must_use]
    pub fn entries_raw(&self) -> Vec<(u32, Vec<u8>)> {
        let mut entries = Vec::new();
        let mut offset = 0usize;
        let mut index = 0u32;

        while offset < self.buffer.len() {
            let Some(end) = entry_end(&self.buffer, offset) else {
                break;
            };
            entries.push((index, self.buffer[offset..end].to_vec()));
            offset = end;
            index += 1;
        }

        entries
    }

    /// Count the number of complete entries in the buffer.
    ///
    /// This counts only the valid prefix. Call [`validate`](Self::validate)
    /// first when the buffer came from an untrusted source.
    #[must_use]
    pub fn entry_count(&self) -> u32 {
        let mut count = 0u32;
        let mut offset = 0usize;

        while offset < self.buffer.len() {
            let Some(end) = entry_end(&self.buffer, offset) else {
                break;
            };
            offset = end;
            count += 1;
        }

        count
    }

    /// Compute `SHA-256(buffer)` over the exact on-wire bytes.
    ///
    /// The hash covers every 4-byte entry length prefix and payload byte in
    /// order. For the high-level attestation API, this exact digest is stored
    /// in `ReportData.payload_hash`.
    #[must_use]
    pub fn commitment_hash(&self) -> [u8; 32] {
        Sha256::digest(&self.buffer).into()
    }

    /// Verify that this buffer's commitment matches `expected`.
    #[must_use]
    pub fn verify_commitment(&self, expected: &[u8; 32]) -> bool {
        self.commitment_hash() == *expected
    }

    /// Borrow raw buffer bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Consume and return the raw buffer.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    /// Base64-encode the buffer.
    #[must_use]
    pub fn to_base64(&self) -> String {
        BASE64.encode(&self.buffer)
    }

    /// Number of bytes in the buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    fn next_entry_bounds(&self) -> Result<(usize, usize), PublicValuesError> {
        let cursor = self.read_cursor.get();
        let end =
            checked_entry_end(&self.buffer, cursor)?.ok_or(PublicValuesError::BufferExhausted)?;
        Ok((cursor + 4, end))
    }
}

impl Default for PublicValues {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the SHA-256 hash of raw entry wire bytes.
///
/// `wire_bytes` should include the 4-byte length prefix followed by the entry
/// payload, such as the values returned by [`PublicValues::entries_raw`].
#[must_use]
pub fn entry_hash(wire_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(wire_bytes).into()
}

fn entry_end(buffer: &[u8], offset: usize) -> Option<usize> {
    checked_entry_end(buffer, offset).ok().flatten()
}

fn checked_entry_end(buffer: &[u8], offset: usize) -> Result<Option<usize>, PublicValuesError> {
    if offset >= buffer.len() {
        return Ok(None);
    }

    let remaining = buffer.len() - offset;
    if remaining < 4 {
        return Err(PublicValuesError::TruncatedLengthPrefix { offset, remaining });
    }

    let len = u32::from_le_bytes(
        buffer[offset..offset + 4]
            .try_into()
            .expect("length prefix is exactly 4 bytes"),
    ) as usize;
    let payload_start = offset + 4;
    let payload_remaining = buffer.len() - payload_start;
    let end = payload_start
        .checked_add(len)
        .ok_or(PublicValuesError::TruncatedEntryPayload {
            offset,
            declared_len: len,
            remaining: payload_remaining,
        })?;

    if end > buffer.len() {
        return Err(PublicValuesError::TruncatedEntryPayload {
            offset,
            declared_len: len,
            remaining: payload_remaining,
        });
    }

    Ok(Some(end))
}

/// Errors when reading from [`PublicValues`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PublicValuesError {
    /// Base64 decoding failed.
    #[error("failed to decode public values base64: {0}")]
    Base64(String),
    /// The buffer has no more complete entries to read.
    #[error("public values buffer exhausted — no more entries to read")]
    BufferExhausted,
    /// A trailing fragment does not contain a full 4-byte length prefix.
    #[error(
        "public values buffer has {remaining} trailing byte(s) at offset {offset}; expected a 4-byte length prefix"
    )]
    TruncatedLengthPrefix {
        /// Byte offset where the incomplete length prefix starts.
        offset: usize,
        /// Number of bytes remaining from that offset to the end of the buffer.
        remaining: usize,
    },
    /// An entry declares more payload bytes than remain in the buffer.
    #[error(
        "public values entry at offset {offset} declares {declared_len} payload byte(s), but only {remaining} remain"
    )]
    TruncatedEntryPayload {
        /// Byte offset where the entry's 4-byte length prefix starts.
        offset: usize,
        /// Payload length declared by the entry's length prefix.
        declared_len: usize,
        /// Payload bytes still available after the 4-byte length prefix.
        remaining: usize,
    },
    /// A value could not be deserialized from the buffer.
    #[error("failed to deserialize public value: {0}")]
    Deserialize(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn malformed_with_truncated_payload_tail() -> (PublicValues, usize) {
        let mut prefix = PublicValues::new();
        prefix.commit(&"ok");

        let tail_offset = prefix.len();
        let mut bytes = prefix.into_bytes();
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.push(b'x');

        (PublicValues::from_bytes(bytes), tail_offset)
    }

    fn malformed_with_truncated_length_prefix_tail() -> (PublicValues, usize) {
        let mut prefix = PublicValues::new();
        prefix.commit(&"ok");

        let tail_offset = prefix.len();
        let mut bytes = prefix.into_bytes();
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

        (PublicValues::from_bytes(bytes), tail_offset)
    }

    #[test]
    fn commit_and_read_roundtrip() {
        let mut pv = PublicValues::new();
        pv.commit(&42u64);
        pv.commit(&"hello world".to_string());
        pv.commit(&[1u8, 2, 3, 4]);

        let reader = PublicValues::from_bytes(pv.into_bytes());
        assert_eq!(reader.read::<u64>().unwrap(), 42);
        assert_eq!(reader.read::<String>().unwrap(), "hello world");
        assert_eq!(reader.read::<Vec<u8>>().unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn commitment_hash_is_deterministic() {
        let mut a = PublicValues::new();
        a.commit(&100i64);
        a.commit(&"test");

        let mut b = PublicValues::new();
        b.commit(&100i64);
        b.commit(&"test");

        assert_eq!(a.commitment_hash(), b.commitment_hash());
    }

    #[test]
    fn commitment_hash_changes_with_different_values() {
        let mut a = PublicValues::new();
        a.commit(&1u32);

        let mut b = PublicValues::new();
        b.commit(&2u32);

        assert_ne!(a.commitment_hash(), b.commitment_hash());
    }

    #[test]
    fn commitment_hash_changes_with_order() {
        let mut a = PublicValues::new();
        a.commit(&1u32);
        a.commit(&2u32);

        let mut b = PublicValues::new();
        b.commit(&2u32);
        b.commit(&1u32);

        assert_ne!(a.commitment_hash(), b.commitment_hash());
    }

    #[test]
    fn verify_commitment_passes() {
        let mut pv = PublicValues::new();
        pv.commit(&"payload");
        let hash = pv.commitment_hash();
        assert!(pv.verify_commitment(&hash));
    }

    #[test]
    fn verify_commitment_rejects_wrong_hash() {
        let mut pv = PublicValues::new();
        pv.commit(&"payload");
        assert!(!pv.verify_commitment(&[0u8; 32]));
    }

    #[test]
    fn read_exhausted_returns_error() {
        let pv = PublicValues::new();
        assert_eq!(pv.read::<u32>(), Err(PublicValuesError::BufferExhausted));
    }

    #[test]
    fn base64_roundtrip() {
        let mut pv = PublicValues::new();
        pv.commit(&99u64);
        pv.commit(&"b64 test");

        let b64 = pv.to_base64();
        let restored = PublicValues::from_base64(&b64).unwrap();
        assert_eq!(restored.read::<u64>().unwrap(), 99);
        assert_eq!(restored.read::<String>().unwrap(), "b64 test");
        assert_eq!(pv.commitment_hash(), restored.commitment_hash());
    }

    #[test]
    fn raw_commit_and_read() {
        let mut pv = PublicValues::new();
        pv.commit_raw(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let reader = PublicValues::from_bytes(pv.into_bytes());
        let raw = reader.read_raw().unwrap();
        assert_eq!(raw, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn reset_cursor_allows_rereading() {
        let mut pv = PublicValues::new();
        pv.commit(&7u32);

        let reader = PublicValues::from_bytes(pv.into_bytes());
        assert_eq!(reader.read::<u32>().unwrap(), 7);
        assert!(reader.try_read::<u32>().is_err());

        reader.reset_cursor();
        assert_eq!(reader.read::<u32>().unwrap(), 7);
    }

    #[test]
    fn entries_raw_returns_entry_boundaries_and_indices() {
        let mut values = PublicValues::new();
        values.commit(&"alpha");
        values.commit(&42u32);
        values.commit(&vec!["x", "y"]);

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
        values.commit(&"same");
        values.commit(&"same");
        values.commit(&"different");

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

        values.commit(&"one");
        values.commit(&"two");
        values.commit(&3u8);

        assert_eq!(values.entry_count(), 3);
    }

    #[test]
    fn entry_count_survives_from_bytes_and_from_base64() {
        let mut values = PublicValues::new();
        values.commit(&"one");
        values.commit(&"two");
        values.commit(&3u8);

        let from_bytes = PublicValues::from_bytes(values.as_bytes().to_vec());
        let from_base64 = PublicValues::from_base64(&values.to_base64()).unwrap();

        assert_eq!(from_bytes.entry_count(), 3);
        assert_eq!(from_base64.entry_count(), 3);
        assert_eq!(from_bytes.entries_raw(), values.entries_raw());
        assert_eq!(from_base64.entries_raw(), values.entries_raw());
    }

    #[test]
    fn entries_raw_does_not_advance_the_read_cursor() {
        let mut values = PublicValues::new();
        values.commit(&"first");
        values.commit(&"second");

        let _ = values.entries_raw();
        let first: String = values.read().unwrap();
        let second: String = values.read().unwrap();

        assert_eq!(first, "first");
        assert_eq!(second, "second");
    }

    #[test]
    fn read_preserves_cursor_on_deserialize_error() {
        let mut values = PublicValues::new();
        values.commit(&7u32);

        assert!(matches!(
            values.read::<String>(),
            Err(PublicValuesError::Deserialize(_))
        ));
        assert_eq!(values.read::<u32>().unwrap(), 7);
    }

    #[test]
    fn base64_roundtrip_preserves_entries() {
        let mut values = PublicValues::new();
        values.commit(&"alpha");
        values.commit(&7u32);

        let encoded = values.to_base64();
        let decoded = PublicValues::from_base64(&encoded).unwrap();

        assert_eq!(decoded.as_bytes(), values.as_bytes());
        assert_eq!(decoded.entries_raw(), values.entries_raw());
    }

    #[test]
    fn from_base64_rejects_invalid_base64() {
        assert!(matches!(
            PublicValues::from_base64("not-base64"),
            Err(PublicValuesError::Base64(_))
        ));
    }

    #[test]
    fn from_base64_rejects_malformed_tail() {
        let (values, tail_offset) = malformed_with_truncated_payload_tail();
        let encoded = values.to_base64();
        let expected = PublicValuesError::TruncatedEntryPayload {
            offset: tail_offset,
            declared_len: 3,
            remaining: 1,
        };

        assert_eq!(PublicValues::from_base64(&encoded).unwrap_err(), expected);
        assert_eq!(
            PublicValues::try_from_bytes(values.into_bytes()).unwrap_err(),
            expected
        );

        let deserialization_error =
            serde_json::from_str::<PublicValues>(&format!("\"{encoded}\"")).unwrap_err();
        assert!(deserialization_error
            .to_string()
            .contains("public values entry at offset"));
    }

    #[test]
    fn truncated_buffer_has_zero_visible_entries() {
        let values = PublicValues::from_bytes(vec![5, 0, 0, 0, b'a']);

        assert_eq!(values.entry_count(), 0);
        assert!(values.entries_raw().is_empty());
        assert_eq!(
            values.try_read::<String>(),
            Err(PublicValuesError::TruncatedEntryPayload {
                offset: 0,
                declared_len: 5,
                remaining: 1,
            })
        );
        assert_eq!(
            values.validate(),
            Err(PublicValuesError::TruncatedEntryPayload {
                offset: 0,
                declared_len: 5,
                remaining: 1,
            })
        );
    }

    #[test]
    fn validate_accepts_well_formed_raw_and_typed_entries() {
        let mut values = PublicValues::new();
        values.commit(&"alpha");
        values.commit_raw(&[0xDE, 0xAD, 0xBE, 0xEF]);
        values.commit(&42u32);

        assert!(values.validate().is_ok());
    }

    #[test]
    fn validate_rejects_truncated_payload_tail_after_valid_prefix() {
        let (values, tail_offset) = malformed_with_truncated_payload_tail();

        assert_eq!(values.entry_count(), 1);
        assert_eq!(values.entries_raw().len(), 1);
        assert_eq!(
            values.validate(),
            Err(PublicValuesError::TruncatedEntryPayload {
                offset: tail_offset,
                declared_len: 3,
                remaining: 1,
            })
        );
    }

    #[test]
    fn validate_rejects_truncated_length_prefix_tail_after_valid_prefix() {
        let (values, tail_offset) = malformed_with_truncated_length_prefix_tail();

        assert_eq!(values.entry_count(), 1);
        assert_eq!(values.entries_raw().len(), 1);
        assert_eq!(
            values.validate(),
            Err(PublicValuesError::TruncatedLengthPrefix {
                offset: tail_offset,
                remaining: 3,
            })
        );
    }

    #[test]
    fn try_from_bytes_rejects_malformed_tail() {
        let (values, tail_offset) = malformed_with_truncated_payload_tail();

        assert_eq!(
            PublicValues::try_from_bytes(values.into_bytes()).unwrap_err(),
            PublicValuesError::TruncatedEntryPayload {
                offset: tail_offset,
                declared_len: 3,
                remaining: 1,
            }
        );
    }

    #[test]
    fn read_and_read_raw_report_malformed_tail_instead_of_exhaustion() {
        let (values, tail_offset) = malformed_with_truncated_payload_tail();

        assert_eq!(values.read::<String>().unwrap(), "ok");
        assert_eq!(
            values.read::<String>(),
            Err(PublicValuesError::TruncatedEntryPayload {
                offset: tail_offset,
                declared_len: 3,
                remaining: 1,
            })
        );

        values.reset_cursor();
        assert_eq!(values.read::<String>().unwrap(), "ok");
        assert_eq!(
            values.read_raw(),
            Err(PublicValuesError::TruncatedEntryPayload {
                offset: tail_offset,
                declared_len: 3,
                remaining: 1,
            })
        );
    }
}
