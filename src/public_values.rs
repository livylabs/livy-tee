// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Ordered, typed public values committed by TEE code and read by verifiers.
//!
//! The on-wire format is a sequence of entries encoded as:
//! `[u32 little-endian payload length][serde_json payload bytes]`.
//! The full buffer is public and can be independently parsed and hashed.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::cell::Cell;

/// Ordered collection of public values committed during a TEE attestation.
#[derive(Debug, Clone)]
pub struct PublicValues {
    buffer: Vec<u8>,
    /// Read cursor with interior mutability so reads work on `&self`.
    read_cursor: Cell<usize>,
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
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            buffer: bytes,
            read_cursor: Cell::new(0),
        }
    }

    /// Reconstruct from a base64-encoded buffer.
    pub fn from_base64(b64: &str) -> Result<Self, base64::DecodeError> {
        Ok(Self::from_bytes(BASE64.decode(b64.trim())?))
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

    /// Read the next committed value.
    ///
    /// # Panics
    ///
    /// Panics if the buffer is exhausted or deserialization fails.
    /// Use [`try_read`](Self::try_read) for a fallible version.
    pub fn read<T: DeserializeOwned>(&self) -> T {
        self.try_read()
            .expect("PublicValues::read: failed to read next value")
    }

    /// Try to read the next committed value.
    pub fn try_read<T: DeserializeOwned>(&self) -> Result<T, PublicValuesError> {
        let (start, end) = self.next_entry_bounds()?;
        let value = serde_json::from_slice(&self.buffer[start..end])
            .map_err(|e| PublicValuesError::Deserialize(e.to_string()))?;
        self.read_cursor.set(end);
        Ok(value)
    }

    /// Read the raw bytes for the next entry payload (without deserializing).
    pub fn read_raw(&self) -> Result<Vec<u8>, PublicValuesError> {
        let (start, end) = self.next_entry_bounds()?;
        let bytes = self.buffer[start..end].to_vec();
        self.read_cursor.set(end);
        Ok(bytes)
    }

    /// Reset the read cursor to the beginning.
    pub fn reset_cursor(&self) {
        self.read_cursor.set(0);
    }

    /// Return each entry as `(field_index, wire_bytes)`.
    ///
    /// `wire_bytes` includes both the 4-byte length prefix and payload bytes.
    /// This helper does not advance the sequential read cursor.
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

    /// Count the number of committed entries in the buffer.
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

    /// Compute `SHA-256(buffer)` — the 32-byte commitment hash.
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
        let end = entry_end(&self.buffer, cursor).ok_or(PublicValuesError::BufferExhausted)?;
        Ok((cursor + 4, end))
    }
}

impl Default for PublicValues {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the SHA-256 hash of a raw entry wire payload.
#[must_use]
pub fn entry_hash(wire_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(wire_bytes).into()
}

fn entry_end(buffer: &[u8], offset: usize) -> Option<usize> {
    if offset + 4 > buffer.len() {
        return None;
    }

    let len = u32::from_le_bytes(buffer[offset..offset + 4].try_into().ok()?) as usize;
    let end = offset + 4 + len;
    if end > buffer.len() {
        return None;
    }

    Some(end)
}

/// Errors when reading from [`PublicValues`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum PublicValuesError {
    /// The buffer has no more complete entries to read.
    #[error("public values buffer exhausted — no more entries to read")]
    BufferExhausted,
    /// A value could not be deserialized from the buffer.
    #[error("failed to deserialize public value: {0}")]
    Deserialize(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_and_read_roundtrip() {
        let mut pv = PublicValues::new();
        pv.commit(&42u64);
        pv.commit(&"hello world".to_string());
        pv.commit(&[1u8, 2, 3, 4]);

        let reader = PublicValues::from_bytes(pv.into_bytes());
        assert_eq!(reader.read::<u64>(), 42);
        assert_eq!(reader.read::<String>(), "hello world");
        assert_eq!(reader.read::<Vec<u8>>(), vec![1, 2, 3, 4]);
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
        assert!(pv.try_read::<u32>().is_err());
    }

    #[test]
    fn base64_roundtrip() {
        let mut pv = PublicValues::new();
        pv.commit(&99u64);
        pv.commit(&"b64 test");

        let b64 = pv.to_base64();
        let restored = PublicValues::from_base64(&b64).unwrap();
        assert_eq!(restored.read::<u64>(), 99);
        assert_eq!(restored.read::<String>(), "b64 test");
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
        assert_eq!(reader.read::<u32>(), 7);
        assert!(reader.try_read::<u32>().is_err());

        reader.reset_cursor();
        assert_eq!(reader.read::<u32>(), 7);
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
        let first: String = values.read();
        let second: String = values.read();

        assert_eq!(first, "first");
        assert_eq!(second, "second");
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
    fn truncated_buffer_has_zero_visible_entries() {
        let values = PublicValues::from_bytes(vec![5, 0, 0, 0, b'a']);

        assert_eq!(values.entry_count(), 0);
        assert!(values.entries_raw().is_empty());
        assert!(values.try_read::<String>().is_err());
    }
}
