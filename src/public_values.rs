// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Ordered, typed public values — the verifier-inspectable outputs of a TEE attestation.
//!
//! This module provides a commit/read model inspired by zkVM journal semantics
//! (e.g. SP1's `env::commit` / `PublicValuesReader`).
//!
//! # TEE side — committing values
//!
//! ```rust,ignore
//! use livy_tee::PublicValues;
//!
//! let mut pv = PublicValues::new();
//! pv.commit(&content_hash);       // [u8; 32]
//! pv.commit(&identity_pubkey);    // String
//! pv.commit(&timestamp_ms);       // i64
//!
//! // The commitment hash goes into REPORTDATA[0..32].
//! let hash: [u8; 32] = pv.commitment_hash();
//! ```
//!
//! # Verifier side — reading values
//!
//! ```rust,ignore
//! use livy_tee::PublicValues;
//!
//! let pv = PublicValues::from_bytes(proof_public_values_bytes);
//! let content_hash: [u8; 32] = pv.read();
//! let pubkey: String          = pv.read();
//! let timestamp: i64          = pv.read();
//!
//! // Verify the commitment matches REPORTDATA:
//! assert_eq!(pv.commitment_hash(), report_data.payload_hash);
//! ```
//!
//! # Wire format
//!
//! The buffer is a sequence of length-prefixed bincode-encoded values:
//! ```text
//! [len: u32 LE] [bincode bytes ...] [len: u32 LE] [bincode bytes ...] ...
//! ```
//!
//! `commitment_hash()` = `SHA-256(buffer)`.  This hash occupies `REPORTDATA[0..32]`.
//! The full buffer travels alongside the attestation so verifiers can reconstruct and
//! inspect individual values.

use sha2::{Digest, Sha256};
use serde::{Serialize, de::DeserializeOwned};
use std::cell::Cell;

/// Ordered collection of public values committed during a TEE attestation.
///
/// Values are written sequentially with [`commit`](Self::commit) and read back
/// in the same order with [`read`](Self::read).  The buffer is
/// length-prefixed per entry so the verifier can parse each value independently.
#[derive(Debug, Clone)]
pub struct PublicValues {
    buffer: Vec<u8>,
    /// Read cursor — interior mutability so `read()` works on `&self`.
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

    /// Reconstruct from a raw byte buffer (e.g. received alongside an attestation).
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            buffer: bytes,
            read_cursor: Cell::new(0),
        }
    }

    /// Reconstruct from a base64-encoded buffer.
    pub fn from_base64(b64: &str) -> Result<Self, base64::DecodeError> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        let bytes = BASE64.decode(b64.trim())?;
        Ok(Self::from_bytes(bytes))
    }

    // ── TEE side: commit ──────────────────────────────────────────────

    /// Commit a value as a public output.
    ///
    /// The value is serialized and appended to the buffer.
    /// Values are read back in commit order by the verifier.
    ///
    /// **Privacy:** the value is stored in plain text. Any party with access to
    /// this buffer can read it back with [`read`](Self::read). Only commit data
    /// that is intended to be public. For sensitive values, hash them before
    /// calling [`commit_raw`](Self::commit_raw) with the 32-byte digest.
    pub fn commit<T: Serialize>(&mut self, value: &T) {
        let encoded = serde_json::to_vec(value)
            .expect("PublicValues::commit: serialization should not fail");
        let len = encoded.len() as u32;
        self.buffer.extend_from_slice(&len.to_le_bytes());
        self.buffer.extend_from_slice(&encoded);
    }

    /// Commit raw bytes directly (no serialization wrapper).
    pub fn commit_raw(&mut self, bytes: &[u8]) {
        let len = bytes.len() as u32;
        self.buffer.extend_from_slice(&len.to_le_bytes());
        self.buffer.extend_from_slice(bytes);
    }

    // ── Verifier side: read ───────────────────────────────────────────

    /// Read the next committed value.
    ///
    /// Values are read in the same order they were committed.
    ///
    /// # Panics
    ///
    /// Panics if the buffer is exhausted or deserialization fails.
    /// Use [`try_read`](Self::try_read) for a fallible version.
    pub fn read<T: DeserializeOwned>(&self) -> T {
        self.try_read().expect("PublicValues::read: failed to read next value")
    }

    /// Try to read the next committed value, returning `None` if the buffer
    /// is exhausted or an error if deserialization fails.
    pub fn try_read<T: DeserializeOwned>(&self) -> Result<T, PublicValuesError> {
        let cursor = self.read_cursor.get();
        if cursor + 4 > self.buffer.len() {
            return Err(PublicValuesError::BufferExhausted);
        }

        let len_bytes: [u8; 4] = self.buffer[cursor..cursor + 4]
            .try_into()
            .map_err(|_| PublicValuesError::BufferExhausted)?;
        let len = u32::from_le_bytes(len_bytes) as usize;

        let start = cursor + 4;
        let end = start + len;
        if end > self.buffer.len() {
            return Err(PublicValuesError::BufferExhausted);
        }

        let value: T = serde_json::from_slice(&self.buffer[start..end])
            .map_err(|e| PublicValuesError::Deserialize(e.to_string()))?;

        self.read_cursor.set(end);
        Ok(value)
    }

    /// Read raw bytes for the next entry (no deserialization).
    pub fn read_raw(&self) -> Result<Vec<u8>, PublicValuesError> {
        let cursor = self.read_cursor.get();
        if cursor + 4 > self.buffer.len() {
            return Err(PublicValuesError::BufferExhausted);
        }

        let len_bytes: [u8; 4] = self.buffer[cursor..cursor + 4]
            .try_into()
            .map_err(|_| PublicValuesError::BufferExhausted)?;
        let len = u32::from_le_bytes(len_bytes) as usize;

        let start = cursor + 4;
        let end = start + len;
        if end > self.buffer.len() {
            return Err(PublicValuesError::BufferExhausted);
        }

        let bytes = self.buffer[start..end].to_vec();
        self.read_cursor.set(end);
        Ok(bytes)
    }

    /// Reset the read cursor to the beginning.
    pub fn reset_cursor(&self) {
        self.read_cursor.set(0);
    }

    // ── Commitment ────────────────────────────────────────────────────

    /// Compute `SHA-256(buffer)` — the 32-byte commitment that goes into
    /// `REPORTDATA[0..32]`.
    ///
    /// A verifier who has the full buffer can recompute this independently
    /// and check it matches the payload_hash extracted from the TDX quote.
    #[must_use]
    pub fn commitment_hash(&self) -> [u8; 32] {
        Sha256::digest(&self.buffer).into()
    }

    /// Verify that this buffer's commitment matches the expected hash
    /// (typically extracted from `REPORTDATA[0..32]`).
    #[must_use]
    pub fn verify_commitment(&self, expected: &[u8; 32]) -> bool {
        self.commitment_hash() == *expected
    }

    // ── Serialization ─────────────────────────────────────────────────

    /// The raw buffer bytes.
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
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
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
}

impl Default for PublicValues {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors when reading from [`PublicValues`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum PublicValuesError {
    /// The buffer has no more entries to read.
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
}
