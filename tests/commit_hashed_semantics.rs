// SPDX-License-Identifier: MIT
//! commit_hashed interoperability and wire-contract tests.
//!
//! Run with: cargo test --test commit_hashed_semantics --features mock-tee,ita-verify
#![cfg(all(feature = "ita-verify", feature = "mock-tee"))]

use livy_tee::Livy;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct SampleStruct<'a> {
    id: u32,
    label: &'a str,
    bytes: Vec<u8>,
}

async fn hashed_entry_for<T: Serialize>(value: &T) -> [u8; 32] {
    let livy = Livy::new("mock-key");
    let mut builder = livy.attest();
    builder.commit_hashed(value);
    let attestation = builder.finalize().await.expect("finalize should succeed");
    let raw = attestation
        .public_values
        .read_raw()
        .expect("hashed entry should be readable");
    raw.as_slice()
        .try_into()
        .expect("commit_hashed should store a 32-byte digest")
}

fn expected_hash<T: Serialize>(value: &T) -> [u8; 32] {
    let encoded = serde_json::to_vec(value).expect("test serialization");
    Sha256::digest(encoded).into()
}

#[derive(Serialize)]
struct SessionBinding<'a> {
    user: &'a str,
    sequence: u64,
    scopes: &'a [&'a str],
}

#[tokio::test]
async fn commit_hashed_vec_u8_uses_serde_json_bytes() {
    let value = vec![1u8, 2, 3, 255];
    let observed = hashed_entry_for(&value).await;
    let raw_bytes_hash: [u8; 32] = Sha256::digest(&value).into();

    assert_eq!(observed, expected_hash(&value));
    assert_ne!(observed, raw_bytes_hash);
}

#[tokio::test]
async fn commit_hashed_slice_u8_matches_vec_u8_semantics() {
    let vec_value = vec![9u8, 8, 7, 6];
    let slice_value: &[u8] = &vec_value;

    let vec_hash = hashed_entry_for(&vec_value).await;
    let slice_hash = hashed_entry_for(&slice_value).await;

    assert_eq!(vec_hash, expected_hash(&vec_value));
    assert_eq!(slice_hash, expected_hash(&slice_value));
    assert_eq!(vec_hash, slice_hash);
}

#[tokio::test]
async fn commit_hashed_string_uses_json_string_encoding() {
    let value = String::from("hello, livy");
    let observed = hashed_entry_for(&value).await;
    let raw_bytes_hash: [u8; 32] = Sha256::digest(value.as_bytes()).into();

    assert_eq!(observed, expected_hash(&value));
    assert_ne!(observed, raw_bytes_hash);
}

#[tokio::test]
async fn commit_hashed_struct_uses_json_object_encoding() {
    let value = SessionBinding {
        user: "alice",
        sequence: 17,
        scopes: &["quote:read", "quote:verify"],
    };
    let observed = hashed_entry_for(&value).await;

    assert_eq!(observed, expected_hash(&value));
}

#[tokio::test]
async fn commit_hashed_struct_uses_serde_json_object_encoding() {
    let value = SampleStruct {
        id: 7,
        label: "proof",
        bytes: vec![1, 2, 3],
    };

    let observed = hashed_entry_for(&value).await;

    assert_eq!(observed, expected_hash(&value));
}
