# livy-tee

[![License: PolyForm Noncommercial](https://img.shields.io/badge/license-PolyForm--Noncommercial-blue.svg)](LICENSE)

Intel TDX attestation library for the Livy protocol.

Provides two layers of API:

1. **High-level** — `Livy` client that any program can use to bind its inputs and outputs to a hardware-backed TDX attestation in three lines.
2. **Low-level** — raw primitives for quote generation, REPORTDATA serialization, and local extraction.

The crate is the trust anchor of the Livy stack. Every provenance claim produced by the TEE is rooted in a TDX DCAP quote whose 64-byte `REPORTDATA` field is built and verified using the types here.

---

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| *(none)* | yes | TSM configfs quote generation — requires TDX hardware (Linux kernel ≥ 6.7) |
| `mock-tee` | no | Correctly-shaped DCAP quote stub — no hardware required, for development |
| `ita-verify` | no | Intel Trust Authority REST API client + high-level `Livy` API |

---

## Quick start — attesting any program

Add to `Cargo.toml`:

```toml
[dependencies]
livy-tee = { version = "0.1", features = ["ita-verify"] }
tokio    = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Then in `main.rs`:

```rust
use livy_tee::Livy;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize — reads ITA_API_KEY from the environment.
    let livy = Livy::from_env()?;

    // 2. Your program logic.
    let input  = b"user request or input data";
    let output = b"computed result or output data";

    // 3. Bind input + output to a TDX attestation.
    let proof = livy.attest()
        .input(input)
        .output(output)
        .commit()
        .await?;

    println!("ita_token:    {}", proof.ita_token);
    println!("mrtd:         {}", proof.mrtd);
    println!("tcb_status:   {}", proof.tcb_status);
    println!("payload_hash: {}", proof.payload_hash_hex());

    // Locally verify the proof covers these exact bytes — no network needed.
    assert!(proof.verify_binding(input, output));
    Ok(())
}
```

Run inside a TDX VM:
```bash
ITA_API_KEY=<your-key> ./your-binary
```

---

## The proof

`livy.attest().commit()` returns a `Proof` containing:

| Field | Description |
|-------|-------------|
| `ita_token` | ITA-signed JWT. Verifiable against Intel's JWKS endpoint. Contains MRTD, REPORTDATA (SHA-512 hash), and TCB status. |
| `mrtd` | Hex-encoded 48-byte measurement of the TEE binary. Anyone who builds the same binary can compute and compare this independently. |
| `tcb_status` | `"UpToDate"` — fully patched. `"OutOfDate"` — firmware update available (quote still valid). `"Revoked"` — hardware revoked. |
| `raw_quote` | Base64-encoded raw DCAP quote (~8 KB). REPORTDATA = SHA-512(nonce.val ‖ nonce.iat ‖ runtime_data). |
| `runtime_data` | Base64-encoded original 64-byte ReportData struct (our structured payload sent to ITA). |
| `verifier_nonce_val` | Base64-encoded verifier nonce value (from ITA GET /nonce, used in REPORTDATA computation). |
| `verifier_nonce_iat` | Base64-encoded verifier nonce issued-at (from ITA GET /nonce, used in REPORTDATA computation). |
| `report_data` | Structured `ReportData` — parsed from `runtime_data` bytes. Contains `payload_hash`, `build_id`, etc. |
| `input_hash` | SHA-256 of the input bytes (or `[0u8;32]` if no input was bound). |
| `output_hash` | SHA-256 of the output bytes (or `[0u8;32]` if no output was bound). |

### Payload hash

The 32-byte `payload_hash` embedded in the `ReportData` struct (and stored in `runtime_data`) is:

```
payload_hash = SHA-256( SHA-256(input) ‖ SHA-256(output) )
```

This is deterministic and reproducible from the original bytes — no Livy infrastructure needed.

---

## External / independent verification

Any third party who has the proof and the original data can verify the binding without contacting Livy or Intel:

```rust
use livy_tee::{verify_quote, payload_hash_for};

// Full Intel CLI-compatible verification via raw DCAP quote.
// Checks: SHA-512(nonce_val ‖ nonce_iat ‖ runtime_data) == quote REPORTDATA
//     AND: ReportData.payload_hash == SHA-256(SHA-256(input) ‖ SHA-256(output))
let ok = verify_quote(
    &proof.raw_quote,
    &proof.runtime_data,        // base64 of our 64-byte ReportData struct
    &proof.verifier_nonce_val,  // base64 of ITA verifier nonce val
    &proof.verifier_nonce_iat,  // base64 of ITA verifier nonce iat
    input,
    output,
)?;
assert!(ok);

// Recompute the expected payload_hash from scratch.
let expected_hash = payload_hash_for(input, output); // [u8; 32]
assert_eq!(expected_hash, proof.report_data.payload_hash);
```

### Step-by-step manual verification recipe

1. Obtain the `raw_quote` (base64-decode it) and `runtime_data` (base64-decode it → 64 bytes).
2. Obtain `verifier_nonce_val` and `verifier_nonce_iat` (base64-decode each).
3. Extract bytes `[568..632]` from the quote — the REPORTDATA field (= SHA-512 hash).
4. Recompute `SHA-512(nonce_val ‖ nonce_iat ‖ runtime_data)` and assert it matches step 3.
5. Parse `runtime_data` bytes: `ReportData::from_bytes(&bytes)`.
6. Recompute: `SHA-256(SHA-256(input) ‖ SHA-256(output))`.
7. Assert `rd.verify_payload(&expected_hash)`.
8. Assert `rd.build_id == build_id_from_hash_hex(&tee_binary_hash)` — confirms which binary ran.
9. Assert `rd.nonce == expected_nonce` — replay protection.
10. *(Optional)* Verify the ITA JWT signature against Intel's JWKS endpoint at `https://portal.trustauthority.intel.com/certs`.

---

## REPORTDATA wire layout

The TDX DCAP quote at bytes `[568..632]` holds a 64-byte REPORTDATA field constructed as:

```
REPORTDATA = SHA-512( nonce.val ‖ nonce.iat ‖ runtime_data )
```

where `nonce` is the ITA verifier nonce (anti-relay) and `runtime_data` is our structured 64-byte payload:

```
runtime_data (64 bytes) — our ReportData struct:

Bytes    Size  Field         Description
─────    ────  ─────         ───────────
00..32    32   payload_hash  SHA-256( SHA-256(input) ‖ SHA-256(output) )
32..40     8   build_id      SHA-256(TEE binary)[0..8] — short build fingerprint
40..44     4   version_code  u32 BE — schema version (increment on layout changes)
44..48     4   build_number  u32 BE — CI build counter (0 in development)
48..56     8   nonce         u64 BE — monotonic counter for replay protection
56..64     8   reserved      Zero-filled
```

`payload_hash` is domain-agnostic — the struct has no opinion on what those 32 bytes represent. The formula above (`SHA-256(SHA-256(input) ‖ SHA-256(output))`) is what `Livy::attest()` uses. You can substitute your own deterministic encoding when using the low-level API directly.

The two-level construction mirrors the Intel Go `trustauthority-cli`:
- ITA verifies server-side: `SHA-512(nonce.val ‖ nonce.iat ‖ runtime_data) == REPORTDATA in quote`
- External verifiers reconstruct the same check locally with `verify_quote`

---

## Low-level API

### Building REPORTDATA manually

```rust
use livy_tee::{binary_hash, report::{build_id_from_hash_hex, ReportData, REPORT_DATA_VERSION}};

let rd = ReportData::new(
    payload_hash,                           // [u8; 32] — your hash
    build_id_from_hash_hex(&binary_hash()?)?, // [u8; 8]
    REPORT_DATA_VERSION,                    // u32 — currently 1
    0,                                      // build_number (0 in dev)
    nonce,                                  // u64 — monotonic counter
);

let bytes: [u8; 64] = rd.to_bytes();   // serialize to wire format
let rd2 = ReportData::from_bytes(&bytes);
assert!(rd2.verify_payload(&expected_hash));
```

### Quote generation

```rust
use livy_tee::generate_evidence;

// mock-tee: 632-byte stub. Real TDX: 8000-byte DCAP quote from TSM configfs.
let evidence = generate_evidence(&rd.to_bytes())?;
```

### Local field extraction (no network)

```rust
use livy_tee::{extract_report_data, extract_mrtd};

let rd_bytes: [u8; 64] = extract_report_data(&evidence)?;
let mrtd: [u8; 48]     = extract_mrtd(&evidence)?;
```

### Combined generation + ITA verification

```rust
use livy_tee::{generate_and_attest, ItaConfig};

let config = ItaConfig {
    api_key: "your-key".to_string(),
    ..ItaConfig::default()
};
let attested = generate_and_attest(&rd.to_bytes(), &config).await?;
// attested.ita_token    — ITA JWT
// attested.mrtd         — hex MRTD from JWT
// attested.tcb_status   — "UpToDate" / "OutOfDate" / "Revoked"
// attested.evidence     — raw DCAP quote (REPORTDATA = SHA-512 hash)
// attested.runtime_data — original 64-byte ReportData struct
// attested.nonce_val    — decoded verifier nonce val bytes
// attested.nonce_iat    — decoded verifier nonce iat bytes
```

### Extracting REPORTDATA from an ITA JWT

```rust
use livy_tee::report_data_from_token;

// No network, no TDX hardware.
if let Some(rd) = report_data_from_token(&ita_token)? {
    println!("payload_hash: {}", hex::encode(rd.payload_hash));
    println!("nonce:        {}", rd.nonce);
}
```

---

## Nonces

There are two distinct nonces in every proof. They protect against different attacks
at different layers.

### 1. ITA verifier nonce — anti-relay at the quote level

**Fields:** `Proof.verifier_nonce_val`, `Proof.verifier_nonce_iat`
**Issued by:** Intel Trust Authority (`GET /appraisal/v2/nonce`)
**Scope:** prevents a DCAP quote from being replayed to ITA from a different machine or session

Without this nonce, an attacker could capture a valid DCAP quote from any TDX machine
and re-submit it to ITA on behalf of a different request — ITA would accept it because
the PCK certificate chain is valid regardless of who submitted it.

`commit()` fetches this nonce automatically before generating the quote and bakes it in:

```
REPORTDATA = SHA-512(nonce.val ‖ nonce.iat ‖ runtime_data)
```

ITA verifies server-side that the REPORTDATA matches this computation. A replayed quote
from another machine will have a different REPORTDATA and be rejected.

### 2. Application nonce — anti-replay at the request level

**Field:** `Proof.report_data.nonce` (bytes `[48..56]` of `runtime_data`, u64 big-endian)
**Issued by:** the developer's application via `.nonce(n)`
**Scope:** prevents a valid proof from being reused across different requests

Without this nonce, an attacker could save the proof from request #1 and replay it
as the response to request #100. Both would have a valid ITA JWT and a correct
payload hash.

```rust
// Application maintains a persistent counter (e.g. in a database).
let proof = livy.attest()
    .input(request_bytes)
    .output(response_bytes)
    .nonce(counter)   // monotonically increasing — increment per request
    .commit()
    .await?;

// Verifier checks: stored_nonce_for_this_request == proof.report_data.nonce
```

Defaults to `0` if `.nonce()` is not called — acceptable for single-request workloads.

### Summary

| | ITA verifier nonce | Application nonce |
|---|---|---|
| Issued by | Intel Trust Authority | Developer's application |
| Prevents | Quote theft across machines | Proof reuse across requests |
| Verified by | ITA (server-side) + `verify_quote` (locally) | Application logic |
| Location in proof | `verifier_nonce_val` / `verifier_nonce_iat` | `report_data.nonce` |

The two are complementary: the ITA nonce pins the quote to a specific ITA session;
the application nonce pins the proof to a specific request slot.

---

## ITA v2 wire protocol notes

### GET /appraisal/v2/nonce

Fetches an anti-replay verifier nonce before quote generation:

```
Headers: x-api-key: <api_key>
Response: { "val": "<base64>", "iat": "<base64>", "signature": "<base64>" }
```

### POST /appraisal/v2/attest (Intel CLI-compatible)

| Property | v1 | v2 (old) | v2 (with nonce) |
|----------|----|----|-----|
| Request body | `{"quote": "<base64url>"}` | `{"tdx": {"quote": "<base64url>"}}` | `{"tdx": {"quote": "...", "runtime_data": "...", "verifier_nonce": {...}}}` |
| Response body | Raw JWT string | `{"token": "<JWT>"}` JSON envelope | same |
| JWT claim location | Top-level | Nested under `"tdx"` | same |
| JWT `tdx_report_data` | base64 of raw struct | **hex** of raw struct | **hex** of SHA-512 hash |
| ITA server-side binding | ❌ | ❌ | ✅ `SHA-512(nonce.val ‖ nonce.iat ‖ runtime_data) == REPORTDATA` |

This crate implements the nonce flow and handles all v2 specifics internally.

---

## Development (no TDX hardware)

```bash
# Compile check
cargo build --features mock-tee

# Tests (ReportData serialization, extraction, error paths)
cargo test --features mock-tee

# Compile-check the smoke test example
cargo build --example tee_verify --features mock-tee
```

In `mock-tee` mode, `generate_evidence` returns a correctly-shaped 632-byte DCAP v4 quote stub. The ITA call is skipped (mock quotes are rejected by real ITA), so `ita_token` is empty. All local extraction functions (`extract_report_data`, `extract_mrtd`) work identically on mock and real quotes.

---

## Architecture

```
livy-tee
├── bind.rs          High-level Livy API (Livy, AttestBuilder, Proof, verify_quote, verify_token)
├── report.rs        ReportData wire format + build_id helpers
├── evidence.rs      Evidence type (wraps raw DCAP quote bytes)
├── generate/
│   ├── mod.rs       generate_evidence, binary_hash
│   ├── tsm.rs       TSM configfs implementation (real TDX)
│   └── mock.rs      Mock quote stub (--features mock-tee)
├── attest.rs        generate_and_attest (generation + ITA in one call)
└── verify/
    ├── extract.rs   extract_report_data, extract_mrtd (local, no network)
    └── ita.rs       Intel Trust Authority v2 REST client, report_data_from_token
```

The high-level `Livy` API in `bind.rs` is a thin layer over `attest.rs`, which combines `generate/` and `verify/ita.rs`. The low-level modules are independently usable.

---

## License

livy-tee is source-available under the [PolyForm Noncommercial License 1.0.0](LICENSE).

Free for personal use, research, education, non-profit organizations, and government institutions. Commercial use requires a separate license — contact [license@livylabs.xyz](mailto:license@livylabs.xyz).
