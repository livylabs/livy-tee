# livy-tee

[![License: PolyForm Noncommercial](https://img.shields.io/badge/license-PolyForm--Noncommercial-blue.svg)](LICENSE)

Intel TDX attestation library for the Livy protocol.

Provides two layers of API:

1. **High-level** — `Livy` client that any program can use to bind its inputs and outputs to a hardware-backed TDX attestation in three lines.
2. **Low-level** — raw primitives for quote generation, REPORTDATA serialization, and local extraction.

The crate is the trust anchor of the Livy stack. Every provenance claim produced by the TEE is rooted in a TDX DCAP quote whose 64-byte `REPORTDATA` field is built and verified using the types here.

---

## Trust model

livy-tee provides **computation attestation**: cryptographic proof that a specific binary processed specific inputs and produced specific outputs inside a genuine Intel TDX enclave.

### What the hardware guarantees

A TDX quote is signed by the CPU's hardware key. It binds three things together:

1. **Binary identity** (MRTD) — the exact measurement of the code running in the TEE. Anyone who builds the same source gets the same MRTD. A different binary, even one bit off, produces a different measurement.
2. **REPORTDATA** (64 bytes) — arbitrary data chosen by the code at attestation time. livy-tee fills this with a `ReportData` struct containing a `payload_hash` (SHA-256 of input+output hashes), a build fingerprint, a version code, and a monotonic nonce.
3. **Intel signature chain** — the quote's ECDSA signature chains back to Intel's root CA via the platform's PCK certificate. Verifiable against Intel PCS without trusting anyone else.

No software — including the host OS, hypervisor, or cloud provider — can forge or tamper with these three bindings once the quote is generated.

### The attestation object

When you call `livy.attest()`, commit values, and call `.finalize().await`, the library:

1. Serializes all committed values into a `public_values` buffer
2. Computes `payload_hash = SHA-256(public_values buffer)`
3. Packs `payload_hash` + build metadata into a 64-byte `ReportData` struct
4. Asks the TDX hardware to generate a quote binding that struct
5. Sends the quote to Intel Trust Authority for verification
6. Returns an `Attestation` containing the quote, the ITA JWT, and the public values

### Privacy and selective disclosure

**Public values are not private.** Anything committed via `.commit()` is stored in plain text inside the `public_values` buffer and is readable by any party who receives the attestation. Only commit data that is intended to be public.

For sensitive inputs that must be bound to the attestation without revealing them, use `.commit_hashed()` — this stores a SHA-256 hash of the value instead of the value itself:

```rust
// Binds the photo bytes to the attestation without revealing them.
builder.commit_hashed(&raw_photo_bytes);

// The verifier recomputes SHA-256(raw_photo_bytes) and checks it matches.
```

A verifier who does not have the raw bytes can still confirm the attestation is genuine (Intel signed it) but cannot learn the original value. The user decides when and to whom they reveal the original data.

### Reconstructing the proof — anyone can verify

This is the key property: given the raw input and output, **any third party** can independently reconstruct the `payload_hash` and verify it matches what's in the TDX quote. No Livy infrastructure needed, no trust in any intermediary.

```
┌─────────┐     ┌──────────┐     ┌───────────────┐
│  User    │     │ Verifier │     │ Intel PCS     │
│          │     │ (anyone) │     │ (public)      │
└────┬─────┘     └────┬─────┘     └───────┬───────┘
     │                │                   │
     │  shares: Proof + raw input/output  │
     │───────────────>│                   │
     │                │                   │
     │                │ 1. SHA-256(input) → input_hash
     │                │ 2. SHA-256(output) → output_hash
     │                │ 3. SHA-256(input_hash ‖ output_hash) → payload_hash
     │                │ 4. Extract REPORTDATA from TDX quote
     │                │ 5. Assert payload_hash == reportdata.payload_hash
     │                │ 6. Assert build_id matches expected binary
     │                │ 7. Assert nonce matches expected counter
     │                │                   │
     │                │  verify quote sig  │
     │                │──────────────────>│
     │                │  ✓ genuine Intel  │
     │                │<──────────────────│
     │                │                   │
     │                │ ✓ Proven: this binary processed
     │                │   this input and produced this output
     │                │   inside a genuine TDX enclave
```

### Example: proving provenance of a photo

```rust
// ── On the TEE server ──────────────────────────────────────────────
let livy = Livy::from_env()?;

let input = raw_photo_bytes;              // original camera capture
let output = provenance_record_bytes;     // the record the server created

// Use commit_hashed for sensitive data — binds by SHA-256 hash, not plaintext.
// Use commit for public metadata that verifiers should be able to read directly.
let mut builder = livy.attest();
builder.commit_hashed(&input);                     // binds photo without revealing it
builder.commit_hashed(&output);                    // binds record without revealing it
builder.commit(&content_hash);                     // public: verifiers can read this
builder.nonce(counter);                            // monotonic — prevents replay
let attestation = builder.finalize().await?;

// Store attestation publicly (on-chain, in C2PA manifest, anywhere).
// Sensitive values are bound by hash — the raw photo is not included.

// ── Later: user wants to prove their photo is authentic ────────────
// They share: the Attestation, the original photo, and the provenance record.

// ── Any verifier, anywhere ─────────────────────────────────────────
use sha2::{Digest, Sha256};

// Read the public content_hash committed in plain text.
let committed_hash: [u8; 32] = attestation.public_values.read(); // skip hashed entries
assert_eq!(committed_hash, expected_content_hash);

// Verify the full chain: public values → REPORTDATA → TDX quote (no network needed).
assert!(attestation.verify().unwrap());

// At this point the verifier knows:
// - The photo and record were processed by the exact binary measured in the quote (MRTD)
// - This happened inside a genuine Intel TDX enclave (hardware guarantee)
// - The attestation hasn't been replayed (nonce is unique and monotonic)
```

### What you can and cannot prove

| Claim | Proven by | How |
|-------|-----------|-----|
| This binary ran in a genuine TDX enclave | TDX quote + Intel PCS signature | Hardware guarantee — unforgeable |
| This binary processed this exact input | `payload_hash` binding in REPORTDATA | Reconstructible from raw bytes |
| This binary produced this exact output | `payload_hash` binding in REPORTDATA | Reconstructible from raw bytes |
| The proof is fresh, not replayed | Application nonce (monotonic counter) | Verifier checks against expected value |
| The quote wasn't relayed from another machine | ITA verifier nonce | Intel Trust Authority checks server-side |
| The input data is authentic (e.g. a real photo) | **Not proven by livy-tee alone** | Requires additional trust anchors (App Attest, Secure Enclave, C2PA) |

livy-tee proves computation integrity — "this code processed this data inside a TEE." Proving the input itself is authentic (e.g. it came from a real camera on a real device) requires the layers above: Apple Secure Enclave for device identity, App Attest for device genuineness, and C2PA for content provenance metadata.

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

    // 3. Commit values and generate a TDX attestation.
    //    commit()       — stores value in plain text (public, readable by anyone)
    //    commit_hashed() — stores SHA-256(value) (binds without revealing)
    let mut builder = livy.attest();
    builder.commit_hashed(input);   // bind input by hash — not revealed in attestation
    builder.commit_hashed(output);  // bind output by hash — not revealed in attestation
    let attestation = builder.finalize().await?;

    println!("ita_token:    {}", attestation.ita_token);
    println!("mrtd:         {}", attestation.mrtd);
    println!("tcb_status:   {}", attestation.tcb_status);
    println!("payload_hash: {}", attestation.payload_hash_hex());

    // Locally verify the full chain — no network needed.
    assert!(attestation.verify().unwrap());
    Ok(())
}
```

Run inside a TDX VM:
```bash
ITA_API_KEY=<your-key> ./your-binary
```

---

## The attestation

`builder.finalize().await` returns an `Attestation` containing:

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
| `public_values` | All values committed via `.commit()` / `.commit_hashed()`. **Plain-text** — readable by any party with the attestation. |

### Payload hash

The 32-byte `payload_hash` embedded in the `ReportData` struct (and stored in `runtime_data`) is:

```
payload_hash = SHA-256(public_values buffer)
```

The `public_values` buffer is the concatenation of all length-prefixed serialized entries committed via `.commit()` or `.commit_hashed()`. This is deterministic and reproducible — no Livy infrastructure needed.

---

## External / independent verification

Any third party who has the attestation and the `public_values` buffer can verify the binding without contacting Livy or Intel:

```rust
use livy_tee::verify_quote_with_public_values;

// Full chain verification via raw DCAP quote.
// Checks: SHA-512(nonce_val ‖ nonce_iat ‖ runtime_data) == quote REPORTDATA
//     AND: SHA-256(public_values buffer) == ReportData.payload_hash
let ok = verify_quote_with_public_values(
    &attestation.raw_quote,
    &attestation.runtime_data,        // base64 of our 64-byte ReportData struct
    &attestation.verifier_nonce_val,  // base64 of ITA verifier nonce val
    &attestation.verifier_nonce_iat,  // base64 of ITA verifier nonce iat
    &attestation.public_values,
)?;
assert!(ok);

// Or use the method form — identical check:
assert!(attestation.verify().unwrap());
```

### Step-by-step manual verification recipe

1. Obtain the `raw_quote` (base64-decode it) and `runtime_data` (base64-decode it → 64 bytes).
2. Obtain `verifier_nonce_val` and `verifier_nonce_iat` (base64-decode each).
3. Extract bytes `[568..632]` from the quote — the REPORTDATA field (= SHA-512 hash).
4. Recompute `SHA-512(nonce_val ‖ nonce_iat ‖ runtime_data)` and assert it matches step 3.
5. Parse `runtime_data` bytes: `ReportData::from_bytes(&bytes)`.
6. Recompute `SHA-256(public_values buffer)` from the raw public values bytes.
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
    build_id_from_hash_hex(&binary_hash()?), // [u8; 8]
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

### Verifying a quote built with the low-level API

If you computed your own `payload_hash` without `PublicValues` — for example,
`SHA-256(SHA-256(input) ‖ SHA-256(output))` — use `verify_quote` directly:

```rust
use livy_tee::verify_quote;

// Checks: SHA-512(nonce_val ‖ nonce_iat ‖ runtime_data) == quote REPORTDATA
//     AND: ReportData.payload_hash == expected_payload_hash
let ok = verify_quote(
    &attested_b64_quote,
    &attested_b64_runtime_data,
    &attested_b64_nonce_val,
    &attested_b64_nonce_iat,
    &expected_payload_hash,    // [u8; 32] — whatever you put in ReportData
)?;
assert!(ok);
```

For the high-level commit/read model, use `verify_quote_with_public_values` or
`Attestation::verify()` instead — both compute the `payload_hash` from the
`PublicValues` buffer automatically.

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
let mut builder = livy.attest();
builder.commit_hashed(request_bytes);
builder.commit_hashed(response_bytes);
builder.nonce(counter);   // monotonically increasing — increment per request
let attestation = builder.finalize().await?;

// Verifier checks: stored_nonce_for_this_request == attestation.report_data.nonce
```

Defaults to `0` if `.nonce()` is not called — acceptable for single-request workloads.

### Summary

| | ITA verifier nonce | Application nonce |
|---|---|---|
| Issued by | Intel Trust Authority | Developer's application |
| Prevents | Quote theft across machines | Attestation reuse across requests |
| Verified by | ITA (server-side) + `verify_quote_with_public_values` (locally) | Application logic |
| Location in attestation | `verifier_nonce_val` / `verifier_nonce_iat` | `report_data.nonce` |

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
├── bind.rs          High-level Livy API (Livy, AttestBuilder, Attestation, verify_quote_with_public_values)
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
