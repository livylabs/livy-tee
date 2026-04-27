# livy-tee

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`livy-tee` is a Rust library for generating Intel TDX attestations, binding
application-visible values into them, and verifying the resulting Intel Trust
Authority (ITA) token.

It exposes two layers:

1. High-level API: [`Livy`], [`AttestBuilder`], [`Attestation`]
2. Low-level API: [`Evidence`], [`ReportData`], quote extraction helpers, and
   ITA helpers

## Trust model

`livy-tee` proves TDX-backed computation integrity, not input authenticity.

At a high level:

- the TDX measurement (`mrtd`) identifies which binary ran
- `public_values` and `report_data.nonce` identify what was bound into the attestation
- the ITA token reports the TCB status and advisory set for that attestation

What it does not prove:

- that an input came from a real device or user
- that an external system stored or delivered the attestation correctly

Verification modes:

- `verify()` trusts the stored signed ITA token and checks local bindings
- `verify_fresh()` also reappraises the bundled evidence artifact with ITA

## What the library proves

At a high level, `livy-tee` lets you prove:

- which TDX-measured binary ran (`mrtd`)
- which public values were committed (`public_values`)
- which application nonce was embedded (`report_data.nonce`)
- which ITA TCB status and advisory set were observed

It does **not** prove that an input itself is authentic. For example, a photo
being signed by a real camera or device needs additional trust anchors above
this library.

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| *(none)* | yes | Runtime provider auto-detection: Azure vTPM/paravisor or Linux TSM configfs |
| `mock-tee` | no | Correctly-shaped quote stub for local development |
| `ita-verify` | no | High-level attestation API and Intel Trust Authority integration |

## Runtime behavior

No cloud-provider flag is needed. `livy-tee` auto-detects the runtime:

- Azure CVMs use the native Azure vTPM/paravisor path
- other Linux TDX guests use TSM configfs

Azure-specific notes:

- no `tpm2-tools` or `curl` dependency is required
- `Evidence` preserves Azure runtime JSON
- `verify()` uses Azure-specific ITA token binding claims
- `verify_fresh()` is the strict path for authenticating bundled Azure evidence

Non-Azure Linux TDX notes:

- quote generation uses `/sys/kernel/config/tsm/report`
- local offline binding is available via `verify_binding()` and
  `verify_quote_with_public_values()`

### Running without `sudo` on Linux TDX guests

On GCP and other non-Azure Linux TDX guests, the VM may expose
`/dev/tdx_guest` and `/sys/kernel/config/tsm/report` as root-owned. The
practical non-`sudo` setup is:

- create a dedicated group such as `tdx-attest`
- grant `/dev/tdx_guest` to that group with a udev rule
- reapply group ownership and write permissions to
  `/sys/kernel/config/tsm/report` at boot with a small systemd unit

That keeps the application process unprivileged. A stricter production option
is a small privileged quote-broker service on a Unix socket.

## Quick start

Add to `Cargo.toml`:

```toml
[dependencies]
livy-tee = { version = "0.1", features = ["ita-verify"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Example:

```rust
use livy_tee::Livy;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let livy = Livy::from_env()?;

    let input = 123u64;
    let output = input * 3;

    let mut builder = livy.attest();
    builder.commit(&input).commit(&output).nonce(1);

    let attestation = builder.finalize().await?;

    let report = attestation.verify().await?;
    report.require_success()?;

    let committed_input: u64 = attestation.public_values.read()?;
    let committed_output: u64 = attestation.public_values.read()?;

    assert_eq!(committed_input, 123);
    assert_eq!(committed_output, 369);
    Ok(())
}
```

Run inside a TDX VM:

```bash
ITA_API_KEY=<your-key> cargo run --release
```

## High-level API

### `Livy`

`Livy` holds an `ItaConfig` and starts the attestation flow:

```rust
use livy_tee::{ItaConfig, Livy};

let livy = Livy::from_env()?;
let livy = Livy::new("your-ita-api-key");
let livy = Livy::with_config(ItaConfig {
    api_key: "your-ita-api-key".to_string(),
    ..ItaConfig::default()
});
```

### `AttestBuilder`

Use `livy.attest()` to create a builder, then:

- `commit(&value)` for public typed values
- `commit_hashed(&value)` for `SHA-256(serde_json(value))`
- `commit_raw(bytes)` for raw bytes
- `nonce(n)` for the application nonce
- `finalize().await` to generate the attestation

Important: `.commit()` stores plaintext. Only commit values that are intended
to be public.

### `Attestation`

`finalize().await` returns an [`Attestation`] that can be stored, serialized,
transmitted, and verified later.

Key fields:

| Field | Meaning |
|-------|---------|
| `ita_token` | ITA-signed JWT |
| `jwks_url` | JWKS URL associated with the token region |
| `mrtd` | Hex-encoded TDX measurement |
| `tcb_status` / `tcb_date` / `advisory_ids` | ITA appraisal result |
| `evidence` | Portable evidence artifact; Azure includes runtime JSON |
| `raw_quote` | Base64 raw quote |
| `runtime_data` | Base64 encoded 64-byte `ReportData` |
| `verifier_nonce_*` | Stored ITA verifier nonce fields |
| `report_data` | Parsed `ReportData` |
| `public_values` | Ordered public-values buffer |

## Verification model

| Method | What it checks | Network |
|--------|----------------|---------|
| `verify_binding()` | Local quote/runtime/public-values binding only | No |
| `verify()` | ITA JWT/JWKS + policy + local binding where portable | Yes |
| `verify_fresh()` | `verify()` plus fresh ITA reappraisal of bundled evidence | Yes |

### `verify_binding()`

Offline helper for local quote binding:

```rust
let ok = attestation.verify_binding()?;
assert!(ok);
```

Use this only when you want the local quote/runtime/public-values relationship.
It does not verify the ITA token or TCB policy.

### `verify()`

Normal full verifier:

```rust
let report = attestation.verify().await?;
report.require_success()?;
```

This validates:

- ITA JWT signature and registered time claims
- token-side binding to the stored nonce and `runtime_data`
- local quote binding where that is portable
- `public_values` commitment
- default TCB policy (`UpToDate`)

### `verify_fresh()`

Strict path:

```rust
let verify_config = livy_tee::ItaConfig {
    api_key: std::env::var("ITA_API_KEY")?,
    ..livy_tee::ItaConfig::default()
};

let report = attestation.verify_fresh(&verify_config).await?;
report.require_success()?;
```

This reappraises the bundled evidence artifact with ITA and sets
`bundled_evidence_authenticated`.

## Policies

Use [`AttestationVerificationPolicy`] when you need to pin token metadata or
relax the default `UpToDate` policy intentionally.

```rust
use livy_tee::{AttestationVerificationPolicy, binary_hash, build_id_from_hash_hex};

let mut policy = AttestationVerificationPolicy::default();
policy.expected_mrtd = Some(expected_mrtd.to_string());
policy.expected_build_id = Some(build_id_from_hash_hex(&binary_hash()?)?);
policy.expected_nonce = Some(expected_nonce);
policy.expected_token_issuer =
    livy_tee::default_issuer_for_jwks_url(&attestation.jwks_url);
policy.expected_token_audience = Some("your-verifier".to_string());

let report = attestation.verify_with_policy(&policy).await?;
report.require_success()?;
```

For an environment that currently appraises as `OutOfDate`, pin the exact
advisory set you intend to allow:

```rust
let mut policy = AttestationVerificationPolicy::default();
policy.accepted_tcb_statuses = vec!["OutOfDate".to_string()];
policy.expected_advisory_ids = Some(vec![
    "INTEL-SA-01192".to_string(),
    "INTEL-SA-01245".to_string(),
    "INTEL-SA-01312".to_string(),
    "INTEL-SA-01313".to_string(),
]);

let report = attestation.verify_with_policy(&policy).await?;
report.require_success()?;
```

Use the exact advisory IDs returned by your target environment. Treat that
allowlist as operational policy, not a fixed library constant.

## Public values

`PublicValues` is the ordered buffer behind `commit`, `commit_hashed`, and
`commit_raw`.

Read values back in commit order:

```rust
let input: u64 = attestation.public_values.read()?;
let output: u64 = attestation.public_values.read()?;
let hash = attestation.public_values.read_raw()?;
```

Important semantics:

- `commit(&value)` stores `serde_json(value)` as a framed entry
- `commit_hashed(&value)` stores `SHA-256(serde_json(value))` as a raw 32-byte entry
- `read()` is for JSON entries
- `read_raw()` is for raw/hash entries

Transport and reconstruction:

- `from_bytes()` for trusted local bytes
- `try_from_bytes()` for untrusted decoded bytes
- `from_base64()` for transport form

## Low-level API

### `ReportData`

`ReportData` is the 64-byte `runtime_data` payload sent to ITA.

```rust
use livy_tee::{binary_hash, build_id_from_hash_hex, ReportData, REPORT_DATA_VERSION};

let rd = ReportData::new(
    payload_hash,
    build_id_from_hash_hex(&binary_hash()?)?,
    REPORT_DATA_VERSION,
    0,
    nonce,
);

let bytes = rd.to_bytes();
let parsed = ReportData::from_bytes(&bytes);
assert!(parsed.verify_payload(&payload_hash));
```

### Quote generation

```rust
use livy_tee::generate_evidence;

let evidence = generate_evidence(&rd.to_bytes())?;
```

### Local extraction

```rust
use livy_tee::{extract_mrtd, extract_report_data};

let report_data = extract_report_data(&evidence)?;
let mrtd = extract_mrtd(&evidence)?;
```

### Offline quote verification

If you already have the expected payload hash:

```rust
use livy_tee::verify_quote;

let ok = verify_quote(
    &raw_quote_b64,
    &runtime_data_b64,
    &nonce_val_b64,
    &nonce_iat_b64,
    &expected_payload_hash,
)?;
assert!(ok);
```

If you want the hash derived from `PublicValues`:

```rust
use livy_tee::verify_quote_with_public_values;

let ok = verify_quote_with_public_values(
    &attestation.raw_quote,
    &attestation.runtime_data,
    &attestation.verifier_nonce_val,
    &attestation.verifier_nonce_iat,
    &attestation.public_values,
)?;
assert!(ok);
```

### Low-level ITA helpers

`generate_and_attest()` combines quote generation and ITA appraisal:

```rust
use livy_tee::{generate_and_attest, ItaConfig};

let config = ItaConfig {
    api_key: std::env::var("ITA_API_KEY")?,
    ..ItaConfig::default()
};

let attested = generate_and_attest(&rd.to_bytes(), &config).await?;
println!("mrtd = {}", attested.mrtd);
println!("tcb_status = {}", attested.tcb_status);
```

If you need raw token-side binding inspection without authenticating the JWT:

```rust
use livy_tee::unauthenticated_report_data_hash_from_token;

if let Some(binding_hash) = unauthenticated_report_data_hash_from_token(&ita_token)? {
    println!("{}", hex::encode(binding_hash));
}
```

That helper is for low-level inspection only. It does not verify the JWT.

## Development

```bash
# Local development without hardware
cargo build --features mock-tee
cargo test --features mock-tee

# Full library tests
cargo test
cargo test --features mock-tee,ita-verify

# Rustdoc
cargo rustdoc --all-features --lib -- -D missing-docs
```

In `mock-tee` mode, evidence generation returns a correctly-shaped stub quote.
Real ITA appraisal is skipped.

## Architecture

```text
livy-tee
├── bind/
│   ├── mod.rs            High-level API entry point
│   ├── attestation.rs    Livy, AttestBuilder, Attestation, verification
│   └── local.rs          Local quote/public-values binding helpers
├── report.rs             ReportData wire format + build_id helpers
├── evidence.rs           Evidence type + portable transport
├── generate/
│   ├── mod.rs            generate_evidence, binary_hash
│   ├── azure.rs          Azure vTPM/paravisor path
│   ├── tsm.rs            Linux TSM configfs path
│   └── mock.rs           Mock quote stub
├── attest.rs             generate_and_attest
└── verify/
    ├── extract.rs        Local quote field extraction
    ├── codec.rs          Shared decoding helpers
    └── ita.rs            Intel Trust Authority helpers
```

## License

livy-tee is released under the [MIT License](LICENSE).
