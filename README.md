# livy-tee

Intel TDX attestation primitives and higher-level attestation artifacts for the
Livy provenance system.

The crate supports two distinct security models:

- **Instance attestation** uses a raw TDX quote plus Intel Trust Authority
  appraisal. It binds `SHA-256(public_values)` into hardware REPORTDATA.
- **Google Confidential Space** obtains Google, Intel, or dual OIDC tokens from
  the Confidential Space launcher. Signed container claims identify the exact
  workload image and its launch configuration.

These models deliberately make different identity claims. An instance MRTD is
a platform/VM launch measurement that requires an externally supplied reference
policy. It does **not** independently identify the application currently
running inside that VM. Confidential Space workload identity comes from the
signed container image and configuration claims.

## Features

| Feature | Description |
|---|---|
| *(none)* | Low-level quote generation, parsing, and extraction |
| `mock-tee` | Correctly shaped local quote stub |
| `ita-verify` | Instance quote appraisal and JWT verification with Intel Trust Authority |
| `confidential-space` | Confidential Space launcher client and strict OIDC workload verification |
| `attestation` | Shared HTTP/JWKS plumbing enabled by the two attestation features |

The minimum supported Rust version is 1.75.

## Commitment model

`PublicValues` stores ordered, length-prefixed values. The sole
application-controlled attestation input is:

```text
commitment = SHA-256(public_values wire bytes)    // 32 bytes
```

There is no self-reported build ID, build number, version, or application
nonce. Application identity must come from an independently trusted source,
not from bytes that the application writes about itself.

For instance attestation, Intel Trust Authority supplies a verifier nonce and
the hardware REPORTDATA field remains 64 bytes:

```text
REPORTDATA = SHA-512(nonce.val || nonce.iat || commitment)
```

The low-level `generate_evidence(&[u8; 64])` and
`extract_report_data(...) -> [u8; 64]` APIs remain available because TDX
hardware REPORTDATA is intrinsically 64 bytes.

## Instance attestation

Enable `ita-verify`:

```toml
[dependencies]
livy-tee = { version = "0.1", features = ["ita-verify"] }
```

Generate an artifact:

```rust,no_run
use livy_tee::Livy;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let livy = Livy::new(std::env::var("ITA_API_KEY")?);
let mut builder = livy.attest();
builder.commit(&123_u64).commit(&369_u64);

let attestation = builder.finalize().await?;
println!("commitment: {}", attestation.payload_hash_hex());
# Ok(())
# }
```

Verify a stored artifact:

```rust,no_run
# async fn example(attestation: livy_tee::Attestation) -> Result<(), Box<dyn std::error::Error>> {
let report = attestation.verify().await?;
report
    .require_success()
    .map_err(|report| format!("verification failed: {report:?}"))?;
# Ok(())
# }
```

`verify()` authenticates the stored ITA token and recomputes the binding from
`public_values`. `verify_fresh()` additionally sends the bundled evidence back
to ITA for a fresh appraisal.

For non-Azure TDX quotes, the local helper verifies the raw quote binding:

```rust,no_run
# fn example(attestation: &livy_tee::Attestation) -> Result<(), livy_tee::ExtractError> {
let valid = livy_tee::verify_quote_with_public_values(
    &attestation.raw_quote,
    &attestation.verifier_nonce_val,
    &attestation.verifier_nonce_iat,
    &attestation.public_values,
)?;
assert!(valid);
# Ok(())
# }
```

Azure uses ITA's signed `attester_held_data` and
`attester_runtime_data.user-data` claims instead of exposing the same portable
raw-quote check. See [Azure attestation](docs/azure-attestation.md).

### Instance artifact schema

Version 2 contains:

| Field | Meaning |
|---|---|
| `schema_version` | Required integer `2` |
| `ita_token` | ITA-signed appraisal JWT |
| `jwks_url` | Regional ITA JWKS location used when generated |
| `mrtd`, `tcb_status`, `tcb_date`, `advisory_ids` | Public copies checked against authenticated token claims |
| `evidence` | Portable low-level evidence, including Azure runtime JSON where needed |
| `raw_quote` | Base64 raw quote |
| `verifier_nonce_*` | ITA verifier nonce material |
| `public_values` | Values from which the 32-byte commitment is derived |

The artifact does not store a duplicate `runtime_data` value or a structured
`report_data` object. Missing, version-1, or unknown schema versions are
rejected. Legacy artifacts must be verified with the library version that
created them.

## Confidential Space

Enable `confidential-space`:

```toml
[dependencies]
livy-tee = { version = "0.1", features = ["confidential-space"] }
```

Inside a Confidential Space workload:

```rust,no_run
use livy_tee::{
    ConfidentialSpace, ConfidentialSpaceAttesterMode, ConfidentialSpaceConfig,
    PublicValues,
};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let mut values = PublicValues::new();
values.commit(&"input")?.commit(&"output")?;

let config = ConfidentialSpaceConfig::new(
    "https://relying-party.example",
    ConfidentialSpaceAttesterMode::Dual,
);
let client = ConfidentialSpace::new(config);
let artifact = client.attest(values).await?;
# let _ = artifact;
# Ok(())
# }
```

The client connects to `/run/container_launcher/teeserver.sock` and requests
OIDC tokens from:

- Google: `POST /v1/token`
- Intel: `POST /v1/intel/token`

Each request has exactly one nonce:

```json
{
  "audience": "https://relying-party.example",
  "token_type": "OIDC",
  "nonces": ["BASE64URL_NO_PAD_SHA256_PUBLIC_VALUES"]
}
```

The relying party must supply both the expected audience and exact image
digest:

```rust,no_run
use livy_tee::ConfidentialSpaceVerificationPolicy;

# async fn example(
#     artifact: livy_tee::ConfidentialSpaceAttestation,
# ) -> Result<(), Box<dyn std::error::Error>> {
let policy = ConfidentialSpaceVerificationPolicy::new(
    "https://relying-party.example",
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
);
let report = artifact.verify(&policy).await?;
report
    .require_success()
    .map_err(|report| format!("verification failed: {report:?}"))?;
# Ok(())
# }
```

Strict verification requires:

- a valid OIDC signature, expiration, not-before time, fixed issuer, and exact
  audience;
- exactly one `eat_nonce` equal to the encoded commitment;
- the exact verifier-supplied `sha256:…` container image digest;
- `swname == "CONFIDENTIAL_SPACE"`;
- a production image, Secure Boot, `GCP_INTEL_TDX`, `STABLE` support, and
  memory monitoring disabled;
- empty `cmd_override` and `env_override`.

Dual mode independently verifies both tokens and then requires equality of
their common workload and posture claims, including the full signed container
environment. Image-defined environment variables are allowed because valid
Confidential Space tokens normally include them; the pinned image must retain
the default `allow_env_override=false` launch policy. A partial dual result is
never returned by generation, and a missing or disagreeing token fails
`all_passed()`.

See [Confidential Space support](docs/confidential-space.md) for the complete
contract and a digest-pinned TDX deployment walkthrough. Runnable examples are
provided for the
[workload](examples/confidential_space_attest.rs) and
[relying party](examples/confidential_space_verify.rs), together with a
[production-oriented Dockerfile](examples/confidential-space/Dockerfile).

## Low-level quote API

```rust,no_run
let hardware_reportdata = [0x42_u8; 64];
let evidence = livy_tee::generate_evidence(&hardware_reportdata)?;
let extracted = livy_tee::extract_report_data(&evidence)?;
assert_eq!(extracted, hardware_reportdata);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Local extraction parses quote fields; it does not validate the DCAP signature
chain. Use ITA appraisal or another trusted quote verifier for authenticity.

## Public values

```rust
use livy_tee::PublicValues;

let mut values = PublicValues::new();
values.commit(&123_u64).unwrap();
values.commit_raw(b"bytes").unwrap();

let commitment = values.commitment_hash();
assert!(values.verify_commitment(&commitment));

let first: u64 = values.read().unwrap();
let second = values.read_raw().unwrap();
assert_eq!(first, 123);
assert_eq!(second, b"bytes");
```

`AttestBuilder::commit_hashed` hashes the `serde_json` representation of a
value before storing the 32-byte digest. It is useful when the original value
must not be embedded in the public artifact.

## Development

```bash
cargo fmt --check
cargo test --features mock-tee
cargo test --features mock-tee,ita-verify
cargo test --features ita-verify
cargo test --features confidential-space
cargo test --all-features
cargo clippy --all-targets --all-features
```

The live hardware tests are ignored by default. Run them on a TDX guest with
`ITA_API_KEY` configured:

```bash
cargo test --features ita-verify --test tdx_integration -- \
    --ignored --test-threads=1
```

## License

MIT
