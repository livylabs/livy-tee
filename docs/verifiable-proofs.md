# Verifiable commitment proofs

`livy-tee` binds an ordered `PublicValues` buffer to remote attestation. The
version-2 contract intentionally contains one application-controlled binding:

```text
commitment = SHA-256(public_values)
```

The commitment is always 32 bytes.

## Public-values wire format

Each entry is encoded as:

```text
[u32 little-endian payload length][payload bytes]
```

Typed values use `serde_json`; raw entries keep their bytes unchanged. Entry
order and framing are part of the commitment. Verifiers must use the exact
wire bytes rather than re-serializing values in another format.

## Instance TDX proof

Intel Trust Authority supplies a verifier nonce. Before quote generation the
library derives:

```text
REPORTDATA = SHA-512(nonce.val || nonce.iat || commitment)
```

```text
PublicValues ── SHA-256 ──► commitment (32 bytes)
                                  │
ITA nonce.val + nonce.iat ────────┼── SHA-512 ──► REPORTDATA (64 bytes)
                                  │                    │
                                  │                    └── TDX quote
                                  │
                                  └── ITA runtime_data / held_data
```

On standard TDX, ITA's signed `tdx_report_data` and the raw quote REPORTDATA
equal the 64-byte hash.

On Azure:

```text
attester_held_data == commitment
attester_runtime_data.user-data == 64-byte hash
```

The high-level appraisal APIs therefore accept `&[u8; 32]`. The low-level
hardware APIs retain `[u8; 64]`.

## Stored instance artifact

The required schema version is `2`. A stored `Attestation` contains:

- the ITA JWT and matching JWKS location;
- public MRTD/TCB/advisory copies, checked against the signed token;
- portable evidence and a raw quote;
- verifier nonce fields;
- `public_values`.

The verifier derives the commitment from `public_values`. There is no
duplicated `runtime_data` or structured `report_data`, and no self-reported
build ID, version, build number, or application nonce.

Deserialization rejects missing, version-1, and unknown schema versions with
an explicit unsupported-version error. There is no compatibility shim because
silently treating a legacy 64-byte payload as a version-2 commitment would
change the security contract.

## Verification levels

### Local binding

For standard non-Azure TDX evidence:

```rust,no_run
# fn example(attestation: &livy_tee::Attestation) -> Result<(), livy_tee::ExtractError> {
let valid = livy_tee::verify_quote_with_public_values(
    &attestation.raw_quote,
    &attestation.verifier_nonce_val,
    &attestation.verifier_nonce_iat,
    &attestation.public_values,
)?;
# Ok(())
# }
```

This confirms the quote bytes contain the expected hash. It does not
authenticate the DCAP signature chain.

### Stored-token verification

`Attestation::verify()` validates the ITA token signature and registered time
claims, verifies the nonce/commitment binding, and enforces policy. Treat the
returned structure as diagnostics until `all_passed()` or
`require_success()` succeeds.

### Fresh appraisal

`Attestation::verify_fresh()` repeats stored-token verification and submits the
bundled evidence to ITA again. On Azure the portable evidence must include the
original Azure runtime JSON.

## What an instance proof establishes

After strict verification, a relying party can conclude that:

- the authenticated attestation service appraised TDX evidence;
- the evidence is bound to the verifier nonce and the exact public-values
  commitment;
- the authenticated TCB/advisory claims satisfy policy;
- an externally pinned MRTD matches, if the relying party configured one.

MRTD is a platform launch measurement. It does not independently establish the
identity of the application that produced the public values. A build ID placed
into application-controlled REPORTDATA would also be self-reported and would
not solve that problem, which is why version 2 removed it.

## Confidential Space proof

Confidential Space tokens add signed workload identity:

- exact container image digest;
- image ID/reference/signatures;
- container arguments and restart policy;
- operator command and environment override claims;
- Confidential Space software/debug/support posture;
- Secure Boot and Intel TDX hardware model.

The verifier supplies the expected image digest and audience. Neither is
trusted from the artifact itself. Dual mode validates Google and Intel tokens
independently and requires equality of their common workload/posture claims.

Only these signed container claims establish workload identity in the
Confidential Space model. See
[Confidential Space support](confidential-space.md).

## Replay and freshness

Instance freshness comes from the ITA verifier nonce included in the
REPORTDATA hash. Confidential Space binds the commitment as the request's
single `eat_nonce`; a relying party that needs session freshness should include
fresh session material among the committed public values or bind the
attestation exchange to its secure channel.

An application-supplied counter is not a substitute for a verifier challenge
and is not part of the version-2 artifact.
