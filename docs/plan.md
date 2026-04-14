# Verification status

Current branch: `feat/full-attestation-verification`

Last updated: `2026-04-14`

This is the current-state snapshot for the verifier, Azure support, and test
surface. It records what is already validated and what remains as follow-up.

For the actionable execution tracker, see `docs/remediation-plan.md`.
For the Azure-specific reference, see `docs/azure-attestation.md`.

---

## Validated now

### What is working

- Full ITA-backed token verification works for standard and Azure attestations.
- Azure attestation generation and `/appraisal/v2/attest/azure` verification pass
  on a real Azure CVM.
- Low-level Azure evidence is portable through `Evidence::to_transport_string()`
  / `Evidence::from_transport_string()`.
- High-level `Attestation` now preserves portable evidence in `attestation.evidence`.
- `Attestation::verify_fresh()` now reappraises the bundled evidence via ITA and
  authenticates the stored evidence artifact, including Azure evidence.
- `PublicValues` now has explicit validation APIs for untrusted buffers.
- JWT failure-mode coverage exists for expired tokens, future `nbf`, wrong `kid`,
  and unsupported signing algorithms.
- `commit_hashed()` interoperability semantics are locked down for `Vec<u8>`,
  `&[u8]`, and `String`.
- Default local contributor commands are fixed again:
  - `cargo test`
  - `cargo test --tests --no-default-features`
  - `cargo test --features mock-tee,ita-verify`
  - `cargo clippy --features mock-tee,ita-verify --all-targets -- -D warnings`

### Live verification that passed

- Azure CVM: `cargo test --test signed_verification --features ita-verify`
- Azure CVM: `cargo test --test tdx_integration --no-default-features --features ita-verify -p livy-tee -- --nocapture --test-threads=1`
- Azure CVM: `cargo run --example tee_verify --no-default-features --features ita-verify -p livy-tee`

---

## Current contract

### `verify()` vs `verify_fresh()`

- `Attestation::verify()`:
  - verifies the ITA JWT against JWKS
  - checks nonce/runtime binding claims
  - checks public-values binding
  - applies TCB / MRTD / build / nonce policy
  - does **not** reappraise the bundled evidence artifact

- `Attestation::verify_fresh()`:
  - performs everything in `verify()`
  - reappraises `attestation.evidence` with ITA using the stored verifier nonce
  - authenticates the bundled evidence artifact
  - checks that `raw_quote` matches the raw quote inside the stored evidence

This split is intentional: `verify()` is the no-API-key signed-token path;
`verify_fresh()` is the strict evidence-authenticating path.

### Azure-specific note

On Azure, the generic offline raw-quote REPORTDATA reconstruction is not the
authoritative provider contract. The authoritative paths are:

- `verify()` for signed-token validation against Azure binding claims
- `verify_fresh()` for authenticating the bundled evidence artifact itself

`verify_binding()` / `verify_quote_with_public_values()` remain non-Azure local
binding helpers.

---

## Remaining follow-up

### 1. Add live GCP coverage

Azure now has real-hardware coverage for:
- signed verifier tests
- integration tests
- smoke example with `verify_fresh()`

The remaining infrastructure gap is equivalent live coverage on GCP.
