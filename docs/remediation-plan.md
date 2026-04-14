# Remediation plan

Current branch: `feat/full-attestation-verification`

Last updated: `2026-04-14`

Status legend:

- `[ ]` not started
- `[-]` in progress
- `[x]` done
- `[!]` blocked / design decision needed

---

## Phase 1: Evidence authenticity

### 1. Preserve portable evidence in high-level `Attestation`

**Status:** `[x]`
**Priority:** High

Problem:

- low-level `Evidence` can preserve Azure runtime JSON, but high-level
  `Attestation` is still centered on `raw_quote`
- that means stored Azure attestations are not yet self-contained evidence
  artifacts

Target outcome:

- every `Attestation` carries a portable evidence payload that is sufficient for
  standard and Azure replay/reappraisal

Acceptance criteria:

- high-level attestation stores the portable evidence transport string
- Azure runtime JSON is preserved end to end
- existing `raw_quote` use remains coherent or is clearly narrowed to a
  convenience field

Validation:

- unit/integration coverage for portable evidence round-trip
- Azure live suite still passes

Relevant files:

- `src/bind/attestation.rs`
- `src/evidence.rs`

### 2. Add strict bundled-evidence authentication

**Status:** `[x]`
**Priority:** High

Problem:

- `Attestation::verify()` proves the ITA token path, but not that the bundled
  evidence inside the `Attestation` object is the exact evidence ITA appraised
  on Azure

Target outcome:

- callers can choose a stricter verification path that reappraises the bundled
  evidence via ITA and marks whether the attestation object's evidence is
  authenticated

Acceptance criteria:

- strict path takes `ItaConfig`
- strict path works for both standard and Azure evidence
- verification report exposes the bundled-evidence result explicitly
- Azure live test covers the strict path

Validation:

- local signed tests cover strict-path success and mismatch
- Azure live suite passes with strict-path assertion

Relevant files:

- `src/bind/attestation.rs`
- `src/verify/ita.rs`
- `tests/signed_verification.rs`
- `tests/tdx_integration.rs`

---

## Phase 2: Provider contract and docs

### 3. Make provider-specific offline guarantees explicit

**Status:** `[x]`
**Priority:** Medium

Problem:

- some docs still read as if raw-quote-only offline verification is universal
- that is not true on Azure

Target outcome:

- the docs consistently distinguish:
  - non-Azure local raw-quote binding
  - Azure ITA-token-authoritative binding
  - strict ITA reappraisal of bundled evidence

Acceptance criteria:

- `README.md` states the Azure caveat plainly
- `docs/verifiable-proofs.md` scopes raw-quote extraction steps to non-Azure
- Rustdoc around `Attestation` and `verify_binding()` stops over-claiming

Relevant files:

- `README.md`
- `docs/verifiable-proofs.md`
- `src/bind/attestation.rs`

### 4. Restore and keep the status tracker current

**Status:** `[x]`
**Priority:** Medium

Problem:

- `docs/plan.md` was missing after an interrupted turn

Target outcome:

- the repo has a current status snapshot and a separate execution tracker

Acceptance criteria:

- `docs/plan.md` exists and reflects the current validated state
- this remediation plan reflects actual done vs missing work

Relevant files:

- `docs/plan.md`
- `docs/remediation-plan.md`

---

## Phase 3: Remaining test hardening

### 5. Add JWT failure-mode tests

**Status:** `[x]`
**Priority:** Medium

Problem:

- the verifier is tested well for binding and policy, but not enough for JWT
  failure modes

Acceptance criteria:

- explicit tests for expired token
- explicit tests for future `nbf`
- explicit tests for wrong `kid`
- explicit tests for wrong algorithm

Relevant files:

- `tests/signed_verification.rs`

### 6. Lock down `commit_hashed()` interoperability semantics

**Status:** `[x]`
**Priority:** Medium

Problem:

- `commit_hashed()` is defined as `SHA-256(serde_json(value))`
- external verifiers can drift if this is not covered across common input types

Acceptance criteria:

- tests cover `Vec<u8>`, `&[u8]`, and `String`
- docs clearly say the hash is over `serde_json` serialization, not raw bytes

Relevant files:

- `src/bind/attestation.rs`
- `README.md`
- `tests`

---

## Phase 4: Later follow-ups

### 7. Add GCP live verification coverage

**Status:** `[ ]`
**Priority:** Medium

Problem:

- Azure has real-hardware coverage; GCP does not yet

Acceptance criteria:

- a live GCP integration pass exists, or the docs explicitly mark it as pending
  infrastructure

Relevant files:

- `tests/tdx_integration.rs`
- `README.md`

---

## Current summary

Done in this branch:

- high-level `Attestation` now preserves portable evidence via `attestation.evidence`
- `Attestation::verify_fresh()` / `verify_fresh_with_policy()` reappraise the bundled evidence via ITA
- Azure evidence routing in `verify_evidence()` now comes from the evidence artifact, not the verifier host
- docs now distinguish `verify()` from `verify_fresh()` and scope offline raw-quote verification correctly
- JWT failure-mode coverage and `commit_hashed()` interoperability coverage are in place

Primary remaining follow-up:

- add equivalent live GCP coverage to match the Azure validation depth
