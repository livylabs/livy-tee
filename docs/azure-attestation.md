# Azure attestation contract

Current branch: `feat/full-attestation-verification`

Last updated: `2026-04-14`

This document is the Azure-specific reference for `livy-tee`. It explains what
is different on Azure, what the library stores, what each verification method
actually guarantees, and what was validated on a real Azure confidential VM.

For the short status snapshot, see `docs/plan.md`.

---

## Why Azure is different

On a standard non-Azure TDX guest, the local quote path is shaped so a verifier
can reconstruct the quote `REPORTDATA` binding directly from:

- `raw_quote`
- `runtime_data`
- `verifier_nonce_val`
- `verifier_nonce_iat`

and check:

```text
SHA-512(nonce.val || nonce.iat || runtime_data) == REPORTDATA in quote
```

Azure confidential VMs do not expose the same provider-neutral local contract.
The authoritative Azure path is Intel Trust Authority's:

```text
/appraisal/v2/attest/azure
```

That flow binds two things together:

- the Azure runtime JSON
- the caller's `user_data` / `runtime_data`

So on Azure, the ITA token and a fresh ITA reappraisal are the authoritative
sources of evidence authenticity. The generic offline raw-quote helper is not.

---

## What `livy-tee` stores on Azure

High-level `Attestation` now stores enough material to replay and reappraise the
evidence later:

- `ita_token`
- `jwks_url`
- `mrtd`
- `tcb_status`
- `tcb_date`
- `evidence`
- `raw_quote`
- `runtime_data`
- `verifier_nonce_val`
- `verifier_nonce_iat`
- `verifier_nonce_signature`
- `report_data`
- `public_values`

The important Azure-specific field is:

- `evidence`: portable evidence transport string

That field is the serialized low-level `Evidence` artifact. On Azure it preserves:

- raw quote bytes
- Azure runtime JSON

Without that runtime JSON, a verifier cannot replay the Azure evidence to ITA.

`raw_quote` is still present as a convenience field, but on Azure it is not a
self-sufficient verification artifact by itself.

---

## Verification levels

There are now three relevant verification levels.

### 1. `verify_binding()`

Purpose:

- local quote/public-values binding helper

Checks:

- local quote `REPORTDATA` binding
- `SHA-256(public_values buffer) == report_data.payload_hash`

Use:

- non-Azure local/offline verification

Azure note:

- do not treat this as the authoritative Azure verification path

### 2. `verify()`

Purpose:

- signed-token verification and policy enforcement

Checks:

- ITA JWT signature against JWKS
- JWT registered time claims
- token binding claims against verifier nonce + runtime data
- `public_values` commitment against `report_data.payload_hash`
- MRTD / TCB / build / nonce policy checks

Azure note:

- on Azure, `verify()` uses ITA's Azure binding claims
- it does not freshly reappraise the stored evidence artifact

This means `verify()` proves:

- the signed ITA token matches the attestation fields
- the Azure binding claims match this attestation's runtime data

But by design it does not prove:

- that the bundled `evidence` field was freshly reappraised now

### 3. `verify_fresh()`

Purpose:

- strict evidence-authenticating verification

Checks:

- everything in `verify()`
- fresh ITA appraisal of the bundled `evidence`
- consistency between the bundled `evidence` and `raw_quote`
- consistency between the fresh appraisal result and the attestation's public fields

This is the strict path for Azure.

If you need to say:

```text
this exact evidence artifact stored in this Attestation was reappraised by ITA
and matched the public attestation fields
```

then `verify_fresh()` is the method to call.

---

## Azure token binding semantics

For Azure, `verify()` does not rely on the generic non-Azure
`tdx_report_data == SHA-512(...)` interpretation.

Instead it validates ITA's Azure-specific claims:

- `attester_held_data == runtime_data`
- `attester_runtime_data.user-data == SHA-512(nonce.val || nonce.iat || runtime_data)`

That is the Azure token-side binding contract.

---

## Evidence replay on Azure

Fresh evidence authentication on Azure requires:

1. the bundled portable `evidence`
2. `runtime_data`
3. `verifier_nonce_val`
4. `verifier_nonce_iat`
5. `verifier_nonce_signature`
6. an `ItaConfig` with API key

`verify_fresh()` reconstructs the stored `Evidence` from `attestation.evidence`,
rebuilds the verifier nonce object, and calls `verify_evidence(...)`.

Provider routing for this fresh appraisal is based on the evidence artifact
itself:

- if `Evidence` has Azure runtime JSON, `livy-tee` uses `/attest/azure`
- otherwise it uses the standard non-Azure path

This is important because an external verifier replaying Azure evidence is not
running inside Azure. The verifier host environment must not decide the ITA
endpoint.

---

## Verification report fields that matter on Azure

When reading `AttestationVerification` on Azure, the most important fields are:

- `jwt_signature_and_expiry_valid`
- `token_report_data_matches`
- `runtime_data_matches_report`
- `public_values_bound`
- `mrtd_matches_token`
- `tcb_status_matches_token`
- `tcb_date_matches_token`
- `tcb_status_allowed`
- `bundled_evidence_authenticated`

And one field intentionally behaves differently:

- `quote_report_data_matches == None`

That `None` is deliberate. It means:

```text
this provider does not expose a portable offline REPORTDATA check through the
attestation artifact in the same way as the standard non-Azure quote path
```

On Azure, the strict authenticity signal is:

- `bundled_evidence_authenticated == Some(true)`

not `quote_report_data_matches == Some(true)`.

---

## Security interpretation on Azure

If `verify()` passes on Azure:

- the ITA token is valid
- the token's Azure binding claims match this attestation's runtime data
- the attestation's public values are correctly bound
- MRTD and TCB policy checks passed

If `verify_fresh()` passes on Azure:

- all of the above are true
- the bundled portable evidence artifact was freshly reappraised by ITA
- the bundled `raw_quote` matches the raw quote inside the stored evidence

That is the strongest Azure statement the library currently makes.

---

## Tests added for Azure

Deterministic local tests now cover:

- signed Azure token success
- Azure `attester_held_data` mismatch
- Azure `attester_runtime_data.user-data` mismatch
- malformed Azure token claims
- fresh Azure evidence authentication success
- tampered Azure `raw_quote` rejection during fresh verification

JWT failure-mode tests also exist for:

- expired token
- future `nbf`
- wrong `kid`
- unsupported algorithm

Hash semantics tests also exist for:

- `commit_hashed(Vec<u8>)`
- `commit_hashed(&[u8])`
- `commit_hashed(String)`

---

## Real Azure validation completed

Validated on a real Azure confidential VM:

- `cargo test --test signed_verification --features ita-verify`
- `cargo test --test tdx_integration --no-default-features --features ita-verify -p livy-tee -- --nocapture --test-threads=1`
- `cargo run --example tee_verify --no-default-features --features ita-verify -p livy-tee`

The live smoke example now uses strict verification and prints:

```text
ITA JWT, TCB policy, public-value binding, and bundled evidence verified
```

---

## What remains outside Azure

The main remaining follow-up is not an Azure gap.

What remains is:

- equivalent live GCP coverage to match the Azure validation depth

Azure-specific remediation work is complete in the current branch state.
