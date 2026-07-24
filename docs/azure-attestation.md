# Azure instance attestation

Azure confidential VMs use a vTPM/paravisor adapter rather than the Linux TSM
configfs path. The application-facing commitment contract is nevertheless the
same as native TDX instance attestation.

## Binding contract

The only application-controlled value is:

```text
user_data = SHA-256(public_values)                   // 32 bytes
quote_hash = SHA-512(nonce.val || nonce.iat || user_data) // 64 bytes
```

The adapter places `quote_hash` in Azure runtime data and obtains a quote from
the local Azure quote endpoint. The ITA Azure appraisal request submits:

- the raw quote;
- the Azure runtime JSON;
- the original 32-byte `user_data` commitment;
- the ITA verifier nonce.

An authenticated Azure ITA token is bound only when:

```text
attester_held_data == user_data
attester_runtime_data.user-data == quote_hash
```

`attester_held_data` is therefore exactly 32 bytes in version 2. The hardware
hash remains 64 bytes because TDX REPORTDATA is 64 bytes.

## Generation flow

```text
PublicValues
    │
    └── SHA-256 ──► 32-byte commitment
                         │
ITA nonce ───────────────┼── SHA-512 ──► 64-byte quote hash
                         │                    │
                         │                    └── Azure vTPM/runtime JSON
                         │
                         └── ITA /appraisal/v2/attest/azure user_data
```

The Azure adapter:

1. ensures the Azure runtime write NV index exists;
2. writes the 64-byte quote hash;
3. waits for runtime JSON whose `user-data` matches that hash;
4. requests the quote through the local Azure endpoint;
5. stores the quote and runtime JSON in `Evidence`.

The portable `evidence` field retains Azure runtime JSON because ITA needs it
for `verify_fresh()`.

## Verification

`Attestation::verify()`:

1. authenticates the ITA JWT against its JWKS;
2. derives the commitment directly from `public_values`;
3. recomputes `SHA-512(nonce.val || nonce.iat || commitment)`;
4. checks the two signed Azure binding claims above;
5. checks copied MRTD/TCB/advisory fields against authenticated claims;
6. enforces the relying-party TCB/MRTD/advisory policy.

Azure normally reports `quote_report_data_matches: None`. This does not mean
the binding was skipped: `token_report_data_matches` covers Azure's signed
held-data/runtime-hash contract. `verify_fresh()` additionally reappraises the
bundled quote and runtime JSON with ITA.

Tampering with `public_values` changes the derived commitment and makes
`token_report_data_matches` false.

## Artifact schema

Version 2 stores `public_values` and derives its commitment during
verification. It no longer stores:

- a duplicate 64-byte `runtime_data`;
- a structured `report_data`;
- a self-reported build ID, version, build number, or application nonce.

Version-1 artifacts are intentionally unsupported.

## Identity limitation

MRTD is a platform/VM launch measurement. Pinning an MRTD can be useful when a
relying party has an independently maintained reference measurement, but MRTD
does not by itself identify the application currently running in the
instance.

For a signed workload image and launch-configuration identity, use the
Confidential Space flow described in
[confidential-space.md](confidential-space.md).
