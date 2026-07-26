# Confidential Space support

The `confidential-space` feature requests and verifies OIDC attestation tokens
for workloads running in Google Confidential Space.

## Launcher protocol

The client connects through:

```text
/run/container_launcher/teeserver.sock
```

Endpoints:

| Attester | Endpoint |
|---|---|
| Google Cloud Attestation | `POST /v1/token` |
| Intel Trust Authority | `POST /v1/intel/token` |

The audience must be non-empty and at most 512 bytes. The request is:

```json
{
  "audience": "RELYING_PARTY_AUDIENCE",
  "token_type": "OIDC",
  "nonces": ["BASE64URL_NO_PAD(SHA-256(public_values))"]
}
```

Raw JWT, JSON-string, and `{ "token": "…" }` launcher responses are
normalized. A non-success status, timeout, missing token, or malformed JWT
fails generation. In dual mode both endpoints must succeed.

PKI tokens are outside the version-2 contract.

## Typed artifacts

`ConfidentialSpaceTokens` has three variants:

- `Google { token }`
- `Intel { token }`
- `Dual { google, intel }`

A `ConfidentialSpaceAttestation` contains only:

- required `schema_version: 2`;
- typed token(s);
- `public_values`.

The commitment is derived during verification. Version-1, missing-version, and
unknown-version artifacts are rejected.

## Trusted issuers and keys

Issuer identities are fixed:

| Attester | Required `iss` | OIDC discovery |
|---|---|---|
| Google | `https://confidentialcomputing.googleapis.com` | `https://confidentialcomputing.googleapis.com/.well-known/openid-configuration` |
| Intel | `https://portal.trustauthority.intel.com` | `https://portal.trustauthority.intel.com/.well-known/openid-configuration` |

Discovery documents must repeat the fixed issuer, and their JWKS URI must use
HTTPS. A policy can point to a trusted JWKS mirror for controlled environments
or tests, but it cannot change the required token issuer.

Google tokens accept RS256. Intel tokens accept the ITA-compatible PS384 and
RS256 algorithms. Tokens must have valid `exp` and `nbf` claims.

## Required relying-party policy

The verifier constructs:

```rust,no_run
let policy = livy_tee::ConfidentialSpaceVerificationPolicy::new(
    "https://relying-party.example",
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
);
```

Both values come from trusted relying-party configuration. The artifact is not
allowed to choose its own audience or acceptable image digest.

The default policy also requires an `UpToDate` signed TDX TCB status and limits
the signed `iat` age to five minutes, with 60 seconds of clock-skew tolerance.
Relying parties can additionally pin minimum platform and Confidential Space
versions:

```rust,no_run
let mut policy = livy_tee::ConfidentialSpaceVerificationPolicy::new(
    "https://relying-party.example",
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
);
policy.minimum_tcb_date = Some("2025-05-14T00:00:00Z".to_string());
policy.minimum_confidential_space_version = Some("260600".to_string());
```

`minimum_tcb_date` uses canonical `YYYY-MM-DDThh:mm:ssZ` UTC form.
Confidential Space versions accept the six-digit launcher form (`YYMM##`) and
the expanded documentation form (`YYYYMM##`).

## Strict issuer checks

Each token must satisfy every check:

1. signature, expiry, and not-before validation;
2. a present, recent signed `iat`;
3. exact fixed issuer;
4. exact policy audience;
5. exactly one `eat_nonce`, equal to
   `BASE64URL_NO_PAD(SHA-256(public_values))`;
6. exact canonical lowercase `sha256:…` image digest;
7. `swname == "CONFIDENTIAL_SPACE"`;
8. `dbgstat == "disabled-since-boot"`;
9. `secboot == true`;
10. `hwmodel == "GCP_INTEL_TDX"`;
11. exactly one Intel entry in `attester_tcb`;
12. one unambiguous TDX claim object;
13. an accepted `gcp_attester_tcb_status`;
14. a canonical `gcp_attester_tcb_date` meeting the optional minimum;
15. one canonical Confidential Space `swversion` meeting the optional minimum;
16. `STABLE` support;
17. memory monitoring explicitly disabled;
18. empty `cmd_override` and `env_override`.

Google's documented token schema describes `tdx` as a single-element array,
while production Google tokens have also used a direct object. The verifier
accepts either unambiguous representation and rejects empty or multi-entry
arrays.

The `container.env` claim is not required to be empty. Confidential Space
includes image-defined and launcher-provided values such as `PATH` and
`HOSTNAME` in valid tokens. The exact image digest must identify an image that
retains the default `tee.launch_policy.allow_env_override=false` policy, and
dual mode compares the complete signed environment between issuers.

The result is issuer-specific diagnostics. `Ok(report)` is not itself a
successful verdict; call `all_passed()` or `require_success()`.

## Dual-attester agreement

Dual mode requires both issuer reports to pass and requires equality of common
signed claims, including:

- commitment nonce and VM subject;
- image digest, ID, reference, and signatures;
- container arguments, overrides, environment, and restart policy;
- hardware model and Secure Boot;
- Confidential Space software version, debug state, support attributes, and
  monitoring state;
- common GCE identity/configuration claims.

Issuer-specific timestamps, issuer strings, and appraisal-specific TCB claims
are not compared. Each issuer's freshness and TCB claims must independently
pass policy.

## Freshness and replay

The JWT `exp` and `nbf` checks bound token validity. The additional `iat` policy
reduces the acceptance window for a captured token. It does not provide
single-use semantics.

The sole `eat_nonce` commits to `public_values`. A relying party that needs
request freshness should include its own random challenge, ephemeral
handshake key, or TLS channel binding in those public values and maintain any
required used-nonce registry. The library intentionally remains stateless and
cannot detect replay by itself.

The signed `gcp_attester_tcb_status` is an appraisal signal, not proof that the
Google fleet still matches Intel's real-time reference values. A minimum TCB
date is an additional relying-party floor, not a replacement for provider
security advisories and key revocation.

## Workload identity

The signed container claims establish which image and launch configuration ran
under Confidential Space. This is stronger and more directly relevant to
application identity than raw instance MRTD.

Instance MRTD remains useful only with an external reference-measurement
policy, and it does not by itself identify the running application.

## Runnable workload and verifier

The repository includes two executable examples:

- `confidential_space_attest` runs inside the workload, commits its public
  values, requests the selected token or tokens through the launcher socket,
  and writes a version-2 artifact as JSON.
- `confidential_space_verify` runs at the relying party, reads the artifact
  from a file or standard input, applies trusted audience and image-digest
  policy, writes issuer diagnostics, and exits unsuccessfully unless
  `all_passed()` is true.

Run the verifier with an artifact received through your application's
authenticated channel:

```bash
export LIVY_TEE_CS_AUDIENCE='https://relying-party.example'
export LIVY_TEE_CS_IMAGE_DIGEST='sha256:REPLACE_WITH_64_LOWERCASE_HEX_DIGITS'

cargo run --locked --features confidential-space \
  --example confidential_space_verify -- artifact.json
```

The workload example accepts `LIVY_TEE_CS_AUDIENCE` and
`LIVY_TEE_CS_ATTESTER=google|intel|dual`. For a production image, bake those
values in at compile time instead of passing them with operator-controlled
`tee-env-*` metadata. The supplied
`examples/confidential-space/Dockerfile` does this and keeps command
overrides and memory monitoring disabled.

The example writes the artifact to standard output only to remain
transport-neutral. A real workload should call the same library API and send
the artifact over its authenticated, encrypted application channel. Do not
log private public values or bearer tokens.

## Build and deploy on Confidential Space

Create an Artifact Registry Docker repository and a workload service account
first. The attached service account needs
`roles/confidentialcomputing.workloadUser` and read access to the repository.
Set these variables to your environment:

```bash
export PROJECT_ID='workload-project'
export REGION='us'
export ZONE='us-central1-a'
export REPOSITORY='confidential-workloads'
export IMAGE_NAME='livy-confidential-space'
export IMAGE_TAG='v1'
export INSTANCE_NAME='livy-confidential-space'
export MACHINE_TYPE='REPLACE_WITH_A_TDX_MACHINE_TYPE'
export WORKLOAD_SERVICE_ACCOUNT='workload@workload-project.iam.gserviceaccount.com'
export LIVY_TEE_CS_AUDIENCE='https://relying-party.example'

IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPOSITORY}/${IMAGE_NAME}:${IMAGE_TAG}"
```

Build an amd64 image, because this security contract requires Intel TDX, and
push it:

```bash
gcloud auth configure-docker "${REGION}-docker.pkg.dev"

docker buildx build \
  --platform linux/amd64 \
  --build-arg LIVY_TEE_CS_AUDIENCE="${LIVY_TEE_CS_AUDIENCE}" \
  --build-arg LIVY_TEE_CS_ATTESTER=dual \
  --file examples/confidential-space/Dockerfile \
  --tag "${IMAGE}" \
  --push \
  .
```

Resolve the immutable digest and use that same value both for launch and
relying-party verification:

```bash
IMAGE_DIGEST="$(
  gcloud artifacts docker images describe "${IMAGE}" \
    --format='value(image_summary.digest)'
)"
IMAGE_BY_DIGEST="${IMAGE%:*}@${IMAGE_DIGEST}"
export LIVY_TEE_CS_IMAGE_DIGEST="${IMAGE_DIGEST}"
```

For Google-only mode, build with `LIVY_TEE_CS_ATTESTER=google` and create a
production TDX Confidential Space VM:

```bash
gcloud compute instances create "${INSTANCE_NAME}" \
  --project="${PROJECT_ID}" \
  --zone="${ZONE}" \
  --machine-type="${MACHINE_TYPE}" \
  --confidential-compute-type=TDX \
  --maintenance-policy=TERMINATE \
  --shielded-secure-boot \
  --image-project=confidential-space-images \
  --image-family=confidential-space \
  --metadata="tee-image-reference=${IMAGE_BY_DIGEST}" \
  --service-account="${WORKLOAD_SERVICE_ACCOUNT}" \
  --scopes=cloud-platform
```

For Intel or dual mode, the launcher also requires an Intel Trust Authority
API key and region. Keep the key out of source control and use either the US
or Europe endpoint:

```bash
export ITA_API_KEY='REPLACE_WITH_ITA_API_KEY'
export ITA_REGION='https://api.trustauthority.intel.com'

gcloud compute instances create "${INSTANCE_NAME}" \
  --project="${PROJECT_ID}" \
  --zone="${ZONE}" \
  --machine-type="${MACHINE_TYPE}" \
  --confidential-compute-type=TDX \
  --maintenance-policy=TERMINATE \
  --shielded-secure-boot \
  --image-project=confidential-space-images \
  --image-family=confidential-space \
  --metadata="^~^tee-image-reference=${IMAGE_BY_DIGEST}~ita-api-key=${ITA_API_KEY}~ita-region=${ITA_REGION}" \
  --service-account="${WORKLOAD_SERVICE_ACCOUNT}" \
  --scopes=cloud-platform
```

Do not add `tee-cmd`, `tee-env-*`, or
`tee-monitoring-memory-enable=true`. Those settings conflict with the strict
verification contract. The production image family is also required; the
debug family deliberately fails `production_image`.

## References

- [Confidential Space external resource token flow](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources)
- [Confidential Space token claims](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims)
- [Build and customize workloads](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/create-customize-workloads)
- [Deploy workloads](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/deploy-workloads)
