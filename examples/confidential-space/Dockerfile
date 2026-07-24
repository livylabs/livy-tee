# syntax=docker/dockerfile:1

FROM rust:1.94-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /work
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples

# Bake verifier-controlled configuration into the executable. Passing these
# values with tee-env-* at launch time would be visible as env_override and is
# intentionally rejected by strict verification.
ARG LIVY_TEE_CS_AUDIENCE
ARG LIVY_TEE_CS_ATTESTER=dual
RUN test -n "${LIVY_TEE_CS_AUDIENCE}" && \
    LIVY_TEE_CS_AUDIENCE="${LIVY_TEE_CS_AUDIENCE}" \
    LIVY_TEE_CS_ATTESTER="${LIVY_TEE_CS_ATTESTER}" \
    cargo build --locked --release --features confidential-space \
      --example confidential_space_attest

FROM scratch

# Keep operator command overrides and production memory monitoring disabled.
# The omitted allow_env_override label defaults to permitting no tee-env-* keys.
LABEL "tee.launch_policy.allow_cmd_override"="false" \
      "tee.launch_policy.monitoring_memory_allow"="never" \
      "tee.launch_policy.log_redirect"="debugonly"

COPY --from=builder \
    /work/target/release/examples/confidential_space_attest \
    /confidential-space-attest

ENTRYPOINT ["/confidential-space-attest"]
CMD []
