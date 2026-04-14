// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Minimal getting-started example for the high-level Livy API.
//!
//! This example:
//! 1. takes the public input `123`
//! 2. computes the public output `369`
//! 3. binds both values into the attestation with `commit()`
//! 4. generates the attestation
//! 5. verifies the resulting attestation
//!
//! Run on a TDX VM:
//!   ITA_API_KEY=<key> cargo run --release --no-default-features \
//!     --features ita-verify --example getting_started
//!
//! Compile-check locally:
//!   cargo build --example getting_started --features mock-tee,ita-verify
//!
//! Example output from an Azure confidential VM (`Standard_DC2es_v6`, 2026-04-14):
//!
//! ```text
//! livy-tee: detected Azure confidential VM (not local TSM configfs); using Azure vTPM/paravisor attestation path
//! input: 123
//! output: 369
//! payload_hash: cd85fb1d8613fbdacc6f1773cfcb8d1198d14057a7087006440919ab918c634f
//! ita_token_prefix: eyJhbGciOiJQUzM4NCIsImprdSI6Imh0
//! evidence_prefix: {"quote":"BAACAIEAAAAAAAAAk5pyM/ecTKmUCg2zlX8GB4
//! raw_quote_b64_prefix: BAACAIEAAAAAAAAAk5pyM/ecTKmUCg2z
//! mrtd: 273828c46252fcbdd8ad2dd907130222b03466d52a2911d70c1a5950895d6bd1ae451d382d5a9b1b4c0ed0e5ae9a3dbd
//! tcb_status: UpToDate
//! verify(): jwt=true token_binding=true public_values=true
//! verify_binding(): skipped on Azure; use verify_fresh() for strict bundled-evidence authentication
//! committed_input: 123
//! committed_output: 369
//! application_nonce: 1
//! ```

use std::error::Error;

use livy_tee::{CloudProvider, Livy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let input: u64 = 123;
    let output = input * 3;
    let provider = livy_tee::detect_cloud_provider();

    let api_key = std::env::var("ITA_API_KEY").unwrap_or_default();
    let livy = Livy::new(api_key);

    let mut builder = livy.attest();
    builder.commit(&input).commit(&output);
    builder.nonce(1);

    let attestation = builder.finalize().await?;

    println!("input: {input}");
    println!("output: {output}");
    println!("payload_hash: {}", attestation.payload_hash_hex());
    println!(
        "ita_token_prefix: {}",
        &attestation.ita_token[..attestation.ita_token.len().min(32)]
    );
    println!(
        "evidence_prefix: {}",
        &attestation.evidence[..attestation.evidence.len().min(48)]
    );
    println!(
        "raw_quote_b64_prefix: {}",
        &attestation.raw_quote[..attestation.raw_quote.len().min(32)]
    );

    if attestation.ita_token.is_empty() {
        println!("mock-tee mode detected: skipping ITA verification");
    } else {
        let report = attestation.verify().await?;
        report
            .require_success()
            .map_err(|report| format!("attestation verification failed: {report:?}"))?;

        println!("mrtd: {}", attestation.mrtd);
        println!("tcb_status: {}", report.tcb_status);
        println!(
            "verify(): jwt={} token_binding={} public_values={}",
            report.jwt_signature_and_expiry_valid,
            report.token_report_data_matches,
            report.public_values_bound
        );

        if provider != Some(CloudProvider::Azure) {
            let offline_ok = attestation.verify_binding()?;
            assert!(offline_ok, "offline quote binding failed");
            println!("verify_binding(): true");
        } else {
            println!("verify_binding(): skipped on Azure; use verify_fresh() for strict bundled-evidence authentication");
        }
    }

    let committed_input: u64 = attestation.public_values.read();
    let committed_output: u64 = attestation.public_values.read();

    assert_eq!(committed_input, input);
    assert_eq!(committed_output, output);

    println!("committed_input: {committed_input}");
    println!("committed_output: {committed_output}");
    println!("application_nonce: {}", attestation.report_data.nonce);

    Ok(())
}
