// SPDX-License-Identifier: MIT
//! livy-tee TDX smoke test — exercises the full primitive chain on real hardware.
//!
//! Build (production):
//!   cargo build --release --no-default-features --features ita-verify --example tee_verify -p livy-tee
//!
//! Build (local dev / compile-check only):
//!   cargo build --example tee_verify -p livy-tee --features mock-tee
//!
//! Run:
//!   ITA_API_KEY=<key> ./tee-verify

fn main() {
    println!("=== livy-tee TDX smoke test ===");
    let is_azure_runtime =
        livy_tee::detect_cloud_provider() == Some(livy_tee::CloudProvider::Azure);

    #[cfg(feature = "ita-verify")]
    let ita_api_key = match std::env::var("ITA_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            eprintln!("Error: ITA_API_KEY is not set.");
            std::process::exit(1);
        }
    };

    let exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("<unknown>"));
    println!("  binary: {}", exe.display());

    let binary_hash = match livy_tee::binary_hash() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("  FAIL  binary_hash: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "  binary_hash: {}...  ({} hex chars)",
        &binary_hash[..binary_hash.len().min(6)],
        binary_hash.len(),
    );
    println!();

    // [1/5] Generate TDX evidence
    println!("[1/5] Generating TDX evidence via runtime quote provider...");

    use sha2::{Digest, Sha256};
    let payload_hash: [u8; 32] = Sha256::digest(b"livy-tee smoke test v1").into();
    let build_id = match livy_tee::build_id_from_hash_hex(&binary_hash) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("  FAIL  build_id_from_hash_hex: {e}");
            std::process::exit(1);
        }
    };
    let rd = livy_tee::ReportData::new(payload_hash, build_id, livy_tee::REPORT_DATA_VERSION, 0, 0);
    let rd_bytes = rd.to_bytes();

    let evidence = match livy_tee::generate_evidence(&rd_bytes) {
        Ok(e) => {
            println!("  OK  {} bytes", e.raw().len());
            e
        }
        Err(e) => {
            eprintln!("  FAIL  generate_evidence: {e}");
            std::process::exit(1);
        }
    };
    println!();

    // [2/5] Extract REPORTDATA (round-trip)
    println!("[2/5] Extracting REPORTDATA (round-trip)...");

    match livy_tee::extract_report_data(&evidence) {
        Ok(extracted) if extracted == rd_bytes => {
            println!("  OK  match verified");
        }
        Ok(extracted) if is_azure_runtime && extracted.iter().any(|b| *b != 0) => {
            println!("  OK  Azure quote uses platform-specific REPORTDATA binding");
        }
        Ok(_) => {
            eprintln!("  FAIL  REPORTDATA mismatch");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("  FAIL  extract_report_data: {e}");
            std::process::exit(1);
        }
    }
    println!();

    // [3/5] Extract MRTD
    println!("[3/5] Extracting MRTD...");

    match livy_tee::extract_mrtd(&evidence) {
        Ok(mrtd) => {
            let mrtd_hex = hex::encode(mrtd);
            println!(
                "  OK  {}...  ({} hex chars, zeros in mock)",
                &mrtd_hex[..mrtd_hex.len().min(6)],
                mrtd_hex.len(),
            );
        }
        Err(e) => {
            eprintln!("  FAIL  extract_mrtd: {e}");
            std::process::exit(1);
        }
    }
    println!();

    // [4/5] Intel Trust Authority verification
    println!("[4/5] Intel Trust Authority verification (via Livy API)...");

    #[cfg(feature = "ita-verify")]
    {
        let livy = livy_tee::Livy::new(&ita_api_key);
        let verify_config = livy_tee::ItaConfig {
            api_key: ita_api_key.to_string(),
            ..livy_tee::ItaConfig::default()
        };
        let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

        let mut builder = livy.attest();
        builder.commit(&"livy-tee smoke test v1: input");
        builder.commit(&"livy-tee smoke test v1: output");

        match rt.block_on(builder.finalize()) {
            Ok(att) => {
                if att.ita_token.is_empty() {
                    eprintln!("  FAIL  ITA returned an empty token");
                    std::process::exit(1);
                }

                let verification = match rt.block_on(att.verify_fresh(&verify_config)) {
                    Ok(report) => report,
                    Err(e) => {
                        eprintln!("  FAIL  attestation verification error: {e}");
                        std::process::exit(1);
                    }
                };
                if !verification.all_passed() {
                    eprintln!("  FAIL  attestation verification report: {verification:?}");
                    std::process::exit(1);
                }

                println!("  OK  tcb_status: {}", verification.tcb_status);
                println!(
                    "  OK  ita_token: {}...  ({} bytes)",
                    &att.ita_token[..att.ita_token.len().min(3)],
                    att.ita_token.len(),
                );
                println!("  OK  payload_hash: {}...", &att.payload_hash_hex()[..12]);
                println!(
                    "  OK  ITA JWT, TCB policy, public-value binding, and bundled evidence verified"
                );

                // External verification
                println!();
                println!("[5/5] External verification (no TEE, no network)...");

                if is_azure_runtime {
                    println!(
                        "  SKIP  Azure /attest/azure uses ITA runtime-data claims instead of the generic raw-quote binding helper"
                    );
                } else {
                    match livy_tee::verify_quote_with_public_values(
                        &att.raw_quote,
                        &att.runtime_data,
                        &att.verifier_nonce_val,
                        &att.verifier_nonce_iat,
                        &att.public_values,
                    ) {
                        Ok(true) => {
                            println!("  OK  verify_quote: SHA-512 binding + commitment match")
                        }
                        Ok(false) => {
                            eprintln!("  FAIL  verify_quote: binding mismatch");
                            std::process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("  FAIL  verify_quote: {e}");
                            std::process::exit(1);
                        }
                    }
                }

                // Read back public values.
                let v1: String = att
                    .public_values
                    .read()
                    .expect("public input should deserialize");
                let v2: String = att
                    .public_values
                    .read()
                    .expect("public output should deserialize");
                println!("  OK  public_values[0]: {v1}");
                println!("  OK  public_values[1]: {v2}");
            }
            Err(e) => {
                eprintln!("  FAIL  livy.attest: {e}");
                std::process::exit(1);
            }
        }
    }

    #[cfg(not(feature = "ita-verify"))]
    println!("  SKIP  ita-verify feature not enabled");

    println!();
    println!("=== All checks passed ===");
}
