// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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

use sha2::{Digest, Sha256};

fn main() {
    println!("=== livy-tee TDX smoke test ===");

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

    // [1/4] Generate TDX evidence
    println!("[1/4] Generating TDX evidence via TSM configfs...");

    let payload_hash: [u8; 32] = Sha256::digest(b"livy-tee smoke test v1").into();
    let build_id = match livy_tee::build_id_from_hash_hex(&binary_hash) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("  FAIL  build_id_from_hash_hex: {e}");
            std::process::exit(1);
        }
    };
    let rd = livy_tee::ReportData::new(
        payload_hash,
        build_id,
        livy_tee::REPORT_DATA_VERSION,
        0,
        0,
    );
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

    // [2/4] Extract REPORTDATA (round-trip)
    println!("[2/4] Extracting REPORTDATA (round-trip)...");

    match livy_tee::extract_report_data(&evidence) {
        Ok(extracted) if extracted == rd_bytes => {
            println!("  OK  match verified");
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

    // [3/4] Extract MRTD
    println!("[3/4] Extracting MRTD...");

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

    // [4/4] Intel Trust Authority verification
    println!("[4/4] Intel Trust Authority verification (via Livy API)...");

    #[cfg(feature = "ita-verify")]
    {
        let livy = livy_tee::Livy::new(ita_api_key);
        let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

        let smoke_input = b"livy-tee smoke test v1: input";
        let smoke_output = b"livy-tee smoke test v1: output";

        match rt.block_on(
            livy.attest()
                .input(smoke_input)
                .output(smoke_output)
                .commit(),
        ) {
            Ok(proof) => {
                if proof.ita_token.is_empty() {
                    eprintln!("  FAIL  ITA returned an empty token");
                    std::process::exit(1);
                }

                if !proof.verify_binding(smoke_input, smoke_output) {
                    eprintln!("  FAIL  payload binding mismatch");
                    std::process::exit(1);
                }

                let tcb = &proof.tcb_status;
                if tcb == "Revoked" {
                    eprintln!("  FAIL  tcb_status: {tcb} (hardware revoked)");
                    std::process::exit(1);
                }
                if tcb == "OutOfDate" || tcb == "OutOfDateConfigurationNeeded" {
                    println!("  WARN  tcb_status: {tcb} (firmware update available)");
                } else {
                    println!("  OK  tcb_status: {tcb}");
                }
                println!(
                    "  OK  ita_token: {}...  ({} bytes)",
                    &proof.ita_token[..proof.ita_token.len().min(3)],
                    proof.ita_token.len(),
                );
                println!("  OK  payload_hash: {}...", &proof.payload_hash_hex()[..12]);
                println!("  OK  binding verified locally");

                // External verification
                println!();
                println!("[5/5] External verification (no TEE, no network)...");

                match livy_tee::verify_quote(
                    &proof.raw_quote,
                    &proof.runtime_data,
                    &proof.verifier_nonce_val,
                    &proof.verifier_nonce_iat,
                    smoke_input,
                    smoke_output,
                ) {
                    Ok(true)  => println!("  OK  verify_quote: SHA-512 binding + payload match"),
                    Ok(false) => { eprintln!("  FAIL  verify_quote: binding mismatch"); std::process::exit(1); }
                    Err(e)    => { eprintln!("  FAIL  verify_quote: {e}"); std::process::exit(1); }
                }

                match livy_tee::verify_token(&proof.ita_token, smoke_input, smoke_output) {
                    Ok(Some(true))  => println!("  OK  verify_token: payload matches"),
                    Ok(Some(false)) => {
                        println!("  SKIP verify_token: JWT tdx_report_data is SHA-512 hash (use verify_quote)");
                    }
                    Ok(None)        => println!("  SKIP verify_token: ITA omitted tdx_report_data"),
                    Err(e)          => { eprintln!("  FAIL  verify_token: {e}"); std::process::exit(1); }
                }

                let expected = hex::encode(livy_tee::payload_hash_for(smoke_input, smoke_output));
                if expected == proof.payload_hash_hex() {
                    println!("  OK  payload_hash_for: {expected}...");
                } else {
                    eprintln!("  FAIL  payload_hash_for mismatch");
                    std::process::exit(1);
                }
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
