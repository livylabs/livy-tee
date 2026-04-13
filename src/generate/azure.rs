// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Azure TDX quote generation via vTPM/paravisor.
//!
//! This path writes caller-supplied 64-byte report data to the Azure vTPM NV
//! index and requests a quote from Azure's local quote endpoint.

use crate::evidence::Evidence;
use crate::generate::GenerateError;
use base64::Engine;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use uuid::Uuid;

const AZ_RUNTIME_READ_IDX: &str = "0x1400001";
const AZ_RUNTIME_WRITE_IDX: &str = "0x1400002";
const AZ_RUNTIME_WRITE_SIZE: &str = "64";
const AZ_QUOTE_URL: &str = "http://169.254.169.254/acc/tdquote";

const AZ_TD_REPORT_OFFSET: usize = 32;
const AZ_TD_REPORT_SIZE: usize = 1024;
const AZ_RUNTIME_DATA_SIZE_OFFSET: usize = 1232;
const AZ_RUNTIME_JSON_MAX_SIZE: usize = 1_048_576;
const AZ_OUTER_RETRIES: usize = 20;
const AZ_INNER_RETRIES: usize = 20;
const AZ_POLL_INTERVAL: Duration = Duration::from_millis(50);

pub(crate) fn generate(report_data: &[u8; 64]) -> Result<Evidence, GenerateError> {
    ensure_tool("tpm2_nvreadpublic")?;
    ensure_tool("tpm2_nvdefine")?;
    ensure_tool("tpm2_nvwrite")?;
    ensure_tool("tpm2_nvread")?;
    ensure_tool("curl")?;

    ensure_runtime_write_index()?;

    let report_path = temp_path("livy-tee-rd");
    let runtime_path = temp_path("livy-tee-runtime");
    let quote_req_path = temp_path("livy-tee-quote-req");

    let result = (|| {
        std::fs::write(&report_path, report_data)?;

        // Azure runtime data can lag the NV write briefly, so poll with a
        // bounded retry window before giving up.
        for _ in 0..AZ_OUTER_RETRIES {
            run_ok(
                "tpm2_nvwrite",
                &[
                    "-Q",
                    "-C",
                    "o",
                    AZ_RUNTIME_WRITE_IDX,
                    "-i",
                    path_str(&report_path)?,
                ],
            )?;

            let mut parsed: Option<ParsedRuntime> = None;
            for _ in 0..AZ_INNER_RETRIES {
                run_ok(
                    "tpm2_nvread",
                    &[
                        "-Q",
                        "-C",
                        "o",
                        AZ_RUNTIME_READ_IDX,
                        "-o",
                        path_str(&runtime_path)?,
                    ],
                )?;
                let runtime = std::fs::read(&runtime_path)?;
                let p = parse_runtime_blob(&runtime)?;
                if p.user_data_hex
                    .eq_ignore_ascii_case(&hex::encode(report_data))
                {
                    parsed = Some(p);
                    break;
                }
                std::thread::sleep(AZ_POLL_INTERVAL);
            }
            let Some(parsed) = parsed else {
                continue;
            };

            let report_b64url =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&parsed.td_report);
            let body = serde_json::json!({ "report": report_b64url });
            std::fs::write(&quote_req_path, body.to_string())?;

            let out = run_capture(
                "curl",
                &[
                    "-sS",
                    "--fail",
                    "-X",
                    "POST",
                    "-H",
                    "Content-Type: application/json",
                    "--noproxy",
                    "*",
                    "--data",
                    &format!("@{}", path_str(&quote_req_path)?),
                    AZ_QUOTE_URL,
                ],
            )?;

            let resp: QuoteResponse = serde_json::from_slice(&out).map_err(|e| {
                GenerateError::AzureQuoteResponse(format!("JSON decode failed: {e}"))
            })?;

            let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(resp.quote.as_bytes())
                .or_else(|_| {
                    base64::engine::general_purpose::URL_SAFE.decode(resp.quote.as_bytes())
                })
                .map_err(|e| {
                    GenerateError::AzureQuoteResponse(format!("quote base64 decode failed: {e}"))
                })?;

            if raw.len() < 632 {
                continue;
            }

            return Ok(
                Evidence::from_bytes_with_azure_runtime(raw, parsed.runtime_json)
                    .expect("size validated above"),
            );
        }

        Err(GenerateError::AzureRuntime(
            "failed to obtain Azure runtime_data matching requested report_data".to_string(),
        ))
    })();

    let _ = std::fs::remove_file(&report_path);
    let _ = std::fs::remove_file(&runtime_path);
    let _ = std::fs::remove_file(&quote_req_path);

    result
}

#[derive(serde::Deserialize)]
struct QuoteResponse {
    quote: String,
}

struct ParsedRuntime {
    td_report: Vec<u8>,
    runtime_json: Vec<u8>,
    user_data_hex: String,
}

fn parse_runtime_blob(runtime: &[u8]) -> Result<ParsedRuntime, GenerateError> {
    if runtime.len() < AZ_RUNTIME_DATA_SIZE_OFFSET + 4 {
        return Err(GenerateError::AzureRuntime(format!(
            "runtime blob too short: {} bytes",
            runtime.len()
        )));
    }

    let runtime_json_size = u32::from_le_bytes(
        runtime[AZ_RUNTIME_DATA_SIZE_OFFSET..AZ_RUNTIME_DATA_SIZE_OFFSET + 4]
            .try_into()
            .expect("slice size checked"),
    ) as usize;
    if runtime_json_size > AZ_RUNTIME_JSON_MAX_SIZE {
        return Err(GenerateError::AzureRuntime(format!(
            "runtime JSON size exceeds {} bytes: {}",
            AZ_RUNTIME_JSON_MAX_SIZE, runtime_json_size
        )));
    }
    let runtime_json_start = AZ_RUNTIME_DATA_SIZE_OFFSET + 4;
    let runtime_json_end = runtime_json_start + runtime_json_size;
    if runtime.len() < runtime_json_end {
        return Err(GenerateError::AzureRuntime(format!(
            "runtime JSON truncated: need {runtime_json_end} bytes, got {}",
            runtime.len()
        )));
    }

    let td_report_end = AZ_TD_REPORT_OFFSET + AZ_TD_REPORT_SIZE;
    if runtime.len() < td_report_end {
        return Err(GenerateError::AzureRuntime(format!(
            "missing TD report region: need {td_report_end} bytes, got {}",
            runtime.len()
        )));
    }

    let v: serde_json::Value =
        serde_json::from_slice(&runtime[runtime_json_start..runtime_json_end])
            .map_err(|e| GenerateError::AzureRuntime(format!("runtime JSON parse failed: {e}")))?;
    let user_data_hex = v.get("user-data").and_then(|x| x.as_str()).ok_or_else(|| {
        GenerateError::AzureRuntime("runtime JSON missing 'user-data'".to_string())
    })?;
    Ok(ParsedRuntime {
        td_report: runtime[AZ_TD_REPORT_OFFSET..td_report_end].to_vec(),
        runtime_json: runtime[runtime_json_start..runtime_json_end].to_vec(),
        user_data_hex: user_data_hex.to_string(),
    })
}

fn ensure_runtime_write_index() -> Result<(), GenerateError> {
    match Command::new("tpm2_nvreadpublic")
        .arg(AZ_RUNTIME_WRITE_IDX)
        .output()
    {
        Ok(out) if out.status.success() => Ok(()),
        Ok(_) => run_ok(
            "tpm2_nvdefine",
            &[
                "-Q",
                "-C",
                "o",
                AZ_RUNTIME_WRITE_IDX,
                "-s",
                AZ_RUNTIME_WRITE_SIZE,
                "-a",
                "ownerread|ownerwrite",
            ],
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(
            GenerateError::AzurePrerequisite("tpm2_nvreadpublic not found in PATH".to_string()),
        ),
        Err(e) => Err(GenerateError::Io(e)),
    }
}

fn ensure_tool(name: &str) -> Result<(), GenerateError> {
    let out = Command::new("which")
        .arg(name)
        .output()
        .map_err(GenerateError::Io)?;
    if out.status.success() {
        Ok(())
    } else {
        Err(GenerateError::AzurePrerequisite(format!(
            "{name} not found in PATH"
        )))
    }
}

fn run_ok(cmd: &str, args: &[&str]) -> Result<(), GenerateError> {
    let _ = run_capture(cmd, args)?;
    Ok(())
}

fn run_capture(cmd: &str, args: &[&str]) -> Result<Vec<u8>, GenerateError> {
    let out = Command::new(cmd).args(args).output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            GenerateError::AzurePrerequisite(format!("{cmd} not found in PATH"))
        } else {
            GenerateError::Io(e)
        }
    })?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(GenerateError::AzureCommand(format!(
            "{cmd} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

fn temp_path(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{prefix}-{}", Uuid::new_v4()))
}

fn path_str(p: &Path) -> Result<&str, GenerateError> {
    p.to_str()
        .ok_or_else(|| GenerateError::AzureRuntime(format!("non-utf8 temp path: {}", p.display())))
}
