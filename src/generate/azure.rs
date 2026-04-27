// SPDX-License-Identifier: MIT
//! Azure TDX quote generation via vTPM/paravisor.
//!
//! This path writes caller-supplied 64-byte report data to the Azure vTPM NV
//! index and requests a quote from Azure's local quote endpoint.

use crate::error::GenerateError;
use crate::evidence::Evidence;
use base64::Engine;
use std::time::Duration;

const AZ_RUNTIME_READ_IDX: u32 = 0x0140_0001;
const AZ_RUNTIME_WRITE_IDX: u32 = 0x0140_0002;
const AZ_RUNTIME_WRITE_SIZE: u16 = 64;
const AZ_OUTER_RETRIES: usize = 20;
const AZ_INNER_RETRIES: usize = 20;
const AZ_POLL_INTERVAL: Duration = Duration::from_millis(50);

pub(crate) fn generate(report_data: &[u8; 64]) -> Result<Evidence, GenerateError> {
    tpm::ensure_runtime_write_index(AZ_RUNTIME_WRITE_IDX, AZ_RUNTIME_WRITE_SIZE)?;
    let mut undersized_quote_warning = UndersizedQuoteWarning::default();

    // Azure runtime data can lag the NV write briefly, so poll with a
    // bounded retry window before giving up.
    for _ in 0..AZ_OUTER_RETRIES {
        tpm::nv_write(AZ_RUNTIME_WRITE_IDX, report_data, 0)?;

        let mut parsed: Option<runtime::ParsedRuntime> = None;
        for _ in 0..AZ_INNER_RETRIES {
            let runtime = tpm::nv_read_all(AZ_RUNTIME_READ_IDX)?;
            let p = runtime::parse_blob(&runtime)?;
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
        let body = serde_json::json!({ "report": report_b64url }).to_string();
        let out = http::post_quote(&body)?;

        let resp: QuoteResponse = serde_json::from_slice(&out)
            .map_err(|e| GenerateError::AzureQuoteResponse(format!("JSON decode failed: {e}")))?;

        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(resp.quote.as_bytes())
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(resp.quote.as_bytes()))
            .map_err(|e| {
                GenerateError::AzureQuoteResponse(format!("quote base64 decode failed: {e}"))
            })?;

        if raw.len() < crate::evidence::QUOTE_MIN_LEN {
            if let Some(message) = undersized_quote_warning.record(raw.len()) {
                eprintln!("{message}");
            }
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
}

#[derive(Debug, Default)]
struct UndersizedQuoteWarning {
    emitted: bool,
}

impl UndersizedQuoteWarning {
    fn record(&mut self, raw_len: usize) -> Option<String> {
        if self.emitted {
            return None;
        }
        self.emitted = true;
        Some(format!(
            "livy-tee: ignoring undersized Azure quote (got {raw_len} bytes, need at least {}); suppressing further short-quote warnings for this attempt",
            crate::evidence::QUOTE_MIN_LEN
        ))
    }
}

#[derive(serde::Deserialize)]
struct QuoteResponse {
    quote: String,
}

#[cfg(test)]
mod tests {
    use super::UndersizedQuoteWarning;

    #[test]
    fn undersized_quote_warning_is_only_emitted_once_per_attempt() {
        let mut warning = UndersizedQuoteWarning::default();

        let first = warning.record(128);
        let second = warning.record(256);

        assert!(first.is_some());
        assert!(first
            .unwrap()
            .contains("suppressing further short-quote warnings"));
        assert!(second.is_none());
    }
}

mod runtime {
    use super::GenerateError;

    const AZ_TD_REPORT_OFFSET: usize = 32;
    const AZ_TD_REPORT_SIZE: usize = 1024;
    const AZ_RUNTIME_DATA_SIZE_OFFSET: usize = 1232;
    const AZ_RUNTIME_JSON_MAX_SIZE: usize = 1_048_576;

    #[derive(Debug)]
    pub(super) struct ParsedRuntime {
        pub(super) td_report: Vec<u8>,
        pub(super) runtime_json: Vec<u8>,
        pub(super) user_data_hex: String,
    }

    pub(super) fn parse_blob(runtime: &[u8]) -> Result<ParsedRuntime, GenerateError> {
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

        let v: serde_json::Value = serde_json::from_slice(
            &runtime[runtime_json_start..runtime_json_end],
        )
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

    #[cfg(test)]
    mod tests {
        use super::{parse_blob, AZ_RUNTIME_DATA_SIZE_OFFSET, AZ_TD_REPORT_OFFSET};

        #[test]
        fn parse_blob_extracts_runtime_json_and_td_report() {
            let runtime_json = br#"{"user-data":"aabbcc"}"#;
            let mut blob = vec![0u8; AZ_RUNTIME_DATA_SIZE_OFFSET + 4 + runtime_json.len()];
            blob[AZ_TD_REPORT_OFFSET] = 7;
            blob[AZ_RUNTIME_DATA_SIZE_OFFSET..AZ_RUNTIME_DATA_SIZE_OFFSET + 4]
                .copy_from_slice(&(runtime_json.len() as u32).to_le_bytes());
            blob[AZ_RUNTIME_DATA_SIZE_OFFSET + 4..].copy_from_slice(runtime_json);

            let parsed = parse_blob(&blob).unwrap();
            assert_eq!(parsed.td_report[0], 7);
            assert_eq!(parsed.runtime_json, runtime_json);
            assert_eq!(parsed.user_data_hex, "aabbcc");
        }

        #[test]
        fn parse_blob_rejects_huge_runtime_json_size() {
            let mut blob = vec![0u8; AZ_RUNTIME_DATA_SIZE_OFFSET + 4];
            blob[AZ_RUNTIME_DATA_SIZE_OFFSET..AZ_RUNTIME_DATA_SIZE_OFFSET + 4]
                .copy_from_slice(&(1_048_577u32).to_le_bytes());

            let err = parse_blob(&blob).unwrap_err().to_string();
            assert!(err.contains("runtime JSON size exceeds"));
        }
    }
}

mod tpm {
    use super::GenerateError;
    use std::io::{Read, Write};

    const TPM_DEVICE_PATHS: [&str; 2] = ["/dev/tpmrm0", "/dev/tpm0"];
    const TPM_ST_NO_SESSIONS: u16 = 0x8001;
    const TPM_ST_SESSIONS: u16 = 0x8002;
    const TPM_CC_NV_DEFINE_SPACE: u32 = 0x0000_012A;
    const TPM_CC_NV_WRITE: u32 = 0x0000_0137;
    const TPM_CC_NV_READ: u32 = 0x0000_014E;
    const TPM_CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
    const TPM_RC_SUCCESS: u32 = 0;
    const TPM_RC_HANDLE: u32 = 0x008B;
    const TPM_RC_1: u32 = 0x0100;
    const TPM_RH_OWNER: u32 = 0x4000_0001;
    const TPM_RS_PW: u32 = 0x4000_0009;
    const TPM_ALG_SHA256: u16 = 0x000B;
    const TPMA_NV_OWNERWRITE: u32 = 1 << 1;
    const TPMA_NV_OWNERREAD: u32 = 1 << 17;
    const AZ_NV_ATTRIBUTES: u32 = TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD;
    const TPM_NV_READ_CHUNK_SIZE: u16 = 768;

    pub(super) fn ensure_runtime_write_index(index: u32, size: u16) -> Result<(), GenerateError> {
        match nv_read_public(index) {
            Ok(actual_size) if actual_size == size => Ok(()),
            Ok(actual_size) => Err(GenerateError::AzureRuntime(format!(
                "Azure runtime write NV index has size {actual_size}, expected {size}"
            ))),
            Err(TpmError::ResponseCode(code)) if is_missing_nv_index(code) => {
                nv_define_space(index, size)
            }
            Err(err) => Err(err.into_generate_error()),
        }
    }

    pub(super) fn nv_write(index: u32, data: &[u8], offset: u16) -> Result<(), GenerateError> {
        let mut body = Vec::new();
        push_u32(&mut body, TPM_RH_OWNER);
        push_u32(&mut body, index);
        push_password_auth(&mut body);

        push_u16(
            &mut body,
            data.len().try_into().map_err(|_| {
                GenerateError::AzureRuntime(format!("TPM NV write too large: {} bytes", data.len()))
            })?,
        );
        body.extend_from_slice(data);
        push_u16(&mut body, offset);

        let response = send_command(TPM_ST_SESSIONS, TPM_CC_NV_WRITE, &body)
            .map_err(TpmError::into_generate_error)?;
        let _ = session_response_params(&response)?;
        Ok(())
    }

    pub(super) fn nv_read_all(index: u32) -> Result<Vec<u8>, GenerateError> {
        let total_size = nv_read_public(index).map_err(TpmError::into_generate_error)?;
        let mut out = Vec::with_capacity(total_size as usize);
        let mut offset = 0u16;
        while offset < total_size {
            let remaining = total_size - offset;
            let chunk_size = remaining.min(TPM_NV_READ_CHUNK_SIZE);
            let chunk = nv_read(index, chunk_size, offset)?;
            if chunk.len() != chunk_size as usize {
                return Err(GenerateError::AzureRuntime(format!(
                    "TPM NV short read at offset {offset}: expected {chunk_size} bytes, got {}",
                    chunk.len()
                )));
            }
            out.extend_from_slice(&chunk);
            offset = offset.checked_add(chunk_size).ok_or_else(|| {
                GenerateError::AzureRuntime("TPM NV read offset overflow".to_string())
            })?;
        }
        Ok(out)
    }

    fn nv_read_public(index: u32) -> Result<u16, TpmError> {
        let mut body = Vec::new();
        push_u32(&mut body, index);
        let response = send_command(TPM_ST_NO_SESSIONS, TPM_CC_NV_READ_PUBLIC, &body)?;
        let params = response_params_no_handles(&response)?;
        parse_nv_public_size(params)
    }

    fn nv_define_space(index: u32, size: u16) -> Result<(), GenerateError> {
        let mut body = Vec::new();
        push_u32(&mut body, TPM_RH_OWNER);
        push_password_auth(&mut body);

        push_u16(&mut body, 0);

        let mut public = Vec::new();
        push_u32(&mut public, index);
        push_u16(&mut public, TPM_ALG_SHA256);
        push_u32(&mut public, AZ_NV_ATTRIBUTES);
        push_u16(&mut public, 0);
        push_u16(&mut public, size);

        push_u16(&mut body, public.len() as u16);
        body.extend_from_slice(&public);

        let response = send_command(TPM_ST_SESSIONS, TPM_CC_NV_DEFINE_SPACE, &body)
            .map_err(TpmError::into_generate_error)?;
        let _ = session_response_params(&response)?;
        Ok(())
    }

    fn nv_read(index: u32, size: u16, offset: u16) -> Result<Vec<u8>, GenerateError> {
        let mut body = Vec::new();
        push_u32(&mut body, TPM_RH_OWNER);
        push_u32(&mut body, index);
        push_password_auth(&mut body);
        push_u16(&mut body, size);
        push_u16(&mut body, offset);

        let response = send_command(TPM_ST_SESSIONS, TPM_CC_NV_READ, &body)
            .map_err(TpmError::into_generate_error)?;
        let params = session_response_params(&response)?;
        if params.len() < 2 {
            return Err(GenerateError::AzureRuntime(
                "TPM NV read response missing buffer size".to_string(),
            ));
        }
        let data_size = u16::from_be_bytes([params[0], params[1]]) as usize;
        if params.len() < 2 + data_size {
            return Err(GenerateError::AzureRuntime(format!(
                "TPM NV read response truncated: need {} bytes, got {}",
                2 + data_size,
                params.len()
            )));
        }
        Ok(params[2..2 + data_size].to_vec())
    }

    fn send_command(tag: u16, command_code: u32, body: &[u8]) -> Result<TpmResponse, TpmError> {
        let mut command = Vec::with_capacity(10 + body.len());
        push_u16(&mut command, tag);
        push_u32(&mut command, (10 + body.len()) as u32);
        push_u32(&mut command, command_code);
        command.extend_from_slice(body);

        let mut last_error = None;
        for path in TPM_DEVICE_PATHS {
            let mut dev = match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
            {
                Ok(dev) => dev,
                Err(e) => {
                    last_error = Some(format!("{path}: {e}"));
                    continue;
                }
            };
            dev.write_all(&command).map_err(GenerateError::Io)?;

            let mut header = [0u8; 10];
            dev.read_exact(&mut header).map_err(GenerateError::Io)?;
            let size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
            if !(10..=65_536).contains(&size) {
                return Err(GenerateError::AzureRuntime(format!(
                    "TPM response size out of range: {size}"
                ))
                .into());
            }
            let mut response = vec![0u8; size];
            response[..10].copy_from_slice(&header);
            dev.read_exact(&mut response[10..])
                .map_err(GenerateError::Io)?;
            return TpmResponse::parse(&response);
        }

        Err(GenerateError::AzurePrerequisite(format!(
            "failed to open TPM device; ensure the VM exposes /dev/tpmrm0 and the user has tss group access ({})",
            last_error.unwrap_or_else(|| "no TPM device candidates tried".to_string())
        ))
        .into())
    }

    #[derive(Debug)]
    struct TpmResponse {
        tag: u16,
        body: Vec<u8>,
    }

    impl TpmResponse {
        fn parse(response: &[u8]) -> Result<Self, TpmError> {
            if response.len() < 10 {
                return Err(GenerateError::AzureRuntime(format!(
                    "TPM response too short: {} bytes",
                    response.len()
                ))
                .into());
            }

            let tag = u16::from_be_bytes([response[0], response[1]]);
            let size = u32::from_be_bytes([response[2], response[3], response[4], response[5]]);
            let code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
            if size as usize > response.len() {
                return Err(GenerateError::AzureRuntime(format!(
                    "TPM response truncated: header says {size} bytes, got {}",
                    response.len()
                ))
                .into());
            }
            if size < 10 {
                return Err(GenerateError::AzureRuntime(format!(
                    "TPM response size out of range: {size}"
                ))
                .into());
            }
            if code != TPM_RC_SUCCESS {
                return Err(TpmError::ResponseCode(code));
            }
            Ok(Self {
                tag,
                body: response[10..size as usize].to_vec(),
            })
        }
    }

    // The TPM commands used in this module do not return response handles, so
    // TPMS_AUTH_RESPONSE parameterSize starts the response body for sessions.
    fn response_params_no_handles(response: &TpmResponse) -> Result<&[u8], TpmError> {
        if response.tag == TPM_ST_SESSIONS {
            session_response_params(response).map_err(Into::into)
        } else {
            Ok(&response.body)
        }
    }

    fn session_response_params(response: &TpmResponse) -> Result<&[u8], GenerateError> {
        if response.tag != TPM_ST_SESSIONS {
            return Ok(&response.body);
        }
        if response.body.len() < 4 {
            return Err(GenerateError::AzureRuntime(
                "TPM session response missing parameter size".to_string(),
            ));
        }
        let param_size = u32::from_be_bytes([
            response.body[0],
            response.body[1],
            response.body[2],
            response.body[3],
        ]) as usize;
        if response.body.len() < 4 + param_size {
            return Err(GenerateError::AzureRuntime(format!(
                "TPM session response truncated: need {} bytes, got {}",
                4 + param_size,
                response.body.len()
            )));
        }
        Ok(&response.body[4..4 + param_size])
    }

    fn parse_nv_public_size(params: &[u8]) -> Result<u16, TpmError> {
        if params.len() < 2 {
            return Err(GenerateError::AzureRuntime(
                "TPM NV public response missing size".to_string(),
            )
            .into());
        }
        let public_size = u16::from_be_bytes([params[0], params[1]]) as usize;
        if params.len() < 2 + public_size {
            return Err(GenerateError::AzureRuntime(format!(
                "TPM NV public response truncated: need {} bytes, got {}",
                2 + public_size,
                params.len()
            ))
            .into());
        }
        let public = &params[2..2 + public_size];
        if public.len() < 14 {
            return Err(GenerateError::AzureRuntime(format!(
                "TPM NV public area too short: {} bytes",
                public.len()
            ))
            .into());
        }
        let auth_policy_size = u16::from_be_bytes([public[10], public[11]]) as usize;
        let data_size_offset = 12 + auth_policy_size;
        if public.len() < data_size_offset + 2 {
            return Err(GenerateError::AzureRuntime(format!(
                "TPM NV public area missing data size: {} bytes",
                public.len()
            ))
            .into());
        }
        Ok(u16::from_be_bytes([
            public[data_size_offset],
            public[data_size_offset + 1],
        ]))
    }

    fn push_password_auth(out: &mut Vec<u8>) {
        push_u32(out, 9);
        push_u32(out, TPM_RS_PW);
        push_u16(out, 0);
        out.push(0);
        push_u16(out, 0);
    }

    fn push_u16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn is_missing_nv_index(code: u32) -> bool {
        code == TPM_RC_HANDLE || code == (TPM_RC_1 | TPM_RC_HANDLE)
    }

    #[derive(Debug)]
    enum TpmError {
        ResponseCode(u32),
        Generate(GenerateError),
    }

    impl TpmError {
        fn into_generate_error(self) -> GenerateError {
            match self {
                Self::ResponseCode(code) => GenerateError::AzureTpmResponseCode(code),
                Self::Generate(err) => err,
            }
        }
    }

    impl From<GenerateError> for TpmError {
        fn from(err: GenerateError) -> Self {
            Self::Generate(err)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{
            is_missing_nv_index, parse_nv_public_size, push_password_auth, session_response_params,
            TpmResponse, TPM_RC_1, TPM_RC_HANDLE, TPM_RS_PW, TPM_ST_SESSIONS,
        };

        #[test]
        fn password_auth_wire_format_is_empty_password_session() {
            let mut out = Vec::new();
            push_password_auth(&mut out);
            let mut expected = Vec::new();
            expected.extend_from_slice(&9u32.to_be_bytes());
            expected.extend_from_slice(&TPM_RS_PW.to_be_bytes());
            expected.extend_from_slice(&0u16.to_be_bytes());
            expected.push(0);
            expected.extend_from_slice(&0u16.to_be_bytes());
            assert_eq!(out, expected);
        }

        #[test]
        fn nv_public_size_parser_reads_data_size_after_auth_policy() {
            let mut public = Vec::new();
            public.extend_from_slice(&0x0140_0002u32.to_be_bytes());
            public.extend_from_slice(&0x000Bu16.to_be_bytes());
            public.extend_from_slice(&0x0002_0002u32.to_be_bytes());
            public.extend_from_slice(&3u16.to_be_bytes());
            public.extend_from_slice(&[1, 2, 3]);
            public.extend_from_slice(&64u16.to_be_bytes());

            let mut params = Vec::new();
            params.extend_from_slice(&(public.len() as u16).to_be_bytes());
            params.extend_from_slice(&public);

            assert_eq!(parse_nv_public_size(&params).unwrap(), 64);
        }

        #[test]
        fn tpm_response_parse_surfaces_response_code() {
            let mut response = Vec::new();
            response.extend_from_slice(&0x8001u16.to_be_bytes());
            response.extend_from_slice(&10u32.to_be_bytes());
            response.extend_from_slice(&0x18Bu32.to_be_bytes());

            let err = TpmResponse::parse(&response).unwrap_err();
            match err {
                super::TpmError::ResponseCode(code) => assert_eq!(code, 0x18B),
                super::TpmError::Generate(_) => panic!("expected TPM response code"),
            }
        }

        #[test]
        fn session_response_params_returns_sized_parameter_area() {
            let response = TpmResponse {
                tag: TPM_ST_SESSIONS,
                body: vec![0, 0, 0, 3, 1, 2, 3, 9, 9],
            };
            assert_eq!(session_response_params(&response).unwrap(), &[1, 2, 3]);
        }

        #[test]
        fn missing_nv_index_codes_are_distinguished() {
            assert!(is_missing_nv_index(TPM_RC_HANDLE));
            assert!(is_missing_nv_index(TPM_RC_1 | TPM_RC_HANDLE));
            assert!(!is_missing_nv_index(0x0000_0922));
        }
    }
}

mod http {
    use super::GenerateError;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    const AZ_QUOTE_HOST: &str = "169.254.169.254";
    const AZ_QUOTE_PORT: u16 = 80;
    const AZ_QUOTE_PATH: &str = "/acc/tdquote";
    const AZ_QUOTE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    const AZ_QUOTE_READ_TIMEOUT: Duration = Duration::from_secs(30);
    const AZ_QUOTE_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
    const AZ_QUOTE_RESPONSE_MAX_BYTES: usize = 2 * 1024 * 1024;

    pub(super) fn post_quote(body: &str) -> Result<Vec<u8>, GenerateError> {
        let addr: SocketAddr = format!("{AZ_QUOTE_HOST}:{AZ_QUOTE_PORT}")
            .parse()
            .expect("Azure quote endpoint host and port are valid");
        let mut stream = TcpStream::connect_timeout(&addr, AZ_QUOTE_CONNECT_TIMEOUT)
            .map_err(GenerateError::Io)?;
        stream
            .set_read_timeout(Some(AZ_QUOTE_READ_TIMEOUT))
            .map_err(GenerateError::Io)?;
        stream
            .set_write_timeout(Some(AZ_QUOTE_WRITE_TIMEOUT))
            .map_err(GenerateError::Io)?;

        let request = http_request(body);
        stream
            .write_all(request.as_bytes())
            .map_err(GenerateError::Io)?;

        let mut response = Vec::new();
        stream
            .take((AZ_QUOTE_RESPONSE_MAX_BYTES + 1) as u64)
            .read_to_end(&mut response)
            .map_err(GenerateError::Io)?;
        if response.len() > AZ_QUOTE_RESPONSE_MAX_BYTES {
            return Err(GenerateError::AzureQuoteResponse(format!(
                "HTTP response exceeds {} bytes",
                AZ_QUOTE_RESPONSE_MAX_BYTES
            )));
        }
        parse_response(&response)
    }

    fn http_request(body: &str) -> String {
        format!(
            "POST {AZ_QUOTE_PATH} HTTP/1.1\r\nHost: {AZ_QUOTE_HOST}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn parse_response(response: &[u8]) -> Result<Vec<u8>, GenerateError> {
        let header_end = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| {
                GenerateError::AzureQuoteResponse(
                    "HTTP response missing header terminator".to_string(),
                )
            })?;
        let headers = std::str::from_utf8(&response[..header_end]).map_err(|e| {
            GenerateError::AzureQuoteResponse(format!("HTTP response headers are not UTF-8: {e}"))
        })?;
        let mut lines = headers.lines();
        let status_line = lines.next().ok_or_else(|| {
            GenerateError::AzureQuoteResponse("HTTP response missing status line".to_string())
        })?;
        let status = status_line
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| {
                GenerateError::AzureQuoteResponse(format!(
                    "invalid HTTP status line: {status_line}"
                ))
            })?
            .parse::<u16>()
            .map_err(|e| GenerateError::AzureQuoteResponse(format!("invalid HTTP status: {e}")))?;

        let body = &response[header_end + 4..];
        if !(200..300).contains(&status) {
            return Err(GenerateError::AzureQuoteResponse(format!(
                "HTTP {status}: {}",
                String::from_utf8_lossy(body)
            )));
        }

        if has_chunked_transfer_encoding(headers) {
            decode_chunked_body(body)
        } else {
            Ok(body.to_vec())
        }
    }

    fn has_chunked_transfer_encoding(headers: &str) -> bool {
        headers.lines().any(|line| {
            let Some((name, value)) = line.split_once(':') else {
                return false;
            };
            name.trim().eq_ignore_ascii_case("transfer-encoding")
                && value
                    .split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case("chunked"))
        })
    }

    fn decode_chunked_body(mut body: &[u8]) -> Result<Vec<u8>, GenerateError> {
        let mut decoded = Vec::new();
        loop {
            let line_end = body.windows(2).position(|w| w == b"\r\n").ok_or_else(|| {
                GenerateError::AzureQuoteResponse("chunked body missing chunk size".to_string())
            })?;
            let size_line = std::str::from_utf8(&body[..line_end]).map_err(|e| {
                GenerateError::AzureQuoteResponse(format!("chunk size is not UTF-8: {e}"))
            })?;
            let size_hex = size_line.split(';').next().unwrap_or(size_line).trim();
            let size = usize::from_str_radix(size_hex, 16).map_err(|e| {
                GenerateError::AzureQuoteResponse(format!("invalid chunk size: {e}"))
            })?;
            body = &body[line_end + 2..];
            if size == 0 {
                return Ok(decoded);
            }
            if body.len() < size + 2 {
                return Err(GenerateError::AzureQuoteResponse(format!(
                    "chunked body truncated: need {} bytes, got {}",
                    size + 2,
                    body.len()
                )));
            }
            decoded.extend_from_slice(&body[..size]);
            if &body[size..size + 2] != b"\r\n" {
                return Err(GenerateError::AzureQuoteResponse(
                    "chunked body missing chunk terminator".to_string(),
                ));
            }
            body = &body[size + 2..];
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{
            decode_chunked_body, has_chunked_transfer_encoding, http_request, parse_response,
        };

        #[test]
        fn http_request_body_starts_immediately_after_header_terminator() {
            let body = r#"{"report":"abc"}"#;
            let request = http_request(body);
            assert!(request.contains("\r\n\r\n{\"report\":\"abc\"}"));
            assert!(!request.contains("\r\n\r\n {"));
        }

        #[test]
        fn parse_response_accepts_plain_body() {
            let body = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap();
            assert_eq!(body, b"{}");
        }

        #[test]
        fn parse_response_accepts_chunked_body_with_spaced_header() {
            let response =
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding : gzip, chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
            let body = parse_response(response).unwrap();
            assert_eq!(body, b"{}");
        }

        #[test]
        fn decode_chunked_body_rejects_truncated_chunks() {
            assert!(decode_chunked_body(b"4\r\n{}").is_err());
        }

        #[test]
        fn chunked_transfer_encoding_detection_handles_lists() {
            assert!(has_chunked_transfer_encoding(
                "Transfer-Encoding: gzip, chunked"
            ));
            assert!(!has_chunked_transfer_encoding(
                "Content-Type: application/json"
            ));
        }
    }
}
