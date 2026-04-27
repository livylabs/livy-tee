// SPDX-License-Identifier: MIT
//! Mock TDX evidence — a correctly-shaped 632-byte DCAP quote stub.
//!
//! The buffer follows the TDX DCAP v4 layout so `extract_report_data` works
//! identically for mock and real evidence:
//!
//! ```text
//!  [0..2]    version      = 4 (u16 LE)
//!  [2..4]    att_key_type = 2 (u16 LE)
//!  [4..8]    tee_type     = 0x81000000 (TDX, u32 LE)
//!  [8..48]   header rest  = zeros
//!  [48..568] TD Report body (all measurements zero)
//!  [568..632] REPORTDATA  = caller-supplied user_data
//! ```

use crate::error::GenerateError;
use crate::evidence::Evidence;

const QUOTE_VERSION: u16 = 4;
const ATT_KEY_TYPE: u16 = 2;
const TEE_TYPE_TDX: u32 = 0x81;
const MOCK_QUOTE_LEN: usize = 632;
const OFFSET_REPORT_DATA: usize = 568;

pub(crate) fn generate(user_data: &[u8; 64]) -> Result<Evidence, GenerateError> {
    let mut buf = vec![0u8; MOCK_QUOTE_LEN];

    buf[0..2].copy_from_slice(&QUOTE_VERSION.to_le_bytes());
    buf[2..4].copy_from_slice(&ATT_KEY_TYPE.to_le_bytes());
    buf[4..8].copy_from_slice(&TEE_TYPE_TDX.to_le_bytes());

    buf[OFFSET_REPORT_DATA..MOCK_QUOTE_LEN].copy_from_slice(user_data);

    Ok(Evidence::from_bytes(buf).expect("mock buffer is always 632 bytes"))
}
