// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! TDX evidence generation via TSM configfs.
//!
//! Requires Linux kernel ≥ 6.7 with the TDX guest driver and configfs-tsm
//! mounted at `/sys/kernel/config/tsm/report/`.

use crate::evidence::Evidence;
use crate::generate::GenerateError;

pub(crate) fn generate(user_data: &[u8; 64]) -> Result<Evidence, GenerateError> {
    let base = std::path::Path::new("/sys/kernel/config/tsm/report");
    if !base.exists() {
        return Err(GenerateError::TsmNotAvailable);
    }

    let dir = base.join(format!("livy-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir)?;

    let result = (|| {
        std::fs::write(dir.join("inblob"), user_data)?;
        std::fs::read(dir.join("outblob"))
    })();

    // Always clean up the configfs directory, even on error.
    let _ = std::fs::remove_dir_all(&dir);

    let raw = result?;
    if raw.len() < 632 {
        return Err(GenerateError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "TSM outblob too short: {} bytes (expected ≥ 632)",
                raw.len()
            ),
        )));
    }

    Ok(Evidence::from_bytes(raw).expect("size already validated above"))
}
