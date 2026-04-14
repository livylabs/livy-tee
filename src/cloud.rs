// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Runtime cloud-provider detection shared by quote generation and ITA routing.

/// Cloud provider detected from the guest runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudProvider {
    /// Azure confidential VM.
    Azure,
    /// Google Cloud VM.
    Gcp,
}

/// Detect the current guest cloud provider from local runtime signals.
#[must_use]
pub fn detect_cloud_provider() -> Option<CloudProvider> {
    if std::path::Path::new("/var/lib/waagent").exists() {
        return Some(CloudProvider::Azure);
    }

    if let Ok(vendor) = std::fs::read_to_string("/sys/class/dmi/id/sys_vendor") {
        let vendor = vendor.to_ascii_lowercase();
        if vendor.contains("microsoft") {
            return Some(CloudProvider::Azure);
        }
        if vendor.contains("google") {
            return Some(CloudProvider::Gcp);
        }
    }

    if let Ok(product) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
        if product
            .to_ascii_lowercase()
            .contains("google compute engine")
        {
            return Some(CloudProvider::Gcp);
        }
    }

    if std::env::var_os("GOOGLE_CLOUD_PROJECT").is_some() {
        return Some(CloudProvider::Gcp);
    }

    None
}

#[cfg(not(feature = "mock-tee"))]
pub(crate) fn log_detected_provider(provider: CloudProvider) {
    if provider == CloudProvider::Azure {
        static AZURE_NOTICE: std::sync::Once = std::sync::Once::new();
        AZURE_NOTICE.call_once(|| {
            eprintln!(
                "livy-tee: detected Azure confidential VM (not local TSM configfs); using Azure vTPM/paravisor attestation path"
            );
        });
    }
}
