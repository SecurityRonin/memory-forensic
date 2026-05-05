//! Cloud provider credential forensics walker.
//!
//! Scans process heap memory for cloud service credentials that applications
//! cache in memory during operation. Covers AWS IAM access keys, GCP API keys,
//! Azure storage and SAS tokens, Stripe secret keys, Twilio SIDs, and generic
//! high-entropy API key patterns.
//!
//! This capability is absent from all major memory forensics frameworks
//! (Volatility 3, pypykatz, MemProcFS) as of 2024.
//!
//! # Forensic guarantee
//!
//! Read-only. No live process access, no Win32 API calls, no state modification.

use std::collections::HashSet;

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{
    process::walk_processes,
    types::CloudCredentialInfo,
    vad::walk_vad_tree,
    Result,
};

/// Maximum bytes read from a single VAD region.
const MAX_REGION_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Walk committed, writable heap regions of ALL processes in the dump and
/// extract any cloud provider credentials found as strings.
///
/// # Arguments
///
/// * `reader` — kernel-space `ObjectReader` (uses kernel CR3 / symbol table).
/// * `ps_head_vaddr` — virtual address of `PsActiveProcessHead`.
pub fn walk_cloud_credentials<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<CloudCredentialInfo>> {
    let procs = walk_processes(reader, ps_head_vaddr)?;

    let vad_root_offset = reader
        .symbols()
        .field_offset("_EPROCESS", "VadRoot")
        .ok_or_else(|| crate::Error::Walker("missing _EPROCESS.VadRoot offset".into()))?;

    let mut results = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new(); // (pid, value)

    for proc in &procs {
        if proc.cr3 == 0 || proc.peb_addr == 0 {
            continue;
        }

        let vad_root_addr = proc.vaddr.wrapping_add(vad_root_offset);
        let vads = match walk_vad_tree(reader, vad_root_addr, proc.pid, &proc.image_name) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let proc_reader = reader.with_cr3(proc.cr3);

        for vad in &vads {
            if !vad.is_private || !vad.protection_str.contains("READWRITE") {
                continue;
            }
            if vad.protection_str.contains("EXECUTE") {
                continue;
            }

            let region_size = (vad.end_vaddr.saturating_sub(vad.start_vaddr) + 1)
                .min(MAX_REGION_BYTES as u64) as usize;

            if region_size == 0 {
                continue;
            }

            let bytes = match proc_reader.read_bytes(vad.start_vaddr, region_size) {
                Ok(b) => b,
                Err(_) => continue,
            };

            for cred in scan_cloud_region(&bytes, proc.pid, &proc.image_name) {
                let key = (proc.pid, cred.value.clone());
                if seen.insert(key) {
                    results.push(cred);
                }
            }
        }
    }

    Ok(results)
}

// AWS IAM Access Key ID (permanent: AKIA, temporary STS: ASIA)
const AWS_KEY_ID: &str = r"(?:AKIA|ASIA)[A-Z0-9]{16}";

// GCP API key
const GCP_API_KEY: &str = r"AIza[0-9A-Za-z\-_]{35}";

// Azure Storage Account key (base64, 88 chars ending in ==)
const AZURE_STORAGE_KEY: &str = r"AccountKey=([A-Za-z0-9+/]{86}==)";

// Azure SAS token
const AZURE_SAS: &str = r"SharedAccessSignature=([A-Za-z0-9%&=+]{30,})";

// Stripe secret key (live and test)
const STRIPE_SECRET: &str = r"sk_(?:live|test)_[A-Za-z0-9]{24,}";

// Stripe publishable key
const STRIPE_PK: &str = r"pk_(?:live|test)_[A-Za-z0-9]{24,}";

// Twilio Account SID
const TWILIO_SID: &str = r"AC[a-f0-9]{32}";

// Generic high-entropy API key pattern near "api_key", "apikey", "api-key" labels
const GENERIC_API_KEY: &str = r#"(?i)api[_\-]?key["\s:=]+([A-Za-z0-9\-_]{32,64})"#;

/// Scan raw bytes from a memory region for cloud provider credentials.
///
/// Run all patterns, label each match with provider + credential_type.
/// For patterns with capture groups (Azure, generic API key), use capture
/// group 1. For others, use full match. Deduplicates by value within the
/// returned slice.
pub(crate) fn scan_cloud_region(data: &[u8], pid: u64, process_name: &str) -> Vec<CloudCredentialInfo> {
    let text = String::from_utf8_lossy(data);
    let mut out: Vec<CloudCredentialInfo> = Vec::new();
    let mut seen_values: HashSet<String> = HashSet::new();

    macro_rules! scan_pattern {
        ($pat:expr, $provider:expr, $cred_type:expr, capture: false) => {{
            if let Ok(re) = regex::Regex::new($pat) {
                for m in re.find_iter(&text) {
                    let value = m.as_str().to_owned();
                    if seen_values.insert(value.clone()) {
                        out.push(CloudCredentialInfo {
                            pid,
                            process_name: process_name.to_owned(),
                            provider: $provider.to_owned(),
                            credential_type: $cred_type.to_owned(),
                            value,
                        });
                    }
                }
            }
        }};
        ($pat:expr, $provider:expr, $cred_type:expr, capture: true) => {{
            if let Ok(re) = regex::Regex::new($pat) {
                for caps in re.captures_iter(&text) {
                    if let Some(m) = caps.get(1) {
                        let value = m.as_str().to_owned();
                        if seen_values.insert(value.clone()) {
                            out.push(CloudCredentialInfo {
                                pid,
                                process_name: process_name.to_owned(),
                                provider: $provider.to_owned(),
                                credential_type: $cred_type.to_owned(),
                                value,
                            });
                        }
                    }
                }
            }
        }};
    }

    // AWS — both AKIA (permanent) and ASIA (temporary STS) are AccessKeyId credentials.
    if let Ok(re) = regex::Regex::new(AWS_KEY_ID) {
        for m in re.find_iter(&text) {
            let value = m.as_str().to_owned();
            if seen_values.insert(value.clone()) {
                out.push(CloudCredentialInfo {
                    pid,
                    process_name: process_name.to_owned(),
                    provider: "AWS".to_owned(),
                    credential_type: "AccessKeyId".to_owned(),
                    value,
                });
            }
        }
    }

    scan_pattern!(GCP_API_KEY, "GCP", "ApiKey", capture: false);
    scan_pattern!(AZURE_STORAGE_KEY, "Azure", "StorageKey", capture: true);
    scan_pattern!(AZURE_SAS, "Azure", "SasToken", capture: true);
    scan_pattern!(STRIPE_SECRET, "Stripe", "SecretKey", capture: false);
    scan_pattern!(STRIPE_PK, "Stripe", "PublishableKey", capture: false);
    scan_pattern!(TWILIO_SID, "Twilio", "AccountSid", capture: false);
    scan_pattern!(GENERIC_API_KEY, "Generic", "ApiKey", capture: true);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_empty_returns_nothing() {
        assert!(scan_cloud_region(b"", 1, "x").is_empty());
    }

    #[test]
    fn scan_detects_aws_access_key_id() {
        let data = b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE123";
        let results = scan_cloud_region(data, 1, "aws.exe");
        assert!(!results.is_empty());
        assert!(results.iter().any(|c| c.provider == "AWS" && c.credential_type == "AccessKeyId"));
        assert!(results.iter().any(|c| c.value.starts_with("AKIA")));
    }

    #[test]
    fn scan_detects_aws_sts_temp_key() {
        let data = b"AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE123";
        let results = scan_cloud_region(data, 1, "app.exe");
        assert!(results.iter().any(|c| c.provider == "AWS" && c.value.starts_with("ASIA")));
    }

    #[test]
    fn scan_detects_gcp_api_key() {
        let data = b"api_key = AIzaSyD-9tSrke72I6e672jd9dgkajhd8273hd91";
        let results = scan_cloud_region(data, 1, "app.exe");
        assert!(!results.is_empty());
        assert!(results.iter().any(|c| c.provider == "GCP"));
    }

    #[test]
    fn scan_detects_stripe_secret_key() {
        let data = b"STRIPE_SECRET_KEY=sk_live_ABCDEFGHIJKLMNOPQRSTUVWXabcdefgh";
        let results = scan_cloud_region(data, 1, "app.exe");
        assert!(!results.is_empty());
        assert!(results.iter().any(|c| c.provider == "Stripe" && c.credential_type == "SecretKey"));
    }

    #[test]
    fn scan_deduplicates_repeated_key() {
        let key = b"AKIAIOSFODNN7EXAMPLE123";
        let mut data = Vec::new();
        data.extend_from_slice(b"key1=");
        data.extend_from_slice(key);
        data.extend_from_slice(b" key2=");
        data.extend_from_slice(key);
        let results = scan_cloud_region(&data, 1, "app.exe");
        let aws: Vec<_> = results.iter().filter(|c| c.provider == "AWS").collect();
        assert_eq!(aws.len(), 1, "same key should deduplicate");
    }
}
