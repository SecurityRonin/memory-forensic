//! LSA secrets extraction from Windows memory dumps.
//!
//! The SECURITY registry hive (`\REGISTRY\MACHINE\SECURITY`) stores LSA
//! (Local Security Authority) secrets under `Policy\Secrets`. These secrets
//! include service account passwords, VPN credentials, auto-logon passwords,
//! DPAPI system master keys, and cached domain key material.
//!
//! Extracting LSA secrets from memory enables:
//!
//! - Recovering service account passwords (`_SC_*` secrets)
//! - Detecting auto-logon credentials (`DefaultPassword`)
//! - Extracting DPAPI system keys for offline decryption
//! - Identifying VPN credentials stored in memory
//! - Discovering cached domain key material (`NL$KM`)
//!
//! The SECURITY hive is structured as:
//! `SECURITY\Policy\Secrets\<name>\CurrVal` — current secret value
//! `SECURITY\Policy\Secrets\<name>\OldVal` — previous secret value

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// Maximum number of LSA secrets to enumerate (safety limit).
const MAX_SECRETS: usize = 4096;

/// Information about an LSA secret recovered from the SECURITY hive.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LsaSecretInfo {
    /// Secret name (e.g., `NL$KM`, `DPAPI_SYSTEM`, `_SC_servicename`).
    pub name: String,
    /// Classified secret type (e.g., `"service_password"`, `"dpapi_key"`).
    pub secret_type: String,
    /// Length of the secret data in bytes.
    pub length: u32,
    /// Whether this secret is suspicious based on heuristics.
    pub is_suspicious: bool,
}

/// Classify an LSA secret by name.
///
/// Returns `(secret_type, is_suspicious)` based on the secret name pattern:
/// - `_SC_*` — service account password (normal)
/// - `NL$KM` — cached domain key material (normal)
/// - `DPAPI_SYSTEM` — DPAPI system master key (normal)
/// - `DefaultPassword` — auto-logon password (risky)
/// - `$MACHINE.ACC` — machine account password (normal)
/// - `L$_RasConn*` / `L$_RasDial*` — VPN credentials (suspicious)
/// - Other `L$*` — generic LSA data (normal)
/// - Anything else — unknown (suspicious if name > 30 chars)
pub fn classify_lsa_secret(name: &str) -> (String, bool) {
    if name.starts_with("_SC_") {
        return ("service_password".to_string(), false);
    }
    if name == "NL$KM" {
        return ("cached_domain_key".to_string(), false);
    }
    if name == "DPAPI_SYSTEM" {
        return ("dpapi_key".to_string(), false);
    }
    if name == "DefaultPassword" {
        return ("default_password".to_string(), true);
    }
    if name == "$MACHINE.ACC" {
        return ("machine_password".to_string(), false);
    }
    if name.starts_with("L$_RasConn") || name.starts_with("L$_RasDial") {
        return ("vpn_credential".to_string(), true);
    }
    if name.starts_with("L$") {
        return ("lsa_data".to_string(), false);
    }
    ("unknown".to_string(), name.len() > 30)
}

/// Extract LSA secrets from the SECURITY registry hive in memory.
///
/// Navigates `SECURITY\Policy\Secrets` in the registry hive at
/// `security_hive_addr`, enumerates subkeys (each representing a secret),
/// reads the `CurrVal` subkey's default value for the secret length,
/// classifies each secret, and returns the results.
///
/// Returns an empty `Vec` if the hive address is zero or navigation fails.
pub fn walk_lsa_secrets<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    security_hive_addr: u64,
) -> crate::Result<Vec<LsaSecretInfo>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ── Classifier tests ─────────────────────────────────────────────

    /// Service account secret (_SC_ prefix) is classified correctly.
    #[test]
    fn classify_service_password() {
        let (secret_type, suspicious) = classify_lsa_secret("_SC_MyService");
        assert_eq!(secret_type, "service_password");
        assert!(!suspicious);
    }

    /// Cached domain key material (NL$KM) is classified correctly.
    #[test]
    fn classify_cached_domain_key() {
        let (secret_type, suspicious) = classify_lsa_secret("NL$KM");
        assert_eq!(secret_type, "cached_domain_key");
        assert!(!suspicious);
    }

    /// DPAPI system key is classified correctly.
    #[test]
    fn classify_dpapi_key() {
        let (secret_type, suspicious) = classify_lsa_secret("DPAPI_SYSTEM");
        assert_eq!(secret_type, "dpapi_key");
        assert!(!suspicious);
    }

    /// Auto-logon DefaultPassword is classified as suspicious.
    #[test]
    fn classify_default_password() {
        let (secret_type, suspicious) = classify_lsa_secret("DefaultPassword");
        assert_eq!(secret_type, "default_password");
        assert!(suspicious, "DefaultPassword should be suspicious");
    }

    /// Machine account password is classified correctly.
    #[test]
    fn classify_machine_password() {
        let (secret_type, suspicious) = classify_lsa_secret("$MACHINE.ACC");
        assert_eq!(secret_type, "machine_password");
        assert!(!suspicious);
    }

    /// VPN RAS credentials are classified as suspicious.
    #[test]
    fn classify_vpn_credential_rasconn() {
        let (secret_type, suspicious) = classify_lsa_secret("L$_RasConn_VPN1");
        assert_eq!(secret_type, "vpn_credential");
        assert!(suspicious, "VPN credentials should be suspicious");
    }

    /// VPN RasDial credentials are also suspicious.
    #[test]
    fn classify_vpn_credential_rasdial() {
        let (secret_type, suspicious) = classify_lsa_secret("L$_RasDial_Corp");
        assert_eq!(secret_type, "vpn_credential");
        assert!(suspicious, "VPN RasDial credentials should be suspicious");
    }

    /// Generic L$ prefixed data is classified as lsa_data.
    #[test]
    fn classify_generic_lsa_data() {
        let (secret_type, suspicious) = classify_lsa_secret("L$SomeOtherData");
        assert_eq!(secret_type, "lsa_data");
        assert!(!suspicious);
    }

    /// Unknown secret with short name is not suspicious.
    #[test]
    fn classify_unknown_short_name() {
        let (secret_type, suspicious) = classify_lsa_secret("SomeSecret");
        assert_eq!(secret_type, "unknown");
        assert!(!suspicious, "Short unknown names should not be suspicious");
    }

    /// Unknown secret with long name (>30 chars) is suspicious.
    #[test]
    fn classify_unknown_long_name_suspicious() {
        let long_name = "a]bcdefghijklmnopqrstuvwxyz012345"; // 32 chars
        assert!(long_name.len() > 30);
        let (secret_type, suspicious) = classify_lsa_secret(long_name);
        assert_eq!(secret_type, "unknown");
        assert!(suspicious, "Long unknown names (>30 chars) should be suspicious");
    }

    // ── Walker tests ─────────────────────────────────────────────────

    /// Zero hive address returns empty Vec (graceful degradation).
    #[test]
    fn walk_lsa_secrets_no_hive() {
        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .add_field("_HHIVE", "BaseBlock", 0x10, "pointer")
            .add_field("_HHIVE", "Storage", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_lsa_secrets(&reader, 0).unwrap();
        assert!(result.is_empty(), "Zero hive address should return empty Vec");
    }
}
