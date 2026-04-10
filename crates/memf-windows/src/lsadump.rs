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
    if security_hive_addr == 0 {
        return Ok(Vec::new());
    }

    // Read _HHIVE.BaseBlock pointer to get _HBASE_BLOCK address.
    let base_block_off = reader
        .symbols()
        .field_offset("_HHIVE", "BaseBlock")
        .unwrap_or(0x10);

    let base_block_addr = match reader.read_bytes(security_hive_addr + base_block_off, 8) {
        Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        _ => return Ok(Vec::new()),
    };

    if base_block_addr == 0 {
        return Ok(Vec::new());
    }

    // Read root cell offset from _HBASE_BLOCK (at offset 0x24, u32).
    let root_cell_off = match reader.read_bytes(base_block_addr + 0x24, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return Ok(Vec::new()),
    };

    if root_cell_off == 0 || root_cell_off == u32::MAX {
        return Ok(Vec::new());
    }

    // Compute flat storage base for cell address resolution.
    let storage_off = reader
        .symbols()
        .field_offset("_HHIVE", "Storage")
        .unwrap_or(0x30);

    let flat_base = match reader.read_bytes(security_hive_addr + storage_off, 8) {
        Ok(bytes) if bytes.len() == 8 => {
            let addr = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            if addr != 0 {
                addr
            } else {
                base_block_addr + 0x1000
            }
        }
        _ => base_block_addr + 0x1000,
    };

    // Navigate: root → Policy → Secrets
    let root_addr = read_cell_addr(reader, flat_base, root_cell_off);
    if root_addr == 0 {
        return Ok(Vec::new());
    }

    let policy_key = find_subkey_by_name(reader, flat_base, root_addr, "Policy");
    if policy_key == 0 {
        return Ok(Vec::new());
    }

    let secrets_key = find_subkey_by_name(reader, flat_base, policy_key, "Secrets");
    if secrets_key == 0 {
        return Ok(Vec::new());
    }

    // Enumerate subkeys under Secrets — each is a secret name.
    let subkey_count: u32 = match reader.read_bytes(secrets_key + 0x18, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => 0,
    };

    if subkey_count == 0 || subkey_count > MAX_SECRETS as u32 {
        return Ok(Vec::new());
    }

    let subkey_list_off: u32 = match reader.read_bytes(secrets_key + 0x20, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return Ok(Vec::new()),
    };

    let list_addr = read_cell_addr(reader, flat_base, subkey_list_off);
    if list_addr == 0 {
        return Ok(Vec::new());
    }

    // Read list signature (lf/lh/li).
    let list_sig = match reader.read_bytes(list_addr, 2) {
        Ok(bytes) if bytes.len() == 2 => [bytes[0], bytes[1]],
        _ => return Ok(Vec::new()),
    };

    let count: u16 = match reader.read_bytes(list_addr + 2, 2) {
        Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
        _ => return Ok(Vec::new()),
    };

    let mut secrets = Vec::new();

    for i in 0..count.min(MAX_SECRETS as u16) {
        let entry_off = match list_sig {
            [b'l', b'f'] | [b'l', b'h'] => {
                // lf/lh: 8-byte entries (offset + hash) starting at +4
                match reader.read_bytes(list_addr + 4 + (i as u64) * 8, 4) {
                    Ok(bytes) if bytes.len() == 4 => {
                        u32::from_le_bytes(bytes[..4].try_into().unwrap())
                    }
                    _ => continue,
                }
            }
            [b'l', b'i'] => {
                // li: 4-byte entries (offset only) starting at +4
                match reader.read_bytes(list_addr + 4 + (i as u64) * 4, 4) {
                    Ok(bytes) if bytes.len() == 4 => {
                        u32::from_le_bytes(bytes[..4].try_into().unwrap())
                    }
                    _ => continue,
                }
            }
            _ => continue,
        };

        let key_addr = read_cell_addr(reader, flat_base, entry_off);
        if key_addr == 0 {
            continue;
        }

        // Read key name (at offset 0x4C in _CM_KEY_NODE, length at 0x4A).
        let name_len: u16 = match reader.read_bytes(key_addr + 0x4A, 2) {
            Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
            _ => continue,
        };

        if name_len == 0 || name_len > 256 {
            continue;
        }

        let secret_name = match reader.read_bytes(key_addr + 0x4C, name_len as usize) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            _ => continue,
        };

        // Read the CurrVal subkey's default value length.
        let length = read_currval_length(reader, flat_base, key_addr);

        let (secret_type, is_suspicious) = classify_lsa_secret(&secret_name);

        secrets.push(LsaSecretInfo {
            name: secret_name,
            secret_type,
            length,
            is_suspicious,
        });
    }

    Ok(secrets)
}

/// Read a cell address from the flat storage base + cell offset.
fn read_cell_addr<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    cell_off: u32,
) -> u64 {
    // Cell data starts 4 bytes after the cell offset (cell size header).
    let addr = flat_base + (cell_off as u64) + 4;
    // Verify we can read from this address.
    match reader.read_bytes(addr, 2) {
        Ok(bytes) if bytes.len() == 2 => addr,
        _ => 0,
    }
}

/// Find a subkey by name under a parent `_CM_KEY_NODE`.
fn find_subkey_by_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    parent_addr: u64,
    target_name: &str,
) -> u64 {
    let subkey_count: u32 = match reader.read_bytes(parent_addr + 0x18, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return 0,
    };

    if subkey_count == 0 || subkey_count > 4096 {
        return 0;
    }

    let list_off: u32 = match reader.read_bytes(parent_addr + 0x20, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return 0,
    };

    let list_addr = read_cell_addr(reader, flat_base, list_off);
    if list_addr == 0 {
        return 0;
    }

    let list_sig = match reader.read_bytes(list_addr, 2) {
        Ok(bytes) if bytes.len() == 2 => [bytes[0], bytes[1]],
        _ => return 0,
    };

    let count: u16 = match reader.read_bytes(list_addr + 2, 2) {
        Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
        _ => return 0,
    };

    for i in 0..count.min(4096) {
        let entry_off = match list_sig {
            [b'l', b'f'] | [b'l', b'h'] => {
                match reader.read_bytes(list_addr + 4 + (i as u64) * 8, 4) {
                    Ok(bytes) if bytes.len() == 4 => {
                        u32::from_le_bytes(bytes[..4].try_into().unwrap())
                    }
                    _ => continue,
                }
            }
            [b'l', b'i'] => match reader.read_bytes(list_addr + 4 + (i as u64) * 4, 4) {
                Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
                _ => continue,
            },
            _ => return 0,
        };

        let key_addr = read_cell_addr(reader, flat_base, entry_off);
        if key_addr == 0 {
            continue;
        }

        let name_len: u16 = match reader.read_bytes(key_addr + 0x4A, 2) {
            Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
            _ => continue,
        };

        if name_len == 0 || name_len > 256 {
            continue;
        }

        let name = match reader.read_bytes(key_addr + 0x4C, name_len as usize) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            _ => continue,
        };

        if name.eq_ignore_ascii_case(target_name) {
            return key_addr;
        }
    }

    0
}

/// Read the data length from a secret's `CurrVal` subkey's default value.
///
/// Navigates `<secret_key>\CurrVal` and reads the `(Default)` value's
/// `DataLength` field to determine the secret size.
fn read_currval_length<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    secret_key_addr: u64,
) -> u32 {
    // Find the CurrVal subkey.
    let currval_addr = find_subkey_by_name(reader, flat_base, secret_key_addr, "CurrVal");
    if currval_addr == 0 {
        return 0;
    }

    // Read value count from CurrVal key node (offset 0x28).
    let val_count: u32 = match reader.read_bytes(currval_addr + 0x28, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return 0,
    };

    if val_count == 0 {
        return 0;
    }

    // Read value list cell offset (0x2C in _CM_KEY_NODE).
    let val_list_off: u32 = match reader.read_bytes(currval_addr + 0x2C, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return 0,
    };

    let val_list_addr = read_cell_addr(reader, flat_base, val_list_off);
    if val_list_addr == 0 {
        return 0;
    }

    // Read the first value offset (the default value).
    let val_off: u32 = match reader.read_bytes(val_list_addr, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return 0,
    };

    let val_addr = read_cell_addr(reader, flat_base, val_off);
    if val_addr == 0 {
        return 0;
    }

    // _CM_KEY_VALUE: DataLength at offset 0x08 (u32). MSB indicates inline data.
    match reader.read_bytes(val_addr + 0x08, 4) {
        Ok(bytes) if bytes.len() == 4 => {
            u32::from_le_bytes(bytes[..4].try_into().unwrap()) & 0x7FFF_FFFF
        }
        _ => 0,
    }
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
        assert!(
            suspicious,
            "Long unknown names (>30 chars) should be suspicious"
        );
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
        assert!(
            result.is_empty(),
            "Zero hive address should return empty Vec"
        );
    }

    /// Non-zero hive address but unreadable base block returns empty Vec.
    #[test]
    fn walk_lsa_secrets_unreadable_base_block() {
        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .add_field("_HHIVE", "BaseBlock", 0x10, "pointer")
            .add_field("_HHIVE", "Storage", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        // No memory mapped at hive address, so read will fail.
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_lsa_secrets(&reader, 0xFFFF_8000_1234_0000).unwrap();
        assert!(result.is_empty(), "Unreadable hive should return empty Vec");
    }

    /// L$_RasConn prefix is detected correctly for various suffixes.
    #[test]
    fn classify_lsa_ras_conn_variants() {
        let (t, s) = classify_lsa_secret("L$_RasConn_Office");
        assert_eq!(t, "vpn_credential");
        assert!(s);

        let (t2, s2) = classify_lsa_secret("L$_RasDial");
        assert_eq!(t2, "vpn_credential");
        assert!(s2);
    }

    /// L$ prefix with non-RAS name is lsa_data, not suspicious.
    #[test]
    fn classify_lsa_generic_l_dollar() {
        let (t, s) = classify_lsa_secret("L$GenericData");
        assert_eq!(t, "lsa_data");
        assert!(!s);
    }

    /// Unknown name exactly 30 chars is NOT suspicious (boundary).
    #[test]
    fn classify_unknown_exactly_30_chars_not_suspicious() {
        let name = "a".repeat(30);
        assert_eq!(name.len(), 30);
        let (t, s) = classify_lsa_secret(&name);
        assert_eq!(t, "unknown");
        assert!(!s, "Exactly 30 chars should not be suspicious (> 30 required)");
    }

    /// LsaSecretInfo serializes correctly.
    #[test]
    fn lsa_secret_info_serializes() {
        let info = LsaSecretInfo {
            name: "NL$KM".to_string(),
            secret_type: "cached_domain_key".to_string(),
            length: 32,
            is_suspicious: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("NL$KM"));
        assert!(json.contains("cached_domain_key"));
        assert!(json.contains("32"));
    }
}
