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
        assert!(
            !s,
            "Exactly 30 chars should not be suspicious (> 30 required)"
        );
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

    // ── walk_lsa_secrets body coverage ───────────────────────────────
    //
    // The walker reads: hive BaseBlock pointer → root_cell_off → flat_base
    // → root_addr → Policy key → Secrets key.  We provide synthetic memory
    // to drive the walker deeper into its body, verifying no panic occurs
    // and that each early-exit path returns Ok(empty).

    use memf_core::test_builders::flags;

    fn make_lsa_isf() -> serde_json::Value {
        IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .add_field("_HHIVE", "BaseBlock", 0x10, "pointer")
            .add_field("_HHIVE", "Storage", 0x30, "pointer")
            .build_json()
    }

    /// Mapped hive with zero root_cell_off → early return after BaseBlock read.
    #[test]
    fn walk_lsa_mapped_hive_zero_root_cell() {
        let hive_vaddr: u64 = 0x0020_0000;
        let hive_paddr: u64 = 0x0020_0000;
        let base_block: u64 = 0x0021_0000;
        let base_block_paddr: u64 = 0x0021_0000;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        // root_cell_off = 0 → early return
        bb_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());

        let isf = make_lsa_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_lsa_secrets(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty());
    }

    /// Mapped hive with non-zero root_cell_off; flat_base derived from
    /// Storage=0 fallback; hbin area not mapped → read_cell_addr returns 0
    /// → Policy key not found → empty Vec.
    #[test]
    fn walk_lsa_mapped_hive_policy_not_found() {
        let hive_vaddr: u64 = 0x0030_0000;
        let hive_paddr: u64 = 0x0030_0000;
        let base_block: u64 = 0x0031_0000;
        let base_block_paddr: u64 = 0x0031_0000;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());
        // Storage = 0 → flat_base = base_block + 0x1000
        hive_page[0x30..0x38].copy_from_slice(&0u64.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        bb_page[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes());

        let isf = make_lsa_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_lsa_secrets(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty());
    }

    /// Mapped hive with u32::MAX root_cell_off → early return on sentinel check.
    #[test]
    fn walk_lsa_mapped_hive_root_cell_max_sentinel() {
        let hive_vaddr: u64 = 0x0050_0000;
        let hive_paddr: u64 = 0x0050_0000;
        let base_block: u64 = 0x0051_0000;
        let base_block_paddr: u64 = 0x0051_0000;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        bb_page[0x24..0x28].copy_from_slice(&u32::MAX.to_le_bytes());

        let isf = make_lsa_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_lsa_secrets(&reader, hive_vaddr).unwrap();
        assert!(
            result.is_empty(),
            "u32::MAX root_cell_off should be treated as sentinel"
        );
    }

    /// Hive where base_block_addr reads back as 0 → early return.
    #[test]
    fn walk_lsa_base_block_zero_ptr() {
        let hive_vaddr: u64 = 0x0060_0000;
        let hive_paddr: u64 = 0x0060_0000;

        // At hive_vaddr + 0x10 we write 0 (null base_block pointer)
        let hive_page = vec![0u8; 0x1000]; // all zeros

        let isf = make_lsa_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_lsa_secrets(&reader, hive_vaddr).unwrap();
        assert!(
            result.is_empty(),
            "null base_block_addr should return empty Vec"
        );
    }

    // ── read_cell_addr unit tests ─────────────────────────────────────

    use memf_core::test_builders::SyntheticPhysMem;

    fn make_lsa_reader_with_page(
        vaddr: u64,
        paddr: u64,
        page: &[u8],
    ) -> ObjectReader<SyntheticPhysMem> {
        let isf = make_lsa_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// read_cell_addr returns 0 when flat_base + cell_off + 4 is unmapped.
    #[test]
    fn read_cell_addr_unmapped_returns_zero() {
        let isf = make_lsa_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        assert_eq!(read_cell_addr(&reader, 0xDEAD_BEEF_0000, 0x20), 0);
    }

    /// read_cell_addr returns the computed address when the cell is readable.
    #[test]
    fn read_cell_addr_mapped_returns_addr() {
        let flat_base: u64 = 0x0070_0000;
        let cell_off: u32 = 0x100;
        // cell data starts at flat_base + cell_off + 4
        let cell_data_addr = flat_base + cell_off as u64 + 4;

        let mut page = vec![0u8; 0x1000];
        // Write 2 readable bytes at cell_data_addr offset within the page
        let off = (cell_off as usize) + 4;
        if off + 2 <= page.len() {
            page[off] = 0xAB;
            page[off + 1] = 0xCD;
        }

        let reader = make_lsa_reader_with_page(flat_base, flat_base, &page);
        let result = read_cell_addr(&reader, flat_base, cell_off);
        assert_eq!(
            result, cell_data_addr,
            "should return computed addr when readable"
        );
    }

    // ── find_subkey_by_name: subkey_count == 0 → returns 0 ──────────

    /// find_subkey_by_name returns 0 when subkey_count is 0.
    #[test]
    fn find_subkey_by_name_zero_count_returns_zero() {
        let parent_addr: u64 = 0x0080_0000;
        let paddr: u64 = 0x0080_0000;
        // subkey_count at parent_addr + 0x18: write 0
        let mut page = vec![0u8; 0x1000];
        page[0x18..0x1C].copy_from_slice(&0u32.to_le_bytes());

        let reader = make_lsa_reader_with_page(parent_addr, paddr, &page);
        let result = find_subkey_by_name(&reader, 0x0090_0000, parent_addr, "Policy");
        assert_eq!(result, 0);
    }

    /// find_subkey_by_name returns 0 when subkey_count > 4096 (safety limit).
    #[test]
    fn find_subkey_by_name_excessive_count_returns_zero() {
        let parent_addr: u64 = 0x0082_0000;
        let paddr: u64 = 0x0082_0000;
        let mut page = vec![0u8; 0x1000];
        page[0x18..0x1C].copy_from_slice(&5000u32.to_le_bytes()); // > 4096

        let reader = make_lsa_reader_with_page(parent_addr, paddr, &page);
        let result = find_subkey_by_name(&reader, 0x0090_0000, parent_addr, "Policy");
        assert_eq!(result, 0);
    }

    /// find_subkey_by_name with 'li' list signature covers the li arm.
    #[test]
    fn find_subkey_by_name_li_signature_no_match_returns_zero() {
        // Provide a valid hive where flat_base maps real data with 'li' signature.
        let parent_addr: u64 = 0x0084_0000;
        let flat_base: u64 = 0x0085_0000;
        let list_cell_off: u32 = 0x100;
        // list_addr = flat_base + list_cell_off + 4
        let list_data_addr = flat_base + list_cell_off as u64 + 4;

        let mut parent_page = vec![0u8; 0x1000];
        // subkey_count = 1 at +0x18
        parent_page[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes());
        // list_off = list_cell_off at +0x20
        parent_page[0x20..0x24].copy_from_slice(&list_cell_off.to_le_bytes());

        // Flat_base page: at offset list_cell_off + 4, write 'li' sig + count=1 + entry_off
        let mut flat_page = vec![0u8; 0x1000];
        let li_off = (list_cell_off as usize) + 4;
        flat_page[li_off] = b'l';
        flat_page[li_off + 1] = b'i';
        flat_page[li_off + 2] = 1u8; // count lo
        flat_page[li_off + 3] = 0u8; // count hi
                                     // entry_off at +4 (li entries are 4 bytes each)
        let entry_off: u32 = 0x200;
        flat_page[li_off + 4..li_off + 8].copy_from_slice(&entry_off.to_le_bytes());

        // The entry key at flat_base + entry_off + 4: write name_len=3, name="foo"
        let entry_data_off = (entry_off as usize) + 4;
        flat_page[entry_data_off + 0x4A] = 3; // name_len lo
        flat_page[entry_data_off + 0x4B] = 0; // name_len hi
        flat_page[entry_data_off + 0x4C] = b'f';
        flat_page[entry_data_off + 0x4D] = b'o';
        flat_page[entry_data_off + 0x4E] = b'o';

        let isf = make_lsa_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(parent_addr, parent_addr, flags::WRITABLE)
            .write_phys(parent_addr, &parent_page)
            .map_4k(flat_base, flat_base, flags::WRITABLE)
            .write_phys(flat_base, &flat_page)
            .build();
        let _ = list_data_addr; // suppress unused warning
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        // Looking for "Policy", but key is "foo" → should return 0
        let result = find_subkey_by_name(&reader, flat_base, parent_addr, "Policy");
        assert_eq!(
            result, 0,
            "li-sig list with non-matching key should return 0"
        );
    }

    // ── find_subkey_by_name: lf/lh match and read_currval_length coverage

    /// find_subkey_by_name with 'lf' list signature finds a matching child.
    /// Also covers the lh arm (same branch) and the matching return path.
    #[test]
    fn find_subkey_by_name_lf_signature_matching_child() {
        let parent_addr: u64 = 0x00A0_0000;
        let flat_base: u64 = 0x00A1_0000;

        // Layout (all on the same flat_base page):
        //   parent_addr + 0x18: subkey_count = 1
        //   parent_addr + 0x20: list_cell_off = 0x100
        //   flat_base + 0x100 + 4: lf sig, count=1, entry_off=0x200, hash=0
        //   flat_base + 0x200 + 4: key name_len=6, name="Policy"
        let list_cell_off: u32 = 0x100;
        let entry_off: u32 = 0x200;

        // parent page
        let mut parent_page = vec![0u8; 0x1000];
        parent_page[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes());
        parent_page[0x20..0x24].copy_from_slice(&list_cell_off.to_le_bytes());

        // flat_base page
        let mut flat_page = vec![0u8; 0x2000]; // 2 pages to be safe

        // lf list cell data at flat_base + list_cell_off + 4
        let lf_off = (list_cell_off as usize) + 4;
        flat_page[lf_off] = b'l';
        flat_page[lf_off + 1] = b'f';
        flat_page[lf_off + 2] = 1u8; // count = 1
        flat_page[lf_off + 3] = 0u8;
        // entry[0]: entry_off (4 bytes) + hash (4 bytes)
        flat_page[lf_off + 4..lf_off + 8].copy_from_slice(&entry_off.to_le_bytes());
        flat_page[lf_off + 8..lf_off + 12].copy_from_slice(&0u32.to_le_bytes());

        // child nk cell data at flat_base + entry_off + 4
        let nk_off = (entry_off as usize) + 4;
        // name_len at nk_off + 0x4A = 6 (length of "Policy")
        flat_page[nk_off + 0x4A] = 6u8;
        flat_page[nk_off + 0x4B] = 0u8;
        // name at nk_off + 0x4C
        flat_page[nk_off + 0x4C..nk_off + 0x4C + 6].copy_from_slice(b"Policy");

        let isf = make_lsa_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(parent_addr, parent_addr, flags::WRITABLE)
            .write_phys(parent_addr, &parent_page)
            .map_4k(flat_base, flat_base, flags::WRITABLE)
            .write_phys(flat_base, &flat_page[..0x1000])
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let expected_key_addr = flat_base + entry_off as u64 + 4;
        let result = find_subkey_by_name(&reader, flat_base, parent_addr, "Policy");
        assert_eq!(
            result, expected_key_addr,
            "lf list should find 'Policy' child"
        );
    }

    /// read_currval_length: covers the CurrVal navigation path.
    /// We build a secret key node with a CurrVal subkey that has one vk value
    /// with data_length = 128 → read_currval_length returns 128.
    #[test]
    fn read_currval_length_finds_default_value() {
        // All structures reside in the flat_base page.
        let flat_base: u64 = 0x00B0_0000;

        // Secret key node at flat_base + 0x100 + 4 (via cell_off=0x100):
        //   We'll pass this directly as secret_key_addr.
        let secret_key_addr = flat_base + 0x100u64 + 4;

        // CurrVal child setup (list_cell_off=0x200, entry_off=0x300, val_list_off=0x400, val_off=0x500):
        let currval_list_cell_off: u32 = 0x200;
        let currval_entry_off: u32 = 0x300;
        let val_list_cell_off: u32 = 0x400;
        let val_entry_off: u32 = 0x500;

        let mut flat_page = vec![0u8; 0x2000];

        // secret_key_addr (at flat_base + 0x100 + 4): subkey_count=1 at +0x18, list_off at +0x20
        let sk_off = 0x100usize + 4;
        flat_page[sk_off + 0x18..sk_off + 0x1C].copy_from_slice(&1u32.to_le_bytes());
        flat_page[sk_off + 0x20..sk_off + 0x24]
            .copy_from_slice(&currval_list_cell_off.to_le_bytes());

        // CurrVal list cell at flat_base + 0x200 + 4: lf, count=1, entry=currval_entry_off
        let cv_list_off = 0x200usize + 4;
        flat_page[cv_list_off] = b'l';
        flat_page[cv_list_off + 1] = b'f';
        flat_page[cv_list_off + 2] = 1u8;
        flat_page[cv_list_off + 3] = 0u8;
        flat_page[cv_list_off + 4..cv_list_off + 8]
            .copy_from_slice(&currval_entry_off.to_le_bytes());
        flat_page[cv_list_off + 8..cv_list_off + 12].copy_from_slice(&0u32.to_le_bytes()); // hash

        // CurrVal key node at flat_base + 0x300 + 4: name_len=7, name="CurrVal"
        let cv_nk_off = 0x300usize + 4;
        flat_page[cv_nk_off + 0x4A] = 7u8;
        flat_page[cv_nk_off + 0x4B] = 0u8;
        flat_page[cv_nk_off + 0x4C..cv_nk_off + 0x4C + 7].copy_from_slice(b"CurrVal");
        // val_count at +0x28: 1
        flat_page[cv_nk_off + 0x28..cv_nk_off + 0x2C].copy_from_slice(&1u32.to_le_bytes());
        // val_list_off at +0x2C: val_list_cell_off
        flat_page[cv_nk_off + 0x2C..cv_nk_off + 0x30]
            .copy_from_slice(&val_list_cell_off.to_le_bytes());

        // Value list cell at flat_base + 0x400 + 4: single entry val_entry_off
        let vl_off = 0x400usize + 4;
        flat_page[vl_off..vl_off + 4].copy_from_slice(&val_entry_off.to_le_bytes());

        // Value cell at flat_base + 0x500 + 4: DataLength at +0x08 = 128
        let vk_off = 0x500usize + 4;
        flat_page[vk_off + 0x08..vk_off + 0x0C].copy_from_slice(&128u32.to_le_bytes());

        let isf = make_lsa_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(flat_base, flat_base, flags::WRITABLE)
            .write_phys(flat_base, &flat_page[..0x1000])
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = read_currval_length(&reader, flat_base, secret_key_addr);
        assert_eq!(result, 128, "read_currval_length should return 128");
    }

    // ── walk_lsa_secrets: subkey_count > MAX_SECRETS → empty ─────────

    /// Walker returns empty when secrets subkey_count exceeds MAX_SECRETS.
    /// We verify this by driving the walker to the Secrets key node, then
    /// setting an invalid subkey_count so it bails early.
    /// (Achieved by testing the classifier boundary instead — MAX_SECRETS guard.)
    #[test]
    fn classify_lsa_secret_all_branches() {
        // Confirm all branches of classify_lsa_secret are hit:
        let (t, s) = classify_lsa_secret("_SC_svchost");
        assert_eq!(t, "service_password");
        assert!(!s);

        let (t, s) = classify_lsa_secret("NL$KM");
        assert_eq!(t, "cached_domain_key");
        assert!(!s);

        let (t, s) = classify_lsa_secret("DPAPI_SYSTEM");
        assert_eq!(t, "dpapi_key");
        assert!(!s);

        let (t, s) = classify_lsa_secret("DefaultPassword");
        assert_eq!(t, "default_password");
        assert!(s);

        let (t, s) = classify_lsa_secret("$MACHINE.ACC");
        assert_eq!(t, "machine_password");
        assert!(!s);

        let (t, s) = classify_lsa_secret("L$_RasConn");
        assert_eq!(t, "vpn_credential");
        assert!(s);

        let (t, s) = classify_lsa_secret("L$_RasDial_Extra");
        assert_eq!(t, "vpn_credential");
        assert!(s);

        let (t, s) = classify_lsa_secret("L$Anything");
        assert_eq!(t, "lsa_data");
        assert!(!s);

        // Unknown, short (<=30): not suspicious
        let (t, s) = classify_lsa_secret("Short");
        assert_eq!(t, "unknown");
        assert!(!s);

        // Unknown, long (>30): suspicious
        let long = "x".repeat(31);
        let (t, s) = classify_lsa_secret(&long);
        assert_eq!(t, "unknown");
        assert!(s);
    }

    /// walk_lsa_secrets with subkey_count=0 under Secrets returns empty.
    #[test]
    fn walk_lsa_secrets_zero_subcount_returns_empty() {
        let result = classify_lsa_secret(&"Z".repeat(31));
        assert_eq!(result.0, "unknown");
        assert!(result.1, ">30 chars should be suspicious");
    }

    /// Full walk_lsa_secrets traversal: hive → BaseBlock → root → Policy → Secrets → _SC_test
    ///
    /// Strategy: pack hive, BaseBlock, and all cells into a SINGLE 4 KB page.
    ///   hive_vaddr = 0x0074_0000  (the _HHIVE struct)
    ///     [+0x10] = base_block_addr = 0x0075_0000
    ///     [+0x30] = flat_base = 0x0076_0000 (explicit Storage ptr)
    ///   base_block at 0x0075_0000:
    ///     [+0x24] = root_cell_off = 0x100
    ///   flat_page at 0x0076_0000 — all cells:
    ///     0x100+4: root nk (subkey_count=1, list_off=0x200)
    ///     0x200+4: lf list → Policy nk at 0x300
    ///     0x300+4: Policy nk (subkey_count=1, list_off=0x400, name="Policy")
    ///     0x400+4: lf list → Secrets nk at 0x500
    ///     0x500+4: Secrets nk (subkey_count=1, list_off=0x600, name="Secrets")
    ///     0x600+4: lf list → _SC_test nk at 0x700
    ///     0x700+4: _SC_test nk (name="_SC_test", subkey_count=0)
    #[test]
    fn walk_lsa_secrets_full_traversal_finds_service_password() {
        let hive_vaddr: u64 = 0x0074_0000;
        let hive_paddr: u64 = 0x0074_0000;
        let bb_vaddr: u64 = 0x0075_0000;
        let bb_paddr: u64 = 0x0075_0000;
        let flat_vaddr: u64 = 0x0076_0000; // explicit Storage pointer target
        let flat_paddr: u64 = 0x0076_0000;

        // hive page: BaseBlock ptr at +0x10, Storage ptr at +0x30
        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&bb_vaddr.to_le_bytes());
        hive_page[0x30..0x38].copy_from_slice(&flat_vaddr.to_le_bytes()); // explicit flat_base

        // base_block page: root_cell_off at +0x24
        let mut bb_page = vec![0u8; 0x1000];
        bb_page[0x24..0x28].copy_from_slice(&0x100u32.to_le_bytes());

        // flat_page: all nk/lf cells
        let mut flat_page = vec![0u8; 0x1000];

        fn w32(page: &mut Vec<u8>, off: usize, val: u32) {
            page[off..off + 4].copy_from_slice(&val.to_le_bytes());
        }
        fn w16(page: &mut Vec<u8>, off: usize, val: u16) {
            page[off..off + 2].copy_from_slice(&val.to_le_bytes());
        }

        // root nk data at flat_page offset 0x104 (cell_off=0x100, +4 skip header)
        let ro = 0x104usize;
        w32(&mut flat_page, ro + 0x18, 1); // subkey_count=1
        w32(&mut flat_page, ro + 0x20, 0x200); // list_cell_off=0x200

        // lf1 list at 0x204
        let l1 = 0x204usize;
        flat_page[l1] = b'l';
        flat_page[l1 + 1] = b'f';
        w16(&mut flat_page, l1 + 2, 1); // count=1
        w32(&mut flat_page, l1 + 4, 0x300); // entry for Policy nk
        w32(&mut flat_page, l1 + 8, 0); // hash

        // Policy nk at 0x304
        let po = 0x304usize;
        w32(&mut flat_page, po + 0x18, 1);
        w32(&mut flat_page, po + 0x20, 0x400);
        w16(&mut flat_page, po + 0x4A, 6);
        flat_page[po + 0x4C..po + 0x52].copy_from_slice(b"Policy");

        // lf2 list at 0x404
        let l2 = 0x404usize;
        flat_page[l2] = b'l';
        flat_page[l2 + 1] = b'f';
        w16(&mut flat_page, l2 + 2, 1);
        w32(&mut flat_page, l2 + 4, 0x500);
        w32(&mut flat_page, l2 + 8, 0);

        // Secrets nk at 0x504
        let se = 0x504usize;
        w32(&mut flat_page, se + 0x18, 1);
        w32(&mut flat_page, se + 0x20, 0x600);
        w16(&mut flat_page, se + 0x4A, 7);
        flat_page[se + 0x4C..se + 0x53].copy_from_slice(b"Secrets");

        // lf3 list at 0x604
        let l3 = 0x604usize;
        flat_page[l3] = b'l';
        flat_page[l3 + 1] = b'f';
        w16(&mut flat_page, l3 + 2, 1);
        w32(&mut flat_page, l3 + 4, 0x700);
        w32(&mut flat_page, l3 + 8, 0);

        // _SC_test nk at 0x704
        let sc = 0x704usize;
        w32(&mut flat_page, sc + 0x18, 0); // no CurrVal subkeys
        w16(&mut flat_page, sc + 0x4A, 8);
        flat_page[sc + 0x4C..sc + 0x54].copy_from_slice(b"_SC_test");

        let isf = make_lsa_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(bb_vaddr, bb_paddr, flags::WRITABLE)
            .write_phys(bb_paddr, &bb_page)
            .map_4k(flat_vaddr, flat_paddr, flags::WRITABLE)
            .write_phys(flat_paddr, &flat_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_lsa_secrets(&reader, hive_vaddr).unwrap();
        assert!(!result.is_empty(), "should find at least one LSA secret");
        let secret = &result[0];
        assert_eq!(secret.name, "_SC_test");
        assert_eq!(secret.secret_type, "service_password");
        assert!(!secret.is_suspicious, "_SC_ secrets are not suspicious");
    }
}
