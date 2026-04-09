//! Domain Cached Credential (DCC/MSCachev2) extraction from Windows memory dumps.
//!
//! When domain users log in to a Windows machine, their credential hashes
//! are cached in `HKLM\SECURITY\Cache` as `NL$1`, `NL$2`, ... entries.
//! These Domain Cached Credentials (DCC2/MSCachev2) can be extracted for
//! offline cracking. This is the memory forensic equivalent of Volatility's
//! `cachedump` plugin.
//!
//! The SECURITY hive cache is structured as:
//! `SECURITY\Cache\NL$1` — first cached credential entry
//! `SECURITY\Cache\NL$2` — second cached credential entry
//! ...up to `NL$10` (typical maximum, configurable via CachedLogonsCount)
//!
//! Each cache entry value contains a DCC2 header (96 bytes) followed by
//! UTF-16LE encoded username and domain name strings.

use std::collections::HashSet;

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// Maximum number of cached credential entries to enumerate (safety limit).
const MAX_CACHED_CREDS: usize = 64;

/// Information about a domain cached credential recovered from the SECURITY hive.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CachedCredentialInfo {
    /// Domain username associated with the cached credential.
    pub username: String,
    /// Domain name the user authenticated against.
    pub domain: String,
    /// Domain SID string (extracted from cache entry metadata).
    pub domain_sid: String,
    /// PBKDF2 iteration count used for the DCC2 hash derivation.
    pub iteration_count: u32,
    /// Length of the hash data portion in bytes.
    pub hash_data_length: u32,
    /// Whether this cached credential is suspicious based on heuristics.
    pub is_suspicious: bool,
}

/// Classify a cached domain credential as suspicious.
///
/// Returns `true` for credentials that match anomalous patterns:
/// - `iteration_count < 10240`: older/weaker hash (pre-Vista default was 1024)
/// - Empty domain name: indicates corrupted or tampered entry
/// - Username contains characters atypical of Active Directory usernames
///   (AD usernames are alphanumeric plus `.`, `-`, `_`)
pub fn classify_cached_credential(username: &str, domain: &str, iteration_count: u32) -> bool {
    // Older/weaker iteration count (Vista+ default is 10240)
    if iteration_count < 10240 {
        return true;
    }

    // Empty domain is anomalous — every valid cached cred has a domain
    if domain.is_empty() {
        return true;
    }

    // Check username for characters atypical of AD usernames.
    // Valid AD sAMAccountName chars: alphanumeric, '.', '-', '_'
    if !username.is_empty()
        && username
            .chars()
            .any(|c| !c.is_alphanumeric() && c != '.' && c != '-' && c != '_')
    {
        return true;
    }

    false
}

/// Extract domain cached credentials from the SECURITY registry hive in memory.
///
/// Navigates `SECURITY\Cache` in the registry hive at `security_hive_addr`,
/// reads `NL$1` through `NL$10` value entries, parses the DCC2 header to
/// extract username, domain, iteration count, and hash metadata, classifies
/// each entry, and returns the results.
///
/// Returns an empty `Vec` if the hive address is zero or navigation fails.
pub fn walk_cached_credentials<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    security_hive_addr: u64,
) -> crate::Result<Vec<CachedCredentialInfo>> {
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
            if addr != 0 { addr } else { base_block_addr + 0x1000 }
        }
        _ => base_block_addr + 0x1000,
    };

    // Navigate: root → Cache
    let root_addr = read_cell_addr(reader, flat_base, root_cell_off);
    if root_addr == 0 {
        return Ok(Vec::new());
    }

    let cache_key = find_subkey_by_name(reader, flat_base, root_addr, "Cache");
    if cache_key == 0 {
        return Ok(Vec::new());
    }

    // Enumerate NL$1 through NL$10 value entries under the Cache key.
    let val_count: u32 = match reader.read_bytes(cache_key + 0x28, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return Ok(Vec::new()),
    };

    if val_count == 0 {
        return Ok(Vec::new());
    }

    let val_list_off: u32 = match reader.read_bytes(cache_key + 0x2C, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return Ok(Vec::new()),
    };

    let val_list_addr = read_cell_addr(reader, flat_base, val_list_off);
    if val_list_addr == 0 {
        return Ok(Vec::new());
    }

    let mut results = Vec::new();
    let mut seen_addrs: HashSet<u64> = HashSet::new();

    // Scan all values, looking for NL$1..NL$10 by name.
    for v in 0..val_count.min(MAX_CACHED_CREDS as u32) {
        let val_off: u32 = match reader.read_bytes(val_list_addr + (v as u64) * 4, 4) {
            Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            _ => continue,
        };

        let val_addr = read_cell_addr(reader, flat_base, val_off);
        if val_addr == 0 {
            continue;
        }

        // Cycle detection.
        if !seen_addrs.insert(val_addr) {
            continue;
        }

        // _CM_KEY_VALUE: NameLength at 0x02 (u16), Name at 0x18.
        let vname_len: u16 = match reader.read_bytes(val_addr + 0x02, 2) {
            Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
            _ => continue,
        };

        if vname_len == 0 || vname_len > 256 {
            continue;
        }

        let vname = match reader.read_bytes(val_addr + 0x18, vname_len as usize) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            _ => continue,
        };

        // Only process NL$1 through NL$10 entries.
        if !is_nl_entry(&vname) {
            continue;
        }

        // Read value data: DataLength at 0x08 (u32), DataOffset at 0x0C (u32).
        let data_len: u32 = match reader.read_bytes(val_addr + 0x08, 4) {
            Ok(bytes) if bytes.len() == 4 => {
                u32::from_le_bytes(bytes[..4].try_into().unwrap()) & 0x7FFF_FFFF
            }
            _ => continue,
        };

        // DCC2 header is 96 bytes minimum; skip entries with insufficient data.
        if data_len < 96 {
            continue;
        }

        let data_off: u32 = match reader.read_bytes(val_addr + 0x0C, 4) {
            Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            _ => continue,
        };

        let data_addr = read_cell_addr(reader, flat_base, data_off);
        if data_addr == 0 {
            continue;
        }

        // Parse DCC2 header:
        //   offset 0x00: username length (u16, in bytes)
        //   offset 0x04: domain length (u16, in bytes)
        //   offset 0x28 (40): iteration count (u32)
        let username_len: u16 = match reader.read_bytes(data_addr, 2) {
            Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
            _ => continue,
        };

        let domain_len: u16 = match reader.read_bytes(data_addr + 4, 2) {
            Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
            _ => continue,
        };

        let iteration_count: u32 = match reader.read_bytes(data_addr + 40, 4) {
            Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            _ => continue,
        };

        // Skip empty entries (username_len == 0 means unused cache slot).
        if username_len == 0 {
            continue;
        }

        // Sanity-check string lengths.
        if username_len > 512 || domain_len > 512 {
            continue;
        }

        // Username starts at offset 96 (after the 96-byte header), UTF-16LE.
        let username = match reader.read_bytes(data_addr + 96, username_len as usize) {
            Ok(bytes) => decode_utf16le(&bytes),
            _ => continue,
        };

        // Domain follows username (aligned to 2-byte boundary, but typically
        // directly after username_len bytes from offset 96).
        let domain_offset = 96 + username_len as u64;
        let domain = match reader.read_bytes(data_addr + domain_offset, domain_len as usize) {
            Ok(bytes) => decode_utf16le(&bytes),
            _ => continue,
        };

        // Hash data length is the total data minus the header and string data.
        let strings_total = username_len as u32 + domain_len as u32;
        let hash_data_length = data_len.saturating_sub(96 + strings_total);

        let is_suspicious = classify_cached_credential(&username, &domain, iteration_count);

        results.push(CachedCredentialInfo {
            username,
            domain,
            domain_sid: String::new(), // SID extraction requires additional parsing
            iteration_count,
            hash_data_length,
            is_suspicious,
        });
    }

    Ok(results)
}

/// Check if a value name is a cached credential entry (`NL$1` through `NL$10`).
fn is_nl_entry(name: &str) -> bool {
    if let Some(suffix) = name.strip_prefix("NL$") {
        matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "10")
    } else {
        false
    }
}

/// Decode a UTF-16LE byte slice into a String.
fn decode_utf16le(bytes: &[u8]) -> String {
    let u16_iter = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    String::from_utf16_lossy(&u16_iter.collect::<Vec<u16>>())
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
            [b'l', b'i'] => {
                match reader.read_bytes(list_addr + 4 + (i as u64) * 4, 4) {
                    Ok(bytes) if bytes.len() == 4 => {
                        u32::from_le_bytes(bytes[..4].try_into().unwrap())
                    }
                    _ => continue,
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ── Classifier tests ─────────────────────────────────────────────

    /// Normal domain credential with sufficient iteration count is benign.
    #[test]
    fn classify_benign_domain_cred() {
        assert!(
            !classify_cached_credential("john.doe", "CONTOSO", 10240),
            "Normal domain cred with iteration_count=10240 should not be suspicious"
        );
    }

    /// High iteration count with standard username is benign.
    #[test]
    fn classify_benign_high_iteration() {
        assert!(
            !classify_cached_credential("admin_user", "CORP.LOCAL", 20480),
            "High iteration count domain cred should not be suspicious"
        );
    }

    /// Low iteration count (pre-Vista default) is suspicious.
    #[test]
    fn classify_suspicious_low_iteration() {
        assert!(
            classify_cached_credential("user1", "DOMAIN", 1024),
            "iteration_count=1024 (below 10240) should be suspicious"
        );
    }

    /// Empty domain name is suspicious (corrupted/tampered entry).
    #[test]
    fn classify_suspicious_empty_domain() {
        assert!(
            classify_cached_credential("user1", "", 10240),
            "Empty domain should be suspicious"
        );
    }

    /// Username with special characters atypical of AD is suspicious.
    #[test]
    fn classify_suspicious_special_chars() {
        assert!(
            classify_cached_credential("user@evil", "DOMAIN", 10240),
            "Username with '@' should be suspicious (not a valid AD sAMAccountName char)"
        );
    }

    /// Username with spaces is suspicious.
    #[test]
    fn classify_suspicious_space_in_username() {
        assert!(
            classify_cached_credential("user name", "DOMAIN", 10240),
            "Username with space should be suspicious"
        );
    }

    // ── Walker tests ─────────────────────────────────────────────────

    /// Zero hive address returns empty Vec (graceful degradation).
    #[test]
    fn walk_cached_credentials_zero_addr() {
        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .add_field("_HHIVE", "BaseBlock", 0x10, "pointer")
            .add_field("_HHIVE", "Storage", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_cached_credentials(&reader, 0).unwrap();
        assert!(result.is_empty(), "Zero hive address should return empty Vec");
    }

    /// Non-zero but unmapped hive address degrades gracefully to empty Vec.
    #[test]
    fn walk_cached_credentials_unmapped_addr_graceful() {
        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .add_field("_HHIVE", "BaseBlock", 0x10, "pointer")
            .add_field("_HHIVE", "Storage", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // Non-zero but unmapped address should return empty Vec, not panic.
        let result = walk_cached_credentials(&reader, 0xDEAD_BEEF).unwrap();
        assert!(result.is_empty(), "Unmapped hive address should degrade gracefully");
    }
}
