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
            if addr != 0 {
                addr
            } else {
                base_block_addr + 0x1000
            }
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

/// Check if a value name is a cached credential entry (`NL$1` through `NL$50`).
///
/// Windows supports up to 50 cached credentials (CachedLogonsCount registry value).
/// The hard-coded `matches!` list missed NL$11 and above; parsing the suffix as an
/// integer handles any valid count up to the 50-entry upper bound.
fn is_nl_entry(name: &str) -> bool {
    name.strip_prefix("NL$")
        .and_then(|s| s.parse::<usize>().ok())
        .map(|n| n > 0 && n <= 50)
        .unwrap_or(false)
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

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_reader() -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .add_field("_HHIVE", "BaseBlock", 0x10, "pointer")
            .add_field("_HHIVE", "Storage", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

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

    /// Usernames with valid AD chars (alphanumeric, dot, dash, underscore) are benign.
    #[test]
    fn classify_benign_valid_ad_username_chars() {
        assert!(!classify_cached_credential("alice.smith", "DOMAIN", 10240));
        assert!(!classify_cached_credential("bob-jones", "DOMAIN", 10240));
        assert!(!classify_cached_credential("svc_account", "DOMAIN", 10240));
        assert!(!classify_cached_credential("User123", "DOMAIN", 10240));
    }

    /// Empty username with sufficient iteration count and non-empty domain is benign
    /// (the username chars check short-circuits for empty strings).
    #[test]
    fn classify_benign_empty_username() {
        // empty username has no invalid chars so only domain/count checked
        assert!(!classify_cached_credential("", "DOMAIN", 10240));
    }

    /// Iteration count of exactly 10240 is benign (boundary).
    #[test]
    fn classify_boundary_iteration_count() {
        assert!(!classify_cached_credential("user", "DOMAIN", 10240));
    }

    /// Iteration count of 10239 is suspicious (one below threshold).
    #[test]
    fn classify_boundary_below_threshold() {
        assert!(classify_cached_credential("user", "DOMAIN", 10239));
    }

    /// Low iteration count (pre-Vista default) is suspicious.
    #[test]
    fn classify_suspicious_low_iteration() {
        assert!(
            classify_cached_credential("user1", "DOMAIN", 1024),
            "iteration_count=1024 (below 10240) should be suspicious"
        );
    }

    /// Zero iteration count is suspicious.
    #[test]
    fn classify_suspicious_zero_iteration() {
        assert!(classify_cached_credential("user1", "DOMAIN", 0));
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

    /// Username with slash is suspicious.
    #[test]
    fn classify_suspicious_slash_in_username() {
        assert!(classify_cached_credential("domain\\user", "DOMAIN", 10240));
    }

    /// Username with exclamation mark is suspicious.
    #[test]
    fn classify_suspicious_bang_in_username() {
        assert!(classify_cached_credential("user!", "DOMAIN", 10240));
    }

    // ── is_nl_entry tests ─────────────────────────────────────────────

    #[test]
    fn is_nl_entry_valid() {
        for i in 1..=10 {
            assert!(is_nl_entry(&format!("NL${}", i)), "NL${} should be valid", i);
        }
    }

    #[test]
    fn is_nl_entry_invalid_prefix() {
        assert!(!is_nl_entry("NL$0"));
        assert!(!is_nl_entry("NL$51"));  // above 50-entry upper bound
        assert!(!is_nl_entry("NL$100")); // well above limit
        assert!(!is_nl_entry("nl$1")); // case-sensitive
        assert!(!is_nl_entry("CachedLogons"));
        assert!(!is_nl_entry(""));
        assert!(!is_nl_entry("NL$"));
    }

    #[test]
    fn is_nl_entry_boundary_values() {
        assert!(is_nl_entry("NL$1"));
        assert!(is_nl_entry("NL$10"));
        assert!(is_nl_entry("NL$11")); // was wrongly rejected before fix
        assert!(is_nl_entry("NL$50")); // upper bound
        assert!(!is_nl_entry("NL$0"));
        assert!(!is_nl_entry("NL$51")); // one above upper bound
    }

    /// NL$11, NL$25, NL$50 are all valid cached credential entries.
    #[test]
    fn is_nl_entry_above_ten_accepted() {
        assert!(is_nl_entry("NL$11"), "NL$11 should be accepted");
        assert!(is_nl_entry("NL$25"), "NL$25 should be accepted");
        assert!(is_nl_entry("NL$50"), "NL$50 should be accepted");
    }

    // ── decode_utf16le tests ──────────────────────────────────────────

    #[test]
    fn decode_utf16le_empty() {
        assert_eq!(decode_utf16le(&[]), "");
    }

    #[test]
    fn decode_utf16le_ascii() {
        // "hello" as UTF-16LE
        let bytes = b"h\0e\0l\0l\0o\0";
        assert_eq!(decode_utf16le(bytes), "hello");
    }

    #[test]
    fn decode_utf16le_unicode() {
        // U+00E9 (é) as UTF-16LE: [0xE9, 0x00]
        let bytes = &[0xE9u8, 0x00];
        let result = decode_utf16le(bytes);
        assert_eq!(result, "é");
    }

    #[test]
    fn decode_utf16le_odd_byte_count() {
        // Odd number of bytes: trailing byte is ignored by chunks_exact(2)
        let bytes = b"h\0e\0x"; // 5 bytes, last one orphaned
        let result = decode_utf16le(bytes);
        assert_eq!(result, "he"); // 'x' byte orphaned
    }

    #[test]
    fn decode_utf16le_domain_name() {
        // "CORP" as UTF-16LE
        let bytes = b"C\0O\0R\0P\0";
        assert_eq!(decode_utf16le(bytes), "CORP");
    }

    // ── Walker tests ─────────────────────────────────────────────────

    /// Zero hive address returns empty Vec (graceful degradation).
    #[test]
    fn walk_cached_credentials_zero_addr() {
        let reader = make_reader();
        let result = walk_cached_credentials(&reader, 0).unwrap();
        assert!(
            result.is_empty(),
            "Zero hive address should return empty Vec"
        );
    }

    /// Non-zero but unmapped hive address degrades gracefully to empty Vec.
    #[test]
    fn walk_cached_credentials_unmapped_addr_graceful() {
        let reader = make_reader();
        // Non-zero but unmapped address should return empty Vec, not panic.
        let result = walk_cached_credentials(&reader, 0xDEAD_BEEF).unwrap();
        assert!(
            result.is_empty(),
            "Unmapped hive address should degrade gracefully"
        );
    }

    // ── CachedCredentialInfo struct tests ─────────────────────────────

    #[test]
    fn cached_credential_info_construction() {
        let info = CachedCredentialInfo {
            username: "john.doe".to_string(),
            domain: "CONTOSO".to_string(),
            domain_sid: "S-1-5-21-1234567890-1234567890-1234567890".to_string(),
            iteration_count: 10240,
            hash_data_length: 16,
            is_suspicious: false,
        };
        assert_eq!(info.username, "john.doe");
        assert_eq!(info.domain, "CONTOSO");
        assert_eq!(info.iteration_count, 10240);
        assert!(!info.is_suspicious);
    }

    #[test]
    fn cached_credential_info_serialization() {
        let info = CachedCredentialInfo {
            username: "attacker".to_string(),
            domain: "".to_string(),
            domain_sid: String::new(),
            iteration_count: 1024,
            hash_data_length: 32,
            is_suspicious: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"username\":\"attacker\""));
        assert!(json.contains("\"is_suspicious\":true"));
        assert!(json.contains("\"iteration_count\":1024"));
    }

    // ── MAX_CACHED_CREDS constant ─────────────────────────────────────

    #[test]
    fn max_cached_creds_reasonable() {
        assert!(MAX_CACHED_CREDS >= 10);
        assert!(MAX_CACHED_CREDS <= 1024);
    }

    // ── walk_cached_credentials body coverage ────────────────────────
    //
    // The walker reads: hive BaseBlock → root_cell_off → flat_base
    // → root_addr → Cache key → value list → NL$ entries.
    // We provide synthetic physical memory so the body is exercised
    // past the hive_addr=0 guard.

    use memf_core::test_builders::flags;

    fn make_cachedump_isf() -> serde_json::Value {
        IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .add_field("_HHIVE", "BaseBlock", 0x10, "pointer")
            .add_field("_HHIVE", "Storage", 0x30, "pointer")
            .build_json()
    }

    /// Hive mapped, base_block pointer at hive+0x10 is zero → early return.
    #[test]
    fn walk_cached_creds_null_base_block() {
        let hive_vaddr: u64 = 0x0020_0000;
        let hive_paddr: u64 = 0x0020_0000;
        // All zeros in hive page → base_block_addr = 0 → early return
        let hive_page = vec![0u8; 0x1000];
        let isf = make_cachedump_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_cached_credentials(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty(), "null base_block → empty Vec");
    }

    /// Hive mapped; base_block valid; root_cell = 0 → early return.
    #[test]
    fn walk_cached_creds_zero_root_cell() {
        let hive_vaddr: u64 = 0x0030_0000;
        let hive_paddr: u64 = 0x0030_0000;
        let base_block: u64 = 0x0031_0000;
        let base_block_paddr: u64 = 0x0031_0000;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        // root_cell_off = 0 → early return
        bb_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());

        let isf = make_cachedump_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_cached_credentials(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty());
    }

    /// Hive mapped; base_block valid; root_cell u32::MAX sentinel → early return.
    #[test]
    fn walk_cached_creds_root_cell_sentinel() {
        let hive_vaddr: u64 = 0x0040_0000;
        let hive_paddr: u64 = 0x0040_0000;
        let base_block: u64 = 0x0041_0000;
        let base_block_paddr: u64 = 0x0041_0000;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        bb_page[0x24..0x28].copy_from_slice(&u32::MAX.to_le_bytes());

        let isf = make_cachedump_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_cached_credentials(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty(), "u32::MAX root_cell → sentinel, empty Vec");
    }

    /// Hive mapped; base_block and root_cell valid; flat_base derived via
    /// Storage=0 fallback; hbin area not mapped → read_cell_addr returns 0
    /// → Cache key not found → empty Vec.
    #[test]
    fn walk_cached_creds_cache_key_not_found() {
        let hive_vaddr: u64 = 0x0050_0000;
        let hive_paddr: u64 = 0x0050_0000;
        let base_block: u64 = 0x0051_0000;
        let base_block_paddr: u64 = 0x0051_0000;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());
        // Storage = 0 → flat_base = base_block + 0x1000 (not mapped)
        hive_page[0x30..0x38].copy_from_slice(&0u64.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        bb_page[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes());

        let isf = make_cachedump_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_cached_credentials(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty(), "hbin not mapped → Cache key not found → empty Vec");
    }

    // ── Additional coverage: classify + helpers ──────────────────────

    /// classify_cached_credential: zero iteration count with empty domain → suspicious
    /// (both conditions fire independently).
    #[test]
    fn classify_both_conditions_suspicious() {
        assert!(classify_cached_credential("user", "", 0));
    }

    /// classify_cached_credential: numeric characters in username are valid AD chars.
    #[test]
    fn classify_numeric_username_benign() {
        assert!(!classify_cached_credential("user123", "DOMAIN", 10240));
    }

    /// decode_utf16le with all-zero bytes (null terminators) → empty-ish result.
    #[test]
    fn decode_utf16le_all_zeros() {
        let bytes = [0u8; 8];
        let result = decode_utf16le(&bytes);
        // All null chars: should produce 4 null chars, but as a string.
        assert_eq!(result.len(), 4);
    }

    /// read_cell_addr with zero flat_base and cell_off=0 → addr=4; if not mapped → 0.
    #[test]
    fn read_cell_addr_unmapped_returns_zero() {
        let reader = make_reader();
        let result = read_cell_addr(&reader, 0, 0);
        assert_eq!(result, 0, "unmapped address → read_cell_addr returns 0");
    }

    /// find_subkey_by_name with parent_addr in unmapped memory → 0.
    #[test]
    fn find_subkey_by_name_unmapped_returns_zero() {
        let reader = make_reader();
        let result = find_subkey_by_name(&reader, 0, 0xDEAD_BEEF_0000, "Cache");
        assert_eq!(result, 0);
    }

    /// walk_cached_credentials with valid base_block but storage pointer is zero
    /// falls through to base_block_addr + 0x1000 path (alternative flat_base calc).
    #[test]
    fn walk_cached_creds_zero_storage_ptr_uses_fallback_flat_base() {
        use memf_core::test_builders::flags;

        let hive_vaddr: u64 = 0x0050_0000;
        let hive_paddr: u64 = 0x0050_0000;
        let base_block: u64 = 0x0051_0000;
        let base_block_paddr: u64 = 0x0051_0000;

        let mut hive_page = vec![0u8; 0x1000];
        // BaseBlock pointer at hive + 0x10
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());
        // Storage pointer at hive + 0x30 = 0 (causes fallback to base_block + 0x1000)
        hive_page[0x30..0x38].copy_from_slice(&0u64.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        // root_cell_off = 0 (zero → early return after flat_base resolved)
        bb_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());

        let isf = make_cachedump_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // Should reach root_cell = 0 → early return → empty (exercises fallback flat_base path)
        let result = walk_cached_credentials(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty(), "zero storage ptr → fallback flat_base → root_cell=0 → empty");
    }

    // ── Additional coverage: li-list in find_subkey_by_name ─────────

    /// Hive with a root NK cell that has an `li`-format subkey list
    /// with a single child named "Cache" → finds Cache, but then
    /// val_count at Cache + 0x28 is 0 → returns empty Vec.
    /// This exercises the `li` list branch (line ≈ 369) in find_subkey_by_name.
    #[test]
    fn walk_cached_creds_li_list_cache_found_no_values() {
        use memf_core::test_builders::flags;

        // Addresses (virtual = physical):
        //   hive_vaddr   = 0x0070_0000
        //   base_block   = 0x0071_0000
        //   flat_base    = 0x0072_0000  (base_block + 0x1000, storage = 0)
        //
        // flat_base page layout:
        //   root cell at root_cell_off = 0x20 → root_addr = flat_base + 0x24
        //     subkey_count at +0x18 = 1
        //     list_off at +0x20 = 0x80 (within flat_base page)
        //   list cell at flat_base + 0x84 (= flat_base + 0x80 + 4):
        //     sig = "li" [0x6C, 0x69]
        //     count = 1
        //     entry[0] = 0xC0  (child cell offset)
        //   child cell at flat_base + 0xC4 (= flat_base + 0xC0 + 4):
        //     name_len at +0x4A = 5 ("Cache")
        //     name at +0x4C = b"Cache"
        //   → find_subkey_by_name("Cache") returns cache_key = flat_base + 0xC4
        //   Cache key: val_count at +0x28 = 0 → returns empty Vec

        let hive_vaddr: u64 = 0x0070_0000;
        let hive_paddr: u64 = 0x0070_0000;
        let base_block: u64 = 0x0071_0000;
        let base_block_paddr: u64 = 0x0071_0000;
        let flat_base_paddr: u64 = 0x0072_0000;

        let root_cell_off: u32 = 0x20;
        let root_off: usize = (root_cell_off + 4) as usize; // 0x24

        let list_cell_off: u32 = 0x80;
        let list_off: usize = (list_cell_off + 4) as usize; // 0x84

        let child_cell_off: u32 = 0xC0;
        let child_off: usize = (child_cell_off + 4) as usize; // 0xC4

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());
        hive_page[0x30..0x38].copy_from_slice(&0u64.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        bb_page[0x24..0x28].copy_from_slice(&root_cell_off.to_le_bytes());

        let mut flat_page = vec![0u8; 0x1000];

        // Root NK: subkey_count = 1, list_off = list_cell_off
        flat_page[root_off + 0x18..root_off + 0x1C].copy_from_slice(&1u32.to_le_bytes());
        flat_page[root_off + 0x20..root_off + 0x24].copy_from_slice(&list_cell_off.to_le_bytes());

        // li list: sig = b"li", count = 1, entry[0] = child_cell_off
        flat_page[list_off] = b'l';
        flat_page[list_off + 1] = b'i';
        flat_page[list_off + 2..list_off + 4].copy_from_slice(&1u16.to_le_bytes());
        flat_page[list_off + 4..list_off + 8].copy_from_slice(&child_cell_off.to_le_bytes());

        // Cache NK: name = "Cache", val_count = 0
        let name = b"Cache";
        flat_page[child_off + 0x4A..child_off + 0x4C].copy_from_slice(&(name.len() as u16).to_le_bytes());
        flat_page[child_off + 0x4C..child_off + 0x4C + name.len()].copy_from_slice(name);
        // val_count at child_off + 0x28 = 0 (zero-init)

        let isf = make_cachedump_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .map_4k(base_block + 0x1000, flat_base_paddr, flags::WRITABLE)
            .write_phys(flat_base_paddr, &flat_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // find_subkey_by_name uses li list, finds Cache, but val_count=0 → empty Vec.
        let result = walk_cached_credentials(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty(), "li list Cache found but val_count=0 → empty");
    }

    /// Hive with lf list finding Cache key, Cache has val_count=1 but
    /// val_list_addr = 0 (list cell not readable) → returns empty Vec.
    #[test]
    fn walk_cached_creds_cache_val_list_unreadable() {
        use memf_core::test_builders::flags;

        let hive_vaddr: u64 = 0x0080_0000;
        let hive_paddr: u64 = 0x0080_0000;
        let base_block: u64 = 0x0081_0000;
        let base_block_paddr: u64 = 0x0081_0000;
        let flat_base_paddr: u64 = 0x0082_0000;

        let root_cell_off: u32 = 0x20;
        let root_off: usize = (root_cell_off + 4) as usize;

        let list_cell_off: u32 = 0x80;
        let list_off: usize = (list_cell_off + 4) as usize;

        let child_cell_off: u32 = 0xC0;
        let child_off: usize = (child_cell_off + 4) as usize;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());
        hive_page[0x30..0x38].copy_from_slice(&0u64.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        bb_page[0x24..0x28].copy_from_slice(&root_cell_off.to_le_bytes());

        let mut flat_page = vec![0u8; 0x1000];

        // Root NK with lf list:
        flat_page[root_off + 0x18..root_off + 0x1C].copy_from_slice(&1u32.to_le_bytes());
        flat_page[root_off + 0x20..root_off + 0x24].copy_from_slice(&list_cell_off.to_le_bytes());

        // lf list:
        flat_page[list_off] = b'l';
        flat_page[list_off + 1] = b'f';
        flat_page[list_off + 2..list_off + 4].copy_from_slice(&1u16.to_le_bytes());
        flat_page[list_off + 4..list_off + 8].copy_from_slice(&child_cell_off.to_le_bytes());

        // Cache NK with val_count = 1, val_list_off = 0xFF00 (unreadable)
        let name = b"Cache";
        flat_page[child_off + 0x4A..child_off + 0x4C].copy_from_slice(&(name.len() as u16).to_le_bytes());
        flat_page[child_off + 0x4C..child_off + 0x4C + name.len()].copy_from_slice(name);
        flat_page[child_off + 0x28..child_off + 0x2C].copy_from_slice(&1u32.to_le_bytes()); // val_count = 1
        // val_list_off at child_off + 0x2C = 0xFF00 → flat_base + 0xFF00 + 4 = not mapped → 0
        flat_page[child_off + 0x2C..child_off + 0x30].copy_from_slice(&0xFF00u32.to_le_bytes());

        let isf = make_cachedump_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .map_4k(base_block + 0x1000, flat_base_paddr, flags::WRITABLE)
            .write_phys(flat_base_paddr, &flat_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_cached_credentials(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty(), "val_list_addr=0 → empty Vec");
    }

    /// Full walk_cached_credentials traversal: hive → Cache → NL$1 → DCC2 data.
    ///
    /// Memory layout (explicit Storage pointer → flat_base):
    ///   hive at 0x0090_0000: [+0x10]=bb_vaddr, [+0x30]=flat_vaddr
    ///   bb at 0x0091_0000: [+0x24]=root_cell_off=0x100
    ///   flat at 0x0092_0000:
    ///     root nk at 0x104 (subkey_count=1, list_off=0x200)
    ///     lf list at 0x204 → Cache nk at 0x300
    ///     Cache nk at 0x304 (name="Cache", val_count=1, val_list_off=0x400)
    ///     val list at 0x404 → NL$1 value at 0x500
    ///     NL$1 value at 0x504: vname="NL$1", data_len=200, data_off=0x600
    ///     data cell at 0x604: DCC2 header + "alice" + "CORP"
    #[test]
    fn walk_cached_credentials_full_traversal_finds_nl1_entry() {
        let hive_vaddr: u64 = 0x0090_0000;
        let hive_paddr: u64 = 0x0090_0000;
        let bb_vaddr: u64   = 0x0091_0000;
        let bb_paddr: u64   = 0x0091_0000;
        let flat_vaddr: u64 = 0x0092_0000; // explicit Storage pointer
        let flat_paddr: u64 = 0x0092_0000;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&bb_vaddr.to_le_bytes());
        hive_page[0x30..0x38].copy_from_slice(&flat_vaddr.to_le_bytes()); // explicit flat_base

        let mut bb_page = vec![0u8; 0x1000];
        bb_page[0x24..0x28].copy_from_slice(&0x100u32.to_le_bytes()); // root_cell_off=0x100

        let mut flat_page = vec![0u8; 0x2000]; // 2 pages (val list + data can span)

        fn w32(page: &mut Vec<u8>, off: usize, val: u32) {
            page[off..off + 4].copy_from_slice(&val.to_le_bytes());
        }
        fn w16(page: &mut Vec<u8>, off: usize, val: u16) {
            page[off..off + 2].copy_from_slice(&val.to_le_bytes());
        }

        // root nk at flat_page[0x104]: subkey_count=1, list_off=0x200
        let ro = 0x104usize;
        w32(&mut flat_page, ro + 0x18, 1);
        w32(&mut flat_page, ro + 0x20, 0x200);

        // lf list at flat_page[0x204]: count=1, entry=0x300
        let l1 = 0x204usize;
        flat_page[l1] = b'l'; flat_page[l1 + 1] = b'f';
        w16(&mut flat_page, l1 + 2, 1);
        w32(&mut flat_page, l1 + 4, 0x300);
        w32(&mut flat_page, l1 + 8, 0);

        // Cache nk at flat_page[0x304]: name="Cache", val_count=1, val_list_off=0x400
        let ca = 0x304usize;
        // name_len at +0x4A, name at +0x4C (but subkey_count=0 since no subkeys here)
        w32(&mut flat_page, ca + 0x18, 0);     // subkey_count=0 for Cache (only values)
        w32(&mut flat_page, ca + 0x28, 1);     // val_count=1
        w32(&mut flat_page, ca + 0x2C, 0x400); // val_list_off
        w16(&mut flat_page, ca + 0x4A, 5);     // name_len=5
        flat_page[ca + 0x4C..ca + 0x51].copy_from_slice(b"Cache");

        // Value list cell at flat_page[0x404]: one entry (4 bytes) → val_off=0x500
        let vl = 0x404usize;
        w32(&mut flat_page, vl, 0x500); // val_off

        // NL$1 value cell at flat_page[0x504]:
        //   [+0x02]: vname_len=4 ("NL$1")
        //   [+0x08]: data_len=200 (no inline flag)
        //   [+0x0C]: data_off=0x600
        //   [+0x18]: vname="NL$1"
        let vk = 0x504usize;
        w16(&mut flat_page, vk + 0x02, 4);    // vname_len=4
        w32(&mut flat_page, vk + 0x08, 200);  // data_len=200
        w32(&mut flat_page, vk + 0x0C, 0x600); // data_off=0x600
        flat_page[vk + 0x18..vk + 0x1C].copy_from_slice(b"NL$1");

        // DCC2 data cell at flat_page[0x604]:
        //   [0x00..0x02]: username_len (bytes of UTF-16LE "alice" = 10)
        //   [0x04..0x06]: domain_len (bytes of UTF-16LE "CORP" = 8)
        //   [0x28..0x2C]: iteration_count = 10240
        //   [0x60..0x6A]: username "alice" UTF-16LE (10 bytes)
        //   [0x6A..0x72]: domain "CORP" UTF-16LE (8 bytes)
        let dc = 0x604usize;
        let username_utf16: Vec<u8> = "alice".encode_utf16().flat_map(u16::to_le_bytes).collect(); // 10 bytes
        let domain_utf16: Vec<u8> = "CORP".encode_utf16().flat_map(u16::to_le_bytes).collect();   // 8 bytes
        w16(&mut flat_page, dc + 0x00, username_utf16.len() as u16); // username_len
        w16(&mut flat_page, dc + 0x04, domain_utf16.len() as u16);   // domain_len
        w32(&mut flat_page, dc + 0x28, 10240); // iteration_count=10240
        // Username at data_addr + 96 = dc + 96 = dc + 0x60
        flat_page[dc + 96..dc + 96 + username_utf16.len()].copy_from_slice(&username_utf16);
        // Domain at data_addr + 96 + username_len
        let dom_off = dc + 96 + username_utf16.len();
        flat_page[dom_off..dom_off + domain_utf16.len()].copy_from_slice(&domain_utf16);

        let isf = make_cachedump_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Map flat_vaddr covering both 4K pages of flat_page
        let flat_page2_vaddr: u64 = flat_vaddr + 0x1000;
        let flat_page2_paddr: u64 = flat_paddr + 0x1000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(bb_vaddr, bb_paddr, flags::WRITABLE)
            .write_phys(bb_paddr, &bb_page)
            .map_4k(flat_vaddr, flat_paddr, flags::WRITABLE)
            .write_phys(flat_paddr, &flat_page[..0x1000].to_vec())
            .map_4k(flat_page2_vaddr, flat_page2_paddr, flags::WRITABLE)
            .write_phys(flat_page2_paddr, &flat_page[0x1000..].to_vec())
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_cached_credentials(&reader, hive_vaddr).unwrap();
        assert!(!result.is_empty(), "should find one cached credential");
        let cred = &result[0];
        assert_eq!(cred.username, "alice");
        assert_eq!(cred.domain, "CORP");
        assert_eq!(cred.iteration_count, 10240);
        assert!(!cred.is_suspicious, "alice/CORP with 10240 iterations should not be suspicious");
    }

    /// walk_cached_credentials with root_cell_off = u32::MAX → early return.
    #[test]
    fn walk_cached_creds_root_cell_max_sentinel() {
        use memf_core::test_builders::flags;

        let hive_vaddr: u64 = 0x0060_0000;
        let hive_paddr: u64 = 0x0060_0000;
        let base_block: u64 = 0x0061_0000;
        let base_block_paddr: u64 = 0x0061_0000;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        bb_page[0x24..0x28].copy_from_slice(&u32::MAX.to_le_bytes());

        let isf = make_cachedump_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_cached_credentials(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty(), "root_cell = u32::MAX sentinel → early return");
    }
}
