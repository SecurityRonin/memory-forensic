//! DPAPI master key extraction from LSASS memory.
//!
//! The Data Protection API (DPAPI) uses master keys to encrypt/decrypt
//! user secrets (browser credentials, WiFi passwords, private keys, etc.).
//! Master keys are loaded into the LSASS process from disk
//! (`%APPDATA%\Microsoft\Protect\<SID>\`) and cached in memory.
//!
//! This module provides:
//! - `DpapiMasterKeyInfo` struct for recovered master key metadata
//! - `walk_dpapi_master_keys` — graceful-degradation stub (RED phase)
//!   returning empty when lsasrv.dll symbols are absent
//!
//! A full implementation requires parsing `lsasrv!g_MasterKeyCache` linked
//! list entries, decrypting key blobs using the DPAPI internal session key,
//! and validating key GUIDs against on-disk master key files.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// A DPAPI master key recovered from LSASS memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DpapiMasterKeyInfo {
    /// Master key GUID (matches filename under %APPDATA%\Microsoft\Protect\<SID>\).
    pub guid: String,
    /// Master key blob version.
    pub version: u32,
    /// Master key flags.
    pub flags: u32,
    /// Human-readable description from the key blob.
    pub description: String,
    /// Decrypted master key bytes (if recoverable from memory).
    pub master_key: Vec<u8>,
    /// True if the master key belongs to a non-standard or unexpected user.
    pub is_suspicious: bool,
}

/// Classify a DPAPI master key entry as suspicious.
///
/// A master key is suspicious when it is found cached for an unexpected
/// user account (e.g. a service account or machine account GUID not
/// associated with any interactive logon session).
pub fn classify_dpapi_master_key(guid: &str, description: &str) -> bool {
    // Suspicious: empty GUID (memory corruption or uninitialized entry)
    // or description containing unusual markers
    guid.is_empty()
        || guid == "{00000000-0000-0000-0000-000000000000}"
        || description.to_ascii_lowercase().contains("backdoor")
}

/// Format a 16-byte Windows GUID (little-endian) as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
///
/// Windows stores GUIDs with the first three components in little-endian byte order:
/// - Data1: 4 bytes LE → u32
/// - Data2: 2 bytes LE → u16
/// - Data3: 2 bytes LE → u16
/// - Data4: 8 bytes as-is
fn format_guid(raw: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let d2 = u16::from_le_bytes([raw[4], raw[5]]);
    let d3 = u16::from_le_bytes([raw[6], raw[7]]);
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        d1, d2, d3, raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]
    )
}

/// Walk LSASS memory for cached DPAPI master keys via `lsasrv!g_MasterKeyCache`.
///
/// Returns `Ok(Vec::new())` when `lsasrv`-related symbols (e.g.
/// `g_MasterKeyCache`) are absent from the symbol table (graceful degradation).
///
/// Walks the doubly-linked `LIST_ENTRY` chain rooted at `g_MasterKeyCache`.
/// For each entry it reads the GUID (offset +0x18), blob pointer (+0x28),
/// and blob length (+0x30), then reads up to 512 bytes of blob data.
pub fn walk_dpapi_master_keys<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<DpapiMasterKeyInfo>> {
    // Graceful degradation: require g_MasterKeyCache symbol from lsasrv.dll
    let list_head_va = match reader.symbols().symbol_address("g_MasterKeyCache") {
        None => return Ok(Vec::new()),
        Some(va) => va,
    };

    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Read the first Flink from the list head
    let flink_bytes = match reader.read_bytes(list_head_va, 8) {
        Ok(b) => b,
        Err(_) => return Ok(results),
    };
    let mut flink_va = u64::from_le_bytes(flink_bytes.try_into().unwrap_or([0u8; 8]));

    for _ in 0..1000 {
        // Stop conditions: full circle or null pointer
        if flink_va == list_head_va || flink_va == 0 {
            break;
        }
        // Cycle detection
        if !seen.insert(flink_va) {
            break;
        }

        let entry_va = flink_va;

        // Read GUID: 16 bytes at entry_va + 0x18
        if let Ok(guid_bytes) = reader.read_bytes(entry_va + 0x18, 16) {
            let mut guid_raw = [0u8; 16];
            guid_raw.copy_from_slice(&guid_bytes);

            // Read blob pointer: 8 bytes at entry_va + 0x28
            // Read blob length: 4 bytes at entry_va + 0x30
            let blob = match (
                reader.read_bytes(entry_va + 0x28, 8),
                reader.read_bytes(entry_va + 0x30, 4),
            ) {
                (Ok(ptr_b), Ok(len_b)) => {
                    let blob_ptr = u64::from_le_bytes(ptr_b.try_into().unwrap_or([0u8; 8]));
                    let blob_len =
                        u32::from_le_bytes(len_b.try_into().unwrap_or([0u8; 4])) as usize;
                    if blob_len > 0 && blob_len <= 512 && blob_ptr != 0 {
                        reader.read_bytes(blob_ptr, blob_len).unwrap_or_default()
                    } else {
                        Vec::new()
                    }
                }
                _ => Vec::new(),
            };

            let guid = format_guid(&guid_raw);
            results.push(DpapiMasterKeyInfo {
                guid,
                version: 1,
                flags: 0,
                description: String::new(),
                master_key: blob,
                is_suspicious: false,
            });
        }

        // Advance: read Flink at entry_va + 0x00
        match reader.read_bytes(entry_va, 8) {
            Ok(b) => flink_va = u64::from_le_bytes(b.try_into().unwrap_or([0u8; 8])),
            Err(_) => break,
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    // Test fixtures declare layout consts/helpers beside the statements that use
    // them to keep each byte-plan readable; that ordering is intentional here.
    #![allow(clippy::items_after_statements)]
    use super::*;

    /// An empty GUID is suspicious (indicates uninitialized or corrupt entry).
    #[test]
    fn classify_empty_guid_suspicious() {
        assert!(classify_dpapi_master_key("", "Normal master key"));
    }

    /// The all-zero GUID is suspicious.
    #[test]
    fn classify_null_guid_suspicious() {
        assert!(classify_dpapi_master_key(
            "{00000000-0000-0000-0000-000000000000}",
            "Normal"
        ));
    }

    /// Description containing "backdoor" is suspicious.
    #[test]
    fn classify_backdoor_description_suspicious() {
        let valid_guid = "{12345678-1234-1234-1234-123456789abc}";
        assert!(classify_dpapi_master_key(valid_guid, "backdoor key"));
        assert!(classify_dpapi_master_key(valid_guid, "BACKDOOR_KEY"));
        assert!(classify_dpapi_master_key(
            valid_guid,
            "My Backdoor Master Key"
        ));
    }

    /// Normal valid GUID with clean description → benign.
    #[test]
    fn classify_valid_guid_benign() {
        assert!(!classify_dpapi_master_key(
            "{12345678-1234-1234-1234-123456789abc}",
            "User master key"
        ));
    }

    /// DpapiMasterKeyInfo serializes correctly.
    #[test]
    fn dpapi_master_key_info_serializes() {
        let info = DpapiMasterKeyInfo {
            guid: "{12345678-1234-1234-1234-123456789abc}".to_string(),
            version: 2,
            flags: 0,
            description: "User master key".to_string(),
            master_key: vec![0x01u8; 64],
            is_suspicious: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"version\":2"));
        assert!(json.contains("\"is_suspicious\":false"));
        assert!(json.contains("User master key"));
    }

    /// Walk g_MasterKeyCache linked list with a synthetic one-entry cache.
    #[test]
    fn walk_master_key_cache_with_synthetic_entry() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // VAs for our synthetic structures
        const LIST_HEAD_VA: u64 = 0xFFFF_8800_0001_0000;
        const ENTRY_VA: u64 = 0xFFFF_8800_0002_0000;
        const BLOB_VA: u64 = 0xFFFF_8800_0003_0000;
        // Corresponding PAs
        const LIST_HEAD_PA: u64 = 0x0010_0000;
        const ENTRY_PA: u64 = 0x0020_0000;
        const BLOB_PA: u64 = 0x0030_0000;

        let guid_bytes = [
            0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0x00,
        ];
        let blob_data = [0x42u8; 64];
        const BLOB_LEN: u32 = 64;

        // List head: Flink → ENTRY_VA
        let mut list_head = [0u8; 16];
        list_head[0..8].copy_from_slice(&ENTRY_VA.to_le_bytes()); // Flink
        list_head[8..16].copy_from_slice(&ENTRY_VA.to_le_bytes()); // Blink

        // Cache entry at ENTRY_VA
        let mut entry = [0u8; 0x40];
        // [0x00] Flink → LIST_HEAD_VA (one-entry list, circles back)
        entry[0x00..0x08].copy_from_slice(&LIST_HEAD_VA.to_le_bytes());
        // [0x08] Blink
        entry[0x08..0x10].copy_from_slice(&LIST_HEAD_VA.to_le_bytes());
        // [0x18] GUID (16 bytes)
        entry[0x18..0x28].copy_from_slice(&guid_bytes);
        // [0x28] blob pointer
        entry[0x28..0x30].copy_from_slice(&BLOB_VA.to_le_bytes());
        // [0x30] blob length
        entry[0x30..0x34].copy_from_slice(&BLOB_LEN.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(LIST_HEAD_VA, LIST_HEAD_PA, flags::WRITABLE)
            .write_phys(LIST_HEAD_PA, &list_head)
            .map_4k(ENTRY_VA, ENTRY_PA, flags::WRITABLE)
            .write_phys(ENTRY_PA, &entry)
            .map_4k(BLOB_VA, BLOB_PA, flags::WRITABLE)
            .write_phys(BLOB_PA, &blob_data)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);

        // ISF: g_MasterKeyCache symbol points to the list head VA
        let isf = IsfBuilder::new()
            .add_symbol("g_MasterKeyCache", LIST_HEAD_VA)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_dpapi_master_keys(&reader).expect("walk must succeed");
        assert_eq!(results.len(), 1, "should find exactly one cache entry");
        assert_eq!(results[0].master_key.len(), 64, "blob should be 64 bytes");
        assert_eq!(results[0].master_key, blob_data, "blob bytes must match");
        // GUID formatting: first 4 bytes LE → 0xDDCCBBAA
        assert!(
            results[0].guid.starts_with("{DDCCBBAA"),
            "GUID prefix must match LE-decoded bytes"
        );
    }

    /// Without g_MasterKeyCache symbol, walker returns empty.
    #[test]
    fn walk_dpapi_master_keys_no_symbol_returns_empty() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &[0u8; 16]);
        let (cr3, mem) = ptb.build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_dpapi_master_keys(&reader).unwrap();
        assert!(results.is_empty());
    }
}
