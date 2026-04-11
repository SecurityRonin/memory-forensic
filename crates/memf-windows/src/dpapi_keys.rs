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

/// Walk LSASS memory for cached DPAPI master keys.
///
/// Returns `Ok(Vec::new())` when `lsasrv`-related symbols (e.g.
/// `g_MasterKeyCache`) are absent from the symbol table (graceful degradation).
///
/// # Full Implementation Notes
/// Would walk `lsasrv!g_MasterKeyCache` → `LSAP_DPAPI_MASTERKEY_CACHE_ENTRY`
/// linked list, extract GUID and encrypted blob, then decrypt using the
/// session key from `lsasrv!h_PreferredMasterKey`.
pub fn walk_dpapi_master_keys<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<DpapiMasterKeyInfo>> {
    // Graceful degradation: require g_MasterKeyCache symbol from lsasrv.dll
    if reader
        .symbols()
        .symbol_address("g_MasterKeyCache")
        .is_none()
    {
        return Ok(Vec::new());
    }

    // Full implementation pending lsasrv struct definitions.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
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
        assert!(classify_dpapi_master_key(valid_guid, "My Backdoor Master Key"));
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
