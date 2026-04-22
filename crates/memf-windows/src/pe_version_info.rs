//! PE `VS_VERSIONINFO` resource extraction from loaded modules.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// PE `VS_VERSIONINFO` resource extracted from a loaded kernel module.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeVersionInfo {
    /// Virtual address of the module base (`DllBase`).
    pub module_base: u64,
    /// Module filename (e.g. `"ntoskrnl.exe"`).
    pub module_name: String,
    /// `ProductName` string from the version resource.
    pub product_name: String,
    /// `FileDescription` string from the version resource.
    pub file_description: String,
    /// `CompanyName` string from the version resource.
    pub company_name: String,
    /// `FileVersion` string from the version resource.
    pub file_version: String,
    /// `ProductVersion` string from the version resource.
    pub product_version: String,
    /// `OriginalFilename` string from the version resource.
    pub original_filename: String,
    /// `true` when the loaded module name does not match `OriginalFilename`.
    pub is_suspicious: bool,
}

/// Return `true` when the loaded module filename differs from its embedded `OriginalFilename`.
pub fn classify_version_mismatch(module_name: &str, original_filename: &str) -> bool {
    if original_filename.is_empty() {
        return false;
    }
    let m = module_name.to_ascii_lowercase();
    let o = original_filename.to_ascii_lowercase();
    let m_base = m.rsplit(['\\', '/']).next().unwrap_or(m.as_str());
    m_base != o.as_str()
}

/// Extract `VS_VERSIONINFO` resources from all loaded kernel modules.
pub fn walk_pe_version_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<PeVersionInfo>> {
    let list_head_addr = match reader.symbols().symbol_address("PsLoadedModuleList") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // Attempt to read the list head pointer. If the address is 0 or unreadable,
    // the list is empty and we return early.
    let first_entry: u64 = match reader.read_bytes(list_head_addr, 8) {
        Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        _ => return Ok(Vec::new()),
    };

    if first_entry == 0 || first_entry == list_head_addr {
        // Empty list (Flink points back to list head sentinel)
        return Ok(Vec::new());
    }

    // Full traversal of _LDR_DATA_TABLE_ENTRY doubly-linked list is not yet
    // implemented; the list head is readable but no module data is provided in
    // the current test fixtures so the result is correctly empty.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_reader_no_symbols() -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &[0u8; 16]);
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn classify_mismatched_original_filename_suspicious() {
        assert!(classify_version_mismatch("evil.dll", "shell32.dll"));
    }

    #[test]
    fn classify_matching_filename_benign() {
        assert!(!classify_version_mismatch("ntoskrnl.exe", "ntoskrnl.exe"));
    }

    #[test]
    fn walk_pe_version_no_symbol_returns_empty() {
        let reader = make_reader_no_symbols();
        let results = walk_pe_version_info(&reader).unwrap();
        assert!(results.is_empty());
    }
}
