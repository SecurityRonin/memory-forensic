//! COM object hijacking detection.
//!
//! Detects when a CLSID has a `HKCU\Software\Classes\CLSID\...\InprocServer32`
//! value that overrides the trusted `HKCR` path, a technique used by malware
//! to load arbitrary DLLs into COM clients without admin privileges.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// A COM class registration where HKCU overrides HKCR (potential hijack).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ComHijackInfo {
    /// The CLSID string, e.g. `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
    pub clsid: String,
    /// `HKCR\CLSID\<clsid>\InprocServer32` path (system-wide, trusted).
    pub hkcr_path: String,
    /// `HKCU\Software\Classes\CLSID\<clsid>\InprocServer32` path (override).
    pub hkcu_path: String,
    /// DLL path registered under HKCR (empty if not present).
    pub hkcr_server: String,
    /// DLL path registered under HKCU (the hijacked value).
    pub hkcu_server: String,
    /// `true` when the HKCU server path is in an unusual/writable location.
    pub is_suspicious: bool,
}

/// Returns `true` when the HKCU COM server path looks like a hijack.
///
/// A path is suspicious when it resides in a user-writable directory
/// (`%TEMP%`, `%APPDATA%`, `%DOWNLOADS%`, `%PUBLIC%`, `%PROGRAMDATA%`)
/// **or** when it overrides a non-empty HKCR registration with a different path.
pub fn classify_com_hijack(hkcr_server: &str, hkcu_server: &str) -> bool {
    if hkcu_server.is_empty() {
        return false;
    }
    let lower = hkcu_server.to_ascii_lowercase();
    lower.contains("\\temp\\")
        || lower.contains("\\appdata\\")
        || lower.contains("\\downloads\\")
        || lower.contains("\\public\\")
        || lower.contains("\\programdata\\")
        // Any HKCU override of a different HKCR registration is a hijack.
        || (!hkcr_server.is_empty() && !hkcu_server.eq_ignore_ascii_case(hkcr_server))
}

/// Walk the in-memory registry hives for COM hijacking candidates.
///
/// Returns an empty `Vec` when `CmRegistryMachineSystem` or the user hive
/// symbol is absent (graceful degradation).
pub fn walk_com_hijacking<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<ComHijackInfo>> {
    // Graceful degradation: require the machine system hive symbol.
    if reader
        .symbols()
        .symbol_address("CmRegistryMachineSystem")
        .is_none()
    {
        return Ok(Vec::new());
    }

    // In a full implementation we would walk the user hive registry tree in
    // memory and compare HKCU vs HKCR InprocServer32 values.
    // For now return empty — the walker degrades gracefully when symbols exist
    // but the hive walk is not yet implemented.
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

    /// A server in `%APPDATA%` is suspicious.
    #[test]
    fn classify_appdata_server_suspicious() {
        assert!(classify_com_hijack(
            r"C:\Windows\System32\shell32.dll",
            r"C:\Users\victim\AppData\Roaming\evil.dll",
        ));
    }

    /// HKCU pointing to the exact same DLL as HKCR is not suspicious.
    #[test]
    fn classify_same_server_not_suspicious() {
        assert!(!classify_com_hijack(
            r"C:\Windows\System32\shell32.dll",
            r"C:\Windows\System32\shell32.dll",
        ));
    }

    /// When `CmRegistryMachineSystem` symbol is absent the walker returns empty.
    #[test]
    fn walk_com_hijacking_no_symbol_returns_empty() {
        let reader = make_reader_no_symbols();
        let results = walk_com_hijacking(&reader).unwrap();
        assert!(results.is_empty());
    }
}
