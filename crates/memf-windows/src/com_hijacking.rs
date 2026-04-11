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
        todo!()
    }

/// Walk the in-memory registry hives for COM hijacking candidates.
///
/// Returns an empty `Vec` when `CmRegistryMachineSystem` or the user hive
/// symbol is absent (graceful degradation).
pub fn walk_com_hijacking<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<ComHijackInfo>> {
        todo!()
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
        todo!()
    }

    /// A server in `%APPDATA%` is suspicious.
    #[test]
    fn classify_appdata_server_suspicious() {
        todo!()
    }

    /// HKCU pointing to the exact same DLL as HKCR is not suspicious.
    #[test]
    fn classify_same_server_not_suspicious() {
        todo!()
    }

    /// When `CmRegistryMachineSystem` symbol is absent the walker returns empty.
    #[test]
    fn walk_com_hijacking_no_symbol_returns_empty() {
        todo!()
    }
}
