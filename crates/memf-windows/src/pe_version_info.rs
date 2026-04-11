//! PE `VS_VERSIONINFO` resource extraction from loaded modules.
//!
//! Walks all loaded kernel drivers via `PsLoadedModuleList` and attempts to
//! parse the `RT_VERSION` (type 16) resource from each module's PE resource
//! directory.  Flags modules whose `OriginalFilename` string does not match
//! the actual on-disk filename — a strong indicator of DLL sideloading.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Version-info strings extracted from a loaded module's PE resources.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeVersionInfo {
    /// Virtual address of the module base.
    pub module_base: u64,
    /// Module filename (leaf name, e.g. `ntoskrnl.exe`).
    pub module_name: String,
    /// `ProductName` string from `StringFileInfo`.
    pub product_name: String,
    /// `FileDescription` string from `StringFileInfo`.
    pub file_description: String,
    /// `CompanyName` string from `StringFileInfo`.
    pub company_name: String,
    /// `FileVersion` string from `StringFileInfo`.
    pub file_version: String,
    /// `ProductVersion` string from `StringFileInfo`.
    pub product_version: String,
    /// `OriginalFilename` string from `StringFileInfo`.
    pub original_filename: String,
    /// `true` when `OriginalFilename` differs from the actual module filename
    /// (potential DLL sideloading).
    pub is_suspicious: bool,
}

/// Returns `true` when the module's on-disk name differs from `OriginalFilename`.
///
/// Comparison is case-insensitive and uses only the base filename (no path).
/// An empty `original_filename` is never flagged.
pub fn classify_version_mismatch(module_name: &str, original_filename: &str) -> bool {
        todo!()
    }

/// Walk all loaded modules via `PsLoadedModuleList` and extract PE version info.
///
/// Returns an empty `Vec` when the `PsLoadedModuleList` symbol is absent
/// (graceful degradation).  Modules whose PE header cannot be parsed are
/// silently skipped.
pub fn walk_pe_version_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<PeVersionInfo>> {
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

    /// A module loaded as `evil.dll` but with `OriginalFilename = shell32.dll` is suspicious.
    #[test]
    fn classify_mismatched_original_filename_suspicious() {
        todo!()
    }

    /// A module whose name matches `OriginalFilename` is not suspicious.
    #[test]
    fn classify_matching_filename_benign() {
        todo!()
    }

    /// When `PsLoadedModuleList` symbol is absent the walker returns empty.
    #[test]
    fn walk_pe_version_no_symbol_returns_empty() {
        todo!()
    }
}
