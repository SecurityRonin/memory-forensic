//! 3-way PEB DLL list cross-reference (ldrmodules).
//!
//! Cross-references the three PEB loader lists (`InLoadOrderModuleList`,
//! `InMemoryOrderModuleList`, `InInitializationOrderModuleList`) to detect
//! DLLs that have been unlinked from one or more lists — a common technique
//! for hiding injected DLLs. Equivalent to Volatility's `windows.ldrmodules`
//! plugin. MITRE ATT&CK T1055.

use std::collections::{BTreeMap, HashSet};

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;
use crate::{Error, Result};

/// Maximum number of modules to walk per linked list (safety bound).
const MAX_MODULES: usize = 4096;

/// Cross-reference result for a single DLL across the three PEB loader lists.
///
/// Each boolean indicates whether the module was found in that particular list.
/// A module missing from one or more lists (while present in at least one)
/// suggests DLL unlinking — a technique used by malware to hide injected DLLs.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LdrModuleInfo {
    /// Process ID that owns this module.
    pub pid: u32,
    /// Process image name (e.g. `notepad.exe`).
    pub process_name: String,
    /// Base address where the DLL is loaded.
    pub base_addr: u64,
    /// Base name of the DLL (e.g. `ntdll.dll`).
    pub dll_name: String,
    /// Present in `InLoadOrderModuleList`.
    pub in_load: bool,
    /// Present in `InMemoryOrderModuleList`.
    pub in_mem: bool,
    /// Present in `InInitializationOrderModuleList`.
    pub in_init: bool,
    /// Whether this module is suspicious (missing from one or more lists).
    pub is_suspicious: bool,
}

/// Classify whether a module's list presence pattern is suspicious.
///
/// Returns `true` (suspicious) if the module is missing from any list but
/// present in at least one. Exception: `ntdll.dll` is legitimately missing
/// from `InInitializationOrderModuleList` on some Windows versions and is
/// not flagged as suspicious for that specific pattern.
pub fn classify_ldr_module(in_load: bool, in_mem: bool, in_init: bool, dll_name: &str) -> bool {
    let present_count = u8::from(in_load) + u8::from(in_mem) + u8::from(in_init);

    // Not in any list — nothing to flag.
    if present_count == 0 {
        return false;
    }

    // Present in all three — benign.
    if present_count == 3 {
        return false;
    }

    // ntdll.dll is legitimately absent from InInitializationOrderModuleList
    // on some Windows versions. Only that specific pattern is benign.
    if dll_name.eq_ignore_ascii_case("ntdll.dll") && in_load && in_mem && !in_init {
        return false;
    }

    // Missing from at least one list while present in another — suspicious.
    true
}

/// Walk all three PEB loader lists for a process and cross-reference them.
///
/// Reads the PEB address from the `_EPROCESS` at `eprocess_addr`, then walks
/// each of the three LDR module lists, collecting base addresses and DLL names.
/// The results are merged by base address, and each entry is classified as
/// suspicious or benign.
///
/// Returns `Ok(Vec::new())` if the process has no PEB (e.g. System, Idle).
pub fn walk_ldrmodules<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    eprocess_addr: u64,
    pid: u32,
    process_name: &str,
) -> Result<Vec<LdrModuleInfo>> {
    let _ = (reader, eprocess_addr, pid, process_name, MAX_MODULES, HashSet::<u64>::new());
    let _ = BTreeMap::<u64, (bool, bool, bool)>::new();
    let _ = read_unicode_string::<P>;
    let _ = Error::Walker(String::new());
    let _ = classify_ldr_module(true, true, true, "");
    todo!("walk_ldrmodules: walk PEB LDR lists and cross-reference")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // classify_ldr_module tests
    // ---------------------------------------------------------------

    #[test]
    fn classify_all_present_benign() {
        assert!(
            !classify_ldr_module(true, true, true, "kernel32.dll"),
            "module present in all three lists should not be suspicious"
        );
    }

    #[test]
    fn classify_missing_from_load_suspicious() {
        assert!(
            classify_ldr_module(false, true, true, "evil.dll"),
            "module missing from InLoadOrder should be suspicious"
        );
    }

    #[test]
    fn classify_missing_from_mem_suspicious() {
        assert!(
            classify_ldr_module(true, false, true, "evil.dll"),
            "module missing from InMemoryOrder should be suspicious"
        );
    }

    #[test]
    fn classify_missing_from_init_suspicious() {
        assert!(
            classify_ldr_module(true, true, false, "evil.dll"),
            "module missing from InInitializationOrder should be suspicious"
        );
    }

    #[test]
    fn classify_ntdll_missing_init_benign() {
        assert!(
            !classify_ldr_module(true, true, false, "ntdll.dll"),
            "ntdll.dll missing from InInitializationOrder is a known benign pattern"
        );
        // Also test case-insensitive matching.
        assert!(
            !classify_ldr_module(true, true, false, "NTDLL.DLL"),
            "ntdll.dll check should be case-insensitive"
        );
    }

    #[test]
    fn walk_no_peb_returns_empty() {
        // When PEB is null (0), walk_ldrmodules should return Ok(empty vec).
        // This test will initially fail because the function body is todo!().
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Create an EPROCESS with Peb = 0 (null).
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_paddr: u64 = 0x0080_0000;

        let mut eproc_data = vec![0u8; 4096];
        // _EPROCESS.Peb is at offset 0x550 — write 0 (null PEB).
        eproc_data[0x550..0x558].copy_from_slice(&0u64.to_le_bytes());

        let (_cr3, mem) = PageTableBuilder::new()
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys(eproc_paddr, &eproc_data)
            .build();

        let vas = VirtualAddressSpace::new(mem, _cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_ldrmodules(&reader, eproc_vaddr, 4, "System").unwrap();
        assert!(results.is_empty(), "process with null PEB should return empty vec");
    }

    #[test]
    fn ldrmodule_serializes() {
        let info = LdrModuleInfo {
            pid: 1234,
            process_name: "test.exe".to_string(),
            base_addr: 0x7FF8_0000_0000,
            dll_name: "kernel32.dll".to_string(),
            in_load: true,
            in_mem: true,
            in_init: false,
            is_suspicious: true,
        };

        let json = serde_json::to_string(&info).expect("LdrModuleInfo should serialize to JSON");
        assert!(json.contains("\"pid\":1234"));
        assert!(json.contains("\"dll_name\":\"kernel32.dll\""));
        assert!(json.contains("\"is_suspicious\":true"));
        assert!(json.contains("\"in_init\":false"));
    }
}
