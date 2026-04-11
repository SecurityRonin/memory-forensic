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
    // Read PEB address from _EPROCESS.Peb (fallback offset 0x550).
    let peb_addr: u64 = reader.read_field(eprocess_addr, "_EPROCESS", "Peb")?;

    // No PEB means kernel process (System, Idle) — nothing to cross-reference.
    if peb_addr == 0 {
        return Ok(Vec::new());
    }

    // Read PEB_LDR_DATA pointer from _PEB.Ldr.
    let ldr_addr: u64 = reader.read_field(peb_addr, "_PEB", "Ldr")?;
    if ldr_addr == 0 {
        return Ok(Vec::new());
    }

    // Resolve list head offsets within _PEB_LDR_DATA.
    let load_head_off = reader
        .symbols()
        .field_offset("_PEB_LDR_DATA", "InLoadOrderModuleList")
        .ok_or_else(|| Error::Walker("missing _PEB_LDR_DATA.InLoadOrderModuleList".into()))?;
    let mem_head_off = reader
        .symbols()
        .field_offset("_PEB_LDR_DATA", "InMemoryOrderModuleList")
        .ok_or_else(|| Error::Walker("missing _PEB_LDR_DATA.InMemoryOrderModuleList".into()))?;
    let init_head_off = reader
        .symbols()
        .field_offset("_PEB_LDR_DATA", "InInitializationOrderModuleList")
        .ok_or_else(|| {
            Error::Walker("missing _PEB_LDR_DATA.InInitializationOrderModuleList".into())
        })?;

    /// Walk a single linked list, returning `(entry_addr, DllBase)` pairs.
    /// Uses a `HashSet` for cycle detection and caps at `MAX_MODULES`.
    fn walk_single_list<P2: PhysicalMemoryProvider>(
        reader: &ObjectReader<P2>,
        ldr_addr: u64,
        head_off: u64,
        link_field: &str,
    ) -> Result<Vec<(u64, u64)>> {
        let head = ldr_addr.wrapping_add(head_off);
        let entries = reader.walk_list_with(
            head,
            "_LIST_ENTRY",
            "Flink",
            "_LDR_DATA_TABLE_ENTRY",
            link_field,
        )?;

        let mut seen = HashSet::new();
        let mut results = Vec::new();
        for entry_addr in entries {
            if results.len() >= MAX_MODULES {
                break;
            }
            if !seen.insert(entry_addr) {
                break; // cycle detected
            }
            let base: u64 = reader.read_field(entry_addr, "_LDR_DATA_TABLE_ENTRY", "DllBase")?;
            if base != 0 {
                results.push((entry_addr, base));
            }
        }
        Ok(results)
    }

    let load_entries = walk_single_list(reader, ldr_addr, load_head_off, "InLoadOrderLinks")?;
    let mem_entries = walk_single_list(reader, ldr_addr, mem_head_off, "InMemoryOrderLinks")?;
    let init_entries = walk_single_list(
        reader,
        ldr_addr,
        init_head_off,
        "InInitializationOrderLinks",
    )?;

    // Collect base addresses into sets for presence checking.
    let load_bases: HashSet<u64> = load_entries.iter().map(|&(_, b)| b).collect();
    let mem_bases: HashSet<u64> = mem_entries.iter().map(|&(_, b)| b).collect();
    let init_bases: HashSet<u64> = init_entries.iter().map(|&(_, b)| b).collect();

    // Build a map from DllBase -> entry_addr (for reading DLL name).
    // Prefer InLoadOrder entries as the canonical source.
    let mut base_to_entry: BTreeMap<u64, u64> = BTreeMap::new();
    for &(entry_addr, base) in &load_entries {
        base_to_entry.entry(base).or_insert(entry_addr);
    }
    for &(entry_addr, base) in &mem_entries {
        base_to_entry.entry(base).or_insert(entry_addr);
    }
    for &(entry_addr, base) in &init_entries {
        base_to_entry.entry(base).or_insert(entry_addr);
    }

    // Resolve the BaseDllName field offset once.
    let base_dll_name_off = reader
        .symbols()
        .field_offset("_LDR_DATA_TABLE_ENTRY", "BaseDllName")
        .ok_or_else(|| Error::Walker("missing _LDR_DATA_TABLE_ENTRY.BaseDllName".into()))?;

    // Cross-reference: for each unique base address, check presence in all three lists.
    let mut results = Vec::new();
    for (&base_addr, &entry_addr) in &base_to_entry {
        let in_load = load_bases.contains(&base_addr);
        let in_mem = mem_bases.contains(&base_addr);
        let in_init = init_bases.contains(&base_addr);

        let dll_name = read_unicode_string(reader, entry_addr.wrapping_add(base_dll_name_off))
            .unwrap_or_default();

        let is_suspicious = classify_ldr_module(in_load, in_mem, in_init, &dll_name);

        results.push(LdrModuleInfo {
            pid,
            process_name: process_name.to_string(),
            base_addr,
            dll_name,
            in_load,
            in_mem,
            in_init,
            is_suspicious,
        });
    }

    Ok(results)
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
        assert!(
            results.is_empty(),
            "process with null PEB should return empty vec"
        );
    }

    /// Walk body: PEB is non-zero and mapped, but _PEB.Ldr = 0 → returns empty.
    /// This exercises the ldr_addr == 0 guard inside the walk body.
    #[test]
    fn walk_ldrmodules_nonzero_peb_zero_ldr_empty() {
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let eproc_vaddr: u64 = 0xFFFF_8000_0060_0000;
        let eproc_paddr: u64 = 0x0060_0000;
        let peb_vaddr: u64 = 0x0000_7FF0_1000_0000;
        let peb_paddr: u64 = 0x0061_0000;

        let mut eproc_data = vec![0u8; 4096];
        // _EPROCESS.Peb at offset 0x550 — non-zero PEB address.
        eproc_data[0x550..0x558].copy_from_slice(&peb_vaddr.to_le_bytes());

        // PEB page: _PEB.Ldr at offset 0x18 — write 0 (null Ldr).
        let mut peb_data = vec![0u8; 4096];
        peb_data[0x18..0x20].copy_from_slice(&0u64.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(peb_vaddr, peb_paddr, flags::WRITABLE)
            .write_phys(eproc_paddr, &eproc_data)
            .write_phys(peb_paddr, &peb_data)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_ldrmodules(&reader, eproc_vaddr, 4, "test.exe").unwrap_or_default();
        assert!(results.is_empty(), "null Ldr pointer should return empty vec");
    }

    #[test]
    fn classify_not_in_any_list_benign() {
        // No presence in any list — nothing to flag.
        assert!(
            !classify_ldr_module(false, false, false, "ghost.dll"),
            "module absent from all lists should not be suspicious"
        );
    }

    #[test]
    fn classify_only_in_load_suspicious() {
        assert!(
            classify_ldr_module(true, false, false, "evil.dll"),
            "module only in InLoad should be suspicious"
        );
    }

    #[test]
    fn classify_only_in_mem_suspicious() {
        assert!(
            classify_ldr_module(false, true, false, "evil.dll"),
            "module only in InMem should be suspicious"
        );
    }

    #[test]
    fn classify_only_in_init_suspicious() {
        assert!(
            classify_ldr_module(false, false, true, "evil.dll"),
            "module only in InInit should be suspicious"
        );
    }

    #[test]
    fn classify_ntdll_missing_load_suspicious() {
        // ntdll.dll exception only applies to the (true, true, false) pattern.
        // Missing from load is still suspicious even for ntdll.
        assert!(
            classify_ldr_module(false, true, true, "ntdll.dll"),
            "ntdll missing from InLoad should still be suspicious"
        );
    }

    #[test]
    fn classify_ntdll_missing_mem_suspicious() {
        assert!(
            classify_ldr_module(true, false, true, "ntdll.dll"),
            "ntdll missing from InMem should still be suspicious"
        );
    }

    #[test]
    fn classify_ntdll_missing_init_case_insensitive_benign() {
        // Already tested in existing test, but verify all case variants.
        assert!(!classify_ldr_module(true, true, false, "NTDLL.DLL"));
        assert!(!classify_ldr_module(true, true, false, "Ntdll.Dll"));
    }

    /// classify: only in load order (missing from mem and init) → suspicious.
    #[test]
    fn classify_only_in_load_missing_mem_and_init_suspicious() {
        assert!(classify_ldr_module(true, false, false, "hidden.dll"));
    }

    /// classify: ntdll with all three present → benign.
    #[test]
    fn classify_ntdll_all_three_present_benign() {
        assert!(!classify_ldr_module(true, true, true, "ntdll.dll"));
    }

    /// classify: ntdll only in init → suspicious (not the benign pattern).
    #[test]
    fn classify_ntdll_only_init_suspicious() {
        assert!(classify_ldr_module(false, false, true, "ntdll.dll"));
    }

    /// classify: ntdll missing from mem is suspicious even if load+init present.
    #[test]
    fn classify_ntdll_missing_mem_with_load_init_suspicious() {
        assert!(classify_ldr_module(true, false, true, "ntdll.dll"));
    }

    /// LdrModuleInfo: pid and process_name are stored correctly.
    #[test]
    fn ldrmodule_info_pid_and_process_name() {
        let info = LdrModuleInfo {
            pid: 4,
            process_name: "System".to_string(),
            base_addr: 0x7FFF_0000_0000,
            dll_name: "ntoskrnl.exe".to_string(),
            in_load: true,
            in_mem: true,
            in_init: true,
            is_suspicious: false,
        };
        assert_eq!(info.pid, 4);
        assert_eq!(info.process_name, "System");
        assert!(!info.is_suspicious);
    }

    /// walk_ldrmodules: PEB is non-zero but _PEB_LDR_DATA symbols are missing → Err.
    /// This exercises the field_offset error path for InLoadOrderModuleList.
    #[test]
    fn walk_ldrmodules_missing_ldr_data_fields_returns_err() {
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // ISF without _PEB_LDR_DATA fields → field_offset returns None → Walker error.
        let mut isf = IsfBuilder::windows_kernel_preset().build_json();
        // Remove _PEB_LDR_DATA so field_offset("_PEB_LDR_DATA", ...) returns None.
        isf["user_types"]
            .as_object_mut()
            .unwrap()
            .remove("_PEB_LDR_DATA");

        let resolver = IsfResolver::from_value(&isf).unwrap();

        let eproc_vaddr: u64 = 0xFFFF_8000_0070_0000;
        let eproc_paddr: u64 = 0x0070_A000;
        let peb_vaddr: u64 = 0x0000_7FF0_2000_0000;
        let peb_paddr: u64 = 0x0071_A000;
        let ldr_vaddr: u64 = 0x0000_7FF0_3000_0000;
        let ldr_paddr: u64 = 0x0072_A000;

        let mut eproc_data = vec![0u8; 4096];
        eproc_data[0x550..0x558].copy_from_slice(&peb_vaddr.to_le_bytes());

        let mut peb_data = vec![0u8; 4096];
        // _PEB.Ldr at offset 0x18 — non-zero.
        peb_data[0x18..0x20].copy_from_slice(&ldr_vaddr.to_le_bytes());

        let mut ldr_data = vec![0u8; 4096];
        // Non-zero ldr data so it passes the ldr_addr==0 check.
        ldr_data[0] = 0x01;

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(peb_vaddr, peb_paddr, flags::WRITABLE)
            .map_4k(ldr_vaddr, ldr_paddr, flags::WRITABLE)
            .write_phys(eproc_paddr, &eproc_data)
            .write_phys(peb_paddr, &peb_data)
            .write_phys(ldr_paddr, &ldr_data)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // Missing _PEB_LDR_DATA fields → returns Err (Walker error).
        let result = walk_ldrmodules(&reader, eproc_vaddr, 1234, "test.exe");
        assert!(result.is_err(), "expected Err when _PEB_LDR_DATA is absent from ISF");
    }

    /// MAX_MODULES constant is sensible.
    #[test]
    fn max_modules_constant_sensible() {
        assert!(MAX_MODULES > 0);
        assert!(MAX_MODULES <= 65536);
    }

    /// walk_ldrmodules with one module in all three lists → 1 result, not suspicious.
    ///
    /// This exercises the walk_single_list inner function body, the cross-reference
    /// loop (lines 186-207), and read_unicode_string for BaseDllName.
    #[test]
    fn walk_ldrmodules_one_module_in_all_three_lists() {
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // ISF offsets from windows_kernel_preset:
        // _EPROCESS.Peb @ 0x550
        // _PEB.Ldr @ 0x18
        // _PEB_LDR_DATA.InLoadOrderModuleList @ 16 (0x10)
        // _PEB_LDR_DATA.InMemoryOrderModuleList @ 32 (0x20)
        // _PEB_LDR_DATA.InInitializationOrderModuleList @ 48 (0x30)
        // _LDR_DATA_TABLE_ENTRY.InLoadOrderLinks @ 0
        // _LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks @ 16
        // _LDR_DATA_TABLE_ENTRY.InInitializationOrderLinks @ 32
        // _LDR_DATA_TABLE_ENTRY.DllBase @ 48
        // _LDR_DATA_TABLE_ENTRY.BaseDllName @ 88 (UNICODE_STRING)
        // _UNICODE_STRING.Length @ 0, Buffer @ 8

        let eproc_vaddr: u64 = 0xFFFF_8001_0000_0000;
        let eproc_paddr: u64 = 0x0001_0000;
        let peb_vaddr: u64 = 0x0000_7FF0_1000_0000;
        let peb_paddr: u64 = 0x0002_0000;
        let ldr_vaddr: u64 = 0x0000_7FF0_2000_0000;
        let ldr_paddr: u64 = 0x0003_0000;
        let entry_vaddr: u64 = 0x0000_7FF0_3000_0000;
        let entry_paddr: u64 = 0x0004_0000;
        let name_buf_vaddr: u64 = 0x0000_7FF0_4000_0000;
        let name_buf_paddr: u64 = 0x0005_0000;

        let dll_base: u64 = 0x7FFF_0000_0000;
        let dll_name = "kernel32.dll";
        // UTF-16LE encoding
        let name_bytes: Vec<u8> = dll_name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let name_len = name_bytes.len() as u16;

        // ldr_addr + 0x10 = head of InLoadOrderModuleList
        // head Flink must point to entry's InLoadOrderLinks field = entry_vaddr + 0
        // entry's InLoadOrderLinks Flink must point back to head = ldr_vaddr + 0x10

        let load_head_vaddr = ldr_vaddr + 0x10;
        let mem_head_vaddr = ldr_vaddr + 0x20;
        let init_head_vaddr = ldr_vaddr + 0x30;

        // InLoadOrderLinks at entry+0: Flink→load_head, Blink→load_head
        // InMemoryOrderLinks at entry+0x10: Flink→mem_head, Blink→mem_head
        // InInitializationOrderLinks at entry+0x20: Flink→init_head, Blink→init_head
        // DllBase at entry+0x30: dll_base
        // BaseDllName at entry+0x58 (UNICODE_STRING):
        //   Length at +0: name_len
        //   Buffer at +8: name_buf_vaddr

        let mut entry_page = vec![0u8; 4096];
        // InLoadOrderLinks.Flink at entry+0
        entry_page[0x00..0x08].copy_from_slice(&load_head_vaddr.to_le_bytes());
        // InMemoryOrderLinks.Flink at entry+0x10
        entry_page[0x10..0x18].copy_from_slice(&mem_head_vaddr.to_le_bytes());
        // InInitializationOrderLinks.Flink at entry+0x20
        entry_page[0x20..0x28].copy_from_slice(&init_head_vaddr.to_le_bytes());
        // DllBase at entry+0x30
        entry_page[0x30..0x38].copy_from_slice(&dll_base.to_le_bytes());
        // BaseDllName._UNICODE_STRING at entry+0x58
        // Length at +0 (so entry+0x58)
        entry_page[0x58..0x5A].copy_from_slice(&name_len.to_le_bytes());
        // Buffer at +8 (so entry+0x60)
        entry_page[0x60..0x68].copy_from_slice(&name_buf_vaddr.to_le_bytes());

        // ldr_page:
        // InLoadOrderModuleList at ldr+0x10: Flink = entry_vaddr + 0
        let mut ldr_page = vec![0u8; 4096];
        ldr_page[0x10..0x18].copy_from_slice(&(entry_vaddr + 0).to_le_bytes()); // load head Flink
        ldr_page[0x20..0x28].copy_from_slice(&(entry_vaddr + 0x10).to_le_bytes()); // mem head Flink
        ldr_page[0x30..0x38].copy_from_slice(&(entry_vaddr + 0x20).to_le_bytes()); // init head Flink

        // peb_page: Ldr at peb+0x18 = ldr_vaddr
        let mut peb_page = vec![0u8; 4096];
        peb_page[0x18..0x20].copy_from_slice(&ldr_vaddr.to_le_bytes());

        // eproc_page: Peb at eproc+0x550 = peb_vaddr
        let mut eproc_page = vec![0u8; 4096];
        eproc_page[0x550..0x558].copy_from_slice(&peb_vaddr.to_le_bytes());

        // name_buf_page: UTF-16LE bytes of "kernel32.dll"
        let mut name_page = vec![0u8; 4096];
        name_page[..name_bytes.len()].copy_from_slice(&name_bytes);

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(peb_vaddr, peb_paddr, flags::WRITABLE)
            .map_4k(ldr_vaddr, ldr_paddr, flags::WRITABLE)
            .map_4k(entry_vaddr, entry_paddr, flags::WRITABLE)
            .map_4k(name_buf_vaddr, name_buf_paddr, flags::WRITABLE)
            .write_phys(eproc_paddr, &eproc_page)
            .write_phys(peb_paddr, &peb_page)
            .write_phys(ldr_paddr, &ldr_page)
            .write_phys(entry_paddr, &entry_page)
            .write_phys(name_buf_paddr, &name_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_ldrmodules(&reader, eproc_vaddr, 1234, "notepad.exe")
            .expect("walk_ldrmodules should succeed");

        assert_eq!(results.len(), 1, "expected 1 module, got {}", results.len());
        let m = &results[0];
        assert_eq!(m.base_addr, dll_base, "DllBase mismatch");
        assert_eq!(m.dll_name, dll_name, "DLL name mismatch");
        assert!(m.in_load, "should be in InLoad list");
        assert!(m.in_mem, "should be in InMem list");
        assert!(m.in_init, "should be in InInit list");
        assert!(!m.is_suspicious, "module in all 3 lists should not be suspicious");
        assert_eq!(m.pid, 1234);
        assert_eq!(m.process_name, "notepad.exe");
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
