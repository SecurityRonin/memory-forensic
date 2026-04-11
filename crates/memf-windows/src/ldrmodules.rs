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
        todo!()
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
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // classify_ldr_module tests
    // ---------------------------------------------------------------

    #[test]
    fn classify_all_present_benign() {
        todo!()
    }

    #[test]
    fn classify_missing_from_load_suspicious() {
        todo!()
    }

    #[test]
    fn classify_missing_from_mem_suspicious() {
        todo!()
    }

    #[test]
    fn classify_missing_from_init_suspicious() {
        todo!()
    }

    #[test]
    fn classify_ntdll_missing_init_benign() {
        todo!()
    }

    #[test]
    fn walk_no_peb_returns_empty() {
        todo!()
    }

    /// Walk body: PEB is non-zero and mapped, but _PEB.Ldr = 0 → returns empty.
    /// This exercises the ldr_addr == 0 guard inside the walk body.
    #[test]
    fn walk_ldrmodules_nonzero_peb_zero_ldr_empty() {
        todo!()
    }

    #[test]
    fn classify_not_in_any_list_benign() {
        todo!()
    }

    #[test]
    fn classify_only_in_load_suspicious() {
        todo!()
    }

    #[test]
    fn classify_only_in_mem_suspicious() {
        todo!()
    }

    #[test]
    fn classify_only_in_init_suspicious() {
        todo!()
    }

    #[test]
    fn classify_ntdll_missing_load_suspicious() {
        todo!()
    }

    #[test]
    fn classify_ntdll_missing_mem_suspicious() {
        todo!()
    }

    #[test]
    fn classify_ntdll_missing_init_case_insensitive_benign() {
        todo!()
    }

    /// classify: only in load order (missing from mem and init) → suspicious.
    #[test]
    fn classify_only_in_load_missing_mem_and_init_suspicious() {
        todo!()
    }

    /// classify: ntdll with all three present → benign.
    #[test]
    fn classify_ntdll_all_three_present_benign() {
        todo!()
    }

    /// classify: ntdll only in init → suspicious (not the benign pattern).
    #[test]
    fn classify_ntdll_only_init_suspicious() {
        todo!()
    }

    /// classify: ntdll missing from mem is suspicious even if load+init present.
    #[test]
    fn classify_ntdll_missing_mem_with_load_init_suspicious() {
        todo!()
    }

    /// LdrModuleInfo: pid and process_name are stored correctly.
    #[test]
    fn ldrmodule_info_pid_and_process_name() {
        todo!()
    }

    /// walk_ldrmodules: PEB is non-zero but _PEB_LDR_DATA symbols are missing → Err.
    /// This exercises the field_offset error path for InLoadOrderModuleList.
    #[test]
    fn walk_ldrmodules_missing_ldr_data_fields_returns_err() {
        todo!()
    }

    /// MAX_MODULES constant is sensible.
    #[test]
    fn max_modules_constant_sensible() {
        todo!()
    }

    /// walk_ldrmodules with one module in all three lists → 1 result, not suspicious.
    ///
    /// This exercises the walk_single_list inner function body, the cross-reference
    /// loop (lines 186-207), and read_unicode_string for BaseDllName.
    #[test]
    fn walk_ldrmodules_one_module_in_all_three_lists() {
        todo!()
    }

    #[test]
    fn ldrmodule_serializes() {
        todo!()
    }
}
