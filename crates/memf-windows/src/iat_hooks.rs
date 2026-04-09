//! Import Address Table (IAT) hook detection.
//!
//! Detects IAT hooking where malware patches the Import Address Table of a
//! DLL/EXE to redirect API calls. Each IAT entry should point into the target
//! DLL's address range. If it points elsewhere (especially to RWX memory or
//! unknown modules), it is a hook.
//!
//! MITRE ATT&CK: T1056 / T1547

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{dll, Result};

/// Maximum number of hooks to collect per process before stopping.
const MAX_HOOKS: usize = 4096;

/// Information about a single detected IAT hook.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IatHookInfo {
    /// Process ID owning the hooked module.
    pub pid: u32,
    /// Process name from `_EPROCESS.ImageFileName`.
    pub process_name: String,
    /// Module whose IAT was patched (e.g. `"ntdll.dll"`).
    pub hooked_module: String,
    /// Imported function name that was hooked (e.g. `"NtCreateFile"`).
    pub hooked_function: String,
    /// Virtual address of the IAT slot that was patched.
    pub iat_address: u64,
    /// Name of the DLL that *should* service this import.
    pub original_target: String,
    /// Address the IAT slot actually points to (the hook destination).
    pub hook_target: u64,
    /// Module name that contains `hook_target`, or `""` if unknown.
    pub hook_module: String,
    /// Whether this hook is considered suspicious.
    pub is_suspicious: bool,
}

/// Classify whether an IAT entry is suspicious.
///
/// An entry is suspicious if:
/// - `hook_target` falls outside the expected module's address range, **or**
/// - `hook_module` is empty or `"unknown"` (unresolvable destination).
///
/// A zero `hook_target` is **not** suspicious — it indicates a NULL /
/// not-yet-resolved import thunk and is common for delay-loaded DLLs.
pub fn classify_iat_hook(
    hook_target: u64,
    expected_module_base: u64,
    expected_module_size: u32,
    hook_module: &str,
) -> bool {
    // Zero target is benign (delay-load / not yet resolved)
    if hook_target == 0 {
        return false;
    }

    let end = expected_module_base.saturating_add(u64::from(expected_module_size));

    // Outside expected module range → suspicious
    if hook_target < expected_module_base || hook_target >= end {
        return true;
    }

    // Inside expected range but hook_module is empty/unknown → suspicious
    let normalized = hook_module.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized == "unknown" {
        return true;
    }

    false
}

/// Walk the IAT of all loaded DLLs for a given process and detect hooks.
///
/// `eprocess_addr` is the virtual address of the `_EPROCESS` structure.
/// The function switches to the process address space (via `_KPROCESS.DirectoryTableBase`)
/// and walks `PEB → PEB_LDR_DATA → InLoadOrderModuleList`. For each DLL it
/// parses the PE Import Directory and compares each IAT entry against the
/// expected target DLL's address range.
///
/// Returns a vector of [`IatHookInfo`] for every detected hook.
/// At most [`MAX_HOOKS`] entries are returned per process.
pub fn walk_iat_hooks<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    eprocess_addr: u64,
    pid: u32,
    process_name: &str,
) -> Result<Vec<IatHookInfo>> {
    todo!("walk_iat_hooks: read PEB, enumerate DLLs, parse PE import tables, detect hooks")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // classify_iat_hook unit tests
    // ---------------------------------------------------------------

    #[test]
    fn classify_target_in_module_benign() {
        // Hook target is inside expected module range → not suspicious
        let base: u64 = 0x7FF8_0000_0000;
        let size: u32 = 0x10_0000; // 1 MiB
        let target = base + 0x1234; // well within range
        assert!(
            !classify_iat_hook(target, base, size, "kernel32.dll"),
            "target inside module range should not be suspicious"
        );
    }

    #[test]
    fn classify_target_outside_module_suspicious() {
        // Hook target outside expected module range → suspicious
        let base: u64 = 0x7FF8_0000_0000;
        let size: u32 = 0x10_0000;
        let target = base + u64::from(size) + 0x1000; // past the end
        assert!(
            classify_iat_hook(target, base, size, "kernel32.dll"),
            "target outside module range should be suspicious"
        );
    }

    #[test]
    fn classify_unknown_hook_module_suspicious() {
        // Target inside range but hook_module is empty → suspicious
        let base: u64 = 0x7FF8_0000_0000;
        let size: u32 = 0x10_0000;
        let target = base + 0x500;
        assert!(
            classify_iat_hook(target, base, size, ""),
            "empty hook_module should be suspicious even if target is in range"
        );
        assert!(
            classify_iat_hook(target, base, size, "unknown"),
            "hook_module 'unknown' should be suspicious"
        );
    }

    #[test]
    fn classify_zero_target_benign() {
        // Zero target (delay-load / unresolved) → not suspicious
        let base: u64 = 0x7FF8_0000_0000;
        let size: u32 = 0x10_0000;
        assert!(
            !classify_iat_hook(0, base, size, ""),
            "zero hook target should not be suspicious (delay-load)"
        );
    }

    #[test]
    fn walk_no_peb_returns_empty() {
        // When PEB is null, walk_iat_hooks should return Ok(empty vec)
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Build an _EPROCESS with PEB = 0 (like System process)
        let eproc_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let eproc_paddr: u64 = 0x0090_0000;

        let mut eproc_data = vec![0u8; 8192];
        // DirectoryTableBase@0x28 — we'll patch after build
        eproc_data[0x28..0x30].copy_from_slice(&0x1AB000u64.to_le_bytes());
        // Peb@0x550 = 0 (null)
        eproc_data[0x550..0x558].copy_from_slice(&0u64.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(
                eproc_vaddr + 0x1000,
                eproc_paddr + 0x1000,
                flags::WRITABLE,
            )
            .write_phys(eproc_paddr, &eproc_data[..4096])
            .write_phys(eproc_paddr + 0x1000, &eproc_data[4096..])
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_iat_hooks(&reader, eproc_vaddr, 4, "System").unwrap();
        assert!(
            results.is_empty(),
            "process with no PEB should return empty hook list"
        );
    }

    #[test]
    fn iat_hook_serializes() {
        let hook = IatHookInfo {
            pid: 1234,
            process_name: "malware.exe".into(),
            hooked_module: "ntdll.dll".into(),
            hooked_function: "NtCreateFile".into(),
            iat_address: 0x7FF8_0000_1000,
            original_target: "ntdll.dll".into(),
            hook_target: 0xDEAD_BEEF_0000,
            hook_module: "evil.dll".into(),
            is_suspicious: true,
        };

        let json = serde_json::to_string(&hook).expect("IatHookInfo should serialize to JSON");
        assert!(json.contains("malware.exe"), "JSON should contain process name");
        assert!(json.contains("NtCreateFile"), "JSON should contain function name");
        assert!(json.contains("evil.dll"), "JSON should contain hook module");
    }
}
