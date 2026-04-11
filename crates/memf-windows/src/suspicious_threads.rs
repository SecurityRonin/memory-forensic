//! Suspicious thread detection for injection analysis.
//!
//! Detects threads with anomalous characteristics indicative of code injection:
//! - Threads with start addresses in unbacked/RWX memory
//! - Orphan threads (not associated with any loaded module)
//! - Threads whose start address doesn't match any known DLL
//!
//! These indicators reveal when malware injects code into a legitimate process
//! and spawns threads to execute it. Common techniques like process hollowing,
//! DLL injection, and shellcode injection leave distinctive thread artifacts.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{dll, process, thread, vad};

/// Information about a suspicious thread detected during injection analysis.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SuspiciousThreadInfo {
    /// Process ID owning this thread.
    pub pid: u32,
    /// Name of the owning process.
    pub process_name: String,
    /// Thread ID.
    pub tid: u32,
    /// Thread start address (`Win32StartAddress`).
    pub start_address: u64,
    /// Which DLL contains the start address, or "unknown".
    pub start_module: String,
    /// Start address not in any loaded module.
    pub is_orphan: bool,
    /// Start address falls within a read-write-execute VAD region.
    pub in_rwx_memory: bool,
    /// Thread belongs to a system process.
    pub is_system_thread: bool,
    /// Human-readable reason why this thread was flagged.
    pub reason: String,
    /// Whether this thread is classified as suspicious.
    pub is_suspicious: bool,
}

/// System processes where orphan threads are highly suspicious.
const SYSTEM_PROCESSES: &[&str] = &[
    "csrss.exe",
    "smss.exe",
    "services.exe",
    "lsass.exe",
    "wininit.exe",
    "svchost.exe",
];

/// DLLs commonly used as injection targets / trampolines.
const KNOWN_INJECTION_TARGETS: &[&str] = &["ntdll.dll", "kernel32.dll", "kernelbase.dll"];

/// Classify whether a thread is suspicious based on its characteristics.
///
/// Returns `(is_suspicious, reason)` where `reason` is a human-readable
/// explanation of why the thread was flagged.
///
/// Classification rules (in priority order):
/// 1. Orphan thread in a system process -> highly suspicious
/// 2. Thread in RWX memory -> suspicious
/// 3. Orphan thread (start address in no module) -> suspicious
/// 4. Known injection target DLL with orphan -> suspicious
/// 5. Normal thread in a known module -> benign
pub fn classify_suspicious_thread(
    start_module: &str,
    is_orphan: bool,
    in_rwx_memory: bool,
    process_name: &str,
) -> (bool, String) {
    let proc_lower = process_name.to_lowercase();
    let is_system = SYSTEM_PROCESSES.iter().any(|&s| proc_lower == s);

    // Rule 1: System process with orphan thread -> highly suspicious
    if is_orphan && is_system {
        return (
            true,
            format!(
                "orphan thread in system process {}; thread start address not in any loaded module",
                process_name
            ),
        );
    }

    // Rule 2: Thread starts in RWX memory -> suspicious
    if in_rwx_memory {
        return (
            true,
            "thread starts in read-write-execute memory".to_string(),
        );
    }

    // Rule 3: Orphan thread (start address not in any module)
    if is_orphan {
        return (
            true,
            "thread start address not in any loaded module".to_string(),
        );
    }

    // Rule 4: Known injection target with orphan status
    // (This is a secondary check: if we reach here, is_orphan is false,
    //  but start_module is a common injection target — only flag if
    //  combined with other signals. Since is_orphan is false here,
    //  this combination doesn't apply. Keep for clarity.)
    let _mod_lower = start_module.to_lowercase();
    if KNOWN_INJECTION_TARGETS.iter().any(|&t| _mod_lower == t) && is_orphan {
        return (
            true,
            format!(
                "thread in known injection target {} with orphan status",
                start_module
            ),
        );
    }

    // Rule 5: Normal thread in a known module -> benign
    (false, String::new())
}

/// Maximum number of suspicious threads to collect (safety limit).
const MAX_SUSPICIOUS_THREADS: usize = 4096;

/// VAD protection index 6 = PAGE_EXECUTE_READWRITE.
const VAD_PROT_EXECUTE_READWRITE: u32 = 6;
/// VAD protection index 7 = PAGE_EXECUTE_WRITECOPY.
const VAD_PROT_EXECUTE_WRITECOPY: u32 = 7;

/// Whether a VAD protection value indicates RWX.
fn is_rwx_protection(prot: u32) -> bool {
    matches!(
        prot,
        VAD_PROT_EXECUTE_READWRITE | VAD_PROT_EXECUTE_WRITECOPY
    )
}

/// Find which module (DLL) contains the given address.
///
/// Returns the DLL base name if found, or "unknown" if the address
/// doesn't fall within any loaded module's range.
fn find_containing_module(dlls: &[crate::WinDllInfo], address: u64) -> (String, bool) {
    for dll in dlls {
        let end = dll.base_addr.saturating_add(dll.size);
        if address >= dll.base_addr && address < end {
            return (dll.name.clone(), false);
        }
    }
    ("unknown".to_string(), true)
}

/// Check whether the given address falls within an RWX VAD region.
fn is_address_in_rwx_vad(vads: &[crate::WinVadInfo], address: u64) -> bool {
    vads.iter().any(|v| {
        address >= v.start_vaddr && address <= v.end_vaddr && is_rwx_protection(v.protection)
    })
}

/// Walk all processes and detect threads with suspicious characteristics.
///
/// For each process, walks the thread list and compares each thread's
/// start address against the process's loaded DLL address ranges (from
/// PEB LDR) and checks VAD protection for the containing region.
///
/// Returns only threads that are flagged as suspicious.
/// Returns `Ok(Vec::new())` if required symbols are missing (graceful degradation).
pub fn walk_suspicious_threads<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<SuspiciousThreadInfo>> {
    // Graceful degradation: check for required symbol
    let Some(ps_head) = reader.symbols().symbol_address("PsActiveProcessHead") else {
        return Ok(Vec::new());
    };

    let procs = process::walk_processes(reader, ps_head)?;

    // Resolve VadRoot offset (optional — degrade gracefully)
    let vad_root_offset = reader.symbols().field_offset("_EPROCESS", "VadRoot");

    let mut suspicious = Vec::new();

    for proc in &procs {
        // Skip processes with no PEB (System, Idle, etc.) — no user-mode threads to check
        if proc.peb_addr == 0 {
            continue;
        }

        // Switch to process address space for user-mode reads
        let proc_reader = reader.with_cr3(proc.cr3);

        // Walk DLLs from PEB LDR (graceful: empty vec on failure)
        let dlls = dll::walk_dlls(&proc_reader, proc.peb_addr).unwrap_or_default();

        // Walk VAD tree (graceful: empty vec on failure)
        let vads = if let Some(vad_off) = vad_root_offset {
            let vad_root_vaddr = proc.vaddr.wrapping_add(vad_off);
            vad::walk_vad_tree(reader, vad_root_vaddr, proc.pid, &proc.image_name)
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        // Walk threads for this process
        let threads = match thread::walk_threads(reader, proc.vaddr, proc.pid) {
            Ok(t) => t,
            Err(_) => continue,
        };

        let proc_lower = proc.image_name.to_lowercase();
        let is_system_proc = SYSTEM_PROCESSES.iter().any(|&s| proc_lower == s);

        for thr in &threads {
            // Skip threads with null start address (kernel threads, idle threads)
            if thr.start_address == 0 {
                continue;
            }

            let (start_module, is_orphan) = find_containing_module(&dlls, thr.start_address);
            let in_rwx = is_address_in_rwx_vad(&vads, thr.start_address);

            let (is_suspicious, reason) =
                classify_suspicious_thread(&start_module, is_orphan, in_rwx, &proc.image_name);

            if is_suspicious {
                suspicious.push(SuspiciousThreadInfo {
                    pid: proc.pid as u32,
                    process_name: proc.image_name.clone(),
                    tid: thr.tid as u32,
                    start_address: thr.start_address,
                    start_module,
                    is_orphan,
                    in_rwx_memory: in_rwx,
                    is_system_thread: is_system_proc,
                    reason,
                    is_suspicious,
                });

                if suspicious.len() >= MAX_SUSPICIOUS_THREADS {
                    return Ok(suspicious);
                }
            }
        }
    }

    Ok(suspicious)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ---------------------------------------------------------------
    // classify_suspicious_thread tests
    // ---------------------------------------------------------------

    #[test]
    fn orphan_thread_suspicious() {
        let (suspicious, reason) =
            classify_suspicious_thread("unknown", true, false, "notepad.exe");
        assert!(suspicious, "orphan thread should be suspicious");
        assert!(
            reason.contains("not in any loaded module"),
            "reason should mention orphan: {reason}"
        );
    }

    #[test]
    fn rwx_memory_suspicious() {
        let (suspicious, reason) =
            classify_suspicious_thread("ntdll.dll", false, true, "explorer.exe");
        assert!(suspicious, "RWX memory thread should be suspicious");
        assert!(
            reason.contains("read-write-execute"),
            "reason should mention RWX: {reason}"
        );
    }

    #[test]
    fn normal_module_benign() {
        let (suspicious, reason) =
            classify_suspicious_thread("kernel32.dll", false, false, "notepad.exe");
        assert!(
            !suspicious,
            "normal thread in known module should be benign"
        );
        assert!(reason.is_empty(), "benign reason should be empty: {reason}");
    }

    #[test]
    fn system_process_orphan_suspicious() {
        let (suspicious, reason) = classify_suspicious_thread("unknown", true, false, "csrss.exe");
        assert!(
            suspicious,
            "orphan thread in system process should be suspicious"
        );
        assert!(
            reason.contains("system process"),
            "reason should mention system process: {reason}"
        );
        assert!(
            reason.contains("csrss.exe"),
            "reason should name the process: {reason}"
        );
    }

    #[test]
    fn known_injection_target_suspicious() {
        // Orphan thread in a known injection target DLL context.
        // When is_orphan=true and start_module is a known target,
        // the orphan rule fires first.
        let (suspicious, reason) =
            classify_suspicious_thread("ntdll.dll", true, false, "notepad.exe");
        assert!(
            suspicious,
            "orphan thread with injection target should be suspicious"
        );
        assert!(
            reason.contains("not in any loaded module"),
            "reason should explain orphan: {reason}"
        );
    }

    #[test]
    fn empty_module_benign() {
        // Thread with empty start_module but not orphan and not RWX -> benign
        let (suspicious, reason) = classify_suspicious_thread("", false, false, "notepad.exe");
        assert!(
            !suspicious,
            "non-orphan thread with empty module should be benign"
        );
        assert!(reason.is_empty(), "benign reason should be empty: {reason}");
    }

    #[test]
    fn rwx_overrides_known_module() {
        // Even if thread is in a known module, RWX memory is suspicious
        let (suspicious, reason) =
            classify_suspicious_thread("kernel32.dll", false, true, "notepad.exe");
        assert!(
            suspicious,
            "RWX memory should be suspicious even in known module"
        );
        assert!(
            reason.contains("read-write-execute"),
            "reason should mention RWX: {reason}"
        );
    }

    // ---------------------------------------------------------------
    // walk_suspicious_threads tests
    // ---------------------------------------------------------------

    #[test]
    fn walk_suspicious_threads_no_symbol() {
        // IsfBuilder::new() has no PsActiveProcessHead symbol -> empty Vec.
        let isf = IsfBuilder::new()
            .add_struct("_EPROCESS", 0x1000)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_suspicious_threads(&reader).unwrap();
        assert!(
            result.is_empty(),
            "should return empty Vec when PsActiveProcessHead symbol is missing"
        );
    }

    // ---------------------------------------------------------------
    // is_rwx_protection unit tests
    // ---------------------------------------------------------------

    #[test]
    fn is_rwx_protection_execute_readwrite() {
        assert!(is_rwx_protection(VAD_PROT_EXECUTE_READWRITE));
    }

    #[test]
    fn is_rwx_protection_execute_writecopy() {
        assert!(is_rwx_protection(VAD_PROT_EXECUTE_WRITECOPY));
    }

    #[test]
    fn is_rwx_protection_readonly_not_rwx() {
        // PAGE_READONLY = 1
        assert!(!is_rwx_protection(1));
        // PAGE_READWRITE = 4
        assert!(!is_rwx_protection(4));
        // PAGE_EXECUTE_READ = 5
        assert!(!is_rwx_protection(5));
        // 0 (not committed)
        assert!(!is_rwx_protection(0));
    }

    // ---------------------------------------------------------------
    // find_containing_module unit tests
    // ---------------------------------------------------------------

    #[test]
    fn find_containing_module_found() {
        let dlls = vec![crate::WinDllInfo {
            name: "ntdll.dll".to_string(),
            base_addr: 0x7FFE_0000_0000,
            size: 0x20_0000,
            full_path: String::new(),
            load_order: 0,
        }];
        let addr = 0x7FFE_0000_0000 + 0x1000; // inside ntdll
        let (module, is_orphan) = find_containing_module(&dlls, addr);
        assert_eq!(module, "ntdll.dll");
        assert!(!is_orphan);
    }

    #[test]
    fn find_containing_module_not_found() {
        let dlls = vec![crate::WinDllInfo {
            name: "ntdll.dll".to_string(),
            base_addr: 0x7FFE_0000_0000,
            size: 0x20_0000,
            full_path: String::new(),
            load_order: 0,
        }];
        let addr = 0xDEAD_BEEF_0000; // outside any dll range
        let (module, is_orphan) = find_containing_module(&dlls, addr);
        assert_eq!(module, "unknown");
        assert!(is_orphan);
    }

    #[test]
    fn find_containing_module_empty_dlls() {
        let (module, is_orphan) = find_containing_module(&[], 0x1000);
        assert_eq!(module, "unknown");
        assert!(is_orphan);
    }

    #[test]
    fn find_containing_module_at_exact_base() {
        let dlls = vec![crate::WinDllInfo {
            name: "kernel32.dll".to_string(),
            base_addr: 0x7700_0000,
            size: 0x10_0000,
            full_path: String::new(),
            load_order: 1,
        }];
        // Exactly at base address
        let (module, is_orphan) = find_containing_module(&dlls, 0x7700_0000);
        assert_eq!(module, "kernel32.dll");
        assert!(!is_orphan);
    }

    // ---------------------------------------------------------------
    // is_address_in_rwx_vad unit tests
    // ---------------------------------------------------------------

    #[test]
    fn is_address_in_rwx_vad_inside_rwx() {
        let vads = vec![crate::WinVadInfo {
            start_vaddr: 0x0001_0000,
            end_vaddr: 0x0002_0000,
            protection: VAD_PROT_EXECUTE_READWRITE,
            protection_str: "PAGE_EXECUTE_READWRITE".to_string(),
            pid: 1,
            image_name: "test.exe".to_string(),
            is_private: true,
        }];
        assert!(is_address_in_rwx_vad(&vads, 0x0001_5000));
    }

    #[test]
    fn is_address_in_rwx_vad_inside_non_rwx() {
        let vads = vec![crate::WinVadInfo {
            start_vaddr: 0x0001_0000,
            end_vaddr: 0x0002_0000,
            protection: 4, // PAGE_READWRITE
            protection_str: "PAGE_READWRITE".to_string(),
            pid: 1,
            image_name: "test.exe".to_string(),
            is_private: true,
        }];
        assert!(!is_address_in_rwx_vad(&vads, 0x0001_5000));
    }

    #[test]
    fn is_address_in_rwx_vad_outside_rwx() {
        let vads = vec![crate::WinVadInfo {
            start_vaddr: 0x0001_0000,
            end_vaddr: 0x0002_0000,
            protection: VAD_PROT_EXECUTE_READWRITE,
            protection_str: "PAGE_EXECUTE_READWRITE".to_string(),
            pid: 1,
            image_name: "test.exe".to_string(),
            is_private: true,
        }];
        // Address outside the VAD range
        assert!(!is_address_in_rwx_vad(&vads, 0x0005_0000));
    }

    #[test]
    fn classify_system_process_orphan_with_rwx_prioritizes_system_rule() {
        // Both system process + rwx; rule 1 (system process orphan) fires first
        let (suspicious, reason) = classify_suspicious_thread("unknown", true, true, "lsass.exe");
        assert!(suspicious);
        assert!(reason.contains("system process"), "rule 1 should fire: {reason}");
    }

    // ---------------------------------------------------------------
    // walk_suspicious_threads walk body tests
    // ---------------------------------------------------------------

    /// walk_suspicious_threads: symbol present, one EPROCESS in list with peb_addr == 0
    /// (kernel process) → skipped → empty result. Exercises the peb_addr==0 guard.
    ///
    /// This uses a full circular _EPROCESS list so walk_processes returns one process.
    #[test]
    fn walk_suspicious_threads_kernel_process_skipped() {
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // ISF preset offsets:
        // _EPROCESS.ActiveProcessLinks = 0x448 (Flink = entry+0x448)
        // _EPROCESS.UniqueProcessId = 0x440
        // _EPROCESS.InheritedFromUniqueProcessId = 0x540
        // _EPROCESS.ImageFileName = 0x5A8
        // _EPROCESS.Peb = 0x550 (set to 0 → kernel process)
        // _EPROCESS.CreateTime = 0x430, ExitTime = 0x438
        // _EPROCESS.Pcb = 0x0, _KPROCESS.DirectoryTableBase = 0x28

        let ps_head_vaddr: u64 = 0xFFFF_8002_0000_0000;
        let ps_head_paddr: u64 = 0x0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8002_0100_0000;
        let eproc_paddr: u64 = 0x0011_0000;

        // Circular list: ps_head.Flink → eproc+0x448, eproc.Flink → ps_head
        let mut ps_head_page = vec![0u8; 4096];
        ps_head_page[0..8].copy_from_slice(&(eproc_vaddr + 0x448).to_le_bytes());

        let mut eproc_page = vec![0u8; 4096];
        // ActiveProcessLinks.Flink at eproc+0x448 → ps_head
        eproc_page[0x448..0x450].copy_from_slice(&ps_head_vaddr.to_le_bytes());
        // UniqueProcessId at eproc+0x440
        eproc_page[0x440..0x448].copy_from_slice(&4u64.to_le_bytes());
        // InheritedFromUniqueProcessId at eproc+0x540
        eproc_page[0x540..0x548].copy_from_slice(&0u64.to_le_bytes());
        // ImageFileName at eproc+0x5A8: "System\0"
        let name = b"System\0";
        eproc_page[0x5A8..0x5A8 + name.len()].copy_from_slice(name);
        // Peb at eproc+0x550 = 0 (kernel process)
        eproc_page[0x550..0x558].copy_from_slice(&0u64.to_le_bytes());
        // DirectoryTableBase (_KPROCESS at offset 0) at kproc+0x28 = eproc+0x28
        eproc_page[0x28..0x30].copy_from_slice(&(ps_head_paddr).to_le_bytes()); // any cr3

        let isf = IsfBuilder::windows_kernel_preset()
            .add_symbol("PsActiveProcessHead", ps_head_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(ps_head_vaddr, ps_head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys(ps_head_paddr, &ps_head_page)
            .write_phys(eproc_paddr, &eproc_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_suspicious_threads(&reader).unwrap();
        assert!(
            result.is_empty(),
            "kernel process (peb==0) should be skipped, got {} results",
            result.len()
        );
    }

    /// walk_suspicious_threads: process with peb_addr != 0, no threads → empty suspicious list.
    /// Exercises the inner loop body (DLL/VAD walk, thread walk) with graceful degradation.
    #[test]
    fn walk_suspicious_threads_user_process_no_threads_empty() {
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let ps_head_vaddr: u64 = 0xFFFF_8003_0000_0000;
        let ps_head_paddr: u64 = 0x0020_0000;
        let eproc_vaddr: u64 = 0xFFFF_8003_0100_0000;
        let eproc_paddr: u64 = 0x0021_0000;

        let mut ps_head_page = vec![0u8; 4096];
        ps_head_page[0..8].copy_from_slice(&(eproc_vaddr + 0x448).to_le_bytes());

        let mut eproc_page = vec![0u8; 4096];
        // ActiveProcessLinks.Flink → ps_head (terminates list)
        eproc_page[0x448..0x450].copy_from_slice(&ps_head_vaddr.to_le_bytes());
        eproc_page[0x440..0x448].copy_from_slice(&1234u64.to_le_bytes()); // PID
        eproc_page[0x540..0x548].copy_from_slice(&0u64.to_le_bytes()); // PPID
        let name = b"notepad.exe\0";
        eproc_page[0x5A8..0x5A8 + name.len()].copy_from_slice(name);
        // Peb at 0x550 = non-zero but unmapped (DLL walk will fail gracefully)
        eproc_page[0x550..0x558].copy_from_slice(&0x0000_7FFF_0000_0000u64.to_le_bytes());
        // CR3 (_KPROCESS.DirectoryTableBase at kproc=eproc+0, so offset 0x28) = cr3 value
        // We'll fix this after building.
        eproc_page[0x28..0x30].copy_from_slice(&0x0020_0000u64.to_le_bytes()); // placeholder

        let isf = IsfBuilder::windows_kernel_preset()
            .add_symbol("PsActiveProcessHead", ps_head_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(ps_head_vaddr, ps_head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys(ps_head_paddr, &ps_head_page)
            .write_phys(eproc_paddr, &eproc_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        // walk_processes reads the EPROCESS, then the inner loop tries to walk DLLs/VADs/threads.
        // All of those fail gracefully (unmapped memory) → empty result.
        let result = walk_suspicious_threads(&reader).unwrap();
        assert!(
            result.is_empty(),
            "user process with no threads should yield empty suspicious list, got {}",
            result.len()
        );
    }

    /// classify: RWX overrides system-process check when not orphan.
    #[test]
    fn classify_rwx_non_orphan_system_process() {
        let (suspicious, reason) =
            classify_suspicious_thread("kernel32.dll", false, true, "lsass.exe");
        assert!(suspicious, "RWX in system process thread should be suspicious");
        assert!(reason.contains("read-write-execute"), "reason: {reason}");
    }

    /// classify: orphan in multiple system processes.
    #[test]
    fn classify_orphan_in_all_system_processes() {
        for proc in SYSTEM_PROCESSES {
            let (suspicious, reason) =
                classify_suspicious_thread("unknown", true, false, proc);
            assert!(suspicious, "orphan in {proc} should be suspicious");
            assert!(reason.contains("system process"), "{proc}: {reason}");
        }
    }

    /// classify: non-system process with normal thread is benign.
    #[test]
    fn classify_non_system_normal_thread_benign() {
        let (suspicious, reason) =
            classify_suspicious_thread("kernelbase.dll", false, false, "notepad.exe");
        assert!(!suspicious);
        assert!(reason.is_empty());
    }

    /// is_rwx_protection: all values from 0..10 exercise the match.
    #[test]
    fn is_rwx_protection_coverage() {
        // Only 6 and 7 are RWX; everything else is not.
        for i in 0u32..10 {
            let result = is_rwx_protection(i);
            let expected = i == 6 || i == 7;
            assert_eq!(result, expected, "protection={i}");
        }
    }

    /// find_containing_module: address at exact end (one past) is NOT in module.
    #[test]
    fn find_containing_module_at_end_exclusive() {
        let dlls = vec![crate::WinDllInfo {
            name: "ntdll.dll".to_string(),
            base_addr: 0x7700_0000,
            size: 0x10_0000,
            full_path: String::new(),
            load_order: 0,
        }];
        // Exactly at base + size is NOT inside the DLL (exclusive end).
        let (module, is_orphan) = find_containing_module(&dlls, 0x7710_0000);
        assert_eq!(module, "unknown");
        assert!(is_orphan);
    }

    /// find_containing_module: multiple DLLs, address in second one.
    #[test]
    fn find_containing_module_multiple_dlls() {
        let dlls = vec![
            crate::WinDllInfo {
                name: "ntdll.dll".to_string(),
                base_addr: 0x7700_0000,
                size: 0x10_0000,
                full_path: String::new(),
                load_order: 0,
            },
            crate::WinDllInfo {
                name: "kernel32.dll".to_string(),
                base_addr: 0x7800_0000,
                size: 0x10_0000,
                full_path: String::new(),
                load_order: 1,
            },
        ];
        let (module, is_orphan) = find_containing_module(&dlls, 0x7800_1000);
        assert_eq!(module, "kernel32.dll");
        assert!(!is_orphan);
    }

    /// SuspiciousThreadInfo: all fields are accessible.
    #[test]
    fn suspicious_thread_info_fields() {
        let info = SuspiciousThreadInfo {
            pid: 4,
            process_name: "lsass.exe".to_string(),
            tid: 100,
            start_address: 0xDEAD_0000,
            start_module: "unknown".to_string(),
            is_orphan: true,
            in_rwx_memory: false,
            is_system_thread: true,
            reason: "test reason".to_string(),
            is_suspicious: true,
        };
        assert_eq!(info.pid, 4);
        assert_eq!(info.tid, 100);
        assert!(info.is_orphan);
        assert!(info.is_system_thread);
    }

    /// SuspiciousThreadInfo serializes correctly.
    #[test]
    fn suspicious_thread_info_serializes() {
        let info = SuspiciousThreadInfo {
            pid: 668,
            process_name: "lsass.exe".to_string(),
            tid: 200,
            start_address: 0xABCD_0000,
            start_module: "unknown".to_string(),
            is_orphan: true,
            in_rwx_memory: true,
            is_system_thread: true,
            reason: "orphan thread in system process".to_string(),
            is_suspicious: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":668"));
        assert!(json.contains("\"is_suspicious\":true"));
        assert!(json.contains("\"in_rwx_memory\":true"));
    }

    /// is_address_in_rwx_vad: address exactly at start_vaddr.
    #[test]
    fn is_address_in_rwx_vad_at_exact_start() {
        let vads = vec![crate::WinVadInfo {
            start_vaddr: 0x1000,
            end_vaddr: 0x2000,
            protection: VAD_PROT_EXECUTE_READWRITE,
            protection_str: "PAGE_EXECUTE_READWRITE".to_string(),
            pid: 1,
            image_name: "test.exe".to_string(),
            is_private: true,
        }];
        assert!(is_address_in_rwx_vad(&vads, 0x1000));
    }

    /// is_address_in_rwx_vad: empty VADs list → always false.
    #[test]
    fn is_address_in_rwx_vad_empty_vads() {
        assert!(!is_address_in_rwx_vad(&[], 0x1234));
    }

    /// is_address_in_rwx_vad: writecopy at boundary.
    #[test]
    fn is_address_in_rwx_vad_writecopy_at_end() {
        let vads = vec![crate::WinVadInfo {
            start_vaddr: 0x1000,
            end_vaddr: 0x2000,
            protection: VAD_PROT_EXECUTE_WRITECOPY,
            protection_str: "PAGE_EXECUTE_WRITECOPY".to_string(),
            pid: 1,
            image_name: "test.exe".to_string(),
            is_private: true,
        }];
        // Exactly at end_vaddr (inclusive).
        assert!(is_address_in_rwx_vad(&vads, 0x2000));
    }

    /// walk_suspicious_threads: process has one thread with a non-zero start address
    /// that is NOT in any DLL → orphan thread → detected as suspicious.
    ///
    /// Layout:
    ///   ps_head (0xFFFF_8004_0000_0000) → eproc+0x448
    ///   eproc   (0xFFFF_8004_0100_0000): image "notepad.exe", peb=0xFFFF_8004_0200_0000, cr3=X
    ///     _KPROCESS.ThreadListHead (eproc+0x30) → kthread+0x2F8
    ///   kthread (0xFFFF_8004_0300_0000):
    ///     ThreadListEntry.Flink (kthread+0x2F8) → eproc+0x30 (sentinel; terminates list)
    ///     Win32StartAddress (kthread+0x680) = 0xDEAD_0000 (orphan, not in any DLL)
    ///     Teb (kthread+0xF0) = 0
    ///     CreateTime (kthread+0x688) = 0
    ///     _ETHREAD.Cid.UniqueThread (kthread+0x628) = 100 (TID)
    #[test]
    fn walk_suspicious_threads_orphan_thread_detected() {
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Virtual addresses (kernel space) → physical addresses (< 16 MB)
        let ps_head_vaddr: u64 = 0xFFFF_8004_0000_0000;
        let ps_head_paddr: u64 = 0x0030_0000;
        let eproc_vaddr: u64   = 0xFFFF_8004_0100_0000;
        let eproc_paddr: u64   = 0x0031_0000;
        let kthread_vaddr: u64 = 0xFFFF_8004_0300_0000;
        let kthread_paddr: u64 = 0x0033_0000;

        // ps_head page: Flink at [0..8] → eproc+0x448 (EPROCESS ActiveProcessLinks)
        let mut ps_head_page = vec![0u8; 4096];
        ps_head_page[0..8].copy_from_slice(&(eproc_vaddr + 0x448).to_le_bytes());

        // eproc page
        let mut eproc_page = vec![0u8; 4096];
        // ActiveProcessLinks.Flink at eproc+0x448 → ps_head (terminates list)
        eproc_page[0x448..0x450].copy_from_slice(&ps_head_vaddr.to_le_bytes());
        // UniqueProcessId at eproc+0x440 = 4
        eproc_page[0x440..0x448].copy_from_slice(&4u64.to_le_bytes());
        // PPID at eproc+0x540 = 0
        eproc_page[0x540..0x548].copy_from_slice(&0u64.to_le_bytes());
        // ImageFileName at eproc+0x5A8: "notepad.exe\0"
        let name = b"notepad.exe\0";
        eproc_page[0x5A8..0x5A8 + name.len()].copy_from_slice(name);
        // Peb at eproc+0x550 = some non-zero but unmapped address (DLL walk fails gracefully)
        eproc_page[0x550..0x558].copy_from_slice(&0x0000_7FFF_0000_0000u64.to_le_bytes());
        // CR3 = eproc_paddr (reuse as cr3 value, just needs to be a valid paddr)
        eproc_page[0x28..0x30].copy_from_slice(&eproc_paddr.to_le_bytes());
        // _KPROCESS.ThreadListHead at eproc+0x30: Flink → kthread+0x2F8
        eproc_page[0x30..0x38].copy_from_slice(&(kthread_vaddr + 0x2F8).to_le_bytes());

        // kthread page
        let mut kthread_page = vec![0u8; 4096];
        // _KTHREAD.ThreadListEntry.Flink at kthread+0x2F8 → eproc+0x30 (sentinel)
        kthread_page[0x2F8..0x300].copy_from_slice(&(eproc_vaddr + 0x30).to_le_bytes());
        // _KTHREAD.Teb at kthread+0xF0 = 0
        kthread_page[0xF0..0xF8].copy_from_slice(&0u64.to_le_bytes());
        // _KTHREAD.Win32StartAddress at kthread+0x680 = 0xDEAD_0000 (orphan)
        kthread_page[0x680..0x688].copy_from_slice(&0xDEAD_0000u64.to_le_bytes());
        // _KTHREAD.CreateTime at kthread+0x688 = 0
        kthread_page[0x688..0x690].copy_from_slice(&0u64.to_le_bytes());
        // _ETHREAD.Cid.UniqueThread at kthread+0x628 (Cid at 0x620, UniqueThread at +8)
        kthread_page[0x628..0x630].copy_from_slice(&100u64.to_le_bytes()); // TID=100

        let isf = IsfBuilder::windows_kernel_preset()
            .add_symbol("PsActiveProcessHead", ps_head_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(ps_head_vaddr, ps_head_paddr, flags::WRITABLE)
            .write_phys(ps_head_paddr, &ps_head_page)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys(eproc_paddr, &eproc_page)
            .map_4k(kthread_vaddr, kthread_paddr, flags::WRITABLE)
            .write_phys(kthread_paddr, &kthread_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_suspicious_threads(&reader).unwrap();
        assert!(
            !result.is_empty(),
            "orphan thread should be detected as suspicious"
        );
        let t = &result[0];
        assert_eq!(t.process_name, "notepad.exe");
        assert!(t.is_orphan, "thread should be flagged as orphan");
        assert!(t.is_suspicious, "thread should be suspicious");
        assert_eq!(t.start_address, 0xDEAD_0000);
    }
}
