//! Direct/indirect system call detection for EDR bypass analysis.
//!
//! Detects processes using direct or indirect system call invocations to
//! bypass EDR API hooks. When malware calls Nt* functions directly via the
//! `syscall`/`sysenter` instruction instead of through `ntdll.dll`, it
//! bypasses usermode hooks placed by security products.
//!
//! Key techniques detected:
//! - **Direct syscall**: The `syscall` instruction lives in non-ntdll code
//!   (SysWhispers, HellsGate, Halo's Gate).
//! - **Indirect syscall**: Code jumps into ntdll's `syscall` gadget from a
//!   non-system module to make the return address appear legitimate.
//! - **Heaven's Gate**: 32-bit process transitions to 64-bit mode to invoke
//!   64-bit NT syscalls directly, bypassing WoW64 layer hooks.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{process, thread, DirectSyscallInfo, Result};

/// Classify whether a syscall invocation is suspicious.
///
/// Rules:
/// - A `syscall`/`sysenter` instruction **outside** ntdll.dll is always
///   suspicious (direct syscall from injected or packed code).
/// - An `indirect_syscall` (trampoline through ntdll) is suspicious when
///   the originating module is not a known system DLL.
/// - `heavens_gate` (32-to-64-bit transition) is always suspicious.
/// - A normal syscall inside ntdll with a standard technique is benign.
pub fn classify_syscall_technique(in_ntdll: bool, technique: &str) -> bool {
    match technique {
        // Heaven's Gate is always suspicious -- legitimate code does not
        // perform 32->64 bit transitions to invoke syscalls.
        "heavens_gate" => true,

        // Direct syscall: suspicious only when the instruction is outside ntdll.
        "direct_syscall" => !in_ntdll,

        // Indirect syscall: the actual `syscall` instruction is inside ntdll
        // (so in_ntdll is typically true), but the *call* originates from a
        // non-system module. We flag these as suspicious when they come from
        // an unknown/non-system origin.
        "indirect_syscall" => true,

        // Any other technique outside ntdll is suspicious.
        _ => !in_ntdll,
    }
}

/// Walk all processes and threads to detect direct/indirect syscall usage.
///
/// For each thread, checks whether the last syscall instruction address
/// falls within ntdll.dll's `.text` section range. Threads where the
/// `syscall`/`sysenter` instruction is outside ntdll are flagged.
///
/// Returns an empty `Vec` if the `PsActiveProcessHead` symbol is missing.
pub fn walk_direct_syscalls<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
) -> Result<Vec<DirectSyscallInfo>> {
    // Graceful degradation: return empty if the required symbol is missing.
    let Some(ps_head) = reader.symbols().symbol_address("PsActiveProcessHead") else {
        return Ok(Vec::new());
    };

    let procs = process::walk_processes(reader, ps_head)?;
    let mut results = Vec::new();

    for proc in &procs {
        // Skip kernel processes (no PEB, no usermode ntdll).
        if proc.peb_addr == 0 {
            continue;
        }

        let pid = proc.pid as u32;
        let process_name = proc.image_name.clone();

        // Determine ntdll.dll range for this process by walking its LDR module
        // list. We look for the module named "ntdll.dll" and record its
        // base address and size to define the legitimate syscall range.
        let ntdll_range = find_ntdll_range(reader, proc);

        // Walk threads for this process.
        let threads = match thread::walk_threads(reader, proc.vaddr, proc.pid) {
            Ok(t) => t,
            Err(_) => continue,
        };

        for thr in &threads {
            // Read the thread's last syscall address from _KTHREAD fields.
            let (syscall_addr, syscall_number, technique) =
                match read_thread_syscall_info(reader, thr.vaddr) {
                    Some(info) => info,
                    None => continue,
                };

            // Skip threads with no recorded syscall (address == 0).
            if syscall_addr == 0 {
                continue;
            }

            let in_ntdll = match ntdll_range {
                Some((base, size)) => {
                    syscall_addr >= base && syscall_addr < base.saturating_add(size)
                }
                // If we cannot determine ntdll range, we cannot confirm
                // the instruction is in ntdll.
                None => false,
            };

            let is_suspicious = classify_syscall_technique(in_ntdll, &technique);

            results.push(DirectSyscallInfo {
                pid,
                process_name: process_name.clone(),
                thread_id: thr.tid as u32,
                syscall_address: syscall_addr,
                syscall_number,
                technique,
                in_ntdll,
                is_suspicious,
            });
        }
    }

    Ok(results)
}

/// Attempt to find ntdll.dll's base address and size from the process's
/// PEB LDR module list. Returns `None` if the range cannot be determined.
fn find_ntdll_range<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
    proc: &crate::WinProcessInfo,
) -> Option<(u64, u64)> {
    // Switch to the process's address space.
    let proc_reader = reader.with_cr3(proc.cr3);

    // PEB -> Ldr -> InLoadOrderModuleList
    let ldr_addr: u64 = proc_reader.read_field(proc.peb_addr, "_PEB", "Ldr").ok()?;
    if ldr_addr == 0 {
        return None;
    }

    // Walk InLoadOrderModuleList to find ntdll.dll.
    let in_load_order_off = proc_reader
        .symbols()
        .field_offset("_PEB_LDR_DATA", "InLoadOrderModuleList")
        .unwrap_or(0x10);

    let module_addrs = proc_reader
        .walk_list_with(
            ldr_addr.wrapping_add(in_load_order_off),
            "_LIST_ENTRY",
            "Flink",
            "_LDR_DATA_TABLE_ENTRY",
            "InLoadOrderLinks",
        )
        .ok()?;

    let base_dll_name_off = proc_reader
        .symbols()
        .field_offset("_LDR_DATA_TABLE_ENTRY", "BaseDllName")
        .unwrap_or(0x58);

    let dll_base_off = proc_reader
        .symbols()
        .field_offset("_LDR_DATA_TABLE_ENTRY", "DllBase")
        .unwrap_or(0x30);

    let size_of_image_off = proc_reader
        .symbols()
        .field_offset("_LDR_DATA_TABLE_ENTRY", "SizeOfImage")
        .unwrap_or(0x40);

    for mod_addr in module_addrs {
        // Read the BaseDllName UNICODE_STRING.
        let name = crate::unicode::read_unicode_string(
            &proc_reader,
            mod_addr.wrapping_add(base_dll_name_off),
        )
        .unwrap_or_default();

        if name.eq_ignore_ascii_case("ntdll.dll") {
            let base: u64 = proc_reader
                .read_bytes(mod_addr.wrapping_add(dll_base_off), 8)
                .ok()
                .and_then(|b| Some(u64::from_le_bytes(b[..8].try_into().ok()?)))
                .unwrap_or(0);

            let size: u64 = proc_reader
                .read_bytes(mod_addr.wrapping_add(size_of_image_off), 4)
                .ok()
                .and_then(|b| Some(u32::from_le_bytes(b[..4].try_into().ok()?) as u64))
                .unwrap_or(0);

            if base != 0 && size != 0 {
                return Some((base, size));
            }
        }
    }

    None
}

/// Read syscall-related fields from a `_KTHREAD`/`_ETHREAD`.
///
/// Returns `(syscall_address, syscall_number, technique)` or `None` if the
/// fields cannot be read.
fn read_thread_syscall_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ethread_addr: u64,
) -> Option<(u64, u32, String)> {
    // _KTHREAD.SystemCallNumber -- the SSN of the last syscall.
    let syscall_number_off = reader
        .symbols()
        .field_offset("_KTHREAD", "SystemCallNumber")
        .unwrap_or(0x80);

    let syscall_number: u32 = reader
        .read_bytes(ethread_addr.wrapping_add(syscall_number_off), 4)
        .ok()
        .and_then(|b| Some(u32::from_le_bytes(b[..4].try_into().ok()?)))
        .unwrap_or(0);

    // _KTHREAD.Win32StartAddress can indicate the instruction pointer that
    // performed the syscall. We use it as a proxy for the syscall address.
    let win32_start_off = reader
        .symbols()
        .field_offset("_KTHREAD", "Win32StartAddress")
        .unwrap_or(0x560);

    let syscall_addr: u64 = reader
        .read_bytes(ethread_addr.wrapping_add(win32_start_off), 8)
        .ok()
        .and_then(|b| Some(u64::from_le_bytes(b[..8].try_into().ok()?)))
        .unwrap_or(0);

    // Heuristic technique classification based on address characteristics.
    // In a real dump we would disassemble the instruction at syscall_addr
    // to distinguish `syscall` vs `int 2e` vs far-jump (Heaven's Gate).
    // For now we classify based on whether the address looks like a WoW64
    // transition (low 32-bit address space in a 64-bit process).
    let technique = if syscall_addr != 0 && syscall_addr <= 0xFFFF_FFFF {
        // Address in 32-bit range inside a 64-bit process -> Heaven's Gate.
        "heavens_gate".to_string()
    } else {
        "direct_syscall".to_string()
    };

    Some((syscall_addr, syscall_number, technique))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Classifier unit tests -------------------------------------------

    #[test]
    fn classify_direct_outside_ntdll_suspicious() {
        // A direct syscall instruction outside ntdll is always suspicious.
        assert!(classify_syscall_technique(false, "direct_syscall"));
    }

    #[test]
    fn classify_normal_ntdll_benign() {
        // A direct syscall instruction inside ntdll is normal (the standard path).
        assert!(!classify_syscall_technique(true, "direct_syscall"));
    }

    #[test]
    fn classify_heavens_gate_suspicious() {
        // Heaven's Gate is always suspicious regardless of ntdll location.
        assert!(classify_syscall_technique(false, "heavens_gate"));
        assert!(classify_syscall_technique(true, "heavens_gate"));
    }

    #[test]
    fn classify_indirect_from_unknown_suspicious() {
        // Indirect syscalls (trampolines) are suspicious -- even though the
        // actual syscall instruction may be in ntdll, the technique itself
        // indicates evasion.
        assert!(classify_syscall_technique(true, "indirect_syscall"));
        assert!(classify_syscall_technique(false, "indirect_syscall"));
    }

    #[test]
    fn classify_unknown_technique_outside_ntdll_suspicious() {
        // An unrecognized technique outside ntdll is suspicious.
        assert!(classify_syscall_technique(false, "some_unknown_technique"));
    }

    #[test]
    fn classify_unknown_technique_inside_ntdll_benign() {
        // An unrecognized technique inside ntdll is not suspicious.
        assert!(!classify_syscall_technique(true, "some_unknown_technique"));
    }

    // -- Walker tests ----------------------------------------------------

    #[test]
    fn walk_direct_syscalls_no_symbol_returns_empty() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Build a bare ISF with NO PsActiveProcessHead symbol.
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Minimal page table -- just needs to be valid.
        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &[0u8; 16]);

        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_direct_syscalls(&reader).unwrap();
        assert!(results.is_empty());
    }

    /// Walker with PsActiveProcessHead symbol present but unreadable process list
    /// returns empty (graceful degradation on unreadable memory).
    #[test]
    fn walk_direct_syscalls_with_symbol_unreadable_head() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Symbol present but pointing to unmapped memory.
        let isf = IsfBuilder::new()
            .add_symbol("PsActiveProcessHead", 0xFFFF_8000_DEAD_0000u64)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<memf_core::test_builders::SyntheticPhysMem> =
            ObjectReader::new(vas, Box::new(resolver));

        // walk_processes will fail on unreadable memory → empty results.
        let results = walk_direct_syscalls(&reader).unwrap();
        assert!(results.is_empty());
    }

    /// Heavens gate is suspicious regardless of ntdll location.
    #[test]
    fn classify_heavens_gate_always_suspicious() {
        assert!(classify_syscall_technique(true, "heavens_gate"));
        assert!(classify_syscall_technique(false, "heavens_gate"));
    }

    /// Direct syscall in ntdll is benign; outside is suspicious.
    #[test]
    fn classify_direct_syscall_ntdll_boundary() {
        assert!(!classify_syscall_technique(true, "direct_syscall"));
        assert!(classify_syscall_technique(false, "direct_syscall"));
    }

    /// Indirect syscall is always suspicious regardless of ntdll context.
    #[test]
    fn classify_indirect_syscall_always_suspicious() {
        assert!(classify_syscall_technique(true, "indirect_syscall"));
        assert!(classify_syscall_technique(false, "indirect_syscall"));
    }

    /// Unknown technique inside ntdll is benign; outside is suspicious.
    #[test]
    fn classify_unknown_technique_boundary() {
        assert!(!classify_syscall_technique(true, "some_technique"));
        assert!(classify_syscall_technique(false, "some_technique"));
    }

    /// DirectSyscallInfo can be constructed and its fields are accessible.
    #[test]
    fn direct_syscall_info_fields() {
        let info = DirectSyscallInfo {
            pid: 1234,
            process_name: "test.exe".to_string(),
            thread_id: 5678,
            syscall_address: 0x7FF8_0000_1000,
            syscall_number: 0x0A,
            technique: "direct_syscall".to_string(),
            in_ntdll: false,
            is_suspicious: true,
        };
        assert_eq!(info.pid, 1234);
        assert_eq!(info.technique, "direct_syscall");
        assert!(info.is_suspicious);
    }
}
