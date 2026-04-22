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

        let results = walk_direct_syscalls(&reader).unwrap_or_default();
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
        let results = walk_direct_syscalls(&reader).unwrap_or_default();
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

    /// Walker with PsActiveProcessHead pointing to an empty circular list
    /// exercises the walk body (process loop) and returns empty.
    #[test]
    fn walk_direct_syscalls_empty_process_list() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let ps_head_vaddr: u64 = 0xFFFF_8000_0040_0000;
        let ps_head_paddr: u64 = 0x0040_0000;

        // ISF with PsActiveProcessHead symbol + minimal _EPROCESS for walk_processes.
        let isf = IsfBuilder::windows_kernel_preset()
            .add_symbol("PsActiveProcessHead", ps_head_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Empty circular doubly-linked list: Flink = Blink = ps_head_vaddr.
        let mut page = [0u8; 4096];
        page[0..8].copy_from_slice(&ps_head_vaddr.to_le_bytes());
        page[8..16].copy_from_slice(&ps_head_vaddr.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(ps_head_vaddr, ps_head_paddr, flags::WRITABLE)
            .write_phys(ps_head_paddr, &page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_direct_syscalls(&reader).unwrap_or_default();
        assert!(
            results.is_empty(),
            "empty process list should yield no syscall entries"
        );
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

    // -- read_thread_syscall_info tests -------------------------------------

    /// read_thread_syscall_info from unmapped ethread addr returns Some((0, 0, "direct_syscall")).
    /// The function uses unwrap_or(0) so it always returns Some.
    #[test]
    fn read_thread_syscall_info_unmapped_returns_some_zeroes() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let (cr3, mem) = PageTableBuilder::new().build();
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = read_thread_syscall_info(&reader, 0xFFFF_8000_DEAD_0000);
        // Unmapped → all fields default to 0 → Some((0, 0, "direct_syscall"))
        assert!(result.is_some());
        let (addr, num, technique) = result.unwrap();
        assert_eq!(addr, 0);
        assert_eq!(num, 0);
        assert_eq!(technique, "direct_syscall");
    }

    /// read_thread_syscall_info with a 32-bit (WoW64) Win32StartAddress returns heavens_gate.
    #[test]
    fn read_thread_syscall_info_wow64_address_heavens_gate() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Default Win32StartAddress offset = 0x560.
        let ethread_vaddr: u64 = 0xFFFF_8000_0050_0000;
        let ethread_paddr: u64 = 0x0050_0000;

        // Write a 32-bit address at offset 0x560 (within the 32-bit address space).
        let win32_start: u64 = 0x0000_0000_7FFF_0010; // <= 0xFFFF_FFFF → heavens_gate
        let syscall_number: u32 = 0x2A;

        let mut page = [0u8; 4096];
        // SystemCallNumber at offset 0x80 (default)
        page[0x80..0x84].copy_from_slice(&syscall_number.to_le_bytes());
        // Win32StartAddress at offset 0x560 (default)
        page[0x560..0x568].copy_from_slice(&win32_start.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(ethread_vaddr, ethread_paddr, flags::WRITABLE)
            .write_phys(ethread_paddr, &page)
            .build();

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = read_thread_syscall_info(&reader, ethread_vaddr).unwrap();
        let (addr, num, technique) = result;
        assert_eq!(addr, win32_start);
        assert_eq!(num, syscall_number);
        assert_eq!(
            technique, "heavens_gate",
            "low address should classify as heavens_gate"
        );
        // heavens_gate is always suspicious regardless of in_ntdll
        assert!(classify_syscall_technique(true, &technique));
        assert!(classify_syscall_technique(false, &technique));
    }

    /// read_thread_syscall_info with a 64-bit Win32StartAddress returns direct_syscall.
    #[test]
    fn read_thread_syscall_info_64bit_address_direct_syscall() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let ethread_vaddr: u64 = 0xFFFF_8000_0051_0000;
        let ethread_paddr: u64 = 0x0051_0000;

        // 64-bit address (> 0xFFFF_FFFF) → direct_syscall technique.
        let win32_start: u64 = 0x7FFF_1234_5678_ABCD;
        let syscall_number: u32 = 0x3B;

        let mut page = [0u8; 4096];
        page[0x80..0x84].copy_from_slice(&syscall_number.to_le_bytes());
        page[0x560..0x568].copy_from_slice(&win32_start.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(ethread_vaddr, ethread_paddr, flags::WRITABLE)
            .write_phys(ethread_paddr, &page)
            .build();

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = read_thread_syscall_info(&reader, ethread_vaddr).unwrap();
        let (addr, num, technique) = result;
        assert_eq!(addr, win32_start);
        assert_eq!(num, syscall_number);
        assert_eq!(
            technique, "direct_syscall",
            "high address should classify as direct_syscall"
        );
    }

    // -- find_ntdll_range tests ------------------------------------------

    /// find_ntdll_range: peb_addr is 0 (proc.peb_addr used internally but
    /// find_ntdll_range reads proc.peb_addr directly) → ldr read fails → None.
    #[test]
    fn find_ntdll_range_null_peb_returns_none() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let (cr3, mem) = PageTableBuilder::new().build();
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<memf_core::test_builders::SyntheticPhysMem> =
            ObjectReader::new(vas, Box::new(resolver));

        let proc = crate::WinProcessInfo {
            vaddr: 0,
            pid: 4,
            ppid: 0,
            image_name: "System".to_string(),
            peb_addr: 0x0000_7FFF_1000_0000, // non-zero but unmapped
            cr3: 0,
            create_time: 0,
            exit_time: 0,
            thread_count: 0,
            is_wow64: false,
        };

        // peb_addr is unmapped → read_field("_PEB", "Ldr") fails → None
        let result = find_ntdll_range(&reader, &proc);
        assert!(
            result.is_none(),
            "unmapped peb → find_ntdll_range returns None"
        );
    }

    /// find_ntdll_range: PEB readable, Ldr = 0 → returns None.
    #[test]
    fn find_ntdll_range_zero_ldr_returns_none() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let peb_vaddr: u64 = 0x0000_7FFF_2000_0000;
        let peb_paddr: u64 = 0x0020_0000;

        // PEB.Ldr at offset 0x18 = 0
        let mut peb_page = vec![0u8; 4096];
        peb_page[0x18..0x20].copy_from_slice(&0u64.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(peb_vaddr, peb_paddr, flags::WRITABLE)
            .write_phys(peb_paddr, &peb_page)
            .build();

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<memf_core::test_builders::SyntheticPhysMem> =
            ObjectReader::new(vas, Box::new(resolver));

        let proc = crate::WinProcessInfo {
            vaddr: 0,
            pid: 100,
            ppid: 0,
            image_name: "notepad.exe".to_string(),
            peb_addr: peb_vaddr,
            cr3,
            create_time: 0,
            exit_time: 0,
            thread_count: 0,
            is_wow64: false,
        };

        let result = find_ntdll_range(&reader, &proc);
        assert!(result.is_none(), "Ldr == 0 → find_ntdll_range returns None");
    }

    /// find_ntdll_range: PEB readable, Ldr non-zero but unmapped → walk_list_with fails → None.
    #[test]
    fn find_ntdll_range_unmapped_ldr_returns_none() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let peb_vaddr: u64 = 0x0000_7FFF_3000_0000;
        let peb_paddr: u64 = 0x0030_0000;
        let ldr_vaddr: u64 = 0xFFFF_DEAD_BEEF_0000; // unmapped ldr

        let mut peb_page = vec![0u8; 4096];
        peb_page[0x18..0x20].copy_from_slice(&ldr_vaddr.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(peb_vaddr, peb_paddr, flags::WRITABLE)
            .write_phys(peb_paddr, &peb_page)
            .build();

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<memf_core::test_builders::SyntheticPhysMem> =
            ObjectReader::new(vas, Box::new(resolver));

        let proc = crate::WinProcessInfo {
            vaddr: 0,
            pid: 200,
            ppid: 0,
            image_name: "test.exe".to_string(),
            peb_addr: peb_vaddr,
            cr3,
            create_time: 0,
            exit_time: 0,
            thread_count: 0,
            is_wow64: false,
        };

        let result = find_ntdll_range(&reader, &proc);
        assert!(
            result.is_none(),
            "unmapped ldr → find_ntdll_range returns None"
        );
    }

    /// classify_syscall_technique: exhaustive boundary table.
    #[test]
    fn classify_syscall_exhaustive_boundaries() {
        // direct_syscall inside ntdll → benign
        assert!(!classify_syscall_technique(true, "direct_syscall"));
        // direct_syscall outside ntdll → suspicious
        assert!(classify_syscall_technique(false, "direct_syscall"));
        // heavens_gate always suspicious
        assert!(classify_syscall_technique(true, "heavens_gate"));
        assert!(classify_syscall_technique(false, "heavens_gate"));
        // indirect_syscall always suspicious
        assert!(classify_syscall_technique(true, "indirect_syscall"));
        assert!(classify_syscall_technique(false, "indirect_syscall"));
        // unknown: in_ntdll=true → benign
        assert!(!classify_syscall_technique(true, "exotic_technique"));
        // unknown: in_ntdll=false → suspicious
        assert!(classify_syscall_technique(false, "exotic_technique"));
    }

    /// DirectSyscallInfo clone works correctly.
    #[test]
    fn direct_syscall_info_clone() {
        let info = DirectSyscallInfo {
            pid: 42,
            process_name: "svchost.exe".to_string(),
            thread_id: 100,
            syscall_address: 0x7FF8_0001_2000,
            syscall_number: 0x05,
            technique: "indirect_syscall".to_string(),
            in_ntdll: true,
            is_suspicious: true,
        };
        let c = info.clone();
        assert_eq!(c.pid, 42);
        assert_eq!(c.technique, "indirect_syscall");
    }

    /// DirectSyscallInfo serialization includes all expected fields.
    #[test]
    fn direct_syscall_info_serializes() {
        let info = DirectSyscallInfo {
            pid: 999,
            process_name: "inject.exe".to_string(),
            thread_id: 1111,
            syscall_address: 0xDEAD_BEEF_1234,
            syscall_number: 0xFF,
            technique: "heavens_gate".to_string(),
            in_ntdll: false,
            is_suspicious: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":999"));
        assert!(json.contains("\"technique\":\"heavens_gate\""));
        assert!(json.contains("\"in_ntdll\":false"));
        assert!(json.contains("\"is_suspicious\":true"));
        assert!(json.contains("\"syscall_number\":255"));
    }

    // -- Walk body: process loop with non-zero PEB + thread ---------------
    //
    // Constants from windows_kernel_preset (matching process.rs and thread.rs):
    //   _EPROCESS: ActiveProcessLinks @ 0x448, Peb @ 0x550, Pcb (=_KPROCESS) @ 0
    //   _KPROCESS: DirectoryTableBase @ 0x28, ThreadListHead @ 0x30
    //   _KTHREAD:  ThreadListEntry @ 0x2F8
    //   read_thread_syscall_info defaults: SystemCallNumber @ 0x80, Win32StartAddress @ 0x560

    const EPROCESS_LINKS: u64 = 0x448;
    const EPROCESS_PEB: u64 = 0x550;
    const EPROCESS_PID: u64 = 0x440;
    const EPROCESS_PPID: u64 = 0x540;
    const EPROCESS_DTB: u64 = 0x28; // within _KPROCESS (= eproc + Pcb=0)
    const EPROCESS_IMAGE: u64 = 0x5A8;
    const KPROCESS_TLH: u64 = 0x30; // _KPROCESS.ThreadListHead within _EPROCESS
    const KTHREAD_TLE: u64 = 0x2F8; // _KTHREAD.ThreadListEntry

    /// Walker with a process having peb_addr != 0 but empty thread list:
    /// - exercises lines 70-86 (skip-kernel guard passes, thread walk returns empty)
    /// - ntdll_range = None (PEB is not mapped → find_ntdll_range returns None)
    #[test]
    fn walk_direct_syscalls_process_nonzero_peb_no_threads() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Physical addresses (well below 16 MB limit)
        let head_paddr: u64 = 0x0060_0000;
        let eproc_paddr: u64 = 0x0061_0000;

        // Virtual addresses (kernel space)
        let head_vaddr: u64 = 0xFFFF_8000_0060_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0061_0000;

        let eproc_links_vaddr = eproc_vaddr + EPROCESS_LINKS;

        let mut head_page = [0u8; 4096];
        // head.Flink → eproc.ActiveProcessLinks, head.Blink → same
        head_page[..8].copy_from_slice(&eproc_links_vaddr.to_le_bytes());
        head_page[8..16].copy_from_slice(&eproc_links_vaddr.to_le_bytes());

        let mut eproc_page = [0u8; 4096];
        // _EPROCESS.ActiveProcessLinks.Flink → head (circular)
        let off = EPROCESS_LINKS as usize;
        eproc_page[off..off + 8].copy_from_slice(&head_vaddr.to_le_bytes());
        eproc_page[off + 8..off + 16].copy_from_slice(&head_vaddr.to_le_bytes());
        // PID = 1000
        let pid_off = EPROCESS_PID as usize;
        eproc_page[pid_off..pid_off + 8].copy_from_slice(&1000u64.to_le_bytes());
        // PPID = 500
        let ppid_off = EPROCESS_PPID as usize;
        eproc_page[ppid_off..ppid_off + 8].copy_from_slice(&500u64.to_le_bytes());
        // Peb = 0x0000_7FFF_5000_0000 (non-zero, but not mapped → find_ntdll_range returns None)
        let peb_val: u64 = 0x0000_7FFF_5000_0000;
        let peb_off = EPROCESS_PEB as usize;
        eproc_page[peb_off..peb_off + 8].copy_from_slice(&peb_val.to_le_bytes());
        // DirectoryTableBase (cr3) at offset 0x28 within eproc (= Pcb + DTB)
        let dtb_off = EPROCESS_DTB as usize;
        eproc_page[dtb_off..dtb_off + 8].copy_from_slice(&0x1000u64.to_le_bytes());
        // ImageFileName = "inject.exe"
        let img_off = EPROCESS_IMAGE as usize;
        eproc_page[img_off..img_off + 10].copy_from_slice(b"inject.exe");
        eproc_page[img_off + 10] = 0;
        // ThreadListHead: Flink = Blink = &ThreadListHead (empty = no threads)
        let tlh_off = KPROCESS_TLH as usize;
        let tlh_vaddr = eproc_vaddr + KPROCESS_TLH;
        eproc_page[tlh_off..tlh_off + 8].copy_from_slice(&tlh_vaddr.to_le_bytes());
        eproc_page[tlh_off + 8..tlh_off + 16].copy_from_slice(&tlh_vaddr.to_le_bytes());

        let isf = IsfBuilder::windows_kernel_preset()
            .add_symbol("PsActiveProcessHead", head_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_page)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys(eproc_paddr, &eproc_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        // Process with peb_addr != 0 but empty thread list → no results
        let results = walk_direct_syscalls(&reader).unwrap_or_default();
        assert!(
            results.is_empty(),
            "process with empty thread list → no syscall entries"
        );
    }

    /// Walker with a process (peb_addr != 0) and one thread whose Win32StartAddress
    /// is a 64-bit kernel address (> 0xFFFF_FFFF) → classified as direct_syscall.
    /// syscall_addr != 0 so the entry IS pushed. ntdll_range = None (peb not mapped).
    /// Exercises lines 88-121 (thread loop and results push).
    #[test]
    fn walk_direct_syscalls_process_with_thread_direct_syscall() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let head_paddr: u64 = 0x0062_0000;
        let eproc_paddr: u64 = 0x0063_0000;
        let kthread_paddr: u64 = 0x0064_0000;

        let head_vaddr: u64 = 0xFFFF_8000_0062_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0063_0000;
        let kthread_vaddr: u64 = 0xFFFF_8000_0064_0000;

        let eproc_links_vaddr = eproc_vaddr + EPROCESS_LINKS;
        let kthread_tle_vaddr = kthread_vaddr + KTHREAD_TLE;
        let tlh_vaddr = eproc_vaddr + KPROCESS_TLH;

        // Head page: single-process circular list
        let mut head_page = [0u8; 4096];
        head_page[..8].copy_from_slice(&eproc_links_vaddr.to_le_bytes());
        head_page[8..16].copy_from_slice(&eproc_links_vaddr.to_le_bytes());

        // EPROCESS page
        let mut eproc_page = [0u8; 4096];
        let off = EPROCESS_LINKS as usize;
        eproc_page[off..off + 8].copy_from_slice(&head_vaddr.to_le_bytes()); // Flink→head
        eproc_page[off + 8..off + 16].copy_from_slice(&head_vaddr.to_le_bytes()); // Blink→head
        eproc_page[EPROCESS_PID as usize..EPROCESS_PID as usize + 8]
            .copy_from_slice(&1001u64.to_le_bytes());
        eproc_page[EPROCESS_PPID as usize..EPROCESS_PPID as usize + 8]
            .copy_from_slice(&500u64.to_le_bytes());
        // Peb = non-zero but unmapped
        let peb_val: u64 = 0x0000_7FFF_6000_0000;
        eproc_page[EPROCESS_PEB as usize..EPROCESS_PEB as usize + 8]
            .copy_from_slice(&peb_val.to_le_bytes());
        eproc_page[EPROCESS_DTB as usize..EPROCESS_DTB as usize + 8]
            .copy_from_slice(&0x1000u64.to_le_bytes());
        eproc_page[EPROCESS_IMAGE as usize..EPROCESS_IMAGE as usize + 10]
            .copy_from_slice(b"malware.ex");
        eproc_page[EPROCESS_IMAGE as usize + 10] = b'e';
        eproc_page[EPROCESS_IMAGE as usize + 11] = 0;
        // ThreadListHead: Flink → kthread.ThreadListEntry, Blink → same
        let tlh_off = KPROCESS_TLH as usize;
        eproc_page[tlh_off..tlh_off + 8].copy_from_slice(&kthread_tle_vaddr.to_le_bytes());
        eproc_page[tlh_off + 8..tlh_off + 16].copy_from_slice(&kthread_tle_vaddr.to_le_bytes());

        // KTHREAD page: one thread
        let mut kthread_page = [0u8; 4096];
        // ThreadListEntry.Flink → tlh_vaddr (back to head)
        let tle_off = KTHREAD_TLE as usize;
        kthread_page[tle_off..tle_off + 8].copy_from_slice(&tlh_vaddr.to_le_bytes());
        kthread_page[tle_off + 8..tle_off + 16].copy_from_slice(&tlh_vaddr.to_le_bytes());
        // Cid.UniqueThread at 0x620 + 8 = 0x628
        kthread_page[0x628..0x630].copy_from_slice(&12u64.to_le_bytes()); // tid=12
        kthread_page[0x620..0x628].copy_from_slice(&1001u64.to_le_bytes()); // pid=1001
                                                                            // Win32StartAddress: the ISF preset defines _KTHREAD.Win32StartAddress @ 0x680.
                                                                            // read_thread_syscall_info uses field_offset() which resolves to 0x680 from the preset.
                                                                            // Use a 64-bit kernel address → direct_syscall technique
        let win32_start: u64 = 0xFFFF_8080_DEAD_1234; // > 0xFFFF_FFFF → direct_syscall
        kthread_page[0x680..0x688].copy_from_slice(&win32_start.to_le_bytes());
        // SystemCallNumber at default offset 0x80
        kthread_page[0x80..0x84].copy_from_slice(&0x3Cu32.to_le_bytes()); // syscall #60

        let isf = IsfBuilder::windows_kernel_preset()
            .add_symbol("PsActiveProcessHead", head_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_page)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys(eproc_paddr, &eproc_page)
            .map_4k(kthread_vaddr, kthread_paddr, flags::WRITABLE)
            .write_phys(kthread_paddr, &kthread_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_direct_syscalls(&reader).unwrap_or_default();
        // Process with peb_addr!=0 + one thread with non-zero Win32StartAddress
        // → one DirectSyscallInfo pushed.
        assert_eq!(
            results.len(),
            1,
            "one thread with non-zero syscall_addr → one result"
        );
        let r = &results[0];
        assert_eq!(r.pid, 1001);
        assert_eq!(r.thread_id, 12);
        assert_eq!(r.syscall_number, 0x3C);
        assert_eq!(r.technique, "direct_syscall");
        // ntdll_range = None (peb not mapped) → in_ntdll = false → is_suspicious = true
        assert!(!r.in_ntdll);
        assert!(r.is_suspicious);
    }

    /// Walker where the process PEB is 0: exercises the `if proc.peb_addr == 0 { continue }`
    /// guard (line 70-71) by verifying no entries are produced for a kernel process.
    #[test]
    fn walk_direct_syscalls_process_zero_peb_skipped() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let head_paddr: u64 = 0x0065_0000;
        let eproc_paddr: u64 = 0x0066_0000;
        let head_vaddr: u64 = 0xFFFF_8000_0065_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0066_0000;
        let eproc_links_vaddr = eproc_vaddr + EPROCESS_LINKS;

        let mut head_page = [0u8; 4096];
        head_page[..8].copy_from_slice(&eproc_links_vaddr.to_le_bytes());
        head_page[8..16].copy_from_slice(&eproc_links_vaddr.to_le_bytes());

        let mut eproc_page = [0u8; 4096];
        let off = EPROCESS_LINKS as usize;
        eproc_page[off..off + 8].copy_from_slice(&head_vaddr.to_le_bytes());
        eproc_page[off + 8..off + 16].copy_from_slice(&head_vaddr.to_le_bytes());
        eproc_page[EPROCESS_PID as usize..EPROCESS_PID as usize + 8]
            .copy_from_slice(&4u64.to_le_bytes()); // System pid=4
                                                   // Peb = 0 → kernel process → skip
                                                   // (zero-initialized by default)
        eproc_page[EPROCESS_DTB as usize..EPROCESS_DTB as usize + 8]
            .copy_from_slice(&0x2000u64.to_le_bytes());
        eproc_page[EPROCESS_IMAGE as usize..EPROCESS_IMAGE as usize + 6].copy_from_slice(b"System");
        eproc_page[EPROCESS_IMAGE as usize + 6] = 0;
        // ThreadListHead self-referential (empty)
        let tlh_off = KPROCESS_TLH as usize;
        let tlh_vaddr = eproc_vaddr + KPROCESS_TLH;
        eproc_page[tlh_off..tlh_off + 8].copy_from_slice(&tlh_vaddr.to_le_bytes());
        eproc_page[tlh_off + 8..tlh_off + 16].copy_from_slice(&tlh_vaddr.to_le_bytes());

        let isf = IsfBuilder::windows_kernel_preset()
            .add_symbol("PsActiveProcessHead", head_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_page)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys(eproc_paddr, &eproc_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        // peb_addr == 0 → skipped → empty
        let results = walk_direct_syscalls(&reader).unwrap_or_default();
        assert!(
            results.is_empty(),
            "kernel process (peb=0) should be skipped"
        );
    }

    /// find_ntdll_range: module list has one entry that is NOT ntdll.dll → returns None.
    /// Exercises the module name comparison loop (L174-199) — non-matching name path.
    #[test]
    fn find_ntdll_range_non_ntdll_module_returns_none() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Build a minimal LDR module list with one entry that is NOT ntdll.dll.
        // Layout:
        //   peb at peb_vaddr: Ldr at offset 0x18
        //   ldr at ldr_vaddr: InLoadOrderModuleList.Flink at offset 0x10
        //   module at mod_vaddr: InLoadOrderLinks.Flink → ldr (sentinel), BaseDllName UNICODE_STRING,
        //     DllBase=0, SizeOfImage=0

        // The ISF preset gives us _PEB.Ldr @ 0x18, _PEB_LDR_DATA.InLoadOrderModuleList @ 0x10,
        // _LDR_DATA_TABLE_ENTRY.BaseDllName @ 0x58, DllBase @ 0x30, SizeOfImage @ 0x40.
        // _UNICODE_STRING: Length @ 0, MaximumLength @ 2, Buffer @ 8.

        let peb_paddr: u64 = 0x0067_0000;
        let ldr_paddr: u64 = 0x0068_0000;
        let mod_paddr: u64 = 0x0069_0000;
        let name_paddr: u64 = 0x006A_0000;

        let peb_vaddr: u64 = 0x0000_7FFF_7000_0000;
        let ldr_vaddr: u64 = 0x0000_7FFF_8000_0000;
        let mod_vaddr: u64 = 0x0000_7FFF_9000_0000;
        let name_vaddr: u64 = 0x0000_7FFF_A000_0000;

        // InLoadOrderModuleList sentinel is at ldr_vaddr + 0x10.
        let list_head_vaddr = ldr_vaddr + 0x10;
        // Module's InLoadOrderLinks is at mod_vaddr + 0 (entry starts at module base).
        let mod_links_vaddr = mod_vaddr;

        // PEB: Ldr pointer at offset 0x18
        let mut peb_page = vec![0u8; 4096];
        peb_page[0x18..0x20].copy_from_slice(&ldr_vaddr.to_le_bytes());

        // LDR: InLoadOrderModuleList.Flink at offset 0x10 → mod_links_vaddr
        //      InLoadOrderModuleList.Blink at offset 0x18 → mod_links_vaddr
        let mut ldr_page = vec![0u8; 4096];
        ldr_page[0x10..0x18].copy_from_slice(&mod_links_vaddr.to_le_bytes());
        ldr_page[0x18..0x20].copy_from_slice(&mod_links_vaddr.to_le_bytes());

        // Module entry: InLoadOrderLinks.Flink → list_head (back to sentinel)
        let mut mod_page = vec![0u8; 4096];
        mod_page[0x00..0x08].copy_from_slice(&list_head_vaddr.to_le_bytes()); // Flink→sentinel
        mod_page[0x08..0x10].copy_from_slice(&list_head_vaddr.to_le_bytes()); // Blink→sentinel
                                                                              // BaseDllName UNICODE_STRING at offset 0x58: Length, MaximumLength, Buffer
        let dll_name = "kernel32.dll";
        let name_bytes: Vec<u16> = dll_name.encode_utf16().collect();
        let name_byte_len = (name_bytes.len() * 2) as u16;
        mod_page[0x58..0x5A].copy_from_slice(&name_byte_len.to_le_bytes()); // Length
        mod_page[0x5A..0x5C].copy_from_slice(&name_byte_len.to_le_bytes()); // MaximumLength
        mod_page[0x60..0x68].copy_from_slice(&name_vaddr.to_le_bytes()); // Buffer ptr
                                                                         // DllBase at 0x30 = 0, SizeOfImage at 0x40 = 0 (already zero)

        // Name page: UTF-16LE "kernel32.dll"
        let mut name_page = vec![0u8; 4096];
        for (i, &ch) in name_bytes.iter().enumerate() {
            name_page[i * 2..i * 2 + 2].copy_from_slice(&ch.to_le_bytes());
        }

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(peb_vaddr, peb_paddr, flags::WRITABLE)
            .write_phys(peb_paddr, &peb_page)
            .map_4k(ldr_vaddr, ldr_paddr, flags::WRITABLE)
            .write_phys(ldr_paddr, &ldr_page)
            .map_4k(mod_vaddr, mod_paddr, flags::WRITABLE)
            .write_phys(mod_paddr, &mod_page)
            .map_4k(name_vaddr, name_paddr, flags::WRITABLE)
            .write_phys(name_paddr, &name_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<memf_core::test_builders::SyntheticPhysMem> =
            ObjectReader::new(vas, Box::new(resolver));

        let proc = crate::WinProcessInfo {
            vaddr: 0,
            pid: 300,
            ppid: 0,
            image_name: "test.exe".to_string(),
            peb_addr: peb_vaddr,
            cr3,
            create_time: 0,
            exit_time: 0,
            thread_count: 0,
            is_wow64: false,
        };

        // Module list has "kernel32.dll" — not ntdll.dll → returns None
        let result = find_ntdll_range(&reader, &proc);
        assert!(
            result.is_none(),
            "non-ntdll module → find_ntdll_range returns None"
        );
    }
}
