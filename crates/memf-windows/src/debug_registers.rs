//! Hardware debug register analysis for anti-debug and rootkit detection.
//!
//! Checks hardware debug registers (DR0-DR3, DR6, DR7) for each thread
//! by reading `_KTHREAD.TrapFrame` -> `_KTRAP_FRAME` debug register fields.
//!
//! Anti-debug malware uses debug registers for hardware breakpoints to detect
//! debuggers, and rootkits use them for stealthy hooking via hardware
//! breakpoint-based execution redirection.
//!
//! MITRE ATT&CK: T1622 (Debugger Evasion)

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{process, thread};

/// Maximum number of results to collect (safety limit).
const MAX_RESULTS: usize = 4096;

// Default offsets for Windows 10/11 x64 when symbols are unavailable.
// _KTHREAD.TrapFrame offset (pointer to _KTRAP_FRAME).
const DEFAULT_KTHREAD_TRAP_FRAME: u64 = 0x90;

// _KTRAP_FRAME debug register offsets (Windows 10/11 x64).
const DEFAULT_KTRAP_FRAME_DR0: u64 = 0x00;
const DEFAULT_KTRAP_FRAME_DR1: u64 = 0x08;
const DEFAULT_KTRAP_FRAME_DR2: u64 = 0x10;
const DEFAULT_KTRAP_FRAME_DR3: u64 = 0x18;
const DEFAULT_KTRAP_FRAME_DR6: u64 = 0x20;
const DEFAULT_KTRAP_FRAME_DR7: u64 = 0x28;

/// Information about debug register state for a single thread.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DebugRegisterInfo {
    /// Process ID owning this thread.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Name of the owning process.
    pub process_name: String,
    /// Debug register 0 — linear address of breakpoint 0.
    pub dr0: u64,
    /// Debug register 1 — linear address of breakpoint 1.
    pub dr1: u64,
    /// Debug register 2 — linear address of breakpoint 2.
    pub dr2: u64,
    /// Debug register 3 — linear address of breakpoint 3.
    pub dr3: u64,
    /// Debug register 6 — debug status (which breakpoint triggered).
    pub dr6: u64,
    /// Debug register 7 — debug control (enable bits and conditions).
    pub dr7: u64,
    /// Whether this thread's debug register state is suspicious.
    pub is_suspicious: bool,
}

/// Classify whether a thread's debug register state is suspicious.
///
/// A thread is suspicious if any of DR0-DR3 contains a non-zero address
/// (indicating a hardware breakpoint is set) **and** DR7 has corresponding
/// local enable bits set (bits 0, 2, 4, 6 for DR0-DR3 respectively).
///
/// This combination means a hardware breakpoint is both configured with an
/// address and actively enabled — a strong indicator of anti-debug techniques
/// or rootkit hooking.
pub fn classify_debug_registers(dr0: u64, dr1: u64, dr2: u64, dr3: u64, dr7: u64) -> bool {
    // DR7 local enable bits:
    //   Bit 0 (L0): local enable for DR0
    //   Bit 2 (L1): local enable for DR1
    //   Bit 4 (L2): local enable for DR2
    //   Bit 6 (L3): local enable for DR3
    let has_bp = [
        (dr0, 0x01_u64), // DR0 + L0
        (dr1, 0x04_u64), // DR1 + L1
        (dr2, 0x10_u64), // DR2 + L2
        (dr3, 0x40_u64), // DR3 + L3
    ];

    has_bp
        .iter()
        .any(|&(dr, enable_bit)| dr != 0 && (dr7 & enable_bit) != 0)
}

/// Read a u64 value from memory, returning 0 on failure.
fn read_u64<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, addr: u64) -> u64 {
    reader
        .read_bytes(addr, 8)
        .ok()
        .and_then(|b| b[..8].try_into().ok().map(u64::from_le_bytes))
        .unwrap_or(0)
}

/// Read the debug registers from a thread's trap frame.
///
/// Returns `None` if the trap frame pointer is null or unreadable.
fn read_thread_debug_regs<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    kthread_addr: u64,
) -> Option<(u64, u64, u64, u64, u64, u64)> {
    // Resolve _KTHREAD.TrapFrame offset (pointer to _KTRAP_FRAME).
    let trap_frame_off = reader
        .symbols()
        .field_offset("_KTHREAD", "TrapFrame")
        .unwrap_or(DEFAULT_KTHREAD_TRAP_FRAME);

    let trap_frame_ptr = read_u64(reader, kthread_addr.wrapping_add(trap_frame_off));
    if trap_frame_ptr == 0 {
        return None;
    }

    // Resolve _KTRAP_FRAME debug register offsets, falling back to defaults.
    let dr0_off = reader
        .symbols()
        .field_offset("_KTRAP_FRAME", "Dr0")
        .unwrap_or(DEFAULT_KTRAP_FRAME_DR0);
    let dr1_off = reader
        .symbols()
        .field_offset("_KTRAP_FRAME", "Dr1")
        .unwrap_or(DEFAULT_KTRAP_FRAME_DR1);
    let dr2_off = reader
        .symbols()
        .field_offset("_KTRAP_FRAME", "Dr2")
        .unwrap_or(DEFAULT_KTRAP_FRAME_DR2);
    let dr3_off = reader
        .symbols()
        .field_offset("_KTRAP_FRAME", "Dr3")
        .unwrap_or(DEFAULT_KTRAP_FRAME_DR3);
    let dr6_off = reader
        .symbols()
        .field_offset("_KTRAP_FRAME", "Dr6")
        .unwrap_or(DEFAULT_KTRAP_FRAME_DR6);
    let dr7_off = reader
        .symbols()
        .field_offset("_KTRAP_FRAME", "Dr7")
        .unwrap_or(DEFAULT_KTRAP_FRAME_DR7);

    let dr0 = read_u64(reader, trap_frame_ptr.wrapping_add(dr0_off));
    let dr1 = read_u64(reader, trap_frame_ptr.wrapping_add(dr1_off));
    let dr2 = read_u64(reader, trap_frame_ptr.wrapping_add(dr2_off));
    let dr3 = read_u64(reader, trap_frame_ptr.wrapping_add(dr3_off));
    let dr6 = read_u64(reader, trap_frame_ptr.wrapping_add(dr6_off));
    let dr7 = read_u64(reader, trap_frame_ptr.wrapping_add(dr7_off));

    Some((dr0, dr1, dr2, dr3, dr6, dr7))
}

/// Walk all processes and threads to extract debug register state.
///
/// For each thread, reads `_KTHREAD.TrapFrame` to locate the `_KTRAP_FRAME`,
/// then reads the DR0-DR3, DR6, and DR7 fields to detect active hardware
/// breakpoints.
///
/// Returns `Ok(Vec::new())` if the process list cannot be walked (graceful
/// degradation).
pub fn walk_debug_registers<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    process_list_head: u64,
) -> crate::Result<Vec<DebugRegisterInfo>> {
    // Graceful degradation: if we cannot walk the process list (missing
    // symbols for _EPROCESS.ActiveProcessLinks, etc.), return empty.
    let procs = match process::walk_processes(reader, process_list_head) {
        Ok(p) => p,
        Err(_) => return Ok(Vec::new()),
    };

    let mut results = Vec::new();

    for proc in &procs {
        let pid = proc.pid as u32;
        let process_name = proc.image_name.clone();

        // Walk threads for this process; skip on failure.
        let threads = match thread::walk_threads(reader, proc.vaddr, proc.pid) {
            Ok(t) => t,
            Err(_) => continue,
        };

        for thr in &threads {
            let (dr0, dr1, dr2, dr3, dr6, dr7) = match read_thread_debug_regs(reader, thr.vaddr) {
                Some(regs) => regs,
                None => continue,
            };

            // Skip threads where all debug registers are zero (the common case).
            if dr0 == 0 && dr1 == 0 && dr2 == 0 && dr3 == 0 && dr6 == 0 && dr7 == 0 {
                continue;
            }

            let is_suspicious = classify_debug_registers(dr0, dr1, dr2, dr3, dr7);

            results.push(DebugRegisterInfo {
                pid,
                tid: thr.tid as u32,
                process_name: process_name.clone(),
                dr0,
                dr1,
                dr2,
                dr3,
                dr6,
                dr7,
                is_suspicious,
            });

            if results.len() >= MAX_RESULTS {
                return Ok(results);
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Classifier unit tests -----------------------------------------------

    #[test]
    fn classify_no_breakpoints_benign() {
        // All debug registers zeroed out — no breakpoints, benign.
        assert!(!classify_debug_registers(0, 0, 0, 0, 0));
    }

    #[test]
    fn classify_breakpoint_set_suspicious() {
        // DR0 has an address and DR7 has L0 (bit 0) enabled.
        assert!(classify_debug_registers(0x7FFE_0000_1000, 0, 0, 0, 0x01));
    }

    #[test]
    fn classify_dr_set_but_disabled_benign() {
        // DR0 has an address but DR7 has no local enable bits set.
        // The breakpoint address is configured but not armed — benign.
        assert!(!classify_debug_registers(0x7FFE_0000_1000, 0, 0, 0, 0));
    }

    #[test]
    fn classify_dr7_enabled_but_no_address_benign() {
        // DR7 has L0 enabled but DR0 is zero — no actual breakpoint target.
        assert!(!classify_debug_registers(0, 0, 0, 0, 0x01));
    }

    #[test]
    fn classify_multiple_breakpoints_suspicious() {
        // DR1 and DR3 have addresses, DR7 enables L1 (bit 2) and L3 (bit 6).
        assert!(classify_debug_registers(
            0,
            0xFFFFF800_01234567,
            0,
            0xFFFFF800_DEADBEEF,
            0x44 // bits 2 and 6
        ));
    }

    #[test]
    fn classify_dr2_enabled_suspicious() {
        // Only DR2 is set with L2 (bit 4) enabled.
        assert!(classify_debug_registers(0, 0, 0xDEAD_BEEF, 0, 0x10));
    }

    #[test]
    fn classify_wrong_enable_bit_benign() {
        // DR0 has an address but DR7 enables L1 (bit 2) instead of L0 (bit 0).
        // The breakpoint on DR0 is not armed.
        assert!(!classify_debug_registers(0x1000, 0, 0, 0, 0x04));
    }

    #[test]
    fn classify_all_breakpoints_armed_suspicious() {
        // All four DRs have addresses, DR7 enables all four local bits.
        assert!(classify_debug_registers(
            0x1000, 0x2000, 0x3000, 0x4000, 0x55 // bits 0, 2, 4, 6
        ));
    }

    #[test]
    fn classify_dr3_enabled_suspicious() {
        // Only DR3 is set with L3 (bit 6) enabled.
        assert!(classify_debug_registers(0, 0, 0, 0xCAFE_BABE, 0x40));
    }

    #[test]
    fn classify_dr1_enabled_suspicious() {
        // Only DR1 is set with L1 (bit 2) enabled.
        assert!(classify_debug_registers(0, 0xBEEF, 0, 0, 0x04));
    }

    #[test]
    fn classify_dr7_all_global_bits_no_address_benign() {
        // DR7 has global enable bits set (bits 1, 3, 5, 7) but no addresses.
        // Global bits do NOT affect our local-enable check.
        assert!(!classify_debug_registers(0, 0, 0, 0, 0xAA));
    }

    #[test]
    fn classify_max_address_with_enable_bit() {
        // DR0 at u64::MAX with L0 enabled — still suspicious.
        assert!(classify_debug_registers(u64::MAX, 0, 0, 0, 0x01));
    }

    #[test]
    fn debug_register_info_serializes() {
        let info = DebugRegisterInfo {
            pid: 1234,
            tid: 5678,
            process_name: "malware.exe".to_string(),
            dr0: 0xDEAD_BEEF,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0x01,
            is_suspicious: true,
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":1234"));
        assert!(json.contains("\"tid\":5678"));
        assert!(json.contains("\"process_name\":\"malware.exe\""));
        assert!(json.contains("\"is_suspicious\":true"));
        assert!(json.contains("\"dr7\":1"));
    }

    // -- Walker tests --------------------------------------------------------

    /// Walker with process_list_head pointing to mapped memory whose Flink
    /// loops back to the head immediately — exercises the walk body and
    /// returns empty (no threads with non-zero debug registers).
    #[test]
    fn walk_debug_registers_empty_process_list() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Minimal Windows kernel ISF so walk_processes can parse _EPROCESS.
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Map a page for the list head, writing Flink = Blink = list_head_vaddr
        // (an empty circular doubly-linked list).
        let list_vaddr: u64 = 0xFFFF_8000_0050_0000;
        let list_paddr: u64 = 0x0050_0000;

        let mut page = [0u8; 4096];
        // _LIST_ENTRY: Flink at 0, Blink at 8.  Both point back to list_vaddr.
        page[0..8].copy_from_slice(&list_vaddr.to_le_bytes());
        page[8..16].copy_from_slice(&list_vaddr.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(list_vaddr, list_paddr, flags::WRITABLE)
            .write_phys(list_paddr, &page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        // walk_processes will walk the empty list and return 0 processes → empty debug info.
        let results = walk_debug_registers(&reader, list_vaddr).unwrap_or_default();
        assert!(results.is_empty(), "empty process list should yield no debug register entries");
    }

    #[test]
    fn walk_no_symbol_returns_empty() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Build a bare ISF with NO _EPROCESS or related struct symbols.
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Minimal page table — just needs to be valid.
        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &[0u8; 16]);

        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // The walker takes an explicit process_list_head, but with no symbols
        // for _EPROCESS fields it should degrade gracefully and return empty.
        let results = walk_debug_registers(&reader, page_vaddr).unwrap();
        assert!(results.is_empty());
    }

    // -- read_u64 helper tests -----------------------------------------------

    /// read_u64 from a mapped address returns the correct value.
    #[test]
    fn read_u64_from_mapped_memory() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let vaddr: u64 = 0xFFFF_8000_0020_0000;
        let paddr: u64 = 0x0020_0000;
        let value: u64 = 0xDEAD_BEEF_1234_5678;

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &value.to_le_bytes())
            .build();

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        assert_eq!(read_u64(&reader, vaddr), value);
    }

    /// read_u64 from unmapped memory returns 0.
    #[test]
    fn read_u64_from_unmapped_memory_returns_zero() {
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

        assert_eq!(read_u64(&reader, 0xFFFF_DEAD_BEEF_0000), 0);
    }

    // -- read_thread_debug_regs tests ----------------------------------------

    /// read_thread_debug_regs returns None when TrapFrame pointer is null (zero).
    #[test]
    fn read_thread_debug_regs_null_trap_frame() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Map a kthread page where TrapFrame pointer (at DEFAULT_KTHREAD_TRAP_FRAME=0x90) = 0.
        let kthread_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let kthread_paddr: u64 = 0x0030_0000;
        let page = [0u8; 4096]; // all zeros → TrapFrame ptr = 0

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(kthread_vaddr, kthread_paddr, flags::WRITABLE)
            .write_phys(kthread_paddr, &page)
            .build();

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // TrapFrame = 0 → None
        let result = read_thread_debug_regs(&reader, kthread_vaddr);
        assert!(result.is_none(), "null TrapFrame pointer should return None");
    }

    /// read_thread_debug_regs returns None when TrapFrame points to unmapped memory.
    #[test]
    fn read_thread_debug_regs_unmapped_trap_frame() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Map a kthread page where TrapFrame pointer = some unmapped address.
        let kthread_vaddr: u64 = 0xFFFF_8000_0031_0000;
        let kthread_paddr: u64 = 0x0031_0000;
        let trap_ptr: u64 = 0xFFFF_8000_DEAD_0000; // unmapped

        let mut page = [0u8; 4096];
        page[DEFAULT_KTHREAD_TRAP_FRAME as usize
            ..DEFAULT_KTHREAD_TRAP_FRAME as usize + 8]
            .copy_from_slice(&trap_ptr.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(kthread_vaddr, kthread_paddr, flags::WRITABLE)
            .write_phys(kthread_paddr, &page)
            .build();

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // TrapFrame != 0 but its memory is unmapped → read_u64 returns 0 for all regs.
        // The function returns Some((0,0,0,0,0,0)) rather than None because the
        // TrapFrame pointer itself is non-zero and read_u64 falls back to 0.
        let result = read_thread_debug_regs(&reader, kthread_vaddr);
        assert!(
            result.is_some(),
            "non-null TrapFrame should return Some (with zeroed regs)"
        );
        let (dr0, dr1, dr2, dr3, dr6, dr7) = result.unwrap();
        assert_eq!((dr0, dr1, dr2, dr3, dr6, dr7), (0, 0, 0, 0, 0, 0));
    }

    /// read_thread_debug_regs with a valid TrapFrame page returns mapped register values.
    #[test]
    fn read_thread_debug_regs_with_valid_trap_frame() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let kthread_vaddr: u64 = 0xFFFF_8000_0032_0000;
        let kthread_paddr: u64 = 0x0032_0000;
        let trap_vaddr: u64 = 0xFFFF_8000_0033_0000;
        let trap_paddr: u64 = 0x0033_0000;

        // Write TrapFrame pointer into kthread at DEFAULT_KTHREAD_TRAP_FRAME.
        let mut kthread_page = [0u8; 4096];
        kthread_page[DEFAULT_KTHREAD_TRAP_FRAME as usize
            ..DEFAULT_KTHREAD_TRAP_FRAME as usize + 8]
            .copy_from_slice(&trap_vaddr.to_le_bytes());

        // Write known DR values into the trap frame page at default offsets.
        let dr0_val: u64 = 0x1111_0000_1111_0000;
        let dr1_val: u64 = 0x2222_0000_2222_0000;
        let dr2_val: u64 = 0x3333_0000_3333_0000;
        let dr3_val: u64 = 0x4444_0000_4444_0000;
        let dr6_val: u64 = 0x5555_0000_5555_0000;
        let dr7_val: u64 = 0x0000_0000_0000_0055; // L0+L1+L2+L3 local bits

        let mut trap_page = [0u8; 4096];
        trap_page[DEFAULT_KTRAP_FRAME_DR0 as usize..DEFAULT_KTRAP_FRAME_DR0 as usize + 8]
            .copy_from_slice(&dr0_val.to_le_bytes());
        trap_page[DEFAULT_KTRAP_FRAME_DR1 as usize..DEFAULT_KTRAP_FRAME_DR1 as usize + 8]
            .copy_from_slice(&dr1_val.to_le_bytes());
        trap_page[DEFAULT_KTRAP_FRAME_DR2 as usize..DEFAULT_KTRAP_FRAME_DR2 as usize + 8]
            .copy_from_slice(&dr2_val.to_le_bytes());
        trap_page[DEFAULT_KTRAP_FRAME_DR3 as usize..DEFAULT_KTRAP_FRAME_DR3 as usize + 8]
            .copy_from_slice(&dr3_val.to_le_bytes());
        trap_page[DEFAULT_KTRAP_FRAME_DR6 as usize..DEFAULT_KTRAP_FRAME_DR6 as usize + 8]
            .copy_from_slice(&dr6_val.to_le_bytes());
        trap_page[DEFAULT_KTRAP_FRAME_DR7 as usize..DEFAULT_KTRAP_FRAME_DR7 as usize + 8]
            .copy_from_slice(&dr7_val.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(kthread_vaddr, kthread_paddr, flags::WRITABLE)
            .write_phys(kthread_paddr, &kthread_page)
            .map_4k(trap_vaddr, trap_paddr, flags::WRITABLE)
            .write_phys(trap_paddr, &trap_page)
            .build();

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = read_thread_debug_regs(&reader, kthread_vaddr);
        assert!(result.is_some(), "should return Some with valid TrapFrame");
        let (dr0, dr1, dr2, dr3, dr6, dr7) = result.unwrap();
        assert_eq!(dr0, dr0_val);
        assert_eq!(dr1, dr1_val);
        assert_eq!(dr2, dr2_val);
        assert_eq!(dr3, dr3_val);
        assert_eq!(dr6, dr6_val);
        assert_eq!(dr7, dr7_val);

        // With all DRs non-zero and DR7 local enable bits set, classify as suspicious.
        assert!(classify_debug_registers(dr0, dr1, dr2, dr3, dr7));
    }

    /// walk_debug_registers with unreadable process list head returns empty (graceful degradation).
    #[test]
    fn walk_debug_registers_unreadable_head_returns_empty() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let (cr3, mem) = PageTableBuilder::new().build();
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // walk_processes with unmapped head fails → Ok(Vec::new())
        let results = walk_debug_registers(&reader, 0xFFFF_8000_DEAD_C0FF).unwrap_or_default();
        assert!(results.is_empty());
    }
}
