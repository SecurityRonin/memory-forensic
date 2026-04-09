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

/// Walk all processes and threads to extract debug register state.
///
/// For each thread, reads `_KTHREAD.TrapFrame` to locate the `_KTRAP_FRAME`,
/// then reads the DR0-DR3, DR6, and DR7 fields to detect active hardware
/// breakpoints.
///
/// Returns `Ok(Vec::new())` if the `PsActiveProcessHead` symbol is missing
/// (graceful degradation).
pub fn walk_debug_registers<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    process_list_head: u64,
) -> crate::Result<Vec<DebugRegisterInfo>> {
    let _ = (reader, process_list_head);
    todo!()
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
            0x1000,
            0x2000,
            0x3000,
            0x4000,
            0x55 // bits 0, 2, 4, 6
        ));
    }

    // -- Walker tests --------------------------------------------------------

    #[test]
    fn walk_no_symbol_returns_empty() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Build a bare ISF with NO PsActiveProcessHead symbol.
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
        // for _EPROCESS fields it should degrade gracefully. Since the walk
        // function is still todo!(), this test will fail in RED phase.
        let results = walk_debug_registers(&reader, page_vaddr).unwrap();
        assert!(results.is_empty());
    }
}
