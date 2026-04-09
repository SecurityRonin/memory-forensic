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

use crate::{DirectSyscallInfo, Result};

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
pub fn walk_direct_syscalls<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
) -> Result<Vec<DirectSyscallInfo>> {
    todo!()
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

        // Build an ISF with standard structs but NO PsActiveProcessHead symbol.
        let isf = IsfBuilder::windows_kernel_preset().build_json();
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
}
