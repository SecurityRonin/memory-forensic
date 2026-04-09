//! Windows kernel named pipe enumeration for C2/lateral-movement detection.
//!
//! Walks the kernel Object Manager namespace tree starting from
//! `ObpRootDirectoryObject`, navigates to `\Device\NamedPipe`, and
//! enumerates all pipe objects within that directory.  Each pipe name
//! is checked against known-suspicious patterns (Cobalt Strike beacon
//! pipes, PsExec service pipes, Meterpreter post-exploitation pipes,
//! GUID-like random pipe names, etc.).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::object_directory::{read_object_name, walk_directory};
use crate::Result;

/// Maximum recursion depth when walking nested object directories.
const MAX_DIR_DEPTH: usize = 8;

/// Information about a single named pipe found in kernel memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NamedPipeInfo {
    /// The name of the pipe.
    pub name: String,
    /// Whether this pipe name matches a known-suspicious pattern.
    pub is_suspicious: bool,
    /// Human-readable reason for flagging, if suspicious.
    pub suspicion_reason: Option<String>,
}

/// Enumerate named pipes from the object directory.
///
/// Resolves `ObpRootDirectoryObject`, walks through `\Device\NamedPipe`,
/// and returns information about each pipe found.  Returns an empty `Vec`
/// if the root directory symbol is missing or the path cannot be resolved.
pub fn walk_named_pipes<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<NamedPipeInfo>> {
    todo!()
}

/// Check if a pipe name matches known C2/lateral-movement patterns.
///
/// Returns `Some(reason)` if the name is suspicious, `None` otherwise.
pub fn classify_pipe(name: &str) -> Option<String> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ISF preset symbol addresses (same as mutant.rs tests)
    const OBP_ROOT_DIR_OBJ_VADDR: u64 = 0xFFFFF805_5A4A0000;

    fn make_test_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    // ─────────────────────────────────────────────────────────────────────
    // classify_pipe tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn classify_pipe_cobalt_strike() {
        // msagent_* pattern
        let reason = classify_pipe("msagent_dc01").unwrap();
        assert!(
            reason.contains("Cobalt Strike"),
            "expected 'Cobalt Strike' in reason, got: {reason}"
        );

        // MSSE-*-server pattern
        let reason = classify_pipe("MSSE-1234-server").unwrap();
        assert!(
            reason.contains("Cobalt Strike"),
            "expected 'Cobalt Strike' in reason, got: {reason}"
        );

        // postex_ssh_* pattern
        let reason = classify_pipe("postex_ssh_1234").unwrap();
        assert!(
            reason.contains("Cobalt Strike"),
            "expected 'Cobalt Strike' in reason, got: {reason}"
        );
    }

    #[test]
    fn classify_pipe_psexec_variants() {
        // psexec
        let reason = classify_pipe("psexecsvc").unwrap();
        assert!(
            reason.contains("PsExec"),
            "expected 'PsExec' in reason, got: {reason}"
        );

        // remcom
        let reason = classify_pipe("remcomsvc").unwrap();
        assert!(
            reason.contains("PsExec"),
            "expected 'PsExec' in reason, got: {reason}"
        );

        // csexec
        let reason = classify_pipe("csexecsvc").unwrap();
        assert!(
            reason.contains("PsExec"),
            "expected 'PsExec' in reason, got: {reason}"
        );
    }

    #[test]
    fn classify_pipe_meterpreter() {
        let reason = classify_pipe("postex_1234").unwrap();
        assert!(
            reason.contains("Meterpreter"),
            "expected 'Meterpreter' in reason, got: {reason}"
        );
    }

    #[test]
    fn classify_pipe_guid_like() {
        // Standard GUID: 8-4-4-4-12 hex chars
        let reason = classify_pipe("deadbeef-1234-5678-abcd-0123456789ab").unwrap();
        assert!(
            reason.contains("GUID"),
            "expected 'GUID' in reason, got: {reason}"
        );
    }

    #[test]
    fn classify_pipe_benign() {
        // Normal Windows pipes should NOT be flagged
        assert!(classify_pipe("lsass").is_none());
        assert!(classify_pipe("wkssvc").is_none());
        assert!(classify_pipe("srvsvc").is_none());
        assert!(classify_pipe("spoolss").is_none());
        assert!(classify_pipe("ntsvcs").is_none());
    }

    // ─────────────────────────────────────────────────────────────────────
    // walk_named_pipes tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn walk_named_pipes_no_symbol() {
        // Build a reader with NO symbols at all — the ISF preset does
        // include ObpRootDirectoryObject, so we test with a reader whose
        // root directory pointer is zero (null) to simulate "no pipes found".
        let root_dir_ptr_paddr: u64 = 0x0010_0000;
        let ptb = PageTableBuilder::new()
            .map_4k(OBP_ROOT_DIR_OBJ_VADDR, root_dir_ptr_paddr, flags::WRITABLE)
            // Write zero as the root directory address (null pointer)
            .write_phys_u64(root_dir_ptr_paddr, 0);

        let reader = make_test_reader(ptb);
        let pipes = walk_named_pipes(&reader).unwrap();
        assert!(pipes.is_empty(), "expected empty Vec for null root dir");
    }
}
