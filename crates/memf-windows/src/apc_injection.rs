//! APC queue forensics walker — MITRE ATT&CK T1055.004.
//!
//! Scans `KTHREAD->ApcState.ApcListHead` for each thread and extracts
//! queued `_KAPC` entries, reporting unbacked or kernel-mode APCs.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{types::ApcInfo, Result};

/// Scan all thread APC queues in the memory image for queued APCs.
///
/// For each `_KTHREAD` found, walks the `ApcState.ApcListHead[0]` (kernel)
/// and `ApcState.ApcListHead[1]` (user) lists and extracts each `_KAPC`.
/// Reports APCs whose `NormalRoutine` does not fall within any loaded
/// module's virtual address range as unbacked (potentially malicious).
///
/// # MITRE ATT&CK
/// T1055.004 — Asynchronous Procedure Call
pub fn scan_apc_queues<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<ApcInfo>> {
    // Walk KTHREAD->ApcState.ApcListHead for each thread.
    // Extract KAPC->NormalRoutine, KernelRoutine function pointers.
    // Check if pointers fall within any loaded module's address range.
    let _ = reader;
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ApcType;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_minimal_reader(
    ) -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn empty_memory_returns_ok_empty() {
        let reader = make_minimal_reader();
        let result = scan_apc_queues(&reader);
        assert!(result.is_ok(), "should succeed with minimal reader");
        assert!(result.unwrap().is_empty(), "empty memory → no APC entries");
    }

    #[test]
    fn result_is_vec_of_apc_info() {
        let reader = make_minimal_reader();
        let result: Result<Vec<ApcInfo>> = scan_apc_queues(&reader);
        assert!(result.is_ok());
    }

    #[test]
    fn apc_info_fields_constructible() {
        let info = ApcInfo {
            pid: 888,
            tid: 1000,
            image_name: "svchost.exe".to_string(),
            apc_type: ApcType::UserMode,
            normal_routine: 0xDEAD_BEEF,
            kernel_routine: 0xC0DE_C0DE,
            is_unbacked: true,
        };
        assert_eq!(info.pid, 888);
        assert_eq!(info.tid, 1000);
        assert_eq!(info.apc_type, ApcType::UserMode);
        assert!(info.is_unbacked);
    }

    #[test]
    fn apc_info_serializes() {
        let info = ApcInfo {
            pid: 4,
            tid: 8,
            image_name: "evil.exe".to_string(),
            apc_type: ApcType::KernelMode,
            normal_routine: 0,
            kernel_routine: 0xFFFF_8000_0000,
            is_unbacked: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":4"));
        assert!(json.contains("evil.exe"));
        assert!(json.contains("KernelMode"));
        assert!(json.contains("\"is_unbacked\":false"));
    }

    #[test]
    fn apc_type_variants_accessible() {
        assert_ne!(ApcType::KernelMode, ApcType::UserMode);
    }

    // --- classifier helper tests (genuine RED: function does not exist yet) ---

    #[test]
    fn normal_routine_outside_all_ranges_is_unbacked_apc() {
        let ranges = [(0x7fff_0000_u64, 0x7fff_1000_u64)];
        // 0xDEAD_BEEF is outside the range → unbacked
        assert!(is_unbacked_apc(0xDEAD_BEEF, &ranges));
    }

    #[test]
    fn normal_routine_inside_a_range_is_backed_apc() {
        let ranges = [(0x7fff_0000_u64, 0x7fff_1000_u64)];
        // 0x7fff_0500 falls within the range
        assert!(!is_unbacked_apc(0x7fff_0500, &ranges));
    }

    #[test]
    fn normal_routine_with_empty_ranges_is_unbacked_apc() {
        assert!(is_unbacked_apc(0x1234, &[]));
    }
}
