//! CPU affinity / cryptominer detection via scheduling policy and CPU pinning.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::types::CpuPinningInfo;
use crate::Result;

/// Scan for processes with suspicious CPU pinning (potential cryptominers).
///
/// Returns `Ok(vec![])` as a stub until full implementation is added.
pub fn scan_cpu_pinning<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<CpuPinningInfo>> {
    let _ = reader;
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let result = scan_cpu_pinning(&reader);
        assert!(result.is_ok(), "should succeed with minimal reader");
        assert!(result.unwrap().is_empty(), "empty memory → no CPU pinning hits");
    }

    #[test]
    fn result_is_vec_of_cpu_pinning_info() {
        let reader = make_minimal_reader();
        let result: Result<Vec<CpuPinningInfo>> = scan_cpu_pinning(&reader);
        assert!(result.is_ok());
    }

    #[test]
    fn cpu_pinning_info_fields_constructible() {
        let info = CpuPinningInfo {
            pid: 9999,
            comm: "xmrig".to_string(),
            pinned_cpu_count: 1,
            total_cpu_count: 8,
            sched_policy: 0,
            cpu_time_ns: 100_000_000_000,
        };
        assert_eq!(info.pid, 9999);
        assert_eq!(info.pinned_cpu_count, 1);
        assert_eq!(info.total_cpu_count, 8);
    }

    #[test]
    fn cpu_pinning_info_serializes() {
        let info = CpuPinningInfo {
            pid: 77,
            comm: "miner".to_string(),
            pinned_cpu_count: 2,
            total_cpu_count: 4,
            sched_policy: 3,
            cpu_time_ns: 500_000,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":77"));
        assert!(json.contains("miner"));
        assert!(json.contains("\"pinned_cpu_count\":2"));
    }

    // --- classifier helper tests (genuine RED: function does not exist yet) ---

    #[test]
    fn differing_cpu_mask_is_suspicious_pinning() {
        // Actual mask restricts to CPU 0 only (0x1), but expected is all 8 CPUs (0xFF)
        assert!(is_suspicious_pinning(0x1, 0xFF));
    }

    #[test]
    fn matching_cpu_mask_is_not_suspicious() {
        assert!(!is_suspicious_pinning(0xFF, 0xFF));
    }
}
