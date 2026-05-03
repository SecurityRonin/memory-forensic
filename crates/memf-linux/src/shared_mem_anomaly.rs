//! Shared memory forensics / anomaly detection.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::types::SharedMemAnomalyInfo;
use crate::Result;

/// Scan for shared memory anomalies (executable memfd, ELF headers, cross-uid sharing).
///
/// Returns `Ok(vec![])` as a stub until full implementation is added.
pub fn scan_shared_mem_anomalies<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<SharedMemAnomalyInfo>> {
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
        let result = scan_shared_mem_anomalies(&reader);
        assert!(result.is_ok(), "should succeed with minimal reader");
        assert!(
            result.unwrap().is_empty(),
            "empty memory → no shared mem anomalies"
        );
    }

    #[test]
    fn result_is_vec_of_shared_mem_anomaly_info() {
        let reader = make_minimal_reader();
        let result: Result<Vec<SharedMemAnomalyInfo>> = scan_shared_mem_anomalies(&reader);
        assert!(result.is_ok());
    }

    #[test]
    fn shared_mem_anomaly_info_fields_constructible() {
        let info = SharedMemAnomalyInfo {
            pid: 500,
            comm: "loader".to_string(),
            shm_base: 0x7f00_0000_0000,
            shm_size: 65536,
            is_memfd: true,
            is_executable: true,
            is_cross_uid: false,
            has_elf_header: true,
        };
        assert_eq!(info.pid, 500);
        assert!(info.is_memfd);
        assert!(info.is_executable);
        assert!(!info.is_cross_uid);
        assert!(info.has_elf_header);
    }

    #[test]
    fn shared_mem_anomaly_info_serializes() {
        let info = SharedMemAnomalyInfo {
            pid: 88,
            comm: "inject".to_string(),
            shm_base: 0x1000,
            shm_size: 4096,
            is_memfd: false,
            is_executable: true,
            is_cross_uid: true,
            has_elf_header: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":88"));
        assert!(json.contains("\"is_executable\":true"));
        assert!(json.contains("\"is_cross_uid\":true"));
    }

    // --- classifier helper tests (genuine RED: function does not exist yet) ---

    #[test]
    fn nattch_above_threshold_is_suspicious_shm() {
        assert!(is_suspicious_shm(100, 50));
    }

    #[test]
    fn nattch_at_threshold_is_not_suspicious() {
        assert!(!is_suspicious_shm(50, 50));
    }

    #[test]
    fn nattch_below_threshold_is_not_suspicious() {
        assert!(!is_suspicious_shm(10, 50));
    }
}
