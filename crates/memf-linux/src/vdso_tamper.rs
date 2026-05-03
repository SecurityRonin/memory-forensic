//! vDSO tampering detection.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::types::VdsoTamperInfo;
use crate::Result;

/// Classify whether a vDSO region has been tampered with.
///
/// Returns `true` if any bytes differ from the canonical kernel copy
/// (`diff_byte_count > 0`). `_vdso_size` is accepted for future use
/// (e.g. percentage-based thresholds) but is currently unused.
pub fn is_vdso_tampered(diff_byte_count: usize, _vdso_size: usize) -> bool {
    diff_byte_count > 0
}

/// Scan for vDSO regions that differ from the canonical kernel copy.
///
/// Returns `Ok(vec![])` as a stub until full implementation is added.
pub fn scan_vdso_tampering<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<VdsoTamperInfo>> {
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
        let result = scan_vdso_tampering(&reader);
        assert!(result.is_ok(), "should succeed with minimal reader");
        assert!(result.unwrap().is_empty(), "empty memory → no vDSO tampering");
    }

    #[test]
    fn result_is_vec_of_vdso_tamper_info() {
        let reader = make_minimal_reader();
        let result: Result<Vec<VdsoTamperInfo>> = scan_vdso_tampering(&reader);
        assert!(result.is_ok());
    }

    #[test]
    fn vdso_tamper_info_fields_constructible() {
        let info = VdsoTamperInfo {
            pid: 100,
            comm: "bash".to_string(),
            vdso_base: 0x7fff_0000_0000,
            vdso_size: 0x2000,
            differs_from_canonical: true,
            diff_byte_count: 8,
        };
        assert_eq!(info.pid, 100);
        assert_eq!(info.vdso_size, 0x2000);
        assert!(info.differs_from_canonical);
        assert_eq!(info.diff_byte_count, 8);
    }

    #[test]
    fn vdso_tamper_info_serializes() {
        let info = VdsoTamperInfo {
            pid: 55,
            comm: "malware".to_string(),
            vdso_base: 0xDEAD_0000,
            vdso_size: 4096,
            differs_from_canonical: true,
            diff_byte_count: 16,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":55"));
        assert!(json.contains("\"differs_from_canonical\":true"));
        assert!(json.contains("\"diff_byte_count\":16"));
    }

    // --- classifier helper tests (genuine RED: function does not exist yet) ---

    #[test]
    fn nonzero_diff_bytes_is_tampered() {
        assert!(is_vdso_tampered(16, 4096));
    }

    #[test]
    fn single_byte_diff_is_tampered() {
        assert!(is_vdso_tampered(1, 4096));
    }

    #[test]
    fn zero_diff_is_clean() {
        assert!(!is_vdso_tampered(0, 4096));
    }
}
