//! Audit rule suppression / netlink audit tamper detection.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::types::AuditTamperInfo;
use crate::Result;

/// Scan for audit subsystem tampering.
///
/// Returns `Ok(vec![])` as a stub until full implementation is added.
pub fn scan_audit_tampering<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<AuditTamperInfo>> {
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
        let result = scan_audit_tampering(&reader);
        assert!(result.is_ok(), "should succeed with minimal reader");
        assert!(
            result.unwrap().is_empty(),
            "empty memory → no audit tampering hits"
        );
    }

    #[test]
    fn result_is_vec_of_audit_tamper_info() {
        let reader = make_minimal_reader();
        let result: Result<Vec<AuditTamperInfo>> = scan_audit_tampering(&reader);
        assert!(result.is_ok());
    }

    #[test]
    fn audit_tamper_info_fields_constructible() {
        let info = AuditTamperInfo {
            audit_enabled: false,
            backlog_limit: 8192,
            suppressed_pids: vec![1337, 1338],
            suppressed_uids: vec![0],
            audit_globally_disabled: true,
        };
        assert!(!info.audit_enabled);
        assert_eq!(info.backlog_limit, 8192);
        assert_eq!(info.suppressed_pids.len(), 2);
        assert!(info.audit_globally_disabled);
    }

    #[test]
    fn audit_tamper_info_serializes() {
        let info = AuditTamperInfo {
            audit_enabled: true,
            backlog_limit: 64,
            suppressed_pids: vec![],
            suppressed_uids: vec![],
            audit_globally_disabled: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"audit_enabled\":true"));
        assert!(json.contains("\"backlog_limit\":64"));
        assert!(json.contains("\"audit_globally_disabled\":false"));
    }
}
