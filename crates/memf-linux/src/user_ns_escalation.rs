//! User namespace escalation detection.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::types::UserNsEscalationInfo;
use crate::Result;

/// Scan for user namespace escalation patterns.
///
/// Returns `Ok(vec![])` as a stub until full implementation is added.
pub fn scan_user_ns_escalation<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<UserNsEscalationInfo>> {
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
        let result = scan_user_ns_escalation(&reader);
        assert!(result.is_ok(), "should succeed with minimal reader");
        assert!(
            result.unwrap().is_empty(),
            "empty memory → no user ns escalation hits"
        );
    }

    #[test]
    fn result_is_vec_of_user_ns_escalation_info() {
        let reader = make_minimal_reader();
        let result: Result<Vec<UserNsEscalationInfo>> = scan_user_ns_escalation(&reader);
        assert!(result.is_ok());
    }

    #[test]
    fn user_ns_escalation_info_fields_constructible() {
        let info = UserNsEscalationInfo {
            pid: 4242,
            comm: "unshare".to_string(),
            ns_depth: 2,
            owner_uid: 1000,
            process_uid: 0,
            has_cap_sys_admin: true,
            is_suspicious: true,
        };
        assert_eq!(info.pid, 4242);
        assert_eq!(info.ns_depth, 2);
        assert_eq!(info.owner_uid, 1000);
        assert_eq!(info.process_uid, 0);
        assert!(info.has_cap_sys_admin);
        assert!(info.is_suspicious);
    }

    #[test]
    fn user_ns_escalation_info_serializes() {
        let info = UserNsEscalationInfo {
            pid: 99,
            comm: "exploit".to_string(),
            ns_depth: 3,
            owner_uid: 1001,
            process_uid: 0,
            has_cap_sys_admin: true,
            is_suspicious: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":99"));
        assert!(json.contains("\"ns_depth\":3"));
        assert!(json.contains("\"has_cap_sys_admin\":true"));
        assert!(json.contains("\"is_suspicious\":true"));
    }
}
