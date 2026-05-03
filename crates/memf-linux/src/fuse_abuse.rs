//! FUSE filesystem abuse detection.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::types::FuseAbuseInfo;
use crate::Result;

/// Scan for FUSE filesystem abuse (mounted over sensitive paths, root daemon with allow_other).
///
/// Returns `Ok(vec![])` as a stub until full implementation is added.
pub fn scan_fuse_abuse<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<FuseAbuseInfo>> {
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
        let result = scan_fuse_abuse(&reader);
        assert!(result.is_ok(), "should succeed with minimal reader");
        assert!(result.unwrap().is_empty(), "empty memory → no FUSE abuse hits");
    }

    #[test]
    fn result_is_vec_of_fuse_abuse_info() {
        let reader = make_minimal_reader();
        let result: Result<Vec<FuseAbuseInfo>> = scan_fuse_abuse(&reader);
        assert!(result.is_ok());
    }

    #[test]
    fn fuse_abuse_info_fields_constructible() {
        let info = FuseAbuseInfo {
            pid: 333,
            comm: "sshfs".to_string(),
            mount_point: "/proc".to_string(),
            is_over_sensitive_path: true,
            daemon_is_root: true,
            allow_other: true,
        };
        assert_eq!(info.pid, 333);
        assert_eq!(info.mount_point, "/proc");
        assert!(info.is_over_sensitive_path);
        assert!(info.allow_other);
    }

    #[test]
    fn fuse_abuse_info_serializes() {
        let info = FuseAbuseInfo {
            pid: 1,
            comm: "fusermount".to_string(),
            mount_point: "/etc".to_string(),
            is_over_sensitive_path: true,
            daemon_is_root: false,
            allow_other: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":1"));
        assert!(json.contains("/etc"));
        assert!(json.contains("\"is_over_sensitive_path\":true"));
    }

    // --- classifier helper tests (genuine RED: function does not exist yet) ---

    #[test]
    fn non_root_uid_with_setuid_is_suspicious_fuse_mount() {
        // Non-root daemon with setuid flag → privilege escalation path
        assert!(is_suspicious_fuse_mount(1000, true));
    }

    #[test]
    fn root_uid_with_setuid_is_not_suspicious() {
        assert!(!is_suspicious_fuse_mount(0, true));
    }

    #[test]
    fn non_root_uid_without_setuid_is_not_suspicious() {
        assert!(!is_suspicious_fuse_mount(1000, false));
    }
}
