//! Timer/signal FD abuse detection.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::types::FdAbuseInfo;
use crate::Result;

/// Scan for timerfd/signalfd/eventfd abuse patterns.
///
/// Returns `Ok(vec![])` as a stub until full implementation is added.
pub fn scan_fd_abuse<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<FdAbuseInfo>> {
    let _ = reader;
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FdAbuseType;
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
        let result = scan_fd_abuse(&reader);
        assert!(result.is_ok(), "should succeed with minimal reader");
        assert!(result.unwrap().is_empty(), "empty memory → no fd abuse hits");
    }

    #[test]
    fn result_is_vec_of_fd_abuse_info() {
        let reader = make_minimal_reader();
        let result: Result<Vec<FdAbuseInfo>> = scan_fd_abuse(&reader);
        assert!(result.is_ok());
    }

    #[test]
    fn fd_abuse_info_timerfd_constructible() {
        let info = FdAbuseInfo {
            pid: 200,
            comm: "evil_timer".to_string(),
            fd_type: FdAbuseType::TimerFd,
            signal_mask: 0,
            interval_ns: 1_000_000_000,
            is_cross_process_shared: false,
        };
        assert_eq!(info.pid, 200);
        assert_eq!(info.fd_type, FdAbuseType::TimerFd);
        assert_eq!(info.interval_ns, 1_000_000_000);
    }

    #[test]
    fn fd_abuse_info_signalfd_constructible() {
        let info = FdAbuseInfo {
            pid: 300,
            comm: "sigmon".to_string(),
            fd_type: FdAbuseType::SignalFd,
            signal_mask: 0b1100,
            interval_ns: 0,
            is_cross_process_shared: true,
        };
        assert_eq!(info.fd_type, FdAbuseType::SignalFd);
        assert_eq!(info.signal_mask, 0b1100);
        assert!(info.is_cross_process_shared);
    }

    #[test]
    fn fd_abuse_info_serializes() {
        let info = FdAbuseInfo {
            pid: 7,
            comm: "efd".to_string(),
            fd_type: FdAbuseType::EventFd,
            signal_mask: 0,
            interval_ns: 0,
            is_cross_process_shared: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":7"));
        assert!(json.contains("EventFd"));
    }

    // --- classifier helper tests (genuine RED: function does not exist yet) ---

    #[test]
    fn fd_count_above_threshold_is_suspicious() {
        assert!(is_suspicious_fd_count(101, 100));
    }

    #[test]
    fn fd_count_at_threshold_is_not_suspicious() {
        assert!(!is_suspicious_fd_count(100, 100));
    }

    #[test]
    fn fd_count_below_threshold_is_not_suspicious() {
        assert!(!is_suspicious_fd_count(5, 100));
    }
}
