//! OOM (Out-of-Memory) kill event recovery from the kernel log buffer.
//!
//! Scans the `__log_buf` printk ring buffer for OOM kill messages and
//! extracts structured event info. Events that killed security/monitoring
//! processes are flagged as suspicious.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about an OOM kill event recovered from kernel logs.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OomEventInfo {
    /// PID of the process that was OOM-killed.
    pub victim_pid: u32,
    /// Command name of the killed process.
    pub victim_comm: String,
    /// OOM score adjustment at time of kill.
    pub oom_score_adj: i16,
    /// Total virtual memory in kilobytes.
    pub total_vm_kb: u64,
    /// Resident set size in kilobytes.
    pub rss_kb: u64,
    /// Timestamp in nanoseconds from the printk record.
    pub timestamp_ns: u64,
    /// Source of the OOM event (e.g. "oom_kill_process", "mem_cgroup_oom").
    pub reason: String,
    /// True when the victim is a security/monitoring process or has PID < 100.
    pub is_suspicious: bool,
}

/// Classify whether an OOM kill event is suspicious.
pub fn classify_oom_victim(_comm: &str, _pid: u32) -> bool {
    todo!("classify_oom_victim not yet implemented")
}

/// Walk the kernel log ring buffer for OOM kill events.
///
/// Returns `Ok(Vec::new())` when the `__log_buf` symbol is absent.
pub fn walk_oom_events<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
) -> Result<Vec<OomEventInfo>> {
    todo!("walk_oom_events not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_no_symbol_reader() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn classify_oom_kill_of_auditd_suspicious() {
        assert!(
            classify_oom_victim("auditd", 1234),
            "OOM kill of auditd must be suspicious"
        );
    }

    #[test]
    fn classify_oom_kill_of_user_process_benign() {
        assert!(
            !classify_oom_victim("chrome", 9999),
            "OOM kill of a regular user process must not be suspicious"
        );
    }

    #[test]
    fn walk_oom_events_no_symbol_returns_empty() {
        let reader = make_no_symbol_reader();
        let result = walk_oom_events(&reader).unwrap();
        assert!(result.is_empty(), "no __log_buf symbol → empty vec expected");
    }
}
