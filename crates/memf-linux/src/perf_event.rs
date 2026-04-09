//! Suspicious `perf_event` detection for Linux memory forensics.
//!
//! Walks each process's `perf_event_context` (via `task_struct.perf_event_ctxp[0]`)
//! and enumerates all attached `perf_event` structs. Hardware cache events and raw
//! PMU accesses are flagged as suspicious (Spectre/cache-timing attack patterns).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about a single perf_event attached to a process.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PerfEventInfo {
    /// PID of the owning process.
    pub pid: u32,
    /// Command name of the owning process.
    pub comm: String,
    /// PERF_TYPE_* constant.
    pub event_type: u32,
    /// Human-readable name for `event_type`.
    pub event_type_name: String,
    /// Event configuration (e.g. `PERF_COUNT_HW_CACHE_MISSES`).
    pub config: u64,
    /// Sample period set on the event.
    pub sample_period: u64,
    /// True when this event matches cache-side-channel or PMU-based attack patterns.
    pub is_suspicious: bool,
}

/// Map a `PERF_TYPE_*` constant to a human-readable name.
pub fn perf_type_name(_t: u32) -> &'static str {
    todo!("perf_type_name not yet implemented")
}

/// Classify whether a perf_event represents a suspicious access pattern.
pub fn classify_perf_event(_event_type: u32, _config: u64) -> bool {
    todo!("classify_perf_event not yet implemented")
}

/// Walk all perf_events across all processes and return structured info.
///
/// Returns `Ok(Vec::new())` when `init_task` symbol or required ISF offsets
/// are absent (graceful degradation).
pub fn walk_perf_events<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
) -> Result<Vec<PerfEventInfo>> {
    todo!("walk_perf_events not yet implemented")
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
    fn perf_type_name_hardware() {
        assert_eq!(perf_type_name(0), "HARDWARE");
    }

    #[test]
    fn classify_ll_cache_event_suspicious() {
        assert!(classify_perf_event(3, 2), "LL cache event must be suspicious");
    }

    #[test]
    fn classify_software_event_not_suspicious() {
        assert!(
            !classify_perf_event(1, 0),
            "SOFTWARE event must not be suspicious"
        );
    }

    #[test]
    fn walk_perf_events_no_symbol_returns_empty() {
        let reader = make_no_symbol_reader();
        let result = walk_perf_events(&reader).unwrap();
        assert!(result.is_empty(), "no init_task symbol → empty vec expected");
    }
}
