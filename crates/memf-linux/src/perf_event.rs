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
pub fn perf_type_name(t: u32) -> &'static str {
    match t {
        0 => "HARDWARE",
        1 => "SOFTWARE",
        2 => "TRACEPOINT",
        3 => "HW_CACHE",
        4 => "RAW",
        5 => "BREAKPOINT",
        _ => "UNKNOWN",
    }
}

/// Classify whether a perf_event represents a suspicious access pattern.
///
/// - `PERF_TYPE_HW_CACHE` (3) with config low byte <= 2 (L1D or LL cache) is
///   a known pattern used in cache-timing / Spectre attacks.
/// - `PERF_TYPE_RAW` (4) gives direct PMU counter access from userspace and is
///   always considered suspicious.
pub fn classify_perf_event(event_type: u32, config: u64) -> bool {
    match event_type {
        3 => (config & 0xFF) <= 2, // L1D (0) or LL (2) cache events
        4 => true,                 // RAW PMU access always suspicious from userspace
        _ => false,
    }
}

/// Walk all perf_events across all processes and return structured info.
///
/// Returns `Ok(Vec::new())` when `init_task` symbol or required ISF offsets
/// are absent (graceful degradation).
pub fn walk_perf_events<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<PerfEventInfo>> {
    // Graceful degradation: require init_task symbol.
    let init_task_addr = match reader.symbols().symbol_address("init_task") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // Require task_struct.tasks offset for process-list traversal.
    let tasks_offset = match reader.symbols().field_offset("task_struct", "tasks") {
        Some(off) => off,
        None => return Ok(Vec::new()),
    };

    // Require perf_event_ctxp offset for perf context pointer array.
    let ctxp_offset = match reader
        .symbols()
        .field_offset("task_struct", "perf_event_ctxp")
    {
        Some(off) => off,
        None => return Ok(Vec::new()),
    };

    let mut results = Vec::new();

    // Collect all task_struct addresses by walking the tasks list_head.
    let mut task_addrs: Vec<u64> = Vec::new();
    {
        let first_next: u64 = match reader.read_field(init_task_addr, "task_struct", "tasks") {
            Ok(v) => v,
            Err(_) => return Ok(Vec::new()),
        };
        let mut cursor = first_next;
        let mut guard = 0usize;
        loop {
            if cursor == 0 || guard > 65536 {
                break;
            }
            let task_addr = cursor.saturating_sub(tasks_offset as u64);
            if task_addr == init_task_addr {
                break;
            }
            task_addrs.push(task_addr);
            cursor = match reader.read_field(cursor, "list_head", "next") {
                Ok(v) => v,
                Err(_) => break,
            };
            guard += 1;
        }
    }

    // Include init_task itself.
    let all_tasks = std::iter::once(init_task_addr).chain(task_addrs.into_iter());

    for task_addr in all_tasks {
        let pid: u32 = reader
            .read_field::<u32>(task_addr, "task_struct", "pid")
            .unwrap_or(0);
        let comm_bytes: [u8; 16] = reader
            .read_field(task_addr, "task_struct", "comm")
            .unwrap_or([0u8; 16]);
        let comm = std::str::from_utf8(&comm_bytes)
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_string();

        // Read perf_event_ctxp[0]: pointer stored at task_addr + ctxp_offset.
        let ctx_ptr_addr = task_addr + ctxp_offset as u64;
        let ctx_ptr: u64 = match reader.read_bytes(ctx_ptr_addr, 8) {
            Ok(bytes) => u64::from_le_bytes(bytes.try_into().unwrap_or([0u8; 8])),
            Err(_) => continue,
        };
        if ctx_ptr == 0 {
            continue;
        }

        // Walk pinned_groups and flexible_groups list_heads of perf_event_context.
        for group_field in &["pinned_groups", "flexible_groups"] {
            let head_addr = match reader
                .symbols()
                .field_offset("perf_event_context", group_field)
            {
                Some(off) => ctx_ptr + off as u64,
                None => continue,
            };

            let first_event_list: u64 = match reader.read_bytes(head_addr, 8) {
                Ok(b) => u64::from_le_bytes(b.try_into().unwrap_or([0u8; 8])),
                Err(_) => continue,
            };

            let event_group_node_offset =
                match reader.symbols().field_offset("perf_event", "group_entry") {
                    Some(off) => off,
                    None => continue,
                };

            let mut cursor = first_event_list;
            let mut guard = 0usize;
            loop {
                if cursor == 0 || cursor == head_addr || guard > 4096 {
                    break;
                }
                let event_addr = cursor.saturating_sub(event_group_node_offset as u64);

                // perf_event.attr is embedded at ~0x20; type at attr+0, config at attr+8.
                let attr_offset: u64 = reader
                    .symbols()
                    .field_offset("perf_event", "attr")
                    .map(|o| o as u64)
                    .unwrap_or(0x20);

                let event_type: u32 = match reader.read_bytes(event_addr + attr_offset, 4) {
                    Ok(b) => u32::from_le_bytes(b.try_into().unwrap_or([0u8; 4])),
                    Err(_) => {
                        cursor = match reader.read_bytes(cursor, 8) {
                            Ok(b) => u64::from_le_bytes(b.try_into().unwrap_or([0u8; 8])),
                            Err(_) => break,
                        };
                        guard += 1;
                        continue;
                    }
                };

                let config: u64 = reader
                    .read_bytes(event_addr + attr_offset + 8, 8)
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .map(u64::from_le_bytes)
                    .unwrap_or(0);

                let sample_period: u64 = reader
                    .read_bytes(event_addr + attr_offset + 16, 8)
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .map(u64::from_le_bytes)
                    .unwrap_or(0);

                let is_suspicious = classify_perf_event(event_type, config);
                results.push(PerfEventInfo {
                    pid,
                    comm: comm.clone(),
                    event_type,
                    event_type_name: perf_type_name(event_type).to_string(),
                    config,
                    sample_period,
                    is_suspicious,
                });

                cursor = match reader.read_bytes(cursor, 8) {
                    Ok(b) => u64::from_le_bytes(b.try_into().unwrap_or([0u8; 8])),
                    Err(_) => break,
                };
                guard += 1;
            }
        }
    }

    Ok(results)
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
    fn perf_type_name_unknown() {
        assert_eq!(perf_type_name(99), "UNKNOWN");
    }

    #[test]
    fn classify_ll_cache_event_suspicious() {
        // PERF_TYPE_HW_CACHE (3), config low byte = 2 (PERF_COUNT_HW_CACHE_LL)
        assert!(
            classify_perf_event(3, 2),
            "LL cache event must be suspicious"
        );
    }

    #[test]
    fn classify_l1d_cache_event_suspicious() {
        // PERF_TYPE_HW_CACHE (3), config low byte = 0 (PERF_COUNT_HW_CACHE_L1D)
        assert!(
            classify_perf_event(3, 0),
            "L1D cache event must be suspicious"
        );
    }

    #[test]
    fn classify_software_event_not_suspicious() {
        assert!(
            !classify_perf_event(1, 0),
            "SOFTWARE event must not be suspicious"
        );
    }

    #[test]
    fn classify_raw_pmu_event_suspicious() {
        assert!(
            classify_perf_event(4, 0xDEAD),
            "RAW PMU event must be suspicious"
        );
    }

    #[test]
    fn classify_hardware_event_not_suspicious() {
        assert!(
            !classify_perf_event(0, 1),
            "plain HARDWARE event must not be suspicious"
        );
    }

    #[test]
    fn walk_perf_events_no_symbol_returns_empty() {
        let reader = make_no_symbol_reader();
        let result = walk_perf_events(&reader).unwrap();
        assert!(
            result.is_empty(),
            "no init_task symbol → empty vec expected"
        );
    }
}
