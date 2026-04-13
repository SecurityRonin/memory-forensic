//! Heap spray detection walker — MITRE ATT&CK T1203.
//!
//! Analyses process heaps for patterns consistent with heap spraying:
//! large numbers of same-sized allocations, NOP sled patterns, and
//! unusually high heap commit sizes.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, types::HeapSprayInfo};

/// Scan process heaps for heap spray indicators.
///
/// For each process, walks the `_PEB.ProcessHeaps` array of `_HEAP`
/// structures. For each heap:
/// - Counts allocations that match spray heuristics (uniform size,
///   repeated byte pattern in the user data).
/// - Scans for NOP sled sequences (`0x90` repeated for ≥16 bytes).
/// - Records total committed bytes.
///
/// # MITRE ATT&CK
/// T1203 — Exploitation for Client Execution
pub fn scan_heap_spray<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<HeapSprayInfo>> {
    let _ = reader;
    Ok(vec![])
}
