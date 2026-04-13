//! CPU affinity / cryptominer detection via scheduling policy and CPU pinning.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::types::CpuPinningInfo;
use crate::Result;

/// Scan for processes with suspicious CPU pinning (potential cryptominers).
///
/// Returns `Ok(vec![])` as a stub until full implementation is added.
pub fn scan_cpu_pinning<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<CpuPinningInfo>> {
    let _ = reader;
    Ok(vec![])
}
