//! Shared memory forensics / anomaly detection.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::types::SharedMemAnomalyInfo;
use crate::Result;

/// Scan for shared memory anomalies (executable memfd, ELF headers, cross-uid sharing).
///
/// Returns `Ok(vec![])` as a stub until full implementation is added.
pub fn scan_shared_mem_anomalies<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<SharedMemAnomalyInfo>> {
    let _ = reader;
    Ok(vec![])
}
