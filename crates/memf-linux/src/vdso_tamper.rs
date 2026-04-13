//! vDSO tampering detection.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::types::VdsoTamperInfo;
use crate::Result;

/// Scan for vDSO regions that differ from the canonical kernel copy.
///
/// Returns `Ok(vec![])` as a stub until full implementation is added.
pub fn scan_vdso_tampering<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<VdsoTamperInfo>> {
    let _ = reader;
    Ok(vec![])
}
