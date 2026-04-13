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
