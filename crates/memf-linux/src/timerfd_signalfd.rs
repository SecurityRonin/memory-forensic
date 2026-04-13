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
