//! User namespace escalation detection.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::types::UserNsEscalationInfo;
use crate::Result;

/// Scan for user namespace escalation patterns.
///
/// Returns `Ok(vec![])` as a stub until full implementation is added.
pub fn scan_user_ns_escalation<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<UserNsEscalationInfo>> {
    let _ = reader;
    Ok(vec![])
}
