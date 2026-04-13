//! Audit rule suppression / netlink audit tamper detection.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::types::AuditTamperInfo;
use crate::Result;

/// Scan for audit subsystem tampering.
///
/// Returns `Ok(vec![])` as a stub until full implementation is added.
pub fn scan_audit_tampering<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<AuditTamperInfo>> {
    let _ = reader;
    Ok(vec![])
}
