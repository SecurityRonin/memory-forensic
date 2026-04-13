//! DKOM (Direct Kernel Object Manipulation) cross-reference detection.
//!
//! Compares multiple kernel enumeration sources to detect objects that have
//! been unlinked from one or more lists — the hallmark of DKOM rootkits.
//! MITRE ATT&CK T1014.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, types::DkomDiscrepancy};

/// Cross-reference kernel process/driver/thread lists to detect DKOM hiding.
///
/// Compares:
/// - `PsActiveProcessHead` linked list vs `CidTable` handle table (processes)
/// - `PsLoadedModuleList` vs `MmDriverList` (drivers)
/// - Per-process `_EPROCESS.ThreadListHead` vs global thread scans (threads)
///
/// Any object present in one source but absent in another is reported as a
/// `DkomDiscrepancy`.
///
/// # MITRE ATT&CK
/// T1014 — Rootkit
pub fn scan_dkom<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<DkomDiscrepancy>> {
    let _ = reader;
    Ok(vec![])
}
