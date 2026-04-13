//! Hidden process detection via PID namespace vs task list discrepancy.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::types::HiddenProcessInfo;
use crate::Result;

/// Scan for processes hidden by DKOM or PID namespace tricks.
///
/// Compares the PID namespace, task list, and PID hash table for discrepancies.
/// Returns `Ok(vec![])` as a stub until full implementation is added.
pub fn find_hidden_processes<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<HiddenProcessInfo>> {
    let _ = reader;
    Ok(vec![])
}
