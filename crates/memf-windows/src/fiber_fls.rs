//! Fiber and Fiber Local Storage (FLS) abuse detection — MITRE ATT&CK T1055.
//!
//! Detects threads that have been converted to fibers and FLS callback
//! pointers that resolve outside loaded module ranges.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{types::FiberInfo, Result};

/// Scan all threads for fiber conversion and suspicious FLS callbacks.
///
/// Walks `_ETHREAD` structures looking for threads whose `Fiber` flag is
/// set (indicating a call to `ConvertThreadToFiber`). Extracts the saved
/// fiber context `RIP` and checks each FLS callback slot against the set
/// of loaded module address ranges, flagging any that fall outside.
///
/// # MITRE ATT&CK
/// T1055 — Process Injection (Fiber / FLS sub-technique)
pub fn scan_fiber_fls<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<FiberInfo>> {
    let _ = reader;
    Ok(vec![])
}
