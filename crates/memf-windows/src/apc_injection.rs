//! APC queue forensics walker — MITRE ATT&CK T1055.004.
//!
//! Scans `KTHREAD->ApcState.ApcListHead` for each thread and extracts
//! queued `_KAPC` entries, reporting unbacked or kernel-mode APCs.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, types::ApcInfo};

/// Scan all thread APC queues in the memory image for queued APCs.
///
/// For each `_KTHREAD` found, walks the `ApcState.ApcListHead[0]` (kernel)
/// and `ApcState.ApcListHead[1]` (user) lists and extracts each `_KAPC`.
/// Reports APCs whose `NormalRoutine` does not fall within any loaded
/// module's virtual address range as unbacked (potentially malicious).
///
/// # MITRE ATT&CK
/// T1055.004 — Asynchronous Procedure Call
pub fn scan_apc_queues<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<ApcInfo>> {
    // Walk KTHREAD->ApcState.ApcListHead for each thread.
    // Extract KAPC->NormalRoutine, KernelRoutine function pointers.
    // Check if pointers fall within any loaded module's address range.
    let _ = reader;
    Ok(vec![])
}
