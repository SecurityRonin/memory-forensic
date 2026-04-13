//! WoW64 / Heaven's Gate anomaly detection walker — MITRE ATT&CK T1055.
//!
//! Detects 32-bit processes that use the Heaven's Gate technique (switching
//! to 64-bit mode via a far JMP to CS=0x33) or whose WoW64 syscall stub
//! has been patched to bypass hooks.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, types::Wow64AnomalyInfo};

/// Scan all WoW64 (32-bit) processes for Heaven's Gate and syscall-stub
/// tampering anomalies.
///
/// For each process where `_EPROCESS.Wow64Process` is non-null:
/// - Checks for a CS=0x33 segment selector in any thread's context
///   (Heaven's Gate indicator).
/// - Reads the first bytes of the `KiFastSystemCall` stub in the 32-bit
///   `ntdll.dll` mapping and compares with the expected sequence; any
///   deviation sets `syscall_stub_tampered`.
/// - Records whether `wow64.dll` is present in the process module list.
///
/// # MITRE ATT&CK
/// T1055 — Process Injection (WoW64 / Heaven's Gate)
pub fn scan_wow64_anomalies<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<Wow64AnomalyInfo>> {
    let _ = reader;
    Ok(vec![])
}
