//! Windows crash dump header and bug check analysis.
//!
//! Extracts crash dump header information, bug check code, and crash parameters
//! from kernel memory. Useful for BSOD analysis and detecting forced crash dumps
//! used as an anti-forensic technique. Equivalent to Volatility's `crashinfo`
//! plugin.
//!
//! Resolves `KiBugCheckData` or `KdDebuggerDataBlock` symbols to locate the
//! bug check code and four associated parameters. The `is_suspicious` flag is
//! set when the bug check code indicates a manually triggered crash (e.g.
//! `0xDEADDEAD` from `NotMyFault` or `0xC000021A` forced BSOD).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use serde::Serialize;

/// Crash dump information extracted from kernel memory.
#[derive(Debug, Clone, Serialize)]
pub struct CrashInfo {
    /// The bug check (stop) code that caused the crash.
    pub bugcheck_code: u32,
    /// First bug check parameter (meaning varies by code).
    pub param1: u64,
    /// Second bug check parameter.
    pub param2: u64,
    /// Third bug check parameter.
    pub param3: u64,
    /// Fourth bug check parameter.
    pub param4: u64,
    /// Dump type description (e.g. "Full", "Kernel", "Small/Minidump").
    pub dump_type: String,
    /// System time at crash (Windows FILETIME, 100-ns intervals since 1601).
    pub system_time: u64,
    /// Human-readable comment describing the bug check code.
    pub comment: String,
    /// Whether this crash is suspicious (manual crash / anti-forensic).
    pub is_suspicious: bool,
}

/// Map a bug check code to a human-readable name.
///
/// Common Windows bug check codes:
/// - `0x0A` = `IRQL_NOT_LESS_OR_EQUAL`
/// - `0x1A` = `MEMORY_MANAGEMENT`
/// - `0x3B` = `SYSTEM_SERVICE_EXCEPTION`
/// - `0x50` = `PAGE_FAULT_IN_NONPAGED_AREA`
/// - `0x7E` = `SYSTEM_THREAD_EXCEPTION_NOT_HANDLED`
/// - `0xD1` = `DRIVER_IRQL_NOT_LESS_OR_EQUAL`
pub fn bugcheck_name(code: u32) -> &'static str {
        todo!()
    }

/// Classify whether a bug check code indicates a suspicious (manually
/// triggered or anti-forensic) crash.
///
/// Returns `true` for:
/// - `0xDEADDEAD` — manual crash via `NotMyFault.exe` or similar tool
/// - `0xC000021A` — `STATUS_SYSTEM_PROCESS_TERMINATED`, often forced
pub fn classify_crashinfo(code: u32) -> bool {
        todo!()
    }

/// Extract crash dump header and bug check information from kernel memory.
///
/// Looks up `KiBugCheckData` or `KdDebuggerDataBlock` to locate the bug check
/// code and four associated parameters. Returns `Ok(None)` if the essential
/// symbols are not found (e.g. non-Windows image or no crash data present).
///
/// Optional fields degrade gracefully: if a symbol is missing, a default
/// value is used (0 for integers, empty string for strings).
///
/// # Symbols read
///
/// | Symbol                | Type | Description                        |
/// |-----------------------|------|------------------------------------|
/// | `KiBugCheckData`      | u32  | Bug check code                     |
/// | `KdDebuggerDataBlock` | -    | Fallback for crash parameters      |
pub fn walk_crashinfo<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Option<CrashInfo>> {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;

    // ── bugcheck_name classifier tests ──

    #[test]
    fn bugcheck_name_irql_not_less_or_equal() {
        todo!()
    }

    #[test]
    fn bugcheck_name_memory_management() {
        todo!()
    }

    #[test]
    fn bugcheck_name_system_service_exception() {
        todo!()
    }

    #[test]
    fn bugcheck_name_page_fault() {
        todo!()
    }

    #[test]
    fn bugcheck_name_system_thread_exception() {
        todo!()
    }

    #[test]
    fn bugcheck_name_driver_irql() {
        todo!()
    }

    #[test]
    fn bugcheck_name_unknown() {
        todo!()
    }

    // ── classify_crashinfo tests ──

    #[test]
    fn classify_manual_crash() {
        todo!()
    }

    #[test]
    fn classify_forced_bsod() {
        todo!()
    }

    #[test]
    fn classify_normal_bugcheck_not_suspicious() {
        todo!()
    }

    // ── serialization test ──

    #[test]
    fn crash_info_serializes() {
        todo!()
    }

    // ── walker tests ──

    #[test]
    fn walker_no_symbol_returns_none() {
        todo!()
    }

    #[test]
    fn walker_with_bugcheck_data_returns_info() {
        todo!()
    }

    #[test]
    fn walker_detects_suspicious_manual_crash() {
        todo!()
    }

    #[test]
    fn walker_detects_suspicious_forced_bsod() {
        todo!()
    }
}
