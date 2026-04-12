//! ETW (Event Tracing for Windows) patch detection.
//!
//! Detects in-memory patches to key ETW functions in `ntdll.dll` and
//! `ntoskrnl.exe`. Attackers patch `EtwEventWrite`, `EtwEventWriteFull`,
//! and `EtwEventWriteEx` to suppress telemetry and evade security monitoring.
//!
//! Uses the same patch classification logic as AMSI bypass detection:
//! - `xor eax, eax; ret` (31 C0 C3 / 33 C0 C3)
//! - `mov eax, 0; ret` (B8 00 00 00 00 C3)
//! - `jmp <stub>` (EB xx)
//! - `int3` (CC xx)

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about a detected ETW patch.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EtwPatchInfo {
    /// Patched function name (e.g. "EtwEventWrite").
    pub function_name: String,
    /// Virtual address of the patched instruction.
    pub patch_address: u64,
    /// Actual bytes found at the function prologue as hex string.
    pub found_bytes: String,
    /// Patch technique identifier.
    pub technique: String,
    /// True if the bytes match a known patch pattern.
    pub is_suspicious: bool,
}

/// Classify the first bytes of a function prologue as an ETW patch technique.
///
/// Returns `Some(technique_name)` if a known patch pattern is detected,
/// `None` for a clean (unpatched) prologue.
pub fn classify_etw_patch(bytes: &[u8]) -> Option<&'static str> {
        todo!()
    }

/// Walk processes and check for ETW function patches in ntdll.dll.
///
/// For each process, locates `ntdll.dll` in the module list and checks
/// the prologues of `EtwEventWrite`, `EtwEventWriteFull`, and
/// `EtwEventWriteEx` for known patch patterns.
///
/// Returns `Ok(Vec::new())` if `PsActiveProcessHead` symbol is absent
/// (graceful degradation).
pub fn walk_etw_patches<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<EtwPatchInfo>> {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;

    /// `xor eax, eax; ret` is a known ETW patch — must be detected.
    #[test]
    fn classify_xor_eax_ret_detected() {
        todo!()
    }

    /// `mov eax, 0; ret` is a known ETW patch.
    #[test]
    fn classify_mov_eax_ret_detected() {
        todo!()
    }

    /// `jmp <stub>` (EB xx) is a known ETW patch.
    #[test]
    fn classify_jmp_stub_detected() {
        todo!()
    }

    /// `int3` patch (CC xx ...) is a known ETW patch.
    #[test]
    fn classify_int3_patch_detected() {
        todo!()
    }

    /// Fewer than 3 bytes returns None (cannot classify).
    #[test]
    fn classify_too_short_returns_none() {
        todo!()
    }

    /// mov_eax_ret requires byte[5] == 0xC3 — without it, no match.
    #[test]
    fn classify_mov_eax_without_ret_not_detected() {
        todo!()
    }

    /// Normal function prologue bytes must not be flagged.
    #[test]
    fn classify_clean_bytes_not_suspicious() {
        todo!()
    }

    /// Without PsActiveProcessHead symbol, walker returns empty.
    #[test]
    fn walk_etw_patches_no_symbol_returns_empty() {
        todo!()
    }
}
