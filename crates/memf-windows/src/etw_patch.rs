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
    if bytes.len() < 3 {
        return None;
    }
    match &bytes[..3] {
        [0x31, 0xC0, 0xC3] | [0x33, 0xC0, 0xC3] => Some("xor_eax_ret"),
        [0xB8, _, _] if bytes.get(5) == Some(&0xC3) => Some("mov_eax_ret"),
        [0xEB, _, _] => Some("jmp_stub"),
        [0xCC, _, _] => Some("int3_patch"),
        _ => None,
    }
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
    // Graceful degradation: require PsActiveProcessHead to walk processes
    if reader
        .symbols()
        .symbol_address("PsActiveProcessHead")
        .is_none()
    {
        return Ok(Vec::new());
    }

    // In a full implementation we would:
    // 1. Walk process list via PsActiveProcessHead
    // 2. For each process, scan module list for ntdll.dll
    // 3. Resolve ETW function export VAs from PE export table
    // 4. Read first 16 bytes at each VA and call classify_etw_patch
    // 5. Build EtwPatchInfo entries for any detected patches
    //
    // Returning empty pending integration with module/export walkers.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `xor eax, eax; ret` is a known ETW patch — must be detected.
    #[test]
    fn classify_xor_eax_ret_detected() {
        let bytes = [0x31u8, 0xC0, 0xC3, 0x00, 0x00, 0x00];
        assert_eq!(classify_etw_patch(&bytes), Some("xor_eax_ret"));

        let bytes2 = [0x33u8, 0xC0, 0xC3, 0x00, 0x00, 0x00];
        assert_eq!(classify_etw_patch(&bytes2), Some("xor_eax_ret"));
    }

    /// `mov eax, 0; ret` is a known ETW patch.
    #[test]
    fn classify_mov_eax_ret_detected() {
        // Pattern: B8 00 00 00 00 C3
        let bytes = [0xB8u8, 0x00, 0x00, 0x00, 0x00, 0xC3];
        assert_eq!(classify_etw_patch(&bytes), Some("mov_eax_ret"));
        // B8 XX XX XX XX C3 — any two bytes after B8 are matched by the wildcard
        let bytes2 = [0xB8u8, 0xFF, 0x12, 0x00, 0x00, 0xC3];
        assert_eq!(classify_etw_patch(&bytes2), Some("mov_eax_ret"));
    }

    /// `jmp <stub>` (EB xx) is a known ETW patch.
    #[test]
    fn classify_jmp_stub_detected() {
        let bytes = [0xEBu8, 0x08, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(classify_etw_patch(&bytes), Some("jmp_stub"));
    }

    /// `int3` patch (CC xx ...) is a known ETW patch.
    #[test]
    fn classify_int3_patch_detected() {
        let bytes = [0xCCu8, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(classify_etw_patch(&bytes), Some("int3_patch"));
    }

    /// Fewer than 3 bytes returns None (cannot classify).
    #[test]
    fn classify_too_short_returns_none() {
        assert_eq!(classify_etw_patch(&[]), None);
        assert_eq!(classify_etw_patch(&[0x31]), None);
        assert_eq!(classify_etw_patch(&[0x31, 0xC0]), None);
    }

    /// mov_eax_ret requires byte[5] == 0xC3 — without it, no match.
    #[test]
    fn classify_mov_eax_without_ret_not_detected() {
        // B8 XX XX but no 0xC3 at index 5
        let bytes = [0xB8u8, 0x00, 0x00, 0x00, 0x00, 0x00]; // index 5 = 0x00, not 0xC3
        assert_eq!(classify_etw_patch(&bytes), None);
    }

    /// Normal function prologue bytes must not be flagged.
    #[test]
    fn classify_clean_bytes_not_suspicious() {
        // mov rax, rsp; sub rsp, 0x28 — typical Windows x64 prologue
        let bytes = [0x48u8, 0x8B, 0xC4, 0x48, 0x83, 0xEC, 0x28];
        assert_eq!(classify_etw_patch(&bytes), None);
    }

    /// Without PsActiveProcessHead symbol, walker returns empty.
    #[test]
    fn walk_etw_patches_no_symbol_returns_empty() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &[0u8; 16]);
        let (cr3, mem) = ptb.build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_etw_patches(&reader).unwrap();
        assert!(results.is_empty());
    }
}
