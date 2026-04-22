//! AMSI (Antimalware Scan Interface) bypass detection.
//!
//! Detects in-memory patches to `AmsiScanBuffer` and `AmsiScanString`
//! exports in `amsi.dll`. Attackers patch these functions to make AMSI
//! always return "clean" (S_OK / AMSI_RESULT_CLEAN), bypassing script
//! and memory scanning.
//!
//! Known patch techniques:
//! - `xor eax, eax; ret` (31 C0 C3 / 33 C0 C3) — returns 0
//! - `mov eax, 0x80070057; ret` (B8 57 00 07 80 C3) — returns E_INVALIDARG
//! - `jmp <stub>` (EB xx) — jumps to bypass stub
//! - `int3` (CC xx) — breakpoint used as patch marker

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about a detected AMSI bypass patch in a process.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AmsiBypassInfo {
    /// PID of the affected process.
    pub pid: u32,
    /// Process image name.
    pub process_name: String,
    /// Patched function name (e.g. "AmsiScanBuffer").
    pub function_name: String,
    /// Virtual address of the patched instruction.
    pub patch_address: u64,
    /// Expected prologue bytes as hex string (e.g. "48 8B C4").
    pub original_expected: String,
    /// Actual bytes found as hex string.
    pub found_bytes: String,
    /// Patch technique identifier.
    pub technique: String,
    /// True if the bytes match a known bypass pattern.
    pub is_suspicious: bool,
}

/// Classify the first bytes of a function prologue as an AMSI bypass technique.
///
/// Returns `Some(technique_name)` if a known bypass pattern is detected,
/// `None` for a clean (unpatched) prologue.
pub fn classify_amsi_patch(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() < 6 {
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

/// Format a byte slice as a space-separated hex string.
#[allow(dead_code)]
fn hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Walk all processes and check for AMSI bypass patches.
///
/// For each process that has `amsi.dll` loaded, reads the first 16 bytes of
/// `AmsiScanBuffer` and `AmsiScanString` exports and checks for known
/// bypass patterns.
///
/// Returns `Ok(Vec::new())` if `PsActiveProcessHead` symbol is absent
/// (graceful degradation).
pub fn walk_amsi_bypass<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<AmsiBypassInfo>> {
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
    // 2. For each process, scan its module list for amsi.dll
    // 3. Read export table to find AmsiScanBuffer / AmsiScanString VAs
    // 4. Read first 16 bytes at each export VA
    // 5. Call classify_amsi_patch and build AmsiBypassInfo entries
    //
    // This requires module list walking + PE export parsing which is handled
    // by other walkers (ldrmodules, dll). Returning empty pending integration.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `xor eax, eax; ret` (31 C0 C3) is a known bypass — must be detected.
    #[test]
    fn classify_xor_eax_ret_detected() {
        let bytes = [0x31u8, 0xC0, 0xC3, 0x00, 0x00, 0x00];
        assert_eq!(classify_amsi_patch(&bytes), Some("xor_eax_ret"));

        // Variant: 33 C0 C3
        let bytes2 = [0x33u8, 0xC0, 0xC3, 0x00, 0x00, 0x00];
        assert_eq!(classify_amsi_patch(&bytes2), Some("xor_eax_ret"));
    }

    /// Byte slices shorter than 6 bytes return None (guard requires len >= 6).
    #[test]
    fn classify_amsi_patch_too_short_returns_none() {
        assert_eq!(classify_amsi_patch(&[]), None);
        assert_eq!(classify_amsi_patch(&[0x31]), None);
        assert_eq!(classify_amsi_patch(&[0x31, 0xC0]), None);
        // 3–5 bytes also too short (mov_eax_ret needs index 5)
        assert_eq!(classify_amsi_patch(&[0x31, 0xC0, 0xC3]), None);
        assert_eq!(classify_amsi_patch(&[0x31, 0xC0, 0xC3, 0x00]), None);
        assert_eq!(classify_amsi_patch(&[0x31, 0xC0, 0xC3, 0x00, 0x00]), None);
    }

    /// `mov eax, imm32; ret` (B8 xx xx xx xx C3) is a bypass.
    #[test]
    fn classify_mov_eax_ret_detected() {
        // B8 57 00 07 80 C3 — mov eax, E_INVALIDARG (0x80070057); ret
        let bytes = [0xB8u8, 0x57, 0x00, 0x07, 0x80, 0xC3];
        assert_eq!(classify_amsi_patch(&bytes), Some("mov_eax_ret"));
    }

    /// `B8 xx xx xx xx` without C3 at index 5 is NOT a bypass.
    #[test]
    fn classify_mov_eax_no_ret_not_detected() {
        // B8 57 00 07 80 00 — 6 bytes present but no RET at index 5
        let bytes = [0xB8u8, 0x57, 0x00, 0x07, 0x80, 0x00];
        assert_eq!(classify_amsi_patch(&bytes), None);
        // 5 bytes — fails length guard (< 6), returns None before pattern check
        let short = [0xB8u8, 0x57, 0x00, 0x07, 0x80];
        assert_eq!(classify_amsi_patch(&short), None);
    }

    /// `jmp_stub` (EB xx) is a bypass.
    #[test]
    fn classify_jmp_stub_detected() {
        let bytes = [0xEBu8, 0x0A, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(classify_amsi_patch(&bytes), Some("jmp_stub"));
    }

    /// `int3_patch` (CC xx xx) is a bypass.
    #[test]
    fn classify_int3_patch_detected() {
        let bytes = [0xCCu8, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(classify_amsi_patch(&bytes), Some("int3_patch"));
    }

    /// hex_string formats bytes correctly.
    #[test]
    fn hex_string_formats_correctly() {
        assert_eq!(hex_string(&[0x31, 0xC0, 0xC3]), "31 C0 C3");
        assert_eq!(hex_string(&[0x00, 0xFF, 0x0A]), "00 FF 0A");
        assert_eq!(hex_string(&[]), "");
    }

    /// AmsiBypassInfo struct and serialization.
    #[test]
    fn amsi_bypass_info_serializes() {
        let info = AmsiBypassInfo {
            pid: 1234,
            process_name: "powershell.exe".to_string(),
            function_name: "AmsiScanBuffer".to_string(),
            patch_address: 0x7FFE_0001_2345,
            original_expected: "48 8B C4".to_string(),
            found_bytes: "31 C0 C3".to_string(),
            technique: "xor_eax_ret".to_string(),
            is_suspicious: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":1234"));
        assert!(json.contains("xor_eax_ret"));
        assert!(json.contains("AmsiScanBuffer"));
        assert!(json.contains("\"is_suspicious\":true"));
    }

    /// walk_amsi_bypass with PsActiveProcessHead symbol present returns empty (stub).
    #[test]
    fn walk_amsi_bypass_with_symbol_returns_empty() {
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let ps_head_vaddr: u64 = 0xFFFF_8001_0010_0000;
        let ps_head_paddr: u64 = 0x00A0_0000;

        let isf = IsfBuilder::windows_kernel_preset()
            .add_symbol("PsActiveProcessHead", ps_head_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let mut page = vec![0u8; 4096];
        page[0..8].copy_from_slice(&ps_head_vaddr.to_le_bytes());
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(ps_head_vaddr, ps_head_paddr, flags::WRITABLE)
            .write_phys(ps_head_paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_amsi_bypass(&reader).unwrap();
        assert!(
            results.is_empty(),
            "stub walker should return empty even with symbol"
        );
    }

    /// Normal function prologue bytes must not be flagged.
    #[test]
    fn classify_clean_bytes_not_suspicious() {
        // mov rax, rsp; sub rsp, 0x28 — typical Windows x64 prologue
        let bytes = [0x48u8, 0x8B, 0xC4, 0x48, 0x83, 0xEC, 0x28];
        assert_eq!(classify_amsi_patch(&bytes), None);
    }

    /// Without PsActiveProcessHead symbol, walker returns empty.
    #[test]
    fn walk_amsi_bypass_no_symbol_returns_empty() {
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

        let results = walk_amsi_bypass(&reader).unwrap();
        assert!(results.is_empty());
    }
}
