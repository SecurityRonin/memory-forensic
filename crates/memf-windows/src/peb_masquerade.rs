//! PEB image path masquerading detection.
//!
//! Detects processes that have modified their PEB `ImagePathName` or
//! `CommandLine` to masquerade as legitimate system processes. Malware
//! commonly overwrites PEB fields to appear as `svchost.exe`, `csrss.exe`,
//! or other system processes. This compares the PEB image path against the
//! `_EPROCESS.ImageFileName`.
//!
//! MITRE ATT&CK T1036.005 (Masquerading: Match Legitimate Name or Location).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;
use crate::{Error, Result};

/// High-value system process names that attackers commonly impersonate.
const HIGH_VALUE_TARGETS: &[&str] = &[
    "svchost.exe",
    "csrss.exe",
    "lsass.exe",
    "services.exe",
    "smss.exe",
    "wininit.exe",
    "explorer.exe",
];

/// Information about a potential PEB masquerade for a single process.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PebMasqueradeInfo {
    /// Process ID.
    pub pid: u32,
    /// Image file name from `_EPROCESS.ImageFileName`.
    pub eprocess_name: String,
    /// Image path from `_RTL_USER_PROCESS_PARAMETERS.ImagePathName`.
    pub peb_image_path: String,
    /// Command line from `_RTL_USER_PROCESS_PARAMETERS.CommandLine`.
    pub peb_command_line: String,
    /// Whether this process is likely masquerading.
    pub is_masquerading: bool,
}

/// Pure classifier: determine if a process is masquerading based on its
/// EPROCESS name and PEB image path.
///
/// Returns `true` (masquerading) when:
/// - The PEB image path filename differs from the EPROCESS name AND the
///   EPROCESS name matches a high-value target (svchost.exe, csrss.exe, etc.)
/// - The PEB image path is empty but the EPROCESS name is not (PEB wiped)
///
/// Returns `false` when:
/// - Both names match (case-insensitive)
/// - Both are empty
/// - Names differ but the EPROCESS name is not a high-value target
pub fn classify_peb_masquerade(eprocess_name: &str, peb_image_path: &str) -> bool {
    // Both empty — nothing to compare.
    if eprocess_name.is_empty() && peb_image_path.is_empty() {
        return false;
    }

    // PEB wiped: path is empty but EPROCESS has a name.
    if peb_image_path.is_empty() && !eprocess_name.is_empty() {
        return true;
    }

    // Extract filename from the PEB image path (last path component).
    let peb_filename = peb_image_path
        .rsplit('\\')
        .next()
        .or_else(|| peb_image_path.rsplit('/').next())
        .unwrap_or(peb_image_path);

    // Case-insensitive comparison.
    if eprocess_name.eq_ignore_ascii_case(peb_filename) {
        return false;
    }

    // Names differ — only flag as masquerading if the EPROCESS name is a
    // high-value target that attackers commonly impersonate.
    let eprocess_lower = eprocess_name.to_ascii_lowercase();
    HIGH_VALUE_TARGETS
        .iter()
        .any(|target| *target == eprocess_lower)
}

/// Walk a single process's PEB to detect image path masquerading.
///
/// Reads the PEB `ImagePathName` and `CommandLine` from
/// `_RTL_USER_PROCESS_PARAMETERS`, then classifies the result against the
/// EPROCESS `ImageFileName`.
///
/// Returns `Ok(None)` for kernel processes (PEB address is 0/null).
pub fn walk_peb_masquerade<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    eprocess_addr: u64,
    pid: u32,
    eprocess_name: &str,
) -> Result<Option<PebMasqueradeInfo>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // Pure classifier tests
    // ---------------------------------------------------------------

    #[test]
    fn classify_matching_names_benign() {
        // svchost.exe EPROCESS with matching PEB path → benign
        assert!(!classify_peb_masquerade(
            "svchost.exe",
            r"C:\Windows\System32\svchost.exe"
        ));
    }

    #[test]
    fn classify_svchost_masquerade_suspicious() {
        // EPROCESS says svchost.exe but PEB says notepad.exe → masquerade
        assert!(classify_peb_masquerade(
            "svchost.exe",
            r"C:\Users\evil\notepad.exe"
        ));
    }

    #[test]
    fn classify_csrss_masquerade_suspicious() {
        // EPROCESS says csrss.exe but PEB points to a completely different binary
        assert!(classify_peb_masquerade(
            "csrss.exe",
            r"C:\Temp\malware.exe"
        ));
    }

    #[test]
    fn classify_wiped_peb_suspicious() {
        // PEB image path is empty but EPROCESS has a name → PEB was wiped
        assert!(classify_peb_masquerade("svchost.exe", ""));
    }

    #[test]
    fn classify_non_system_mismatch_benign() {
        // EPROCESS says notepad.exe, PEB says calc.exe — mismatch but
        // notepad.exe is not a high-value target, so not flagged.
        assert!(!classify_peb_masquerade(
            "notepad.exe",
            r"C:\Windows\System32\calc.exe"
        ));
    }

    #[test]
    fn classify_case_insensitive_match_benign() {
        // Same name, different casing → benign
        assert!(!classify_peb_masquerade(
            "SVCHOST.EXE",
            r"C:\Windows\System32\svchost.exe"
        ));
    }

    #[test]
    fn classify_empty_both_benign() {
        // Both empty → nothing to flag
        assert!(!classify_peb_masquerade("", ""));
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn walk_no_peb_returns_none() {
        // The walker is not yet implemented; calling it should panic with
        // `todo!()`. This test verifies the RED state.
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0010_0000;
        let page_data = vec![0u8; 4096];

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &page_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // This will panic because walk_peb_masquerade is todo!()
        let _ = walk_peb_masquerade(&reader, vaddr, 4, "System");
    }
}
