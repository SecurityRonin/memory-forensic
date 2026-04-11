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
        todo!()
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
        todo!()
    }

    #[test]
    fn classify_svchost_masquerade_suspicious() {
        todo!()
    }

    #[test]
    fn classify_csrss_masquerade_suspicious() {
        todo!()
    }

    #[test]
    fn classify_wiped_peb_suspicious() {
        todo!()
    }

    #[test]
    fn classify_non_system_mismatch_benign() {
        todo!()
    }

    #[test]
    fn classify_case_insensitive_match_benign() {
        todo!()
    }

    #[test]
    fn classify_empty_both_benign() {
        todo!()
    }

    // ---------------------------------------------------------------
    // Walker tests
    // ---------------------------------------------------------------

    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Encode a Rust &str as UTF-16LE bytes.
    fn utf16le_bytes(s: &str) -> Vec<u8> {
        todo!()
    }

    /// Build a _UNICODE_STRING in a byte buffer at the given offset.
    /// Layout: [offset..+2] Length, [offset+2..+4] MaximumLength,
    ///         [offset+8..+16] Buffer pointer.
    fn build_unicode_string_at(buf: &mut [u8], offset: usize, length: u16, buffer_ptr: u64) {
        todo!()
    }

    fn make_win_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        todo!()
    }

    // Offsets from windows_kernel_preset:
    const EPROCESS_PEB: u64 = 0x550;
    const PEB_PROCESS_PARAMETERS: u64 = 0x20;
    const PARAMS_IMAGE_PATH_NAME: u64 = 0x60;
    const PARAMS_COMMAND_LINE: u64 = 0x70;

    #[test]
    fn walk_no_peb_returns_none() {
        todo!()
    }

    #[test]
    fn walk_detects_masquerade() {
        todo!()
    }

    #[test]
    fn walk_benign_process() {
        todo!()
    }
}
