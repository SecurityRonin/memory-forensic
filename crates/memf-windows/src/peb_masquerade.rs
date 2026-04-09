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
    // Read PEB address from _EPROCESS.Peb
    let peb_addr: u64 = reader.read_field(eprocess_addr, "_EPROCESS", "Peb")?;

    // Kernel processes have no PEB (address is 0/null).
    if peb_addr == 0 {
        return Ok(None);
    }

    // Read PEB.ProcessParameters pointer.
    let params_ptr: u64 = reader.read_field(peb_addr, "_PEB", "ProcessParameters")?;
    if params_ptr == 0 {
        return Ok(None);
    }

    // Resolve ImagePathName offset within _RTL_USER_PROCESS_PARAMETERS.
    let image_path_offset = reader
        .symbols()
        .field_offset("_RTL_USER_PROCESS_PARAMETERS", "ImagePathName")
        .ok_or_else(|| {
            Error::Walker(
                "missing _RTL_USER_PROCESS_PARAMETERS.ImagePathName offset".into(),
            )
        })?;
    let image_path_ustr_addr = params_ptr.wrapping_add(image_path_offset);
    let peb_image_path = read_unicode_string(reader, image_path_ustr_addr)?;

    // Resolve CommandLine offset within _RTL_USER_PROCESS_PARAMETERS.
    let cmdline_offset = reader
        .symbols()
        .field_offset("_RTL_USER_PROCESS_PARAMETERS", "CommandLine")
        .ok_or_else(|| {
            Error::Walker(
                "missing _RTL_USER_PROCESS_PARAMETERS.CommandLine offset".into(),
            )
        })?;
    let cmdline_ustr_addr = params_ptr.wrapping_add(cmdline_offset);
    let peb_command_line = read_unicode_string(reader, cmdline_ustr_addr)?;

    // Classify the result.
    let is_masquerading = classify_peb_masquerade(eprocess_name, &peb_image_path);

    Ok(Some(PebMasqueradeInfo {
        pid,
        eprocess_name: eprocess_name.to_string(),
        peb_image_path,
        peb_command_line,
        is_masquerading,
    }))
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
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// Build a _UNICODE_STRING in a byte buffer at the given offset.
    /// Layout: [offset..+2] Length, [offset+2..+4] MaximumLength,
    ///         [offset+8..+16] Buffer pointer.
    fn build_unicode_string_at(buf: &mut [u8], offset: usize, length: u16, buffer_ptr: u64) {
        buf[offset..offset + 2].copy_from_slice(&length.to_le_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&length.to_le_bytes());
        buf[offset + 8..offset + 16].copy_from_slice(&buffer_ptr.to_le_bytes());
    }

    fn make_win_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    // Offsets from windows_kernel_preset:
    const EPROCESS_PEB: u64 = 0x550;
    const PEB_PROCESS_PARAMETERS: u64 = 0x20;
    const PARAMS_IMAGE_PATH_NAME: u64 = 0x60;
    const PARAMS_COMMAND_LINE: u64 = 0x70;

    #[test]
    fn walk_no_peb_returns_none() {
        // EPROCESS with Peb = 0 → kernel process, should return None.
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_paddr: u64 = 0x0010_0000;

        // Zero-filled page: Peb field at offset 0x550 is 0.
        let page_data = vec![0u8; 4096];

        let ptb = PageTableBuilder::new()
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys(eproc_paddr, &page_data);

        let reader = make_win_reader(ptb);
        let result = walk_peb_masquerade(&reader, eproc_vaddr, 4, "System").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn walk_detects_masquerade() {
        // Layout:
        //   Page 1 (eproc): _EPROCESS with Peb pointing to page 2
        //   Page 2 (peb):   PEB + _RTL_USER_PROCESS_PARAMETERS + string data
        //
        // EPROCESS name is "svchost.exe" but PEB ImagePathName points to
        // "C:\Temp\evil.exe" → masquerade detected.

        let eproc_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_paddr: u64 = 0x0010_0000;
        let peb_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let peb_paddr: u64 = 0x0020_0000;

        // Build EPROCESS page: write PEB pointer at offset 0x550.
        let mut eproc_data = vec![0u8; 4096];
        eproc_data[EPROCESS_PEB as usize..EPROCESS_PEB as usize + 8]
            .copy_from_slice(&peb_vaddr.to_le_bytes());

        // Build PEB page:
        //   [0x20..0x28]: ProcessParameters pointer → same page at offset 0x100
        //   [0x100 + 0x60]: ImagePathName UNICODE_STRING
        //   [0x100 + 0x70]: CommandLine UNICODE_STRING
        //   String data at offset 0x400 and 0x500
        let params_offset: usize = 0x100;
        let params_vaddr = peb_vaddr + params_offset as u64;

        let image_path = r"C:\Temp\evil.exe";
        let image_path_utf16 = utf16le_bytes(image_path);
        let image_path_len = image_path_utf16.len() as u16;
        let image_path_str_offset: usize = 0x400;
        let image_path_str_vaddr = peb_vaddr + image_path_str_offset as u64;

        let cmdline = r"C:\Temp\evil.exe --payload";
        let cmdline_utf16 = utf16le_bytes(cmdline);
        let cmdline_len = cmdline_utf16.len() as u16;
        let cmdline_str_offset: usize = 0x500;
        let cmdline_str_vaddr = peb_vaddr + cmdline_str_offset as u64;

        let mut peb_data = vec![0u8; 4096];

        // PEB.ProcessParameters pointer
        peb_data[PEB_PROCESS_PARAMETERS as usize..PEB_PROCESS_PARAMETERS as usize + 8]
            .copy_from_slice(&params_vaddr.to_le_bytes());

        // ImagePathName UNICODE_STRING at ProcessParameters + 0x60
        build_unicode_string_at(
            &mut peb_data,
            params_offset + PARAMS_IMAGE_PATH_NAME as usize,
            image_path_len,
            image_path_str_vaddr,
        );

        // CommandLine UNICODE_STRING at ProcessParameters + 0x70
        build_unicode_string_at(
            &mut peb_data,
            params_offset + PARAMS_COMMAND_LINE as usize,
            cmdline_len,
            cmdline_str_vaddr,
        );

        // String data
        peb_data[image_path_str_offset..image_path_str_offset + image_path_utf16.len()]
            .copy_from_slice(&image_path_utf16);
        peb_data[cmdline_str_offset..cmdline_str_offset + cmdline_utf16.len()]
            .copy_from_slice(&cmdline_utf16);

        let ptb = PageTableBuilder::new()
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys(eproc_paddr, &eproc_data)
            .map_4k(peb_vaddr, peb_paddr, flags::WRITABLE)
            .write_phys(peb_paddr, &peb_data);

        let reader = make_win_reader(ptb);
        let result = walk_peb_masquerade(&reader, eproc_vaddr, 1234, "svchost.exe")
            .unwrap()
            .expect("should return Some for process with PEB");

        assert_eq!(result.pid, 1234);
        assert_eq!(result.eprocess_name, "svchost.exe");
        assert_eq!(result.peb_image_path, image_path);
        assert_eq!(result.peb_command_line, cmdline);
        assert!(result.is_masquerading);
    }

    #[test]
    fn walk_benign_process() {
        // EPROCESS name matches PEB ImagePathName → not masquerading.
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_paddr: u64 = 0x0010_0000;
        let peb_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let peb_paddr: u64 = 0x0020_0000;

        let mut eproc_data = vec![0u8; 4096];
        eproc_data[EPROCESS_PEB as usize..EPROCESS_PEB as usize + 8]
            .copy_from_slice(&peb_vaddr.to_le_bytes());

        let params_offset: usize = 0x100;
        let params_vaddr = peb_vaddr + params_offset as u64;

        let image_path = r"C:\Windows\System32\svchost.exe";
        let image_path_utf16 = utf16le_bytes(image_path);
        let image_path_len = image_path_utf16.len() as u16;
        let image_path_str_offset: usize = 0x400;
        let image_path_str_vaddr = peb_vaddr + image_path_str_offset as u64;

        let cmdline = r"C:\Windows\System32\svchost.exe -k netsvcs";
        let cmdline_utf16 = utf16le_bytes(cmdline);
        let cmdline_len = cmdline_utf16.len() as u16;
        let cmdline_str_offset: usize = 0x500;
        let cmdline_str_vaddr = peb_vaddr + cmdline_str_offset as u64;

        let mut peb_data = vec![0u8; 4096];
        peb_data[PEB_PROCESS_PARAMETERS as usize..PEB_PROCESS_PARAMETERS as usize + 8]
            .copy_from_slice(&params_vaddr.to_le_bytes());

        build_unicode_string_at(
            &mut peb_data,
            params_offset + PARAMS_IMAGE_PATH_NAME as usize,
            image_path_len,
            image_path_str_vaddr,
        );
        build_unicode_string_at(
            &mut peb_data,
            params_offset + PARAMS_COMMAND_LINE as usize,
            cmdline_len,
            cmdline_str_vaddr,
        );

        peb_data[image_path_str_offset..image_path_str_offset + image_path_utf16.len()]
            .copy_from_slice(&image_path_utf16);
        peb_data[cmdline_str_offset..cmdline_str_offset + cmdline_utf16.len()]
            .copy_from_slice(&cmdline_utf16);

        let ptb = PageTableBuilder::new()
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys(eproc_paddr, &eproc_data)
            .map_4k(peb_vaddr, peb_paddr, flags::WRITABLE)
            .write_phys(peb_paddr, &peb_data);

        let reader = make_win_reader(ptb);
        let result = walk_peb_masquerade(&reader, eproc_vaddr, 800, "svchost.exe")
            .unwrap()
            .expect("should return Some for process with PEB");

        assert_eq!(result.pid, 800);
        assert_eq!(result.eprocess_name, "svchost.exe");
        assert_eq!(result.peb_image_path, image_path);
        assert!(!result.is_masquerading);
    }
}
