//! Skeleton Key backdoor detection (MITRE ATT&CK T1556.001).
//!
//! The Skeleton Key attack patches LSASS process memory to install a master
//! password that works alongside every user's real password. Detection
//! involves scanning for known byte patterns in authentication DLLs
//! (`msv1_0.dll`, `kdcsvc.dll`, `cryptdll.dll`, `lsasrv.dll`) loaded by
//! `lsass.exe`.
//!
//! Key indicators:
//! - NOP sleds (0x90 repeated) in `msv1_0.dll` near `MsvpPasswordValidate`
//! - Patched conditional jumps (0xEB replacing 0x75) in `kdcsvc.dll`
//! - Modified RC4 init routines in `cryptdll.dll`
//! - Authentication bypass patches in `lsasrv.dll`

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{dll, process};

/// DLL modules targeted by the Skeleton Key attack.
const TARGET_MODULES: &[&str] = &["msv1_0.dll", "kdcsvc.dll", "cryptdll.dll", "lsasrv.dll"];

/// Minimum number of consecutive NOP bytes (0x90) to flag as a NOP sled.
///
/// 5 consecutive NOPs is too common in legitimate code (compiler padding etc.).
/// 16+ consecutive NOPs is a strong indicator of an actual attack-inserted NOP sled.
const NOP_SLED_THRESHOLD: usize = 16;

/// Number of bytes to read from each target DLL's .text section for scanning.
const TEXT_SECTION_SCAN_SIZE: usize = 4096;

/// A single Skeleton Key attack indicator found in LSASS process memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SkeletonKeyIndicator {
    /// Type of indicator (e.g., "auth_patch", "kdc_patch", "rc4_patch").
    pub indicator_type: String,
    /// Virtual address where the indicator was found.
    pub address: u64,
    /// DLL module where the indicator was found (e.g., "msv1_0.dll").
    pub module: String,
    /// Human-readable description of the indicator.
    pub description: String,
    /// Confidence score (0-100) for this indicator.
    pub confidence: u8,
    /// Whether a Skeleton Key indicator was positively detected.
    pub is_detected: bool,
}

/// Classify a Skeleton Key byte pattern based on the module and pattern type.
///
/// Returns a `(description, confidence)` tuple for known attack signatures.
/// Unknown combinations receive a generic description with lower confidence.
pub fn classify_skeleton_key_pattern(module: &str, pattern_type: &str) -> (String, u8) {
    match (module, pattern_type) {
        ("msv1_0.dll", "auth_patch") => ("MSV1_0 authentication bypass patch".into(), 90),
        ("kdcsvc.dll", "kdc_patch") => ("KDC service Kerberos validation bypass".into(), 90),
        ("cryptdll.dll", "rc4_patch") => ("RC4 HMAC encryption downgrade patch".into(), 80),
        ("lsasrv.dll", "auth_patch") => ("LSA Server authentication bypass".into(), 85),
        _ => ("Unknown modification".into(), 50),
    }
}

/// Scan lsass.exe process memory for Skeleton Key backdoor indicators.
///
/// Walks the process list to find `lsass.exe`, switches to its address space,
/// enumerates loaded DLLs, and scans authentication-critical modules for
/// known Skeleton Key byte patterns.
///
/// Returns an empty `Vec` if lsass.exe is not found or if the
/// `PsActiveProcessHead` symbol cannot be resolved.
pub fn walk_skeleton_key<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<SkeletonKeyIndicator>> {
    // Resolve PsActiveProcessHead; graceful degradation if missing.
    let ps_head = match reader.symbols().symbol_address("PsActiveProcessHead") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // Walk process list and find lsass.exe.
    let procs = match process::walk_processes(reader, ps_head) {
        Ok(p) => p,
        Err(_) => return Ok(Vec::new()),
    };

    let lsass = match procs
        .iter()
        .find(|p| p.image_name.eq_ignore_ascii_case("lsass.exe"))
    {
        Some(p) => p,
        None => return Ok(Vec::new()),
    };

    // Switch to lsass.exe's address space (CR3).
    if lsass.cr3 == 0 || lsass.peb_addr == 0 {
        return Ok(Vec::new());
    }
    let lsass_reader = reader.with_cr3(lsass.cr3);

    // Walk lsass.exe's loaded DLLs.
    let dlls = match dll::walk_dlls(&lsass_reader, lsass.peb_addr) {
        Ok(d) => d,
        Err(_) => return Ok(Vec::new()),
    };

    let mut indicators = Vec::new();

    for target_dll in &dlls {
        let dll_name_lower = target_dll.name.to_ascii_lowercase();
        if !TARGET_MODULES.contains(&dll_name_lower.as_str()) {
            continue;
        }

        // Check for non-standard load path (path masquerade).
        if is_suspicious_dll_path(&target_dll.full_path) {
            let (_desc, conf) = classify_skeleton_key_pattern(&dll_name_lower, "auth_patch");
            indicators.push(SkeletonKeyIndicator {
                indicator_type: "path_masquerade".into(),
                address: target_dll.base_addr,
                module: dll_name_lower.clone(),
                description: format!(
                    "{dll_name_lower} loaded from non-standard path: {}",
                    target_dll.full_path
                ),
                confidence: conf.saturating_sub(20),
                is_detected: true,
            });
        }

        // Read the first bytes of the DLL's in-memory image (.text section).
        // The .text section typically starts at offset 0x1000 from the base.
        let text_vaddr = target_dll.base_addr.wrapping_add(0x1000);
        let text_bytes = match lsass_reader.read_bytes(text_vaddr, TEXT_SECTION_SCAN_SIZE) {
            Ok(b) => b,
            Err(_) => continue,
        };

        // Scan for module-specific Skeleton Key patterns.
        scan_module_patterns(&dll_name_lower, text_vaddr, &text_bytes, &mut indicators);
    }

    Ok(indicators)
}

/// Check whether a DLL was loaded from a non-standard path.
///
/// Legitimate Windows system DLLs load from `\SystemRoot\System32\` or
/// `C:\Windows\System32\`. A module loaded from elsewhere may indicate
/// a DLL side-loading or masquerade attack.
fn is_suspicious_dll_path(full_path: &str) -> bool {
    let path_lower = full_path.to_ascii_lowercase();
    if path_lower.is_empty() {
        return false;
    }
    let standard_prefixes = [
        "c:\\windows\\system32\\",
        "\\systemroot\\system32\\",
        "\\??\\c:\\windows\\system32\\",
    ];
    !standard_prefixes.iter().any(|p| path_lower.starts_with(p))
}

/// Scan a target module's .text section bytes for Skeleton Key byte patterns.
fn scan_module_patterns(
    module: &str,
    text_vaddr: u64,
    text_bytes: &[u8],
    indicators: &mut Vec<SkeletonKeyIndicator>,
) {
    match module {
        "msv1_0.dll" => scan_nop_sled(module, "auth_patch", text_vaddr, text_bytes, indicators),
        "kdcsvc.dll" => scan_kdc_patterns(module, text_vaddr, text_bytes, indicators),
        "cryptdll.dll" => scan_nop_sled(module, "rc4_patch", text_vaddr, text_bytes, indicators),
        "lsasrv.dll" => scan_nop_sled(module, "auth_patch", text_vaddr, text_bytes, indicators),
        _ => {}
    }
}

/// Scan for NOP sled patterns (5+ consecutive 0x90 bytes).
///
/// The Skeleton Key attack patches authentication functions with NOP
/// instructions to bypass credential validation checks.
fn scan_nop_sled(
    module: &str,
    pattern_type: &str,
    text_vaddr: u64,
    text_bytes: &[u8],
    indicators: &mut Vec<SkeletonKeyIndicator>,
) {
    if let Some(offset) = find_nop_sled(text_bytes, NOP_SLED_THRESHOLD) {
        let (desc, conf) = classify_skeleton_key_pattern(module, pattern_type);
        indicators.push(SkeletonKeyIndicator {
            indicator_type: pattern_type.into(),
            address: text_vaddr.wrapping_add(offset as u64),
            module: module.into(),
            description: desc,
            confidence: conf,
            is_detected: true,
        });
    }
}

/// Scan kdcsvc.dll for patched conditional jumps.
///
/// The attack replaces `JNZ` (0x75) instructions with `JMP` (0xEB) near
/// `KdcVerifyPacSignature` to skip Kerberos PAC validation.
fn scan_kdc_patterns(
    module: &str,
    text_vaddr: u64,
    text_bytes: &[u8],
    indicators: &mut Vec<SkeletonKeyIndicator>,
) {
    if let Some(offset) = find_patched_conditional_jump(text_bytes) {
        let (desc, conf) = classify_skeleton_key_pattern(module, "kdc_patch");
        indicators.push(SkeletonKeyIndicator {
            indicator_type: "kdc_patch".into(),
            address: text_vaddr.wrapping_add(offset as u64),
            module: module.into(),
            description: desc,
            confidence: conf,
            is_detected: true,
        });
    }
}

/// Find a NOP sled of at least `min_count` consecutive 0x90 bytes.
///
/// Returns the byte offset of the first NOP in the sled, or `None`.
fn find_nop_sled(data: &[u8], min_count: usize) -> Option<usize> {
    let mut run_start = 0;
    let mut run_len = 0;
    for (i, &b) in data.iter().enumerate() {
        if b == 0x90 {
            if run_len == 0 {
                run_start = i;
            }
            run_len += 1;
            if run_len >= min_count {
                return Some(run_start);
            }
        } else {
            run_len = 0;
        }
    }
    None
}

/// Find a patched conditional jump: `0xEB` (JMP short) preceded by a
/// comparison-family opcode, suggesting it replaced a `0x75` (JNZ).
fn find_patched_conditional_jump(data: &[u8]) -> Option<usize> {
    for i in 1..data.len().saturating_sub(1) {
        if data[i] == 0xEB {
            let prev = data[i - 1];
            if matches!(prev, 0x83 | 0x85 | 0x3B | 0x84 | 0x39 | 0xF6 | 0xF7) {
                return Some(i);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_msv_patch() {
        let (desc, conf) = classify_skeleton_key_pattern("msv1_0.dll", "auth_patch");
        assert_eq!(desc, "MSV1_0 authentication bypass patch");
        assert_eq!(conf, 90);
    }

    #[test]
    fn classify_kdc_patch() {
        let (desc, conf) = classify_skeleton_key_pattern("kdcsvc.dll", "kdc_patch");
        assert_eq!(desc, "KDC service Kerberos validation bypass");
        assert_eq!(conf, 90);
    }

    #[test]
    fn classify_rc4_patch() {
        let (desc, conf) = classify_skeleton_key_pattern("cryptdll.dll", "rc4_patch");
        assert_eq!(desc, "RC4 HMAC encryption downgrade patch");
        assert_eq!(conf, 80);
    }

    #[test]
    fn classify_lsasrv_patch() {
        let (desc, conf) = classify_skeleton_key_pattern("lsasrv.dll", "auth_patch");
        assert_eq!(desc, "LSA Server authentication bypass");
        assert_eq!(conf, 85);
    }

    #[test]
    fn classify_unknown_pattern() {
        let (desc, conf) = classify_skeleton_key_pattern("foo.dll", "bar");
        assert_eq!(desc, "Unknown modification");
        assert_eq!(conf, 50);
    }

    #[test]
    fn walk_no_symbol_returns_empty() {
        // When PsActiveProcessHead is not in symbols, walker should return empty.
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Build an ISF with no PsActiveProcessHead symbol
        let isf = IsfBuilder::new()
            .add_struct("_EPROCESS", 2048)
            .add_field("_EPROCESS", "UniqueProcessId", 0x440, "pointer")
            .add_field("_EPROCESS", "ActiveProcessLinks", 0x448, "_LIST_ENTRY")
            .add_field("_EPROCESS", "ImageFileName", 0x5A8, "char")
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_skeleton_key(&reader).unwrap();
        assert!(
            results.is_empty(),
            "no PsActiveProcessHead should yield empty results"
        );
    }

    // ── walk_skeleton_key body coverage tests ──────────────────────────────

    /// Build a reader with the windows_kernel_preset and one EPROCESS for
    /// the given image_name. Returns the reader plus the head vaddr.
    ///
    /// EPROCESS layout (from windows_kernel_preset):
    ///   _KPROCESS.DirectoryTableBase at eproc + 0x28
    ///   CreateTime at 0x430, ExitTime at 0x438
    ///   UniqueProcessId at 0x440
    ///   ActiveProcessLinks at 0x448 (Flink@0, Blink@8)
    ///   InheritedFromUniqueProcessId at 0x540
    ///   Peb at 0x550
    ///   ImageFileName at 0x5A8
    fn make_reader_with_process(
        image_name: &str,
        pid: u64,
        cr3_val: u64,
        peb_val: u64,
    ) -> (ObjectReader<memf_core::test_builders::SyntheticPhysMem>, u64) {
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // PsActiveProcessHead symbol vaddr (from preset)
        let head_vaddr: u64  = 0xFFFFF805_5A400000;
        let head_paddr: u64  = 0x0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let eproc_paddr: u64 = 0x0020_0000;

        let elinks_vaddr = eproc_vaddr + 0x448;

        let name_bytes = image_name.as_bytes();
        let mut ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            // head.Flink → elinks_vaddr
            .write_phys_u64(head_paddr, elinks_vaddr)
            // head.Blink → elinks_vaddr
            .write_phys_u64(head_paddr + 8, elinks_vaddr)
            // _KPROCESS.DirectoryTableBase at eproc + 0x28
            .write_phys_u64(eproc_paddr + 0x28, cr3_val)
            // UniqueProcessId at 0x440
            .write_phys_u64(eproc_paddr + 0x440, pid)
            // ActiveProcessLinks.Flink → head_vaddr (circular: one-entry list)
            .write_phys_u64(eproc_paddr + 0x448, head_vaddr)
            // ActiveProcessLinks.Blink → head_vaddr
            .write_phys_u64(eproc_paddr + 0x448 + 8, head_vaddr)
            // InheritedFromUniqueProcessId
            .write_phys_u64(eproc_paddr + 0x540, 0)
            // Peb
            .write_phys_u64(eproc_paddr + 0x550, peb_val)
            // ImageFileName
            .write_phys(eproc_paddr + 0x5A8, name_bytes);
        if name_bytes.len() < 15 {
            ptb = ptb.write_phys(eproc_paddr + 0x5A8 + name_bytes.len() as u64, &[0]);
        }

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3_root, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3_root, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));
        (reader, head_vaddr)
    }

    /// Process list with no lsass.exe (e.g., only System) → returns empty.
    /// Covers lines 82-89: procs.find() returns None.
    #[test]
    fn walk_skeleton_key_no_lsass_returns_empty() {
        let (reader, _) = make_reader_with_process("System", 4, 0x1ab000, 0);
        let results = walk_skeleton_key(&reader).unwrap();
        assert!(results.is_empty(), "no lsass.exe → empty indicators");
    }

    /// lsass.exe found but cr3 == 0 → returns empty.
    /// Covers line 92: `if lsass.cr3 == 0 || lsass.peb_addr == 0`.
    #[test]
    fn walk_skeleton_key_lsass_zero_cr3_returns_empty() {
        let (reader, _) = make_reader_with_process("lsass.exe", 668, 0, 0x7FF0_0000);
        let results = walk_skeleton_key(&reader).unwrap();
        assert!(results.is_empty(), "lsass.exe with cr3=0 → empty indicators");
    }

    /// lsass.exe found with non-zero cr3 but peb_addr == 0 → returns empty.
    /// Covers line 92: second branch of `if lsass.cr3 == 0 || lsass.peb_addr == 0`.
    #[test]
    fn walk_skeleton_key_lsass_zero_peb_returns_empty() {
        let (reader, _) = make_reader_with_process("lsass.exe", 668, 0x1AB000, 0);
        let results = walk_skeleton_key(&reader).unwrap();
        assert!(results.is_empty(), "lsass.exe with peb_addr=0 → empty indicators");
    }

    /// lsass.exe found with valid cr3 and peb_addr, but DLL walk fails
    /// (peb_addr is unmapped) → walk_dlls returns Err → returns empty (line 98-101).
    #[test]
    fn walk_skeleton_key_lsass_dll_walk_fails_returns_empty() {
        // peb_addr is non-zero but points to unmapped memory → walk_dlls fails.
        let (reader, _) = make_reader_with_process("lsass.exe", 668, 0x1AB000, 0xFFFF_DEAD_0000);
        let results = walk_skeleton_key(&reader).unwrap();
        assert!(results.is_empty(), "lsass.exe with unmapped PEB → empty indicators");
    }

    // -- find_nop_sled tests -------------------------------------------------

    #[test]
    fn find_nop_sled_not_found_empty() {
        assert_eq!(find_nop_sled(&[], 5), None);
    }

    #[test]
    fn find_nop_sled_not_enough_nops() {
        // Only 4 consecutive NOPs, threshold is 5 — should return None.
        let data = [0x55u8, 0x90, 0x90, 0x90, 0x90, 0x48];
        assert_eq!(find_nop_sled(&data, 5), None);
    }

    #[test]
    fn find_nop_sled_exact_threshold() {
        // Exactly 5 NOPs starting at index 1.
        let data = [0x55u8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x48];
        assert_eq!(find_nop_sled(&data, 5), Some(1));
    }

    #[test]
    fn find_nop_sled_returns_first_occurrence() {
        // First sled starts at index 0 (5 NOPs), second starts at index 8.
        let data = [0x90u8, 0x90, 0x90, 0x90, 0x90, 0x48, 0x89, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90];
        assert_eq!(find_nop_sled(&data, 5), Some(0));
    }

    #[test]
    fn find_nop_sled_no_nops_in_data() {
        let data = [0x55u8, 0x48, 0x89, 0xE5, 0x41, 0x57];
        assert_eq!(find_nop_sled(&data, 5), None);
    }

    #[test]
    fn find_nop_sled_all_nops() {
        let data = [0x90u8; 10];
        assert_eq!(find_nop_sled(&data, 5), Some(0));
    }

    // -- find_patched_conditional_jump tests ---------------------------------

    #[test]
    fn find_patched_jump_not_found_empty() {
        assert_eq!(find_patched_conditional_jump(&[]), None);
    }

    #[test]
    fn find_patched_jump_eb_after_cmp() {
        // 0x3B (cmp r/m) followed by 0xEB (short jmp) — matches.
        let data = [0x48u8, 0x3B, 0xEB, 0x05, 0x00];
        assert_eq!(find_patched_conditional_jump(&data), Some(2));
    }

    #[test]
    fn find_patched_jump_eb_after_test() {
        // 0x85 (test) followed by 0xEB — matches.
        let data = [0x85u8, 0xEB, 0x10];
        assert_eq!(find_patched_conditional_jump(&data), Some(1));
    }

    #[test]
    fn find_patched_jump_eb_after_unrelated() {
        // 0xEB after an unrelated byte (0x48, MOV prefix) — not a match.
        let data = [0x48u8, 0xEB, 0x05];
        assert_eq!(find_patched_conditional_jump(&data), None);
    }

    #[test]
    fn find_patched_jump_eb_after_f7() {
        // 0xF7 (test r/m32) followed by 0xEB — matches.
        let data = [0x00u8, 0xF7, 0xEB, 0x08];
        assert_eq!(find_patched_conditional_jump(&data), Some(2));
    }

    #[test]
    fn find_patched_jump_eb_after_84() {
        // 0x84 (test r/m8, r8) followed by 0xEB — matches.
        let data = [0x00u8, 0x84, 0xEB, 0x08];
        assert_eq!(find_patched_conditional_jump(&data), Some(2));
    }

    #[test]
    fn find_patched_jump_eb_after_83() {
        // 0x83 (cmp r/m, imm8) followed by 0xEB — matches.
        let data = [0x00u8, 0x83, 0xEB, 0x00];
        assert_eq!(find_patched_conditional_jump(&data), Some(2));
    }

    #[test]
    fn find_patched_jump_eb_after_39() {
        // 0x39 (cmp r/m, r) followed by 0xEB — matches.
        let data = [0x00u8, 0x39, 0xEB, 0x08];
        assert_eq!(find_patched_conditional_jump(&data), Some(2));
    }

    #[test]
    fn find_patched_jump_no_eb_at_all() {
        let data = [0x48u8, 0x83, 0xC0, 0x01, 0x75, 0x0A];
        assert_eq!(find_patched_conditional_jump(&data), None);
    }

    // -- is_suspicious_dll_path tests ----------------------------------------

    #[test]
    fn suspicious_path_standard_system32_benign() {
        assert!(!is_suspicious_dll_path("C:\\Windows\\System32\\msv1_0.dll"));
        assert!(!is_suspicious_dll_path("c:\\windows\\system32\\ntdll.dll"));
    }

    #[test]
    fn suspicious_path_systemroot_benign() {
        assert!(!is_suspicious_dll_path("\\SystemRoot\\System32\\msv1_0.dll"));
    }

    #[test]
    fn suspicious_path_device_prefix_benign() {
        assert!(!is_suspicious_dll_path("\\??\\C:\\Windows\\System32\\lsasrv.dll"));
    }

    #[test]
    fn suspicious_path_temp_suspicious() {
        assert!(is_suspicious_dll_path("C:\\Temp\\msv1_0.dll"));
    }

    #[test]
    fn suspicious_path_appdata_suspicious() {
        assert!(is_suspicious_dll_path("C:\\Users\\evil\\AppData\\Roaming\\msv1_0.dll"));
    }

    #[test]
    fn suspicious_path_empty_benign() {
        // Empty path returns false (not suspicious, treated as unknown).
        assert!(!is_suspicious_dll_path(""));
    }

    // -- scan_module_patterns tests ------------------------------------------

    #[test]
    fn scan_module_patterns_msv_with_nop_sled() {
        let mut indicators = Vec::new();
        // Need at least NOP_SLED_THRESHOLD (16) consecutive NOPs to trigger.
        let mut data = vec![0x55u8; 20];
        data[4..20].fill(0x90); // 16 NOPs at offset 4
        scan_module_patterns("msv1_0.dll", 0x1000_0000, &data, &mut indicators);
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].indicator_type, "auth_patch");
        assert_eq!(indicators[0].module, "msv1_0.dll");
        assert!(indicators[0].is_detected);
    }

    #[test]
    fn scan_module_patterns_msv_no_nop_sled() {
        let mut indicators = Vec::new();
        let data = vec![0x48u8, 0x89, 0xC3, 0x55, 0x41]; // no NOPs
        scan_module_patterns("msv1_0.dll", 0x1000_0000, &data, &mut indicators);
        assert!(indicators.is_empty());
    }

    #[test]
    fn scan_module_patterns_kdcsvc_with_patched_jump() {
        let mut indicators = Vec::new();
        // 0x3B (cmp) then 0xEB (patched jmp) at index 1
        let data = [0x3Bu8, 0xEB, 0x08, 0x00, 0x00];
        scan_module_patterns("kdcsvc.dll", 0x2000_0000, &data, &mut indicators);
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].indicator_type, "kdc_patch");
    }

    #[test]
    fn scan_module_patterns_cryptdll_with_nop_sled() {
        let mut indicators = Vec::new();
        let data = [0x90u8; 16]; // exactly NOP_SLED_THRESHOLD
        scan_module_patterns("cryptdll.dll", 0x3000_0000, &data, &mut indicators);
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].indicator_type, "rc4_patch");
    }

    #[test]
    fn scan_module_patterns_lsasrv_with_nop_sled() {
        let mut indicators = Vec::new();
        let data = [0x90u8; 16]; // exactly NOP_SLED_THRESHOLD
        scan_module_patterns("lsasrv.dll", 0x4000_0000, &data, &mut indicators);
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].indicator_type, "auth_patch");
        assert_eq!(indicators[0].module, "lsasrv.dll");
    }

    #[test]
    fn scan_module_patterns_unknown_module_no_crash() {
        let mut indicators = Vec::new();
        let data = [0x90u8; 8];
        scan_module_patterns("unknown.dll", 0x5000_0000, &data, &mut indicators);
        // Unknown modules produce no indicators.
        assert!(indicators.is_empty());
    }

    /// TARGET_MODULES constant check.
    #[test]
    fn target_modules_constant() {
        assert!(TARGET_MODULES.contains(&"msv1_0.dll"));
        assert!(TARGET_MODULES.contains(&"kdcsvc.dll"));
        assert!(TARGET_MODULES.contains(&"cryptdll.dll"));
        assert!(TARGET_MODULES.contains(&"lsasrv.dll"));
        assert_eq!(TARGET_MODULES.len(), 4);
    }

    /// NOP_SLED_THRESHOLD and TEXT_SECTION_SCAN_SIZE constants.
    #[test]
    fn constants_sane() {
        assert_eq!(NOP_SLED_THRESHOLD, 16);
        assert_eq!(TEXT_SECTION_SCAN_SIZE, 4096);
    }

    /// is_suspicious_dll_path: comprehensive coverage of all branches.
    #[test]
    fn suspicious_path_comprehensive() {
        assert!(!is_suspicious_dll_path("C:\\Windows\\System32\\msv1_0.dll"));
        assert!(!is_suspicious_dll_path("\\SystemRoot\\System32\\lsasrv.dll"));
        assert!(!is_suspicious_dll_path("\\??\\C:\\Windows\\System32\\kdcsvc.dll"));
        assert!(!is_suspicious_dll_path(""));
        assert!(is_suspicious_dll_path("C:\\evil\\msv1_0.dll"));
        assert!(is_suspicious_dll_path("C:\\Users\\attacker\\cryptdll.dll"));
        assert!(is_suspicious_dll_path("D:\\Temp\\msv1_0.dll"));
    }

    /// SkeletonKeyIndicator clone works correctly.
    #[test]
    fn indicator_clone() {
        let ind = SkeletonKeyIndicator {
            indicator_type: "auth_patch".into(),
            address: 0x1000,
            module: "msv1_0.dll".into(),
            description: "test desc".into(),
            confidence: 90,
            is_detected: true,
        };
        let cloned = ind.clone();
        assert_eq!(cloned.indicator_type, ind.indicator_type);
        assert_eq!(cloned.address, ind.address);
        assert_eq!(cloned.confidence, ind.confidence);
    }

    /// scan_module_patterns: unknown module produces no indicators even with NOPs.
    #[test]
    fn scan_module_patterns_unknown_nop_no_indicator() {
        let mut indicators = Vec::new();
        let data = [0x90u8; 10];
        scan_module_patterns("unknown_module.dll", 0x5000_0000, &data, &mut indicators);
        assert!(indicators.is_empty(), "unknown module → no indicators");
    }

    /// find_nop_sled: single NOP (below threshold of 5) → None.
    #[test]
    fn find_nop_sled_single_nop_below_threshold() {
        assert_eq!(find_nop_sled(&[0x90u8], 5), None);
    }

    /// find_nop_sled: run of 4 followed by break, then 5 → finds second run.
    #[test]
    fn find_nop_sled_second_run_found() {
        let mut data = vec![0x90u8; 4];
        data.push(0x48); // break
        data.extend_from_slice(&[0x90u8; 5]);
        // First run (4) is < threshold, second run (5) starts at index 5.
        assert_eq!(find_nop_sled(&data, 5), Some(5));
    }

    /// find_patched_conditional_jump: tests all matching opcodes.
    #[test]
    fn find_patched_jump_all_matching_opcodes() {
        for prev in [0x83u8, 0x85, 0x3B, 0x84, 0x39, 0xF6, 0xF7] {
            let data = [0x00u8, prev, 0xEB, 0x00];
            let result = find_patched_conditional_jump(&data);
            assert_eq!(result, Some(2), "opcode 0x{prev:02X} should match");
        }
    }

    /// find_patched_conditional_jump: EB at index 0 (no prev byte) → None.
    #[test]
    fn find_patched_jump_eb_at_start_no_prev() {
        let data = [0xEB, 0x05, 0x83, 0x00];
        // Loop starts at i=1, so i=0 is never a candidate.
        assert_eq!(find_patched_conditional_jump(&data), None);
    }

    /// find_patched_conditional_jump: data of length 1 → None (loop condition).
    #[test]
    fn find_patched_jump_one_byte_data() {
        assert_eq!(find_patched_conditional_jump(&[0xEB]), None);
    }

    #[test]
    fn indicator_serializes() {
        let indicator = SkeletonKeyIndicator {
            indicator_type: "auth_patch".into(),
            address: 0x7FFE_0001_0000,
            module: "msv1_0.dll".into(),
            description: "MSV1_0 authentication bypass patch".into(),
            confidence: 90,
            is_detected: true,
        };

        let json = serde_json::to_string(&indicator).unwrap();
        assert!(json.contains("auth_patch"));
        assert!(json.contains("msv1_0.dll"));
        assert!(json.contains("90"));
        assert!(json.contains("true"));
        assert!(json.contains("MSV1_0 authentication bypass patch"));
    }
}
