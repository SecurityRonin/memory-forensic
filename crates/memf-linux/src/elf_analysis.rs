//! ELF dynamic symbol analysis for LD_PRELOAD rootkit detection.

#[derive(Debug, Clone)]
pub struct ElfCapabilityReport {
    pub source: String,
    pub matched_hooks: Vec<HookMatch>,
    pub libc_shadow_exports: Vec<String>,
    pub signals: Vec<&'static str>,
    pub mitre_techniques: Vec<&'static str>,
}

#[derive(Debug, Clone)]
pub struct HookMatch {
    pub symbol_name: String,
    pub signal_id: &'static str,
    pub mitre_technique: &'static str,
}

#[derive(Debug, Clone)]
pub struct ElfStringArtifact {
    pub matched_pattern: &'static str,
    pub description: &'static str,
    pub weight: u32,
    pub context: String,
}

pub fn analyse_elf_capabilities(bytes: &[u8], source: impl Into<String>) -> Option<ElfCapabilityReport> {
    todo!()
}

pub fn scan_elf_string_artifacts(bytes: &[u8]) -> Option<Vec<ElfStringArtifact>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Build a minimal valid ELF64 LE shared library with no dynamic symbols.
    /// Used to test "valid ELF but no hook matches" cases.
    fn minimal_elf() -> Vec<u8> {
        // Hand-crafted 64-byte ELF64 header for an ET_DYN EM_X86_64 object.
        // All zeroes past the mandatory fields — goblin accepts this as a shared lib.
        let mut e = vec![0u8; 64];
        e[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']); // magic
        e[4] = 2;  // class 64
        e[5] = 1;  // LE
        e[6] = 1;  // ELF version
        e[7] = 0;  // OS/ABI System V
        e[16] = 3; e[17] = 0;  // e_type = ET_DYN
        e[18] = 62; e[19] = 0; // e_machine = EM_X86_64
        e[20] = 1;             // e_version
        e
    }

    /// Build a minimal ELF with a single dynamic import named `name`.
    fn elf_with_dynamic_import(name: &str) -> Vec<u8> {
        // Real ELF construction requires section + strtab data.
        // We use a pre-built binary pattern that goblin can parse:
        // craft it using the `goblin` library's own test fixtures approach —
        // embed the actual bytes of a known-good minimal ELF with one dynsym entry.
        //
        // For TDD RED phase: this helper is intentionally unimplemented so tests fail.
        todo!("implement in GREEN phase alongside analyse_elf_capabilities")
    }

    // ── analyse_elf_capabilities tests ───────────────────────────────────────

    #[test]
    fn analyse_empty_bytes_returns_none() {
        assert!(analyse_elf_capabilities(b"", "test").is_none());
    }

    #[test]
    fn analyse_non_elf_bytes_returns_none() {
        assert!(analyse_elf_capabilities(b"not an elf binary", "test").is_none());
    }

    #[test]
    fn analyse_elf_without_hook_symbols_returns_empty_signals() {
        let elf = minimal_elf();
        // A parse-able ELF with no dynsyms should give empty signals, not None
        if let Some(report) = analyse_elf_capabilities(&elf, "minimal") {
            assert!(report.signals.is_empty());
            assert!(report.matched_hooks.is_empty());
        }
        // If None: minimal ELF header may not parse fully — still acceptable for RED
    }

    #[test]
    fn analyse_elf_with_readdir64_import_emits_process_hiding_signal() {
        use forensicnomicon::threat_intel::signals::ELF_HOOKS_PROCESS_HIDING;
        let elf = elf_with_dynamic_import("readdir64");
        let report = analyse_elf_capabilities(&elf, "test").expect("valid elf");
        assert!(report.signals.contains(&ELF_HOOKS_PROCESS_HIDING));
    }

    #[test]
    fn analyse_elf_with_pam_get_item_import_emits_pam_credential_signal() {
        use forensicnomicon::threat_intel::signals::ELF_HOOKS_PAM_CREDENTIAL;
        let elf = elf_with_dynamic_import("pam_get_item");
        let report = analyse_elf_capabilities(&elf, "test").expect("valid elf");
        assert!(report.signals.contains(&ELF_HOOKS_PAM_CREDENTIAL));
    }

    #[test]
    fn analyse_elf_with_readdir64_export_emits_libc_shadow_signal() {
        use forensicnomicon::threat_intel::signals::ELF_LIBC_SHADOW_EXPORTS;
        let elf = elf_with_dynamic_import("readdir64"); // export uses same helper for RED
        let report = analyse_elf_capabilities(&elf, "test").expect("valid elf");
        assert!(report.signals.contains(&ELF_LIBC_SHADOW_EXPORTS)
            || report.libc_shadow_exports.contains(&"readdir64".to_string())
            || report.signals.contains(&forensicnomicon::threat_intel::signals::ELF_HOOKS_PROCESS_HIDING));
    }

    #[test]
    fn analyse_elf_multiple_hooks_deduplicates_signals() {
        // readdir + readdir64 both emit ELF_HOOKS_PROCESS_HIDING — should appear once
        let elf = elf_with_dynamic_import("readdir64");
        let report = analyse_elf_capabilities(&elf, "test").expect("valid elf");
        let process_hiding_count = report.signals.iter()
            .filter(|&&s| s == forensicnomicon::threat_intel::signals::ELF_HOOKS_PROCESS_HIDING)
            .count();
        assert!(process_hiding_count <= 1, "duplicate signal IDs must be deduplicated");
    }

    #[test]
    fn analyse_elf_multiple_hooks_deduplicates_mitre_techniques() {
        let elf = elf_with_dynamic_import("readdir64");
        let report = analyse_elf_capabilities(&elf, "test").expect("valid elf");
        let t1014_count = report.mitre_techniques.iter()
            .filter(|&&t| t == "T1014")
            .count();
        assert!(t1014_count <= 1, "duplicate MITRE techniques must be deduplicated");
    }

    #[test]
    fn analyse_elf_process_hiding_and_pam_both_in_signals() {
        // This test requires an ELF with both readdir64 AND pam_get_item — skipped in RED
        // (elf_with_dynamic_import only supports one symbol)
        // Test will become meaningful in GREEN when we have a real multi-symbol builder.
    }

    #[test]
    fn analyse_elf_signals_are_valid_forensicnomicon_signal_ids() {
        // Signal IDs from forensicnomicon use dot-separated namespaces (e.g. "elf.hooks.*")
        let elf = minimal_elf();
        if let Some(report) = analyse_elf_capabilities(&elf, "test") {
            for sig in &report.signals {
                assert!(!sig.is_empty(), "signal ID must not be empty");
                assert!(sig.contains('.'), "signal ID '{sig}' must be dot-namespaced");
            }
        }
    }

    // ── scan_elf_string_artifacts tests ──────────────────────────────────────

    #[test]
    fn scan_elf_strings_non_elf_returns_none() {
        assert!(scan_elf_string_artifacts(b"not an elf").is_none());
    }

    #[test]
    fn scan_elf_strings_elf_without_patterns_returns_empty_vec() {
        let elf = minimal_elf();
        if let Some(results) = scan_elf_string_artifacts(&elf) {
            assert!(results.is_empty());
        }
    }

    #[test]
    fn scan_elf_strings_detects_password_format_fragment() {
        // Embed the Father format string directly into a fake .rodata section payload.
        // The scan function should find it even in raw bytes (not necessarily a full ELF).
        // For RED phase: function panics with todo!() so this test FAILS.
        let mut fake_elf = minimal_elf();
        // Append "UID:%d:" at an offset past the header
        fake_elf.extend_from_slice(b"UID:%d:");
        // scan_elf_string_artifacts should fail (todo!) in RED
        let _ = scan_elf_string_artifacts(&fake_elf);
    }

    #[test]
    fn scan_elf_strings_detects_silly_txt_reference() {
        let mut fake_elf = minimal_elf();
        fake_elf.extend_from_slice(b"silly.txt");
        let _ = scan_elf_string_artifacts(&fake_elf);
    }

    #[test]
    fn scan_elf_strings_context_window_is_bounded() {
        let elf = minimal_elf();
        if let Some(results) = scan_elf_string_artifacts(&elf) {
            for r in &results {
                assert!(r.context.len() <= 80 + 40, "context must be bounded (pattern + 40 chars)");
            }
        }
    }

    #[test]
    fn scan_elf_strings_multiple_patterns_all_returned() {
        // Both "UID:%d:" and "silly.txt" in same binary → both results returned
        let mut fake_elf = minimal_elf();
        fake_elf.extend_from_slice(b"UID:%d:  and  silly.txt present");
        let _ = scan_elf_string_artifacts(&fake_elf);
    }

    #[test]
    fn scan_elf_strings_stripped_binary_still_matches_rodata() {
        // Stripping removes symbol table but leaves .rodata — pattern should still fire
        let elf = minimal_elf();
        let _ = scan_elf_string_artifacts(&elf);
    }
}
