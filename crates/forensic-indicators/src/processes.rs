/// Legitimate Windows process names commonly masqueraded by attackers.
pub const WINDOWS_MASQUERADE_TARGETS: &[&str] = &[];

/// Well-known malware / offensive-tool process names.
pub const KNOWN_MALWARE_PROCESS_NAMES: &[&str] = &[];

/// Returns `true` if `name` is a high-value masquerade target (case-insensitive).
pub fn is_masquerade_target(_name: &str) -> bool {
    false
}

/// Returns `true` if `name` matches a known malware process name (case-insensitive).
pub fn is_known_malware_process(_name: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- constant membership ---
    #[test]
    fn masquerade_targets_contains_svchost() {
        assert!(WINDOWS_MASQUERADE_TARGETS.contains(&"svchost.exe"));
    }

    #[test]
    fn masquerade_targets_contains_lsass() {
        assert!(WINDOWS_MASQUERADE_TARGETS.contains(&"lsass.exe"));
    }

    #[test]
    fn malware_names_contains_mimikatz() {
        assert!(KNOWN_MALWARE_PROCESS_NAMES.contains(&"mimikatz"));
    }

    #[test]
    fn malware_names_contains_xmrig() {
        assert!(KNOWN_MALWARE_PROCESS_NAMES.contains(&"xmrig"));
    }

    // --- is_masquerade_target ---
    #[test]
    fn detects_svchost_lowercase() {
        assert!(is_masquerade_target("svchost.exe"));
    }

    #[test]
    fn detects_lsass_uppercase() {
        assert!(is_masquerade_target("LSASS.EXE"));
    }

    #[test]
    fn detects_explorer_mixed_case() {
        assert!(is_masquerade_target("Explorer.exe"));
    }

    #[test]
    fn does_not_flag_random_process() {
        assert!(!is_masquerade_target("mygame.exe"));
    }

    // Edge: empty
    #[test]
    fn empty_string_not_masquerade_target() {
        assert!(!is_masquerade_target(""));
    }

    // --- is_known_malware_process ---
    #[test]
    fn detects_mimikatz() {
        assert!(is_known_malware_process("mimikatz"));
    }

    #[test]
    fn detects_meterpreter_uppercase() {
        assert!(is_known_malware_process("METERPRETER"));
    }

    #[test]
    fn detects_beacon() {
        assert!(is_known_malware_process("beacon"));
    }

    #[test]
    fn does_not_flag_chrome() {
        assert!(!is_known_malware_process("chrome"));
    }

    // Edge: empty
    #[test]
    fn empty_string_not_malware_process() {
        assert!(!is_known_malware_process(""));
    }
}
