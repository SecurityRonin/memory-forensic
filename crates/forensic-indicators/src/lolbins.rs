/// Windows Living-Off-the-Land binaries (include `.exe` suffix).
pub const WINDOWS_LOLBINS: &[&str] = &[];

/// Linux Living-Off-the-Land binaries.
pub const LINUX_LOLBINS: &[&str] = &[];

/// Returns `true` if `name` matches a known Windows LOLBin (case-insensitive).
pub fn is_windows_lolbin(_name: &str) -> bool {
    false
}

/// Returns `true` if `name` matches a known Linux LOLBin (case-insensitive).
pub fn is_linux_lolbin(_name: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- constant membership ---
    #[test]
    fn windows_lolbins_contains_certutil() {
        assert!(WINDOWS_LOLBINS.contains(&"certutil.exe"));
    }

    #[test]
    fn windows_lolbins_contains_mshta() {
        assert!(WINDOWS_LOLBINS.contains(&"mshta.exe"));
    }

    #[test]
    fn windows_lolbins_contains_powershell() {
        assert!(WINDOWS_LOLBINS.contains(&"powershell.exe"));
    }

    #[test]
    fn linux_lolbins_contains_nc() {
        assert!(LINUX_LOLBINS.contains(&"nc"));
    }

    #[test]
    fn linux_lolbins_contains_python3() {
        assert!(LINUX_LOLBINS.contains(&"python3"));
    }

    // --- is_windows_lolbin ---
    #[test]
    fn detects_certutil_exact() {
        assert!(is_windows_lolbin("certutil.exe"));
    }

    #[test]
    fn detects_certutil_uppercase() {
        assert!(is_windows_lolbin("CERTUTIL.EXE"));
    }

    #[test]
    fn detects_mshta_mixed_case() {
        assert!(is_windows_lolbin("Mshta.Exe"));
    }

    #[test]
    fn does_not_flag_notepad() {
        assert!(!is_windows_lolbin("notepad.exe"));
    }

    // Edge: empty string
    #[test]
    fn empty_string_not_windows_lolbin() {
        assert!(!is_windows_lolbin(""));
    }

    // --- is_linux_lolbin ---
    #[test]
    fn detects_bash() {
        assert!(is_linux_lolbin("bash"));
    }

    #[test]
    fn detects_socat_uppercase() {
        assert!(is_linux_lolbin("SOCAT"));
    }

    #[test]
    fn detects_python3() {
        assert!(is_linux_lolbin("python3"));
    }

    #[test]
    fn does_not_flag_grep() {
        assert!(!is_linux_lolbin("grep"));
    }

    // Edge: empty string
    #[test]
    fn empty_string_not_linux_lolbin() {
        assert!(!is_linux_lolbin(""));
    }
}
