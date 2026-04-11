/// Windows Living-Off-the-Land binaries (include `.exe` suffix).
pub const WINDOWS_LOLBINS: &[&str] = &[
    "certutil.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "msiexec.exe",
    "bitsadmin.exe",
    "msbuild.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "cmstp.exe",
    "odbcconf.exe",
    "mavinject.exe",
    "ieexec.exe",
    "xwizard.exe",
    "presentationhost.exe",
    "msdeploy.exe",
    "wmic.exe",
    "powershell.exe",
    "pwsh.exe",
];

/// Linux Living-Off-the-Land binaries.
pub const LINUX_LOLBINS: &[&str] = &[
    "bash",
    "sh",
    "python",
    "python3",
    "perl",
    "ruby",
    "php",
    "nc",
    "ncat",
    "socat",
    "tclsh",
    "openssl",
    "curl",
    "wget",
    "lua",
    "awk",
    "find",
    "vim",
    "less",
    "git",
    "env",
    "node",
    "dd",
    "strace",
    "gdb",
    "nmap",
];

/// Returns `true` if `name` matches a known Windows LOLBin (case-insensitive).
pub fn is_windows_lolbin(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    WINDOWS_LOLBINS.iter().any(|b| b.to_ascii_lowercase() == lower)
}

/// Returns `true` if `name` matches a known Linux LOLBin (case-insensitive).
pub fn is_linux_lolbin(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    LINUX_LOLBINS.iter().any(|b| b.to_ascii_lowercase() == lower)
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
