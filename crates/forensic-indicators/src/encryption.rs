/// Registry paths that indicate presence of VeraCrypt encryption tool.
/// Source: encryption-and-antifore-registry-artifacts.md §1 VeraCrypt
pub const VERACRYPT_PATHS: &[&str] = &[
    r"SOFTWARE\VeraCrypt",
    r"SOFTWARE\Wow6432Node\VeraCrypt",
    r"SYSTEM\CurrentControlSet\Services\veracrypt",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\VeraCrypt",
];

/// BitLocker-related registry evidence.
/// Source: encryption-and-antifore-registry-artifacts.md §4 BitLocker
pub const BITLOCKER_PATHS: &[&str] = &[
    r"SOFTWARE\Policies\Microsoft\FVE",
    r"SYSTEM\CurrentControlSet\Control\BitLockerStatus",
    r"SYSTEM\CurrentControlSet\Services\BDESVC",
    r"SYSTEM\CurrentControlSet\Services\fvevol",
];

/// EFS (Encrypting File System) policy paths.
/// Source: encryption-and-antifore-registry-artifacts.md §5 EFS
pub const EFS_PATHS: &[&str] = &[
    r"SOFTWARE\Policies\Microsoft\Windows\System",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\EFS",
    r"SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\EFS",
];

/// 7-Zip MRU and settings paths.
/// Source: encryption-and-antifore-registry-artifacts.md §6 7-Zip
pub const SEVENZIP_PATHS: &[&str] = &[
    r"SOFTWARE\7-Zip",
    r"SOFTWARE\Wow6432Node\7-Zip",
    r"Software\7-Zip",
];

/// WinRAR MRU paths (archive access evidence).
/// Source: encryption-and-antifore-registry-artifacts.md §7 WinRAR
pub const WINRAR_PATHS: &[&str] = &[
    r"SOFTWARE\WinRAR",
    r"SOFTWARE\WinRAR SFX",
    r"Software\WinRAR",
];

/// Tor Browser / Tor Project registry paths.
/// Source: third-party-app-registry-forensics.md §3.7 Tor Browser
pub const TOR_PATHS: &[&str] = &[
    r"SOFTWARE\Tor Project",
    r"SOFTWARE\Wow6432Node\Tor Project",
];

/// All encryption tool indicator paths combined (for bulk scanning).
pub const ALL_ENCRYPTION_PATHS: &[&str] = &[
    // VERACRYPT_PATHS
    r"SOFTWARE\VeraCrypt",
    r"SOFTWARE\Wow6432Node\VeraCrypt",
    r"SYSTEM\CurrentControlSet\Services\veracrypt",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\VeraCrypt",
    // BITLOCKER_PATHS
    r"SOFTWARE\Policies\Microsoft\FVE",
    r"SYSTEM\CurrentControlSet\Control\BitLockerStatus",
    r"SYSTEM\CurrentControlSet\Services\BDESVC",
    r"SYSTEM\CurrentControlSet\Services\fvevol",
    // EFS_PATHS
    r"SOFTWARE\Policies\Microsoft\Windows\System",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\EFS",
    r"SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\EFS",
    // SEVENZIP_PATHS
    r"SOFTWARE\7-Zip",
    r"SOFTWARE\Wow6432Node\7-Zip",
    r"Software\7-Zip",
    // WINRAR_PATHS
    r"SOFTWARE\WinRAR",
    r"SOFTWARE\WinRAR SFX",
    r"Software\WinRAR",
    // TOR_PATHS
    r"SOFTWARE\Tor Project",
    r"SOFTWARE\Wow6432Node\Tor Project",
];

/// Returns true if the given registry path matches a known encryption tool indicator
/// (case-insensitive contains match).
pub fn is_encryption_tool_path(_path: &str) -> bool {
    todo!("implement is_encryption_tool_path")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn veracrypt_paths_not_empty() {
        assert!(!VERACRYPT_PATHS.is_empty(), "VERACRYPT_PATHS must not be empty");
    }

    #[test]
    fn bitlocker_paths_not_empty() {
        assert!(!BITLOCKER_PATHS.is_empty(), "BITLOCKER_PATHS must not be empty");
    }

    #[test]
    fn sevenzip_paths_not_empty() {
        assert!(!SEVENZIP_PATHS.is_empty(), "SEVENZIP_PATHS must not be empty");
    }

    #[test]
    fn all_encryption_paths_includes_tor() {
        assert!(
            ALL_ENCRYPTION_PATHS.contains(&r"SOFTWARE\Tor Project"),
            "ALL_ENCRYPTION_PATHS must include Tor Project"
        );
    }

    #[test]
    fn is_encryption_tool_path_veracrypt_matches() {
        assert!(
            is_encryption_tool_path(r"SOFTWARE\VeraCrypt\MRUList"),
            "VeraCrypt path must match"
        );
    }

    #[test]
    fn is_encryption_tool_path_case_insensitive() {
        assert!(
            is_encryption_tool_path(r"software\veracrypt"),
            "Match must be case-insensitive"
        );
    }

    #[test]
    fn is_encryption_tool_path_unrelated_returns_false() {
        assert!(
            !is_encryption_tool_path(r"SOFTWARE\Microsoft\Office"),
            "Unrelated path must not match"
        );
    }
}
