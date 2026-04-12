/// PuTTY registry paths — saved sessions, SSH host key cache.
/// Source: third-party-app-registry-forensics.md §1.1 PuTTY
pub const PUTTY_PATHS: &[&str] = &[
    r"Software\SimonTatham\PuTTY\Sessions",
    r"Software\SimonTatham\PuTTY\SshHostKeys",
    r"Software\SimonTatham\PuTTY\Jumplist\Recent sessions",
];

/// WinSCP registry paths — saved sessions including obfuscated passwords.
/// Source: third-party-app-registry-forensics.md §1.2 WinSCP
pub const WINSCP_PATHS: &[&str] = &[
    r"Software\Martin Prikryl\WinSCP 2\Sessions",
    r"Software\Martin Prikryl\WinSCP 2\Configuration",
];

/// Microsoft OneDrive registry paths.
/// Source: third-party-app-registry-forensics.md §5.1 OneDrive
pub const ONEDRIVE_PATHS: &[&str] = &[
    r"Software\Microsoft\OneDrive",
    r"Software\Microsoft\OneDrive\Accounts\Personal",
    r"Software\Microsoft\OneDrive\Accounts\Business1",
    r"SOFTWARE\Policies\Microsoft\Windows\OneDrive",
    r"SOFTWARE\Microsoft\OneDrive",
];

/// Dropbox registry paths.
/// Source: third-party-app-registry-forensics.md §5.2 Dropbox
pub const DROPBOX_PATHS: &[&str] = &[
    r"Software\Dropbox",
    r"Software\Dropbox\ks\client",
    r"SOFTWARE\Dropbox",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Dropbox",
];

/// Google Chrome registry paths (installation, policies, extensions).
/// Source: third-party-app-registry-forensics.md §3.1 Google Chrome
pub const CHROME_PATHS: &[&str] = &[
    r"Software\Google\Chrome",
    r"SOFTWARE\Google\Chrome",
    r"SOFTWARE\Policies\Google\Chrome",
    r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist",
    r"SOFTWARE\Google\Update\Clients",
    r"SOFTWARE\Clients\StartMenuInternet\Google Chrome",
];

/// KiTTY registry paths (PuTTY fork).
/// Source: third-party-app-registry-forensics.md §1.7 KiTTY
pub const KITTY_PATHS: &[&str] = &[
    r"Software\9bis.com\KiTTY\Sessions",
    r"Software\9bis.com\KiTTY\SshHostKeys",
];

/// All third-party application forensic artifact paths combined.
pub const ALL_THIRD_PARTY_PATHS: &[&str] = &[
    // PUTTY_PATHS
    r"Software\SimonTatham\PuTTY\Sessions",
    r"Software\SimonTatham\PuTTY\SshHostKeys",
    r"Software\SimonTatham\PuTTY\Jumplist\Recent sessions",
    // WINSCP_PATHS
    r"Software\Martin Prikryl\WinSCP 2\Sessions",
    r"Software\Martin Prikryl\WinSCP 2\Configuration",
    // ONEDRIVE_PATHS
    r"Software\Microsoft\OneDrive",
    r"Software\Microsoft\OneDrive\Accounts\Personal",
    r"Software\Microsoft\OneDrive\Accounts\Business1",
    r"SOFTWARE\Policies\Microsoft\Windows\OneDrive",
    r"SOFTWARE\Microsoft\OneDrive",
    // DROPBOX_PATHS
    r"Software\Dropbox",
    r"Software\Dropbox\ks\client",
    r"SOFTWARE\Dropbox",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Dropbox",
    // CHROME_PATHS
    r"Software\Google\Chrome",
    r"SOFTWARE\Google\Chrome",
    r"SOFTWARE\Policies\Google\Chrome",
    r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist",
    r"SOFTWARE\Google\Update\Clients",
    r"SOFTWARE\Clients\StartMenuInternet\Google Chrome",
    // KITTY_PATHS
    r"Software\9bis.com\KiTTY\Sessions",
    r"Software\9bis.com\KiTTY\SshHostKeys",
];

/// Returns true if the given registry path matches a known third-party application
/// forensic artifact path (case-insensitive contains match).
pub fn is_third_party_artifact_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    ALL_THIRD_PARTY_PATHS
        .iter()
        .any(|entry| lower.contains(&entry.to_ascii_lowercase()))
}

/// Returns the application name if the path matches a known third-party app artifact,
/// or None if not recognized.
pub fn identify_application(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    let matches = |entries: &[&str]| {
        entries
            .iter()
            .any(|e| lower.contains(&e.to_ascii_lowercase()))
    };
    if matches(PUTTY_PATHS) {
        Some("PuTTY")
    } else if matches(KITTY_PATHS) {
        Some("KiTTY")
    } else if matches(WINSCP_PATHS) {
        Some("WinSCP")
    } else if matches(ONEDRIVE_PATHS) {
        Some("OneDrive")
    } else if matches(DROPBOX_PATHS) {
        Some("Dropbox")
    } else if matches(CHROME_PATHS) {
        Some("Chrome")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn putty_paths_not_empty() {
        assert!(!PUTTY_PATHS.is_empty(), "PUTTY_PATHS must not be empty");
    }

    #[test]
    fn onedrive_paths_not_empty() {
        assert!(!ONEDRIVE_PATHS.is_empty(), "ONEDRIVE_PATHS must not be empty");
    }

    #[test]
    fn all_third_party_paths_not_empty() {
        assert!(!ALL_THIRD_PARTY_PATHS.is_empty(), "ALL_THIRD_PARTY_PATHS must not be empty");
    }

    #[test]
    fn is_third_party_artifact_path_putty_matches() {
        assert!(
            is_third_party_artifact_path(r"Software\SimonTatham\PuTTY\Sessions\my-server"),
            "PuTTY sessions path must match"
        );
    }

    #[test]
    fn is_third_party_artifact_path_case_insensitive() {
        assert!(
            is_third_party_artifact_path(r"software\simontatham\putty\sessions"),
            "Match must be case-insensitive"
        );
    }

    #[test]
    fn is_third_party_artifact_path_unrelated_returns_false() {
        assert!(
            !is_third_party_artifact_path(r"SOFTWARE\Microsoft\Office"),
            "Unrelated path must not match"
        );
    }

    #[test]
    fn identify_application_putty() {
        assert_eq!(
            identify_application(r"Software\SimonTatham\PuTTY\SshHostKeys"),
            Some("PuTTY"),
            "Should identify PuTTY"
        );
    }

    #[test]
    fn identify_application_unknown_returns_none() {
        assert_eq!(
            identify_application(r"SOFTWARE\SomethingElse\Unknown"),
            None,
            "Unknown path should return None"
        );
    }
}
