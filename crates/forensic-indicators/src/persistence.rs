/// Windows registry autorun keys used for persistence.
pub const WINDOWS_RUN_KEYS: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"SYSTEM\CurrentControlSet\Services",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"Software\Classes\exefile\shell\open\command",
    r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls",
    r"SYSTEM\CurrentControlSet\Control\Lsa",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
];

/// Linux filesystem paths associated with persistence mechanisms.
pub const LINUX_PERSISTENCE_PATHS: &[&str] = &[
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.monthly",
    "/etc/cron.weekly",
    "/var/spool/cron",
    "/etc/init.d",
    "/etc/rc.local",
    "/etc/profile.d",
    "/etc/ld.so.preload",
    "/etc/pam.d",
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/run/systemd/system",
    "~/.bashrc",
    "~/.bash_profile",
    "~/.profile",
    "~/.config/autostart",
];

/// macOS filesystem paths associated with persistence mechanisms.
pub const MACOS_PERSISTENCE_PATHS: &[&str] = &[
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    "~/Library/LaunchAgents",
    "/System/Library/LaunchAgents",
    "/System/Library/LaunchDaemons",
    "/Library/StartupItems",
    "/etc/periodic/daily",
    "/etc/periodic/weekly",
    "/etc/periodic/monthly",
];

/// Returns `true` if `path` references a known persistence location on any platform
/// (case-insensitive).
pub fn is_persistence_location(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let check = |entry: &&str| lower.contains(&entry.to_ascii_lowercase());
    WINDOWS_RUN_KEYS.iter().any(check)
        || LINUX_PERSISTENCE_PATHS.iter().any(check)
        || MACOS_PERSISTENCE_PATHS.iter().any(check)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- constant membership ---
    #[test]
    fn windows_run_keys_contains_run() {
        assert!(
            WINDOWS_RUN_KEYS.contains(&r"Software\Microsoft\Windows\CurrentVersion\Run"),
            "Run key must be present"
        );
    }

    #[test]
    fn windows_run_keys_contains_services() {
        assert!(
            WINDOWS_RUN_KEYS.contains(&r"SYSTEM\CurrentControlSet\Services"),
            "Services key must be present"
        );
    }

    #[test]
    fn linux_persistence_contains_cron_d() {
        assert!(
            LINUX_PERSISTENCE_PATHS.contains(&"/etc/cron.d"),
            "/etc/cron.d must be present"
        );
    }

    #[test]
    fn linux_persistence_contains_ld_so_preload() {
        assert!(
            LINUX_PERSISTENCE_PATHS.contains(&"/etc/ld.so.preload"),
            "/etc/ld.so.preload must be present"
        );
    }

    #[test]
    fn macos_persistence_contains_launch_agents() {
        assert!(
            MACOS_PERSISTENCE_PATHS.contains(&"/Library/LaunchAgents"),
            "/Library/LaunchAgents must be present"
        );
    }

    #[test]
    fn macos_persistence_contains_launch_daemons() {
        assert!(
            MACOS_PERSISTENCE_PATHS.contains(&"/Library/LaunchDaemons"),
            "/Library/LaunchDaemons must be present"
        );
    }

    // --- is_persistence_location ---
    #[test]
    fn detects_windows_run_key_path() {
        assert!(is_persistence_location(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        ));
    }

    #[test]
    fn detects_linux_cron_path() {
        assert!(is_persistence_location("/etc/cron.daily/malware"));
    }

    #[test]
    fn detects_macos_launch_agents() {
        assert!(is_persistence_location("/Library/LaunchAgents/com.evil.plist"));
    }

    #[test]
    fn detects_ld_so_preload() {
        assert!(is_persistence_location("/etc/ld.so.preload"));
    }

    #[test]
    fn does_not_flag_random_path() {
        assert!(!is_persistence_location("/usr/bin/ls"));
    }

    // Edge: empty string
    #[test]
    fn empty_string_not_persistence() {
        assert!(!is_persistence_location(""));
    }
}
