/// Windows registry autorun keys used for persistence.
pub const WINDOWS_RUN_KEYS: &[&str] = &[];

/// Linux filesystem paths associated with persistence mechanisms.
pub const LINUX_PERSISTENCE_PATHS: &[&str] = &[];

/// macOS filesystem paths associated with persistence mechanisms.
pub const MACOS_PERSISTENCE_PATHS: &[&str] = &[];

/// Returns `true` if `path` references a known persistence location on any platform.
pub fn is_persistence_location(_path: &str) -> bool {
    false
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
