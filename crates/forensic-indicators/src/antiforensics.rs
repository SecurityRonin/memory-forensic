/// Command substrings indicative of log-wiping activity.
pub const LOG_WIPE_COMMANDS: &[&str] = &[
    "wevtutil cl",
    "wevtutil cl System",
    "wevtutil cl Security",
    "wevtutil cl Application",
    "auditpol /clear",
    "Clear-EventLog",
    "Remove-EventLog",
    "echo > /var/log",
    "truncate -s 0",
    "> /var/log/auth.log",
    "shred ",
    "srm ",
    "secure-delete",
];

/// Well-known Linux rootkit names.
pub const KNOWN_ROOTKIT_NAMES: &[&str] = &[
    "reptile",
    "diamorphine",
    "azazel",
    "necurs",
    "rkperfect",
    "knark",
    "suterusu",
    "Adore",
    "rkit",
    "enyelkm",
    "beurk",
    "jynx",
    "jynx2",
    "vlany",
];

/// Substrings indicative of timestamp-manipulation (timestomping) activity.
pub const TIMESTOMP_INDICATORS: &[&str] = &[
    "timestomp",
    "touch -t",
    "touch -d",
    "SetFileTime",
    "NtSetInformationFile",
    "ChangeFileTime",
];

/// Returns `true` if `cmd` contains a log-wipe pattern (case-insensitive).
pub fn is_log_wipe_command(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    LOG_WIPE_COMMANDS
        .iter()
        .any(|p| lower.contains(&p.to_ascii_lowercase()))
}

/// Returns `true` if `name` matches a known rootkit name (case-insensitive).
pub fn is_known_rootkit(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    KNOWN_ROOTKIT_NAMES
        .iter()
        .any(|r| r.to_ascii_lowercase() == lower)
}

/// Returns `true` if `s` contains a timestomp indicator (case-insensitive).
pub fn is_timestomp_indicator(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    TIMESTOMP_INDICATORS
        .iter()
        .any(|t| lower.contains(&t.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- constant membership ---
    #[test]
    fn log_wipe_contains_wevtutil_cl() {
        assert!(LOG_WIPE_COMMANDS.contains(&"wevtutil cl"));
    }

    #[test]
    fn log_wipe_contains_clear_eventlog() {
        assert!(LOG_WIPE_COMMANDS.contains(&"Clear-EventLog"));
    }

    #[test]
    fn log_wipe_contains_shred() {
        assert!(LOG_WIPE_COMMANDS.contains(&"shred "));
    }

    #[test]
    fn rootkit_names_contains_reptile() {
        assert!(KNOWN_ROOTKIT_NAMES.contains(&"reptile"));
    }

    #[test]
    fn rootkit_names_contains_diamorphine() {
        assert!(KNOWN_ROOTKIT_NAMES.contains(&"diamorphine"));
    }

    #[test]
    fn timestomp_indicators_contains_timestomp() {
        assert!(TIMESTOMP_INDICATORS.contains(&"timestomp"));
    }

    #[test]
    fn timestomp_indicators_contains_touch_t() {
        assert!(TIMESTOMP_INDICATORS.contains(&"touch -t"));
    }

    // --- is_log_wipe_command ---
    #[test]
    fn detects_wevtutil_cl_system() {
        assert!(is_log_wipe_command("wevtutil cl System"));
    }

    #[test]
    fn detects_clear_eventlog_cmdlet() {
        assert!(is_log_wipe_command("Clear-EventLog -LogName Application"));
    }

    #[test]
    fn detects_truncate_s_zero() {
        assert!(is_log_wipe_command("truncate -s 0 /var/log/auth.log"));
    }

    #[test]
    fn detects_shred_log() {
        assert!(is_log_wipe_command("shred /var/log/syslog"));
    }

    #[test]
    fn detects_case_insensitive_clear_eventlog() {
        assert!(is_log_wipe_command("CLEAR-EVENTLOG -logname security"));
    }

    #[test]
    fn does_not_flag_benign_command() {
        assert!(!is_log_wipe_command("Get-EventLog -LogName Application -Newest 10"));
    }

    // Edge: empty
    #[test]
    fn empty_string_not_log_wipe() {
        assert!(!is_log_wipe_command(""));
    }

    // --- is_known_rootkit ---
    #[test]
    fn detects_reptile_exact() {
        assert!(is_known_rootkit("reptile"));
    }

    #[test]
    fn detects_diamorphine_uppercase() {
        assert!(is_known_rootkit("DIAMORPHINE"));
    }

    #[test]
    fn detects_azazel() {
        assert!(is_known_rootkit("azazel"));
    }

    #[test]
    fn does_not_flag_legitimate_module() {
        assert!(!is_known_rootkit("ext4"));
    }

    // Edge: empty
    #[test]
    fn empty_string_not_rootkit() {
        assert!(!is_known_rootkit(""));
    }

    // --- is_timestomp_indicator ---
    #[test]
    fn detects_timestomp_tool() {
        assert!(is_timestomp_indicator("timestomp C:\\secret.doc -z \"01/01/2000 00:00:00\""));
    }

    #[test]
    fn detects_touch_t() {
        assert!(is_timestomp_indicator("touch -t 200001010000 /etc/passwd"));
    }

    #[test]
    fn detects_setfiletime_api() {
        assert!(is_timestomp_indicator("SetFileTime(hFile, &ct, &at, &wt)"));
    }

    #[test]
    fn does_not_flag_regular_touch() {
        assert!(!is_timestomp_indicator("touch newfile.txt"));
    }

    // Edge: empty
    #[test]
    fn empty_string_not_timestomp() {
        assert!(!is_timestomp_indicator(""));
    }
}
