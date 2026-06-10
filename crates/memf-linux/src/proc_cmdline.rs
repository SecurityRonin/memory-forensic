//! Pure-logic process command-line parsing and forensic classification.
//!
//! Parses `/proc/<pid>/cmdline`-style byte slices (NUL-separated argv fields)
//! into a structured [`ProcessCmdline`] and provides heuristic classifiers for
//! common attacker-controlled process patterns (SSH tunnels, cryptominers).

/// Parsed process command line.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessCmdline {
    /// Process ID.
    pub pid: u32,
    /// Process name (`task_struct.comm`, max 16 chars).
    pub comm: String,
    /// Executable path (first NUL-delimited field).
    pub exe: String,
    /// Arguments after the executable (remaining NUL-delimited fields).
    pub args: Vec<String>,
    /// Full command line reconstructed as a space-joined string.
    pub cmdline_raw: String,
}

/// Parse a `/proc/<pid>/cmdline` byte slice (NUL-separated fields) into a
/// [`ProcessCmdline`].
///
/// The first NUL-delimited field becomes `exe`; subsequent fields become
/// `args`. `cmdline_raw` is all fields joined with spaces.
pub fn parse_proc_cmdline(pid: u32, comm: &str, bytes: &[u8]) -> ProcessCmdline {
    let fields: Vec<String> = bytes
        .split(|&b| b == 0)
        .filter_map(|chunk| {
            if chunk.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(chunk).into_owned())
            }
        })
        .collect();

    let exe = fields.first().cloned().unwrap_or_default();
    let args = fields.get(1..).unwrap_or(&[]).to_vec();
    let cmdline_raw = fields.join(" ");

    ProcessCmdline {
        pid,
        comm: comm.to_string(),
        exe,
        args,
        cmdline_raw,
    }
}

/// Returns `true` if this cmdline looks like an SSH port-forwarding tunnel.
///
/// Matches when the executable contains `"ssh"` and the arguments include
/// `-L`, `-R`, or `-D`.
pub fn is_ssh_tunnel_cmdline(cmdline: &ProcessCmdline) -> bool {
    if !cmdline.exe.contains("ssh") {
        return false;
    }
    cmdline.args.iter().any(|a| matches!(a.as_str(), "-L" | "-R" | "-D"))
}

/// Returns `true` if this cmdline looks like a cryptominer.
///
/// Matches when the executable contains `"xmrig"` or the arguments contain
/// `"stratum+"` or `"--pool"`.
pub fn is_miner_cmdline(cmdline: &ProcessCmdline) -> bool {
    if cmdline.exe.contains("xmrig") {
        return true;
    }
    cmdline
        .args
        .iter()
        .any(|a| a.contains("stratum+") || a == "--pool")
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_proc_cmdline ---

    #[test]
    fn parse_ssh_tunnel_cmdline() {
        let cmdline = parse_proc_cmdline(941, "ssh", b"ssh\0-L\x003333:pool:3333\0");
        assert_eq!(cmdline.pid, 941);
        assert_eq!(cmdline.comm, "ssh");
        assert_eq!(cmdline.exe, "ssh");
        assert_eq!(cmdline.args, vec!["-L", "3333:pool:3333"]);
    }

    #[test]
    fn parse_xmrig_cmdline() {
        let cmdline = parse_proc_cmdline(
            100,
            "xmrig",
            b"xmrig\0--pool\0stratum+tcp://pool:3333\0-u\0user\0",
        );
        assert_eq!(cmdline.exe, "xmrig");
        assert!(cmdline.args.contains(&"--pool".to_string()));
        assert!(cmdline.args.iter().any(|a| a.starts_with("stratum+")));
    }

    #[test]
    fn parse_empty_bytes_produces_empty_exe() {
        let cmdline = parse_proc_cmdline(1, "init", b"");
        assert_eq!(cmdline.exe, "");
        assert!(cmdline.args.is_empty());
        assert_eq!(cmdline.cmdline_raw, "");
    }

    #[test]
    fn parse_single_exe_no_args() {
        let cmdline = parse_proc_cmdline(2, "bash", b"/bin/bash\0");
        assert_eq!(cmdline.exe, "/bin/bash");
        assert!(cmdline.args.is_empty());
        assert_eq!(cmdline.cmdline_raw, "/bin/bash");
    }

    #[test]
    fn parse_cmdline_raw_space_joins_all_fields() {
        let cmdline = parse_proc_cmdline(3, "python3", b"python3\0-m\0http.server\x008080\0");
        assert_eq!(cmdline.cmdline_raw, "python3 -m http.server 8080");
    }

    // --- is_ssh_tunnel_cmdline ---

    #[test]
    fn ssh_tunnel_forward_l_is_tunnel() {
        let cmdline = parse_proc_cmdline(941, "ssh", b"ssh\0-L\x003333:pool:3333\0");
        assert!(is_ssh_tunnel_cmdline(&cmdline));
    }

    #[test]
    fn ssh_tunnel_forward_r_is_tunnel() {
        let cmdline = parse_proc_cmdline(942, "ssh", b"ssh\0-R\x008080:localhost:80\0user@host\0");
        assert!(is_ssh_tunnel_cmdline(&cmdline));
    }

    #[test]
    fn ssh_tunnel_socks_d_is_tunnel() {
        let cmdline = parse_proc_cmdline(943, "ssh", b"ssh\0-D\x001080\0user@host\0");
        assert!(is_ssh_tunnel_cmdline(&cmdline));
    }

    #[test]
    fn bash_is_not_ssh_tunnel() {
        let cmdline = parse_proc_cmdline(1, "bash", b"/bin/bash\0-c\0true\0");
        assert!(!is_ssh_tunnel_cmdline(&cmdline));
    }

    #[test]
    fn ssh_without_tunnel_flags_is_not_tunnel() {
        // Plain ssh login, no port-forwarding flags
        let cmdline = parse_proc_cmdline(944, "ssh", b"ssh\0user@host\0");
        assert!(!is_ssh_tunnel_cmdline(&cmdline));
    }

    // --- is_miner_cmdline ---

    #[test]
    fn xmrig_exe_is_miner() {
        let cmdline = parse_proc_cmdline(200, "xmrig", b"xmrig\0--pool\0pool.minexmr.com:443\0");
        assert!(is_miner_cmdline(&cmdline));
    }

    #[test]
    fn stratum_arg_is_miner() {
        let cmdline = parse_proc_cmdline(
            201,
            "miner",
            b"./miner\0stratum+tcp://pool:3333\0",
        );
        assert!(is_miner_cmdline(&cmdline));
    }

    #[test]
    fn pool_flag_is_miner() {
        let cmdline = parse_proc_cmdline(202, "miner2", b"miner2\0--pool\0pool.example.com\0");
        assert!(is_miner_cmdline(&cmdline));
    }

    #[test]
    fn bash_is_not_miner() {
        let cmdline = parse_proc_cmdline(1, "bash", b"/bin/bash\0-c\0echo hello\0");
        assert!(!is_miner_cmdline(&cmdline));
    }

    // --- struct fields ---

    #[test]
    fn process_cmdline_clone_and_debug() {
        let cmdline = parse_proc_cmdline(5, "sh", b"sh\0-c\0true\0");
        let cloned = cmdline.clone();
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("ProcessCmdline"));
    }

    #[test]
    fn process_cmdline_serializes_to_json() {
        let cmdline = parse_proc_cmdline(6, "nginx", b"nginx\0-g\0daemon off;\0");
        let json = serde_json::to_string(&cmdline).unwrap();
        assert!(json.contains("\"pid\":6"));
        assert!(json.contains("\"exe\":\"nginx\""));
    }
}
