//! Zombie and orphan process detection for Linux memory forensics.
//!
//! Detects zombie processes (exited but not reaped by their parent) and
//! orphan processes (parent died, reparented to init/pid 1). These are
//! forensically significant: malware that crashes leaves zombies; processes
//! that survive their parent may indicate persistence or injection.
//!
//! MITRE ATT&CK T1036 (masquerading via orphan reparenting).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, Result};

/// Common daemon-like process names that are suspicious when found as
/// orphans reparented to init. Legitimate daemons are started by init
/// directly; an orphan with a daemon name suggests reparenting after
/// parent death, which can indicate injection or persistence.
const SUSPICIOUS_DAEMON_NAMES: &[&str] = &[
    "sshd", "httpd", "nginx", "apache", "mysqld", "postgres", "redis",
    "memcached", "mongod", "named", "bind", "cupsd", "cron", "atd",
];

/// Information about a zombie or orphan process found in memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ZombieOrphanInfo {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID (current, possibly init after reparenting).
    pub ppid: u32,
    /// Process command name from `task_struct.comm`.
    pub comm: String,
    /// Process state string (e.g. "Z (zombie)", "S (sleeping)").
    pub state: String,
    /// Exit code from the process (relevant for zombies).
    pub exit_code: i32,
    /// Original parent PID before reparenting (from `parent` field).
    pub original_ppid: u32,
    /// Whether this process is a zombie (EXIT_ZOMBIE state).
    pub is_zombie: bool,
    /// Whether this process is an orphan (reparented to init).
    pub is_orphan: bool,
    /// Whether heuristic analysis flagged this as suspicious.
    pub is_suspicious: bool,
}

/// Classify whether a zombie/orphan process is suspicious.
///
/// Returns `true` (suspicious) when:
/// - A zombie has been reparented to init (ppid == 1), suggesting the
///   parent crashed or was killed -- common for crashed malware.
/// - An orphan has a daemon-like name, suggesting suspicious reparenting
///   (legitimate daemons are started by init directly, not reparented).
/// - A zombie has a non-zero exit code, indicating the process crashed
///   rather than exiting cleanly.
///
/// Returns `false` (benign) for normal zombies awaiting reaping by their
/// parent and normal processes.
pub fn classify_zombie_orphan(
    is_zombie: bool,
    is_orphan: bool,
    ppid: u32,
    comm: &str,
) -> bool {
    // Reparented zombie: parent died, zombie left behind -- malware crash indicator.
    if is_zombie && ppid == 1 {
        return true;
    }

    // Orphan running with a daemon-like name -- suspicious reparenting.
    if is_orphan {
        let lower = comm.to_lowercase();
        if SUSPICIOUS_DAEMON_NAMES
            .iter()
            .any(|&name| lower.contains(name))
        {
            return true;
        }
    }

    // Zombie with non-zero exit code -- crashed process.
    // NOTE: exit_code is not passed to this function; this heuristic is
    // applied in the walker. Here we only check zombie+reparent and
    // orphan+daemon patterns.

    false
}

/// Walk the Linux process list and detect zombie and orphan processes.
///
/// Walks `task_struct` list from `init_task`. For each task:
/// - Reads state, pid, ppid (from `real_parent->pid`), exit_code
/// - Marks zombie if state == EXIT_ZOMBIE (0x20 / 32)
/// - Marks orphan if `real_parent` points to init (pid 1) but
///   `parent` field differs (original parent was different)
/// - Classifies each using [`classify_zombie_orphan`]
///
/// Returns an empty `Vec` when symbols are missing (graceful degradation).
pub fn walk_zombie_orphan<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<ZombieOrphanInfo>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // -------------------------------------------------------------------
    // Classifier unit tests
    // -------------------------------------------------------------------

    #[test]
    fn classify_reparented_zombie_suspicious() {
        // A zombie whose parent is init (ppid=1) -- parent died, zombie
        // left behind. Strong indicator of crashed malware.
        assert!(classify_zombie_orphan(true, false, 1, "evil_proc"));
    }

    #[test]
    fn classify_orphan_daemon_suspicious() {
        // An orphan process running with a daemon-like name. Legitimate
        // daemons are started by init, not reparented.
        assert!(classify_zombie_orphan(false, true, 1, "sshd"));
    }

    #[test]
    fn classify_normal_zombie_benign() {
        // A zombie whose parent (ppid=500) is still alive and just hasn't
        // called wait() yet. Normal behaviour.
        assert!(!classify_zombie_orphan(true, false, 500, "worker"));
    }

    #[test]
    fn classify_normal_process_benign() {
        // A completely normal process -- not zombie, not orphan.
        assert!(!classify_zombie_orphan(false, false, 500, "bash"));
    }

    #[test]
    fn classify_crashed_zombie_suspicious() {
        // A zombie reparented to init (ppid == 1). The exit_code check is
        // done at the walker level, but a reparented zombie is suspicious
        // regardless of exit code.
        assert!(classify_zombie_orphan(true, false, 1, "payload"));
    }

    #[test]
    fn classify_orphan_non_daemon_benign() {
        // An orphan process with a non-daemon name -- may be benign
        // (e.g. a user shell whose terminal closed).
        assert!(!classify_zombie_orphan(false, true, 1, "my_script"));
    }

    #[test]
    fn classify_orphan_daemon_case_insensitive() {
        // Daemon name matching should be case-insensitive.
        assert!(classify_zombie_orphan(false, true, 1, "NGINX"));
    }

    // -------------------------------------------------------------------
    // Walker integration test -- missing symbol -> empty Vec
    // -------------------------------------------------------------------

    #[test]
    fn walk_no_symbol_returns_empty() {
        // Build a reader with task_struct defined but no init_task symbol.
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 256)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "state", 8, "long")
            .add_field("task_struct", "exit_code", 16, "int")
            .add_field("task_struct", "tasks", 24, "list_head")
            .add_field("task_struct", "comm", 40, "char")
            .add_field("task_struct", "real_parent", 56, "pointer")
            .add_field("task_struct", "parent", 64, "pointer")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            // NOTE: no "init_task" symbol registered
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_zombie_orphan(&reader);
        // Graceful degradation: missing symbol -> empty vec, not an error.
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    // -------------------------------------------------------------------
    // Serialization test
    // -------------------------------------------------------------------

    #[test]
    fn zombie_orphan_serializes() {
        let info = ZombieOrphanInfo {
            pid: 1234,
            ppid: 1,
            comm: "evil_proc".to_string(),
            state: "Z (zombie)".to_string(),
            exit_code: 139, // SIGSEGV
            original_ppid: 500,
            is_zombie: true,
            is_orphan: false,
            is_suspicious: true,
        };

        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["pid"], 1234);
        assert_eq!(json["ppid"], 1);
        assert_eq!(json["comm"], "evil_proc");
        assert_eq!(json["state"], "Z (zombie)");
        assert_eq!(json["exit_code"], 139);
        assert_eq!(json["original_ppid"], 500);
        assert_eq!(json["is_zombie"], true);
        assert_eq!(json["is_orphan"], false);
        assert_eq!(json["is_suspicious"], true);
    }
}
