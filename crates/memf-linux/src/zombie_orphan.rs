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

use crate::{ProcessState, Result};

/// Common daemon-like process names that are suspicious when found as
/// orphans reparented to init. Legitimate daemons are started by init
/// directly; an orphan with a daemon name suggests reparenting after
/// parent death, which can indicate injection or persistence.
const SUSPICIOUS_DAEMON_NAMES: &[&str] = &[
    "sshd",
    "httpd",
    "nginx",
    "apache",
    "mysqld",
    "postgres",
    "redis",
    "memcached",
    "mongod",
    "named",
    "bind",
    "cupsd",
    "cron",
    "atd",
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
pub fn classify_zombie_orphan(is_zombie: bool, is_orphan: bool, ppid: u32, comm: &str) -> bool {
        todo!()
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
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // -------------------------------------------------------------------
    // Classifier unit tests
    // -------------------------------------------------------------------

    #[test]
    fn classify_reparented_zombie_suspicious() {
        todo!()
    }

    #[test]
    fn classify_orphan_daemon_suspicious() {
        todo!()
    }

    #[test]
    fn classify_normal_zombie_benign() {
        todo!()
    }

    #[test]
    fn classify_normal_process_benign() {
        todo!()
    }

    #[test]
    fn classify_crashed_zombie_suspicious() {
        todo!()
    }

    #[test]
    fn classify_orphan_non_daemon_benign() {
        todo!()
    }

    #[test]
    fn classify_orphan_daemon_case_insensitive() {
        todo!()
    }

    // -------------------------------------------------------------------
    // Walker integration test -- missing symbol -> empty Vec
    // -------------------------------------------------------------------

    #[test]
    fn walk_no_symbol_returns_empty() {
        todo!()
    }

    // -------------------------------------------------------------------
    // Walker integration test -- missing tasks field -> empty Vec
    // -------------------------------------------------------------------

    #[test]
    fn walk_no_tasks_offset_returns_empty() {
        todo!()
    }

    // -------------------------------------------------------------------
    // walk_zombie_orphan: symbol present + self-pointing list (body runs)
    // -------------------------------------------------------------------

    #[test]
    fn walk_zombie_orphan_symbol_present_empty_list() {
        todo!()
    }

    // -------------------------------------------------------------------
    // walk_zombie_orphan: init_task has zombie state → read_task returns Some
    // Exercises the branch where is_zombie=true and ppid==1 → suspicious.
    // Uses self-pointing list (no other tasks) so only init_task is processed.
    // -------------------------------------------------------------------

    #[test]
    fn walk_zombie_orphan_zombie_task_detected() {
        todo!()
    }

    // -------------------------------------------------------------------
    // ZombieOrphanInfo: Clone + Debug
    // -------------------------------------------------------------------

    #[test]
    fn zombie_orphan_info_clone_and_debug() {
        todo!()
    }

    // -------------------------------------------------------------------
    // classify edge cases — all SUSPICIOUS_DAEMON_NAMES are matched
    // -------------------------------------------------------------------

    #[test]
    fn classify_orphan_httpd_suspicious() {
        todo!()
    }

    #[test]
    fn classify_orphan_nginx_suspicious() {
        todo!()
    }

    #[test]
    fn classify_orphan_apache_suspicious() {
        todo!()
    }

    #[test]
    fn classify_orphan_mysqld_suspicious() {
        todo!()
    }

    #[test]
    fn classify_orphan_postgres_suspicious() {
        todo!()
    }

    #[test]
    fn classify_orphan_redis_suspicious() {
        todo!()
    }

    #[test]
    fn classify_orphan_memcached_suspicious() {
        todo!()
    }

    #[test]
    fn classify_orphan_mongod_suspicious() {
        todo!()
    }

    #[test]
    fn classify_orphan_named_suspicious() {
        todo!()
    }

    #[test]
    fn classify_orphan_bind_suspicious() {
        todo!()
    }

    #[test]
    fn classify_orphan_cupsd_suspicious() {
        todo!()
    }

    #[test]
    fn classify_orphan_cron_suspicious() {
        todo!()
    }

    #[test]
    fn classify_orphan_atd_suspicious() {
        todo!()
    }

    #[test]
    fn classify_zombie_non_init_parent_benign() {
        todo!()
    }

    // -------------------------------------------------------------------
    // Serialization test
    // -------------------------------------------------------------------

    #[test]
    fn zombie_orphan_serializes() {
        todo!()
    }
}
