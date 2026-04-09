//! Detect processes running from deleted executables.
//!
//! When malware deletes its binary after execution, the process keeps running
//! but the `/proc/<pid>/exe` symlink (backed by `mm->exe_file->f_path->dentry->d_name`)
//! shows `(deleted)`. This is a strong indicator of malicious activity.
//!
//! MITRE ATT&CK: T1070.004 — Indicator Removal: File Deletion.
//!
//! Legitimate cases include package manager upgrades (apt, dpkg, yum, dnf, rpm)
//! where the old binary is replaced while the process is still running, and
//! kernel threads with empty exe paths.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use serde::Serialize;

use crate::{Error, Result};

/// Known-benign process names that may legitimately run from deleted executables.
///
/// Package managers and their helpers frequently replace their own binaries
/// during upgrade operations, causing a transient "(deleted)" state.
const KNOWN_BENIGN_COMMS: &[&str] = &[
    "apt", "apt-get", "apt-check", "aptd",
    "dpkg", "dpkg-deb",
    "yum", "dnf",
    "rpm", "rpmdb",
    "packagekitd", "unattended-upgr",
];

/// Information about a process whose executable may have been deleted.
#[derive(Debug, Clone, Serialize)]
pub struct DeletedExeInfo {
    /// Process ID.
    pub pid: u32,
    /// Process command name (`task_struct.comm`, max 16 chars).
    pub comm: String,
    /// Executable path as read from memory (may include "(deleted)" suffix).
    pub exe_path: String,
    /// Whether the executable path contains the "(deleted)" marker.
    pub is_deleted: bool,
    /// Whether this deleted executable is suspicious (not a known-benign case).
    pub is_suspicious: bool,
}

/// Classify whether a deleted executable is suspicious.
///
/// Returns `true` (suspicious) if:
/// - The exe path contains "(deleted)" AND
/// - The process is NOT a known-benign package manager process AND
/// - The exe path is not empty (kernel threads have no exe)
///
/// Returns `false` (benign) for:
/// - Normal executables (no "(deleted)" marker)
/// - Package manager processes (apt, dpkg, yum, dnf, rpm, etc.)
/// - Kernel threads with empty exe paths
/// - Processes with empty comm (likely kernel threads)
pub fn classify_deleted_exe(exe_path: &str, comm: &str) -> bool {
    // Not deleted at all -> not suspicious
    if !exe_path.contains("(deleted)") {
        return false;
    }

    // Empty exe path -> kernel thread, not suspicious
    if exe_path.is_empty() {
        return false;
    }

    // Empty comm -> likely kernel thread, not suspicious
    if comm.is_empty() {
        return false;
    }

    // Check against known-benign process names
    let comm_lower = comm.to_lowercase();
    for &benign in KNOWN_BENIGN_COMMS {
        if comm_lower == benign {
            return false;
        }
    }

    // All other deleted executables are suspicious
    true
}

/// Walk the task list and detect processes running from deleted executables.
///
/// For each process, reads the `mm->exe_file->f_path->dentry->d_name` chain
/// to recover the executable path. If the path contains "(deleted)", the
/// process is flagged and classified.
///
/// Kernel threads (NULL mm) are silently skipped.
pub fn walk_deleted_exe<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<DeletedExeInfo>> {
    todo!("walk_deleted_exe: implement task list walking and exe_file extraction")
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // --- classify_deleted_exe unit tests ---

    #[test]
    fn classify_normal_benign() {
        // A normal executable that is NOT deleted should never be suspicious.
        assert!(
            !classify_deleted_exe("/usr/bin/nginx", "nginx"),
            "a live (non-deleted) executable must not be flagged suspicious"
        );
    }

    #[test]
    fn classify_deleted_suspicious() {
        // A deleted executable from an unknown process IS suspicious.
        assert!(
            classify_deleted_exe("/tmp/.x11 (deleted)", "payload"),
            "a deleted exe from unknown process 'payload' must be suspicious"
        );
    }

    #[test]
    fn classify_deleted_apt_benign() {
        // apt running from a deleted exe during upgrade is benign.
        assert!(
            !classify_deleted_exe("/usr/bin/apt (deleted)", "apt"),
            "apt with deleted exe during package upgrade must not be suspicious"
        );
    }

    #[test]
    fn classify_deleted_dpkg_benign() {
        // dpkg running from a deleted exe during upgrade is benign.
        assert!(
            !classify_deleted_exe("/usr/bin/dpkg (deleted)", "dpkg"),
            "dpkg with deleted exe during package upgrade must not be suspicious"
        );
    }

    #[test]
    fn classify_kernel_thread_benign() {
        // Kernel threads have empty comm or empty exe path — not suspicious.
        assert!(
            !classify_deleted_exe("", ""),
            "kernel thread with empty exe and comm must not be suspicious"
        );
    }

    #[test]
    fn classify_empty_path_benign() {
        // Empty exe path (kernel thread) with a comm name should not be suspicious
        // even though it technically can't contain "(deleted)" — test the guard.
        assert!(
            !classify_deleted_exe("", "kworker/0:1"),
            "empty exe path must not be flagged suspicious"
        );
    }

    #[test]
    fn classify_deleted_yum_benign() {
        // yum running from a deleted exe during upgrade is benign.
        assert!(
            !classify_deleted_exe("/usr/bin/yum (deleted)", "yum"),
            "yum with deleted exe during package upgrade must not be suspicious"
        );
    }

    #[test]
    fn classify_deleted_with_suspicious_name() {
        // A process with a suspicious-looking name running from /dev/shm (deleted).
        assert!(
            classify_deleted_exe("/dev/shm/.hidden (deleted)", "a]"),
            "deleted exe from /dev/shm with obfuscated name must be suspicious"
        );
    }

    // --- walk_deleted_exe integration test ---

    /// Helper: build an ObjectReader with no init_task symbol.
    fn make_reader_no_symbol() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_no_symbol_returns_error() {
        // Without init_task symbol, walk should return an error (not panic).
        let reader = make_reader_no_symbol();
        let result = walk_deleted_exe(&reader);
        assert!(result.is_err(), "walk_deleted_exe must error when init_task symbol is missing");
    }
}
