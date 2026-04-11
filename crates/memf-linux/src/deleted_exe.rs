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
    "apt",
    "apt-get",
    "apt-check",
    "aptd",
    "dpkg",
    "dpkg-deb",
    "yum",
    "dnf",
    "rpm",
    "rpmdb",
    "packagekitd",
    "unattended-upgr",
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
        todo!()
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
        todo!()
    }

/// Read the executable path for a single task and classify it.
///
/// Returns `None` for kernel threads (NULL mm) or if any field cannot be read.
fn read_deleted_exe_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
) -> Option<DeletedExeInfo> {
        todo!()
    }

/// Read the dentry name from a `struct file` pointer via `f_path.dentry->d_name`.
///
/// Follows the embedded struct chain: `file.f_path` (embedded `struct path`) ->
/// `path.dentry` (pointer) -> `dentry.d_name` (embedded `struct qstr`) ->
/// `qstr.name` (pointer to string).
fn read_file_dentry_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    file_ptr: u64,
) -> Option<String> {
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

    // --- classify_deleted_exe unit tests ---

    #[test]
    fn classify_normal_benign() {
        todo!()
    }

    #[test]
    fn classify_deleted_suspicious() {
        todo!()
    }

    #[test]
    fn classify_deleted_apt_benign() {
        todo!()
    }

    #[test]
    fn classify_deleted_dpkg_benign() {
        todo!()
    }

    #[test]
    fn classify_kernel_thread_benign() {
        todo!()
    }

    #[test]
    fn classify_empty_path_benign() {
        todo!()
    }

    #[test]
    fn classify_deleted_yum_benign() {
        todo!()
    }

    #[test]
    fn classify_deleted_with_suspicious_name() {
        todo!()
    }

    #[test]
    fn classify_deleted_empty_comm_benign() {
        todo!()
    }

    #[test]
    fn classify_all_known_benign_comms() {
        todo!()
    }

    #[test]
    fn classify_benign_comm_case_insensitive() {
        todo!()
    }

    #[test]
    fn classify_near_benign_name_suspicious() {
        todo!()
    }

    #[test]
    fn classify_deleted_exe_info_struct_fields() {
        todo!()
    }

    #[test]
    fn classify_deleted_exe_info_serializes_to_json() {
        todo!()
    }

    // --- walk_deleted_exe integration test ---

    /// Helper: build an ObjectReader with no init_task symbol.
    fn make_reader_no_symbol() -> ObjectReader<SyntheticPhysMem> {
        todo!()
    }

    #[test]
    fn walk_no_symbol_returns_error() {
        todo!()
    }

    // --- walk_deleted_exe: symbol present, self-pointing tasks list, mm != 0, exe_file == 0 ---
    // Exercises read_deleted_exe_info: mm pointer is non-null (reads ok), but
    // mm_struct.exe_file == 0 → returns None → result stays empty.
    #[test]
    fn walk_deleted_exe_mm_non_null_exe_file_null_returns_empty() {
        todo!()
    }

    // --- walk_deleted_exe: exe_file non-null, dentry chain fully readable, non-deleted path ---
    // Exercises read_deleted_exe_info returning Some (lines 120, 124-126), and
    // read_file_dentry_name (lines 177-203) on a path without "(deleted)".
    #[test]
    fn walk_deleted_exe_full_chain_no_deleted_marker() {
        todo!()
    }

    // --- walk_deleted_exe: symbol present, self-pointing tasks list, mm == 0 → exercises body ---
    // Exercises the task-list body and `read_deleted_exe_info`: init_task has mm=0 (kernel thread),
    // so it is skipped, and walk_list returns empty → result is empty but no error.
    #[test]
    fn walk_deleted_exe_symbol_present_kernel_thread_returns_empty() {
        todo!()
    }

    // --- walk_deleted_exe: walk_list returns a non-empty task list → exercises the for loop body ---
    // init_task has mm=0 (kernel thread, skipped). A linked task has mm != 0 but exe_file = 0
    // → read_deleted_exe_info returns None → loop body runs but produces no result.
    #[test]
    fn walk_deleted_exe_task_list_loop_body_covered() {
        todo!()
    }

    // --- walk_deleted_exe: full chain produces a (deleted) exe entry ---
    // Exercises lines 119-120 (init_task result pushed) and 160-162 (is_deleted=true, is_suspicious).
    #[test]
    fn walk_deleted_exe_full_chain_with_deleted_marker() {
        todo!()
    }
}
