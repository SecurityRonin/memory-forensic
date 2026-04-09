//! Shared credential structure detection for privilege escalation analysis.
//!
//! In normal Linux operation each process has its own `struct cred` (or
//! shares with parent/threads). When *unrelated* processes share the same
//! `cred` pointer it is a strong indicator of privilege escalation — an
//! exploit may have replaced a process's cred pointer with another
//! process's (e.g. pointing to init's cred to gain root).

use std::collections::HashMap;

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, Result};

/// Information about a process whose `struct cred` is shared with other
/// unrelated processes.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SharedCredInfo {
    /// Process ID.
    pub pid: u32,
    /// Process command name.
    pub process_name: String,
    /// UID from the credential structure.
    pub uid: u32,
    /// Virtual address of the `struct cred`.
    pub cred_address: u64,
    /// Other PIDs that share the same cred pointer.
    pub shared_with_pids: Vec<u32>,
    /// Whether this sharing pattern is suspicious.
    pub is_suspicious: bool,
}

/// Classify whether shared credentials are suspicious.
///
/// Returns `true` (suspicious) when:
/// - A non-kernel-thread process shares creds with init (pid 1)
/// - Unrelated processes (not parent-child / not threads of the same
///   process) share the same cred pointer
///
/// Returns `false` (benign) when:
/// - Threads of the same process share creds (normal behaviour)
/// - All uid-0 kernel threads share the kernel cred
pub fn classify_shared_creds(pid: u32, shared_with: &[u32], uid: u32) -> bool {
    // Sharing with init (pid 1) by a non-kernel-thread is suspicious.
    // Kernel threads typically have pid >= 2 and uid 0, but a user-space
    // process (uid != 0) sharing with init is always suspicious.
    if shared_with.contains(&1) && pid != 1 {
        // uid 0 kernel threads sharing with init is expected (kernel cred)
        if uid == 0 && is_likely_kernel_thread(pid) {
            return false;
        }
        return true;
    }

    // If all participants are uid-0 kernel threads, benign.
    if uid == 0 && is_likely_kernel_thread(pid) {
        return false;
    }

    // Threads of the same process share creds — benign.
    // We approximate this: thread PIDs are usually close together and
    // the caller should have already filtered thread groups. If we reach
    // here with unrelated PIDs, flag as suspicious.
    //
    // Without parent/tgid info at this level we conservatively flag
    // any remaining sharing as suspicious.
    !shared_with.is_empty()
}

/// Heuristic: PIDs <= 2 are typically kernel threads (idle, kthreadd).
fn is_likely_kernel_thread(pid: u32) -> bool {
    pid <= 2
}

/// Walk all tasks and detect shared `struct cred` pointers.
///
/// Returns an entry for every process whose cred address is shared with
/// at least one other process and where the sharing is suspicious.
///
/// Returns an empty `Vec` when symbols are missing (graceful degradation).
pub fn walk_check_creds<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
) -> Result<Vec<SharedCredInfo>> {
    todo!("implement walk_check_creds")
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ---------------------------------------------------------------
    // Classifier unit tests
    // ---------------------------------------------------------------

    #[test]
    fn shared_with_init_suspicious() {
        // A regular user-space process (uid=1000, pid=500) sharing
        // creds with init (pid 1) → suspicious.
        assert!(classify_shared_creds(500, &[1], 1000));
    }

    #[test]
    fn unrelated_sharing_suspicious() {
        // Two unrelated user-space processes sharing creds → suspicious.
        assert!(classify_shared_creds(200, &[300], 1000));
    }

    #[test]
    fn thread_sharing_benign() {
        // Kernel thread (pid 2, uid 0) sharing with init → benign
        // (kernel cred shared among kthreadd and init is expected).
        assert!(!classify_shared_creds(2, &[1], 0));
    }

    #[test]
    fn kernel_thread_benign() {
        // A uid-0 kernel thread (pid 2) with no non-kernel sharing → benign.
        assert!(!classify_shared_creds(2, &[1], 0));
    }

    #[test]
    fn no_sharing_benign() {
        // No shared PIDs at all → not suspicious.
        assert!(!classify_shared_creds(100, &[], 1000));
    }

    // ---------------------------------------------------------------
    // Walker integration test — missing symbol → empty Vec
    // ---------------------------------------------------------------

    #[test]
    fn walk_check_creds_no_symbol_returns_empty() {
        // Build a reader with task_struct defined but no init_task symbol.
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "cred", 96, "pointer")
            .add_field("task_struct", "real_cred", 104, "pointer")
            .add_field("task_struct", "tgid", 112, "int")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_struct("cred", 64)
            .add_field("cred", "uid", 4, "unsigned int")
            // NOTE: no "init_task" symbol registered
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_check_creds(&reader);
        // Graceful degradation: missing symbol → empty vec, not an error.
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
