//! Detailed process information extraction (Linux `ps aux` equivalent).
//!
//! Extracts runtime statistics from each `task_struct`: CPU state,
//! virtual/resident memory sizes, TTY, process state, nice value.
//! Extends basic process enumeration with data useful for DFIR triage.
//! Identifies zombie processes, stopped processes, and resource anomalies.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Linux `PF_KTHREAD` flag — set on kernel threads.
const PF_KTHREAD: u64 = 0x0020_0000;

/// Threshold for extremely large virtual memory size (100 GB).
const VSIZE_ABUSE_THRESHOLD: u64 = 100 * 1024 * 1024 * 1024;

/// Detailed process information similar to `ps aux` output.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PsAuxInfo {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// User ID (from `task_struct.cred->uid`).
    pub uid: u32,
    /// Group ID (from `task_struct.cred->gid`).
    pub gid: u32,
    /// Command name (`task_struct.comm`, max 16 chars).
    pub comm: String,
    /// Human-readable process state name.
    pub state: String,
    /// Nice value (`task_struct.static_prio - 120`).
    pub nice: i32,
    /// Virtual memory size in bytes (`mm->total_vm * PAGE_SIZE`).
    pub vsize: u64,
    /// Resident set size in pages (`mm->rss_stat`).
    pub rss: u64,
    /// Controlling TTY name, or empty string if none.
    pub tty: String,
    /// Process start time in nanoseconds since boot.
    pub start_time: u64,
    /// Raw `task_struct.flags` value.
    pub flags: u64,
    /// Whether heuristic analysis flagged this process as suspicious.
    pub is_suspicious: bool,
}

/// Map a raw Linux task state value to a human-readable name.
///
/// Uses the kernel's `__TASK_*` bitmask values.
pub fn task_state_name(state: u64) -> String {
    match state {
        0 => "Running".to_string(),
        1 => "Sleeping".to_string(),
        2 => "DiskSleep".to_string(),
        4 => "Stopped".to_string(),
        8 => "Tracing".to_string(),
        16 => "Zombie".to_string(),
        32 => "Dead".to_string(),
        64 => "Wakekill".to_string(),
        128 => "Waking".to_string(),
        256 => "Parked".to_string(),
        _ => format!("Unknown({})", state),
    }
}

/// Classify a process as suspicious based on forensic heuristics.
///
/// Returns `true` if any of these conditions hold:
/// - Zombie process (state=16) with UID 0 — root zombies are unusual
///   and may indicate a rootkit leaving behind artifacts.
/// - `PF_KTHREAD` flag set but UID != 0 — userspace process
///   impersonating a kernel thread.
/// - Extremely large vsize (> 100 GB) — potential memory abuse or
///   mapping anomaly.
pub fn classify_psaux(state: u64, uid: u32, flags: u64, vsize: u64) -> bool {
    // Root zombie: zombie state + UID 0
    if state == 16 && uid == 0 {
        return true;
    }

    // Fake kthread: PF_KTHREAD flag set but not running as root
    if (flags & PF_KTHREAD) != 0 && uid != 0 {
        return true;
    }

    // Absurd vsize: > 100 GB
    if vsize > VSIZE_ABUSE_THRESHOLD {
        return true;
    }

    false
}

/// Walk the Linux process list and extract detailed `ps aux`-style information.
///
/// Looks up `init_task`, then traverses the `task_struct.tasks` linked list.
/// For each process, reads PID, PPID, UID/GID (from `cred`), nice value,
/// flags, virtual/resident memory sizes, controlling TTY, and start time.
///
/// Returns `Ok(Vec::new())` when the `init_task` symbol is not found
/// (e.g., wrong profile or missing symbols).
pub fn walk_psaux<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
) -> Result<Vec<PsAuxInfo>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // task_state_name tests
    // -----------------------------------------------------------------------

    #[test]
    fn state_running() {
        assert_eq!(task_state_name(0), "Running");
    }

    #[test]
    fn state_zombie() {
        assert_eq!(task_state_name(16), "Zombie");
    }

    #[test]
    fn state_unknown() {
        assert_eq!(task_state_name(999), "Unknown(999)");
    }

    #[test]
    fn state_sleeping() {
        assert_eq!(task_state_name(1), "Sleeping");
    }

    #[test]
    fn state_disk_sleep() {
        assert_eq!(task_state_name(2), "DiskSleep");
    }

    #[test]
    fn state_stopped() {
        assert_eq!(task_state_name(4), "Stopped");
    }

    #[test]
    fn state_dead() {
        assert_eq!(task_state_name(32), "Dead");
    }

    // -----------------------------------------------------------------------
    // classify_psaux tests
    // -----------------------------------------------------------------------

    #[test]
    fn classify_root_zombie_suspicious() {
        // Zombie (state=16) + UID 0 → suspicious
        assert!(classify_psaux(16, 0, 0, 0));
    }

    #[test]
    fn classify_fake_kthread_suspicious() {
        // PF_KTHREAD flag set but UID != 0 → suspicious
        assert!(classify_psaux(0, 1000, PF_KTHREAD, 0));
    }

    #[test]
    fn classify_huge_vsize_suspicious() {
        // > 100 GB vsize → suspicious
        let huge = 200 * 1024 * 1024 * 1024; // 200 GB
        assert!(classify_psaux(0, 1000, 0, huge));
    }

    #[test]
    fn classify_normal_benign() {
        // Normal sleeping process, UID 1000, no flags, 1 GB vsize
        assert!(!classify_psaux(1, 1000, 0, 1024 * 1024 * 1024));
    }

    #[test]
    fn classify_root_kthread_benign() {
        // PF_KTHREAD with UID 0 is normal (real kernel thread)
        assert!(!classify_psaux(0, 0, PF_KTHREAD, 0));
    }

    #[test]
    fn classify_nonroot_zombie_benign() {
        // Zombie but not root → not suspicious by this heuristic
        assert!(!classify_psaux(16, 1000, 0, 0));
    }

    // -----------------------------------------------------------------------
    // walk_psaux tests
    // -----------------------------------------------------------------------

    #[test]
    fn walk_no_symbol_returns_empty() {
        use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Build an ISF with task_struct but NO init_task symbol
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
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_psaux(&reader).unwrap();
        assert!(result.is_empty());
    }
}
