//! Detailed process information extraction (Linux `ps aux` equivalent).
//!
//! Extracts runtime statistics from each `task_struct`: CPU state,
//! virtual/resident memory sizes, TTY, process state, nice value.
//! Extends basic process enumeration with data useful for DFIR triage.
//! Identifies zombie processes, stopped processes, and resource anomalies.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use std::collections::HashSet;

use crate::{Error, Result};

/// Linux `PF_KTHREAD` flag — set on kernel threads.
const PF_KTHREAD: u64 = 0x0020_0000;

/// Threshold for extremely large virtual memory size (100 GB).
const VSIZE_ABUSE_THRESHOLD: u64 = 100 * 1024 * 1024 * 1024;

/// Maximum number of processes to enumerate (safety bound).
const MAX_PROCESSES: usize = 8192;

/// x86_64 page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

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
pub fn walk_psaux<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>) -> Result<Vec<PsAuxInfo>> {
    let init_task_addr = match reader.symbols().symbol_address("init_task") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    let tasks_offset = reader
        .symbols()
        .field_offset("task_struct", "tasks")
        .ok_or_else(|| Error::Walker("task_struct.tasks field not found".into()))?;

    let head_vaddr = init_task_addr + tasks_offset;
    let task_addrs = reader.walk_list(head_vaddr, "task_struct", "tasks")?;

    let mut results = Vec::new();
    let mut seen = HashSet::new();

    // Include init_task itself (it's the list head, not in walk results)
    if let Ok(info) = read_psaux_info(reader, init_task_addr) {
        seen.insert(init_task_addr);
        results.push(info);
    }

    for &task_addr in &task_addrs {
        if results.len() >= MAX_PROCESSES {
            break;
        }
        if !seen.insert(task_addr) {
            // Cycle detected
            break;
        }
        if let Ok(info) = read_psaux_info(reader, task_addr) {
            results.push(info);
        }
    }

    results.sort_by_key(|p| p.pid);
    Ok(results)
}

/// Read detailed process info from a single `task_struct`.
fn read_psaux_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
) -> Result<PsAuxInfo> {
    let pid: u32 = reader.read_field(task_addr, "task_struct", "pid")?;
    let comm = reader.read_field_string(task_addr, "task_struct", "comm", 16)?;

    // State — read as u64 to handle both `long` and `unsigned long` layouts.
    let state: u64 = reader
        .read_field::<i64>(task_addr, "task_struct", "state")
        .map(|v| v as u64)
        .unwrap_or(0);

    let ppid = read_parent_pid(reader, task_addr).unwrap_or(0);

    // Credentials (uid, gid) from task_struct.cred pointer
    let (uid, gid) = read_cred_ids(reader, task_addr).unwrap_or((0, 0));

    // Nice value: static_prio - 120
    let nice: i32 = reader
        .read_field::<i32>(task_addr, "task_struct", "static_prio")
        .map(|prio| prio - 120)
        .unwrap_or(0);

    // Flags
    let flags: u64 = reader
        .read_field::<u32>(task_addr, "task_struct", "flags")
        .map(u64::from)
        .unwrap_or(0);

    // Virtual memory size and RSS from mm_struct
    let (vsize, rss) = read_mm_stats(reader, task_addr).unwrap_or((0, 0));

    // TTY name from signal->tty
    let tty = read_tty_name(reader, task_addr).unwrap_or_default();

    // Start time
    let start_time: u64 = reader
        .read_field(task_addr, "task_struct", "real_start_time")
        .or_else(|_| reader.read_field(task_addr, "task_struct", "start_time"))
        .unwrap_or(0);

    let state_name = task_state_name(state);
    let is_suspicious = classify_psaux(state, uid, flags, vsize);

    Ok(PsAuxInfo {
        pid,
        ppid,
        uid,
        gid,
        comm,
        state: state_name,
        nice,
        vsize,
        rss,
        tty,
        start_time,
        flags,
        is_suspicious,
    })
}

/// Read parent PID by following `task_struct.real_parent`.
fn read_parent_pid<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
) -> Result<u32> {
    let parent_ptr: u64 = reader.read_field(task_addr, "task_struct", "real_parent")?;
    if parent_ptr == 0 {
        return Ok(0);
    }
    let ppid: u32 = reader.read_field(parent_ptr, "task_struct", "pid")?;
    Ok(ppid)
}

/// Read UID and GID from the `cred` structure pointed to by `task_struct.cred`.
fn read_cred_ids<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
) -> Result<(u32, u32)> {
    let cred_ptr: u64 = reader.read_field(task_addr, "task_struct", "cred")?;
    if cred_ptr == 0 {
        return Ok((0, 0));
    }
    let uid: u32 = reader.read_field(cred_ptr, "cred", "uid").unwrap_or(0);
    let gid: u32 = reader.read_field(cred_ptr, "cred", "gid").unwrap_or(0);
    Ok((uid, gid))
}

/// Read virtual memory size and RSS from `task_struct.mm`.
fn read_mm_stats<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
) -> Result<(u64, u64)> {
    let mm_ptr: u64 = reader.read_field(task_addr, "task_struct", "mm")?;
    if mm_ptr == 0 {
        // Kernel thread — no mm
        return Ok((0, 0));
    }
    let total_vm: u64 = reader
        .read_field::<u64>(mm_ptr, "mm_struct", "total_vm")
        .unwrap_or(0);
    let rss: u64 = reader
        .read_field::<u64>(mm_ptr, "mm_struct", "rss_stat")
        .unwrap_or(0);
    Ok((total_vm * PAGE_SIZE, rss))
}

/// Read the controlling TTY name from `task_struct.signal->tty`.
fn read_tty_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
) -> Result<String> {
    let signal_ptr: u64 = reader.read_field(task_addr, "task_struct", "signal")?;
    if signal_ptr == 0 {
        return Ok(String::new());
    }
    let tty_ptr: u64 = reader
        .read_field(signal_ptr, "signal_struct", "tty")
        .unwrap_or(0);
    if tty_ptr == 0 {
        return Ok(String::new());
    }
    let name = reader
        .read_field_string(tty_ptr, "tty_struct", "name", 64)
        .unwrap_or_default();
    Ok(name)
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

    #[test]
    fn state_tracing() {
        assert_eq!(task_state_name(8), "Tracing");
    }

    #[test]
    fn state_wakekill() {
        assert_eq!(task_state_name(64), "Wakekill");
    }

    #[test]
    fn state_waking() {
        assert_eq!(task_state_name(128), "Waking");
    }

    #[test]
    fn state_parked() {
        assert_eq!(task_state_name(256), "Parked");
    }

    #[test]
    fn state_unknown_zero_based_checks() {
        // Verify a variety of non-matching values produce Unknown(n)
        assert_eq!(task_state_name(3), "Unknown(3)");
        assert_eq!(task_state_name(5), "Unknown(5)");
        assert_eq!(task_state_name(512), "Unknown(512)");
        assert_eq!(task_state_name(u64::MAX), format!("Unknown({})", u64::MAX));
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
    fn classify_exact_vsize_threshold_suspicious() {
        // Exactly one byte over the threshold → suspicious
        let over = VSIZE_ABUSE_THRESHOLD + 1;
        assert!(classify_psaux(0, 1000, 0, over));
    }

    #[test]
    fn classify_exact_vsize_threshold_benign() {
        // Exactly at the threshold → not suspicious (> not >=)
        assert!(!classify_psaux(0, 1000, 0, VSIZE_ABUSE_THRESHOLD));
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

    #[test]
    fn classify_pf_kthread_uid_1_suspicious() {
        // PF_KTHREAD with uid=1 (not root) → suspicious
        assert!(classify_psaux(0, 1, PF_KTHREAD, 0));
    }

    #[test]
    fn classify_multiple_flags_with_pf_kthread_nonroot_suspicious() {
        // Additional flags alongside PF_KTHREAD, nonroot → still suspicious
        let flags = PF_KTHREAD | 0x0001_0000;
        assert!(classify_psaux(0, 500, flags, 0));
    }

    // -----------------------------------------------------------------------
    // PsAuxInfo struct tests
    // -----------------------------------------------------------------------

    #[test]
    fn ps_aux_info_serializes_to_json() {
        let info = PsAuxInfo {
            pid: 42,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "bash".to_string(),
            state: "Sleeping".to_string(),
            nice: 0,
            vsize: 4096,
            rss: 2,
            tty: "pts/0".to_string(),
            start_time: 12345678,
            flags: 0,
            is_suspicious: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":42"));
        assert!(json.contains("\"comm\":\"bash\""));
        assert!(json.contains("\"state\":\"Sleeping\""));
        assert!(json.contains("\"is_suspicious\":false"));
        assert!(json.contains("\"tty\":\"pts/0\""));
    }

    #[test]
    fn ps_aux_info_clone_and_debug() {
        let info = PsAuxInfo {
            pid: 1,
            ppid: 0,
            uid: 0,
            gid: 0,
            comm: "systemd".to_string(),
            state: "Running".to_string(),
            nice: -5,
            vsize: 0,
            rss: 0,
            tty: String::new(),
            start_time: 0,
            flags: 0,
            is_suspicious: false,
        };
        let cloned = info.clone();
        assert_eq!(cloned.pid, 1);
        // Debug trait exercised
        let debug_str = format!("{:?}", cloned);
        assert!(debug_str.contains("systemd"));
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

    #[test]
    fn walk_missing_tasks_field_returns_error() {
        use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // init_task symbol present, but task_struct.tasks field is missing
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            // NOTE: no "tasks" field
            .add_symbol("init_task", 0xFFFF_8000_0010_0000)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_psaux(&reader);
        assert!(result.is_err(), "missing tasks field must return an error");
    }
}
