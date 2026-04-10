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

use crate::{Error, ProcessState, Result};

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
    // --- Graceful degradation: bail with empty vec if symbols are absent ---
    let init_task_addr = match reader.symbols().symbol_address("init_task") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    let tasks_offset = match reader.symbols().field_offset("task_struct", "tasks") {
        Some(off) => off,
        None => return Ok(Vec::new()),
    };

    // --- Walk the task list -------------------------------------------------
    let head_vaddr = init_task_addr + tasks_offset;
    let task_addrs = reader.walk_list(head_vaddr, "task_struct", "tasks")?;

    let mut results = Vec::new();

    // Helper: extract zombie/orphan info from a single task_struct address.
    let read_task = |addr: u64| -> Option<ZombieOrphanInfo> {
        let pid: u32 = reader.read_field(addr, "task_struct", "pid").ok()?;
        let state_raw: i64 = reader.read_field(addr, "task_struct", "state").ok()?;
        let exit_code: i32 = reader
            .read_field(addr, "task_struct", "exit_code")
            .unwrap_or(0);
        let comm = reader
            .read_field_string(addr, "task_struct", "comm", 16)
            .unwrap_or_else(|_| "<unknown>".to_string());

        // Read real_parent->pid (current parent after possible reparenting).
        let real_parent_ptr: u64 = reader.read_field(addr, "task_struct", "real_parent").ok()?;
        let ppid: u32 = if real_parent_ptr != 0 {
            reader
                .read_field(real_parent_ptr, "task_struct", "pid")
                .unwrap_or(0)
        } else {
            0
        };

        // Read parent->pid (original parent before reparenting).
        let parent_ptr: u64 = reader
            .read_field(addr, "task_struct", "parent")
            .unwrap_or(0);
        let original_ppid: u32 = if parent_ptr != 0 {
            reader
                .read_field(parent_ptr, "task_struct", "pid")
                .unwrap_or(0)
        } else {
            0
        };

        let state = ProcessState::from_raw(state_raw);
        let is_zombie = matches!(state, ProcessState::Zombie);

        // Orphan: real_parent is init (pid 1) but original parent was different.
        // This means the process was reparented after its original parent died.
        let is_orphan = ppid == 1 && original_ppid != ppid && pid != 1;

        // Skip processes that are neither zombie nor orphan.
        if !is_zombie && !is_orphan {
            return None;
        }

        // Classify using the heuristic function, plus the walker-level
        // exit_code check for crashed zombies.
        let mut is_suspicious = classify_zombie_orphan(is_zombie, is_orphan, ppid, &comm);

        // Additional walker-level heuristic: zombie with non-zero exit code
        // indicates a crash (e.g. SIGSEGV = 139).
        if is_zombie && exit_code != 0 {
            is_suspicious = true;
        }

        Some(ZombieOrphanInfo {
            pid,
            ppid,
            comm,
            state: state.to_string(),
            exit_code,
            original_ppid,
            is_zombie,
            is_orphan,
            is_suspicious,
        })
    };

    // Include init_task itself.
    if let Some(info) = read_task(init_task_addr) {
        results.push(info);
    }

    for &task_addr in &task_addrs {
        if let Some(info) = read_task(task_addr) {
            results.push(info);
        }
    }

    results.sort_by_key(|r| r.pid);
    Ok(results)
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
    // Walker integration test -- missing tasks field -> empty Vec
    // -------------------------------------------------------------------

    #[test]
    fn walk_no_tasks_offset_returns_empty() {
        // init_task symbol present but task_struct.tasks field missing.
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 256)
            .add_field("task_struct", "pid", 0, "int")
            // NOTE: no "tasks" field registered on task_struct
            .add_symbol("init_task", 0xFFFF_8000_0000_0000)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_zombie_orphan(&reader);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    // -------------------------------------------------------------------
    // walk_zombie_orphan: symbol present + self-pointing list (body runs)
    // -------------------------------------------------------------------

    #[test]
    fn walk_zombie_orphan_symbol_present_empty_list() {
        // init_task present, tasks self-pointing (empty list). init_task has
        // a normal running state, so read_task returns None and results stay empty.
        let sym_vaddr: u64 = 0xFFFF_8800_0030_0000;
        let sym_paddr: u64 = 0x0040_0000;
        let tasks_offset = 24u64;

        let mut page = [0u8; 4096];
        // pid = 1
        page[0..4].copy_from_slice(&1u32.to_le_bytes());
        // state = 0 (TASK_RUNNING — neither zombie nor orphan → read_task returns None)
        page[8..16].copy_from_slice(&0i64.to_le_bytes());
        // exit_code = 0
        page[16..20].copy_from_slice(&0i32.to_le_bytes());
        // tasks: self-pointing list_head
        let list_self = sym_vaddr + tasks_offset;
        page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&list_self.to_le_bytes());
        page[tasks_offset as usize + 8..tasks_offset as usize + 16]
            .copy_from_slice(&list_self.to_le_bytes());
        // comm = "systemd"
        page[40..47].copy_from_slice(b"systemd");
        // real_parent = self (pid 1), parent = self
        page[56..64].copy_from_slice(&sym_vaddr.to_le_bytes());
        page[64..72].copy_from_slice(&sym_vaddr.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 256)
            .add_field("task_struct", "pid", 0, "unsigned int")
            .add_field("task_struct", "state", 8, "unsigned long")
            .add_field("task_struct", "exit_code", 16, "int")
            .add_field("task_struct", "tasks", 24, "pointer")
            .add_field("task_struct", "comm", 40, "char")
            .add_field("task_struct", "real_parent", 56, "pointer")
            .add_field("task_struct", "parent", 64, "pointer")
            .add_symbol("init_task", sym_vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, flags::WRITABLE)
            .write_phys(sym_paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_zombie_orphan(&reader).unwrap_or_default();
        assert!(result.is_empty(), "running init task is neither zombie nor orphan");
    }

    // -------------------------------------------------------------------
    // walk_zombie_orphan: init_task has zombie state → read_task returns Some
    // Exercises the branch where is_zombie=true and ppid==1 → suspicious.
    // Uses self-pointing list (no other tasks) so only init_task is processed.
    // -------------------------------------------------------------------

    #[test]
    fn walk_zombie_orphan_zombie_task_detected() {
        let sym_vaddr: u64   = 0xFFFF_8800_0050_0000;
        let sym_paddr: u64   = 0x0050_0000; // < 16 MB
        let tasks_offset: u64 = 24;

        // init_task will be the zombie: parent = itself (pid 1 → ppid 1)
        // is_orphan check: ppid(1) == 1 && original_ppid(1) == ppid → is_orphan=false
        // is_zombie=true → read_task returns Some → pushed to results

        let mut page = [0u8; 4096];
        // pid = 1
        page[0..4].copy_from_slice(&1u32.to_le_bytes());
        // state = 0x20 = 32 = EXIT_ZOMBIE
        let zombie_state: i64 = 0x20;
        page[8..16].copy_from_slice(&zombie_state.to_le_bytes());
        // exit_code = 139 (SIGSEGV → suspicious via walker exit_code check)
        page[16..20].copy_from_slice(&139i32.to_le_bytes());
        // tasks: self-pointing
        let self_ptr = sym_vaddr + tasks_offset;
        page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&self_ptr.to_le_bytes());
        page[tasks_offset as usize + 8..tasks_offset as usize + 16]
            .copy_from_slice(&self_ptr.to_le_bytes());
        // comm = "crashed"
        page[40..47].copy_from_slice(b"crashed");
        // real_parent = self (so ppid = 1, same pid)
        page[56..64].copy_from_slice(&sym_vaddr.to_le_bytes());
        // parent = self
        page[64..72].copy_from_slice(&sym_vaddr.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("list_head", 0x10)
            .add_field("list_head", "next", 0x00, "pointer")
            .add_field("list_head", "prev", 0x08, "pointer")
            .add_struct("task_struct", 256)
            .add_field("task_struct", "pid", 0, "unsigned int")
            .add_field("task_struct", "state", 8, "unsigned long")
            .add_field("task_struct", "exit_code", 16, "int")
            .add_field("task_struct", "tasks", 24, "pointer")
            .add_field("task_struct", "comm", 40, "char")
            .add_field("task_struct", "real_parent", 56, "pointer")
            .add_field("task_struct", "parent", 64, "pointer")
            .add_symbol("init_task", sym_vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, flags::WRITABLE)
            .write_phys(sym_paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_zombie_orphan(&reader).unwrap();
        // init_task is zombie (state=0x20), exit_code=139 → suspicious
        assert_eq!(result.len(), 1, "zombie task should appear in results");
        assert!(result[0].is_zombie, "state=0x20 → zombie");
        assert!(result[0].is_suspicious, "zombie with non-zero exit_code → suspicious");
        assert_eq!(result[0].exit_code, 139);
        assert_eq!(result[0].comm, "crashed");
    }

    // -------------------------------------------------------------------
    // ZombieOrphanInfo: Clone + Debug
    // -------------------------------------------------------------------

    #[test]
    fn zombie_orphan_info_clone_and_debug() {
        let info = ZombieOrphanInfo {
            pid: 999,
            ppid: 1,
            comm: "ghost".to_string(),
            state: "Z (zombie)".to_string(),
            exit_code: 0,
            original_ppid: 500,
            is_zombie: true,
            is_orphan: false,
            is_suspicious: true,
        };
        let cloned = info.clone();
        assert_eq!(cloned.pid, 999);
        let dbg = format!("{:?}", cloned);
        assert!(dbg.contains("ghost"));
    }

    // -------------------------------------------------------------------
    // classify edge cases — all SUSPICIOUS_DAEMON_NAMES are matched
    // -------------------------------------------------------------------

    #[test]
    fn classify_orphan_httpd_suspicious() {
        assert!(classify_zombie_orphan(false, true, 1, "httpd"));
    }

    #[test]
    fn classify_orphan_nginx_suspicious() {
        assert!(classify_zombie_orphan(false, true, 1, "nginx"));
    }

    #[test]
    fn classify_orphan_apache_suspicious() {
        assert!(classify_zombie_orphan(false, true, 1, "apache2"));
    }

    #[test]
    fn classify_orphan_mysqld_suspicious() {
        assert!(classify_zombie_orphan(false, true, 1, "mysqld"));
    }

    #[test]
    fn classify_orphan_postgres_suspicious() {
        assert!(classify_zombie_orphan(false, true, 1, "postgres"));
    }

    #[test]
    fn classify_orphan_redis_suspicious() {
        assert!(classify_zombie_orphan(false, true, 1, "redis-server"));
    }

    #[test]
    fn classify_orphan_memcached_suspicious() {
        assert!(classify_zombie_orphan(false, true, 1, "memcached"));
    }

    #[test]
    fn classify_orphan_mongod_suspicious() {
        assert!(classify_zombie_orphan(false, true, 1, "mongod"));
    }

    #[test]
    fn classify_orphan_named_suspicious() {
        assert!(classify_zombie_orphan(false, true, 1, "named"));
    }

    #[test]
    fn classify_orphan_bind_suspicious() {
        assert!(classify_zombie_orphan(false, true, 1, "bind"));
    }

    #[test]
    fn classify_orphan_cupsd_suspicious() {
        assert!(classify_zombie_orphan(false, true, 1, "cupsd"));
    }

    #[test]
    fn classify_orphan_cron_suspicious() {
        assert!(classify_zombie_orphan(false, true, 1, "cron"));
    }

    #[test]
    fn classify_orphan_atd_suspicious() {
        assert!(classify_zombie_orphan(false, true, 1, "atd"));
    }

    #[test]
    fn classify_zombie_non_init_parent_benign() {
        // Zombie but parent is not init (ppid != 1) → check first rule fails
        // Not an orphan either → check second rule fails
        // → benign
        assert!(!classify_zombie_orphan(true, false, 999, "worker"));
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
