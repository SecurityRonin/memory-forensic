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

const SUSPICIOUS_DAEMON_NAMES: &[&str] = &[
    "sshd", "httpd", "nginx", "apache", "mysqld", "postgres", "redis",
    "memcached", "mongod", "named", "bind", "cupsd", "cron", "atd",
];

/// Information about a zombie or orphan process found in memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ZombieOrphanInfo {
    /// Process ID.
    pub pid: u32,
    /// PID of the current parent (may be 1/init after reparenting).
    pub ppid: u32,
    /// Process name from `task_struct.comm`.
    pub comm: String,
    /// Human-readable process state string.
    pub state: String,
    /// Exit code stored in `task_struct.exit_code`.
    pub exit_code: i32,
    /// PID of the original parent before any reparenting.
    pub original_ppid: u32,
    /// True if the process is in zombie state (exited, not yet reaped).
    pub is_zombie: bool,
    /// True if the process was reparented to init (PID 1).
    pub is_orphan: bool,
    /// True if heuristics flag this entry as anomalous.
    pub is_suspicious: bool,
}

/// Classify whether a zombie/orphan process is suspicious.
pub fn classify_zombie_orphan(is_zombie: bool, is_orphan: bool, ppid: u32, comm: &str) -> bool {
    if is_zombie && ppid == 1 {
        return true;
    }
    if is_orphan {
        let lower = comm.to_lowercase();
        if SUSPICIOUS_DAEMON_NAMES
            .iter()
            .any(|&name| lower.contains(name))
        {
            return true;
        }
    }
    false
}

/// Walk the Linux process list and detect zombie and orphan processes.
pub fn walk_zombie_orphan<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<ZombieOrphanInfo>> {
    let init_task_addr = match reader.symbols().symbol_address("init_task") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    let tasks_offset = match reader.symbols().field_offset("task_struct", "tasks") {
        Some(off) => off,
        None => return Ok(Vec::new()),
    };

    let head_vaddr = init_task_addr + tasks_offset;
    let task_addrs = reader.walk_list(head_vaddr, "task_struct", "tasks")?;

    let mut results = Vec::new();

    let read_task = |addr: u64| -> Option<ZombieOrphanInfo> {
        let pid: u32 = reader.read_field(addr, "task_struct", "pid").ok()?;
        let state_raw: i64 = reader.read_field(addr, "task_struct", "state").ok()?;
        let exit_code: i32 = reader
            .read_field(addr, "task_struct", "exit_code")
            .unwrap_or(0);
        let comm = reader
            .read_field_string(addr, "task_struct", "comm", 16)
            .unwrap_or_else(|_| "<unknown>".to_string());

        let real_parent_ptr: u64 = reader.read_field(addr, "task_struct", "real_parent").ok()?;
        let ppid: u32 = if real_parent_ptr != 0 {
            reader
                .read_field(real_parent_ptr, "task_struct", "pid")
                .unwrap_or(0)
        } else {
            0
        };

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
        let is_orphan = ppid == 1 && original_ppid != ppid && pid != 1;

        if !is_zombie && !is_orphan {
            return None;
        }

        let mut is_suspicious = classify_zombie_orphan(is_zombie, is_orphan, ppid, &comm);
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

    #[test]
    fn classify_reparented_zombie_suspicious() {
        assert!(classify_zombie_orphan(true, false, 1, "evil_proc"));
    }

    #[test]
    fn classify_orphan_daemon_suspicious() {
        assert!(classify_zombie_orphan(false, true, 1, "sshd"));
    }

    #[test]
    fn classify_normal_zombie_benign() {
        assert!(!classify_zombie_orphan(true, false, 500, "worker"));
    }

    #[test]
    fn classify_normal_process_benign() {
        assert!(!classify_zombie_orphan(false, false, 500, "bash"));
    }

    #[test]
    fn classify_crashed_zombie_suspicious() {
        assert!(classify_zombie_orphan(true, false, 1, "payload"));
    }

    #[test]
    fn classify_orphan_non_daemon_benign() {
        assert!(!classify_zombie_orphan(false, true, 1, "my_script"));
    }

    #[test]
    fn classify_orphan_daemon_case_insensitive() {
        assert!(classify_zombie_orphan(false, true, 1, "NGINX"));
    }

    #[test]
    fn walk_no_symbol_returns_empty() {
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
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_zombie_orphan(&reader);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn walk_no_tasks_offset_returns_empty() {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 256)
            .add_field("task_struct", "pid", 0, "int")
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

    #[test]
    fn walk_zombie_orphan_symbol_present_empty_list() {
        let sym_vaddr: u64 = 0xFFFF_8800_0030_0000;
        let sym_paddr: u64 = 0x0040_0000;
        let tasks_offset = 24u64;

        let mut page = [0u8; 4096];
        page[0..4].copy_from_slice(&1u32.to_le_bytes());
        page[8..16].copy_from_slice(&0i64.to_le_bytes());
        page[16..20].copy_from_slice(&0i32.to_le_bytes());
        let list_self = sym_vaddr + tasks_offset;
        page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&list_self.to_le_bytes());
        page[tasks_offset as usize + 8..tasks_offset as usize + 16]
            .copy_from_slice(&list_self.to_le_bytes());
        page[40..47].copy_from_slice(b"systemd");
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

    #[test]
    fn walk_zombie_orphan_zombie_task_detected() {
        let sym_vaddr: u64   = 0xFFFF_8800_0050_0000;
        let sym_paddr: u64   = 0x0050_0000;
        let tasks_offset: u64 = 24;

        let mut page = [0u8; 4096];
        page[0..4].copy_from_slice(&1u32.to_le_bytes());
        let zombie_state: i64 = 0x20;
        page[8..16].copy_from_slice(&zombie_state.to_le_bytes());
        page[16..20].copy_from_slice(&139i32.to_le_bytes());
        let self_ptr = sym_vaddr + tasks_offset;
        page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&self_ptr.to_le_bytes());
        page[tasks_offset as usize + 8..tasks_offset as usize + 16]
            .copy_from_slice(&self_ptr.to_le_bytes());
        page[40..47].copy_from_slice(b"crashed");
        page[56..64].copy_from_slice(&sym_vaddr.to_le_bytes());
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
        assert_eq!(result.len(), 1, "zombie task should appear in results");
        assert!(result[0].is_zombie, "state=0x20 → zombie");
        assert!(result[0].is_suspicious, "zombie with non-zero exit_code → suspicious");
        assert_eq!(result[0].exit_code, 139);
        assert_eq!(result[0].comm, "crashed");
    }

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
        assert!(!classify_zombie_orphan(true, false, 999, "worker"));
    }

    #[test]
    fn zombie_orphan_serializes() {
        let info = ZombieOrphanInfo {
            pid: 1234,
            ppid: 1,
            comm: "evil_proc".to_string(),
            state: "Z (zombie)".to_string(),
            exit_code: 139,
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
