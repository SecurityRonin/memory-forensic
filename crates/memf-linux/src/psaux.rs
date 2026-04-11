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
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub state: String,
    pub nice: i32,
    pub vsize: u64,
    pub rss: u64,
    pub tty: String,
    pub start_time: u64,
    pub flags: u64,
    pub is_suspicious: bool,
}

/// Map a raw Linux task state value to a human-readable name.
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
pub fn classify_psaux(state: u64, uid: u32, flags: u64, vsize: u64) -> bool {
    if state == 16 && uid == 0 {
        return true;
    }
    if (flags & PF_KTHREAD) != 0 && uid != 0 {
        return true;
    }
    if vsize > VSIZE_ABUSE_THRESHOLD {
        return true;
    }
    false
}

/// Walk the Linux process list and extract detailed `ps aux`-style information.
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

    if let Ok(info) = read_psaux_info(reader, init_task_addr) {
        seen.insert(init_task_addr);
        results.push(info);
    }

    for &task_addr in &task_addrs {
        if results.len() >= MAX_PROCESSES {
            break;
        }
        if !seen.insert(task_addr) {
            break;
        }
        if let Ok(info) = read_psaux_info(reader, task_addr) {
            results.push(info);
        }
    }

    results.sort_by_key(|p| p.pid);
    Ok(results)
}

fn read_psaux_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
) -> Result<PsAuxInfo> {
    let pid: u32 = reader.read_field(task_addr, "task_struct", "pid")?;
    let comm = reader.read_field_string(task_addr, "task_struct", "comm", 16)?;

    let state: u64 = reader
        .read_field::<i64>(task_addr, "task_struct", "state")
        .map(|v| v as u64)
        .unwrap_or(0);

    let ppid = read_parent_pid(reader, task_addr).unwrap_or(0);
    let (uid, gid) = read_cred_ids(reader, task_addr).unwrap_or((0, 0));

    let nice: i32 = reader
        .read_field::<i32>(task_addr, "task_struct", "static_prio")
        .map(|prio| prio - 120)
        .unwrap_or(0);

    let flags: u64 = reader
        .read_field::<u32>(task_addr, "task_struct", "flags")
        .map(u64::from)
        .unwrap_or(0);

    let (vsize, rss) = read_mm_stats(reader, task_addr).unwrap_or((0, 0));
    let tty = read_tty_name(reader, task_addr).unwrap_or_default();

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

fn read_mm_stats<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
) -> Result<(u64, u64)> {
    let mm_ptr: u64 = reader.read_field(task_addr, "task_struct", "mm")?;
    if mm_ptr == 0 {
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
        assert_eq!(task_state_name(3), "Unknown(3)");
        assert_eq!(task_state_name(5), "Unknown(5)");
        assert_eq!(task_state_name(512), "Unknown(512)");
        assert_eq!(task_state_name(u64::MAX), format!("Unknown({})", u64::MAX));
    }

    #[test]
    fn classify_root_zombie_suspicious() {
        assert!(classify_psaux(16, 0, 0, 0));
    }

    #[test]
    fn classify_fake_kthread_suspicious() {
        assert!(classify_psaux(0, 1000, PF_KTHREAD, 0));
    }

    #[test]
    fn classify_huge_vsize_suspicious() {
        let huge = 200 * 1024 * 1024 * 1024;
        assert!(classify_psaux(0, 1000, 0, huge));
    }

    #[test]
    fn classify_exact_vsize_threshold_suspicious() {
        let over = VSIZE_ABUSE_THRESHOLD + 1;
        assert!(classify_psaux(0, 1000, 0, over));
    }

    #[test]
    fn classify_exact_vsize_threshold_benign() {
        assert!(!classify_psaux(0, 1000, 0, VSIZE_ABUSE_THRESHOLD));
    }

    #[test]
    fn classify_normal_benign() {
        assert!(!classify_psaux(1, 1000, 0, 1024 * 1024 * 1024));
    }

    #[test]
    fn classify_root_kthread_benign() {
        assert!(!classify_psaux(0, 0, PF_KTHREAD, 0));
    }

    #[test]
    fn classify_nonroot_zombie_benign() {
        assert!(!classify_psaux(16, 1000, 0, 0));
    }

    #[test]
    fn classify_pf_kthread_uid_1_suspicious() {
        assert!(classify_psaux(0, 1, PF_KTHREAD, 0));
    }

    #[test]
    fn classify_multiple_flags_with_pf_kthread_nonroot_suspicious() {
        let flags = PF_KTHREAD | 0x0001_0000;
        assert!(classify_psaux(0, 500, flags, 0));
    }

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
        let debug_str = format!("{:?}", cloned);
        assert!(debug_str.contains("systemd"));
    }

    #[test]
    fn walk_no_symbol_returns_empty() {
        use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

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

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_symbol("init_task", 0xFFFF_8000_0010_0000)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_psaux(&reader);
        assert!(result.is_err(), "missing tasks field must return an error");
    }

    #[test]
    fn walk_psaux_with_readable_parent_and_minimal_fields() {
        use memf_core::test_builders::{flags as ptf, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let tasks_offset: u64   = 0x10;
        let parent_offset: u64  = 0x40;
        let cred_offset: u64    = 0x48;
        let mm_offset: u64      = 0x50;
        let signal_offset: u64  = 0x58;

        let sym_vaddr: u64    = 0xFFFF_8800_00B0_0000;
        let sym_paddr: u64    = 0x00B0_0000;
        let parent_vaddr: u64 = 0xFFFF_8800_00B1_0000;
        let parent_paddr: u64 = 0x00B1_0000;

        let mut task_page = [0u8; 4096];
        task_page[0..4].copy_from_slice(&42u32.to_le_bytes());
        let self_ptr = sym_vaddr + tasks_offset;
        task_page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&self_ptr.to_le_bytes());
        task_page[0x20..0x27].copy_from_slice(b"worker\0");
        task_page[parent_offset as usize..parent_offset as usize + 8]
            .copy_from_slice(&parent_vaddr.to_le_bytes());

        let mut parent_page = [0u8; 4096];
        parent_page[0..4].copy_from_slice(&1u32.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_symbol("init_task", sym_vaddr)
            .add_struct("list_head", 0x10)
            .add_field("list_head", "next", 0x00, "pointer")
            .add_struct("task_struct", 0x400)
            .add_field("task_struct", "tasks", tasks_offset, "pointer")
            .add_field("task_struct", "pid", 0x00, "unsigned int")
            .add_field("task_struct", "comm", 0x20, "char")
            .add_field("task_struct", "state", 0x08, "int")
            .add_field("task_struct", "real_parent", parent_offset, "pointer")
            .add_field("task_struct", "cred", cred_offset, "pointer")
            .add_field("task_struct", "mm", mm_offset, "pointer")
            .add_field("task_struct", "signal", signal_offset, "pointer")
            .add_field("task_struct", "static_prio", 0x60, "int")
            .add_field("task_struct", "flags", 0x64, "unsigned int")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &task_page)
            .map_4k(parent_vaddr, parent_paddr, ptf::WRITABLE)
            .write_phys(parent_paddr, &parent_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_psaux(&reader).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].pid, 42);
        assert_eq!(result[0].ppid, 1, "ppid should be read from real_parent.pid");
        assert_eq!(result[0].uid, 0, "cred=null → uid defaults to 0");
        assert_eq!(result[0].vsize, 0, "mm=null → vsize defaults to 0");
        assert!(result[0].tty.is_empty(), "signal=null → tty defaults to empty");
    }

    #[test]
    fn walk_psaux_with_two_tasks_and_full_chains() {
        use memf_core::test_builders::{flags as ptf, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let tasks_offset:    u64 = 0x10;
        let pid_offset:      u64 = 0x00;
        let comm_offset:     u64 = 0x20;
        let state_offset:    u64 = 0x08;
        let real_parent_off: u64 = 0x40;
        let cred_offset:     u64 = 0x48;
        let mm_offset:       u64 = 0x50;
        let signal_offset:   u64 = 0x58;
        let static_prio_off: u64 = 0x60;
        let flags_offset:    u64 = 0x64;

        let cred_uid_off:    u64 = 0x04;
        let cred_gid_off:    u64 = 0x08;
        let total_vm_off:    u64 = 0x00;
        let rss_stat_off:    u64 = 0x08;
        let sig_tty_off:     u64 = 0x00;
        let tty_name_off:    u64 = 0x00;

        let init_vaddr: u64 = 0xFFFF_8800_00E0_0000;
        let init_paddr: u64 = 0x00E0_0000;
        let t2_vaddr:   u64 = 0xFFFF_8800_00E1_0000;
        let t2_paddr:   u64 = 0x00E1_0000;
        let cred_vaddr: u64 = 0xFFFF_8800_00E2_0000;
        let cred_paddr: u64 = 0x00E2_0000;
        let mm_vaddr:   u64 = 0xFFFF_8800_00E3_0000;
        let mm_paddr:   u64 = 0x00E3_0000;
        let sig_vaddr:  u64 = 0xFFFF_8800_00E4_0000;
        let sig_paddr:  u64 = 0x00E4_0000;
        let tty_vaddr:  u64 = 0xFFFF_8800_00E5_0000;
        let tty_paddr:  u64 = 0x00E5_0000;

        let mut init_page = [0u8; 4096];
        let t2_list_node = t2_vaddr + tasks_offset;
        init_page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&t2_list_node.to_le_bytes());
        init_page[comm_offset as usize..comm_offset as usize + 7]
            .copy_from_slice(b"swapper");

        let mut t2_page = [0u8; 4096];
        t2_page[pid_offset as usize..pid_offset as usize + 4]
            .copy_from_slice(&42u32.to_le_bytes());
        t2_page[state_offset as usize..state_offset as usize + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        let init_list_node = init_vaddr + tasks_offset;
        t2_page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&init_list_node.to_le_bytes());
        t2_page[comm_offset as usize..comm_offset as usize + 4]
            .copy_from_slice(b"bash");
        t2_page[real_parent_off as usize..real_parent_off as usize + 8]
            .copy_from_slice(&init_vaddr.to_le_bytes());
        t2_page[cred_offset as usize..cred_offset as usize + 8]
            .copy_from_slice(&cred_vaddr.to_le_bytes());
        t2_page[mm_offset as usize..mm_offset as usize + 8]
            .copy_from_slice(&mm_vaddr.to_le_bytes());
        t2_page[signal_offset as usize..signal_offset as usize + 8]
            .copy_from_slice(&sig_vaddr.to_le_bytes());
        t2_page[static_prio_off as usize..static_prio_off as usize + 4]
            .copy_from_slice(&120i32.to_le_bytes());

        let mut cred_page = [0u8; 4096];
        cred_page[cred_uid_off as usize..cred_uid_off as usize + 4]
            .copy_from_slice(&1000u32.to_le_bytes());
        cred_page[cred_gid_off as usize..cred_gid_off as usize + 4]
            .copy_from_slice(&2000u32.to_le_bytes());

        let mut mm_page = [0u8; 4096];
        mm_page[total_vm_off as usize..total_vm_off as usize + 8]
            .copy_from_slice(&256u64.to_le_bytes());
        mm_page[rss_stat_off as usize..rss_stat_off as usize + 8]
            .copy_from_slice(&128u64.to_le_bytes());

        let mut sig_page = [0u8; 4096];
        sig_page[sig_tty_off as usize..sig_tty_off as usize + 8]
            .copy_from_slice(&tty_vaddr.to_le_bytes());

        let mut tty_page = [0u8; 4096];
        tty_page[tty_name_off as usize..tty_name_off as usize + 6]
            .copy_from_slice(b"pts/0\0");

        let isf = IsfBuilder::new()
            .add_symbol("init_task", init_vaddr)
            .add_struct("list_head", 0x10)
            .add_field("list_head", "next", 0x00u64, "pointer")
            .add_struct("task_struct", 0x400)
            .add_field("task_struct", "tasks", tasks_offset, "pointer")
            .add_field("task_struct", "pid", pid_offset, "unsigned int")
            .add_field("task_struct", "comm", comm_offset, "char")
            .add_field("task_struct", "state", state_offset, "int")
            .add_field("task_struct", "real_parent", real_parent_off, "pointer")
            .add_field("task_struct", "cred", cred_offset, "pointer")
            .add_field("task_struct", "mm", mm_offset, "pointer")
            .add_field("task_struct", "signal", signal_offset, "pointer")
            .add_field("task_struct", "static_prio", static_prio_off, "int")
            .add_field("task_struct", "flags", flags_offset, "unsigned int")
            .add_struct("cred", 0x80)
            .add_field("cred", "uid", cred_uid_off, "unsigned int")
            .add_field("cred", "gid", cred_gid_off, "unsigned int")
            .add_struct("mm_struct", 0x200)
            .add_field("mm_struct", "total_vm", total_vm_off, "unsigned long")
            .add_field("mm_struct", "rss_stat", rss_stat_off, "unsigned long")
            .add_struct("signal_struct", 0x200)
            .add_field("signal_struct", "tty", sig_tty_off, "pointer")
            .add_struct("tty_struct", 0x200)
            .add_field("tty_struct", "name", tty_name_off, "char")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(init_vaddr, init_paddr, ptf::WRITABLE)
            .write_phys(init_paddr, &init_page)
            .map_4k(t2_vaddr, t2_paddr, ptf::WRITABLE)
            .write_phys(t2_paddr, &t2_page)
            .map_4k(cred_vaddr, cred_paddr, ptf::WRITABLE)
            .write_phys(cred_paddr, &cred_page)
            .map_4k(mm_vaddr, mm_paddr, ptf::WRITABLE)
            .write_phys(mm_paddr, &mm_page)
            .map_4k(sig_vaddr, sig_paddr, ptf::WRITABLE)
            .write_phys(sig_paddr, &sig_page)
            .map_4k(tty_vaddr, tty_paddr, ptf::WRITABLE)
            .write_phys(tty_paddr, &tty_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_psaux(&reader).unwrap();
        assert_eq!(result.len(), 2, "both tasks should appear");
        let t2 = result.iter().find(|p| p.pid == 42).expect("task2 missing");
        assert_eq!(t2.uid, 1000);
        assert_eq!(t2.gid, 2000);
        assert_eq!(t2.vsize, 256 * 4096, "vsize = total_vm * PAGE_SIZE");
        assert_eq!(t2.rss, 128);
        assert_eq!(t2.tty, "pts/0");
        assert_eq!(t2.state, "Sleeping");
        assert_eq!(t2.nice, 0);
    }

    #[test]
    fn walk_psaux_symbol_present_self_pointing_list_returns_init_task() {
        use memf_core::test_builders::{flags as ptf, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let tasks_offset: u64 = 0x10;
        let sym_vaddr: u64 = 0xFFFF_8800_0060_0000;
        let sym_paddr: u64 = 0x0060_0000;

        let isf = IsfBuilder::new()
            .add_symbol("init_task", sym_vaddr)
            .add_struct("list_head", 0x10)
            .add_field("list_head", "next", 0x00, "pointer")
            .add_struct("task_struct", 0x400)
            .add_field("task_struct", "tasks", tasks_offset, "pointer")
            .add_field("task_struct", "pid", 0x00, "unsigned int")
            .add_field("task_struct", "comm", 0x20, "char")
            .add_field("task_struct", "state", 0x08, "int")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut page = [0u8; 4096];
        let self_ptr = sym_vaddr + tasks_offset;
        page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&self_ptr.to_le_bytes());
        page[0x20..0x28].copy_from_slice(b"swapper\0");

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_psaux(&reader).unwrap();
        assert_eq!(result.len(), 1, "only init_task should appear (self-pointing list)");
        assert_eq!(result[0].pid, 0);
    }
}
