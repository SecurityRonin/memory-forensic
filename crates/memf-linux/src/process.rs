//! Linux process walker.
//!
//! Enumerates processes by walking the `task_struct` linked list starting
//! from `init_task`. Each `task_struct` is connected via `tasks` (`list_head`)
//! to form a circular doubly-linked list of all processes.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, ProcessInfo, ProcessState, PsTreeEntry, Result};

/// Walk the Linux process list starting from `init_task`.
pub fn walk_processes<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<ProcessInfo>> {
    let init_task_addr = reader
        .symbols()
        .symbol_address("init_task")
        .ok_or_else(|| Error::Walker("symbol 'init_task' not found".into()))?;

    let tasks_offset = reader
        .symbols()
        .field_offset("task_struct", "tasks")
        .ok_or_else(|| Error::Walker("task_struct.tasks field not found".into()))?;

    let head_vaddr = init_task_addr + tasks_offset;
    let task_addrs = reader.walk_list(head_vaddr, "task_struct", "tasks")?;

    let mut processes = Vec::new();

    // Include init_task itself (it's the list head, not in walk results)
    if let Ok(info) = read_process_info(reader, init_task_addr) {
        processes.push(info);
    }

    for &task_addr in &task_addrs {
        if let Ok(info) = read_process_info(reader, task_addr) {
            processes.push(info);
        }
    }

    processes.sort_by_key(|p| p.pid);
    Ok(processes)
}

/// Build a process tree from a flat process list.
///
/// Produces a depth-annotated flat list suitable for indented display.
/// Processes whose parent PID is 0 or whose parent is not in the list
/// are treated as roots. Children are sorted by PID within each parent.
pub fn build_pstree(procs: &[ProcessInfo]) -> Vec<PsTreeEntry> {
    use std::collections::{HashMap, HashSet};

    let pid_set: HashSet<u64> = procs.iter().map(|p| p.pid).collect();
    let mut children: HashMap<u64, Vec<usize>> = HashMap::new();
    let mut roots = Vec::new();

    for (i, proc) in procs.iter().enumerate() {
        if proc.ppid == 0 || !pid_set.contains(&proc.ppid) {
            roots.push(i);
        } else {
            children.entry(proc.ppid).or_default().push(i);
        }
    }

    // Sort roots and children by PID for deterministic output
    roots.sort_by_key(|&i| procs[i].pid);
    for kids in children.values_mut() {
        kids.sort_by_key(|&i| procs[i].pid);
    }

    // DFS walk
    let mut result = Vec::with_capacity(procs.len());
    let mut stack: Vec<(usize, u32)> = roots.into_iter().rev().map(|i| (i, 0)).collect();

    while let Some((idx, depth)) = stack.pop() {
        result.push(PsTreeEntry {
            process: procs[idx].clone(),
            depth,
        });
        if let Some(kids) = children.get(&procs[idx].pid) {
            for &kid_idx in kids.iter().rev() {
                stack.push((kid_idx, depth + 1));
            }
        }
    }

    result
}

fn read_process_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
) -> Result<ProcessInfo> {
    let pid: u32 = reader.read_field(task_addr, "task_struct", "pid")?;
    let state: i64 = reader.read_field(task_addr, "task_struct", "state")?;
    let comm = reader.read_field_string(task_addr, "task_struct", "comm", 16)?;
    let ppid = read_parent_pid(reader, task_addr).unwrap_or(0);
    let cr3 = read_cr3(reader, task_addr).ok();

    // Try start_time first, then real_start_time (renamed in newer kernels).
    let start_time: u64 = reader
        .read_field(task_addr, "task_struct", "start_time")
        .or_else(|_| reader.read_field(task_addr, "task_struct", "real_start_time"))
        .unwrap_or(0);

    Ok(ProcessInfo {
        pid: u64::from(pid),
        ppid,
        comm,
        state: ProcessState::from_raw(state),
        vaddr: task_addr,
        cr3,
        start_time,
    })
}

fn read_parent_pid<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
) -> Result<u64> {
    let parent_ptr: u64 = reader.read_field(task_addr, "task_struct", "real_parent")?;
    if parent_ptr == 0 {
        return Ok(0);
    }
    let ppid: u32 = reader.read_field(parent_ptr, "task_struct", "pid")?;
    Ok(u64::from(ppid))
}

fn read_cr3<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, task_addr: u64) -> Result<u64> {
    let mm_ptr: u64 = reader.read_field(task_addr, "task_struct", "mm")?;
    if mm_ptr == 0 {
        return Err(Error::Walker("mm is NULL (kernel thread)".into()));
    }
    let pgd: u64 = reader.read_field(mm_ptr, "mm_struct", "pgd")?;
    Ok(pgd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // task_struct layout:
    //   pid          @ 0   (int, 4 bytes)
    //   state        @ 4   (long, 8 bytes)
    //   tasks        @ 16  (list_head, 16 bytes)
    //   comm         @ 32  (char, 16 bytes)
    //   mm           @ 48  (pointer, 8 bytes)
    //   real_parent  @ 56  (pointer, 8 bytes)
    //   tgid         @ 64  (int, 4 bytes)
    //   thread_group @ 72  (list_head, 16 bytes)
    //   start_time   @ 88  (unsigned long, 8 bytes)
    //   total: 128
    const START_TIME_OFF: usize = 88;

    fn make_test_reader(data: &[u8], vaddr: u64, paddr: u64) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "state", 4, "long")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "mm", 48, "pointer")
            .add_field("task_struct", "real_parent", 56, "pointer")
            .add_field("task_struct", "start_time", 88, "unsigned long")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_struct("mm_struct", 128)
            .add_field("mm_struct", "pgd", 0, "pointer")
            .add_symbol("init_task", vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_single_process() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        data[4..12].copy_from_slice(&0i64.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..41].copy_from_slice(b"swapper/0");
        data[56..64].copy_from_slice(&vaddr.to_le_bytes());
        // start_time = 0 (boot)
        data[START_TIME_OFF..START_TIME_OFF + 8].copy_from_slice(&0u64.to_le_bytes());

        let reader = make_test_reader(&data, vaddr, paddr);
        let procs = walk_processes(&reader).unwrap();

        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].pid, 0);
        assert_eq!(procs[0].comm, "swapper/0");
        assert_eq!(procs[0].state, ProcessState::Running);
        assert_eq!(procs[0].cr3, None);
        assert_eq!(procs[0].start_time, 0);
    }

    #[test]
    fn walk_three_processes() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        let init_addr = vaddr;
        let a_addr = vaddr + 0x200;
        let b_addr = vaddr + 0x400;
        let init_tasks = init_addr + 16;
        let a_tasks = a_addr + 16;
        let b_tasks = b_addr + 16;

        // init_task (PID 0)
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        data[4..12].copy_from_slice(&0i64.to_le_bytes());
        data[16..24].copy_from_slice(&a_tasks.to_le_bytes());
        data[24..32].copy_from_slice(&b_tasks.to_le_bytes());
        data[32..41].copy_from_slice(b"swapper/0");
        data[56..64].copy_from_slice(&init_addr.to_le_bytes());
        data[START_TIME_OFF..START_TIME_OFF + 8].copy_from_slice(&0u64.to_le_bytes());

        // Task A (PID 1) — started at 1_000_000_000 ns (1s after boot)
        data[0x200..0x204].copy_from_slice(&1u32.to_le_bytes());
        data[0x204..0x20C].copy_from_slice(&1i64.to_le_bytes());
        data[0x210..0x218].copy_from_slice(&b_tasks.to_le_bytes());
        data[0x218..0x220].copy_from_slice(&init_tasks.to_le_bytes());
        data[0x220..0x227].copy_from_slice(b"systemd");
        data[0x238..0x240].copy_from_slice(&init_addr.to_le_bytes());
        data[0x200 + START_TIME_OFF..0x200 + START_TIME_OFF + 8]
            .copy_from_slice(&1_000_000_000u64.to_le_bytes());

        // Task B (PID 42) — started at 5_000_000_000 ns (5s after boot)
        data[0x400..0x404].copy_from_slice(&42u32.to_le_bytes());
        data[0x404..0x40C].copy_from_slice(&0i64.to_le_bytes());
        data[0x410..0x418].copy_from_slice(&init_tasks.to_le_bytes());
        data[0x418..0x420].copy_from_slice(&a_tasks.to_le_bytes());
        data[0x420..0x424].copy_from_slice(b"bash");
        data[0x438..0x440].copy_from_slice(&a_addr.to_le_bytes());
        data[0x400 + START_TIME_OFF..0x400 + START_TIME_OFF + 8]
            .copy_from_slice(&5_000_000_000u64.to_le_bytes());

        let reader = make_test_reader(&data, vaddr, paddr);
        let procs = walk_processes(&reader).unwrap();

        assert_eq!(procs.len(), 3);
        assert_eq!(procs[0].pid, 0);
        assert_eq!(procs[0].comm, "swapper/0");
        assert_eq!(procs[1].pid, 1);
        assert_eq!(procs[1].comm, "systemd");
        assert_eq!(procs[1].state, ProcessState::Sleeping);
        assert_eq!(procs[1].ppid, 0);
        assert_eq!(procs[2].pid, 42);
        assert_eq!(procs[2].comm, "bash");
        assert_eq!(procs[2].state, ProcessState::Running);
        assert_eq!(procs[2].ppid, 1);
        // Verify start_time extraction
        assert_eq!(procs[0].start_time, 0); // swapper: boot
        assert_eq!(procs[1].start_time, 1_000_000_000); // systemd: 1s
        assert_eq!(procs[2].start_time, 5_000_000_000); // bash: 5s
    }

    #[test]
    fn missing_init_task_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 8, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_processes(&reader);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // build_pstree tests (pure function, no ObjectReader needed)
    // -----------------------------------------------------------------------

    fn make_proc(pid: u64, ppid: u64, comm: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            comm: comm.to_string(),
            state: ProcessState::Running,
            vaddr: 0xFFFF_0000_0000_0000 + pid * 0x1000,
            cr3: None,
            start_time: pid * 1_000_000_000, // synthetic: PID * 1s
        }
    }

    /// Single root process (PID 1, PPID 0) → depth 0, single entry.
    #[test]
    fn pstree_single_root() {
        let procs = vec![make_proc(1, 0, "init")];
        let tree = build_pstree(&procs);

        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].process.pid, 1);
        assert_eq!(tree[0].depth, 0);
    }

    /// Linear chain: init(1) → bash(100) → vim(200).
    /// Expected DFS order: init@0, bash@1, vim@2.
    #[test]
    fn pstree_linear_chain() {
        let procs = vec![
            make_proc(1, 0, "init"),
            make_proc(100, 1, "bash"),
            make_proc(200, 100, "vim"),
        ];
        let tree = build_pstree(&procs);

        assert_eq!(tree.len(), 3);
        assert_eq!(tree[0].process.pid, 1);
        assert_eq!(tree[0].depth, 0);
        assert_eq!(tree[1].process.pid, 100);
        assert_eq!(tree[1].depth, 1);
        assert_eq!(tree[2].process.pid, 200);
        assert_eq!(tree[2].depth, 2);
    }

    /// Branching: init(1) has children sshd(50) and cron(30).
    /// Children sorted by PID → cron@1 before sshd@1.
    #[test]
    fn pstree_branching_sorted_by_pid() {
        let procs = vec![
            make_proc(1, 0, "init"),
            make_proc(50, 1, "sshd"),
            make_proc(30, 1, "cron"),
        ];
        let tree = build_pstree(&procs);

        assert_eq!(tree.len(), 3);
        assert_eq!(tree[0].process.pid, 1);
        assert_eq!(tree[0].depth, 0);
        // cron (PID 30) before sshd (PID 50) because sorted by PID
        assert_eq!(tree[1].process.pid, 30);
        assert_eq!(tree[1].process.comm, "cron");
        assert_eq!(tree[1].depth, 1);
        assert_eq!(tree[2].process.pid, 50);
        assert_eq!(tree[2].process.comm, "sshd");
        assert_eq!(tree[2].depth, 1);
    }

    /// Orphaned process: parent PID not in the list → treated as root.
    #[test]
    fn pstree_orphan_becomes_root() {
        let procs = vec![
            make_proc(1, 0, "init"),
            make_proc(999, 777, "orphan"), // PPID 777 not in list
        ];
        let tree = build_pstree(&procs);

        assert_eq!(tree.len(), 2);
        // Both are roots, sorted by PID
        assert_eq!(tree[0].process.pid, 1);
        assert_eq!(tree[0].depth, 0);
        assert_eq!(tree[1].process.pid, 999);
        assert_eq!(tree[1].depth, 0);
    }

    /// Empty input produces empty output.
    #[test]
    fn pstree_empty() {
        let tree = build_pstree(&[]);
        assert!(tree.is_empty());
    }

    /// Full tree: init(1) → systemd(2) → sshd(10) → bash(20), plus cron(3) under init.
    /// Tests DFS ordering with mixed branching and depth.
    #[test]
    fn pstree_full_tree_dfs_order() {
        let procs = vec![
            make_proc(1, 0, "init"),
            make_proc(2, 1, "systemd"),
            make_proc(3, 1, "cron"),
            make_proc(10, 2, "sshd"),
            make_proc(20, 10, "bash"),
        ];
        let tree = build_pstree(&procs);

        assert_eq!(tree.len(), 5);
        // DFS: init(0) → systemd(1) → sshd(2) → bash(3) → cron(1)
        assert_eq!(tree[0].process.pid, 1);
        assert_eq!(tree[0].depth, 0);
        assert_eq!(tree[1].process.pid, 2);
        assert_eq!(tree[1].depth, 1);
        assert_eq!(tree[2].process.pid, 10);
        assert_eq!(tree[2].depth, 2);
        assert_eq!(tree[3].process.pid, 20);
        assert_eq!(tree[3].depth, 3);
        assert_eq!(tree[4].process.pid, 3);
        assert_eq!(tree[4].depth, 1);
    }
}
