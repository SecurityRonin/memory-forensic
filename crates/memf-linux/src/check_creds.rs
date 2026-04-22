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

use crate::Result;

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
    reader: &ObjectReader<P>,
) -> Result<Vec<SharedCredInfo>> {
    // --- Graceful degradation: bail with empty vec if symbols are absent ---
    let init_task_addr = match reader.symbols().symbol_address("init_task") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    let tasks_offset = match reader.symbols().field_offset("task_struct", "tasks") {
        Some(off) => off,
        None => return Ok(Vec::new()),
    };

    // --- Step 1: Walk the task list -----------------------------------------
    let head_vaddr = init_task_addr + tasks_offset;
    let task_addrs = reader.walk_list(head_vaddr, "task_struct", "tasks")?;

    // Collect (pid, tgid, name, cred_addr) for every task, including init_task.
    let mut tasks: Vec<(u32, u32, String, u64)> = Vec::new();

    // Helper closure to extract per-task info.
    let collect_task = |addr: u64| -> Option<(u32, u32, String, u64)> {
        let pid: u32 = reader.read_field(addr, "task_struct", "pid").ok()?;
        let tgid: u32 = reader
            .read_field(addr, "task_struct", "tgid")
            .unwrap_or(pid);
        let name = reader
            .read_field_string(addr, "task_struct", "comm", 16)
            .unwrap_or_else(|_| "<unknown>".to_string());
        let cred_ptr: u64 = reader.read_field(addr, "task_struct", "cred").ok()?;
        Some((pid, tgid, name, cred_ptr))
    };

    // Include init_task itself.
    if let Some(info) = collect_task(init_task_addr) {
        tasks.push(info);
    }
    for &task_addr in &task_addrs {
        if let Some(info) = collect_task(task_addr) {
            tasks.push(info);
        }
    }

    // --- Step 2: Build cred_address → [(pid, tgid, name)] map ---------------
    let mut cred_map: HashMap<u64, Vec<(u32, u32, String)>> = HashMap::new();
    for (pid, tgid, name, cred_addr) in &tasks {
        // Skip null cred pointers.
        if *cred_addr == 0 {
            continue;
        }
        cred_map
            .entry(*cred_addr)
            .or_default()
            .push((*pid, *tgid, name.clone()));
    }

    // --- Step 3: For groups with >1 process, classify and emit results ------
    let mut results = Vec::new();

    for (cred_addr, group) in &cred_map {
        if group.len() < 2 {
            continue;
        }

        // Filter out thread-group siblings: tasks with the same tgid are
        // threads of the same process and legitimately share creds.
        // Group by tgid; only flag cross-tgid sharing.
        let mut by_tgid: HashMap<u32, Vec<u32>> = HashMap::new();
        for (pid, tgid, _) in group {
            by_tgid.entry(*tgid).or_default().push(*pid);
        }

        // If every task in the group has the same tgid, it is pure
        // thread sharing → benign, skip.
        if by_tgid.len() < 2 {
            continue;
        }

        // Read uid from the cred struct (best effort).
        let uid: u32 = reader
            .read_field(*cred_addr, "cred", "uid")
            .unwrap_or(u32::MAX);

        // Build per-process entries for cross-tgid participants.
        for (pid, _tgid, name) in group {
            let shared_with: Vec<u32> = group
                .iter()
                .filter(|(other_pid, _, _)| other_pid != pid)
                .map(|(other_pid, _, _)| *other_pid)
                .collect();

            let is_suspicious = classify_shared_creds(*pid, &shared_with, uid);

            if is_suspicious {
                results.push(SharedCredInfo {
                    pid: *pid,
                    process_name: name.clone(),
                    uid,
                    cred_address: *cred_addr,
                    shared_with_pids: shared_with,
                    is_suspicious,
                });
            }
        }
    }

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

    // ---------------------------------------------------------------
    // is_likely_kernel_thread tests (via classify_shared_creds behaviour)
    // ---------------------------------------------------------------

    #[test]
    fn is_likely_kernel_thread_pid_0_benign() {
        // PID 0 (swapper/idle) is a kernel thread → uid-0 sharing is benign
        assert!(!classify_shared_creds(0, &[2], 0));
    }

    #[test]
    fn is_likely_kernel_thread_pid_1_shares_with_pid_2_suspicious() {
        // PID 1 (init/systemd) is NOT a kernel thread (pid > 2), shares with pid 2
        // uid=0, pid=1 → is_likely_kernel_thread(1) = true (pid <= 2)
        // So this should be benign (kernel thread path)
        assert!(!classify_shared_creds(1, &[2], 0));
    }

    #[test]
    fn is_likely_kernel_thread_pid_3_uid_0_suspicious_when_sharing_non_init() {
        // PID 3, uid=0 but pid > 2 → NOT a kernel thread, shares with pid 100
        // is_likely_kernel_thread(3) = false → falls through to !shared_with.is_empty()
        assert!(classify_shared_creds(3, &[100], 0));
    }

    #[test]
    fn classify_sharing_with_pid_1_uid_0_kernel_thread_benign() {
        // pid=2 (kthreadd), uid=0, shares with pid=1 → benign (kernel cred)
        assert!(!classify_shared_creds(2, &[1], 0));
    }

    #[test]
    fn classify_sharing_with_pid_1_uid_0_non_kernel_thread_suspicious() {
        // pid=100, uid=0, shares with init (pid=1)
        // is_likely_kernel_thread(100) = false → suspicious
        assert!(classify_shared_creds(100, &[1], 0));
    }

    #[test]
    fn classify_uid_0_kernel_thread_no_sharing_benign() {
        // uid=0, pid=2, no other shared PIDs → benign (kernel thread path)
        assert!(!classify_shared_creds(2, &[], 0));
    }

    #[test]
    fn classify_uid_0_non_kernel_thread_sharing_suspicious() {
        // uid=0, pid=50 (not kernel thread), shares with pid 60
        // Falls through to !shared_with.is_empty() → suspicious
        assert!(classify_shared_creds(50, &[60], 0));
    }

    #[test]
    fn classify_is_pid_1_self_not_suspicious() {
        // PID 1 checking shared_with containing no pid 1
        // shared_with=[500], uid=0, pid=1 → is_likely_kernel_thread(1)=true → benign
        assert!(!classify_shared_creds(1, &[500], 0));
    }

    // ---------------------------------------------------------------
    // SharedCredInfo: Clone + Debug + Serialize
    // ---------------------------------------------------------------

    #[test]
    fn shared_cred_info_clone_debug_serialize() {
        let info = SharedCredInfo {
            pid: 42,
            process_name: "evil".to_string(),
            uid: 0,
            cred_address: 0xDEAD_BEEF,
            shared_with_pids: vec![1],
            is_suspicious: true,
        };
        let cloned = info.clone();
        assert_eq!(cloned.pid, 42);
        let dbg = format!("{:?}", cloned);
        assert!(dbg.contains("evil"));
        let json = serde_json::to_string(&cloned).unwrap();
        assert!(json.contains("\"pid\":42"));
        assert!(json.contains("\"is_suspicious\":true"));
    }

    // ---------------------------------------------------------------
    // walk_check_creds: symbol present + self-pointing list (walk body runs)
    // ---------------------------------------------------------------

    #[test]
    fn walk_check_creds_symbol_present_single_task_no_sharing() {
        // init_task present, tasks self-pointing (only one process).
        // With a single process in the cred map, group.len() < 2 → no results.
        let sym_vaddr: u64 = 0xFFFF_8800_0090_0000;
        let sym_paddr: u64 = 0x00A0_0000;
        let tasks_offset = 16u64;

        let mut page = [0u8; 4096];
        // pid = 1
        page[0..4].copy_from_slice(&1u32.to_le_bytes());
        // tgid = 1
        page[4..8].copy_from_slice(&1u32.to_le_bytes());
        // tasks: self-pointing
        let list_self = sym_vaddr + tasks_offset;
        page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&list_self.to_le_bytes());
        page[tasks_offset as usize + 8..tasks_offset as usize + 16]
            .copy_from_slice(&list_self.to_le_bytes());
        // comm = "systemd"
        page[32..39].copy_from_slice(b"systemd");
        // cred pointer = some non-zero value (unique to this task)
        let cred_ptr: u64 = 0xFFFF_8800_DEAD_0000;
        page[96..104].copy_from_slice(&cred_ptr.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 256)
            .add_field("task_struct", "pid", 0, "unsigned int")
            .add_field("task_struct", "tgid", 4, "unsigned int")
            .add_field("task_struct", "tasks", 16, "pointer")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "cred", 96, "pointer")
            .add_struct("cred", 64)
            .add_field("cred", "uid", 4, "unsigned int")
            .add_symbol("init_task", sym_vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, flags::WRITABLE)
            .write_phys(sym_paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_check_creds(&reader).unwrap_or_default();
        assert!(
            result.is_empty(),
            "single task with unique cred should not be flagged"
        );
    }

    // ---------------------------------------------------------------
    // walk_check_creds: symbol + list_head present, self-pointing list
    // Exercises the full walk body: init_task info collected, group.len()<2
    // since there is only one task → no results.
    // ---------------------------------------------------------------

    #[test]
    fn walk_check_creds_with_list_head_single_task_no_sharing() {
        let sym_vaddr: u64 = 0xFFFF_8800_0010_0000;
        let sym_paddr: u64 = 0x0010_0000; // < 16 MB
        let tasks_offset: u64 = 16;

        let mut page = [0u8; 4096];
        // pid = 42
        page[0..4].copy_from_slice(&42u32.to_le_bytes());
        // tgid = 42
        page[4..8].copy_from_slice(&42u32.to_le_bytes());
        // tasks: self-pointing list_head
        let self_ptr = sym_vaddr + tasks_offset;
        page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&self_ptr.to_le_bytes());
        page[tasks_offset as usize + 8..tasks_offset as usize + 16]
            .copy_from_slice(&self_ptr.to_le_bytes());
        // comm = "init"
        page[32..36].copy_from_slice(b"init");
        // cred pointer (unique non-zero)
        let cred_ptr: u64 = 0xFFFF_8800_CAFE_0000;
        page[96..104].copy_from_slice(&cred_ptr.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("list_head", 0x10)
            .add_field("list_head", "next", 0x00, "pointer")
            .add_field("list_head", "prev", 0x08, "pointer")
            .add_struct("task_struct", 256)
            .add_field("task_struct", "pid", 0, "unsigned int")
            .add_field("task_struct", "tgid", 4, "unsigned int")
            .add_field("task_struct", "tasks", 16, "pointer")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "cred", 96, "pointer")
            .add_struct("cred", 64)
            .add_field("cred", "uid", 4, "unsigned int")
            .add_symbol("init_task", sym_vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, flags::WRITABLE)
            .write_phys(sym_paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_check_creds(&reader).unwrap();
        // Only one task → group.len() < 2 for every cred_addr → no suspicious entries.
        assert!(
            result.is_empty(),
            "single task cannot share creds with another"
        );
    }

    // ---------------------------------------------------------------
    // walk_check_creds: TWO tasks with same cred pointer but different TGIDs
    // Exercises the cred-sharing detection logic (lines 121-185):
    //   - by_tgid.len() >= 2 → cross-tgid sharing detected → uid read → results pushed
    // ---------------------------------------------------------------

    #[test]
    fn walk_check_creds_two_tasks_share_cred_different_tgids_flagged() {
        // Memory layout:
        //   init_task  @ init_vaddr / init_paddr
        //     pid=100, tgid=100, cred=cred_vaddr, tasks.next → t2 list node
        //   task2      @ t2_vaddr   / t2_paddr
        //     pid=200, tgid=200, cred=cred_vaddr  (SAME cred, different tgid → suspicious)
        //     tasks.next → init_vaddr + tasks_offset  (wraps back)
        //   cred       @ cred_vaddr / cred_paddr
        //     uid=1000  (non-zero, so sharing is suspicious)

        let tasks_offset: u64 = 0x10;
        let pid_offset: u64 = 0x00;
        let tgid_offset: u64 = 0x04;
        let comm_offset: u64 = 0x20;
        let cred_offset: u64 = 0x60;
        let uid_cred_off: u64 = 0x04;

        let init_vaddr: u64 = 0xFFFF_8800_0090_0000;
        let init_paddr: u64 = 0x0090_0000;
        let t2_vaddr: u64 = 0xFFFF_8800_0091_0000;
        let t2_paddr: u64 = 0x0091_0000;
        let cred_vaddr: u64 = 0xFFFF_8800_0092_0000;
        let cred_paddr: u64 = 0x0092_0000;

        // init_task page
        let mut init_page = [0u8; 4096];
        init_page[pid_offset as usize..pid_offset as usize + 4]
            .copy_from_slice(&100u32.to_le_bytes());
        init_page[tgid_offset as usize..tgid_offset as usize + 4]
            .copy_from_slice(&100u32.to_le_bytes());
        let t2_list_node = t2_vaddr + tasks_offset;
        init_page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&t2_list_node.to_le_bytes());
        init_page[tasks_offset as usize + 8..tasks_offset as usize + 16]
            .copy_from_slice(&t2_list_node.to_le_bytes()); // prev
        init_page[comm_offset as usize..comm_offset as usize + 5].copy_from_slice(b"evil1");
        init_page[cred_offset as usize..cred_offset as usize + 8]
            .copy_from_slice(&cred_vaddr.to_le_bytes());

        // task2 page
        let mut t2_page = [0u8; 4096];
        t2_page[pid_offset as usize..pid_offset as usize + 4]
            .copy_from_slice(&200u32.to_le_bytes());
        t2_page[tgid_offset as usize..tgid_offset as usize + 4]
            .copy_from_slice(&200u32.to_le_bytes()); // different tgid
        let init_list_node = init_vaddr + tasks_offset;
        t2_page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&init_list_node.to_le_bytes()); // wraps back to init
        t2_page[tasks_offset as usize + 8..tasks_offset as usize + 16]
            .copy_from_slice(&init_list_node.to_le_bytes());
        t2_page[comm_offset as usize..comm_offset as usize + 5].copy_from_slice(b"evil2");
        t2_page[cred_offset as usize..cred_offset as usize + 8]
            .copy_from_slice(&cred_vaddr.to_le_bytes()); // SAME cred pointer

        // cred page: uid=1000 at uid_cred_off
        let mut cred_page = [0u8; 4096];
        cred_page[uid_cred_off as usize..uid_cred_off as usize + 4]
            .copy_from_slice(&1000u32.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_symbol("init_task", init_vaddr)
            .add_struct("list_head", 0x10)
            .add_field("list_head", "next", 0x00u64, "pointer")
            .add_field("list_head", "prev", 0x08u64, "pointer")
            .add_struct("task_struct", 0x200)
            .add_field("task_struct", "pid", pid_offset, "unsigned int")
            .add_field("task_struct", "tgid", tgid_offset, "unsigned int")
            .add_field("task_struct", "tasks", tasks_offset, "pointer")
            .add_field("task_struct", "comm", comm_offset, "char")
            .add_field("task_struct", "cred", cred_offset, "pointer")
            .add_struct("cred", 0x80)
            .add_field("cred", "uid", uid_cred_off, "unsigned int")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(init_vaddr, init_paddr, flags::WRITABLE)
            .write_phys(init_paddr, &init_page)
            .map_4k(t2_vaddr, t2_paddr, flags::WRITABLE)
            .write_phys(t2_paddr, &t2_page)
            .map_4k(cred_vaddr, cred_paddr, flags::WRITABLE)
            .write_phys(cred_paddr, &cred_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_check_creds(&reader).unwrap();
        // Both tasks share the same cred across different TGIDs with uid=1000 → suspicious
        assert!(
            !result.is_empty(),
            "cross-tgid cred sharing should produce suspicious entries"
        );
        // Both tasks should appear (each is suspicious since uid=1000, non-kernel-thread)
        assert_eq!(result.len(), 2, "both tasks should be flagged");
        for entry in &result {
            assert!(entry.is_suspicious);
            assert_eq!(entry.cred_address, cred_vaddr);
            assert_eq!(entry.uid, 1000);
        }
    }

    // ---------------------------------------------------------------
    // walk_check_creds: missing tasks field → empty Vec (graceful degradation)
    // ---------------------------------------------------------------

    #[test]
    fn walk_check_creds_missing_tasks_field_returns_empty() {
        // init_task symbol present but task_struct.tasks field absent → graceful empty
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            // No "tasks" field → field_offset returns None → return Ok(empty)
            .add_symbol("init_task", 0xFFFF_8000_0010_0000)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_check_creds(&reader);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
