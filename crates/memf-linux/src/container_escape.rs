//! Container escape artifact detection.
//!
//! Detects processes that may have escaped container namespace isolation by
//! comparing mount namespace pointers against the init task's namespace
//! (MITRE ATT&CK T1611 — Escape to Host).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about a process exhibiting container escape indicators.
#[derive(Debug, Clone)]
pub struct ContainerEscapeInfo {
    /// Process ID.
    pub pid: u32,
    /// Process command name.
    pub comm: String,
    /// Indicator type: "namespace_mismatch", "host_mount_access", "pivot_root_anomaly".
    pub indicator: String,
    /// PID in the host namespace if detectable.
    pub host_pid: Option<u32>,
    /// True if the process is considered suspicious.
    pub is_suspicious: bool,
}

/// Kernel thread comm prefixes that are never suspicious.
const KERNEL_THREAD_COMMS: &[&str] = &["kthread", "kworker", "migration", "ksoftirqd", "rcu_"];

/// Classify whether a process's indicator is suspicious.
///
/// Returns `false` for kernel threads regardless of indicator.
pub fn classify_container_escape(comm: &str, indicator: &str) -> bool {
    let is_kernel = KERNEL_THREAD_COMMS
        .iter()
        .any(|prefix| comm.starts_with(prefix));
    if is_kernel {
        return false;
    }
    matches!(indicator, "namespace_mismatch" | "host_mount_access")
}

/// Walk all tasks and report container escape indicators.
///
/// On missing `init_task` symbol, returns `Ok(vec![])`.
pub fn walk_container_escape<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<ContainerEscapeInfo>> {
    let init_task_addr = match reader.symbols().symbol_address("init_task") {
        Some(a) => a,
        None => return Ok(vec![]),
    };

    let tasks_offset = match reader.symbols().field_offset("task_struct", "tasks") {
        Some(o) => o,
        None => return Ok(vec![]),
    };

    // Read init_task's nsproxy and its mnt_ns to use as the host reference.
    let init_nsproxy: u64 = match reader.read_field(init_task_addr, "task_struct", "nsproxy") {
        Ok(v) => v,
        Err(_) => return Ok(vec![]),
    };
    let init_mnt_ns: u64 = if init_nsproxy != 0 {
        reader
            .read_field(init_nsproxy, "nsproxy", "mnt_ns")
            .unwrap_or(0)
    } else {
        0
    };

    let head_vaddr = init_task_addr + tasks_offset;
    let task_addrs = reader.walk_list(head_vaddr, "task_struct", "tasks")?;

    let mut findings = Vec::new();

    for &task_addr in &task_addrs {
        if let Some(info) = check_task_namespace(reader, task_addr, init_mnt_ns) {
            findings.push(info);
        }
    }

    Ok(findings)
}

/// Check a single task for namespace escape indicators.
fn check_task_namespace<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
    init_mnt_ns: u64,
) -> Option<ContainerEscapeInfo> {
    let pid: u32 = reader.read_field(task_addr, "task_struct", "pid").ok()?;
    let comm = reader
        .read_field_string(task_addr, "task_struct", "comm", 16)
        .unwrap_or_default();

    let nsproxy: u64 = reader
        .read_field(task_addr, "task_struct", "nsproxy")
        .ok()?;

    if nsproxy == 0 || init_mnt_ns == 0 {
        return None;
    }

    let mnt_ns: u64 = reader.read_field(nsproxy, "nsproxy", "mnt_ns").unwrap_or(0);

    // Processes in a different mount namespace from init are in a container.
    if mnt_ns != init_mnt_ns && mnt_ns != 0 {
        let indicator = "namespace_mismatch".to_string();
        let is_suspicious = classify_container_escape(&comm, &indicator);
        return Some(ContainerEscapeInfo {
            pid,
            comm,
            indicator,
            host_pid: None,
            is_suspicious,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ---------------------------------------------------------------------------
    // Unit tests for classify_container_escape
    // ---------------------------------------------------------------------------

    #[test]
    fn classify_container_escape_namespace_mismatch_suspicious() {
        assert!(classify_container_escape("bash", "namespace_mismatch"));
    }

    #[test]
    fn classify_container_escape_kworker_not_suspicious() {
        assert!(!classify_container_escape(
            "kworker/0:0",
            "namespace_mismatch"
        ));
    }

    #[test]
    fn classify_container_escape_host_mount_suspicious() {
        assert!(classify_container_escape("python3", "host_mount_access"));
    }

    #[test]
    fn classify_container_escape_migration_not_suspicious() {
        assert!(!classify_container_escape(
            "migration/0",
            "host_mount_access"
        ));
    }

    #[test]
    fn classify_container_escape_unknown_indicator_not_suspicious() {
        assert!(!classify_container_escape("bash", "pivot_root_anomaly"));
    }

    // ---------------------------------------------------------------------------
    // Walker tests
    // ---------------------------------------------------------------------------

    fn make_minimal_reader_no_init_task() -> ObjectReader<SyntheticPhysMem> {
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
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_container_escape_missing_init_task_returns_empty() {
        let reader = make_minimal_reader_no_init_task();
        let result = walk_container_escape(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// Build a reader where init_task and one other task share the same
    /// mount namespace — no escape detected.
    ///
    /// Each object lives at a distinct 4K-aligned virtual address so that
    /// `PageTableBuilder::map_4k` can map them independently.
    fn make_same_namespace_reader() -> ObjectReader<SyntheticPhysMem> {
        // All virtual addresses are 4K-aligned and on distinct pages.
        const INIT_VADDR: u64 = 0xFFFF_8000_0010_0000;
        const NSP_VADDR: u64 = 0xFFFF_8000_0011_0000;
        const TASK2_VADDR: u64 = 0xFFFF_8000_0012_0000;

        let init_paddr: u64 = 0x0080_0000;
        let nsp_paddr: u64 = 0x0081_0000;
        let task2_paddr: u64 = 0x0082_0000;

        // init_task: pid=1, tasks.next → task2.tasks, nsproxy → NSP_VADDR
        let mut init_data = vec![0u8; 4096];
        init_data[0..4].copy_from_slice(&1u32.to_le_bytes());
        init_data[16..24].copy_from_slice(&(TASK2_VADDR + 16).to_le_bytes()); // tasks.next
        init_data[24..32].copy_from_slice(&(TASK2_VADDR + 16).to_le_bytes()); // tasks.prev
        init_data[32..39].copy_from_slice(b"systemd");
        init_data[48..56].copy_from_slice(&NSP_VADDR.to_le_bytes()); // nsproxy

        // nsproxy: mnt_ns = 0xAAAA_0000 (same for both tasks)
        let mut nsp_data = vec![0u8; 4096];
        nsp_data[0..8].copy_from_slice(&0xAAAA_0000u64.to_le_bytes());

        // task2: pid=2, tasks.next → init.tasks (circular), same nsproxy
        let mut task2_data = vec![0u8; 4096];
        task2_data[0..4].copy_from_slice(&2u32.to_le_bytes());
        task2_data[16..24].copy_from_slice(&(INIT_VADDR + 16).to_le_bytes()); // tasks.next
        task2_data[24..32].copy_from_slice(&(INIT_VADDR + 16).to_le_bytes()); // tasks.prev
        task2_data[32..36].copy_from_slice(b"bash");
        task2_data[48..56].copy_from_slice(&NSP_VADDR.to_le_bytes()); // same nsproxy

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "nsproxy", 48, "pointer")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_struct("nsproxy", 64)
            .add_field("nsproxy", "mnt_ns", 0, "pointer")
            .add_symbol("init_task", INIT_VADDR)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(INIT_VADDR, init_paddr, ptflags::WRITABLE)
            .write_phys(init_paddr, &init_data)
            .map_4k(NSP_VADDR, nsp_paddr, ptflags::WRITABLE)
            .write_phys(nsp_paddr, &nsp_data)
            .map_4k(TASK2_VADDR, task2_paddr, ptflags::WRITABLE)
            .write_phys(task2_paddr, &task2_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_container_escape_missing_tasks_field_returns_empty() {
        // Covers line 56: init_task present but task_struct.tasks field absent → Ok(vec![])
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            // tasks field absent
            .add_symbol("init_task", 0xFFFF_8000_0020_0000)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_container_escape(&reader).unwrap();
        assert!(result.is_empty(), "missing tasks field → graceful empty");
    }

    #[test]
    fn walk_container_escape_nsproxy_read_fails_returns_empty() {
        // Covers line 62: nsproxy field missing in ISF → read_field returns Err → Ok(vec![])
        // We have init_task, tasks field, but no nsproxy field → read_field fails → Ok([])
        let isf = IsfBuilder::new()
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 16, "list_head")
            // nsproxy field intentionally absent → read_field("task_struct", "nsproxy") fails
            .add_symbol("init_task", 0xFFFF_8000_0025_0000)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_container_escape(&reader).unwrap();
        assert!(result.is_empty(), "missing nsproxy field → graceful empty");
    }

    #[test]
    fn walk_container_escape_init_nsproxy_zero_empty_list() {
        // Covers lines 69 (init_nsproxy == 0 → init_mnt_ns = 0) and
        // line 102 in check_task_namespace (init_mnt_ns == 0 → None).
        let init_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let init_paddr: u64 = 0x0092_0000;

        let mut page = [0u8; 4096];
        // pid = 1
        page[0..4].copy_from_slice(&1u32.to_le_bytes());
        // tasks self-pointing
        let tasks_self = init_vaddr + 16;
        page[16..24].copy_from_slice(&tasks_self.to_le_bytes());
        page[24..32].copy_from_slice(&tasks_self.to_le_bytes());
        page[32..36].copy_from_slice(b"init");
        // nsproxy = 0 → init_mnt_ns will be 0
        page[48..56].copy_from_slice(&0u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "nsproxy", 48, "pointer")
            .add_struct("nsproxy", 64)
            .add_field("nsproxy", "mnt_ns", 0, "pointer")
            .add_symbol("init_task", init_vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(init_vaddr, init_paddr, ptflags::WRITABLE)
            .write_phys(init_paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_container_escape(&reader).unwrap();
        assert!(
            result.is_empty(),
            "init_nsproxy == 0 → init_mnt_ns = 0 → no findings"
        );
    }

    #[test]
    fn walk_container_escape_namespace_mismatch_detected() {
        // Covers lines 79, 102-117: a task with a different mnt_ns than init is detected.
        const INIT_VADDR: u64 = 0xFFFF_8000_0040_0000;
        const NSP_INIT_VADDR: u64 = 0xFFFF_8000_0041_0000;
        const TASK2_VADDR: u64 = 0xFFFF_8000_0042_0000;
        const NSP_TASK2_VADDR: u64 = 0xFFFF_8000_0043_0000;

        let init_paddr: u64 = 0x0093_0000;
        let nsp_init_paddr: u64 = 0x0094_0000;
        let task2_paddr: u64 = 0x0095_0000;
        let nsp_task2_paddr: u64 = 0x0096_0000;

        // init_task: nsproxy → NSP_INIT_VADDR, tasks → task2
        let mut init_data = vec![0u8; 4096];
        init_data[0..4].copy_from_slice(&1u32.to_le_bytes());
        init_data[16..24].copy_from_slice(&(TASK2_VADDR + 16).to_le_bytes());
        init_data[24..32].copy_from_slice(&(TASK2_VADDR + 16).to_le_bytes());
        init_data[32..39].copy_from_slice(b"systemd");
        init_data[48..56].copy_from_slice(&NSP_INIT_VADDR.to_le_bytes());

        // nsproxy for init: mnt_ns = 0xAAAA_0000 (host namespace)
        let mut nsp_init = vec![0u8; 4096];
        nsp_init[0..8].copy_from_slice(&0xAAAA_0000u64.to_le_bytes());

        // task2: nsproxy → NSP_TASK2_VADDR, different mnt_ns → detected
        let mut task2_data = vec![0u8; 4096];
        task2_data[0..4].copy_from_slice(&2u32.to_le_bytes());
        task2_data[16..24].copy_from_slice(&(INIT_VADDR + 16).to_le_bytes());
        task2_data[24..32].copy_from_slice(&(INIT_VADDR + 16).to_le_bytes());
        task2_data[32..37].copy_from_slice(b"bash\0");
        task2_data[48..56].copy_from_slice(&NSP_TASK2_VADDR.to_le_bytes());

        // nsproxy for task2: mnt_ns = 0xBBBB_0000 (different → container escape)
        let mut nsp_task2 = vec![0u8; 4096];
        nsp_task2[0..8].copy_from_slice(&0xBBBB_0000u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "nsproxy", 48, "pointer")
            .add_struct("nsproxy", 64)
            .add_field("nsproxy", "mnt_ns", 0, "pointer")
            .add_symbol("init_task", INIT_VADDR)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(INIT_VADDR, init_paddr, ptflags::WRITABLE)
            .write_phys(init_paddr, &init_data)
            .map_4k(NSP_INIT_VADDR, nsp_init_paddr, ptflags::WRITABLE)
            .write_phys(nsp_init_paddr, &nsp_init)
            .map_4k(TASK2_VADDR, task2_paddr, ptflags::WRITABLE)
            .write_phys(task2_paddr, &task2_data)
            .map_4k(NSP_TASK2_VADDR, nsp_task2_paddr, ptflags::WRITABLE)
            .write_phys(nsp_task2_paddr, &nsp_task2)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_container_escape(&reader).unwrap();
        assert_eq!(result.len(), 1, "exactly one namespace mismatch expected");
        assert_eq!(result[0].pid, 2);
        assert_eq!(result[0].comm, "bash");
        assert_eq!(result[0].indicator, "namespace_mismatch");
        assert!(result[0].is_suspicious);
    }

    #[test]
    fn classify_container_escape_kthread_prefix_not_suspicious() {
        // Covers: kthread prefix in KERNEL_THREAD_COMMS
        assert!(!classify_container_escape(
            "kthread_worker",
            "namespace_mismatch"
        ));
        assert!(!classify_container_escape(
            "ksoftirqd/0",
            "namespace_mismatch"
        ));
        assert!(!classify_container_escape(
            "rcu_sched",
            "namespace_mismatch"
        ));
    }

    #[test]
    fn walk_container_escape_single_namespace_returns_empty() {
        let reader = make_same_namespace_reader();
        let result = walk_container_escape(&reader).unwrap();
        assert!(result.is_empty());
    }
}
