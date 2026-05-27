//! Hidden process detection via PID namespace vs task list discrepancy.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::types::HiddenProcessInfo;
use crate::Result;

/// Classify whether a process is DKOM-hidden based on its visibility in the
/// task list and PID hash table.
///
/// Returns `true` if the process is absent from either the task list or the
/// PID hash table — both must be present for a process to be considered
/// visible by the kernel.
pub fn is_dkom_hidden(in_task_list: bool, in_pid_hash: bool) -> bool {
    !in_task_list || !in_pid_hash
}

/// Scan for processes hidden by DKOM or PID namespace tricks.
///
/// Compares the PID namespace, task list, and PID hash table for discrepancies.
/// Returns `Ok(vec![])` as a stub until full implementation is added.
pub fn find_hidden_processes<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<HiddenProcessInfo>> {
    let _ = reader;
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_minimal_reader(
    ) -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn empty_memory_returns_ok_empty() {
        let reader = make_minimal_reader();
        let result = find_hidden_processes(&reader);
        assert!(result.is_ok(), "should succeed with minimal reader");
        assert!(
            result.unwrap().is_empty(),
            "empty memory → no hidden processes"
        );
    }

    #[test]
    fn result_is_vec_of_hidden_process_info() {
        let reader = make_minimal_reader();
        let result: Result<Vec<HiddenProcessInfo>> = find_hidden_processes(&reader);
        assert!(result.is_ok());
    }

    #[test]
    fn hidden_process_info_fields_constructible() {
        let info = HiddenProcessInfo {
            pid: 1234,
            comm: "evil".to_string(),
            present_in_pid_ns: false,
            present_in_task_list: true,
            present_in_pid_hash: true,
        };
        assert_eq!(info.pid, 1234);
        assert_eq!(info.comm, "evil");
        assert!(!info.present_in_pid_ns);
        assert!(info.present_in_task_list);
        assert!(info.present_in_pid_hash);
    }

    #[test]
    fn hidden_process_info_serializes() {
        let info = HiddenProcessInfo {
            pid: 42,
            comm: "rootkit".to_string(),
            present_in_pid_ns: false,
            present_in_task_list: false,
            present_in_pid_hash: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":42"));
        assert!(json.contains("rootkit"));
        assert!(json.contains("\"present_in_pid_hash\":true"));
    }

    // --- classifier helper tests ---

    #[test]
    fn process_missing_from_task_list_is_hidden() {
        assert!(is_dkom_hidden(false, true));
    }

    #[test]
    fn process_missing_from_pid_hash_is_hidden() {
        assert!(is_dkom_hidden(true, false));
    }

    #[test]
    fn process_in_all_sources_is_not_hidden() {
        assert!(!is_dkom_hidden(true, true));
    }

    // --- integration tests: find_hidden_processes must delegate to walk_psxview ---
    //
    // Layout used in the two tests below:
    //   vaddr = 0xFFFF_8000_0010_0000  (init_task, one 4KB page)
    //   paddr = 0x0080_0000
    //   offset  0: pid         (u32) = 1
    //   offset  4: state       (long) = 0
    //   offset 16: tasks.next  (u64) = vaddr+16  ← self-loop (only process)
    //   offset 24: tasks.prev  (u64) = vaddr+16
    //   offset 32: comm        (15 bytes) = "init"
    //   offset 48: mm          (u64) = 0
    //   offset 56: pid_links.next  (u64)  ← set differently per test
    //   offset 64: pid_links.pprev (u64)
    //   offset 0x800: first pid_hash bucket ← set differently per test

    use memf_core::test_builders::{flags as ptflags, SyntheticPhysMem};

    fn make_proc_hidden_reader(
        page_data: [u8; 4096],
        vaddr: u64,
        paddr: u64,
    ) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "state", 4, "long")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "mm", 48, "pointer")
            .add_field("task_struct", "pid_links", 56, "hlist_node")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_struct("hlist_node", 16)
            .add_field("hlist_node", "next", 0, "pointer")
            .add_field("hlist_node", "pprev", 8, "pointer")
            .add_symbol("init_task", vaddr)
            .add_symbol("pid_hash", vaddr + 0x800)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, ptflags::WRITABLE)
            .write_phys(paddr, &page_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    fn base_task_page(vaddr: u64) -> [u8; 4096] {
        let mut page = [0u8; 4096];
        page[0..4].copy_from_slice(&1u32.to_le_bytes()); // pid = 1
        let tasks_va = vaddr + 16;
        page[16..24].copy_from_slice(&tasks_va.to_le_bytes()); // tasks.next
        page[24..32].copy_from_slice(&tasks_va.to_le_bytes()); // tasks.prev
        page[32..36].copy_from_slice(b"init"); // comm
        page
    }

    /// RED: process in task list but pid_hash has no entry for it → must be flagged.
    #[test]
    fn find_hidden_processes_detects_task_list_only_process() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        // pid_hash bucket at 0x800 stays 0 (null) → no PIDs in hash
        let page = base_task_page(vaddr);
        let reader = make_proc_hidden_reader(page, vaddr, paddr);

        let hidden = find_hidden_processes(&reader).unwrap();
        assert_eq!(hidden.len(), 1, "init absent from pid_hash must be flagged");
        assert_eq!(hidden[0].pid, 1);
        assert!(hidden[0].present_in_task_list);
        assert!(!hidden[0].present_in_pid_hash);
    }

    /// RED: same process appears in pid_hash → must NOT be flagged.
    #[test]
    fn find_hidden_processes_clean_image_all_visible_returns_empty() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut page = base_task_page(vaddr);
        // pid_hash bucket at 0x800 → pid_links field at vaddr+56
        let pid_links_va = vaddr + 56;
        page[0x800..0x808].copy_from_slice(&pid_links_va.to_le_bytes());
        // pid_links.next = 0 (end of chain); .pprev points back to bucket
        page[0x808..0x810].copy_from_slice(&(vaddr + 0x800).to_le_bytes());
        let reader = make_proc_hidden_reader(page, vaddr, paddr);

        let hidden = find_hidden_processes(&reader).unwrap();
        assert!(hidden.is_empty(), "process visible in all sources must not be flagged");
    }
}
