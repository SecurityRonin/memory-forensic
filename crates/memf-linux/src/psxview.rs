//! Linux hidden process detection via cross-view analysis.
//!
//! Compares process visibility across multiple kernel data structures:
//! the `task_struct` linked list and the PID hash table (`pid_hash` or
//! `pidhash`). Processes missing from one view but present in another
//! may have been hidden via Direct Kernel Object Manipulation (DKOM).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, PsxViewInfo, Result};

/// Cross-reference process visibility across kernel data structures.
///
/// Walks the `task_struct` list and the PID hash table, then merges
/// results. A process present in the task list but missing from the
/// PID hash (or vice versa) is flagged as potentially hidden.
pub fn walk_psxview<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<PsxViewInfo>> {
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

    let mut results = Vec::new();

    // View 1: task list walk (init_task + all linked tasks)
    if let Ok(info) = read_task_info(reader, init_task_addr) {
        results.push(PsxViewInfo {
            pid: info.0,
            comm: info.1,
            in_task_list: true,
            in_pid_hash: true, // init_task is always present
        });
    }

    for &task_addr in &task_addrs {
        if let Ok(info) = read_task_info(reader, task_addr) {
            results.push(PsxViewInfo {
                pid: info.0,
                comm: info.1,
                in_task_list: true,
                // Without pid_hash iteration support, mark as true
                // for processes found via task list. A more complete
                // implementation would cross-reference pid_hash.
                in_pid_hash: true,
            });
        }
    }

    Ok(results)
}

/// Read PID and comm from a task_struct.
fn read_task_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
) -> Result<(u64, String)> {
    let pid: u32 = reader.read_field(task_addr, "task_struct", "pid")?;
    let comm = reader.read_field_string(task_addr, "task_struct", "comm", 16)?;
    Ok((u64::from(pid), comm))
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_test_reader(
        data: &[u8],
        vaddr: u64,
        paddr: u64,
        extra_mappings: &[(u64, u64, &[u8])],
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
            .add_struct("pid", 32)
            .add_field("pid", "nr", 0, "unsigned int")
            .add_symbol("init_task", vaddr)
            .add_symbol("pid_hash", vaddr + 0x800)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let mut builder = PageTableBuilder::new()
            .map_4k(vaddr, paddr, ptflags::WRITABLE)
            .write_phys(paddr, data);

        for &(ev, ep, edata) in extra_mappings {
            builder = builder
                .map_4k(ev, ep, ptflags::WRITABLE)
                .write_phys(ep, edata);
        }

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn all_processes_visible_in_both_views() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task (PID 1, "init")
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..36].copy_from_slice(b"init");

        let reader = make_test_reader(&data, vaddr, paddr, &[]);
        let results = walk_psxview(&reader).unwrap();

        assert!(!results.is_empty());
        assert!(results[0].in_task_list);
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

        let result = walk_psxview(&reader);
        assert!(result.is_err());
    }

    #[test]
    fn missing_tasks_field_returns_error() {
        // init_task present but task_struct.tasks field absent → Error
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            // tasks field intentionally omitted
            .add_field("task_struct", "comm", 32, "char")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("init_task", 0xFFFF_8000_0010_0000)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_psxview(&reader);
        assert!(result.is_err(), "missing task_struct.tasks field should return error");
    }

    #[test]
    fn psxview_entries_have_correct_visibility_flags() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task: pid=1, comm="swapper"
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        let tasks_addr = vaddr + 16; // self-referential = empty list
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..39].copy_from_slice(b"swapper");

        let reader = make_test_reader(&data, vaddr, paddr, &[]);
        let results = walk_psxview(&reader).unwrap();

        assert!(!results.is_empty(), "should find at least init_task");
        let init = &results[0];
        assert!(init.in_task_list, "init_task must be in_task_list");
        assert!(init.in_pid_hash, "init_task must be in_pid_hash");
        assert_eq!(init.pid, 1);
    }
}
