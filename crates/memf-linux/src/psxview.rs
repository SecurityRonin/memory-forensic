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

    // Build set of PIDs found in the PID hash table.
    // If the hash table is unavailable (no symbol, unreadable memory, missing ISF
    // fields, or completely empty — which is impossible on a live system), we fall
    // back to assuming all PIDs are present (in_pid_hash = true).
    let pid_hash_pids = collect_pid_hash_pids(reader).filter(|s| !s.is_empty());

    let mut results = Vec::new();

    if let Ok(info) = read_task_info(reader, init_task_addr) {
        let in_pid_hash = pid_hash_pids
            .as_ref()
            .map(|set| set.contains(&info.0))
            .unwrap_or(true);
        results.push(PsxViewInfo {
            pid: info.0,
            comm: info.1,
            in_task_list: true,
            in_pid_hash,
        });
    }

    for &task_addr in &task_addrs {
        if let Ok(info) = read_task_info(reader, task_addr) {
            let in_pid_hash = pid_hash_pids
                .as_ref()
                .map(|set| set.contains(&info.0))
                .unwrap_or(true);
            results.push(PsxViewInfo {
                pid: info.0,
                comm: info.1,
                in_task_list: true,
                in_pid_hash,
            });
        }
    }

    Ok(results)
}

/// Walk the PID hash table and collect every PID found there.
///
/// Linux maintains a hash table (`pid_hash`) indexed by PID value. Each bucket
/// is an `hlist_head` — a pointer to the first `hlist_node`. Each `task_struct`
/// embeds an `hlist_node` in its `pid_links` field. By walking every non-empty
/// bucket and following `hlist_node.next` chains we get the set of PIDs visible
/// in the hash. A process absent from this set but present in the task list has
/// been hidden via DKOM (Direct Kernel Object Manipulation).
///
/// Returns `None` when the symbol or required ISF fields are unavailable (the
/// caller should fall back to `in_pid_hash = true`).
fn collect_pid_hash_pids<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Option<std::collections::HashSet<u64>> {
    // Require the pid_hash symbol and hlist_node/pid_links field offsets.
    let pid_hash_addr = reader.symbols().symbol_address("pid_hash")?;
    let pid_links_offset = reader.symbols().field_offset("task_struct", "pid_links")?;
    let hlist_next_offset = reader.symbols().field_offset("hlist_node", "next")?;

    let mut found_pids = std::collections::HashSet::new();

    // pid_hash is an array of hlist_head structs (each is a single pointer).
    // We scan until we hit an unreadable address; bucket count is not in ISF
    // so we probe until the first read failure.
    let mut bucket_offset: u64 = 0;
    loop {
        let bucket_head_addr = pid_hash_addr.wrapping_add(bucket_offset);
        // Each hlist_head is a single pointer to the first hlist_node (or NULL).
        let first_node_ptr: u64 = match reader
            .read_bytes(bucket_head_addr, 8)
            .ok()
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes)
        {
            Some(v) => v,
            None => break,
        };

        // Walk the hlist_node chain for this bucket.
        let mut node_ptr = first_node_ptr;
        let mut depth = 0usize;
        while node_ptr != 0 && depth < 10_000 {
            // task_struct base = hlist_node address − pid_links_offset
            let task_addr = node_ptr.wrapping_sub(pid_links_offset);
            if let Ok(pid) = reader.read_field::<u32>(task_addr, "task_struct", "pid") {
                found_pids.insert(u64::from(pid));
            }
            // Advance to hlist_node.next
            let next_ptr: u64 = match reader
                .read_bytes(node_ptr.wrapping_add(hlist_next_offset), 8)
                .ok()
                .and_then(|b| b.try_into().ok())
                .map(u64::from_le_bytes)
            {
                Some(v) => v,
                None => break,
            };
            node_ptr = next_ptr;
            depth += 1;
        }

        bucket_offset = bucket_offset.wrapping_add(8);
        // Stop after scanning a reasonable upper bound of buckets (typically
        // pid_hash has 4096 buckets on a 64-bit system). We stop early on
        // read failure so this cap just prevents runaway on synthetic memory.
        if bucket_offset >= 8 * 4096 {
            break;
        }
    }

    Some(found_pids)
}

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
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
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
        assert!(
            result.is_err(),
            "missing task_struct.tasks field should return error"
        );
    }

    #[test]
    fn walk_psxview_multiple_tasks_in_list() {
        let init_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let init_paddr: u64 = 0x0090_0000;
        let task2_vaddr: u64 = 0xFFFF_8000_0021_0000;
        let task2_paddr: u64 = 0x0091_0000;

        let mut init_data = vec![0u8; 4096];
        init_data[0..4].copy_from_slice(&1u32.to_le_bytes());
        let task2_tasks = task2_vaddr + 16;
        init_data[16..24].copy_from_slice(&task2_tasks.to_le_bytes());
        init_data[24..32].copy_from_slice(&task2_tasks.to_le_bytes());
        init_data[32..38].copy_from_slice(b"init\0\0");

        let mut task2_data = vec![0u8; 4096];
        task2_data[0..4].copy_from_slice(&2u32.to_le_bytes());
        let init_tasks = init_vaddr + 16;
        task2_data[16..24].copy_from_slice(&init_tasks.to_le_bytes());
        task2_data[24..32].copy_from_slice(&init_tasks.to_le_bytes());
        task2_data[32..36].copy_from_slice(b"sh\0\0");

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "state", 4, "long")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_field("task_struct", "comm", 32, "char")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("init_task", init_vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(init_vaddr, init_paddr, ptflags::WRITABLE)
            .write_phys(init_paddr, &init_data)
            .map_4k(task2_vaddr, task2_paddr, ptflags::WRITABLE)
            .write_phys(task2_paddr, &task2_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_psxview(&reader).unwrap();

        assert_eq!(results.len(), 2, "expected two tasks: init + task2");

        let init_entry = results
            .iter()
            .find(|r| r.pid == 1)
            .expect("init_task missing");
        assert!(init_entry.in_task_list);
        assert!(init_entry.in_pid_hash);

        let task2_entry = results.iter().find(|r| r.pid == 2).expect("task2 missing");
        assert!(task2_entry.in_task_list);
        assert!(task2_entry.in_pid_hash);
        assert_eq!(task2_entry.comm, "sh");
    }

    #[test]
    fn psxview_entries_have_correct_visibility_flags() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
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
