//! Linux process memory map (VMA) walker.
//!
//! Enumerates virtual memory areas by walking the `vm_area_struct` singly-linked
//! list from `mm_struct.mmap` for each process in the task list.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, Result, VmaFlags, VmaInfo};

/// Walk all process VMAs from the task list.
///
/// For each process, follows `task_struct.mm → mm_struct.mmap` to the head
/// of the `vm_area_struct` chain, then traverses via `vm_next` pointers.
pub fn walk_maps<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<VmaInfo>> {
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

    let mut all_vmas = Vec::new();

    // Include init_task itself
    collect_process_vmas(reader, init_task_addr, &mut all_vmas);

    for &task_addr in &task_addrs {
        collect_process_vmas(reader, task_addr, &mut all_vmas);
    }

    Ok(all_vmas)
}

/// Collect VMAs for a single process, silently skipping kernel threads (mm == NULL).
fn collect_process_vmas<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
    out: &mut Vec<VmaInfo>,
) {
    let mm_ptr: u64 = match reader.read_field(task_addr, "task_struct", "mm") {
        Ok(v) => v,
        Err(_) => return,
    };
    if mm_ptr == 0 {
        return; // kernel thread — no user VMAs
    }

    if let Ok(vmas) = walk_process_maps(reader, task_addr) {
        out.extend(vmas);
    }
}

/// Walk VMAs for a single process given its `task_struct` address.
pub fn walk_process_maps<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
) -> Result<Vec<VmaInfo>> {
    let pid: u32 = reader.read_field(task_addr, "task_struct", "pid")?;
    let comm = reader.read_field_string(task_addr, "task_struct", "comm", 16)?;
    let mm_ptr: u64 = reader.read_field(task_addr, "task_struct", "mm")?;

    if mm_ptr == 0 {
        return Err(Error::Walker(format!(
            "task {} (PID {}) has NULL mm (kernel thread)",
            comm, pid
        )));
    }

    let mmap_ptr: u64 = reader.read_field(mm_ptr, "mm_struct", "mmap")?;

    let mut vmas = Vec::new();
    let mut vma_addr = mmap_ptr;

    // Walk the singly-linked vm_next chain (NULL-terminated)
    while vma_addr != 0 {
        let vm_start: u64 = reader.read_field(vma_addr, "vm_area_struct", "vm_start")?;
        let vm_end: u64 = reader.read_field(vma_addr, "vm_area_struct", "vm_end")?;
        let vm_flags: u64 = reader.read_field(vma_addr, "vm_area_struct", "vm_flags")?;
        let vm_pgoff: u64 = reader.read_field(vma_addr, "vm_area_struct", "vm_pgoff")?;
        let vm_file: u64 = reader.read_field(vma_addr, "vm_area_struct", "vm_file")?;

        vmas.push(VmaInfo {
            pid: u64::from(pid),
            comm: comm.clone(),
            start: vm_start,
            end: vm_end,
            flags: VmaFlags::from_raw(vm_flags),
            pgoff: vm_pgoff,
            file_backed: vm_file != 0,
        });

        vma_addr = reader.read_field(vma_addr, "vm_area_struct", "vm_next")?;
    }

    Ok(vmas)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_test_reader(data: &[u8], vaddr: u64, paddr: u64) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            // task_struct
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "state", 4, "long")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "mm", 48, "pointer")
            .add_field("task_struct", "real_parent", 56, "pointer")
            // list_head
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            // mm_struct
            .add_struct("mm_struct", 128)
            .add_field("mm_struct", "pgd", 0, "pointer")
            .add_field("mm_struct", "mmap", 8, "pointer")
            // vm_area_struct
            .add_struct("vm_area_struct", 64)
            .add_field("vm_area_struct", "vm_start", 0, "unsigned long")
            .add_field("vm_area_struct", "vm_end", 8, "unsigned long")
            .add_field("vm_area_struct", "vm_next", 16, "pointer")
            .add_field("vm_area_struct", "vm_flags", 24, "unsigned long")
            .add_field("vm_area_struct", "vm_pgoff", 32, "unsigned long")
            .add_field("vm_area_struct", "vm_file", 40, "pointer")
            // symbol
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
    fn walk_single_process_two_vmas() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task (PID 1, "systemd")
        data[0..4].copy_from_slice(&1u32.to_le_bytes());     // pid
        data[4..12].copy_from_slice(&0i64.to_le_bytes());    // state
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes()); // tasks.next → self
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes()); // tasks.prev → self
        data[32..39].copy_from_slice(b"systemd");             // comm
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes()); // mm → mm_struct

        // mm_struct at +0x200
        data[0x200..0x208].copy_from_slice(&0x1000u64.to_le_bytes()); // pgd (unused here)
        let vma1_addr = vaddr + 0x300;
        data[0x208..0x210].copy_from_slice(&vma1_addr.to_le_bytes()); // mmap → first VMA

        // VMA #1 at +0x300: code segment (r-x)
        data[0x300..0x308].copy_from_slice(&0x0040_0000u64.to_le_bytes()); // vm_start
        data[0x308..0x310].copy_from_slice(&0x0040_1000u64.to_le_bytes()); // vm_end
        let vma2_addr = vaddr + 0x400;
        data[0x310..0x318].copy_from_slice(&vma2_addr.to_le_bytes());      // vm_next → VMA #2
        data[0x318..0x320].copy_from_slice(&0x5u64.to_le_bytes());         // vm_flags: r-x
        data[0x320..0x328].copy_from_slice(&0u64.to_le_bytes());           // vm_pgoff
        data[0x328..0x330].copy_from_slice(&0x9999u64.to_le_bytes());      // vm_file (non-null)

        // VMA #2 at +0x400: heap (rw-)
        data[0x400..0x408].copy_from_slice(&0x7FFF_0000u64.to_le_bytes()); // vm_start
        data[0x408..0x410].copy_from_slice(&0x7FFF_2000u64.to_le_bytes()); // vm_end
        data[0x410..0x418].copy_from_slice(&0u64.to_le_bytes());           // vm_next: NULL (end)
        data[0x418..0x420].copy_from_slice(&0x3u64.to_le_bytes());         // vm_flags: rw-
        data[0x420..0x428].copy_from_slice(&0u64.to_le_bytes());           // vm_pgoff
        data[0x428..0x430].copy_from_slice(&0u64.to_le_bytes());           // vm_file: NULL (anon)

        let reader = make_test_reader(&data, vaddr, paddr);
        let vmas = walk_maps(&reader).unwrap();

        assert_eq!(vmas.len(), 2);

        assert_eq!(vmas[0].pid, 1);
        assert_eq!(vmas[0].comm, "systemd");
        assert_eq!(vmas[0].start, 0x0040_0000);
        assert_eq!(vmas[0].end, 0x0040_1000);
        assert!(vmas[0].flags.read);
        assert!(!vmas[0].flags.write);
        assert!(vmas[0].flags.exec);
        assert!(vmas[0].file_backed);

        assert_eq!(vmas[1].start, 0x7FFF_0000);
        assert_eq!(vmas[1].end, 0x7FFF_2000);
        assert!(vmas[1].flags.read);
        assert!(vmas[1].flags.write);
        assert!(!vmas[1].flags.exec);
        assert!(!vmas[1].file_backed);
    }

    #[test]
    fn walk_maps_skips_kernel_threads() {
        // Kernel threads have mm == NULL — should produce no VMAs
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task (PID 0, "swapper/0", mm = NULL)
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..41].copy_from_slice(b"swapper/0");
        data[48..56].copy_from_slice(&0u64.to_le_bytes()); // mm = NULL

        let reader = make_test_reader(&data, vaddr, paddr);
        let vmas = walk_maps(&reader).unwrap();

        assert!(vmas.is_empty());
    }

    #[test]
    fn walk_process_maps_returns_error_for_missing_mm() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        data[48..56].copy_from_slice(&0u64.to_le_bytes()); // mm = NULL

        let reader = make_test_reader(&data, vaddr, paddr);
        let result = walk_process_maps(&reader, vaddr);
        assert!(result.is_err());
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

        let result = walk_maps(&reader);
        assert!(result.is_err());
    }
}
