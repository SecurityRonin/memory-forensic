//! VMA region walker — shared abstraction for Linux walkers.
//!
//! Provides [`for_each_task_vma`], which encapsulates the repeated pattern of
//! reading `mm_struct.mmap` and walking the VMA linked list via `vm_next`.
//! Any walker that needs to inspect VMAs for a single task can delegate to
//! this function instead of reimplementing the linked-list traversal.

use std::collections::HashSet;

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::types::VmaFlags;

/// Hard cap on VMAs walked for one task — defence in depth against a corrupt
/// `vm_next` chain that is absurdly long but not strictly cyclic. The Linux
/// default `vm.max_map_count` is 65 530, so this never trips on real data.
const MAX_VMAS: usize = 1_000_000;

/// Data read from a single `vm_area_struct` entry.
#[derive(Debug, Clone)]
pub struct VmaEntry {
    /// Virtual address of the `vm_area_struct` in kernel memory.
    pub vma_addr: u64,
    /// First byte of the mapping (inclusive).
    pub start: u64,
    /// First byte past the mapping (exclusive).
    pub end: u64,
    /// Decoded page-protection flags.
    pub flags: VmaFlags,
    /// Pointer to the backing `struct file` (0 if anonymous).
    pub file_ptr: u64,
}

/// Walk every VMA for a single task and call `callback` for each entry.
///
/// Gracefully skips the task if `mm == 0` (kernel thread or no address space)
/// or if `mm_struct.mmap` is unreadable. Individual unreadable VMAs terminate
/// the walk early (same behaviour as the walkers this replaces).
///
/// # Arguments
///
/// * `reader`     — kernel `ObjectReader` with the kernel CR3.
/// * `task_addr`  — virtual address of the `task_struct`.
/// * `callback`   — called for each successfully read VMA entry.
pub fn for_each_task_vma<P, F>(reader: &ObjectReader<P>, task_addr: u64, callback: &mut F)
where
    P: PhysicalMemoryProvider,
    F: FnMut(VmaEntry),
{
    let mm_ptr: u64 = match reader.read_field(task_addr, "task_struct", "mm") {
        Ok(v) => v,
        Err(_) => return,
    };
    if mm_ptr == 0 {
        return;
    }
    let mmap_ptr: u64 = match reader.read_field(mm_ptr, "mm_struct", "mmap") {
        Ok(v) => v,
        Err(_) => return,
    };

    // Cycle / runaway guard: an attacker-controllable image can have a `vm_next`
    // that points back into the list (e.g. a VMA whose vm_next is itself). Track
    // visited VMA addresses and stop on revisit, plus a hard cap, so a corrupt
    // chain can never spin forever.
    let mut seen: HashSet<u64> = HashSet::new();
    let mut vma_addr = mmap_ptr;
    while vma_addr != 0 {
        if seen.len() >= MAX_VMAS || !seen.insert(vma_addr) {
            break;
        }
        let start: u64 = match reader.read_field(vma_addr, "vm_area_struct", "vm_start") {
            Ok(v) => v,
            Err(_) => break,
        };
        let end: u64 = match reader.read_field(vma_addr, "vm_area_struct", "vm_end") {
            Ok(v) => v,
            Err(_) => break,
        };
        let raw_flags: u64 = reader
            .read_field(vma_addr, "vm_area_struct", "vm_flags")
            .unwrap_or(0);
        let file_ptr: u64 = reader
            .read_field(vma_addr, "vm_area_struct", "vm_file")
            .unwrap_or(0);

        callback(VmaEntry {
            vma_addr,
            start,
            end,
            flags: VmaFlags::from_raw(raw_flags),
            file_ptr,
        });

        vma_addr = reader
            .read_field(vma_addr, "vm_area_struct", "vm_next")
            .unwrap_or(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags as ptflags, PageTableBuilder};
    use memf_symbols::test_builders::IsfBuilder;

    fn make_reader_with_isf(
        isf: &IsfBuilder,
        ptb: PageTableBuilder,
    ) -> memf_core::object_reader::ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let json = isf.build_json();
        let resolver = memf_symbols::isf::IsfResolver::from_value(&json).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = memf_core::vas::VirtualAddressSpace::new(
            mem,
            cr3,
            memf_core::vas::TranslationMode::X86_64FourLevel,
        );
        memf_core::object_reader::ObjectReader::new(vas, Box::new(resolver))
    }

    // ---------------------------------------------------------------
    // RED tests — these define the expected contract of for_each_task_vma
    // ---------------------------------------------------------------

    #[test]
    fn task_with_null_mm_produces_no_vmas() {
        // A task_struct where mm == 0 (kernel thread) must yield no entries.
        let isf = IsfBuilder::new().add_struct("task_struct", 32).add_field(
            "task_struct",
            "mm",
            0,
            "pointer",
        );
        let task_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let task_paddr: u64 = 0x0010_0000;
        let mut page = [0u8; 4096];
        // mm field at offset 0 = 0 (null pointer)
        page[0..8].copy_from_slice(&0u64.to_le_bytes());
        let ptb = PageTableBuilder::new()
            .map_4k(task_vaddr, task_paddr, ptflags::WRITABLE)
            .write_phys(task_paddr, &page);
        let reader = make_reader_with_isf(&isf, ptb);

        let mut entries: Vec<VmaEntry> = Vec::new();
        for_each_task_vma(&reader, task_vaddr, &mut |e| entries.push(e));
        assert!(
            entries.is_empty(),
            "kernel thread (mm=0) should yield no VMAs"
        );
    }

    #[test]
    fn unreadable_mm_field_produces_no_vmas() {
        // If the task_struct itself is not mapped, no VMAs should be yielded.
        let isf = IsfBuilder::new().add_struct("task_struct", 32).add_field(
            "task_struct",
            "mm",
            0,
            "pointer",
        );
        let reader = memf_core::test_builders::make_reader(&isf);

        let mut entries: Vec<VmaEntry> = Vec::new();
        for_each_task_vma(&reader, 0xDEAD_BEEF_0000_0000, &mut |e| entries.push(e));
        assert!(
            entries.is_empty(),
            "unreadable task_struct should yield no VMAs"
        );
    }

    #[test]
    fn single_vma_yields_correct_entry() {
        // task_struct.mm → mm_struct.mmap → vm_area_struct → vm_next=0 (end)
        let task_vaddr: u64 = 0xFFFF_8000_0001_0000;
        let task_paddr: u64 = 0x0001_0000;
        let mm_vaddr: u64 = 0xFFFF_8000_0002_0000;
        let mm_paddr: u64 = 0x0002_0000;
        let vma_vaddr: u64 = 0xFFFF_8000_0003_0000;
        let vma_paddr: u64 = 0x0003_0000;

        // task_struct layout: mm@0 (pointer, 8 bytes)
        // mm_struct layout: mmap@0 (pointer, 8 bytes)
        // vm_area_struct layout: vm_start@0, vm_end@8, vm_flags@16, vm_file@24, vm_next@32

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 16)
            .add_field("task_struct", "mm", 0, "pointer")
            .add_struct("mm_struct", 16)
            .add_field("mm_struct", "mmap", 0, "pointer")
            .add_struct("vm_area_struct", 48)
            .add_field("vm_area_struct", "vm_start", 0, "unsigned long")
            .add_field("vm_area_struct", "vm_end", 8, "unsigned long")
            .add_field("vm_area_struct", "vm_flags", 16, "unsigned long")
            .add_field("vm_area_struct", "vm_file", 24, "pointer")
            .add_field("vm_area_struct", "vm_next", 32, "pointer");

        let mut task_page = [0u8; 4096];
        task_page[0..8].copy_from_slice(&mm_vaddr.to_le_bytes()); // task.mm

        let mut mm_page = [0u8; 4096];
        mm_page[0..8].copy_from_slice(&vma_vaddr.to_le_bytes()); // mm.mmap

        let vm_start: u64 = 0x0000_7FFF_0000_0000;
        let vm_end: u64 = 0x0000_7FFF_0001_0000;
        let vm_flags: u64 = 0x3; // read + write
        let vm_file: u64 = 0; // anonymous
        let vm_next: u64 = 0; // end of list

        let mut vma_page = [0u8; 4096];
        vma_page[0..8].copy_from_slice(&vm_start.to_le_bytes());
        vma_page[8..16].copy_from_slice(&vm_end.to_le_bytes());
        vma_page[16..24].copy_from_slice(&vm_flags.to_le_bytes());
        vma_page[24..32].copy_from_slice(&vm_file.to_le_bytes());
        vma_page[32..40].copy_from_slice(&vm_next.to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(task_vaddr, task_paddr, ptflags::WRITABLE)
            .write_phys(task_paddr, &task_page)
            .map_4k(mm_vaddr, mm_paddr, ptflags::WRITABLE)
            .write_phys(mm_paddr, &mm_page)
            .map_4k(vma_vaddr, vma_paddr, ptflags::WRITABLE)
            .write_phys(vma_paddr, &vma_page);

        let reader = make_reader_with_isf(&isf, ptb);

        let mut entries: Vec<VmaEntry> = Vec::new();
        for_each_task_vma(&reader, task_vaddr, &mut |e| entries.push(e));

        assert_eq!(entries.len(), 1, "expected exactly one VMA");
        let e = &entries[0];
        assert_eq!(e.start, vm_start);
        assert_eq!(e.end, vm_end);
        assert_eq!(e.file_ptr, 0, "anonymous mapping");
        assert!(e.flags.read, "read flag should be set");
        assert!(e.flags.write, "write flag should be set");
        assert!(!e.flags.exec, "exec flag should not be set");
    }

    #[test]
    fn cyclic_vm_next_terminates_after_one_visit() {
        // An attacker-controllable image can have a vm_next that points back into
        // the list. A VMA whose vm_next is itself must be visited once and then
        // the cycle guard must stop the walk — never loop forever.
        let task_vaddr: u64 = 0xFFFF_8000_0001_0000;
        let task_paddr: u64 = 0x0001_0000;
        let mm_vaddr: u64 = 0xFFFF_8000_0002_0000;
        let mm_paddr: u64 = 0x0002_0000;
        let vma_vaddr: u64 = 0xFFFF_8000_0003_0000;
        let vma_paddr: u64 = 0x0003_0000;

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 16)
            .add_field("task_struct", "mm", 0, "pointer")
            .add_struct("mm_struct", 16)
            .add_field("mm_struct", "mmap", 0, "pointer")
            .add_struct("vm_area_struct", 48)
            .add_field("vm_area_struct", "vm_start", 0, "unsigned long")
            .add_field("vm_area_struct", "vm_end", 8, "unsigned long")
            .add_field("vm_area_struct", "vm_flags", 16, "unsigned long")
            .add_field("vm_area_struct", "vm_file", 24, "pointer")
            .add_field("vm_area_struct", "vm_next", 32, "pointer");

        let mut task_page = [0u8; 4096];
        task_page[0..8].copy_from_slice(&mm_vaddr.to_le_bytes());
        let mut mm_page = [0u8; 4096];
        mm_page[0..8].copy_from_slice(&vma_vaddr.to_le_bytes());

        let mut vma_page = [0u8; 4096];
        vma_page[0..8].copy_from_slice(&0x0000_7FFF_0000_0000u64.to_le_bytes()); // vm_start
        vma_page[8..16].copy_from_slice(&0x0000_7FFF_0001_0000u64.to_le_bytes()); // vm_end
        vma_page[16..24].copy_from_slice(&3u64.to_le_bytes()); // vm_flags
        vma_page[24..32].copy_from_slice(&0u64.to_le_bytes()); // vm_file = anonymous
        vma_page[32..40].copy_from_slice(&vma_vaddr.to_le_bytes()); // vm_next = self (cycle!)

        let ptb = PageTableBuilder::new()
            .map_4k(task_vaddr, task_paddr, ptflags::WRITABLE)
            .write_phys(task_paddr, &task_page)
            .map_4k(mm_vaddr, mm_paddr, ptflags::WRITABLE)
            .write_phys(mm_paddr, &mm_page)
            .map_4k(vma_vaddr, vma_paddr, ptflags::WRITABLE)
            .write_phys(vma_paddr, &vma_page);

        let reader = make_reader_with_isf(&isf, ptb);

        let mut count = 0usize;
        for_each_task_vma(&reader, task_vaddr, &mut |_| count += 1);
        assert_eq!(
            count, 1,
            "self-referencing vm_next must be visited once, then the walk stops"
        );
    }

    #[test]
    fn two_vmas_chained_via_vm_next() {
        let task_vaddr: u64 = 0xFFFF_8000_0001_0000;
        let task_paddr: u64 = 0x0001_0000;
        let mm_vaddr: u64 = 0xFFFF_8000_0002_0000;
        let mm_paddr: u64 = 0x0002_0000;
        let vma1_vaddr: u64 = 0xFFFF_8000_0003_0000;
        let vma1_paddr: u64 = 0x0003_0000;
        let vma2_vaddr: u64 = 0xFFFF_8000_0004_0000;
        let vma2_paddr: u64 = 0x0004_0000;

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 16)
            .add_field("task_struct", "mm", 0, "pointer")
            .add_struct("mm_struct", 16)
            .add_field("mm_struct", "mmap", 0, "pointer")
            .add_struct("vm_area_struct", 48)
            .add_field("vm_area_struct", "vm_start", 0, "unsigned long")
            .add_field("vm_area_struct", "vm_end", 8, "unsigned long")
            .add_field("vm_area_struct", "vm_flags", 16, "unsigned long")
            .add_field("vm_area_struct", "vm_file", 24, "pointer")
            .add_field("vm_area_struct", "vm_next", 32, "pointer");

        let mut task_page = [0u8; 4096];
        task_page[0..8].copy_from_slice(&mm_vaddr.to_le_bytes());
        let mut mm_page = [0u8; 4096];
        mm_page[0..8].copy_from_slice(&vma1_vaddr.to_le_bytes());

        // VMA 1: anonymous rw, vm_next → vma2
        let mut vma1_page = [0u8; 4096];
        vma1_page[0..8].copy_from_slice(&0x0000_7FFF_0000_0000u64.to_le_bytes());
        vma1_page[8..16].copy_from_slice(&0x0000_7FFF_0001_0000u64.to_le_bytes());
        vma1_page[16..24].copy_from_slice(&3u64.to_le_bytes()); // r+w
        vma1_page[24..32].copy_from_slice(&0u64.to_le_bytes());
        vma1_page[32..40].copy_from_slice(&vma2_vaddr.to_le_bytes());

        // VMA 2: file-backed rx, vm_next = 0
        let fake_file_ptr: u64 = 0xFFFF_8888_0000_0000;
        let mut vma2_page = [0u8; 4096];
        vma2_page[0..8].copy_from_slice(&0x0000_7FFF_0010_0000u64.to_le_bytes());
        vma2_page[8..16].copy_from_slice(&0x0000_7FFF_0020_0000u64.to_le_bytes());
        vma2_page[16..24].copy_from_slice(&5u64.to_le_bytes()); // r+x
        vma2_page[24..32].copy_from_slice(&fake_file_ptr.to_le_bytes());
        vma2_page[32..40].copy_from_slice(&0u64.to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(task_vaddr, task_paddr, ptflags::WRITABLE)
            .write_phys(task_paddr, &task_page)
            .map_4k(mm_vaddr, mm_paddr, ptflags::WRITABLE)
            .write_phys(mm_paddr, &mm_page)
            .map_4k(vma1_vaddr, vma1_paddr, ptflags::WRITABLE)
            .write_phys(vma1_paddr, &vma1_page)
            .map_4k(vma2_vaddr, vma2_paddr, ptflags::WRITABLE)
            .write_phys(vma2_paddr, &vma2_page);

        let reader = make_reader_with_isf(&isf, ptb);

        let mut entries: Vec<VmaEntry> = Vec::new();
        for_each_task_vma(&reader, task_vaddr, &mut |e| entries.push(e));

        assert_eq!(entries.len(), 2, "expected two VMAs");
        assert_eq!(entries[0].file_ptr, 0, "vma1 is anonymous");
        assert_eq!(entries[1].file_ptr, fake_file_ptr, "vma2 is file-backed");
        assert!(entries[1].flags.read && entries[1].flags.exec, "vma2 is rx");
    }
}
