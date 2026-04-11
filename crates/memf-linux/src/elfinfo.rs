//! Linux ELF header extraction from process memory.
//!
//! Walks process VMAs and checks for the ELF magic (`\x7fELF`) at the
//! start of file-backed regions. Extracts ELF header fields to identify
//! loaded binaries and shared libraries.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{ElfInfo, ElfType, Error, Result};

/// ELF magic bytes.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Minimum ELF header size (64-bit).
const ELF64_HEADER_SIZE: usize = 64;

/// Walk all process VMAs and extract ELF headers.
///
/// For each process, walks the VMA list and reads the first
/// [`ELF64_HEADER_SIZE`] bytes from each region. Regions starting
/// with the ELF magic are parsed and returned.
pub fn walk_elfinfo<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>) -> Result<Vec<ElfInfo>> {
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

    scan_process_elfs(reader, init_task_addr, &mut results);

    for &task_addr in &task_addrs {
        scan_process_elfs(reader, task_addr, &mut results);
    }

    Ok(results)
}

/// Scan a single process's VMAs for ELF headers.
fn scan_process_elfs<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
    out: &mut Vec<ElfInfo>,
) {
    let mm_ptr: u64 = match reader.read_field(task_addr, "task_struct", "mm") {
        Ok(v) => v,
        Err(_) => return,
    };
    if mm_ptr == 0 {
        return;
    }

    let pid: u32 = match reader.read_field(task_addr, "task_struct", "pid") {
        Ok(v) => v,
        Err(_) => return,
    };
    let comm = reader
        .read_field_string(task_addr, "task_struct", "comm", 16)
        .unwrap_or_default();

    let mmap_ptr: u64 = match reader.read_field(mm_ptr, "mm_struct", "mmap") {
        Ok(v) => v,
        Err(_) => return,
    };

    let mut vma_addr = mmap_ptr;
    while vma_addr != 0 {
        let vm_start: u64 = match reader.read_field(vma_addr, "vm_area_struct", "vm_start") {
            Ok(v) => v,
            Err(_) => break,
        };

        // Read the first 64 bytes and check for ELF magic
        if let Ok(header_bytes) = reader.read_bytes(vm_start, ELF64_HEADER_SIZE) {
            if let Some(info) = parse_elf64_header(&header_bytes, u64::from(pid), &comm, vm_start) {
                out.push(info);
            }
        }

        vma_addr = reader
            .read_field(vma_addr, "vm_area_struct", "vm_next")
            .unwrap_or(0);
    }
}

/// Parse a 64-bit ELF header from raw bytes.
///
/// Returns `None` if the magic doesn't match or the header is too short.
fn parse_elf64_header(bytes: &[u8], pid: u64, comm: &str, vma_start: u64) -> Option<ElfInfo> {
    if bytes.len() < ELF64_HEADER_SIZE {
        return None;
    }
    if bytes[0..4] != ELF_MAGIC {
        return None;
    }
    // Verify ELFCLASS64 (e_ident[4] == 2)
    if bytes[4] != 2 {
        return None;
    }

    let e_type = u16::from_le_bytes(bytes[16..18].try_into().unwrap());
    let e_machine = u16::from_le_bytes(bytes[18..20].try_into().unwrap());
    let e_entry = u64::from_le_bytes(bytes[24..32].try_into().unwrap());

    Some(ElfInfo {
        pid,
        comm: comm.to_string(),
        vma_start,
        elf_type: ElfType::from_raw(e_type),
        machine: e_machine,
        entry_point: e_entry,
    })
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
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_struct("mm_struct", 128)
            .add_field("mm_struct", "pgd", 0, "pointer")
            .add_field("mm_struct", "mmap", 8, "pointer")
            .add_struct("vm_area_struct", 64)
            .add_field("vm_area_struct", "vm_start", 0, "unsigned long")
            .add_field("vm_area_struct", "vm_end", 8, "unsigned long")
            .add_field("vm_area_struct", "vm_next", 16, "pointer")
            .add_field("vm_area_struct", "vm_flags", 24, "unsigned long")
            .add_field("vm_area_struct", "vm_pgoff", 32, "unsigned long")
            .add_field("vm_area_struct", "vm_file", 40, "pointer")
            .add_symbol("init_task", vaddr)
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

    /// Build a minimal ELF64 header for testing.
    fn build_elf64_header(elf_type: u16, machine: u16, entry: u64) -> Vec<u8> {
        let mut hdr = vec![0u8; 4096];
        // e_ident
        hdr[0..4].copy_from_slice(&ELF_MAGIC);
        hdr[4] = 2; // ELFCLASS64
        hdr[5] = 1; // ELFDATA2LSB
        hdr[6] = 1; // EV_CURRENT
                    // e_type (offset 16)
        hdr[16..18].copy_from_slice(&elf_type.to_le_bytes());
        // e_machine (offset 18)
        hdr[18..20].copy_from_slice(&machine.to_le_bytes());
        // e_version (offset 20)
        hdr[20..24].copy_from_slice(&1u32.to_le_bytes());
        // e_entry (offset 24)
        hdr[24..32].copy_from_slice(&entry.to_le_bytes());
        hdr
    }

    #[test]
    fn detects_elf_in_process_vma() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task (PID 1, "cat")
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..35].copy_from_slice(b"cat");
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());

        // mm_struct
        data[0x200..0x208].copy_from_slice(&0x1000u64.to_le_bytes()); // pgd
        let vma_addr = vaddr + 0x300;
        data[0x208..0x210].copy_from_slice(&vma_addr.to_le_bytes()); // mmap

        // VMA: code segment (r-x, file-backed)
        let code_vaddr: u64 = 0x0000_5555_0000_0000;
        let code_paddr: u64 = 0x0090_0000;
        data[0x300..0x308].copy_from_slice(&code_vaddr.to_le_bytes());
        data[0x308..0x310].copy_from_slice(&(code_vaddr + 0x1000).to_le_bytes());
        data[0x310..0x318].copy_from_slice(&0u64.to_le_bytes()); // vm_next = NULL
        data[0x318..0x320].copy_from_slice(&0x5u64.to_le_bytes()); // r-x
        data[0x328..0x330].copy_from_slice(&0xABCDu64.to_le_bytes()); // vm_file non-null

        let elf = build_elf64_header(
            3,  // ET_DYN (PIE executable)
            62, // EM_X86_64
            0x0000_5555_0000_1000,
        );

        let reader = make_test_reader(&data, vaddr, paddr, &[(code_vaddr, code_paddr, &elf)]);
        let results = walk_elfinfo(&reader).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pid, 1);
        assert_eq!(results[0].comm, "cat");
        assert_eq!(results[0].elf_type, ElfType::SharedObject);
        assert_eq!(results[0].machine, 62);
        assert_eq!(results[0].entry_point, 0x0000_5555_0000_1000);
    }

    #[test]
    fn skips_non_elf_regions() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..36].copy_from_slice(b"test");
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());

        data[0x200..0x208].copy_from_slice(&0x1000u64.to_le_bytes());
        let vma_addr = vaddr + 0x300;
        data[0x208..0x210].copy_from_slice(&vma_addr.to_le_bytes());

        // VMA with non-ELF data
        let region_vaddr: u64 = 0x0000_5555_0000_0000;
        let region_paddr: u64 = 0x0090_0000;
        data[0x300..0x308].copy_from_slice(&region_vaddr.to_le_bytes());
        data[0x308..0x310].copy_from_slice(&(region_vaddr + 0x1000).to_le_bytes());
        data[0x310..0x318].copy_from_slice(&0u64.to_le_bytes());
        data[0x318..0x320].copy_from_slice(&0x5u64.to_le_bytes());
        data[0x328..0x330].copy_from_slice(&0xABCDu64.to_le_bytes());

        let non_elf = vec![0xFFu8; 4096]; // garbage, not ELF

        let reader = make_test_reader(
            &data,
            vaddr,
            paddr,
            &[(region_vaddr, region_paddr, &non_elf)],
        );
        let results = walk_elfinfo(&reader).unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn parse_elf64_header_validates_magic() {
        let mut bad = vec![0u8; 64];
        bad[0..4].copy_from_slice(b"NOPE");
        assert!(parse_elf64_header(&bad, 1, "test", 0x1000).is_none());
    }

    #[test]
    fn parse_elf64_header_too_short() {
        let short = vec![0x7f, b'E', b'L', b'F']; // only 4 bytes
        assert!(parse_elf64_header(&short, 1, "test", 0x1000).is_none());
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

        let result = walk_elfinfo(&reader);
        assert!(result.is_err());
    }
}
