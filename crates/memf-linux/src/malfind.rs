//! Linux suspicious memory region detector (malfind).
//!
//! Scans process VMAs for regions that have suspicious permission
//! combinations — primarily anonymous (non-file-backed) regions with
//! both write and execute permissions, which often indicate injected code.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, MalfindInfo, Result, VmaFlags};

/// Number of header bytes to capture from suspicious regions.
const HEADER_SIZE: usize = 64;

/// Scan all process VMAs for suspicious memory regions.
///
/// Walks the task list, then for each process walks its VMAs via
/// `mm_struct.mmap`. Flags anonymous regions with write+execute
/// permissions.
pub fn scan_malfind<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<MalfindInfo>> {
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

    let mut findings = Vec::new();

    // Include init_task itself
    scan_process_vmas(reader, init_task_addr, &mut findings);

    for &task_addr in &task_addrs {
        scan_process_vmas(reader, task_addr, &mut findings);
    }

    Ok(findings)
}

/// Scan a single process's VMAs for suspicious regions.
fn scan_process_vmas<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
    out: &mut Vec<MalfindInfo>,
) {
    let mm_ptr: u64 = match reader.read_field(task_addr, "task_struct", "mm") {
        Ok(v) => v,
        Err(_) => return,
    };
    if mm_ptr == 0 {
        return; // kernel thread
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
        if let Ok(Some(f)) = check_vma(reader, vma_addr, u64::from(pid), &comm) {
            out.push(f);
        }

        vma_addr = reader
            .read_field(vma_addr, "vm_area_struct", "vm_next")
            .unwrap_or(0);
    }
}

/// Check a single VMA for suspicious characteristics.
/// Returns `Ok(Some(finding))` if suspicious, `Ok(None)` if clean.
fn check_vma<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    vma_addr: u64,
    pid: u64,
    comm: &str,
) -> Result<Option<MalfindInfo>> {
    let vm_flags: u64 = reader.read_field(vma_addr, "vm_area_struct", "vm_flags")?;
    let vm_file: u64 = reader.read_field(vma_addr, "vm_area_struct", "vm_file")?;

    let flags = VmaFlags::from_raw(vm_flags);
    let file_backed = vm_file != 0;

    // Suspicious: write+exec AND anonymous (not file-backed)
    if !(flags.write && flags.exec && !file_backed) {
        return Ok(None);
    }

    let vm_start: u64 = reader.read_field(vma_addr, "vm_area_struct", "vm_start")?;
    let vm_end: u64 = reader.read_field(vma_addr, "vm_area_struct", "vm_end")?;

    // Try to read header bytes from the region
    let read_size = HEADER_SIZE.min((vm_end - vm_start) as usize);
    let header_bytes = reader.read_bytes(vm_start, read_size).unwrap_or_default();

    let reason = format!(
        "anonymous rwx region ({} flags, {} bytes)",
        flags,
        vm_end - vm_start
    );

    Ok(Some(MalfindInfo {
        pid,
        comm: comm.to_string(),
        start: vm_start,
        end: vm_end,
        flags,
        reason,
        header_bytes,
    }))
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

    #[test]
    fn detects_rwx_anonymous_region() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task (PID 1, "victim")
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..38].copy_from_slice(b"victim");
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());

        // mm_struct
        data[0x200..0x208].copy_from_slice(&0x1000u64.to_le_bytes());
        let vma1_addr = vaddr + 0x300;
        data[0x208..0x210].copy_from_slice(&vma1_addr.to_le_bytes());

        // VMA #1: normal code segment r-x, file-backed — NOT suspicious
        let code_start: u64 = 0xFFFF_8000_0020_0000;
        data[0x300..0x308].copy_from_slice(&code_start.to_le_bytes());
        data[0x308..0x310].copy_from_slice(&(code_start + 0x1000).to_le_bytes());
        let vma2_addr = vaddr + 0x400;
        data[0x310..0x318].copy_from_slice(&vma2_addr.to_le_bytes());
        data[0x318..0x320].copy_from_slice(&0x5u64.to_le_bytes()); // r-x
        data[0x328..0x330].copy_from_slice(&0x9999u64.to_le_bytes()); // vm_file non-null

        // VMA #2: suspicious! anonymous rwx — injected shellcode
        let suspect_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let suspect_paddr: u64 = 0x0090_0000;
        data[0x400..0x408].copy_from_slice(&suspect_vaddr.to_le_bytes());
        data[0x408..0x410].copy_from_slice(&(suspect_vaddr + 0x1000).to_le_bytes());
        data[0x410..0x418].copy_from_slice(&0u64.to_le_bytes()); // vm_next = NULL
        data[0x418..0x420].copy_from_slice(&0x7u64.to_le_bytes()); // rwx
        data[0x420..0x428].copy_from_slice(&0u64.to_le_bytes()); // vm_pgoff
        data[0x428..0x430].copy_from_slice(&0u64.to_le_bytes()); // vm_file = NULL (anon)

        // Write MZ header into the suspicious region
        let mut suspect_data = vec![0u8; 4096];
        suspect_data[0] = b'M';
        suspect_data[1] = b'Z';
        suspect_data[2..64].fill(0x90); // NOP sled

        let reader = make_test_reader(
            &data,
            vaddr,
            paddr,
            &[(suspect_vaddr, suspect_paddr, &suspect_data)],
        );
        let findings = scan_malfind(&reader).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pid, 1);
        assert_eq!(findings[0].comm, "victim");
        assert_eq!(findings[0].start, suspect_vaddr);
        assert!(findings[0].flags.write);
        assert!(findings[0].flags.exec);
        assert_eq!(findings[0].header_bytes[0], b'M');
        assert_eq!(findings[0].header_bytes[1], b'Z');
        assert!(findings[0].reason.contains("anonymous"));
    }

    #[test]
    fn ignores_file_backed_rwx() {
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

        // rwx but FILE-BACKED — not suspicious (e.g. JIT region from mapped file)
        data[0x300..0x308].copy_from_slice(&0x0040_0000u64.to_le_bytes());
        data[0x308..0x310].copy_from_slice(&0x0040_1000u64.to_le_bytes());
        data[0x310..0x318].copy_from_slice(&0u64.to_le_bytes());
        data[0x318..0x320].copy_from_slice(&0x7u64.to_le_bytes()); // rwx
        data[0x328..0x330].copy_from_slice(&0xABCDu64.to_le_bytes()); // vm_file non-null

        let reader = make_test_reader(&data, vaddr, paddr, &[]);
        let findings = scan_malfind(&reader).unwrap();

        assert!(findings.is_empty());
    }

    #[test]
    fn skips_kernel_threads() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..41].copy_from_slice(b"swapper/0");
        data[48..56].copy_from_slice(&0u64.to_le_bytes()); // mm = NULL

        let reader = make_test_reader(&data, vaddr, paddr, &[]);
        let findings = scan_malfind(&reader).unwrap();

        assert!(findings.is_empty());
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

        let result = scan_malfind(&reader);
        assert!(result.is_err());
    }
}
