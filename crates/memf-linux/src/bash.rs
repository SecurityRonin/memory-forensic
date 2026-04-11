//! Linux bash command history recovery.
//!
//! Scans bash process heap memory for `HIST_ENTRY` structures to recover
//! command history. Works by finding bash processes, walking their VMAs
//! to locate anonymous RW regions (the heap), then pattern-matching
//! for valid `HIST_ENTRY` structs (24 bytes: line ptr, timestamp ptr, data ptr).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{BashHistoryInfo, Error, Result, VmaFlags};

/// Maximum heap region size to scan (1 MiB safety limit).
const MAX_HEAP_SCAN: u64 = 1024 * 1024;

/// Maximum length for a valid command string.
const MAX_COMMAND_LEN: usize = 4096;

/// Walk all bash processes and recover command history from their heaps.
///
/// Finds processes with `comm == "bash"`, then scans their anonymous
/// RW VMAs for `HIST_ENTRY` patterns — 24-byte structs where the first
/// pointer leads to a printable ASCII string and the second leads to
/// a `#DIGITS` timestamp string.
pub fn walk_bash_history<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<BashHistoryInfo>> {
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

    // Include init_task itself
    scan_process_history(reader, init_task_addr, &mut results);

    for &task_addr in &task_addrs {
        scan_process_history(reader, task_addr, &mut results);
    }

    Ok(results)
}

/// Scan a single process for bash history entries.
fn scan_process_history<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
    out: &mut Vec<BashHistoryInfo>,
) {
    let Ok(comm) = reader.read_field_string(task_addr, "task_struct", "comm", 16) else {
        return;
    };

    if comm != "bash" {
        return;
    }

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

    // Collect VMA ranges for pointer validation
    let mmap_ptr: u64 = match reader.read_field(mm_ptr, "mm_struct", "mmap") {
        Ok(v) => v,
        Err(_) => return,
    };

    let mut vma_ranges: Vec<(u64, u64)> = Vec::new();
    let mut heap_regions: Vec<(u64, u64)> = Vec::new();
    let mut vma_addr = mmap_ptr;

    while vma_addr != 0 {
        let vm_start: u64 = match reader.read_field(vma_addr, "vm_area_struct", "vm_start") {
            Ok(v) => v,
            Err(_) => break,
        };
        let vm_end: u64 = match reader.read_field(vma_addr, "vm_area_struct", "vm_end") {
            Ok(v) => v,
            Err(_) => break,
        };
        let vm_flags: u64 = reader
            .read_field(vma_addr, "vm_area_struct", "vm_flags")
            .unwrap_or(0);
        let vm_file: u64 = reader
            .read_field(vma_addr, "vm_area_struct", "vm_file")
            .unwrap_or(0);

        vma_ranges.push((vm_start, vm_end));

        let flags = VmaFlags::from_raw(vm_flags);
        // Heap candidate: anonymous (vm_file == 0), read+write
        if vm_file == 0 && flags.read && flags.write && !flags.exec {
            heap_regions.push((vm_start, vm_end));
        }

        vma_addr = reader
            .read_field(vma_addr, "vm_area_struct", "vm_next")
            .unwrap_or(0);
    }

    // Scan each heap region for HIST_ENTRY patterns
    let mut index = 0u64;
    for &(start, end) in &heap_regions {
        let size = (end - start).min(MAX_HEAP_SCAN) as usize;
        let Ok(data) = reader.read_bytes(start, size) else {
            continue;
        };

        scan_heap_for_entries(
            reader,
            &data,
            &vma_ranges,
            u64::from(pid),
            &comm,
            &mut index,
            out,
        );
    }
}

/// Scan a heap region for HIST_ENTRY structs.
///
/// HIST_ENTRY layout (24 bytes on 64-bit):
///   offset 0:  char *line      (pointer to command string)
///   offset 8:  char *timestamp (pointer to "#DIGITS" string, or NULL)
///   offset 16: histdata_t *data (usually NULL)
fn scan_heap_for_entries<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    data: &[u8],
    vma_ranges: &[(u64, u64)],
    pid: u64,
    comm: &str,
    index: &mut u64,
    out: &mut Vec<BashHistoryInfo>,
) {
    if data.len() < 24 {
        return;
    }

    // Scan at 8-byte alignment for HIST_ENTRY candidates
    let limit = data.len() - 23;
    let mut off = 0;
    while off < limit {
        let line_ptr = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let ts_ptr = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());

        // Quick reject: line_ptr must be non-zero and within a VMA
        if line_ptr == 0 || !addr_in_vmas(line_ptr, vma_ranges) {
            off += 8;
            continue;
        }

        // ts_ptr must be NULL or within a VMA
        if ts_ptr != 0 && !addr_in_vmas(ts_ptr, vma_ranges) {
            off += 8;
            continue;
        }

        // Try to read the command string
        let Ok(line_str) = reader.read_string(line_ptr, MAX_COMMAND_LEN) else {
            off += 8;
            continue;
        };

        if line_str.is_empty() || !is_printable_ascii(line_str.as_bytes()) {
            off += 8;
            continue;
        }

        // Try to read and parse the timestamp
        let timestamp = if ts_ptr != 0 {
            reader
                .read_string(ts_ptr, 32)
                .ok()
                .and_then(|s| parse_bash_timestamp(&s))
        } else {
            None
        };

        // Validate timestamp pointer actually looks like a bash timestamp
        if ts_ptr != 0 && timestamp.is_none() {
            off += 8;
            continue;
        }

        out.push(BashHistoryInfo {
            pid,
            comm: comm.to_string(),
            command: line_str,
            timestamp,
            index: *index,
        });
        *index += 1;

        // Skip past this HIST_ENTRY (24 bytes)
        off += 24;
    }
}

/// Check whether an address falls within any of the given VMA ranges.
fn addr_in_vmas(addr: u64, ranges: &[(u64, u64)]) -> bool {
    ranges
        .iter()
        .any(|&(start, end)| addr >= start && addr < end)
}

/// Check whether a byte sequence is printable ASCII (no control chars except tab).
fn is_printable_ascii(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|&b| b == b'\t' || (0x20..=0x7E).contains(&b))
}

/// Parse a bash timestamp string (`#1700000000`) into a Unix timestamp.
fn parse_bash_timestamp(s: &str) -> Option<i64> {
    let digits = s.strip_prefix('#')?;
    if digits.is_empty() {
        return None;
    }
    digits.parse::<i64>().ok()
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

    /// Build a synthetic heap page containing HIST_ENTRY structs and strings.
    ///
    /// Layout at `heap_vaddr`:
    ///   0x000: "ls -la\0"
    ///   0x010: "#1700000000\0"
    ///   0x020: "whoami\0"
    ///   0x030: "#1700000001\0"
    ///   0x040: "cat /etc/shadow\0"
    ///   0x050: "#1700000002\0"
    ///   0x100: HIST_ENTRY[0] { line=heap+0, ts=heap+0x10, data=0 }
    ///   0x118: HIST_ENTRY[1] { line=heap+0x20, ts=heap+0x30, data=0 }
    ///   0x130: HIST_ENTRY[2] { line=heap+0x40, ts=heap+0x50, data=0 }
    fn build_heap_with_history(heap_vaddr: u64) -> Vec<u8> {
        let mut heap = vec![0u8; 4096];

        // String pool
        let strings: &[(&[u8], usize)] = &[
            (b"ls -la\0", 0x000),
            (b"#1700000000\0", 0x010),
            (b"whoami\0", 0x020),
            (b"#1700000001\0", 0x030),
            (b"cat /etc/shadow\0", 0x040),
            (b"#1700000002\0", 0x050),
        ];
        for &(s, off) in strings {
            heap[off..off + s.len()].copy_from_slice(s);
        }

        // HIST_ENTRY structs (24 bytes each: line ptr, timestamp ptr, data ptr)
        let entries: &[(u64, u64)] = &[
            (heap_vaddr + 0x000, heap_vaddr + 0x010), // ls -la
            (heap_vaddr + 0x020, heap_vaddr + 0x030), // whoami
            (heap_vaddr + 0x040, heap_vaddr + 0x050), // cat /etc/shadow
        ];
        let mut off = 0x100;
        for &(line_ptr, ts_ptr) in entries {
            heap[off..off + 8].copy_from_slice(&line_ptr.to_le_bytes());
            heap[off + 8..off + 16].copy_from_slice(&ts_ptr.to_le_bytes());
            heap[off + 16..off + 24].copy_from_slice(&0u64.to_le_bytes()); // data = NULL
            off += 24;
        }

        heap
    }

    #[test]
    fn recovers_bash_history_from_heap() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task (PID 42, comm "bash")
        data[0..4].copy_from_slice(&42u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes()); // tasks.next = self
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes()); // tasks.prev = self
        data[32..36].copy_from_slice(b"bash");
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes()); // mm

        // mm_struct at +0x200
        data[0x200..0x208].copy_from_slice(&0x1000u64.to_le_bytes()); // pgd
        let vma_addr = vaddr + 0x300;
        data[0x208..0x210].copy_from_slice(&vma_addr.to_le_bytes()); // mmap

        // VMA: anonymous RW heap region in userspace
        let heap_vaddr: u64 = 0x0000_5555_0000_0000;
        let heap_paddr: u64 = 0x0090_0000;
        data[0x300..0x308].copy_from_slice(&heap_vaddr.to_le_bytes()); // vm_start
        data[0x308..0x310].copy_from_slice(&(heap_vaddr + 0x1000).to_le_bytes()); // vm_end
        data[0x310..0x318].copy_from_slice(&0u64.to_le_bytes()); // vm_next = NULL
        data[0x318..0x320].copy_from_slice(&0x3u64.to_le_bytes()); // vm_flags: rw-
        data[0x320..0x328].copy_from_slice(&0u64.to_le_bytes()); // vm_pgoff
        data[0x328..0x330].copy_from_slice(&0u64.to_le_bytes()); // vm_file = NULL (anon)

        let heap = build_heap_with_history(heap_vaddr);

        let reader = make_test_reader(&data, vaddr, paddr, &[(heap_vaddr, heap_paddr, &heap)]);
        let results = walk_bash_history(&reader).unwrap();

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].pid, 42);
        assert_eq!(results[0].comm, "bash");
        assert_eq!(results[0].command, "ls -la");
        assert_eq!(results[0].timestamp, Some(1_700_000_000));
        assert_eq!(results[1].command, "whoami");
        assert_eq!(results[1].timestamp, Some(1_700_000_001));
        assert_eq!(results[2].command, "cat /etc/shadow");
        assert_eq!(results[2].timestamp, Some(1_700_000_002));
    }

    #[test]
    fn skips_non_bash_processes() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task (PID 1, comm "nginx") — not bash
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..37].copy_from_slice(b"nginx");
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());

        data[0x200..0x208].copy_from_slice(&0x1000u64.to_le_bytes());
        data[0x208..0x210].copy_from_slice(&0u64.to_le_bytes()); // mmap = NULL

        let reader = make_test_reader(&data, vaddr, paddr, &[]);
        let results = walk_bash_history(&reader).unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn skips_kernel_threads() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // comm is "bash" but mm = NULL (kernel thread)
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..36].copy_from_slice(b"bash");
        data[48..56].copy_from_slice(&0u64.to_le_bytes()); // mm = NULL

        let reader = make_test_reader(&data, vaddr, paddr, &[]);
        let results = walk_bash_history(&reader).unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn is_printable_ascii_validates() {
        assert!(is_printable_ascii(b"hello world"));
        assert!(is_printable_ascii(b"ls -la /etc"));
        assert!(is_printable_ascii(b"echo\t\"test\""));
        assert!(!is_printable_ascii(b"")); // empty
        assert!(!is_printable_ascii(b"\x01\x02")); // control chars
        assert!(!is_printable_ascii(b"hello\x00world")); // embedded null
    }

    #[test]
    fn parse_bash_timestamp_valid() {
        assert_eq!(parse_bash_timestamp("#1700000000"), Some(1_700_000_000));
        assert_eq!(parse_bash_timestamp("#0"), Some(0));
        assert_eq!(parse_bash_timestamp("#999999999999"), Some(999_999_999_999));
    }

    #[test]
    fn parse_bash_timestamp_invalid() {
        assert_eq!(parse_bash_timestamp("1700000000"), None); // missing #
        assert_eq!(parse_bash_timestamp("#abc"), None); // not digits
        assert_eq!(parse_bash_timestamp("#"), None); // just hash
        assert_eq!(parse_bash_timestamp(""), None); // empty
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

        let result = walk_bash_history(&reader);
        assert!(result.is_err());
    }
}
