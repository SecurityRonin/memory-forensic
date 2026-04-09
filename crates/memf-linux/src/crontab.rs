//! Linux crontab entry recovery from cron process memory.
//!
//! Scans memory regions of cron-related processes (cron, crond, anacron, atd)
//! for lines matching crontab format: five time fields followed by a command.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{CrontabEntry, Error, Result, VmaFlags};

/// Cron-related process names to scan.
const CRON_PROCS: &[&str] = &["cron", "crond", "anacron", "atd"];

/// Maximum readable region size to scan (4 MiB safety limit).
const MAX_REGION_SCAN: u64 = 4 * 1024 * 1024;

/// Walk all cron-related processes and recover crontab entries from memory.
///
/// Finds processes with `comm` matching known cron daemon names, then scans
/// their readable anonymous VMAs for lines matching crontab format (five
/// time fields followed by a command).
pub fn walk_crontab_entries<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<CrontabEntry>> {
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
    scan_process_crontab(reader, init_task_addr, &mut results);

    for &task_addr in &task_addrs {
        scan_process_crontab(reader, task_addr, &mut results);
    }

    Ok(results)
}

/// Scan a single process for crontab entries in its memory.
fn scan_process_crontab<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
    out: &mut Vec<CrontabEntry>,
) {
    let Ok(comm) = reader.read_field_string(task_addr, "task_struct", "comm", 16) else {
        return;
    };

    if !CRON_PROCS.iter().any(|name| comm == *name) {
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

    // Walk VMAs via the mmap linked list
    let mmap_ptr: u64 = match reader.read_field(mm_ptr, "mm_struct", "mmap") {
        Ok(v) => v,
        Err(_) => return,
    };

    let mut readable_regions: Vec<(u64, u64)> = Vec::new();
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

        let flags = VmaFlags::from_raw(vm_flags);
        if flags.read {
            readable_regions.push((vm_start, vm_end));
        }

        vma_addr = reader
            .read_field(vma_addr, "vm_area_struct", "vm_next")
            .unwrap_or(0);
    }

    // Scan each readable region for crontab-format lines
    for &(start, end) in &readable_regions {
        let size = end.saturating_sub(start);
        if size == 0 || size > MAX_REGION_SCAN {
            continue;
        }
        let Ok(data) = reader.read_bytes(start, size as usize) else {
            continue;
        };
        // Split on null bytes to handle C-string boundaries in heap memory,
        // then scan each segment for crontab lines.
        for chunk in data.split(|&b| b == 0) {
            if chunk.is_empty() {
                continue;
            }
            let text = String::from_utf8_lossy(chunk);
            for line in text.lines() {
                let trimmed = line.trim();
                if is_crontab_line(trimmed) {
                    out.push(CrontabEntry {
                        pid: u64::from(pid),
                        comm: comm.clone(),
                        line: trimmed.to_string(),
                    });
                }
            }
        }
    }
}

/// Check if a string looks like a crontab entry.
///
/// Matches: five whitespace-separated time fields (digits, `*`, `/`, `-`, comma)
/// followed by at least one command character.
fn is_crontab_line(line: &str) -> bool {
    // Skip empty, comments, variable assignments
    if line.is_empty() || line.starts_with('#') {
        return false;
    }
    // Bare variable assignments like PATH=/usr/bin (no spaces before '=')
    if let Some(eq_pos) = line.find('=') {
        if !line[..eq_pos].contains(' ') {
            return false;
        }
    }

    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 6 {
        return false;
    }

    // First 5 fields must be valid cron time fields
    for field in &parts[..5] {
        if !is_cron_time_field(field) {
            return false;
        }
    }

    // 6th field (command) must start with / or a letter
    let cmd = parts[5];
    cmd.starts_with('/')
        || cmd
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
}

/// Check if a string is a valid cron time field.
///
/// Valid characters: digits, `*`, `/`, `-`, `,`.
fn is_cron_time_field(field: &str) -> bool {
    if field == "*" {
        return true;
    }
    !field.is_empty()
        && field
            .chars()
            .all(|c| c.is_ascii_digit() || c == '*' || c == '/' || c == '-' || c == ',')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_crontab_line_valid() {
        assert!(is_crontab_line("0 * * * * /usr/bin/backup.sh"));
        assert!(is_crontab_line("*/5 * * * * curl http://example.com"));
        assert!(is_crontab_line("0 0 1 * * /bin/monthly_report"));
        assert!(is_crontab_line("30 2 * * 1-5 /opt/weekday_job"));
    }

    #[test]
    fn is_crontab_line_invalid() {
        assert!(!is_crontab_line(""));
        assert!(!is_crontab_line("# This is a comment"));
        assert!(!is_crontab_line("PATH=/usr/bin"));
        assert!(!is_crontab_line("hello world"));
        assert!(!is_crontab_line("abc def ghi jkl mno pqr")); // non-cron fields
    }

    #[test]
    fn is_cron_time_field_valid() {
        assert!(is_cron_time_field("*"));
        assert!(is_cron_time_field("0"));
        assert!(is_cron_time_field("*/5"));
        assert!(is_cron_time_field("1-5"));
        assert!(is_cron_time_field("0,15,30,45"));
    }

    #[test]
    fn is_cron_time_field_invalid() {
        assert!(!is_cron_time_field(""));
        assert!(!is_cron_time_field("abc"));
        assert!(!is_cron_time_field("hello"));
    }

    // --- Integration test with synthetic memory ---

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

    /// Build a synthetic heap page containing crontab entries as text.
    fn build_heap_with_crontab(entries: &[&str]) -> Vec<u8> {
        let mut heap = vec![0u8; 4096];
        let text = entries.join("\n");
        let bytes = text.as_bytes();
        let len = bytes.len().min(4096);
        heap[..len].copy_from_slice(&bytes[..len]);
        heap
    }

    #[test]
    fn recovers_crontab_from_crond_heap() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task (PID 100, comm "crond")
        data[0..4].copy_from_slice(&100u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes()); // tasks.next = self
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes()); // tasks.prev = self
        data[32..37].copy_from_slice(b"crond");
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes()); // mm

        // mm_struct at +0x200
        data[0x200..0x208].copy_from_slice(&0x1000u64.to_le_bytes()); // pgd
        let vma_addr = vaddr + 0x300;
        data[0x208..0x210].copy_from_slice(&vma_addr.to_le_bytes()); // mmap

        // VMA: readable region in userspace
        let heap_vaddr: u64 = 0x0000_5555_0000_0000;
        let heap_paddr: u64 = 0x0090_0000;
        data[0x300..0x308].copy_from_slice(&heap_vaddr.to_le_bytes()); // vm_start
        data[0x308..0x310].copy_from_slice(&(heap_vaddr + 0x1000).to_le_bytes()); // vm_end
        data[0x310..0x318].copy_from_slice(&0u64.to_le_bytes()); // vm_next = NULL
        data[0x318..0x320].copy_from_slice(&0x1u64.to_le_bytes()); // vm_flags: read
        data[0x320..0x328].copy_from_slice(&0u64.to_le_bytes()); // vm_pgoff
        data[0x328..0x330].copy_from_slice(&0u64.to_le_bytes()); // vm_file = NULL

        let heap = build_heap_with_crontab(&[
            "0 * * * * /usr/bin/backup.sh",
            "*/5 * * * * curl http://example.com",
            "# this is a comment",
            "30 2 * * 1-5 /opt/weekday_job",
        ]);

        let reader = make_test_reader(&data, vaddr, paddr, &[(heap_vaddr, heap_paddr, &heap)]);
        let results = walk_crontab_entries(&reader).unwrap();

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].pid, 100);
        assert_eq!(results[0].comm, "crond");
        assert_eq!(results[0].line, "0 * * * * /usr/bin/backup.sh");
        assert_eq!(results[1].line, "*/5 * * * * curl http://example.com");
        assert_eq!(results[2].line, "30 2 * * 1-5 /opt/weekday_job");
    }

    #[test]
    fn skips_non_cron_processes() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task (PID 1, comm "nginx") — not a cron process
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
        let results = walk_crontab_entries(&reader).unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn skips_kernel_threads() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // comm is "cron" but mm = NULL (kernel thread)
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..36].copy_from_slice(b"cron");
        data[48..56].copy_from_slice(&0u64.to_le_bytes()); // mm = NULL

        let reader = make_test_reader(&data, vaddr, paddr, &[]);
        let results = walk_crontab_entries(&reader).unwrap();

        assert!(results.is_empty());
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

        let result = walk_crontab_entries(&reader);
        assert!(result.is_err());
    }

    #[test]
    fn recognizes_all_cron_daemon_names() {
        // Verify CRON_PROCS contains expected entries
        assert!(CRON_PROCS.contains(&"cron"));
        assert!(CRON_PROCS.contains(&"crond"));
        assert!(CRON_PROCS.contains(&"anacron"));
        assert!(CRON_PROCS.contains(&"atd"));
        assert!(!CRON_PROCS.contains(&"bash"));
    }
}
