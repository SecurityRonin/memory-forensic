//! SSH key extraction from sshd process memory.
//!
//! Scans sshd process heap and mapped memory for SSH public key material
//! (e.g. `ssh-rsa`, `ssh-ed25519`). During incident response this reveals
//! lateral movement paths and compromised credentials by recovering keys
//! that were present in the SSH daemon's address space at the time of
//! the memory capture.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, Result, SshKeyInfo, SshKeyType, VmaFlags};

/// SSH key type prefixes to scan for.
const SSH_KEY_PREFIXES: &[(&str, SshKeyType)] = &[
    ("ssh-rsa ", SshKeyType::Rsa),
    ("ssh-ed25519 ", SshKeyType::Ed25519),
    ("ssh-dss ", SshKeyType::Dsa),
    ("ecdsa-sha2-nistp256 ", SshKeyType::Ecdsa256),
    ("ecdsa-sha2-nistp384 ", SshKeyType::Ecdsa384),
    ("ecdsa-sha2-nistp521 ", SshKeyType::Ecdsa521),
];

/// Maximum key line length (bytes) before we stop reading.
const MAX_KEY_LINE: usize = 8192;

/// Maximum VMA region size to scan (16 MiB safety limit).
const MAX_VMA_SCAN: u64 = 16 * 1024 * 1024;

/// Extract SSH public keys from sshd process memory.
///
/// Walks the process list to find `sshd` processes, then scans their
/// readable VMAs for SSH key prefix strings. When a prefix is found,
/// extracts the full key line (up to newline/null, max 8 KiB) and
/// parses the key type, base64 data, and optional comment.
///
/// Results are deduplicated by `(pid, key_data)`.
pub fn extract_ssh_keys<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<SshKeyInfo>> {
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
    let mut seen = std::collections::HashSet::new();

    // Scan init_task itself
    scan_sshd_keys(reader, init_task_addr, &mut results, &mut seen);

    for &task_addr in &task_addrs {
        scan_sshd_keys(reader, task_addr, &mut results, &mut seen);
    }

    Ok(results)
}

/// Check if a task is sshd and, if so, scan its VMAs for SSH keys.
fn scan_sshd_keys<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
    results: &mut Vec<SshKeyInfo>,
    seen: &mut std::collections::HashSet<(u64, String)>,
) {
    let pid: u32 = match reader.read_field(task_addr, "task_struct", "pid") {
        Ok(v) => v,
        Err(_) => return,
    };
    let Ok(comm) = reader.read_field_string(task_addr, "task_struct", "comm", 16) else {
        return;
    };

    if comm != "sshd" {
        return;
    }

    let mm_ptr: u64 = match reader.read_field(task_addr, "task_struct", "mm") {
        Ok(v) => v,
        Err(_) => return,
    };
    if mm_ptr == 0 {
        return; // kernel thread
    }

    let mmap_ptr: u64 = match reader.read_field(mm_ptr, "mm_struct", "mmap") {
        Ok(v) => v,
        Err(_) => return,
    };

    // Walk VMAs
    let mut vma_addr = mmap_ptr;
    let mut vma_count = 0u32;
    while vma_addr != 0 && vma_count < 4096 {
        vma_count += 1;

        let vm_start: u64 = match reader.read_field(vma_addr, "vm_area_struct", "vm_start") {
            Ok(v) => v,
            Err(_) => break,
        };
        let vm_end: u64 = match reader.read_field(vma_addr, "vm_area_struct", "vm_end") {
            Ok(v) => v,
            Err(_) => break,
        };
        let vm_flags: u64 = match reader.read_field(vma_addr, "vm_area_struct", "vm_flags") {
            Ok(v) => v,
            Err(_) => break,
        };

        let flags = VmaFlags::from_raw(vm_flags);
        let size = vm_end.saturating_sub(vm_start);

        // Only scan readable regions within size limit
        if flags.read && size > 0 && size <= MAX_VMA_SCAN {
            scan_region_for_keys(reader, u64::from(pid), vm_start, size, results, seen);
        }

        // Follow vm_next
        vma_addr = match reader.read_field(vma_addr, "vm_area_struct", "vm_next") {
            Ok(v) => v,
            Err(_) => break,
        };
    }
}

/// Scan a memory region for SSH key prefixes.
fn scan_region_for_keys<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    pid: u64,
    start: u64,
    size: u64,
    results: &mut Vec<SshKeyInfo>,
    seen: &mut std::collections::HashSet<(u64, String)>,
) {
    let Ok(buf) = reader.read_bytes(start, size as usize) else {
        return;
    };

    for &(prefix, _key_type) in SSH_KEY_PREFIXES {
        let prefix_bytes = prefix.as_bytes();
        // Scan for all occurrences of this prefix in the buffer
        let mut search_from = 0;
        while search_from + prefix_bytes.len() <= buf.len() {
            let haystack = &buf[search_from..];
            let Some(pos) = find_bytes(haystack, prefix_bytes) else {
                break;
            };

            let abs_pos = search_from + pos;

            // Extract key line: from prefix position to newline/null/end, max MAX_KEY_LINE
            let line_start = abs_pos;
            let max_end = buf.len().min(line_start + MAX_KEY_LINE);
            let line_end = buf[line_start..max_end]
                .iter()
                .position(|&b| b == b'\n' || b == b'\0' || b == b'\r')
                .map_or(max_end, |p| line_start + p);

            let line_bytes = &buf[line_start..line_end];
            if let Ok(line_str) = std::str::from_utf8(line_bytes) {
                if let Some((key_type, key_data, comment)) = parse_key_line(line_str) {
                    let dedup_key = (pid, key_data.clone());
                    if seen.insert(dedup_key) {
                        results.push(SshKeyInfo {
                            pid,
                            key_type,
                            key_data,
                            comment,
                        });
                    }
                }
            }

            // Advance past this match
            search_from = abs_pos + prefix_bytes.len();
        }
    }
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// Parse a key line into `(key_type, full_key_data, comment)`.
///
/// The key line format is: `<type> <base64> [comment]`
fn parse_key_line(line: &str) -> Option<(SshKeyType, String, String)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Find the type prefix
    let space_idx = trimmed.find(' ')?;
    let type_str = &trimmed[..space_idx];
    let key_type = SshKeyType::from_prefix(type_str);
    if key_type == SshKeyType::Unknown {
        return None;
    }

    let rest = &trimmed[space_idx + 1..];

    // Split on the next space to get base64 and optional comment
    let (base64_data, comment) = match rest.find(' ') {
        Some(idx) => (&rest[..idx], rest[idx + 1..].trim()),
        None => (rest, ""),
    };

    // Sanity: base64 data should be non-empty and look like base64
    if base64_data.is_empty() {
        return None;
    }

    let full_key = format!("{type_str} {base64_data}");
    Some((key_type, full_key, comment.to_string()))
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
    fn ssh_key_type_from_prefix() {
        assert_eq!(SshKeyType::from_prefix("ssh-rsa"), SshKeyType::Rsa);
        assert_eq!(SshKeyType::from_prefix("ssh-ed25519"), SshKeyType::Ed25519);
        assert_eq!(SshKeyType::from_prefix("ssh-dss"), SshKeyType::Dsa);
        assert_eq!(
            SshKeyType::from_prefix("ecdsa-sha2-nistp256"),
            SshKeyType::Ecdsa256
        );
        assert_eq!(
            SshKeyType::from_prefix("ecdsa-sha2-nistp384"),
            SshKeyType::Ecdsa384
        );
        assert_eq!(
            SshKeyType::from_prefix("ecdsa-sha2-nistp521"),
            SshKeyType::Ecdsa521
        );
        assert_eq!(SshKeyType::from_prefix("bogus"), SshKeyType::Unknown);
        assert_eq!(SshKeyType::from_prefix(""), SshKeyType::Unknown);
    }

    #[test]
    fn ssh_key_type_display() {
        assert_eq!(SshKeyType::Rsa.to_string(), "ssh-rsa");
        assert_eq!(SshKeyType::Ed25519.to_string(), "ssh-ed25519");
        assert_eq!(SshKeyType::Dsa.to_string(), "ssh-dss");
        assert_eq!(SshKeyType::Ecdsa256.to_string(), "ecdsa-sha2-nistp256");
        assert_eq!(SshKeyType::Ecdsa384.to_string(), "ecdsa-sha2-nistp384");
        assert_eq!(SshKeyType::Ecdsa521.to_string(), "ecdsa-sha2-nistp521");
        assert_eq!(SshKeyType::Unknown.to_string(), "unknown");
    }

    #[test]
    fn extract_ssh_keys_no_sshd() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task (PID 1, comm "systemd") — not sshd
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes()); // tasks.next → self
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes()); // tasks.prev → self
        data[32..39].copy_from_slice(b"systemd");
        data[48..56].copy_from_slice(&0u64.to_le_bytes()); // mm = NULL

        let reader = make_test_reader(&data, vaddr, paddr, &[]);
        let results = extract_ssh_keys(&reader).unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn extracts_ed25519_key_from_sshd_heap() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task (PID 22, comm "sshd")
        data[0..4].copy_from_slice(&22u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..36].copy_from_slice(b"sshd");
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());

        // mm_struct at +0x200
        data[0x200..0x208].copy_from_slice(&0x1000u64.to_le_bytes()); // pgd
        let vma_addr = vaddr + 0x300;
        data[0x208..0x210].copy_from_slice(&vma_addr.to_le_bytes()); // mmap

        // VMA: readable anonymous region
        let heap_vaddr: u64 = 0x0000_5555_0000_0000;
        let heap_paddr: u64 = 0x0090_0000;
        data[0x300..0x308].copy_from_slice(&heap_vaddr.to_le_bytes()); // vm_start
        data[0x308..0x310].copy_from_slice(&(heap_vaddr + 0x1000).to_le_bytes()); // vm_end
        data[0x310..0x318].copy_from_slice(&0u64.to_le_bytes()); // vm_next = NULL
        data[0x318..0x320].copy_from_slice(&0x3u64.to_le_bytes()); // vm_flags: rw-
        data[0x320..0x328].copy_from_slice(&0u64.to_le_bytes()); // vm_pgoff
        data[0x328..0x330].copy_from_slice(&0u64.to_le_bytes()); // vm_file = NULL

        // Heap page with an ed25519 key
        let mut heap = vec![0u8; 4096];
        let key_line = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBzBZ user@host\0";
        heap[0x100..0x100 + key_line.len()].copy_from_slice(key_line);

        let reader = make_test_reader(&data, vaddr, paddr, &[(heap_vaddr, heap_paddr, &heap)]);
        let results = extract_ssh_keys(&reader).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pid, 22);
        assert_eq!(results[0].key_type, SshKeyType::Ed25519);
        assert_eq!(
            results[0].key_data,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBzBZ"
        );
        assert_eq!(results[0].comment, "user@host");
    }

    #[test]
    fn extracts_rsa_key_without_comment() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task (PID 99, comm "sshd")
        data[0..4].copy_from_slice(&99u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..36].copy_from_slice(b"sshd");
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());

        // mm_struct at +0x200
        data[0x200..0x208].copy_from_slice(&0x1000u64.to_le_bytes());
        let vma_addr = vaddr + 0x300;
        data[0x208..0x210].copy_from_slice(&vma_addr.to_le_bytes());

        // VMA: readable region
        let heap_vaddr: u64 = 0x0000_5555_0000_0000;
        let heap_paddr: u64 = 0x0090_0000;
        data[0x300..0x308].copy_from_slice(&heap_vaddr.to_le_bytes());
        data[0x308..0x310].copy_from_slice(&(heap_vaddr + 0x1000).to_le_bytes());
        data[0x310..0x318].copy_from_slice(&0u64.to_le_bytes());
        data[0x318..0x320].copy_from_slice(&0x1u64.to_le_bytes()); // vm_flags: r--
        data[0x320..0x328].copy_from_slice(&0u64.to_le_bytes());
        data[0x328..0x330].copy_from_slice(&0u64.to_le_bytes());

        // Heap page with an RSA key (no comment)
        let mut heap = vec![0u8; 4096];
        let key_line = b"ssh-rsa AAAAB3NzaC1yc2EAAA\n";
        heap[0x200..0x200 + key_line.len()].copy_from_slice(key_line);

        let reader = make_test_reader(&data, vaddr, paddr, &[(heap_vaddr, heap_paddr, &heap)]);
        let results = extract_ssh_keys(&reader).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pid, 99);
        assert_eq!(results[0].key_type, SshKeyType::Rsa);
        assert_eq!(results[0].key_data, "ssh-rsa AAAAB3NzaC1yc2EAAA");
        assert!(results[0].comment.is_empty());
    }

    #[test]
    fn deduplicates_identical_keys() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task (PID 10, comm "sshd")
        data[0..4].copy_from_slice(&10u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..36].copy_from_slice(b"sshd");
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());

        // mm_struct at +0x200
        data[0x200..0x208].copy_from_slice(&0x1000u64.to_le_bytes());
        let vma_addr = vaddr + 0x300;
        data[0x208..0x210].copy_from_slice(&vma_addr.to_le_bytes());

        // VMA: single readable region
        let heap_vaddr: u64 = 0x0000_5555_0000_0000;
        let heap_paddr: u64 = 0x0090_0000;
        data[0x300..0x308].copy_from_slice(&heap_vaddr.to_le_bytes());
        data[0x308..0x310].copy_from_slice(&(heap_vaddr + 0x1000).to_le_bytes());
        data[0x310..0x318].copy_from_slice(&0u64.to_le_bytes());
        data[0x318..0x320].copy_from_slice(&0x1u64.to_le_bytes()); // r--
        data[0x320..0x328].copy_from_slice(&0u64.to_le_bytes());
        data[0x328..0x330].copy_from_slice(&0u64.to_le_bytes());

        // Same key appears twice in the heap
        let mut heap = vec![0u8; 4096];
        let key_line = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA root@server\0";
        heap[0x100..0x100 + key_line.len()].copy_from_slice(key_line);
        heap[0x300..0x300 + key_line.len()].copy_from_slice(key_line);

        let reader = make_test_reader(&data, vaddr, paddr, &[(heap_vaddr, heap_paddr, &heap)]);
        let results = extract_ssh_keys(&reader).unwrap();

        assert_eq!(results.len(), 1, "duplicate keys should be deduplicated");
    }

    #[test]
    fn parse_key_line_ed25519_with_comment() {
        let (kt, kd, comment) =
            parse_key_line("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBzBZ user@host").unwrap();
        assert_eq!(kt, SshKeyType::Ed25519);
        assert_eq!(kd, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBzBZ");
        assert_eq!(comment, "user@host");
    }

    #[test]
    fn parse_key_line_rsa_no_comment() {
        let (kt, kd, comment) = parse_key_line("ssh-rsa AAAAB3NzaC1yc2EAAA").unwrap();
        assert_eq!(kt, SshKeyType::Rsa);
        assert_eq!(kd, "ssh-rsa AAAAB3NzaC1yc2EAAA");
        assert!(comment.is_empty());
    }

    #[test]
    fn parse_key_line_invalid() {
        assert!(parse_key_line("").is_none());
        assert!(parse_key_line("not-a-key AAAA").is_none());
        assert!(parse_key_line("ssh-rsa").is_none()); // no base64 data
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

        let result = extract_ssh_keys(&reader);
        assert!(result.is_err());
    }
}
