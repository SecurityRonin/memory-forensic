//! Detect fileless payloads loaded via `memfd_create(2)`.
//!
//! `memfd_create` creates an anonymous file living only in RAM. Malware uses
//! this to load shellcode or staged payloads without touching disk. The file
//! descriptor appears in the process's open-fd table with a dentry name of
//! `memfd:<name>` (e.g. `memfd:payload`).
//!
//! MITRE ATT&CK: T1055.009 — Process Injection: Process Hollowing (via anonymous memory).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use serde::Serialize;

use crate::Result;

/// VM flag bit: region is executable.
const VM_EXEC: u64 = 0x4;

/// Known-benign memfd name prefixes produced by legitimate system components.
const BENIGN_MEMFD_PREFIXES: &[&str] = &[
    "shm",
    "pulseaudio",
    "wayland",
    "dbus",
    "chrome",
    "firefox",
    "v8",
];

/// Suspicious memfd name substrings (case-insensitive).
const SUSPICIOUS_NAMES: &[&str] = &["payload", "shellcode", "stage", "loader", "inject", "hack"];

/// Information about an open `memfd_create` file descriptor.
#[derive(Debug, Clone, Serialize)]
pub struct MemfdInfo {
    /// Process ID.
    pub pid: u32,
    /// Process command name (`task_struct.comm`, max 16 chars).
    pub comm: String,
    /// Name given to `memfd_create`, e.g. `"payload"` (without the `memfd:` prefix).
    pub memfd_name: String,
    /// Total byte size of all VMAs backed by this memfd.
    pub size_bytes: u64,
    /// Whether any VMA backed by this memfd is mapped executable (`PROT_EXEC`).
    pub is_executable: bool,
    /// Whether this memfd is considered suspicious.
    pub is_suspicious: bool,
}

/// Classify whether a memfd mapping is suspicious.
///
/// Returns `true` (suspicious) if any of:
/// - `is_executable` — executable anonymous memory implies injected code.
/// - `name` contains a known-malicious substring (`payload`, `shellcode`, …).
/// - `name` is empty — anonymous memfd with no name is an evasion technique.
///
/// Returns `false` (benign) if `name` starts with a known-benign prefix.
pub fn classify_memfd(name: &str, is_executable: bool) -> bool {
    // Executable anonymous memory is always suspicious.
    if is_executable {
        return true;
    }

    let name_lower = name.to_lowercase();

    // Known-benign prefixes override everything else.
    for prefix in BENIGN_MEMFD_PREFIXES {
        if name_lower.starts_with(prefix) {
            return false;
        }
    }

    // Empty name → evasion attempt.
    if name.is_empty() {
        return true;
    }

    // Suspicious substrings.
    for s in SUSPICIOUS_NAMES {
        if name_lower.contains(s) {
            return true;
        }
    }

    false
}

/// Walk the task list and collect information about open `memfd_create` file descriptors.
///
/// For each process, walks `mm_struct.mmap` (the VMA chain). For every VMA
/// that is file-backed, the dentry name is read; if it starts with `"memfd:"`
/// the mapping is recorded.
///
/// Gracefully returns `Ok(vec![])` if any required kernel symbol is absent,
/// so callers on unexpected kernel versions are not broken.
pub fn walk_memfd_create<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<MemfdInfo>> {
    // --- symbol resolution (graceful degradation) ---
    let init_task_addr = match reader.symbols().symbol_address("init_task") {
        Some(a) => a,
        None => return Ok(vec![]),
    };
    let tasks_offset = match reader.symbols().field_offset("task_struct", "tasks") {
        Some(o) => o,
        None => return Ok(vec![]),
    };

    let head_vaddr = init_task_addr + tasks_offset;
    let task_addrs = reader.walk_list(head_vaddr, "task_struct", "tasks")?;

    let mut results: Vec<MemfdInfo> = Vec::new();

    collect_memfd_for_task(reader, init_task_addr, &mut results);
    for &task_addr in &task_addrs {
        collect_memfd_for_task(reader, task_addr, &mut results);
    }

    results.sort_by_key(|r| r.pid);
    Ok(results)
}

/// Collect all memfd VMAs for a single task.
fn collect_memfd_for_task<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
    out: &mut Vec<MemfdInfo>,
) {
    let pid: u32 = match reader.read_field(task_addr, "task_struct", "pid") {
        Ok(v) => v,
        Err(_) => return,
    };
    let comm = reader
        .read_field_string(task_addr, "task_struct", "comm", 16)
        .unwrap_or_default();

    // Kernel threads have mm == NULL.
    let mm_ptr: u64 = match reader.read_field(task_addr, "task_struct", "mm") {
        Ok(v) => v,
        Err(_) => return,
    };
    if mm_ptr == 0 {
        return;
    }

    // Walk the VMA list via mm_struct.mmap.
    let mmap_ptr: u64 = match reader.read_field(mm_ptr, "mm_struct", "mmap") {
        Ok(v) => v,
        Err(_) => return,
    };

    let mut vma_addr = mmap_ptr;
    while vma_addr != 0 {
        if let Some(info) = try_read_memfd_vma(reader, pid, &comm, vma_addr) {
            // Merge with existing entry for same (pid, memfd_name) if present.
            let existing = out
                .iter_mut()
                .find(|e| e.pid == info.pid && e.memfd_name == info.memfd_name);
            if let Some(e) = existing {
                e.size_bytes += info.size_bytes;
                e.is_executable |= info.is_executable;
                e.is_suspicious = classify_memfd(&e.memfd_name, e.is_executable);
            } else {
                out.push(info);
            }
        }

        // Advance via vm_area_struct.vm_next.
        vma_addr = match reader.read_field(vma_addr, "vm_area_struct", "vm_next") {
            Ok(v) => v,
            Err(_) => break,
        };
    }
}

/// Attempt to read memfd information from a single VMA.
///
/// Returns `None` if the VMA is not a memfd mapping or fields cannot be read.
fn try_read_memfd_vma<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    pid: u32,
    comm: &str,
    vma_addr: u64,
) -> Option<MemfdInfo> {
    // vm_file pointer — NULL means anonymous (not memfd-named).
    let vm_file_ptr: u64 = reader
        .read_field(vma_addr, "vm_area_struct", "vm_file")
        .ok()?;
    if vm_file_ptr == 0 {
        return None;
    }

    // Read dentry name via file->f_path.dentry->d_name.name.
    let dentry_name = read_file_dentry_name(reader, vm_file_ptr)?;

    // memfd dentries are named "memfd:<user-name>".
    let memfd_name = dentry_name.strip_prefix("memfd:")?;

    let vm_start: u64 = reader
        .read_field(vma_addr, "vm_area_struct", "vm_start")
        .ok()?;
    let vm_end: u64 = reader
        .read_field(vma_addr, "vm_area_struct", "vm_end")
        .ok()?;
    let vm_flags: u64 = reader
        .read_field(vma_addr, "vm_area_struct", "vm_flags")
        .ok()?;

    let size_bytes = vm_end.saturating_sub(vm_start);
    let is_executable = (vm_flags & VM_EXEC) != 0;
    let is_suspicious = classify_memfd(memfd_name, is_executable);

    Some(MemfdInfo {
        pid,
        comm: comm.to_string(),
        memfd_name: memfd_name.to_string(),
        size_bytes,
        is_executable,
        is_suspicious,
    })
}

/// Read the dentry name from a `struct file` pointer via `f_path.dentry->d_name`.
fn read_file_dentry_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    file_ptr: u64,
) -> Option<String> {
    let f_path_offset = reader.symbols().field_offset("file", "f_path")?;
    let dentry_in_path = reader.symbols().field_offset("path", "dentry")?;
    let d_name_offset = reader.symbols().field_offset("dentry", "d_name")?;
    let name_in_qstr = reader.symbols().field_offset("qstr", "name")?;

    let dentry_addr = file_ptr + f_path_offset + dentry_in_path;
    let dentry_raw = reader.read_bytes(dentry_addr, 8).ok()?;
    let dentry_ptr = u64::from_le_bytes(dentry_raw.try_into().ok()?);
    if dentry_ptr == 0 {
        return None;
    }

    let name_addr = dentry_ptr + d_name_offset + name_in_qstr;
    let name_raw = reader.read_bytes(name_addr, 8).ok()?;
    let name_ptr = u64::from_le_bytes(name_raw.try_into().ok()?);
    if name_ptr == 0 {
        return None;
    }

    reader.read_string(name_ptr, 256).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // -----------------------------------------------------------------------
    // classify_memfd unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn classify_memfd_executable_is_suspicious() {
        assert!(
            classify_memfd("harmless", true),
            "an executable memfd mapping must always be suspicious"
        );
    }

    #[test]
    fn classify_memfd_shellcode_name_is_suspicious() {
        assert!(
            classify_memfd("shellcode", false),
            "a memfd named 'shellcode' must be suspicious"
        );
    }

    #[test]
    fn classify_memfd_empty_name_is_suspicious() {
        assert!(
            classify_memfd("", false),
            "an anonymous memfd with empty name must be suspicious (evasion)"
        );
    }

    #[test]
    fn classify_memfd_pulseaudio_benign() {
        assert!(
            !classify_memfd("pulseaudio-shm", false),
            "a non-executable memfd named 'pulseaudio-shm' must not be suspicious"
        );
    }

    #[test]
    fn classify_memfd_payload_name_is_suspicious() {
        assert!(
            classify_memfd("payload", false),
            "a memfd named 'payload' must be suspicious"
        );
    }

    #[test]
    fn classify_memfd_wayland_benign() {
        assert!(
            !classify_memfd("wayland-shm", false),
            "a non-executable memfd named 'wayland-shm' must not be suspicious"
        );
    }

    // -----------------------------------------------------------------------
    // walk_memfd_create integration tests
    // -----------------------------------------------------------------------

    fn make_reader_no_init_task() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    fn make_reader_no_memfd() -> ObjectReader<SyntheticPhysMem> {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;

        let mut data = vec![0u8; 4096];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        let tasks_next = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_next.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_next.to_le_bytes());
        data[32..37].copy_from_slice(b"init\0");
        // mm = 0 (kernel thread / no user mm)
        data[48..56].copy_from_slice(&0u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "mm", 48, "pointer")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("init_task", vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_memfd_missing_init_task_returns_empty() {
        let reader = make_reader_no_init_task();
        let result = walk_memfd_create(&reader).expect("should not error");
        assert!(
            result.is_empty(),
            "missing init_task symbol must yield empty result (graceful degradation)"
        );
    }

    #[test]
    fn walk_memfd_no_memfd_processes_returns_empty() {
        let reader = make_reader_no_memfd();
        let result = walk_memfd_create(&reader).expect("should not error");
        assert!(
            result.is_empty(),
            "a kernel thread with mm==NULL must not produce any memfd results"
        );
    }

    #[test]
    fn walk_memfd_missing_tasks_offset_returns_empty() {
        // init_task present but task_struct.tasks field missing → graceful degradation.
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            // No "tasks" field
            .add_symbol("init_task", 0xFFFF_8000_0000_0000)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_memfd_create(&reader).expect("should not error");
        assert!(result.is_empty(), "missing tasks offset must yield empty result");
    }

    // -----------------------------------------------------------------------
    // Additional classify_memfd branch coverage
    // -----------------------------------------------------------------------

    #[test]
    fn classify_memfd_shm_prefix_benign() {
        assert!(!classify_memfd("shm_region", false), "shm prefix must be benign");
    }

    #[test]
    fn classify_memfd_chrome_prefix_benign() {
        assert!(!classify_memfd("chrome_shared", false), "chrome prefix must be benign");
    }

    #[test]
    fn classify_memfd_firefox_prefix_benign() {
        assert!(!classify_memfd("firefox-ipc", false), "firefox prefix must be benign");
    }

    #[test]
    fn classify_memfd_v8_prefix_benign() {
        assert!(!classify_memfd("v8-heap", false), "v8 prefix must be benign");
    }

    #[test]
    fn classify_memfd_dbus_prefix_benign() {
        assert!(!classify_memfd("dbus-shm", false), "dbus prefix must be benign");
    }

    #[test]
    fn classify_memfd_stage_name_suspicious() {
        assert!(classify_memfd("stage2", false), "stage substring must be suspicious");
    }

    #[test]
    fn classify_memfd_loader_name_suspicious() {
        assert!(classify_memfd("loader", false), "loader substring must be suspicious");
    }

    #[test]
    fn classify_memfd_inject_name_suspicious() {
        assert!(classify_memfd("inject_hook", false), "inject substring must be suspicious");
    }

    #[test]
    fn classify_memfd_hack_name_suspicious() {
        assert!(classify_memfd("hack_tool", false), "hack substring must be suspicious");
    }

    #[test]
    fn classify_memfd_benign_non_prefix_non_suspicious_name() {
        // Name does not match any prefix or suspicious substring, not executable
        assert!(!classify_memfd("my_normal_buffer", false), "innocuous name must be benign");
    }

    #[test]
    fn classify_memfd_case_insensitive_suspicious() {
        // Suspicious substring matching should be case-insensitive
        assert!(classify_memfd("PAYLOAD_EXEC", false), "case-insensitive suspicious match");
    }

    #[test]
    fn memfd_info_serializes() {
        let info = MemfdInfo {
            pid: 999,
            comm: "evil".to_string(),
            memfd_name: "payload".to_string(),
            size_bytes: 4096,
            is_executable: true,
            is_suspicious: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":999"));
        assert!(json.contains("\"is_suspicious\":true"));
        assert!(json.contains("\"is_executable\":true"));
    }
}
