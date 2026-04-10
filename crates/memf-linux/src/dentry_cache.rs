//! Detect files hidden via dentry unlink (open-but-unlinked file descriptors).
//!
//! A classic rootkit technique is to `unlink()` a file while keeping a file
//! descriptor open. The file disappears from the directory tree (`i_nlink == 0`)
//! but remains accessible via the open fd. This walker scans every process's
//! open fd table looking for file-backed fds whose dentry inode has `i_nlink == 0`.
//!
//! MITRE ATT&CK: T1564.001 — Hide Artifacts: Hidden Files and Directories.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use serde::Serialize;

use crate::Result;

/// Suspicious file extensions that indicate executable/library payloads.
const SUSPICIOUS_EXTENSIONS: &[&str] = &[".so", ".py", ".sh", ".elf", ".bin"];

/// Information about a hidden (unlinked but open) file descriptor.
#[derive(Debug, Clone, Serialize)]
pub struct HiddenDentryInfo {
    /// Process ID.
    pub pid: u32,
    /// Process command name (`task_struct.comm`, max 16 chars).
    pub comm: String,
    /// File descriptor number.
    pub fd: u32,
    /// Virtual address of the `struct dentry` in kernel memory.
    pub dentry_addr: u64,
    /// Filename from `dentry->d_name`.
    pub filename: String,
    /// Inode number from `dentry->d_inode->i_ino`.
    pub inode_num: u64,
    /// File size in bytes from `dentry->d_inode->i_size`.
    pub file_size: u64,
    /// Hard link count (`dentry->d_inode->i_nlink`); 0 means the file is unlinked.
    pub nlink: u32,
    /// Whether this hidden dentry is considered suspicious.
    pub is_suspicious: bool,
}

/// Classify whether an open-but-unlinked file descriptor is suspicious.
///
/// Returns `true` (suspicious) if:
/// - `nlink == 0` (file is unlinked, only reachable via open fd), OR
/// - `filename` ends with a suspicious extension (`.so`, `.py`, `.sh`, `.elf`, `.bin`).
///
/// Returns `false` (benign) if:
/// - `filename` is empty (kernel internal anonymous files).
/// - `nlink > 0` and no suspicious extension.
pub fn classify_hidden_dentry(nlink: u32, filename: &str) -> bool {
    // Empty filename → kernel internal file, not suspicious.
    if filename.is_empty() {
        return false;
    }

    let name_lower = filename.to_lowercase();

    // File still in the directory tree → check only for suspicious extensions.
    if nlink > 0 {
        return SUSPICIOUS_EXTENSIONS
            .iter()
            .any(|ext| name_lower.ends_with(ext));
    }

    // nlink == 0 → file is unlinked (hidden), always suspicious.
    true
}

/// Walk the task list and enumerate all open-but-unlinked file descriptors.
///
/// For each process, walks `task_struct.files -> files_struct.fdt -> fdtable.fd[]`,
/// then reads `file->f_path.dentry->d_inode->i_nlink`. Entries with `i_nlink == 0`
/// are recorded as hidden.
///
/// Gracefully returns `Ok(vec![])` if any required symbol is absent.
pub fn walk_dentry_cache<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<HiddenDentryInfo>> {
    // --- symbol resolution (graceful degradation) ---
    let init_task_addr = match reader.symbols().symbol_address("init_task") {
        Some(a) => a,
        None => return Ok(vec![]),
    };
    let tasks_offset = match reader.symbols().field_offset("task_struct", "tasks") {
        Some(o) => o,
        None => return Ok(vec![]),
    };
    if reader
        .symbols()
        .field_offset("task_struct", "files")
        .is_none()
    {
        return Ok(vec![]);
    }

    let head_vaddr = init_task_addr + tasks_offset;
    let task_addrs = reader.walk_list(head_vaddr, "task_struct", "tasks")?;

    let mut results: Vec<HiddenDentryInfo> = Vec::new();

    collect_hidden_dentries_for_task(reader, init_task_addr, &mut results);
    for &task_addr in &task_addrs {
        collect_hidden_dentries_for_task(reader, task_addr, &mut results);
    }

    results.sort_by_key(|r| (r.pid, r.fd));
    Ok(results)
}

/// Collect hidden-dentry information for a single task.
fn collect_hidden_dentries_for_task<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
    out: &mut Vec<HiddenDentryInfo>,
) {
    let pid: u32 = match reader.read_field(task_addr, "task_struct", "pid") {
        Ok(v) => v,
        Err(_) => return,
    };
    let comm = reader
        .read_field_string(task_addr, "task_struct", "comm", 16)
        .unwrap_or_default();

    // files_struct pointer.
    let files_ptr: u64 = match reader.read_field(task_addr, "task_struct", "files") {
        Ok(v) => v,
        Err(_) => return,
    };
    if files_ptr == 0 {
        return;
    }

    // files_struct.fdt → fdtable pointer.
    let fdt_ptr: u64 = match reader.read_field(files_ptr, "files_struct", "fdt") {
        Ok(v) => v,
        Err(_) => return,
    };
    if fdt_ptr == 0 {
        return;
    }

    // fdtable.fd → pointer to array of file pointers.
    let fd_array_ptr: u64 = match reader.read_field(fdt_ptr, "fdtable", "fd") {
        Ok(v) => v,
        Err(_) => return,
    };
    if fd_array_ptr == 0 {
        return;
    }

    for fd_index in 0u64..256 {
        let file_slot_addr = fd_array_ptr + fd_index * 8;
        let file_ptr_raw = match reader.read_bytes(file_slot_addr, 8) {
            Ok(b) => b,
            Err(_) => break,
        };
        let file_ptr = u64::from_le_bytes(match file_ptr_raw.try_into() {
            Ok(b) => b,
            Err(_) => break,
        });
        if file_ptr == 0 {
            continue;
        }

        if let Some(info) = try_read_hidden_dentry(reader, pid, &comm, fd_index as u32, file_ptr) {
            out.push(info);
        }
    }
}

/// Attempt to read hidden-dentry information from a single open file.
///
/// Returns `None` if the dentry is not unlinked or fields cannot be read.
fn try_read_hidden_dentry<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    pid: u32,
    comm: &str,
    fd: u32,
    file_ptr: u64,
) -> Option<HiddenDentryInfo> {
    // Navigate file->f_path.dentry.
    let f_path_offset = reader.symbols().field_offset("file", "f_path")?;
    let dentry_in_path = reader.symbols().field_offset("path", "dentry")?;

    let dentry_slot = file_ptr + f_path_offset + dentry_in_path;
    let dentry_raw = reader.read_bytes(dentry_slot, 8).ok()?;
    let dentry_ptr = u64::from_le_bytes(dentry_raw.try_into().ok()?);
    if dentry_ptr == 0 {
        return None;
    }

    // dentry->d_inode (pointer).
    let inode_ptr: u64 = reader.read_field(dentry_ptr, "dentry", "d_inode").ok()?;
    if inode_ptr == 0 {
        return None;
    }

    // inode->i_nlink (u32).
    let nlink: u32 = reader.read_field(inode_ptr, "inode", "i_nlink").ok()?;
    // inode->i_size (stored as u64 for simplicity).
    let file_size: u64 = reader
        .read_field::<u64>(inode_ptr, "inode", "i_size")
        .unwrap_or(0);
    // inode->i_ino (unsigned long, 8 bytes on x86_64).
    let inode_num: u64 = reader
        .read_field::<u64>(inode_ptr, "inode", "i_ino")
        .unwrap_or(0);

    // dentry->d_name (qstr) → name pointer.
    let filename = read_dentry_name(reader, dentry_ptr).unwrap_or_default();

    let is_suspicious = classify_hidden_dentry(nlink, &filename);

    // Skip entries that are neither unlinked nor suspicious.
    if nlink > 0 && !is_suspicious {
        return None;
    }

    Some(HiddenDentryInfo {
        pid,
        comm: comm.to_string(),
        fd,
        dentry_addr: dentry_ptr,
        filename,
        inode_num,
        file_size,
        nlink,
        is_suspicious,
    })
}

/// Read `dentry->d_name.name` string.
fn read_dentry_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    dentry_ptr: u64,
) -> Option<String> {
    let d_name_offset = reader.symbols().field_offset("dentry", "d_name")?;
    let name_in_qstr = reader.symbols().field_offset("qstr", "name")?;

    let name_ptr_addr = dentry_ptr + d_name_offset + name_in_qstr;
    let name_raw = reader.read_bytes(name_ptr_addr, 8).ok()?;
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
    // classify_hidden_dentry unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn classify_hidden_nlink_zero_is_suspicious() {
        assert!(
            classify_hidden_dentry(0, "rootkit.so"),
            "nlink==0 file must be suspicious"
        );
    }

    #[test]
    fn classify_hidden_so_file_suspicious() {
        assert!(
            classify_hidden_dentry(0, "libevil.so"),
            "unlinked .so file must be suspicious"
        );
    }

    #[test]
    fn classify_hidden_nlink_positive_not_suspicious() {
        assert!(
            !classify_hidden_dentry(1, "normal.txt"),
            "file with nlink>0 and no suspicious extension must not be suspicious"
        );
    }

    #[test]
    fn classify_hidden_empty_filename_not_suspicious() {
        assert!(
            !classify_hidden_dentry(0, ""),
            "empty filename (kernel internal) must not be suspicious"
        );
    }

    #[test]
    fn classify_hidden_sh_script_suspicious() {
        assert!(
            classify_hidden_dentry(0, "dropper.sh"),
            "unlinked .sh script must be suspicious"
        );
    }

    #[test]
    fn classify_hidden_py_script_suspicious() {
        assert!(
            classify_hidden_dentry(0, "stage2.py"),
            "unlinked .py script must be suspicious"
        );
    }

    // -----------------------------------------------------------------------
    // walk_dentry_cache integration tests
    // -----------------------------------------------------------------------

    fn make_reader_no_init_task() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    fn make_reader_no_open_files() -> ObjectReader<SyntheticPhysMem> {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;

        let mut data = vec![0u8; 4096];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        let tasks_next = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_next.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_next.to_le_bytes());
        data[32..39].copy_from_slice(b"kthread");
        // files = 0 (NULL — no open fds)
        data[48..56].copy_from_slice(&0u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "files", 48, "pointer")
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
    fn walk_dentry_missing_init_task_returns_empty() {
        let reader = make_reader_no_init_task();
        let result = walk_dentry_cache(&reader).expect("should not error");
        assert!(
            result.is_empty(),
            "missing init_task must yield empty results (graceful degradation)"
        );
    }

    #[test]
    fn walk_dentry_no_open_files_returns_empty() {
        let reader = make_reader_no_open_files();
        let result = walk_dentry_cache(&reader).expect("should not error");
        assert!(
            result.is_empty(),
            "kernel thread with files==NULL must produce no hidden-dentry results"
        );
    }

    #[test]
    fn walk_dentry_missing_tasks_field_returns_empty() {
        // init_task symbol present but task_struct.tasks field is not defined.
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            // No "tasks" field → graceful degradation
            .add_field("task_struct", "files", 48, "pointer")
            .add_symbol("init_task", 0xFFFF_8000_0000_0000)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_dentry_cache(&reader).expect("should not error");
        assert!(result.is_empty(), "missing tasks field must yield empty (graceful degradation)");
    }

    #[test]
    fn walk_dentry_missing_files_field_returns_empty() {
        // init_task and tasks present, but task_struct.files field missing.
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 16, "list_head")
            // No "files" field → graceful degradation
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("init_task", 0xFFFF_8000_0000_0000)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_dentry_cache(&reader).expect("should not error");
        assert!(result.is_empty(), "missing files field must yield empty (graceful degradation)");
    }

    // -----------------------------------------------------------------------
    // Additional classify_hidden_dentry branch coverage
    // -----------------------------------------------------------------------

    #[test]
    fn classify_hidden_nlink_positive_so_is_suspicious() {
        // nlink > 0 but .so extension → suspicious (file in use with dangerous extension)
        assert!(
            classify_hidden_dentry(2, "libplugin.so"),
            "linked .so file must be suspicious due to extension"
        );
    }

    #[test]
    fn classify_hidden_nlink_positive_bin_is_suspicious() {
        assert!(
            classify_hidden_dentry(1, "stage2.bin"),
            "linked .bin file must be suspicious due to extension"
        );
    }

    #[test]
    fn classify_hidden_nlink_positive_elf_is_suspicious() {
        assert!(
            classify_hidden_dentry(1, "payload.elf"),
            "linked .elf file must be suspicious due to extension"
        );
    }

    #[test]
    fn classify_hidden_nlink_positive_py_is_suspicious() {
        assert!(
            classify_hidden_dentry(3, "backdoor.py"),
            "linked .py file must be suspicious due to extension"
        );
    }

    #[test]
    fn classify_hidden_nlink_positive_sh_is_suspicious() {
        assert!(
            classify_hidden_dentry(1, "install.sh"),
            "linked .sh file must be suspicious due to extension"
        );
    }

    #[test]
    fn classify_hidden_extension_check_is_case_insensitive() {
        // Extension matching uses to_lowercase()
        assert!(
            classify_hidden_dentry(1, "PAYLOAD.SO"),
            "extension check should be case-insensitive"
        );
    }

    #[test]
    fn hidden_dentry_info_serializes() {
        let info = HiddenDentryInfo {
            pid: 42,
            comm: "evil".to_string(),
            fd: 3,
            dentry_addr: 0xFFFF_8000_0001_0000,
            filename: "rootkit.so".to_string(),
            inode_num: 12345,
            file_size: 65536,
            nlink: 0,
            is_suspicious: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":42"));
        assert!(json.contains("rootkit.so"));
        assert!(json.contains("\"is_suspicious\":true"));
    }
}
