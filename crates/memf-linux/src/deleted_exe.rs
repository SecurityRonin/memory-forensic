//! Detect processes running from deleted executables.
//!
//! When malware deletes its binary after execution, the process keeps running
//! but the `/proc/<pid>/exe` symlink (backed by `mm->exe_file->f_path->dentry->d_name`)
//! shows `(deleted)`. This is a strong indicator of malicious activity.
//!
//! MITRE ATT&CK: T1070.004 — Indicator Removal: File Deletion.
//!
//! Legitimate cases include package manager upgrades (apt, dpkg, yum, dnf, rpm)
//! where the old binary is replaced while the process is still running, and
//! kernel threads with empty exe paths.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use serde::Serialize;

use crate::{Error, Result};

/// Known-benign process names that may legitimately run from deleted executables.
///
/// Package managers and their helpers frequently replace their own binaries
/// during upgrade operations, causing a transient "(deleted)" state.
const KNOWN_BENIGN_COMMS: &[&str] = &[
    "apt",
    "apt-get",
    "apt-check",
    "aptd",
    "dpkg",
    "dpkg-deb",
    "yum",
    "dnf",
    "rpm",
    "rpmdb",
    "packagekitd",
    "unattended-upgr",
];

/// Information about a process whose executable may have been deleted.
#[derive(Debug, Clone, Serialize)]
pub struct DeletedExeInfo {
    /// Process ID.
    pub pid: u32,
    /// Process command name (`task_struct.comm`, max 16 chars).
    pub comm: String,
    /// Executable path as read from memory (may include "(deleted)" suffix).
    pub exe_path: String,
    /// Whether the executable path contains the "(deleted)" marker.
    pub is_deleted: bool,
    /// Whether this deleted executable is suspicious (not a known-benign case).
    pub is_suspicious: bool,
}

/// Classify whether a deleted executable is suspicious.
///
/// Returns `true` (suspicious) if:
/// - The exe path contains "(deleted)" AND
/// - The process is NOT a known-benign package manager process AND
/// - The exe path is not empty (kernel threads have no exe)
///
/// Returns `false` (benign) for:
/// - Normal executables (no "(deleted)" marker)
/// - Package manager processes (apt, dpkg, yum, dnf, rpm, etc.)
/// - Kernel threads with empty exe paths
/// - Processes with empty comm (likely kernel threads)
pub fn classify_deleted_exe(exe_path: &str, comm: &str) -> bool {
    // Not deleted at all -> not suspicious
    if !exe_path.contains("(deleted)") {
        return false;
    }

    // Empty exe path -> kernel thread, not suspicious
    if exe_path.is_empty() {
        return false;
    }

    // Empty comm -> likely kernel thread, not suspicious
    if comm.is_empty() {
        return false;
    }

    // Check against known-benign process names
    let comm_lower = comm.to_lowercase();
    for &benign in KNOWN_BENIGN_COMMS {
        if comm_lower == benign {
            return false;
        }
    }

    // All other deleted executables are suspicious
    true
}

/// Walk the task list and detect processes running from deleted executables.
///
/// For each process, reads the `mm->exe_file->f_path->dentry->d_name` chain
/// to recover the executable path. If the path contains "(deleted)", the
/// process is flagged and classified.
///
/// Kernel threads (NULL mm) are silently skipped.
pub fn walk_deleted_exe<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<DeletedExeInfo>> {
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
    if let Some(info) = read_deleted_exe_info(reader, init_task_addr) {
        results.push(info);
    }

    for &task_addr in &task_addrs {
        if let Some(info) = read_deleted_exe_info(reader, task_addr) {
            results.push(info);
        }
    }

    results.sort_by_key(|r| r.pid);
    Ok(results)
}

/// Read the executable path for a single task and classify it.
///
/// Returns `None` for kernel threads (NULL mm) or if any field cannot be read.
fn read_deleted_exe_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
) -> Option<DeletedExeInfo> {
    let pid: u32 = reader.read_field(task_addr, "task_struct", "pid").ok()?;
    let comm = reader
        .read_field_string(task_addr, "task_struct", "comm", 16)
        .unwrap_or_default();

    // Kernel threads have mm == NULL — skip them.
    let mm_ptr: u64 = reader.read_field(task_addr, "task_struct", "mm").ok()?;
    if mm_ptr == 0 {
        return None;
    }

    // Follow mm->exe_file (pointer to struct file).
    let exe_file_ptr: u64 = reader.read_field(mm_ptr, "mm_struct", "exe_file").ok()?;
    if exe_file_ptr == 0 {
        return None;
    }

    // Navigate exe_file->f_path.dentry to read the path name.
    let exe_path = read_file_dentry_name(reader, exe_file_ptr).unwrap_or_default();

    let is_deleted = exe_path.contains("(deleted)");
    let is_suspicious = classify_deleted_exe(&exe_path, &comm);

    Some(DeletedExeInfo {
        pid,
        comm,
        exe_path,
        is_deleted,
        is_suspicious,
    })
}

/// Read the dentry name from a `struct file` pointer via `f_path.dentry->d_name`.
///
/// Follows the embedded struct chain: `file.f_path` (embedded `struct path`) ->
/// `path.dentry` (pointer) -> `dentry.d_name` (embedded `struct qstr`) ->
/// `qstr.name` (pointer to string).
fn read_file_dentry_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    file_ptr: u64,
) -> Option<String> {
    let f_path_offset = reader.symbols().field_offset("file", "f_path")?;
    let dentry_in_path = reader.symbols().field_offset("path", "dentry")?;
    let d_name_offset = reader.symbols().field_offset("dentry", "d_name")?;
    let name_in_qstr = reader.symbols().field_offset("qstr", "name")?;

    // file.f_path is embedded; dentry is a pointer within the embedded path struct.
    let dentry_addr = file_ptr + f_path_offset + dentry_in_path;
    let dentry_raw = reader.read_bytes(dentry_addr, 8).ok()?;
    let dentry_ptr = u64::from_le_bytes(dentry_raw.try_into().ok()?);
    if dentry_ptr == 0 {
        return None;
    }

    // dentry.d_name is an embedded qstr; name is a pointer within qstr.
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

    // --- classify_deleted_exe unit tests ---

    #[test]
    fn classify_normal_benign() {
        // A normal executable that is NOT deleted should never be suspicious.
        assert!(
            !classify_deleted_exe("/usr/bin/nginx", "nginx"),
            "a live (non-deleted) executable must not be flagged suspicious"
        );
    }

    #[test]
    fn classify_deleted_suspicious() {
        // A deleted executable from an unknown process IS suspicious.
        assert!(
            classify_deleted_exe("/tmp/.x11 (deleted)", "payload"),
            "a deleted exe from unknown process 'payload' must be suspicious"
        );
    }

    #[test]
    fn classify_deleted_apt_benign() {
        // apt running from a deleted exe during upgrade is benign.
        assert!(
            !classify_deleted_exe("/usr/bin/apt (deleted)", "apt"),
            "apt with deleted exe during package upgrade must not be suspicious"
        );
    }

    #[test]
    fn classify_deleted_dpkg_benign() {
        // dpkg running from a deleted exe during upgrade is benign.
        assert!(
            !classify_deleted_exe("/usr/bin/dpkg (deleted)", "dpkg"),
            "dpkg with deleted exe during package upgrade must not be suspicious"
        );
    }

    #[test]
    fn classify_kernel_thread_benign() {
        // Kernel threads have empty comm or empty exe path — not suspicious.
        assert!(
            !classify_deleted_exe("", ""),
            "kernel thread with empty exe and comm must not be suspicious"
        );
    }

    #[test]
    fn classify_empty_path_benign() {
        // Empty exe path (kernel thread) with a comm name should not be suspicious
        // even though it technically can't contain "(deleted)" — test the guard.
        assert!(
            !classify_deleted_exe("", "kworker/0:1"),
            "empty exe path must not be flagged suspicious"
        );
    }

    #[test]
    fn classify_deleted_yum_benign() {
        // yum running from a deleted exe during upgrade is benign.
        assert!(
            !classify_deleted_exe("/usr/bin/yum (deleted)", "yum"),
            "yum with deleted exe during package upgrade must not be suspicious"
        );
    }

    #[test]
    fn classify_deleted_with_suspicious_name() {
        // A process with a suspicious-looking name running from /dev/shm (deleted).
        assert!(
            classify_deleted_exe("/dev/shm/.hidden (deleted)", "a]"),
            "deleted exe from /dev/shm with obfuscated name must be suspicious"
        );
    }

    #[test]
    fn classify_deleted_empty_comm_benign() {
        // Deleted path but empty comm → kernel thread, not suspicious
        assert!(
            !classify_deleted_exe("/tmp/.evil (deleted)", ""),
            "empty comm with deleted exe must not be suspicious"
        );
    }

    #[test]
    fn classify_all_known_benign_comms() {
        // Every entry in KNOWN_BENIGN_COMMS must be suppressed
        for comm in KNOWN_BENIGN_COMMS {
            let path = format!("/usr/bin/{comm} (deleted)");
            assert!(
                !classify_deleted_exe(&path, comm),
                "known-benign comm '{comm}' must not be flagged suspicious"
            );
        }
    }

    #[test]
    fn classify_benign_comm_case_insensitive() {
        // Classification is case-insensitive for known-benign names
        assert!(!classify_deleted_exe("/usr/bin/APT (deleted)", "APT"));
        assert!(!classify_deleted_exe("/usr/bin/Dpkg (deleted)", "Dpkg"));
        assert!(!classify_deleted_exe("/usr/bin/YUM (deleted)", "YUM"));
    }

    #[test]
    fn classify_near_benign_name_suspicious() {
        // "apt2" is NOT in the benign list → suspicious
        assert!(classify_deleted_exe("/usr/bin/apt2 (deleted)", "apt2"));
        // "dpkg-query" is not in the list → suspicious
        assert!(classify_deleted_exe("/usr/bin/dpkg-query (deleted)", "dpkg-query"));
    }

    #[test]
    fn classify_deleted_exe_info_struct_fields() {
        let info = DeletedExeInfo {
            pid: 999,
            comm: "evil".to_string(),
            exe_path: "/tmp/.x (deleted)".to_string(),
            is_deleted: true,
            is_suspicious: true,
        };
        let cloned = info.clone();
        assert_eq!(cloned.pid, 999);
        assert!(cloned.is_deleted);
        assert!(cloned.is_suspicious);
        let dbg = format!("{:?}", cloned);
        assert!(dbg.contains("evil"));
    }

    #[test]
    fn classify_deleted_exe_info_serializes_to_json() {
        let info = DeletedExeInfo {
            pid: 42,
            comm: "malware".to_string(),
            exe_path: "/dev/shm/.bin (deleted)".to_string(),
            is_deleted: true,
            is_suspicious: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":42"));
        assert!(json.contains("\"is_deleted\":true"));
        assert!(json.contains("\"is_suspicious\":true"));
    }

    // --- walk_deleted_exe integration test ---

    /// Helper: build an ObjectReader with no init_task symbol.
    fn make_reader_no_symbol() -> ObjectReader<SyntheticPhysMem> {
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

    #[test]
    fn walk_no_symbol_returns_error() {
        // Without init_task symbol, walk should return an error (not panic).
        let reader = make_reader_no_symbol();
        let result = walk_deleted_exe(&reader);
        assert!(
            result.is_err(),
            "walk_deleted_exe must error when init_task symbol is missing"
        );
    }

    // --- walk_deleted_exe: symbol present, self-pointing tasks list, mm != 0, exe_file == 0 ---
    // Exercises read_deleted_exe_info: mm pointer is non-null (reads ok), but
    // mm_struct.exe_file == 0 → returns None → result stays empty.
    #[test]
    fn walk_deleted_exe_mm_non_null_exe_file_null_returns_empty() {
        let tasks_offset: u64 = 0x10;
        let mm_offset: u64    = 0x30;
        let sym_vaddr: u64    = 0xFFFF_8800_0090_0000;
        let sym_paddr: u64    = 0x0090_0000; // < 16 MB
        let mm_vaddr: u64     = 0xFFFF_8800_0091_0000;
        let mm_paddr: u64     = 0x0091_0000;

        // task page
        let mut task_page = [0u8; 4096];
        // pid = 5
        task_page[0..4].copy_from_slice(&5u32.to_le_bytes());
        // tasks self-pointing
        let self_ptr = sym_vaddr + tasks_offset;
        task_page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&self_ptr.to_le_bytes());
        // mm at offset 0x30 → non-zero (points to mm page)
        task_page[mm_offset as usize..mm_offset as usize + 8]
            .copy_from_slice(&mm_vaddr.to_le_bytes());
        // comm = "worker"
        task_page[0x20..0x26].copy_from_slice(b"worker");

        // mm page: exe_file at offset 0x18 = 0 (null)
        let mm_page = [0u8; 4096];

        let isf = IsfBuilder::new()
            .add_symbol("init_task", sym_vaddr)
            .add_struct("list_head", 0x10)
            .add_field("list_head", "next", 0x00, "pointer")
            .add_field("list_head", "prev", 0x08, "pointer")
            .add_struct("task_struct", 0x400)
            .add_field("task_struct", "tasks", tasks_offset, "pointer")
            .add_field("task_struct", "pid", 0x00, "unsigned int")
            .add_field("task_struct", "comm", 0x20, "char")
            .add_field("task_struct", "mm", mm_offset, "pointer")
            .add_struct("mm_struct", 0x200)
            .add_field("mm_struct", "exe_file", 0x18, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, flags::WRITABLE)
            .write_phys(sym_paddr, &task_page)
            .map_4k(mm_vaddr, mm_paddr, flags::WRITABLE)
            .write_phys(mm_paddr, &mm_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_deleted_exe(&reader).unwrap();
        assert!(
            result.is_empty(),
            "mm non-null but exe_file==0 → read_deleted_exe_info returns None → empty"
        );
    }

    // --- walk_deleted_exe: symbol present, self-pointing tasks list, mm == 0 → exercises body ---
    // Exercises the task-list body and `read_deleted_exe_info`: init_task has mm=0 (kernel thread),
    // so it is skipped, and walk_list returns empty → result is empty but no error.
    #[test]
    fn walk_deleted_exe_symbol_present_kernel_thread_returns_empty() {
        // tasks at offset 0x10; pid at 0x00; comm at 0x20; mm at 0x30.
        let tasks_offset: u64 = 0x10;
        let sym_vaddr: u64 = 0xFFFF_8800_0080_0000;
        let sym_paddr: u64 = 0x0080_0000; // unique, < 16 MB

        let isf = IsfBuilder::new()
            .add_symbol("init_task", sym_vaddr)
            .add_struct("list_head", 0x10)
            .add_field("list_head", "next", 0x00, "pointer")
            .add_struct("task_struct", 0x400)
            .add_field("task_struct", "tasks", tasks_offset, "pointer")
            .add_field("task_struct", "pid", 0x00, "unsigned int")
            .add_field("task_struct", "comm", 0x20, "char")
            .add_field("task_struct", "mm", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Build init_task page: tasks.next self-pointing, mm = 0 (kernel thread).
        let mut page = [0u8; 4096];
        let self_ptr = sym_vaddr + tasks_offset;
        page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&self_ptr.to_le_bytes());
        // mm at 0x30 remains 0 → read_deleted_exe_info returns None.

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, flags::WRITABLE)
            .write_phys(sym_paddr, &page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_deleted_exe(&reader).unwrap();
        assert!(
            result.is_empty(),
            "init_task with mm=0 → skipped as kernel thread → empty results"
        );
    }
}
