//! PAM library hook detection.
//!
//! Detects processes that have loaded a PAM-related shared library
//! (`libpam*.so`) from non-standard system paths, which is a strong
//! indicator of credential theft (MITRE ATT&CK T1556.003).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, Result};

/// Information about a suspicious PAM library loaded by a process.
#[derive(Debug, Clone)]
pub struct PamHookInfo {
    /// Process ID.
    pub pid: u32,
    /// Process command name.
    pub comm: String,
    /// Full path of the loaded PAM library (dentry name component).
    pub library_path: String,
    /// True if the library originates from a standard system lib directory.
    pub is_system_path: bool,
    /// True if the library is considered suspicious.
    pub is_suspicious: bool,
}

/// Standard system library path prefixes that are NOT suspicious.
const SYSTEM_LIB_PREFIXES: &[&str] =
    &["/lib", "/usr/lib", "/usr/lib64", "/lib64", "/usr/local/lib"];

/// Classify whether a PAM library path is suspicious.
///
/// Returns `true` if the path contains "pam" (case-insensitive) AND does
/// not start with a known system library directory.
pub fn classify_pam_hook(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let lower = path.to_lowercase();
    if !lower.contains("pam") {
        return false;
    }
    !SYSTEM_LIB_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// Walk all process VMAs and report PAM libraries loaded from non-system paths.
///
/// On missing `init_task` symbol, returns `Ok(vec![])` rather than an error
/// so callers can treat a missing symbol table as a no-op.
pub fn walk_pam_hooks<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<PamHookInfo>> {
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

    let mut findings = Vec::new();
    scan_process_pam(reader, init_task_addr, &mut findings);
    for &task_addr in &task_addrs {
        scan_process_pam(reader, task_addr, &mut findings);
    }

    Ok(findings)
}

/// Scan a single process's VMAs for PAM-related file-backed mappings.
fn scan_process_pam<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
    out: &mut Vec<PamHookInfo>,
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
        let vm_file: u64 = match reader.read_field(vma_addr, "vm_area_struct", "vm_file") {
            Ok(v) => v,
            Err(_) => {
                vma_addr = reader
                    .read_field(vma_addr, "vm_area_struct", "vm_next")
                    .unwrap_or(0);
                continue;
            }
        };

        if vm_file != 0 {
            // Read dentry name via vm_file -> f_path -> dentry -> d_name -> name
            if let Some(library_path) = read_dentry_name(reader, vm_file) {
                if library_path.to_lowercase().contains("pam") {
                    let is_system_path = SYSTEM_LIB_PREFIXES
                        .iter()
                        .any(|prefix| library_path.starts_with(prefix));
                    let is_suspicious = classify_pam_hook(&library_path);
                    out.push(PamHookInfo {
                        pid,
                        comm: comm.clone(),
                        library_path,
                        is_system_path,
                        is_suspicious,
                    });
                }
            }
        }

        vma_addr = reader
            .read_field(vma_addr, "vm_area_struct", "vm_next")
            .unwrap_or(0);
    }
}

/// Attempt to read the dentry name from a `struct file *`.
///
/// Follows: `file.f_path.dentry -> dentry.d_name.name` (pointer to C string).
fn read_dentry_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    file_ptr: u64,
) -> Option<String> {
    // f_path is embedded in file at field "f_path"; dentry is inside path
    let f_path_dentry: u64 = reader.read_field(file_ptr, "file", "f_path").ok()?;
    if f_path_dentry == 0 {
        return None;
    }
    // dentry -> d_name (qstr) -> name (pointer to char)
    let name_ptr: u64 = reader.read_field(f_path_dentry, "dentry", "d_name").ok()?;
    if name_ptr == 0 {
        return None;
    }
    // Read null-terminated string from name_ptr (up to 256 bytes)
    let bytes = reader.read_bytes(name_ptr, 256).ok()?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8(bytes[..end].to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ---------------------------------------------------------------------------
    // Unit tests for classify_pam_hook (no memory reader needed)
    // ---------------------------------------------------------------------------

    #[test]
    fn classify_pam_hook_tmp_path_suspicious() {
        assert!(classify_pam_hook("/tmp/libpam_evil.so"));
    }

    #[test]
    fn classify_pam_hook_home_path_suspicious() {
        assert!(classify_pam_hook(
            "/home/attacker/.local/libpam_backdoor.so"
        ));
    }

    #[test]
    fn classify_pam_hook_system_lib_not_suspicious() {
        assert!(!classify_pam_hook("/lib/x86_64-linux-gnu/libpam.so.0"));
        assert!(!classify_pam_hook("/usr/lib/libpam.so.0"));
        assert!(!classify_pam_hook("/usr/lib64/libpam.so.0"));
        assert!(!classify_pam_hook("/lib64/libpam.so.0"));
        assert!(!classify_pam_hook("/usr/local/lib/libpam.so.0"));
    }

    #[test]
    fn classify_pam_hook_empty_path_not_suspicious() {
        assert!(!classify_pam_hook(""));
    }

    #[test]
    fn classify_pam_hook_devshm_suspicious() {
        assert!(classify_pam_hook("/dev/shm/libpam_hook.so"));
    }

    // ---------------------------------------------------------------------------
    // Walker tests — missing symbol → Ok(empty)
    // ---------------------------------------------------------------------------

    fn make_minimal_reader_no_init_task() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 8, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            // No "init_task" symbol registered
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_pam_hooks_missing_init_task_returns_empty() {
        let reader = make_minimal_reader_no_init_task();
        let result = walk_pam_hooks(&reader).unwrap();
        assert!(result.is_empty());
    }

    // ---------------------------------------------------------------------------
    // Integration: kernel thread (mm == 0) produces no output
    // ---------------------------------------------------------------------------

    fn make_kernel_thread_reader() -> ObjectReader<SyntheticPhysMem> {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task: pid=0, tasks list → self, mm=NULL
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..41].copy_from_slice(b"swapper/0");
        data[48..56].copy_from_slice(&0u64.to_le_bytes()); // mm = NULL

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "mm", 48, "pointer")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_struct("mm_struct", 64)
            .add_field("mm_struct", "mmap", 8, "pointer")
            .add_struct("vm_area_struct", 64)
            .add_field("vm_area_struct", "vm_next", 16, "pointer")
            .add_field("vm_area_struct", "vm_file", 40, "pointer")
            .add_symbol("init_task", vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, ptflags::WRITABLE)
            .write_phys(paddr, &data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_pam_hooks_kernel_thread_returns_empty() {
        let reader = make_kernel_thread_reader();
        let result = walk_pam_hooks(&reader).unwrap();
        assert!(result.is_empty());
    }

    // ---------------------------------------------------------------------------
    // Additional classify_pam_hook edge cases
    // ---------------------------------------------------------------------------

    #[test]
    fn classify_pam_hook_no_pam_in_path_not_suspicious() {
        // Path that is not a system path but also doesn't contain "pam"
        assert!(!classify_pam_hook("/tmp/libssl.so"));
        assert!(!classify_pam_hook("/home/user/.local/libfoo.so"));
    }

    #[test]
    fn classify_pam_hook_uppercase_pam_suspicious() {
        // Classification is case-insensitive; "PAM" should be detected
        assert!(classify_pam_hook("/tmp/libPAM_evil.so"));
    }

    #[test]
    fn classify_pam_hook_mixed_case_pam_suspicious() {
        assert!(classify_pam_hook("/opt/libPam.so"));
    }

    #[test]
    fn classify_pam_hook_system_lib64_not_suspicious() {
        // /usr/lib64 prefix — must not be flagged
        assert!(!classify_pam_hook("/usr/lib64/security/libpam_unix.so"));
    }

    // ---------------------------------------------------------------------------
    // walk_pam_hooks: symbol present + self-pointing list (walk body runs)
    // ---------------------------------------------------------------------------

    #[test]
    fn walk_pam_hooks_symbol_present_empty_list() {
        // init_task present with self-pointing tasks list and mm==NULL.
        // walk body runs but scan_process_pam returns early on mm==0.
        let sym_vaddr: u64 = 0xFFFF_8800_0040_0000;
        let sym_paddr: u64 = 0x0050_0000;
        let tasks_offset = 16u64;

        let mut page = [0u8; 4096];
        // pid = 0 (swapper)
        page[0..4].copy_from_slice(&0u32.to_le_bytes());
        // tasks: self-pointing
        let list_self = sym_vaddr + tasks_offset;
        page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&list_self.to_le_bytes());
        page[tasks_offset as usize + 8..tasks_offset as usize + 16]
            .copy_from_slice(&list_self.to_le_bytes());
        // comm = "swapper"
        page[32..39].copy_from_slice(b"swapper");
        // mm = 0 (kernel thread)
        page[48..56].copy_from_slice(&0u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "unsigned int")
            .add_field("task_struct", "tasks", 16, "pointer")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "mm", 48, "pointer")
            .add_symbol("init_task", sym_vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptflags::WRITABLE)
            .write_phys(sym_paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_pam_hooks(&reader).unwrap_or_default();
        assert!(result.is_empty(), "kernel thread with mm==NULL should produce no PAM findings");
    }

    #[test]
    fn walk_pam_hooks_missing_tasks_field_returns_empty() {
        // init_task is present but "tasks" field offset is absent.
        // walk_list will not find the list offset so we expect graceful return.
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            // tasks field intentionally omitted
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("init_task", 0xFFFF_8000_0010_0000)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // Missing tasks offset → Ok(empty) per graceful degradation
        let result = walk_pam_hooks(&reader).unwrap();
        assert!(result.is_empty());
    }
}
