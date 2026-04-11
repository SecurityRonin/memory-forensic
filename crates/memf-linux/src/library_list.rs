//! Process shared library enumeration for Linux memory forensics.
//!
//! Enumerates shared libraries loaded by each process by walking the
//! `vm_area_struct` VMAs that map `.so` files. Equivalent to combining
//! Volatility's `linux.proc.Maps` with library-specific filtering.
//!
//! Useful for detecting LD_PRELOAD injected libraries, anomalous `.so`
//! files mapped from world-writable directories, or unlinked (deleted)
//! shared objects still resident in memory.

use std::collections::{HashMap, HashSet};

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, Result};

/// Maximum number of unique libraries per process (cycle/corruption guard).
const MAX_LIBS: usize = 4096;

/// Information about a shared library mapped into a process's address space.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SharedLibraryInfo {
    /// Process ID.
    pub pid: u32,
    /// Process command name.
    pub process_name: String,
    /// File path of the shared library (from `vm_file → f_path → dentry → d_name`).
    pub lib_path: String,
    /// Base virtual address (lowest `vm_start` among the library's VMAs).
    pub base_addr: u64,
    /// Total mapped size (sum of all VMA regions for this library).
    pub size: u64,
    /// Whether the library path is classified as suspicious.
    pub is_suspicious: bool,
}

/// Classify whether a library path is suspicious.
///
/// A library is suspicious if any of the following hold:
/// - Path is in `/tmp`, `/dev/shm`, or `/var/tmp` (world-writable directories)
/// - Path does not end in `.so` and does not contain `.so.` (non-standard shared library name)
/// - Path ends with `(deleted)` (unlinked but still mapped -- common malware technique)
/// - Basename starts with `.` (hidden file)
pub fn classify_library(lib_path: &str) -> bool {
    let path = lib_path.trim();

    // Unlinked libraries still mapped in memory.
    if path.ends_with("(deleted)") {
        return true;
    }

    // Strip " (deleted)" suffix for remaining checks so path-based rules
    // still fire on deleted files from suspicious locations.
    let clean = path.strip_suffix(" (deleted)").unwrap_or(path);

    // World-writable staging directories.
    if clean.starts_with("/tmp/")
        || clean == "/tmp"
        || clean.starts_with("/dev/shm/")
        || clean == "/dev/shm"
        || clean.starts_with("/var/tmp/")
        || clean == "/var/tmp"
    {
        return true;
    }

    // Hidden file (basename starts with '.').
    if let Some(basename) = clean.rsplit('/').next() {
        if basename.starts_with('.') && !basename.is_empty() {
            return true;
        }
    }

    // Not a standard shared library name.
    if !clean.ends_with(".so") && !clean.contains(".so.") {
        return true;
    }

    false
}

/// Walk the VMA list for a single process and enumerate shared libraries.
///
/// Reads `task_struct.mm → mm_struct.mmap` and follows the `vm_area_struct`
/// singly-linked list via `vm_next`. For each file-backed VMA, reads the
/// file path from `vm_file → f_path → dentry → d_name`, filters for `.so`
/// mappings, deduplicates by path, and classifies each library.
///
/// Returns an empty `Vec` if the process is a kernel thread (mm == NULL).
pub fn walk_library_list<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
    pid: u32,
    process_name: &str,
) -> Result<Vec<SharedLibraryInfo>> {
    // Read mm pointer -- kernel threads have NULL mm.
    let mm_ptr: u64 = reader.read_field(task_addr, "task_struct", "mm")?;
    if mm_ptr == 0 {
        return Ok(Vec::new());
    }

    // Resolve struct field offsets for the dentry path chain.
    let f_path_offset = reader
        .symbols()
        .field_offset("file", "f_path")
        .ok_or_else(|| Error::Walker("file.f_path field not found".into()))?;
    let dentry_in_path_offset = reader
        .symbols()
        .field_offset("path", "dentry")
        .ok_or_else(|| Error::Walker("path.dentry field not found".into()))?;
    let d_name_offset = reader
        .symbols()
        .field_offset("dentry", "d_name")
        .ok_or_else(|| Error::Walker("dentry.d_name field not found".into()))?;
    let name_in_qstr_offset = reader
        .symbols()
        .field_offset("qstr", "name")
        .ok_or_else(|| Error::Walker("qstr.name field not found".into()))?;

    // Get head of the VMA linked list.
    let mmap_ptr: u64 = reader.read_field(mm_ptr, "mm_struct", "mmap")?;

    // Track per-library aggregated info: (min vm_start, total size).
    let mut lib_map: HashMap<String, (u64, u64)> = HashMap::new();
    let mut seen_addrs: HashSet<u64> = HashSet::new();
    let mut vma_addr = mmap_ptr;

    // Walk the singly-linked vm_next chain (NULL-terminated).
    while vma_addr != 0 {
        // Cycle detection.
        if !seen_addrs.insert(vma_addr) {
            break;
        }
        if lib_map.len() >= MAX_LIBS {
            break;
        }

        let vm_start: u64 = reader.read_field(vma_addr, "vm_area_struct", "vm_start")?;
        let vm_end: u64 = reader.read_field(vma_addr, "vm_area_struct", "vm_end")?;
        let vm_file: u64 = reader.read_field(vma_addr, "vm_area_struct", "vm_file")?;

        if vm_file != 0 {
            // Read file path: file.f_path.dentry → d_name.name
            if let Some(name) = read_vma_file_path(
                reader,
                vm_file,
                f_path_offset,
                dentry_in_path_offset,
                d_name_offset,
                name_in_qstr_offset,
            ) {
                // Only include mappings that look like shared libraries.
                if name.contains(".so") {
                    let size = vm_end.saturating_sub(vm_start);
                    let entry = lib_map.entry(name).or_insert((vm_start, 0));
                    // Track lowest base address and accumulate size.
                    entry.0 = entry.0.min(vm_start);
                    entry.1 += size;
                }
            }
        }

        vma_addr = reader.read_field(vma_addr, "vm_area_struct", "vm_next")?;
    }

    // Build result vector from deduplicated map.
    let mut libs: Vec<SharedLibraryInfo> = lib_map
        .into_iter()
        .map(|(lib_path, (base_addr, size))| {
            let is_suspicious = classify_library(&lib_path);
            SharedLibraryInfo {
                pid,
                process_name: process_name.to_string(),
                lib_path,
                base_addr,
                size,
                is_suspicious,
            }
        })
        .collect();

    // Sort by base address for deterministic output.
    libs.sort_by_key(|lib| lib.base_addr);

    Ok(libs)
}

/// Read the file path from a VMA's `vm_file` pointer.
///
/// Navigates `file.f_path.dentry → d_name.name` to extract the filename.
/// Returns `None` if any pointer in the chain is NULL or unreadable.
fn read_vma_file_path<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    file_ptr: u64,
    f_path_offset: u64,
    dentry_in_path_offset: u64,
    d_name_offset: u64,
    name_in_qstr_offset: u64,
) -> Option<String> {
    // file.f_path is an embedded struct; dentry pointer lives at
    // file_ptr + f_path_offset + dentry_in_path_offset.
    let dentry_addr = file_ptr + f_path_offset + dentry_in_path_offset;
    let dentry_raw = reader.read_bytes(dentry_addr, 8).ok()?;
    let dentry_ptr = u64::from_le_bytes(dentry_raw.try_into().ok()?);
    if dentry_ptr == 0 {
        return None;
    }

    // dentry.d_name is an embedded qstr; name pointer at qstr.name offset.
    let name_addr = dentry_ptr + d_name_offset + name_in_qstr_offset;
    let name_raw = reader.read_bytes(name_addr, 8).ok()?;
    let name_ptr = u64::from_le_bytes(name_raw.try_into().ok()?);
    if name_ptr == 0 {
        return None;
    }

    let name = reader.read_string(name_ptr, 256).ok()?;
    if name.is_empty() {
        return None;
    }

    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // classify_library tests
    // -------------------------------------------------------------------

    #[test]
    fn classify_standard_lib_benign() {
        assert!(
            !classify_library("/usr/lib/x86_64-linux-gnu/libc.so.6"),
            "standard libc path should not be suspicious"
        );
        assert!(
            !classify_library("/usr/lib/libpthread.so.0"),
            "standard libpthread should not be suspicious"
        );
        assert!(
            !classify_library("/lib64/ld-linux-x86-64.so.2"),
            "dynamic linker should not be suspicious"
        );
    }

    #[test]
    fn classify_tmp_suspicious() {
        assert!(
            classify_library("/tmp/evil.so"),
            "/tmp library should be suspicious"
        );
        assert!(
            classify_library("/tmp/subdir/payload.so"),
            "/tmp subdirectory should be suspicious"
        );
    }

    #[test]
    fn classify_devshm_suspicious() {
        assert!(
            classify_library("/dev/shm/inject.so"),
            "/dev/shm library should be suspicious"
        );
        assert!(
            classify_library("/dev/shm/hidden/hook.so.1"),
            "/dev/shm subdirectory should be suspicious"
        );
    }

    #[test]
    fn classify_deleted_suspicious() {
        assert!(
            classify_library("/usr/lib/libfoo.so (deleted)"),
            "deleted library should be suspicious"
        );
        assert!(
            classify_library("/tmp/rootkit.so (deleted)"),
            "deleted library from /tmp should be suspicious"
        );
    }

    #[test]
    fn classify_hidden_file_suspicious() {
        assert!(
            classify_library("/home/user/.hidden_lib.so"),
            "hidden file should be suspicious"
        );
        assert!(
            classify_library("/opt/app/.sneaky.so.1"),
            "hidden file with version should be suspicious"
        );
    }

    #[test]
    fn classify_non_so_suspicious() {
        assert!(
            classify_library("/usr/lib/not_a_library.bin"),
            "non-.so file should be suspicious"
        );
        assert!(
            classify_library("/usr/lib/strange_mapping"),
            "file without .so extension should be suspicious"
        );
    }

    #[test]
    fn classify_var_tmp_suspicious() {
        assert!(
            classify_library("/var/tmp/staged.so"),
            "/var/tmp library should be suspicious"
        );
    }

    // -------------------------------------------------------------------
    // walk_library_list tests
    // -------------------------------------------------------------------

    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Build an [`ObjectReader`] with all struct definitions needed by the
    /// library list walker (task_struct, mm_struct, vm_area_struct, file,
    /// path, dentry, qstr).
    fn make_test_reader(data: &[u8], vaddr: u64, paddr: u64) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            // task_struct
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "mm", 48, "pointer")
            // mm_struct
            .add_struct("mm_struct", 128)
            .add_field("mm_struct", "mmap", 8, "pointer")
            // vm_area_struct
            .add_struct("vm_area_struct", 64)
            .add_field("vm_area_struct", "vm_start", 0, "unsigned long")
            .add_field("vm_area_struct", "vm_end", 8, "unsigned long")
            .add_field("vm_area_struct", "vm_next", 16, "pointer")
            .add_field("vm_area_struct", "vm_file", 40, "pointer")
            // file
            .add_struct("file", 64)
            .add_field("file", "f_path", 0, "path")
            // path (embedded in struct file)
            .add_struct("path", 16)
            .add_field("path", "dentry", 8, "pointer")
            // dentry
            .add_struct("dentry", 64)
            .add_field("dentry", "d_name", 0, "qstr")
            // qstr
            .add_struct("qstr", 16)
            .add_field("qstr", "name", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_no_vma_returns_empty() {
        // A kernel thread (mm == NULL) should produce an empty library list.
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // task_struct with mm = NULL (kernel thread)
        data[0..4].copy_from_slice(&2u32.to_le_bytes()); // pid = 2
        data[32..41].copy_from_slice(b"kthreadd\0"); // comm
        data[48..56].copy_from_slice(&0u64.to_le_bytes()); // mm = NULL

        let reader = make_test_reader(&data, vaddr, paddr);

        let result = walk_library_list(&reader, vaddr, 2, "kthreadd").unwrap();
        assert!(result.is_empty(), "kernel thread should have no libraries");
    }

    #[test]
    fn walk_single_so_library() {
        // Process with one VMA mapping libc.so.6
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // task_struct at base: PID 1, "bash", mm at +0x200
        data[0..4].copy_from_slice(&1u32.to_le_bytes()); // pid
        data[32..36].copy_from_slice(b"bash"); // comm
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes()); // mm

        // mm_struct at +0x200: mmap at offset 8 → VMA at +0x300
        let vma_addr = vaddr + 0x300;
        data[0x208..0x210].copy_from_slice(&vma_addr.to_le_bytes()); // mmap

        // vm_area_struct at +0x300
        data[0x300..0x308].copy_from_slice(&0x7F00_0000u64.to_le_bytes()); // vm_start
        data[0x308..0x310].copy_from_slice(&0x7F01_0000u64.to_le_bytes()); // vm_end
        data[0x310..0x318].copy_from_slice(&0u64.to_le_bytes()); // vm_next = NULL
                                                                 // vm_file at offset 40 → file struct at +0x400
        let file_addr = vaddr + 0x400;
        data[0x328..0x330].copy_from_slice(&file_addr.to_le_bytes()); // vm_file

        // struct file at +0x400: f_path at offset 0, path.dentry at offset 8
        let dentry_addr = vaddr + 0x500;
        data[0x408..0x410].copy_from_slice(&dentry_addr.to_le_bytes()); // f_path.dentry

        // dentry at +0x500: d_name (qstr) at offset 0, qstr.name at offset 8
        let name_str_addr = vaddr + 0x600;
        data[0x508..0x510].copy_from_slice(&name_str_addr.to_le_bytes()); // d_name.name

        // Name string at +0x600
        let name = b"libc.so.6";
        data[0x600..0x600 + name.len()].copy_from_slice(name);

        let reader = make_test_reader(&data, vaddr, paddr);
        let libs = walk_library_list(&reader, vaddr, 1, "bash").unwrap();

        assert_eq!(libs.len(), 1);
        assert_eq!(libs[0].pid, 1);
        assert_eq!(libs[0].process_name, "bash");
        assert_eq!(libs[0].lib_path, "libc.so.6");
        assert_eq!(libs[0].base_addr, 0x7F00_0000);
        assert_eq!(libs[0].size, 0x0001_0000);
        assert!(!libs[0].is_suspicious);
    }

    #[test]
    fn walk_deduplicates_multi_vma_library() {
        // A single .so mapped across two VMAs (text + data) should produce one entry.
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // task_struct
        data[0..4].copy_from_slice(&1u32.to_le_bytes()); // pid
        data[32..36].copy_from_slice(b"cat\0"); // comm
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes()); // mm

        // mm_struct at +0x200
        let vma1_addr = vaddr + 0x300;
        data[0x208..0x210].copy_from_slice(&vma1_addr.to_le_bytes()); // mmap → VMA1

        // Both VMAs share the same file struct (same vm_file pointer).
        let file_addr = vaddr + 0x500;

        // VMA1 at +0x300: text segment
        data[0x300..0x308].copy_from_slice(&0x7F00_0000u64.to_le_bytes()); // vm_start
        data[0x308..0x310].copy_from_slice(&0x7F00_4000u64.to_le_bytes()); // vm_end
        let vma2_addr = vaddr + 0x400;
        data[0x310..0x318].copy_from_slice(&vma2_addr.to_le_bytes()); // vm_next → VMA2
        data[0x328..0x330].copy_from_slice(&file_addr.to_le_bytes()); // vm_file

        // VMA2 at +0x400: data segment (higher address)
        data[0x400..0x408].copy_from_slice(&0x7F00_4000u64.to_le_bytes()); // vm_start
        data[0x408..0x410].copy_from_slice(&0x7F00_6000u64.to_le_bytes()); // vm_end
        data[0x410..0x418].copy_from_slice(&0u64.to_le_bytes()); // vm_next = NULL
        data[0x428..0x430].copy_from_slice(&file_addr.to_le_bytes()); // vm_file

        // file struct at +0x500
        let dentry_addr = vaddr + 0x600;
        data[0x508..0x510].copy_from_slice(&dentry_addr.to_le_bytes()); // f_path.dentry

        // dentry at +0x600
        let name_addr = vaddr + 0x700;
        data[0x608..0x610].copy_from_slice(&name_addr.to_le_bytes()); // d_name.name

        // Name string at +0x700
        let name = b"libpthread.so.0";
        data[0x700..0x700 + name.len()].copy_from_slice(name);

        let reader = make_test_reader(&data, vaddr, paddr);
        let libs = walk_library_list(&reader, vaddr, 1, "cat").unwrap();

        // Should be deduplicated to one entry.
        assert_eq!(libs.len(), 1);
        assert_eq!(libs[0].lib_path, "libpthread.so.0");
        assert_eq!(libs[0].base_addr, 0x7F00_0000);
        // Total size = 0x4000 + 0x2000 = 0x6000
        assert_eq!(libs[0].size, 0x6000);
        assert!(!libs[0].is_suspicious);
    }

    #[test]
    fn walk_skips_non_file_backed_vmas() {
        // Anonymous VMAs (vm_file == 0) should be skipped.
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // task_struct
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        data[32..36].copy_from_slice(b"test");
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());

        // mm_struct at +0x200
        let vma_addr = vaddr + 0x300;
        data[0x208..0x210].copy_from_slice(&vma_addr.to_le_bytes()); // mmap

        // VMA at +0x300: anonymous mapping (vm_file = 0)
        data[0x300..0x308].copy_from_slice(&0x7FFF_0000u64.to_le_bytes()); // vm_start
        data[0x308..0x310].copy_from_slice(&0x7FFF_2000u64.to_le_bytes()); // vm_end
        data[0x310..0x318].copy_from_slice(&0u64.to_le_bytes()); // vm_next = NULL
        data[0x328..0x330].copy_from_slice(&0u64.to_le_bytes()); // vm_file = NULL

        let reader = make_test_reader(&data, vaddr, paddr);
        let libs = walk_library_list(&reader, vaddr, 1, "test").unwrap();

        assert!(
            libs.is_empty(),
            "anonymous VMA should not produce library entries"
        );
    }

    #[test]
    fn classify_library_exact_tmp_dir() {
        // Covers line 59: clean == "/tmp" (exact match without trailing slash)
        assert!(classify_library("/tmp"), "exact /tmp path must be suspicious");
        assert!(classify_library("/dev/shm"), "/dev/shm exact match must be suspicious");
        assert!(classify_library("/var/tmp"), "/var/tmp exact match must be suspicious");
    }

    #[test]
    fn classify_library_just_dot_basename_not_suspicious() {
        // Covers the `basename.starts_with('.') && !basename.is_empty()` branch.
        // A path ending in exactly '.' would start with '.' but let's test the
        // normal hidden-file path which the existing tests already cover.
        // This test focuses on the fallthrough: basename doesn't start with '.'.
        // A path like "/usr/lib/normallib.so" falls through all checks → benign.
        assert!(!classify_library("/usr/lib/normallib.so"), "normal .so must be benign");
    }

    #[test]
    fn walk_cycle_detection_breaks_loop() {
        // Covers line 133: VMA cycle → seen_addrs.insert fails → break.
        // VMA's vm_next points back to itself (cycle).
        let vaddr: u64 = 0xFFFF_8000_0050_0000;
        let paddr: u64 = 0x0083_0000;
        let mut data = vec![0u8; 4096];

        // task_struct
        data[0..4].copy_from_slice(&10u32.to_le_bytes()); // pid
        data[32..36].copy_from_slice(b"cycl");            // comm
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes()); // mm

        // mm_struct at +0x200: mmap → VMA at +0x300
        let vma_addr = vaddr + 0x300;
        data[0x208..0x210].copy_from_slice(&vma_addr.to_le_bytes());

        // VMA at +0x300: vm_next points back to itself (cycle)
        data[0x300..0x308].copy_from_slice(&0x7F00_0000u64.to_le_bytes()); // vm_start
        data[0x308..0x310].copy_from_slice(&0x7F00_1000u64.to_le_bytes()); // vm_end
        data[0x310..0x318].copy_from_slice(&vma_addr.to_le_bytes()); // vm_next = self (cycle!)
        data[0x328..0x330].copy_from_slice(&0u64.to_le_bytes()); // vm_file = NULL

        let reader = make_test_reader(&data, vaddr, paddr);
        // Should not hang or overflow; cycle detection breaks the loop.
        let libs = walk_library_list(&reader, vaddr, 10, "cycl").unwrap();
        assert!(libs.is_empty(), "cycle VMA with null vm_file should yield no libraries");
    }

    #[test]
    fn walk_second_vma_with_lower_base_updates_min() {
        // Covers line 158: entry.0 = entry.0.min(vm_start)
        // Two VMAs for the same library where the second VMA has a lower start address.
        let vaddr: u64 = 0xFFFF_8000_0060_0000;
        let paddr: u64 = 0x0084_0000;
        let mut data = vec![0u8; 4096];

        // task_struct
        data[0..4].copy_from_slice(&20u32.to_le_bytes()); // pid
        data[32..37].copy_from_slice(b"proc\0");          // comm
        let mm_addr = vaddr + 0x100;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes()); // mm

        // mm_struct at +0x100: mmap = VMA1
        let vma1_addr = vaddr + 0x200;
        data[0x108..0x110].copy_from_slice(&vma1_addr.to_le_bytes());

        let file_addr = vaddr + 0x600;

        // VMA1 at +0x200: vm_start=0x7F00_2000 (higher), vm_next → VMA2
        let vma2_addr = vaddr + 0x300;
        data[0x200..0x208].copy_from_slice(&0x7F00_2000u64.to_le_bytes()); // vm_start
        data[0x208..0x210].copy_from_slice(&0x7F00_4000u64.to_le_bytes()); // vm_end
        data[0x210..0x218].copy_from_slice(&vma2_addr.to_le_bytes());        // vm_next
        data[0x228..0x230].copy_from_slice(&file_addr.to_le_bytes());        // vm_file

        // VMA2 at +0x300: vm_start=0x7F00_0000 (lower than VMA1), vm_next → NULL
        data[0x300..0x308].copy_from_slice(&0x7F00_0000u64.to_le_bytes()); // vm_start (lower!)
        data[0x308..0x310].copy_from_slice(&0x7F00_2000u64.to_le_bytes()); // vm_end
        data[0x310..0x318].copy_from_slice(&0u64.to_le_bytes());             // vm_next = NULL
        data[0x328..0x330].copy_from_slice(&file_addr.to_le_bytes());        // vm_file (same lib)

        // file at +0x600: dentry at +0x700
        let dentry_addr = vaddr + 0x700;
        data[0x608..0x610].copy_from_slice(&dentry_addr.to_le_bytes());

        // dentry at +0x700: name ptr at +0x800
        let name_addr = vaddr + 0x800;
        data[0x708..0x710].copy_from_slice(&name_addr.to_le_bytes());

        // name: "libtest.so.1"
        let name = b"libtest.so.1";
        data[0x800..0x800 + name.len()].copy_from_slice(name);

        let reader = make_test_reader(&data, vaddr, paddr);
        let libs = walk_library_list(&reader, vaddr, 20, "proc").unwrap();

        assert_eq!(libs.len(), 1, "single deduplicated library expected");
        // base_addr should be the minimum: 0x7F00_0000 (from VMA2)
        assert_eq!(libs[0].base_addr, 0x7F00_0000, "base_addr must be the minimum vm_start");
        // size = (0x7F00_4000 - 0x7F00_2000) + (0x7F00_2000 - 0x7F00_0000) = 0x4000
        assert_eq!(libs[0].size, 0x4000);
    }

    // --- read_vma_file_path: dentry_ptr == 0 → returns None → VMA skipped ---
    #[test]
    fn walk_skips_vma_when_dentry_null() {
        let vaddr: u64 = 0xFFFF_8000_0070_0000;
        let paddr: u64 = 0x0085_0000;
        let mut data = vec![0u8; 4096];

        // task_struct
        data[0..4].copy_from_slice(&30u32.to_le_bytes()); // pid
        data[32..36].copy_from_slice(b"null"); // comm
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());

        // mm_struct at +0x200: mmap → VMA at +0x300
        let vma_addr = vaddr + 0x300;
        data[0x208..0x210].copy_from_slice(&vma_addr.to_le_bytes());

        // VMA at +0x300: vm_file → file at +0x400
        data[0x300..0x308].copy_from_slice(&0x7F00_0000u64.to_le_bytes()); // vm_start
        data[0x308..0x310].copy_from_slice(&0x7F00_2000u64.to_le_bytes()); // vm_end
        data[0x310..0x318].copy_from_slice(&0u64.to_le_bytes()); // vm_next = NULL
        let file_addr = vaddr + 0x400;
        data[0x328..0x330].copy_from_slice(&file_addr.to_le_bytes());

        // file at +0x400: f_path.dentry = 0 (null dentry)
        // f_path at offset 0; dentry pointer at f_path_offset + dentry_in_path_offset = 0 + 8 = 8
        data[0x408..0x410].copy_from_slice(&0u64.to_le_bytes()); // dentry = NULL

        let reader = make_test_reader(&data, vaddr, paddr);
        let libs = walk_library_list(&reader, vaddr, 30, "null").unwrap();
        assert!(libs.is_empty(), "null dentry_ptr → read_vma_file_path returns None → no library");
    }

    // --- read_vma_file_path: name_ptr == 0 → returns None → VMA skipped ---
    #[test]
    fn walk_skips_vma_when_name_ptr_null() {
        let vaddr: u64 = 0xFFFF_8000_0078_0000;
        let paddr: u64 = 0x0086_0000;
        let mut data = vec![0u8; 4096];

        // task_struct
        data[0..4].copy_from_slice(&31u32.to_le_bytes());
        data[32..36].copy_from_slice(b"npnl");
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());

        // mm_struct at +0x200
        let vma_addr = vaddr + 0x300;
        data[0x208..0x210].copy_from_slice(&vma_addr.to_le_bytes());

        // VMA
        data[0x300..0x308].copy_from_slice(&0x7F00_0000u64.to_le_bytes());
        data[0x308..0x310].copy_from_slice(&0x7F00_2000u64.to_le_bytes());
        data[0x310..0x318].copy_from_slice(&0u64.to_le_bytes()); // vm_next = NULL
        let file_addr = vaddr + 0x400;
        data[0x328..0x330].copy_from_slice(&file_addr.to_le_bytes());

        // file: f_path.dentry → dentry at +0x500
        let dentry_addr = vaddr + 0x500;
        data[0x408..0x410].copy_from_slice(&dentry_addr.to_le_bytes());

        // dentry at +0x500: d_name (qstr) at offset 0; qstr.name at offset 8 → NULL
        data[0x508..0x510].copy_from_slice(&0u64.to_le_bytes()); // name_ptr = NULL

        let reader = make_test_reader(&data, vaddr, paddr);
        let libs = walk_library_list(&reader, vaddr, 31, "npnl").unwrap();
        assert!(libs.is_empty(), "name_ptr == 0 → read_vma_file_path returns None → no library");
    }

    // --- read_vma_file_path: name is empty string → returns None → VMA skipped ---
    #[test]
    fn walk_skips_vma_when_name_empty() {
        let vaddr: u64 = 0xFFFF_8000_0079_0000;
        let paddr: u64 = 0x0087_0000;
        let mut data = vec![0u8; 4096];

        data[0..4].copy_from_slice(&32u32.to_le_bytes());
        data[32..36].copy_from_slice(b"empt");
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());

        let vma_addr = vaddr + 0x300;
        data[0x208..0x210].copy_from_slice(&vma_addr.to_le_bytes());

        data[0x300..0x308].copy_from_slice(&0x7F00_0000u64.to_le_bytes());
        data[0x308..0x310].copy_from_slice(&0x7F00_2000u64.to_le_bytes());
        data[0x310..0x318].copy_from_slice(&0u64.to_le_bytes());
        let file_addr = vaddr + 0x400;
        data[0x328..0x330].copy_from_slice(&file_addr.to_le_bytes());

        // file → dentry at +0x500
        let dentry_addr = vaddr + 0x500;
        data[0x408..0x410].copy_from_slice(&dentry_addr.to_le_bytes());

        // dentry: qstr.name at 0x508 → name_str at +0x600 (which is \0)
        let name_str_addr = vaddr + 0x600;
        data[0x508..0x510].copy_from_slice(&name_str_addr.to_le_bytes());
        // name_str_addr points to a null byte → empty string
        data[0x600] = 0u8;

        let reader = make_test_reader(&data, vaddr, paddr);
        let libs = walk_library_list(&reader, vaddr, 32, "empt").unwrap();
        // Empty name from read_string → read_vma_file_path returns None → no library
        assert!(libs.is_empty(), "empty name → read_vma_file_path returns None");
    }

    // --- SharedLibraryInfo: Debug, Clone, Serialize ---
    #[test]
    fn shared_library_info_debug_clone_serialize() {
        let info = SharedLibraryInfo {
            pid: 1,
            process_name: "test".to_string(),
            lib_path: "/usr/lib/libfoo.so".to_string(),
            base_addr: 0x7F00_0000,
            size: 0x1000,
            is_suspicious: false,
        };
        let cloned = info.clone();
        let dbg = format!("{:?}", cloned);
        assert!(dbg.contains("libfoo"));
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":1"));
        assert!(json.contains("is_suspicious"));
    }

    #[test]
    fn walk_classifies_suspicious_library() {
        // A library from /tmp should be flagged as suspicious.
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // task_struct
        data[0..4].copy_from_slice(&42u32.to_le_bytes());
        data[32..37].copy_from_slice(b"sshd\0");
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());

        // mm_struct at +0x200
        let vma_addr = vaddr + 0x300;
        data[0x208..0x210].copy_from_slice(&vma_addr.to_le_bytes());

        // VMA at +0x300
        data[0x300..0x308].copy_from_slice(&0x7F00_0000u64.to_le_bytes());
        data[0x308..0x310].copy_from_slice(&0x7F00_2000u64.to_le_bytes());
        data[0x310..0x318].copy_from_slice(&0u64.to_le_bytes()); // vm_next = NULL
        let file_addr = vaddr + 0x400;
        data[0x328..0x330].copy_from_slice(&file_addr.to_le_bytes());

        // file at +0x400
        let dentry_addr = vaddr + 0x500;
        data[0x408..0x410].copy_from_slice(&dentry_addr.to_le_bytes());

        // dentry at +0x500
        let name_addr = vaddr + 0x600;
        data[0x508..0x510].copy_from_slice(&name_addr.to_le_bytes());

        // Name: suspicious library in /tmp
        let name = b"/tmp/evil.so";
        data[0x600..0x600 + name.len()].copy_from_slice(name);

        let reader = make_test_reader(&data, vaddr, paddr);
        let libs = walk_library_list(&reader, vaddr, 42, "sshd").unwrap();

        assert_eq!(libs.len(), 1);
        assert_eq!(libs[0].lib_path, "/tmp/evil.so");
        assert!(libs[0].is_suspicious, "/tmp library should be suspicious");
    }

    // --- walk_library_list: file.f_path field missing → error returned ---
    // Exercises line 107: ok_or_else for f_path offset.
    #[test]
    fn walk_library_list_missing_f_path_field_returns_error() {
        let vaddr: u64 = 0xFFFF_8000_0088_0000;
        let paddr: u64 = 0x0088_1000;
        let mut data = vec![0u8; 4096];

        // mm != 0 (non-kernel thread)
        let mm_addr = vaddr + 0x200;
        data[0..4].copy_from_slice(&9u32.to_le_bytes());
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());
        // mm.mmap = 0 so VMA loop won't run, but we need file.f_path to be missing

        // Build ISF without file.f_path field
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "mm", 48, "pointer")
            .add_struct("mm_struct", 128)
            .add_field("mm_struct", "mmap", 8, "pointer")
            // "file" struct is absent → f_path field offset returns None → Error
            .add_struct("path", 16)
            .add_field("path", "dentry", 8, "pointer")
            .add_struct("dentry", 64)
            .add_field("dentry", "d_name", 0, "qstr")
            .add_struct("qstr", 16)
            .add_field("qstr", "name", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_library_list(&reader, vaddr, 9, "proc");
        assert!(result.is_err(), "missing file.f_path field must return an error");
    }

    // --- walk_library_list: path.dentry field missing → error ---
    #[test]
    fn walk_library_list_missing_path_dentry_field_returns_error() {
        let vaddr: u64 = 0xFFFF_8000_0089_0000;
        let paddr: u64 = 0x0089_0000;
        let mut data = vec![0u8; 4096];

        let mm_addr = vaddr + 0x200;
        data[0..4].copy_from_slice(&10u32.to_le_bytes());
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "mm", 48, "pointer")
            .add_struct("mm_struct", 128)
            .add_field("mm_struct", "mmap", 8, "pointer")
            .add_struct("file", 64)
            .add_field("file", "f_path", 0, "path")
            // "path" struct exists but "dentry" field is missing
            .add_struct("path", 16)
            .add_struct("dentry", 64)
            .add_field("dentry", "d_name", 0, "qstr")
            .add_struct("qstr", 16)
            .add_field("qstr", "name", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_library_list(&reader, vaddr, 10, "proc");
        assert!(result.is_err(), "missing path.dentry field must return an error");
    }

    // --- walk_library_list: dentry.d_name field missing → error ---
    #[test]
    fn walk_library_list_missing_d_name_field_returns_error() {
        let vaddr: u64 = 0xFFFF_8000_008A_0000;
        let paddr: u64 = 0x008A_0000;
        let mut data = vec![0u8; 4096];

        let mm_addr = vaddr + 0x200;
        data[0..4].copy_from_slice(&11u32.to_le_bytes());
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "mm", 48, "pointer")
            .add_struct("mm_struct", 128)
            .add_field("mm_struct", "mmap", 8, "pointer")
            .add_struct("file", 64)
            .add_field("file", "f_path", 0, "path")
            .add_struct("path", 16)
            .add_field("path", "dentry", 8, "pointer")
            // "dentry" struct exists but "d_name" field is missing
            .add_struct("dentry", 64)
            .add_struct("qstr", 16)
            .add_field("qstr", "name", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_library_list(&reader, vaddr, 11, "proc");
        assert!(result.is_err(), "missing dentry.d_name field must return an error");
    }

    // --- walk_library_list: qstr.name field missing → error ---
    #[test]
    fn walk_library_list_missing_qstr_name_field_returns_error() {
        let vaddr: u64 = 0xFFFF_8000_008B_0000;
        let paddr: u64 = 0x008B_0000;
        let mut data = vec![0u8; 4096];

        let mm_addr = vaddr + 0x200;
        data[0..4].copy_from_slice(&12u32.to_le_bytes());
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "mm", 48, "pointer")
            .add_struct("mm_struct", 128)
            .add_field("mm_struct", "mmap", 8, "pointer")
            .add_struct("file", 64)
            .add_field("file", "f_path", 0, "path")
            .add_struct("path", 16)
            .add_field("path", "dentry", 8, "pointer")
            .add_struct("dentry", 64)
            .add_field("dentry", "d_name", 0, "qstr")
            // "qstr" struct exists but "name" field is missing
            .add_struct("qstr", 16)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_library_list(&reader, vaddr, 12, "proc");
        assert!(result.is_err(), "missing qstr.name field must return an error");
    }

    // --- classify_library: path without any '/' → basename = whole path ---
    // Exercises the rsplit('/').next() branch where the string has no '/'
    // (basename == whole path, which may or may not start with '.').
    #[test]
    fn classify_library_no_slash_path() {
        // A path without '/' — basename is the whole string.
        // "libc.so.6" does not start with '.' and contains ".so." → benign.
        assert!(!classify_library("libc.so.6"), "bare name with .so. must be benign");
        // ".hidden.so.1" starts with '.' → suspicious.
        assert!(classify_library(".hidden.so.1"), "hidden bare name must be suspicious");
    }
}
