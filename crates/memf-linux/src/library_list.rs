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
    todo!("walk_library_list: VMA walking not yet implemented")
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

    #[test]
    fn walk_no_vma_returns_empty() {
        // A kernel thread (mm == NULL) should produce an empty library list.
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // task_struct with mm = NULL (kernel thread)
        data[0..4].copy_from_slice(&2u32.to_le_bytes()); // pid = 2
        data[32..41].copy_from_slice(b"kthreadd\0"); // comm
        data[48..56].copy_from_slice(&0u64.to_le_bytes()); // mm = NULL

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "mm", 48, "pointer")
            .add_struct("mm_struct", 128)
            .add_field("mm_struct", "mmap", 8, "pointer")
            .add_struct("vm_area_struct", 64)
            .add_field("vm_area_struct", "vm_start", 0, "unsigned long")
            .add_field("vm_area_struct", "vm_end", 8, "unsigned long")
            .add_field("vm_area_struct", "vm_next", 16, "pointer")
            .add_field("vm_area_struct", "vm_file", 40, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_library_list(&reader, vaddr, 2, "kthreadd").unwrap();
        assert!(result.is_empty(), "kernel thread should have no libraries");
    }
}
