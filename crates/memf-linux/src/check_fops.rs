//! Linux file_operations table hook detector.
//!
//! Rootkits often replace function pointers in `file_operations` structs
//! (read, write, open, etc.) for /proc entries or device files. By comparing
//! these pointers against the kernel text range (`_stext`..`_etext`), we can
//! detect hooks pointing to non-kernel code (loaded module code or injected
//! memory).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Function pointer field names within the `file_operations` struct.
const FOP_FIELDS: &[&str] = &[
    "read",
    "write",
    "open",
    "release",
    "unlocked_ioctl",
    "llseek",
    "mmap",
    "poll",
    "read_iter",
    "write_iter",
];

/// Information about a file_operations struct with potential hooks.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FopsHookInfo {
    /// Path of the /proc or device entry, e.g. "/proc/modules".
    pub path: String,
    /// Virtual address of the file_operations struct.
    pub struct_address: u64,
    /// List of function pointers that were checked.
    pub hooked_functions: Vec<HookedFop>,
    /// Whether any function pointer targets outside kernel text.
    pub is_suspicious: bool,
}

/// A single function pointer from a file_operations struct.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HookedFop {
    /// Name of the function pointer field, e.g. "read", "write".
    pub function_name: String,
    /// Virtual address the function pointer targets.
    pub target_address: u64,
    /// Whether the target falls within the kernel text section.
    pub is_in_kernel_text: bool,
}

/// Check whether an address falls within the kernel text section.
///
/// Returns `true` if `addr` is in `[kernel_start, kernel_end]`.
pub fn is_kernel_text_address(addr: u64, kernel_start: u64, kernel_end: u64) -> bool {
    addr >= kernel_start && addr <= kernel_end
}

/// Read function pointers from a `file_operations` struct and classify each.
///
/// For each known field in [`FOP_FIELDS`], reads the pointer value. Non-null
/// pointers are checked against the kernel text range.
pub fn check_fops_entry<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    fops_addr: u64,
    kernel_start: u64,
    kernel_end: u64,
) -> Vec<HookedFop> {
    let mut results = Vec::new();

    for &field_name in FOP_FIELDS {
        let ptr: u64 = match reader.read_pointer(fops_addr, "file_operations", field_name) {
            Ok(p) => p,
            Err(_) => continue, // Field not in symbol table, skip
        };

        // Skip null pointers — they mean the operation is not implemented
        if ptr == 0 {
            continue;
        }

        results.push(HookedFop {
            function_name: field_name.to_string(),
            target_address: ptr,
            is_in_kernel_text: is_kernel_text_address(ptr, kernel_start, kernel_end),
        });
    }

    results
}

/// Maximum number of /proc entries to walk (cycle protection).
const MAX_PROC_ENTRIES: usize = 10_000;

/// Scan key /proc entries for file_operations hooks.
///
/// Looks up `proc_root` (the root /proc directory entry), walks the
/// `proc_dir_entry` tree via `subdir`/`next`, and for each entry
/// with a non-null `proc_fops` pointer, reads the `file_operations` struct
/// and checks function pointers against the kernel text range.
///
/// Returns `Ok(Vec::new())` if required symbols (`proc_root`, `_stext`,
/// `_etext`) are missing.
pub fn scan_proc_fops<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<FopsHookInfo>> {
    // Look up required symbols; return empty if missing (graceful degradation)
    let Some(proc_root) = reader.symbols().symbol_address("proc_root") else {
        return Ok(Vec::new());
    };
    let Some(kernel_start) = reader.symbols().symbol_address("_stext") else {
        return Ok(Vec::new());
    };
    let Some(kernel_end) = reader.symbols().symbol_address("_etext") else {
        return Ok(Vec::new());
    };

    let mut results = Vec::new();

    // Walk the proc_dir_entry tree starting from proc_root's subdir
    let mut stack = Vec::new();
    let subdir: u64 = reader
        .read_pointer(proc_root, "proc_dir_entry", "subdir")
        .unwrap_or(0);
    if subdir != 0 {
        stack.push((subdir, "/proc".to_string()));
    }

    let mut visited = 0usize;
    while let Some((entry_addr, parent_path)) = stack.pop() {
        if visited >= MAX_PROC_ENTRIES {
            break;
        }
        visited += 1;

        // Read the entry name
        let name = reader
            .read_field_string(entry_addr, "proc_dir_entry", "name", 128)
            .unwrap_or_else(|_| "<unknown>".to_string());
        let path = format!("{parent_path}/{name}");

        // Check if this entry has a proc_fops pointer
        let fops_addr: u64 = reader
            .read_pointer(entry_addr, "proc_dir_entry", "proc_fops")
            .unwrap_or(0);

        if fops_addr != 0 {
            let hooked_functions = check_fops_entry(reader, fops_addr, kernel_start, kernel_end);
            let is_suspicious = hooked_functions.iter().any(|f| !f.is_in_kernel_text);

            results.push(FopsHookInfo {
                path: path.clone(),
                struct_address: fops_addr,
                hooked_functions,
                is_suspicious,
            });
        }

        // Recurse into subdirectories
        let child: u64 = reader
            .read_pointer(entry_addr, "proc_dir_entry", "subdir")
            .unwrap_or(0);
        if child != 0 {
            stack.push((child, path));
        }

        // Follow the next sibling
        let next: u64 = reader
            .read_pointer(entry_addr, "proc_dir_entry", "next")
            .unwrap_or(0);
        if next != 0 {
            stack.push((next, parent_path));
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // -----------------------------------------------------------------------
    // is_kernel_text_address tests
    // -----------------------------------------------------------------------

    #[test]
    fn is_kernel_text_address_inside() {
        let start = 0xFFFF_8000_0000_0000u64;
        let end = 0xFFFF_8000_00FF_FFFFu64;

        // Exactly at start
        assert!(is_kernel_text_address(start, start, end));
        // In the middle
        assert!(is_kernel_text_address(start + 0x1000, start, end));
        // Exactly at end
        assert!(is_kernel_text_address(end, start, end));
    }

    #[test]
    fn is_kernel_text_address_outside() {
        let start = 0xFFFF_8000_0000_0000u64;
        let end = 0xFFFF_8000_00FF_FFFFu64;

        // One below start
        assert!(!is_kernel_text_address(start - 1, start, end));
        // One above end
        assert!(!is_kernel_text_address(end + 1, start, end));
        // Way outside (module space)
        assert!(!is_kernel_text_address(0xFFFF_C900_DEAD_BEEF, start, end));
        // Zero address
        assert!(!is_kernel_text_address(0, start, end));
    }

    // -----------------------------------------------------------------------
    // check_fops_entry tests
    // -----------------------------------------------------------------------

    /// Helper: build a test reader with a file_operations struct in memory.
    fn make_fops_reader(
        fops_data: &[u8],
        fops_vaddr: u64,
        fops_paddr: u64,
        kernel_start: u64,
        kernel_end: u64,
    ) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("file_operations", 256)
            .add_field("file_operations", "read", 0, "pointer")
            .add_field("file_operations", "write", 8, "pointer")
            .add_field("file_operations", "open", 16, "pointer")
            .add_field("file_operations", "release", 24, "pointer")
            .add_field("file_operations", "unlocked_ioctl", 32, "pointer")
            .add_field("file_operations", "llseek", 40, "pointer")
            .add_field("file_operations", "mmap", 48, "pointer")
            .add_field("file_operations", "poll", 56, "pointer")
            .add_field("file_operations", "read_iter", 64, "pointer")
            .add_field("file_operations", "write_iter", 72, "pointer")
            .add_symbol("_stext", kernel_start)
            .add_symbol("_etext", kernel_end)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(fops_vaddr, fops_paddr, ptflags::WRITABLE)
            .write_phys(fops_paddr, fops_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn classify_fops_all_kernel() {
        let kernel_start: u64 = 0xFFFF_8000_0000_0000;
        let kernel_end: u64 = 0xFFFF_8000_00FF_FFFF;
        let fops_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let fops_paddr: u64 = 0x0080_0000;

        // Build a file_operations struct where all pointers are in kernel text
        let mut fops_data = vec![0u8; 4096];
        let kernel_func = kernel_start + 0x1000; // Solidly inside kernel text
        for i in 0..FOP_FIELDS.len() {
            let offset = i * 8;
            fops_data[offset..offset + 8].copy_from_slice(&kernel_func.to_le_bytes());
        }

        let reader = make_fops_reader(&fops_data, fops_vaddr, fops_paddr, kernel_start, kernel_end);

        let results = check_fops_entry(&reader, fops_vaddr, kernel_start, kernel_end);

        // All function pointers should be classified as in-kernel
        assert!(!results.is_empty());
        for fop in &results {
            assert!(
                fop.is_in_kernel_text,
                "function {} at {:#x} should be in kernel text",
                fop.function_name, fop.target_address,
            );
        }
    }

    #[test]
    fn classify_fops_hooked_pointer() {
        let kernel_start: u64 = 0xFFFF_8000_0000_0000;
        let kernel_end: u64 = 0xFFFF_8000_00FF_FFFF;
        let fops_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let fops_paddr: u64 = 0x0080_0000;

        // Build file_operations: read points to module space, rest are kernel
        let mut fops_data = vec![0u8; 4096];
        let kernel_func = kernel_start + 0x1000;
        let hooked_addr: u64 = 0xFFFF_C900_DEAD_BEEF; // Outside kernel text (module space)

        // read (offset 0) is hooked
        fops_data[0..8].copy_from_slice(&hooked_addr.to_le_bytes());
        // write through write_iter are kernel
        for i in 1..FOP_FIELDS.len() {
            let offset = i * 8;
            fops_data[offset..offset + 8].copy_from_slice(&kernel_func.to_le_bytes());
        }

        let reader = make_fops_reader(&fops_data, fops_vaddr, fops_paddr, kernel_start, kernel_end);

        let results = check_fops_entry(&reader, fops_vaddr, kernel_start, kernel_end);

        // Find the "read" entry
        let read_fop = results.iter().find(|f| f.function_name == "read").unwrap();
        assert!(!read_fop.is_in_kernel_text);
        assert_eq!(read_fop.target_address, hooked_addr);

        // All others should be in-kernel
        for fop in results.iter().filter(|f| f.function_name != "read") {
            assert!(
                fop.is_in_kernel_text,
                "function {} should be in kernel text",
                fop.function_name,
            );
        }
    }

    // -----------------------------------------------------------------------
    // scan_proc_fops tests
    // -----------------------------------------------------------------------

    #[test]
    fn scan_proc_fops_no_symbol() {
        // No proc_root symbol → should return Ok(empty vec), not an error
        let isf = IsfBuilder::new()
            .add_struct("file_operations", 256)
            .add_field("file_operations", "read", 0, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = scan_proc_fops(&reader).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn scan_proc_fops_missing_stext_returns_empty() {
        // proc_root present but _stext absent → graceful empty
        let isf = IsfBuilder::new()
            .add_struct("file_operations", 256)
            .add_field("file_operations", "read", 0, "pointer")
            .add_symbol("proc_root", 0xFFFF_8000_0010_0000)
            // _stext intentionally omitted
            .add_symbol("_etext", 0xFFFF_8000_00FF_FFFF)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = scan_proc_fops(&reader).unwrap();
        assert!(results.is_empty(), "missing _stext should yield empty vec");
    }

    #[test]
    fn scan_proc_fops_missing_etext_returns_empty() {
        // proc_root + _stext present but _etext absent → graceful empty
        let isf = IsfBuilder::new()
            .add_struct("file_operations", 256)
            .add_field("file_operations", "read", 0, "pointer")
            .add_symbol("proc_root", 0xFFFF_8000_0010_0000)
            .add_symbol("_stext", 0xFFFF_8000_0000_0000)
            // _etext intentionally omitted
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = scan_proc_fops(&reader).unwrap();
        assert!(results.is_empty(), "missing _etext should yield empty vec");
    }

    #[test]
    fn check_fops_entry_null_pointer_skipped() {
        // file_operations struct where all pointers are NULL → no results
        let kernel_start: u64 = 0xFFFF_8000_0000_0000;
        let kernel_end: u64 = 0xFFFF_8000_00FF_FFFF;
        let fops_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let fops_paddr: u64 = 0x0080_0000;

        // All zeros (null pointers) in the fops struct
        let fops_data = vec![0u8; 4096];

        let reader = make_fops_reader(&fops_data, fops_vaddr, fops_paddr, kernel_start, kernel_end);
        let results = check_fops_entry(&reader, fops_vaddr, kernel_start, kernel_end);

        assert!(
            results.is_empty(),
            "all-null fops struct should produce no HookedFop entries"
        );
    }
}
