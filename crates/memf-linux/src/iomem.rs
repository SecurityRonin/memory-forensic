//! I/O memory resource region enumeration.
//!
//! Enumerates I/O memory resource regions from the `iomem_resource` kernel
//! structure. Shows system memory layout, ACPI regions, PCI MMIO, firmware
//! areas. Useful for understanding hardware layout and detecting suspicious
//! memory-mapped regions. Equivalent to `/proc/iomem` from memory.
//!
//! The kernel maintains a tree of `struct resource` rooted at `iomem_resource`.
//! Each resource has `start`, `end`, `name`, `flags`, and pointers to `child`
//! and `sibling` forming a tree of nested memory regions.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Maximum number of resource entries to walk (runaway protection).
const MAX_RESOURCES: usize = 10_000;

/// Information about a single I/O memory resource region.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IoMemRegion {
    /// Start physical address of the region.
    pub start: u64,
    /// End physical address of the region (inclusive).
    pub end: u64,
    /// Human-readable name of the region (e.g., "System RAM", "ACPI Tables").
    pub name: String,
    /// Resource flags from the kernel (`IORESOURCE_*` bitmask).
    pub flags: u64,
    /// Depth in the resource tree (0 = top-level).
    pub depth: u32,
    /// Whether this region is classified as suspicious.
    pub is_suspicious: bool,
}

/// Classify whether an I/O memory region is suspicious.
///
/// A region is suspicious if:
/// - The name is empty and the region spans more than 1 MiB (large unnamed regions).
/// - The name contains unusual characters (control chars, non-ASCII).
/// - The region overlaps kernel text (`0xffffffff81000000..0xffffffff82000000`)
///   but is not named "Kernel code".
pub fn classify_iomem(name: &str, start: u64, end: u64) -> bool {
    // Empty name on a large region (> 1 MiB) is suspicious.
    let size = end.saturating_sub(start);
    if name.is_empty() && size > 1024 * 1024 {
        return true;
    }

    // Name with unusual characters (control chars or non-ASCII) is suspicious.
    if name.chars().any(|c| c.is_control() || !c.is_ascii()) {
        return true;
    }

    // Region overlapping kernel text range but not named "Kernel code".
    const KERNEL_TEXT_START: u64 = 0xffff_ffff_8100_0000;
    const KERNEL_TEXT_END: u64 = 0xffff_ffff_8200_0000;
    if start < KERNEL_TEXT_END && end > KERNEL_TEXT_START && name != "Kernel code" {
        return true;
    }

    false
}

/// Walk I/O memory resource regions from the `iomem_resource` kernel structure.
///
/// Returns `Ok(Vec::new())` if the `iomem_resource` symbol is not found
/// (graceful degradation).
pub fn walk_iomem_regions<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<IoMemRegion>> {
    // Resolve iomem_resource symbol (a struct resource, not a pointer).
    let root_addr = match reader.symbols().symbol_address("iomem_resource") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // Resolve field offsets within `struct resource`.
    let start_offset = reader
        .symbols()
        .field_offset("resource", "start")
        .unwrap_or(0x00);
    let end_offset = reader
        .symbols()
        .field_offset("resource", "end")
        .unwrap_or(0x08);
    let flags_offset = reader
        .symbols()
        .field_offset("resource", "flags")
        .unwrap_or(0x10);
    let name_offset = reader
        .symbols()
        .field_offset("resource", "name")
        .unwrap_or(0x18);
    let child_offset = reader
        .symbols()
        .field_offset("resource", "child")
        .unwrap_or(0x28);
    let sibling_offset = reader
        .symbols()
        .field_offset("resource", "sibling")
        .unwrap_or(0x20);

    let mut regions = Vec::new();

    // Iterative DFS stack: (resource_addr, depth).
    // Start with the children of the root (skip the root itself).
    let first_child = read_ptr(reader, root_addr + child_offset);
    if first_child == 0 {
        return Ok(Vec::new());
    }

    let mut stack: Vec<(u64, u32)> = vec![(first_child, 0)];
    let mut seen = std::collections::HashSet::new();

    while let Some((addr, depth)) = stack.pop() {
        if addr == 0 || regions.len() >= MAX_RESOURCES {
            continue;
        }
        if !seen.insert(addr) {
            continue;
        }

        let start = read_u64(reader, addr + start_offset);
        let end = read_u64(reader, addr + end_offset);
        let flags = read_u64(reader, addr + flags_offset);

        // Read name: pointer to a C string.
        let name_ptr = read_ptr(reader, addr + name_offset);
        let name = if name_ptr != 0 {
            match reader.read_bytes(name_ptr, 256) {
                Ok(bytes) => {
                    let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                    String::from_utf8_lossy(&bytes[..nul]).into_owned()
                }
                Err(_) => String::new(),
            }
        } else {
            String::new()
        };

        let is_suspicious = classify_iomem(&name, start, end);

        regions.push(IoMemRegion {
            start,
            end,
            name,
            flags,
            depth,
            is_suspicious,
        });

        // Push sibling (to be visited after returning from children).
        let sibling = read_ptr(reader, addr + sibling_offset);
        if sibling != 0 {
            stack.push((sibling, depth));
        }

        // Push child (deeper level).
        let child = read_ptr(reader, addr + child_offset);
        if child != 0 {
            stack.push((child, depth + 1));
        }
    }

    Ok(regions)
}

/// Read a 64-bit little-endian value from memory; returns 0 on failure.
fn read_u64<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, addr: u64) -> u64 {
    match reader.read_bytes(addr, 8) {
        Ok(b) if b.len() == 8 => u64::from_le_bytes(b[..8].try_into().unwrap()),
        _ => 0,
    }
}

/// Read a pointer (64-bit) from memory; returns 0 on failure.
fn read_ptr<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, addr: u64) -> u64 {
    read_u64(reader, addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // Classifier unit tests
    // ---------------------------------------------------------------

    #[test]
    fn classify_normal_system_ram_benign() {
        // Standard "System RAM" region is not suspicious.
        assert!(!classify_iomem("System RAM", 0x0010_0000, 0x7FFF_FFFF));
    }

    #[test]
    fn classify_empty_name_large_region_suspicious() {
        // Empty name on a region larger than 1 MiB is suspicious.
        assert!(classify_iomem("", 0x0, 0x0020_0000)); // 2 MiB
    }

    #[test]
    fn classify_empty_name_small_region_benign() {
        // Empty name on a small region (< 1 MiB) is not suspicious.
        assert!(!classify_iomem("", 0x0, 0x100)); // 256 bytes
    }

    #[test]
    fn classify_control_chars_in_name_suspicious() {
        // Name containing control characters is suspicious (corrupted name pointer).
        assert!(classify_iomem("System\x00RAM", 0x0, 0x1000));
    }

    #[test]
    fn classify_non_ascii_name_suspicious() {
        // Name containing non-ASCII bytes is suspicious.
        assert!(classify_iomem("Syst\u{00e9}m RAM", 0x0, 0x1000));
    }

    #[test]
    fn classify_kernel_text_overlap_not_named_kernel_code_suspicious() {
        // Region overlapping kernel text but not named "Kernel code" is suspicious.
        assert!(classify_iomem(
            "Evil Region",
            0xffff_ffff_8100_0000,
            0xffff_ffff_8180_0000,
        ));
    }

    #[test]
    fn classify_kernel_code_region_benign() {
        // The legitimate "Kernel code" region overlapping kernel text is fine.
        assert!(!classify_iomem(
            "Kernel code",
            0xffff_ffff_8100_0000,
            0xffff_ffff_8180_0000,
        ));
    }

    #[test]
    fn classify_acpi_tables_benign() {
        // Standard ACPI region is not suspicious.
        assert!(!classify_iomem("ACPI Tables", 0xBFFE_0000, 0xBFFF_FFFF));
    }

    #[test]
    fn classify_pci_mmio_benign() {
        // Standard PCI MMIO region is not suspicious.
        assert!(!classify_iomem("PCI Bus 0000:00", 0xE000_0000, 0xEFFF_FFFF));
    }

    // ---------------------------------------------------------------
    // Walker test — missing symbol graceful degradation
    // ---------------------------------------------------------------

    #[test]
    fn walk_iomem_no_symbol_returns_empty() {
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new().map_4k(vaddr, paddr, flags::WRITABLE);
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // With no iomem_resource symbol the walker must return empty, not panic.
        let result = walk_iomem_regions(&reader).unwrap();
        assert!(result.is_empty(), "missing symbol should yield empty vec");
    }

    // ---------------------------------------------------------------
    // classify_iomem: additional boundary and branch tests
    // ---------------------------------------------------------------

    #[test]
    fn classify_empty_name_exactly_1mib_not_suspicious() {
        // Empty name, region size exactly 1 MiB → NOT suspicious (> not >=)
        let size: u64 = 1024 * 1024;
        assert!(!classify_iomem("", 0, size));
    }

    #[test]
    fn classify_empty_name_1mib_plus_1_suspicious() {
        // Empty name, region size 1 MiB + 1 byte → suspicious
        let size: u64 = 1024 * 1024 + 1;
        assert!(classify_iomem("", 0, size));
    }

    #[test]
    fn classify_empty_name_small_region_explicit_benign() {
        // Empty name on 0-byte region → not suspicious
        assert!(!classify_iomem("", 100, 100)); // end == start → size = 0
    }

    #[test]
    fn classify_named_region_small_benign() {
        // Named region of any size is not suspicious on name-check alone
        assert!(!classify_iomem("Reserved", 0, 0x0100_0000)); // 16 MiB but named
    }

    #[test]
    fn classify_kernel_text_overlap_exact_boundary_suspicious() {
        // Region starts exactly at KERNEL_TEXT_START, not named "Kernel code"
        const KERNEL_TEXT_START: u64 = 0xffff_ffff_8100_0000;
        const KERNEL_TEXT_END: u64 = 0xffff_ffff_8200_0000;
        // start < KERNEL_TEXT_END AND end > KERNEL_TEXT_START
        assert!(classify_iomem("Other", KERNEL_TEXT_START, KERNEL_TEXT_END));
    }

    #[test]
    fn classify_region_just_before_kernel_text_benign() {
        // Region ends at exactly KERNEL_TEXT_START → no overlap (end > start check: end == start fails >)
        const KERNEL_TEXT_START: u64 = 0xffff_ffff_8100_0000;
        // end == KERNEL_TEXT_START means end is NOT > KERNEL_TEXT_START
        assert!(!classify_iomem(
            "Anything",
            0xffff_ffff_8000_0000,
            KERNEL_TEXT_START
        ));
    }

    #[test]
    fn classify_region_just_after_kernel_text_benign() {
        // Region starts at exactly KERNEL_TEXT_END → start < KERNEL_TEXT_END fails (== not <)
        const KERNEL_TEXT_END: u64 = 0xffff_ffff_8200_0000;
        assert!(!classify_iomem(
            "Anything",
            KERNEL_TEXT_END,
            KERNEL_TEXT_END + 0x1000
        ));
    }

    #[test]
    fn classify_kernel_code_partial_overlap_benign() {
        // Legitimately named "Kernel code" overlapping kernel text range is benign
        const KERNEL_TEXT_START: u64 = 0xffff_ffff_8100_0000;
        assert!(!classify_iomem(
            "Kernel code",
            KERNEL_TEXT_START,
            KERNEL_TEXT_START + 0x1000
        ));
    }

    #[test]
    fn classify_tab_char_in_name_suspicious() {
        // Tab is a control character → suspicious
        assert!(classify_iomem("System\tRAM", 0, 0x1000));
    }

    #[test]
    fn classify_newline_char_in_name_suspicious() {
        // Newline is a control character → suspicious
        assert!(classify_iomem("Sys\nRAM", 0, 0x1000));
    }

    #[test]
    fn classify_saturating_sub_overflow_protection() {
        // end < start → saturating_sub yields 0 → not suspicious on size alone
        assert!(!classify_iomem("", 0x1000, 0x0)); // end < start → size = 0
    }

    // ---------------------------------------------------------------
    // walk_iomem_regions: symbol present, child == 0 → exercises body, returns empty
    // ---------------------------------------------------------------

    #[test]
    fn walk_iomem_symbol_present_no_children_returns_empty() {
        use memf_core::test_builders::{flags as ptf, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // iomem_resource is the root struct resource (not a pointer to it).
        // The walk reads root_addr + child_offset; child_offset defaults to 0x28.
        // If that value is 0, the walk returns Ok(Vec::new()) immediately.
        let root_vaddr: u64 = 0xFFFF_8800_00A0_0000;
        let root_paddr: u64 = 0x00A0_0000; // unique, < 16 MB

        let isf = IsfBuilder::new()
            .add_symbol("iomem_resource", root_vaddr)
            .add_struct("resource", 0x60)
            .add_field("resource", "start", 0x00, "unsigned long")
            .add_field("resource", "end", 0x08, "unsigned long")
            .add_field("resource", "flags", 0x10, "unsigned long")
            .add_field("resource", "name", 0x18, "pointer")
            .add_field("resource", "sibling", 0x20, "pointer")
            .add_field("resource", "child", 0x28, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // All zeros: child pointer at 0x28 == 0 → walk returns empty immediately.
        let page = [0u8; 4096];

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(root_vaddr, root_paddr, ptf::WRITABLE)
            .write_phys(root_paddr, &page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_iomem_regions(&reader).unwrap();
        assert!(
            result.is_empty(),
            "iomem_resource with zero child pointer → no regions"
        );
    }

    // ---------------------------------------------------------------
    // walk_iomem_regions: symbol present, child != 0 → exercises DFS loop
    // ---------------------------------------------------------------

    #[test]
    fn walk_iomem_symbol_present_with_one_child_returns_entry() {
        use memf_core::test_builders::{flags as ptf, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Layout:
        //   root_vaddr  = iomem_resource (struct resource)
        //     child ptr (at +0x28) → child_vaddr
        //   child_vaddr = one resource entry; sibling=0, child=0, name_ptr=0
        let root_vaddr: u64 = 0xFFFF_8800_00B0_0000;
        let root_paddr: u64 = 0x00B0_0000;
        let child_vaddr: u64 = 0xFFFF_8800_00B1_0000;
        let child_paddr: u64 = 0x00B1_0000;

        // Root page: zeros except child pointer at offset 0x28
        let mut root_page = [0u8; 4096];
        root_page[0x28..0x30].copy_from_slice(&child_vaddr.to_le_bytes());

        // Child page: start=0x1000, end=0x2000, flags=0x200, name_ptr=0, sibling=0, child=0
        let mut child_page = [0u8; 4096];
        child_page[0x00..0x08].copy_from_slice(&0x1000u64.to_le_bytes()); // start
        child_page[0x08..0x10].copy_from_slice(&0x2000u64.to_le_bytes()); // end
        child_page[0x10..0x18].copy_from_slice(&0x0200u64.to_le_bytes()); // flags
                                                                          // name_ptr at 0x18 = 0 (null → name = "")
                                                                          // sibling at 0x20 = 0
                                                                          // child at 0x28 = 0

        let isf = IsfBuilder::new()
            .add_symbol("iomem_resource", root_vaddr)
            .add_struct("resource", 0x60)
            .add_field("resource", "start", 0x00u64, "unsigned long")
            .add_field("resource", "end", 0x08u64, "unsigned long")
            .add_field("resource", "flags", 0x10u64, "unsigned long")
            .add_field("resource", "name", 0x18u64, "pointer")
            .add_field("resource", "sibling", 0x20u64, "pointer")
            .add_field("resource", "child", 0x28u64, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(root_vaddr, root_paddr, ptf::WRITABLE)
            .write_phys(root_paddr, &root_page)
            .map_4k(child_vaddr, child_paddr, ptf::WRITABLE)
            .write_phys(child_paddr, &child_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_iomem_regions(&reader).unwrap_or_default();
        assert_eq!(result.len(), 1, "should find exactly one resource entry");
        assert_eq!(result[0].start, 0x1000);
        assert_eq!(result[0].end, 0x2000);
        assert_eq!(result[0].flags, 0x200);
        assert_eq!(result[0].depth, 0);
        // name_ptr=0 → empty name; size=0x1000 < 1MiB → not suspicious
        assert!(!result[0].is_suspicious);
    }

    // ---------------------------------------------------------------
    // walk_iomem_regions: child has a sibling → exercises sibling push
    // ---------------------------------------------------------------

    #[test]
    fn walk_iomem_symbol_present_child_with_sibling() {
        use memf_core::test_builders::{flags as ptf, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // root → child_a (sibling → child_b)
        let root_vaddr: u64 = 0xFFFF_8800_00C0_0000;
        let root_paddr: u64 = 0x00C0_0000;
        let child_a_vaddr: u64 = 0xFFFF_8800_00C1_0000;
        let child_a_paddr: u64 = 0x00C1_0000;
        let child_b_vaddr: u64 = 0xFFFF_8800_00C2_0000;
        let child_b_paddr: u64 = 0x00C2_0000;

        // root: child ptr at 0x28 = child_a_vaddr
        let mut root_page = [0u8; 4096];
        root_page[0x28..0x30].copy_from_slice(&child_a_vaddr.to_le_bytes());

        // child_a: start=0x10000, end=0x20000, sibling=child_b, child=0
        let mut a_page = [0u8; 4096];
        a_page[0x00..0x08].copy_from_slice(&0x0001_0000u64.to_le_bytes());
        a_page[0x08..0x10].copy_from_slice(&0x0002_0000u64.to_le_bytes());
        a_page[0x20..0x28].copy_from_slice(&child_b_vaddr.to_le_bytes()); // sibling

        // child_b: start=0x30000, end=0x40000, sibling=0, child=0
        let mut b_page = [0u8; 4096];
        b_page[0x00..0x08].copy_from_slice(&0x0003_0000u64.to_le_bytes());
        b_page[0x08..0x10].copy_from_slice(&0x0004_0000u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_symbol("iomem_resource", root_vaddr)
            .add_struct("resource", 0x60)
            .add_field("resource", "start", 0x00u64, "unsigned long")
            .add_field("resource", "end", 0x08u64, "unsigned long")
            .add_field("resource", "flags", 0x10u64, "unsigned long")
            .add_field("resource", "name", 0x18u64, "pointer")
            .add_field("resource", "sibling", 0x20u64, "pointer")
            .add_field("resource", "child", 0x28u64, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(root_vaddr, root_paddr, ptf::WRITABLE)
            .write_phys(root_paddr, &root_page)
            .map_4k(child_a_vaddr, child_a_paddr, ptf::WRITABLE)
            .write_phys(child_a_paddr, &a_page)
            .map_4k(child_b_vaddr, child_b_paddr, ptf::WRITABLE)
            .write_phys(child_b_paddr, &b_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_iomem_regions(&reader).unwrap_or_default();
        assert_eq!(result.len(), 2, "should find both sibling resource entries");
    }

    // ---------------------------------------------------------------
    // walk_iomem_regions: child has a sub-child → exercises child push (depth+1)
    // ---------------------------------------------------------------

    #[test]
    fn walk_iomem_symbol_present_nested_child() {
        use memf_core::test_builders::{flags as ptf, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let root_vaddr: u64 = 0xFFFF_8800_00D0_0000;
        let root_paddr: u64 = 0x00D0_0000;
        let child_vaddr: u64 = 0xFFFF_8800_00D1_0000;
        let child_paddr: u64 = 0x00D1_0000;
        let grandchild_vaddr: u64 = 0xFFFF_8800_00D2_0000;
        let grandchild_paddr: u64 = 0x00D2_0000;

        let mut root_page = [0u8; 4096];
        root_page[0x28..0x30].copy_from_slice(&child_vaddr.to_le_bytes());

        // child: has a child → grandchild
        let mut child_page = [0u8; 4096];
        child_page[0x00..0x08].copy_from_slice(&0x1000u64.to_le_bytes());
        child_page[0x08..0x10].copy_from_slice(&0x2000u64.to_le_bytes());
        child_page[0x28..0x30].copy_from_slice(&grandchild_vaddr.to_le_bytes()); // child ptr

        // grandchild: no further children
        let mut gc_page = [0u8; 4096];
        gc_page[0x00..0x08].copy_from_slice(&0x5000u64.to_le_bytes());
        gc_page[0x08..0x10].copy_from_slice(&0x6000u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_symbol("iomem_resource", root_vaddr)
            .add_struct("resource", 0x60)
            .add_field("resource", "start", 0x00u64, "unsigned long")
            .add_field("resource", "end", 0x08u64, "unsigned long")
            .add_field("resource", "flags", 0x10u64, "unsigned long")
            .add_field("resource", "name", 0x18u64, "pointer")
            .add_field("resource", "sibling", 0x20u64, "pointer")
            .add_field("resource", "child", 0x28u64, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(root_vaddr, root_paddr, ptf::WRITABLE)
            .write_phys(root_paddr, &root_page)
            .map_4k(child_vaddr, child_paddr, ptf::WRITABLE)
            .write_phys(child_paddr, &child_page)
            .map_4k(grandchild_vaddr, grandchild_paddr, ptf::WRITABLE)
            .write_phys(grandchild_paddr, &gc_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_iomem_regions(&reader).unwrap_or_default();
        assert_eq!(result.len(), 2, "child + grandchild = 2 entries");
        // grandchild should be at depth 1
        let gc = result
            .iter()
            .find(|r| r.start == 0x5000)
            .expect("grandchild entry");
        assert_eq!(gc.depth, 1);
    }

    // ---------------------------------------------------------------
    // IoMemRegion: Clone + Debug + Serialize
    // ---------------------------------------------------------------

    #[test]
    fn io_mem_region_clone_debug_serialize() {
        let region = IoMemRegion {
            start: 0x1000,
            end: 0x2000,
            name: "System RAM".to_string(),
            flags: 0x200,
            depth: 0,
            is_suspicious: false,
        };
        let cloned = region.clone();
        assert_eq!(cloned.start, 0x1000);
        assert_eq!(cloned.depth, 0);
        let dbg = format!("{:?}", cloned);
        assert!(dbg.contains("System RAM"));
        let json = serde_json::to_string(&cloned).unwrap();
        assert!(json.contains("\"start\":4096"));
        assert!(json.contains("\"is_suspicious\":false"));
    }
}
