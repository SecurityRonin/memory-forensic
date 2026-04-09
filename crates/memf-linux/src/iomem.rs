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
}
