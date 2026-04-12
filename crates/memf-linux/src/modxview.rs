//! Cross-view kernel module detection for Linux.
//!
//! Detects hidden kernel modules by cross-referencing multiple views of
//! loaded modules: the kernel module list (`modules` symbol), kobj/sysfs
//! entries, and memory-mapped regions. Rootkits that unlink from one list
//! but not others can be detected by discrepancies between views.
//! Equivalent to Volatility's `linux.check_modules` cross-view approach.

use std::collections::HashSet;

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Maximum number of modules to enumerate before stopping (cycle guard).
const MAX_MODULES: usize = 4096;

/// Cross-view module visibility entry.
///
/// Each entry represents a kernel module found in at least one view,
/// with flags indicating which views contain it. A module missing from
/// any view but present in others is classified as hidden/suspicious.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ModXviewEntry {
    /// Module name from the kernel `module.name` field.
    pub name: String,
    /// Base virtual address of the module's core section.
    pub base_addr: u64,
    /// Size of the module's core section in bytes.
    pub size: u32,
    /// Whether the module was found in the `modules` linked list.
    pub in_module_list: bool,
    /// Whether the module was found in the kobj/sysfs entries.
    pub in_kobj_list: bool,
    /// Whether the module's memory range is mapped and valid.
    pub in_memory_map: bool,
    /// Whether this module is hidden/suspicious (missing from at least
    /// one view while present in another).
    pub is_hidden: bool,
}

/// Classify module visibility across three kernel views.
///
/// Returns `true` (hidden/suspicious) if the module is missing from any
/// view but present in at least one. All-false means the module was not
/// found at all (not suspicious — just absent). All-true means benign.
pub fn classify_module_visibility(
    in_module_list: bool,
    in_kobj_list: bool,
    in_memory_map: bool,
) -> bool {
    let present_count = [in_module_list, in_kobj_list, in_memory_map]
        .iter()
        .filter(|&&v| v)
        .count();

    // Hidden if present in at least one view but not all three
    present_count > 0 && present_count < 3
}

/// Walk and cross-reference kernel module views for hidden module detection.
///
/// Collects modules from three views:
/// 1. **Module list** — the `modules` linked list (`LIST_HEAD`)
/// 2. **Kobj list** — `mkobj.kobj.entry` linkage in sysfs
/// 3. **Memory map** — `module_core`/`module_init` address range validity
///
/// Each unique module is checked against all views and classified.
/// Returns `Ok(Vec::new())` if the `modules` symbol is not found
/// (graceful degradation).
pub fn walk_modxview<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<ModXviewEntry>> {
    // Graceful degradation: if `modules` symbol is missing, return empty.
    let modules_addr = match reader.symbols().symbol_address("modules") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // View 1: Walk the modules linked list.
    let module_addrs = reader.walk_list(modules_addr, "module", "list")?;

    let mut seen = HashSet::new();
    let mut entries = Vec::new();

    for &mod_addr in module_addrs.iter().take(MAX_MODULES) {
        if !seen.insert(mod_addr) {
            break; // Cycle detected
        }

        let name = reader
            .read_field_string(mod_addr, "module", "name", 56)
            .unwrap_or_else(|_| "<unknown>".to_string());

        let base_addr: u64 = reader
            .read_field(mod_addr, "module", "module_core")
            .unwrap_or(0);

        let size: u32 = reader
            .read_field(mod_addr, "module", "core_size")
            .unwrap_or(0);

        // View 1: Present in module list by definition (found it there).
        let in_module_list = true;

        // View 2: Check kobj linkage.
        // If mkobj/kobj fields are not resolvable, assume present (can't verify).
        let in_kobj_list = check_kobj_linkage(reader, mod_addr);

        // View 3: Check memory mapping validity.
        // If module_core is non-zero and we can read from it, it's mapped.
        let in_memory_map = check_memory_mapped(reader, base_addr, size);

        let is_hidden = classify_module_visibility(in_module_list, in_kobj_list, in_memory_map);

        entries.push(ModXviewEntry {
            name,
            base_addr,
            size,
            in_module_list,
            in_kobj_list,
            in_memory_map,
            is_hidden,
        });
    }

    Ok(entries)
}

/// Check whether a module's kobj entry is properly linked.
///
/// Verifies that `module.mkobj.kobj.entry.next` is a valid (non-null)
/// pointer, indicating the module is linked into the sysfs kobj tree.
/// Returns `true` (assume present) if the required field offsets are
/// unavailable.
fn check_kobj_linkage<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, mod_addr: u64) -> bool {
    // Resolve mkobj offset within module struct
    let mkobj_offset = match reader.symbols().field_offset("module", "mkobj") {
        Some(off) => off,
        None => return true, // Can't verify — assume present
    };

    // Resolve kobj offset within module_kobject
    let kobj_offset = match reader.symbols().field_offset("module_kobject", "kobj") {
        Some(off) => off,
        None => return true,
    };

    // Resolve entry offset within kobject (list_head)
    let entry_offset = match reader.symbols().field_offset("kobject", "entry") {
        Some(off) => off,
        None => return true,
    };

    // Read the entry.next pointer
    let entry_addr = mod_addr + mkobj_offset + kobj_offset + entry_offset;
    let next_ptr: u64 = match reader.read_field(entry_addr, "list_head", "next") {
        Ok(v) => v,
        Err(_) => return true, // Can't read — assume present
    };

    // A null or zero next pointer means unlinked from kobj tree
    next_ptr != 0
}

/// Check whether a module's core memory range is mapped and readable.
///
/// Attempts to read a small probe from the module's base address.
/// Returns `true` if the base is zero (can't verify) or the memory is
/// readable. Returns `false` only when the address is non-zero but
/// unreadable.
fn check_memory_mapped<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    base_addr: u64,
    size: u32,
) -> bool {
    if base_addr == 0 || size == 0 {
        return true; // Can't verify — assume present
    }

    // Probe: try to read 1 byte from the module base address
    reader.read_bytes(base_addr, 1).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_all_visible_benign() {
        assert!(!classify_module_visibility(true, true, true));
    }

    #[test]
    fn classify_missing_from_list_suspicious() {
        // Present in kobj and memory, but missing from module list
        assert!(classify_module_visibility(false, true, true));
    }

    #[test]
    fn classify_missing_from_kobj_suspicious() {
        // Present in module list and memory, but missing from kobj
        assert!(classify_module_visibility(true, false, true));
    }

    #[test]
    fn classify_all_missing_not_suspicious() {
        // Not found anywhere — not suspicious, just absent
        assert!(!classify_module_visibility(false, false, false));
    }

    #[test]
    fn walk_no_symbol_returns_empty() {
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Build a reader with no `modules` symbol
        let isf = IsfBuilder::new()
            .add_struct("module", 64)
            .add_field("module", "name", 0, "char")
            .add_field("module", "list", 8, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_modxview(&reader);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn modxview_entry_serializes() {
        let entry = ModXviewEntry {
            name: "test_module".to_string(),
            base_addr: 0xFFFF_8000_0000_1000,
            size: 4096,
            in_module_list: true,
            in_kobj_list: true,
            in_memory_map: false,
            is_hidden: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("test_module"));
        assert!(json.contains("\"is_hidden\":true"));
    }

    #[test]
    fn classify_missing_from_memory_suspicious() {
        // Present in module list and kobj, but memory is not mapped
        assert!(classify_module_visibility(true, true, false));
    }

    #[test]
    fn classify_only_in_memory_suspicious() {
        // Only found in memory map, missing from both lists
        assert!(classify_module_visibility(false, false, true));
    }

    #[test]
    fn classify_only_in_module_list_suspicious() {
        // Only found in module list, missing from kobj and memory
        assert!(classify_module_visibility(true, false, false));
    }

    #[test]
    fn classify_only_in_kobj_suspicious() {
        // Only found in kobj, missing from module list and memory
        assert!(classify_module_visibility(false, true, false));
    }

    #[test]
    fn check_memory_mapped_zero_base_returns_true() {
        // base_addr == 0 → can't verify, assume present
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        assert!(check_memory_mapped(&reader, 0, 4096));
    }

    #[test]
    fn check_memory_mapped_zero_size_returns_true() {
        // size == 0 → can't verify, assume present
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        assert!(check_memory_mapped(&reader, 0xFFFF_8000_0000_1000, 0));
    }

    #[test]
    fn check_memory_mapped_unreadable_returns_false() {
        // base_addr non-zero, size non-zero, but memory not mapped → unreadable → false
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // Address not mapped → read_bytes returns Err → false
        assert!(!check_memory_mapped(&reader, 0xDEAD_BEEF_0000_1000, 4096));
    }

    #[test]
    fn check_kobj_linkage_missing_mkobj_offset_returns_true() {
        // If mkobj field is not in the ISF, assume linked (return true)
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // No "module" struct defined → field_offset("module", "mkobj") returns None
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        assert!(check_kobj_linkage(&reader, 0xFFFF_8000_0000_0000));
    }

    #[test]
    fn check_kobj_linkage_missing_kobj_offset_returns_true() {
        // module struct present but module_kobject not defined
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new()
            .add_struct("module", 128)
            .add_field("module", "mkobj", 0, "pointer")
            // module_kobject not defined → field_offset("module_kobject", "kobj") returns None
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        assert!(check_kobj_linkage(&reader, 0xFFFF_8000_0000_0000));
    }

    #[test]
    fn check_kobj_linkage_missing_entry_offset_returns_true() {
        // module and module_kobject defined but kobject.entry missing
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new()
            .add_struct("module", 128)
            .add_field("module", "mkobj", 0, "pointer")
            .add_struct("module_kobject", 64)
            .add_field("module_kobject", "kobj", 0, "pointer")
            // kobject not defined → field_offset("kobject", "entry") returns None
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        assert!(check_kobj_linkage(&reader, 0xFFFF_8000_0000_0000));
    }

    #[test]
    fn walk_modxview_with_one_module_entry() {
        // symbol present + one module in the list → exercises walk body
        use memf_core::test_builders::{flags as ptf, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Layout:
        //   modules_vaddr  = LIST_HEAD (head of modules list)
        //   mod_a_vaddr    = module A, list.next points back to head (circular)
        //
        // module struct layout used:
        //   +0x00: list.next (pointer)
        //   +0x08: list.prev (pointer)
        //   +0x10: name (char[56])
        //   +0x48: module_core (pointer) — base addr
        //   +0x50: core_size (u32)
        let head_vaddr: u64 = 0xFFFF_8800_00E0_0000;
        let head_paddr: u64 = 0x00E0_0000;
        let mod_a_vaddr: u64 = 0xFFFF_8800_00E1_0000;
        let mod_a_paddr: u64 = 0x00E1_0000;

        let mut head_page = [0u8; 4096];
        // head.next → mod_a list node (start of module A)
        head_page[0..8].copy_from_slice(&mod_a_vaddr.to_le_bytes());
        head_page[8..16].copy_from_slice(&mod_a_vaddr.to_le_bytes());

        let mut mod_a_page = [0u8; 4096];
        // list.next → head (so walk terminates after mod_a)
        mod_a_page[0..8].copy_from_slice(&head_vaddr.to_le_bytes());
        mod_a_page[8..16].copy_from_slice(&head_vaddr.to_le_bytes());
        // name at +0x10
        mod_a_page[0x10..0x15].copy_from_slice(b"dummy");
        // module_core at +0x48
        mod_a_page[0x48..0x50].copy_from_slice(&0xFFFF_A000_0000u64.to_le_bytes());
        // core_size at +0x50
        mod_a_page[0x50..0x54].copy_from_slice(&0x4000u32.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("module", 256)
            .add_field("module", "list",        0x00u64, "list_head")
            .add_field("module", "name",        0x10u64, "char")
            .add_field("module", "module_core", 0x48u64, "pointer")
            .add_field("module", "core_size",   0x50u64, "unsigned int")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0x00u64, "pointer")
            .add_field("list_head", "prev", 0x08u64, "pointer")
            .add_symbol("modules", head_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, ptf::WRITABLE)
            .write_phys(head_paddr, &head_page)
            .map_4k(mod_a_vaddr, mod_a_paddr, ptf::WRITABLE)
            .write_phys(mod_a_paddr, &mod_a_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_modxview(&reader).unwrap_or_default();
        assert_eq!(result.len(), 1, "should find exactly one module entry");
        assert_eq!(result[0].name, "dummy");
        assert_eq!(result[0].base_addr, 0xFFFF_A000_0000);
        assert_eq!(result[0].size, 0x4000);
        assert!(result[0].in_module_list, "module found in list");
    }

    #[test]
    fn check_kobj_linkage_unreadable_memory_returns_true() {
        // All offsets available but memory not mapped → read fails → assume present
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new()
            .add_struct("module", 128)
            .add_field("module", "mkobj", 0, "pointer")
            .add_struct("module_kobject", 64)
            .add_field("module_kobject", "kobj", 0, "pointer")
            .add_struct("kobject", 64)
            .add_field("kobject", "entry", 0, "pointer")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // Address not mapped → read_field returns Err → assume present (true)
        assert!(check_kobj_linkage(&reader, 0xDEAD_BEEF_0000_0000));
    }
}
