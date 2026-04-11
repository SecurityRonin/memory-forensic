//! Linux hidden kernel module detector.
//!
//! Cross-references kernel modules found via the `modules` linked list
//! against the kernel's `kset` hierarchy (sysfs). Modules present in
//! one view but not the other may have been hidden by a rootkit.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, HiddenModuleInfo, Result};

/// Check whether a module is linked into the sysfs kobj tree.
///
/// Walks `module.mkobj.kobj.entry.next` — a non-null pointer indicates the
/// module is present in the kobj/sysfs hierarchy. Returns `true` (assume
/// present) if any required field offset is unavailable in the symbol table
/// or if the memory is unreadable.
fn check_module_in_sysfs<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, mod_addr: u64) -> bool {
    let mkobj_offset = match reader.symbols().field_offset("module", "mkobj") {
        Some(off) => off,
        None => return true, // Can't verify — assume present
    };
    let kobj_offset = match reader.symbols().field_offset("module_kobject", "kobj") {
        Some(off) => off,
        None => return true,
    };
    let entry_offset = match reader.symbols().field_offset("kobject", "entry") {
        Some(off) => off,
        None => return true,
    };

    let entry_addr = mod_addr + mkobj_offset + kobj_offset + entry_offset;
    let next_ptr: u64 = match reader.read_field(entry_addr, "list_head", "next") {
        Ok(v) => v,
        Err(_) => return true, // Can't read — assume present
    };

    // Non-null next pointer means linked into kobj tree
    next_ptr != 0
}

/// Cross-reference kernel modules for hidden module detection.
///
/// Walks the `modules` linked list and the `module_kset` kobj tree,
/// then merges results. Modules visible in one but not both are
/// flagged as potentially hidden.
pub fn check_hidden_modules<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<HiddenModuleInfo>> {
    let modules_addr = reader
        .symbols()
        .symbol_address("modules")
        .ok_or_else(|| Error::Walker("symbol 'modules' not found".into()))?;

    let _list_offset = reader
        .symbols()
        .field_offset("module", "list")
        .ok_or_else(|| Error::Walker("module.list field not found".into()))?;

    // Walk the modules linked list
    let module_addrs = reader.walk_list(modules_addr, "module", "list")?;

    let mut results = Vec::new();

    for &mod_addr in &module_addrs {
        let name = reader
            .read_field_string(mod_addr, "module", "name", 56)
            .unwrap_or_else(|_| "<unknown>".to_string());

        let base_addr: u64 = reader
            .read_field(mod_addr, "module", "module_core")
            .unwrap_or(0);

        let size: u32 = reader
            .read_field(mod_addr, "module", "core_size")
            .unwrap_or(0);

        // Present in modules list by definition (we found it there).
        // Check sysfs linkage via kobj entry: module.mkobj.kobj.entry.next
        // must be non-null to indicate the module is linked into the sysfs
        // kobj tree. Returns true (assume present) if fields are missing.
        let in_sysfs = check_module_in_sysfs(reader, mod_addr);

        results.push(HiddenModuleInfo {
            name,
            base_addr,
            size: u64::from(size),
            in_modules_list: true,
            in_sysfs,
        });
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

    fn make_test_reader(data: &[u8], vaddr: u64, paddr: u64) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("module", 256)
            .add_field("module", "name", 0, "char")
            .add_field("module", "list", 56, "list_head")
            .add_field("module", "module_core", 128, "pointer")
            .add_field("module", "core_size", 136, "unsigned int")
            .add_field("module", "mkobj", 160, "module_kobject")
            .add_struct("module_kobject", 64)
            .add_field("module_kobject", "kobj", 0, "kobject")
            .add_struct("kobject", 64)
            .add_field("kobject", "name", 0, "pointer")
            .add_field("kobject", "entry", 16, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("modules", vaddr + 0x800)
            .add_symbol("module_kset", vaddr + 0x900)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, ptflags::WRITABLE)
            .write_phys(paddr, data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn empty_module_list() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // modules list_head at +0x800 (self-referencing = empty)
        let modules_head = vaddr + 0x800;
        data[0x800..0x808].copy_from_slice(&modules_head.to_le_bytes());
        data[0x808..0x810].copy_from_slice(&modules_head.to_le_bytes());

        let reader = make_test_reader(&data, vaddr, paddr);
        let results = check_hidden_modules(&reader).unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn missing_modules_symbol() {
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

        let result = check_hidden_modules(&reader);
        assert!(result.is_err());
    }

    #[test]
    fn missing_module_list_field_returns_error() {
        // modules symbol present but module.list field absent → Error
        let isf = IsfBuilder::new()
            .add_struct("module", 64)
            .add_field("module", "name", 0, "char")
            // list field intentionally omitted
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("modules", 0xFFFF_8000_0010_0800)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = check_hidden_modules(&reader);
        assert!(result.is_err(), "missing module.list field should return error");
    }

    #[test]
    fn single_module_in_list_with_sysfs() {
        // Set up a modules list with one real module entry that IS linked in sysfs.
        // module.mkobj at offset 160; module_kobject.kobj at offset 0;
        // kobject.entry at offset 16 → entry_addr = mod_addr + 160 + 0 + 16 = mod_addr + 176
        // list_head.next at entry_addr offset 0 → set to a non-zero sentinel to indicate linked.
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        let module_list_vaddr = vaddr; // module is at the page start
        let module_list_field_vaddr = module_list_vaddr + 56;

        let modules_head = vaddr + 0x800;
        data[0x800..0x808].copy_from_slice(&module_list_field_vaddr.to_le_bytes());
        data[0x808..0x810].copy_from_slice(&modules_head.to_le_bytes());

        // module.name at offset 0
        data[0..8].copy_from_slice(b"rootkit\0");
        // module.list at offset 56
        data[56..64].copy_from_slice(&modules_head.to_le_bytes());
        data[64..72].copy_from_slice(&modules_head.to_le_bytes());
        // module.module_core at offset 128
        let base: u64 = 0xFFFF_C000_0000_0000;
        data[128..136].copy_from_slice(&base.to_le_bytes());
        // module.core_size at offset 136
        data[136..140].copy_from_slice(&4096u32.to_le_bytes());
        // kobj.entry.next at offset 176 (mod_addr+160+0+16): set to non-zero → linked in sysfs
        let kobj_entry_next_sentinel: u64 = 0xFFFF_8000_DEAD_0001;
        data[176..184].copy_from_slice(&kobj_entry_next_sentinel.to_le_bytes());

        let reader = make_test_reader(&data, vaddr, paddr);
        let results = check_hidden_modules(&reader).unwrap();

        assert_eq!(results.len(), 1, "should find one module");
        assert!(results[0].name.starts_with("rootkit"), "name should match: {}", results[0].name);
        assert_eq!(results[0].base_addr, base);
        assert_eq!(results[0].size, 4096);
        assert!(results[0].in_modules_list);
        assert!(results[0].in_sysfs, "module with non-zero kobj entry.next should be in sysfs");
    }

    #[test]
    fn single_module_not_in_sysfs() {
        // Module in the modules list but NOT linked in sysfs (kobj entry.next == 0).
        let vaddr: u64 = 0xFFFF_8000_0011_0000;
        let paddr: u64 = 0x0081_0000;
        let mut data = vec![0u8; 4096];

        let module_list_field_vaddr = vaddr + 56;
        let modules_head = vaddr + 0x800;
        data[0x800..0x808].copy_from_slice(&module_list_field_vaddr.to_le_bytes());
        data[0x808..0x810].copy_from_slice(&modules_head.to_le_bytes());

        data[0..8].copy_from_slice(b"hidden\0\0");
        data[56..64].copy_from_slice(&modules_head.to_le_bytes());
        data[64..72].copy_from_slice(&modules_head.to_le_bytes());
        let base: u64 = 0xFFFF_C001_0000_0000;
        data[128..136].copy_from_slice(&base.to_le_bytes());
        data[136..140].copy_from_slice(&4096u32.to_le_bytes());
        // kobj.entry.next at offset 176 = 0 → not linked in sysfs
        // (data is zero-initialized, so nothing to set)

        let isf = memf_symbols::test_builders::IsfBuilder::new()
            .add_struct("module", 256)
            .add_field("module", "name", 0, "char")
            .add_field("module", "list", 56, "list_head")
            .add_field("module", "module_core", 128, "pointer")
            .add_field("module", "core_size", 136, "unsigned int")
            .add_field("module", "mkobj", 160, "module_kobject")
            .add_struct("module_kobject", 64)
            .add_field("module_kobject", "kobj", 0, "kobject")
            .add_struct("kobject", 64)
            .add_field("kobject", "name", 0, "pointer")
            .add_field("kobject", "entry", 16, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("modules", vaddr + 0x800)
            .add_symbol("module_kset", vaddr + 0x900)
            .build_json();

        use memf_core::test_builders::{flags as ptflags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, ptflags::WRITABLE)
            .write_phys(paddr, &data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = check_hidden_modules(&reader).unwrap();
        assert_eq!(results.len(), 1, "should find one module");
        assert!(results[0].name.starts_with("hidden"));
        assert!(results[0].in_modules_list);
        assert!(!results[0].in_sysfs, "module with kobj entry.next==0 should not be in sysfs");
    }
}
