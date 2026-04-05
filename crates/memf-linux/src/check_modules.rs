//! Linux hidden kernel module detector.
//!
//! Cross-references kernel modules found via the `modules` linked list
//! against the kernel's `kset` hierarchy (sysfs). Modules present in
//! one view but not the other may have been hidden by a rootkit.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, HiddenModuleInfo, Result};

/// Cross-reference kernel modules for hidden module detection.
///
/// Walks the `modules` linked list and the `module_kset` kobj tree,
/// then merges results. Modules visible in one but not both are
/// flagged as potentially hidden.
pub fn check_hidden_modules<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<HiddenModuleInfo>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_test_reader(
        data: &[u8],
        vaddr: u64,
        paddr: u64,
    ) -> ObjectReader<SyntheticPhysMem> {
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
}
