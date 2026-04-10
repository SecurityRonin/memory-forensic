//! Linux kernel module walker.
//!
//! Enumerates loaded kernel modules by walking the `modules` linked list.
//! Each `struct module` is connected via `list` (`list_head`).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, ModuleInfo, ModuleState, Result};

/// Walk the Linux kernel module list.
pub fn walk_modules<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<ModuleInfo>> {
    let modules_addr = reader
        .symbols()
        .symbol_address("modules")
        .ok_or_else(|| Error::Walker("symbol 'modules' not found".into()))?;

    let module_addrs = reader.walk_list(modules_addr, "module", "list")?;

    let mut modules = Vec::new();
    for &mod_addr in &module_addrs {
        if let Ok(info) = read_module_info(reader, mod_addr) {
            modules.push(info);
        }
    }

    Ok(modules)
}

fn read_module_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    mod_addr: u64,
) -> Result<ModuleInfo> {
    let name = reader.read_field_string(mod_addr, "module", "name", 56)?;
    let state: u32 = reader.read_field(mod_addr, "module", "state")?;
    let (base_addr, size) = read_core_layout(reader, mod_addr)?;

    Ok(ModuleInfo {
        name,
        base_addr,
        size,
        state: ModuleState::from_raw(state),
    })
}

fn read_core_layout<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    mod_addr: u64,
) -> Result<(u64, u64)> {
    // Try core_layout.base / core_layout.size (kernel >= 4.5)
    if let (Some(layout_off), Some(_base_off), Some(_size_off)) = (
        reader.symbols().field_offset("module", "core_layout"),
        reader.symbols().field_offset("module_layout", "base"),
        reader.symbols().field_offset("module_layout", "size"),
    ) {
        let layout_addr = mod_addr + layout_off;
        let base: u64 = reader.read_field(layout_addr, "module_layout", "base")?;
        let size: u32 = reader.read_field(layout_addr, "module_layout", "size")?;
        return Ok((base, u64::from(size)));
    }

    // Fallback: older kernels with module_core / core_size
    if reader
        .symbols()
        .field_offset("module", "module_core")
        .is_some()
        && reader
            .symbols()
            .field_offset("module", "core_size")
            .is_some()
    {
        let base: u64 = reader.read_field(mod_addr, "module", "module_core")?;
        let size: u32 = reader.read_field(mod_addr, "module", "core_size")?;
        return Ok((base, u64::from(size)));
    }

    Err(Error::Walker(
        "cannot determine module core layout: no core_layout or module_core field".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_module_reader(data: &[u8], vaddr: u64, paddr: u64) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("module", 256)
            .add_field("module", "list", 0, "list_head")
            .add_field("module", "name", 16, "char")
            .add_field("module", "state", 72, "unsigned int")
            .add_field("module", "core_layout", 80, "module_layout")
            .add_struct("module_layout", 32)
            .add_field("module_layout", "base", 0, "pointer")
            .add_field("module_layout", "size", 8, "unsigned int")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("modules", vaddr)
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
    fn walk_two_modules() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let head = vaddr;
        let a_list = vaddr + 0x100;
        let b_list = vaddr + 0x300;

        let mut data = vec![0u8; 4096];

        // head: next -> A.list, prev -> B.list
        data[0..8].copy_from_slice(&a_list.to_le_bytes());
        data[8..16].copy_from_slice(&b_list.to_le_bytes());

        // Module A at 0x100
        data[0x100..0x108].copy_from_slice(&b_list.to_le_bytes());
        data[0x108..0x110].copy_from_slice(&head.to_le_bytes());
        data[0x110..0x118].copy_from_slice(b"ext4\0\0\0\0");
        data[0x148..0x14C].copy_from_slice(&0u32.to_le_bytes());
        data[0x150..0x158].copy_from_slice(&0xFFFF_A000u64.to_le_bytes());
        data[0x158..0x15C].copy_from_slice(&0x2000u32.to_le_bytes());

        // Module B at 0x300
        data[0x300..0x308].copy_from_slice(&head.to_le_bytes());
        data[0x308..0x310].copy_from_slice(&a_list.to_le_bytes());
        data[0x310..0x318].copy_from_slice(b"nf_nat\0\0");
        data[0x348..0x34C].copy_from_slice(&0u32.to_le_bytes());
        data[0x350..0x358].copy_from_slice(&0xFFFF_B000u64.to_le_bytes());
        data[0x358..0x35C].copy_from_slice(&0x1000u32.to_le_bytes());

        let reader = make_module_reader(&data, vaddr, paddr);
        let mods = walk_modules(&reader).unwrap();

        assert_eq!(mods.len(), 2);
        assert_eq!(mods[0].name, "ext4");
        assert_eq!(mods[0].base_addr, 0xFFFF_A000);
        assert_eq!(mods[0].size, 0x2000);
        assert_eq!(mods[0].state, ModuleState::Live);
        assert_eq!(mods[1].name, "nf_nat");
        assert_eq!(mods[1].base_addr, 0xFFFF_B000);
        assert_eq!(mods[1].size, 0x1000);
    }

    #[test]
    fn walk_modules_with_legacy_module_core_layout() {
        // Uses module_core / core_size fields (old kernel fallback path)
        // module_layout and core_layout fields intentionally absent
        let vaddr: u64 = 0xFFFF_8000_0020_0000;
        let paddr: u64 = 0x0090_0000;
        let mod_vaddr: u64 = 0xFFFF_8000_0021_0000;
        let mod_paddr: u64 = 0x0091_0000;

        let mut head_page = [0u8; 4096];
        head_page[0..8].copy_from_slice(&mod_vaddr.to_le_bytes());
        head_page[8..16].copy_from_slice(&mod_vaddr.to_le_bytes());

        let mut mod_page = [0u8; 4096];
        // list.next → head (terminate after one module)
        mod_page[0..8].copy_from_slice(&vaddr.to_le_bytes());
        mod_page[8..16].copy_from_slice(&vaddr.to_le_bytes());
        // name at offset 16
        mod_page[16..23].copy_from_slice(b"virtio\0");
        // state at offset 72
        mod_page[72..76].copy_from_slice(&0u32.to_le_bytes()); // MODULE_STATE_LIVE
        // module_core at offset 80
        mod_page[80..88].copy_from_slice(&0xFFFF_C000_0000u64.to_le_bytes());
        // core_size at offset 88
        mod_page[88..92].copy_from_slice(&0x8000u32.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("module", 256)
            .add_field("module", "list",        0x00u64, "list_head")
            .add_field("module", "name",        0x10u64, "char")
            .add_field("module", "state",       0x48u64, "unsigned int")
            .add_field("module", "module_core", 0x50u64, "pointer")
            .add_field("module", "core_size",   0x58u64, "unsigned int")
            // core_layout intentionally absent → fallback to module_core/core_size
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0x00u64, "pointer")
            .add_field("list_head", "prev", 0x08u64, "pointer")
            .add_symbol("modules", vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &head_page)
            .map_4k(mod_vaddr, mod_paddr, flags::WRITABLE)
            .write_phys(mod_paddr, &mod_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let mods = walk_modules(&reader).unwrap();
        assert_eq!(mods.len(), 1, "should find one module via legacy layout");
        assert_eq!(mods[0].name, "virtio");
        assert_eq!(mods[0].base_addr, 0xFFFF_C000_0000);
        assert_eq!(mods[0].size, 0x8000);
    }

    #[test]
    fn walk_modules_no_layout_fields_skips_module() {
        // Neither core_layout nor module_core/core_size fields exist
        // → read_core_layout returns Err → module is skipped via if let Ok
        let vaddr: u64 = 0xFFFF_8000_0030_0000;
        let paddr: u64 = 0x0092_0000;
        let mod_vaddr: u64 = 0xFFFF_8000_0031_0000;
        let mod_paddr: u64 = 0x0093_0000;

        let mut head_page = [0u8; 4096];
        head_page[0..8].copy_from_slice(&mod_vaddr.to_le_bytes());
        head_page[8..16].copy_from_slice(&mod_vaddr.to_le_bytes());

        let mut mod_page = [0u8; 4096];
        mod_page[0..8].copy_from_slice(&vaddr.to_le_bytes());
        mod_page[8..16].copy_from_slice(&vaddr.to_le_bytes());
        mod_page[16..23].copy_from_slice(b"broken\0");
        mod_page[72..76].copy_from_slice(&0u32.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("module", 256)
            .add_field("module", "list",  0x00u64, "list_head")
            .add_field("module", "name",  0x10u64, "char")
            .add_field("module", "state", 0x48u64, "unsigned int")
            // No core_layout field and no module_core/core_size fields
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0x00u64, "pointer")
            .add_field("list_head", "prev", 0x08u64, "pointer")
            .add_symbol("modules", vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &head_page)
            .map_4k(mod_vaddr, mod_paddr, flags::WRITABLE)
            .write_phys(mod_paddr, &mod_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let mods = walk_modules(&reader).unwrap();
        // Module skipped because read_core_layout returns Err
        assert!(mods.is_empty(), "module with no layout fields must be skipped");
    }

    #[test]
    fn walk_modules_missing_symbol_returns_error() {
        // No "modules" symbol → walk_modules returns Err
        let isf = IsfBuilder::new()
            .add_struct("module", 256)
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0x00u64, "pointer")
            .add_field("list_head", "prev", 0x08u64, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_modules(&reader);
        assert!(result.is_err(), "missing modules symbol must return Err");
    }

    #[test]
    fn empty_module_list() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];
        data[0..8].copy_from_slice(&vaddr.to_le_bytes());
        data[8..16].copy_from_slice(&vaddr.to_le_bytes());

        let reader = make_module_reader(&data, vaddr, paddr);
        let mods = walk_modules(&reader).unwrap();
        assert_eq!(mods.len(), 0);
    }
}
