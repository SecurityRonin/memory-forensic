//! Minimal in-memory PE helpers shared across walkers (section-table parsing).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// Safety cap on the PE section count scanned (real images have < 32).
const MAX_PE_SECTIONS: u64 = 96;

/// Return the `(virtual address, virtual size)` of the named section in an
/// in-memory PE module at `module_base`, or `None` if the headers are unreadable
/// or the section is absent. Parses the DOS header (`e_lfanew`@0x3C) and PE
/// headers, then the section table (40-byte entries: `Name[8]`@0, `VirtualSize`@8,
/// `VirtualAddress`@0xC). Section names are 8 bytes, NUL-padded (e.g. `".data"`,
/// `"PAGE"`).
pub(crate) fn module_section_range<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    module_base: u64,
    section_name: &str,
) -> Option<(u64, u64)> {
    let read_u16 = |va: u64| -> Option<u16> {
        let b = reader.read_bytes(va, 2).ok()?;
        Some(u16::from_le_bytes(b.get(..2)?.try_into().ok()?))
    };
    let read_u32 = |va: u64| -> Option<u32> {
        let b = reader.read_bytes(va, 4).ok()?;
        Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?))
    };

    // DOS header: e_lfanew (u32) @ 0x3C points to the PE header.
    let pe = module_base.wrapping_add(u64::from(read_u32(module_base + 0x3C)?));
    // PE signature "PE\0\0".
    if reader.read_bytes(pe, 4).ok()?.get(..4)? != b"PE\0\0" {
        return None;
    }
    // COFF header: NumberOfSections @ pe+6, SizeOfOptionalHeader @ pe+0x14.
    let num_sections = read_u16(pe + 6)?;
    let opt_size = read_u16(pe + 0x14)?;
    // Section table follows the 4-byte sig + 20-byte COFF + optional header.
    let sec_table = pe + 0x18 + u64::from(opt_size);
    let target = section_name.as_bytes();

    for i in 0..u64::from(num_sections).min(MAX_PE_SECTIONS) {
        let sh = sec_table + i * 40;
        let name = reader.read_bytes(sh, 8).ok()?;
        // PE section names are 8 bytes, NUL-padded.
        let end = name.iter().position(|&b| b == 0).unwrap_or(8);
        if &name[..end] == target {
            let vsize = read_u32(sh + 8)?;
            let vaddr = read_u32(sh + 0xC)?;
            return Some((module_base.wrapping_add(u64::from(vaddr)), u64::from(vsize)));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// `module_section_range` parses the PE section table of an in-memory module
    /// and returns each named section's (va, size).
    #[test]
    fn module_section_range_parses_named_sections() {
        let base: u64 = 0xFFFF_F800_0010_0000;
        let paddr: u64 = 0x0050_0000;
        let mut page = vec![0u8; 4096];
        // DOS: e_lfanew @ 0x3C -> 0x80
        page[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // PE signature @ 0x80
        page[0x80..0x84].copy_from_slice(b"PE\0\0");
        // COFF: NumberOfSections @ 0x86 = 2; SizeOfOptionalHeader @ 0x94 = 0xF0
        page[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        page[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        // Section table @ 0x98 + 0xF0 = 0x188 (PE sig 4 + COFF 0x14 = 0x18)
        let sec0 = 0x188usize;
        page[sec0..sec0 + 4].copy_from_slice(b"PAGE");
        page[sec0 + 8..sec0 + 12].copy_from_slice(&0x3000u32.to_le_bytes());
        page[sec0 + 12..sec0 + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        let sec1 = sec0 + 40;
        page[sec1..sec1 + 5].copy_from_slice(b".data");
        page[sec1 + 8..sec1 + 12].copy_from_slice(&0x2000u32.to_le_bytes());
        page[sec1 + 12..sec1 + 16].copy_from_slice(&0x5000u32.to_le_bytes());

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(base, paddr, flags::WRITABLE)
            .write_phys(paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        assert_eq!(
            module_section_range(&reader, base, ".data"),
            Some((base + 0x5000, 0x2000))
        );
        assert_eq!(
            module_section_range(&reader, base, "PAGE"),
            Some((base + 0x1000, 0x3000))
        );
        assert_eq!(module_section_range(&reader, base, ".missing"), None);
    }
}
