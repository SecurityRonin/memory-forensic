//! Windows UNICODE_STRING reader.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// Read a Windows `_UNICODE_STRING` at the given virtual address.
///
/// Reads `Length` (u16 at offset 0) and `Buffer` (pointer at offset 8),
/// then reads `Length` bytes of UTF-16LE from `Buffer` and converts to
/// a Rust `String`.
pub fn read_unicode_string<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ustr_vaddr: u64,
) -> crate::Result<String> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Encode a Rust &str as UTF-16LE bytes.
    fn utf16le_bytes(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
    }

    /// Build a _UNICODE_STRING struct in memory (16 bytes):
    /// [0..2]: Length (u16 LE) — number of bytes, not chars
    /// [2..4]: MaximumLength (u16 LE)
    /// [8..16]: Buffer (u64 LE pointer to UTF-16LE data)
    fn build_unicode_string_bytes(length: u16, max_length: u16, buffer_ptr: u64) -> Vec<u8> {
        let mut data = vec![0u8; 16];
        data[0..2].copy_from_slice(&length.to_le_bytes());
        data[2..4].copy_from_slice(&max_length.to_le_bytes());
        data[8..16].copy_from_slice(&buffer_ptr.to_le_bytes());
        data
    }

    fn make_unicode_reader(
        data: &[u8],
        vaddr: u64,
        paddr: u64,
    ) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn read_simple_unicode_string() {
        // "ntoskrnl.exe" — 12 chars, 24 bytes as UTF-16LE
        let text = "ntoskrnl.exe";
        let utf16 = utf16le_bytes(text);
        let length = utf16.len() as u16; // 24

        // Layout in one 4KB page at paddr 0x10_0000, vaddr 0xFFFF_8000_0000_0000:
        // offset 0..16: _UNICODE_STRING struct
        // offset 256..256+24: UTF-16LE string data
        let vaddr_base = 0xFFFF_8000_0000_0000u64;
        let paddr_base = 0x10_0000u64;
        let string_data_offset = 256u64;
        let buffer_vaddr = vaddr_base + string_data_offset;

        let ustr_bytes = build_unicode_string_bytes(length, length, buffer_vaddr);

        // Build the page data: unicode_string struct at start, UTF-16 data at offset 256
        let mut page_data = vec![0u8; 4096];
        page_data[0..16].copy_from_slice(&ustr_bytes);
        page_data[string_data_offset as usize..string_data_offset as usize + utf16.len()]
            .copy_from_slice(&utf16);

        let reader = make_unicode_reader(&page_data, vaddr_base, paddr_base);
        let result = read_unicode_string(&reader, vaddr_base).unwrap();
        assert_eq!(result, "ntoskrnl.exe");
    }

    #[test]
    fn read_empty_unicode_string() {
        // Length=0, Buffer=0 → should return empty string
        let vaddr_base = 0xFFFF_8000_0000_0000u64;
        let paddr_base = 0x10_0000u64;

        let ustr_bytes = build_unicode_string_bytes(0, 0, 0);

        let mut page_data = vec![0u8; 4096];
        page_data[0..16].copy_from_slice(&ustr_bytes);

        let reader = make_unicode_reader(&page_data, vaddr_base, paddr_base);
        let result = read_unicode_string(&reader, vaddr_base).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn read_unicode_string_with_null_terminator() {
        // "hal.dll\0" — string with trailing null should be trimmed
        let text = "hal.dll\0";
        let utf16 = utf16le_bytes(text);
        // Length includes the null terminator bytes
        let length = utf16.len() as u16;

        let vaddr_base = 0xFFFF_8000_0000_0000u64;
        let paddr_base = 0x10_0000u64;
        let string_data_offset = 256u64;
        let buffer_vaddr = vaddr_base + string_data_offset;

        let ustr_bytes = build_unicode_string_bytes(length, length, buffer_vaddr);

        let mut page_data = vec![0u8; 4096];
        page_data[0..16].copy_from_slice(&ustr_bytes);
        page_data[string_data_offset as usize..string_data_offset as usize + utf16.len()]
            .copy_from_slice(&utf16);

        let reader = make_unicode_reader(&page_data, vaddr_base, paddr_base);
        let result = read_unicode_string(&reader, vaddr_base).unwrap();
        assert_eq!(result, "hal.dll");
    }
}
