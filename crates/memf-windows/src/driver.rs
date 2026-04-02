//! Windows loaded driver walker.
//!
//! Enumerates loaded kernel drivers by walking `PsLoadedModuleList`,
//! a `_LIST_ENTRY` chain of `_KLDR_DATA_TABLE_ENTRY` structures.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;
use crate::{Result, WinDriverInfo};

/// Walk the Windows loaded driver list starting from `PsLoadedModuleList`.
///
/// `module_list_vaddr` is the virtual address of the `PsLoadedModuleList` symbol.
pub fn walk_drivers<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    module_list_vaddr: u64,
) -> Result<Vec<WinDriverInfo>> {
    todo!()
}

/// Read driver info from a single `_KLDR_DATA_TABLE_ENTRY`.
fn read_driver_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    entry_addr: u64,
) -> Result<WinDriverInfo> {
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
    /// [0..2]: Length (u16 LE)
    /// [2..4]: MaximumLength (u16 LE)
    /// [8..16]: Buffer (u64 LE pointer)
    fn build_unicode_string_at(buf: &mut [u8], offset: usize, length: u16, buffer_ptr: u64) {
        buf[offset..offset + 2].copy_from_slice(&length.to_le_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&length.to_le_bytes());
        buf[offset + 8..offset + 16].copy_from_slice(&buffer_ptr.to_le_bytes());
    }

    /// Build a _KLDR_DATA_TABLE_ENTRY in a byte buffer at the given offset.
    ///
    /// Layout (from windows_kernel_preset):
    /// - InLoadOrderLinks (offset 0): _LIST_ENTRY { Flink@0, Blink@8 }
    /// - DllBase (offset 48): pointer
    /// - SizeOfImage (offset 64): u32
    /// - FullDllName (offset 72): _UNICODE_STRING
    /// - BaseDllName (offset 88): _UNICODE_STRING
    fn build_kldr_entry(
        buf: &mut [u8],
        entry_offset: usize,
        flink: u64,
        blink: u64,
        dll_base: u64,
        size_of_image: u32,
        full_name_ptr: u64,
        full_name_len: u16,
        base_name_ptr: u64,
        base_name_len: u16,
    ) {
        // InLoadOrderLinks.Flink (offset 0)
        buf[entry_offset..entry_offset + 8].copy_from_slice(&flink.to_le_bytes());
        // InLoadOrderLinks.Blink (offset 8)
        buf[entry_offset + 8..entry_offset + 16].copy_from_slice(&blink.to_le_bytes());
        // DllBase (offset 48)
        buf[entry_offset + 48..entry_offset + 56].copy_from_slice(&dll_base.to_le_bytes());
        // SizeOfImage (offset 64)
        buf[entry_offset + 64..entry_offset + 68].copy_from_slice(&size_of_image.to_le_bytes());
        // FullDllName (offset 72) — _UNICODE_STRING
        build_unicode_string_at(buf, entry_offset + 72, full_name_len, full_name_ptr);
        // BaseDllName (offset 88) — _UNICODE_STRING
        build_unicode_string_at(buf, entry_offset + 88, base_name_len, base_name_ptr);
    }

    /// Place UTF-16LE string data at a physical offset and return the byte length.
    fn place_utf16_string(buf: &mut [u8], phys_offset: usize, s: &str) -> u16 {
        let utf16 = utf16le_bytes(s);
        let len = utf16.len();
        buf[phys_offset..phys_offset + len].copy_from_slice(&utf16);
        len as u16
    }

    #[test]
    fn walk_two_drivers() {
        // Two _KLDR_DATA_TABLE_ENTRY structs in a circular linked list.
        //
        // Memory layout (all on one 4KB page mapped at vaddr 0xFFFF_8000_0000_0000):
        //   offset 0..16:   PsLoadedModuleList sentinel (_LIST_ENTRY)
        //   offset 256..512: Driver A (_KLDR_DATA_TABLE_ENTRY, 256 bytes)
        //   offset 512..768: Driver B (_KLDR_DATA_TABLE_ENTRY, 256 bytes)
        //   offset 1024..:  UTF-16LE string data

        let vaddr_base = 0xFFFF_8000_0000_0000u64;
        let paddr_base = 0x10_0000u64;
        let mut page = vec![0u8; 4096];

        // Virtual addresses for each structure
        let sentinel_vaddr = vaddr_base; // offset 0
        let entry_a_vaddr = vaddr_base + 256; // offset 256
        let entry_b_vaddr = vaddr_base + 512; // offset 512

        // The list links are at offset 0 within _KLDR_DATA_TABLE_ENTRY
        // (InLoadOrderLinks), so the Flink/Blink point to the InLoadOrderLinks
        // field of the next/prev entry.
        let link_a = entry_a_vaddr; // InLoadOrderLinks of A = entry_a_vaddr + 0
        let link_b = entry_b_vaddr; // InLoadOrderLinks of B = entry_b_vaddr + 0

        // Circular: sentinel → A → B → sentinel
        // Sentinel.Flink = link_a, Sentinel.Blink = link_b
        page[0..8].copy_from_slice(&link_a.to_le_bytes()); // sentinel Flink
        page[8..16].copy_from_slice(&link_b.to_le_bytes()); // sentinel Blink

        // String data locations (physical offsets within the page)
        let str_offset_a_full = 1024usize;
        let str_offset_a_base = 1200usize;
        let str_offset_b_full = 1400usize;
        let str_offset_b_base = 1600usize;

        // Driver A: ntoskrnl.exe
        let full_a = r"\SystemRoot\system32\ntoskrnl.exe";
        let base_a = "ntoskrnl.exe";
        let full_a_len = place_utf16_string(&mut page, str_offset_a_full, full_a);
        let base_a_len = place_utf16_string(&mut page, str_offset_a_base, base_a);

        build_kldr_entry(
            &mut page,
            256, // entry A at page offset 256
            link_b,            // A.Flink → B
            sentinel_vaddr,    // A.Blink → sentinel
            0xFFFFF800_00000000, // DllBase
            0x0080_0000,       // SizeOfImage = 8MB
            vaddr_base + str_offset_a_full as u64, // FullDllName buffer ptr
            full_a_len,
            vaddr_base + str_offset_a_base as u64, // BaseDllName buffer ptr
            base_a_len,
        );

        // Driver B: hal.dll
        let full_b = r"\SystemRoot\system32\hal.dll";
        let base_b = "hal.dll";
        let full_b_len = place_utf16_string(&mut page, str_offset_b_full, full_b);
        let base_b_len = place_utf16_string(&mut page, str_offset_b_base, base_b);

        build_kldr_entry(
            &mut page,
            512, // entry B at page offset 512
            sentinel_vaddr,    // B.Flink → sentinel (end of list)
            link_a,            // B.Blink → A
            0xFFFFF800_01000000, // DllBase
            0x0010_0000,       // SizeOfImage = 1MB
            vaddr_base + str_offset_b_full as u64,
            full_b_len,
            vaddr_base + str_offset_b_base as u64,
            base_b_len,
        );

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr_base, paddr_base, flags::WRITABLE)
            .write_phys(paddr_base, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let drivers = walk_drivers(&reader, sentinel_vaddr).unwrap();
        assert_eq!(drivers.len(), 2);

        // Driver A
        assert_eq!(drivers[0].name, "ntoskrnl.exe");
        assert_eq!(
            drivers[0].full_path,
            r"\SystemRoot\system32\ntoskrnl.exe"
        );
        assert_eq!(drivers[0].base_addr, 0xFFFFF800_00000000);
        assert_eq!(drivers[0].size, 0x0080_0000);
        assert_eq!(drivers[0].vaddr, entry_a_vaddr);

        // Driver B
        assert_eq!(drivers[1].name, "hal.dll");
        assert_eq!(drivers[1].full_path, r"\SystemRoot\system32\hal.dll");
        assert_eq!(drivers[1].base_addr, 0xFFFFF800_01000000);
        assert_eq!(drivers[1].size, 0x0010_0000);
        assert_eq!(drivers[1].vaddr, entry_b_vaddr);
    }

    #[test]
    fn walk_empty_driver_list() {
        // PsLoadedModuleList.Flink points to itself → empty list.
        let vaddr_base = 0xFFFF_8000_0000_0000u64;
        let paddr_base = 0x10_0000u64;

        let mut page = vec![0u8; 4096];
        // sentinel Flink → sentinel (self-referential = empty)
        page[0..8].copy_from_slice(&vaddr_base.to_le_bytes());
        page[8..16].copy_from_slice(&vaddr_base.to_le_bytes());

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr_base, paddr_base, flags::WRITABLE)
            .write_phys(paddr_base, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let drivers = walk_drivers(&reader, vaddr_base).unwrap();
        assert!(drivers.is_empty());
    }

    #[test]
    fn walk_single_driver() {
        // One _KLDR_DATA_TABLE_ENTRY in a circular list.
        let vaddr_base = 0xFFFF_8000_0000_0000u64;
        let paddr_base = 0x10_0000u64;
        let mut page = vec![0u8; 4096];

        let sentinel_vaddr = vaddr_base;
        let entry_vaddr = vaddr_base + 256;
        let link_entry = entry_vaddr; // InLoadOrderLinks at offset 0

        // Sentinel → entry → sentinel (circular with one node)
        page[0..8].copy_from_slice(&link_entry.to_le_bytes()); // sentinel.Flink
        page[8..16].copy_from_slice(&link_entry.to_le_bytes()); // sentinel.Blink

        let str_offset_full = 1024usize;
        let str_offset_base = 1200usize;

        let full_name = r"\SystemRoot\system32\ACPI.sys";
        let base_name = "ACPI.sys";
        let full_len = place_utf16_string(&mut page, str_offset_full, full_name);
        let base_len = place_utf16_string(&mut page, str_offset_base, base_name);

        build_kldr_entry(
            &mut page,
            256,
            sentinel_vaddr,    // entry.Flink → sentinel
            sentinel_vaddr,    // entry.Blink → sentinel
            0xFFFFF800_02000000, // DllBase
            0x0004_0000,       // SizeOfImage = 256KB
            vaddr_base + str_offset_full as u64,
            full_len,
            vaddr_base + str_offset_base as u64,
            base_len,
        );

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr_base, paddr_base, flags::WRITABLE)
            .write_phys(paddr_base, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let drivers = walk_drivers(&reader, sentinel_vaddr).unwrap();
        assert_eq!(drivers.len(), 1);
        assert_eq!(drivers[0].name, "ACPI.sys");
        assert_eq!(drivers[0].full_path, r"\SystemRoot\system32\ACPI.sys");
        assert_eq!(drivers[0].base_addr, 0xFFFFF800_02000000);
        assert_eq!(drivers[0].size, 0x0004_0000);
        assert_eq!(drivers[0].vaddr, entry_vaddr);
    }
}
