//! Windows DLL walker.
//!
//! Enumerates loaded DLLs for a process by walking
//! `_PEB` -> `_PEB_LDR_DATA` -> `InLoadOrderModuleList`,
//! a `_LIST_ENTRY` chain of `_LDR_DATA_TABLE_ENTRY` structures.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;
use crate::{Error, Result, WinDllInfo};

/// Walk DLLs loaded in a process.
///
/// `peb_addr` is the virtual address of the process's `_PEB`.
/// Note: This must be called with the process's own page table (CR3)
/// since PEB and LDR live in user-mode virtual address space.
pub fn walk_dlls<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    peb_addr: u64,
) -> Result<Vec<WinDllInfo>> {
    // Read Ldr pointer from _PEB at offset 0x18
    let ldr_addr: u64 = reader.read_field(peb_addr, "_PEB", "Ldr")?;

    if ldr_addr == 0 {
        return Err(Error::Walker("PEB.Ldr is NULL".into()));
    }

    // Get InLoadOrderModuleList offset from _PEB_LDR_DATA
    let in_load_order_offset = reader
        .symbols()
        .field_offset("_PEB_LDR_DATA", "InLoadOrderModuleList")
        .ok_or_else(|| {
            Error::Core(memf_core::Error::MissingSymbol(
                "_PEB_LDR_DATA.InLoadOrderModuleList".into(),
            ))
        })?;

    let list_head_vaddr = ldr_addr.wrapping_add(in_load_order_offset);

    let entries = reader.walk_list_with(
        list_head_vaddr,
        "_LIST_ENTRY",
        "Flink",
        "_LDR_DATA_TABLE_ENTRY",
        "InLoadOrderLinks",
    )?;

    entries
        .into_iter()
        .enumerate()
        .map(|(idx, entry_addr)| read_dll_info(reader, entry_addr, idx as u32))
        .collect()
}

/// Read DLL info from a single `_LDR_DATA_TABLE_ENTRY`.
fn read_dll_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    entry_addr: u64,
    load_order: u32,
) -> Result<WinDllInfo> {
    // DllBase (pointer at offset 48)
    let base_addr: u64 = reader.read_field(entry_addr, "_LDR_DATA_TABLE_ENTRY", "DllBase")?;

    // SizeOfImage (u32 at offset 64)
    let size_of_image: u32 =
        reader.read_field(entry_addr, "_LDR_DATA_TABLE_ENTRY", "SizeOfImage")?;

    // FullDllName (_UNICODE_STRING at offset 72)
    let full_dll_name_offset = reader
        .symbols()
        .field_offset("_LDR_DATA_TABLE_ENTRY", "FullDllName")
        .ok_or_else(|| {
            Error::Core(memf_core::Error::MissingSymbol(
                "_LDR_DATA_TABLE_ENTRY.FullDllName".into(),
            ))
        })?;
    let full_path = read_unicode_string(reader, entry_addr.wrapping_add(full_dll_name_offset))?;

    // BaseDllName (_UNICODE_STRING at offset 88)
    let base_dll_name_offset = reader
        .symbols()
        .field_offset("_LDR_DATA_TABLE_ENTRY", "BaseDllName")
        .ok_or_else(|| {
            Error::Core(memf_core::Error::MissingSymbol(
                "_LDR_DATA_TABLE_ENTRY.BaseDllName".into(),
            ))
        })?;
    let name = read_unicode_string(reader, entry_addr.wrapping_add(base_dll_name_offset))?;

    Ok(WinDllInfo {
        name,
        full_path,
        base_addr,
        size: u64::from(size_of_image),
        load_order,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder};
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

    /// Build a _LDR_DATA_TABLE_ENTRY in a byte buffer at the given offset.
    ///
    /// Layout (from windows_kernel_preset):
    /// - InLoadOrderLinks (offset 0): _LIST_ENTRY { Flink@0, Blink@8 }
    /// - DllBase (offset 48): pointer
    /// - SizeOfImage (offset 64): u32
    /// - FullDllName (offset 72): _UNICODE_STRING
    /// - BaseDllName (offset 88): _UNICODE_STRING
    fn build_ldr_entry(
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
        // FullDllName (offset 72) -- _UNICODE_STRING
        build_unicode_string_at(buf, entry_offset + 72, full_name_len, full_name_ptr);
        // BaseDllName (offset 88) -- _UNICODE_STRING
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
    fn walk_two_dlls() {
        // Two _LDR_DATA_TABLE_ENTRY structs in a circular linked list,
        // reachable from PEB -> LDR -> InLoadOrderModuleList.
        //
        // Memory layout (two 4KB pages mapped contiguously):
        //   Page 1 (offset 0..4096):
        //     0..2048:  PEB (Ldr pointer at offset 0x18)
        //     2048..2112: _PEB_LDR_DATA (InLoadOrderModuleList at offset 16)
        //   Page 2 (offset 4096..8192):
        //     0..256:   Entry A (_LDR_DATA_TABLE_ENTRY)
        //     256..512: Entry B (_LDR_DATA_TABLE_ENTRY)
        //     1024..:   UTF-16LE string data

        let vaddr_base = 0xFFFF_8000_0000_0000u64;
        let paddr_base = 0x10_0000u64;

        // We need two pages: one for PEB+LDR, one for entries+strings
        let vaddr_page1 = vaddr_base; // PEB + LDR
        let vaddr_page2 = vaddr_base + 0x1000; // entries + strings
        let paddr_page1 = paddr_base;
        let paddr_page2 = paddr_base + 0x1000;

        let mut page1 = vec![0u8; 4096];
        let mut page2 = vec![0u8; 4096];

        // PEB at vaddr_page1
        let peb_vaddr = vaddr_page1;
        let ldr_vaddr = vaddr_page1 + 2048; // LDR at page1 offset 2048

        // PEB.Ldr (offset 0x18) = pointer to _PEB_LDR_DATA
        page1[0x18..0x20].copy_from_slice(&ldr_vaddr.to_le_bytes());

        // _PEB_LDR_DATA at page1 offset 2048
        // InLoadOrderModuleList at offset 16 within _PEB_LDR_DATA
        // This is a _LIST_ENTRY acting as the list head (sentinel).
        let list_head_vaddr = ldr_vaddr + 16; // vaddr of InLoadOrderModuleList

        // Entry virtual addresses (on page 2)
        let entry_a_vaddr = vaddr_page2; // page2 offset 0
        let entry_b_vaddr = vaddr_page2 + 256; // page2 offset 256

        // InLoadOrderLinks are at offset 0 of each _LDR_DATA_TABLE_ENTRY,
        // so link addresses equal the entry addresses.
        let link_a = entry_a_vaddr;
        let link_b = entry_b_vaddr;

        // Circular list: head -> A -> B -> head
        // head.Flink = link_a, head.Blink = link_b
        let ldr_offset = 2048usize;
        page1[ldr_offset + 16..ldr_offset + 24].copy_from_slice(&link_a.to_le_bytes()); // Flink
        page1[ldr_offset + 24..ldr_offset + 32].copy_from_slice(&list_head_vaddr.to_le_bytes()); // Blink (not used by walker, but set for correctness)

        // String data locations (physical offsets within page2)
        let str_offset_a_full = 1024usize;
        let str_offset_a_base = 1200usize;
        let str_offset_b_full = 1400usize;
        let str_offset_b_base = 1600usize;

        // DLL A: ntdll.dll
        let full_a = r"C:\Windows\System32\ntdll.dll";
        let base_a = "ntdll.dll";
        let full_a_len = place_utf16_string(&mut page2, str_offset_a_full, full_a);
        let base_a_len = place_utf16_string(&mut page2, str_offset_a_base, base_a);

        build_ldr_entry(
            &mut page2,
            0,                                      // entry A at page2 offset 0
            link_b,                                 // A.Flink -> B
            list_head_vaddr,                        // A.Blink -> head
            0x7FF8_0000_0000,                       // DllBase
            0x001F_0000,                            // SizeOfImage
            vaddr_page2 + str_offset_a_full as u64, // FullDllName buffer ptr
            full_a_len,
            vaddr_page2 + str_offset_a_base as u64, // BaseDllName buffer ptr
            base_a_len,
        );

        // DLL B: kernel32.dll
        let full_b = r"C:\Windows\System32\kernel32.dll";
        let base_b = "kernel32.dll";
        let full_b_len = place_utf16_string(&mut page2, str_offset_b_full, full_b);
        let base_b_len = place_utf16_string(&mut page2, str_offset_b_base, base_b);

        build_ldr_entry(
            &mut page2,
            256,              // entry B at page2 offset 256
            list_head_vaddr,  // B.Flink -> head (end of list)
            link_a,           // B.Blink -> A
            0x7FF8_1000_0000, // DllBase
            0x0012_0000,      // SizeOfImage
            vaddr_page2 + str_offset_b_full as u64,
            full_b_len,
            vaddr_page2 + str_offset_b_base as u64,
            base_b_len,
        );

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr_page1, paddr_page1, flags::WRITABLE)
            .map_4k(vaddr_page2, paddr_page2, flags::WRITABLE)
            .write_phys(paddr_page1, &page1)
            .write_phys(paddr_page2, &page2)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let dlls = walk_dlls(&reader, peb_vaddr).unwrap();
        assert_eq!(dlls.len(), 2);

        // DLL A (load_order = 0)
        assert_eq!(dlls[0].name, "ntdll.dll");
        assert_eq!(dlls[0].full_path, r"C:\Windows\System32\ntdll.dll");
        assert_eq!(dlls[0].base_addr, 0x7FF8_0000_0000);
        assert_eq!(dlls[0].size, 0x001F_0000);
        assert_eq!(dlls[0].load_order, 0);

        // DLL B (load_order = 1)
        assert_eq!(dlls[1].name, "kernel32.dll");
        assert_eq!(dlls[1].full_path, r"C:\Windows\System32\kernel32.dll");
        assert_eq!(dlls[1].base_addr, 0x7FF8_1000_0000);
        assert_eq!(dlls[1].size, 0x0012_0000);
        assert_eq!(dlls[1].load_order, 1);
    }

    #[test]
    fn walk_no_dlls_null_ldr() {
        // PEB with Ldr = 0 (null pointer) should return Walker error.
        let vaddr_base = 0xFFFF_8000_0000_0000u64;
        let paddr_base = 0x10_0000u64;

        let mut page = vec![0u8; 4096];
        // PEB at vaddr_base: Ldr (offset 0x18) = 0 (already zero-filled)
        // Explicitly ensure it's zero:
        page[0x18..0x20].copy_from_slice(&0u64.to_le_bytes());

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr_base, paddr_base, flags::WRITABLE)
            .write_phys(paddr_base, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_dlls(&reader, vaddr_base);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("PEB.Ldr is NULL"),
            "expected Walker error about NULL Ldr, got: {err_msg}"
        );
    }

    #[test]
    fn walk_single_dll() {
        // One _LDR_DATA_TABLE_ENTRY in the InLoadOrderModuleList.
        let vaddr_base = 0xFFFF_8000_0000_0000u64;
        let paddr_base = 0x10_0000u64;

        let vaddr_page1 = vaddr_base;
        let vaddr_page2 = vaddr_base + 0x1000;
        let paddr_page1 = paddr_base;
        let paddr_page2 = paddr_base + 0x1000;

        let mut page1 = vec![0u8; 4096];
        let mut page2 = vec![0u8; 4096];

        // PEB at vaddr_page1
        let peb_vaddr = vaddr_page1;
        let ldr_vaddr = vaddr_page1 + 2048;

        // PEB.Ldr -> _PEB_LDR_DATA
        page1[0x18..0x20].copy_from_slice(&ldr_vaddr.to_le_bytes());

        // List head at ldr_vaddr + 16
        let list_head_vaddr = ldr_vaddr + 16;

        // Single entry on page 2
        let entry_vaddr = vaddr_page2;
        let link_entry = entry_vaddr; // InLoadOrderLinks at offset 0

        // Circular: head -> entry -> head
        let ldr_offset = 2048usize;
        page1[ldr_offset + 16..ldr_offset + 24].copy_from_slice(&link_entry.to_le_bytes()); // head.Flink
        page1[ldr_offset + 24..ldr_offset + 32].copy_from_slice(&list_head_vaddr.to_le_bytes()); // head.Blink

        // String data
        let str_offset_full = 1024usize;
        let str_offset_base = 1200usize;

        let full_name = r"C:\Windows\System32\user32.dll";
        let base_name = "user32.dll";
        let full_len = place_utf16_string(&mut page2, str_offset_full, full_name);
        let base_len = place_utf16_string(&mut page2, str_offset_base, base_name);

        build_ldr_entry(
            &mut page2,
            0,
            list_head_vaddr,  // entry.Flink -> head
            list_head_vaddr,  // entry.Blink -> head
            0x7FF8_2000_0000, // DllBase
            0x0019_E000,      // SizeOfImage
            vaddr_page2 + str_offset_full as u64,
            full_len,
            vaddr_page2 + str_offset_base as u64,
            base_len,
        );

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr_page1, paddr_page1, flags::WRITABLE)
            .map_4k(vaddr_page2, paddr_page2, flags::WRITABLE)
            .write_phys(paddr_page1, &page1)
            .write_phys(paddr_page2, &page2)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let dlls = walk_dlls(&reader, peb_vaddr).unwrap();
        assert_eq!(dlls.len(), 1);
        assert_eq!(dlls[0].name, "user32.dll");
        assert_eq!(dlls[0].full_path, r"C:\Windows\System32\user32.dll");
        assert_eq!(dlls[0].base_addr, 0x7FF8_2000_0000);
        assert_eq!(dlls[0].size, 0x0019_E000);
        assert_eq!(dlls[0].load_order, 0);
    }
}
