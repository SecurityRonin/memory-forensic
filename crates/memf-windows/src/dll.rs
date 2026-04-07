//! Windows DLL walker.
//!
//! Enumerates loaded DLLs for a process by walking
//! `_PEB` -> `_PEB_LDR_DATA` -> `InLoadOrderModuleList`,
//! a `_LIST_ENTRY` chain of `_LDR_DATA_TABLE_ENTRY` structures.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;
use crate::{Error, LdrModuleInfo, Result, WinDllInfo};

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

/// Cross-reference all three PEB LDR module lists.
///
/// Walks `InLoadOrderModuleList`, `InMemoryOrderModuleList`, and
/// `InInitializationOrderModuleList`, then merges results by `DllBase`.
/// Each returned entry indicates which lists contained that module.
///
/// A module missing from one or more lists may indicate DLL unlinking
/// (a technique used by malware to hide injected DLLs).
pub fn walk_ldr_modules<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    peb_addr: u64,
) -> Result<Vec<LdrModuleInfo>> {
    todo!("walk_ldr_modules")
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

    // -----------------------------------------------------------------------
    // LdrModules cross-reference tests
    // -----------------------------------------------------------------------

    /// Helper: build a _LDR_DATA_TABLE_ENTRY with all three link sets.
    ///
    /// Offsets within _LDR_DATA_TABLE_ENTRY:
    ///   InLoadOrderLinks          @ 0  (Flink@0,  Blink@8)
    ///   InMemoryOrderLinks        @ 16 (Flink@16, Blink@24)
    ///   InInitializationOrderLinks@ 32 (Flink@32, Blink@40)
    ///   DllBase                   @ 48
    ///   SizeOfImage               @ 64
    ///   FullDllName               @ 72
    ///   BaseDllName               @ 88
    #[allow(clippy::too_many_arguments)]
    fn build_ldr_entry_full(
        buf: &mut [u8],
        off: usize,
        load_flink: u64,
        load_blink: u64,
        mem_flink: u64,
        mem_blink: u64,
        init_flink: u64,
        init_blink: u64,
        dll_base: u64,
        size_of_image: u32,
        full_name_ptr: u64,
        full_name_len: u16,
        base_name_ptr: u64,
        base_name_len: u16,
    ) {
        // InLoadOrderLinks (offset 0)
        buf[off..off + 8].copy_from_slice(&load_flink.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&load_blink.to_le_bytes());
        // InMemoryOrderLinks (offset 16)
        buf[off + 16..off + 24].copy_from_slice(&mem_flink.to_le_bytes());
        buf[off + 24..off + 32].copy_from_slice(&mem_blink.to_le_bytes());
        // InInitializationOrderLinks (offset 32)
        buf[off + 32..off + 40].copy_from_slice(&init_flink.to_le_bytes());
        buf[off + 40..off + 48].copy_from_slice(&init_blink.to_le_bytes());
        // DllBase (offset 48)
        buf[off + 48..off + 56].copy_from_slice(&dll_base.to_le_bytes());
        // SizeOfImage (offset 64)
        buf[off + 64..off + 68].copy_from_slice(&size_of_image.to_le_bytes());
        // FullDllName (offset 72)
        build_unicode_string_at(buf, off + 72, full_name_len, full_name_ptr);
        // BaseDllName (offset 88)
        build_unicode_string_at(buf, off + 88, base_name_len, base_name_ptr);
    }

    #[test]
    fn ldr_modules_all_three_lists() {
        // Two DLLs present in all three lists → in_load, in_mem, in_init all true.
        let vp1 = 0xFFFF_8000_0000_0000u64; // PEB + LDR
        let vp2 = 0xFFFF_8000_0000_1000u64; // entries + strings
        let pp1 = 0x10_0000u64;
        let pp2 = 0x11_0000u64;

        let mut p1 = vec![0u8; 4096];
        let mut p2 = vec![0u8; 4096];

        let peb_vaddr = vp1;
        let ldr_vaddr = vp1 + 2048;

        // PEB.Ldr → ldr_vaddr
        p1[0x18..0x20].copy_from_slice(&ldr_vaddr.to_le_bytes());

        // List heads within _PEB_LDR_DATA:
        let load_head = ldr_vaddr + 16;
        let mem_head = ldr_vaddr + 32;
        let init_head = ldr_vaddr + 48;

        // Entry addresses
        let ea = vp2;         // entry A at page2 offset 0
        let eb = vp2 + 256;   // entry B at page2 offset 256

        // --- InLoadOrderModuleList: head → A → B → head ---
        // head.Flink → entry_A + 0 (InLoadOrderLinks)
        let ldr_off = 2048usize;
        p1[ldr_off + 16..ldr_off + 24].copy_from_slice(&(ea).to_le_bytes());
        p1[ldr_off + 24..ldr_off + 32].copy_from_slice(&(eb).to_le_bytes());

        // --- InMemoryOrderModuleList: head → A → B → head ---
        // head.Flink → entry_A + 16 (InMemoryOrderLinks)
        p1[ldr_off + 32..ldr_off + 40].copy_from_slice(&(ea + 16).to_le_bytes());
        p1[ldr_off + 40..ldr_off + 48].copy_from_slice(&(eb + 16).to_le_bytes());

        // --- InInitializationOrderModuleList: head → A → B → head ---
        // head.Flink → entry_A + 32 (InInitializationOrderLinks)
        p1[ldr_off + 48..ldr_off + 56].copy_from_slice(&(ea + 32).to_le_bytes());
        p1[ldr_off + 56..ldr_off + 64].copy_from_slice(&(eb + 32).to_le_bytes());

        // Strings
        let full_a = r"C:\Windows\System32\ntdll.dll";
        let base_a = "ntdll.dll";
        let full_b = r"C:\Windows\System32\kernel32.dll";
        let base_b = "kernel32.dll";
        let fa_len = place_utf16_string(&mut p2, 1024, full_a);
        let ba_len = place_utf16_string(&mut p2, 1200, base_a);
        let fb_len = place_utf16_string(&mut p2, 1400, full_b);
        let bb_len = place_utf16_string(&mut p2, 1600, base_b);

        // Entry A: all three lists → B, blink → head
        build_ldr_entry_full(
            &mut p2, 0,
            eb,             load_head,       // InLoadOrder: Flink→B, Blink→head
            eb + 16,        mem_head,        // InMemoryOrder: Flink→B+16, Blink→head
            eb + 32,        init_head,       // InInitOrder: Flink→B+32, Blink→head
            0x7FF8_0000_0000, 0x001F_0000,
            vp2 + 1024, fa_len,
            vp2 + 1200, ba_len,
        );

        // Entry B: all three lists → head, blink → A
        build_ldr_entry_full(
            &mut p2, 256,
            load_head,      ea,              // InLoadOrder: Flink→head, Blink→A
            mem_head,       ea + 16,         // InMemoryOrder: Flink→head, Blink→A+16
            init_head,      ea + 32,         // InInitOrder: Flink→head, Blink→A+32
            0x7FF8_1000_0000, 0x0012_0000,
            vp2 + 1400, fb_len,
            vp2 + 1600, bb_len,
        );

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vp1, pp1, flags::WRITABLE)
            .map_4k(vp2, pp2, flags::WRITABLE)
            .write_phys(pp1, &p1)
            .write_phys(pp2, &p2)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let mods = walk_ldr_modules(&reader, peb_vaddr).unwrap();
        assert_eq!(mods.len(), 2);

        let ntdll = mods.iter().find(|m| m.name == "ntdll.dll").unwrap();
        assert_eq!(ntdll.base_addr, 0x7FF8_0000_0000);
        assert!(ntdll.in_load);
        assert!(ntdll.in_mem);
        assert!(ntdll.in_init);

        let k32 = mods.iter().find(|m| m.name == "kernel32.dll").unwrap();
        assert_eq!(k32.base_addr, 0x7FF8_1000_0000);
        assert!(k32.in_load);
        assert!(k32.in_mem);
        assert!(k32.in_init);
    }

    #[test]
    fn ldr_modules_detects_unlinked_dll() {
        // One DLL (B) is unlinked from InInitializationOrderModuleList.
        // Expected: B.in_init = false, everything else = true.
        let vp1 = 0xFFFF_8000_0000_0000u64;
        let vp2 = 0xFFFF_8000_0000_1000u64;
        let pp1 = 0x10_0000u64;
        let pp2 = 0x11_0000u64;

        let mut p1 = vec![0u8; 4096];
        let mut p2 = vec![0u8; 4096];

        let peb_vaddr = vp1;
        let ldr_vaddr = vp1 + 2048;
        p1[0x18..0x20].copy_from_slice(&ldr_vaddr.to_le_bytes());

        let load_head = ldr_vaddr + 16;
        let mem_head = ldr_vaddr + 32;
        let init_head = ldr_vaddr + 48;

        let ea = vp2;
        let eb = vp2 + 256;

        let ldr_off = 2048usize;

        // InLoadOrder: head → A → B → head (both present)
        p1[ldr_off + 16..ldr_off + 24].copy_from_slice(&ea.to_le_bytes());
        p1[ldr_off + 24..ldr_off + 32].copy_from_slice(&(eb).to_le_bytes());

        // InMemoryOrder: head → A → B → head (both present)
        p1[ldr_off + 32..ldr_off + 40].copy_from_slice(&(ea + 16).to_le_bytes());
        p1[ldr_off + 40..ldr_off + 48].copy_from_slice(&(eb + 16).to_le_bytes());

        // InInitializationOrder: head → A → head (B MISSING — unlinked)
        p1[ldr_off + 48..ldr_off + 56].copy_from_slice(&(ea + 32).to_le_bytes());
        p1[ldr_off + 56..ldr_off + 64].copy_from_slice(&(ea + 32).to_le_bytes());

        // Strings
        let full_a = r"C:\Windows\System32\ntdll.dll";
        let base_a = "ntdll.dll";
        let full_b = r"C:\evil\injected.dll";
        let base_b = "injected.dll";
        let fa_len = place_utf16_string(&mut p2, 1024, full_a);
        let ba_len = place_utf16_string(&mut p2, 1200, base_a);
        let fb_len = place_utf16_string(&mut p2, 1400, full_b);
        let bb_len = place_utf16_string(&mut p2, 1600, base_b);

        // Entry A: in all three lists
        build_ldr_entry_full(
            &mut p2, 0,
            eb,             load_head,       // InLoadOrder → B → head
            eb + 16,        mem_head,        // InMemoryOrder → B+16 → head
            init_head,      init_head,       // InInitOrder → head (A is only entry, wraps)
            0x7FF8_0000_0000, 0x001F_0000,
            vp2 + 1024, fa_len,
            vp2 + 1200, ba_len,
        );

        // Entry B: in Load + Memory, but NOT in Init
        build_ldr_entry_full(
            &mut p2, 256,
            load_head,      ea,              // InLoadOrder → head
            mem_head,       ea + 16,         // InMemoryOrder → head
            0,              0,               // InInitOrder: zeroed (unlinked)
            0x7FF8_DEAD_0000, 0x0001_0000,
            vp2 + 1400, fb_len,
            vp2 + 1600, bb_len,
        );

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vp1, pp1, flags::WRITABLE)
            .map_4k(vp2, pp2, flags::WRITABLE)
            .write_phys(pp1, &p1)
            .write_phys(pp2, &p2)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let mods = walk_ldr_modules(&reader, peb_vaddr).unwrap();
        assert_eq!(mods.len(), 2);

        let ntdll = mods.iter().find(|m| m.name == "ntdll.dll").unwrap();
        assert!(ntdll.in_load);
        assert!(ntdll.in_mem);
        assert!(ntdll.in_init);

        let injected = mods.iter().find(|m| m.name == "injected.dll").unwrap();
        assert_eq!(injected.base_addr, 0x7FF8_DEAD_0000);
        assert!(injected.in_load, "should be in InLoadOrder");
        assert!(injected.in_mem, "should be in InMemoryOrder");
        assert!(!injected.in_init, "should NOT be in InInitializationOrder");
    }

    #[test]
    fn ldr_modules_null_ldr_returns_error() {
        let vaddr = 0xFFFF_8000_0000_0000u64;
        let paddr = 0x10_0000u64;

        let mut page = vec![0u8; 4096];
        page[0x18..0x20].copy_from_slice(&0u64.to_le_bytes()); // PEB.Ldr = 0

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_ldr_modules(&reader, vaddr);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Ldr"));
    }
}
