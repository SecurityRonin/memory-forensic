//! Process hollowing detection.
//!
//! Detects process hollowing by reading the PE header at each process's
//! `PEB.ImageBaseAddress` and checking for:
//! 1. Missing MZ magic (`0x4D5A`) — image unmapped or overwritten
//! 2. Missing PE signature (`PE\0\0`) — corrupt or replaced header
//! 3. `SizeOfImage` mismatch between PE header and LDR module entry
//!
//! These indicators reveal when malware creates a legitimate process in a
//! suspended state, unmaps its image, and replaces it with malicious code.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, WinHollowingInfo};

/// Check all running processes for signs of process hollowing.
///
/// For each process with a non-null PEB, switches to the process's CR3
/// and reads the PE header at `PEB.ImageBaseAddress`. Compares the PE
/// `SizeOfImage` against the first entry in `InLoadOrderModuleList`.
///
/// Returns one `WinHollowingInfo` per process (including clean ones).
/// Check the `suspicious` field to filter findings.
pub fn check_hollowing<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<WinHollowingInfo>> {
    todo!()
}

/// Read and validate the PE header at the given virtual address.
///
/// Returns `(has_mz, has_pe, size_of_image)`.
/// If the memory is unreadable, returns `(false, false, 0)`.
fn read_pe_header<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    image_base: u64,
) -> (bool, bool, u32) {
    todo!()
}

/// Get the image size from the first entry in `InLoadOrderModuleList`.
///
/// The first entry typically represents the process's main executable.
/// Returns 0 if the LDR data is unreadable.
fn ldr_first_image_size<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    peb_addr: u64,
) -> u64 {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// Build a minimal valid PE header at a given offset in a buffer.
    /// Returns the expected SizeOfImage value.
    fn write_pe_header(buf: &mut [u8], offset: usize, size_of_image: u32) -> u32 {
        // DOS header: MZ magic + e_lfanew at offset 0x3C
        buf[offset] = 0x4D; // 'M'
        buf[offset + 1] = 0x5A; // 'Z'
        let pe_offset: u32 = 0x80; // PE header at relative offset 0x80
        buf[offset + 0x3C..offset + 0x40].copy_from_slice(&pe_offset.to_le_bytes());
        // PE signature
        let pe_abs = offset + pe_offset as usize;
        buf[pe_abs] = b'P';
        buf[pe_abs + 1] = b'E';
        buf[pe_abs + 2] = 0;
        buf[pe_abs + 3] = 0;
        // COFF header: Machine (2 bytes) + ... SizeOfOptionalHeader at +20
        // Optional header starts at pe_abs + 24
        // PE32+ magic
        let opt_abs = pe_abs + 24;
        buf[opt_abs..opt_abs + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
        // SizeOfImage is at optional header offset 56
        buf[opt_abs + 56..opt_abs + 60].copy_from_slice(&size_of_image.to_le_bytes());
        size_of_image
    }

    /// Set up a single-process memory layout for hollowing tests.
    /// Returns (cr3, mem, ps_head_vaddr).
    fn build_single_process_memory(
        pid: u64,
        name: &str,
        peb_paddr: u64,
        image_base_vaddr: u64,
        image_base_paddr: u64,
        image_data: &[u8],
        ldr_size: u64,
    ) -> (u64, memf_core::test_builders::SyntheticPhysMem, u64) {
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let peb_vaddr: u64 = 0x0000_0000_7FFE_0000; // user-mode PEB

        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0090_0000;

        // LDR data addresses
        let ldr_vaddr: u64 = 0x0000_0000_7FFD_0000;
        let ldr_paddr: u64 = 0x00C0_0000;
        let ldr_entry_vaddr: u64 = 0x0000_0000_7FFD_1000;
        let ldr_entry_paddr: u64 = 0x00C1_0000;
        let ldr_strings_vaddr: u64 = 0x0000_0000_7FFD_2000;
        let ldr_strings_paddr: u64 = 0x00C2_0000;

        let mut head_data = vec![0u8; 4096];
        let mut eproc_data = vec![0u8; 8192];
        let mut peb_data = vec![0u8; 4096];
        let mut ldr_data = vec![0u8; 4096];
        let mut ldr_entry_data = vec![0u8; 4096];
        let mut ldr_string_data = vec![0u8; 4096];

        let active_links_off: u64 = 0x448;

        // PsActiveProcessHead: Flink → eproc.ActiveProcessLinks
        let eproc_links = eproc_vaddr + active_links_off;
        head_data[0..8].copy_from_slice(&eproc_links.to_le_bytes());
        head_data[8..16].copy_from_slice(&eproc_links.to_le_bytes());

        // _EPROCESS
        // Pcb@0x0 (_KPROCESS): DirectoryTableBase@0x28
        // We'll set CR3 later from PageTableBuilder
        // CreateTime@0x430, ExitTime@0x438
        eproc_data[0x430..0x438].copy_from_slice(&132800000000000000u64.to_le_bytes());
        eproc_data[0x438..0x440].copy_from_slice(&0u64.to_le_bytes());
        // UniqueProcessId@0x440
        eproc_data[0x440..0x448].copy_from_slice(&pid.to_le_bytes());
        // ActiveProcessLinks@0x448: circular back to head
        eproc_data[0x448..0x450].copy_from_slice(&head_vaddr.to_le_bytes());
        eproc_data[0x450..0x458].copy_from_slice(&head_vaddr.to_le_bytes());
        // InheritedFromUniqueProcessId@0x540
        eproc_data[0x540..0x548].copy_from_slice(&0u64.to_le_bytes());
        // Peb@0x550
        eproc_data[0x550..0x558].copy_from_slice(&peb_vaddr.to_le_bytes());
        // ImageFileName@0x5A8
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(15);
        eproc_data[0x5A8..0x5A8 + copy_len].copy_from_slice(&name_bytes[..copy_len]);
        // ThreadListHead@0x30 (empty: points to itself)
        let thread_list_head = eproc_vaddr + 0x30;
        eproc_data[0x30..0x38].copy_from_slice(&thread_list_head.to_le_bytes());
        eproc_data[0x38..0x40].copy_from_slice(&thread_list_head.to_le_bytes());

        // _PEB
        // ImageBaseAddress@0x10
        peb_data[0x10..0x18].copy_from_slice(&image_base_vaddr.to_le_bytes());
        // Ldr@0x18 → ldr_vaddr
        peb_data[0x18..0x20].copy_from_slice(&ldr_vaddr.to_le_bytes());
        // ProcessParameters@0x20 (null — not needed for hollowing)
        peb_data[0x20..0x28].copy_from_slice(&0u64.to_le_bytes());

        // _PEB_LDR_DATA at ldr_vaddr
        // InLoadOrderModuleList@16: Flink → ldr_entry.InLoadOrderLinks
        let ldr_entry_in_load = ldr_entry_vaddr; // InLoadOrderLinks is at offset 0
        ldr_data[16..24].copy_from_slice(&ldr_entry_in_load.to_le_bytes()); // Flink
        let ldr_in_load_head = ldr_vaddr + 16;
        ldr_data[24..32].copy_from_slice(&ldr_entry_in_load.to_le_bytes()); // Blink

        // _LDR_DATA_TABLE_ENTRY at ldr_entry_vaddr
        // InLoadOrderLinks@0: circular back to PEB_LDR_DATA.InLoadOrderModuleList
        ldr_entry_data[0..8].copy_from_slice(&ldr_in_load_head.to_le_bytes()); // Flink
        ldr_entry_data[8..16].copy_from_slice(&ldr_in_load_head.to_le_bytes()); // Blink
        // DllBase@48
        ldr_entry_data[48..56].copy_from_slice(&image_base_vaddr.to_le_bytes());
        // SizeOfImage@64 (as u32, but stored in u64 slot effectively — read 4 bytes)
        ldr_entry_data[64..68].copy_from_slice(&(ldr_size as u32).to_le_bytes());
        // FullDllName@72 (_UNICODE_STRING)
        let full_name = utf16le(name);
        let full_len = full_name.len() as u16;
        ldr_entry_data[72..74].copy_from_slice(&full_len.to_le_bytes());
        ldr_entry_data[74..76].copy_from_slice(&(full_len + 2).to_le_bytes());
        ldr_entry_data[80..88].copy_from_slice(&ldr_strings_vaddr.to_le_bytes());
        // BaseDllName@88
        ldr_entry_data[88..90].copy_from_slice(&full_len.to_le_bytes());
        ldr_entry_data[90..92].copy_from_slice(&(full_len + 2).to_le_bytes());
        let base_str_vaddr = ldr_strings_vaddr + 0x100;
        ldr_entry_data[96..104].copy_from_slice(&base_str_vaddr.to_le_bytes());

        // String buffers
        ldr_string_data[0..full_name.len()].copy_from_slice(&full_name);
        ldr_string_data[0x100..0x100 + full_name.len()].copy_from_slice(&full_name);

        // Image data at image_base_paddr
        let mut image_page = vec![0u8; 4096];
        let copy_len = image_data.len().min(4096);
        image_page[..copy_len].copy_from_slice(&image_data[..copy_len]);

        let (cr3, mut mem) = PageTableBuilder::new()
            // Kernel space mappings (identity-like, high addresses)
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr + 0x1000, eproc_paddr + 0x1000, flags::WRITABLE)
            // User space mappings (process-specific via shared CR3 for simplicity)
            .map_4k(peb_vaddr, peb_paddr, flags::WRITABLE | flags::USER)
            .map_4k(image_base_vaddr, image_base_paddr, flags::WRITABLE | flags::USER)
            .map_4k(ldr_vaddr, ldr_paddr, flags::WRITABLE | flags::USER)
            .map_4k(ldr_entry_vaddr, ldr_entry_paddr, flags::WRITABLE | flags::USER)
            .map_4k(ldr_strings_vaddr, ldr_strings_paddr, flags::WRITABLE | flags::USER)
            .write_phys(head_paddr, &head_data)
            .write_phys(eproc_paddr, &eproc_data[..4096])
            .write_phys(eproc_paddr + 0x1000, &eproc_data[4096..])
            .write_phys(peb_paddr, &peb_data)
            .write_phys(image_base_paddr, &image_page)
            .write_phys(ldr_paddr, &ldr_data)
            .write_phys(ldr_entry_paddr, &ldr_entry_data)
            .write_phys(ldr_strings_paddr, &ldr_string_data)
            .build();

        // Write CR3 into _EPROCESS.Pcb.DirectoryTableBase
        // CR3 is at physical eproc_paddr + 0x28
        mem.write_u64(eproc_paddr + 0x28, cr3);

        (cr3, mem, head_vaddr)
    }

    #[test]
    fn legitimate_process_not_flagged() {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let peb_paddr: u64 = 0x00B0_0000;
        let image_base_vaddr: u64 = 0x0000_0000_0040_0000;
        let image_base_paddr: u64 = 0x00A0_0000;
        let size_of_image: u32 = 0x1_0000;

        let mut image_data = vec![0u8; 4096];
        write_pe_header(&mut image_data, 0, size_of_image);

        let (_cr3, mem, head_vaddr) = build_single_process_memory(
            1234,
            "notepad.exe",
            peb_paddr,
            image_base_vaddr,
            image_base_paddr,
            &image_data,
            u64::from(size_of_image),
        );

        let vas = VirtualAddressSpace::new(mem, _cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = check_hollowing(&reader, head_vaddr).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].has_mz, "should detect MZ header");
        assert!(results[0].has_pe, "should detect PE signature");
        assert_eq!(results[0].pe_size_of_image, size_of_image);
        assert!(!results[0].suspicious, "legitimate process should not be flagged");
    }

    #[test]
    fn hollowed_process_no_mz_flagged() {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let peb_paddr: u64 = 0x00B0_0000;
        let image_base_vaddr: u64 = 0x0000_0000_0040_0000;
        let image_base_paddr: u64 = 0x00A0_0000;

        // Zeroed image — no MZ magic (classic hollowing indicator)
        let image_data = vec![0u8; 4096];

        let (_cr3, mem, head_vaddr) = build_single_process_memory(
            666,
            "svchost.exe",
            peb_paddr,
            image_base_vaddr,
            image_base_paddr,
            &image_data,
            0x2_0000,
        );

        let vas = VirtualAddressSpace::new(mem, _cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = check_hollowing(&reader, head_vaddr).unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].has_mz, "zeroed memory should lack MZ");
        assert!(!results[0].has_pe, "zeroed memory should lack PE");
        assert!(results[0].suspicious, "hollowed process must be flagged");
        assert!(results[0].reason.contains("MZ"), "reason should mention missing MZ");
    }

    #[test]
    fn hollowed_process_size_mismatch_flagged() {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let peb_paddr: u64 = 0x00B0_0000;
        let image_base_vaddr: u64 = 0x0000_0000_0040_0000;
        let image_base_paddr: u64 = 0x00A0_0000;

        // Valid PE but with different SizeOfImage than LDR expects
        let pe_size: u32 = 0x5_0000;
        let ldr_size: u64 = 0x1_0000; // mismatch!
        let mut image_data = vec![0u8; 4096];
        write_pe_header(&mut image_data, 0, pe_size);

        let (_cr3, mem, head_vaddr) = build_single_process_memory(
            999,
            "explorer.exe",
            peb_paddr,
            image_base_vaddr,
            image_base_paddr,
            &image_data,
            ldr_size,
        );

        let vas = VirtualAddressSpace::new(mem, _cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = check_hollowing(&reader, head_vaddr).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].has_mz, "PE header is valid");
        assert!(results[0].has_pe, "PE signature is valid");
        assert_eq!(results[0].pe_size_of_image, pe_size);
        assert!(results[0].suspicious, "size mismatch should be flagged");
        assert!(
            results[0].reason.contains("SizeOfImage"),
            "reason should mention SizeOfImage mismatch"
        );
    }

    #[test]
    fn system_process_skipped_no_peb() {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // System (pid=4) has PEB=0
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0090_0000;

        let mut head_data = vec![0u8; 4096];
        let mut eproc_data = vec![0u8; 8192];

        let active_links_off: u64 = 0x448;
        let eproc_links = eproc_vaddr + active_links_off;
        head_data[0..8].copy_from_slice(&eproc_links.to_le_bytes());
        head_data[8..16].copy_from_slice(&eproc_links.to_le_bytes());

        eproc_data[0x28..0x30].copy_from_slice(&0x1AB000u64.to_le_bytes()); // CR3
        eproc_data[0x430..0x438].copy_from_slice(&132800000000000000u64.to_le_bytes());
        eproc_data[0x440..0x448].copy_from_slice(&4u64.to_le_bytes()); // pid=4
        eproc_data[0x448..0x450].copy_from_slice(&head_vaddr.to_le_bytes());
        eproc_data[0x450..0x458].copy_from_slice(&head_vaddr.to_le_bytes());
        eproc_data[0x550..0x558].copy_from_slice(&0u64.to_le_bytes()); // PEB=0
        eproc_data[0x5A8..0x5AE].copy_from_slice(b"System");
        let tl = eproc_vaddr + 0x30;
        eproc_data[0x30..0x38].copy_from_slice(&tl.to_le_bytes());
        eproc_data[0x38..0x40].copy_from_slice(&tl.to_le_bytes());

        let (cr3, mut mem) = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr + 0x1000, eproc_paddr + 0x1000, flags::WRITABLE)
            .write_phys(head_paddr, &head_data)
            .write_phys(eproc_paddr, &eproc_data[..4096])
            .write_phys(eproc_paddr + 0x1000, &eproc_data[4096..])
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = check_hollowing(&reader, head_vaddr).unwrap();
        // System has PEB=0, should be skipped entirely
        assert!(results.is_empty(), "System (PEB=0) should be skipped");
    }

    #[test]
    fn mz_present_but_pe_missing_flagged() {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let peb_paddr: u64 = 0x00B0_0000;
        let image_base_vaddr: u64 = 0x0000_0000_0040_0000;
        let image_base_paddr: u64 = 0x00A0_0000;

        // MZ header present but PE signature corrupted
        let mut image_data = vec![0u8; 4096];
        image_data[0] = 0x4D; // 'M'
        image_data[1] = 0x5A; // 'Z'
        // e_lfanew points to offset 0x80
        image_data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // But at 0x80 we have garbage, not "PE\0\0"
        image_data[0x80] = 0xFF;
        image_data[0x81] = 0xFF;

        let (_cr3, mem, head_vaddr) = build_single_process_memory(
            888,
            "cmd.exe",
            peb_paddr,
            image_base_vaddr,
            image_base_paddr,
            &image_data,
            0x1_0000,
        );

        let vas = VirtualAddressSpace::new(mem, _cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = check_hollowing(&reader, head_vaddr).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].has_mz, "MZ should be detected");
        assert!(!results[0].has_pe, "PE should not be detected");
        assert!(results[0].suspicious, "corrupt PE should be flagged");
        assert!(results[0].reason.contains("PE"), "reason should mention PE");
    }
}
