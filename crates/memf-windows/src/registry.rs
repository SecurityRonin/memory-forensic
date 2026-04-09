//! Windows registry hive walker.
//!
//! Enumerates loaded registry hives by walking `CmpHiveListHead`,
//! a `_LIST_ENTRY` chain of `_CMHIVE` structures maintained by
//! the Windows Configuration Manager.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;
use crate::{RegistryHive, Result};

/// Maximum number of hives to walk before bailing out (safety limit).
const MAX_HIVE_COUNT: usize = 256;

/// Walk the Windows registry hive list.
///
/// Looks up the `CmpHiveListHead` (or `CmHiveListHead`) kernel symbol
/// and walks the `_CMHIVE.HiveList` doubly-linked `_LIST_ENTRY` chain.
///
/// For each `_CMHIVE`, reads:
/// - `FileFullPath` (`_UNICODE_STRING`) — the registry path
/// - `FileUserName` (`_UNICODE_STRING`) — the on-disk file path
/// - `Hive._HHIVE.BaseBlock` — pointer to the hive base block
/// - `Hive.Storage[Stable].Length` — stable storage size
/// - `Hive.Storage[Volatile].Length` — volatile storage size
///
/// Returns an empty `Vec` if no hive list symbol is found.
pub fn walk_hive_list<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<RegistryHive>> {
    // Try CmpHiveListHead first, fall back to CmHiveListHead
    let head_vaddr = reader
        .symbols()
        .symbol_address("CmpHiveListHead")
        .or_else(|| reader.symbols().symbol_address("CmHiveListHead"));

    let Some(head_vaddr) = head_vaddr else {
        return Ok(Vec::new());
    };

    walk_hive_list_from(reader, head_vaddr)
}

/// Walk the hive list starting from a known list head virtual address.
fn walk_hive_list_from<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    head_vaddr: u64,
) -> Result<Vec<RegistryHive>> {
    let entries =
        reader.walk_list_with(head_vaddr, "_LIST_ENTRY", "Flink", "_CMHIVE", "HiveList")?;

    let mut hives = Vec::new();
    for (i, cmhive_addr) in entries.into_iter().enumerate() {
        if i >= MAX_HIVE_COUNT {
            break;
        }
        hives.push(read_hive_info(reader, cmhive_addr)?);
    }
    Ok(hives)
}

/// Read registry hive info from a single `_CMHIVE` structure.
fn read_hive_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    cmhive_addr: u64,
) -> Result<RegistryHive> {
    // FileFullPath (_UNICODE_STRING)
    let file_full_path_offset = reader
        .symbols()
        .field_offset("_CMHIVE", "FileFullPath")
        .ok_or_else(|| {
            crate::Error::Core(memf_core::Error::MissingSymbol(
                "_CMHIVE.FileFullPath".into(),
            ))
        })?;
    let file_full_path =
        read_unicode_string(reader, cmhive_addr.wrapping_add(file_full_path_offset))?;

    // FileUserName (_UNICODE_STRING)
    let file_user_name_offset = reader
        .symbols()
        .field_offset("_CMHIVE", "FileUserName")
        .ok_or_else(|| {
            crate::Error::Core(memf_core::Error::MissingSymbol(
                "_CMHIVE.FileUserName".into(),
            ))
        })?;
    let file_user_name =
        read_unicode_string(reader, cmhive_addr.wrapping_add(file_user_name_offset))?;

    // Hive._HHIVE.BaseBlock (pointer)
    let hive_offset = reader
        .symbols()
        .field_offset("_CMHIVE", "Hive")
        .ok_or_else(|| {
            crate::Error::Core(memf_core::Error::MissingSymbol("_CMHIVE.Hive".into()))
        })?;
    let hhive_addr = cmhive_addr.wrapping_add(hive_offset);

    let base_block: u64 = reader.read_field(hhive_addr, "_HHIVE", "BaseBlock")?;

    // Hive.Storage[Stable].Length — _DUAL at _HHIVE.Storage offset
    let storage_offset = reader
        .symbols()
        .field_offset("_HHIVE", "Storage")
        .ok_or_else(|| {
            crate::Error::Core(memf_core::Error::MissingSymbol("_HHIVE.Storage".into()))
        })?;
    let dual_size = reader
        .symbols()
        .struct_size("_DUAL")
        .ok_or_else(|| crate::Error::Core(memf_core::Error::MissingSymbol("_DUAL size".into())))?;

    // Storage[0] = Stable
    let stable_dual_addr = hhive_addr.wrapping_add(storage_offset);
    let stable_length: u32 = reader.read_field(stable_dual_addr, "_DUAL", "Length")?;

    // Storage[1] = Volatile (next _DUAL element after Storage[0])
    let volatile_dual_addr = stable_dual_addr.wrapping_add(dual_size);
    let volatile_length: u32 = reader.read_field(volatile_dual_addr, "_DUAL", "Length")?;

    Ok(RegistryHive {
        base_addr: cmhive_addr,
        file_full_path,
        file_user_name,
        hive_addr: base_block,
        stable_length,
        volatile_length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Encode a Rust &str as UTF-16LE bytes.
    fn utf16le_bytes(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
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

    /// Place UTF-16LE string data at a physical offset and return the byte length.
    fn place_utf16_string(buf: &mut [u8], phys_offset: usize, s: &str) -> u16 {
        let utf16 = utf16le_bytes(s);
        let len = utf16.len();
        buf[phys_offset..phys_offset + len].copy_from_slice(&utf16);
        len as u16
    }

    // ── Test 1: No hive list symbol → empty Vec ─────────────────────

    #[test]
    fn walk_hive_list_no_symbol() {
        // Build an ISF with NO CmpHiveListHead symbol at all.
        let isf = IsfBuilder::new()
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Minimal page table — we just need a valid VAS.
        let vaddr_base = 0xFFFF_8000_0000_0000u64;
        let paddr_base = 0x10_0000u64;
        let page = vec![0u8; 4096];

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr_base, paddr_base, flags::WRITABLE)
            .write_phys(paddr_base, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let hives = walk_hive_list(&reader).unwrap();
        assert!(
            hives.is_empty(),
            "Expected empty Vec when no hive list symbol exists"
        );
    }

    // ── Test 2: Single hive in the list ─────────────────────────────

    #[test]
    fn walk_hive_list_single_hive() {
        // Memory layout (all on pages mapped into kernel VA space):
        //
        // Page 0 (vaddr 0xFFFF_8000_0010_0000): CmpHiveListHead (_LIST_ENTRY)
        // Page 1 (vaddr 0xFFFF_8000_0020_0000): _CMHIVE struct
        // Page 2 (vaddr 0xFFFF_8000_0020_1000): string data for UNICODE_STRINGs
        //
        // _CMHIVE layout (from preset):
        //   Hive (_HHIVE) at offset 0x0
        //     BaseBlock at 0x28
        //     Storage[0] (_DUAL) at 0x38 → Length at 0x38+0x0 = 0x38
        //     Storage[1] (_DUAL) at 0x58 → Length at 0x58+0x0 = 0x58
        //   FileFullPath at offset 0x70
        //   FileUserName at offset 0x80
        //   HiveList at offset 0x300

        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let cmhive_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let strings_vaddr: u64 = 0xFFFF_8000_0020_1000;

        let head_paddr: u64 = 0x0080_0000;
        let cmhive_paddr: u64 = 0x0090_0000;
        let strings_paddr: u64 = 0x0091_0000;

        let mut head_data = vec![0u8; 4096];
        let mut cmhive_data = vec![0u8; 4096];
        let mut string_data = vec![0u8; 4096];

        // HiveList field is at offset 0x300 within _CMHIVE.
        let hive_list_entry_vaddr = cmhive_vaddr + 0x300;

        // CmpHiveListHead: Flink → cmhive.HiveList, Blink → cmhive.HiveList
        head_data[0..8].copy_from_slice(&hive_list_entry_vaddr.to_le_bytes());
        head_data[8..16].copy_from_slice(&hive_list_entry_vaddr.to_le_bytes());

        // _CMHIVE.HiveList: Flink → head, Blink → head (single entry, circular)
        cmhive_data[0x300..0x308].copy_from_slice(&head_vaddr.to_le_bytes());
        cmhive_data[0x308..0x310].copy_from_slice(&head_vaddr.to_le_bytes());

        // _HHIVE.BaseBlock at offset 0x28
        let base_block_addr: u64 = 0xDEAD_BEEF_0000;
        cmhive_data[0x28..0x30].copy_from_slice(&base_block_addr.to_le_bytes());

        // _HHIVE.Storage[Stable].Length at offset 0x38 (Stable _DUAL starts at 0x38)
        let stable_len: u32 = 0x0040_0000; // 4MB
        cmhive_data[0x38..0x3C].copy_from_slice(&stable_len.to_le_bytes());

        // _HHIVE.Storage[Volatile].Length at offset 0x58 (Volatile _DUAL starts at 0x58)
        // _DUAL size is 0x20, so Storage[1] = Storage[0] offset + 0x20 = 0x38 + 0x20 = 0x58
        let volatile_len: u32 = 0x0001_0000; // 64KB
        cmhive_data[0x58..0x5C].copy_from_slice(&volatile_len.to_le_bytes());

        // FileFullPath (_UNICODE_STRING) at offset 0x70
        let full_path = r"\REGISTRY\MACHINE\SYSTEM";
        let full_path_len = place_utf16_string(&mut string_data, 0x000, full_path);
        build_unicode_string_at(&mut cmhive_data, 0x70, full_path_len, strings_vaddr);

        // FileUserName (_UNICODE_STRING) at offset 0x80
        let user_name = r"\??\C:\Windows\System32\config\SYSTEM";
        let user_name_len = place_utf16_string(&mut string_data, 0x200, user_name);
        build_unicode_string_at(&mut cmhive_data, 0x80, user_name_len, strings_vaddr + 0x200);

        // Build ISF with CmpHiveListHead pointing to our head_vaddr
        let isf = IsfBuilder::windows_kernel_preset()
            .add_symbol("CmpHiveListHead", head_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(cmhive_vaddr, cmhive_paddr, flags::WRITABLE)
            .map_4k(strings_vaddr, strings_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_data)
            .write_phys(cmhive_paddr, &cmhive_data)
            .write_phys(strings_paddr, &string_data)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let hives = walk_hive_list(&reader).unwrap();
        assert_eq!(hives.len(), 1);

        let h = &hives[0];
        assert_eq!(h.base_addr, cmhive_vaddr);
        assert_eq!(h.file_full_path, r"\REGISTRY\MACHINE\SYSTEM");
        assert_eq!(h.file_user_name, r"\??\C:\Windows\System32\config\SYSTEM");
        assert_eq!(h.hive_addr, base_block_addr);
        assert_eq!(h.stable_length, stable_len);
        assert_eq!(h.volatile_length, volatile_len);
    }

    // ── Test 3: Two hives in a circular list ────────────────────────

    #[test]
    fn walk_hive_list_two_hives() {
        // Two _CMHIVE entries in the circular HiveList chain.
        //
        // Page 0: CmpHiveListHead
        // Page 1: _CMHIVE A (SYSTEM)
        // Page 2: _CMHIVE B (SOFTWARE)
        // Page 3: string data

        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let cmhive_a_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let cmhive_b_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let strings_vaddr: u64 = 0xFFFF_8000_0040_0000;

        let head_paddr: u64 = 0x0080_0000;
        let cmhive_a_paddr: u64 = 0x0090_0000;
        let cmhive_b_paddr: u64 = 0x00A0_0000;
        let strings_paddr: u64 = 0x00B0_0000;

        let mut head_data = vec![0u8; 4096];
        let mut cmhive_a_data = vec![0u8; 4096];
        let mut cmhive_b_data = vec![0u8; 4096];
        let mut string_data = vec![0u8; 4096];

        let hive_list_a = cmhive_a_vaddr + 0x300;
        let hive_list_b = cmhive_b_vaddr + 0x300;

        // CmpHiveListHead: Flink → A.HiveList, Blink → B.HiveList
        head_data[0..8].copy_from_slice(&hive_list_a.to_le_bytes());
        head_data[8..16].copy_from_slice(&hive_list_b.to_le_bytes());

        // A.HiveList: Flink → B.HiveList, Blink → head
        cmhive_a_data[0x300..0x308].copy_from_slice(&hive_list_b.to_le_bytes());
        cmhive_a_data[0x308..0x310].copy_from_slice(&head_vaddr.to_le_bytes());

        // B.HiveList: Flink → head, Blink → A.HiveList
        cmhive_b_data[0x300..0x308].copy_from_slice(&head_vaddr.to_le_bytes());
        cmhive_b_data[0x308..0x310].copy_from_slice(&hive_list_a.to_le_bytes());

        // ── Hive A: SYSTEM ──
        let base_block_a: u64 = 0xAAAA_0000_0000;
        cmhive_a_data[0x28..0x30].copy_from_slice(&base_block_a.to_le_bytes());
        cmhive_a_data[0x38..0x3C].copy_from_slice(&0x0040_0000u32.to_le_bytes()); // stable 4MB
        cmhive_a_data[0x58..0x5C].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // volatile 64KB

        let full_a = r"\REGISTRY\MACHINE\SYSTEM";
        let user_a = r"\??\C:\Windows\System32\config\SYSTEM";
        let full_a_len = place_utf16_string(&mut string_data, 0x000, full_a);
        let user_a_len = place_utf16_string(&mut string_data, 0x100, user_a);
        build_unicode_string_at(&mut cmhive_a_data, 0x70, full_a_len, strings_vaddr);
        build_unicode_string_at(&mut cmhive_a_data, 0x80, user_a_len, strings_vaddr + 0x100);

        // ── Hive B: SOFTWARE ──
        let base_block_b: u64 = 0xBBBB_0000_0000;
        cmhive_b_data[0x28..0x30].copy_from_slice(&base_block_b.to_le_bytes());
        cmhive_b_data[0x38..0x3C].copy_from_slice(&0x0100_0000u32.to_le_bytes()); // stable 16MB
        cmhive_b_data[0x58..0x5C].copy_from_slice(&0x0002_0000u32.to_le_bytes()); // volatile 128KB

        let full_b = r"\REGISTRY\MACHINE\SOFTWARE";
        let user_b = r"\??\C:\Windows\System32\config\SOFTWARE";
        let full_b_len = place_utf16_string(&mut string_data, 0x300, full_b);
        let user_b_len = place_utf16_string(&mut string_data, 0x500, user_b);
        build_unicode_string_at(&mut cmhive_b_data, 0x70, full_b_len, strings_vaddr + 0x300);
        build_unicode_string_at(&mut cmhive_b_data, 0x80, user_b_len, strings_vaddr + 0x500);

        let isf = IsfBuilder::windows_kernel_preset()
            .add_symbol("CmpHiveListHead", head_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(cmhive_a_vaddr, cmhive_a_paddr, flags::WRITABLE)
            .map_4k(cmhive_b_vaddr, cmhive_b_paddr, flags::WRITABLE)
            .map_4k(strings_vaddr, strings_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_data)
            .write_phys(cmhive_a_paddr, &cmhive_a_data)
            .write_phys(cmhive_b_paddr, &cmhive_b_data)
            .write_phys(strings_paddr, &string_data)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let hives = walk_hive_list(&reader).unwrap();
        assert_eq!(hives.len(), 2);

        // Hive A
        assert_eq!(hives[0].base_addr, cmhive_a_vaddr);
        assert_eq!(hives[0].file_full_path, r"\REGISTRY\MACHINE\SYSTEM");
        assert_eq!(
            hives[0].file_user_name,
            r"\??\C:\Windows\System32\config\SYSTEM"
        );
        assert_eq!(hives[0].hive_addr, base_block_a);
        assert_eq!(hives[0].stable_length, 0x0040_0000);
        assert_eq!(hives[0].volatile_length, 0x0001_0000);

        // Hive B
        assert_eq!(hives[1].base_addr, cmhive_b_vaddr);
        assert_eq!(hives[1].file_full_path, r"\REGISTRY\MACHINE\SOFTWARE");
        assert_eq!(
            hives[1].file_user_name,
            r"\??\C:\Windows\System32\config\SOFTWARE"
        );
        assert_eq!(hives[1].hive_addr, base_block_b);
        assert_eq!(hives[1].stable_length, 0x0100_0000);
        assert_eq!(hives[1].volatile_length, 0x0002_0000);
    }
}
