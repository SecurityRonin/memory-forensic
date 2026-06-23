//! Windows AppCompatCache (Shimcache) extraction from kernel memory.
//!
//! The Application Compatibility Cache tracks recently executed programs
//! and is a key forensic artifact for proving execution history. Windows
//! maintains this cache in kernel memory via the `g_ShimCache` symbol,
//! which points to an `_RTL_AVL_TABLE` (Win8+) or linked list (Win7)
//! of `_SHIM_CACHE_ENTRY` structures.
//!
//! Each entry records the full executable path, last-modification
//! timestamp (FILETIME), an execution flag (InsertFlag), and the size
//! of any associated shim data. The position in the cache indicates
//! recency — position 0 is the most recently cached entry.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;

/// Resolve a PE section's virtual range `(section_va, virtual_size)` within an
/// in-memory module image mapped at `module_base`, looked up by name (e.g.
/// `".data"`, `"PAGE"`). Parses the DOS (`e_lfanew`@0x3C) and PE headers, then
/// the section table (40-byte entries: Name[8]@0, VirtualSize@8, VirtualAddress
/// @0xC). Returns `None` if the headers are unreadable or the section is absent.
// Wired into walk_shimcache in increment 5 of the shimcache rewrite; until then
// it is exercised only by unit tests.
/// Safety cap on the PE section count scanned (real images have < 32).
const MAX_PE_SECTIONS: u64 = 96;

#[allow(dead_code)] // wired into walk_shimcache in increment 5
fn module_section_range<P: PhysicalMemoryProvider>(
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

/// Maximum number of shimcache entries to iterate (safety limit).
const MAX_SHIMCACHE_ENTRIES: usize = 4096;

/// Walk the `SHIM_CACHE_ENTRY` LRU `_LIST_ENTRY` chain from the list head and
/// parse each node (Win8.1+/Win10 x64 layout). `head_va` is the sentinel head
/// (the `_RTL_AVL_TABLE`-adjacent cache head); the sentinel itself is not
/// emitted. Bounded by `MAX_SHIMCACHE_ENTRIES`.
#[allow(dead_code)] // wired into walk_shimcache in increment 3
fn parse_shimcache_list<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
    _head_va: u64,
) -> Vec<ShimcacheEntry> {
    Vec::new()
}

/// A single Application Compatibility Cache (Shimcache) entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShimcacheEntry {
    /// Full executable path (e.g., `\??\C:\Windows\System32\cmd.exe`).
    pub path: String,
    /// FILETIME of the file's last modification timestamp.
    pub last_modified: u64,
    /// Whether the InsertFlag indicates the program was executed.
    pub exec_flag: bool,
    /// Size of shim data associated with this entry.
    pub data_size: u32,
    /// Position in the cache (0 = most recent).
    pub position: u32,
}

/// Walk the AppCompatCache (Shimcache) from kernel memory.
///
/// Locates the `g_ShimCache` symbol, which points to an RTL_AVL_TABLE
/// containing `_SHIM_CACHE_ENTRY` nodes. Each node holds a
/// `_UNICODE_STRING` path, a FILETIME timestamp, an insert/exec flag,
/// and shim data size.
///
/// Returns an empty `Vec` if the required symbols are not present
/// (graceful degradation).
///
/// # Errors
///
/// Returns an error if memory reads fail after the symbol has been
/// located and validated.
pub fn walk_shimcache<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<ShimcacheEntry>> {
    // Locate the g_ShimCache pointer symbol.
    let Some(cache_ptr_addr) = reader.symbols().symbol_address("g_ShimCache") else {
        return Ok(Vec::new()); // graceful degradation
    };

    // g_ShimCache is a pointer — read 8 bytes at the symbol address to
    // get the address of the cache header.
    let header_addr: u64 = match reader.read_bytes(cache_ptr_addr, 8) {
        Ok(bytes) if bytes.len() == 8 => bytes[..8].try_into().map_or(0, u64::from_le_bytes),
        _ => return Ok(Vec::new()),
    };

    if header_addr == 0 {
        return Ok(Vec::new());
    }

    // Read the entry count from the cache header.
    // The header contains: NumEntries (u32 at offset 0), then a linked
    // list of entries starting at offset 0x8 (ListHead Flink pointer).
    let num_entries: u32 = reader
        .read_field(header_addr, "_SHIM_CACHE_HEADER", "NumEntries")
        .unwrap_or(0);

    let safe_count = (num_entries as usize).min(MAX_SHIMCACHE_ENTRIES);
    if safe_count == 0 {
        return Ok(Vec::new());
    }

    // Read the ListHead.Flink pointer (first entry in the doubly-linked list).
    let list_head_offset = reader
        .symbols()
        .field_offset("_SHIM_CACHE_HEADER", "ListHead")
        .unwrap_or(0x8);

    let list_head_addr = header_addr + list_head_offset;

    // Read Flink of ListHead to get first entry.
    let mut current: u64 = match reader.read_bytes(list_head_addr, 8) {
        Ok(bytes) if bytes.len() == 8 => bytes[..8].try_into().map_or(0, u64::from_le_bytes),
        _ => return Ok(Vec::new()),
    };

    let path_offset = reader
        .symbols()
        .field_offset("_SHIM_CACHE_ENTRY", "Path")
        .unwrap_or(0x10);

    let mut entries = Vec::new();

    for position in 0..safe_count {
        // Stop if we loop back to the list head.
        if current == list_head_addr || current == 0 {
            break;
        }

        // The _LIST_ENTRY is at offset 0 of _SHIM_CACHE_ENTRY, so
        // current points directly to the entry base address.
        let entry_addr = current;

        // Read the path _UNICODE_STRING.
        let path = read_unicode_string(reader, entry_addr + path_offset).unwrap_or_default();

        // Read LastModified (FILETIME, u64).
        let last_modified: u64 = reader
            .read_field(entry_addr, "_SHIM_CACHE_ENTRY", "LastModified")
            .unwrap_or(0);

        // Read InsertFlag (u32) — non-zero means executed.
        let insert_flag: u32 = reader
            .read_field(entry_addr, "_SHIM_CACHE_ENTRY", "InsertFlag")
            .unwrap_or(0);

        // Read DataSize (u32).
        let data_size: u32 = reader
            .read_field(entry_addr, "_SHIM_CACHE_ENTRY", "DataSize")
            .unwrap_or(0);

        entries.push(ShimcacheEntry {
            path,
            last_modified,
            exec_flag: insert_flag != 0,
            data_size,
            position: position as u32,
        });

        // Advance to next entry (Flink at offset 0 of _LIST_ENTRY).
        current = match reader.read_bytes(entry_addr, 8) {
            Ok(bytes) if bytes.len() == 8 => bytes[..8].try_into().map_or(0, u64::from_le_bytes),
            _ => break,
        };

        // Safety: stop if we exceed the entry limit.
        if entries.len() >= MAX_SHIMCACHE_ENTRIES {
            break;
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Build an ISF with the shimcache structures but no g_ShimCache symbol.
    fn shimcache_isf_no_symbol() -> IsfBuilder {
        IsfBuilder::new()
            .add_struct("_SHIM_CACHE_HEADER", 0x80)
            .add_field("_SHIM_CACHE_HEADER", "NumEntries", 0x0, "unsigned int")
            .add_field("_SHIM_CACHE_HEADER", "ListHead", 0x8, "_LIST_ENTRY")
            .add_struct("_SHIM_CACHE_ENTRY", 0x60)
            .add_field("_SHIM_CACHE_ENTRY", "ListEntry", 0x0, "_LIST_ENTRY")
            .add_field("_SHIM_CACHE_ENTRY", "Path", 0x10, "_UNICODE_STRING")
            .add_field("_SHIM_CACHE_ENTRY", "LastModified", 0x20, "unsigned long")
            .add_field("_SHIM_CACHE_ENTRY", "InsertFlag", 0x28, "unsigned int")
            .add_field("_SHIM_CACHE_ENTRY", "DataSize", 0x2C, "unsigned int")
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer")
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
    }

    /// Build an ISF with the shimcache structures AND the g_ShimCache symbol.
    fn shimcache_isf_with_symbol(symbol_addr: u64) -> IsfBuilder {
        shimcache_isf_no_symbol().add_symbol("g_ShimCache", symbol_addr)
    }

    /// Encode a Rust &str as UTF-16LE bytes.
    fn encode_utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    // ── No symbol → empty Vec ───────────────────────────────────────

    /// No g_ShimCache symbol → empty Vec (not an error).
    #[test]
    fn walk_shimcache_no_symbol() {
        let isf = shimcache_isf_no_symbol().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_shimcache(&reader).unwrap();
        assert!(result.is_empty());
    }

    // ── Single entry with path + timestamp ──────────────────────────

    // Memory layout:
    //   g_ShimCache pointer @ PTR_VADDR → HEADER_VADDR
    //
    //   _SHIM_CACHE_HEADER @ HEADER_VADDR:
    //     NumEntries = 1
    //     ListHead.Flink @ +0x8 → ENTRY0_VADDR
    //
    //   _SHIM_CACHE_ENTRY @ ENTRY0_VADDR:
    //     ListEntry.Flink @ +0x0 → HEADER_VADDR + 0x8 (back to list head)
    //     Path @ +0x10 (_UNICODE_STRING → "\\??\\C:\\Windows\\System32\\cmd.exe")
    //     LastModified @ +0x20 = 0x01D9_ABCD_1234_5678
    //     InsertFlag @ +0x28 = 0 (not executed)
    //     DataSize @ +0x2C = 0

    const PTR_VADDR: u64 = 0xFFFF_8000_0010_0000;
    const PTR_PADDR: u64 = 0x0080_0000;
    const HEADER_VADDR: u64 = 0xFFFF_8000_0020_0000;
    const HEADER_PADDR: u64 = 0x0090_0000;
    const ENTRY0_VADDR: u64 = 0xFFFF_8000_0030_0000;
    const ENTRY0_PADDR: u64 = 0x00A0_0000;
    const PATH0_BUF_VADDR: u64 = 0xFFFF_8000_0030_1000;
    const PATH0_BUF_PADDR: u64 = 0x00A1_0000;

    fn build_single_entry_reader(insert_flag: u32) -> ObjectReader<SyntheticPhysMem> {
        let isf = shimcache_isf_with_symbol(PTR_VADDR).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // g_ShimCache pointer page: contains the VA of the header.
        let mut ptr_data = vec![0u8; 4096];
        ptr_data[0..8].copy_from_slice(&HEADER_VADDR.to_le_bytes());

        // Header page:
        //   NumEntries (u32) @ 0x0 = 1
        //   ListHead.Flink (u64) @ 0x8 = ENTRY0_VADDR
        //   ListHead.Blink (u64) @ 0x10 = ENTRY0_VADDR
        let mut header_data = vec![0u8; 4096];
        header_data[0x0..0x4].copy_from_slice(&1u32.to_le_bytes());
        header_data[0x8..0x10].copy_from_slice(&ENTRY0_VADDR.to_le_bytes());
        header_data[0x10..0x18].copy_from_slice(&ENTRY0_VADDR.to_le_bytes());

        // Entry page:
        //   ListEntry.Flink @ 0x0 = HEADER_VADDR + 0x8 (back to list head)
        //   ListEntry.Blink @ 0x8 = HEADER_VADDR + 0x8
        //   Path (_UNICODE_STRING) @ 0x10
        //   LastModified (u64) @ 0x20
        //   InsertFlag (u32) @ 0x28
        //   DataSize (u32) @ 0x2C
        let path_str = r"\??\C:\Windows\System32\cmd.exe";
        let path_utf16 = encode_utf16le(path_str);
        let path_len = path_utf16.len() as u16;
        let timestamp: u64 = 0x01D9_ABCD_1234_5678;

        let list_head_flink = HEADER_VADDR + 0x8;

        let mut entry_data = vec![0u8; 4096];
        // ListEntry.Flink → back to list head
        entry_data[0x0..0x8].copy_from_slice(&list_head_flink.to_le_bytes());
        // ListEntry.Blink → back to list head
        entry_data[0x8..0x10].copy_from_slice(&list_head_flink.to_le_bytes());
        // Path _UNICODE_STRING: Length, MaximumLength, Buffer
        entry_data[0x10..0x12].copy_from_slice(&path_len.to_le_bytes());
        entry_data[0x12..0x14].copy_from_slice(&(path_len + 2).to_le_bytes());
        entry_data[0x18..0x20].copy_from_slice(&PATH0_BUF_VADDR.to_le_bytes());
        // LastModified
        entry_data[0x20..0x28].copy_from_slice(&timestamp.to_le_bytes());
        // InsertFlag
        entry_data[0x28..0x2C].copy_from_slice(&insert_flag.to_le_bytes());
        // DataSize = 0
        entry_data[0x2C..0x30].copy_from_slice(&0u32.to_le_bytes());

        // Path buffer page
        let mut path_data = vec![0u8; 4096];
        path_data[..path_utf16.len()].copy_from_slice(&path_utf16);

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(PTR_VADDR, PTR_PADDR, flags::WRITABLE)
            .write_phys(PTR_PADDR, &ptr_data)
            .map_4k(HEADER_VADDR, HEADER_PADDR, flags::WRITABLE)
            .write_phys(HEADER_PADDR, &header_data)
            .map_4k(ENTRY0_VADDR, ENTRY0_PADDR, flags::WRITABLE)
            .write_phys(ENTRY0_PADDR, &entry_data)
            .map_4k(PATH0_BUF_VADDR, PATH0_BUF_PADDR, flags::WRITABLE)
            .write_phys(PATH0_BUF_PADDR, &path_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// One entry with path + timestamp → correct ShimcacheEntry.
    #[test]
    fn walk_shimcache_single_entry() {
        let reader = build_single_entry_reader(0);
        let entries = walk_shimcache(&reader).unwrap();

        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.path, r"\??\C:\Windows\System32\cmd.exe");
        assert_eq!(e.last_modified, 0x01D9_ABCD_1234_5678);
        assert!(!e.exec_flag);
        assert_eq!(e.data_size, 0);
        assert_eq!(e.position, 0);
    }

    // ── Exec flag set → exec_flag = true ────────────────────────────

    /// Entry with InsertFlag set → exec_flag = true.
    #[test]
    fn shimcache_exec_flag() {
        let reader = build_single_entry_reader(1);
        let entries = walk_shimcache(&reader).unwrap();

        assert_eq!(entries.len(), 1);
        assert!(entries[0].exec_flag);
    }

    /// `module_section_range` parses the PE section table of an in-memory module
    /// and returns each named section's (va, size). The stub returns None, so
    /// this FAILS until the parser is implemented (increment 1 GREEN).
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

    /// `parse_shimcache_list` walks the SHIM_CACHE_ENTRY LRU list (Win10 x64
    /// layout) and parses path / last-modified / exec-flag per node. Stub
    /// returns empty → RED until the walker is implemented (increment 2 GREEN).
    #[test]
    fn parse_shimcache_list_walks_and_parses_entries() {
        let head = 0xFFFF_8000_0010_0000u64;
        let e1 = 0xFFFF_8000_0011_0000u64;
        let e2 = 0xFFFF_8000_0012_0000u64;
        let d1 = 0xFFFF_8000_0013_0000u64;
        let d2 = 0xFFFF_8000_0014_0000u64;
        let p1 = 0xFFFF_8000_0015_0000u64;
        let p2 = 0xFFFF_8000_0016_0000u64;
        let b1 = 0xFFFF_8000_0017_0000u64;
        let b2 = 0xFFFF_8000_0018_0000u64;
        let ts1 = 0x01D9_ABCD_1234_5678u64;
        let ts2 = 0x01D5_1111_2222_3333u64;
        let path1 = r"\??\C:\Windows\System32\cmd.exe";
        let path2 = r"C:\Users\rick\AppData\evil.exe";

        let mut head_pg = vec![0u8; 4096];
        head_pg[0..8].copy_from_slice(&e1.to_le_bytes());
        head_pg[8..16].copy_from_slice(&e2.to_le_bytes());

        let mk_entry = |flink: u64, plen: u16, pbuf: u64, detail: u64| {
            let mut pg = vec![0u8; 4096];
            pg[0..8].copy_from_slice(&flink.to_le_bytes());
            pg[0x18..0x1A].copy_from_slice(&plen.to_le_bytes());
            pg[0x1A..0x1C].copy_from_slice(&plen.to_le_bytes());
            pg[0x20..0x28].copy_from_slice(&pbuf.to_le_bytes());
            pg[0x28..0x30].copy_from_slice(&detail.to_le_bytes());
            pg
        };
        let mk_detail = |lastmod: u64, blob: u64| {
            let mut pg = vec![0u8; 4096];
            pg[0x8..0x10].copy_from_slice(&lastmod.to_le_bytes());
            pg[0x10..0x14].copy_from_slice(&4u32.to_le_bytes());
            pg[0x18..0x20].copy_from_slice(&blob.to_le_bytes());
            pg
        };
        let utf16 = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let p1b = utf16(path1);
        let p2b = utf16(path2);

        let e1_pg = mk_entry(e2, p1b.len() as u16, p1, d1);
        let e2_pg = mk_entry(head, p2b.len() as u16, p2, d2);
        let d1_pg = mk_detail(ts1, b1);
        let d2_pg = mk_detail(ts2, b2);
        let mut p1_pg = vec![0u8; 4096];
        p1_pg[..p1b.len()].copy_from_slice(&p1b);
        let mut p2_pg = vec![0u8; 4096];
        p2_pg[..p2b.len()].copy_from_slice(&p2b);
        let mut b1_pg = vec![0u8; 4096];
        b1_pg[0..4].copy_from_slice(&2u32.to_le_bytes());
        let mut b2_pg = vec![0u8; 4096];
        b2_pg[0..4].copy_from_slice(&0u32.to_le_bytes());

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let mut ptb = PageTableBuilder::new();
        for (i, (va, pg)) in [
            (head, &head_pg), (e1, &e1_pg), (e2, &e2_pg), (d1, &d1_pg), (d2, &d2_pg),
            (p1, &p1_pg), (p2, &p2_pg), (b1, &b1_pg), (b2, &b2_pg),
        ]
        .into_iter()
        .enumerate()
        {
            let pa = 0x0010_0000u64 + (i as u64) * 0x1000;
            ptb = ptb.map_4k(va, pa, flags::WRITABLE).write_phys(pa, pg);
        }
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let entries = parse_shimcache_list(&reader, head);
        assert_eq!(entries.len(), 2, "expected 2 entries, got {}", entries.len());
        assert_eq!(entries[0].path, path1);
        assert_eq!(entries[0].last_modified, ts1);
        assert!(entries[0].exec_flag, "blob != 0 -> executed");
        assert_eq!(entries[0].position, 0);
        assert_eq!(entries[1].path, path2);
        assert_eq!(entries[1].last_modified, ts2);
        assert!(!entries[1].exec_flag, "blob == 0 -> not executed");
        assert_eq!(entries[1].position, 1);
    }
}
