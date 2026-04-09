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

/// Maximum number of shimcache entries to iterate (safety limit).
const MAX_SHIMCACHE_ENTRIES: usize = 4096;

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
        Ok(bytes) if bytes.len() == 8 => {
            u64::from_le_bytes(bytes[..8].try_into().unwrap())
        }
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
        Ok(bytes) if bytes.len() == 8 => {
            u64::from_le_bytes(bytes[..8].try_into().unwrap())
        }
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
        let path = read_unicode_string(reader, entry_addr + path_offset)
            .unwrap_or_default();

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
            Ok(bytes) if bytes.len() == 8 => {
                u64::from_le_bytes(bytes[..8].try_into().unwrap())
            }
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
        shimcache_isf_no_symbol()
            .add_symbol("g_ShimCache", symbol_addr)
    }

    /// Encode a Rust &str as UTF-16LE bytes.
    fn encode_utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect()
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

    fn build_single_entry_reader(
        insert_flag: u32,
    ) -> ObjectReader<SyntheticPhysMem> {
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
}
