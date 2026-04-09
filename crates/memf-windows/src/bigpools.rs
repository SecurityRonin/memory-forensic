//! Big page pool tag scanning (Windows).
//!
//! The Windows kernel tracks large pool allocations (> 4 KB) in a dedicated
//! table exposed via the `PoolBigPageTable` symbol.  Each entry records the
//! virtual address of the allocation, its 4-byte pool tag, pool type, and
//! size in bytes.  Enumerating these entries is equivalent to Volatility's
//! `bigpools` plugin and is valuable for:
//!
//! - Identifying large kernel object allocations (drivers, registry hives).
//! - Detecting suspicious allocations with blank/null tags.
//! - Profiling memory usage by pool type.
//!
//! The table is an array of `_POOL_TRACKER_BIG_PAGES` structures.  Each
//! entry is 24 bytes (x64) or 32 bytes depending on alignment.  The
//! structure layout is:
//!
//! | Offset | Field           | Size |
//! |--------|-----------------|------|
//! | 0x00   | VirtualAddress  | u64  |
//! | 0x08   | Tag             | u32  |
//! | 0x0C   | PoolType        | u32  |
//! | 0x10   | NumberOfBytes   | u64  |
//!
//! Free entries have bit 0 of VirtualAddress set to 1.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Maximum number of big pool entries to iterate (safety limit).
const MAX_BIGPOOL_ENTRIES: u64 = 65536;

/// A single big page pool allocation entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BigPoolEntry {
    /// Virtual address of the big pool allocation.
    pub address: u64,
    /// 4-character ASCII pool tag (e.g., "CM31", "MmSt").
    pub pool_tag: String,
    /// Size of the allocation in bytes.
    pub size: u64,
    /// Human-readable pool type name (e.g., "NonPagedPool", "PagedPool").
    pub pool_type: String,
    /// Whether the entry is marked as free (VA bit 0 set).
    pub is_free: bool,
}

/// Map a numeric pool type to its human-readable name.
///
/// Windows defines pool types as an enum (`_POOL_TYPE`).  The most common
/// values are documented below; unknown values are formatted as
/// `"Unknown(N)"`.
pub fn pool_type_name(pool_type: u32) -> String {
    match pool_type {
        0 => "NonPagedPool".into(),
        1 => "PagedPool".into(),
        2 => "NonPagedPoolMustSucceed".into(),
        3 => "DontUseThisType".into(),
        4 => "NonPagedPoolCacheAligned".into(),
        5 => "PagedPoolCacheAligned".into(),
        512 => "NonPagedPoolNx".into(),
        other => format!("Unknown({})", other),
    }
}

/// Classify a big pool allocation as suspicious.
///
/// Returns `true` if the tag is all null bytes (`\0\0\0\0`) or all spaces
/// (`"    "`), which can indicate wiped or uninitialized allocations, or if
/// the size exceeds 100 MB (unusually large for a single kernel allocation).
pub fn classify_bigpool(tag: &str, size: u64) -> bool {
    const HUNDRED_MB: u64 = 100 * 1024 * 1024;

    // Null tag (all zeroes show up as 4 null chars).
    if tag == "\0\0\0\0" {
        return true;
    }

    // Blank tag (all spaces).
    if tag == "    " {
        return true;
    }

    // Unusually large allocation.
    if size > HUNDRED_MB {
        return true;
    }

    false
}

/// Walk the big page pool table and extract entries.
///
/// Reads `PoolBigPageTable` and `PoolBigPageTableSize` symbols to locate
/// the array of `_POOL_TRACKER_BIG_PAGES` entries.  Returns an empty `Vec`
/// if the required symbols are not present (graceful degradation).
///
/// # Errors
///
/// Returns an error if memory reads fail for the big pool table after the
/// symbol has been located and validated.
pub fn walk_bigpools<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<BigPoolEntry>> {
    // Locate the PoolBigPageTable pointer symbol.
    let Some(table_ptr_addr) = reader.symbols().symbol_address("PoolBigPageTable") else {
        return Ok(Vec::new()); // graceful degradation
    };

    // PoolBigPageTable is a pointer — dereference to get the table VA.
    let table_addr: u64 = match reader.read_bytes(table_ptr_addr, 8) {
        Ok(bytes) => {
            let arr: [u8; 8] = match bytes[..8].try_into() {
                Ok(a) => a,
                Err(_) => return Ok(Vec::new()),
            };
            u64::from_le_bytes(arr)
        }
        Err(_) => return Ok(Vec::new()),
    };

    if table_addr == 0 {
        return Ok(Vec::new());
    }

    // Read entry count from PoolBigPageTableSize.
    let entry_count = match reader.symbols().symbol_address("PoolBigPageTableSize") {
        Some(size_addr) => match reader.read_bytes(size_addr, 8) {
            Ok(bytes) => {
                let arr: [u8; 8] = match bytes[..8].try_into() {
                    Ok(a) => a,
                    Err(_) => return Ok(Vec::new()),
                };
                let raw = u64::from_le_bytes(arr);
                raw.min(MAX_BIGPOOL_ENTRIES)
            }
            Err(_) => return Ok(Vec::new()),
        },
        None => return Ok(Vec::new()),
    };

    if entry_count == 0 {
        return Ok(Vec::new());
    }

    // Each _POOL_TRACKER_BIG_PAGES entry is 24 bytes:
    //   Va:            u64 @ 0x00
    //   Key:           u32 @ 0x08
    //   PoolType:      u32 @ 0x0C
    //   NumberOfBytes: u64 @ 0x10
    const ENTRY_SIZE: u64 = 24;

    let total_bytes = entry_count * ENTRY_SIZE;
    let table_data = reader.read_bytes(table_addr, total_bytes as usize)?;

    let mut results = Vec::new();

    for i in 0..entry_count {
        let offset = (i * ENTRY_SIZE) as usize;
        let entry = &table_data[offset..offset + ENTRY_SIZE as usize];

        let va = u64::from_le_bytes(entry[0..8].try_into().unwrap());
        let tag_raw = u32::from_le_bytes(entry[8..12].try_into().unwrap());
        let pool_type_raw = u32::from_le_bytes(entry[12..16].try_into().unwrap());
        let number_of_bytes = u64::from_le_bytes(entry[16..24].try_into().unwrap());

        // Skip completely empty entries (all zeros).
        if va == 0 && tag_raw == 0 && number_of_bytes == 0 {
            continue;
        }

        // Free entries have bit 0 of Va set.
        let is_free = (va & 1) != 0;
        let address = va & !1u64; // mask off free bit

        // Decode the 4-byte ASCII tag.
        let tag_bytes = tag_raw.to_le_bytes();
        let pool_tag: String = tag_bytes
            .iter()
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '\0' })
            .collect();

        results.push(BigPoolEntry {
            address,
            pool_tag,
            size: number_of_bytes,
            pool_type: pool_type_name(pool_type_raw),
            is_free,
        });
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ── pool_type_name tests ────────────────────────────────────────

    /// NonPagedPool (0) maps correctly.
    #[test]
    fn pool_type_nonpaged() {
        assert_eq!(pool_type_name(0), "NonPagedPool");
    }

    /// PagedPool (1) maps correctly.
    #[test]
    fn pool_type_paged() {
        assert_eq!(pool_type_name(1), "PagedPool");
    }

    /// NonPagedPoolNx (512) maps correctly.
    #[test]
    fn pool_type_nx() {
        assert_eq!(pool_type_name(512), "NonPagedPoolNx");
    }

    /// Unknown pool types produce a formatted string.
    #[test]
    fn pool_type_unknown() {
        assert_eq!(pool_type_name(999), "Unknown(999)");
    }

    // ── classify_bigpool tests ──────────────────────────────────────

    /// Normal tag + reasonable size is not suspicious.
    #[test]
    fn classify_normal_benign() {
        assert!(!classify_bigpool("CM31", 4096));
        assert!(!classify_bigpool("Proc", 8192));
    }

    /// Huge allocation (> 100 MB) is suspicious.
    #[test]
    fn classify_huge_suspicious() {
        let over_100mb = 101 * 1024 * 1024;
        assert!(classify_bigpool("Proc", over_100mb));
    }

    /// Null tag is suspicious.
    #[test]
    fn classify_null_tag_suspicious() {
        assert!(classify_bigpool("\0\0\0\0", 4096));
    }

    /// Blank (all spaces) tag is suspicious.
    #[test]
    fn classify_blank_tag_suspicious() {
        assert!(classify_bigpool("    ", 4096));
    }

    // ── walk_bigpools tests ─────────────────────────────────────────

    /// No PoolBigPageTable symbol -> empty Vec (not an error).
    #[test]
    fn walk_no_symbol_returns_empty() {
        let isf = IsfBuilder::new()
            .add_struct("_POOL_TRACKER_BIG_PAGES", 24)
            .add_field("_POOL_TRACKER_BIG_PAGES", "Va", 0, "unsigned long long")
            .add_field("_POOL_TRACKER_BIG_PAGES", "Key", 8, "unsigned int")
            .add_field("_POOL_TRACKER_BIG_PAGES", "PoolType", 12, "unsigned int")
            .add_field(
                "_POOL_TRACKER_BIG_PAGES",
                "NumberOfBytes",
                16,
                "unsigned long long",
            )
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_bigpools(&reader).unwrap();
        assert!(result.is_empty());
    }
}
