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
    todo!()
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
