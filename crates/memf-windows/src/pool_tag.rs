//! Windows kernel pool tag scanning.
//!
//! The Windows kernel tracks memory allocations by 4-character ASCII "pool
//! tags" in the `PoolTrackTable` kernel symbol. Each entry records the tag,
//! pool type, allocation/free counts, and bytes consumed. Extracting these
//! statistics from a memory dump reveals what kernel objects are allocated —
//! useful for detecting rootkits, identifying resource exhaustion, and
//! profiling system behaviour during DFIR triage.
//!
//! The tracking table is an array of `_POOL_TRACKER_TABLE` structures,
//! sized by `PoolTrackTableSize` (or a safety-capped scan). Each entry
//! contains a 4-byte tag, pool type flags, and running allocation counters.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{PoolTagEntry, Result};

/// Maximum number of pool tracking entries to iterate (safety limit).
const MAX_POOL_TAG_ENTRIES: u64 = 65536;

/// Walk the kernel pool tracking table and extract pool tag statistics.
///
/// Reads the `PoolTrackTable` symbol to locate the array of
/// `_POOL_TRACKER_TABLE` entries, then iterates up to `PoolTrackTableSize`
/// entries (capped at [`MAX_POOL_TAG_ENTRIES`]). Returns an empty `Vec` if
/// the required symbols are not present (graceful degradation).
pub fn walk_pool_tags<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<PoolTagEntry>> {
    todo!()
}

/// Look up a human-readable description for a well-known Windows pool tag.
///
/// Returns `None` for unrecognised tags. The mapping covers the most
/// forensically relevant kernel pool tags.
fn describe_tag(tag: &str) -> Option<&'static str> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ── describe_tag tests ──────────────────────────────────────────

    /// Well-known tags return the expected description.
    #[test]
    fn describe_tag_known() {
        assert_eq!(
            describe_tag("Proc"),
            Some("Process objects (_EPROCESS)")
        );
        assert_eq!(
            describe_tag("Thre"),
            Some("Thread objects (_ETHREAD)")
        );
        assert_eq!(describe_tag("File"), Some("File objects"));
        assert_eq!(
            describe_tag("MmSt"),
            Some("Memory manager section")
        );
    }

    /// Unknown tags return None.
    #[test]
    fn describe_tag_unknown() {
        assert_eq!(describe_tag("Zzzz"), None);
        assert_eq!(describe_tag("XXXX"), None);
        assert_eq!(describe_tag(""), None);
    }

    // ── walk_pool_tags tests ────────────────────────────────────────

    /// No PoolTrackTable symbol → empty Vec (not an error).
    #[test]
    fn walk_pool_tags_no_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("_POOL_TRACKER_TABLE", 40)
            .add_field("_POOL_TRACKER_TABLE", "Key", 0, "unsigned int")
            .add_field("_POOL_TRACKER_TABLE", "PoolType", 4, "unsigned int")
            .add_field("_POOL_TRACKER_TABLE", "PagedAllocs", 8, "unsigned long long")
            .add_field("_POOL_TRACKER_TABLE", "PagedFrees", 16, "unsigned long long")
            .add_field("_POOL_TRACKER_TABLE", "PagedBytes", 24, "unsigned long long")
            .add_field("_POOL_TRACKER_TABLE", "NonPagedAllocs", 8, "unsigned long long")
            .add_field("_POOL_TRACKER_TABLE", "NonPagedFrees", 16, "unsigned long long")
            .add_field("_POOL_TRACKER_TABLE", "NonPagedBytes", 24, "unsigned long long")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_pool_tags(&reader).unwrap();
        assert!(result.is_empty());
    }

    // Synthetic layout:
    //   PoolTrackTable pointer @ TABLE_PTR_VADDR → TABLE_VADDR
    //   PoolTrackTableSize @ SIZE_VADDR → 2 (u64)
    //
    //   _POOL_TRACKER_TABLE[0] @ TABLE_VADDR + 0:
    //     Key = b"Proc" (0x636F7250 little-endian)
    //     PoolType = 1 (Paged)
    //     PagedAllocs = 42
    //     PagedFrees = 10
    //     PagedBytes = 8192
    //
    //   _POOL_TRACKER_TABLE[1] @ TABLE_VADDR + 40:
    //     Key = b"Thre" (0x65726854 little-endian)
    //     PoolType = 0 (NonPaged)
    //     NonPagedAllocs = 100
    //     NonPagedFrees = 25
    //     NonPagedBytes = 16384

    const TABLE_PTR_VADDR: u64 = 0xFFFF_8000_0010_0000;
    const TABLE_PTR_PADDR: u64 = 0x0080_0000;
    const SIZE_VADDR: u64 = 0xFFFF_8000_0010_1000;
    const SIZE_PADDR: u64 = 0x0080_1000;
    const TABLE_VADDR: u64 = 0xFFFF_8000_0020_0000;
    const TABLE_PADDR: u64 = 0x0090_0000;

    fn build_pool_tag_reader() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("_POOL_TRACKER_TABLE", 40)
            .add_field("_POOL_TRACKER_TABLE", "Key", 0, "unsigned int")
            .add_field("_POOL_TRACKER_TABLE", "PoolType", 4, "unsigned int")
            .add_field("_POOL_TRACKER_TABLE", "PagedAllocs", 8, "unsigned long long")
            .add_field("_POOL_TRACKER_TABLE", "PagedFrees", 16, "unsigned long long")
            .add_field("_POOL_TRACKER_TABLE", "PagedBytes", 24, "unsigned long long")
            .add_field("_POOL_TRACKER_TABLE", "NonPagedAllocs", 8, "unsigned long long")
            .add_field("_POOL_TRACKER_TABLE", "NonPagedFrees", 16, "unsigned long long")
            .add_field("_POOL_TRACKER_TABLE", "NonPagedBytes", 24, "unsigned long long")
            .add_symbol("PoolTrackTable", TABLE_PTR_VADDR)
            .add_symbol("PoolTrackTableSize", SIZE_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // PoolTrackTable pointer page: contains the VA of the actual table
        let mut ptr_data = vec![0u8; 4096];
        ptr_data[0..8].copy_from_slice(&TABLE_VADDR.to_le_bytes());

        // PoolTrackTableSize page: u64 = 2
        let mut size_data = vec![0u8; 4096];
        size_data[0..8].copy_from_slice(&2u64.to_le_bytes());

        // Table entries (2 × 40 bytes)
        let mut table_data = vec![0u8; 4096];

        // Entry 0: tag "Proc", PoolType=1 (Paged), allocs=42, frees=10, bytes=8192
        table_data[0..4].copy_from_slice(b"Proc"); // Key
        table_data[4..8].copy_from_slice(&1u32.to_le_bytes()); // PoolType (Paged)
        table_data[8..16].copy_from_slice(&42u64.to_le_bytes()); // PagedAllocs
        table_data[16..24].copy_from_slice(&10u64.to_le_bytes()); // PagedFrees
        table_data[24..32].copy_from_slice(&8192u64.to_le_bytes()); // PagedBytes

        // Entry 1: tag "Thre", PoolType=0 (NonPaged), allocs=100, frees=25, bytes=16384
        let off = 40;
        table_data[off..off + 4].copy_from_slice(b"Thre"); // Key
        table_data[off + 4..off + 8].copy_from_slice(&0u32.to_le_bytes()); // PoolType (NonPaged)
        table_data[off + 8..off + 16].copy_from_slice(&100u64.to_le_bytes()); // NonPagedAllocs
        table_data[off + 16..off + 24].copy_from_slice(&25u64.to_le_bytes()); // NonPagedFrees
        table_data[off + 24..off + 32].copy_from_slice(&16384u64.to_le_bytes()); // NonPagedBytes

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(TABLE_PTR_VADDR, TABLE_PTR_PADDR, flags::WRITABLE)
            .write_phys(TABLE_PTR_PADDR, &ptr_data)
            .map_4k(SIZE_VADDR, SIZE_PADDR, flags::WRITABLE)
            .write_phys(SIZE_PADDR, &size_data)
            .map_4k(TABLE_VADDR, TABLE_PADDR, flags::WRITABLE)
            .write_phys(TABLE_PADDR, &table_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// Two synthetic pool tag entries are correctly parsed.
    #[test]
    fn walk_pool_tags_with_entries() {
        let reader = build_pool_tag_reader();
        let entries = walk_pool_tags(&reader).unwrap();

        assert_eq!(entries.len(), 2);

        // Entry 0: "Proc" — Paged pool
        let proc_entry = &entries[0];
        assert_eq!(proc_entry.tag, "Proc");
        assert_eq!(proc_entry.pool_type, "Paged");
        assert_eq!(proc_entry.allocation_count, 42);
        assert_eq!(proc_entry.free_count, 10);
        assert_eq!(proc_entry.bytes_used, 8192);
        assert_eq!(
            proc_entry.description.as_deref(),
            Some("Process objects (_EPROCESS)")
        );

        // Entry 1: "Thre" — NonPaged pool
        let thre_entry = &entries[1];
        assert_eq!(thre_entry.tag, "Thre");
        assert_eq!(thre_entry.pool_type, "NonPaged");
        assert_eq!(thre_entry.allocation_count, 100);
        assert_eq!(thre_entry.free_count, 25);
        assert_eq!(thre_entry.bytes_used, 16384);
        assert_eq!(
            thre_entry.description.as_deref(),
            Some("Thread objects (_ETHREAD)")
        );
    }
}
