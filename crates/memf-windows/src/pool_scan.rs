//! Pool scanner for finding kernel objects by pool tag.
//!
//! Scans physical memory ranges for pool allocation headers identified
//! by their 4-character ASCII pool tag. This technique finds kernel
//! objects (processes, threads, drivers) independently of linked lists,
//! catching DKOM-hidden objects that have been unlinked from
//! `PsActiveProcessHead` or similar structures.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// A pool allocation header found in physical memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PoolEntry {
    /// Physical address of the pool header.
    pub physical_addr: u64,
    /// 4-character ASCII pool tag (e.g. "Proc").
    pub pool_tag: String,
    /// Pool type string: "NonPagedPool", "PagedPool", etc.
    pub pool_type: String,
    /// Allocation size in bytes.
    pub block_size: u32,
    /// Inferred struct type based on pool tag.
    pub struct_type: String,
    /// True if the tag is outside the known-good list or in an unexpected pool.
    pub is_suspicious: bool,
}

/// A hidden process found via pool scan but absent from PsActiveProcessHead.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HiddenProcessInfo {
    /// Physical address of the EPROCESS pool header.
    pub physical_addr: u64,
    /// Process ID.
    pub pid: u32,
    /// Image name from EPROCESS.
    pub image_name: String,
    /// Pool tag used to locate this entry.
    pub pool_tag: String,
    /// Reason this process is flagged as hidden.
    pub reason: String,
}

/// Known pool tags and their associated struct types.
const KNOWN_TAGS: &[(&str, &str)] = &[
    ("Proc", "EPROCESS"),
    ("Thre", "ETHREAD"),
    ("Driv", "DRIVER_OBJECT"),
    ("File", "FILE_OBJECT"),
    ("Mutant", "KMUTANT"),
    ("Even", "EVENT"),
    ("Sema", "SEMAPHORE"),
    ("Sect", "SECTION"),
    ("Port", "ALPC_PORT"),
    ("Vad\x20", "VAD_NODE"),
    ("CM10", "CM_KEY_BODY"),
    ("CM31", "CM_KEY_BODY"),
    ("ObNm", "OBJECT_NAME_INFO"),
    ("ObHd", "OBJECT_HEADER"),
];

/// Convert a pool type byte to a human-readable string.
fn pool_type_name(pool_type: u8) -> &'static str {
    match pool_type & 0x0F {
        0 => "NonPagedPool",
        1 => "PagedPool",
        2 => "NonPagedPoolMustSucceed",
        4 => "NonPagedPoolCacheAligned",
        5 => "PagedPoolCacheAligned",
        6 => "NonPagedPoolCacheAlignedMustS",
        _ => "Unknown",
    }
}

/// Infer the struct type associated with a pool tag.
fn infer_struct_type(tag: &str) -> &'static str {
    for (known_tag, struct_type) in KNOWN_TAGS {
        if tag == *known_tag {
            return struct_type;
        }
    }
    "Unknown"
}

/// Returns `true` if the pool tag is NOT in the known-good set (suspicious).
pub fn classify_pool_tag(tag: &str) -> bool {
    !KNOWN_TAGS.iter().any(|(known, _)| *known == tag)
}

/// Scan a virtual memory range for occurrences of a specific pool tag (u32 little-endian).
///
/// The `_POOL_HEADER` layout on x64:
/// - Bytes 0–1: BlockSize (u16, units of 16 bytes)
/// - Byte 2:    PoolType (u8)
/// - Byte 3:    PoolIndex (u8)
/// - Bytes 4–7: PoolTag (u32 little-endian ASCII)
///
/// Returns a list of virtual addresses where the tag was found.
pub fn scan_pool_for_tag<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    tag: u32,
    start: u64,
    end: u64,
) -> Vec<u64> {
    let tag_bytes = tag.to_le_bytes();
    let mut hits = Vec::new();

    // Scan in 16-byte aligned steps (pool headers are 16-byte aligned on x64)
    let mut addr = start;
    while addr + 8 <= end {
        // Read 8 bytes for the pool header
        let bytes = match reader.read_bytes(addr, 8) {
            Ok(b) => b,
            Err(_) => {
                addr += 16;
                continue;
            }
        };

        // Check if bytes 4–7 match the pool tag
        if bytes.len() >= 8 && bytes[4..8] == tag_bytes {
            hits.push(addr);
        }

        addr += 16;
    }

    hits
}

/// Walk the pool scan looking for known kernel object pool headers.
///
/// Attempts to locate `MmNonPagedPoolStart` and `MmNonPagedPoolEnd` symbols
/// to bound the scan. Returns an empty Vec if these symbols are absent
/// (graceful degradation).
pub fn walk_pool_scan<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<PoolEntry>> {
    // Graceful degradation: require MmNonPagedPoolStart symbol
    let Some(_start_sym) = reader.symbols().symbol_address("MmNonPagedPoolStart") else {
        return Ok(Vec::new());
    };

    let Some(_end_sym) = reader.symbols().symbol_address("MmNonPagedPoolEnd") else {
        return Ok(Vec::new());
    };

    // In a real implementation we would read the pointer values and scan.
    // For now, return empty as we cannot dereference without a VAS translation.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "Proc" is a well-known tag — must not be flagged suspicious.
    #[test]
    fn classify_known_proc_tag_not_suspicious() {
        assert!(!classify_pool_tag("Proc"));
    }

    /// "XxXx" is not in the known-good list — must be flagged suspicious.
    #[test]
    fn classify_unknown_tag_suspicious() {
        assert!(classify_pool_tag("XxXx"));
    }

    /// When MmNonPagedPoolStart symbol is absent, walker returns empty.
    #[test]
    fn walk_pool_scan_no_symbol_returns_empty() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &[0u8; 16]);
        let (cr3, mem) = ptb.build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_pool_scan(&reader).unwrap();
        assert!(results.is_empty());
    }
}
