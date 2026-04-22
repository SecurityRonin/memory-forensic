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
///
/// # Errors
///
/// Returns an error if memory reads fail for the pool tracking table
/// after the symbol has been located and validated.
pub fn walk_pool_tags<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<PoolTagEntry>> {
    // Locate the PoolTrackTable pointer symbol
    let Some(table_ptr_addr) = reader.symbols().symbol_address("PoolTrackTable") else {
        return Ok(Vec::new()); // graceful degradation
    };

    // PoolTrackTable is a pointer — read 8 bytes at the symbol address
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

    // Read the table size from PoolTrackTableSize symbol
    let entry_count = match reader.symbols().symbol_address("PoolTrackTableSize") {
        Some(size_addr) => match reader.read_bytes(size_addr, 8) {
            Ok(bytes) => {
                let arr: [u8; 8] = match bytes[..8].try_into() {
                    Ok(a) => a,
                    Err(_) => return Ok(Vec::new()),
                };
                u64::from_le_bytes(arr).min(MAX_POOL_TAG_ENTRIES)
            }
            Err(_) => return Ok(Vec::new()),
        },
        None => return Ok(Vec::new()),
    };

    let entry_size = reader
        .symbols()
        .struct_size("_POOL_TRACKER_TABLE")
        .unwrap_or(40);

    let mut entries = Vec::new();

    for i in 0..entry_count {
        let entry_addr = table_addr + i * entry_size;

        // Read the 4-byte pool tag key
        let Ok(key_bytes) = reader.read_bytes(entry_addr, 4) else {
            continue;
        };

        // Skip empty entries (all-zero tag)
        if key_bytes.iter().all(|&b| b == 0) {
            continue;
        }

        // Convert tag bytes to ASCII string (replace non-printable with '.')
        let tag: String = key_bytes
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();

        // Read pool type flags
        let pool_type_raw: u32 = reader
            .read_field(entry_addr, "_POOL_TRACKER_TABLE", "PoolType")
            .unwrap_or(0);

        // Bit 0 clear = NonPaged, Bit 0 set = Paged
        // Bit 5 set (0x20) = NonPagedExecute (NX pool)
        let pool_type = if pool_type_raw & 1 != 0 {
            "Paged".to_string()
        } else if pool_type_raw & 0x20 != 0 {
            "NonPagedExecute".to_string()
        } else {
            "NonPaged".to_string()
        };

        // Read allocation statistics based on pool type
        let (allocation_count, free_count, bytes_used) = if pool_type_raw & 1 != 0 {
            // Paged pool
            let allocs: u64 = reader
                .read_field(entry_addr, "_POOL_TRACKER_TABLE", "PagedAllocs")
                .unwrap_or(0);
            let frees: u64 = reader
                .read_field(entry_addr, "_POOL_TRACKER_TABLE", "PagedFrees")
                .unwrap_or(0);
            let bytes: u64 = reader
                .read_field(entry_addr, "_POOL_TRACKER_TABLE", "PagedBytes")
                .unwrap_or(0);
            (allocs, frees, bytes)
        } else {
            // NonPaged pool
            let allocs: u64 = reader
                .read_field(entry_addr, "_POOL_TRACKER_TABLE", "NonPagedAllocs")
                .unwrap_or(0);
            let frees: u64 = reader
                .read_field(entry_addr, "_POOL_TRACKER_TABLE", "NonPagedFrees")
                .unwrap_or(0);
            let bytes: u64 = reader
                .read_field(entry_addr, "_POOL_TRACKER_TABLE", "NonPagedBytes")
                .unwrap_or(0);
            (allocs, frees, bytes)
        };

        let description = describe_tag(&tag).map(String::from);

        entries.push(PoolTagEntry {
            tag,
            pool_type,
            allocation_count,
            free_count,
            bytes_used,
            description,
        });
    }

    Ok(entries)
}

/// Look up a human-readable description for a well-known Windows pool tag.
///
/// Returns `None` for unrecognised tags. The mapping covers the most
/// forensically relevant kernel pool tags.
fn describe_tag(tag: &str) -> Option<&'static str> {
    match tag {
        "Proc" => Some("Process objects (_EPROCESS)"),
        "Thre" => Some("Thread objects (_ETHREAD)"),
        "File" => Some("File objects"),
        "MmSt" => Some("Memory manager section"),
        "MmCa" => Some("Memory manager control area"),
        "MmCi" => Some("Memory manager subsection"),
        "Driv" => Some("Driver objects (_DRIVER_OBJECT)"),
        "Devi" => Some("Device objects (_DEVICE_OBJECT)"),
        "ObNm" => Some("Object name buffer"),
        "ObDi" => Some("Object directory"),
        "CcBc" => Some("Cache manager BCB"),
        "Pool" => Some("Pool tracking table"),
        "Ntfx" => Some("NTFS general allocation"),
        "NtfF" => Some("NTFS FCB"),
        "FMfn" => Some("FltMgr file name"),
        "Tokn" => Some("Token objects (_TOKEN)"),
        "Sema" => Some("Semaphore objects"),
        "Muta" => Some("Mutant objects"),
        "Even" => Some("Event objects"),
        "Key " => Some("Registry key objects"),
        "Irp " => Some("I/O request packets"),
        "Mdl " => Some("Memory descriptor lists"),
        "Vad " => Some("Virtual address descriptors"),
        "VadS" => Some("VAD short nodes"),
        "CM  " => Some("Configuration manager"),
        "Ica " => Some("ICA (terminal services) buffer"),
        "Afd " => Some("AFD (ancillary function driver)"),
        "TcpE" => Some("TCP endpoint"),
        "UdpA" => Some("UDP endpoint"),
        _ => None,
    }
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
        assert_eq!(describe_tag("Proc"), Some("Process objects (_EPROCESS)"));
        assert_eq!(describe_tag("Thre"), Some("Thread objects (_ETHREAD)"));
        assert_eq!(describe_tag("File"), Some("File objects"));
        assert_eq!(describe_tag("MmSt"), Some("Memory manager section"));
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
            .add_field(
                "_POOL_TRACKER_TABLE",
                "PagedAllocs",
                8,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "PagedFrees",
                16,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "PagedBytes",
                24,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "NonPagedAllocs",
                8,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "NonPagedFrees",
                16,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "NonPagedBytes",
                24,
                "unsigned long long",
            )
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
            .add_field(
                "_POOL_TRACKER_TABLE",
                "PagedAllocs",
                8,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "PagedFrees",
                16,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "PagedBytes",
                24,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "NonPagedAllocs",
                8,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "NonPagedFrees",
                16,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "NonPagedBytes",
                24,
                "unsigned long long",
            )
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

    /// More well-known tags return the expected description.
    #[test]
    fn describe_tag_more_known_tags() {
        assert!(describe_tag("MmCa").is_some());
        assert!(describe_tag("MmCi").is_some());
        assert!(describe_tag("Driv").is_some());
        assert!(describe_tag("Devi").is_some());
        assert!(describe_tag("ObNm").is_some());
        assert!(describe_tag("ObDi").is_some());
        assert!(describe_tag("CcBc").is_some());
        assert!(describe_tag("Pool").is_some());
        assert!(describe_tag("Ntfx").is_some());
        assert!(describe_tag("NtfF").is_some());
        assert!(describe_tag("FMfn").is_some());
        assert!(describe_tag("Tokn").is_some());
        assert!(describe_tag("Sema").is_some());
        assert!(describe_tag("Muta").is_some());
        assert!(describe_tag("Even").is_some());
        assert!(describe_tag("Key ").is_some());
        assert!(describe_tag("Irp ").is_some());
        assert!(describe_tag("Mdl ").is_some());
        assert!(describe_tag("Vad ").is_some());
        assert!(describe_tag("VadS").is_some());
        assert!(describe_tag("CM  ").is_some());
        assert!(describe_tag("Ica ").is_some());
        assert!(describe_tag("Afd ").is_some());
        assert!(describe_tag("TcpE").is_some());
        assert!(describe_tag("UdpA").is_some());
    }

    /// NonPagedExecute pool type (pool_type_raw & 0x20 set, bit 0 clear).
    #[test]
    fn walk_pool_tags_nonpaged_execute_entry() {
        // Add a 3rd entry with PoolType=0x20 (NonPagedExecute) to the existing fixture
        // by building a dedicated reader with one NonPagedExecute entry.
        const NX_TABLE_PTR_VADDR: u64 = 0xFFFF_8000_0011_0000;
        const NX_TABLE_PTR_PADDR: u64 = 0x0082_0000;
        const NX_SIZE_VADDR: u64 = 0xFFFF_8000_0011_1000;
        const NX_SIZE_PADDR: u64 = 0x0083_0000;
        const NX_TABLE_VADDR: u64 = 0xFFFF_8000_0012_0000;
        const NX_TABLE_PADDR: u64 = 0x0084_0000;

        let isf = IsfBuilder::new()
            .add_struct("_POOL_TRACKER_TABLE", 40)
            .add_field("_POOL_TRACKER_TABLE", "Key", 0, "unsigned int")
            .add_field("_POOL_TRACKER_TABLE", "PoolType", 4, "unsigned int")
            .add_field(
                "_POOL_TRACKER_TABLE",
                "PagedAllocs",
                8,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "PagedFrees",
                16,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "PagedBytes",
                24,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "NonPagedAllocs",
                8,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "NonPagedFrees",
                16,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "NonPagedBytes",
                24,
                "unsigned long long",
            )
            .add_symbol("PoolTrackTable", NX_TABLE_PTR_VADDR)
            .add_symbol("PoolTrackTableSize", NX_SIZE_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut ptr_data = vec![0u8; 4096];
        ptr_data[0..8].copy_from_slice(&NX_TABLE_VADDR.to_le_bytes());

        let mut size_data = vec![0u8; 4096];
        size_data[0..8].copy_from_slice(&1u64.to_le_bytes()); // 1 entry

        let mut table_data = vec![0u8; 4096];
        // Tag "Exec" with PoolType=0x20 (NonPagedExecute: bit 0 clear, bit 5 set)
        table_data[0..4].copy_from_slice(b"Exec");
        table_data[4..8].copy_from_slice(&0x20u32.to_le_bytes()); // NonPagedExecute
        table_data[8..16].copy_from_slice(&5u64.to_le_bytes()); // NonPagedAllocs
        table_data[16..24].copy_from_slice(&0u64.to_le_bytes()); // NonPagedFrees
        table_data[24..32].copy_from_slice(&1024u64.to_le_bytes()); // NonPagedBytes

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(NX_TABLE_PTR_VADDR, NX_TABLE_PTR_PADDR, flags::WRITABLE)
            .write_phys(NX_TABLE_PTR_PADDR, &ptr_data)
            .map_4k(NX_SIZE_VADDR, NX_SIZE_PADDR, flags::WRITABLE)
            .write_phys(NX_SIZE_PADDR, &size_data)
            .map_4k(NX_TABLE_VADDR, NX_TABLE_PADDR, flags::WRITABLE)
            .write_phys(NX_TABLE_PADDR, &table_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let entries = walk_pool_tags(&reader).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tag, "Exec");
        assert_eq!(entries[0].pool_type, "NonPagedExecute");
        assert_eq!(entries[0].allocation_count, 5);
        assert_eq!(entries[0].bytes_used, 1024);
    }

    /// PoolTrackTable symbol present but table pointer is 0 → empty.
    #[test]
    fn walk_pool_tags_zero_table_addr_empty() {
        const ZPTR_VADDR: u64 = 0xFFFF_8000_0013_0000;
        const ZPTR_PADDR: u64 = 0x0085_0000;
        const ZSIZE_VADDR: u64 = 0xFFFF_8000_0013_1000;
        const ZSIZE_PADDR: u64 = 0x0086_0000;

        let isf = IsfBuilder::new()
            .add_struct("_POOL_TRACKER_TABLE", 40)
            .add_field("_POOL_TRACKER_TABLE", "Key", 0, "unsigned int")
            .add_field("_POOL_TRACKER_TABLE", "PoolType", 4, "unsigned int")
            .add_field(
                "_POOL_TRACKER_TABLE",
                "PagedAllocs",
                8,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "PagedFrees",
                16,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "PagedBytes",
                24,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "NonPagedAllocs",
                8,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "NonPagedFrees",
                16,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "NonPagedBytes",
                24,
                "unsigned long long",
            )
            .add_symbol("PoolTrackTable", ZPTR_VADDR)
            .add_symbol("PoolTrackTableSize", ZSIZE_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // table ptr page: all zeros (pointer is 0 → table_addr == 0 → early return)
        let ptr_data = vec![0u8; 4096];
        let mut size_data = vec![0u8; 4096];
        size_data[0..8].copy_from_slice(&2u64.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(ZPTR_VADDR, ZPTR_PADDR, flags::WRITABLE)
            .write_phys(ZPTR_PADDR, &ptr_data)
            .map_4k(ZSIZE_VADDR, ZSIZE_PADDR, flags::WRITABLE)
            .write_phys(ZSIZE_PADDR, &size_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let entries = walk_pool_tags(&reader).unwrap();
        assert!(entries.is_empty(), "zero table_addr should return empty");
    }

    /// PoolTrackTable symbol present but PoolTrackTableSize symbol absent → empty.
    #[test]
    fn walk_pool_tags_no_size_symbol_empty() {
        const NPTR_VADDR: u64 = 0xFFFF_8000_0014_0000;
        const NPTR_PADDR: u64 = 0x0087_0000;

        let isf = IsfBuilder::new()
            .add_struct("_POOL_TRACKER_TABLE", 40)
            .add_field("_POOL_TRACKER_TABLE", "Key", 0, "unsigned int")
            .add_field("_POOL_TRACKER_TABLE", "PoolType", 4, "unsigned int")
            .add_field(
                "_POOL_TRACKER_TABLE",
                "PagedAllocs",
                8,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "PagedFrees",
                16,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "PagedBytes",
                24,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "NonPagedAllocs",
                8,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "NonPagedFrees",
                16,
                "unsigned long long",
            )
            .add_field(
                "_POOL_TRACKER_TABLE",
                "NonPagedBytes",
                24,
                "unsigned long long",
            )
            .add_symbol("PoolTrackTable", NPTR_VADDR)
            // intentionally no PoolTrackTableSize symbol
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // table ptr page: non-zero pointer so we pass the zero-ptr check
        let mut ptr_data = vec![0u8; 4096];
        ptr_data[0..8].copy_from_slice(&0xFFFF_8000_0015_0000u64.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(NPTR_VADDR, NPTR_PADDR, flags::WRITABLE)
            .write_phys(NPTR_PADDR, &ptr_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let entries = walk_pool_tags(&reader).unwrap();
        assert!(
            entries.is_empty(),
            "absent PoolTrackTableSize symbol → empty"
        );
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
