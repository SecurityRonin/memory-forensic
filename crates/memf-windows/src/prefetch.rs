//! Windows Prefetch file metadata extraction from process memory.
//!
//! Prefetch files (.pf) record application execution history and are
//! critical forensic artifacts. This module scans memory regions for
//! Prefetch file signatures to extract execution evidence.
//!
//! # Prefetch v30 header layout (Windows 10+)
//!
//! | Offset | Size | Field                          |
//! |--------|------|--------------------------------|
//! | 0x00   | 4    | Version (0x1A = 26 for v30)    |
//! | 0x04   | 4    | Signature "SCCA"               |
//! | 0x08   | 4    | Unknown                        |
//! | 0x0C   | 4    | File size                      |
//! | 0x10   | 60   | Executable name (UTF-16LE, 30 wchars) |
//! | 0x4C   | 4    | Prefetch path hash             |
//! | 0x50   | 4    | Unknown (flags)                |
//!
//! For v30 (compressed MAM format), the outer header contains:
//! | 0x00   | 4    | MAM signature (0x044D414D)     |
//! | 0x04   | 4    | Uncompressed size              |
//! | 0x08   | ...  | Compressed data (SCCA inside)  |
//!
//! We scan for the raw SCCA signature which appears either at offset 0
//! of uncompressed prefetch files or within decompressed regions in memory.
//!
//! The 8-byte magic we scan for: `1A 00 00 00 53 43 43 41`
//! (version u32 LE = 0x1A, then ASCII "SCCA").

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Metadata extracted from a Prefetch file header found in memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PrefetchInfo {
    /// Virtual address where the Prefetch header was found.
    pub offset: u64,
    /// Name of the prefetched executable (from the header).
    pub executable_name: String,
    /// Prefetch path hash.
    pub hash: u32,
    /// Number of times the application was executed.
    pub run_count: u32,
    /// FILETIME of the last execution.
    pub last_run_time: u64,
}

/// Prefetch v30 magic: version 0x1A (26) as u32 LE, followed by "SCCA".
const PREFETCH_MAGIC: [u8; 8] = [0x1A, 0x00, 0x00, 0x00, 0x53, 0x43, 0x43, 0x41];

/// Scan on 4 KiB page boundaries.
const SCAN_ALIGNMENT: u64 = 0x1000;

/// Minimum size needed to parse a Prefetch v30 header.
/// We need at least through the run count and last-run-time fields.
const MIN_HEADER_SIZE: usize = 0xA0;

/// Maximum number of Prefetch entries to recover (safety limit).
const MAX_ENTRIES: usize = 4096;

/// Offset of the executable name field (UTF-16LE, 30 wchars = 60 bytes).
const EXE_NAME_OFFSET: usize = 0x10;
/// Length of the executable name field in bytes (30 wchars * 2).
const EXE_NAME_LEN: usize = 60;

/// Offset of the path hash field.
const HASH_OFFSET: usize = 0x4C;

/// Offset of the run count field in v30 (Windows 10).
const RUN_COUNT_OFFSET: usize = 0xD0;

/// Offset of the last run time field (FILETIME) in v30 (Windows 10).
const LAST_RUN_TIME_OFFSET: usize = 0x80;

/// Minimum Prefetch header + execution data size for v30.
const MIN_PARSE_SIZE: usize = 0xD4;

/// Scan memory regions for Windows Prefetch file headers (version 30).
///
/// Takes a list of `(start_vaddr, length)` regions to scan. Scans each
/// region for the Prefetch v30 magic bytes (`1A 00 00 00 53 43 43 41`)
/// at page-aligned boundaries and parses headers to extract execution
/// metadata.
///
/// Returns a `Vec<PrefetchInfo>` with one entry per recovered Prefetch header.
pub fn scan_prefetch<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    search_regions: &[(u64, u64)],
) -> Result<Vec<PrefetchInfo>> {
    let mut entries = Vec::new();

    for &(region_start, region_len) in search_regions {
        // Align the start address up to the next page boundary.
        let aligned_start = (region_start + SCAN_ALIGNMENT - 1) & !(SCAN_ALIGNMENT - 1);
        let region_end = region_start.saturating_add(region_len);

        let mut addr = aligned_start;
        while addr + MIN_PARSE_SIZE as u64 <= region_end {
            if entries.len() >= MAX_ENTRIES {
                return Ok(entries);
            }

            // Read the first 8 bytes to check for the Prefetch v30 magic.
            if let Ok(magic_bytes) = reader.read_bytes(addr, 8) {
                if magic_bytes.len() == 8 && magic_bytes[..8] == PREFETCH_MAGIC {
                    if let Some(info) = parse_prefetch_header(reader, addr) {
                        entries.push(info);
                    }
                }
            }

            addr += SCAN_ALIGNMENT;
        }
    }

    Ok(entries)
}

/// Parse a single Prefetch v30 header at the given virtual address.
///
/// Reads the executable name (UTF-16LE at offset 0x10), path hash
/// (u32 at offset 0x4C), last run time (FILETIME at offset 0x80),
/// and run count (u32 at offset 0xD0).
fn parse_prefetch_header<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    addr: u64,
) -> Option<PrefetchInfo> {
    // Read the executable name (UTF-16LE, 30 wchars = 60 bytes).
    let name_bytes = reader.read_bytes(addr + EXE_NAME_OFFSET as u64, EXE_NAME_LEN).ok()?;
    if name_bytes.len() < EXE_NAME_LEN {
        return None;
    }
    let executable_name = utf16le_to_string(&name_bytes);
    if executable_name.is_empty() {
        return None;
    }

    // Read the path hash.
    let hash = read_u32_at(reader, addr + HASH_OFFSET as u64)?;

    // Read the last run time (FILETIME).
    let last_run_time = read_u64_at(reader, addr + LAST_RUN_TIME_OFFSET as u64).unwrap_or(0);

    // Read the run count.
    let run_count = read_u32_at(reader, addr + RUN_COUNT_OFFSET as u64).unwrap_or(0);

    Some(PrefetchInfo {
        offset: addr,
        executable_name,
        hash,
        run_count,
        last_run_time,
    })
}

/// Read a little-endian u32 from virtual memory, returning `None` on failure.
fn read_u32_at<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, vaddr: u64) -> Option<u32> {
    let bytes = reader.read_bytes(vaddr, 4).ok()?;
    if bytes.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes(bytes[..4].try_into().expect("4 bytes")))
}

/// Read a little-endian u64 from virtual memory, returning `None` on failure.
fn read_u64_at<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, vaddr: u64) -> Option<u64> {
    let bytes = reader.read_bytes(vaddr, 8).ok()?;
    if bytes.len() < 8 {
        return None;
    }
    Some(u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")))
}

/// Extract a UTF-16LE string from raw bytes, trimming null terminators.
fn utf16le_to_string(bytes: &[u8]) -> String {
    let u16s: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&ch| ch != 0)
        .collect();
    String::from_utf16_lossy(&u16s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Helper: build a minimal ObjectReader with no special symbols.
    fn build_empty_reader() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// Empty regions list produces an empty result — not an error.
    #[test]
    fn scan_prefetch_no_regions() {
        let reader = build_empty_reader();
        let result = scan_prefetch(&reader, &[]).unwrap();
        assert!(result.is_empty());
    }

    /// A region filled with zeroes (no Prefetch magic) yields no entries.
    #[test]
    fn scan_prefetch_no_magic() {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        const REGION_VADDR: u64 = 0xFFFF_8000_0010_0000;
        const REGION_PADDR: u64 = 0x0080_0000;
        const REGION_SIZE: u64 = 0x2_0000; // 128 KiB = 32 pages

        let mut builder = PageTableBuilder::new();
        for i in 0..32 {
            builder = builder.map_4k(
                REGION_VADDR + i * 0x1000,
                REGION_PADDR + i * 0x1000,
                flags::PRESENT | flags::WRITABLE,
            );
        }
        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = scan_prefetch(&reader, &[(REGION_VADDR, REGION_SIZE)]).unwrap();
        assert!(result.is_empty());
    }

    /// A synthetic Prefetch v30 header produces the correct PrefetchInfo.
    #[test]
    fn scan_prefetch_single_entry() {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // We need enough pages for the Prefetch header (1 page is enough
        // since MIN_PARSE_SIZE < 0x1000, but map a few for the region).
        const PF_VADDR: u64 = 0xFFFF_8000_0010_0000;
        const PF_PADDR: u64 = 0x0080_0000;
        const REGION_SIZE: u64 = 0x4000; // 16 KiB = 4 pages

        let mut builder = PageTableBuilder::new();
        for i in 0..4 {
            builder = builder.map_4k(
                PF_VADDR + i * 0x1000,
                PF_PADDR + i * 0x1000,
                flags::PRESENT | flags::WRITABLE,
            );
        }

        // Write the Prefetch v30 magic at offset 0: version=0x1A, "SCCA"
        builder = builder.write_phys(PF_PADDR, &PREFETCH_MAGIC);

        // Write executable name at offset 0x10 as UTF-16LE: "NOTEPAD.EXE"
        let exe_name = "NOTEPAD.EXE";
        let exe_utf16: Vec<u8> = exe_name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        builder = builder.write_phys(PF_PADDR + EXE_NAME_OFFSET as u64, &exe_utf16);

        // Write path hash at offset 0x4C
        let expected_hash: u32 = 0xDEAD_BEEF;
        builder = builder.write_phys(PF_PADDR + HASH_OFFSET as u64, &expected_hash.to_le_bytes());

        // Write last run time (FILETIME) at offset 0x80: 2024-01-15 12:00:00 UTC
        let expected_last_run: u64 = 133_500_672_000_000_000;
        builder = builder.write_phys(
            PF_PADDR + LAST_RUN_TIME_OFFSET as u64,
            &expected_last_run.to_le_bytes(),
        );

        // Write run count at offset 0xD0
        let expected_run_count: u32 = 42;
        builder = builder.write_phys(
            PF_PADDR + RUN_COUNT_OFFSET as u64,
            &expected_run_count.to_le_bytes(),
        );

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = scan_prefetch(&reader, &[(PF_VADDR, REGION_SIZE)]).unwrap();
        assert_eq!(result.len(), 1, "expected exactly one Prefetch entry");

        let pf = &result[0];
        assert_eq!(pf.offset, PF_VADDR);
        assert_eq!(pf.executable_name, "NOTEPAD.EXE");
        assert_eq!(pf.hash, expected_hash);
        assert_eq!(pf.run_count, expected_run_count);
        assert_eq!(pf.last_run_time, expected_last_run);
    }
}
