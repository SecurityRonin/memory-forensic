//! Windows Prefetch file metadata extraction from process memory.
//!
//! Prefetch files (.pf) record application execution history and are
//! critical forensic artifacts. This module performs the **memory-specific**
//! work: scanning physical/virtual regions for a decompressed prefetch payload
//! at page boundaries by its `SCCA` signature (`53 43 43 41` at byte offset 4
//! of the SCCA header, version-independent).
//!
//! Once a candidate is located, the surrounding bytes are carved and the SCCA
//! field parsing is delegated to the [`prefetch_core`] crate
//! ([`prefetch_core::parse_decompressed`]), which handles SCCA v30/v31, the
//! shifted Win10 run-count layout, and the MAM/Xpress-Huffman container —
//! coverage memf's former hand-rolled subset lacked.

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

/// Scan on 4 KiB page boundaries.
const SCAN_ALIGNMENT: u64 = 0x1000;

/// Maximum number of Prefetch entries to recover (safety limit).
const MAX_ENTRIES: usize = 4096;

/// Offset of the path hash field within the SCCA header. `prefetch-core` does
/// not surface this value, so memf carves it directly to keep its public
/// [`PrefetchInfo::hash`] field populated.
const HASH_OFFSET: usize = 0x4C;

/// Smallest in-memory window worth handing to the parser: the SCCA signature
/// sits at byte 4 and `parse_decompressed` needs at least the 84-byte header
/// plus the `FileInformation` block. We carve more than this so volume and
/// filename blocks resolve, but never less.
const MIN_CARVE: usize = 0x100;

/// Largest in-memory window carved per candidate before handing it to the
/// parser. A decompressed SCCA payload with its volume/filename blocks fits
/// comfortably below this; the cap bounds the read against a runaway region.
const MAX_CARVE: usize = 0x4_0000;

/// Scan memory regions for in-memory Windows Prefetch (SCCA) structures.
///
/// Takes a list of `(start_vaddr, length)` regions to scan. At each page
/// boundary it checks for the `SCCA` signature (the structural invariant of a
/// decompressed prefetch payload, version-independent), carves the surrounding
/// bytes, and delegates field parsing to [`prefetch_core::parse_decompressed`]
/// — which handles SCCA v30/v31 (and the shifted run-count layout) that memf's
/// former hand-rolled subset could not.
///
/// Returns a `Vec<PrefetchInfo>` with one entry per recovered prefetch payload.
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
        while addr + MIN_CARVE as u64 <= region_end {
            if entries.len() >= MAX_ENTRIES {
                return Ok(entries);
            }

            // The SCCA signature lives at byte 4: `[u32 version][b"SCCA"]`.
            let sig_addr = addr + prefetch_core::SCCA_SIGNATURE_OFFSET as u64;
            if let Ok(sig) = reader.read_bytes(sig_addr, prefetch_core::SCCA_SIGNATURE.len()) {
                if sig == prefetch_core::SCCA_SIGNATURE {
                    if let Some(info) = parse_prefetch_at(reader, addr, region_end) {
                        entries.push(info);
                    }
                }
            }

            addr += SCAN_ALIGNMENT;
        }
    }

    Ok(entries)
}

/// Carve a candidate SCCA payload at `addr` and parse it via `prefetch-core`.
///
/// The carve window grows up to [`MAX_CARVE`] (bounded by `region_end`) so the
/// volume/filename blocks resolve; if those trailing pages are unmapped the
/// read shrinks to the header so a valid header still parses. Returns `None`
/// when nothing maps, the version is unsupported, or the payload is malformed —
/// a per-candidate miss, not a hard error.
fn parse_prefetch_at<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    addr: u64,
    region_end: u64,
) -> Option<PrefetchInfo> {
    let available = region_end.saturating_sub(addr).min(MAX_CARVE as u64) as usize;
    if available < MIN_CARVE {
        return None;
    }

    // Prefer the widest mapped window; fall back to the header if the trailing
    // pages of the candidate are not present.
    let bytes = read_widest(reader, addr, available)?;

    let info = prefetch_core::parse_decompressed(&bytes).ok()?;
    if info.executable.is_empty() {
        return None;
    }

    // `prefetch-core` does not expose the path hash; carve it from the header.
    let hash = bytes
        .get(HASH_OFFSET..HASH_OFFSET + 4)
        .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));

    Some(PrefetchInfo {
        offset: addr,
        executable_name: info.executable,
        hash,
        run_count: info.run_count,
        last_run_time: info.last_run_times.first().copied().unwrap_or(0) as u64,
    })
}

/// Read the widest mapped window at `addr`, shrinking from `available` toward
/// [`MIN_CARVE`] when trailing pages are unmapped. Returns `None` only if even
/// the minimum window cannot be read.
fn read_widest<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    addr: u64,
    available: usize,
) -> Option<Vec<u8>> {
    let mut len = available;
    loop {
        if let Ok(bytes) = reader.read_bytes(addr, len) {
            return Some(bytes);
        }
        if len <= MIN_CARVE {
            return None;
        }
        len = (len / 2).max(MIN_CARVE);
    }
}

#[cfg(test)]
mod tests {
    // Test fixtures declare layout consts/helpers beside the statements that use
    // them to keep each byte-plan readable; that ordering is intentional here.
    #![allow(clippy::items_after_statements)]
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

    /// SCCA `FileInformation` block starts right after the 84-byte header
    /// (mirrors `prefetch_core`'s constant; redeclared here for the fixtures).
    const FILE_INFO_OFFSET: usize = 84;

    /// Build a minimal valid SCCA **v30** payload that `prefetch_core` parses:
    /// the version/signature header, the executable name, the path hash at
    /// `0x4C` (which memf carves itself), one run time, and the run count in the
    /// pre-shift Win10 slot (`FileInfo+124`).
    fn build_v30_scca(exe: &str, hash: u32, run_count: u32, run_time: i64) -> Vec<u8> {
        let mut p = vec![0u8; FILE_INFO_OFFSET + 224];
        p[0..4].copy_from_slice(&30u32.to_le_bytes());
        p[4..8].copy_from_slice(b"SCCA");
        for (i, u) in exe.encode_utf16().enumerate() {
            p[16 + i * 2..16 + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        p[0x4C..0x50].copy_from_slice(&hash.to_le_bytes());
        let fi = FILE_INFO_OFFSET;
        p[fi + 44..fi + 52].copy_from_slice(&run_time.to_le_bytes());
        // fi+120 stays zero → count read from fi+124 (pre-shift layout).
        p[fi + 124..fi + 128].copy_from_slice(&run_count.to_le_bytes());
        p
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

    /// A synthetic SCCA v30 payload produces the correct PrefetchInfo via the
    /// delegated `prefetch_core` parse.
    #[test]
    fn scan_prefetch_single_entry() {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

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

        let expected_hash: u32 = 0xDEAD_BEEF;
        let expected_last_run: i64 = 133_500_672_000_000_000;
        let expected_run_count: u32 = 42;
        let scca = build_v30_scca(
            "NOTEPAD.EXE",
            expected_hash,
            expected_run_count,
            expected_last_run,
        );
        builder = builder.write_phys(PF_PADDR, &scca);

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
        assert_eq!(pf.last_run_time, expected_last_run as u64);
    }

    /// scan_prefetch with a region too small (< MIN_CARVE) skips it entirely.
    #[test]
    fn scan_prefetch_region_too_small() {
        let reader = build_empty_reader();
        // MIN_CARVE is 0x100 = 256 bytes; a region of 100 bytes is too small.
        let result = scan_prefetch(&reader, &[(0xFFFF_8000_0000_0000, 100)]).unwrap();
        assert!(result.is_empty());
    }

    /// scan_prefetch: a valid v30 SCCA whose executable name is all-null →
    /// parse yields an empty executable, which is dropped (no entry).
    #[test]
    fn scan_prefetch_empty_exe_name_skipped() {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        const PF_VADDR: u64 = 0xFFFF_8000_0020_0000;
        const PF_PADDR: u64 = 0x0090_0000;
        const REGION_SIZE: u64 = 0x4000;

        let mut builder = PageTableBuilder::new();
        for i in 0..4u64 {
            builder = builder.map_4k(
                PF_VADDR + i * 0x1000,
                PF_PADDR + i * 0x1000,
                flags::PRESENT | flags::WRITABLE,
            );
        }

        // Valid v30 header (version + SCCA signature) but the exe-name field
        // stays all-zero → empty executable → dropped.
        let scca = build_v30_scca("", 0, 0, 0);
        builder = builder.write_phys(PF_PADDR, &scca);

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = scan_prefetch(&reader, &[(PF_VADDR, REGION_SIZE)]).unwrap();
        assert!(
            result.is_empty(),
            "empty exe name should not produce an entry"
        );
    }

    /// scan_prefetch: two adjacent prefetch headers at different page boundaries are both found.
    #[test]
    fn scan_prefetch_two_entries_found() {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Map 8 pages = 32 KiB; place a prefetch header at page 0 and page 4.
        const REGION_VADDR: u64 = 0xFFFF_8000_0030_0000;
        const REGION_PADDR: u64 = 0x00A0_0000;
        const REGION_SIZE: u64 = 0x8000; // 32 KiB

        let mut builder = PageTableBuilder::new();
        for i in 0..8u64 {
            builder = builder.map_4k(
                REGION_VADDR + i * 0x1000,
                REGION_PADDR + i * 0x1000,
                flags::PRESENT | flags::WRITABLE,
            );
        }

        // Helper: write a full v30 SCCA payload at a given physical offset.
        let write_pf = |b: PageTableBuilder, base_paddr: u64, exe: &str, hash: u32| {
            let scca = build_v30_scca(exe, hash, 1, 0);
            b.write_phys(base_paddr, &scca)
        };

        builder = write_pf(builder, REGION_PADDR, "CMD.EXE", 0xAAAA_AAAA);
        builder = write_pf(builder, REGION_PADDR + 0x4000, "SVCHOST.EXE", 0xBBBB_BBBB);

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = scan_prefetch(&reader, &[(REGION_VADDR, REGION_SIZE)]).unwrap();
        assert_eq!(result.len(), 2, "should find both prefetch entries");
        assert_eq!(result[0].executable_name, "CMD.EXE");
        assert_eq!(result[1].executable_name, "SVCHOST.EXE");
    }

    /// PrefetchInfo serializes correctly.
    #[test]
    fn prefetch_info_serializes() {
        let info = PrefetchInfo {
            offset: 0xFFFF_8000_0010_0000,
            executable_name: "NOTEPAD.EXE".to_string(),
            hash: 0xDEAD_BEEF,
            run_count: 7,
            last_run_time: 133_500_672_000_000_000,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("NOTEPAD.EXE"));
        assert!(json.contains("\"run_count\":7"));
        assert!(json.contains("\"hash\":3735928559")); // 0xDEAD_BEEF decimal
    }

    /// Build a minimal valid SCCA v30 payload that exercises the
    /// `prefetch-core` parsing contract's *shifted* run-count layout
    /// (`FileInfo+120` non-zero → count lives at `FileInfo+116`, not
    /// `FileInfo+124`). The old hand-rolled parser, which always read the run
    /// count at a fixed `0xD0` (== `FileInfo+124`), gets the shifted count
    /// wrong — so this fixture only passes once the parsing is delegated to
    /// `prefetch_core::parse_decompressed`.
    fn build_v30_scca_shifted_run_count(exe: &str, run_count: u32, run_time: i64) -> Vec<u8> {
        let mut p = vec![0u8; FILE_INFO_OFFSET + 224];
        p[0..4].copy_from_slice(&30u32.to_le_bytes());
        p[4..8].copy_from_slice(b"SCCA");
        // Executable name: UTF-16LE, 60-byte field at offset 16.
        for (i, u) in exe.encode_utf16().enumerate() {
            p[16 + i * 2..16 + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        let fi = FILE_INFO_OFFSET;
        // First of the eight FILETIME slots at fi+44.
        p[fi + 44..fi + 52].copy_from_slice(&run_time.to_le_bytes());
        // Shifted layout: fi+120 non-zero selects the count at fi+116.
        p[fi + 120..fi + 124].copy_from_slice(&1u32.to_le_bytes());
        p[fi + 116..fi + 120].copy_from_slice(&run_count.to_le_bytes());
        p
    }

    /// The heap scan carves the SCCA bytes and delegates field parsing to
    /// `prefetch_core::parse_decompressed`, so a v30 header with the shifted
    /// run-count layout is parsed correctly.
    #[test]
    fn scan_prefetch_delegates_to_prefetch_core() {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        const PF_VADDR: u64 = 0xFFFF_8000_0040_0000;
        const PF_PADDR: u64 = 0x00B0_0000;
        const REGION_SIZE: u64 = 0x4000;

        let scca = build_v30_scca_shifted_run_count("EXPLORER.EXE", 9, 1000);

        let mut builder = PageTableBuilder::new();
        for i in 0..4u64 {
            builder = builder.map_4k(
                PF_VADDR + i * 0x1000,
                PF_PADDR + i * 0x1000,
                flags::PRESENT | flags::WRITABLE,
            );
        }
        builder = builder.write_phys(PF_PADDR, &scca);

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = scan_prefetch(&reader, &[(PF_VADDR, REGION_SIZE)]).unwrap();
        assert_eq!(result.len(), 1, "expected exactly one Prefetch entry");
        let pf = &result[0];
        assert_eq!(pf.offset, PF_VADDR);
        assert_eq!(pf.executable_name, "EXPLORER.EXE");
        assert_eq!(
            pf.run_count, 9,
            "shifted run-count must come from FileInfo+116"
        );
        assert_eq!(pf.last_run_time, 1000);
    }
}
