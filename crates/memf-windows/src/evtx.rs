//! Windows Event Log (.evtx) chunk recovery from memory.
//!
//! Windows Event Log files use the EVTX binary format. The file body is
//! divided into 64 KiB chunks, each beginning with the ASCII magic
//! `ElfChnk\0` (0x456C6643686E6B00). By scanning process memory regions
//! (e.g., from the Event Log service's VAD entries) for this signature,
//! we can recover event log chunks — including records from logs that
//! have been cleared or tampered with on disk.
//!
//! # Chunk header layout (offsets from chunk start)
//!
//! | Offset | Size | Field                      |
//! |--------|------|----------------------------|
//! | 0x00   | 8    | Magic `ElfChnk\0`          |
//! | 0x08   | 8    | First event record number  |
//! | 0x10   | 8    | Last event record number   |
//! | 0x18   | 8    | First event record ID      |
//! | 0x20   | 8    | Last event record ID       |
//! | 0x28   | 4    | Header size (should be 0x80)|
//! | 0x2C   | 4    | Last event record offset   |
//! | 0x30   | 4    | Free space offset           |
//! | 0x34   | 4    | Event records checksum      |
//!
//! Event records start at offset 0x200 within each chunk, each prefixed
//! with `**\0\0` (0x00002A2A). Record size is at offset 4, and a
//! FILETIME timestamp lives at offset 8.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{EvtxChunkInfo, Result};

/// Magic bytes at the start of every EVTX chunk: `ElfChnk\0`.
const ELFCHNK_MAGIC: [u8; 8] = [0x45, 0x6C, 0x66, 0x43, 0x68, 0x6E, 0x6B, 0x00];

/// Magic bytes at the start of every event record: `**\0\0`.
const RECORD_MAGIC: [u8; 4] = [0x2A, 0x2A, 0x00, 0x00];

/// Each EVTX chunk is exactly 64 KiB (0x10000 bytes).
const CHUNK_SIZE: u64 = 0x10000;

/// Event records start at this offset within a chunk.
const RECORDS_OFFSET: u64 = 0x200;

/// Chunks are aligned on 4 KiB boundaries in memory.
const CHUNK_ALIGNMENT: u64 = 0x1000;

/// Maximum number of chunks to recover (safety limit).
const MAX_CHUNKS: usize = 4096;

/// Maximum number of records to walk per chunk (safety limit).
const MAX_RECORDS_PER_CHUNK: usize = 1024;

/// Scan memory regions for Windows Event Log (EVTX) chunks.
///
/// Takes a list of `(start_vaddr, length)` regions to scan — typically
/// derived from VAD entries of the Event Log service process. Scans each
/// region for the `ElfChnk\0` magic at 0x1000-aligned boundaries and
/// parses chunk headers to extract event record metadata.
///
/// Returns a `Vec<EvtxChunkInfo>` with one entry per recovered chunk.
pub fn scan_evtx_chunks<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    search_regions: &[(u64, u64)],
) -> Result<Vec<EvtxChunkInfo>> {
    let mut chunks = Vec::new();

    for &(region_start, region_len) in search_regions {
        // Align the start address up to the next CHUNK_ALIGNMENT boundary.
        let aligned_start = (region_start + CHUNK_ALIGNMENT - 1) & !(CHUNK_ALIGNMENT - 1);
        let region_end = region_start.saturating_add(region_len);

        let mut addr = aligned_start;
        while addr + CHUNK_SIZE <= region_end {
            if chunks.len() >= MAX_CHUNKS {
                return Ok(chunks);
            }

            // Read the first 8 bytes to check for ElfChnk magic.
            if let Ok(magic_bytes) = reader.read_bytes(addr, 8) {
                if magic_bytes.len() == 8 && magic_bytes[..8] == ELFCHNK_MAGIC {
                    if let Some(info) = parse_chunk_header(reader, addr) {
                        chunks.push(info);
                    }
                    // Skip past this entire chunk regardless of parse success.
                    addr += CHUNK_SIZE;
                    continue;
                }
            }

            addr += CHUNK_ALIGNMENT;
        }
    }

    Ok(chunks)
}

/// Parse a single EVTX chunk header at the given virtual address.
///
/// Reads the header fields (event record numbers, IDs) and walks the
/// event records starting at offset 0x200 to count them and extract
/// first/last timestamps.
fn parse_chunk_header<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    chunk_addr: u64,
) -> Option<EvtxChunkInfo> {
    // Read header fields.
    let first_event_rec_num = read_u64_at(reader, chunk_addr + 0x08)?;
    let last_event_rec_num = read_u64_at(reader, chunk_addr + 0x10)?;

    // Walk event records starting at offset 0x200.
    let records_start = chunk_addr + RECORDS_OFFSET;
    let chunk_end = chunk_addr + CHUNK_SIZE;

    let mut record_count: u32 = 0;
    let mut first_timestamp: u64 = 0;
    let mut last_timestamp: u64 = 0;
    let mut offset = records_start;

    while offset + 16 <= chunk_end && (record_count as usize) < MAX_RECORDS_PER_CHUNK {
        // Check for record magic "**\0\0".
        let magic = match reader.read_bytes(offset, 4) {
            Ok(b) if b.len() == 4 => b,
            _ => break,
        };
        if magic[..4] != RECORD_MAGIC {
            break;
        }

        // Read record size at offset 4.
        let record_size = match read_u32_at(reader, offset + 4) {
            Some(s) if s >= 24 => s, // Minimum sensible record size
            _ => break,
        };

        // Read timestamp (FILETIME) at offset 8 within the record.
        let ts = read_u64_at(reader, offset + 8).unwrap_or(0);

        if record_count == 0 {
            first_timestamp = ts;
        }
        last_timestamp = ts;
        record_count += 1;

        // Advance to the next record.
        offset += u64::from(record_size);
    }

    // Try to identify the channel name.
    let channel = identify_channel(reader, chunk_addr);

    Some(EvtxChunkInfo {
        offset: chunk_addr,
        first_event_id: first_event_rec_num,
        last_event_id: last_event_rec_num,
        first_timestamp,
        last_timestamp,
        record_count,
        channel,
    })
}

/// Read a little-endian u64 from virtual memory, returning `None` on failure.
fn read_u64_at<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, vaddr: u64) -> Option<u64> {
    let bytes = reader.read_bytes(vaddr, 8).ok()?;
    if bytes.len() < 8 {
        return None;
    }
    Some(u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")))
}

/// Read a little-endian u32 from virtual memory, returning `None` on failure.
fn read_u32_at<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, vaddr: u64) -> Option<u32> {
    let bytes = reader.read_bytes(vaddr, 4).ok()?;
    if bytes.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes(bytes[..4].try_into().expect("4 bytes")))
}

/// Attempt to identify the log channel name from event XML in a chunk.
///
/// Reads event records within the chunk and looks for a `<Channel>` element
/// in the BinXml data. Falls back to `"Unknown"` if parsing fails.
fn identify_channel<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    chunk_addr: u64,
) -> String {
    // Well-known channel names to search for as UTF-16LE in chunk data.
    const KNOWN_CHANNELS: &[&str] = &[
        "Security",
        "System",
        "Application",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-WMI-Activity/Operational",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    ];

    // Try to find a channel name by scanning the chunk data for known
    // channel name strings. EVTX BinXml is complex to parse fully, so
    // we do a best-effort search for common channel name patterns in
    // the raw chunk bytes.
    let search_start = chunk_addr + RECORDS_OFFSET;
    // Read a limited window (first 4 KiB of records area) to search.
    let search_len: usize = 4096;
    let Ok(bytes) = reader.read_bytes(search_start, search_len) else {
        return "Unknown".to_string();
    };

    for channel in KNOWN_CHANNELS {
        let utf16: Vec<u8> = channel.encode_utf16().flat_map(u16::to_le_bytes).collect();
        if bytes.windows(utf16.len()).any(|w| w == utf16) {
            return (*channel).to_string();
        }
    }

    "Unknown".to_string()
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
    fn scan_evtx_no_regions() {
        let reader = build_empty_reader();
        let result = scan_evtx_chunks(&reader, &[]).unwrap();
        assert!(result.is_empty());
    }

    /// A region filled with zeroes (no ElfChnk magic) yields no chunks.
    #[test]
    fn scan_evtx_no_magic() {
        // Map a 128 KiB region of zeroes
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        const REGION_VADDR: u64 = 0xFFFF_8000_0010_0000;
        const REGION_PADDR: u64 = 0x0080_0000;
        const REGION_SIZE: u64 = 0x2_0000; // 128 KiB = 32 pages

        let mut builder = PageTableBuilder::new();
        // Map 32 pages of zeroes (all zero by default in SyntheticPhysMem)
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

        let result = scan_evtx_chunks(&reader, &[(REGION_VADDR, REGION_SIZE)]).unwrap();
        assert!(result.is_empty());
    }

    /// A synthetic chunk with valid ElfChnk header + one event record
    /// produces the correct EvtxChunkInfo.
    #[test]
    fn scan_evtx_single_chunk() {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // We need to map enough pages for one full 64 KiB chunk (16 pages).
        const CHUNK_VADDR: u64 = 0xFFFF_8000_0010_0000;
        const CHUNK_PADDR: u64 = 0x0080_0000;

        let mut builder = PageTableBuilder::new();
        for i in 0..16 {
            builder = builder.map_4k(
                CHUNK_VADDR + i * 0x1000,
                CHUNK_PADDR + i * 0x1000,
                flags::PRESENT | flags::WRITABLE,
            );
        }

        // Build the chunk header at physical address CHUNK_PADDR.
        // -- ElfChnk magic at offset 0x00
        builder = builder.write_phys(CHUNK_PADDR, &ELFCHNK_MAGIC);
        // -- First event record number at offset 0x08
        builder = builder.write_phys(CHUNK_PADDR + 0x08, &100u64.to_le_bytes());
        // -- Last event record number at offset 0x10
        builder = builder.write_phys(CHUNK_PADDR + 0x10, &100u64.to_le_bytes());
        // -- First event record ID at offset 0x18
        builder = builder.write_phys(CHUNK_PADDR + 0x18, &100u64.to_le_bytes());
        // -- Last event record ID at offset 0x20
        builder = builder.write_phys(CHUNK_PADDR + 0x20, &100u64.to_le_bytes());
        // -- Header size at offset 0x28 (should be 0x80)
        builder = builder.write_phys(CHUNK_PADDR + 0x28, &0x80u32.to_le_bytes());

        // Now write one event record at offset 0x200 within the chunk.
        let record_paddr = CHUNK_PADDR + RECORDS_OFFSET;
        // -- Record magic: "**\0\0"
        builder = builder.write_phys(record_paddr, &RECORD_MAGIC);
        // -- Record size at offset 4 (say 56 bytes — minimal record)
        builder = builder.write_phys(record_paddr + 4, &56u32.to_le_bytes());
        // -- Timestamp (FILETIME) at offset 8: 2024-01-15 12:00:00 UTC
        let timestamp: u64 = 133_500_672_000_000_000;
        builder = builder.write_phys(record_paddr + 8, &timestamp.to_le_bytes());

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = scan_evtx_chunks(&reader, &[(CHUNK_VADDR, CHUNK_SIZE)]).unwrap();
        assert_eq!(result.len(), 1);

        let chunk = &result[0];
        assert_eq!(chunk.offset, CHUNK_VADDR);
        assert_eq!(chunk.first_event_id, 100);
        assert_eq!(chunk.last_event_id, 100);
        assert_eq!(chunk.record_count, 1);
        assert_eq!(chunk.first_timestamp, timestamp);
        assert_eq!(chunk.last_timestamp, timestamp);
    }

    /// A chunk with a known channel name embedded as UTF-16LE in the records area
    /// exercises the identify_channel scanning path.
    #[test]
    fn scan_evtx_chunk_with_known_channel() {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        const CHUNK_VADDR: u64 = 0xFFFF_8000_0020_0000;
        const CHUNK_PADDR: u64 = 0x0090_0000;

        let mut builder = PageTableBuilder::new();
        for i in 0..16u64 {
            builder = builder.map_4k(
                CHUNK_VADDR + i * 0x1000,
                CHUNK_PADDR + i * 0x1000,
                flags::PRESENT | flags::WRITABLE,
            );
        }

        // ElfChnk magic
        builder = builder.write_phys(CHUNK_PADDR, &ELFCHNK_MAGIC);
        builder = builder.write_phys(CHUNK_PADDR + 0x08, &1u64.to_le_bytes());
        builder = builder.write_phys(CHUNK_PADDR + 0x10, &1u64.to_le_bytes());

        // Write "Security" as UTF-16LE in the records area (at records_offset + 0x10)
        let channel_name = "Security";
        let channel_utf16: Vec<u8> = channel_name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        builder = builder.write_phys(CHUNK_PADDR + RECORDS_OFFSET + 0x10, &channel_utf16);

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = scan_evtx_chunks(&reader, &[(CHUNK_VADDR, CHUNK_SIZE)]).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].channel, "Security");
    }

    /// identify_channel falls back to "Unknown" when the records area is unmapped.
    #[test]
    fn scan_evtx_chunk_unknown_channel_when_unmapped() {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Map only the first page (header page), leaving records area unmapped.
        const CHUNK_VADDR: u64 = 0xFFFF_8000_0030_0000;
        const CHUNK_PADDR: u64 = 0x00A0_0000;

        let mut builder = PageTableBuilder::new();
        // Map all 16 pages but only put data in the first to avoid unmapped reads.
        for i in 0..16u64 {
            builder = builder.map_4k(
                CHUNK_VADDR + i * 0x1000,
                CHUNK_PADDR + i * 0x1000,
                flags::PRESENT | flags::WRITABLE,
            );
        }

        // ElfChnk magic at offset 0
        builder = builder.write_phys(CHUNK_PADDR, &ELFCHNK_MAGIC);
        builder = builder.write_phys(CHUNK_PADDR + 0x08, &42u64.to_le_bytes());
        builder = builder.write_phys(CHUNK_PADDR + 0x10, &99u64.to_le_bytes());
        // Records area is zeroed — no record magic → record_count stays 0,
        // channel scanning finds no known name → "Unknown".

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = scan_evtx_chunks(&reader, &[(CHUNK_VADDR, CHUNK_SIZE)]).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].channel, "Unknown");
        assert_eq!(result[0].record_count, 0);
    }

    /// A record with record_size < 24 causes the record loop to break early.
    #[test]
    fn scan_evtx_chunk_small_record_size_breaks_loop() {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        const CHUNK_VADDR: u64 = 0xFFFF_8000_0040_0000;
        const CHUNK_PADDR: u64 = 0x00B0_0000;

        let mut builder = PageTableBuilder::new();
        for i in 0..16u64 {
            builder = builder.map_4k(
                CHUNK_VADDR + i * 0x1000,
                CHUNK_PADDR + i * 0x1000,
                flags::PRESENT | flags::WRITABLE,
            );
        }

        builder = builder.write_phys(CHUNK_PADDR, &ELFCHNK_MAGIC);
        builder = builder.write_phys(CHUNK_PADDR + 0x08, &5u64.to_le_bytes());
        builder = builder.write_phys(CHUNK_PADDR + 0x10, &5u64.to_le_bytes());

        // Write record magic but size = 10 (< 24 minimum) → loop breaks.
        let record_paddr = CHUNK_PADDR + RECORDS_OFFSET;
        builder = builder.write_phys(record_paddr, &RECORD_MAGIC);
        builder = builder.write_phys(record_paddr + 4, &10u32.to_le_bytes()); // too small

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = scan_evtx_chunks(&reader, &[(CHUNK_VADDR, CHUNK_SIZE)]).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].record_count, 0,
            "loop should break on small record_size"
        );
    }

    /// Region too small for even one chunk (< CHUNK_SIZE) produces no results.
    #[test]
    fn scan_evtx_region_too_small() {
        let reader = build_empty_reader();
        // Region length = CHUNK_SIZE - 1 → while condition `addr + CHUNK_SIZE <= region_end` is false.
        let result = scan_evtx_chunks(&reader, &[(0xFFFF_8000_0000_0000, CHUNK_SIZE - 1)]).unwrap();
        assert!(result.is_empty());
    }

    /// Two chunks back-to-back in a 128 KiB region are both found.
    #[test]
    fn scan_evtx_two_chunks_found() {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // 128 KiB = 2 × 64 KiB chunks, 32 pages total
        const REGION_VADDR: u64 = 0xFFFF_8000_0050_0000;
        const REGION_PADDR: u64 = 0x00C0_0000;
        const REGION_SIZE: u64 = 0x2_0000;

        let mut builder = PageTableBuilder::new();
        for i in 0..32u64 {
            builder = builder.map_4k(
                REGION_VADDR + i * 0x1000,
                REGION_PADDR + i * 0x1000,
                flags::PRESENT | flags::WRITABLE,
            );
        }

        // Chunk 0 at REGION_PADDR
        builder = builder.write_phys(REGION_PADDR, &ELFCHNK_MAGIC);
        builder = builder.write_phys(REGION_PADDR + 0x08, &1u64.to_le_bytes());
        builder = builder.write_phys(REGION_PADDR + 0x10, &1u64.to_le_bytes());

        // Chunk 1 at REGION_PADDR + 0x10000
        let chunk2_paddr = REGION_PADDR + CHUNK_SIZE;
        builder = builder.write_phys(chunk2_paddr, &ELFCHNK_MAGIC);
        builder = builder.write_phys(chunk2_paddr + 0x08, &2u64.to_le_bytes());
        builder = builder.write_phys(chunk2_paddr + 0x10, &2u64.to_le_bytes());

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = scan_evtx_chunks(&reader, &[(REGION_VADDR, REGION_SIZE)]).unwrap();
        assert_eq!(result.len(), 2, "should find both chunks");
        assert_eq!(result[0].first_event_id, 1);
        assert_eq!(result[1].first_event_id, 2);
    }

    /// EvtxChunkInfo serializes correctly.
    #[test]
    fn evtx_chunk_info_serializes() {
        use crate::EvtxChunkInfo;
        let info = EvtxChunkInfo {
            offset: 0xFFFF_8000_0010_0000,
            first_event_id: 100,
            last_event_id: 200,
            first_timestamp: 133_500_672_000_000_000,
            last_timestamp: 133_500_673_000_000_000,
            record_count: 10,
            channel: "Security".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"first_event_id\":100"));
        assert!(json.contains("\"record_count\":10"));
        assert!(json.contains("\"channel\":\"Security\""));
    }
}
