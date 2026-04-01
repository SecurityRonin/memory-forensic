//! Kdump (makedumpfile / diskdump) format provider.
//!
//! Parses kdump files with `KDUMP   ` or `DISKDUMP` header signatures.
//! Uses lazy page decompression with an LRU cache for random-access reads.
//! Supports zlib (flate2), snappy (snap), zstd (ruzstd), and uncompressed pages.
//! LZO decompression is deferred with a clear error message.

use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Mutex;

use crate::{DumpMetadata, Error, FormatPlugin, PhysicalMemoryProvider, PhysicalRange, Result};

/// KDUMP signature: "KDUMP   " (8 bytes with 3 trailing spaces).
const KDUMP_SIG: &[u8; 8] = b"KDUMP   ";
/// DISKDUMP signature: "DISKDUMP" (8 bytes).
const DISKDUMP_SIG: &[u8; 8] = b"DISKDUMP";

/// Compression flag: zlib.
const COMPRESS_ZLIB: u32 = 0x01;
/// Compression flag: LZO.
const COMPRESS_LZO: u32 = 0x02;
/// Compression flag: snappy.
const COMPRESS_SNAPPY: u32 = 0x04;
/// Compression flag: zstd.
const COMPRESS_ZSTD: u32 = 0x20;

/// Size of a single `page_desc` entry in bytes.
const PAGE_DESC_SIZE: usize = 24;

/// LRU cache capacity (number of decompressed pages).
const CACHE_CAPACITY: usize = 1024;

/// A parsed page descriptor from the kdump file.
#[derive(Debug, Clone)]
struct PageDesc {
    /// File offset of the compressed page data.
    offset: i64,
    /// Size of the compressed data in bytes.
    size: u32,
    /// Compression flags.
    flags: u32,
}

/// Kdump format provider with lazy decompression and LRU cache.
pub struct KdumpProvider {
    /// Raw file data.
    data: Vec<u8>,
    /// Block size in bytes (typically 4096).
    block_size: u32,
    /// Maximum page frame number.
    max_mapnr: u32,
    /// 2nd bitmap (dumped PFNs): byte offset and length in `data`.
    bitmap2_offset: usize,
    bitmap2_len: usize,
    /// File offset where page descriptors start.
    desc_offset: usize,
    /// Total number of page descriptors.
    num_descs: usize,
    /// Pre-computed physical ranges from the bitmap.
    ranges: Vec<PhysicalRange>,
    /// LRU cache: PFN -> decompressed page data.
    cache: Mutex<lru::LruCache<u64, Vec<u8>>>,
}

/// Read a little-endian i32 from `data` at `offset`.
fn read_i32(data: &[u8], offset: usize) -> Result<i32> {
    data.get(offset..offset + 4)
        .and_then(|s| s.try_into().ok())
        .map(i32::from_le_bytes)
        .ok_or_else(|| Error::Corrupt(format!("read_i32 out of bounds at offset {offset}")))
}

/// Read a little-endian u32 from `data` at `offset`.
fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    data.get(offset..offset + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| Error::Corrupt(format!("read_u32 out of bounds at offset {offset}")))
}

/// Read a little-endian i64 from `data` at `offset`.
fn read_i64(data: &[u8], offset: usize) -> Result<i64> {
    data.get(offset..offset + 8)
        .and_then(|s| s.try_into().ok())
        .map(i64::from_le_bytes)
        .ok_or_else(|| Error::Corrupt(format!("read_i64 out of bounds at offset {offset}")))
}

/// Check whether the first 8 bytes match a known kdump/diskdump signature.
fn is_kdump_signature(header: &[u8]) -> bool {
    if header.len() < 8 {
        return false;
    }
    &header[0..8] == KDUMP_SIG || &header[0..8] == DISKDUMP_SIG
}

/// Parse a page descriptor from the raw data at the given offset.
fn parse_page_desc(data: &[u8], offset: usize) -> Result<PageDesc> {
    Ok(PageDesc {
        offset: read_i64(data, offset)?,
        size: read_u32(data, offset + 8)?,
        flags: read_u32(data, offset + 12)?,
    })
}

/// Test whether a specific bit is set in a bitmap.
fn bitmap_test(bitmap: &[u8], bit: usize) -> bool {
    let byte_idx = bit / 8;
    let bit_idx = bit % 8;
    if byte_idx >= bitmap.len() {
        return false;
    }
    (bitmap[byte_idx] >> bit_idx) & 1 != 0
}

/// Count the number of set bits in a bitmap before the given bit position.
fn bitmap_popcount_before(bitmap: &[u8], bit: usize) -> usize {
    let full_bytes = bit / 8;
    let remaining_bits = bit % 8;
    let mut count = 0usize;
    for &b in &bitmap[..full_bytes.min(bitmap.len())] {
        count += b.count_ones() as usize;
    }
    if remaining_bits > 0 && full_bytes < bitmap.len() {
        // Count only the bits below the target bit position in the partial byte.
        let mask = (1u8 << remaining_bits) - 1;
        count += (bitmap[full_bytes] & mask).count_ones() as usize;
    }
    count
}

/// Build physical ranges from a bitmap: contiguous runs of set bits.
fn ranges_from_bitmap(bitmap: &[u8], max_pfn: u32, block_size: u32) -> Vec<PhysicalRange> {
    let mut ranges = Vec::new();
    let mut run_start: Option<u64> = None;
    let bs = u64::from(block_size);

    for pfn in 0..max_pfn as usize {
        if bitmap_test(bitmap, pfn) {
            if run_start.is_none() {
                run_start = Some(pfn as u64 * bs);
            }
        } else if let Some(start) = run_start.take() {
            ranges.push(PhysicalRange {
                start,
                end: pfn as u64 * bs,
            });
        }
    }
    // Close any trailing run.
    if let Some(start) = run_start {
        ranges.push(PhysicalRange {
            start,
            end: u64::from(max_pfn) * bs,
        });
    }
    ranges
}

/// Decompress page data based on the compression flags.
fn decompress_page(compressed: &[u8], flags: u32, block_size: u32) -> Result<Vec<u8>> {
    let bs = block_size as usize;
    match flags {
        0 => {
            // Uncompressed: size must equal block_size.
            if compressed.len() == bs {
                Ok(compressed.to_vec())
            } else {
                Err(Error::Corrupt(format!(
                    "uncompressed page size {} != block_size {bs}",
                    compressed.len()
                )))
            }
        }
        COMPRESS_ZLIB => {
            use std::io::Read as _;
            let mut decoder = flate2::read::ZlibDecoder::new(compressed);
            let mut out = vec![0u8; bs];
            decoder
                .read_exact(&mut out)
                .map_err(|e| Error::Decompression(format!("zlib: {e}")))?;
            Ok(out)
        }
        COMPRESS_LZO => Err(Error::Decompression("LZO not yet supported".into())),
        COMPRESS_SNAPPY => {
            let mut decoder = snap::raw::Decoder::new();
            decoder
                .decompress_vec(compressed)
                .map_err(|e| Error::Decompression(format!("snappy: {e}")))
        }
        COMPRESS_ZSTD => {
            use std::io::Read as _;
            let cursor = std::io::Cursor::new(compressed);
            let mut decoder = ruzstd::decoding::StreamingDecoder::new(cursor)
                .map_err(|e| Error::Decompression(format!("zstd init: {e}")))?;
            let mut out = vec![0u8; bs];
            decoder
                .read_exact(&mut out)
                .map_err(|e| Error::Decompression(format!("zstd: {e}")))?;
            Ok(out)
        }
        other => Err(Error::Decompression(format!(
            "unknown compression flags: 0x{other:02X}"
        ))),
    }
}

impl KdumpProvider {
    /// Parse a kdump file from an in-memory byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::parse(bytes.to_vec())
    }

    /// Parse a kdump file from a file path.
    pub fn from_path(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::parse(data)
    }

    /// Internal: parse the kdump file from owned data.
    fn parse(data: Vec<u8>) -> Result<Self> {
        if !is_kdump_signature(&data) {
            return Err(Error::Corrupt("not a kdump/diskdump file".into()));
        }

        // Header field offsets:
        // utsname starts at 0x0C, is 390 bytes (6 * 65).
        // Align to 4: (0x0C + 390 + 3) & !3 = 0x19C
        let fields_off = (0x0C + 390 + 3) & !3; // 0x19C

        let block_size_raw = read_i32(&data, fields_off)?;
        let sub_hdr_size_raw = read_i32(&data, fields_off + 4)?;
        let block_size = u32::try_from(block_size_raw)
            .map_err(|_| Error::Corrupt(format!("negative block_size: {block_size_raw}")))?;
        let sub_hdr_size = u32::try_from(sub_hdr_size_raw)
            .map_err(|_| Error::Corrupt(format!("negative sub_hdr_size: {sub_hdr_size_raw}")))?;
        let bitmap_blocks = read_u32(&data, fields_off + 8)?;
        let max_mapnr = read_u32(&data, fields_off + 12)?;

        let bs = block_size as usize;
        if bs == 0 {
            return Err(Error::Corrupt("block_size is 0".into()));
        }

        // Bitmaps start after disk_dump_header (block 0) + kdump_sub_header (sub_hdr_size blocks).
        let bitmap_start_block = 1 + sub_hdr_size as usize;
        let bm1_offset = bitmap_start_block * bs;
        let bm_byte_len = bitmap_blocks as usize * bs;

        // 2nd bitmap follows immediately after the 1st.
        let bm2_offset = bm1_offset + bm_byte_len;

        // Validate bounds.
        if bm2_offset + bm_byte_len > data.len() {
            return Err(Error::Corrupt("bitmaps extend beyond file".into()));
        }

        // Count total dumped pages from bitmap2 to determine descriptor count.
        let bitmap2 = &data[bm2_offset..bm2_offset + bm_byte_len];
        let mut num_descs = 0usize;
        for pfn in 0..max_mapnr as usize {
            if bitmap_test(bitmap2, pfn) {
                num_descs += 1;
            }
        }

        // Page descriptors start after both bitmaps.
        let desc_offset = bm2_offset + bm_byte_len;
        let descs_raw_size = num_descs * PAGE_DESC_SIZE;
        if desc_offset + descs_raw_size > data.len() {
            return Err(Error::Corrupt("page descriptors extend beyond file".into()));
        }

        // Build physical ranges from the 2nd bitmap.
        let ranges = ranges_from_bitmap(bitmap2, max_mapnr, block_size);

        let cache = Mutex::new(lru::LruCache::new(
            NonZeroUsize::new(CACHE_CAPACITY).expect("CACHE_CAPACITY must be > 0"),
        ));

        Ok(Self {
            data,
            block_size,
            max_mapnr,
            bitmap2_offset: bm2_offset,
            bitmap2_len: bm_byte_len,
            desc_offset,
            num_descs,
            ranges,
            cache,
        })
    }

    /// Get the 2nd bitmap slice.
    fn bitmap2(&self) -> &[u8] {
        &self.data[self.bitmap2_offset..self.bitmap2_offset + self.bitmap2_len]
    }

    /// Read and decompress a page by its PFN.
    fn load_page(&self, pfn: u64) -> Result<Vec<u8>> {
        let bitmap2 = self.bitmap2();

        // Check if PFN is in the dumped bitmap.
        if !bitmap_test(bitmap2, pfn as usize) {
            // Not dumped — return zeros.
            return Ok(vec![]);
        }

        // Count set bits before this PFN to get the descriptor index.
        let desc_idx = bitmap_popcount_before(bitmap2, pfn as usize);
        if desc_idx >= self.num_descs {
            return Err(Error::Corrupt(format!(
                "descriptor index {desc_idx} out of range (max {})",
                self.num_descs
            )));
        }

        let desc = parse_page_desc(&self.data, self.desc_offset + desc_idx * PAGE_DESC_SIZE)?;
        let file_offset = usize::try_from(desc.offset)
            .map_err(|_| Error::Corrupt(format!("negative page offset: {}", desc.offset)))?;
        let size = desc.size as usize;

        if file_offset + size > self.data.len() {
            return Err(Error::Corrupt(format!(
                "page data at offset {file_offset} + size {size} extends beyond file"
            )));
        }

        let compressed = &self.data[file_offset..file_offset + size];
        decompress_page(compressed, desc.flags, self.block_size)
    }
}

impl PhysicalMemoryProvider for KdumpProvider {
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let bs = u64::from(self.block_size);
        let pfn = addr / bs;
        let page_offset = (addr % bs) as usize;

        // Check LRU cache first.
        {
            let mut cache = self.cache.lock().expect("cache lock poisoned");
            if let Some(page) = cache.get(&pfn) {
                let avail = page.len().saturating_sub(page_offset);
                let to_read = buf.len().min(avail);
                buf[..to_read].copy_from_slice(&page[page_offset..page_offset + to_read]);
                return Ok(to_read);
            }
        }

        // Check bitmap: if PFN not dumped, return 0.
        if pfn >= u64::from(self.max_mapnr) || !bitmap_test(self.bitmap2(), pfn as usize) {
            return Ok(0);
        }

        // Load and decompress the page.
        let page = self.load_page(pfn)?;
        let avail = page.len().saturating_sub(page_offset);
        let to_read = buf.len().min(avail);
        buf[..to_read].copy_from_slice(&page[page_offset..page_offset + to_read]);

        // Cache the decompressed page.
        {
            let mut cache = self.cache.lock().expect("cache lock poisoned");
            cache.put(pfn, page);
        }

        Ok(to_read)
    }

    fn ranges(&self) -> &[PhysicalRange] {
        &self.ranges
    }

    fn format_name(&self) -> &str {
        "kdump"
    }

    fn metadata(&self) -> Option<DumpMetadata> {
        Some(DumpMetadata {
            dump_type: Some("kdump".into()),
            ..DumpMetadata::default()
        })
    }
}

/// Format plugin for kdump files.
pub struct KdumpPlugin;

impl FormatPlugin for KdumpPlugin {
    fn name(&self) -> &str {
        "kdump"
    }

    fn probe(&self, header: &[u8]) -> u8 {
        if is_kdump_signature(header) {
            90
        } else {
            0
        }
    }

    fn open(&self, path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>> {
        Ok(Box::new(KdumpProvider::from_path(path)?))
    }
}

inventory::submit!(&KdumpPlugin as &dyn FormatPlugin);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_builders::KdumpBuilder;

    #[test]
    fn probe_kdump_signature() {
        let dump = KdumpBuilder::new()
            .add_page(0, &[0xAAu8; 4096])
            .build();
        let plugin = KdumpPlugin;
        assert_eq!(plugin.probe(&dump), 90);
    }

    #[test]
    fn probe_diskdump_signature() {
        // Build a kdump and overwrite signature to "DISKDUMP"
        let mut dump = KdumpBuilder::new()
            .add_page(0, &[0xAAu8; 4096])
            .build();
        dump[0..8].copy_from_slice(b"DISKDUMP");
        let plugin = KdumpPlugin;
        assert_eq!(plugin.probe(&dump), 90);
    }

    #[test]
    fn probe_non_kdump() {
        let zeros = vec![0u8; 4096];
        let plugin = KdumpPlugin;
        assert_eq!(plugin.probe(&zeros), 0);
    }

    #[test]
    fn probe_short_header_returns_zero() {
        let plugin = KdumpPlugin;
        // Less than 8 bytes
        assert_eq!(plugin.probe(&[0u8; 4]), 0);
        // Empty
        assert_eq!(plugin.probe(&[]), 0);
    }

    #[test]
    fn single_page_snappy_read() {
        let mut page = vec![0u8; 4096];
        page[0] = 0xDE;
        page[1] = 0xAD;
        page[2] = 0xBE;
        page[3] = 0xEF;
        let dump = KdumpBuilder::new()
            .compression(0x04)
            .add_page(1, &page)
            .build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();
        let mut buf = [0u8; 4];
        let n = provider.read_phys(4096, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn single_page_zlib_read() {
        let mut page = vec![0u8; 4096];
        page[100] = 0x42;
        page[101] = 0x43;
        let dump = KdumpBuilder::new()
            .compression(0x01)
            .add_page(2, &page)
            .build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();
        let mut buf = [0u8; 2];
        let n = provider.read_phys(2 * 4096 + 100, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0x42, 0x43]);
    }

    #[test]
    fn uncompressed_page_read() {
        let mut page = vec![0u8; 4096];
        page[0] = 0xFF;
        page[4095] = 0x01;
        let dump = KdumpBuilder::new()
            .compression(0x00)
            .add_page(0, &page)
            .build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();
        let mut buf = [0u8; 1];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf, [0xFF]);
        let n = provider.read_phys(4095, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf, [0x01]);
    }

    #[test]
    fn multi_page_read() {
        let mut page_a = vec![0xAAu8; 4096];
        page_a[0] = 0x11;
        let mut page_b = vec![0xBBu8; 4096];
        page_b[0] = 0x22;
        // PFN 2 and PFN 5: gap between them
        let dump = KdumpBuilder::new()
            .add_page(2, &page_a)
            .add_page(5, &page_b)
            .build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();

        let mut buf = [0u8; 1];
        let n = provider.read_phys(2 * 4096, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf, [0x11]);

        let n = provider.read_phys(5 * 4096, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf, [0x22]);
    }

    #[test]
    fn read_gap_returns_zero() {
        let page = vec![0xAAu8; 4096];
        // Only PFN 1 is mapped
        let dump = KdumpBuilder::new().add_page(1, &page).build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();

        // Read PFN 0 (unmapped)
        let mut buf = [0u8; 4];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_empty_buffer() {
        let page = vec![0xAAu8; 4096];
        let dump = KdumpBuilder::new().add_page(0, &page).build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();

        let mut buf = [0u8; 0];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn metadata_extraction() {
        let page = vec![0u8; 4096];
        let dump = KdumpBuilder::new().add_page(0, &page).build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();

        let meta = provider.metadata().expect("should return metadata");
        assert_eq!(meta.dump_type.as_deref(), Some("kdump"));
    }

    #[test]
    fn lru_cache_hit() {
        let mut page = vec![0u8; 4096];
        page[0] = 0xCA;
        page[100] = 0xFE;
        let dump = KdumpBuilder::new().add_page(0, &page).build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();

        // First read: offset 0
        let mut buf = [0u8; 1];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf, [0xCA]);

        // Second read: offset 100 (same page, should hit cache)
        let n = provider.read_phys(100, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf, [0xFE]);
    }

    #[test]
    fn lzo_returns_error() {
        // Build a dump but manually set flags to 0x02 (LZO) in the page_desc.
        // We can't use the builder for LZO, so build snappy then patch the flags.
        let page = vec![0xAAu8; 4096];
        let mut dump = KdumpBuilder::new()
            .compression(0x04)
            .add_page(0, &page)
            .build();

        // Find the page_desc and patch flags from 0x04 to 0x02.
        // page_desc is at desc_start = (2 + 2*bitmap_blocks) * 4096
        // For 1 PFN (max_pfn=1), bitmap needs ceil(1/8)=1 byte, ceil(1/4096)=1 block
        // desc_start = (2 + 2*1) * 4096 = 4 * 4096 = 16384
        let desc_start = 4 * 4096;
        // flags field is at offset 12 within page_desc
        let flags_off = desc_start + 12;
        dump[flags_off..flags_off + 4].copy_from_slice(&0x02u32.to_le_bytes());

        let provider = KdumpProvider::from_bytes(&dump).unwrap();
        let mut buf = [0u8; 4];
        let result = provider.read_phys(0, &mut buf);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("LZO"),
            "error should mention LZO: {err}"
        );
    }

    #[test]
    fn plugin_name() {
        let plugin = KdumpPlugin;
        assert_eq!(plugin.name(), "kdump");
    }

    #[test]
    fn from_path_roundtrip() {
        let mut page = vec![0u8; 4096];
        page[0] = 0x99;
        let dump = KdumpBuilder::new().add_page(0, &page).build();

        let path = std::env::temp_dir().join("memf_test_kdump.bin");
        std::fs::write(&path, &dump).unwrap();

        let provider = KdumpProvider::from_path(&path).unwrap();
        let mut buf = [0u8; 1];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf, [0x99]);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn builder_produces_kdump_signature() {
        let dump = KdumpBuilder::new()
            .add_page(0, &[0u8; 4096])
            .build();
        assert_eq!(&dump[0..8], b"KDUMP   ");
    }
}
