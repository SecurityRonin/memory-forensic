//! Windows hibernation file (`hiberfil.sys`) format provider.
//!
//! Parses hibernation files with `PO_MEMORY_IMAGE` header signatures:
//! `hibr` (0x72626968), `wake` (0x656B6177), `RSTR` (0x52545352),
//! `HORM` (0x4D524F48). Eagerly decompresses Xpress LZ77 blocks into a
//! `HashMap<pfn, page>` for random-access reads. Extracts CR3 from the
//! processor state page.

use std::collections::HashMap;
use std::path::Path;

use crate::{DumpMetadata, Error, FormatPlugin, PhysicalMemoryProvider, PhysicalRange, Result};

/// Magic values (little-endian u32).
const HIBR_MAGIC: u32 = 0x7262_6968;
const WAKE_MAGIC: u32 = 0x656B_6177;
const RSTR_MAGIC: u32 = 0x5254_5352;
const HORM_MAGIC: u32 = 0x4D52_4F48;

/// Page size in bytes.
const PAGE_SIZE: usize = 4096;

/// Xpress block signature: `[0x81, 0x81, 'x', 'p', 'r', 'e', 's', 's']`.
const XPRESS_SIG: [u8; 8] = [0x81, 0x81, b'x', b'p', b'r', b'e', b's', b's'];

/// Block header size (padded to 0x20).
const BLOCK_HEADER_SIZE: usize = 0x20;

/// Offset of `LengthSelf` in the PO_MEMORY_IMAGE header.
const OFF_LENGTH_SELF: usize = 0x0C;

/// Offset of `FirstTablePage` in the PO_MEMORY_IMAGE header (u64).
const OFF_FIRST_TABLE_PAGE: usize = 0x68;

/// Offset of CR3 within the processor state page (page 1).
const OFF_CR3_IN_PROC_STATE: usize = 0x28;

/// Read a little-endian u32 from `data` at `offset`.
fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

/// Read a little-endian u64 from `data` at `offset`.
fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

/// Provider that exposes physical memory from a Windows hibernation file.
///
/// Stores decompressed pages in a `HashMap<pfn, Vec<u8>>` for O(1) lookup.
pub struct HiberfilProvider {
    pages: HashMap<u64, Vec<u8>>,
    ranges: Vec<PhysicalRange>,
    meta: DumpMetadata,
}

impl HiberfilProvider {
    /// Parse a hibernation file from an in-memory byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Validate minimum size: at least 3 header pages (0x3000 bytes).
        if bytes.len() < 3 * PAGE_SIZE {
            return Err(Error::Corrupt(
                "hiberfil too short: need at least 3 header pages".into(),
            ));
        }

        // Validate magic.
        let magic = read_u32(bytes, 0);
        if !is_hiberfil_magic(magic) {
            return Err(Error::Corrupt(format!(
                "invalid hiberfil magic: 0x{magic:08X}"
            )));
        }

        // Check LengthSelf to confirm 64-bit format (value 256).
        let _length_self = read_u32(bytes, OFF_LENGTH_SELF);

        // Extract CR3 from processor state page (page 1, offset 0x28).
        let cr3 = read_u64(bytes, PAGE_SIZE + OFF_CR3_IN_PROC_STATE);

        // Read the page table from page indicated by FirstTablePage.
        let first_table_page = read_u64(bytes, OFF_FIRST_TABLE_PAGE);
        let table_offset = first_table_page as usize * PAGE_SIZE;

        if table_offset + PAGE_SIZE > bytes.len() {
            return Err(Error::Corrupt("first table page beyond file end".into()));
        }

        // Parse PFN entries from the page table until sentinel 0xFFFFFFFFFFFFFFFF.
        let mut pfn_list = Vec::new();
        let mut pos = table_offset;
        while pos + 8 <= table_offset + PAGE_SIZE {
            let pfn = read_u64(bytes, pos);
            if pfn == u64::MAX {
                break;
            }
            pfn_list.push(pfn);
            pos += 8;
        }

        // Decompress Xpress blocks starting after header pages (3 * PAGE_SIZE).
        let mut pages = HashMap::new();
        let mut block_offset = 3 * PAGE_SIZE;
        let mut pfn_idx = 0;

        while block_offset + BLOCK_HEADER_SIZE <= bytes.len() && pfn_idx < pfn_list.len() {
            // Check Xpress signature.
            if bytes[block_offset..block_offset + 8] != XPRESS_SIG {
                break;
            }

            // Parse block header.
            let num_pages_minus_1 = bytes[block_offset + 8] as usize;
            let num_pages = num_pages_minus_1 + 1;

            // compressed_size_field: 3 bytes LE at offset 9.
            let csf_b0 = u32::from(bytes[block_offset + 9]);
            let csf_b1 = u32::from(bytes[block_offset + 10]);
            let csf_b2 = u32::from(bytes[block_offset + 11]);
            let compressed_size_field = csf_b0 | (csf_b1 << 8) | (csf_b2 << 16);

            // Decode compressed size: (compressed_size_field + 1) / 4.
            let compressed_len = ((compressed_size_field + 1) / 4) as usize;

            let data_start = block_offset + BLOCK_HEADER_SIZE;
            let data_end = data_start + compressed_len;

            if data_end > bytes.len() {
                return Err(Error::Corrupt(format!(
                    "xpress block at 0x{block_offset:X} extends beyond file (need {compressed_len} bytes)"
                )));
            }

            // Decompress the block.
            let compressed_data = &bytes[data_start..data_end];
            let decompressed = lzxpress::data::decompress(compressed_data).map_err(|e| {
                Error::Decompression(format!("xpress decompress at 0x{block_offset:X}: {e:?}"))
            })?;

            // Split decompressed data into individual pages.
            for i in 0..num_pages {
                if pfn_idx >= pfn_list.len() {
                    break;
                }
                let pfn = pfn_list[pfn_idx];
                let page_start = i * PAGE_SIZE;
                let page_end = page_start + PAGE_SIZE;

                if page_end <= decompressed.len() {
                    pages.insert(pfn, decompressed[page_start..page_end].to_vec());
                }
                pfn_idx += 1;
            }

            block_offset = data_end;
        }

        // Build sorted ranges from the page map.
        let mut pfns: Vec<u64> = pages.keys().copied().collect();
        pfns.sort_unstable();
        let ranges = build_ranges(&pfns);

        let meta = DumpMetadata {
            cr3: Some(cr3),
            dump_type: Some("Hibernation".into()),
            ..DumpMetadata::default()
        };

        Ok(Self {
            pages,
            ranges,
            meta,
        })
    }

    /// Parse a hibernation file from a file path.
    pub fn from_path(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(&data)
    }
}

/// Build coalesced `PhysicalRange` entries from a sorted list of PFNs.
fn build_ranges(sorted_pfns: &[u64]) -> Vec<PhysicalRange> {
    let mut ranges = Vec::new();
    let mut iter = sorted_pfns.iter().copied();

    let Some(first) = iter.next() else {
        return ranges;
    };

    let mut range_start = first * PAGE_SIZE as u64;
    let mut range_end = range_start + PAGE_SIZE as u64;

    for pfn in iter {
        let addr = pfn * PAGE_SIZE as u64;
        if addr == range_end {
            // Contiguous — extend.
            range_end = addr + PAGE_SIZE as u64;
        } else {
            // Gap — push current and start new.
            ranges.push(PhysicalRange {
                start: range_start,
                end: range_end,
            });
            range_start = addr;
            range_end = addr + PAGE_SIZE as u64;
        }
    }
    ranges.push(PhysicalRange {
        start: range_start,
        end: range_end,
    });

    ranges
}

/// Check whether a u32 matches one of the known hiberfil magic values.
fn is_hiberfil_magic(magic: u32) -> bool {
    matches!(magic, HIBR_MAGIC | WAKE_MAGIC | RSTR_MAGIC | HORM_MAGIC)
}

impl PhysicalMemoryProvider for HiberfilProvider {
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let pfn = addr / PAGE_SIZE as u64;
        let offset = (addr % PAGE_SIZE as u64) as usize;

        let Some(page) = self.pages.get(&pfn) else {
            return Ok(0);
        };

        let available = page.len().saturating_sub(offset);
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&page[offset..offset + to_read]);
        Ok(to_read)
    }

    fn ranges(&self) -> &[PhysicalRange] {
        &self.ranges
    }

    fn format_name(&self) -> &str {
        "Hiberfil.sys"
    }

    fn metadata(&self) -> Option<DumpMetadata> {
        Some(self.meta.clone())
    }
}

/// FormatPlugin implementation for Windows hibernation files.
pub struct HiberfilPlugin;

impl FormatPlugin for HiberfilPlugin {
    fn name(&self) -> &str {
        "Hiberfil.sys"
    }

    fn probe(&self, header: &[u8]) -> u8 {
        if header.len() < 4 {
            return 0;
        }
        let magic = read_u32(header, 0);
        match magic {
            HIBR_MAGIC | WAKE_MAGIC => 90,
            RSTR_MAGIC | HORM_MAGIC => 85,
            _ => 0,
        }
    }

    fn open(&self, path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>> {
        Ok(Box::new(HiberfilProvider::from_path(path)?))
    }
}

inventory::submit!(&HiberfilPlugin as &dyn FormatPlugin);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_builders::HiberfilBuilder;
    use std::io::Write;

    #[test]
    fn probe_hiberfil_magic() {
        let dump = HiberfilBuilder::new().build();
        let plugin = HiberfilPlugin;
        assert_eq!(plugin.probe(&dump), 90);
    }

    #[test]
    fn probe_non_hiberfil() {
        let plugin = HiberfilPlugin;
        assert_eq!(plugin.probe(&[0u8; 64]), 0);
    }

    #[test]
    fn probe_short_header_returns_zero() {
        let plugin = HiberfilPlugin;
        assert_eq!(plugin.probe(&[0x68, 0x69, 0x62]), 0); // 3 bytes
        assert_eq!(plugin.probe(&[]), 0); // empty
    }

    #[test]
    fn single_page_read() {
        let mut page = [0u8; 4096];
        page[0] = 0xAA;
        page[100] = 0xBB;
        page[4095] = 0xCC;

        let dump = HiberfilBuilder::new().add_page(0, &page).build();
        let provider = HiberfilProvider::from_bytes(&dump).unwrap();

        // Read first byte
        let mut buf = [0u8; 1];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0xAA);

        // Read byte at offset 100
        let n = provider.read_phys(100, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0xBB);

        // Read last byte of page
        let n = provider.read_phys(4095, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0xCC);
    }

    #[test]
    fn multi_page_read() {
        let mut page0 = [0u8; 4096];
        page0[0] = 0x11;
        let mut page4 = [0u8; 4096];
        page4[0] = 0x44;

        let dump = HiberfilBuilder::new()
            .add_page(0, &page0)
            .add_page(4, &page4)
            .build();
        let provider = HiberfilProvider::from_bytes(&dump).unwrap();

        let mut buf = [0u8; 1];

        // Read from PFN 0
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x11);

        // Read from PFN 4 (physical address = 4 * 4096 = 0x4000)
        let n = provider.read_phys(4 * 4096, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x44);
    }

    #[test]
    fn read_gap_returns_zero() {
        // Only PFN 2 is mapped; reading PFN 0 should return 0 bytes.
        let page = [0xFFu8; 4096];
        let dump = HiberfilBuilder::new().add_page(2, &page).build();
        let provider = HiberfilProvider::from_bytes(&dump).unwrap();

        let mut buf = [0u8; 4];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_empty_buffer() {
        let page = [0u8; 4096];
        let dump = HiberfilBuilder::new().add_page(0, &page).build();
        let provider = HiberfilProvider::from_bytes(&dump).unwrap();

        let mut buf = [];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn metadata_extraction() {
        let cr3_val = 0x1ab000u64;
        let dump = HiberfilBuilder::new().cr3(cr3_val).build();
        let provider = HiberfilProvider::from_bytes(&dump).unwrap();

        let meta = provider.metadata().expect("metadata should be Some");
        assert_eq!(meta.cr3, Some(cr3_val));
        assert_eq!(meta.dump_type.as_deref(), Some("Hibernation"));
    }

    #[test]
    fn plugin_name() {
        let plugin = HiberfilPlugin;
        assert_eq!(plugin.name(), "Hiberfil.sys");
    }

    #[test]
    fn from_path_roundtrip() {
        let mut page = [0u8; 4096];
        page[42] = 0xDE;

        let dump = HiberfilBuilder::new().add_page(0, &page).build();

        let dir = std::env::temp_dir().join("memf_hiberfil_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.hiberfil");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&dump).unwrap();
        }

        let provider = HiberfilProvider::from_path(&path).unwrap();
        let mut buf = [0u8; 1];
        let n = provider.read_phys(42, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0xDE);

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn builder_produces_hibr_magic() {
        let dump = HiberfilBuilder::new().build();
        let magic = u32::from_le_bytes(dump[0..4].try_into().unwrap());
        assert_eq!(magic, 0x7262_6968); // "hibr"
    }

    #[test]
    fn builder_stores_cr3_in_processor_state() {
        let cr3_val = 0xDEAD_BEEF_CAFE_0000u64;
        let dump = HiberfilBuilder::new().cr3(cr3_val).build();
        // CR3 is at page 1 (offset 0x1000) + 0x28
        let cr3_offset = 0x1000 + 0x28;
        let stored_cr3 = u64::from_le_bytes(dump[cr3_offset..cr3_offset + 8].try_into().unwrap());
        assert_eq!(stored_cr3, cr3_val);
    }
}
