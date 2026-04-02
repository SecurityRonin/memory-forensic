//! Pagefile and swapfile sources for resolving paged-out memory.

use std::collections::HashMap;
use std::path::Path;

use crate::Result;

/// A source of paged-out memory pages (pagefile.sys, swapfile.sys, etc.).
pub trait PagefileSource: Send + Sync {
    /// Which pagefile number this source handles (0 = pagefile.sys, 1-15 = secondary).
    fn pagefile_number(&self) -> u8;

    /// Read a 4KB page at the given page offset.
    /// Returns `Ok(None)` if the offset is beyond the file's page count.
    fn read_page(&self, page_offset: u64) -> Result<Option<[u8; 4096]>>;
}

/// Provider for Windows pagefile.sys — a flat file of 4KB pages.
///
/// pagefile.sys has no headers and no compression. Each page occupies
/// exactly 4096 bytes at offset `page_index * 0x1000`.
pub struct PagefileProvider {
    mmap: memmap2::Mmap,
    pagefile_num: u8,
    page_count: u64,
}

impl PagefileProvider {
    /// Open a pagefile and memory-map it.
    #[allow(unsafe_code)]
    pub fn open(path: &Path, pagefile_num: u8) -> Result<Self> {
        let file = std::fs::File::open(path)
            .map_err(|e| crate::Error::Physical(memf_format::Error::Io(e)))?;
        let mmap = unsafe { memmap2::MmapOptions::new().map(&file) }
            .map_err(|e| crate::Error::Physical(memf_format::Error::Io(e)))?;
        let page_count = mmap.len() as u64 / 0x1000;
        Ok(Self {
            mmap,
            pagefile_num,
            page_count,
        })
    }
}

impl PagefileSource for PagefileProvider {
    fn pagefile_number(&self) -> u8 {
        self.pagefile_num
    }

    fn read_page(&self, page_offset: u64) -> Result<Option<[u8; 4096]>> {
        if page_offset >= self.page_count {
            return Ok(None);
        }
        let byte_offset = page_offset as usize * 0x1000;
        let mut page = [0u8; 4096];
        page.copy_from_slice(&self.mmap[byte_offset..byte_offset + 4096]);
        Ok(Some(page))
    }
}

const SM_MAGIC: u16 = 0x4D53; // "SM" in little-endian: 'S'=0x53 at byte 0, 'M'=0x4D at byte 1
const SM_HEADER_SIZE: usize = 20;
const REGION_ENTRY_SIZE: usize = 24;

/// Provider for Windows swapfile.sys — SM header format with optional Xpress compression.
#[derive(Debug)]
pub struct SwapfileProvider {
    mmap: memmap2::Mmap,
    /// Maps page offset -> (file_offset, compressed_size).
    index: HashMap<u64, (u64, u32)>,
}

impl SwapfileProvider {
    /// Open a swapfile.sys and parse its SM header to build the page index.
    #[allow(unsafe_code)]
    pub fn open(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)
            .map_err(|e| crate::Error::Physical(memf_format::Error::Io(e)))?;
        let mmap = unsafe { memmap2::MmapOptions::new().map(&file) }
            .map_err(|e| crate::Error::Physical(memf_format::Error::Io(e)))?;

        if mmap.len() < SM_HEADER_SIZE {
            return Err(crate::Error::Physical(memf_format::Error::Corrupt(
                "swapfile too small for SM header".into(),
            )));
        }

        let magic = u16::from_le_bytes([mmap[0], mmap[1]]);
        if magic != SM_MAGIC {
            return Err(crate::Error::Physical(memf_format::Error::Corrupt(
                format!("invalid SM magic: expected 0x4D53, got {magic:#06X}"),
            )));
        }

        let region_table_offset = u64::from_le_bytes(mmap[8..16].try_into().unwrap()) as usize;
        let region_count = u32::from_le_bytes(mmap[16..20].try_into().unwrap()) as usize;

        let mut index = HashMap::new();

        for i in 0..region_count {
            let entry_offset = region_table_offset + i * REGION_ENTRY_SIZE;
            if entry_offset + REGION_ENTRY_SIZE > mmap.len() {
                return Err(crate::Error::Physical(memf_format::Error::Corrupt(
                    format!("SM region entry {i} at offset {entry_offset:#x} truncated"),
                )));
            }

            let page_offset =
                u64::from_le_bytes(mmap[entry_offset..entry_offset + 8].try_into().unwrap());
            let file_offset = u64::from_le_bytes(
                mmap[entry_offset + 8..entry_offset + 16]
                    .try_into()
                    .unwrap(),
            );
            let page_count = u32::from_le_bytes(
                mmap[entry_offset + 16..entry_offset + 20]
                    .try_into()
                    .unwrap(),
            );
            let compressed_size = u32::from_le_bytes(
                mmap[entry_offset + 20..entry_offset + 24]
                    .try_into()
                    .unwrap(),
            );

            for p in 0..u64::from(page_count) {
                let fo = file_offset + p * u64::from(compressed_size);
                index.insert(page_offset + p, (fo, compressed_size));
            }
        }

        Ok(Self { mmap, index })
    }
}

impl PagefileSource for SwapfileProvider {
    fn pagefile_number(&self) -> u8 {
        2 // Windows convention for swapfile virtual store
    }

    fn read_page(&self, page_offset: u64) -> Result<Option<[u8; 4096]>> {
        let Some(&(file_offset, compressed_size)) = self.index.get(&page_offset) else {
            return Ok(None);
        };

        let fo = file_offset as usize;
        let cs = compressed_size as usize;

        if fo + cs > self.mmap.len() {
            return Err(crate::Error::Physical(memf_format::Error::Corrupt(
                format!(
                    "swapfile page at offset {page_offset:#x}: data at {fo:#x}+{cs:#x} beyond file"
                ),
            )));
        }

        if compressed_size == 0x1000 {
            let mut page = [0u8; 4096];
            page.copy_from_slice(&self.mmap[fo..fo + 4096]);
            Ok(Some(page))
        } else {
            let compressed_data = &self.mmap[fo..fo + cs];
            let decompressed = lzxpress::data::decompress(compressed_data).map_err(|e| {
                crate::Error::Physical(memf_format::Error::Decompression(format!(
                    "swapfile xpress decompress at page {page_offset:#x}: {e:?}"
                )))
            })?;
            if decompressed.len() < 4096 {
                return Err(crate::Error::Physical(memf_format::Error::Corrupt(
                    format!(
                        "swapfile decompressed page {page_offset:#x}: {} bytes (expected 4096)",
                        decompressed.len()
                    ),
                )));
            }
            let mut page = [0u8; 4096];
            page.copy_from_slice(&decompressed[..4096]);
            Ok(Some(page))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn create_temp_pagefile(num_pages: usize) -> (tempfile::NamedTempFile, Vec<[u8; 4096]>) {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let mut pages = Vec::new();
        for i in 0..num_pages {
            let mut page = [0u8; 4096];
            page[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            page[4] = 0xFF;
            file.write_all(&page).unwrap();
            pages.push(page);
        }
        file.flush().unwrap();
        (file, pages)
    }

    #[test]
    fn pagefile_provider_open_and_read() {
        let (file, pages) = create_temp_pagefile(4);
        let provider = PagefileProvider::open(file.path(), 0).unwrap();
        assert_eq!(provider.pagefile_number(), 0);

        let page = provider.read_page(0).unwrap().unwrap();
        assert_eq!(page, pages[0]);

        let page2 = provider.read_page(2).unwrap().unwrap();
        assert_eq!(page2, pages[2]);
    }

    #[test]
    fn pagefile_provider_out_of_range() {
        let (file, _pages) = create_temp_pagefile(4);
        let provider = PagefileProvider::open(file.path(), 0).unwrap();
        assert!(provider.read_page(4).unwrap().is_none());
        assert!(provider.read_page(9999).unwrap().is_none());
    }

    #[test]
    fn pagefile_provider_number() {
        let (file, _) = create_temp_pagefile(1);
        let provider = PagefileProvider::open(file.path(), 3).unwrap();
        assert_eq!(provider.pagefile_number(), 3);
    }

    #[test]
    fn swapfile_provider_invalid_magic() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&[0x00; 4096]).unwrap();
        file.flush().unwrap();
        let result = SwapfileProvider::open(file.path());
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("SM") || msg.contains("magic"),
            "error should mention SM magic: {msg}"
        );
    }

    #[test]
    fn swapfile_provider_too_small() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&[0x53, 0x4D]).unwrap(); // "SM" but too short
        file.flush().unwrap();
        let result = SwapfileProvider::open(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn swapfile_provider_valid_sm_header() {
        // Build a synthetic SM swapfile with one uncompressed page
        let mut data = vec![0u8; 0x3000];

        // SM header at offset 0
        data[0] = 0x53; // 'S'
        data[1] = 0x4D; // 'M'
        data[2..4].copy_from_slice(&1u16.to_le_bytes()); // version = 1
        data[4..8].copy_from_slice(&0x1000u32.to_le_bytes()); // page_size
        data[8..16].copy_from_slice(&0x1000u64.to_le_bytes()); // region_table_offset
        data[16..20].copy_from_slice(&1u32.to_le_bytes()); // region_count

        // Region entry at offset 0x1000:
        let region_off = 0x1000usize;
        data[region_off..region_off + 8].copy_from_slice(&5u64.to_le_bytes()); // page_offset = 5
        data[region_off + 8..region_off + 16].copy_from_slice(&0x1800u64.to_le_bytes()); // file_offset
        data[region_off + 16..region_off + 20].copy_from_slice(&1u32.to_le_bytes()); // page_count
        data[region_off + 20..region_off + 24].copy_from_slice(&0x1000u32.to_le_bytes()); // compressed_size (uncompressed)

        // Page data at file offset 0x1800
        data.resize(0x2800, 0); // ensure enough space: 0x1800 + 0x1000 = 0x2800
        data[0x1800] = 0x42;
        data[0x1801] = 0x43;
        for i in 2..4096 {
            data[0x1800 + i] = 0xAB;
        }

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        let provider = SwapfileProvider::open(file.path()).unwrap();
        assert_eq!(provider.pagefile_number(), 2);

        let page = provider.read_page(5).unwrap().unwrap();
        assert_eq!(page[0], 0x42);
        assert_eq!(page[1], 0x43);
        assert_eq!(page[2], 0xAB);

        assert!(provider.read_page(99).unwrap().is_none());
    }

    #[test]
    fn swapfile_provider_compressed_page() {
        let mut original_page = [0u8; 4096];
        original_page[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        for i in (4..4096).step_by(4) {
            original_page[i..i + 4].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        }

        let compressed = lzxpress::data::compress(&original_page).unwrap();
        assert!(compressed.len() < 4096, "compressed should be smaller");

        let mut data = vec![0u8; 0x3000 + compressed.len()];

        // SM header
        data[0] = 0x53;
        data[1] = 0x4D;
        data[2..4].copy_from_slice(&1u16.to_le_bytes());
        data[4..8].copy_from_slice(&0x1000u32.to_le_bytes());
        data[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        data[16..20].copy_from_slice(&1u32.to_le_bytes());

        let region_off = 0x1000usize;
        data[region_off..region_off + 8].copy_from_slice(&7u64.to_le_bytes());
        data[region_off + 8..region_off + 16].copy_from_slice(&0x1800u64.to_le_bytes());
        data[region_off + 16..region_off + 20].copy_from_slice(&1u32.to_le_bytes());
        data[region_off + 20..region_off + 24]
            .copy_from_slice(&(compressed.len() as u32).to_le_bytes());

        data[0x1800..0x1800 + compressed.len()].copy_from_slice(&compressed);

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        let provider = SwapfileProvider::open(file.path()).unwrap();
        let page = provider.read_page(7).unwrap().unwrap();
        assert_eq!(page, original_page);
    }
}
