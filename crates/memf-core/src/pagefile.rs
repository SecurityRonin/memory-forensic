//! Pagefile and swapfile sources for resolving paged-out memory.

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
        let file = std::fs::File::open(path).map_err(|e| {
            crate::Error::Physical(memf_format::Error::Io(e))
        })?;
        let mmap = unsafe { memmap2::MmapOptions::new().map(&file) }.map_err(|e| {
            crate::Error::Physical(memf_format::Error::Io(e))
        })?;
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
}
