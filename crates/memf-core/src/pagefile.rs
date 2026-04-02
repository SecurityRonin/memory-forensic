//! Pagefile and swapfile sources for resolving paged-out memory.

use crate::Result;

/// A source of paged-out memory pages (pagefile.sys, swapfile.sys, etc.).
pub trait PagefileSource: Send + Sync {
    /// Which pagefile number this source handles (0 = pagefile.sys, 1-15 = secondary).
    fn pagefile_number(&self) -> u8;

    /// Read a 4KB page at the given page offset.
    /// Returns `Ok(None)` if the offset is beyond the file's page count.
    fn read_page(&self, page_offset: u64) -> Result<Option<[u8; 4096]>>;
}
