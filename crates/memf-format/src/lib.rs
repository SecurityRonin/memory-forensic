#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Physical memory dump format parsers.

use std::path::Path;

/// Error type for memf-format operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error reading the dump file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The dump format could not be identified.
    #[error("unknown dump format")]
    UnknownFormat,

    /// Multiple formats matched with similar confidence.
    #[error("ambiguous format: multiple plugins scored >= 50")]
    AmbiguousFormat,

    /// The dump file is corrupt or truncated.
    #[error("corrupt dump: {0}")]
    Corrupt(String),

    /// Snappy decompression error.
    #[error("decompression error: {0}")]
    Decompression(String),
}

/// A Result alias for memf-format.
pub type Result<T> = std::result::Result<T, Error>;

/// A contiguous range of physical memory present in the dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalRange {
    /// Start physical address (inclusive).
    pub start: u64,
    /// End physical address (exclusive).
    pub end: u64,
}

impl PhysicalRange {
    /// Number of bytes in this range.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Whether this range is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the given address falls within this range.
    #[must_use]
    pub fn contains_addr(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

/// A provider of physical memory from a dump file.
pub trait PhysicalMemoryProvider: Send + Sync {
    /// Read up to `buf.len()` bytes starting at physical address `addr`.
    /// Returns the number of bytes actually read (may be less if crossing a gap).
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize>;

    /// Return all valid physical address ranges in the dump.
    fn ranges(&self) -> &[PhysicalRange];

    /// Total physical memory size (sum of all range lengths).
    fn total_size(&self) -> u64 {
        self.ranges().iter().map(PhysicalRange::len).sum()
    }

    /// Human-readable format name (e.g., "LiME", "AVML v2").
    fn format_name(&self) -> &str;
}

/// A plugin that can detect and open a specific dump format.
pub trait FormatPlugin: Send + Sync {
    /// Human-readable name for this format.
    fn name(&self) -> &str;

    /// Probe the first `header` bytes of a file. Return confidence 0-100.
    fn probe(&self, header: &[u8]) -> u8;

    /// Open the file and return a `PhysicalMemoryProvider`.
    fn open(&self, path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>>;
}

inventory::collect!(&'static dyn FormatPlugin);

/// Open a dump file by probing all registered format plugins.
///
/// Reads the first 4096 bytes and asks each plugin for a confidence score.
/// Returns the provider from the highest-confidence plugin (>=80 returns
/// immediately; otherwise the best score >=50 wins).
pub fn open_dump(path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut header = [0u8; 4096];
    let n = file.read(&mut header)?;
    let header = &header[..n];

    let mut best: Option<(&dyn FormatPlugin, u8)> = None;
    let mut ambiguous = false;

    for plugin in inventory::iter::<&dyn FormatPlugin> {
        let score = plugin.probe(header);
        if score >= 80 {
            return plugin.open(path);
        }
        if score >= 50 {
            if let Some((_, prev_score)) = best {
                if score >= prev_score {
                    if score == prev_score {
                        ambiguous = true;
                    } else {
                        ambiguous = false;
                        best = Some((*plugin, score));
                    }
                }
            } else {
                best = Some((*plugin, score));
            }
        } else if score >= 20 && best.is_none() {
            best = Some((*plugin, score));
        }
    }

    if ambiguous {
        return Err(Error::AmbiguousFormat);
    }

    match best {
        Some((plugin, _)) => plugin.open(path),
        None => Err(Error::UnknownFormat),
    }
}

pub mod avml;
pub mod lime;
pub mod test_builders;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_range_len() {
        let r = PhysicalRange { start: 0x1000, end: 0x2000 };
        assert_eq!(r.len(), 0x1000);
    }

    #[test]
    fn physical_range_empty() {
        let r = PhysicalRange { start: 0x1000, end: 0x1000 };
        assert!(r.is_empty());
    }

    #[test]
    fn physical_range_contains() {
        let r = PhysicalRange { start: 0x1000, end: 0x2000 };
        assert!(r.contains_addr(0x1000));
        assert!(r.contains_addr(0x1FFF));
        assert!(!r.contains_addr(0x2000));
        assert!(!r.contains_addr(0x0FFF));
    }
}
