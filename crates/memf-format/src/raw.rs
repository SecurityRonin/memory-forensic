//! Raw (contiguous) memory dump format provider.
//!
//! The simplest possible format: a flat byte array representing contiguous
//! physical memory starting at address 0.

use std::path::Path;

use crate::{FormatPlugin, PhysicalMemoryProvider, PhysicalRange, Result};

/// Provider that exposes physical memory from a raw (flat) dump.
///
/// The entire file is treated as a single range `[0, data.len())`.
#[derive(Debug)]
pub struct RawProvider {
    data: Vec<u8>,
    /// Pre-extracted ranges for the `ranges()` slice return.
    ranges: Vec<PhysicalRange>,
}

impl RawProvider {
    /// Construct a `RawProvider` from an in-memory byte slice (infallible).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        todo!()
    }

    /// Construct a `RawProvider` by reading a file from the given path.
    pub fn from_path(path: &Path) -> Result<Self> {
        todo!()
    }
}

impl PhysicalMemoryProvider for RawProvider {
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        todo!()
    }

    fn ranges(&self) -> &[PhysicalRange] {
        todo!()
    }

    fn format_name(&self) -> &str {
        todo!()
    }
}

/// FormatPlugin implementation for raw (flat) dumps.
///
/// This is the lowest-confidence fallback: any non-empty file can be treated
/// as a raw dump, so the probe returns 5 (not 0) for non-empty files.
pub struct RawPlugin;

impl FormatPlugin for RawPlugin {
    fn name(&self) -> &str {
        todo!()
    }

    fn probe(&self, header: &[u8]) -> u8 {
        todo!()
    }

    fn open(&self, path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>> {
        todo!()
    }
}

inventory::submit!(&RawPlugin as &dyn FormatPlugin);

#[cfg(test)]
mod tests {
    use super::*;

    // Test 1: probe returns 5 for non-empty, 0 for empty.
    #[test]
    fn probe_confidence() {
        let plugin = RawPlugin;
        assert_eq!(plugin.probe(&[0u8; 64]), 5);
        assert_eq!(plugin.probe(&[]), 0);
    }

    // Test 2: basic read from start.
    #[test]
    fn read_from_start() {
        let data: Vec<u8> = (0u8..=255).collect();
        let provider = RawProvider::from_bytes(&data);

        assert_eq!(provider.ranges().len(), 1);
        assert_eq!(provider.ranges()[0].start, 0);
        assert_eq!(provider.ranges()[0].end, 256);
        assert_eq!(provider.total_size(), 256);

        let mut buf = [0u8; 4];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf, &[0, 1, 2, 3]);
    }

    // Test 3: reading past end returns 0.
    #[test]
    fn read_past_end() {
        let data = vec![0xFFu8; 64];
        let provider = RawProvider::from_bytes(&data);

        let mut buf = [0u8; 4];
        let n = provider.read_phys(64, &mut buf).unwrap();
        assert_eq!(n, 0);

        let n2 = provider.read_phys(1000, &mut buf).unwrap();
        assert_eq!(n2, 0);
    }

    // Test 4: partial read when buffer extends past end.
    #[test]
    fn read_partial() {
        let data = vec![0xABu8; 10];
        let provider = RawProvider::from_bytes(&data);

        let mut buf = [0u8; 8];
        let n = provider.read_phys(6, &mut buf).unwrap();
        assert_eq!(n, 4); // only 4 bytes remain (10 - 6)
        assert_eq!(&buf[..4], &[0xABu8; 4]);
    }

    // Test 5: empty dump has no ranges and total_size 0.
    #[test]
    fn empty_dump() {
        let provider = RawProvider::from_bytes(&[]);
        assert_eq!(provider.ranges().len(), 0);
        assert_eq!(provider.total_size(), 0);
    }
}
