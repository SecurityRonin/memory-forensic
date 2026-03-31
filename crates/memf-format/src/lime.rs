//! LiME (Linux Memory Extractor) dump format provider.
//!
//! Parses the binary format produced by the LiME kernel module:
//! <https://github.com/504ensicsLabs/LiME>

use std::path::Path;

use crate::{Error, FormatPlugin, PhysicalMemoryProvider, PhysicalRange, Result};

const LIME_MAGIC: u32 = 0x4C694D45;
const LIME_VERSION: u32 = 1;
const HEADER_SIZE: usize = 32;

/// A parsed LiME record: physical address range + byte offset into the dump data.
#[derive(Debug)]
struct LimeRecord {
    range: PhysicalRange,
    /// Byte offset into `LimeProvider::data` where this record's payload begins.
    data_offset: usize,
}

/// Provider that exposes physical memory from a LiME dump.
///
/// Stores the raw dump bytes and a pre-parsed record table so that
/// `read_phys` is a simple linear scan with no allocation.
#[derive(Debug)]
pub struct LimeProvider {
    data: Vec<u8>,
    records: Vec<LimeRecord>,
    /// Pre-extracted ranges for the `ranges()` slice return.
    ranges: Vec<PhysicalRange>,
}

impl LimeProvider {
    /// Parse a LiME dump from an in-memory byte slice (used in tests).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        todo!()
    }

    /// Parse a LiME dump from a file path.
    pub fn from_path(path: &Path) -> Result<Self> {
        todo!()
    }
}

/// Parse all LiME records from `data`, returning validated `LimeRecord`s.
fn parse_records(data: &[u8]) -> Result<Vec<LimeRecord>> {
    todo!()
}

impl PhysicalMemoryProvider for LimeProvider {
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

/// FormatPlugin implementation for LiME dumps.
pub struct LimePlugin;

impl FormatPlugin for LimePlugin {
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

inventory::submit!(&LimePlugin as &dyn FormatPlugin);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_builders::LimeBuilder;

    fn parse(bytes: &[u8]) -> Result<LimeProvider> {
        LimeProvider::from_bytes(bytes)
    }

    #[test]
    fn probe_lime_magic() {
        let dump = LimeBuilder::new().add_range(0x1000, &[0u8; 0x1000]).build();
        let plugin = LimePlugin;
        assert_eq!(plugin.probe(&dump), 90);
    }

    #[test]
    fn probe_non_lime() {
        let zeros = vec![0u8; 64];
        let plugin = LimePlugin;
        assert_eq!(plugin.probe(&zeros), 0);
    }

    #[test]
    fn single_range() {
        let data: Vec<u8> = (0u8..=255).collect();
        let dump = LimeBuilder::new().add_range(0x1000, &data).build();
        let provider = parse(&dump).unwrap();

        assert_eq!(provider.ranges().len(), 1);
        assert_eq!(provider.ranges()[0].start, 0x1000);
        assert_eq!(provider.ranges()[0].end, 0x1100); // exclusive: 0x1000 + 256

        assert_eq!(provider.total_size(), 256);
        assert_eq!(provider.format_name(), "LiME");

        let mut buf = [0u8; 4];
        let n = provider.read_phys(0x1000, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf, &[0, 1, 2, 3]);
    }

    #[test]
    fn two_ranges() {
        let data_a = vec![0xAAu8; 0x2000];
        let data_b = vec![0xBBu8; 0x1000];
        let dump = LimeBuilder::new()
            .add_range(0x0000, &data_a)
            .add_range(0x4000, &data_b)
            .build();
        let provider = parse(&dump).unwrap();

        assert_eq!(provider.ranges().len(), 2);
        assert_eq!(provider.total_size(), 0x3000);

        let mut buf = [0u8; 2];

        let n = provider.read_phys(0x0000, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xAA, 0xAA]);

        let n = provider.read_phys(0x4000, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xBB, 0xBB]);
    }

    #[test]
    fn read_gap_returns_zero() {
        let data = vec![0xCCu8; 0x1000];
        let dump = LimeBuilder::new().add_range(0x1000, &data).build();
        let provider = parse(&dump).unwrap();

        // Address 0x0000 is not mapped.
        let mut buf = [0xFFu8; 4];
        let n = provider.read_phys(0x0000, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn corrupt_magic_errors() {
        let mut dump = LimeBuilder::new().add_range(0x1000, &[0u8; 64]).build();
        // Corrupt first byte of the magic.
        dump[0] = 0xFF;
        let err = parse(&dump).unwrap_err();
        assert!(
            matches!(err, Error::Corrupt(_)),
            "expected Corrupt, got {err:?}"
        );
    }

    #[test]
    fn truncated_header_errors() {
        // Only 4 bytes — not enough for a full 32-byte header.
        let truncated = vec![0x45u8, 0x4D, 0x69, 0x4C]; // just the magic bytes
        let err = parse(&truncated).unwrap_err();
        assert!(
            matches!(err, Error::Corrupt(_)),
            "expected Corrupt, got {err:?}"
        );
    }
}
