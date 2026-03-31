//! AVML v2 dump format provider.
//!
//! Parses the binary format produced by AVML (Acquisition of Volatile Memory for Linux):
//! <https://github.com/microsoft/avml>

use std::path::Path;

use crate::{Error, FormatPlugin, PhysicalMemoryProvider, PhysicalRange, Result};

const AVML_MAGIC: u32 = 0x4C4D5641;
const AVML_VERSION: u32 = 2;
const HEADER_SIZE: usize = 32;

/// A parsed AVML block: physical address range + decompressed payload bytes.
#[derive(Debug)]
struct AvmlBlock {
    range: PhysicalRange,
    /// Decompressed payload bytes for this block.
    data: Vec<u8>,
}

/// Provider that exposes physical memory from an AVML v2 dump.
///
/// Each block is fully decompressed on construction so that `read_phys`
/// requires no allocation at query time.
#[derive(Debug)]
pub struct AvmlProvider {
    blocks: Vec<AvmlBlock>,
    /// Pre-extracted ranges for the `ranges()` slice return.
    ranges: Vec<PhysicalRange>,
}

impl AvmlProvider {
    /// Parse an AVML v2 dump from an in-memory byte slice (used in tests).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        todo!()
    }

    /// Parse an AVML v2 dump from a file path.
    pub fn from_path(path: &Path) -> Result<Self> {
        todo!()
    }
}

/// Parse all AVML v2 blocks from `data`, returning validated `AvmlBlock`s.
fn parse_blocks(data: &[u8]) -> Result<Vec<AvmlBlock>> {
    todo!()
}

impl PhysicalMemoryProvider for AvmlProvider {
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

/// FormatPlugin implementation for AVML v2 dumps.
pub struct AvmlPlugin;

impl FormatPlugin for AvmlPlugin {
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

inventory::submit!(&AvmlPlugin as &dyn FormatPlugin);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_builders::AvmlBuilder;

    // ---------------------------------------------------------------------------
    // Test 1: probe returns 90 for valid AVML magic + version=2
    // ---------------------------------------------------------------------------
    #[test]
    fn probe_avml_magic() {
        let data = AvmlBuilder::new().add_range(0x1000, &[0u8; 64]).build();
        let plugin = AvmlPlugin;
        assert_eq!(plugin.probe(&data), 90);
    }

    // ---------------------------------------------------------------------------
    // Test 2: probe returns 0 for non-AVML bytes
    // ---------------------------------------------------------------------------
    #[test]
    fn probe_non_avml() {
        let data = vec![0u8; 64];
        let plugin = AvmlPlugin;
        assert_eq!(plugin.probe(&data), 0);
    }

    // ---------------------------------------------------------------------------
    // Test 3: single range round-trip
    // ---------------------------------------------------------------------------
    #[test]
    fn single_range_roundtrip() {
        let payload: Vec<u8> = (0u8..=255).collect();
        let dump = AvmlBuilder::new().add_range(0x1000, &payload).build();

        let provider = AvmlProvider::from_bytes(&dump).expect("parse");

        // ranges
        let ranges = provider.ranges();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, 0x1000);
        assert_eq!(ranges[0].end, 0x1000 + 256);

        // total_size
        assert_eq!(provider.total_size(), 256);

        // format_name
        assert_eq!(provider.format_name(), "AVML v2");

        // read_phys — full range
        let mut buf = vec![0u8; 256];
        let n = provider.read_phys(0x1000, &mut buf).expect("read");
        assert_eq!(n, 256);
        assert_eq!(buf, payload);

        // read_phys — mid-range
        let mut buf2 = vec![0u8; 4];
        let n2 = provider.read_phys(0x1010, &mut buf2).expect("read mid");
        assert_eq!(n2, 4);
        assert_eq!(buf2, &payload[0x10..0x14]);
    }

    // ---------------------------------------------------------------------------
    // Test 4: two ranges round-trip
    // ---------------------------------------------------------------------------
    #[test]
    fn two_ranges_roundtrip() {
        let data_a = vec![0xAAu8; 256];
        let data_b = vec![0xBBu8; 256];
        let dump = AvmlBuilder::new()
            .add_range(0x0000, &data_a)
            .add_range(0x1000, &data_b)
            .build();

        let provider = AvmlProvider::from_bytes(&dump).expect("parse");

        let ranges = provider.ranges();
        assert_eq!(ranges.len(), 2);
        assert_eq!(
            ranges[0],
            PhysicalRange {
                start: 0x0000,
                end: 0x0100
            }
        );
        assert_eq!(
            ranges[1],
            PhysicalRange {
                start: 0x1000,
                end: 0x1100
            }
        );
        assert_eq!(provider.total_size(), 512);

        let mut buf = vec![0u8; 256];
        let n = provider.read_phys(0x0000, &mut buf).expect("read a");
        assert_eq!(n, 256);
        assert_eq!(buf, data_a);

        let n = provider.read_phys(0x1000, &mut buf).expect("read b");
        assert_eq!(n, 256);
        assert_eq!(buf, data_b);
    }

    // ---------------------------------------------------------------------------
    // Test 5: reading an unmapped address returns 0 bytes written (gap)
    // ---------------------------------------------------------------------------
    #[test]
    fn gap_returns_zero() {
        let dump = AvmlBuilder::new().add_range(0x1000, &[0xCCu8; 256]).build();

        let provider = AvmlProvider::from_bytes(&dump).expect("parse");

        let mut buf = vec![0u8; 64];
        let n = provider.read_phys(0x5000, &mut buf).expect("read gap");
        assert_eq!(n, 0);
    }
}
