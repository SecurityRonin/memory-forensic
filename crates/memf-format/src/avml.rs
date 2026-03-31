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
        let blocks = parse_blocks(bytes)?;
        let ranges = blocks.iter().map(|b| b.range.clone()).collect();
        Ok(Self { blocks, ranges })
    }

    /// Parse an AVML v2 dump from a file path.
    pub fn from_path(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes)
    }
}

/// Parse all AVML v2 blocks from `data`, returning validated `AvmlBlock`s.
fn parse_blocks(data: &[u8]) -> Result<Vec<AvmlBlock>> {
    let mut blocks = Vec::new();
    let mut pos = 0usize;

    while pos < data.len() {
        // Need at least a 32-byte header.
        if pos + HEADER_SIZE > data.len() {
            return Err(Error::Corrupt(format!(
                "truncated header at offset {pos:#x}"
            )));
        }

        let magic = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        let version = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap());
        let start = u64::from_le_bytes(data[pos + 8..pos + 16].try_into().unwrap());
        let end = u64::from_le_bytes(data[pos + 16..pos + 24].try_into().unwrap());
        // bytes [24..32] are reserved — ignored.

        if magic != AVML_MAGIC {
            return Err(Error::Corrupt(format!(
                "bad magic {magic:#010x} at offset {pos:#x}"
            )));
        }
        if version != AVML_VERSION {
            return Err(Error::Corrupt(format!(
                "unsupported AVML version {version} at offset {pos:#x}"
            )));
        }
        if start >= end {
            return Err(Error::Corrupt(format!(
                "invalid range start={start:#x} end={end:#x} at offset {pos:#x}"
            )));
        }

        let expected_uncompressed = end - start;

        // Payload starts right after the 32-byte header.
        // We need to find the 8-byte trailer that encodes the uncompressed size.
        // The trailer immediately follows the compressed payload.
        // Strategy: scan forward from pos+HEADER_SIZE to find where the
        // 8-byte u64-LE trailer = expected_uncompressed.  To bound the scan
        // we use the fact that snappy never expands more than ~1/3 past the
        // original, so compressed_len <= expected_uncompressed + overhead.
        // In practice we just look for the trailer at positions where the
        // 8-byte value matches.
        let payload_start = pos + HEADER_SIZE;

        // Upper bound: we won't search more than uncompressed_size + 32 bytes
        // of compressed data (snappy is never larger than input + small overhead).
        let search_end = (payload_start + expected_uncompressed as usize + 64).min(data.len());

        if search_end < payload_start + 8 {
            return Err(Error::Corrupt(format!(
                "block at {pos:#x}: not enough data for trailer"
            )));
        }

        // Find the trailer: last 8 bytes whose LE u64 == expected_uncompressed.
        // We scan backwards from search_end-8 to find it quickly.
        let mut trailer_pos: Option<usize> = None;
        let scan_start = payload_start;
        let scan_end = search_end - 8;

        // Scan forward; multiple matches are unlikely but we want the first
        // one that, when used as the trailer boundary, produces valid Snappy data.
        let mut i = scan_start;
        while i <= scan_end {
            let val = u64::from_le_bytes(data[i..i + 8].try_into().unwrap());
            if val == expected_uncompressed {
                // Try to decompress data[payload_start..i].
                let compressed = &data[payload_start..i];
                let mut decoder = snap::raw::Decoder::new();
                match decoder.decompress_vec(compressed) {
                    Ok(decompressed) if decompressed.len() as u64 == expected_uncompressed => {
                        trailer_pos = Some(i);
                        let range = PhysicalRange { start, end };
                        blocks.push(AvmlBlock {
                            range,
                            data: decompressed,
                        });
                        pos = i + 8; // advance past trailer
                        break;
                    }
                    _ => {
                        // Not a valid trailer at this position; keep scanning.
                        i += 1;
                        continue;
                    }
                }
            }
            i += 1;
        }

        if trailer_pos.is_none() {
            return Err(Error::Corrupt(format!(
                "block at {pos:#x}: could not locate valid Snappy trailer \
                 (expected uncompressed size {expected_uncompressed})"
            )));
        }
    }

    Ok(blocks)
}

impl PhysicalMemoryProvider for AvmlProvider {
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        for block in &self.blocks {
            if block.range.contains_addr(addr) {
                let offset_in_block = (addr - block.range.start) as usize;
                let available = block.data.len().saturating_sub(offset_in_block);
                let to_read = buf.len().min(available);
                buf[..to_read]
                    .copy_from_slice(&block.data[offset_in_block..offset_in_block + to_read]);
                return Ok(to_read);
            }
        }

        // Address not in any mapped block — gap.
        Ok(0)
    }

    fn ranges(&self) -> &[PhysicalRange] {
        &self.ranges
    }

    fn format_name(&self) -> &str {
        "AVML v2"
    }
}

/// FormatPlugin implementation for AVML v2 dumps.
pub struct AvmlPlugin;

impl FormatPlugin for AvmlPlugin {
    fn name(&self) -> &str {
        "AVML v2"
    }

    fn probe(&self, header: &[u8]) -> u8 {
        if header.len() < 8 {
            return 0;
        }
        let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let version = u32::from_le_bytes(header[4..8].try_into().unwrap());
        if magic == AVML_MAGIC && version == AVML_VERSION {
            90
        } else {
            0
        }
    }

    fn open(&self, path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>> {
        Ok(Box::new(AvmlProvider::from_path(path)?))
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
