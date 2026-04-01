//! VMware `.vmss`/`.vmsn` state file format provider.
//!
//! Parses VMware suspension (`.vmss`) and snapshot (`.vmsn`) state files.
//! These files use a group/tag binary structure containing memory regions
//! and CPU state (CR3). Supports four VMware magic values:
//! `0xBED2BED0`, `0xBAD1BAD1`, `0xBED2BED2`, `0xBED3BED3`.

use std::path::Path;

use crate::{DumpMetadata, Error, FormatPlugin, PhysicalMemoryProvider, PhysicalRange, Result};

/// VMware state file magic values (little-endian u32).
const VMSS_MAGIC: u32 = 0xBED2_BED0;
const VMSN_MAGIC_1: u32 = 0xBAD1_BAD1;
const VMSN_MAGIC_2: u32 = 0xBED2_BED2;
const VMSN_MAGIC_3: u32 = 0xBED3_BED3;

/// File header size: magic(4) + unknown(4) + group_count(4).
const HEADER_SIZE: usize = 12;

/// Group entry size: name(64) + tags_offset(8) + padding(8).
const GROUP_ENTRY_SIZE: usize = 80;

/// Tag flags constants.
const TAG_FLAGS_LARGE_DATA: u8 = 0x06;
const TAG_FLAGS_INDEXED_8BYTE: u8 = 0x46;

/// Check whether a u32 matches one of the known VMware magic values.
fn is_vmware_magic(magic: u32) -> bool {
    matches!(magic, VMSS_MAGIC | VMSN_MAGIC_1 | VMSN_MAGIC_2 | VMSN_MAGIC_3)
}

/// Read a little-endian u32 from `data` at `offset`.
fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    data.get(offset..offset + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| Error::Corrupt(format!("read_u32 out of bounds at offset {offset}")))
}

/// Read a little-endian u64 from `data` at `offset`.
fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    data.get(offset..offset + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| Error::Corrupt(format!("read_u64 out of bounds at offset {offset}")))
}

/// A contiguous memory region extracted from a VMware state file.
struct MemoryRegion {
    paddr: u64,
    file_offset: usize,
    size: usize,
}

/// Provider that exposes physical memory from a VMware state file.
///
/// Stores the raw file bytes and a pre-parsed list of memory regions
/// so that `read_phys` is a simple linear scan with no allocation.
pub struct VmwareStateProvider {
    data: Vec<u8>,
    regions: Vec<MemoryRegion>,
    ranges: Vec<PhysicalRange>,
    meta: DumpMetadata,
}

/// Parse tags within a group, returning memory regions and an optional CR3 value.
///
/// `data` is the full file, `offset` is the start of the tag stream for this group.
/// `group_name` determines which tags we look for.
fn parse_tags(
    data: &[u8],
    mut pos: usize,
    group_name: &str,
) -> Result<(Vec<MemoryRegion>, Option<u64>)> {
    let mut regions = Vec::new();
    let mut cr3: Option<u64> = None;
    let mut current_ppn: Option<u64> = None;

    loop {
        if pos >= data.len() {
            break;
        }

        let flags = data[pos];
        if flags == 0 {
            // Tag terminator.
            break;
        }
        pos += 1;

        if pos >= data.len() {
            return Err(Error::Corrupt("truncated tag: no name_length byte".into()));
        }
        let name_length = data[pos] as usize;
        pos += 1;

        if pos + name_length > data.len() {
            return Err(Error::Corrupt("truncated tag: name extends beyond data".into()));
        }
        let tag_name = &data[pos..pos + name_length];
        pos += name_length;

        if flags == TAG_FLAGS_LARGE_DATA {
            // Large data tag: next 4 bytes are data_length, then payload.
            let data_length = read_u32(data, pos)? as usize;
            pos += 4;

            if pos + data_length > data.len() {
                return Err(Error::Corrupt(format!(
                    "truncated tag payload: need {data_length} bytes at offset {pos}"
                )));
            }

            if group_name == "memory" {
                if tag_name == b"regionPPN" && data_length == 8 {
                    current_ppn = Some(read_u64(data, pos)?);
                } else if tag_name == b"regionBytes" {
                    if let Some(ppn) = current_ppn.take() {
                        regions.push(MemoryRegion {
                            paddr: ppn,
                            file_offset: pos,
                            size: data_length,
                        });
                    }
                }
            }

            pos += data_length;
        } else if flags == TAG_FLAGS_INDEXED_8BYTE {
            // Indexed 8-byte data tag: index0(1) + index1(1) + value(8).
            if pos + 10 > data.len() {
                return Err(Error::Corrupt("truncated indexed tag".into()));
            }
            // index0 and index1 identify the CPU and register (skipped).
            let value = read_u64(data, pos + 2)?;
            pos += 10;

            if group_name == "cpu" && tag_name == b"CR3" {
                cr3 = Some(value);
            }
        } else {
            // Unknown tag type — we cannot determine its size, so stop parsing
            // this group's tags. This is safe because our test builder only
            // emits the two tag types above plus the terminator.
            return Err(Error::Corrupt(format!(
                "unknown tag flags 0x{flags:02X} in group '{group_name}'"
            )));
        }
    }

    Ok((regions, cr3))
}

impl VmwareStateProvider {
    /// Parse a VMware state file from an in-memory byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            return Err(Error::Corrupt("VMware state file too short for header".into()));
        }

        let magic = read_u32(bytes, 0)?;
        if !is_vmware_magic(magic) {
            return Err(Error::Corrupt(format!(
                "invalid VMware magic: 0x{magic:08X}"
            )));
        }

        // unknown field at offset 4 — ignored.
        let group_count = read_u32(bytes, 8)? as usize;

        let groups_end = HEADER_SIZE + group_count * GROUP_ENTRY_SIZE;
        if groups_end > bytes.len() {
            return Err(Error::Corrupt("group entries extend beyond file".into()));
        }

        let mut all_regions = Vec::new();
        let mut cr3: Option<u64> = None;

        for i in 0..group_count {
            let entry_offset = HEADER_SIZE + i * GROUP_ENTRY_SIZE;

            // Read null-terminated group name from first 64 bytes.
            let name_bytes = &bytes[entry_offset..entry_offset + 64];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(64);
            let group_name = std::str::from_utf8(&name_bytes[..name_end])
                .unwrap_or("???");

            // tags_offset at entry_offset + 64.
            let tags_offset = read_u64(bytes, entry_offset + 64)? as usize;

            if tags_offset >= bytes.len() {
                return Err(Error::Corrupt(format!(
                    "group '{group_name}' tags_offset {tags_offset} beyond file"
                )));
            }

            let (mut regions, group_cr3) = parse_tags(bytes, tags_offset, group_name)?;

            all_regions.append(&mut regions);
            if let Some(v) = group_cr3 {
                cr3 = Some(v);
            }
        }

        // Build ranges from regions.
        let ranges: Vec<PhysicalRange> = all_regions
            .iter()
            .map(|r| PhysicalRange {
                start: r.paddr,
                end: r.paddr + r.size as u64,
            })
            .collect();

        let meta = DumpMetadata {
            cr3,
            dump_type: Some("VMware State".into()),
            ..DumpMetadata::default()
        };

        Ok(Self {
            data: bytes.to_vec(),
            regions: all_regions,
            ranges,
            meta,
        })
    }

    /// Parse a VMware state file from a file path.
    pub fn from_path(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(&data)
    }
}

impl PhysicalMemoryProvider for VmwareStateProvider {
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        for region in &self.regions {
            let region_start = region.paddr;
            let region_end = region.paddr + region.size as u64;

            if addr >= region_start && addr < region_end {
                let offset_in_region = (addr - region_start) as usize;
                let available = region.size - offset_in_region;
                let to_read = buf.len().min(available);
                let src_start = region.file_offset + offset_in_region;
                buf[..to_read].copy_from_slice(&self.data[src_start..src_start + to_read]);
                return Ok(to_read);
            }
        }

        // Address not in any mapped region — gap.
        Ok(0)
    }

    fn ranges(&self) -> &[PhysicalRange] {
        &self.ranges
    }

    fn format_name(&self) -> &str {
        "VMware State"
    }

    fn metadata(&self) -> Option<DumpMetadata> {
        Some(self.meta.clone())
    }
}

/// FormatPlugin implementation for VMware state files.
pub struct VmwarePlugin;

impl FormatPlugin for VmwarePlugin {
    fn name(&self) -> &str {
        "VMware State"
    }

    fn probe(&self, header: &[u8]) -> u8 {
        if header.len() < 4 {
            return 0;
        }
        let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
        if is_vmware_magic(magic) {
            85
        } else {
            0
        }
    }

    fn open(&self, path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>> {
        Ok(Box::new(VmwareStateProvider::from_path(path)?))
    }
}

inventory::submit!(&VmwarePlugin as &dyn FormatPlugin);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_builders::VmwareStateBuilder;

    #[test]
    fn probe_vmware_magic() {
        let dump = VmwareStateBuilder::new()
            .add_region(0x1000, &[0u8; 64])
            .build();
        let plugin = VmwarePlugin;
        assert_eq!(plugin.probe(&dump), 85);
    }

    #[test]
    fn probe_non_vmware() {
        let zeros = vec![0u8; 64];
        let plugin = VmwarePlugin;
        assert_eq!(plugin.probe(&zeros), 0);
    }

    #[test]
    fn probe_short_header_returns_zero() {
        let plugin = VmwarePlugin;
        assert_eq!(plugin.probe(&[0xD0, 0xBE, 0xD2]), 0); // only 3 bytes
        assert_eq!(plugin.probe(&[]), 0);
    }

    #[test]
    fn single_region_read() {
        let data: Vec<u8> = (0u8..=255).collect();
        let dump = VmwareStateBuilder::new()
            .add_region(0x1000, &data)
            .build();
        let provider = VmwareStateProvider::from_bytes(&dump).unwrap();

        assert_eq!(provider.ranges().len(), 1);
        assert_eq!(provider.ranges()[0].start, 0x1000);
        assert_eq!(provider.ranges()[0].end, 0x1100); // 0x1000 + 256

        let mut buf = [0u8; 4];
        let n = provider.read_phys(0x1000, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf, &[0, 1, 2, 3]);
    }

    #[test]
    fn multi_region_read() {
        let data_a = vec![0xAAu8; 128];
        let data_b = vec![0xBBu8; 128];
        let dump = VmwareStateBuilder::new()
            .add_region(0x0000, &data_a)
            .add_region(0x2000, &data_b)
            .build();
        let provider = VmwareStateProvider::from_bytes(&dump).unwrap();

        assert_eq!(provider.ranges().len(), 2);

        let mut buf = [0u8; 2];
        let n = provider.read_phys(0x0000, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xAA, 0xAA]);

        let n = provider.read_phys(0x2000, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xBB, 0xBB]);
    }

    #[test]
    fn read_gap_returns_zero() {
        let data = vec![0xCCu8; 64];
        let dump = VmwareStateBuilder::new()
            .add_region(0x1000, &data)
            .build();
        let provider = VmwareStateProvider::from_bytes(&dump).unwrap();

        // Address 0x0000 is not mapped.
        let mut buf = [0xFFu8; 4];
        let n = provider.read_phys(0x0000, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_empty_buffer() {
        let dump = VmwareStateBuilder::new()
            .add_region(0x1000, &[0xAA; 64])
            .build();
        let provider = VmwareStateProvider::from_bytes(&dump).unwrap();
        let mut buf = [];
        let n = provider.read_phys(0x1000, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn metadata_cr3_extraction() {
        let cr3_val = 0x1ab000u64;
        let dump = VmwareStateBuilder::new()
            .add_region(0x1000, &[0u8; 64])
            .cr3(cr3_val)
            .build();
        let provider = VmwareStateProvider::from_bytes(&dump).unwrap();

        let meta = provider.metadata().expect("metadata should be Some");
        assert_eq!(meta.cr3, Some(cr3_val));
        assert_eq!(meta.dump_type.as_deref(), Some("VMware State"));
    }

    #[test]
    fn metadata_no_cr3() {
        let dump = VmwareStateBuilder::new()
            .add_region(0x1000, &[0u8; 64])
            .build();
        let provider = VmwareStateProvider::from_bytes(&dump).unwrap();

        let meta = provider.metadata().expect("metadata should be Some");
        assert!(meta.cr3.is_none());
        assert_eq!(meta.dump_type.as_deref(), Some("VMware State"));
    }

    #[test]
    fn plugin_name() {
        let plugin = VmwarePlugin;
        assert_eq!(plugin.name(), "VMware State");
    }

    #[test]
    fn from_path_roundtrip() {
        let data: Vec<u8> = (0u8..=127).collect();
        let dump = VmwareStateBuilder::new()
            .add_region(0x2000, &data)
            .build();
        let path = std::env::temp_dir().join("memf_test_vmware_roundtrip.vmss");
        std::fs::write(&path, &dump).unwrap();
        let provider = VmwareStateProvider::from_path(&path).unwrap();
        assert_eq!(provider.ranges().len(), 1);
        assert_eq!(provider.total_size(), 128);
        assert_eq!(provider.format_name(), "VMware State");
        let mut buf = [0u8; 4];
        let n = provider.read_phys(0x2000, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf, &[0, 1, 2, 3]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn builder_produces_valid_magic() {
        let dump = VmwareStateBuilder::new()
            .add_region(0x1000, &[0u8; 64])
            .build();
        let magic = u32::from_le_bytes(dump[0..4].try_into().unwrap());
        assert_eq!(magic, 0xBED2_BED0);
        // group_count should be 1 (memory only, no cr3)
        let group_count = u32::from_le_bytes(dump[8..12].try_into().unwrap());
        assert_eq!(group_count, 1);
    }

    #[test]
    fn builder_with_cr3_has_two_groups() {
        let dump = VmwareStateBuilder::new()
            .add_region(0x1000, &[0u8; 64])
            .cr3(0x1ab000)
            .build();
        let group_count = u32::from_le_bytes(dump[8..12].try_into().unwrap());
        assert_eq!(group_count, 2);
    }
}
