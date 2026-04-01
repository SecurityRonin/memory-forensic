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

/// Check whether a u32 matches one of the known VMware magic values.
fn is_vmware_magic(magic: u32) -> bool {
    matches!(magic, VMSS_MAGIC | VMSN_MAGIC_1 | VMSN_MAGIC_2 | VMSN_MAGIC_3)
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

impl VmwareStateProvider {
    /// Parse a VMware state file from an in-memory byte slice.
    pub fn from_bytes(_bytes: &[u8]) -> Result<Self> {
        todo!()
    }

    /// Parse a VMware state file from a file path.
    pub fn from_path(_path: &Path) -> Result<Self> {
        todo!()
    }
}

impl PhysicalMemoryProvider for VmwareStateProvider {
    fn read_phys(&self, _addr: u64, _buf: &mut [u8]) -> Result<usize> {
        todo!()
    }

    fn ranges(&self) -> &[PhysicalRange] {
        todo!()
    }

    fn format_name(&self) -> &str {
        todo!()
    }

    fn metadata(&self) -> Option<DumpMetadata> {
        todo!()
    }
}

/// FormatPlugin implementation for VMware state files.
pub struct VmwarePlugin;

impl FormatPlugin for VmwarePlugin {
    fn name(&self) -> &str {
        todo!()
    }

    fn probe(&self, _header: &[u8]) -> u8 {
        todo!()
    }

    fn open(&self, _path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>> {
        todo!()
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
