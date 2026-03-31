//! ELF core dump format provider.
//!
//! Parses ELF core dumps (ET_CORE) and exposes PT_LOAD segments as physical
//! memory ranges. This covers Linux kernel crash dumps (makedumpfile, QEMU).

use std::path::Path;

use crate::{Error, FormatPlugin, PhysicalMemoryProvider, PhysicalRange, Result};

/// A segment from an ELF core's PT_LOAD program header.
#[derive(Debug, Clone)]
struct LoadSegment {
    /// Physical address (p_paddr).
    paddr: u64,
    /// File offset where data begins (p_offset).
    file_offset: u64,
    /// Size in the file (p_filesz).
    file_size: u64,
}

/// Physical memory provider backed by an ELF core dump.
pub struct ElfCoreProvider {
    data: Vec<u8>,
    segments: Vec<LoadSegment>,
    ranges: Vec<PhysicalRange>,
}

impl ElfCoreProvider {
    /// Parse an ELF core dump from a byte slice.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        todo!()
    }
}

impl PhysicalMemoryProvider for ElfCoreProvider {
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

/// Format plugin for ELF core dumps.
struct ElfCorePlugin;

impl FormatPlugin for ElfCorePlugin {
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

inventory::submit!(&ElfCorePlugin as &dyn FormatPlugin);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_builders::ElfCoreBuilder;

    #[test]
    fn probe_elf_core() {
        let dump = ElfCoreBuilder::new()
            .add_segment(0x1000, &[0xAA; 128])
            .build();
        let plugin = ElfCorePlugin;
        assert_eq!(plugin.probe(&dump[..64.min(dump.len())]), 90);
    }

    #[test]
    fn probe_non_core_elf() {
        // Build an ELF header with ET_EXEC (2) instead of ET_CORE (4)
        let mut header = vec![0u8; 64];
        header[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        header[4] = 2; // ELFCLASS64
        header[5] = 1; // ELFDATA2LSB
        header[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        let plugin = ElfCorePlugin;
        assert_eq!(plugin.probe(&header), 0);
    }

    #[test]
    fn probe_non_elf() {
        let data = vec![0u8; 128];
        let plugin = ElfCorePlugin;
        assert_eq!(plugin.probe(&data), 0);
    }

    #[test]
    fn single_segment() {
        let payload = vec![0xBB; 256];
        let dump = ElfCoreBuilder::new().add_segment(0x1000, &payload).build();
        let provider = ElfCoreProvider::from_bytes(dump).unwrap();

        assert_eq!(provider.format_name(), "ELF Core");
        assert_eq!(provider.ranges().len(), 1);
        assert_eq!(provider.ranges()[0].start, 0x1000);
        assert_eq!(provider.ranges()[0].end, 0x1000 + 256);

        let mut buf = [0u8; 8];
        let n = provider.read_phys(0x1000, &mut buf).unwrap();
        assert_eq!(n, 8);
        assert_eq!(buf, [0xBB; 8]);
    }

    #[test]
    fn two_segments() {
        let dump = ElfCoreBuilder::new()
            .add_segment(0x1000, &[0xAA; 128])
            .add_segment(0x5000, &[0xCC; 256])
            .build();
        let provider = ElfCoreProvider::from_bytes(dump).unwrap();

        assert_eq!(provider.ranges().len(), 2);
        assert_eq!(provider.total_size(), 128 + 256);

        let mut buf = [0u8; 4];
        let n = provider.read_phys(0x5000, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [0xCC; 4]);
    }

    #[test]
    fn read_gap_returns_zero() {
        let dump = ElfCoreBuilder::new()
            .add_segment(0x1000, &[0xAA; 128])
            .build();
        let provider = ElfCoreProvider::from_bytes(dump).unwrap();

        let mut buf = [0xFF; 8];
        let n = provider.read_phys(0x9000, &mut buf).unwrap();
        assert_eq!(n, 0);
        // buf should be unchanged since nothing was read
        assert_eq!(buf, [0xFF; 8]);
    }
}
