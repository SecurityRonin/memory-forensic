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
        let elf = goblin::elf::Elf::parse(&data)
            .map_err(|e| Error::Corrupt(format!("ELF parse error: {e}")))?;

        if elf.header.e_type != goblin::elf::header::ET_CORE {
            return Err(Error::Corrupt("not an ELF core dump".into()));
        }

        let mut segments = Vec::new();
        for phdr in &elf.program_headers {
            if phdr.p_type == goblin::elf::program_header::PT_LOAD && phdr.p_filesz > 0 {
                segments.push(LoadSegment {
                    paddr: phdr.p_paddr,
                    file_offset: phdr.p_offset,
                    file_size: phdr.p_filesz,
                });
            }
        }

        segments.sort_by_key(|s| s.paddr);

        let ranges: Vec<PhysicalRange> = segments
            .iter()
            .map(|s| PhysicalRange {
                start: s.paddr,
                end: s.paddr + s.file_size,
            })
            .collect();

        Ok(Self {
            data,
            segments,
            ranges,
        })
    }
}

impl PhysicalMemoryProvider for ElfCoreProvider {
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        for seg in &self.segments {
            let seg_end = seg.paddr + seg.file_size;
            if addr >= seg.paddr && addr < seg_end {
                let offset_in_seg = addr - seg.paddr;
                let available = (seg.file_size - offset_in_seg) as usize;
                let to_read = buf.len().min(available);
                let file_pos = seg.file_offset + offset_in_seg;
                let file_pos_usize = file_pos as usize;
                buf[..to_read]
                    .copy_from_slice(&self.data[file_pos_usize..file_pos_usize + to_read]);
                return Ok(to_read);
            }
        }

        Ok(0)
    }

    fn ranges(&self) -> &[PhysicalRange] {
        &self.ranges
    }

    fn format_name(&self) -> &str {
        "ELF Core"
    }
}

/// Format plugin for ELF core dumps.
struct ElfCorePlugin;

impl FormatPlugin for ElfCorePlugin {
    fn name(&self) -> &str {
        "ELF Core"
    }

    fn probe(&self, header: &[u8]) -> u8 {
        if header.len() < 18 {
            return 0;
        }
        // Check ELF magic
        if header[0..4] != [0x7F, b'E', b'L', b'F'] {
            return 0;
        }
        // Check ET_CORE (e_type at offset 16, little-endian u16)
        let e_type = u16::from_le_bytes([header[16], header[17]]);
        if e_type == 4 {
            90
        } else {
            0
        }
    }

    fn open(&self, path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>> {
        let data = std::fs::read(path)?;
        let provider = ElfCoreProvider::from_bytes(data)?;
        Ok(Box::new(provider))
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

    #[test]
    fn from_path_via_plugin_open() {
        let payload = vec![0xDD; 256];
        let dump = ElfCoreBuilder::new().add_segment(0x3000, &payload).build();
        let path = std::env::temp_dir().join("memf_test_elf_core_from_path.core");
        std::fs::write(&path, &dump).unwrap();
        let plugin = ElfCorePlugin;
        let provider = plugin.open(&path).unwrap();
        assert_eq!(provider.format_name(), "ELF Core");
        assert_eq!(provider.ranges().len(), 1);
        assert_eq!(provider.total_size(), 256);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn plugin_name() {
        let plugin = ElfCorePlugin;
        assert_eq!(plugin.name(), "ELF Core");
    }

    #[test]
    fn probe_too_short_returns_zero() {
        let plugin = ElfCorePlugin;
        assert_eq!(plugin.probe(&[0x7F, b'E', b'L', b'F']), 0); // only 4 bytes, need 18
        assert_eq!(plugin.probe(&[]), 0);
    }

    #[test]
    fn read_phys_empty_buffer() {
        let dump = ElfCoreBuilder::new()
            .add_segment(0x1000, &[0xAA; 128])
            .build();
        let provider = ElfCoreProvider::from_bytes(dump).unwrap();
        let mut buf = [];
        let n = provider.read_phys(0x1000, &mut buf).unwrap();
        assert_eq!(n, 0);
    }
}
