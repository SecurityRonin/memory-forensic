//! Kdump (makedumpfile / diskdump) format provider.
//!
//! Parses kdump files with `KDUMP   ` or `DISKDUMP` header signatures.
//! Uses lazy page decompression with an LRU cache for random-access reads.
//! Supports zlib (flate2), snappy (snap), zstd (ruzstd), and uncompressed pages.
//! LZO decompression is deferred with a clear error message.

use std::path::Path;

use crate::{DumpMetadata, Error, FormatPlugin, PhysicalMemoryProvider, PhysicalRange, Result};

/// Kdump format provider with lazy decompression and LRU cache.
pub struct KdumpProvider {
    _placeholder: (),
}

impl KdumpProvider {
    /// Parse a kdump file from an in-memory byte slice.
    pub fn from_bytes(_bytes: &[u8]) -> Result<Self> {
        todo!("KdumpProvider::from_bytes")
    }

    /// Parse a kdump file from a file path.
    pub fn from_path(_path: &Path) -> Result<Self> {
        todo!("KdumpProvider::from_path")
    }
}

impl PhysicalMemoryProvider for KdumpProvider {
    fn read_phys(&self, _addr: u64, _buf: &mut [u8]) -> Result<usize> {
        todo!("KdumpProvider::read_phys")
    }

    fn ranges(&self) -> &[PhysicalRange] {
        todo!("KdumpProvider::ranges")
    }

    fn format_name(&self) -> &str {
        "kdump"
    }

    fn metadata(&self) -> Option<DumpMetadata> {
        todo!("KdumpProvider::metadata")
    }
}

/// Format plugin for kdump files.
pub struct KdumpPlugin;

impl FormatPlugin for KdumpPlugin {
    fn name(&self) -> &str {
        "kdump"
    }

    fn probe(&self, _header: &[u8]) -> u8 {
        todo!("KdumpPlugin::probe")
    }

    fn open(&self, _path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>> {
        todo!("KdumpPlugin::open")
    }
}

inventory::submit!(&KdumpPlugin as &dyn FormatPlugin);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_builders::KdumpBuilder;

    #[test]
    fn probe_kdump_signature() {
        let dump = KdumpBuilder::new()
            .add_page(0, &[0xAAu8; 4096])
            .build();
        let plugin = KdumpPlugin;
        assert_eq!(plugin.probe(&dump), 90);
    }

    #[test]
    fn probe_diskdump_signature() {
        // Build a kdump and overwrite signature to "DISKDUMP"
        let mut dump = KdumpBuilder::new()
            .add_page(0, &[0xAAu8; 4096])
            .build();
        dump[0..8].copy_from_slice(b"DISKDUMP");
        let plugin = KdumpPlugin;
        assert_eq!(plugin.probe(&dump), 90);
    }

    #[test]
    fn probe_non_kdump() {
        let zeros = vec![0u8; 4096];
        let plugin = KdumpPlugin;
        assert_eq!(plugin.probe(&zeros), 0);
    }

    #[test]
    fn probe_short_header_returns_zero() {
        let plugin = KdumpPlugin;
        // Less than 8 bytes
        assert_eq!(plugin.probe(&[0u8; 4]), 0);
        // Empty
        assert_eq!(plugin.probe(&[]), 0);
    }

    #[test]
    fn single_page_snappy_read() {
        let mut page = vec![0u8; 4096];
        page[0] = 0xDE;
        page[1] = 0xAD;
        page[2] = 0xBE;
        page[3] = 0xEF;
        let dump = KdumpBuilder::new()
            .compression(0x04)
            .add_page(1, &page)
            .build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();
        let mut buf = [0u8; 4];
        let n = provider.read_phys(4096, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn single_page_zlib_read() {
        let mut page = vec![0u8; 4096];
        page[100] = 0x42;
        page[101] = 0x43;
        let dump = KdumpBuilder::new()
            .compression(0x01)
            .add_page(2, &page)
            .build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();
        let mut buf = [0u8; 2];
        let n = provider.read_phys(2 * 4096 + 100, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0x42, 0x43]);
    }

    #[test]
    fn uncompressed_page_read() {
        let mut page = vec![0u8; 4096];
        page[0] = 0xFF;
        page[4095] = 0x01;
        let dump = KdumpBuilder::new()
            .compression(0x00)
            .add_page(0, &page)
            .build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();
        let mut buf = [0u8; 1];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf, [0xFF]);
        let n = provider.read_phys(4095, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf, [0x01]);
    }

    #[test]
    fn multi_page_read() {
        let mut page_a = vec![0xAAu8; 4096];
        page_a[0] = 0x11;
        let mut page_b = vec![0xBBu8; 4096];
        page_b[0] = 0x22;
        // PFN 2 and PFN 5: gap between them
        let dump = KdumpBuilder::new()
            .add_page(2, &page_a)
            .add_page(5, &page_b)
            .build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();

        let mut buf = [0u8; 1];
        let n = provider.read_phys(2 * 4096, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf, [0x11]);

        let n = provider.read_phys(5 * 4096, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf, [0x22]);
    }

    #[test]
    fn read_gap_returns_zero() {
        let page = vec![0xAAu8; 4096];
        // Only PFN 1 is mapped
        let dump = KdumpBuilder::new().add_page(1, &page).build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();

        // Read PFN 0 (unmapped)
        let mut buf = [0u8; 4];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_empty_buffer() {
        let page = vec![0xAAu8; 4096];
        let dump = KdumpBuilder::new().add_page(0, &page).build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();

        let mut buf = [0u8; 0];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn metadata_extraction() {
        let page = vec![0u8; 4096];
        let dump = KdumpBuilder::new().add_page(0, &page).build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();

        let meta = provider.metadata().expect("should return metadata");
        assert_eq!(meta.dump_type.as_deref(), Some("kdump"));
    }

    #[test]
    fn lru_cache_hit() {
        let mut page = vec![0u8; 4096];
        page[0] = 0xCA;
        page[100] = 0xFE;
        let dump = KdumpBuilder::new().add_page(0, &page).build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();

        // First read: offset 0
        let mut buf = [0u8; 1];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf, [0xCA]);

        // Second read: offset 100 (same page, should hit cache)
        let n = provider.read_phys(100, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf, [0xFE]);
    }

    #[test]
    fn lzo_returns_error() {
        // Build a dump but manually set flags to 0x02 (LZO) in the page_desc.
        // We can't use the builder for LZO, so build snappy then patch the flags.
        let page = vec![0xAAu8; 4096];
        let mut dump = KdumpBuilder::new()
            .compression(0x04)
            .add_page(0, &page)
            .build();

        // Find the page_desc and patch flags from 0x04 to 0x02.
        // page_desc is at desc_start = (2 + 2*bitmap_blocks) * 4096
        // For 1 PFN (max_pfn=1), bitmap needs ceil(1/8)=1 byte, ceil(1/4096)=1 block
        // desc_start = (2 + 2*1) * 4096 = 4 * 4096 = 16384
        let desc_start = 4 * 4096;
        // flags field is at offset 12 within page_desc
        let flags_off = desc_start + 12;
        dump[flags_off..flags_off + 4].copy_from_slice(&0x02u32.to_le_bytes());

        let provider = KdumpProvider::from_bytes(&dump).unwrap();
        let mut buf = [0u8; 4];
        let result = provider.read_phys(0, &mut buf);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("LZO"),
            "error should mention LZO: {err}"
        );
    }

    #[test]
    fn plugin_name() {
        let plugin = KdumpPlugin;
        assert_eq!(plugin.name(), "kdump");
    }

    #[test]
    fn from_path_roundtrip() {
        let mut page = vec![0u8; 4096];
        page[0] = 0x99;
        let dump = KdumpBuilder::new().add_page(0, &page).build();

        let path = std::env::temp_dir().join("memf_test_kdump.bin");
        std::fs::write(&path, &dump).unwrap();

        let provider = KdumpProvider::from_path(&path).unwrap();
        let mut buf = [0u8; 1];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf, [0x99]);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn builder_produces_kdump_signature() {
        let dump = KdumpBuilder::new()
            .add_page(0, &[0u8; 4096])
            .build();
        assert_eq!(&dump[0..8], b"KDUMP   ");
    }
}
