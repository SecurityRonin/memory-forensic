//! Windows crash dump (`.dmp`) format provider.
//!
//! Parses 64-bit Windows crash dumps with `_DUMP_HEADER64`.
//! Supports run-based (DumpType 0x01) and bitmap (0x02/0x05) layouts.

#[cfg(test)]
mod tests {
    use crate::test_builders::CrashDumpBuilder;
    use crate::{Error, MachineType, PhysicalMemoryProvider};

    use super::{CrashDumpPlugin, CrashDumpProvider};
    use crate::FormatPlugin;

    const PAGE: usize = 4096;

    #[test]
    fn probe_crashdump_magic() {
        let dump = CrashDumpBuilder::new().add_run(0, &[0xAA; PAGE]).build();
        let plugin = CrashDumpPlugin;
        assert_eq!(plugin.probe(&dump), 95);
    }

    #[test]
    fn probe_non_crashdump() {
        let zeros = vec![0u8; 64];
        let plugin = CrashDumpPlugin;
        assert_eq!(plugin.probe(&zeros), 0);
    }

    #[test]
    fn probe_short_header_returns_zero() {
        let plugin = CrashDumpPlugin;
        assert_eq!(plugin.probe(&[0x50, 0x41, 0x47, 0x45, 0x44, 0x55, 0x36]), 0); // 7 bytes
        assert_eq!(plugin.probe(&[]), 0);
    }

    #[test]
    fn single_run_read() {
        let mut page_data = vec![0u8; PAGE];
        page_data[0] = 0xDE;
        page_data[1] = 0xAD;
        page_data[2] = 0xBE;
        page_data[3] = 0xEF;
        let dump = CrashDumpBuilder::new().add_run(0, &page_data).build();
        let provider = CrashDumpProvider::from_bytes(&dump).unwrap();
        let mut buf = [0u8; 4];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn multi_run_read() {
        // Run 0: PFN 0 (1 page), Run 1: PFN 4 (1 page), gap at PFN 1-3.
        let page_a = vec![0xAAu8; PAGE];
        let page_b = vec![0xBBu8; PAGE];
        let dump = CrashDumpBuilder::new()
            .add_run(0, &page_a)
            .add_run(4, &page_b)
            .build();
        let provider = CrashDumpProvider::from_bytes(&dump).unwrap();

        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xAA, 0xAA]);

        let n = provider.read_phys(4 * PAGE as u64, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xBB, 0xBB]);
    }

    #[test]
    fn read_gap_returns_zero() {
        let page_data = vec![0xCCu8; PAGE];
        let dump = CrashDumpBuilder::new().add_run(2, &page_data).build();
        let provider = CrashDumpProvider::from_bytes(&dump).unwrap();

        // PFN 0 is not mapped (run starts at PFN 2).
        let mut buf = [0xFFu8; 4];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_empty_buffer() {
        let page_data = vec![0xAAu8; PAGE];
        let dump = CrashDumpBuilder::new().add_run(0, &page_data).build();
        let provider = CrashDumpProvider::from_bytes(&dump).unwrap();
        let mut buf = [];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn metadata_extraction() {
        let dump = CrashDumpBuilder::new()
            .cr3(0x0018_7000)
            .machine_type(0x8664)
            .num_processors(4)
            .dump_type(0x01)
            .ps_active_process_head(0xFFFFF802_1A2B3C40)
            .ps_loaded_module_list(0xFFFFF802_1A2B3D60)
            .kd_debugger_data_block(0xFFFFF802_1A000000)
            .system_time(0x01DA_5678_9ABC_DEF0)
            .add_run(0, &[0u8; PAGE])
            .build();
        let provider = CrashDumpProvider::from_bytes(&dump).unwrap();
        let meta = provider.metadata().expect("metadata should be Some");
        assert_eq!(meta.cr3, Some(0x0018_7000));
        assert_eq!(meta.machine_type, Some(MachineType::Amd64));
        assert_eq!(meta.num_processors, Some(4));
        assert_eq!(meta.dump_type.as_deref(), Some("Full"));
        assert_eq!(
            meta.ps_active_process_head,
            Some(0xFFFFF802_1A2B3C40)
        );
        assert_eq!(
            meta.ps_loaded_module_list,
            Some(0xFFFFF802_1A2B3D60)
        );
        assert_eq!(
            meta.kd_debugger_data_block,
            Some(0xFFFFF802_1A000000)
        );
        assert_eq!(meta.system_time, Some(0x01DA_5678_9ABC_DEF0));
    }

    #[test]
    fn plugin_name() {
        let plugin = CrashDumpPlugin;
        assert_eq!(plugin.name(), "Windows Crash Dump");
    }

    #[test]
    fn builder_produces_valid_header() {
        let dump = CrashDumpBuilder::new().add_run(0, &[0u8; PAGE]).build();
        // Check PAGE magic at 0x000
        let magic = u32::from_le_bytes(dump[0..4].try_into().unwrap());
        assert_eq!(magic, 0x4547_4150);
        // Check DU64 signature at 0x004
        let sig = u32::from_le_bytes(dump[4..8].try_into().unwrap());
        assert_eq!(sig, 0x3436_5544);
        // Data starts at 0x2000 (8192)
        assert!(dump.len() >= 0x2000 + PAGE);
    }

    #[test]
    fn bitmap_single_page_read() {
        let mut page_data = vec![0u8; PAGE];
        page_data[0] = 0x42;
        page_data[1] = 0x4D;
        let dump = CrashDumpBuilder::new()
            .dump_type(0x05)
            .add_run(0, &page_data)
            .build();
        let provider = CrashDumpProvider::from_bytes(&dump).unwrap();
        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0x42, 0x4D]);
    }

    #[test]
    fn bitmap_multi_run_with_gap() {
        let page_a = vec![0xAAu8; PAGE];
        let page_b = vec![0xBBu8; PAGE];
        let dump = CrashDumpBuilder::new()
            .dump_type(0x05)
            .add_run(0, &page_a)
            .add_run(4, &page_b)
            .build();
        let provider = CrashDumpProvider::from_bytes(&dump).unwrap();

        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xAA, 0xAA]);

        let n = provider.read_phys(4 * PAGE as u64, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xBB, 0xBB]);

        // Gap at PFN 1-3 returns 0
        let n = provider.read_phys(PAGE as u64, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn bitmap_popcount_correctness() {
        // 3 contiguous pages at PFN 2, 3, 4 with DumpType 0x02.
        let mut data = vec![0u8; PAGE * 3];
        // Page 0 (PFN 2): fill with 0x11
        data[0..PAGE].fill(0x11);
        // Page 1 (PFN 3): fill with 0x22
        data[PAGE..PAGE * 2].fill(0x22);
        // Page 2 (PFN 4): fill with 0x33
        data[PAGE * 2..PAGE * 3].fill(0x33);
        let dump = CrashDumpBuilder::new()
            .dump_type(0x02)
            .add_run(2, &data)
            .build();
        let provider = CrashDumpProvider::from_bytes(&dump).unwrap();

        let mut buf = [0u8; 1];
        // PFN 2
        let n = provider.read_phys(2 * PAGE as u64, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x11);
        // PFN 3
        let n = provider.read_phys(3 * PAGE as u64, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x22);
        // PFN 4
        let n = provider.read_phys(4 * PAGE as u64, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x33);
    }

    #[test]
    fn from_path_roundtrip() {
        let mut page_data = vec![0u8; PAGE];
        page_data[0..4].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        let dump = CrashDumpBuilder::new().add_run(0, &page_data).build();
        let path = std::env::temp_dir().join("memf_test_crashdump_roundtrip.dmp");
        std::fs::write(&path, &dump).unwrap();
        let provider = CrashDumpProvider::from_path(&path).unwrap();
        let mut buf = [0u8; 4];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [0xCA, 0xFE, 0xBA, 0xBE]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn corrupt_magic_errors() {
        let mut dump = CrashDumpBuilder::new().add_run(0, &[0u8; PAGE]).build();
        // Corrupt the PAGE magic
        dump[0] = 0xFF;
        let err = CrashDumpProvider::from_bytes(&dump).unwrap_err();
        assert!(
            matches!(err, Error::Corrupt(_)),
            "expected Corrupt, got {err:?}"
        );
    }

    #[test]
    fn too_small_header_errors() {
        let data = vec![0u8; 100];
        let err = CrashDumpProvider::from_bytes(&data).unwrap_err();
        assert!(
            matches!(err, Error::Corrupt(_)),
            "expected Corrupt, got {err:?}"
        );
    }
}
