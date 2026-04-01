//! Windows crash dump (`.dmp`) format provider.
//!
//! Parses 64-bit Windows crash dumps with `_DUMP_HEADER64`.
//! Supports run-based (DumpType 0x01) and bitmap (0x02/0x05) layouts.

use std::path::Path;

use crate::{DumpMetadata, Error, FormatPlugin, MachineType, PhysicalMemoryProvider, PhysicalRange, Result};

/// PAGE magic: "PAGE" as little-endian u32 = 0x4547_4150.
const PAGE_MAGIC: u32 = 0x4547_4150;
/// DU64 signature: "DU64" as little-endian u32 = 0x3436_5544.
const DU64_SIG: u32 = 0x3436_5544;
/// Minimum header size for `_DUMP_HEADER64` (8192 bytes).
const HEADER_SIZE: usize = 0x2000;
/// Page size (4096 bytes).
const PAGE_SIZE: u64 = 4096;
/// "DUMP" as little-endian u32 for bitmap summary ValidDump field.
const DUMP_VALID: u32 = 0x504D_5544;

// Header field offsets.
const OFF_MAGIC: usize = 0x000;
const OFF_SIG: usize = 0x004;
const OFF_CR3: usize = 0x010;
const OFF_PS_LOADED_MODULE_LIST: usize = 0x020;
const OFF_PS_ACTIVE_PROCESS_HEAD: usize = 0x028;
const OFF_MACHINE_TYPE: usize = 0x030;
const OFF_NUM_PROCESSORS: usize = 0x034;
const OFF_KD_DEBUGGER_DATA_BLOCK: usize = 0x080;
const OFF_PHYS_MEM_BLOCK: usize = 0x088;
const OFF_DUMP_TYPE: usize = 0xF98;
const OFF_SYSTEM_TIME: usize = 0xFA8;

/// A physical memory run descriptor from the crash dump header.
#[derive(Debug, Clone)]
struct PhysMemRun {
    /// Base page frame number (PFN).
    base_page: u64,
    /// Number of pages in this run.
    page_count: u64,
}

/// Layout of physical memory data within the crash dump.
#[derive(Debug)]
enum CrashDumpLayout {
    /// Run-based layout (DumpType 0x01): data pages stored sequentially after header.
    RunBased {
        /// Parsed runs from the header.
        runs: Vec<PhysMemRun>,
        /// Pre-computed file offset where each run's data begins.
        run_file_offsets: Vec<u64>,
    },
    /// Bitmap layout (DumpType 0x02 or 0x05): bitmap indicates which PFNs are present.
    Bitmap {
        /// The bitmap bytes (one bit per PFN).
        bitmap: Vec<u8>,
        /// File offset where page data begins (after summary header + bitmap).
        data_start: u64,
    },
}

/// Provider that exposes physical memory from a Windows 64-bit crash dump.
#[derive(Debug)]
pub struct CrashDumpProvider {
    data: Vec<u8>,
    metadata: DumpMetadata,
    layout: CrashDumpLayout,
    ranges: Vec<PhysicalRange>,
}

/// Read a little-endian u32 from `data` at `offset`.
fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

/// Read a little-endian u64 from `data` at `offset`.
fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

/// Convert a MachineImageType u32 to a [`MachineType`].
fn parse_machine_type(val: u32) -> Option<MachineType> {
    match val {
        0x8664 => Some(MachineType::Amd64),
        0x014C => Some(MachineType::I386),
        0xAA64 => Some(MachineType::Aarch64),
        _ => None,
    }
}

/// Convert a DumpType u32 to a human-readable label.
fn dump_type_label(val: u32) -> &'static str {
    match val {
        0x01 => "Full",
        0x02 => "Kernel",
        0x05 => "Bitmap",
        _ => "Unknown",
    }
}

impl CrashDumpProvider {
    /// Parse a crash dump from an in-memory byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            return Err(Error::Corrupt(format!(
                "crash dump too small: {} bytes, need at least {HEADER_SIZE}",
                bytes.len()
            )));
        }

        // Validate magic.
        let magic = read_u32(bytes, OFF_MAGIC);
        let sig = read_u32(bytes, OFF_SIG);
        if magic != PAGE_MAGIC || sig != DU64_SIG {
            return Err(Error::Corrupt(format!(
                "invalid crash dump magic: expected PAGE+DU64, got 0x{magic:08X}+0x{sig:08X}"
            )));
        }

        // Extract metadata fields.
        let cr3 = read_u64(bytes, OFF_CR3);
        let ps_loaded_module_list = read_u64(bytes, OFF_PS_LOADED_MODULE_LIST);
        let ps_active_process_head = read_u64(bytes, OFF_PS_ACTIVE_PROCESS_HEAD);
        let machine_img_type = read_u32(bytes, OFF_MACHINE_TYPE);
        let num_processors = read_u32(bytes, OFF_NUM_PROCESSORS);
        let kd_debugger_data_block = read_u64(bytes, OFF_KD_DEBUGGER_DATA_BLOCK);
        let dump_type_val = read_u32(bytes, OFF_DUMP_TYPE);
        let system_time = read_u64(bytes, OFF_SYSTEM_TIME);

        let metadata = DumpMetadata {
            cr3: Some(cr3),
            machine_type: parse_machine_type(machine_img_type),
            os_version: None,
            num_processors: Some(num_processors),
            ps_active_process_head: Some(ps_active_process_head),
            ps_loaded_module_list: Some(ps_loaded_module_list),
            kd_debugger_data_block: Some(kd_debugger_data_block),
            system_time: Some(system_time),
            dump_type: Some(dump_type_label(dump_type_val).to_string()),
        };

        // Parse runs from PhysicalMemoryBlockBuffer at 0x088.
        let num_runs = read_u32(bytes, OFF_PHYS_MEM_BLOCK) as usize;
        // _num_pages at 0x090 (skip padding at 0x08C)
        let mut runs = Vec::with_capacity(num_runs);
        for i in 0..num_runs {
            let off = 0x098 + i * 16;
            let base_page = read_u64(bytes, off);
            let page_count = read_u64(bytes, off + 8);
            runs.push(PhysMemRun {
                base_page,
                page_count,
            });
        }

        // Build ranges from runs.
        let ranges: Vec<PhysicalRange> = runs
            .iter()
            .map(|r| PhysicalRange {
                start: r.base_page * PAGE_SIZE,
                end: (r.base_page + r.page_count) * PAGE_SIZE,
            })
            .collect();

        let is_bitmap = dump_type_val == 0x02 || dump_type_val == 0x05;
        let layout = if is_bitmap {
            Self::parse_bitmap_layout(bytes, HEADER_SIZE)?
        } else {
            Self::parse_run_layout(&runs)
        };

        Ok(Self {
            data: bytes.to_vec(),
            metadata,
            layout,
            ranges,
        })
    }

    /// Parse a crash dump from a file path.
    pub fn from_path(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(&data)
    }

    /// Build run-based layout: data starts at HEADER_SIZE, runs stored sequentially.
    fn parse_run_layout(runs: &[PhysMemRun]) -> CrashDumpLayout {
        let mut run_file_offsets = Vec::with_capacity(runs.len());
        let mut offset = HEADER_SIZE as u64;
        for run in runs {
            run_file_offsets.push(offset);
            offset += run.page_count * PAGE_SIZE;
        }
        CrashDumpLayout::RunBased {
            runs: runs.to_vec(),
            run_file_offsets,
        }
    }

    /// Parse bitmap layout from the summary header at `summary_offset`.
    fn parse_bitmap_layout(data: &[u8], summary_offset: usize) -> Result<CrashDumpLayout> {
        if data.len() < summary_offset + 16 {
            return Err(Error::Corrupt(
                "crash dump too small for bitmap summary header".into(),
            ));
        }

        let valid_dump = read_u32(data, summary_offset);
        if valid_dump != DUMP_VALID {
            return Err(Error::Corrupt(format!(
                "invalid bitmap summary ValidDump: expected 0x{DUMP_VALID:08X}, got 0x{valid_dump:08X}"
            )));
        }

        let header_size = read_u32(data, summary_offset + 4) as usize;
        let bitmap_size = read_u32(data, summary_offset + 8) as usize;

        // Bitmap starts right after the 16-byte summary header fields.
        let bitmap_start = summary_offset + 16;
        if data.len() < bitmap_start + bitmap_size {
            return Err(Error::Corrupt("crash dump bitmap truncated".into()));
        }

        let bitmap = data[bitmap_start..bitmap_start + bitmap_size].to_vec();
        let data_start = (summary_offset + header_size) as u64;

        Ok(CrashDumpLayout::Bitmap {
            bitmap,
            data_start,
        })
    }

    /// Read physical memory using run-based layout.
    fn read_run_based(
        &self,
        addr: u64,
        buf: &mut [u8],
        runs: &[PhysMemRun],
        run_file_offsets: &[u64],
    ) -> Result<usize> {
        let pfn = addr / PAGE_SIZE;
        let page_offset = (addr % PAGE_SIZE) as usize;

        for (i, run) in runs.iter().enumerate() {
            if pfn >= run.base_page && pfn < run.base_page + run.page_count {
                let pages_into_run = pfn - run.base_page;
                let file_offset =
                    run_file_offsets[i] + pages_into_run * PAGE_SIZE + page_offset as u64;
                let remaining_in_run =
                    ((run.page_count - pages_into_run) * PAGE_SIZE - page_offset as u64) as usize;
                let to_read = buf.len().min(remaining_in_run);
                let src = file_offset as usize;
                if src + to_read > self.data.len() {
                    return Err(Error::Corrupt("run data extends beyond file".into()));
                }
                buf[..to_read].copy_from_slice(&self.data[src..src + to_read]);
                return Ok(to_read);
            }
        }

        // Address not in any run — gap.
        Ok(0)
    }

    /// Read physical memory using bitmap layout.
    fn read_bitmap(
        &self,
        addr: u64,
        buf: &mut [u8],
        bitmap: &[u8],
        data_start: u64,
    ) -> Result<usize> {
        let pfn = addr / PAGE_SIZE;
        let page_offset = (addr % PAGE_SIZE) as usize;

        // Check if this PFN's bit is set in the bitmap.
        let byte_idx = pfn as usize / 8;
        let bit_idx = pfn as usize % 8;
        if byte_idx >= bitmap.len() || (bitmap[byte_idx] & (1 << bit_idx)) == 0 {
            return Ok(0); // PFN not present.
        }

        // Count set bits before this PFN to find the page index in the data area.
        let page_index = popcount_before(bitmap, pfn as usize);
        let file_offset = data_start + page_index as u64 * PAGE_SIZE + page_offset as u64;
        let remaining_in_page = (PAGE_SIZE as usize) - page_offset;
        let to_read = buf.len().min(remaining_in_page);
        let src = file_offset as usize;
        if src + to_read > self.data.len() {
            return Err(Error::Corrupt("bitmap page data extends beyond file".into()));
        }
        buf[..to_read].copy_from_slice(&self.data[src..src + to_read]);
        Ok(to_read)
    }
}

/// Count the number of set bits in `bitmap` for all positions before `bit_pos`.
fn popcount_before(bitmap: &[u8], bit_pos: usize) -> usize {
    let full_bytes = bit_pos / 8;
    let remaining_bits = bit_pos % 8;

    let mut count: usize = 0;
    for &byte in &bitmap[..full_bytes] {
        count += byte.count_ones() as usize;
    }
    if remaining_bits > 0 && full_bytes < bitmap.len() {
        // Mask off bits at positions >= remaining_bits.
        let mask = (1u8 << remaining_bits) - 1;
        count += (bitmap[full_bytes] & mask).count_ones() as usize;
    }
    count
}

impl PhysicalMemoryProvider for CrashDumpProvider {
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        match &self.layout {
            CrashDumpLayout::RunBased {
                runs,
                run_file_offsets,
            } => self.read_run_based(addr, buf, runs, run_file_offsets),
            CrashDumpLayout::Bitmap {
                bitmap,
                data_start,
            } => self.read_bitmap(addr, buf, bitmap, *data_start),
        }
    }

    fn ranges(&self) -> &[PhysicalRange] {
        &self.ranges
    }

    fn format_name(&self) -> &str {
        "Windows Crash Dump"
    }

    fn metadata(&self) -> Option<DumpMetadata> {
        Some(self.metadata.clone())
    }
}

/// FormatPlugin implementation for Windows crash dumps.
pub struct CrashDumpPlugin;

impl FormatPlugin for CrashDumpPlugin {
    fn name(&self) -> &str {
        "Windows Crash Dump"
    }

    fn probe(&self, header: &[u8]) -> u8 {
        if header.len() < 8 {
            return 0;
        }
        let magic = read_u32(header, 0);
        let sig = read_u32(header, 4);
        if magic == PAGE_MAGIC && sig == DU64_SIG {
            95
        } else {
            0
        }
    }

    fn open(&self, path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>> {
        Ok(Box::new(CrashDumpProvider::from_path(path)?))
    }
}

inventory::submit!(&CrashDumpPlugin as &dyn FormatPlugin);

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
