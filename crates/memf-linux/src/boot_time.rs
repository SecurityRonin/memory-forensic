//! Linux boot time extraction from kernel timekeeper.
//!
//! Reads the kernel `timekeeper` struct (via `tk_core` symbol) to derive
//! the system boot epoch. The wall-clock time at dump capture (`xtime_sec`)
//! combined with `wall_to_monotonic` and `offs_boot` yields the boot time:
//!
//! ```text
//! boot_epoch = -wall_to_monotonic.tv_sec - (offs_boot / 1_000_000_000)
//! ```
//!
//! This allows converting process `start_time` (nanoseconds since boot)
//! into absolute wall-clock timestamps for DFIR timelining.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{BootTimeEstimate, BootTimeSource, Error, Result};

/// Extract boot time from the kernel timekeeper struct.
///
/// Reads `tk_core` (or `timekeeper`) symbol, then extracts:
/// - `xtime_sec` (wall-clock seconds since Unix epoch at dump time)
/// - `wall_to_monotonic.tv_sec` (negative offset from wall to monotonic)
/// - `offs_boot` (nanoseconds spent in suspend, ktime_t/s64)
///
/// Returns `boot_epoch = -wall_to_monotonic.tv_sec - offs_boot/1e9`.
pub fn extract_boot_time<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<BootTimeEstimate> {
    // Find tk_core symbol (or fall back to timekeeper symbol)
    let tk_addr = reader
        .symbols()
        .symbol_address("tk_core")
        .or_else(|| reader.symbols().symbol_address("timekeeper"))
        .ok_or_else(|| Error::Walker("symbol 'tk_core'/'timekeeper' not found".into()))?;

    // tk_core wraps timekeeper at offset 0 (or is timekeeper itself).
    // Try reading timekeeper offset within tk_core; if the field doesn't
    // exist, assume tk_addr IS the timekeeper.
    let tk_offset = reader
        .symbols()
        .field_offset("tk_core", "timekeeper")
        .unwrap_or(0);
    let timekeeper_addr = tk_addr + tk_offset;

    // Read xtime_sec (wall-clock at dump time) — validates the timekeeper is readable.
    let _xtime_sec: i64 =
        reader.read_field(timekeeper_addr, "timekeeper", "xtime_sec")?;

    // Read wall_to_monotonic (struct timespec64 embedded in timekeeper)
    let w2m_offset = reader
        .symbols()
        .field_offset("timekeeper", "wall_to_monotonic")
        .ok_or_else(|| {
            Error::Walker("timekeeper.wall_to_monotonic field not found".into())
        })?;
    let w2m_addr = timekeeper_addr + w2m_offset;
    let w2m_tv_sec: i64 = reader.read_field(w2m_addr, "timespec64", "tv_sec")?;

    // Read offs_boot (ktime_t = s64, nanoseconds in suspend).
    // May not exist on older kernels — default to 0 (no suspend adjustment).
    let offs_boot_ns: i64 = reader
        .read_field(timekeeper_addr, "timekeeper", "offs_boot")
        .unwrap_or(0);

    // boot_epoch = -wall_to_monotonic.tv_sec - offs_boot_ns / 1_000_000_000
    let boot_epoch = -w2m_tv_sec - offs_boot_ns / 1_000_000_000;

    Ok(BootTimeEstimate {
        source: BootTimeSource::Timekeeper,
        boot_epoch_secs: boot_epoch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BootTimeSource;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // Synthetic layout:
    //   tk_core @ symbol address 0xFFFF_8000_0010_0000
    //     timekeeper @ offset 0 within tk_core (128 bytes)
    //       xtime_sec     @ 0   (long long, 8 bytes)
    //       wall_to_monotonic @ 8  (timespec64, 16 bytes)
    //       offs_boot     @ 24  (long long / ktime_t, 8 bytes)
    //   timespec64:
    //     tv_sec  @ 0  (long long, 8 bytes)
    //     tv_nsec @ 8  (long long, 8 bytes)

    const XTIME_SEC_OFF: usize = 0;
    const W2M_OFF: usize = 8;
    const OFFS_BOOT_OFF: usize = 24;

    fn build_boot_time_reader(
        xtime_sec: i64,
        w2m_tv_sec: i64,
        offs_boot_ns: i64,
    ) -> ObjectReader<SyntheticPhysMem> {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;

        let isf = IsfBuilder::new()
            .add_struct("tk_core", 128)
            .add_field("tk_core", "timekeeper", 0, "timekeeper")
            .add_struct("timekeeper", 128)
            .add_field("timekeeper", "xtime_sec", 0, "long long")
            .add_field("timekeeper", "wall_to_monotonic", 8, "timespec64")
            .add_field("timekeeper", "offs_boot", 24, "long long")
            .add_struct("timespec64", 16)
            .add_field("timespec64", "tv_sec", 0, "long long")
            .add_field("timespec64", "tv_nsec", 8, "long long")
            .add_symbol("tk_core", vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut data = vec![0u8; 4096];
        data[XTIME_SEC_OFF..XTIME_SEC_OFF + 8]
            .copy_from_slice(&xtime_sec.to_le_bytes());
        data[W2M_OFF..W2M_OFF + 8]
            .copy_from_slice(&w2m_tv_sec.to_le_bytes());
        // tv_nsec at W2M_OFF + 8 (leave as 0)
        data[OFFS_BOOT_OFF..OFFS_BOOT_OFF + 8]
            .copy_from_slice(&offs_boot_ns.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// System booted at epoch 1_712_000_000, dumped 100_000s later.
    /// xtime_sec = 1_712_100_000, wall_to_monotonic.tv_sec = -1_712_000_000
    /// offs_boot = 0 (no suspend).
    /// Expected boot_epoch = 1_712_000_000.
    #[test]
    fn extract_boot_time_no_suspend() {
        let reader = build_boot_time_reader(
            1_712_100_000,    // xtime_sec (wall-clock at dump)
            -1_712_000_000,   // wall_to_monotonic.tv_sec
            0,                // offs_boot (no suspend)
        );
        let est = extract_boot_time(&reader).unwrap();
        assert_eq!(est.source, BootTimeSource::Timekeeper);
        assert_eq!(est.boot_epoch_secs, 1_712_000_000);
    }

    /// System was suspended for 7200 seconds (2 hours).
    /// wall_to_monotonic.tv_sec = -1_712_000_000 (same as no-suspend)
    /// offs_boot = 7_200_000_000_000 ns (7200s in nanoseconds)
    /// boot_epoch = -(-1_712_000_000) - 7200 = 1_711_992_800
    /// (boot was 7200s earlier than monotonic-only would suggest)
    #[test]
    fn extract_boot_time_with_suspend() {
        let reader = build_boot_time_reader(
            1_712_100_000,
            -1_712_000_000,
            7_200_000_000_000, // 7200s in nanoseconds
        );
        let est = extract_boot_time(&reader).unwrap();
        assert_eq!(est.source, BootTimeSource::Timekeeper);
        assert_eq!(est.boot_epoch_secs, 1_711_992_800);
    }

    /// Missing tk_core symbol should produce an error.
    #[test]
    fn extract_boot_time_missing_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("timekeeper", 64)
            .add_field("timekeeper", "xtime_sec", 0, "long long")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = extract_boot_time(&reader);
        assert!(result.is_err());
    }
}
