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
        todo!()
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
        todo!()
    }

    /// System booted at epoch 1_712_000_000, dumped 100_000s later.
    /// xtime_sec = 1_712_100_000, wall_to_monotonic.tv_sec = -1_712_000_000
    /// offs_boot = 0 (no suspend).
    /// Expected boot_epoch = 1_712_000_000.
    #[test]
    fn extract_boot_time_no_suspend() {
        todo!()
    }

    /// System was suspended for 7200 seconds (2 hours).
    /// wall_to_monotonic.tv_sec = -1_712_000_000 (same as no-suspend)
    /// offs_boot = 7_200_000_000_000 ns (7200s in nanoseconds)
    /// boot_epoch = -(-1_712_000_000) - 7200 = 1_711_992_800
    /// (boot was 7200s earlier than monotonic-only would suggest)
    #[test]
    fn extract_boot_time_with_suspend() {
        todo!()
    }

    /// Missing tk_core symbol should produce an error.
    #[test]
    fn extract_boot_time_missing_symbol() {
        todo!()
    }
}
