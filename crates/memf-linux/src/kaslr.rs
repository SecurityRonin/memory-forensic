//! KASLR offset detection for Linux kernels.
//!
//! Scans physical memory for the `"Linux version "` banner string.
//! The banner's physical address, combined with the known virtual address
//! of `linux_banner` from the symbol table, yields the KASLR slide.

use memf_format::PhysicalMemoryProvider;
use memf_symbols::SymbolResolver;

use crate::{Error, Result};

/// The banner prefix to search for in physical memory.
const BANNER_PREFIX: &[u8] = b"Linux version ";

/// x86_64 kernel text mapping base (`__START_KERNEL_map`).
const KERNEL_MAP_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// Detect the KASLR offset by scanning for the Linux banner string.
///
/// Returns the KASLR slide (0 if KASLR is disabled).
pub fn detect_kaslr_offset(
    physical: &dyn PhysicalMemoryProvider,
    symbols: &dyn SymbolResolver,
) -> Result<u64> {
        todo!()
    }

/// Scan physical memory for the `"Linux version "` banner string.
fn scan_for_banner(physical: &dyn PhysicalMemoryProvider) -> Result<u64> {
        todo!()
    }

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        todo!()
    }

/// Apply a KASLR offset to a symbol address.
#[must_use]
pub fn adjust_address(original: u64, kaslr_offset: u64) -> u64 {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;
    use memf_format::PhysicalRange;
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    struct BannerPhysMem {
        data: Vec<u8>,
        ranges: Vec<PhysicalRange>,
    }

    impl PhysicalMemoryProvider for BannerPhysMem {
        fn read_phys(&self, addr: u64, buf: &mut [u8]) -> memf_format::Result<usize> {
        todo!()
    }

        fn ranges(&self) -> &[PhysicalRange] {
        todo!()
    }

        fn format_name(&self) -> &str {
        todo!()
    }
    }

    #[test]
    fn detect_no_kaslr() {
        todo!()
    }

    #[test]
    fn detect_with_kaslr() {
        todo!()
    }

    #[test]
    fn no_banner_found() {
        todo!()
    }

    #[test]
    fn adjust_address_with_offset() {
        todo!()
    }

    #[test]
    fn find_subsequence_basic() {
        todo!()
    }

    #[test]
    fn find_subsequence_not_found() {
        todo!()
    }
}
