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
    let banner_symbol_vaddr = symbols
        .symbol_address("linux_banner")
        .ok_or_else(|| Error::Walker("symbol 'linux_banner' not found".into()))?;

    let banner_phys = scan_for_banner(physical)?;

    let actual_virt = banner_phys.wrapping_add(KERNEL_MAP_BASE);
    let offset = actual_virt.wrapping_sub(banner_symbol_vaddr);

    Ok(offset)
}

/// Scan physical memory for the `"Linux version "` banner string.
fn scan_for_banner(physical: &dyn PhysicalMemoryProvider) -> Result<u64> {
    let mut buf = vec![0u8; 4096];

    for range in physical.ranges() {
        let mut addr = range.start;
        while addr < range.end {
            let to_read = ((range.end - addr) as usize).min(buf.len());
            let n = physical
                .read_phys(addr, &mut buf[..to_read])
                .map_err(|e| Error::Walker(format!("physical read error: {e}")))?;
            if n == 0 {
                break;
            }

            if let Some(pos) = find_subsequence(&buf[..n], BANNER_PREFIX) {
                return Ok(addr + pos as u64);
            }

            // Overlap by BANNER_PREFIX.len() to catch cross-boundary matches
            if n > BANNER_PREFIX.len() {
                addr += (n - BANNER_PREFIX.len()) as u64;
            } else {
                addr += n as u64;
            }
        }
    }

    Err(Error::Walker(
        "Linux banner string not found in physical memory".into(),
    ))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Apply a KASLR offset to a symbol address.
#[must_use]
pub fn adjust_address(original: u64, kaslr_offset: u64) -> u64 {
    original.wrapping_add(kaslr_offset)
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
            let start = addr as usize;
            if start >= self.data.len() {
                return Ok(0);
            }
            let available = self.data.len() - start;
            let to_read = buf.len().min(available);
            buf[..to_read].copy_from_slice(&self.data[start..start + to_read]);
            Ok(to_read)
        }

        fn ranges(&self) -> &[PhysicalRange] {
            &self.ranges
        }

        fn format_name(&self) -> &str {
            "Test"
        }
    }

    #[test]
    fn detect_no_kaslr() {
        let banner_phys: u64 = 0x0200_0000;
        let banner_vaddr: u64 = 0xFFFF_FFFF_8200_0000;

        let mut data = vec![0u8; (banner_phys as usize) + 4096];
        let banner = b"Linux version 5.15.0-generic";
        data[banner_phys as usize..banner_phys as usize + banner.len()].copy_from_slice(banner);

        let mem = BannerPhysMem {
            ranges: vec![PhysicalRange {
                start: 0,
                end: data.len() as u64,
            }],
            data,
        };

        let isf = IsfBuilder::new()
            .add_symbol("linux_banner", banner_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let offset = detect_kaslr_offset(&mem, &resolver).unwrap();
        assert_eq!(offset, 0);
    }

    #[test]
    fn detect_with_kaslr() {
        let kaslr_slide: u64 = 0x0060_0000;
        let default_banner_vaddr: u64 = 0xFFFF_FFFF_8200_0000;
        let banner_phys: u64 = 0x0260_0000;

        let mut data = vec![0u8; (banner_phys as usize) + 4096];
        let banner = b"Linux version 6.1.0-kaslr";
        data[banner_phys as usize..banner_phys as usize + banner.len()].copy_from_slice(banner);

        let mem = BannerPhysMem {
            ranges: vec![PhysicalRange {
                start: 0,
                end: data.len() as u64,
            }],
            data,
        };

        let isf = IsfBuilder::new()
            .add_symbol("linux_banner", default_banner_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let offset = detect_kaslr_offset(&mem, &resolver).unwrap();
        assert_eq!(offset, kaslr_slide);
    }

    #[test]
    fn no_banner_found() {
        let data = vec![0u8; 4096];
        let mem = BannerPhysMem {
            ranges: vec![PhysicalRange {
                start: 0,
                end: 4096,
            }],
            data,
        };

        let isf = IsfBuilder::new()
            .add_symbol("linux_banner", 0xFFFF_FFFF_8200_0000)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let result = detect_kaslr_offset(&mem, &resolver);
        assert!(result.is_err());
    }

    #[test]
    fn adjust_address_with_offset() {
        let original = 0xFFFF_FFFF_8260_0000u64;
        let kaslr = 0x0060_0000u64;
        let adjusted = adjust_address(original, kaslr);
        assert_eq!(adjusted, 0xFFFF_FFFF_82C0_0000);
    }

    #[test]
    fn find_subsequence_basic() {
        let haystack = b"hello world Linux version 5.15";
        let needle = b"Linux version ";
        assert_eq!(find_subsequence(haystack, needle), Some(12));
    }

    #[test]
    fn find_subsequence_not_found() {
        let haystack = b"no banner here";
        let needle = b"Linux version ";
        assert_eq!(find_subsequence(haystack, needle), None);
    }
}
