//! A [`forensic_carve::RegionSource`] over a process's **virtual** address space.

use forensic_carve::RegionSource;
use memf_core::vas::VirtualAddressSpace;
use memf_format::PhysicalMemoryProvider;

/// Positioned-read edge the sweep engine drives, backed by a
/// [`VirtualAddressSpace`]. `read_at(va, buf)` returns virtually-contiguous bytes
/// (page-crossing resolved by `memf-core`); a non-resident / paged-out page ends the
/// read as a **short read** — bytes are never fabricated or zero-filled to fill the
/// request.
pub struct VaRegionSource<'a, P: PhysicalMemoryProvider> {
    vas: &'a VirtualAddressSpace<P>,
}

impl<'a, P: PhysicalMemoryProvider> VaRegionSource<'a, P> {
    /// Wrap a borrowed virtual address space.
    #[must_use]
    pub fn new(vas: &'a VirtualAddressSpace<P>) -> Self {
        Self { vas }
    }
}

impl<P: PhysicalMemoryProvider> RegionSource for VaRegionSource<'_, P> {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> usize {
        // stub — replaced in GREEN
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::TranslationMode;

    const VBASE: u64 = 0x0000_0001_0000_0000;
    const PA1: u64 = 0x0080_0000;
    const PA2: u64 = 0x0081_0000;

    fn boundary_vas() -> VirtualAddressSpace<memf_core::test_builders::SyntheticPhysMem> {
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(VBASE, PA1, flags::WRITABLE)
            .map_4k(VBASE + 0x1000, PA2, flags::WRITABLE)
            .write_phys(PA1 + 0xFFC, &[0xAA; 4])
            .write_phys(PA2, &[0xBB; 4])
            .build();
        VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel)
    }

    #[test]
    fn read_at_returns_virtually_contiguous_bytes_across_page_boundary() {
        let vas = boundary_vas();
        let src = VaRegionSource::new(&vas);
        let mut buf = [0u8; 8];
        let n = src.read_at(VBASE + 0xFFC, &mut buf);
        assert_eq!(n, 8, "full contiguous read across the page boundary");
        assert_eq!(buf, [0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB]);
    }

    #[test]
    fn read_at_short_reads_at_a_gap_never_fabricating() {
        // Only VBASE is mapped; VBASE+0x1000 is not. A read straddling the boundary
        // returns just the resident prefix.
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(VBASE, PA1, flags::WRITABLE)
            .write_phys(PA1 + 0xFFC, &[0xCC; 4])
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let src = VaRegionSource::new(&vas);
        let mut buf = [0u8; 8];
        let n = src.read_at(VBASE + 0xFFC, &mut buf);
        assert_eq!(
            n, 4,
            "read stops at the unmapped page — no fabricated bytes"
        );
        assert_eq!(&buf[..4], &[0xCC; 4]);
    }

    #[test]
    fn read_at_fully_unmapped_returns_zero() {
        let vas = boundary_vas();
        let src = VaRegionSource::new(&vas);
        let mut buf = [0u8; 16];
        let n = src.read_at(0x0000_0009_0000_0000, &mut buf);
        assert_eq!(n, 0);
    }
}
