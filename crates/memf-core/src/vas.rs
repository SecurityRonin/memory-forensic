//! Virtual address space and page table walking.

use memf_format::PhysicalMemoryProvider;

use crate::{Error, Result};

/// Translation mode for virtual-to-physical address translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslationMode {
    /// x86_64 4-level paging (PML4 -> PDPT -> PD -> PT).
    X86_64FourLevel,
}

/// A virtual address space backed by physical memory and page tables.
pub struct VirtualAddressSpace<P: PhysicalMemoryProvider> {
    physical: P,
    page_table_root: u64,
    mode: TranslationMode,
}

// x86_64 page table constants
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const PRESENT: u64 = 1;
const PS: u64 = 1 << 7;

impl<P: PhysicalMemoryProvider> VirtualAddressSpace<P> {
    /// Create a new virtual address space.
    pub fn new(physical: P, page_table_root: u64, mode: TranslationMode) -> Self {
        Self {
            physical,
            page_table_root,
            mode,
        }
    }

    /// Translate a virtual address to a physical address.
    pub fn virt_to_phys(&self, vaddr: u64) -> Result<u64> {
        match self.mode {
            TranslationMode::X86_64FourLevel => self.walk_x86_64_4level(vaddr),
        }
    }

    /// Read `buf.len()` bytes from virtual address `vaddr`, handling page boundary crossings.
    pub fn read_virt(&self, vaddr: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        let mut offset = 0usize;
        let mut current_vaddr = vaddr;

        while offset < buf.len() {
            let paddr = self.virt_to_phys(current_vaddr)?;

            // Calculate how many bytes until the next page boundary
            let page_offset = current_vaddr & 0xFFF;
            let remaining_in_page = 0x1000 - page_offset as usize;
            let remaining_to_read = buf.len() - offset;
            let chunk = remaining_to_read.min(remaining_in_page);

            let n = self
                .physical
                .read_phys(paddr, &mut buf[offset..offset + chunk])?;
            if n == 0 {
                return Err(Error::PartialRead {
                    addr: vaddr,
                    requested: buf.len(),
                    got: offset,
                });
            }
            offset += n;
            current_vaddr = current_vaddr.wrapping_add(n as u64);
        }

        Ok(())
    }

    /// Return a reference to the underlying physical memory provider.
    pub fn physical(&self) -> &P {
        &self.physical
    }

    fn read_pte(&self, addr: u64) -> Result<u64> {
        let mut buf = [0u8; 8];
        let n = self.physical.read_phys(addr, &mut buf)?;
        if n < 8 {
            return Err(Error::PartialRead {
                addr,
                requested: 8,
                got: n,
            });
        }
        Ok(u64::from_le_bytes(buf))
    }

    fn walk_x86_64_4level(&self, vaddr: u64) -> Result<u64> {
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pd_idx = (vaddr >> 21) & 0x1FF;
        let pt_idx = (vaddr >> 12) & 0x1FF;
        let page_offset = vaddr & 0xFFF;

        // PML4
        let pml4e = self.read_pte(self.page_table_root + pml4_idx * 8)?;
        if pml4e & PRESENT == 0 {
            return Err(Error::PageNotPresent(vaddr));
        }

        // PDPT
        let pdpt_base = pml4e & ADDR_MASK;
        let pdpte = self.read_pte(pdpt_base + pdpt_idx * 8)?;
        if pdpte & PRESENT == 0 {
            return Err(Error::PageNotPresent(vaddr));
        }

        // 1GB huge page?
        if pdpte & PS != 0 {
            let phys_base = pdpte & 0x000F_FFFF_C000_0000;
            let offset_1g = vaddr & 0x3FFF_FFFF;
            return Ok(phys_base | offset_1g);
        }

        // PD
        let pd_base = pdpte & ADDR_MASK;
        let pde = self.read_pte(pd_base + pd_idx * 8)?;
        if pde & PRESENT == 0 {
            return Err(Error::PageNotPresent(vaddr));
        }

        // 2MB large page?
        if pde & PS != 0 {
            let phys_base = pde & 0x000F_FFFF_FFE0_0000;
            let offset_2m = vaddr & 0x1F_FFFF;
            return Ok(phys_base | offset_2m);
        }

        // PT (4K page)
        let pt_base = pde & ADDR_MASK;
        let pte = self.read_pte(pt_base + pt_idx * 8)?;
        if pte & PRESENT == 0 {
            return Err(Error::PageNotPresent(vaddr));
        }

        let phys_base = pte & ADDR_MASK;
        Ok(phys_base | page_offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_builders::{flags, PageTableBuilder};

    #[test]
    fn translate_4k_page() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let result = vas.virt_to_phys(vaddr).unwrap();
        assert_eq!(result, paddr);
    }

    #[test]
    fn translate_4k_with_offset() {
        let vaddr: u64 = 0xFFFF_8000_0010_0ABC;
        let paddr_base: u64 = 0x0080_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr & !0xFFF, paddr_base, flags::WRITABLE)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let result = vas.virt_to_phys(vaddr).unwrap();
        assert_eq!(result, paddr_base + 0xABC);
    }

    #[test]
    fn read_virt_4k() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &[0xDE, 0xAD, 0xBE, 0xEF])
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let mut buf = [0u8; 4];
        vas.read_virt(vaddr, &mut buf).unwrap();
        assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn translate_2mb_page() {
        let vaddr: u64 = 0xFFFF_8000_0020_0000;
        let paddr: u64 = 0x0100_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_2m(vaddr, paddr, flags::WRITABLE)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let result = vas.virt_to_phys(vaddr).unwrap();
        assert_eq!(result, paddr);

        // Test with offset within the 2MB page
        let result_offset = vas.virt_to_phys(vaddr + 0x1234).unwrap();
        assert_eq!(result_offset, paddr + 0x1234);
    }

    #[test]
    fn translate_1gb_page() {
        let vaddr: u64 = 0xFFFF_8000_4000_0000;
        let paddr: u64 = 0x4000_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_1g(vaddr, paddr, flags::WRITABLE)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let result = vas.virt_to_phys(vaddr).unwrap();
        assert_eq!(result, paddr);

        // Test with offset within the 1GB page
        let result_offset = vas.virt_to_phys(vaddr + 0x12_3456).unwrap();
        assert_eq!(result_offset, paddr + 0x12_3456);
    }

    #[test]
    fn non_present_page_returns_error() {
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let result = vas.virt_to_phys(0xFFFF_8000_0010_0000);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::PageNotPresent(addr) => assert_eq!(addr, 0xFFFF_8000_0010_0000),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn read_virt_cross_page_boundary() {
        // Map two adjacent virtual pages to different physical pages
        let vaddr_page1: u64 = 0xFFFF_8000_0010_0000;
        let vaddr_page2: u64 = 0xFFFF_8000_0010_1000;
        let paddr1: u64 = 0x0080_0000;
        let paddr2: u64 = 0x0090_0000;

        // Write data at end of page1 and start of page2
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr_page1, paddr1, flags::WRITABLE)
            .map_4k(vaddr_page2, paddr2, flags::WRITABLE)
            .write_phys(paddr1 + 0xFFC, &[0xAA, 0xBB, 0xCC, 0xDD])
            .write_phys(paddr2, &[0x11, 0x22, 0x33, 0x44])
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let mut buf = [0u8; 8];
        vas.read_virt(vaddr_page1 + 0xFFC, &mut buf).unwrap();
        assert_eq!(buf, [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn read_virt_empty_buffer() {
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let mut buf = [];
        vas.read_virt(0xFFFF_8000_0010_0000, &mut buf).unwrap();
    }

    #[test]
    fn multiple_mappings_same_pml4() {
        let vaddr1: u64 = 0xFFFF_8000_0010_0000;
        let vaddr2: u64 = 0xFFFF_8000_0010_1000;
        let paddr1: u64 = 0x0080_0000;
        let paddr2: u64 = 0x0090_0000;

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr1, paddr1, flags::WRITABLE)
            .map_4k(vaddr2, paddr2, flags::WRITABLE)
            .write_phys(paddr1, &[0x11; 8])
            .write_phys(paddr2, &[0x22; 8])
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);

        let mut buf1 = [0u8; 8];
        vas.read_virt(vaddr1, &mut buf1).unwrap();
        assert_eq!(buf1, [0x11; 8]);

        let mut buf2 = [0u8; 8];
        vas.read_virt(vaddr2, &mut buf2).unwrap();
        assert_eq!(buf2, [0x22; 8]);
    }
}
