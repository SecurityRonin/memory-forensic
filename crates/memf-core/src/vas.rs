//! Virtual address space and page table walking.

use memf_format::PhysicalMemoryProvider;

use crate::pagefile::PagefileSource;
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
    pagefiles: Vec<Box<dyn PagefileSource>>,
}

// x86_64 page table constants
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const PRESENT: u64 = 1;
const PS: u64 = 1 << 7;

/// Internal result of page table walk — not exposed publicly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TranslationResult {
    /// Page is in physical memory at this address.
    Physical(u64),
    /// Page is demand-zero (all zeroes).
    DemandZero,
    /// Page is in a pagefile.
    PagefileEntry { pagefile_num: u8, page_offset: u64 },
    /// Page is a transition page (still in physical memory at this PFN-derived address).
    Transition(u64),
    /// Page uses a prototype PTE (Phase 3F-B).
    Prototype,
}

impl<P: PhysicalMemoryProvider> VirtualAddressSpace<P> {
    /// Create a new virtual address space.
    pub fn new(physical: P, page_table_root: u64, mode: TranslationMode) -> Self {
        Self {
            physical,
            page_table_root,
            mode,
            pagefiles: Vec::new(),
        }
    }

    /// Attach a pagefile source for resolving paged-out memory.
    pub fn with_pagefile(mut self, source: Box<dyn PagefileSource>) -> Self {
        self.pagefiles.push(source);
        self
    }

    /// Translate a virtual address to a physical address.
    pub fn virt_to_phys(&self, vaddr: u64) -> Result<u64> {
        match self.mode {
            TranslationMode::X86_64FourLevel => self.walk_x86_64_4level(vaddr),
        }
    }

    /// Read `buf.len()` bytes from virtual address `vaddr`, handling page boundary crossings.
    ///
    /// Uses `walk_x86_64_4level_internal()` to resolve each 4K chunk, transparently
    /// handling physical, transition, demand-zero, and pagefile pages.
    pub fn read_virt(&self, vaddr: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        let mut offset = 0usize;
        let mut current_vaddr = vaddr;

        while offset < buf.len() {
            let page_off = (current_vaddr & 0xFFF) as usize;
            let remaining_in_page = 0x1000 - page_off;
            let remaining_to_read = buf.len() - offset;
            let chunk = remaining_to_read.min(remaining_in_page);

            let result = match self.mode {
                TranslationMode::X86_64FourLevel => {
                    self.walk_x86_64_4level_internal(current_vaddr)?
                }
            };

            match result {
                TranslationResult::Physical(paddr) | TranslationResult::Transition(paddr) => {
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
                TranslationResult::DemandZero => {
                    buf[offset..offset + chunk].fill(0);
                    offset += chunk;
                    current_vaddr = current_vaddr.wrapping_add(chunk as u64);
                }
                TranslationResult::PagefileEntry {
                    pagefile_num,
                    page_offset,
                } => {
                    let page = self.read_pagefile_page(current_vaddr, pagefile_num, page_offset)?;
                    buf[offset..offset + chunk].copy_from_slice(&page[page_off..page_off + chunk]);
                    offset += chunk;
                    current_vaddr = current_vaddr.wrapping_add(chunk as u64);
                }
                TranslationResult::Prototype => {
                    return Err(Error::PrototypePte(current_vaddr));
                }
            }
        }

        Ok(())
    }

    fn read_pagefile_page(
        &self,
        vaddr: u64,
        pagefile_num: u8,
        page_offset: u64,
    ) -> Result<[u8; 4096]> {
        for source in &self.pagefiles {
            if source.pagefile_number() == pagefile_num {
                if let Some(page) = source.read_page(page_offset)? {
                    return Ok(page);
                }
                break;
            }
        }
        Err(Error::PagedOut {
            vaddr,
            pagefile_num,
            page_offset,
        })
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
        let result = self.walk_x86_64_4level_internal(vaddr)?;
        match result {
            TranslationResult::Physical(addr) | TranslationResult::Transition(addr) => Ok(addr),
            TranslationResult::DemandZero => Err(Error::PageNotPresent(vaddr)),
            TranslationResult::PagefileEntry {
                pagefile_num,
                page_offset,
            } => Err(Error::PagedOut {
                vaddr,
                pagefile_num,
                page_offset,
            }),
            TranslationResult::Prototype => Err(Error::PrototypePte(vaddr)),
        }
    }

    fn walk_x86_64_4level_internal(&self, vaddr: u64) -> Result<TranslationResult> {
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

        // 1GB huge page check
        if pdpte & PS != 0 {
            let phys_base = pdpte & 0x000F_FFFF_C000_0000;
            let offset_1g = vaddr & 0x3FFF_FFFF;
            return Ok(TranslationResult::Physical(phys_base | offset_1g));
        }

        // PD
        let pd_base = pdpte & ADDR_MASK;
        let pde = self.read_pte(pd_base + pd_idx * 8)?;
        if pde & PRESENT == 0 {
            return Err(Error::PageNotPresent(vaddr));
        }

        // 2MB large page check
        if pde & PS != 0 {
            let phys_base = pde & 0x000F_FFFF_FFE0_0000;
            let offset_2m = vaddr & 0x1F_FFFF;
            return Ok(TranslationResult::Physical(phys_base | offset_2m));
        }

        // PT (4K page)
        let pt_base = pde & ADDR_MASK;
        let pte = self.read_pte(pt_base + pt_idx * 8)?;

        if pte & PRESENT != 0 {
            let phys_base = pte & ADDR_MASK;
            return Ok(TranslationResult::Physical(phys_base | page_offset));
        }

        // Non-present PTE decoding (PT level only)
        Ok(Self::decode_non_present_pte(pte, page_offset))
    }

    fn decode_non_present_pte(pte: u64, page_offset: u64) -> TranslationResult {
        if pte == 0 {
            return TranslationResult::DemandZero;
        }
        if pte & (1 << 11) != 0 {
            let pfn = (pte >> 12) & 0xF_FFFF_FFFF;
            return TranslationResult::Transition(pfn * 0x1000 + page_offset);
        }
        if pte & (1 << 10) != 0 {
            return TranslationResult::Prototype;
        }
        let pagefile_num = ((pte >> 1) & 0xF) as u8;
        let pf_page_offset = (pte >> 12) & 0xF_FFFF_FFFF;
        TranslationResult::PagefileEntry {
            pagefile_num,
            page_offset: pf_page_offset,
        }
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
    fn virt_to_phys_4k_direct() {
        // Test virt_to_phys as the public API (not just internal translate)
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        assert_eq!(vas.virt_to_phys(vaddr).unwrap(), paddr);
        assert_eq!(vas.virt_to_phys(vaddr + 0x42).unwrap(), paddr + 0x42);
    }

    #[test]
    fn physical_accessor() {
        let (cr3, mem) = PageTableBuilder::new()
            .write_phys(0x5000, &[0xAB; 8])
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let phys = vas.physical();
        let mut buf = [0u8; 4];
        let n = phys.read_phys(0x5000, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [0xAB; 4]);
    }

    #[test]
    fn demand_zero_pte_returns_page_not_present() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new().map_demand_zero(vaddr).build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let result = vas.virt_to_phys(vaddr);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::PageNotPresent(addr) => assert_eq!(addr, vaddr),
            other => panic!("expected PageNotPresent, got: {other}"),
        }
    }

    #[test]
    fn transition_pte_resolves_to_physical() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let pfn: u64 = 0x800;
        let (cr3, mem) = PageTableBuilder::new()
            .map_transition(vaddr, pfn)
            .write_phys(pfn * 0x1000, &[0xDE, 0xAD, 0xBE, 0xEF])
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let paddr = vas.virt_to_phys(vaddr).unwrap();
        assert_eq!(paddr, pfn * 0x1000);
    }

    #[test]
    fn transition_pte_with_offset() {
        let vaddr_base: u64 = 0xFFFF_8000_0010_0000;
        let vaddr: u64 = vaddr_base + 0x42;
        let pfn: u64 = 0x800;
        let (cr3, mem) = PageTableBuilder::new()
            .map_transition(vaddr_base, pfn)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let paddr = vas.virt_to_phys(vaddr).unwrap();
        assert_eq!(paddr, pfn * 0x1000 + 0x42);
    }

    #[test]
    fn prototype_pte_returns_error() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new().map_prototype(vaddr).build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let result = vas.virt_to_phys(vaddr);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::PrototypePte(addr) => assert_eq!(addr, vaddr),
            other => panic!("expected PrototypePte, got: {other}"),
        }
    }

    #[test]
    fn pagefile_pte_returns_paged_out() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_pagefile(vaddr, 0, 0x1234)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let result = vas.virt_to_phys(vaddr);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::PagedOut {
                vaddr: v,
                pagefile_num,
                page_offset,
            } => {
                assert_eq!(v, vaddr);
                assert_eq!(pagefile_num, 0);
                assert_eq!(page_offset, 0x1234);
            }
            other => panic!("expected PagedOut, got: {other}"),
        }
    }

    #[test]
    fn pagefile_pte_number_routing() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_pagefile(vaddr, 2, 0xABCD)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let result = vas.virt_to_phys(vaddr);
        match result.unwrap_err() {
            Error::PagedOut {
                pagefile_num,
                page_offset,
                ..
            } => {
                assert_eq!(pagefile_num, 2);
                assert_eq!(page_offset, 0xABCD);
            }
            other => panic!("expected PagedOut, got: {other}"),
        }
    }

    use crate::test_builders::MockPagefileSource;

    #[test]
    fn read_virt_demand_zero_returns_zeroes() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new().map_demand_zero(vaddr).build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let mut buf = [0xFFu8; 4096];
        vas.read_virt(vaddr, &mut buf).unwrap();
        assert!(
            buf.iter().all(|&b| b == 0),
            "demand-zero page must be all zeroes"
        );
    }

    #[test]
    fn read_virt_transition_reads_physical() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let pfn: u64 = 0x800;
        let (cr3, mem) = PageTableBuilder::new()
            .map_transition(vaddr, pfn)
            .write_phys(pfn * 0x1000, &[0xCA, 0xFE, 0xBA, 0xBE])
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let mut buf = [0u8; 4];
        vas.read_virt(vaddr, &mut buf).unwrap();
        assert_eq!(buf, [0xCA, 0xFE, 0xBA, 0xBE]);
    }

    #[test]
    fn read_virt_pagefile_with_provider() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_offset: u64 = 0x10;
        let mut page_data = [0u8; 4096];
        page_data[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let (cr3, mem) = PageTableBuilder::new()
            .map_pagefile(vaddr, 0, page_offset)
            .build();

        let mock = MockPagefileSource::new(0, vec![(page_offset, page_data)]);
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel)
            .with_pagefile(Box::new(mock));

        let mut buf = [0u8; 4];
        vas.read_virt(vaddr, &mut buf).unwrap();
        assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn read_virt_pagefile_without_provider_errors() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new().map_pagefile(vaddr, 0, 0x10).build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let mut buf = [0u8; 4];
        let result = vas.read_virt(vaddr, &mut buf);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::PagedOut {
                pagefile_num: 0,
                page_offset: 0x10,
                ..
            } => {}
            other => panic!("expected PagedOut, got: {other}"),
        }
    }

    #[test]
    fn read_virt_prototype_pte_errors() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new().map_prototype(vaddr).build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let mut buf = [0u8; 4];
        let result = vas.read_virt(vaddr, &mut buf);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::PrototypePte(addr) => assert_eq!(addr, vaddr),
            other => panic!("expected PrototypePte, got: {other}"),
        }
    }

    #[test]
    fn read_virt_pagefile_number_routing() {
        let vaddr1: u64 = 0xFFFF_8000_0010_0000;
        let vaddr2: u64 = 0xFFFF_8000_0010_1000;

        let mut page0_data = [0u8; 4096];
        page0_data[0..4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let mut page1_data = [0u8; 4096];
        page1_data[0..4].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        let (cr3, mem) = PageTableBuilder::new()
            .map_pagefile(vaddr1, 0, 0x10)
            .map_pagefile(vaddr2, 1, 0x20)
            .build();

        let mock0 = MockPagefileSource::new(0, vec![(0x10, page0_data)]);
        let mock1 = MockPagefileSource::new(1, vec![(0x20, page1_data)]);

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel)
            .with_pagefile(Box::new(mock0))
            .with_pagefile(Box::new(mock1));

        let mut buf1 = [0u8; 4];
        vas.read_virt(vaddr1, &mut buf1).unwrap();
        assert_eq!(buf1, [0x11, 0x22, 0x33, 0x44]);

        let mut buf2 = [0u8; 4];
        vas.read_virt(vaddr2, &mut buf2).unwrap();
        assert_eq!(buf2, [0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn read_virt_pagefile_out_of_range() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_pagefile(vaddr, 0, 0x9999)
            .build();
        let mock = MockPagefileSource::new(0, vec![]);
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel)
            .with_pagefile(Box::new(mock));
        let mut buf = [0u8; 4];
        let result = vas.read_virt(vaddr, &mut buf);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::PagedOut {
                page_offset: 0x9999,
                ..
            } => {}
            other => panic!("expected PagedOut, got: {other}"),
        }
    }

    #[test]
    fn read_virt_mixed_pages_cross_boundary() {
        let vaddr1: u64 = 0xFFFF_8000_0010_0000;
        let vaddr2: u64 = 0xFFFF_8000_0010_1000;
        let vaddr3: u64 = 0xFFFF_8000_0010_2000;
        let paddr1: u64 = 0x0080_0000;

        let mut pf_page = [0u8; 4096];
        pf_page[0..4].copy_from_slice(&[0xBB; 4]);

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr1, paddr1, flags::WRITABLE)
            .write_phys(paddr1 + 0xFFC, &[0xAA; 4])
            .map_pagefile(vaddr2, 0, 0x10)
            .map_demand_zero(vaddr3)
            .build();

        let mock = MockPagefileSource::new(0, vec![(0x10, pf_page)]);
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel)
            .with_pagefile(Box::new(mock));

        // Read spanning: last 4 bytes of phys page + first 4 bytes of pagefile page
        let mut buf = [0u8; 8];
        vas.read_virt(vaddr1 + 0xFFC, &mut buf).unwrap();
        assert_eq!(buf, [0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB]);

        // Read spanning: last 4 bytes of pagefile page + first 4 bytes of demand-zero page
        let mut buf2 = [0u8; 8];
        vas.read_virt(vaddr2 + 0xFFC, &mut buf2).unwrap();
        assert_eq!(buf2, [0u8; 8]);
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
