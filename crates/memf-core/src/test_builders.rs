//! Test builders for synthetic page tables and kernel structs.

use memf_format::{PhysicalMemoryProvider, PhysicalRange};

/// A synthetic physical memory image for testing.
#[derive(Debug, Clone)]
pub struct SyntheticPhysMem {
    data: Vec<u8>,
}

impl SyntheticPhysMem {
    /// Create a new synthetic image of `size` bytes, zero-filled.
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }

    /// Write bytes at a physical address.
    pub fn write_bytes(&mut self, addr: u64, bytes: &[u8]) {
        let start = addr as usize;
        self.data[start..start + bytes.len()].copy_from_slice(bytes);
    }

    /// Write a u64 value at a physical address (little-endian).
    pub fn write_u64(&mut self, addr: u64, value: u64) {
        self.write_bytes(addr, &value.to_le_bytes());
    }

    /// Read a u64 from a physical address (little-endian).
    pub fn read_u64(&self, addr: u64) -> u64 {
        let start = addr as usize;
        u64::from_le_bytes(self.data[start..start + 8].try_into().unwrap())
    }

    /// Return the raw data slice.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl PhysicalMemoryProvider for SyntheticPhysMem {
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> memf_format::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
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
        &[]
    }
    fn format_name(&self) -> &str {
        "Synthetic"
    }
}

/// Page table entry flags for x86_64.
pub mod flags {
    /// Page is present in physical memory.
    pub const PRESENT: u64 = 1 << 0;
    /// Page is writable.
    pub const WRITABLE: u64 = 1 << 1;
    /// Page is accessible from user mode.
    pub const USER: u64 = 1 << 2;
    /// Page Size bit: indicates a large/huge page at PD/PDPT level.
    pub const PS: u64 = 1 << 7;
}

/// Builder for x86_64 4-level page tables.
pub struct PageTableBuilder {
    mem: SyntheticPhysMem,
    next_page: u64,
    cr3: u64,
}

impl PageTableBuilder {
    /// Physical address of the PML4 table (CR3).
    pub const CR3: u64 = 0x0000_0000;
    const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    /// Create a new builder with a 16 MB synthetic memory image.
    pub fn new() -> Self {
        let mut mem = SyntheticPhysMem::new(16 * 1024 * 1024);
        let cr3 = Self::CR3;
        let next_page = 0x1000;
        // Zero-initialize the PML4 table at CR3
        for i in 0..512 {
            mem.write_u64(cr3 + i * 8, 0);
        }
        Self {
            mem,
            next_page,
            cr3,
        }
    }

    fn alloc_page(&mut self) -> u64 {
        let addr = self.next_page;
        self.next_page += 0x1000;
        // Zero-initialize the new page
        for i in 0..512 {
            self.mem.write_u64(addr + i * 8, 0);
        }
        addr
    }

    /// Map a 4K virtual address to a physical address with given flags.
    pub fn map_4k(mut self, vaddr: u64, paddr: u64, page_flags: u64) -> Self {
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pd_idx = (vaddr >> 21) & 0x1FF;
        let pt_idx = (vaddr >> 12) & 0x1FF;

        // PML4 -> PDPT
        let pml4e_addr = self.cr3 + pml4_idx * 8;
        let mut pml4e = self.mem.read_u64(pml4e_addr);
        if pml4e & flags::PRESENT == 0 {
            let pdpt_page = self.alloc_page();
            pml4e = pdpt_page | flags::PRESENT | flags::WRITABLE;
            self.mem.write_u64(pml4e_addr, pml4e);
        }
        let pdpt_base = pml4e & Self::ADDR_MASK;

        // PDPT -> PD
        let pdpte_addr = pdpt_base + pdpt_idx * 8;
        let mut pdpte = self.mem.read_u64(pdpte_addr);
        if pdpte & flags::PRESENT == 0 {
            let pd_page = self.alloc_page();
            pdpte = pd_page | flags::PRESENT | flags::WRITABLE;
            self.mem.write_u64(pdpte_addr, pdpte);
        }
        let pd_base = pdpte & Self::ADDR_MASK;

        // PD -> PT
        let pde_addr = pd_base + pd_idx * 8;
        let mut pde = self.mem.read_u64(pde_addr);
        if pde & flags::PRESENT == 0 {
            let pt_page = self.alloc_page();
            pde = pt_page | flags::PRESENT | flags::WRITABLE;
            self.mem.write_u64(pde_addr, pde);
        }
        let pt_base = pde & Self::ADDR_MASK;

        // PT entry -> physical page
        let pte_addr = pt_base + pt_idx * 8;
        let pte = (paddr & Self::ADDR_MASK) | page_flags | flags::PRESENT;
        self.mem.write_u64(pte_addr, pte);
        self
    }

    /// Map a 2MB large page (sets PS bit at PD level).
    pub fn map_2m(mut self, vaddr: u64, paddr: u64, page_flags: u64) -> Self {
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pd_idx = (vaddr >> 21) & 0x1FF;

        // PML4 -> PDPT
        let pml4e_addr = self.cr3 + pml4_idx * 8;
        let mut pml4e = self.mem.read_u64(pml4e_addr);
        if pml4e & flags::PRESENT == 0 {
            let pdpt_page = self.alloc_page();
            pml4e = pdpt_page | flags::PRESENT | flags::WRITABLE;
            self.mem.write_u64(pml4e_addr, pml4e);
        }
        let pdpt_base = pml4e & Self::ADDR_MASK;

        // PDPT -> PD
        let pdpte_addr = pdpt_base + pdpt_idx * 8;
        let mut pdpte = self.mem.read_u64(pdpte_addr);
        if pdpte & flags::PRESENT == 0 {
            let pd_page = self.alloc_page();
            pdpte = pd_page | flags::PRESENT | flags::WRITABLE;
            self.mem.write_u64(pdpte_addr, pdpte);
        }
        let pd_base = pdpte & Self::ADDR_MASK;

        // PD entry with PS bit set for 2MB page
        let pde_addr = pd_base + pd_idx * 8;
        let pde = (paddr & 0x000F_FFFF_FFE0_0000) | page_flags | flags::PRESENT | flags::PS;
        self.mem.write_u64(pde_addr, pde);
        self
    }

    /// Map a 1GB huge page (sets PS bit at PDPT level).
    pub fn map_1g(mut self, vaddr: u64, paddr: u64, page_flags: u64) -> Self {
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pdpt_idx = (vaddr >> 30) & 0x1FF;

        // PML4 -> PDPT
        let pml4e_addr = self.cr3 + pml4_idx * 8;
        let mut pml4e = self.mem.read_u64(pml4e_addr);
        if pml4e & flags::PRESENT == 0 {
            let pdpt_page = self.alloc_page();
            pml4e = pdpt_page | flags::PRESENT | flags::WRITABLE;
            self.mem.write_u64(pml4e_addr, pml4e);
        }
        let pdpt_base = pml4e & Self::ADDR_MASK;

        // PDPT entry with PS bit set for 1GB page
        let pdpte_addr = pdpt_base + pdpt_idx * 8;
        let pdpte = (paddr & 0x000F_FFFF_C000_0000) | page_flags | flags::PRESENT | flags::PS;
        self.mem.write_u64(pdpte_addr, pdpte);
        self
    }

    /// Write data bytes at a physical address in the synthetic memory.
    pub fn write_phys(mut self, addr: u64, data: &[u8]) -> Self {
        self.mem.write_bytes(addr, data);
        self
    }

    /// Write a u64 value at a physical address.
    pub fn write_phys_u64(mut self, addr: u64, value: u64) -> Self {
        self.mem.write_u64(addr, value);
        self
    }

    /// Consume the builder and return the CR3 value + synthetic memory.
    pub fn build(self) -> (u64, SyntheticPhysMem) {
        (self.cr3, self.mem)
    }
}

impl Default for PageTableBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock pagefile source for testing pagefile PTE resolution.
pub struct MockPagefileSource {
    pagefile_num: u8,
    pages: std::collections::HashMap<u64, [u8; 4096]>,
}

impl MockPagefileSource {
    /// Create a mock with the given pagefile number and pre-loaded pages.
    /// Each tuple is `(page_offset, page_data)`.
    pub fn new(pagefile_num: u8, pages: Vec<(u64, [u8; 4096])>) -> Self {
        Self {
            pagefile_num,
            pages: pages.into_iter().collect(),
        }
    }
}

impl crate::pagefile::PagefileSource for MockPagefileSource {
    fn pagefile_number(&self) -> u8 {
        self.pagefile_num
    }

    fn read_page(&self, page_offset: u64) -> crate::Result<Option<[u8; 4096]>> {
        Ok(self.pages.get(&page_offset).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_mem_read_write() {
        let mut mem = SyntheticPhysMem::new(4096);
        mem.write_bytes(0x100, &[0xAA, 0xBB, 0xCC, 0xDD]);
        let mut buf = [0u8; 4];
        let n = mem.read_phys(0x100, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn synthetic_mem_u64() {
        let mut mem = SyntheticPhysMem::new(4096);
        mem.write_u64(0x200, 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(mem.read_u64(0x200), 0xDEAD_BEEF_CAFE_BABE);
    }

    #[test]
    fn page_table_builder_creates_pml4() {
        let (cr3, mem) = PageTableBuilder::new().build();
        assert_eq!(cr3, 0);
        for i in 0..512 {
            assert_eq!(mem.read_u64(cr3 + i * 8), 0);
        }
    }

    #[test]
    fn page_table_builder_map_4k() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &[0x42; 64])
            .build();
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pml4e = mem.read_u64(cr3 + pml4_idx * 8);
        assert_ne!(pml4e & flags::PRESENT, 0);
        let mut buf = [0u8; 4];
        mem.read_phys(paddr, &mut buf).unwrap();
        assert_eq!(buf, [0x42; 4]);
    }

    #[test]
    fn page_table_builder_map_2m() {
        let vaddr: u64 = 0xFFFF_8000_0020_0000;
        let paddr: u64 = 0x0100_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_2m(vaddr, paddr, flags::WRITABLE)
            .build();
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pml4e = mem.read_u64(cr3 + pml4_idx * 8);
        assert_ne!(pml4e & flags::PRESENT, 0);
    }

    #[test]
    fn mock_pagefile_source_read_page() {
        use crate::pagefile::PagefileSource;

        let mut page_data = [0xABu8; 4096];
        page_data[0] = 0x42;
        let mock = MockPagefileSource::new(0, vec![(0x10, page_data)]);
        assert_eq!(mock.pagefile_number(), 0);
        let page = mock.read_page(0x10).unwrap().unwrap();
        assert_eq!(page[0], 0x42);
        assert_eq!(page[1], 0xAB);
    }

    #[test]
    fn mock_pagefile_source_missing_page() {
        use crate::pagefile::PagefileSource;

        let mock = MockPagefileSource::new(1, vec![]);
        assert_eq!(mock.pagefile_number(), 1);
        assert!(mock.read_page(0x999).unwrap().is_none());
    }
}
