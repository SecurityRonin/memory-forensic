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
        todo!()
    }

    /// Write bytes at a physical address.
    pub fn write_bytes(&mut self, addr: u64, bytes: &[u8]) {
        todo!()
    }

    /// Write a u64 value at a physical address (little-endian).
    pub fn write_u64(&mut self, addr: u64, value: u64) {
        todo!()
    }

    /// Read a u64 from a physical address (little-endian).
    pub fn read_u64(&self, addr: u64) -> u64 {
        todo!()
    }

    /// Return the raw data slice.
    pub fn data(&self) -> &[u8] {
        todo!()
    }
}

impl PhysicalMemoryProvider for SyntheticPhysMem {
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
        todo!()
    }

    fn alloc_page(&mut self) -> u64 {
        todo!()
    }

    /// Map a 4K virtual address to a physical address with given flags.
    pub fn map_4k(mut self, vaddr: u64, paddr: u64, page_flags: u64) -> Self {
        todo!()
    }

    /// Map a 2MB large page (sets PS bit at PD level).
    pub fn map_2m(mut self, vaddr: u64, paddr: u64, page_flags: u64) -> Self {
        todo!()
    }

    /// Map a 1GB huge page (sets PS bit at PDPT level).
    pub fn map_1g(mut self, vaddr: u64, paddr: u64, page_flags: u64) -> Self {
        todo!()
    }

    /// Write data bytes at a physical address in the synthetic memory.
    pub fn write_phys(mut self, addr: u64, data: &[u8]) -> Self {
        todo!()
    }

    /// Write a u64 value at a physical address.
    pub fn write_phys_u64(mut self, addr: u64, value: u64) -> Self {
        todo!()
    }

    /// Consume the builder and return the CR3 value + synthetic memory.
    pub fn build(self) -> (u64, SyntheticPhysMem) {
        todo!()
    }
}

impl Default for PageTableBuilder {
    fn default() -> Self {
        todo!()
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
}
