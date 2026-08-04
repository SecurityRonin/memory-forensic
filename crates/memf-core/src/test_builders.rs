//! Test builders for synthetic page tables and kernel structs.
//!
//! Test-fixture infrastructure (a `pub mod` reachable from integration tests);
//! panic-on-failure via `unwrap`/`expect` is intended — a broken fixture
//! should fail loudly, not silently degrade.
#![allow(clippy::unwrap_used, clippy::expect_used)]

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

/// A [`SyntheticPhysMem`] that advertises a physical extent.
///
/// [`SyntheticPhysMem`] deliberately reports no ranges, which models a provider
/// that cannot enumerate its own layout. But
/// [`PhysicalMemoryProvider::total_size`] is derived by summing those ranges, so
/// it is zero — and a physical scan bounded by that extent traverses `(0, 0)`
/// and sees nothing, however many bytes the image really holds.
///
/// Anything under test that *scans* physical memory therefore needs a provider
/// that says how big it is. Wrap the image:
///
/// ```
/// use memf_core::test_builders::{PageTableBuilder, RangedPhysMem};
/// use memf_format::PhysicalMemoryProvider;
///
/// let (_cr3, mem) = PageTableBuilder::new().build();
/// let scannable = RangedPhysMem::whole(mem);
/// assert!(scannable.total_size() > 0);
/// ```
///
/// Use [`RangedPhysMem::with_ranges`] when the shape matters — a real dump is
/// rarely one contiguous span, and a scanner that mishandles a gap is exactly
/// the kind of defect a contiguous fixture hides.
#[derive(Debug, Clone)]
pub struct RangedPhysMem {
    inner: SyntheticPhysMem,
    ranges: Vec<PhysicalRange>,
}

impl RangedPhysMem {
    /// Advertise the whole image as one contiguous range.
    #[must_use]
    pub fn whole(inner: SyntheticPhysMem) -> Self {
        let end = inner.data().len() as u64;
        Self {
            inner,
            ranges: vec![PhysicalRange { start: 0, end }],
        }
    }

    /// Advertise explicit ranges, for images with gaps.
    ///
    /// The ranges describe what the provider *claims*; they are not checked
    /// against the backing image, so a test can deliberately advertise an extent
    /// that does not match — which is how you exercise a consumer's handling of
    /// a truncated or over-declared dump.
    #[must_use]
    pub fn with_ranges(inner: SyntheticPhysMem, ranges: Vec<PhysicalRange>) -> Self {
        Self { inner, ranges }
    }
}

impl PhysicalMemoryProvider for RangedPhysMem {
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> memf_format::Result<usize> {
        self.inner.read_phys(addr, buf)
    }

    fn ranges(&self) -> &[PhysicalRange] {
        &self.ranges
    }

    fn format_name(&self) -> &str {
        "Synthetic(ranged)"
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

    /// Ensure PML4→PDPT→PD→PT hierarchy exists for a 4K vaddr, returning the PT entry address.
    fn ensure_pt_entry(&mut self, vaddr: u64) -> u64 {
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

        pt_base + pt_idx * 8
    }

    /// Map a demand-zero PTE: upper levels present, PT entry = 0.
    pub fn map_demand_zero(mut self, vaddr: u64) -> Self {
        let pte_addr = self.ensure_pt_entry(vaddr);
        // PT entry is already zero from page allocation; write explicitly for clarity
        self.mem.write_u64(pte_addr, 0);
        self
    }

    /// Map a transition PTE: PRESENT=0, bit 11 (TRANSITION)=1, PFN in bits [12..48].
    pub fn map_transition(mut self, vaddr: u64, pfn: u64) -> Self {
        let pte_addr = self.ensure_pt_entry(vaddr);
        let pte = (pfn << 12) | (1 << 11);
        self.mem.write_u64(pte_addr, pte);
        self
    }

    /// Map a pagefile PTE: PRESENT=0, pagefile_num in bits [1..5], page_offset in bits [12..48].
    pub fn map_pagefile(mut self, vaddr: u64, pagefile_num: u8, page_offset: u64) -> Self {
        let pte_addr = self.ensure_pt_entry(vaddr);
        let pte = ((u64::from(pagefile_num) & 0xF) << 1) | (page_offset << 12);
        self.mem.write_u64(pte_addr, pte);
        self
    }

    /// Map a prototype PTE: PRESENT=0, bit 10 (PROTOTYPE)=1.
    pub fn map_prototype(mut self, vaddr: u64) -> Self {
        let pte_addr = self.ensure_pt_entry(vaddr);
        let pte: u64 = 1 << 10;
        self.mem.write_u64(pte_addr, pte);
        self
    }

    /// Map a prototype PTE with a specific raw PTE value. Bit 10 must be set.
    pub fn map_prototype_raw(mut self, vaddr: u64, raw_pte: u64) -> Self {
        assert!(raw_pte & (1 << 10) != 0, "prototype bit (10) must be set");
        assert!(raw_pte & 1 == 0, "PRESENT bit must be clear");
        let pte_addr = self.ensure_pt_entry(vaddr);
        self.mem.write_u64(pte_addr, raw_pte);
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

/// Mock prototype PTE source for testing prototype PTE resolution.
pub struct MockPrototypePteSource {
    /// Maps raw PTE value -> resolved physical address.
    entries: std::collections::HashMap<u64, u64>,
}

impl MockPrototypePteSource {
    /// Create a mock with the given `(pte_value, phys_addr)` pairs.
    pub fn new(entries: Vec<(u64, u64)>) -> Self {
        Self {
            entries: entries.into_iter().collect(),
        }
    }
}

impl crate::proto_pte::PrototypePteSource for MockPrototypePteSource {
    fn resolve(&self, pte_value: u64) -> Option<u64> {
        self.entries.get(&pte_value).copied()
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

/// Build an `ObjectReader` from a pre-built ISF JSON value and an empty page table.
///
/// Eliminates the four-line setup boilerplate that repeats across every walker test:
/// resolver construction, page table build, VAS construction, and reader assembly.
pub fn make_reader(
    isf: &memf_symbols::test_builders::IsfBuilder,
) -> crate::object_reader::ObjectReader<SyntheticPhysMem> {
    let json = isf.build_json();
    let resolver = memf_symbols::isf::IsfResolver::from_value(&json).unwrap();
    let (cr3, mem) = PageTableBuilder::new().build();
    let vas = crate::vas::VirtualAddressSpace::new(
        mem,
        cr3,
        crate::vas::TranslationMode::X86_64FourLevel,
    );
    crate::object_reader::ObjectReader::new(vas, Box::new(resolver))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The trap this module's ranged provider exists to close, asserted rather
    /// than merely described: `SyntheticPhysMem` advertises no ranges, and
    /// `PhysicalMemoryProvider::total_size` is derived by summing them, so a
    /// 16 MiB image reports a size of zero. Every physical scan bounds itself by
    /// that extent, so scanning code under test traverses `(0, 0)` and sees
    /// nothing — passing for the wrong reason.
    #[test]
    fn plain_synthetic_mem_advertises_no_extent() {
        let mem = SyntheticPhysMem::new(16 * 1024 * 1024);
        assert!(mem.ranges().is_empty());
        assert_eq!(
            mem.total_size(),
            0,
            "if this ever becomes non-zero the ranged wrapper is redundant"
        );
    }

    /// A ranged provider must report the extent it actually holds, so that a
    /// scan bounded by `total_size()` covers the bytes a test wrote.
    #[test]
    fn ranged_provider_advertises_the_whole_image() {
        let mut mem = SyntheticPhysMem::new(1024 * 1024);
        mem.write_bytes(0x40_000, b"19041.1.amd64fre.vb_release.191206-1406\0");
        let ranged = RangedPhysMem::whole(mem);

        assert_eq!(ranged.ranges().len(), 1);
        assert_eq!(ranged.total_size(), 1024 * 1024);

        // The bytes are reachable through the extent the provider advertises.
        let (start, end) = (ranged.ranges()[0].start, ranged.ranges()[0].end);
        assert!(start == 0 && end == 1024 * 1024);
        let mut buf = [0u8; 8];
        assert_eq!(ranged.read_phys(0x40_000, &mut buf).unwrap(), 8);
        assert_eq!(&buf, b"19041.1.");
    }

    /// Sparse images are the realistic case — a dump is rarely one contiguous
    /// span — so explicit ranges must be expressible too.
    #[test]
    fn ranged_provider_accepts_explicit_sparse_ranges() {
        let mem = SyntheticPhysMem::new(1024 * 1024);
        let ranged = RangedPhysMem::with_ranges(
            mem,
            vec![
                PhysicalRange {
                    start: 0,
                    end: 0x1000,
                },
                PhysicalRange {
                    start: 0x10_000,
                    end: 0x11_000,
                },
            ],
        );
        assert_eq!(ranged.ranges().len(), 2);
        assert_eq!(ranged.total_size(), 0x2000, "sum of the declared ranges");
    }

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

    #[test]
    fn page_table_builder_map_demand_zero() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new().map_demand_zero(vaddr).build();
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pml4e = mem.read_u64(cr3 + pml4_idx * 8);
        assert_ne!(pml4e & flags::PRESENT, 0, "PML4 entry should be present");
        let pdpt_base = pml4e & PageTableBuilder::ADDR_MASK;
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pdpte = mem.read_u64(pdpt_base + pdpt_idx * 8);
        assert_ne!(pdpte & flags::PRESENT, 0, "PDPT entry should be present");
        let pd_base = pdpte & PageTableBuilder::ADDR_MASK;
        let pd_idx = (vaddr >> 21) & 0x1FF;
        let pde = mem.read_u64(pd_base + pd_idx * 8);
        assert_ne!(pde & flags::PRESENT, 0, "PD entry should be present");
        let pt_base = pde & PageTableBuilder::ADDR_MASK;
        let pt_idx = (vaddr >> 12) & 0x1FF;
        let pte = mem.read_u64(pt_base + pt_idx * 8);
        assert_eq!(pte, 0, "demand-zero PTE must be all zeros");
    }

    #[test]
    fn page_table_builder_map_transition_pte() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let pfn: u64 = 0x800;
        let (cr3, mem) = PageTableBuilder::new().map_transition(vaddr, pfn).build();
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pml4e = mem.read_u64(cr3 + pml4_idx * 8);
        let pdpt_base = pml4e & PageTableBuilder::ADDR_MASK;
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pdpte = mem.read_u64(pdpt_base + pdpt_idx * 8);
        let pd_base = pdpte & PageTableBuilder::ADDR_MASK;
        let pd_idx = (vaddr >> 21) & 0x1FF;
        let pde = mem.read_u64(pd_base + pd_idx * 8);
        let pt_base = pde & PageTableBuilder::ADDR_MASK;
        let pt_idx = (vaddr >> 12) & 0x1FF;
        let pte = mem.read_u64(pt_base + pt_idx * 8);
        assert_eq!(pte & 1, 0, "PRESENT must be clear");
        assert_ne!(pte & (1 << 11), 0, "TRANSITION bit must be set");
        assert_eq!((pte >> 12) & 0xF_FFFF_FFFF, pfn, "PFN must match");
    }

    #[test]
    fn page_table_builder_map_pagefile_pte() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let pagefile_num: u8 = 0;
        let page_offset: u64 = 0x5678;
        let (cr3, mem) = PageTableBuilder::new()
            .map_pagefile(vaddr, pagefile_num, page_offset)
            .build();
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pml4e = mem.read_u64(cr3 + pml4_idx * 8);
        let pdpt_base = pml4e & PageTableBuilder::ADDR_MASK;
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pdpte = mem.read_u64(pdpt_base + pdpt_idx * 8);
        let pd_base = pdpte & PageTableBuilder::ADDR_MASK;
        let pd_idx = (vaddr >> 21) & 0x1FF;
        let pde = mem.read_u64(pd_base + pd_idx * 8);
        let pt_base = pde & PageTableBuilder::ADDR_MASK;
        let pt_idx = (vaddr >> 12) & 0x1FF;
        let pte = mem.read_u64(pt_base + pt_idx * 8);
        assert_eq!(pte & 1, 0, "PRESENT must be clear");
        assert_eq!((pte >> 1) & 0xF, u64::from(pagefile_num), "pagefile_num");
        assert_eq!(pte & (1 << 10), 0, "prototype bit must be clear");
        assert_eq!(pte & (1 << 11), 0, "transition bit must be clear");
        assert_eq!((pte >> 12) & 0xF_FFFF_FFFF, page_offset, "page_offset");
    }

    #[test]
    fn page_table_builder_map_prototype_pte() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new().map_prototype(vaddr).build();
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pml4e = mem.read_u64(cr3 + pml4_idx * 8);
        let pdpt_base = pml4e & PageTableBuilder::ADDR_MASK;
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pdpte = mem.read_u64(pdpt_base + pdpt_idx * 8);
        let pd_base = pdpte & PageTableBuilder::ADDR_MASK;
        let pd_idx = (vaddr >> 21) & 0x1FF;
        let pde = mem.read_u64(pd_base + pd_idx * 8);
        let pt_base = pde & PageTableBuilder::ADDR_MASK;
        let pt_idx = (vaddr >> 12) & 0x1FF;
        let pte = mem.read_u64(pt_base + pt_idx * 8);
        assert_eq!(pte & 1, 0, "PRESENT must be clear");
        assert_ne!(pte & (1 << 10), 0, "PROTOTYPE bit must be set");
    }
}
