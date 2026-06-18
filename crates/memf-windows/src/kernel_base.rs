//! Recover the ntoskrnl image base virtual address by **reverse-mapping its
//! RSDS debug record**, for dumps where the low-stub `LmTarget` hint is wrong.
//!
//! The low-stub-based [`memf_symbols::resolve_kernel_base_va`] only page-scans a
//! ±2 MiB window around the hint, so it fails when the hint points far from the
//! real kernel (observed on `citadeldc01.mem`: hint `…cbe00000`, true base
//! `…cb804000`, ~6 MiB below). It also fails when ntoskrnl's PE *header* page is
//! not mapped at the guessed VA, so a virtual MZ scan can't find it.
//!
//! This locator sidesteps both: ntoskrnl's CodeView RSDS record (`RSDS` + GUID +
//! age + `ntkrnlmp.pdb`) is resident in physical memory; reverse-map its page to
//! a kernel VA through the page tables, then walk 4 KiB-grain *downward* for the
//! image's MZ/PE header (the base is page-granular under KASLR, never 2 MiB
//! aligned). All reads go through the address space, which resolves transition
//! PTEs — so a resident-but-not-valid kernel page is still readable.

use memf_core::vas::VirtualAddressSpace;
use memf_format::PhysicalMemoryProvider;

/// Page-table leaves examined before giving up the reverse-map (DoS cap).
const REVMAP_BUDGET: usize = 50_000_000;
/// How far below the RSDS VA to scan for the image MZ header.
const MZ_SCAN_BELOW: u64 = 20 * 1024 * 1024;
/// Physical scan chunk.
const CHUNK: usize = 1 << 20;
/// RSDS record name we anchor on.
const KERNEL_PDB: &[u8] = b"ntkrnlmp.pdb\0";

/// Recover the ntoskrnl image base VA via its RSDS record, or `None`.
///
/// Requires `vas` to be configured with the kernel DTB (so kernel VAs translate).
#[must_use]
pub fn resolve_kernel_base_via_rsds<P: PhysicalMemoryProvider>(
    vas: &VirtualAddressSpace<P>,
) -> Option<u64> {
    for rsds_phys in scan_phys_kernel_rsds_pages(vas.physical()) {
        let Some(rsds_va) = vas.find_kernel_va_for_phys(rsds_phys, REVMAP_BUDGET) else {
            continue;
        };
        let top = rsds_va & !0xFFF;
        let floor = top.saturating_sub(MZ_SCAN_BELOW);
        let mut va = top;
        while va >= floor {
            if is_amd64_pe_at(vas, va) {
                return Some(va);
            }
            va -= 0x1000;
        }
    }
    None
}

/// Read 1 page at `va` and report whether it is the start of an AMD64 PE image
/// (`MZ` … `PE\0\0`, machine 0x8664).
fn is_amd64_pe_at<P: PhysicalMemoryProvider>(vas: &VirtualAddressSpace<P>, va: u64) -> bool {
    let mut mz = [0u8; 2];
    if vas.read_virt(va, &mut mz).is_err() || mz != *b"MZ" {
        return false;
    }
    let mut e = [0u8; 4];
    if vas.read_virt(va + 0x3C, &mut e).is_err() {
        return false;
    }
    let e_lfanew = u32::from_le_bytes(e) as u64;
    if e_lfanew > 0x400 {
        return false;
    }
    let mut sig = [0u8; 6];
    if vas.read_virt(va + e_lfanew, &mut sig).is_err() {
        return false;
    }
    &sig[0..4] == b"PE\0\0" && u16::from_le_bytes([sig[4], sig[5]]) == 0x8664
}

/// Scan physical memory for the page(s) holding an ntoskrnl RSDS record and
/// yield each page-aligned physical address (most-likely first).
fn scan_phys_kernel_rsds_pages<P: PhysicalMemoryProvider + ?Sized>(prov: &P) -> Vec<u64> {
    let ranges: Vec<(u64, u64)> = {
        let r = prov.ranges();
        if r.is_empty() {
            vec![(0, prov.total_size())]
        } else {
            r.iter().map(|x| (x.start, x.end)).collect()
        }
    };
    let mut out = Vec::new();
    let mut buf = vec![0u8; CHUNK + KERNEL_PDB.len()];
    for (start, end) in ranges {
        let mut addr = start;
        while addr < end {
            let n = prov.read_phys(addr, &mut buf).unwrap_or(0);
            if n < KERNEL_PDB.len() {
                addr = addr.saturating_add(CHUNK as u64);
                continue;
            }
            let mut i = 0usize;
            while i + KERNEL_PDB.len() <= n {
                if &buf[i..i + KERNEL_PDB.len()] == KERNEL_PDB {
                    // The name follows "RSDS"(4) + GUID(16) + Age(4) = 24 bytes.
                    let name_pa = addr + i as u64;
                    if name_pa >= 24 {
                        let rsds_pa = name_pa - 24;
                        let mut tag = [0u8; 4];
                        if prov.read_phys(rsds_pa, &mut tag).unwrap_or(0) == 4 && &tag == b"RSDS" {
                            let page = rsds_pa & !0xFFF;
                            if !out.contains(&page) {
                                out.push(page);
                            }
                        }
                    }
                }
                i += 1;
            }
            addr = addr.saturating_add(CHUNK as u64 - KERNEL_PDB.len() as u64);
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::TranslationMode;
    use memf_format::{PhysicalRange, Result as FmtResult};

    /// Wrap a `SyntheticPhysMem` so it advertises a physical range (the builder's
    /// mem reports none, which would make the physical RSDS scan cover nothing).
    struct RangedMem {
        inner: SyntheticPhysMem,
        ranges: Vec<PhysicalRange>,
    }
    impl RangedMem {
        fn new(inner: SyntheticPhysMem) -> Self {
            let len = inner.data().len() as u64;
            Self {
                inner,
                ranges: vec![PhysicalRange { start: 0, end: len }],
            }
        }
    }
    impl PhysicalMemoryProvider for RangedMem {
        fn read_phys(&self, addr: u64, buf: &mut [u8]) -> FmtResult<usize> {
            self.inner.read_phys(addr, buf)
        }
        fn ranges(&self) -> &[PhysicalRange] {
            &self.ranges
        }
        fn format_name(&self) -> &str {
            "RangedSynthetic"
        }
    }

    /// Build a minimal AMD64 PE first page: MZ, e_lfanew=0x40, "PE\0\0", machine.
    fn pe_page() -> Vec<u8> {
        let mut p = vec![0u8; 0x1000];
        p[0] = b'M';
        p[1] = b'Z';
        p[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        p[0x40..0x44].copy_from_slice(b"PE\0\0");
        p[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
        p
    }

    /// Build an RSDS record page: "RSDS" + guid(16) + age(4) + "ntkrnlmp.pdb".
    fn rsds_page() -> Vec<u8> {
        let mut p = vec![0u8; 0x1000];
        p[0..4].copy_from_slice(b"RSDS");
        // guid + age occupy [4..24); leave as zeros.
        p[24..24 + KERNEL_PDB.len()].copy_from_slice(KERNEL_PDB);
        p
    }

    #[test]
    fn resolves_kernel_base_via_rsds_record() {
        let base_va = 0xFFFF_F800_0100_0000u64; // image base (has MZ)
        let rsds_va = base_va + 0x1_0000; // RSDS 64 KiB above base
        let base_pa = 0x20_0000u64;
        let rsds_pa = 0x30_0000u64;
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(base_va, base_pa, flags::WRITABLE)
            .map_4k(rsds_va, rsds_pa, flags::WRITABLE)
            .write_phys(base_pa, &pe_page())
            .write_phys(rsds_pa, &rsds_page())
            .build();
        let vas =
            VirtualAddressSpace::new(RangedMem::new(mem), cr3, TranslationMode::X86_64FourLevel);
        assert_eq!(resolve_kernel_base_via_rsds(&vas), Some(base_va));
    }

    #[test]
    fn returns_none_when_no_rsds_present() {
        let base_va = 0xFFFF_F800_0100_0000u64;
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(base_va, 0x20_0000, flags::WRITABLE)
            .write_phys(0x20_0000, &pe_page())
            .build();
        let vas =
            VirtualAddressSpace::new(RangedMem::new(mem), cr3, TranslationMode::X86_64FourLevel);
        assert_eq!(resolve_kernel_base_via_rsds(&vas), None);
    }

    #[test]
    fn returns_none_when_no_mz_below_rsds() {
        // RSDS present and reverse-mappable, but no MZ image below it.
        let rsds_va = 0xFFFF_F800_0100_0000u64;
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(rsds_va, 0x30_0000, flags::WRITABLE)
            .write_phys(0x30_0000, &rsds_page())
            .build();
        let vas =
            VirtualAddressSpace::new(RangedMem::new(mem), cr3, TranslationMode::X86_64FourLevel);
        assert_eq!(resolve_kernel_base_via_rsds(&vas), None);
    }
}
