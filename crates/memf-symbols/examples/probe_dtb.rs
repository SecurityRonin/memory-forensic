//! G2 diagnostic: how far does header-less DTB discovery get on a raw dump?
//! Counts self-referencing PML4 candidates (per kernel-half slot) directly via
//! the public provider API, then reports whether `scan_for_kernel_dtb` selects
//! one. Distinguishes "no candidates" from "candidates that fail verification".
//!
//! Usage: cargo run --release -p memf-symbols --example probe_dtb -- <dump>

use memf_format::{open_dump_with_raw_fallback, PhysicalMemoryProvider};
use memf_symbols::scan_for_kernel_dtb;

const PRESENT: u64 = 1;
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const PAGE: usize = 4096;

fn main() {
    let path = std::env::args().nth(1).expect("usage: probe_dtb <dump>");
    let prov = open_dump_with_raw_fallback(std::path::Path::new(&path)).expect("open dump");
    println!("format: {}  total: {} bytes", prov.format_name(), prov.total_size());
    let ranges: Vec<_> = prov.ranges().to_vec();
    println!("ranges: {} (first={:?})", ranges.len(), ranges.first());

    let mut page = [0u8; PAGE];
    let mut candidates = 0usize;
    let mut first_few = Vec::new();
    for r in &ranges {
        let mut pa = r.start & !0xFFF;
        while pa < r.end {
            let n = prov.read_phys(pa, &mut page).unwrap_or(0);
            for idx in 0x100usize..0x200 {
                let off = idx * 8;
                if off + 8 > n {
                    break;
                }
                let e = u64::from_le_bytes(page[off..off + 8].try_into().unwrap());
                if e & PRESENT != 0 && (e & ADDR_MASK) == pa {
                    candidates += 1;
                    if first_few.len() < 12 {
                        first_few.push((pa, idx));
                    }
                    break;
                }
            }
            pa += PAGE as u64;
        }
    }
    println!("self-ref PML4 candidates: {candidates}");
    for (pa, idx) in &first_few {
        println!("  candidate dtb={pa:#x} self-map-index={idx:#x}");
    }
    // Focused walk on the lowest few candidates: replicate the verifier's
    // kernel-half descent and report present PML4Es / present PDPTEs / MZ hits,
    // isolating "translation fails" from "PE/RSDS check fails".
    for &(cr3, _) in first_few.iter().take(4) {
        let mut present_pml4 = 0u32;
        let mut present_pdpt = 0u32;
        let mut mz_hits = 0u32;
        let mut first_mz_va = 0u64;
        for p4 in 0x100u64..0x200 {
            let Some(e4) = rd_pte(&prov, (cr3 & ADDR_MASK) + p4 * 8) else { continue };
            if e4 & PRESENT == 0 { continue; }
            present_pml4 += 1;
            for p3 in 0u64..0x200 {
                let Some(e3) = rd_pte(&prov, (e4 & ADDR_MASK) + p3 * 8) else { continue };
                if e3 & PRESENT == 0 { continue; }
                present_pdpt += 1;
                let base = canon((p4 << 39) | (p3 << 30));
                for slot in 0..512u64 {
                    let va = base + slot * 0x20_0000;
                    let mut sig = [0u8; 2];
                    if rd_virt(&prov, cr3, va, &mut sig) == 2 && sig == [b'M', b'Z'] {
                        mz_hits += 1;
                        if first_mz_va == 0 { first_mz_va = va; }
                    }
                }
            }
        }
        println!(
            "cr3={cr3:#x}: present_pml4={present_pml4} present_pdpt={present_pdpt} mz_hits={mz_hits} first_mz_va={first_mz_va:#x}"
        );
    }

    // List EVERY kernel-half MZ image under the lowest candidate with the PDB
    // name the tolerant scan recovers — is ntkrnlmp among them, and if so why
    // is it rejected?
    if let Some(&(cr3, _)) = first_few.first() {
        println!("all kernel-half MZ images under cr3={cr3:#x}:");
        for p4 in 0x100u64..0x200 {
            let Some(e4) = rd_pte(&prov, (cr3 & ADDR_MASK) + p4 * 8) else { continue };
            if e4 & PRESENT == 0 { continue; }
            for p3 in 0u64..0x200 {
                let Some(e3) = rd_pte(&prov, (e4 & ADDR_MASK) + p3 * 8) else { continue };
                if e3 & PRESENT == 0 { continue; }
                let base = canon((p4 << 39) | (p3 << 30));
                for slot in 0..512u64 {
                    let va = base + slot * 0x20_0000;
                    let mut sig = [0u8; 2];
                    if rd_virt(&prov, cr3, va, &mut sig) != 2 || sig != [b'M', b'Z'] { continue; }
                    let mut hdr = [0u8; 4096];
                    let _ = rd_virt(&prov, cr3, va, &mut hdr);
                    let elf = u32::from_le_bytes([hdr[0x3C], hdr[0x3D], hdr[0x3E], hdr[0x3F]]) as usize;
                    let opt = elf + 24;
                    let soi = hdr.get(opt + 56..opt + 60)
                        .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
                    let scan_len = (soi as usize).clamp(4096, 0x30_0000);
                    let mut img = vec![0u8; scan_len];
                    let got = rd_virt(&prov, cr3, va, &mut img);
                    img.truncate(got);
                    let name = match memf_symbols::pe_debug::extract_pdb_id_tolerant(&img) {
                        Ok(id) => id.pdb_name,
                        Err(e) => format!("<err: {e}>"),
                    };
                    println!("  va={va:#x} SizeOfImage={soi:#x} filled={got:#x} pdb={name:?}");
                }
            }
        }
    }

    // Finer scan: 64 KiB-aligned VAs across present PDPT regions, hunting any
    // MZ whose PDB name contains "nt" — pinpoints ntoskrnl's true alignment.
    if let Some(&(cr3, _)) = first_few.first() {
        println!("64KiB-granular kernel-name hits under cr3={cr3:#x}:");
        let mut hits = 0;
        'outer: for p4 in 0x100u64..0x200 {
            let Some(e4) = rd_pte(&prov, (cr3 & ADDR_MASK) + p4 * 8) else { continue };
            if e4 & PRESENT == 0 { continue; }
            for p3 in 0u64..0x200 {
                let Some(e3) = rd_pte(&prov, (e4 & ADDR_MASK) + p3 * 8) else { continue };
                if e3 & PRESENT == 0 { continue; }
                let base = canon((p4 << 39) | (p3 << 30));
                for slot in 0..(0x4000_0000u64 / 0x1_0000) {
                    let va = base + slot * 0x1_0000;
                    let mut sig = [0u8; 2];
                    if rd_virt(&prov, cr3, va, &mut sig) != 2 || sig != [b'M', b'Z'] { continue; }
                    let mut img = vec![0u8; 0x30_0000];
                    let got = rd_virt(&prov, cr3, va, &mut img);
                    img.truncate(got);
                    if let Ok(id) = memf_symbols::pe_debug::extract_pdb_id_tolerant(&img) {
                        let l = id.pdb_name.to_lowercase();
                        if l.contains("nt") {
                            println!("  va={va:#x} (2MiB-aligned={}) pdb={:?}", va & 0x1F_FFFF == 0, id.pdb_name);
                            hits += 1;
                            if hits >= 6 { break 'outer; }
                        }
                    }
                }
            }
        }
        if hits == 0 { println!("  (none — ntoskrnl MZ header not resident, or deeper alignment)"); }
    }

    match scan_for_kernel_dtb(&prov) {
        Some(dtb) => println!("scan_for_kernel_dtb => {dtb:#x} (VERIFIED kernel DTB)"),
        None => println!("scan_for_kernel_dtb => None (no candidate verified as mapping a kernel)"),
    }
}

fn rd_pte(p: &dyn PhysicalMemoryProvider, pa: u64) -> Option<u64> {
    let mut b = [0u8; 8];
    if p.read_phys(pa, &mut b).unwrap_or(0) < 8 { return None; }
    Some(u64::from_le_bytes(b))
}

fn canon(va: u64) -> u64 {
    if va & (1 << 47) != 0 { va | 0xFFFF_0000_0000_0000 } else { va }
}

fn v2p(p: &dyn PhysicalMemoryProvider, cr3: u64, va: u64) -> Option<u64> {
    let i4 = (va >> 39) & 0x1FF;
    let i3 = (va >> 30) & 0x1FF;
    let i2 = (va >> 21) & 0x1FF;
    let i1 = (va >> 12) & 0x1FF;
    let e4 = rd_pte(p, (cr3 & ADDR_MASK) + i4 * 8)?;
    if e4 & PRESENT == 0 { return None; }
    let e3 = rd_pte(p, (e4 & ADDR_MASK) + i3 * 8)?;
    if e3 & PRESENT == 0 { return None; }
    if e3 & (1 << 7) != 0 { return Some((e3 & 0x000F_FFFF_C000_0000) | (va & 0x3FFF_FFFF)); }
    let e2 = rd_pte(p, (e3 & ADDR_MASK) + i2 * 8)?;
    if e2 & PRESENT == 0 { return None; }
    if e2 & (1 << 7) != 0 { return Some((e2 & 0x000F_FFFF_FFE0_0000) | (va & 0x1F_FFFF)); }
    let e1 = rd_pte(p, (e2 & ADDR_MASK) + i1 * 8)?;
    if e1 & PRESENT == 0 { return None; }
    Some((e1 & ADDR_MASK) | (va & 0xFFF))
}

fn rd_virt(p: &dyn PhysicalMemoryProvider, cr3: u64, va: u64, buf: &mut [u8]) -> usize {
    let mut filled = 0;
    while filled < buf.len() {
        let cur = va + filled as u64;
        let off = (cur & 0xFFF) as usize;
        let chunk = (PAGE - off).min(buf.len() - filled);
        let Some(pa) = v2p(p, cr3, cur) else { break };
        let n = p.read_phys(pa, &mut buf[filled..filled + chunk]).unwrap_or(0);
        if n == 0 { break; }
        filled += n;
        if n < chunk { break; }
    }
    filled
}
