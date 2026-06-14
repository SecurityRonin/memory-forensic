//! Kernel PE scanner for Windows physical memory dumps.
//!
//! Scans physical pages for the ntoskrnl.exe MZ header and extracts
//! the PDB identification (GUID + age + filename) from its CodeView
//! debug directory.
//!
//! The scan-then-fetch technique — locating the kernel PE in physical memory,
//! reading its CodeView RSDS GUID, and resolving the matching PDB from
//! `msdl.microsoft.com` — was documented by S12:
//! <https://medium.com/@s12deff/kernel-dynamic-offset-resolution-using-pdb-symbols-b0aaa499ac25>

use memf_format::PhysicalMemoryProvider;

use crate::pe_debug::PdbId;

/// Physical address range to scan for the kernel (1 MiB – 128 MiB).
/// The Windows kernel always loads within this window on x64 systems.
const SCAN_START: u64 = 0x0010_0000;
const SCAN_END: u64 = 0x0800_0000;
const PAGE_SIZE: usize = 0x1000;

/// 2 MiB — the granularity the kernel image base is aligned to.
const TWO_MIB: u64 = 0x20_0000;
/// How far below the anchor to search (256 MiB of kernel VA space).
const DTB_DESCENT_WINDOW: u64 = 0x1000_0000;
/// Cap on how many bytes of a candidate image to scan for the RSDS record.
const MAX_IMAGE_SCAN: usize = 0x30_0000; // 3 MiB

/// The x64 boot "Low Stub" (`PROCESSOR_START_BLOCK`) recovered from low physical
/// memory: it carries both the kernel page-table base (CR3/DTB) and a kernel
/// virtual-address hint, neither of which depends on ntoskrnl's PE header being
/// page-resident. This is the authoritative header-less anchor (the technique
/// Volatility 3's `method_low_stub` uses; reimplemented clean-room from the
/// documented `PROCESSOR_START_BLOCK` layout, not copied).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LowStub {
    /// Kernel page-table base (physical), 4 KiB-aligned.
    pub cr3: u64,
    /// 2 MiB-aligned kernel image base **virtual** address (the KVO hint), to
    /// which symbol RVAs are added.
    pub kernel_base_va: u64,
}

// PROCESSOR_START_BLOCK field layout (AMD64 WRK), the architectural constants
// the Low Stub scan keys on.
const LOW_STUB_SIGNATURE: u64 = 0x0000_0001_0006_00E9;
// The jmp offset's low byte varies, so wildcard bits 8:15 in the match.
const LOW_STUB_SIGNATURE_MASK: u64 = 0xFFFF_FFFF_FFFF_00FF;
const PSB_LM_TARGET_OFFSET: u64 = 0x70; // PROCESSOR_START_BLOCK->LmTarget (PVOID)
const PSB_CR3_OFFSET: u64 = 0xA0; // ...->ProcessorState->SpecialRegisters->Cr3

/// Recover the [`LowStub`] by scanning the lower 1 MiB of physical memory for the
/// `PROCESSOR_START_BLOCK` signature. Returns `None` if not present (e.g. the
/// "Discard Low Memory" BIOS case can push it past the first MiB, or the page is
/// absent). Panic-free and bounds-checked.
#[must_use]
pub fn find_low_stub<P: PhysicalMemoryProvider>(mem: &P) -> Option<LowStub> {
    let read_u64 = |pa: u64| -> Option<u64> {
        let mut b = [0u8; 8];
        if mem.read_phys(pa, &mut b).unwrap_or(0) < 8 {
            return None;
        }
        Some(u64::from_le_bytes(b))
    };
    // Start at the second page (the first is the real-mode IVT / BIOS area).
    let mut offset = 0x1000u64;
    while offset < 0x10_0000 {
        if let Some(sig) = read_u64(offset) {
            if sig & LOW_STUB_SIGNATURE_MASK == LOW_STUB_SIGNATURE {
                if let (Some(cr3), Some(lm_target)) = (
                    read_u64(offset + PSB_CR3_OFFSET),
                    read_u64(offset + PSB_LM_TARGET_OFFSET),
                ) {
                    // LmTarget is a canonical kernel VA; the low two bits must be
                    // clear (it is a code address). Reject otherwise.
                    if lm_target & 0x3 == 0 {
                        // 48-bit hint → 2 MiB-aligned base → canonical (sign-extend bit 47).
                        let base48 = (lm_target & 0xFFFF_FFFF_FFFF) & !(TWO_MIB - 1);
                        let kernel_base_va = if base48 & (1 << 47) != 0 {
                            base48 | 0xFFFF_0000_0000_0000
                        } else {
                            base48
                        };
                        if cr3 != 0 && base48 != 0 {
                            return Some(LowStub {
                                cr3: cr3 & 0x000F_FFFF_FFFF_F000,
                                kernel_base_va,
                            });
                        }
                    }
                }
            }
        }
        offset += PAGE_SIZE as u64;
    }
    None
}

/// Scan physical memory for ntoskrnl.exe and extract its PDB identification.
///
/// Searches page-aligned addresses from 1 MiB to 128 MiB for a valid
/// AMD64 PE image whose CodeView record identifies it as an ntoskrnl variant.
/// Returns `Error::NotFound` if no kernel PE is found in the scan window.
pub fn scan_for_kernel<P: PhysicalMemoryProvider>(mem: &P) -> crate::Result<PdbId> {
    let mut addr = SCAN_START;
    while addr < SCAN_END {
        let mut mz = [0u8; 2];
        // treat read errors as absent pages — providers return Ok(0) for unmapped ranges
        if mem.read_phys(addr, &mut mz).unwrap_or(0) < 2 || mz != [b'M', b'Z'] {
            addr += PAGE_SIZE as u64;
            continue;
        }
        let mut page = [0u8; PAGE_SIZE];
        // treat read errors as absent pages — providers return Ok(0) for unmapped ranges
        if mem.read_phys(addr, &mut page).unwrap_or(0) < PAGE_SIZE {
            addr += PAGE_SIZE as u64;
            continue;
        }
        let e_lfanew =
            u32::from_le_bytes([page[0x3C], page[0x3D], page[0x3E], page[0x3F]]) as usize;
        if e_lfanew + 6 > PAGE_SIZE || &page[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            addr += PAGE_SIZE as u64;
            continue;
        }
        let machine = u16::from_le_bytes([page[e_lfanew + 4], page[e_lfanew + 5]]);
        if machine != 0x8664 {
            addr += PAGE_SIZE as u64;
            continue;
        }
        if let Ok(pdb_id) = crate::pe_debug::extract_pdb_id(&page) {
            if is_kernel_pdb_name(&pdb_id.pdb_name) {
                return Ok(pdb_id);
            }
        }
        addr += PAGE_SIZE as u64;
    }

    // Physical scan missed — on real dumps the kernel is mapped high and is only
    // reachable through CR3/DTB translation. Fall back to the VA-aware locator
    // using the page-table root and a known kernel VA from the dump header.
    if let Some(meta) = mem.metadata() {
        if let (Some(cr3), Some(anchor_va)) = (meta.cr3, dtb_anchor_va(&meta)) {
            if let Ok(pdb_id) = scan_for_kernel_via_dtb(mem, cr3, anchor_va) {
                return Ok(pdb_id);
            }
        }
    }

    // Header-less last resort: no embedded CR3 / anchor VA to lean on. Recover
    // the kernel DTB from raw physical memory by self-map enumeration. A 64-bit
    // self-referential DTB that maps kernel space is itself proof the image is
    // AMD64 Windows (the architecture gate vol3 applies at the DTB layer), so it
    // is only inside this branch that we trust a kernel profile.
    if let Some(cr3) = scan_for_kernel_dtb(mem) {
        // Preferred: ntoskrnl's own PE header is resident → full verification.
        if let Some(pdb_id) = locate_kernel_via_dtb_only(mem, cr3) {
            return Ok(pdb_id);
        }
        // ntoskrnl's PE header is paged out (the Case 001 DC shape), but its
        // CodeView RSDS in `.rdata` is still resident. Sweep physical memory for
        // an RSDS whose PDB name is a kernel image. The DTB above already
        // established AMD64, so this cannot mis-profile a 32-bit image.
        if let Some(id) = scan_physical_for_kernel_rsds(mem) {
            return Ok(id);
        }
    }

    Err(crate::Error::NotFound(
        "kernel PE not found in physical memory or via DTB translation".into(),
    ))
}

/// Sweep physical memory for a CodeView RSDS record whose PDB name is a kernel
/// image (`ntkrnlmp`/`ntoskrnl`), returning its [`PdbId`]. The anchor of last
/// resort when the kernel's PE header is not page-resident. Reads overlapping
/// windows so a record spanning a boundary is parsed whole; panic-free.
fn scan_physical_for_kernel_rsds<P: PhysicalMemoryProvider>(mem: &P) -> Option<PdbId> {
    const CHUNK: usize = 1 << 20; // 1 MiB
                                  // A full RSDS record: magic(4) + GUID(16) + age(4) + a generous PDB name.
                                  // Overlap each window by this so a record on a boundary is still parsed whole.
    const OVERLAP: u64 = (4 + 16 + 4 + 256) as u64;
    let page = PAGE_SIZE as u64;
    let mut buf = vec![0u8; CHUNK + OVERLAP as usize];
    // Scan the physical layer's available ranges (Raw exposes one [0,len) range;
    // sparse providers expose mapped extents) — the same model vol3's
    // `PageMapScanner`/`PDBUtility.scan` use. Within each range, read overlapping
    // windows; a gap (short read) advances one page.
    for range in mem.ranges() {
        let mut addr = range.start & !0xFFF;
        while addr < range.end {
            let n = mem.read_phys(addr, &mut buf).unwrap_or(0);
            if n == 0 {
                addr = addr.saturating_add(page); // gap — step to the next page
                continue;
            }
            if let Ok(id) = crate::pe_debug::extract_pdb_id_tolerant_where(&buf[..n], |name| {
                is_kernel_pdb_name(name)
            }) {
                return Some(id);
            }
            // Advance by what we read, less the overlap, never less than a page.
            let step = (n as u64).saturating_sub(OVERLAP).max(page);
            addr = addr.saturating_add(step);
        }
    }
    None
}

/// Pick a known kernel virtual address from the dump header to anchor the DTB
/// descent. `PsLoadedModuleList` is preferred (it lives inside ntoskrnl's mapped
/// image); `PsActiveProcessHead` is a fallback known kernel VA.
fn dtb_anchor_va(meta: &memf_format::DumpMetadata) -> Option<u64> {
    meta.ps_loaded_module_list
        .or(meta.ps_active_process_head)
        .or(meta.kd_debugger_data_block)
}

/// Check whether a PDB filename looks like an ntoskrnl variant.
fn is_kernel_pdb_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("ntkrnl") || lower.contains("ntoskrnl")
}

/// Locate the kernel PE via CR3/DTB-based virtual address translation.
///
/// On many real dumps the kernel image is mapped high in the kernel virtual
/// address space and is **not** reachable by a low physical scan
/// ([`scan_for_kernel`]). Given the page-table root (`cr3`/DTB) and a known
/// kernel virtual address `anchor_va` (e.g. `PsLoadedModuleList` from the crash
/// dump header), this descends in 2 MiB steps from `anchor_va`, translating each
/// candidate base through the page tables, until it finds an AMD64 PE whose
/// CodeView RSDS record identifies it as an ntoskrnl variant.
///
/// Returns [`Error::NotFound`] if no kernel PE is located within the search
/// window.
pub fn scan_for_kernel_via_dtb<P: PhysicalMemoryProvider>(
    mem: &P,
    cr3: u64,
    anchor_va: u64,
) -> crate::Result<PdbId> {
    // Descend from the anchor in 2 MiB steps. The kernel base is 2 MiB-aligned
    // and lies at or below the anchor (PsLoadedModuleList sits inside ntoskrnl's
    // mapped image). Bound the descent so a bogus anchor cannot loop forever.
    let start = anchor_va & !(TWO_MIB - 1);
    let mut va = start;
    let floor = start.saturating_sub(DTB_DESCENT_WINDOW);
    while va >= floor {
        if let Some(pdb_id) = try_kernel_at_va(mem, cr3, va, &|name| is_kernel_pdb_name(name)) {
            return Ok(pdb_id);
        }
        // Stop before underflow when floor is 0.
        if va < TWO_MIB {
            break;
        }
        va -= TWO_MIB;
    }
    Err(crate::Error::NotFound(
        "kernel PE not found via DTB translation".into(),
    ))
}

// --- Header-less DTB/CR3 discriminator (#62) -----------------------------
// A raw dump with no crash-dump metadata (no embedded CR3, no
// PsLoadedModuleList) still lets us recover the kernel DTB: Win10/11 build a
// recursive PML4 self-map at a fixed index, so the page-table root self-
// references. But a bare self-reference scan is AMBIGUOUS — every *process*
// DTB self-references at the same index too, and (validated on the SecurityNik
// dump: 220 self-ref candidates) the kernel's upper-half page tables are shared
// into every process DTB, so *all* of them resolve the kernel image. The
// discriminator therefore combines two signals:
//   1. VERIFICATION (necessary): a candidate must be a real DTB whose page
//      tables locate an ntkrnlmp/ntoskrnl PE with a valid RSDS GUID — this
//      rejects self-referencing pages that are not page-table roots at all.
//   2. LOWEST-PHYSICAL prior (the selector): among the verified DTBs, the kernel
//      DTB sits lowest in physical memory (0x1AE000 on SecurityNik), below the
//      per-process DTBs. Because the kernel half is shared, verification alone
//      does not single out the kernel DTB; the ascending order does.

/// Canonical Windows 10/11 PML4 recursive self-map index.
///
/// The kernel installs a self-referencing entry here so the page tables are
/// reachable through their own virtual address window. Both the kernel DTB and
/// every process DTB carry it, which is exactly why the self-map scan alone is
/// ambiguous and a verification step is required.
const SELF_MAP_INDEX: u64 = 0x1F9;

/// Cap on self-referencing PML4 candidate pages collected from the dump.
/// A multi-GiB dump can contain hundreds of process DTBs; bound the work so a
/// crafted dump cannot turn the scan into a denial of service.
const MAX_PML4_CANDIDATES: usize = 4096;

/// Cap on full RSDS verification attempts per DTB. The cheap MZ pre-check gates
/// these, so only 2 MiB-aligned VAs that actually start with `MZ` (a handful per
/// dump — ntoskrnl plus a few boot drivers) ever reach the expensive image read.
/// Bounds the work a crafted dump full of fake `MZ` headers could impose.
const MAX_KERNEL_VERIFY_ATTEMPTS: usize = 256;

/// Number of 2 MiB slots probed within each present kernel-half PDPT region
/// when hunting the 2 MiB-aligned ntkrnlmp base. A present PDPT entry covers a
/// full 1 GiB (512 × 2 MiB pages), so probe the whole region.
const KERNEL_PROBE_SLOTS: u64 = 512;

/// Build a canonical kernel virtual address whose PML4 index is `pml4_idx`.
/// Bits 47:39 carry the PML4 index; bit 47 is sign-extended into 63:48 so the
/// address lands in the canonical kernel (high) half.
fn kernel_va_for_pml4_index(pml4_idx: u64, pdpt_idx: u64) -> u64 {
    let va = ((pml4_idx & 0x1FF) << 39) | ((pdpt_idx & 0x1FF) << 30);
    // Canonical sign-extension: replicate bit 47 into 63:48.
    if va & (1 << 47) != 0 {
        va | 0xFFFF_0000_0000_0000
    } else {
        va
    }
}

/// Enumerate physical pages that look like a self-referencing PML4 — a present
/// entry that points back at the page itself.
///
/// The self-map index is NOT fixed: Windows Server 2012 R2 uses the classic
/// `0x1ED`, later Win10/11 use other kernel-half slots, and 1607+ randomizes it
/// per boot. So every kernel-half slot (`0x100..0x200`) of each page is checked,
/// not one constant — keying on a single index misses whole OS generations
/// (`SELF_MAP_INDEX` remains the canonical example used elsewhere). The page is
/// read once and scanned in memory.
///
/// These are the DTB *candidates*. The set is ambiguous (process + kernel DTBs
/// alike); [`scan_for_kernel_dtb`] disambiguates by verification. Bounded by
/// [`MAX_PML4_CANDIDATES`]; never panics (all reads bounds-/present-checked).
fn enumerate_self_ref_pml4s<P: PhysicalMemoryProvider>(mem: &P) -> Vec<u64> {
    let mut candidates = Vec::new();
    let mut page = [0u8; PAGE_SIZE];
    for range in mem.ranges() {
        let mut pa = range.start & !0xFFF;
        while pa < range.end {
            if candidates.len() >= MAX_PML4_CANDIDATES {
                return candidates;
            }
            let n = mem.read_phys(pa, &mut page).unwrap_or(0);
            let is_self_ref = |idx: usize| -> bool {
                let off = idx * 8;
                if off + 8 > n {
                    return false;
                }
                let entry = u64::from_le_bytes(page[off..off + 8].try_into().unwrap_or([0u8; 8]));
                entry & PTE_PRESENT != 0 && (entry & PTE_ADDR_MASK) == pa
            };
            // The self-map is architecturally a kernel-half entry (index >= 0x100).
            // Probe the common modern slot first, then the rest of the kernel half
            // — the index is not fixed (2012 R2 = 0x1ED; 1607+ randomizes it).
            let found =
                is_self_ref(SELF_MAP_INDEX as usize) || (0x100usize..0x200).any(is_self_ref);
            if found {
                candidates.push(pa);
            }
            // Stop before overflow at the top of the address space.
            let Some(next) = pa.checked_add(PAGE_SIZE as u64) else {
                break; // cov:unreachable: dump ranges never reach u64::MAX page
            };
            pa = next;
        }
    }
    candidates
}

/// Treating physical `cr3` as the page-table root, try to reach an
/// ntkrnlmp/ntoskrnl PE with a valid RSDS record, returning its PDB identity.
/// `Some` means the candidate is a real DTB that maps the kernel — necessary,
/// but on a live Windows dump *not* sufficient to single out the kernel DTB
/// (the kernel half is shared into every process DTB). [`scan_for_kernel_dtb`]
/// adds the lowest-physical prior to make the final selection.
///
/// With no dump metadata there is no known kernel VA, so we derive candidate
/// kernel bases from the page tables themselves: walk every present kernel-half
/// PML4 entry (indices 0x100..0x200) and present PDPT entry below it, and probe
/// each 2 MiB-aligned virtual address in that 1 GiB region. A cheap two-byte
/// `MZ` pre-check gates the expensive image read + RSDS scan, so only genuine PE
/// bases are fully verified. ntoskrnl is the lowest such kernel-half image, so
/// the ascending walk reaches it first. Full verifications are bounded by
/// [`MAX_KERNEL_VERIFY_ATTEMPTS`]; the descent itself is bounded by the
/// architectural kernel-half size and [`KERNEL_PROBE_SLOTS`].
fn locate_kernel_via_dtb_only<P: PhysicalMemoryProvider>(mem: &P, cr3: u64) -> Option<PdbId> {
    locate_pe_via_dtb(mem, cr3, &|name| is_kernel_pdb_name(name))
}

/// Walk the kernel half of `cr3`'s page tables and return the PDB identity of the
/// first 2 MiB-aligned, MZ-headed PE image whose recovered PDB name satisfies
/// `accept`. The page-table descent is identical regardless of `accept`; only the
/// acceptance test differs, so [`locate_kernel_via_dtb_only`] (ntoskrnl-only, for
/// profile resolution) and the any-kernel-PE genuineness test in
/// [`scan_for_kernel_dtb`] share one walk.
fn locate_pe_via_dtb<P: PhysicalMemoryProvider>(
    mem: &P,
    cr3: u64,
    accept: &dyn Fn(&str) -> bool,
) -> Option<PdbId> {
    let mut verify_attempts = 0usize;
    for pml4_idx in 0x100u64..0x200 {
        let pml4e = match read_pte(mem, (cr3 & PTE_ADDR_MASK) + pml4_idx * 8) {
            Some(e) if e & PTE_PRESENT != 0 => e,
            _ => continue,
        };
        for pdpt_idx in 0u64..0x200 {
            match read_pte(mem, (pml4e & PTE_ADDR_MASK) + pdpt_idx * 8) {
                Some(e) if e & PTE_PRESENT != 0 => {}
                _ => continue,
            }
            // Probe 2 MiB-aligned VAs within this 1 GiB PDPT region for a PE.
            let base_va = kernel_va_for_pml4_index(pml4_idx, pdpt_idx);
            for slot in 0..KERNEL_PROBE_SLOTS {
                let va = base_va + slot * TWO_MIB;
                // Cheap gate: only 2 MiB-aligned VAs that start with `MZ` are
                // worth a full image read. Unmapped pages read short → skipped.
                let mut sig = [0u8; 2];
                if read_virt(mem, cr3, va, &mut sig) < 2 || sig != [b'M', b'Z'] {
                    continue;
                }
                if verify_attempts >= MAX_KERNEL_VERIFY_ATTEMPTS {
                    return None;
                }
                verify_attempts += 1;
                if let Some(pdb_id) = try_kernel_at_va(mem, cr3, va, accept) {
                    return Some(pdb_id);
                }
            }
        }
    }
    None
}

/// `true` if `cr3` is a genuine page-table root: its kernel half maps at least
/// one valid PE image with a recoverable RSDS record. On a real dump the kernel's
/// own header may be paged out, but resident boot drivers in the shared kernel
/// half still prove the candidate is a real DTB (not a stray self-referencing
/// page). The kernel DTB is then the lowest-physical such root.
fn dtb_maps_kernel_space<P: PhysicalMemoryProvider>(mem: &P, cr3: u64) -> bool {
    locate_pe_via_dtb(mem, cr3, &|_| true).is_some()
}

/// Recover the kernel DTB (page-table root) from a **header-less** raw dump.
///
/// For dumps with no crash-dump metadata (no embedded CR3, no
/// `PsLoadedModuleList`), [`scan_for_kernel`] has nothing to anchor the DTB
/// descent on. This entry point recovers the kernel DTB directly from raw
/// physical memory:
///
/// 1. Enumerate self-referencing PML4 candidates ([`enumerate_self_ref_pml4s`]).
///    On a real dump this surfaces the kernel DTB *and* many process DTBs — all
///    self-reference at the same canonical index (220 on SecurityNik), so the
///    set is ambiguous.
/// 2. Order candidates by ascending physical address and accept the first whose
///    page tables map an ntkrnlmp/ntoskrnl PE with a valid RSDS GUID
///    ([`locate_kernel_via_dtb_only`]). Verification rejects self-referencing
///    pages that are not page-table roots; the lowest-physical ordering selects
///    the kernel DTB among the process DTBs (whose shared kernel half also maps
///    the kernel, so verification alone would not distinguish them).
///
/// Returns the physical address of the kernel DTB, or `None` if no candidate
/// verifies. Panic-free and bounded against crafted dumps.
pub fn scan_for_kernel_dtb<P: PhysicalMemoryProvider>(mem: &P) -> Option<u64> {
    let mut candidates = enumerate_self_ref_pml4s(mem);
    // The kernel DTB sits lowest in physical memory (0x1AE000 on SecurityNik),
    // below the per-process DTBs. Because the kernel's upper-half page tables are
    // shared into every process DTB, every candidate's walk reaches the kernel
    // image — so verification confirms "is a DTB mapping the kernel" but does not
    // single out the kernel DTB. Ascending order makes that selection, and also
    // finds the answer fast (the kernel is tried first).
    candidates.sort_unstable();
    candidates
        .into_iter()
        .find(|&cr3| dtb_maps_kernel_space(mem, cr3))
}

/// If a valid AMD64 PE is mapped at `base_va` whose recovered PDB name satisfies
/// `accept`, return its PDB identity.
fn try_kernel_at_va<P: PhysicalMemoryProvider>(
    mem: &P,
    cr3: u64,
    base_va: u64,
    accept: &dyn Fn(&str) -> bool,
) -> Option<PdbId> {
    // Read the first page to validate the PE header.
    let mut first = [0u8; PAGE_SIZE];
    let n = read_virt(mem, cr3, base_va, &mut first);
    if n < 0x40 || first[0] != b'M' || first[1] != b'Z' {
        return None;
    }
    let e_lfanew =
        u32::from_le_bytes([first[0x3C], first[0x3D], first[0x3E], first[0x3F]]) as usize;
    if e_lfanew + 6 > PAGE_SIZE || first.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0") {
        return None;
    }
    let machine = u16::from_le_bytes([first[e_lfanew + 4], first[e_lfanew + 5]]);
    if machine != 0x8664 {
        return None;
    }

    // Determine how much of the image to scan: SizeOfImage lives at
    // offset 56 in the PE32+ optional header (e_lfanew + 24 + 56).
    let opt_off = e_lfanew + 24;
    let size_of_image = first
        .get(opt_off + 56..opt_off + 60)
        .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize);
    let scan_len = size_of_image.clamp(PAGE_SIZE, MAX_IMAGE_SCAN);

    // Read the image (capped) and run the tolerant RSDS scan over it. Pages that
    // are not mapped read as zeros (read_virt fills the buffer up to the first gap).
    let mut image = vec![0u8; scan_len];
    let got = read_virt(mem, cr3, base_va, &mut image);
    if got == 0 {
        return None; // cov:unreachable: first-page read above already returned >= 0x40
    }
    image.truncate(got);

    match crate::pe_debug::extract_pdb_id_tolerant(&image) {
        Ok(pdb_id) if accept(&pdb_id.pdb_name) => Some(pdb_id),
        _ => None,
    }
}

// --- Minimal, self-contained x86-64 4-level page-table walk --------------
// memf-symbols sits below memf-core in the dependency graph (memf-core depends
// ON memf-symbols), so it cannot reuse memf-core's VirtualAddressSpace without
// creating a cycle. This is a deliberately small walker that needs only the
// PhysicalMemoryProvider trait from memf-format.

/// Physical-address mask for a 4 KiB-aligned page-table entry (bits 51:12).
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
/// Present bit in a page-table entry.
const PTE_PRESENT: u64 = 1;
/// Page-size bit (1 GiB / 2 MiB large pages).
const PTE_PAGE_SIZE: u64 = 1 << 7;

/// Read one little-endian 8-byte PTE from physical address `pa`.
/// Returns `None` on a short/unmapped read (never panics).
fn read_pte<P: PhysicalMemoryProvider>(mem: &P, pa: u64) -> Option<u64> {
    let mut buf = [0u8; 8];
    let n = mem.read_phys(pa, &mut buf).unwrap_or(0);
    if n < 8 {
        return None;
    }
    Some(u64::from_le_bytes(buf))
}

/// Translate virtual address `va` to a physical address using 4-level paging.
/// Returns `None` for any non-present level (bounds- and present-checked).
fn virt_to_phys<P: PhysicalMemoryProvider>(mem: &P, cr3: u64, va: u64) -> Option<u64> {
    let i4 = (va >> 39) & 0x1FF;
    let i3 = (va >> 30) & 0x1FF;
    let i2 = (va >> 21) & 0x1FF;
    let i1 = (va >> 12) & 0x1FF;
    let page_off = va & 0xFFF;

    let pml4e = read_pte(mem, (cr3 & PTE_ADDR_MASK) + i4 * 8)?;
    if pml4e & PTE_PRESENT == 0 {
        return None;
    }

    let pdpte = read_pte(mem, (pml4e & PTE_ADDR_MASK) + i3 * 8)?;
    if pdpte & PTE_PRESENT == 0 {
        return None;
    }
    if pdpte & PTE_PAGE_SIZE != 0 {
        // 1 GiB page
        return Some((pdpte & 0x000F_FFFF_C000_0000) | (va & 0x3FFF_FFFF));
    }

    let pde = read_pte(mem, (pdpte & PTE_ADDR_MASK) + i2 * 8)?;
    if pde & PTE_PRESENT == 0 {
        return None;
    }
    if pde & PTE_PAGE_SIZE != 0 {
        // 2 MiB page
        return Some((pde & 0x000F_FFFF_FFE0_0000) | (va & 0x1F_FFFF));
    }

    let pte = read_pte(mem, (pde & PTE_ADDR_MASK) + i1 * 8)?;
    if pte & PTE_PRESENT == 0 {
        return None;
    }
    Some((pte & PTE_ADDR_MASK) | page_off)
}

/// Read up to `buf.len()` bytes starting at virtual address `va`, translating
/// each 4 KiB page through `cr3`. Stops at the first untranslatable / unmapped
/// page and returns the number of bytes filled (the rest of `buf` is untouched).
fn read_virt<P: PhysicalMemoryProvider>(mem: &P, cr3: u64, va: u64, buf: &mut [u8]) -> usize {
    let mut filled = 0usize;
    let mut cur = va;
    while filled < buf.len() {
        let page_off = (cur & 0xFFF) as usize;
        let chunk = (PAGE_SIZE - page_off).min(buf.len() - filled);
        let Some(pa) = virt_to_phys(mem, cr3, cur) else {
            break;
        };
        let n = mem
            .read_phys(pa, &mut buf[filled..filled + chunk])
            .unwrap_or(0);
        if n == 0 {
            break;
        }
        filled += n;
        cur = cur.wrapping_add(n as u64);
    }
    filled
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_format::{PhysicalRange, Result as FmtResult};

    /// Minimal in-memory PhysicalMemoryProvider for tests.
    struct FakeMem {
        data: Vec<u8>,
        base: u64,
    }

    impl FakeMem {
        fn new(base: u64, data: Vec<u8>) -> Self {
            Self { data, base }
        }
    }

    impl PhysicalMemoryProvider for FakeMem {
        fn read_phys(&self, addr: u64, buf: &mut [u8]) -> FmtResult<usize> {
            if addr < self.base {
                return Ok(0);
            }
            let off = (addr - self.base) as usize;
            if off >= self.data.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.data.len() - off);
            buf[..n].copy_from_slice(&self.data[off..off + n]);
            Ok(n)
        }

        fn ranges(&self) -> &[PhysicalRange] {
            &[]
        }

        fn format_name(&self) -> &str {
            "fake"
        }
    }

    /// Build a valid AMD64 PE parseable by goblin, with a CodeView RSDS debug directory.
    ///
    /// Layout mirrors `pe_debug::build_pe_with_debug`: e_lfanew=0x80, one .rdata
    /// section mapping RVA 0x200 → file 0x200, NumberOfRvaAndSizes=16.
    ///
    /// GUID bytes must be in mixed-endian format (Data1/2/3 LE, Data4 BE).
    /// For "1B72224D-37B8-1792-…" use `[0x4D,0x22,0x72,0x1B, 0xB8,0x37, 0x92,0x17, …]`.
    fn build_kernel_pe(pdb_name: &str, guid: [u8; 16], age: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];

        // DOS header
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew

        let mut pos = 0x80usize;

        // PE signature
        buf[pos..pos + 4].copy_from_slice(b"PE\0\0");
        pos += 4;

        // COFF header (20 bytes)
        buf[pos..pos + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine: AMD64
        buf[pos + 2..pos + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections: 1
        let opt_size: u16 = 240;
        buf[pos + 16..pos + 18].copy_from_slice(&opt_size.to_le_bytes());
        buf[pos + 18..pos + 20].copy_from_slice(&0x0022u16.to_le_bytes()); // Characteristics
        pos += 20;

        // PE32+ optional header
        let opt_start = pos;
        buf[opt_start..opt_start + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // Magic
        buf[opt_start + 32..opt_start + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        buf[opt_start + 36..opt_start + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
        buf[opt_start + 56..opt_start + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // SizeOfImage
        buf[opt_start + 60..opt_start + 64].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
        buf[opt_start + 108..opt_start + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
                                                                                     // Debug directory: data dir index 6 → offset 112 + 6*8 = 160 from opt_start
        buf[opt_start + 160..opt_start + 164].copy_from_slice(&0x200u32.to_le_bytes()); // RVA
        buf[opt_start + 164..opt_start + 168].copy_from_slice(&28u32.to_le_bytes()); // size

        pos = opt_start + opt_size as usize;

        // Section header: .rdata, RVA 0x200 → file offset 0x200
        buf[pos..pos + 8].copy_from_slice(b".rdata\0\0");
        buf[pos + 8..pos + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        buf[pos + 12..pos + 16].copy_from_slice(&0x200u32.to_le_bytes()); // VirtualAddress
        buf[pos + 16..pos + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        buf[pos + 20..pos + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData

        // IMAGE_DEBUG_DIRECTORY at file offset 0x200
        buf[0x200 + 12..0x200 + 16].copy_from_slice(&2u32.to_le_bytes()); // Type=CODEVIEW
        let pdb_bytes = pdb_name.as_bytes();
        let cv_size = (24 + pdb_bytes.len() + 1) as u32;
        buf[0x200 + 16..0x200 + 20].copy_from_slice(&cv_size.to_le_bytes());
        buf[0x200 + 20..0x200 + 24].copy_from_slice(&0x220u32.to_le_bytes()); // AddressOfRawData
        buf[0x200 + 24..0x200 + 28].copy_from_slice(&0x220u32.to_le_bytes()); // PointerToRawData

        // CodeView RSDS record at file offset 0x220
        buf[0x220..0x224].copy_from_slice(b"RSDS");
        buf[0x224..0x234].copy_from_slice(&guid);
        buf[0x234..0x238].copy_from_slice(&age.to_le_bytes());
        buf[0x238..0x238 + pdb_bytes.len()].copy_from_slice(pdb_bytes);
        // null terminator already zero from vec initialisation

        buf
    }

    #[test]
    fn is_kernel_pdb_name_accepts_variants() {
        assert!(is_kernel_pdb_name("ntoskrnl.pdb"));
        assert!(is_kernel_pdb_name("ntkrnlmp.pdb"));
        assert!(is_kernel_pdb_name("ntkrnlpa.pdb"));
        assert!(is_kernel_pdb_name("NTOSKRNL.PDB"));
    }

    #[test]
    fn is_kernel_pdb_name_rejects_others() {
        assert!(!is_kernel_pdb_name("notepad.pdb"));
        assert!(!is_kernel_pdb_name("hal.pdb"));
        assert!(!is_kernel_pdb_name(""));
    }

    #[test]
    fn scan_returns_not_found_on_empty_memory() {
        let mem = FakeMem::new(0, vec![0u8; 0x100]);
        let result = scan_for_kernel(&mem);
        assert!(matches!(result, Err(crate::Error::NotFound(_))));
    }

    #[test]
    fn scan_finds_kernel_pe_at_scan_start() {
        let guid = [
            0x4D, 0x22, 0x72, 0x1B, // Data1 LE → "1B72224D"
            0xB8, 0x37, // Data2 LE → "37B8"
            0x92, 0x17, // Data3 LE → "1792"
            0x28, 0x20, 0x0E, 0xD8, 0x99, 0x44, 0x98, 0xB2,
        ];
        let pe = build_kernel_pe("ntkrnlmp.pdb", guid, 1);
        let mem = FakeMem::new(SCAN_START, pe);
        let pdb_id = scan_for_kernel(&mem).expect("should find kernel PE");
        assert_eq!(pdb_id.pdb_name, "ntkrnlmp.pdb");
        assert_eq!(pdb_id.age, 1);
        assert!(pdb_id.guid.contains("1B72224D"));
    }

    /// Case 001 DC shape: ntoskrnl's PE header is paged out (no MZ to anchor on)
    /// but its CodeView RSDS record — `RSDS` + GUID + age + `ntkrnlmp.pdb` — sits
    /// resident in .rdata. `scan_for_kernel` must recover the profile from that
    /// physical RSDS, not give up because no MZ header is reachable.
    #[test]
    fn scan_finds_kernel_via_physical_rsds_when_header_paged() {
        let mut mem = SparseMem::new();
        // A genuine 64-bit DTB that maps a resident *driver* PE (no ntoskrnl
        // header) — this establishes AMD64 and lets scan_for_kernel_dtb succeed,
        // while locate_kernel_via_dtb_only (ntoskrnl-only) finds nothing.
        map_kernel_under_pml4(
            &mut mem,
            0x1AE000,
            0x40_0000,
            0xFFFF_F800_6420_0000,
            0x1_0040_0000,
            "bootvid.pdb",
            securitynik_guid(),
            1,
        );
        // ntoskrnl's CodeView RSDS, resident in .rdata, with NO MZ/PE header.
        let guid = [
            0x4D, 0x22, 0x72, 0x1B, 0xB8, 0x37, 0x92, 0x17, 0x28, 0x20, 0x0E, 0xD8, 0x99, 0x44,
            0x98, 0xB2,
        ];
        let mut rsds = Vec::new();
        rsds.extend_from_slice(b"RSDS");
        rsds.extend_from_slice(&guid);
        rsds.extend_from_slice(&1u32.to_le_bytes());
        rsds.extend_from_slice(b"ntkrnlmp.pdb\0");
        mem.write_phys(0x05_00_0000, &rsds);

        let pdb_id = scan_for_kernel(&mem)
            .expect("kernel profile must be recoverable from a resident physical RSDS");
        assert_eq!(pdb_id.pdb_name, "ntkrnlmp.pdb");
        assert!(pdb_id.guid.contains("1B72224D"));
    }

    #[test]
    fn scan_skips_pages_before_valid_pe() {
        let guid = [0xAA; 16];
        let pe = build_kernel_pe("ntoskrnl.pdb", guid, 2);
        let offset = 0x2000usize;
        let mut data = vec![0xCC_u8; offset];
        data.extend_from_slice(&pe);
        let mem = FakeMem::new(SCAN_START, data);
        let pdb_id = scan_for_kernel(&mem).expect("should find kernel PE after garbage");
        assert_eq!(pdb_id.pdb_name, "ntoskrnl.pdb");
    }

    #[test]
    fn scan_rejects_non_amd64_pe() {
        let guid = [0xBB; 16];
        let mut pe = build_kernel_pe("ntoskrnl.pdb", guid, 1);
        // Patch Machine to x86 (0x014c)
        pe[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes());
        let mem = FakeMem::new(SCAN_START, pe);
        let result = scan_for_kernel(&mem);
        assert!(matches!(result, Err(crate::Error::NotFound(_))));
    }

    #[test]
    fn scan_rejects_non_kernel_pdb_name() {
        let guid = [0xCC; 16];
        let pe = build_kernel_pe("notepad.pdb", guid, 1);
        let mem = FakeMem::new(SCAN_START, pe);
        let result = scan_for_kernel(&mem);
        assert!(matches!(result, Err(crate::Error::NotFound(_))));
    }

    // -----------------------------------------------------------------------
    // VA-aware (DTB) locator fixtures and tests
    // -----------------------------------------------------------------------

    use memf_format::DumpMetadata;
    use std::collections::HashMap;

    /// A sparse physical memory provider keyed by page. Lets a test place page
    /// tables and a kernel image at arbitrary physical addresses, and exposes
    /// optional [`DumpMetadata`] (cr3 + ps_loaded_module_list) like a real dump.
    struct SparseMem {
        pages: HashMap<u64, [u8; PAGE_SIZE]>,
        meta: Option<DumpMetadata>,
        ranges: Vec<memf_format::PhysicalRange>,
    }

    impl SparseMem {
        fn new() -> Self {
            Self {
                pages: HashMap::new(),
                meta: None,
                ranges: Vec::new(),
            }
        }

        /// Write `data` starting at physical address `pa`, spanning pages as needed.
        fn write_phys(&mut self, pa: u64, data: &[u8]) -> &mut Self {
            let mut off = 0usize;
            let mut cur = pa;
            while off < data.len() {
                let page_base = cur & !0xFFF;
                let in_page = (cur & 0xFFF) as usize;
                let n = (PAGE_SIZE - in_page).min(data.len() - off);
                let page = self.pages.entry(page_base).or_insert([0u8; PAGE_SIZE]);
                page[in_page..in_page + n].copy_from_slice(&data[off..off + n]);
                off += n;
                cur += n as u64;
            }
            self.rebuild_ranges();
            self
        }

        /// Recompute one PhysicalRange per mapped page (coverage of the page-scan
        /// path; real providers expose contiguous ranges, page granularity is fine).
        fn rebuild_ranges(&mut self) {
            let mut bases: Vec<u64> = self.pages.keys().copied().collect();
            bases.sort_unstable();
            self.ranges = bases
                .into_iter()
                .map(|b| memf_format::PhysicalRange {
                    start: b,
                    end: b + PAGE_SIZE as u64,
                })
                .collect();
        }

        /// Write a single 8-byte little-endian PTE at physical address `pa`.
        fn write_pte(&mut self, pa: u64, value: u64) -> &mut Self {
            self.write_phys(pa, &value.to_le_bytes())
        }

        fn with_metadata(&mut self, meta: DumpMetadata) -> &mut Self {
            self.meta = Some(meta);
            self
        }
    }

    impl PhysicalMemoryProvider for SparseMem {
        fn read_phys(&self, addr: u64, buf: &mut [u8]) -> memf_format::Result<usize> {
            let mut off = 0usize;
            let mut cur = addr;
            while off < buf.len() {
                let page_base = cur & !0xFFF;
                let in_page = (cur & 0xFFF) as usize;
                let n = (PAGE_SIZE - in_page).min(buf.len() - off);
                match self.pages.get(&page_base) {
                    Some(page) => buf[off..off + n].copy_from_slice(&page[in_page..in_page + n]),
                    None => return Ok(off), // unmapped — short read like a real provider
                }
                off += n;
                cur += n as u64;
            }
            Ok(off)
        }

        fn ranges(&self) -> &[memf_format::PhysicalRange] {
            &self.ranges
        }

        fn format_name(&self) -> &str {
            "sparse"
        }

        fn metadata(&self) -> Option<DumpMetadata> {
            self.meta.clone()
        }
    }

    /// Map a kernel-base VA → kernel image physical base by building a minimal
    /// x86-64 4-level page table. Page-table pages occupy a reserved physical
    /// region; the kernel image occupies `kernel_pa`. Returns the populated mem.
    ///
    /// `pdb_name`/`guid`/`age` define the RSDS record embedded in the image.
    fn build_dtb_fixture(
        cr3: u64,
        kernel_va: u64,
        kernel_pa: u64,
        pdb_name: &str,
        guid: [u8; 16],
        age: u32,
    ) -> SparseMem {
        const PRESENT: u64 = 1;

        let mut mem = SparseMem::new();

        // Reserve physical pages for PML4/PDPT/PD/PT tables.
        let pml4 = cr3 & !0xFFF;
        let pdpt = 0x10_0000u64;
        let pd = 0x11_0000u64;
        let pt = 0x12_0000u64;

        let i4 = (kernel_va >> 39) & 0x1FF;
        let i3 = (kernel_va >> 30) & 0x1FF;
        let i2 = (kernel_va >> 21) & 0x1FF;
        let i1 = (kernel_va >> 12) & 0x1FF;

        mem.write_pte(pml4 + i4 * 8, pdpt | PRESENT);
        mem.write_pte(pdpt + i3 * 8, pd | PRESENT);
        mem.write_pte(pd + i2 * 8, pt | PRESENT);
        mem.write_pte(pt + i1 * 8, kernel_pa | PRESENT);

        // Place the kernel image at kernel_pa.
        let pe = build_kernel_pe(pdb_name, guid, age);
        mem.write_phys(kernel_pa, &pe);

        mem
    }

    #[test]
    fn dtb_locator_finds_kernel_at_anchor() {
        let cr3 = 0x1AE000u64;
        let kernel_va = 0xFFFF_F802_1F40_0000u64;
        let kernel_pa = 0x1_0040_0000u64;
        let guid = [
            0x69, 0xFC, 0xC3, 0x9D, 0xCA, 0xB1, 0x34, 0x4B, 0x70, 0x7E, 0xBC, 0x57, 0xFD, 0x1D,
            0x61, 0x26,
        ];
        let mem = build_dtb_fixture(cr3, kernel_va, kernel_pa, "ntkrnlmp.pdb", guid, 1);
        let id = scan_for_kernel_via_dtb(&mem, cr3, kernel_va).expect("should find kernel via DTB");
        assert_eq!(id.pdb_name, "ntkrnlmp.pdb");
        assert_eq!(id.age, 1);
        assert_eq!(id.guid, "9DC3FC69-B1CA-4B34-707E-BC57FD1D6126");
    }

    #[test]
    fn dtb_locator_descends_from_anchor_above_kernel() {
        // Anchor sits 6 MiB above the kernel base; locator must descend to find it.
        let cr3 = 0x1AE000u64;
        let kernel_va = 0xFFFF_F802_1F40_0000u64;
        let anchor_va = kernel_va + 0x60_0000; // 6 MiB above, within the same 2MB grid
        let kernel_pa = 0x1_0040_0000u64;
        let guid = [0xAA; 16];
        let mem = build_dtb_fixture(cr3, kernel_va, kernel_pa, "ntoskrnl.pdb", guid, 3);
        let id =
            scan_for_kernel_via_dtb(&mem, cr3, anchor_va).expect("should descend to kernel base");
        assert_eq!(id.pdb_name, "ntoskrnl.pdb");
        assert_eq!(id.age, 3);
    }

    #[test]
    fn dtb_locator_not_found_on_empty_tables() {
        let cr3 = 0x1AE000u64;
        let mut mem = SparseMem::new();
        // Map only the cr3 page (all zero PTEs) so the walk fails cleanly.
        mem.write_phys(cr3 & !0xFFF, &[0u8; PAGE_SIZE]);
        let result = scan_for_kernel_via_dtb(&mem, cr3, 0xFFFF_F802_1F40_0000);
        assert!(matches!(result, Err(crate::Error::NotFound(_))));
    }

    #[test]
    fn scan_for_kernel_falls_back_to_dtb_via_metadata() {
        // No kernel in the low physical scan window; the kernel is reachable only
        // through the DTB. scan_for_kernel must read cr3 + ps_loaded_module_list
        // from metadata and fall back to the VA-aware locator.
        let cr3 = 0x1AE000u64;
        let kernel_va = 0xFFFF_F802_1F40_0000u64;
        let ps_lml = kernel_va + 0x40_0000; // 4 MiB above kernel base
        let kernel_pa = 0x1_0040_0000u64;
        let guid = [
            0x69, 0xFC, 0xC3, 0x9D, 0xCA, 0xB1, 0x34, 0x4B, 0x70, 0x7E, 0xBC, 0x57, 0xFD, 0x1D,
            0x61, 0x26,
        ];
        let mut mem = build_dtb_fixture(cr3, kernel_va, kernel_pa, "ntkrnlmp.pdb", guid, 1);
        let meta = DumpMetadata {
            cr3: Some(cr3),
            ps_loaded_module_list: Some(ps_lml),
            ..Default::default()
        };
        mem.with_metadata(meta);

        let id = scan_for_kernel(&mem).expect("fallback to DTB should find kernel");
        assert_eq!(id.pdb_name, "ntkrnlmp.pdb");
        assert_eq!(id.guid, "9DC3FC69-B1CA-4B34-707E-BC57FD1D6126");
    }

    // -----------------------------------------------------------------------
    // Header-less DTB discriminator fixtures and tests (#62)
    // -----------------------------------------------------------------------

    /// Place a self-referencing PML4 page at physical `pml4_pa`: its entry at the
    /// canonical Win10/11 self-map index (0x1F9) points back at the page itself.
    /// Used to model a DTB candidate that the naive self-ref scan would surface.
    fn write_self_ref_pml4(mem: &mut SparseMem, pml4_pa: u64) {
        const PRESENT: u64 = 1;
        // Ensure the PML4 page exists (zero-filled) even with no other entries.
        mem.write_phys(pml4_pa & !0xFFF, &[0u8; PAGE_SIZE]);
        mem.write_pte(pml4_pa + SELF_MAP_INDEX * 8, (pml4_pa & !0xFFF) | PRESENT);
    }

    /// Build a self-referencing PML4 that ALSO maps a kernel image at `kernel_va`.
    /// Page-table pages live in a per-DTB reserved physical region so multiple
    /// candidates do not collide. Returns nothing; mutates `mem` in place.
    #[allow(clippy::too_many_arguments)]
    fn map_kernel_under_pml4(
        mem: &mut SparseMem,
        pml4_pa: u64,
        table_base: u64,
        kernel_va: u64,
        kernel_pa: u64,
        pdb_name: &str,
        guid: [u8; 16],
        age: u32,
    ) {
        const PRESENT: u64 = 1;
        write_self_ref_pml4(mem, pml4_pa);

        let pdpt = table_base;
        let pd = table_base + 0x1000;
        let pt = table_base + 0x2000;

        let i4 = (kernel_va >> 39) & 0x1FF;
        let i3 = (kernel_va >> 30) & 0x1FF;
        let i2 = (kernel_va >> 21) & 0x1FF;
        let i1 = (kernel_va >> 12) & 0x1FF;

        mem.write_pte(pml4_pa + i4 * 8, pdpt | PRESENT);
        mem.write_pte(pdpt + i3 * 8, pd | PRESENT);
        mem.write_pte(pd + i2 * 8, pt | PRESENT);
        mem.write_pte(pt + i1 * 8, kernel_pa | PRESENT);

        let pe = build_kernel_pe(pdb_name, guid, age);
        mem.write_phys(kernel_pa, &pe);
    }

    /// SecurityNik ground-truth GUID bytes (mixed-endian) for
    /// `9DC3FC69-B1CA-4B34-707E-BC57FD1D6126`.
    fn securitynik_guid() -> [u8; 16] {
        [
            0x69, 0xFC, 0xC3, 0x9D, 0xCA, 0xB1, 0x34, 0x4B, 0x70, 0x7E, 0xBC, 0x57, 0xFD, 0x1D,
            0x61, 0x26,
        ]
    }

    #[test]
    fn naive_self_ref_scan_yields_multiple_candidates() {
        // Three self-referencing PML4s exist; only one maps ntkrnlmp. The naive
        // self-ref enumeration must surface all three (the ambiguity #58 found).
        let mut mem = SparseMem::new();
        write_self_ref_pml4(&mut mem, 0x30_0000); // decoy process DTB
        write_self_ref_pml4(&mut mem, 0x40_0000); // decoy process DTB
        let kernel_dtb = 0x1AE000u64;
        map_kernel_under_pml4(
            &mut mem,
            kernel_dtb,
            0x50_0000,
            0xFFFF_F802_1F40_0000,
            0x1_0040_0000,
            "ntkrnlmp.pdb",
            securitynik_guid(),
            1,
        );

        let candidates = enumerate_self_ref_pml4s(&mem);
        assert!(
            candidates.len() >= 3,
            "expected >= 3 self-ref candidates, got {}",
            candidates.len()
        );
        assert!(candidates.contains(&kernel_dtb));
        assert!(candidates.contains(&0x30_0000));
        assert!(candidates.contains(&0x40_0000));
    }

    #[test]
    fn discriminator_selects_kernel_dtb_among_decoys() {
        // The whole point: header-less, with multiple self-ref PML4 candidates,
        // the discriminator must select the one that maps ntkrnlmp — the kernel DTB.
        let mut mem = SparseMem::new();
        write_self_ref_pml4(&mut mem, 0x30_0000); // decoy: self-refs, no ntkrnlmp
        write_self_ref_pml4(&mut mem, 0x40_0000); // decoy: self-refs, no ntkrnlmp
        let kernel_dtb = 0x1AE000u64;
        map_kernel_under_pml4(
            &mut mem,
            kernel_dtb,
            0x50_0000,
            0xFFFF_F802_1F40_0000,
            0x1_0040_0000,
            "ntkrnlmp.pdb",
            securitynik_guid(),
            1,
        );

        let dtb = scan_for_kernel_dtb(&mem).expect("discriminator should select the kernel DTB");
        assert_eq!(dtb, kernel_dtb, "must pick the DTB that maps ntkrnlmp");
    }

    /// The Case 001 DC dump shape: ntoskrnl's PE-header page is paged out, so NO
    /// candidate maps an `nt*` image — only resident driver images are reachable.
    /// The discriminator must still recover a kernel DTB: a candidate that maps
    /// any valid kernel-space PE with an RSDS is a genuine page-table root, and
    /// the kernel DTB is the lowest-physical such root. Requiring ntoskrnl's own
    /// header to be resident leaves the whole memory leg dark on real dumps.
    #[test]
    fn discriminator_selects_lowest_dtb_when_ntoskrnl_header_absent() {
        let mut mem = SparseMem::new();
        // A bare self-ref decoy that maps no PE at all — must be rejected.
        write_self_ref_pml4(&mut mem, 0x70_0000);
        // Two genuine DTBs, each mapping only a *driver* PE (no ntoskrnl).
        let low_dtb = 0x1AE000u64;
        let high_dtb = 0x60_0000u64;
        for (dtb, table_base, kpa) in [
            (low_dtb, 0x20_0000u64, 0x1_0040_0000u64),
            (high_dtb, 0x90_0000, 0x1_0080_0000),
        ] {
            map_kernel_under_pml4(
                &mut mem,
                dtb,
                table_base,
                0xFFFF_F800_6420_0000,
                kpa,
                "bootvid.pdb",
                securitynik_guid(),
                1,
            );
        }
        let dtb = scan_for_kernel_dtb(&mem)
            .expect("a DTB mapping a resident kernel-space PE must be recovered");
        assert_eq!(
            dtb, low_dtb,
            "the kernel DTB is the lowest-physical genuine root"
        );
    }

    /// The x64 Low Stub yields the kernel CR3 and a kernel-base VA from low
    /// physical memory with no dependence on ntoskrnl's PE header — the
    /// authoritative header-less anchor (vol3 `method_low_stub`).
    #[test]
    fn find_low_stub_recovers_cr3_and_kernel_base() {
        let mut mem = SparseMem::new();
        let stub = 0x3000u64; // a page within the lower 1 MiB
                              // Signature with a non-zero jmp-offset low byte (must be wildcarded).
        mem.write_phys(stub, &0x0000_0001_0006_42E9u64.to_le_bytes());
        // CR3 at +0xA0 (low 12 bits noise → masked to a 4 KiB-aligned base).
        mem.write_phys(stub + 0xA0, &0x001A_7867u64.to_le_bytes());
        // LmTarget at +0x70: a canonical kernel VA inside ntoskrnl (4-aligned).
        mem.write_phys(stub + 0x70, &0xFFFF_F800_6421_3454u64.to_le_bytes());

        let ls = find_low_stub(&mem).expect("low stub must be found");
        assert_eq!(ls.cr3, 0x1A7000, "CR3 masked to a 4 KiB-aligned page base");
        assert_eq!(
            ls.kernel_base_va, 0xFFFF_F800_6420_0000,
            "kernel base VA is the LmTarget rounded down to 2 MiB"
        );
    }

    #[test]
    fn find_low_stub_absent_yields_none() {
        let mut mem = SparseMem::new();
        mem.write_phys(0x4000, &[0u8; 0x200]); // present page, no signature
        assert!(find_low_stub(&mem).is_none());
    }

    /// Write a minimal x64 boot Low Stub (`PROCESSOR_START_BLOCK`) at physical
    /// `stub_pa`: signature, CR3 at +0xA0, LmTarget kernel VA at +0x70.
    fn write_low_stub(mem: &mut SparseMem, stub_pa: u64, cr3: u64, lm_target: u64) {
        mem.write_phys(stub_pa, &0x0000_0001_0006_42E9u64.to_le_bytes());
        mem.write_phys(stub_pa + PSB_CR3_OFFSET, &cr3.to_le_bytes());
        mem.write_phys(stub_pa + PSB_LM_TARGET_OFFSET, &lm_target.to_le_bytes());
    }

    /// On modern Win10/11, KASLR places the kernel image base at PAGE (4 KiB)
    /// granularity — NOT 2 MiB-aligned (DESKTOP-SDN1RPT.mem: base ...A14000,
    /// 0x14000 above its 2 MiB floor). The low stub's LmTarget only floors to
    /// 2 MiB, so the true base must be recovered by a page-granular scan within
    /// that 2 MiB window. `resolve_kernel_base_va` must return the page-aligned
    /// base, not the 2 MiB floor.
    #[test]
    fn resolve_kernel_base_va_finds_page_granular_base() {
        let cr3 = 0x1AE000u64;
        // Kernel base sits 0x14000 ABOVE its 2 MiB floor — like the real dump.
        let kernel_va = 0xFFFF_F802_1F41_4000u64;
        let two_mib_floor = kernel_va & !(TWO_MIB - 1); // 0x...1F40_0000
        assert_ne!(kernel_va, two_mib_floor, "fixture base must be page-granular");
        let kernel_pa = 0x1_0040_0000u64;
        let guid = [0xCDu8; 16];
        let mut mem = build_dtb_fixture(cr3, kernel_va, kernel_pa, "ntkrnlmp.pdb", guid, 1);
        // Low stub: CR3 (noise in low bits, masked) + LmTarget inside the image
        // so it floors to the kernel's 2 MiB region.
        write_low_stub(&mut mem, 0x3000, cr3 | 0x867, kernel_va);

        let base = resolve_kernel_base_va(&mem).expect("page-granular base must be found");
        assert_eq!(base, kernel_va, "must recover the page-aligned base, not the 2 MiB floor");
    }

    /// Windows Server 2012 R2 (pre-1607: no self-ref randomization) places the
    /// self-map at the classic index 0x1ED — the Case 001 DC dump. A real
    /// PML4's self-ref can sit at ANY of the 512 slots (randomized on Win10
    /// 1607+), so enumeration keyed to one fixed slot misses whole OS
    /// generations; it must scan every slot of each candidate page.
    #[test]
    fn enumeration_finds_self_ref_at_any_slot() {
        const PRESENT: u64 = 1;
        let mut mem = SparseMem::new();
        for (pa, index) in [
            (0x30_0000u64, 0x1EDu64), // 2012 R2 classic
            (0x40_0000, 0x1F9),       // Win10/11 randomized example
            (0x50_0000, 0x100),       // arbitrary kernel-half slot
        ] {
            mem.write_phys(pa, &[0u8; PAGE_SIZE]);
            mem.write_pte(pa + index * 8, pa | PRESENT);
        }
        let candidates = enumerate_self_ref_pml4s(&mem);
        for pa in [0x30_0000u64, 0x40_0000, 0x50_0000] {
            assert!(
                candidates.contains(&pa),
                "self-ref at any slot must be enumerated; missed {pa:#x}"
            );
        }
    }

    #[test]
    fn discriminator_returns_none_with_only_decoys() {
        // Self-referencing PML4s that map no kernel must yield no kernel DTB.
        let mut mem = SparseMem::new();
        write_self_ref_pml4(&mut mem, 0x30_0000);
        write_self_ref_pml4(&mut mem, 0x40_0000);
        assert!(scan_for_kernel_dtb(&mem).is_none());
    }

    #[test]
    fn discriminator_returns_none_on_empty_memory() {
        let mem = SparseMem::new();
        assert!(scan_for_kernel_dtb(&mem).is_none());
    }
}
