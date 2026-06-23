//! Windows AppCompatCache (Shimcache) extraction from kernel memory.
//!
//! The Application Compatibility Cache tracks recently executed programs
//! and is a key forensic artifact for proving execution history. On
//! Win8.1+/Win10 the cache lives in the `ahcache.sys` driver, reached by
//! scanning its `.data` section for a `SHIM_CACHE_HANDLE` whose `_RTL_AVL_TABLE`
//! validates against the `PAGE` section, then walking the `SHIM_CACHE_ENTRY`
//! LRU list (Volatility `shimcachemem` parity).
//!
//! Each entry records the full executable path, last-modification
//! timestamp (FILETIME), an execution flag (InsertFlag), and the size
//! of any associated shim data. The position in the cache indicates
//! recency — position 0 is the most recently cached entry.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// Resolve a PE section's virtual range `(section_va, virtual_size)` within an
/// in-memory module image mapped at `module_base`, looked up by name (e.g.
/// `".data"`, `"PAGE"`). Parses the DOS (`e_lfanew`@0x3C) and PE headers, then
/// the section table (40-byte entries: Name[8]@0, VirtualSize@8, VirtualAddress
/// @0xC). Returns `None` if the headers are unreadable or the section is absent.
// Wired into walk_shimcache in increment 5 of the shimcache rewrite; until then
// it is exercised only by unit tests.
/// Safety cap on the PE section count scanned (real images have < 32).
const MAX_PE_SECTIONS: u64 = 96;

fn module_section_range<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    module_base: u64,
    section_name: &str,
) -> Option<(u64, u64)> {
    let read_u16 = |va: u64| -> Option<u16> {
        let b = reader.read_bytes(va, 2).ok()?;
        Some(u16::from_le_bytes(b.get(..2)?.try_into().ok()?))
    };
    let read_u32 = |va: u64| -> Option<u32> {
        let b = reader.read_bytes(va, 4).ok()?;
        Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?))
    };

    // DOS header: e_lfanew (u32) @ 0x3C points to the PE header.
    let pe = module_base.wrapping_add(u64::from(read_u32(module_base + 0x3C)?));
    // PE signature "PE\0\0".
    if reader.read_bytes(pe, 4).ok()?.get(..4)? != b"PE\0\0" {
        return None;
    }
    // COFF header: NumberOfSections @ pe+6, SizeOfOptionalHeader @ pe+0x14.
    let num_sections = read_u16(pe + 6)?;
    let opt_size = read_u16(pe + 0x14)?;
    // Section table follows the 4-byte sig + 20-byte COFF + optional header.
    let sec_table = pe + 0x18 + u64::from(opt_size);
    let target = section_name.as_bytes();

    for i in 0..u64::from(num_sections).min(MAX_PE_SECTIONS) {
        let sh = sec_table + i * 40;
        let name = reader.read_bytes(sh, 8).ok()?;
        // PE section names are 8 bytes, NUL-padded.
        let end = name.iter().position(|&b| b == 0).unwrap_or(8);
        if &name[..end] == target {
            let vsize = read_u32(sh + 8)?;
            let vaddr = read_u32(sh + 0xC)?;
            return Some((module_base.wrapping_add(u64::from(vaddr)), u64::from(vsize)));
        }
    }
    None
}

/// Maximum number of shimcache entries to iterate (safety limit).
const MAX_SHIMCACHE_ENTRIES: usize = 4096;

/// Walk the `SHIM_CACHE_ENTRY` LRU `_LIST_ENTRY` chain from the list head and
/// parse each node (Win8.1+/Win10 x64 layout). `head_va` is the sentinel head
/// (the `_RTL_AVL_TABLE`-adjacent cache head); the sentinel itself is not
/// emitted. Bounded by `MAX_SHIMCACHE_ENTRIES`.
// _SHIM_CACHE_ENTRY (Win8.1+/Win10 x64) field offsets — cited to Volatility
// shimcache-win10-x64.json: ListEntry@0x0, Path(_UNICODE_STRING)@0x18,
// ListEntryDetail(ptr)@0x28; detail: LastModified@0x8, BlobSize@0x10, BlobBuffer@0x18.
const SHIM_ENTRY_PATH: u64 = 0x18;
const SHIM_ENTRY_DETAIL: u64 = 0x28;
const SHIM_DETAIL_LASTMOD: u64 = 0x8;
const SHIM_DETAIL_BLOBSIZE: u64 = 0x10;
const SHIM_DETAIL_BLOBBUF: u64 = 0x18;

fn parse_shimcache_list<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    head_va: u64,
) -> Vec<ShimcacheEntry> {
    let read_u64 = |va: u64| -> Option<u64> {
        let b = reader.read_bytes(va, 8).ok()?;
        Some(u64::from_le_bytes(b.get(..8)?.try_into().ok()?))
    };

    let mut entries = Vec::new();
    // The sentinel head's ListEntry.Flink @ +0 is the first real node.
    let Some(mut current) = read_u64(head_va) else {
        return entries;
    };
    let mut position = 0u32;
    while current != head_va && current != 0 && entries.len() < MAX_SHIMCACHE_ENTRIES {
        let path = read_shim_unicode(reader, current + SHIM_ENTRY_PATH);

        let (last_modified, exec_flag) = match read_u64(current + SHIM_ENTRY_DETAIL) {
            Some(d) if d != 0 => (
                read_u64(d + SHIM_DETAIL_LASTMOD).unwrap_or(0),
                read_exec_blob(reader, d),
            ),
            _ => (0, false),
        };

        entries.push(ShimcacheEntry {
            path,
            last_modified,
            exec_flag,
            data_size: 0, // not present in the Win10 SHIM_CACHE_ENTRY layout
            position,
        });
        position += 1;

        let Some(next) = read_u64(current) else { break };
        current = next;
    }
    entries
}

/// Read a `_UNICODE_STRING` (x64 ABI: Length@0x0 u16, Buffer@0x8 ptr) at `va`
/// and decode its buffer as UTF-16LE. ISF-independent: the layout is fixed ABI,
/// so this works whether or not the active symbol table defines the type.
fn read_shim_unicode<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, va: u64) -> String {
    let len = match reader.read_bytes(va, 2) {
        Ok(b) if b.len() == 2 => u16::from_le_bytes([b[0], b[1]]) as usize,
        _ => return String::new(),
    };
    if len == 0 || len > 0x1000 {
        return String::new();
    }
    let buf = match reader.read_bytes(va + 8, 8) {
        Ok(b) if b.len() == 8 => u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8])),
        _ => return String::new(),
    };
    if buf == 0 {
        return String::new();
    }
    match reader.read_bytes(buf, len) {
        Ok(raw) => {
            let words: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&words)
        }
        _ => String::new(),
    }
}

/// Win10 exec flag: a non-zero u32 in the `BlobSize`-byte blob at
/// `detail.BlobBuffer` is the CSRSS-created (executed) marker.
fn read_exec_blob<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, detail_va: u64) -> bool {
    let blob_size = match reader.read_bytes(detail_va + SHIM_DETAIL_BLOBSIZE, 4) {
        Ok(b) if b.len() == 4 => u32::from_le_bytes(b[..4].try_into().unwrap_or([0; 4])),
        _ => return false,
    };
    if blob_size < 4 {
        return false;
    }
    let blob_buf = match reader.read_bytes(detail_va + SHIM_DETAIL_BLOBBUF, 8) {
        Ok(b) if b.len() == 8 => u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8])),
        _ => return false,
    };
    if blob_buf == 0 {
        return false;
    }
    match reader.read_bytes(blob_buf, 4) {
        Ok(b) if b.len() == 4 => u32::from_le_bytes(b[..4].try_into().unwrap_or([0; 4])) != 0,
        _ => false,
    }
}

/// A single Application Compatibility Cache (Shimcache) entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShimcacheEntry {
    /// Full executable path (e.g., `\??\C:\Windows\System32\cmd.exe`).
    pub path: String,
    /// FILETIME of the file's last modification timestamp.
    pub last_modified: u64,
    /// Whether the InsertFlag indicates the program was executed.
    pub exec_flag: bool,
    /// Size of shim data associated with this entry.
    pub data_size: u32,
    /// Position in the cache (0 = most recent).
    pub position: u32,
}

/// Walk the AppCompatCache (Shimcache) from kernel memory.
///
/// Win8.1+/Win10 **x64**: the cache lives in the `ahcache.sys` driver. Resolves
/// `ahcache.sys`, locates the `SHIM_CACHE_HANDLE` by scanning its `.data`
/// section (validating each candidate's `_RTL_AVL_TABLE` against the `PAGE`
/// section), then walks the `SHIM_CACHE_ENTRY` LRU list via
/// [`parse_shimcache_list`].
///
/// Returns an empty `Vec` when `ahcache.sys` or its sections are absent (e.g.
/// an unsupported OS/arch — this targets Win8.1+/Win10 x64 only) or no valid
/// handle pair is found.
///
/// # Errors
/// Propagates a fatal `PsLoadedModuleList` read failure from module resolution.
pub fn walk_shimcache<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<ShimcacheEntry>> {
    // Win8.1+/Win10: the shim cache moved from ntoskrnl to ahcache.sys.
    let ahcache_base = match crate::kernel_modules::find_loaded_module(reader, "ahcache.sys")? {
        Some(b) if b != 0 => b,
        _ => return Ok(Vec::new()),
    };
    let (Some((data_start, data_size)), Some((page_start, page_size))) = (
        module_section_range(reader, ahcache_base, ".data"),
        module_section_range(reader, ahcache_base, "PAGE"),
    ) else {
        return Ok(Vec::new());
    };
    let page_end = page_start.wrapping_add(page_size);
    let data_end = data_start.wrapping_add(data_size);

    let read_u64 = |va: u64| -> Option<u64> {
        let b = reader.read_bytes(va, 8).ok()?;
        Some(u64::from_le_bytes(b.get(..8)?.try_into().ok()?))
    };

    // Scan .data (8-byte stride) for pointers to a valid SHIM_CACHE_HANDLE; the
    // section holds two cache globals.
    let mut heads = Vec::new();
    let mut off = data_start;
    while off < data_end && heads.len() < 2 {
        if let Some(handle) = read_u64(off) {
            if let Some(head) = valid_shim_head(reader, handle, page_start, page_end) {
                heads.push(head);
            }
        }
        off = off.wrapping_add(8);
    }
    if heads.len() != 2 {
        return Ok(Vec::new());
    }
    // Win8.1+/Win10 x64: the second cache holds the shim cache.
    Ok(parse_shimcache_list(reader, heads[1]))
}

// _RTL_AVL_TABLE (x64) offsets — cited to Volatility shimcache-win10-x64.json.
// Note: that table defines _RTL_BALANCED_LINKS as Parent@0x0 (shimcache-specific,
// differs from the standard ntoskrnl layout where Parent@0x10).
const RTL_AVL_TABLE_SIZE: u64 = 0x68;
const RTL_AVL_BALROOT_PARENT: u64 = 0x0;
const RTL_AVL_COMPARE_ROUTINE: u64 = 0x48;
const RTL_AVL_ALLOCATE_ROUTINE: u64 = 0x50;
const RTL_AVL_FREE_ROUTINE: u64 = 0x58;

/// Validate a candidate `SHIM_CACHE_HANDLE` at `handle_va` and return the cache
/// list-head VA (the `SHIM_CACHE_ENTRY` immediately after the `_RTL_AVL_TABLE`),
/// or `None`. Mirrors Volatility's structural checks: a valid `_RTL_AVL_TABLE`
/// (self-referential `BalancedRoot`, Compare/Allocate routines inside `PAGE`,
/// three distinct routines) plus a self-consistent non-empty list head.
fn valid_shim_head<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    handle_va: u64,
    page_start: u64,
    page_end: u64,
) -> Option<u64> {
    if handle_va == 0 {
        return None;
    }
    let read_u64 = |va: u64| -> Option<u64> {
        let b = reader.read_bytes(va, 8).ok()?;
        Some(u64::from_le_bytes(b.get(..8)?.try_into().ok()?))
    };
    // SHIM_CACHE_HANDLE: eresource@0x0, rtl_avl_table@0x8.
    let avl = read_u64(handle_va + 8)?;
    if avl == 0 {
        return None;
    }
    // _RTL_AVL_TABLE: BalancedRoot.Parent must point back to the table itself.
    if read_u64(avl + RTL_AVL_BALROOT_PARENT)? != avl {
        return None;
    }
    let compare = read_u64(avl + RTL_AVL_COMPARE_ROUTINE)?;
    let allocate = read_u64(avl + RTL_AVL_ALLOCATE_ROUTINE)?;
    let free = read_u64(avl + RTL_AVL_FREE_ROUTINE)?;
    let in_page = |p: u64| p >= page_start && p <= page_end;
    if !in_page(compare) || !in_page(allocate) {
        return None;
    }
    if compare == allocate || compare == free || allocate == free {
        return None;
    }
    // List head = SHIM_CACHE_ENTRY immediately after the RTL_AVL_TABLE.
    let head = avl.wrapping_add(RTL_AVL_TABLE_SIZE);
    let flink = read_u64(head)?;
    if flink == 0 || flink == head {
        return None;
    }
    // The first node's Blink must point back to the head (circular list).
    if read_u64(flink + 8)? != head {
        return None;
    }
    Some(head)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ── No symbol → empty Vec ───────────────────────────────────────

    // ── Exec flag set → exec_flag = true ────────────────────────────

    /// `module_section_range` parses the PE section table of an in-memory module
    /// and returns each named section's (va, size). The stub returns None, so
    /// this FAILS until the parser is implemented (increment 1 GREEN).
    #[test]
    fn module_section_range_parses_named_sections() {
        let base: u64 = 0xFFFF_F800_0010_0000;
        let paddr: u64 = 0x0050_0000;
        let mut page = vec![0u8; 4096];
        // DOS: e_lfanew @ 0x3C -> 0x80
        page[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // PE signature @ 0x80
        page[0x80..0x84].copy_from_slice(b"PE\0\0");
        // COFF: NumberOfSections @ 0x86 = 2; SizeOfOptionalHeader @ 0x94 = 0xF0
        page[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        page[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        // Section table @ 0x98 + 0xF0 = 0x188 (PE sig 4 + COFF 0x14 = 0x18)
        let sec0 = 0x188usize;
        page[sec0..sec0 + 4].copy_from_slice(b"PAGE");
        page[sec0 + 8..sec0 + 12].copy_from_slice(&0x3000u32.to_le_bytes());
        page[sec0 + 12..sec0 + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        let sec1 = sec0 + 40;
        page[sec1..sec1 + 5].copy_from_slice(b".data");
        page[sec1 + 8..sec1 + 12].copy_from_slice(&0x2000u32.to_le_bytes());
        page[sec1 + 12..sec1 + 16].copy_from_slice(&0x5000u32.to_le_bytes());

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(base, paddr, flags::WRITABLE)
            .write_phys(paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        assert_eq!(
            module_section_range(&reader, base, ".data"),
            Some((base + 0x5000, 0x2000))
        );
        assert_eq!(
            module_section_range(&reader, base, "PAGE"),
            Some((base + 0x1000, 0x3000))
        );
        assert_eq!(module_section_range(&reader, base, ".missing"), None);
    }

    /// `parse_shimcache_list` walks the SHIM_CACHE_ENTRY LRU list (Win10 x64
    /// layout) and parses path / last-modified / exec-flag per node. Stub
    /// returns empty → RED until the walker is implemented (increment 2 GREEN).
    #[test]
    fn parse_shimcache_list_walks_and_parses_entries() {
        let head = 0xFFFF_8000_0010_0000u64;
        let e1 = 0xFFFF_8000_0011_0000u64;
        let e2 = 0xFFFF_8000_0012_0000u64;
        let d1 = 0xFFFF_8000_0013_0000u64;
        let d2 = 0xFFFF_8000_0014_0000u64;
        let p1 = 0xFFFF_8000_0015_0000u64;
        let p2 = 0xFFFF_8000_0016_0000u64;
        let b1 = 0xFFFF_8000_0017_0000u64;
        let b2 = 0xFFFF_8000_0018_0000u64;
        let ts1 = 0x01D9_ABCD_1234_5678u64;
        let ts2 = 0x01D5_1111_2222_3333u64;
        let path1 = r"\??\C:\Windows\System32\cmd.exe";
        let path2 = r"C:\Users\rick\AppData\evil.exe";

        let mut head_pg = vec![0u8; 4096];
        head_pg[0..8].copy_from_slice(&e1.to_le_bytes());
        head_pg[8..16].copy_from_slice(&e2.to_le_bytes());

        let mk_entry = |flink: u64, plen: u16, pbuf: u64, detail: u64| {
            let mut pg = vec![0u8; 4096];
            pg[0..8].copy_from_slice(&flink.to_le_bytes());
            pg[0x18..0x1A].copy_from_slice(&plen.to_le_bytes());
            pg[0x1A..0x1C].copy_from_slice(&plen.to_le_bytes());
            pg[0x20..0x28].copy_from_slice(&pbuf.to_le_bytes());
            pg[0x28..0x30].copy_from_slice(&detail.to_le_bytes());
            pg
        };
        let mk_detail = |lastmod: u64, blob: u64| {
            let mut pg = vec![0u8; 4096];
            pg[0x8..0x10].copy_from_slice(&lastmod.to_le_bytes());
            pg[0x10..0x14].copy_from_slice(&4u32.to_le_bytes());
            pg[0x18..0x20].copy_from_slice(&blob.to_le_bytes());
            pg
        };
        let utf16 = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let p1b = utf16(path1);
        let p2b = utf16(path2);

        let e1_pg = mk_entry(e2, p1b.len() as u16, p1, d1);
        let e2_pg = mk_entry(head, p2b.len() as u16, p2, d2);
        let d1_pg = mk_detail(ts1, b1);
        let d2_pg = mk_detail(ts2, b2);
        let mut p1_pg = vec![0u8; 4096];
        p1_pg[..p1b.len()].copy_from_slice(&p1b);
        let mut p2_pg = vec![0u8; 4096];
        p2_pg[..p2b.len()].copy_from_slice(&p2b);
        let mut b1_pg = vec![0u8; 4096];
        b1_pg[0..4].copy_from_slice(&2u32.to_le_bytes());
        let mut b2_pg = vec![0u8; 4096];
        b2_pg[0..4].copy_from_slice(&0u32.to_le_bytes());

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let mut ptb = PageTableBuilder::new();
        for (i, (va, pg)) in [
            (head, &head_pg),
            (e1, &e1_pg),
            (e2, &e2_pg),
            (d1, &d1_pg),
            (d2, &d2_pg),
            (p1, &p1_pg),
            (p2, &p2_pg),
            (b1, &b1_pg),
            (b2, &b2_pg),
        ]
        .into_iter()
        .enumerate()
        {
            let pa = 0x0010_0000u64 + (i as u64) * 0x1000;
            ptb = ptb.map_4k(va, pa, flags::WRITABLE).write_phys(pa, pg);
        }
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let entries = parse_shimcache_list(&reader, head);
        assert_eq!(
            entries.len(),
            2,
            "expected 2 entries, got {}",
            entries.len()
        );
        assert_eq!(entries[0].path, path1);
        assert_eq!(entries[0].last_modified, ts1);
        assert!(entries[0].exec_flag, "blob != 0 -> executed");
        assert_eq!(entries[0].position, 0);
        assert_eq!(entries[1].path, path2);
        assert_eq!(entries[1].last_modified, ts2);
        assert!(!entries[1].exec_flag, "blob == 0 -> not executed");
        assert_eq!(entries[1].position, 1);
    }

    /// Path-aware per-entry filter: a node is dropped only when it is BOTH
    /// link-inconsistent AND has no usable path. A link-inconsistent node that
    /// still carries a path is kept (we surface recovered evidence rather than
    /// discard it). Current code emits all 3 nodes → RED until the filter lands.
    #[test]
    fn parse_shimcache_list_drops_only_linkbad_and_pathless() {
        let head = 0xFFFF_8000_0020_0000u64;
        let a = 0xFFFF_8000_0021_0000u64;
        let b = 0xFFFF_8000_0022_0000u64;
        let cc = 0xFFFF_8000_0023_0000u64;
        let pa = 0xFFFF_8000_0024_0000u64;
        let pc = 0xFFFF_8000_0025_0000u64;
        let unmapped = 0xFFFF_8000_DEAD_0000u64; // never mapped → reads fail
        let utf16 = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };

        // head: Flink->a, Blink->cc
        let mut head_pg = vec![0u8; 4096];
        head_pg[0..8].copy_from_slice(&a.to_le_bytes());
        head_pg[8..16].copy_from_slice(&cc.to_le_bytes());

        let link = |flink: u64, blink: u64, plen: u16, pbuf: u64| {
            let mut pg = vec![0u8; 4096];
            pg[0..8].copy_from_slice(&flink.to_le_bytes());
            pg[8..16].copy_from_slice(&blink.to_le_bytes());
            if plen > 0 {
                pg[0x18..0x1A].copy_from_slice(&plen.to_le_bytes());
                pg[0x20..0x28].copy_from_slice(&pbuf.to_le_bytes());
            }
            pg
        };
        let pa_b = utf16("keep1.exe");
        let pc_b = utf16("keep2.exe");
        // a: consistent (a.Flink=b, b.Blink=a readable), has path → kept
        let a_pg = link(b, head, pa_b.len() as u16, pa);
        // b: Flink=cc, Blink=a; cc.Blink is unmapped → b cond3 fails → inconsistent;
        //    empty path → DROPPED
        let b_pg = link(cc, a, 0, 0);
        // cc: Flink=head, Blink=unmapped → cc inconsistent, but has path → kept
        let cc_pg = link(head, unmapped, pc_b.len() as u16, pc);
        let mut pa_pg = vec![0u8; 4096];
        pa_pg[..pa_b.len()].copy_from_slice(&pa_b);
        let mut pc_pg = vec![0u8; 4096];
        pc_pg[..pc_b.len()].copy_from_slice(&pc_b);

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let mut ptb = PageTableBuilder::new();
        for (i, (va, pg)) in [
            (head, &head_pg), (a, &a_pg), (b, &b_pg), (cc, &cc_pg), (pa, &pa_pg), (pc, &pc_pg),
        ]
        .into_iter()
        .enumerate()
        {
            let p = 0x0020_0000u64 + (i as u64) * 0x1000;
            ptb = ptb.map_4k(va, p, flags::WRITABLE).write_phys(p, pg);
        }
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let entries = parse_shimcache_list(&reader, head);
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            entries.len(),
            2,
            "link-bad+pathless node must drop; path-bearing kept; got {paths:?}"
        );
        assert_eq!(entries[0].path, "keep1.exe");
        assert_eq!(entries[1].path, "keep2.exe");
    }
}
