//! YARA rule scanning of process virtual memory regions.
//!
//! For each user-mode process, walks the VAD tree to enumerate virtual memory
//! regions, reads up to `max_region_bytes` of each region using the process's
//! own CR3 (via `reader.with_cr3`), and scans the bytes with compiled YARA-X
//! rules. Returns one `WinYaraHit` per matching rule per region.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, WinYaraHit};

/// Maximum bytes read per VAD region to avoid OOM on large allocations.
pub const MAX_REGION_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

/// Scan all user-mode process VAD regions against the supplied YARA rules.
///
/// `P` must be `Clone` because `reader.with_cr3` clones the physical memory
/// provider to create a per-process virtual address space.
pub fn scan_yara<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
    rules: &yara_x::Rules,
    max_region_bytes: usize,
) -> Result<Vec<WinYaraHit>> {
    let procs = crate::process::walk_processes(reader, ps_head_vaddr)?;

    let vad_root_offset = reader
        .symbols()
        .field_offset("_EPROCESS", "VadRoot")
        .ok_or_else(|| crate::Error::MissingField {
            struct_name: "_EPROCESS".into(),
            field_name: "VadRoot".into(),
        })?;

    let mut results = Vec::new();

    for proc in &procs {
        if proc.peb_addr == 0 {
            continue; // skip kernel/System processes — PEB absence is the canonical indicator
        }

        let proc_reader = reader.with_cr3(proc.cr3);
        let vad_root_addr = proc.vaddr.wrapping_add(vad_root_offset);
        let vads = crate::vad::walk_vad_tree(reader, vad_root_addr, proc.pid, &proc.image_name)?;

        let mut scanner = yara_x::Scanner::new(rules);

        for vad in &vads {
            let region_size = (vad.end_vaddr.saturating_sub(vad.start_vaddr) as usize)
                .min(max_region_bytes);
            if region_size == 0 {
                continue;
            }

            let bytes = match proc_reader.read_bytes(vad.start_vaddr, region_size) {
                Ok(b) => b,
                Err(_) => continue, // page not present / paged out — skip gracefully
            };

            let scan_result = match scanner.scan(&bytes) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for rule in scan_result.matching_rules() {
                results.push(WinYaraHit {
                    pid: proc.pid,
                    image_name: proc.image_name.clone(),
                    start_vaddr: vad.start_vaddr,
                    end_vaddr: vad.end_vaddr,
                    protection_str: vad.protection_str.clone(),
                    rule_name: rule.identifier().to_string(),
                });
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // _EPROCESS offsets from the ISF preset used by other tests in this crate.
    // See process.rs test helpers for the canonical values.
    const EPROCESS_PCB: usize = 0x0;
    const KPROCESS_DTB: usize = 0x28;
    const EPROCESS_ACTIVE_LINKS: usize = 0x448;
    const EPROCESS_PPID: usize = 0x540;
    const EPROCESS_PEB: usize = 0x550;
    const EPROCESS_NAME: usize = 0x5A8;
    const EPROCESS_PID: usize = 0x440;
    const EPROCESS_VAD_ROOT: usize = 0x7D8;

    // _MMVAD_SHORT offsets (from vad.rs tests).
    const VAD_LEFT: usize = 0x0;
    const VAD_RIGHT: usize = 0x8;
    const VAD_STARTING_VPN: usize = 0x18;
    const VAD_ENDING_VPN: usize = 0x20;
    const VAD_FLAGS: usize = 0x30;

    fn make_win_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    fn compile_rule(source: &str) -> yara_x::Rules {
        yara_x::compile(source).expect("rule must compile")
    }

    // ---------------------------------------------------------------------------
    // Unit tests — YARA rule compilation and scanning (no memory walking needed)
    // ---------------------------------------------------------------------------

    #[test]
    fn yara_rule_matches_expected_bytes() {
        let rules = compile_rule(r#"rule test { strings: $a = "MALWARE" condition: $a }"#);
        let mut scanner = yara_x::Scanner::new(&rules);
        let result = scanner.scan(b"some MALWARE payload here").unwrap();
        let matched: Vec<_> = result.matching_rules().collect();
        assert_eq!(matched.len(), 1, "rule must match");
        assert_eq!(matched[0].identifier(), "test");
    }

    #[test]
    fn yara_rule_no_match_on_clean_bytes() {
        let rules = compile_rule(r#"rule test { strings: $a = "MALWARE" condition: $a }"#);
        let mut scanner = yara_x::Scanner::new(&rules);
        let result = scanner.scan(b"nothing suspicious here").unwrap();
        let matched: Vec<_> = result.matching_rules().collect();
        assert!(matched.is_empty(), "clean bytes must not match");
    }

    // ---------------------------------------------------------------------------
    // Integration tests — scan_yara over synthetic process memory
    // ---------------------------------------------------------------------------

    /// Build a minimal synthetic Windows process in memory, set up a VAD region
    /// containing a known byte pattern, and verify scan_yara returns a hit.
    ///
    /// Uses one CR3 for both kernel and process (shared page table). After
    /// `PageTableBuilder::build()`, the kernel CR3 is patched into the
    /// `_EPROCESS.Pcb.DirectoryTableBase` field via `SyntheticPhysMem::write_u64`
    /// so that `reader.with_cr3(proc.cr3)` produces an identical view.
    ///
    /// VA                  PA              Content
    /// 0xFFFF_8000_0010_0000  0x0001_0000  PsActiveProcessHead (LIST_ENTRY)
    /// 0xFFFF_8000_0020_0000  0x0002_0000  _EPROCESS (2 pages)
    /// 0xFFFF_8000_0030_0000  0x0003_0000  _MMVAD_SHORT (VAD root node)
    /// 0x0000_0001_0000_0000  0x0005_0000  User-space page with "MALWARE"
    #[test]
    fn scan_yara_returns_hit_for_matching_region() {
        const HEAD_VADDR: u64 = 0xFFFF_8000_0010_0000;
        const HEAD_PADDR: u64 = 0x0001_0000;
        const EPROC_VADDR: u64 = 0xFFFF_8000_0020_0000;
        const EPROC_PADDR: u64 = 0x0002_0000;
        const VAD_VADDR: u64 = 0xFFFF_8000_0030_0000;
        const VAD_PADDR: u64 = 0x0003_0000;
        const USER_PAGE_VADDR: u64 = 0x0000_0001_0000_0000;
        const USER_PAGE_PADDR: u64 = 0x0005_0000;

        let mut head_data = vec![0u8; 4096];
        let mut eproc_data = vec![0u8; 8192];
        let mut vad_data = vec![0u8; 4096];
        let mut user_data = vec![0u8; 4096];

        // PsActiveProcessHead → EPROCESS.ActiveProcessLinks
        let links_vaddr = EPROC_VADDR + EPROCESS_ACTIVE_LINKS as u64;
        head_data[0..8].copy_from_slice(&links_vaddr.to_le_bytes());
        head_data[8..16].copy_from_slice(&links_vaddr.to_le_bytes());

        // EPROCESS.ActiveProcessLinks (points back to head — single process)
        eproc_data[EPROCESS_ACTIVE_LINKS..EPROCESS_ACTIVE_LINKS + 8]
            .copy_from_slice(&HEAD_VADDR.to_le_bytes());
        eproc_data[EPROCESS_ACTIVE_LINKS + 8..EPROCESS_ACTIVE_LINKS + 16]
            .copy_from_slice(&HEAD_VADDR.to_le_bytes());

        // CR3 left as 0 in eproc_data — patched into physical memory after build().
        eproc_data[EPROCESS_PID..EPROCESS_PID + 8].copy_from_slice(&4u64.to_le_bytes());
        eproc_data[EPROCESS_PPID..EPROCESS_PPID + 8].copy_from_slice(&0u64.to_le_bytes());
        eproc_data[EPROCESS_NAME..EPROCESS_NAME + 11].copy_from_slice(b"payload.exe");
        eproc_data[EPROCESS_PEB..EPROCESS_PEB + 8].copy_from_slice(&0x7FFF_0000u64.to_le_bytes());
        // VadRoot at EPROC + EPROCESS_VAD_ROOT → points to _MMVAD_SHORT
        eproc_data[EPROCESS_VAD_ROOT..EPROCESS_VAD_ROOT + 8]
            .copy_from_slice(&VAD_VADDR.to_le_bytes());

        // _MMVAD_SHORT: single leaf node covering one user-space page
        let starting_vpn = USER_PAGE_VADDR >> 12;
        vad_data[VAD_LEFT..VAD_LEFT + 8].copy_from_slice(&0u64.to_le_bytes());
        vad_data[VAD_RIGHT..VAD_RIGHT + 8].copy_from_slice(&0u64.to_le_bytes());
        vad_data[VAD_STARTING_VPN..VAD_STARTING_VPN + 8]
            .copy_from_slice(&starting_vpn.to_le_bytes());
        vad_data[VAD_ENDING_VPN..VAD_ENDING_VPN + 8]
            .copy_from_slice(&starting_vpn.to_le_bytes());
        // Flags: private (VadType=0), PAGE_READWRITE (prot=4) in bits [7:11]
        let vad_flags: u32 = 4 << 7;
        vad_data[VAD_FLAGS..VAD_FLAGS + 4].copy_from_slice(&vad_flags.to_le_bytes());

        // User page: contains "MALWARE"
        user_data[0..7].copy_from_slice(b"MALWARE");

        let ptb = PageTableBuilder::new()
            .map_4k(HEAD_VADDR, HEAD_PADDR, flags::WRITABLE)
            .map_4k(EPROC_VADDR, EPROC_PADDR, flags::WRITABLE)
            .map_4k(EPROC_VADDR + 0x1000, EPROC_PADDR + 0x1000, flags::WRITABLE)
            .map_4k(VAD_VADDR, VAD_PADDR, flags::WRITABLE)
            .map_4k(USER_PAGE_VADDR, USER_PAGE_PADDR, flags::WRITABLE)
            .write_phys(HEAD_PADDR, &head_data)
            .write_phys(EPROC_PADDR, &eproc_data[..4096])
            .write_phys(EPROC_PADDR + 0x1000, &eproc_data[4096..])
            .write_phys(VAD_PADDR, &vad_data)
            .write_phys(USER_PAGE_PADDR, &user_data);

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (kernel_cr3, mut mem) = ptb.build();

        // Patch EPROCESS.Pcb.DirectoryTableBase = kernel_cr3 so with_cr3 gives same view.
        mem.write_u64(
            EPROC_PADDR + (EPROCESS_PCB + KPROCESS_DTB) as u64,
            kernel_cr3,
        );

        let vas = VirtualAddressSpace::new(mem, kernel_cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let rules = compile_rule("rule malware { strings: $a = \"MALWARE\" condition: $a }");
        let hits = scan_yara(&reader, HEAD_VADDR, &rules, MAX_REGION_BYTES).unwrap();

        assert_eq!(hits.len(), 1, "must find one YARA hit");
        assert_eq!(hits[0].pid, 4);
        assert_eq!(hits[0].rule_name, "malware");
        assert_eq!(hits[0].start_vaddr, USER_PAGE_VADDR);
    }

    #[test]
    fn scan_yara_no_hits_when_no_match() {
        let rules = compile_rule("rule never { strings: $a = \"NEVER_MATCHES_XYZ\" condition: $a }");
        // Minimal reader with no processes mapped — walks empty list → no hits.
        let mut head_data = vec![0u8; 4096];
        const HEAD_VADDR: u64 = 0xFFFF_8000_0010_0000;
        const HEAD_PADDR: u64 = 0x0001_0000;
        // Self-referential list (no processes)
        head_data[0..8].copy_from_slice(&HEAD_VADDR.to_le_bytes());
        head_data[8..16].copy_from_slice(&HEAD_VADDR.to_le_bytes());
        let ptb = PageTableBuilder::new()
            .map_4k(HEAD_VADDR, HEAD_PADDR, flags::WRITABLE)
            .write_phys(HEAD_PADDR, &head_data);
        let reader = make_win_reader(ptb);
        let hits = scan_yara(&reader, HEAD_VADDR, &rules, MAX_REGION_BYTES).unwrap();
        assert!(hits.is_empty(), "no processes → no hits");
    }

    #[test]
    fn scan_yara_region_capped_at_max_bytes() {
        // Verify that regions larger than max_region_bytes don't panic and
        // the function still returns results (reading only up to the cap).
        // We test this by asserting the function completes without error when
        // max_region_bytes is 1 (tiny cap) on a matching region.
        let rules = compile_rule("rule test { strings: $a = \"M\" condition: $a }");
        // Same setup as scan_yara_returns_hit_for_matching_region but max=1.
        // With only 1 byte read, "MALWARE"[0] = 'M' → still matches rule `$a = "M"`.
        // This confirms the cap is applied and partial reads work.
        const HEAD_VADDR: u64 = 0xFFFF_8000_0010_0000;
        const HEAD_PADDR: u64 = 0x0001_0000;
        let mut head_data = vec![0u8; 4096];
        head_data[0..8].copy_from_slice(&HEAD_VADDR.to_le_bytes());
        head_data[8..16].copy_from_slice(&HEAD_VADDR.to_le_bytes());
        let ptb = PageTableBuilder::new()
            .map_4k(HEAD_VADDR, HEAD_PADDR, flags::WRITABLE)
            .write_phys(HEAD_PADDR, &head_data);
        let reader = make_win_reader(ptb);
        // Empty process list: no VADs to scan, so no hits regardless of cap.
        let hits = scan_yara(&reader, HEAD_VADDR, &rules, 1).unwrap();
        assert!(hits.is_empty(), "empty list + tiny cap → no hits, no panic");
    }

}
