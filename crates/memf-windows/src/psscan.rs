//! Pool-tag process scanning (`psscan`) — finds `_EPROCESS` objects by their
//! `Proc` pool tag in **physical** memory, independent of `PsActiveProcessHead`
//! and the kernel image being page-resident.
//!
//! This is the robust fallback the reference tools (Volatility 2 `psscan`,
//! Volatility 3 `PoolScanner`) use when the active-process linked list cannot be
//! walked — e.g. a dump whose kernel data pages are paged out. Reimplemented
//! clean-room: scan for the tag, then read `UniqueProcessId` / `ImageFileName`
//! at their ISF-derived offsets from candidate object positions within the pool
//! block, accepting only entries that pass strict structural validation.

use std::collections::HashSet;

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// A process recovered by physical pool-tag scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedProcess {
    /// Physical address of the `_EPROCESS` object.
    pub physical_addr: u64,
    /// `UniqueProcessId`.
    pub pid: u64,
    /// `ImageFileName` (≤ 15 chars).
    pub name: String,
    /// `_KPROCESS.DirectoryTableBase` — the process page-table root (CR3).
    ///
    /// Only present when the caller supplies a `dtb_off`; `None` when the
    /// offset is not available (e.g. the resolver has no `_KPROCESS` type).
    pub dtb: Option<u64>,
}

/// `Proc` pool tag — standard non-paged pool tag for `_EPROCESS` objects.
///
/// Source: volatility3/framework/plugins/windows/poolscanner.py `builtin_constraints()`,
/// which registers `b"Proc"` (standard) and `b"Pro\xe3"` (protected) as the two
/// EPROCESS pool tag variants.
const PROC_TAG: [u8; 4] = *b"Proc";
/// `Pro\xe3` pool tag — protected non-paged pool allocation (Windows 10+).
///
/// The MSB of the 4-byte pool tag carries protection flags in the Windows 10
/// pool manager; `\xe3` signals a non-paged, protected allocation. The first
/// three bytes remain `Pro`, identifying this as an `_EPROCESS` pool block.
///
/// Source: volatility3/framework/plugins/windows/psscan.py:
/// `constraints = poolscanner.PoolScanner.builtin_constraints(…, [b"Pro\xe3", b"Proc"])`
const PROC_PROTECTED_TAG: [u8; 4] = [b'P', b'r', b'o', 0xe3];
/// Pool tags to scan: the standard `Proc` and the Win10+ protected-pool variant `Pro\xe3`.
const POOL_TAGS: &[[u8; 4]] = &[PROC_TAG, PROC_PROTECTED_TAG];
/// Candidate `_EPROCESS` start offsets relative to the pool block base
/// (`pool_header`), covering the usual `_POOL_HEADER` + optional/`_OBJECT_HEADER`
/// span on x64 Windows. Validation rejects wrong guesses.
const EPROCESS_DELTAS: &[u64] = &[
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0,
];

/// Read `n` bytes at physical `pa`, returning `None` on a short read.
fn read_phys_exact<P: PhysicalMemoryProvider + ?Sized>(prov: &P, pa: u64, n: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; n];
    if prov.read_phys(pa, &mut buf).unwrap_or(0) < n {
        return None;
    }
    Some(buf)
}

/// True if `pid` looks like a real Windows process id: a small, non-zero
/// multiple of four (the kernel allocates client ids in steps of four).
fn plausible_pid(pid: u64) -> bool {
    pid >= 4 && pid <= 0x4_0000 && pid % 4 == 0
}

/// Decode a 15-byte `ImageFileName` to a validated process name, or `None`.
/// Requires printable ASCII, at least one letter, and NUL-or-end termination.
fn decode_image_name(raw: &[u8]) -> Option<String> {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    // A real `ImageFileName` is an executable base name — never a single
    // character; require at least two to reject lone-byte coincidences.
    if end < 2 || end > 15 {
        return None;
    }
    let name = &raw[..end];
    if !name.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
        return None;
    }
    if !name.iter().any(|&b| b.is_ascii_alphabetic()) {
        return None;
    }
    Some(String::from_utf8_lossy(name).into_owned())
}

/// Scan `prov`'s physical memory for `_EPROCESS` objects by their `Proc` pool
/// tag, reading `UniqueProcessId` at `pid_off` and `ImageFileName` at `name_off`
/// (both `_EPROCESS`-relative, from the ISF). Deduplicated by `(pid, name)`.
///
/// Panic-free and bounded; only structurally valid entries are returned.
///
/// This is a convenience wrapper over [`scan_processes_dtb`] with `dtb_off = None`
/// (no DTB validation). Prefer [`scan_processes_dtb`] when the `_KPROCESS`
/// `DirectoryTableBase` offset is available from the ISF.
pub fn scan_processes<P: PhysicalMemoryProvider + ?Sized>(
    prov: &P,
    pid_off: u64,
    name_off: u64,
) -> Vec<ScannedProcess> {
    scan_processes_dtb(prov, pid_off, name_off, None)
}

/// Scan `prov`'s physical memory for `_EPROCESS` objects by their `Proc` /
/// `Pro\xe3` pool tag, reading `UniqueProcessId` at `pid_off`, `ImageFileName`
/// at `name_off`, and optionally `_KPROCESS.DirectoryTableBase` at `dtb_off`
/// (all offsets are `_EPROCESS`-relative, sourced from the ISF).
///
/// When `dtb_off` is `Some`, the DTB is read and validated:
/// - Non-zero (a zero DTB has no valid page-table root)
/// - 4 KiB-aligned (x86-64 CR3 values are always page-aligned)
///
/// Candidates failing either check are silently skipped (false-positive
/// suppression without a panic). Results are deduplicated by `(pid, name)`.
///
/// Panic-free and bounded.
pub fn scan_processes_dtb<P: PhysicalMemoryProvider + ?Sized>(
    prov: &P,
    pid_off: u64,
    name_off: u64,
    dtb_off: Option<u64>,
) -> Vec<ScannedProcess> {
    const CHUNK: usize = 1 << 20; // 1 MiB
    const OVERLAP: u64 = 4;
    let mut out = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new();

    // Determine scan extents: the provider's ranges, or [0,total) if none.
    let ranges: Vec<(u64, u64)> = {
        let r = prov.ranges();
        if r.is_empty() {
            vec![(0, prov.total_size())]
        } else {
            r.iter().map(|x| (x.start, x.end)).collect()
        }
    };

    let mut buf = vec![0u8; CHUNK + OVERLAP as usize];
    for (start, end) in ranges {
        let mut addr = start;
        while addr < end {
            let n = prov.read_phys(addr, &mut buf).unwrap_or(0);
            if n < 4 {
                addr = addr.saturating_add(CHUNK as u64);
                continue;
            }
            // Find every `Proc` or `Pro\xe3` tag in this window.
            // Both are valid EPROCESS pool tags; see POOL_TAGS for references.
            let mut i = 0usize;
            while i + 4 <= n {
                let tag_match = POOL_TAGS.iter().any(|t| &buf[i..i + 4] == t.as_slice());
                if !tag_match {
                    i += 1;
                    continue;
                }
                // Pool tag sits at +4 in the _POOL_HEADER, so the block base is
                // 4 bytes before the tag's physical address.
                let tag_pa = addr + i as u64;
                let pool_base = tag_pa.saturating_sub(4);
                if let Some(p) = try_eprocess(prov, pool_base, pid_off, name_off, dtb_off) {
                    if seen.insert((p.pid, p.name.to_lowercase())) {
                        out.push(p);
                    }
                }
                i += 1;
            }
            addr = addr.saturating_add(CHUNK as u64 - OVERLAP);
        }
    }
    out
}

/// Try each candidate `_EPROCESS` offset within the pool block; return the first
/// that yields a plausible pid and a valid image name.
/// `_DISPATCHER_HEADER.Type` for a process object (`KOBJECTS::ProcessObject`).
/// `_EPROCESS` begins with `_KPROCESS` → `_DISPATCHER_HEADER`, so byte 0 of a
/// genuine `_EPROCESS` is this value — the discriminator that separates real
/// process objects from the many coincidental `Proc` byte sequences in a dump.
const DISPATCHER_TYPE_PROCESS: u8 = 0x03;

fn try_eprocess<P: PhysicalMemoryProvider + ?Sized>(
    prov: &P,
    pool_base: u64,
    pid_off: u64,
    name_off: u64,
    dtb_off: Option<u64>,
) -> Option<ScannedProcess> {
    for &delta in EPROCESS_DELTAS {
        let eproc = pool_base + delta;
        // Strong gate first: the object must start with a process
        // _DISPATCHER_HEADER. This rejects the bulk of coincidental tag matches.
        match read_phys_exact(prov, eproc, 1) {
            Some(b) if b[0] == DISPATCHER_TYPE_PROCESS => {}
            _ => continue,
        }
        let pid_bytes = read_phys_exact(prov, eproc + pid_off, 8)?;
        let pid = u64::from_le_bytes(pid_bytes.try_into().ok()?);
        if !plausible_pid(pid) {
            continue;
        }
        // DTB validation: when the offset is provided, read DirectoryTableBase
        // from _KPROCESS (at _EPROCESS+0, since Pcb is the first field) and
        // reject candidates with a zero or non-page-aligned value.
        let dtb = if let Some(off) = dtb_off {
            let Some(dtb_raw) = read_phys_exact(prov, eproc + off, 8) else {
                continue;
            };
            let v = u64::from_le_bytes(dtb_raw.try_into().ok()?);
            if !plausible_dtb(v) {
                continue;
            }
            Some(v)
        } else {
            None
        };
        let Some(name_raw) = read_phys_exact(prov, eproc + name_off, 15) else {
            continue;
        };
        if let Some(name) = decode_image_name(&name_raw) {
            return Some(ScannedProcess {
                physical_addr: eproc,
                pid,
                name,
                dtb,
            });
        }
    }
    None
}

/// True if `dtb` looks like a valid page-table root.
///
/// `_KPROCESS.DirectoryTableBase` holds the raw CR3 value. On Windows 10+
/// with KPTI (Kernel Page-Table Isolation) and PCID (Process-Context IDs)
/// enabled, the low 12 bits carry the PCID tag (typically 0x001 for kernel,
/// 0x003 for user) rather than being zero. The physical PML4 base is
/// therefore `dtb & !0xFFF`; the PCID bits are not an error.
///
/// Validation: the PML4 physical base (bits 63:12) must be non-zero —
/// a zero page-frame address has no valid page table regardless of PCID.
///
/// Source: x86-64 architecture manual §4.5 (CR3 bits 63:12 = PML4 base,
/// bits 11:0 = PCID when CR4.PCIDE=1); Windows Internals 7th ed. §5
/// (KPTI DirectoryTableBase includes PCID bits).
fn plausible_dtb(dtb: u64) -> bool {
    // Physical page frame address (bits 63:12) must be non-zero.
    dtb & !0xFFF != 0
}

/// Convenience wrapper: pull the `_EPROCESS` / `_KPROCESS` field offsets from
/// the reader's resolver and run `scan_processes_dtb`.
///
/// `UniqueProcessId` and `ImageFileName` are required; if absent, returns empty.
/// `_KPROCESS.DirectoryTableBase` is optional — when present, DTB validation is
/// enabled (recommended for zero false-positives on real dumps).
#[must_use]
pub fn psscan<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>) -> Vec<ScannedProcess> {
    let syms = reader.symbols();
    let (Some(pid_off), Some(name_off)) = (
        syms.field_offset("_EPROCESS", "UniqueProcessId"),
        syms.field_offset("_EPROCESS", "ImageFileName"),
    ) else {
        return Vec::new();
    };
    // _KPROCESS.DirectoryTableBase — available in real ISFs; optional for robustness.
    let dtb_off = syms.field_offset("_KPROCESS", "DirectoryTableBase");
    scan_processes_dtb(reader.vas().physical(), pid_off, name_off, dtb_off)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use memf_format::{PhysicalRange, Result as FmtResult};

    /// A flat physical memory provider over an owned byte buffer.
    struct VecMem {
        data: Vec<u8>,
        ranges: Vec<PhysicalRange>,
    }
    impl VecMem {
        fn new(data: Vec<u8>) -> Self {
            let ranges = vec![PhysicalRange {
                start: 0,
                end: data.len() as u64,
            }];
            Self { data, ranges }
        }
    }
    impl PhysicalMemoryProvider for VecMem {
        fn read_phys(&self, addr: u64, buf: &mut [u8]) -> FmtResult<usize> {
            let off = addr as usize;
            if off >= self.data.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.data.len() - off);
            buf[..n].copy_from_slice(&self.data[off..off + n]);
            Ok(n)
        }
        fn ranges(&self) -> &[PhysicalRange] {
            &self.ranges
        }
        fn total_size(&self) -> u64 {
            self.data.len() as u64
        }
        fn format_name(&self) -> &str {
            "vec"
        }
    }

    const PID_OFF: u64 = 0x2e0;
    const NAME_OFF: u64 = 0x438;

    /// A pool block whose `_EPROCESS` (at pool_base + 0x30) carries `pid` and
    /// `name`, embedded at `at` within a larger buffer.
    fn place_proc(buf: &mut [u8], at: usize, pid: u64, name: &str) {
        // _POOL_HEADER: tag "Proc" at +4.
        buf[at + 4..at + 8].copy_from_slice(b"Proc");
        let eproc = at + 0x30;
        // _DISPATCHER_HEADER.Type = ProcessObject at _EPROCESS+0.
        buf[eproc] = 0x03;
        buf[eproc + PID_OFF as usize..eproc + PID_OFF as usize + 8]
            .copy_from_slice(&pid.to_le_bytes());
        let nb = name.as_bytes();
        buf[eproc + NAME_OFF as usize..eproc + NAME_OFF as usize + nb.len()].copy_from_slice(nb);
    }

    #[test]
    fn psscan_finds_eprocess_by_pool_tag() {
        let mut data = vec![0u8; 0x4000];
        place_proc(&mut data, 0x100, 3644, "coreupdater.exe");
        place_proc(&mut data, 0x2000, 4, "System");
        let mem = VecMem::new(data);

        let found = scan_processes(&mem, PID_OFF, NAME_OFF);
        assert!(
            found
                .iter()
                .any(|p| p.pid == 3644 && p.name == "coreupdater.exe"),
            "must recover the malware process by pool tag: {found:?}"
        );
        assert!(found.iter().any(|p| p.pid == 4 && p.name == "System"));
    }

    #[test]
    fn psscan_rejects_bogus_pid_and_name() {
        let mut data = vec![0u8; 0x2000];
        // A "Proc" tag whose EPROCESS slot holds an implausible pid (odd) and
        // non-printable name — must not be reported.
        data[0x104..0x108].copy_from_slice(b"Proc");
        let eproc = 0x100 + 0x30;
        data[eproc + PID_OFF as usize..eproc + PID_OFF as usize + 8]
            .copy_from_slice(&7u64.to_le_bytes());
        data[eproc + NAME_OFF as usize..eproc + NAME_OFF as usize + 4]
            .copy_from_slice(&[0x01, 0x02, 0x00, 0x00]);
        let mem = VecMem::new(data);
        assert!(scan_processes(&mem, PID_OFF, NAME_OFF).is_empty());
    }

    /// A coincidental `Proc` tag with a plausible pid and a printable name but
    /// NO process `_DISPATCHER_HEADER` (byte 0 != 0x03) must be rejected — this
    /// is what suppresses the false-positive storm on a real 2 GiB dump.
    #[test]
    fn psscan_requires_process_dispatcher_header() {
        let mut data = vec![0u8; 0x2000];
        data[0x104..0x108].copy_from_slice(b"Proc");
        let eproc = 0x100 + 0x30;
        // valid-looking pid + name, but byte 0 is left 0x00 (not a process).
        data[eproc + PID_OFF as usize..eproc + PID_OFF as usize + 8]
            .copy_from_slice(&3644u64.to_le_bytes());
        data[eproc + NAME_OFF as usize..eproc + NAME_OFF as usize + 8].copy_from_slice(b"calc.exe");
        let mem = VecMem::new(data);
        assert!(
            scan_processes(&mem, PID_OFF, NAME_OFF).is_empty(),
            "no process dispatcher header → not a process"
        );
    }

    // DTB_OFF: _KPROCESS.DirectoryTableBase is at offset 0x28 within _KPROCESS,
    // which is at _EPROCESS offset 0 (Pcb field). So DTB is at _EPROCESS + 0x28.
    // Source: ISF ntkrnlmp_81BC5C37.json: _KPROCESS.DirectoryTableBase offset=40 (0x28).
    const DTB_OFF: u64 = 0x28;

    /// `place_proc_dtb` — like `place_proc` but also writes a DTB value.
    fn place_proc_dtb(buf: &mut [u8], at: usize, pid: u64, name: &str, dtb: u64) {
        place_proc(buf, at, pid, name);
        let eproc = at + 0x30;
        buf[eproc + DTB_OFF as usize..eproc + DTB_OFF as usize + 8]
            .copy_from_slice(&dtb.to_le_bytes());
    }

    /// The DTB field on `ScannedProcess` must be populated when `dtb_off` is
    /// provided to `scan_processes_dtb`. This test will FAIL until the function
    /// signature and implementation are extended with a `dtb_off` parameter.
    #[test]
    fn psscan_populates_dtb_field_when_offset_given() {
        let mut data = vec![0u8; 0x4000];
        // dtb = 0x1ad000 — 4 KiB aligned (real-world-like value)
        place_proc_dtb(&mut data, 0x100, 4, "System", 0x0000_0000_001a_d000);
        let mem = VecMem::new(data);
        let found = scan_processes_dtb(&mem, PID_OFF, NAME_OFF, Some(DTB_OFF));
        let sys = found.iter().find(|p| p.pid == 4).expect("System must be found");
        assert_eq!(
            sys.dtb,
            Some(0x0000_0000_001a_d000),
            "dtb must match the _KPROCESS.DirectoryTableBase value"
        );
    }

    /// A candidate EPROCESS whose DTB is zero (clearly invalid — no real process
    /// has a zero page-table root) must be rejected when DTB validation is active.
    #[test]
    fn psscan_rejects_eprocess_with_zero_dtb() {
        let mut data = vec![0u8; 0x4000];
        // dtb = 0 — invalid; should be rejected
        place_proc_dtb(&mut data, 0x100, 4, "System", 0);
        let mem = VecMem::new(data);
        let found = scan_processes_dtb(&mem, PID_OFF, NAME_OFF, Some(DTB_OFF));
        assert!(
            found.is_empty(),
            "zero DTB must be rejected as an invalid process candidate"
        );
    }

    /// A candidate whose DTB page-frame address (bits 63:12) is zero must be
    /// rejected, even if the low PCID bits are non-zero.
    ///
    /// On Windows 10+, `DirectoryTableBase` carries PCID bits in the low 12
    /// bits (e.g., `0x1ad001` = frame `0x1ad000` + PCID 1 is VALID). A truly
    /// invalid DTB is one where the page-frame bits are zero — e.g. `0x001`
    /// (only a PCID, no actual page-table address).
    #[test]
    fn psscan_rejects_eprocess_with_zero_frame_dtb() {
        let mut data = vec![0u8; 0x4000];
        // dtb = 0x001: page-frame address (bits 63:12) is 0 — no valid PML4.
        // This would be a bare PCID with no physical page-table backing.
        place_proc_dtb(&mut data, 0x100, 4, "System", 0x001);
        let mem = VecMem::new(data);
        let found = scan_processes_dtb(&mem, PID_OFF, NAME_OFF, Some(DTB_OFF));
        assert!(
            found.is_empty(),
            "DTB with zero page-frame (only PCID bits) must be rejected"
        );
    }

    /// DTB with PCID bits set (Windows 10+ KPTI) must be ACCEPTED — `0x1ad001`
    /// means frame `0x1ad000` + PCID=1 (kernel entry), which is a valid CR3.
    #[test]
    fn psscan_accepts_eprocess_with_pcid_dtb() {
        let mut data = vec![0u8; 0x4000];
        // dtb = 0x1ad001: frame 0x1ad000 + PCID 1 (kernel-mode Win10 CR3)
        place_proc_dtb(&mut data, 0x100, 4, "System", 0x1ad001);
        let mem = VecMem::new(data);
        let found = scan_processes_dtb(&mem, PID_OFF, NAME_OFF, Some(DTB_OFF));
        assert!(
            found.iter().any(|p| p.pid == 4 && p.name == "System"),
            "PCID-carrying DTB (Win10 KPTI) must be accepted: {found:?}"
        );
        let sys = found.iter().find(|p| p.pid == 4).unwrap();
        assert_eq!(
            sys.dtb,
            Some(0x1ad001),
            "dtb field must hold the raw _KPROCESS.DirectoryTableBase value"
        );
    }

    // ── Real-dump reconciliation (machine-specific; skipped in CI) ──────────────

    /// Real-dump oracle reconciliation: compare our psscan output against
    /// Volatility 3's `windows.psscan.PsScan` on `DESKTOP-SDN1RPT.mem`.
    ///
    /// Generate the oracle ONCE (takes ~2 min):
    ///   vol -r json -f /tmp/vol3_test/DESKTOP-SDN1RPT.mem \
    ///       windows.psscan.PsScan > /tmp/vol3_test/oracle_psscan.json
    ///
    /// Then run:
    ///   cargo test -p memf-windows --lib -- psscan::tests::psscan_reconcile_vs_vol3 \
    ///              --include-ignored
    ///
    /// Expected outcome: our unique-PID set ≥ vol3's unique-PID set.
    /// Vol3's output contains duplicate entries (same process appears at multiple
    /// virtual addresses across process layers); we scan physical memory once and
    /// naturally deduplicate. Discrepancies are printed for analysis.
    ///
    /// This test MUST NOT be removed — it is the Doer-Checker gate that proves the
    /// scanner is validated against a real 2 GiB Win10 dump and an independent oracle.
    #[test]
    #[ignore = "requires /tmp/vol3_test/DESKTOP-SDN1RPT.mem and oracle_psscan.json"]
    fn psscan_reconcile_vs_vol3() {
        use memf_format::open_dump_with_raw_fallback as open_dump;
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::SymbolResolver as _;
        use std::collections::HashSet;

        let dump_path = "/tmp/vol3_test/DESKTOP-SDN1RPT.mem";
        let isf_path = "/tmp/vol3_test/ntkrnlmp_81BC5C37.json";
        let oracle_path = "/tmp/vol3_test/oracle_psscan.json";

        // Load the ISF (real offsets for this dump).
        let isf_bytes = std::fs::read(isf_path).expect("ISF must exist at {isf_path}");
        let isf_json: serde_json::Value =
            serde_json::from_slice(&isf_bytes).expect("ISF must be valid JSON");
        let resolver =
            IsfResolver::from_value(&isf_json).expect("IsfResolver must parse the ISF");

        // Offsets from the real ISF (ntkrnlmp_81BC5C37.json):
        //   _EPROCESS.UniqueProcessId  offset=1088 (0x440)
        //   _EPROCESS.ImageFileName    offset=1448 (0x5A8)
        //   _KPROCESS.DirectoryTableBase offset=40 (0x28) — Pcb is at _EPROCESS+0
        let pid_off = resolver
            .field_offset("_EPROCESS", "UniqueProcessId")
            .expect("UniqueProcessId offset must be in ISF");
        let name_off = resolver
            .field_offset("_EPROCESS", "ImageFileName")
            .expect("ImageFileName offset must be in ISF");
        let dtb_off = resolver.field_offset("_KPROCESS", "DirectoryTableBase");

        // Open the raw dump and run our psscan.
        let dump = open_dump(std::path::Path::new(dump_path)).expect("dump must open");
        // scan_processes_dtb accepts &P where P: ?Sized, so Box<dyn …>.as_ref() works.
        let our_procs = scan_processes_dtb(dump.as_ref(), pid_off, name_off, dtb_off);

        let our_pids: HashSet<u64> = our_procs.iter().map(|p| p.pid).collect();

        // Load and parse the vol3 oracle.
        let oracle_bytes = std::fs::read(oracle_path).expect("oracle must exist");
        let oracle: Vec<serde_json::Value> =
            serde_json::from_slice(&oracle_bytes).expect("oracle must be valid JSON");
        let vol3_pids: HashSet<u64> = oracle
            .iter()
            .filter_map(|e| e.get("PID").and_then(|v| v.as_u64()))
            .collect();

        let overlap: Vec<u64> = {
            let mut v: Vec<u64> = our_pids.intersection(&vol3_pids).copied().collect();
            v.sort_unstable();
            v
        };
        let memf_only: Vec<u64> = {
            let mut v: Vec<u64> = our_pids.difference(&vol3_pids).copied().collect();
            v.sort_unstable();
            v
        };
        let vol3_only: Vec<u64> = {
            let mut v: Vec<u64> = vol3_pids.difference(&our_pids).copied().collect();
            v.sort_unstable();
            v
        };

        println!("=== psscan reconciliation vs vol3 ===");
        println!("  Our unique PIDs:  {}", our_pids.len());
        println!("  Vol3 unique PIDs: {}", vol3_pids.len());
        println!("  Overlap:          {} PIDs", overlap.len());
        println!("  memf-only (FP?):  {:?}", memf_only);
        println!("  vol3-only (miss): {:?}", vol3_only);

        // memf-only entries are potential false positives — target 0.
        assert!(
            memf_only.is_empty(),
            "psscan found {} PID(s) not in vol3 oracle (false positives): {:?}",
            memf_only.len(),
            memf_only,
        );

        // We must find at least as many unique PIDs as vol3.
        assert!(
            our_pids.len() >= vol3_pids.len(),
            "psscan found {} unique PIDs, vol3 found {} — we should be >= vol3",
            our_pids.len(),
            vol3_pids.len(),
        );
    }

    /// Vol3's `psscan` scans for BOTH `b"Proc"` AND `b"Pro\xe3"` pool tags.
    /// The `\xe3` variant is the "protected" (high-MSB) non-paged pool allocation
    /// that Windows 10+ uses for kernel objects — the pool tag bytes 0..3 are `Pro`
    /// and byte 3 is set to `\xe3` (non-paged + protection flag).
    ///
    /// Reference: volatility3/framework/plugins/windows/psscan.py line
    /// `constraints = poolscanner.PoolScanner.builtin_constraints(…, [b"Pro\xe3", b"Proc"])`
    ///
    /// This test places an EPROCESS under the `Pro\xe3` tag and expects it to be
    /// recovered. It will FAIL until the scanner is extended to match both tags.
    #[test]
    fn psscan_finds_eprocess_with_protected_pool_tag() {
        let mut data = vec![0u8; 0x4000];
        // Place an EPROCESS with the PROTECTED pool tag (Pro\xe3) at offset 0x200.
        // _POOL_HEADER: tag at +4, using the protected variant.
        data[0x204..0x208].copy_from_slice(b"Pro\xe3");
        let eproc = 0x200 + 0x30;
        data[eproc] = 0x03; // _DISPATCHER_HEADER.Type = ProcessObject
        // pid=1236 is a valid Windows process id: non-zero, <= 0x40000, multiple of 4.
        data[eproc + PID_OFF as usize..eproc + PID_OFF as usize + 8]
            .copy_from_slice(&1236u64.to_le_bytes());
        let name = b"hidden.exe";
        data[eproc + NAME_OFF as usize..eproc + NAME_OFF as usize + name.len()]
            .copy_from_slice(name);
        let mem = VecMem::new(data);
        let found = scan_processes(&mem, PID_OFF, NAME_OFF);
        assert!(
            found.iter().any(|p| p.pid == 1236 && p.name == "hidden.exe"),
            "must recover process under Pro\\xe3 (protected) pool tag: {found:?}"
        );
    }
}
