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
}

/// `Proc` pool tag, little-endian.
const PROC_TAG: [u8; 4] = *b"Proc";
/// Candidate `_EPROCESS` start offsets relative to the pool block base
/// (`pool_header`), covering the usual `_POOL_HEADER` + optional/`_OBJECT_HEADER`
/// span on x64 Windows. Validation rejects wrong guesses.
const EPROCESS_DELTAS: &[u64] = &[
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0,
];

/// Read `n` bytes at physical `pa`, returning `None` on a short read.
fn read_phys_exact<P: PhysicalMemoryProvider>(prov: &P, pa: u64, n: usize) -> Option<Vec<u8>> {
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
pub fn scan_processes<P: PhysicalMemoryProvider>(
    prov: &P,
    pid_off: u64,
    name_off: u64,
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
            // Find every `Proc` tag in this window.
            let mut i = 0usize;
            while i + 4 <= n {
                if buf[i..i + 4] != PROC_TAG {
                    i += 1;
                    continue;
                }
                // Pool tag sits at +4 in the _POOL_HEADER, so the block base is
                // 4 bytes before the tag's physical address.
                let tag_pa = addr + i as u64;
                let pool_base = tag_pa.saturating_sub(4);
                if let Some(p) = try_eprocess(prov, pool_base, pid_off, name_off) {
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

fn try_eprocess<P: PhysicalMemoryProvider>(
    prov: &P,
    pool_base: u64,
    pid_off: u64,
    name_off: u64,
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
        let Some(name_raw) = read_phys_exact(prov, eproc + name_off, 15) else {
            continue;
        };
        if let Some(name) = decode_image_name(&name_raw) {
            return Some(ScannedProcess {
                physical_addr: eproc,
                pid,
                name,
            });
        }
    }
    None
}

/// Convenience wrapper: pull the `_EPROCESS` field offsets from the reader's
/// resolver and scan. Empty if the offsets are unavailable.
#[must_use]
pub fn psscan<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>) -> Vec<ScannedProcess> {
    let syms = reader.symbols();
    let (Some(pid_off), Some(name_off)) = (
        syms.field_offset("_EPROCESS", "UniqueProcessId"),
        syms.field_offset("_EPROCESS", "ImageFileName"),
    ) else {
        return Vec::new();
    };
    scan_processes(reader.vas().physical(), pid_off, name_off)
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
}
