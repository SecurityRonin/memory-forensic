//! LD_PRELOAD injection detection for Linux memory forensics.
//!
//! LD_PRELOAD is a Linux environment variable that forces shared libraries
//! to be loaded before any others. Attackers abuse it for function hooking,
//! credential stealing, and rootkit injection. This module detects
//! LD_PRELOAD usage by reading each process's environment block from
//! `mm_struct.env_start`..`env_end` and scanning for `LD_PRELOAD=`.
//!
//! Suspicious indicators include libraries in `/tmp`, `/dev/shm`, hidden
//! paths (dotfiles), and other uncommon locations.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, ProcessInfo, Result};

/// Maximum environment region size to read (64 KiB safety limit).
const MAX_ENV_SIZE: u64 = 64 * 1024;

/// Information about an LD_PRELOAD value found in a process's environment.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LdPreloadInfo {
    /// Process ID.
    pub pid: u32,
    /// Process command name.
    pub process_name: String,
    /// The raw LD_PRELOAD environment variable value.
    pub ld_preload_value: String,
    /// Individual library paths extracted from the LD_PRELOAD value.
    pub preloaded_libraries: Vec<String>,
    /// Whether the LD_PRELOAD value looks suspicious (tmp, devshm, hidden paths).
    pub is_suspicious: bool,
}

/// Parse an LD_PRELOAD value into individual library paths.
///
/// LD_PRELOAD entries are separated by `:` or whitespace. Empty entries
/// (from consecutive delimiters) are filtered out.
pub fn parse_ld_preload(value: &str) -> Vec<String> {
    value
        .split(|c: char| c == ':' || c.is_ascii_whitespace())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Classify an LD_PRELOAD value as suspicious or benign.
///
/// A value is suspicious if any library path:
/// - Resides in `/tmp` or subdirectories
/// - Resides in `/dev/shm` or subdirectories
/// - Contains a hidden path component (directory or file starting with `.`)
/// - Resides outside standard library directories (`/usr/lib`, `/lib`, etc.)
pub fn classify_ld_preload(value: &str) -> bool {
    /// Standard library directories considered benign.
    const SAFE_PREFIXES: &[&str] = &[
        "/usr/lib/",
        "/usr/lib64/",
        "/usr/lib32/",
        "/usr/local/lib/",
        "/usr/local/lib64/",
        "/lib/",
        "/lib64/",
        "/lib32/",
    ];

    let libraries = parse_ld_preload(value);
    libraries.iter().any(|lib| is_suspicious_path(lib, SAFE_PREFIXES))
}

/// Check whether a single library path looks suspicious.
fn is_suspicious_path(path: &str, safe_prefixes: &[&str]) -> bool {
    // Libraries in /tmp are suspicious (attacker staging area).
    if path.starts_with("/tmp/") || path == "/tmp" {
        return true;
    }

    // Libraries in /dev/shm are suspicious (shared memory, no disk footprint).
    if path.starts_with("/dev/shm/") || path == "/dev/shm" {
        return true;
    }

    // Hidden path components (directories or files starting with '.') are suspicious.
    if path.split('/').any(|component| {
        !component.is_empty() && component.starts_with('.')
    }) {
        return true;
    }

    // Libraries outside standard directories are suspicious.
    if !safe_prefixes.iter().any(|prefix| path.starts_with(prefix)) {
        return true;
    }

    false
}

/// Scan processes for LD_PRELOAD environment variable injection.
///
/// For each process in the provided list, reads the environment block from
/// `mm_struct.env_start`..`env_end`, scans for a `LD_PRELOAD=` entry, and
/// if found, parses the libraries and classifies the value.
///
/// Returns only processes that **have** LD_PRELOAD set in their environment.
/// Kernel threads (NULL mm) and processes with unreadable environment blocks
/// are silently skipped.
pub fn scan_ld_preload<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    processes: &[ProcessInfo],
) -> Result<Vec<LdPreloadInfo>> {
    if processes.is_empty() {
        return Ok(Vec::new());
    }

    let mut results = Vec::new();

    for proc in processes {
        if let Some(info) = scan_process_ld_preload(reader, proc) {
            results.push(info);
        }
    }

    Ok(results)
}

/// Scan a single process for LD_PRELOAD in its environment block.
///
/// Returns `None` if the process has no mm_struct, unreadable environment,
/// or no LD_PRELOAD variable set.
fn scan_process_ld_preload<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    proc: &ProcessInfo,
) -> Option<LdPreloadInfo> {
    // Read mm pointer from task_struct.
    let mm_ptr: u64 = reader.read_field(proc.vaddr, "task_struct", "mm").ok()?;
    if mm_ptr == 0 {
        return None; // kernel thread
    }

    // Read env_start and env_end from mm_struct.
    let env_start: u64 = reader.read_field(mm_ptr, "mm_struct", "env_start").ok()?;
    let env_end: u64 = reader.read_field(mm_ptr, "mm_struct", "env_end").ok()?;

    if env_start == 0 || env_end <= env_start {
        return None;
    }

    let size = (env_end - env_start).min(MAX_ENV_SIZE);
    let data = reader.read_bytes(env_start, size as usize).ok()?;

    // Scan null-terminated strings for LD_PRELOAD=
    let ld_preload_value = extract_ld_preload(&data)?;

    let preloaded_libraries = parse_ld_preload(&ld_preload_value);
    let is_suspicious = classify_ld_preload(&ld_preload_value);

    Some(LdPreloadInfo {
        pid: proc.pid as u32,
        process_name: proc.comm.clone(),
        ld_preload_value,
        preloaded_libraries,
        is_suspicious,
    })
}

/// Extract the LD_PRELOAD value from a raw environment block.
///
/// The environment block contains null-separated `KEY=VALUE\0` strings.
/// Returns `Some(value)` if an `LD_PRELOAD=...` entry is found.
fn extract_ld_preload(data: &[u8]) -> Option<String> {
    const PREFIX: &[u8] = b"LD_PRELOAD=";

    for chunk in data.split(|&b| b == 0) {
        if chunk.starts_with(PREFIX) {
            let value = String::from_utf8_lossy(&chunk[PREFIX.len()..]);
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // parse_ld_preload tests
    // ---------------------------------------------------------------

    #[test]
    fn parse_ld_preload_single() {
        let result = parse_ld_preload("/usr/lib/libfoo.so");
        assert_eq!(result, vec!["/usr/lib/libfoo.so"]);
    }

    #[test]
    fn parse_ld_preload_multiple_colon() {
        let result = parse_ld_preload("/lib/a.so:/lib/b.so");
        assert_eq!(result, vec!["/lib/a.so", "/lib/b.so"]);
    }

    #[test]
    fn parse_ld_preload_multiple_space() {
        let result = parse_ld_preload("/lib/a.so /lib/b.so");
        assert_eq!(result, vec!["/lib/a.so", "/lib/b.so"]);
    }

    #[test]
    fn parse_ld_preload_mixed_delimiters() {
        let result = parse_ld_preload("/lib/a.so:/lib/b.so /lib/c.so");
        assert_eq!(result, vec!["/lib/a.so", "/lib/b.so", "/lib/c.so"]);
    }

    #[test]
    fn parse_ld_preload_empty_string() {
        let result = parse_ld_preload("");
        assert!(result.is_empty());
    }

    // ---------------------------------------------------------------
    // classify_ld_preload tests
    // ---------------------------------------------------------------

    #[test]
    fn classify_benign_preload() {
        // Address sanitizer in standard library path — not suspicious.
        assert!(
            !classify_ld_preload("/usr/lib/libasan.so"),
            "standard library path should not be suspicious"
        );
    }

    #[test]
    fn classify_benign_lib64() {
        assert!(
            !classify_ld_preload("/usr/lib64/libjemalloc.so"),
            "/usr/lib64 should not be suspicious"
        );
    }

    #[test]
    fn classify_suspicious_tmp() {
        assert!(
            classify_ld_preload("/tmp/.hidden/rootkit.so"),
            "/tmp path should be suspicious"
        );
    }

    #[test]
    fn classify_suspicious_devshm() {
        assert!(
            classify_ld_preload("/dev/shm/inject.so"),
            "/dev/shm path should be suspicious"
        );
    }

    #[test]
    fn classify_suspicious_hidden_path() {
        assert!(
            classify_ld_preload("/home/user/.config/.evil/hook.so"),
            "hidden path component should be suspicious"
        );
    }

    #[test]
    fn classify_suspicious_uncommon_location() {
        assert!(
            classify_ld_preload("/var/run/payload.so"),
            "uncommon location should be suspicious"
        );
    }

    #[test]
    fn classify_multiple_with_one_suspicious() {
        // If any library in the value is suspicious, the whole value is suspicious.
        assert!(
            classify_ld_preload("/usr/lib/libasan.so:/tmp/evil.so"),
            "one suspicious library should flag the whole value"
        );
    }

    // ---------------------------------------------------------------
    // scan_ld_preload tests
    // ---------------------------------------------------------------

    #[test]
    fn scan_ld_preload_empty() {
        // Empty process list should return empty Vec.
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let json = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();
        let ptb = PageTableBuilder::new();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = scan_ld_preload(&reader, &[]).unwrap();
        assert!(result.is_empty(), "expected empty vec for empty process list");
    }
}
