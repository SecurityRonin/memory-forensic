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

use crate::{ProcessInfo, Result};

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
    libraries
        .iter()
        .any(|lib| is_suspicious_path(lib, SAFE_PREFIXES))
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
    if path
        .split('/')
        .any(|component| !component.is_empty() && component.starts_with('.'))
    {
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
        assert!(
            result.is_empty(),
            "expected empty vec for empty process list"
        );
    }

    // ---------------------------------------------------------------
    // extract_ld_preload unit tests
    // ---------------------------------------------------------------

    #[test]
    fn extract_ld_preload_finds_value() {
        let env = b"PATH=/usr/bin\0LD_PRELOAD=/tmp/evil.so\0HOME=/root\0";
        let result = extract_ld_preload(env);
        assert_eq!(result.unwrap(), "/tmp/evil.so");
    }

    #[test]
    fn extract_ld_preload_not_present_returns_none() {
        let env = b"PATH=/usr/bin\0HOME=/root\0";
        assert!(extract_ld_preload(env).is_none());
    }

    #[test]
    fn extract_ld_preload_empty_value_returns_none() {
        // LD_PRELOAD= with empty value (whitespace only) → None
        let env = b"LD_PRELOAD=   \0OTHER=val\0";
        assert!(extract_ld_preload(env).is_none(), "whitespace-only value must return None");
    }

    #[test]
    fn extract_ld_preload_trims_whitespace() {
        let env = b"LD_PRELOAD=  /usr/lib/lib.so  \0";
        let result = extract_ld_preload(env);
        assert_eq!(result.unwrap(), "/usr/lib/lib.so");
    }

    // ---------------------------------------------------------------
    // is_suspicious_path boundary tests
    // ---------------------------------------------------------------

    #[test]
    fn is_suspicious_path_tmp_exact_is_suspicious() {
        const SAFE: &[&str] = &["/usr/lib/"];
        assert!(is_suspicious_path("/tmp", SAFE), "/tmp itself must be suspicious");
    }

    #[test]
    fn is_suspicious_path_devshm_exact_is_suspicious() {
        const SAFE: &[&str] = &["/usr/lib/"];
        assert!(is_suspicious_path("/dev/shm", SAFE), "/dev/shm itself must be suspicious");
    }

    #[test]
    fn is_suspicious_path_hidden_dotfile_is_suspicious() {
        const SAFE: &[&str] = &["/usr/lib/"];
        assert!(is_suspicious_path("/home/user/.hidden.so", SAFE), "dotfile must be suspicious");
    }

    #[test]
    fn is_suspicious_path_safe_prefix_not_suspicious() {
        const SAFE: &[&str] = &["/usr/lib/"];
        assert!(!is_suspicious_path("/usr/lib/libasan.so", SAFE));
    }

    #[test]
    fn is_suspicious_path_non_safe_non_tmp_non_hidden_is_suspicious() {
        const SAFE: &[&str] = &["/usr/lib/"];
        // /var/run does not match any safe prefix and is not /tmp or /dev/shm
        assert!(is_suspicious_path("/var/run/payload.so", SAFE));
    }

    // ---------------------------------------------------------------
    // classify_ld_preload additional paths
    // ---------------------------------------------------------------

    #[test]
    fn classify_lib_not_suspicious() {
        assert!(!classify_ld_preload("/lib/libasan.so"));
    }

    #[test]
    fn classify_lib64_not_suspicious() {
        assert!(!classify_ld_preload("/lib64/libasan.so"));
    }

    #[test]
    fn classify_lib32_not_suspicious() {
        assert!(!classify_ld_preload("/lib32/libasan.so"));
    }

    #[test]
    fn classify_usr_local_lib_not_suspicious() {
        assert!(!classify_ld_preload("/usr/local/lib/libfoo.so"));
    }

    #[test]
    fn classify_usr_local_lib64_not_suspicious() {
        assert!(!classify_ld_preload("/usr/local/lib64/libfoo.so"));
    }

    #[test]
    fn classify_usr_lib32_not_suspicious() {
        assert!(!classify_ld_preload("/usr/lib32/libfoo.so"));
    }

    // ---------------------------------------------------------------
    // scan_ld_preload with an unreadable task_struct → silently skipped
    // ---------------------------------------------------------------

    #[test]
    fn scan_ld_preload_unreadable_task_skips_silently() {
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 256)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "mm", 8, "pointer")
            .add_struct("mm_struct", 128)
            .add_field("mm_struct", "env_start", 0, "unsigned long")
            .add_field("mm_struct", "env_end", 8, "unsigned long")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // vaddr not mapped → read_field("mm") fails → scan_process_ld_preload returns None
        let proc = ProcessInfo {
            pid: 500,
            ppid: 1,
            comm: "bash".to_string(),
            state: crate::types::ProcessState::Running,
            vaddr: 0xDEAD_0000_0000_0000,
            cr3: None,
            start_time: 0,
        };

        let result = scan_ld_preload(&reader, &[proc]).unwrap();
        assert!(result.is_empty(), "unreadable process must be silently skipped");
    }

    #[test]
    fn ld_preload_info_serializes() {
        let info = LdPreloadInfo {
            pid: 42,
            process_name: "bash".to_string(),
            ld_preload_value: "/tmp/evil.so".to_string(),
            preloaded_libraries: vec!["/tmp/evil.so".to_string()],
            is_suspicious: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":42"));
        assert!(json.contains("\"is_suspicious\":true"));
    }

    // ---------------------------------------------------------------
    // parse_ld_preload edge cases
    // ---------------------------------------------------------------

    #[test]
    fn parse_ld_preload_consecutive_delimiters_filtered() {
        // Consecutive delimiters produce empty entries which should be filtered
        let result = parse_ld_preload("/lib/a.so::/lib/b.so");
        assert_eq!(result, vec!["/lib/a.so", "/lib/b.so"]);
    }

    #[test]
    fn parse_ld_preload_tab_delimiter() {
        let result = parse_ld_preload("/lib/a.so\t/lib/b.so");
        assert_eq!(result, vec!["/lib/a.so", "/lib/b.so"]);
    }

    // ---------------------------------------------------------------
    // scan_ld_preload: process with mm=0 (kernel thread) → skipped
    // ---------------------------------------------------------------

    #[test]
    fn scan_ld_preload_mm_null_skipped() {
        use memf_core::test_builders::{flags as ptf, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let task_vaddr: u64 = 0xFFFF_8800_00D0_0000;
        let task_paddr: u64 = 0x00D0_0000;

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 0x200)
            .add_field("task_struct", "pid", 0x00, "unsigned int")
            .add_field("task_struct", "mm", 0x08, "pointer")
            .add_struct("mm_struct", 0x100)
            .add_field("mm_struct", "env_start", 0x00, "unsigned long")
            .add_field("mm_struct", "env_end", 0x08, "unsigned long")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // task page: mm at 0x08 = 0 (kernel thread)
        let mut task_page = [0u8; 4096];
        task_page[0..4].copy_from_slice(&77u32.to_le_bytes()); // pid=77
        // mm stays 0

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(task_vaddr, task_paddr, ptf::WRITABLE)
            .write_phys(task_paddr, &task_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let proc = ProcessInfo {
            pid: 77,
            ppid: 1,
            comm: "kworker".to_string(),
            state: crate::types::ProcessState::Running,
            vaddr: task_vaddr,
            cr3: None,
            start_time: 0,
        };

        let result = scan_ld_preload(&reader, &[proc]).unwrap();
        assert!(result.is_empty(), "kernel thread with mm=0 must be skipped");
    }

    // ---------------------------------------------------------------
    // scan_ld_preload: env block readable, LD_PRELOAD present → LdPreloadInfo produced
    // ---------------------------------------------------------------

    #[test]
    fn scan_ld_preload_env_block_with_ld_preload_produces_entry() {
        use memf_core::test_builders::{flags as ptf, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Layout:
        //   task_vaddr: task_struct (mm at 0x08)
        //   mm_vaddr:   mm_struct   (env_start at 0x00, env_end at 0x08)
        //   env_vaddr:  env block containing "LD_PRELOAD=/tmp/evil.so\0"

        let task_vaddr: u64 = 0xFFFF_8800_00D1_0000;
        let task_paddr: u64 = 0x00D1_0000;
        let mm_vaddr: u64   = 0xFFFF_8800_00D2_0000;
        let mm_paddr: u64   = 0x00D2_0000;
        let env_vaddr: u64  = 0xFFFF_8800_00D3_0000;
        let env_paddr: u64  = 0x00D3_0000;

        let env_data: &[u8] = b"PATH=/usr/bin\0LD_PRELOAD=/tmp/evil.so\0HOME=/root\0";
        let env_end_vaddr = env_vaddr + env_data.len() as u64;

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 0x200)
            .add_field("task_struct", "pid", 0x00, "unsigned int")
            .add_field("task_struct", "mm", 0x08, "pointer")
            .add_struct("mm_struct", 0x100)
            .add_field("mm_struct", "env_start", 0x00, "unsigned long")
            .add_field("mm_struct", "env_end", 0x08, "unsigned long")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // task page: mm at 0x08 → mm_vaddr
        let mut task_page = [0u8; 4096];
        task_page[0..4].copy_from_slice(&123u32.to_le_bytes()); // pid=123
        task_page[8..16].copy_from_slice(&mm_vaddr.to_le_bytes());

        // mm page: env_start, env_end
        let mut mm_page = [0u8; 4096];
        mm_page[0..8].copy_from_slice(&env_vaddr.to_le_bytes());
        mm_page[8..16].copy_from_slice(&env_end_vaddr.to_le_bytes());

        // env page
        let mut env_page = [0u8; 4096];
        env_page[..env_data.len()].copy_from_slice(env_data);

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(task_vaddr, task_paddr, ptf::WRITABLE)
            .write_phys(task_paddr, &task_page)
            .map_4k(mm_vaddr, mm_paddr, ptf::WRITABLE)
            .write_phys(mm_paddr, &mm_page)
            .map_4k(env_vaddr, env_paddr, ptf::WRITABLE)
            .write_phys(env_paddr, &env_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let proc = ProcessInfo {
            pid: 123,
            ppid: 1,
            comm: "evil_proc".to_string(),
            state: crate::types::ProcessState::Running,
            vaddr: task_vaddr,
            cr3: None,
            start_time: 0,
        };

        let result = scan_ld_preload(&reader, &[proc]).unwrap();
        assert_eq!(result.len(), 1, "one LD_PRELOAD entry should be produced");
        assert_eq!(result[0].ld_preload_value, "/tmp/evil.so");
        assert_eq!(result[0].preloaded_libraries, vec!["/tmp/evil.so"]);
        assert!(result[0].is_suspicious, "/tmp/ path must be suspicious");
        assert_eq!(result[0].pid, 123);
    }

    // ---------------------------------------------------------------
    // scan_ld_preload: env_start == env_end → None (empty env)
    // ---------------------------------------------------------------

    #[test]
    fn scan_ld_preload_empty_env_region_skipped() {
        use memf_core::test_builders::{flags as ptf, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let task_vaddr: u64 = 0xFFFF_8800_00D4_0000;
        let task_paddr: u64 = 0x00D4_0000;
        let mm_vaddr: u64   = 0xFFFF_8800_00D5_0000;
        let mm_paddr: u64   = 0x00D5_0000;

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 0x200)
            .add_field("task_struct", "pid", 0x00, "unsigned int")
            .add_field("task_struct", "mm", 0x08, "pointer")
            .add_struct("mm_struct", 0x100)
            .add_field("mm_struct", "env_start", 0x00, "unsigned long")
            .add_field("mm_struct", "env_end", 0x08, "unsigned long")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut task_page = [0u8; 4096];
        task_page[8..16].copy_from_slice(&mm_vaddr.to_le_bytes());

        // mm: env_start = env_end = 0x1000 → size=0 → None
        let mut mm_page = [0u8; 4096];
        let same_addr: u64 = 0xFFFF_8800_00D6_0000;
        mm_page[0..8].copy_from_slice(&same_addr.to_le_bytes()); // env_start
        mm_page[8..16].copy_from_slice(&same_addr.to_le_bytes()); // env_end (equal → skip)

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(task_vaddr, task_paddr, ptf::WRITABLE)
            .write_phys(task_paddr, &task_page)
            .map_4k(mm_vaddr, mm_paddr, ptf::WRITABLE)
            .write_phys(mm_paddr, &mm_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let proc = ProcessInfo {
            pid: 88,
            ppid: 1,
            comm: "proc88".to_string(),
            state: crate::types::ProcessState::Running,
            vaddr: task_vaddr,
            cr3: None,
            start_time: 0,
        };

        let result = scan_ld_preload(&reader, &[proc]).unwrap();
        assert!(result.is_empty(), "env_start == env_end → empty env region → no entry");
    }
}
