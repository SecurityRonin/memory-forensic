//! UserAssist evidence-of-execution walker.
//!
//! Windows stores program launch counts and last-run timestamps in the
//! NTUSER.DAT registry hive under
//! `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`.
//! Values are ROT13-encoded file paths with a fixed-size binary data
//! structure containing run count and FILETIME.
//!
//! The binary value data (72 bytes on Vista+) has the following layout:
//!   - Offset  4: Run count (u32)
//!   - Offset  8: Focus count (u32)
//!   - Offset 12: Focus time in milliseconds (u32)
//!   - Offset 60: Last run time (u64, FILETIME)

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// Maximum number of UserAssist entries to enumerate (safety limit).
const MAX_USERASSIST_ENTRIES: usize = 4096;

/// Minimum binary data size for a UserAssist value (Vista+ format).
const USERASSIST_DATA_SIZE: usize = 72;

/// A single UserAssist entry recovered from the registry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UserAssistEntry {
    /// ROT13-decoded path (executable name or GUID-prefixed path).
    pub name: String,
    /// Number of times the program was run.
    pub run_count: u32,
    /// Number of times the program gained focus.
    pub focus_count: u32,
    /// Last run time as a Windows FILETIME (100-ns intervals since 1601-01-01).
    pub last_run_time: u64,
    /// Total focus time in milliseconds.
    pub focus_time_ms: u32,
    /// Whether this entry matches suspicious patterns (hacking tools,
    /// living-off-the-land binaries from unusual paths, etc.).
    pub is_suspicious: bool,
}

/// Decode a ROT13-encoded string.
///
/// ROT13 rotates ASCII letters by 13 positions, wrapping around.
/// Non-alphabetic characters pass through unchanged. This is used by
/// Windows to obfuscate UserAssist value names in the registry.
pub fn rot13_decode(s: &str) -> String {
    todo!()
}

/// Classify a decoded UserAssist name as suspicious.
///
/// Returns `true` if the name matches patterns commonly associated with
/// post-exploitation tools, living-off-the-land abuse, or programs run
/// from unusual locations:
///
/// - Known offensive tools: mimikatz, psexec, cobalt strike, etc.
/// - Shell interpreters from unusual paths (not `\Windows\System32\`)
/// - Script engines (wscript, cscript, mshta) -- frequently abused
/// - Encoded command-line launchers
pub fn classify_userassist(name: &str) -> bool {
    todo!()
}

/// Walk UserAssist entries from a registry hive loaded in memory.
///
/// `hive_addr` is the virtual address of the `_HBASE_BLOCK` for an
/// NTUSER.DAT hive. The walker navigates:
///   1. Root key -> `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`
///   2. Each GUID subkey -> `Count` subkey
///   3. Each value in `Count`: ROT13-decode the name, parse the 72-byte
///      binary data for run count, focus count, focus time, and last-run FILETIME.
///
/// Returns `Ok(Vec::new())` if required symbols are missing or the path
/// does not exist (graceful degradation).
pub fn walk_userassist<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
) -> crate::Result<Vec<UserAssistEntry>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ── rot13_decode tests ───────────────────────────────────────────

    /// Basic ROT13: "Pzq.rkr" decodes to "Cmd.exe".
    #[test]
    fn rot13_decode_basic() {
        assert_eq!(rot13_decode("Pzq.rkr"), "Cmd.exe");
    }

    /// Non-alpha characters pass through unchanged; letters still rotate.
    /// "P:\\Hfref" (ROT13 of "C:\Users") decodes back to "C:\\Users".
    #[test]
    fn rot13_decode_passthrough() {
        assert_eq!(rot13_decode("P:\\Hfref"), "C:\\Users");
    }

    // ── classify_userassist tests ────────────────────────────────────

    /// Normal Windows programs should not be flagged.
    #[test]
    fn classify_userassist_benign() {
        assert!(!classify_userassist("C:\\Windows\\System32\\notepad.exe"));
        assert!(!classify_userassist("C:\\Program Files\\Microsoft Office\\WINWORD.EXE"));
        assert!(!classify_userassist("{6D809377-6AF0-444B-8957-A3773F02200E}\\calc.exe"));
    }

    /// Known offensive/hacking tools must be flagged as suspicious.
    #[test]
    fn classify_userassist_suspicious_tool() {
        assert!(classify_userassist("C:\\Temp\\mimikatz.exe"));
        assert!(classify_userassist("C:\\Users\\admin\\Desktop\\PsExec.exe"));
        assert!(classify_userassist("D:\\tools\\cobalt_strike\\beacon.exe"));
        assert!(classify_userassist("C:\\Users\\hacker\\procdump.exe"));
    }

    /// Script engines and living-off-the-land binaries from unusual
    /// paths should be flagged.
    #[test]
    fn classify_userassist_lolbin_suspicious() {
        // mshta from any path is suspicious
        assert!(classify_userassist("C:\\Windows\\System32\\mshta.exe"));
        // wscript/cscript are suspicious
        assert!(classify_userassist("C:\\Windows\\System32\\wscript.exe"));
        assert!(classify_userassist("C:\\Windows\\System32\\cscript.exe"));
    }

    // ── walk_userassist tests ────────────────────────────────────────

    /// Empty reader with no relevant symbols → returns empty Vec.
    #[test]
    fn walk_userassist_no_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("_CM_KEY_NODE", 0x50)
            .add_field("_CM_KEY_NODE", "Signature", 0x00, "unsigned short")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_userassist(&reader, 0).unwrap();
        assert!(result.is_empty());
    }
}
