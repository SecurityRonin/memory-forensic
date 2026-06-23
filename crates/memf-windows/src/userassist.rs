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

use crate::registry;

/// Maximum number of UserAssist entries to enumerate (safety limit).
const MAX_USERASSIST_ENTRIES: usize = 4096;

/// Minimum binary data size for a UserAssist value (Vista+ format).
const USERASSIST_DATA_SIZE: usize = 72;

/// The path components from the hive root to the UserAssist key.
const USERASSIST_PATH: &[&str] = &[
    "Software",
    "Microsoft",
    "Windows",
    "CurrentVersion",
    "Explorer",
    "UserAssist",
];

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

// ── ROT13 ────────────────────────────────────────────────────────────

/// Decode a ROT13-encoded string.
///
/// ROT13 rotates ASCII letters by 13 positions, wrapping around.
/// Non-alphabetic characters pass through unchanged. This is used by
/// Windows to obfuscate UserAssist value names in the registry.
pub fn rot13_decode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='M' | 'a'..='m' => (c as u8 + 13) as char,
            'N'..='Z' | 'n'..='z' => (c as u8 - 13) as char,
            other => other,
        })
        .collect()
}

// ── Suspicious classification ────────────────────────────────────────

/// Known offensive/post-exploitation tool names (lowercase for matching).
const SUSPICIOUS_TOOLS: &[&str] = &[
    "mimikatz",
    "psexec",
    "procdump",
    "beacon",
    "cobalt",
    "rubeus",
    "seatbelt",
    "sharpup",
    "sharphound",
    "bloodhound",
    "lazagne",
    "safetykatz",
    "winpeas",
    "linpeas",
    "chisel",
    "plink",
    "ncat",
    "netcat",
    "nc.exe",
    "nc64.exe",
    "whoami",   // not always suspicious, but in UserAssist context it is noteworthy
    "certutil", // frequently abused for downloads
];

/// Script engines and living-off-the-land binaries that are always
/// suspicious in a UserAssist context (indicating interactive use).
const SUSPICIOUS_LOLBINS: &[&str] = &[
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "msiexec.exe",
    "certutil.exe",
    "bitsadmin.exe",
];

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
    let lower = name.to_ascii_lowercase();

    // Check for known offensive tool names anywhere in the path.
    for tool in SUSPICIOUS_TOOLS {
        if lower.contains(tool) {
            return true;
        }
    }

    // Check for LOLBins — these are suspicious when they appear in
    // UserAssist because it means a user interactively launched them.
    for lolbin in SUSPICIOUS_LOLBINS {
        if lower.ends_with(lolbin)
            || lower.contains(&format!("\\{lolbin}"))
            || lower.contains(&format!("/{lolbin}"))
        {
            return true;
        }
    }

    // cmd.exe or powershell.exe from outside System32 is suspicious.
    let is_cmd_or_ps = lower.contains("cmd.exe") || lower.contains("powershell.exe");
    if is_cmd_or_ps && !lower.contains("\\windows\\system32\\") {
        return true;
    }

    false
}

// ── UserAssist walker (shared HMAP cell-map navigation) ──────────────────

/// Walk the UserAssist subkeys of an in-memory NTUSER.DAT hive.
///
/// `hive_addr` is the `_CMHIVE`/`_HHIVE` VA. Navigates
/// `Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist`, then
/// for each `{GUID}\\Count` subkey reads every value (a ROT13-encoded program
/// name + a Vista+ binary blob) via the shared HMAP walkers. Returns an empty
/// `Vec` on a missing hive or absent UserAssist key (graceful degradation).
pub fn walk_userassist<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
) -> crate::Result<Vec<UserAssistEntry>> {
    let mut current = registry::resolve_root_cell(reader, hive_addr);
    if current == 0 {
        return Ok(Vec::new());
    }
    for &component in USERASSIST_PATH {
        if current == 0 {
            return Ok(Vec::new());
        }
        current = registry::find_subkey_by_name(reader, hive_addr, current, component);
    }
    if current == 0 {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for (_guid_name, guid_va) in registry::list_subkeys(reader, hive_addr, current)
        .into_iter()
        .take(MAX_USERASSIST_ENTRIES)
    {
        let count_va = registry::find_subkey_by_name(reader, hive_addr, guid_va, "Count");
        if count_va == 0 {
            continue;
        }
        for value in registry::list_values(reader, hive_addr, count_va) {
            if entries.len() >= MAX_USERASSIST_ENTRIES {
                break;
            }
            if let Some(entry) = parse_userassist_entry(&value.name, &value.data) {
                entries.push(entry);
            }
        }
    }
    Ok(entries)
}

/// Parse one UserAssist value — a ROT13-encoded `raw_name` plus a Vista+ binary
/// `data` blob — into a [`UserAssistEntry`]. Returns `None` if the blob is
/// smaller than the 72-byte Vista+ record. Layout: run_count@4, focus_count@8,
/// focus_time_ms@12, last_run_time (FILETIME)@60.
fn parse_userassist_entry(raw_name: &str, data: &[u8]) -> Option<UserAssistEntry> {
    if data.len() < USERASSIST_DATA_SIZE {
        return None;
    }
    let name = rot13_decode(raw_name);
    let run_count = data[4..8].try_into().map_or(0, u32::from_le_bytes);
    let focus_count = data[8..12].try_into().map_or(0, u32::from_le_bytes);
    let focus_time_ms = data[12..16].try_into().map_or(0, u32::from_le_bytes);
    let last_run_time = data[60..68].try_into().map_or(0, u64::from_le_bytes);
    let is_suspicious = classify_userassist(&name);
    Some(UserAssistEntry {
        name,
        run_count,
        focus_count,
        last_run_time,
        focus_time_ms,
        is_suspicious,
    })
}

#[cfg(test)]
mod tests {
    // Test fixtures declare layout consts/helpers beside the statements that use
    // them to keep each byte-plan readable; that ordering is intentional here.
    #![allow(clippy::items_after_statements)]
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_reader() -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("_CM_KEY_NODE", 0x50)
            .add_field("_CM_KEY_NODE", "Signature", 0x00, "unsigned short")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    // ── rot13_decode exhaustive tests ────────────────────────────────

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

    /// ROT13 is its own inverse.
    #[test]
    fn rot13_involutory() {
        let original = "mimikatz.exe";
        assert_eq!(rot13_decode(&rot13_decode(original)), original);
    }

    /// Empty string decodes to empty string.
    #[test]
    fn rot13_empty_string() {
        assert_eq!(rot13_decode(""), "");
    }

    /// Digits and punctuation pass through unchanged.
    #[test]
    fn rot13_digits_unchanged() {
        assert_eq!(rot13_decode("1234567890!@#$%"), "1234567890!@#$%");
    }

    /// ROT13 wraps at alphabet boundaries: 'N'→'A', 'Z'→'M', 'n'→'a', 'z'→'m'.
    #[test]
    fn rot13_boundary_wrap() {
        assert_eq!(rot13_decode("N"), "A");
        assert_eq!(rot13_decode("Z"), "M");
        assert_eq!(rot13_decode("n"), "a");
        assert_eq!(rot13_decode("z"), "m");
        // Forward direction
        assert_eq!(rot13_decode("A"), "N");
        assert_eq!(rot13_decode("M"), "Z");
        assert_eq!(rot13_decode("a"), "n");
        assert_eq!(rot13_decode("m"), "z");
    }

    /// Decode a known ROT13 encoded UserAssist name.
    #[test]
    fn rot13_decode_userassist_known() {
        // "zvzvxngm.rkr" is ROT13 of "mimikatz.exe"
        assert_eq!(rot13_decode("zvzvxngm.rkr"), "mimikatz.exe");
    }

    // ── classify_userassist tests ────────────────────────────────────

    /// Normal Windows programs should not be flagged.
    #[test]
    fn classify_userassist_benign() {
        assert!(!classify_userassist("C:\\Windows\\System32\\notepad.exe"));
        assert!(!classify_userassist(
            "C:\\Program Files\\Microsoft Office\\WINWORD.EXE"
        ));
        assert!(!classify_userassist(
            "{6D809377-6AF0-444B-8957-A3773F02200E}\\calc.exe"
        ));
    }

    /// Known offensive/hacking tools must be flagged as suspicious.
    #[test]
    fn classify_userassist_suspicious_tool() {
        assert!(classify_userassist("C:\\Temp\\mimikatz.exe"));
        assert!(classify_userassist("C:\\Users\\admin\\Desktop\\PsExec.exe"));
        assert!(classify_userassist("D:\\tools\\cobalt_strike\\beacon.exe"));
        assert!(classify_userassist("C:\\Users\\hacker\\procdump.exe"));
    }

    /// All known suspicious tools are flagged.
    #[test]
    fn classify_userassist_all_suspicious_tools() {
        let tools = [
            "mimikatz",
            "psexec",
            "procdump",
            "beacon",
            "cobalt",
            "rubeus",
            "seatbelt",
            "sharpup",
            "sharphound",
            "bloodhound",
            "lazagne",
            "safetykatz",
            "winpeas",
            "linpeas",
            "chisel",
            "plink",
            "ncat",
            "netcat",
            "nc.exe",
            "nc64.exe",
            "whoami",
            "certutil",
        ];
        for tool in &tools {
            assert!(
                classify_userassist(&format!("C:\\Temp\\{tool}.exe")),
                "Expected {tool} to be suspicious"
            );
        }
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

    /// All LOLBins are flagged.
    #[test]
    fn classify_userassist_all_lolbins_suspicious() {
        let lolbins = [
            "mshta.exe",
            "wscript.exe",
            "cscript.exe",
            "regsvr32.exe",
            "rundll32.exe",
            "msiexec.exe",
            "certutil.exe",
            "bitsadmin.exe",
        ];
        for bin in &lolbins {
            assert!(
                classify_userassist(&format!("C:\\Windows\\System32\\{bin}")),
                "Expected LOLBin {bin} to be suspicious"
            );
        }
    }

    /// LOLBins also detected by path component.
    #[test]
    fn classify_userassist_lolbin_path_contains() {
        assert!(classify_userassist("C:\\Users\\user\\mshta.exe"));
        assert!(classify_userassist("C:\\Temp\\rundll32.exe"));
    }

    /// cmd.exe from system32 is NOT suspicious.
    #[test]
    fn classify_userassist_cmd_system32_benign() {
        assert!(!classify_userassist("C:\\Windows\\System32\\cmd.exe"));
    }

    /// cmd.exe from outside system32 IS suspicious.
    #[test]
    fn classify_userassist_cmd_outside_system32_suspicious() {
        assert!(classify_userassist("C:\\Temp\\cmd.exe"));
        assert!(classify_userassist("C:\\Users\\admin\\cmd.exe"));
    }

    /// powershell.exe from system32 is NOT suspicious.
    #[test]
    fn classify_userassist_powershell_system32_benign() {
        assert!(!classify_userassist(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        ));
    }

    /// powershell.exe from outside system32 IS suspicious.
    #[test]
    fn classify_userassist_powershell_outside_system32_suspicious() {
        assert!(classify_userassist("C:\\Temp\\powershell.exe"));
    }

    /// Empty string is benign.
    #[test]
    fn classify_userassist_empty_benign() {
        assert!(!classify_userassist(""));
    }

    // ── walk_userassist tests ────────────────────────────────────────

    /// Empty reader with no relevant symbols → returns empty Vec.
    #[test]
    fn walk_userassist_no_symbol() {
        let reader = make_reader();
        let result = walk_userassist(&reader, 0).unwrap();
        assert!(result.is_empty());
    }

    /// Non-zero but unmapped hive address → returns empty Vec.
    #[test]
    fn walk_userassist_unmapped_hive_graceful() {
        let reader = make_reader();
        let result = walk_userassist(&reader, 0xDEAD_BEEF_0000).unwrap();
        assert!(result.is_empty());
    }

    /// Walk body exercises past root-cell read when hive is mapped but root cell is 0.
    ///
    /// Puts a valid `_HBASE_BLOCK` in memory with `RootCell` = 0.
    /// The walker reads the root cell at offset 0x24, gets 0, and returns empty.
    #[test]
    fn walk_userassist_mapped_hive_root_cell_zero_empty() {
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};

        let isf = IsfBuilder::new()
            .add_struct("_HBASE_BLOCK", 0x200)
            .add_field("_HBASE_BLOCK", "RootCell", 0x24, "unsigned long")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let hive_vaddr: u64 = 0xFFFF_8000_0100_0000;
        let hive_paddr: u64 = 0x0010_0000;

        // Build a 4096-byte page for the hive block with RootCell = 0 at offset 0x24.
        let hive_page = [0u8; 4096];
        // RootCell at offset 0x24 stays 0 (default zero-init).
        let _ = hive_page; // used below

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_userassist(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty(), "root cell == 0 should return empty");
    }

    // ── UserAssistEntry struct tests ─────────────────────────────────

    #[test]
    fn userassist_entry_construction() {
        let entry = UserAssistEntry {
            name: "C:\\Windows\\System32\\notepad.exe".to_string(),
            run_count: 5,
            focus_count: 3,
            last_run_time: 132_000_000_000_000_000,
            focus_time_ms: 15000,
            is_suspicious: false,
        };
        assert_eq!(entry.run_count, 5);
        assert_eq!(entry.focus_count, 3);
        assert!(!entry.is_suspicious);
    }

    #[test]
    fn userassist_entry_serialization() {
        let entry = UserAssistEntry {
            name: "mimikatz.exe".to_string(),
            run_count: 1,
            focus_count: 1,
            last_run_time: 0,
            focus_time_ms: 0,
            is_suspicious: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"is_suspicious\":true"));
        assert!(json.contains("\"run_count\":1"));
        assert!(json.contains("\"name\":\"mimikatz.exe\""));
    }

    /// classify_userassist: lolbin ends_with variant coverage (path ends with lolbin name).
    #[test]
    fn classify_userassist_lolbin_ends_with() {
        // This uses the `ends_with(lolbin)` branch.
        assert!(classify_userassist("mshta.exe"));
        assert!(classify_userassist("rundll32.exe"));
        assert!(classify_userassist("bitsadmin.exe"));
    }

    /// classify_userassist: path contains /lolbin (Unix-style path).
    #[test]
    fn classify_userassist_lolbin_forward_slash_path() {
        // Forward slash path contains "/wscript.exe"
        assert!(classify_userassist("/usr/bin/wscript.exe"));
    }

    /// rot13_decode: full alphabet test.
    #[test]
    fn rot13_decode_full_alphabet() {
        let input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let expected = "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm";
        assert_eq!(rot13_decode(input), expected);
    }

    #[test]
    fn userassist_path_components() {
        assert_eq!(USERASSIST_PATH[0], "Software");
        assert_eq!(USERASSIST_PATH[1], "Microsoft");
        assert_eq!(USERASSIST_PATH[2], "Windows");
        assert_eq!(USERASSIST_PATH[3], "CurrentVersion");
        assert_eq!(USERASSIST_PATH[4], "Explorer");
        assert_eq!(USERASSIST_PATH[5], "UserAssist");
    }

    /// RED (flat→HMAP migration): a real cell-map NTUSER.DAT laid out as
    /// Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
    /// with one ROT13-named value (72-byte Vista+ blob), built with the shared
    /// CellHive harness. The flat walker reads the root cell from
    /// _HBASE_BLOCK+0x24 (a zeroed page on a cell-map hive) → empty. Asserts the
    /// entry is recovered, so it FAILS until walk_userassist uses the HMAP walker.
    #[test]
    fn walk_userassist_hmap_recovers_entry() {
        use crate::test_hive::CellHive;
        let decoded = r"C:\Windows\System32\cmd.exe";
        let encoded = rot13_decode(decoded); // ROT13 is involutory → stored name
        let guid = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}";

        let mut h = CellHive::new(0x0050_0000);
        h.nk(0x020, b"Root", 1, 0x0A0, 0);
        h.lf(0x0A0, &[0x0E0]);
        h.nk(0x0E0, b"Software", 1, 0x140, 0);
        h.lf(0x140, &[0x180]);
        h.nk(0x180, b"Microsoft", 1, 0x1E0, 0);
        h.lf(0x1E0, &[0x220]);
        h.nk(0x220, b"Windows", 1, 0x280, 0);
        h.lf(0x280, &[0x2C0]);
        h.nk(0x2C0, b"CurrentVersion", 1, 0x320, 0);
        h.lf(0x320, &[0x360]);
        h.nk(0x360, b"Explorer", 1, 0x3C0, 0);
        h.lf(0x3C0, &[0x400]);
        h.nk(0x400, b"UserAssist", 1, 0x460, 0);
        h.lf(0x460, &[0x4A0]);
        h.nk(0x4A0, guid.as_bytes(), 1, 0x520, 0);
        h.lf(0x520, &[0x560]);
        h.nk(0x560, b"Count", 0, 0, 0);
        h.values(0x560, 1, 0x600);
        h.value_list(0x600, &[0x640]);

        // 72-byte Vista+ UserAssist blob: run_count@4, focus_count@8,
        // focus_time_ms@12, last_run_time(FILETIME)@60.
        let mut blob = vec![0u8; 72];
        blob[4..8].copy_from_slice(&7u32.to_le_bytes());
        blob[8..12].copy_from_slice(&3u32.to_le_bytes());
        blob[12..16].copy_from_slice(&1500u32.to_le_bytes());
        blob[60..68].copy_from_slice(&0x01D9_1234_5678_9ABCu64.to_le_bytes());
        h.vk(0x640, encoded.as_bytes(), 3, blob.len() as u32, 0x700);
        h.data(0x700, &blob);

        let reader = h.reader();
        let entries = walk_userassist(&reader, h.hhive_va).unwrap();

        assert_eq!(
            entries.len(),
            1,
            "expected 1 userassist entry, got {}",
            entries.len()
        );
        let e = &entries[0];
        assert_eq!(e.name, decoded, "ROT13 value name must decode");
        assert_eq!(e.run_count, 7);
        assert_eq!(e.focus_count, 3);
        assert_eq!(e.focus_time_ms, 1500);
        assert_eq!(e.last_run_time, 0x01D9_1234_5678_9ABC);
    }
}
