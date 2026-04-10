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

// ── Hive cell constants (duplicated from registry_keys for encapsulation) ──

/// Offset of `RootCell` (u32) within `_HBASE_BLOCK`.
const HBASE_BLOCK_ROOT_CELL_OFFSET: u64 = 0x24;

/// Offset from `_HBASE_BLOCK` to the first HBIN (cell storage start).
const HBIN_START_OFFSET: u64 = 0x1000;

/// `_CM_KEY_NODE` signature "nk".
const NK_SIGNATURE: u16 = 0x6B6E;

/// Stable subkey count: u32 at offset 0x14 in nk cell data.
const NK_STABLE_SUBKEY_COUNT_OFFSET: usize = 0x14;

/// Stable subkeys list cell index: u32 at offset 0x1C.
const NK_STABLE_SUBKEYS_LIST_OFFSET: usize = 0x1C;

/// Value count: u32 at offset 0x24.
const NK_VALUE_COUNT_OFFSET: usize = 0x24;

/// Values list cell index: u32 at offset 0x28.
const NK_VALUES_LIST_OFFSET: usize = 0x28;

/// Name length: u16 at offset 0x48.
const NK_NAME_LENGTH_OFFSET: usize = 0x48;

/// Name data starts at offset 0x4C.
const NK_NAME_OFFSET: usize = 0x4C;

/// `_CM_KEY_VALUE` signature "vk".
const VK_SIGNATURE: u16 = 0x6B76;

/// Value name length: u16 at offset 0x02.
const VK_NAME_LENGTH_OFFSET: usize = 0x02;

/// Value data length: u32 at offset 0x04.
const VK_DATA_LENGTH_OFFSET: usize = 0x04;

/// Value data offset (cell index): u32 at offset 0x08.
const VK_DATA_OFFSET_OFFSET: usize = 0x08;

/// Value name starts at offset 0x14.
const VK_NAME_OFFSET: usize = 0x14;

/// Maximum subkeys per node (safety limit).
const MAX_SUBKEYS: usize = 4096;

/// Maximum values per key (safety limit).
const MAX_VALUES: usize = 4096;

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

// ── Hive cell helpers ────────────────────────────────────────────────

/// Compute the virtual address of a cell given its cell index.
fn cell_address(hive_addr: u64, cell_index: u32) -> u64 {
    hive_addr
        .wrapping_add(HBIN_START_OFFSET)
        .wrapping_add(cell_index as u64)
}

/// Read cell data from a cell at `cell_vaddr`, skipping the 4-byte size header.
fn read_cell_data<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    cell_vaddr: u64,
) -> crate::Result<Vec<u8>> {
    let size_bytes = reader.read_bytes(cell_vaddr, 4)?;
    let raw_size = i32::from_le_bytes(size_bytes[..4].try_into().unwrap());
    let abs_size = raw_size.unsigned_abs() as usize;
    if abs_size <= 4 {
        return Ok(Vec::new());
    }
    let data_len = (abs_size - 4).min(0x10000);
    reader
        .read_bytes(cell_vaddr.wrapping_add(4), data_len)
        .map_err(Into::into)
}

/// Extract the key name from an nk cell's data bytes (ASCII, compressed).
fn read_key_name(nk_data: &[u8]) -> String {
    if nk_data.len() < NK_NAME_OFFSET + 1 {
        return String::new();
    }
    let name_len = u16::from_le_bytes(
        nk_data[NK_NAME_LENGTH_OFFSET..NK_NAME_LENGTH_OFFSET + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let end = NK_NAME_OFFSET + name_len;
    if end > nk_data.len() {
        return String::new();
    }
    String::from_utf8_lossy(&nk_data[NK_NAME_OFFSET..end]).into_owned()
}

/// Read the value name from a vk cell's data bytes.
fn read_value_name(vk_data: &[u8]) -> String {
    if vk_data.len() < VK_NAME_OFFSET + 1 {
        return String::new();
    }
    let name_len = u16::from_le_bytes(
        vk_data[VK_NAME_LENGTH_OFFSET..VK_NAME_LENGTH_OFFSET + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let end = VK_NAME_OFFSET + name_len;
    if end > vk_data.len() {
        return String::new();
    }
    String::from_utf8_lossy(&vk_data[VK_NAME_OFFSET..end]).into_owned()
}

/// Find a subkey by name (case-insensitive) under a given nk cell.
///
/// Returns the cell index of the matching subkey, or `None`.
fn find_subkey<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    nk_data: &[u8],
    target_name: &str,
) -> crate::Result<Option<u32>> {
    if nk_data.len() < NK_STABLE_SUBKEYS_LIST_OFFSET + 4 {
        return Ok(None);
    }

    let subkey_count = u32::from_le_bytes(
        nk_data[NK_STABLE_SUBKEY_COUNT_OFFSET..NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;

    if subkey_count == 0 {
        return Ok(None);
    }

    let subkeys_list_cell = u32::from_le_bytes(
        nk_data[NK_STABLE_SUBKEYS_LIST_OFFSET..NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .try_into()
            .unwrap(),
    );

    // The subkeys list cell may be an index node (lf, lh, ri, li).
    // Read its data and iterate child cell indices.
    let list_vaddr = cell_address(hive_addr, subkeys_list_cell);
    let list_data = read_cell_data(reader, list_vaddr)?;

    if list_data.len() < 4 {
        return Ok(None);
    }

    let sig = u16::from_le_bytes(list_data[0..2].try_into().unwrap());
    let count = u16::from_le_bytes(list_data[2..4].try_into().unwrap()) as usize;
    let count = count.min(MAX_SUBKEYS);

    match sig {
        // "lf" (0x666C) or "lh" (0x686C): each entry is 8 bytes (cell index + hash).
        0x666C | 0x686C => {
            for i in 0..count {
                let off = 4 + i * 8;
                if off + 4 > list_data.len() {
                    break;
                }
                let child_cell = u32::from_le_bytes(list_data[off..off + 4].try_into().unwrap());
                let child_vaddr = cell_address(hive_addr, child_cell);
                if let Ok(child_nk) = read_cell_data(reader, child_vaddr) {
                    if child_nk.len() >= NK_NAME_OFFSET {
                        let child_sig = u16::from_le_bytes(child_nk[0..2].try_into().unwrap());
                        if child_sig == NK_SIGNATURE {
                            let name = read_key_name(&child_nk);
                            if name.eq_ignore_ascii_case(target_name) {
                                return Ok(Some(child_cell));
                            }
                        }
                    }
                }
            }
        }
        // "li" (0x696C): each entry is 4 bytes (cell index only).
        0x696C => {
            for i in 0..count {
                let off = 4 + i * 4;
                if off + 4 > list_data.len() {
                    break;
                }
                let child_cell = u32::from_le_bytes(list_data[off..off + 4].try_into().unwrap());
                let child_vaddr = cell_address(hive_addr, child_cell);
                if let Ok(child_nk) = read_cell_data(reader, child_vaddr) {
                    if child_nk.len() >= NK_NAME_OFFSET {
                        let child_sig = u16::from_le_bytes(child_nk[0..2].try_into().unwrap());
                        if child_sig == NK_SIGNATURE {
                            let name = read_key_name(&child_nk);
                            if name.eq_ignore_ascii_case(target_name) {
                                return Ok(Some(child_cell));
                            }
                        }
                    }
                }
            }
        }
        // "ri" (0x6972): index of indices — each entry is a cell index to
        // another lf/lh/li list. Recurse one level.
        0x6972 => {
            for i in 0..count {
                let off = 4 + i * 4;
                if off + 4 > list_data.len() {
                    break;
                }
                let sub_list_cell = u32::from_le_bytes(list_data[off..off + 4].try_into().unwrap());
                // Build a synthetic nk_data-like slice so we can call ourselves
                // with the sub-list. Instead, just read the sub-list directly.
                let sub_vaddr = cell_address(hive_addr, sub_list_cell);
                let sub_data = read_cell_data(reader, sub_vaddr)?;
                if sub_data.len() < 4 {
                    continue;
                }
                let sub_sig = u16::from_le_bytes(sub_data[0..2].try_into().unwrap());
                let sub_count = u16::from_le_bytes(sub_data[2..4].try_into().unwrap()) as usize;
                let sub_count = sub_count.min(MAX_SUBKEYS);
                let entry_size: usize = match sub_sig {
                    0x666C | 0x686C => 8,
                    0x696C => 4,
                    _ => continue,
                };
                for j in 0..sub_count {
                    let soff = 4 + j * entry_size;
                    if soff + 4 > sub_data.len() {
                        break;
                    }
                    let child_cell =
                        u32::from_le_bytes(sub_data[soff..soff + 4].try_into().unwrap());
                    let child_vaddr = cell_address(hive_addr, child_cell);
                    if let Ok(child_nk) = read_cell_data(reader, child_vaddr) {
                        if child_nk.len() >= NK_NAME_OFFSET {
                            let child_sig = u16::from_le_bytes(child_nk[0..2].try_into().unwrap());
                            if child_sig == NK_SIGNATURE {
                                let name = read_key_name(&child_nk);
                                if name.eq_ignore_ascii_case(target_name) {
                                    return Ok(Some(child_cell));
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    Ok(None)
}

/// List all subkey cell indices under a given nk cell.
fn list_subkeys<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    nk_data: &[u8],
) -> crate::Result<Vec<u32>> {
    if nk_data.len() < NK_STABLE_SUBKEYS_LIST_OFFSET + 4 {
        return Ok(Vec::new());
    }

    let subkey_count = u32::from_le_bytes(
        nk_data[NK_STABLE_SUBKEY_COUNT_OFFSET..NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;

    if subkey_count == 0 {
        return Ok(Vec::new());
    }

    let subkeys_list_cell = u32::from_le_bytes(
        nk_data[NK_STABLE_SUBKEYS_LIST_OFFSET..NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .try_into()
            .unwrap(),
    );

    let list_vaddr = cell_address(hive_addr, subkeys_list_cell);
    let list_data = read_cell_data(reader, list_vaddr)?;

    if list_data.len() < 4 {
        return Ok(Vec::new());
    }

    let sig = u16::from_le_bytes(list_data[0..2].try_into().unwrap());
    let count = u16::from_le_bytes(list_data[2..4].try_into().unwrap()) as usize;
    let count = count.min(MAX_SUBKEYS);
    let mut cells = Vec::with_capacity(count);

    match sig {
        0x666C | 0x686C => {
            for i in 0..count {
                let off = 4 + i * 8;
                if off + 4 > list_data.len() {
                    break;
                }
                cells.push(u32::from_le_bytes(
                    list_data[off..off + 4].try_into().unwrap(),
                ));
            }
        }
        0x696C => {
            for i in 0..count {
                let off = 4 + i * 4;
                if off + 4 > list_data.len() {
                    break;
                }
                cells.push(u32::from_le_bytes(
                    list_data[off..off + 4].try_into().unwrap(),
                ));
            }
        }
        0x6972 => {
            for i in 0..count {
                let off = 4 + i * 4;
                if off + 4 > list_data.len() {
                    break;
                }
                let sub_cell = u32::from_le_bytes(list_data[off..off + 4].try_into().unwrap());
                let sub_vaddr = cell_address(hive_addr, sub_cell);
                if let Ok(sub_data) = read_cell_data(reader, sub_vaddr) {
                    if sub_data.len() >= 4 {
                        let sub_sig = u16::from_le_bytes(sub_data[0..2].try_into().unwrap());
                        let sub_count =
                            u16::from_le_bytes(sub_data[2..4].try_into().unwrap()) as usize;
                        let sub_count = sub_count.min(MAX_SUBKEYS);
                        let entry_size: usize = match sub_sig {
                            0x666C | 0x686C => 8,
                            0x696C => 4,
                            _ => continue,
                        };
                        for j in 0..sub_count {
                            let soff = 4 + j * entry_size;
                            if soff + 4 > sub_data.len() {
                                break;
                            }
                            cells.push(u32::from_le_bytes(
                                sub_data[soff..soff + 4].try_into().unwrap(),
                            ));
                        }
                    }
                }
            }
        }
        _ => {}
    }

    Ok(cells)
}

// ── Walk function ────────────────────────────────────────────────────

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
    // Read root cell index from _HBASE_BLOCK.
    let root_cell_bytes =
        match reader.read_bytes(hive_addr.wrapping_add(HBASE_BLOCK_ROOT_CELL_OFFSET), 4) {
            Ok(b) => b,
            Err(_) => return Ok(Vec::new()),
        };
    let root_cell = u32::from_le_bytes(root_cell_bytes[..4].try_into().unwrap());
    if root_cell == 0 {
        return Ok(Vec::new());
    }

    // Navigate from root to the UserAssist key.
    let mut current_cell = root_cell;
    for &component in USERASSIST_PATH {
        let cell_vaddr = cell_address(hive_addr, current_cell);
        let nk_data = match read_cell_data(reader, cell_vaddr) {
            Ok(d) => d,
            Err(_) => return Ok(Vec::new()),
        };
        if nk_data.len() < NK_NAME_OFFSET {
            return Ok(Vec::new());
        }
        let sig = u16::from_le_bytes(nk_data[0..2].try_into().unwrap());
        if sig != NK_SIGNATURE {
            return Ok(Vec::new());
        }
        match find_subkey(reader, hive_addr, &nk_data, component)? {
            Some(child) => current_cell = child,
            None => return Ok(Vec::new()),
        }
    }

    // `current_cell` now points to the UserAssist key.
    // Enumerate GUID subkeys.
    let ua_vaddr = cell_address(hive_addr, current_cell);
    let ua_nk = read_cell_data(reader, ua_vaddr)?;
    let guid_cells = list_subkeys(reader, hive_addr, &ua_nk)?;

    let mut entries = Vec::new();

    for guid_cell in guid_cells {
        if entries.len() >= MAX_USERASSIST_ENTRIES {
            break;
        }

        let guid_vaddr = cell_address(hive_addr, guid_cell);
        let guid_nk = match read_cell_data(reader, guid_vaddr) {
            Ok(d) => d,
            Err(_) => continue,
        };
        if guid_nk.len() < NK_NAME_OFFSET {
            continue;
        }
        let sig = u16::from_le_bytes(guid_nk[0..2].try_into().unwrap());
        if sig != NK_SIGNATURE {
            continue;
        }

        // Find the "Count" subkey under the GUID key.
        let count_cell = match find_subkey(reader, hive_addr, &guid_nk, "Count")? {
            Some(c) => c,
            None => continue,
        };

        // Read values from the Count key.
        let count_vaddr = cell_address(hive_addr, count_cell);
        let count_nk = match read_cell_data(reader, count_vaddr) {
            Ok(d) => d,
            Err(_) => continue,
        };
        if count_nk.len() < NK_VALUES_LIST_OFFSET + 4 {
            continue;
        }

        let value_count = u32::from_le_bytes(
            count_nk[NK_VALUE_COUNT_OFFSET..NK_VALUE_COUNT_OFFSET + 4]
                .try_into()
                .unwrap(),
        ) as usize;

        if value_count == 0 {
            continue;
        }

        let values_list_cell = u32::from_le_bytes(
            count_nk[NK_VALUES_LIST_OFFSET..NK_VALUES_LIST_OFFSET + 4]
                .try_into()
                .unwrap(),
        );

        let vl_vaddr = cell_address(hive_addr, values_list_cell);
        let vl_data = match read_cell_data(reader, vl_vaddr) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let count = value_count.min(MAX_VALUES);
        for i in 0..count {
            if entries.len() >= MAX_USERASSIST_ENTRIES {
                break;
            }
            let off = i * 4;
            if off + 4 > vl_data.len() {
                break;
            }
            let val_cell = u32::from_le_bytes(vl_data[off..off + 4].try_into().unwrap());

            match parse_userassist_value(reader, hive_addr, val_cell) {
                Ok(Some(entry)) => entries.push(entry),
                _ => continue,
            }
        }
    }

    Ok(entries)
}

/// Parse a single UserAssist value cell into a `UserAssistEntry`.
///
/// Returns `Ok(None)` if the value data is too small (not Vista+ format)
/// or the value cell is invalid.
fn parse_userassist_value<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    val_cell: u32,
) -> crate::Result<Option<UserAssistEntry>> {
    let val_vaddr = cell_address(hive_addr, val_cell);
    let vk_data = read_cell_data(reader, val_vaddr)?;

    if vk_data.len() < VK_NAME_OFFSET {
        return Ok(None);
    }

    let sig = u16::from_le_bytes(vk_data[0..2].try_into().unwrap());
    if sig != VK_SIGNATURE {
        return Ok(None);
    }

    // Read the ROT13-encoded value name.
    let rot13_name = read_value_name(&vk_data);
    let decoded_name = rot13_decode(&rot13_name);

    // Read the binary value data.
    let data_length = u32::from_le_bytes(
        vk_data[VK_DATA_LENGTH_OFFSET..VK_DATA_LENGTH_OFFSET + 4]
            .try_into()
            .unwrap(),
    );

    // Strip MSB (inline data flag) for size check.
    let actual_length = (data_length & 0x7FFF_FFFF) as usize;

    if actual_length < USERASSIST_DATA_SIZE {
        return Ok(None);
    }

    // Read the value data from the data cell.
    let data_cell = u32::from_le_bytes(
        vk_data[VK_DATA_OFFSET_OFFSET..VK_DATA_OFFSET_OFFSET + 4]
            .try_into()
            .unwrap(),
    );

    let data_vaddr = cell_address(hive_addr, data_cell);
    let raw_data = read_cell_data(reader, data_vaddr)?;

    if raw_data.len() < USERASSIST_DATA_SIZE {
        return Ok(None);
    }

    // Parse the 72-byte UserAssist data structure (Vista+ format).
    let run_count = u32::from_le_bytes(raw_data[4..8].try_into().unwrap());
    let focus_count = u32::from_le_bytes(raw_data[8..12].try_into().unwrap());
    let focus_time_ms = u32::from_le_bytes(raw_data[12..16].try_into().unwrap());
    let last_run_time = u64::from_le_bytes(raw_data[60..68].try_into().unwrap());

    let is_suspicious = classify_userassist(&decoded_name);

    Ok(Some(UserAssistEntry {
        name: decoded_name,
        run_count,
        focus_count,
        last_run_time,
        focus_time_ms,
        is_suspicious,
    }))
}

#[cfg(test)]
mod tests {
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
            "mimikatz", "psexec", "procdump", "beacon", "cobalt", "rubeus",
            "seatbelt", "sharpup", "sharphound", "bloodhound", "lazagne",
            "safetykatz", "winpeas", "linpeas", "chisel", "plink", "ncat",
            "netcat", "nc.exe", "nc64.exe", "whoami", "certutil",
        ];
        for tool in &tools {
            assert!(
                classify_userassist(&format!("C:\\Temp\\{}.exe", tool)),
                "Expected {} to be suspicious",
                tool
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
            "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe",
            "rundll32.exe", "msiexec.exe", "certutil.exe", "bitsadmin.exe",
        ];
        for bin in &lolbins {
            assert!(
                classify_userassist(&format!("C:\\Windows\\System32\\{}", bin)),
                "Expected LOLBin {} to be suspicious",
                bin
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
        assert!(!classify_userassist(
            "C:\\Windows\\System32\\cmd.exe"
        ));
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

    // ── read_key_name unit tests ─────────────────────────────────────

    #[test]
    fn read_key_name_too_short() {
        let data = vec![0u8; NK_NAME_OFFSET]; // exactly NK_NAME_OFFSET bytes, no room for data
        assert_eq!(read_key_name(&data), "");
    }

    #[test]
    fn read_key_name_valid() {
        let mut data = vec![0u8; 0x60];
        let name = b"Software";
        // NK_NAME_LENGTH_OFFSET = 0x48, NK_NAME_OFFSET = 0x4C
        data[NK_NAME_LENGTH_OFFSET] = name.len() as u8;
        data[NK_NAME_LENGTH_OFFSET + 1] = 0;
        data[NK_NAME_OFFSET..NK_NAME_OFFSET + name.len()].copy_from_slice(name);
        assert_eq!(read_key_name(&data), "Software");
    }

    #[test]
    fn read_key_name_overflow_returns_empty() {
        let mut data = vec![0u8; 0x60];
        // Set name length to something larger than buffer allows
        data[NK_NAME_LENGTH_OFFSET] = 0xFF;
        data[NK_NAME_LENGTH_OFFSET + 1] = 0xFF;
        assert_eq!(read_key_name(&data), "");
    }

    // ── read_value_name unit tests ────────────────────────────────────

    #[test]
    fn read_value_name_too_short() {
        let data = vec![0u8; VK_NAME_OFFSET]; // exactly VK_NAME_OFFSET, no room
        assert_eq!(read_value_name(&data), "");
    }

    #[test]
    fn read_value_name_valid() {
        let mut data = vec![0u8; 0x30];
        let name = b"url1";
        // VK_NAME_LENGTH_OFFSET = 0x02, VK_NAME_OFFSET = 0x14
        data[VK_NAME_LENGTH_OFFSET] = name.len() as u8;
        data[VK_NAME_LENGTH_OFFSET + 1] = 0;
        data[VK_NAME_OFFSET..VK_NAME_OFFSET + name.len()].copy_from_slice(name);
        assert_eq!(read_value_name(&data), "url1");
    }

    #[test]
    fn read_value_name_overflow_returns_empty() {
        let mut data = vec![0u8; 0x30];
        data[VK_NAME_LENGTH_OFFSET] = 0xFF;
        data[VK_NAME_LENGTH_OFFSET + 1] = 0xFF;
        assert_eq!(read_value_name(&data), "");
    }

    // ── cell_address unit test ────────────────────────────────────────

    #[test]
    fn cell_address_calculation() {
        // cell_address(hive_addr, cell_index) = hive_addr + HBIN_START + cell_index
        let hive_addr: u64 = 0x1000_0000;
        let cell_index: u32 = 0x100;
        let expected = hive_addr + HBIN_START_OFFSET + cell_index as u64;
        assert_eq!(cell_address(hive_addr, cell_index), expected);
    }

    #[test]
    fn cell_address_zero_index() {
        let hive_addr: u64 = 0x2000_0000;
        let expected = hive_addr + HBIN_START_OFFSET;
        assert_eq!(cell_address(hive_addr, 0), expected);
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

    // ── Constants ─────────────────────────────────────────────────────

    #[test]
    fn userassist_constants_sane() {
        assert_eq!(HBASE_BLOCK_ROOT_CELL_OFFSET, 0x24);
        assert_eq!(HBIN_START_OFFSET, 0x1000);
        assert_eq!(NK_SIGNATURE, 0x6B6E);
        assert_eq!(VK_SIGNATURE, 0x6B76);
        assert_eq!(USERASSIST_DATA_SIZE, 72);
        assert_eq!(MAX_USERASSIST_ENTRIES, 4096);
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
}
