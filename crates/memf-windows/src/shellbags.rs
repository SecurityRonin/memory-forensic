//! Shellbags folder-access evidence walker.
//!
//! Windows stores folder browsing history in NTUSER.DAT and UsrClass.dat
//! registry hives under `Software\Microsoft\Windows\Shell\BagMRU` and
//! `Shell\Bags`. Each entry contains a folder path and access timestamps.
//! Shellbags persist even after folder deletion — valuable for proving
//! lateral movement during incident response.
//!
//! The BagMRU tree uses `_CM_KEY_NODE` structures. Each numbered subkey
//! (0, 1, 2...) contains a default value holding a SHITEMID blob that
//! encodes the folder name and optional extension blocks with timestamps.
//! Walking the tree recursively builds the full folder path.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// Maximum number of BagMRU subkeys to walk per level (safety limit).
const MAX_SUBKEYS_PER_LEVEL: usize = 256;

/// Maximum recursion depth for the BagMRU tree.
const MAX_DEPTH: usize = 32;

/// Information about a single shellbag entry recovered from memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShellbagEntry {
    /// Reconstructed folder path from the BagMRU tree.
    pub path: String,
    /// Registry key last-write time (Windows FILETIME, 100ns ticks since 1601-01-01).
    pub slot_modified_time: u64,
    /// Access time extracted from the SHITEMID extension block.
    pub access_time: u64,
    /// Creation time extracted from the SHITEMID extension block.
    pub creation_time: u64,
    /// Whether this path is suspicious (admin shares, temp dirs, UNC paths).
    pub is_suspicious: bool,
}

/// Classify a shellbag folder path as suspicious.
///
/// Returns `true` if the path matches patterns commonly associated with
/// lateral movement or attacker activity:
/// - Admin shares (`\\C$`, `\\ADMIN$`, `\\IPC$`)
/// - UNC paths (`\\\\server\\share`) indicating remote folder access
/// - Temp/staging directories commonly used for tool drops
/// - Uncommon system paths rarely browsed by legitimate users
pub fn classify_shellbag(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }

    let upper = path.to_uppercase();

    // UNC paths (\\server\share) — any remote folder access is suspicious.
    // This also catches admin shares since they are UNC paths.
    if upper.starts_with("\\\\") {
        return true;
    }

    // Temp/staging directories commonly used for tool drops.
    let suspicious_path_fragments: &[&str] = &[
        "\\WINDOWS\\TEMP",
        "\\USERS\\PUBLIC",
        "\\PERFLOGS",
        "\\PROGRAMDATA\\TEMP",
        "\\APPDATA\\LOCAL\\TEMP",
    ];

    for fragment in suspicious_path_fragments {
        if upper.contains(fragment) {
            return true;
        }
    }

    // Exact matches for top-level suspicious directories.
    let suspicious_exact: &[&str] = &["C:\\PERFLOGS", "C:\\WINDOWS\\TEMP"];

    for exact in suspicious_exact {
        if upper == *exact {
            return true;
        }
    }

    false
}

/// Walk the BagMRU tree in a registry hive to recover shellbag entries.
///
/// Looks up the `_CM_KEY_NODE` symbol and walks the BagMRU tree starting
/// from `hive_addr`. Each numbered subkey's default value is parsed as a
/// SHITEMID blob to extract the folder name. Extension blocks (signature
/// `0xBEEF0004`) provide access and creation timestamps.
///
/// Returns `Ok(Vec::new())` if required symbols are not available in the
/// profile (graceful degradation).
pub fn walk_shellbags<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
) -> crate::Result<Vec<ShellbagEntry>> {
    // Verify the _CM_KEY_NODE struct is available and we have a valid hive address.
    let _sig_offset = match reader.symbols().field_offset("_CM_KEY_NODE", "Signature") {
        Some(offset) => offset,
        None => return Ok(Vec::new()),
    };

    // Need the BagMRU root symbol or a valid hive address to start walking.
    if hive_addr == 0 {
        return Ok(Vec::new());
    }

    let subkeys_offset = reader
        .symbols()
        .field_offset("_CM_KEY_NODE", "SubKeyLists")
        .unwrap_or(0x20);

    let value_list_offset = reader
        .symbols()
        .field_offset("_CM_KEY_NODE", "ValueList")
        .unwrap_or(0x28);

    let last_write_offset = reader
        .symbols()
        .field_offset("_CM_KEY_NODE", "LastWriteTime")
        .unwrap_or(0x08);

    let mut entries = Vec::new();

    // Recursively walk the BagMRU tree.
    walk_bagmru_node(
        reader,
        hive_addr,
        String::new(),
        0,
        subkeys_offset,
        value_list_offset,
        last_write_offset,
        &mut entries,
    );

    Ok(entries)
}

/// Recursively walk a BagMRU key node, building up the folder path.
fn walk_bagmru_node<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    node_addr: u64,
    parent_path: String,
    depth: usize,
    subkeys_offset: u64,
    value_list_offset: u64,
    last_write_offset: u64,
    entries: &mut Vec<ShellbagEntry>,
) {
    if depth >= MAX_DEPTH || node_addr == 0 {
        return;
    }

    // Read the last-write time for this key node.
    let slot_modified_time: u64 = reader
        .read_field(node_addr, "_CM_KEY_NODE", "LastWriteTime")
        .unwrap_or(0);

    // Read the default value (SHITEMID blob) for this node.
    let value_list_addr: u64 = match reader.read_bytes(node_addr + value_list_offset, 8) {
        Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        _ => 0,
    };

    // Parse SHITEMID blob from the default value to extract folder name and timestamps.
    let (folder_name, access_time, creation_time) = if value_list_addr != 0 {
        parse_shitemid(reader, value_list_addr)
    } else {
        (String::new(), 0u64, 0u64)
    };

    // Build the full path for this node.
    let current_path = if parent_path.is_empty() {
        folder_name.clone()
    } else if folder_name.is_empty() {
        parent_path.clone()
    } else {
        format!("{}\\{}", parent_path, folder_name)
    };

    // Record this entry if we have a non-empty path.
    if !current_path.is_empty() {
        let is_suspicious = classify_shellbag(&current_path);
        entries.push(ShellbagEntry {
            path: current_path.clone(),
            slot_modified_time,
            access_time,
            creation_time,
            is_suspicious,
        });
    }

    // Walk numbered subkeys (0, 1, 2, ...).
    let subkeys_list_addr: u64 = match reader.read_bytes(node_addr + subkeys_offset, 8) {
        Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        _ => return,
    };

    if subkeys_list_addr == 0 {
        return;
    }

    for i in 0..MAX_SUBKEYS_PER_LEVEL {
        let subkey_ptr_addr = subkeys_list_addr + (i as u64) * 8;
        let subkey_addr: u64 = match reader.read_bytes(subkey_ptr_addr, 8) {
            Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            _ => break,
        };

        if subkey_addr == 0 {
            break;
        }

        walk_bagmru_node(
            reader,
            subkey_addr,
            current_path.clone(),
            depth + 1,
            subkeys_offset,
            value_list_offset,
            last_write_offset,
            entries,
        );
    }
}

/// Parse a SHITEMID blob to extract folder name and timestamps.
///
/// SHITEMID format:
/// - `[0..2]`: cb (size in bytes, u16 LE)
/// - `[2]`: type byte
/// - `[3..]`: type-specific data containing the folder name
///
/// Extension block signature `0xBEEF0004` contains access/creation timestamps.
fn parse_shitemid<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    value_addr: u64,
) -> (String, u64, u64) {
    // Read the SHITEMID header: 2 bytes size + 1 byte type.
    let header = match reader.read_bytes(value_addr, 4) {
        Ok(bytes) if bytes.len() >= 4 => bytes,
        _ => return (String::new(), 0, 0),
    };

    let cb = u16::from_le_bytes([header[0], header[1]]) as usize;
    if cb < 4 || cb > 0x800 {
        return (String::new(), 0, 0);
    }

    // Read the full SHITEMID blob.
    let blob = match reader.read_bytes(value_addr, cb) {
        Ok(bytes) if bytes.len() == cb => bytes,
        _ => return (String::new(), 0, 0),
    };

    // Extract folder name: scan for printable ASCII starting at offset 3.
    let name = extract_folder_name(&blob[2..]);

    // Scan for BEEF0004 extension block to get timestamps.
    let (access_time, creation_time) = find_extension_timestamps(&blob);

    (name, access_time, creation_time)
}

/// Extract a folder name from a SHITEMID data region.
///
/// Scans for a run of printable ASCII or UTF-16LE characters.
fn extract_folder_name(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    // Skip type byte, try to find a null-terminated ASCII string.
    let start = 1.min(data.len());
    let mut name_bytes = Vec::new();

    for &b in &data[start..] {
        if b == 0 {
            break;
        }
        if b.is_ascii_graphic() || b == b' ' {
            name_bytes.push(b);
        } else {
            // Non-ASCII: might be UTF-16, stop ASCII scan.
            break;
        }
    }

    if name_bytes.len() >= 2 {
        return String::from_utf8_lossy(&name_bytes).into_owned();
    }

    // Fallback: try UTF-16LE decoding.
    if data.len() >= 4 {
        let mut utf16_units = Vec::new();
        let scan_start = start;
        let mut i = scan_start;
        while i + 1 < data.len() {
            let unit = u16::from_le_bytes([data[i], data[i + 1]]);
            if unit == 0 {
                break;
            }
            utf16_units.push(unit);
            i += 2;
        }
        if !utf16_units.is_empty() {
            let decoded = String::from_utf16_lossy(&utf16_units);
            if decoded.len() >= 2 {
                return decoded;
            }
        }
    }

    String::new()
}

/// Scan a SHITEMID blob for the BEEF0004 extension block and extract timestamps.
///
/// Extension block layout:
/// - `[0..2]`: extension size (u16 LE)
/// - `[2..4]`: version
/// - `[4..8]`: signature (0x04 0x00 0xEF 0xBE = 0xBEEF0004 LE)
/// - `[8..16]`: creation time (FILETIME, u64 LE)
/// - `[16..24]`: access time (FILETIME, u64 LE)
fn find_extension_timestamps(blob: &[u8]) -> (u64, u64) {
    if blob.len() < 24 {
        return (0, 0);
    }

    // Scan for the BEEF0004 signature.
    let sig: [u8; 4] = [0x04, 0x00, 0xEF, 0xBE];
    for i in 0..blob.len().saturating_sub(24) {
        if blob[i..i + 4] == sig {
            // Found extension block signature at offset i.
            // Timestamps follow at i+4 (creation) and i+12 (access).
            let creation = if i + 12 <= blob.len() {
                u64::from_le_bytes(blob[i + 4..i + 12].try_into().unwrap_or([0; 8]))
            } else {
                0
            };
            let access = if i + 20 <= blob.len() {
                u64::from_le_bytes(blob[i + 12..i + 20].try_into().unwrap_or([0; 8]))
            } else {
                0
            };
            return (access, creation);
        }
    }

    (0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    #[allow(unused_imports)]
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// No BagMRU symbol → empty Vec (graceful degradation).
    #[test]
    fn walk_shellbags_no_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("_CM_KEY_NODE", 0x50)
            .add_field("_CM_KEY_NODE", "Signature", 0x00, "unsigned short")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_shellbags(&reader, 0).unwrap();
        assert!(result.is_empty());
    }

    /// Normal folder paths like "Desktop" and "Documents" are not suspicious.
    #[test]
    fn classify_shellbag_benign() {
        assert!(!classify_shellbag("Desktop"));
        assert!(!classify_shellbag("Documents"));
        assert!(!classify_shellbag("Downloads"));
        assert!(!classify_shellbag("C:\\Users\\alice\\Pictures"));
        assert!(!classify_shellbag("D:\\Projects\\src"));
    }

    /// Admin share paths (\\C$, \\ADMIN$, \\IPC$) are suspicious — lateral movement indicator.
    #[test]
    fn classify_shellbag_suspicious_admin_share() {
        assert!(classify_shellbag("\\\\fileserver\\C$"));
        assert!(classify_shellbag("\\\\10.0.0.5\\ADMIN$"));
        assert!(classify_shellbag("\\\\dc01\\IPC$"));
        assert!(classify_shellbag("\\\\dc01\\C$\\Windows\\Temp"));
    }

    /// UNC paths (\\\\server\\share) indicate remote folder access — lateral movement.
    #[test]
    fn classify_shellbag_suspicious_remote() {
        assert!(classify_shellbag("\\\\192.168.1.100\\share"));
        assert!(classify_shellbag("\\\\fileserver\\data"));
        assert!(classify_shellbag("\\\\corp-dc\\SYSVOL"));
    }

    /// Temp/staging directories are suspicious.
    #[test]
    fn classify_shellbag_suspicious_temp() {
        assert!(classify_shellbag("C:\\Windows\\Temp"));
        assert!(classify_shellbag("C:\\Users\\Public\\Downloads"));
        assert!(classify_shellbag("C:\\PerfLogs"));
    }

    /// Empty path is not suspicious.
    #[test]
    fn classify_shellbag_empty() {
        assert!(!classify_shellbag(""));
    }

    /// AppData Local Temp path is suspicious.
    #[test]
    fn classify_shellbag_appdata_local_temp() {
        assert!(classify_shellbag(
            "C:\\Users\\victim\\AppData\\Local\\Temp\\malware"
        ));
    }

    /// ProgramData Temp path is suspicious.
    #[test]
    fn classify_shellbag_programdata_temp() {
        assert!(classify_shellbag("C:\\ProgramData\\Temp\\dropper"));
    }

    /// Users Public directory is suspicious.
    #[test]
    fn classify_shellbag_users_public() {
        assert!(classify_shellbag("C:\\Users\\Public\\Documents"));
    }

    /// Case-insensitive detection works (mixed case paths).
    #[test]
    fn classify_shellbag_case_insensitive() {
        assert!(classify_shellbag("c:\\windows\\temp\\payload"));
        assert!(classify_shellbag("C:\\WINDOWS\\TEMP"));
        assert!(classify_shellbag("\\\\SERVER\\SHARE"));
    }

    /// extract_folder_name with empty data returns empty string.
    #[test]
    fn extract_folder_name_empty() {
        let result = extract_folder_name(&[]);
        assert!(result.is_empty());
    }

    /// extract_folder_name with short ASCII string (>=2 bytes) returns that string.
    #[test]
    fn extract_folder_name_ascii() {
        // Type byte (0x31) + ASCII "Documents\0"
        let mut data = vec![0x31u8]; // type byte
        data.extend_from_slice(b"Documents\0more");
        let result = extract_folder_name(&data);
        assert_eq!(result, "Documents");
    }

    /// extract_folder_name with a single-char ASCII result (< 2 bytes) tries UTF-16.
    #[test]
    fn extract_folder_name_single_char_falls_back() {
        // Type byte + single printable ASCII byte — too short for ASCII path,
        // but the UTF-16 fallback is attempted.
        let data = [0x31u8, b'X']; // type byte + one char
        let result = extract_folder_name(&data);
        // Either empty or just "X" — we just verify it doesn't panic.
        let _ = result;
    }

    /// extract_folder_name with valid UTF-16LE "AB\0" returns "AB".
    #[test]
    fn extract_folder_name_utf16le() {
        // Type byte (0x31), then UTF-16LE for "AB\0":
        // 'A' = 0x41 0x00, 'B' = 0x42 0x00, '\0' = 0x00 0x00
        let data = [0x31u8, 0x41, 0x00, 0x42, 0x00, 0x00, 0x00];
        let result = extract_folder_name(&data);
        assert_eq!(result, "AB");
    }

    /// find_extension_timestamps with too-short blob returns (0, 0).
    #[test]
    fn find_extension_timestamps_too_short() {
        let (access, creation) = find_extension_timestamps(&[0u8; 10]);
        assert_eq!(access, 0);
        assert_eq!(creation, 0);
    }

    /// find_extension_timestamps with no BEEF0004 signature returns (0, 0).
    #[test]
    fn find_extension_timestamps_no_signature() {
        let blob = [0xABu8; 64];
        let (access, creation) = find_extension_timestamps(&blob);
        assert_eq!(access, 0);
        assert_eq!(creation, 0);
    }

    /// find_extension_timestamps correctly parses a crafted BEEF0004 block.
    #[test]
    fn find_extension_timestamps_with_signature() {
        // Craft a blob containing the BEEF0004 signature at offset 4.
        let mut blob = [0u8; 48];
        // BEEF0004 signature = [0x04, 0x00, 0xEF, 0xBE] at offset 4.
        blob[4] = 0x04;
        blob[5] = 0x00;
        blob[6] = 0xEF;
        blob[7] = 0xBE;
        // creation time at blob[8..16] = 0x0000_0001_0000_0002 LE
        blob[8..16].copy_from_slice(&0x0000_0001_0000_0002u64.to_le_bytes());
        // access time at blob[16..24] = 0x0000_0003_0000_0004 LE
        blob[16..24].copy_from_slice(&0x0000_0003_0000_0004u64.to_le_bytes());

        let (access, creation) = find_extension_timestamps(&blob);
        assert_eq!(access, 0x0000_0003_0000_0004);
        assert_eq!(creation, 0x0000_0001_0000_0002);
    }

    /// ShellbagEntry serializes to JSON.
    #[test]
    fn shellbag_entry_serializes() {
        let entry = ShellbagEntry {
            path: "C:\\Users\\Public".to_string(),
            slot_modified_time: 0,
            access_time: 0,
            creation_time: 0,
            is_suspicious: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("C:\\\\Users\\\\Public"));
        assert!(json.contains("is_suspicious"));
    }

    /// Walker returns empty when hive_addr is 0 even with Signature field present.
    #[test]
    fn walk_shellbags_zero_hive_with_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("_CM_KEY_NODE", 0x50)
            .add_field("_CM_KEY_NODE", "Signature", 0x00, "unsigned short")
            .add_field("_CM_KEY_NODE", "SubKeyLists", 0x20, "pointer")
            .add_field("_CM_KEY_NODE", "ValueList", 0x28, "pointer")
            .add_field("_CM_KEY_NODE", "LastWriteTime", 0x08, "unsigned long long")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // hive_addr = 0 → should return empty immediately.
        let result = walk_shellbags(&reader, 0).unwrap();
        assert!(result.is_empty());
    }

    /// Walk with no Signature field in ISF → graceful empty return.
    #[test]
    fn walk_shellbags_no_signature_field() {
        // _CM_KEY_NODE exists but has no Signature field.
        let isf = IsfBuilder::new()
            .add_struct("_CM_KEY_NODE", 0x50)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_shellbags(&reader, 0xFFFF_8000_0000_1234).unwrap();
        assert!(result.is_empty());
    }

    // ── Additional coverage: classify_shellbag edge cases ────────────

    /// Exact match for "C:\\PERFLOGS" (uppercase) is suspicious.
    #[test]
    fn classify_shellbag_perflogs_exact_match() {
        assert!(classify_shellbag("C:\\PerfLogs"));
        assert!(classify_shellbag("C:\\PERFLOGS"));
    }

    /// Exact match for "C:\\WINDOWS\\TEMP" is suspicious.
    #[test]
    fn classify_shellbag_windows_temp_exact_match() {
        assert!(classify_shellbag("C:\\Windows\\Temp"));
        assert!(classify_shellbag("C:\\WINDOWS\\TEMP"));
    }

    /// Non-suspicious path with colon (drive letter) not UNC is benign.
    #[test]
    fn classify_shellbag_drive_letter_benign() {
        assert!(!classify_shellbag("D:\\Projects\\work"));
        assert!(!classify_shellbag("E:\\Backup\\data"));
    }

    /// Path with single backslash (not UNC) is benign.
    #[test]
    fn classify_shellbag_single_backslash_benign() {
        assert!(!classify_shellbag("\\local_path\\folder"));
    }

    // ── Additional coverage: extract_folder_name branches ─────────────

    /// extract_folder_name with only a type byte (len=1) returns empty (too short for scan).
    #[test]
    fn extract_folder_name_only_type_byte() {
        let data = [0x31u8]; // only type byte, nothing else
        let result = extract_folder_name(&data);
        // start = 1.min(1) = 1, loop over data[1..] is empty → name_bytes empty
        // data.len() = 1 < 4 → no UTF-16 fallback
        assert!(result.is_empty());
    }

    /// extract_folder_name with non-ASCII first byte stops immediately.
    #[test]
    fn extract_folder_name_non_ascii_stops() {
        // type byte 0x31, then 0x80 (non-ASCII graphic) → stops immediately
        let data = [0x31u8, 0x80, 0x41, 0x00, 0x42, 0x00];
        let result = extract_folder_name(&data);
        // ASCII scan yields 0 bytes (0x80 is non-ASCII), tries UTF-16LE from offset 1
        // UTF-16 at offset 1: [0x80, 0x41] = 0x4180 (non-null), [0x00, 0x42] = 0x4200,
        // both non-zero, yields 2 chars → decoded.len() >= 2 → returns that.
        // We just verify no panic.
        let _ = result;
    }

    /// extract_folder_name with UTF-16LE single char (decoded.len() < 2) → empty.
    #[test]
    fn extract_folder_name_utf16_single_char_empty() {
        // type byte, then UTF-16LE 'A' = [0x41, 0x00], null terminator [0x00, 0x00]
        // ASCII scan: 0x41 is graphic → pushed, then 0x00 → breaks; name_bytes = [0x41], len=1 < 2
        // UTF-16 fallback: from offset 1: [0x41,0x00]=0x41 (non-zero pushed), [0x00,0x00]=0 → break
        // utf16_units = [0x41], decoded = "A", len=1 < 2 → returns empty
        let data = [0x31u8, 0x41, 0x00, 0x00, 0x00];
        let result = extract_folder_name(&data);
        // The ASCII scan gets 0x41='A' and stops at 0x00, name_bytes=['A'], len=1<2
        // The UTF-16 fallback gets "A" (len=1<2) → empty string
        assert!(result.is_empty());
    }

    /// extract_folder_name: data has only type byte + non-graphic non-null byte.
    #[test]
    fn extract_folder_name_non_graphic_non_null() {
        // type=0x31, then 0x01 (non-ASCII graphic, non-null) → ASCII scan stops,
        // data.len()=2 < 4 → no UTF-16 fallback → empty
        let data = [0x31u8, 0x01];
        let result = extract_folder_name(&data);
        assert!(result.is_empty());
    }

    // ── Additional coverage: find_extension_timestamps branches ───────

    /// find_extension_timestamps: blob more than 24 bytes with sig near start.
    #[test]
    fn find_extension_timestamps_sig_at_start() {
        // Need blob.len() > 24 so the loop runs (loop is 0..blob.len()-24).
        let mut blob = [0u8; 48];
        // sig at offset 0 (i=0, i+4=4 matches sig check)
        blob[0] = 0x04;
        blob[1] = 0x00;
        blob[2] = 0xEF;
        blob[3] = 0xBE;
        // creation at blob[4..12] (i+4..i+12)
        blob[4..12].copy_from_slice(&0x1234_5678_9ABC_DEF0u64.to_le_bytes());
        // access at blob[12..20] (i+12..i+20)
        blob[12..20].copy_from_slice(&0xFEDC_BA98_7654_3210u64.to_le_bytes());
        let (access, creation) = find_extension_timestamps(&blob);
        assert_eq!(access, 0xFEDC_BA98_7654_3210);
        assert_eq!(creation, 0x1234_5678_9ABC_DEF0);
    }

    /// find_extension_timestamps: sig at an offset with truncated access field.
    /// Access field requires i+20 <= blob.len(). If blob is just large enough that
    /// the loop runs (blob.len() > 24) but i+20 > blob.len() → access = 0.
    #[test]
    fn find_extension_timestamps_truncated_after_sig() {
        // blob of 25 bytes: loop runs for i in 0..1 (only i=0).
        // At i=0: sig at [0..4]; creation at [4..12]; access at [12..20] where i+20=20 <=25 ok.
        // So we need blob to be 28 bytes with sig at offset 4:
        // i=4, i+12=16 <=28 ok, i+20=24 <=28 ok. Doesn't test truncated.
        // For truncated access: place sig so i+20 > blob.len.
        // blob=26 bytes, sig at i=0: i+20=20 <=26 ok. No truncation.
        // To hit truncated creation (i+12 > blob.len): blob=25, sig at i=0:
        //   i+4=4 → sig found; i+12=12 <=25 → creation OK; i+20=20 <=25 → access OK.
        // Actually the truncated branches are unreachable via the loop condition
        // (loop runs only when i < blob.len()-24, so i+24 <= blob.len() always).
        // This test documents that and verifies no panic with a valid-looking blob.
        let mut blob = [0u8; 32];
        // Sig at offset 4 (i=4, 4 < 32-24=8 → loop runs)
        blob[4] = 0x04;
        blob[5] = 0x00;
        blob[6] = 0xEF;
        blob[7] = 0xBE;
        // creation at i+4..i+12 = 8..16
        blob[8..16].copy_from_slice(&0xAAAA_BBBB_CCCC_DDDDu64.to_le_bytes());
        // access at i+12..i+20 = 16..24
        blob[16..24].copy_from_slice(&0x1111_2222_3333_4444u64.to_le_bytes());
        let (access, creation) = find_extension_timestamps(&blob);
        assert_eq!(creation, 0xAAAA_BBBB_CCCC_DDDD);
        assert_eq!(access, 0x1111_2222_3333_4444);
    }

    // ── Additional coverage: walk_shellbags with mapped memory ────────

    /// walk_shellbags with non-zero hive_addr but all reads fail → empty (graceful).
    #[test]
    fn walk_shellbags_unmapped_hive_empty() {
        let isf = IsfBuilder::new()
            .add_struct("_CM_KEY_NODE", 0x50)
            .add_field("_CM_KEY_NODE", "Signature", 0x00, "unsigned short")
            .add_field("_CM_KEY_NODE", "SubKeyLists", 0x20, "pointer")
            .add_field("_CM_KEY_NODE", "ValueList", 0x28, "pointer")
            .add_field("_CM_KEY_NODE", "LastWriteTime", 0x08, "unsigned long long")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // Non-zero hive_addr but nothing mapped — reads fail → walk_bagmru_node
        // fails to read value_list_addr → folder_name empty → current_path empty
        // → no entry pushed; subkeys_list_addr = 0 → return immediately.
        let result = walk_shellbags(&reader, 0x0010_0000).unwrap();
        assert!(result.is_empty());
    }
}
