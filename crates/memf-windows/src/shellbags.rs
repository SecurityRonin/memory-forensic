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
    let _sig_offset = match reader
        .symbols()
        .field_offset("_CM_KEY_NODE", "Signature")
    {
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
}
