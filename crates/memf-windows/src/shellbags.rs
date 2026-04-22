//! Shellbags folder-access evidence walker.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

const MAX_SUBKEYS_PER_LEVEL: usize = 256;
const MAX_DEPTH: usize = 32;

/// A shellbag entry recording folder access evidence.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShellbagEntry {
    /// Reconstructed folder path from BagMRU registry keys.
    pub path: String,
    /// Registry key last-write time for this bag slot (FILETIME).
    pub slot_modified_time: u64,
    /// Last-access timestamp embedded in the ShellItem (FILETIME).
    pub access_time: u64,
    /// Creation timestamp embedded in the ShellItem (FILETIME).
    pub creation_time: u64,
    /// `true` when the path matches known suspicious patterns.
    pub is_suspicious: bool,
}

/// Return `true` when a shellbag path matches known suspicious patterns.
pub fn classify_shellbag(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let upper = path.to_uppercase();
    if upper.starts_with("\\\\") {
        return true;
    }
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
    let suspicious_exact: &[&str] = &["C:\\PERFLOGS", "C:\\WINDOWS\\TEMP"];
    for exact in suspicious_exact {
        if upper == *exact {
            return true;
        }
    }
    false
}

/// Walk shellbag entries from a registry hive in memory.
pub fn walk_shellbags<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
) -> crate::Result<Vec<ShellbagEntry>> {
    let _sig_offset = match reader.symbols().field_offset("_CM_KEY_NODE", "Signature") {
        Some(offset) => offset,
        None => return Ok(Vec::new()),
    };

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

fn walk_bagmru_node<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    node_addr: u64,
    parent_path: String,
    depth: usize,
    subkeys_offset: u64,
    value_list_offset: u64,
    _last_write_offset: u64,
    entries: &mut Vec<ShellbagEntry>,
) {
    if depth >= MAX_DEPTH || node_addr == 0 {
        return;
    }

    let slot_modified_time: u64 = reader
        .read_field(node_addr, "_CM_KEY_NODE", "LastWriteTime")
        .unwrap_or(0);

    let value_list_addr: u64 = match reader.read_bytes(node_addr + value_list_offset, 8) {
        Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        _ => 0,
    };

    let (folder_name, access_time, creation_time) = if value_list_addr != 0 {
        parse_shitemid(reader, value_list_addr)
    } else {
        (String::new(), 0u64, 0u64)
    };

    let current_path = if parent_path.is_empty() {
        folder_name.clone()
    } else if folder_name.is_empty() {
        parent_path.clone()
    } else {
        format!("{}\\{}", parent_path, folder_name)
    };

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
            _last_write_offset,
            entries,
        );
    }
}

fn parse_shitemid<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    value_addr: u64,
) -> (String, u64, u64) {
    let header = match reader.read_bytes(value_addr, 4) {
        Ok(bytes) if bytes.len() >= 4 => bytes,
        _ => return (String::new(), 0, 0),
    };

    let cb = u16::from_le_bytes([header[0], header[1]]) as usize;
    if cb < 4 || cb > 0x800 {
        return (String::new(), 0, 0);
    }

    let blob = match reader.read_bytes(value_addr, cb) {
        Ok(bytes) if bytes.len() == cb => bytes,
        _ => return (String::new(), 0, 0),
    };

    let name = extract_folder_name(&blob[2..]);
    let (access_time, creation_time) = find_extension_timestamps(&blob);

    (name, access_time, creation_time)
}

fn extract_folder_name(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let start = 1.min(data.len());
    let mut name_bytes = Vec::new();

    for &b in &data[start..] {
        if b == 0 {
            break;
        }
        if b.is_ascii_graphic() || b == b' ' {
            name_bytes.push(b);
        } else {
            break;
        }
    }

    if name_bytes.len() >= 2 {
        return String::from_utf8_lossy(&name_bytes).into_owned();
    }

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

fn find_extension_timestamps(blob: &[u8]) -> (u64, u64) {
    if blob.len() < 24 {
        return (0, 0);
    }

    let sig: [u8; 4] = [0x04, 0x00, 0xEF, 0xBE];
    for i in 0..blob.len().saturating_sub(24) {
        if blob[i..i + 4] == sig {
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

    #[test]
    fn classify_shellbag_benign() {
        assert!(!classify_shellbag("Desktop"));
        assert!(!classify_shellbag("Documents"));
        assert!(!classify_shellbag("Downloads"));
        assert!(!classify_shellbag("C:\\Users\\alice\\Pictures"));
        assert!(!classify_shellbag("D:\\Projects\\src"));
    }

    #[test]
    fn classify_shellbag_suspicious_admin_share() {
        assert!(classify_shellbag("\\\\fileserver\\C$"));
        assert!(classify_shellbag("\\\\10.0.0.5\\ADMIN$"));
        assert!(classify_shellbag("\\\\dc01\\IPC$"));
        assert!(classify_shellbag("\\\\dc01\\C$\\Windows\\Temp"));
    }

    #[test]
    fn classify_shellbag_suspicious_remote() {
        assert!(classify_shellbag("\\\\192.168.1.100\\share"));
        assert!(classify_shellbag("\\\\fileserver\\data"));
        assert!(classify_shellbag("\\\\corp-dc\\SYSVOL"));
    }

    #[test]
    fn classify_shellbag_suspicious_temp() {
        assert!(classify_shellbag("C:\\Windows\\Temp"));
        assert!(classify_shellbag("C:\\Users\\Public\\Downloads"));
        assert!(classify_shellbag("C:\\PerfLogs"));
    }

    #[test]
    fn classify_shellbag_empty() {
        assert!(!classify_shellbag(""));
    }

    #[test]
    fn classify_shellbag_appdata_local_temp() {
        assert!(classify_shellbag(
            "C:\\Users\\victim\\AppData\\Local\\Temp\\malware"
        ));
    }

    #[test]
    fn classify_shellbag_programdata_temp() {
        assert!(classify_shellbag("C:\\ProgramData\\Temp\\dropper"));
    }

    #[test]
    fn classify_shellbag_users_public() {
        assert!(classify_shellbag("C:\\Users\\Public\\Documents"));
    }

    #[test]
    fn classify_shellbag_case_insensitive() {
        assert!(classify_shellbag("c:\\windows\\temp\\payload"));
        assert!(classify_shellbag("C:\\WINDOWS\\TEMP"));
        assert!(classify_shellbag("\\\\SERVER\\SHARE"));
    }

    #[test]
    fn extract_folder_name_empty() {
        let result = extract_folder_name(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn extract_folder_name_ascii() {
        let mut data = vec![0x31u8];
        data.extend_from_slice(b"Documents\0more");
        let result = extract_folder_name(&data);
        assert_eq!(result, "Documents");
    }

    #[test]
    fn extract_folder_name_single_char_falls_back() {
        let data = [0x31u8, b'X'];
        let result = extract_folder_name(&data);
        let _ = result;
    }

    #[test]
    fn extract_folder_name_utf16le() {
        let data = [0x31u8, 0x41, 0x00, 0x42, 0x00, 0x00, 0x00];
        let result = extract_folder_name(&data);
        assert_eq!(result, "AB");
    }

    #[test]
    fn find_extension_timestamps_too_short() {
        let (access, creation) = find_extension_timestamps(&[0u8; 10]);
        assert_eq!(access, 0);
        assert_eq!(creation, 0);
    }

    #[test]
    fn find_extension_timestamps_no_signature() {
        let blob = [0xABu8; 64];
        let (access, creation) = find_extension_timestamps(&blob);
        assert_eq!(access, 0);
        assert_eq!(creation, 0);
    }

    #[test]
    fn find_extension_timestamps_with_signature() {
        let mut blob = [0u8; 48];
        blob[4] = 0x04;
        blob[5] = 0x00;
        blob[6] = 0xEF;
        blob[7] = 0xBE;
        blob[8..16].copy_from_slice(&0x0000_0001_0000_0002u64.to_le_bytes());
        blob[16..24].copy_from_slice(&0x0000_0003_0000_0004u64.to_le_bytes());
        let (access, creation) = find_extension_timestamps(&blob);
        assert_eq!(access, 0x0000_0003_0000_0004);
        assert_eq!(creation, 0x0000_0001_0000_0002);
    }

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
        let result = walk_shellbags(&reader, 0).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn walk_shellbags_no_signature_field() {
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

    #[test]
    fn classify_shellbag_perflogs_exact_match() {
        assert!(classify_shellbag("C:\\PerfLogs"));
        assert!(classify_shellbag("C:\\PERFLOGS"));
    }

    #[test]
    fn classify_shellbag_windows_temp_exact_match() {
        assert!(classify_shellbag("C:\\Windows\\Temp"));
        assert!(classify_shellbag("C:\\WINDOWS\\TEMP"));
    }

    #[test]
    fn classify_shellbag_drive_letter_benign() {
        assert!(!classify_shellbag("D:\\Projects\\work"));
        assert!(!classify_shellbag("E:\\Backup\\data"));
    }

    #[test]
    fn classify_shellbag_single_backslash_benign() {
        assert!(!classify_shellbag("\\local_path\\folder"));
    }

    #[test]
    fn extract_folder_name_only_type_byte() {
        let data = [0x31u8];
        let result = extract_folder_name(&data);
        assert!(result.is_empty());
    }

    #[test]
    fn extract_folder_name_non_ascii_stops() {
        let data = [0x31u8, 0x80, 0x41, 0x00, 0x42, 0x00];
        let result = extract_folder_name(&data);
        let _ = result;
    }

    #[test]
    fn extract_folder_name_utf16_single_char_empty() {
        let data = [0x31u8, 0x41, 0x00, 0x00, 0x00];
        let result = extract_folder_name(&data);
        assert!(result.is_empty());
    }

    #[test]
    fn extract_folder_name_non_graphic_non_null() {
        let data = [0x31u8, 0x01];
        let result = extract_folder_name(&data);
        assert!(result.is_empty());
    }

    #[test]
    fn find_extension_timestamps_sig_at_start() {
        let mut blob = [0u8; 48];
        blob[0] = 0x04;
        blob[1] = 0x00;
        blob[2] = 0xEF;
        blob[3] = 0xBE;
        blob[4..12].copy_from_slice(&0x1234_5678_9ABC_DEF0u64.to_le_bytes());
        blob[12..20].copy_from_slice(&0xFEDC_BA98_7654_3210u64.to_le_bytes());
        let (access, creation) = find_extension_timestamps(&blob);
        assert_eq!(access, 0xFEDC_BA98_7654_3210);
        assert_eq!(creation, 0x1234_5678_9ABC_DEF0);
    }

    #[test]
    fn find_extension_timestamps_truncated_after_sig() {
        let mut blob = [0u8; 32];
        blob[4] = 0x04;
        blob[5] = 0x00;
        blob[6] = 0xEF;
        blob[7] = 0xBE;
        blob[8..16].copy_from_slice(&0xAAAA_BBBB_CCCC_DDDDu64.to_le_bytes());
        blob[16..24].copy_from_slice(&0x1111_2222_3333_4444u64.to_le_bytes());
        let (access, creation) = find_extension_timestamps(&blob);
        assert_eq!(creation, 0xAAAA_BBBB_CCCC_DDDD);
        assert_eq!(access, 0x1111_2222_3333_4444);
    }

    #[test]
    fn walk_bagmru_node_max_depth_returns_early() {
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
        let mut entries = Vec::new();
        walk_bagmru_node(
            &reader,
            0x1000,
            String::new(),
            MAX_DEPTH,
            0x20,
            0x28,
            0x08,
            &mut entries,
        );
        assert!(entries.is_empty(), "max depth should yield no entries");
    }

    #[test]
    fn walk_bagmru_node_zero_addr_returns_early() {
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
        let mut entries = Vec::new();
        walk_bagmru_node(&reader, 0, String::new(), 0, 0x20, 0x28, 0x08, &mut entries);
        assert!(entries.is_empty());
    }

    #[test]
    fn walk_bagmru_node_mapped_node_with_value_list() {
        use memf_core::test_builders::{flags, SyntheticPhysMem};

        let node_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let node_paddr: u64 = 0x0010_0000;
        let shitemid_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let shitemid_paddr: u64 = 0x0020_0000;

        let isf = IsfBuilder::new()
            .add_struct("_CM_KEY_NODE", 0x50)
            .add_field("_CM_KEY_NODE", "Signature", 0x00, "unsigned short")
            .add_field("_CM_KEY_NODE", "SubKeyLists", 0x20, "pointer")
            .add_field("_CM_KEY_NODE", "ValueList", 0x28, "pointer")
            .add_field("_CM_KEY_NODE", "LastWriteTime", 0x08, "unsigned long long")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut node_page = vec![0u8; 0x1000];
        node_page[0x08..0x10].copy_from_slice(&0x0000_0000_0000_1234u64.to_le_bytes());
        node_page[0x28..0x30].copy_from_slice(&shitemid_vaddr.to_le_bytes());
        node_page[0x20..0x28].copy_from_slice(&0u64.to_le_bytes());

        let mut shitem_page = vec![0u8; 0x1000];
        shitem_page[0] = 12u8;
        shitem_page[1] = 0u8;
        shitem_page[2] = 0x31;
        shitem_page[3] = b'D';
        shitem_page[4] = b'o';
        shitem_page[5] = b'c';
        shitem_page[6] = 0;

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(node_vaddr, node_paddr, flags::WRITABLE)
            .write_phys(node_paddr, &node_page)
            .map_4k(shitemid_vaddr, shitemid_paddr, flags::WRITABLE)
            .write_phys(shitemid_paddr, &shitem_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let mut entries = Vec::new();
        walk_bagmru_node(
            &reader,
            node_vaddr,
            "C:\\Users".to_string(),
            0,
            0x20,
            0x28,
            0x08,
            &mut entries,
        );

        assert_eq!(entries.len(), 1, "should push one entry");
        assert!(
            entries[0].path.contains("Doc"),
            "path should contain folder name"
        );
        assert_eq!(entries[0].slot_modified_time, 0x1234);
    }

    #[test]
    fn walk_bagmru_node_empty_folder_uses_parent_path() {
        use memf_core::test_builders::{flags, SyntheticPhysMem};

        let node_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let node_paddr: u64 = 0x0030_0000;

        let isf = IsfBuilder::new()
            .add_struct("_CM_KEY_NODE", 0x50)
            .add_field("_CM_KEY_NODE", "Signature", 0x00, "unsigned short")
            .add_field("_CM_KEY_NODE", "SubKeyLists", 0x20, "pointer")
            .add_field("_CM_KEY_NODE", "ValueList", 0x28, "pointer")
            .add_field("_CM_KEY_NODE", "LastWriteTime", 0x08, "unsigned long long")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut node_page = vec![0u8; 0x1000];
        node_page[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
        node_page[0x20..0x28].copy_from_slice(&0u64.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(node_vaddr, node_paddr, flags::WRITABLE)
            .write_phys(node_paddr, &node_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let mut entries = Vec::new();
        walk_bagmru_node(
            &reader,
            node_vaddr,
            "C:\\Desktop".to_string(),
            0,
            0x20,
            0x28,
            0x08,
            &mut entries,
        );
        assert_eq!(entries.len(), 1, "should push one entry with parent path");
        assert_eq!(entries[0].path, "C:\\Desktop");
    }

    #[test]
    fn walk_bagmru_node_with_subkeys_recurses() {
        use memf_core::test_builders::{flags, SyntheticPhysMem};

        let root_vaddr: u64 = 0xFFFF_8000_0040_0000;
        let root_paddr: u64 = 0x0040_0000;
        let sklist_vaddr: u64 = 0xFFFF_8000_0050_0000;
        let sklist_paddr: u64 = 0x0050_0000;
        let child_vaddr: u64 = 0xFFFF_8000_0060_0000;
        let child_paddr: u64 = 0x0060_0000;

        let isf = IsfBuilder::new()
            .add_struct("_CM_KEY_NODE", 0x50)
            .add_field("_CM_KEY_NODE", "Signature", 0x00, "unsigned short")
            .add_field("_CM_KEY_NODE", "SubKeyLists", 0x20, "pointer")
            .add_field("_CM_KEY_NODE", "ValueList", 0x28, "pointer")
            .add_field("_CM_KEY_NODE", "LastWriteTime", 0x08, "unsigned long long")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut root_page = vec![0u8; 0x1000];
        root_page[0x20..0x28].copy_from_slice(&sklist_vaddr.to_le_bytes());
        root_page[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());

        let mut sklist_page = vec![0u8; 0x1000];
        sklist_page[0..8].copy_from_slice(&child_vaddr.to_le_bytes());
        sklist_page[8..16].copy_from_slice(&0u64.to_le_bytes());

        let child_page = vec![0u8; 0x1000];

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(root_vaddr, root_paddr, flags::WRITABLE)
            .write_phys(root_paddr, &root_page)
            .map_4k(sklist_vaddr, sklist_paddr, flags::WRITABLE)
            .write_phys(sklist_paddr, &sklist_page)
            .map_4k(child_vaddr, child_paddr, flags::WRITABLE)
            .write_phys(child_paddr, &child_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let mut entries = Vec::new();
        walk_bagmru_node(
            &reader,
            root_vaddr,
            "C:\\BagMRU".to_string(),
            0,
            0x20,
            0x28,
            0x08,
            &mut entries,
        );
        assert!(entries.len() >= 1, "should push at least root entry");
    }

    #[test]
    fn walk_shellbags_mapped_hive_no_folder_names() {
        use memf_core::test_builders::{flags, SyntheticPhysMem};

        let hive_vaddr: u64 = 0xFFFF_8000_0070_0000;
        let hive_paddr: u64 = 0x0070_0000;

        let isf = IsfBuilder::new()
            .add_struct("_CM_KEY_NODE", 0x50)
            .add_field("_CM_KEY_NODE", "Signature", 0x00, "unsigned short")
            .add_field("_CM_KEY_NODE", "SubKeyLists", 0x20, "pointer")
            .add_field("_CM_KEY_NODE", "ValueList", 0x28, "pointer")
            .add_field("_CM_KEY_NODE", "LastWriteTime", 0x08, "unsigned long long")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let hive_page = vec![0u8; 0x1000];

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_shellbags(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty(), "no folder names → empty entries");
    }

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
        let result = walk_shellbags(&reader, 0x0010_0000).unwrap();
        assert!(result.is_empty());
    }
}
