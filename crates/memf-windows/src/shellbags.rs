//! Shellbags folder-access evidence walker.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::registry;

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

/// `Shell\BagMRU` lives under one of two paths: `Local Settings\Software\...`
/// in UsrClass.dat, or `Software\...` in NTUSER.DAT.
const BAGMRU_PATHS: &[&[&str]] = &[
    &[
        "Local Settings",
        "Software",
        "Microsoft",
        "Windows",
        "Shell",
        "BagMRU",
    ],
    &["Software", "Microsoft", "Windows", "Shell", "BagMRU"],
];

/// Walk shellbag folder-access evidence from a registry hive in memory.
///
/// Navigates the HMAP cell map to `Shell\BagMRU` and recurses the BagMRU tree:
/// each numbered subkey "N" is a folder whose name comes from the parent's value
/// "N" (a shell item), and whose registry LastWriteTime is the subkey's own.
pub fn walk_shellbags<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
) -> crate::Result<Vec<ShellbagEntry>> {
    if hive_addr == 0 {
        return Ok(Vec::new());
    }
    let root = registry::resolve_root_cell(reader, hive_addr);
    if root == 0 {
        return Ok(Vec::new());
    }
    let Some(bagmru) = find_bagmru(reader, hive_addr, root) else {
        return Ok(Vec::new());
    };

    let last_write_off = reader
        .symbols()
        .field_offset("_CM_KEY_NODE", "LastWriteTime")
        .unwrap_or(0x04);

    let mut entries = Vec::new();
    walk_bagmru_node(
        reader,
        hive_addr,
        bagmru,
        "",
        0,
        last_write_off,
        &mut entries,
    );
    Ok(entries)
}

/// Navigate `root` down to the first `Shell\BagMRU` key that exists (UsrClass.dat
/// or NTUSER.DAT layout), returning its cell VA.
fn find_bagmru<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    root: u64,
) -> Option<u64> {
    for path in BAGMRU_PATHS {
        let mut cur = root;
        for &component in *path {
            cur = registry::find_subkey_by_name(reader, hive_addr, cur, component);
            if cur == 0 {
                break;
            }
        }
        if cur != 0 {
            return Some(cur);
        }
    }
    None
}

fn walk_bagmru_node<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    node_addr: u64,
    parent_path: &str,
    depth: usize,
    last_write_off: u64,
    entries: &mut Vec<ShellbagEntry>,
) {
    if depth >= MAX_DEPTH || node_addr == 0 {
        return;
    }

    // Each child's folder name is carried by the parent's value of the same name
    // (the shell item); MRUListEx / NodeSlot values have no matching subkey.
    let values = registry::list_values(reader, hive_addr, node_addr);

    for (name, child_addr) in registry::list_subkeys(reader, hive_addr, node_addr)
        .into_iter()
        .take(MAX_SUBKEYS_PER_LEVEL)
    {
        let (folder_name, access_time, creation_time) = values
            .iter()
            .find(|v| v.name == name)
            .map_or((String::new(), 0, 0), |v| parse_shell_item(&v.data));

        let current_path = if parent_path.is_empty() {
            folder_name.clone()
        } else if folder_name.is_empty() {
            parent_path.to_string()
        } else {
            format!("{parent_path}\\{folder_name}")
        };

        if !current_path.is_empty() {
            // The bag slot's registry LastWriteTime is this subkey's own.
            let slot_modified_time = reader
                .read_bytes(child_addr + last_write_off, 8)
                .ok()
                .filter(|b| b.len() == 8)
                .map_or(0, |b| {
                    u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]))
                });
            entries.push(ShellbagEntry {
                path: current_path.clone(),
                slot_modified_time,
                access_time,
                creation_time,
                is_suspicious: classify_shellbag(&current_path),
            });
        }

        walk_bagmru_node(
            reader,
            hive_addr,
            child_addr,
            &current_path,
            depth + 1,
            last_write_off,
            entries,
        );
    }
}

/// Parse a BagMRU value's shell-item bytes → (folder name, access, creation).
/// The value data is a SHITEMID: `cb`(2) size then the item body; the folder name
/// and the BEEF extension-block timestamps live within.
fn parse_shell_item(data: &[u8]) -> (String, u64, u64) {
    if data.len() < 4 {
        return (String::new(), 0, 0);
    }
    let cb = u16::from_le_bytes([data[0], data[1]]) as usize;
    if !(4..=0x800).contains(&cb) {
        return (String::new(), 0, 0);
    }
    let blob = &data[..cb.min(data.len())];
    let name = extract_folder_name(&blob[2..]);
    let (access_time, creation_time) = find_extension_timestamps(blob);
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
        walk_bagmru_node(&reader, 0x1000, 0x2000, "", MAX_DEPTH, 0x08, &mut entries);
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
        walk_bagmru_node(&reader, 0, 0, "", 0, 0x08, &mut entries);
        assert!(entries.is_empty());
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

    /// RED (rewrite): a real cell-map UsrClass.dat laid out as
    /// Local Settings\Software\Microsoft\Windows\Shell\BagMRU → subkey "0" with a
    /// value "0" whose shell item names folder "Desktop". The current walker
    /// treats hive_addr as a key node and reads SubKeyLists/ValueList as raw VA
    /// pointers (never reaching BagMRU) → recovers nothing. Asserts the path is
    /// reconstructed, so it FAILS until walk_shellbags uses the HMAP walker.
    #[test]
    fn walk_shellbags_hmap_recovers_bagmru_path() {
        use crate::test_hive::CellHive;
        // Shell item value data: cb(2)=11, type(1)=0x31, "Desktop\0".
        let mut item = vec![0x0Bu8, 0x00, 0x31];
        item.extend_from_slice(b"Desktop\0");

        let mut h = CellHive::new(0x0050_0000);
        h.nk(0x020, b"Root", 1, 0x0A0, 0);
        h.lf(0x0A0, &[0x120]);
        h.nk(0x120, b"Local Settings", 1, 0x1A0, 0);
        h.lf(0x1A0, &[0x220]);
        h.nk(0x220, b"Software", 1, 0x2A0, 0);
        h.lf(0x2A0, &[0x320]);
        h.nk(0x320, b"Microsoft", 1, 0x3A0, 0);
        h.lf(0x3A0, &[0x420]);
        h.nk(0x420, b"Windows", 1, 0x4A0, 0);
        h.lf(0x4A0, &[0x520]);
        h.nk(0x520, b"Shell", 1, 0x5A0, 0);
        h.lf(0x5A0, &[0x620]);
        // BagMRU: 1 subkey ("0"), 1 value ("0" = the Desktop shell item).
        h.nk(0x620, b"BagMRU", 1, 0x6A0, 0);
        h.values(0x620, 1, 0x720);
        h.lf(0x6A0, &[0x800]);
        h.value_list(0x720, &[0x760]);
        h.vk(0x760, b"0", 3, item.len() as u32, 0x880);
        h.nk(0x800, b"0", 0, 0, 0); // child node (leaf)
        h.data(0x880, &item);

        let reader = h.reader();
        let bags = walk_shellbags(&reader, h.hhive_va).unwrap();

        assert!(
            bags.iter().any(|b| b.path == "Desktop"),
            "expected a BagMRU entry with path 'Desktop', got {:?}",
            bags.iter().map(|b| &b.path).collect::<Vec<_>>()
        );
    }

    /// HMAP recursion: BagMRU\0 (Desktop) → \0 (Downloads). Each level's folder
    /// name comes from the parent node's value of the same name; the walker must
    /// descend and join the path. Covers multi-level recursion + path joining.
    #[test]
    fn walk_shellbags_hmap_recurses_nested_path() {
        use crate::test_hive::CellHive;
        let mut desktop = vec![0x0Bu8, 0x00, 0x31];
        desktop.extend_from_slice(b"Desktop\0");
        let mut downloads = vec![0x0Du8, 0x00, 0x31];
        downloads.extend_from_slice(b"Downloads\0");

        let mut h = CellHive::new(0x0050_0000);
        h.nk(0x020, b"Root", 1, 0x0A0, 0);
        h.lf(0x0A0, &[0x120]);
        h.nk(0x120, b"Local Settings", 1, 0x1A0, 0);
        h.lf(0x1A0, &[0x220]);
        h.nk(0x220, b"Software", 1, 0x2A0, 0);
        h.lf(0x2A0, &[0x320]);
        h.nk(0x320, b"Microsoft", 1, 0x3A0, 0);
        h.lf(0x3A0, &[0x420]);
        h.nk(0x420, b"Windows", 1, 0x4A0, 0);
        h.lf(0x4A0, &[0x520]);
        h.nk(0x520, b"Shell", 1, 0x5A0, 0);
        h.lf(0x5A0, &[0x620]);
        // BagMRU → subkey 0 (Desktop), value 0 (Desktop shell item).
        h.nk(0x620, b"BagMRU", 1, 0x6A0, 0);
        h.values(0x620, 1, 0x720);
        h.lf(0x6A0, &[0x800]);
        h.value_list(0x720, &[0x760]);
        h.vk(0x760, b"0", 3, desktop.len() as u32, 0x880);
        h.data(0x880, &desktop);
        // Desktop node → subkey 0 (Downloads), value 0 (Downloads shell item).
        h.nk(0x800, b"0", 1, 0x8A0, 0);
        h.values(0x800, 1, 0x920);
        h.lf(0x8A0, &[0xA00]);
        h.value_list(0x920, &[0x960]);
        h.vk(0x960, b"0", 3, downloads.len() as u32, 0xA80);
        h.data(0xA80, &downloads);
        h.nk(0xA00, b"0", 0, 0, 0); // Downloads leaf

        let reader = h.reader();
        let bags = walk_shellbags(&reader, h.hhive_va).unwrap();
        let paths: Vec<&String> = bags.iter().map(|b| &b.path).collect();
        assert!(paths.iter().any(|p| *p == "Desktop"), "got {paths:?}");
        assert!(
            paths.iter().any(|p| *p == "Desktop\\Downloads"),
            "expected nested path Desktop\\Downloads, got {paths:?}"
        );
    }
}
