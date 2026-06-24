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

/// Parse a BagMRU value's shell-item bytes → (folder name, access FILETIME,
/// creation FILETIME). Each value holds a single SHITEMID; delegate decoding to
/// the `shellitem` crate (volume / directory / GUID classes + the `0xbeef0004`
/// long-name + timestamp extension), which handles the real on-disk layout the
/// previous hand-rolled scanner mis-read.
fn parse_shell_item(data: &[u8]) -> (String, u64, u64) {
    let Some(item) = shellitem::parse_idlist(data).into_iter().next() else {
        return (String::new(), 0, 0);
    };
    let name = item.display_name().unwrap_or_default().to_owned();
    (
        name,
        unix_to_filetime(item.accessed),
        unix_to_filetime(item.created),
    )
}

/// Convert a Unix-epoch-seconds timestamp (as `shellitem` yields) to a Windows
/// FILETIME (100 ns ticks since 1601), matching `ShellbagEntry`'s FILETIME fields.
/// `None` (no extension block / absent timestamp) and out-of-range values → 0.
fn unix_to_filetime(secs: Option<i64>) -> u64 {
    secs.and_then(|s| u64::try_from(s + 11_644_473_600).ok())
        .map_or(0, |t| t.saturating_mul(10_000_000))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a real 0x31 directory shell item — the on-disk SHITEMID layout
    /// `shellitem` decodes: cb, class 0x31, unknown, size, modified, attrs
    /// (DIRECTORY), then the ASCII NUL-terminated name (no extension block).
    fn dir_item(name: &[u8]) -> Vec<u8> {
        let mut body = vec![0x31u8, 0x00];
        body.extend_from_slice(&0u32.to_le_bytes()); // file size
        body.extend_from_slice(&0u32.to_le_bytes()); // modified (FAT date/time)
        body.extend_from_slice(&0x10u16.to_le_bytes()); // FILE_ATTRIBUTE_DIRECTORY
        body.extend_from_slice(name);
        let cb = (2 + body.len()) as u16;
        let mut item = cb.to_le_bytes().to_vec();
        item.extend_from_slice(&body);
        item
    }
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
        // Real 0x31 directory shell item (the layout shellitem decodes).
        let item = dir_item(b"Desktop\0");

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
        let desktop = dir_item(b"Desktop\0");
        let downloads = dir_item(b"Downloads\0");

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
