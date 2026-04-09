//! Windows kernel symbolic link object scanner.
//!
//! Enumerates symbolic link objects in the Windows Object Manager namespace
//! by walking from `ObpRootDirectoryObject` and filtering for objects whose
//! type name is "SymbolicLink".  Symlinks map DOS device names
//! (`\DosDevices\C:`) to NT device paths (`\Device\HarddiskVolume1`).
//! Rootkits create rogue symlinks to redirect device access, making this
//! a useful forensic artifact for drive mapping analysis and anti-forensics
//! detection.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::object_directory::walk_directory;
use crate::unicode::read_unicode_string;
use crate::Result;

/// Maximum recursion depth when walking nested object directories.
const MAX_DIR_DEPTH: usize = 8;

/// Information about a kernel symbolic link object.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SymlinkInfo {
    /// Name of the symbolic link (e.g. "C:" under `\DosDevices`).
    pub name: String,
    /// Target path the symlink resolves to (e.g. `\Device\HarddiskVolume1`).
    pub target: String,
    /// Creation timestamp (Windows FILETIME, 100-ns ticks since 1601-01-01).
    pub create_time: u64,
    /// Whether this symlink exhibits suspicious characteristics.
    pub is_suspicious: bool,
}

/// Standard volume-style target prefixes considered benign for `\DosDevices` entries.
const STANDARD_DOSDEVICE_TARGETS: &[&str] = &[
    "\\Device\\HarddiskVolume",
    "\\Device\\LanmanRedirector",
    "\\Device\\Mup",
    "\\Device\\Floppy",
    "\\Device\\CdRom",
    "\\Device\\NamedPipe",
    "\\Device\\Mailslot",
    "\\Device\\Null",
    "\\Device\\Mup",
    "\\??\\",
];

/// Target prefixes that are inherently suspicious for any symlink.
const SUSPICIOUS_TARGETS: &[&str] = &[
    "\\Device\\Tcp",
    "\\Device\\RawIp",
    "\\Device\\Ip",
    "\\Device\\Udp",
    "\\Device\\RawIp6",
];

/// Classify whether a symbolic link is suspicious.
///
/// A symlink is considered suspicious if:
/// - Its target points to an unusual network device (`\Device\Tcp`, `\Device\RawIp`)
/// - Its name appears under `\DosDevices` but points to a non-standard target
///   (not a volume, pipe, mailslot, etc.)
/// - Its target is empty (corrupted or intentionally cleared)
pub fn classify_symlink(name: &str, target: &str) -> bool {
    // Empty target is always suspicious.
    if target.is_empty() {
        return true;
    }

    // Check for inherently suspicious target devices.
    for prefix in SUSPICIOUS_TARGETS {
        if target.starts_with(prefix) {
            return true;
        }
    }

    // For DosDevices entries, check if the target is a standard mapping.
    if name.contains("DosDevices") || name.contains("GLOBALROOT") {
        let is_standard = STANDARD_DOSDEVICE_TARGETS
            .iter()
            .any(|prefix| target.starts_with(prefix));
        if !is_standard {
            return true;
        }
    }

    false
}

/// Walk the kernel object namespace and return all symbolic link objects.
///
/// Resolves `ObpRootDirectoryObject` to find the root `_OBJECT_DIRECTORY`,
/// then recursively enumerates entries.  For each object whose type name
/// (via `_OBJECT_HEADER.TypeIndex` -> `ObTypeIndexTable`) equals
/// "SymbolicLink", reads the `_OBJECT_SYMBOLIC_LINK` body to extract the
/// link target and creation time.
pub fn walk_symlinks<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<SymlinkInfo>> {
    // Resolve the root object directory pointer.
    let root_dir_ptr_addr = match reader.symbols().symbol_address("ObpRootDirectoryObject") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // Read the root directory pointer value.
    let root_dir_addr = match reader.read_bytes(root_dir_ptr_addr, 8) {
        Ok(b) if b.len() == 8 => u64::from_le_bytes(b[..8].try_into().unwrap()),
        _ => return Ok(Vec::new()),
    };
    if root_dir_addr == 0 {
        return Ok(Vec::new());
    }

    // Resolve _OBJECT_HEADER offsets.
    let body_offset = reader
        .symbols()
        .field_offset("_OBJECT_HEADER", "Body")
        .unwrap_or(0x30);
    let type_index_offset = reader
        .symbols()
        .field_offset("_OBJECT_HEADER", "TypeIndex")
        .unwrap_or(0x18);
    let info_mask_offset = reader
        .symbols()
        .field_offset("_OBJECT_HEADER", "InfoMask")
        .unwrap_or(0x1a);

    // _OBJECT_HEADER_NAME_INFO size (InfoMask bit 0x2 indicates its presence).
    let name_info_size = reader
        .symbols()
        .struct_size("_OBJECT_HEADER_NAME_INFO")
        .unwrap_or(0x20);

    // Resolve ObTypeIndexTable symbol for type lookup.
    let ob_type_table = reader.symbols().symbol_address("ObTypeIndexTable");

    // _OBJECT_SYMBOLIC_LINK body field offsets.
    let link_target_offset = reader
        .symbols()
        .field_offset("_OBJECT_SYMBOLIC_LINK", "LinkTarget")
        .unwrap_or(0x00);
    let create_time_offset = reader
        .symbols()
        .field_offset("_OBJECT_SYMBOLIC_LINK", "CreationTime")
        .unwrap_or(0x10);

    // Walk the directory tree recursively (bounded by MAX_DIR_DEPTH).
    let mut symlinks = Vec::new();
    walk_dir_recursive(
        reader,
        root_dir_addr,
        body_offset,
        type_index_offset,
        info_mask_offset,
        name_info_size,
        ob_type_table,
        link_target_offset,
        create_time_offset,
        0,
        MAX_DIR_DEPTH,
        &mut symlinks,
    );

    Ok(symlinks)
}

/// Recursively walk an `_OBJECT_DIRECTORY` and collect symbolic link objects.
#[allow(clippy::too_many_arguments)]
fn walk_dir_recursive<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    dir_addr: u64,
    body_offset: u64,
    type_index_offset: u64,
    info_mask_offset: u64,
    name_info_size: u64,
    ob_type_table: Option<u64>,
    link_target_offset: u64,
    create_time_offset: u64,
    depth: usize,
    max_depth: usize,
    symlinks: &mut Vec<SymlinkInfo>,
) {
    if depth > max_depth {
        return;
    }

    let entries = match walk_directory(reader, dir_addr) {
        Ok(e) => e,
        Err(_) => return,
    };

    for (name, body_addr) in entries {
        // Determine the type name by reading _OBJECT_HEADER.TypeIndex.
        let header_addr = body_addr.wrapping_sub(body_offset);
        let type_index = match reader.read_bytes(header_addr + type_index_offset, 1) {
            Ok(b) if !b.is_empty() => b[0],
            _ => continue,
        };

        let type_name = resolve_type_name(reader, ob_type_table, type_index, body_offset);

        if type_name.as_deref() == Some("Directory") {
            // Recurse into sub-directory.
            walk_dir_recursive(
                reader,
                body_addr,
                body_offset,
                type_index_offset,
                info_mask_offset,
                name_info_size,
                ob_type_table,
                link_target_offset,
                create_time_offset,
                depth + 1,
                max_depth,
                symlinks,
            );
        } else if type_name.as_deref() == Some("SymbolicLink") {
            // Read link target (UNICODE_STRING at body_addr + link_target_offset).
            let target =
                read_unicode_string(reader, body_addr + link_target_offset).unwrap_or_default();

            // Read creation time (u64 at body_addr + create_time_offset).
            let create_time = match reader.read_bytes(body_addr + create_time_offset, 8) {
                Ok(b) if b.len() == 8 => u64::from_le_bytes(b[..8].try_into().unwrap()),
                _ => 0,
            };

            let is_suspicious = classify_symlink(&name, &target);

            symlinks.push(SymlinkInfo {
                name,
                target,
                create_time,
                is_suspicious,
            });
        }
    }
}

/// Resolve a type name from the `ObTypeIndexTable` given a type index byte.
///
/// Each entry in `ObTypeIndexTable` is a pointer to an `_OBJECT_TYPE`.
/// The type name is a `_UNICODE_STRING` at a fixed offset within `_OBJECT_TYPE`.
fn resolve_type_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ob_type_table: Option<u64>,
    type_index: u8,
    body_offset: u64,
) -> Option<String> {
    let table = ob_type_table?;

    // Each slot is an 8-byte pointer.
    let slot_addr = table + u64::from(type_index) * 8;
    let type_obj_ptr = match reader.read_bytes(slot_addr, 8) {
        Ok(b) if b.len() == 8 => u64::from_le_bytes(b[..8].try_into().unwrap()),
        _ => return None,
    };
    if type_obj_ptr == 0 {
        return None;
    }

    // _OBJECT_TYPE.Name is a _UNICODE_STRING.
    let name_offset = reader
        .symbols()
        .field_offset("_OBJECT_TYPE", "Name")
        .unwrap_or(0x10);

    read_unicode_string(reader, type_obj_ptr + name_offset).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────
    // classify_symlink unit tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn classify_empty_target_is_suspicious() {
        assert!(classify_symlink("C:", ""));
        assert!(classify_symlink("\\DosDevices\\X:", ""));
        assert!(classify_symlink("SomeLink", ""));
    }

    #[test]
    fn classify_tcp_target_is_suspicious() {
        assert!(classify_symlink(
            "SomeLink",
            "\\Device\\Tcp"
        ));
        assert!(classify_symlink(
            "\\DosDevices\\Backdoor",
            "\\Device\\Tcp\\SomeEndpoint"
        ));
    }

    #[test]
    fn classify_rawip_target_is_suspicious() {
        assert!(classify_symlink(
            "AnyName",
            "\\Device\\RawIp"
        ));
        assert!(classify_symlink(
            "AnyName",
            "\\Device\\RawIp6\\Something"
        ));
    }

    #[test]
    fn classify_standard_volume_is_benign() {
        assert!(!classify_symlink(
            "C:",
            "\\Device\\HarddiskVolume1"
        ));
        assert!(!classify_symlink(
            "D:",
            "\\Device\\HarddiskVolume3"
        ));
    }

    #[test]
    fn classify_dosdevices_nonstandard_target_is_suspicious() {
        // DosDevices entry pointing to something unusual
        assert!(classify_symlink(
            "\\DosDevices\\Z:",
            "\\Device\\SomeRogueDriver"
        ));
        assert!(classify_symlink(
            "\\DosDevices\\PIPE",
            "\\SomeWeirdPath"
        ));
    }

    #[test]
    fn classify_dosdevices_standard_targets_are_benign() {
        assert!(!classify_symlink(
            "\\DosDevices\\PIPE",
            "\\Device\\NamedPipe"
        ));
        assert!(!classify_symlink(
            "\\DosDevices\\MAILSLOT",
            "\\Device\\Mailslot"
        ));
        assert!(!classify_symlink(
            "\\DosDevices\\A:",
            "\\Device\\Floppy0"
        ));
        assert!(!classify_symlink(
            "\\DosDevices\\E:",
            "\\Device\\CdRom0"
        ));
    }

    #[test]
    fn classify_non_dosdevice_normal_target_is_benign() {
        // A symlink outside DosDevices with a non-suspicious target
        assert!(!classify_symlink(
            "SomeOtherLink",
            "\\Device\\HarddiskVolume2"
        ));
        assert!(!classify_symlink(
            "CustomLink",
            "\\Device\\SomeCustomDriver"
        ));
    }

    #[test]
    fn classify_ip_and_udp_targets_are_suspicious() {
        assert!(classify_symlink("Link", "\\Device\\Ip"));
        assert!(classify_symlink("Link", "\\Device\\Udp"));
    }

    // ─────────────────────────────────────────────────────────────────────
    // walk_symlinks integration tests (will fail until GREEN phase)
    // ─────────────────────────────────────────────────────────────────────

    use memf_core::object_reader::ObjectReader as ObjReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ISF preset symbol addresses
    const OBP_ROOT_DIR_OBJ_VADDR: u64 = 0xFFFFF805_5A4A0000;
    const OB_TYPE_INDEX_TABLE_VADDR: u64 = 0xFFFFF805_5A490000;

    // _OBJECT_HEADER offsets (from preset)
    const OBJ_HEADER_TYPE_INDEX: u64 = 0x18;
    const OBJ_HEADER_INFO_MASK: u64 = 0x1a;
    const OBJ_HEADER_BODY: u64 = 0x30;

    // _OBJECT_HEADER_NAME_INFO size (from preset)
    const NAME_INFO_SIZE: u64 = 0x20;
    // _OBJECT_HEADER_NAME_INFO.Name offset
    const NAME_INFO_NAME: u64 = 0x10;

    // _OBJECT_TYPE.Name offset
    const OBJ_TYPE_NAME: u64 = 0x10;

    // _OBJECT_SYMBOLIC_LINK offsets (matching the preset we add)
    const SYMLINK_LINK_TARGET: u64 = 0x00;
    const SYMLINK_CREATE_TIME: u64 = 0x10;

    fn make_test_reader(ptb: PageTableBuilder) -> ObjReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjReader::new(vas, Box::new(resolver))
    }

    fn write_unicode_string(
        ptb: PageTableBuilder,
        unistr_paddr: u64,
        str_vaddr: u64,
        str_paddr: u64,
        text: &str,
    ) -> PageTableBuilder {
        let utf16: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let len = utf16.len() as u16;
        ptb.write_phys(unistr_paddr, &len.to_le_bytes())
            .write_phys(unistr_paddr + 2, &len.to_le_bytes())
            .write_phys_u64(unistr_paddr + 8, str_vaddr)
            .write_phys(str_paddr, &utf16)
    }

    fn write_object_type(
        ptb: PageTableBuilder,
        type_vaddr: u64,
        type_paddr: u64,
        str_vaddr: u64,
        str_paddr: u64,
        type_name: &str,
    ) -> PageTableBuilder {
        let ptb = ptb.map_4k(type_vaddr, type_paddr, flags::WRITABLE);
        write_unicode_string(ptb, type_paddr + OBJ_TYPE_NAME, str_vaddr, str_paddr, type_name)
    }

    fn write_named_object(
        ptb: PageTableBuilder,
        base_vaddr: u64,
        base_paddr: u64,
        str_vaddr: u64,
        str_paddr: u64,
        name: &str,
        type_index: u8,
    ) -> (u64, PageTableBuilder) {
        let ni_paddr = base_paddr;
        let ptb =
            write_unicode_string(ptb, ni_paddr + NAME_INFO_NAME, str_vaddr, str_paddr, name);
        let hdr_paddr = base_paddr + NAME_INFO_SIZE;
        let ptb = ptb
            .write_phys(hdr_paddr + OBJ_HEADER_INFO_MASK, &[0x02])
            .write_phys(hdr_paddr + OBJ_HEADER_TYPE_INDEX, &[type_index]);
        let body_vaddr = base_vaddr + NAME_INFO_SIZE + OBJ_HEADER_BODY;
        (body_vaddr, ptb)
    }

    fn write_dir_entry(
        ptb: PageTableBuilder,
        entry_paddr: u64,
        chain_link: u64,
        object_body: u64,
    ) -> PageTableBuilder {
        ptb.write_phys_u64(entry_paddr, chain_link)
            .write_phys_u64(entry_paddr + 8, object_body)
    }

    fn set_bucket(
        ptb: PageTableBuilder,
        dir_paddr: u64,
        bucket_idx: usize,
        entry_vaddr: u64,
    ) -> PageTableBuilder {
        ptb.write_phys_u64(dir_paddr + (bucket_idx as u64) * 8, entry_vaddr)
    }

    /// Build an empty root directory pointed to by `ObpRootDirectoryObject`.
    fn build_empty_root() -> PageTableBuilder {
        let root_dir_ptr_paddr: u64 = 0x0010_0000;
        let root_dir_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let root_dir_paddr: u64 = 0x0020_0000;

        PageTableBuilder::new()
            .map_4k(OBP_ROOT_DIR_OBJ_VADDR, root_dir_ptr_paddr, flags::WRITABLE)
            .write_phys_u64(root_dir_ptr_paddr, root_dir_vaddr)
            .map_4k(root_dir_vaddr, root_dir_paddr, flags::WRITABLE)
    }

    /// Build a root directory with a `\DosDevices` subdirectory containing
    /// one symbolic link with the given name, target, and create_time.
    fn build_single_symlink(
        link_name: &str,
        link_target: &str,
        create_time: u64,
    ) -> PageTableBuilder {
        let root_dir_ptr_paddr: u64 = 0x0010_0000;
        let root_dir_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let root_dir_paddr: u64 = 0x0020_0000;

        let dosdev_obj_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let dosdev_obj_paddr: u64 = 0x0030_0000;
        let root_entry_vaddr: u64 = 0xFFFF_8000_0020_0C00;
        let root_entry_paddr: u64 = 0x0030_0C00;

        let symlink_obj_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let symlink_obj_paddr: u64 = 0x0040_0000;
        let subdir_entry_vaddr: u64 = 0xFFFF_8000_0030_0C00;
        let subdir_entry_paddr: u64 = 0x0040_0C00;

        let symlink_type_vaddr: u64 = 0xFFFF_8000_0050_0000;
        let symlink_type_paddr: u64 = 0x0060_0000;
        let dir_type_vaddr: u64 = 0xFFFF_8000_0050_1000;
        let dir_type_paddr: u64 = 0x0061_0000;
        let ob_table_paddr: u64 = 0x0070_0000;

        // Separate page for symlink target string
        let target_str_vaddr: u64 = 0xFFFF_8000_0040_0000;
        let target_str_paddr: u64 = 0x0050_0000;

        let symlink_type_index: u8 = 20;
        let dir_type_index: u8 = 3;

        let mut ptb = PageTableBuilder::new()
            .map_4k(OBP_ROOT_DIR_OBJ_VADDR, root_dir_ptr_paddr, flags::WRITABLE)
            .write_phys_u64(root_dir_ptr_paddr, root_dir_vaddr)
            .map_4k(root_dir_vaddr, root_dir_paddr, flags::WRITABLE)
            .map_4k(dosdev_obj_vaddr, dosdev_obj_paddr, flags::WRITABLE)
            .map_4k(symlink_obj_vaddr, symlink_obj_paddr, flags::WRITABLE)
            .map_4k(OB_TYPE_INDEX_TABLE_VADDR, ob_table_paddr, flags::WRITABLE)
            .map_4k(target_str_vaddr, target_str_paddr, flags::WRITABLE);

        // Type objects: "Directory" and "SymbolicLink"
        ptb = write_object_type(
            ptb,
            dir_type_vaddr,
            dir_type_paddr,
            dir_type_vaddr + 0x800,
            dir_type_paddr + 0x800,
            "Directory",
        );
        ptb = ptb.write_phys_u64(
            ob_table_paddr + u64::from(dir_type_index) * 8,
            dir_type_vaddr,
        );
        ptb = write_object_type(
            ptb,
            symlink_type_vaddr,
            symlink_type_paddr,
            symlink_type_vaddr + 0x800,
            symlink_type_paddr + 0x800,
            "SymbolicLink",
        );
        ptb = ptb.write_phys_u64(
            ob_table_paddr + u64::from(symlink_type_index) * 8,
            symlink_type_vaddr,
        );

        // DosDevices directory object
        let (dosdev_body, ptb2) = write_named_object(
            ptb,
            dosdev_obj_vaddr,
            dosdev_obj_paddr,
            dosdev_obj_vaddr + 0x800,
            dosdev_obj_paddr + 0x800,
            "DosDevices",
            dir_type_index,
        );
        ptb = ptb2;
        ptb = ptb.map_4k(root_entry_vaddr, root_entry_paddr, flags::WRITABLE);
        ptb = write_dir_entry(ptb, root_entry_paddr, 0, dosdev_body);
        ptb = set_bucket(ptb, root_dir_paddr, 0, root_entry_vaddr);

        // Symbolic link object
        let (symlink_body, ptb2) = write_named_object(
            ptb,
            symlink_obj_vaddr,
            symlink_obj_paddr,
            symlink_obj_vaddr + 0x800,
            symlink_obj_paddr + 0x800,
            link_name,
            symlink_type_index,
        );
        ptb = ptb2;

        // Write _OBJECT_SYMBOLIC_LINK body: LinkTarget (UNICODE_STRING) at +0x00
        let body_phys_off = symlink_body - symlink_obj_vaddr;
        ptb = write_unicode_string(
            ptb,
            symlink_obj_paddr + body_phys_off + SYMLINK_LINK_TARGET,
            target_str_vaddr,
            target_str_paddr,
            link_target,
        );
        // Write CreateTime at +0x10
        ptb = ptb.write_phys(
            symlink_obj_paddr + body_phys_off + SYMLINK_CREATE_TIME,
            &create_time.to_le_bytes(),
        );

        // Link symlink into subdirectory
        ptb = ptb.map_4k(subdir_entry_vaddr, subdir_entry_paddr, flags::WRITABLE);
        ptb = write_dir_entry(ptb, subdir_entry_paddr, 0, symlink_body);
        let dosdev_body_paddr = dosdev_obj_paddr + (dosdev_body - dosdev_obj_vaddr);
        ptb = set_bucket(ptb, dosdev_body_paddr, 0, subdir_entry_vaddr);

        ptb
    }

    #[test]
    fn walk_symlinks_empty_root() {
        let reader = make_test_reader(build_empty_root());
        let symlinks = walk_symlinks(&reader).unwrap();
        assert!(symlinks.is_empty());
    }

    #[test]
    fn walk_symlinks_finds_single_link() {
        let ptb = build_single_symlink("C:", "\\Device\\HarddiskVolume1", 132800000000000000);
        let reader = make_test_reader(ptb);
        let symlinks = walk_symlinks(&reader).unwrap();

        assert_eq!(symlinks.len(), 1);
        assert_eq!(symlinks[0].name, "C:");
        assert_eq!(symlinks[0].target, "\\Device\\HarddiskVolume1");
        assert_eq!(symlinks[0].create_time, 132800000000000000);
        assert!(!symlinks[0].is_suspicious);
    }

    #[test]
    fn walk_symlinks_detects_suspicious_target() {
        let ptb = build_single_symlink("Backdoor", "\\Device\\Tcp", 132800000000000000);
        let reader = make_test_reader(ptb);
        let symlinks = walk_symlinks(&reader).unwrap();

        assert_eq!(symlinks.len(), 1);
        assert!(symlinks[0].is_suspicious);
    }

    #[test]
    fn walk_symlinks_reads_create_time() {
        let ts: u64 = 133_500_000_000_000_000;
        let ptb = build_single_symlink("D:", "\\Device\\HarddiskVolume2", ts);
        let reader = make_test_reader(ptb);
        let symlinks = walk_symlinks(&reader).unwrap();

        assert_eq!(symlinks.len(), 1);
        assert_eq!(symlinks[0].create_time, ts);
    }
}
