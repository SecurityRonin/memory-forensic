//! Windows kernel named mutant (mutex) scanner.
//!
//! Walks the kernel Object Manager namespace tree starting from
//! `ObpRootDirectoryObject`, filters for objects whose type name is
//! "Mutant", and extracts name, owner PID/TID, and abandoned status
//! from each `_KMUTANT` body.  Named mutexes are a key DFIR artifact
//! because malware frequently creates them for single-instance execution.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::object_directory::walk_directory;
use crate::unicode::read_unicode_string;
use crate::{MutantInfo, Result};

/// Maximum recursion depth when walking nested object directories.
const MAX_DIR_DEPTH: usize = 8;

/// Walk the kernel object namespace and return all named mutant objects.
///
/// Resolves `ObpRootDirectoryObject` to find the root `_OBJECT_DIRECTORY`,
/// then recursively enumerates entries.  For each object whose type name
/// (via `_OBJECT_HEADER.TypeIndex` → `ObTypeIndexTable`) equals "Mutant",
/// reads the `_KMUTANT` body to extract owner thread / PID / abandoned.
pub fn walk_mutants<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<MutantInfo>> {
    // Read the pointer stored at ObpRootDirectoryObject.
    let root_ptr_addr = reader
        .symbols()
        .symbol_address("ObpRootDirectoryObject")
        .ok_or_else(|| crate::Error::Walker("missing ObpRootDirectoryObject symbol".into()))?;

    // ObpRootDirectoryObject is a pointer TO the root _OBJECT_DIRECTORY.
    let root_dir_addr = {
        let bytes = reader.read_bytes(root_ptr_addr, 8)?;
        u64::from_le_bytes(bytes.try_into().expect("8 bytes"))
    };

    if root_dir_addr == 0 {
        return Ok(Vec::new());
    }

    let ob_type_table_addr = reader
        .symbols()
        .symbol_address("ObTypeIndexTable")
        .ok_or_else(|| crate::Error::Walker("missing ObTypeIndexTable symbol".into()))?;

    let body_offset = reader
        .symbols()
        .field_offset("_OBJECT_HEADER", "Body")
        .ok_or_else(|| crate::Error::Walker("missing _OBJECT_HEADER.Body offset".into()))?;

    let mut results = Vec::new();
    walk_directory_recursive(
        reader,
        root_dir_addr,
        ob_type_table_addr,
        body_offset,
        0,
        &mut results,
    )?;

    Ok(results)
}

/// Recursively walk an `_OBJECT_DIRECTORY` and collect mutant objects.
fn walk_directory_recursive<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    dir_addr: u64,
    ob_type_table_addr: u64,
    body_offset: u64,
    depth: usize,
    results: &mut Vec<MutantInfo>,
) -> Result<()> {
    if depth >= MAX_DIR_DEPTH {
        return Ok(());
    }

    let entries = walk_directory(reader, dir_addr)?;

    for (name, object_body) in entries {
        // Resolve the type of this object via _OBJECT_HEADER.TypeIndex.
        let header_addr = object_body.wrapping_sub(body_offset);
        let type_index: u8 = match reader.read_bytes(
            header_addr.wrapping_add(
                reader
                    .symbols()
                    .field_offset("_OBJECT_HEADER", "TypeIndex")
                    .unwrap_or(0x18),
            ),
            1,
        ) {
            Ok(bytes) => bytes[0],
            Err(_) => continue,
        };

        let type_name = resolve_type_name(reader, ob_type_table_addr, type_index);

        if type_name == "Mutant" {
            if let Ok(info) = read_mutant_info(reader, object_body, name) {
                results.push(info);
            }
        } else if type_name == "Directory" {
            // The object body IS the _OBJECT_DIRECTORY — recurse into it.
            let _ = walk_directory_recursive(
                reader,
                object_body,
                ob_type_table_addr,
                body_offset,
                depth + 1,
                results,
            );
        }
    }

    Ok(())
}

/// Resolve the object type name from `ObTypeIndexTable[type_index]`.
fn resolve_type_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ob_table_addr: u64,
    type_index: u8,
) -> String {
    let slot_addr = ob_table_addr.wrapping_add(u64::from(type_index) * 8);
    let obj_type_addr: u64 = match reader.read_bytes(slot_addr, 8) {
        Ok(bytes) => u64::from_le_bytes(bytes.try_into().expect("8 bytes")),
        Err(_) => return String::from("<unknown>"),
    };

    if obj_type_addr == 0 {
        return String::from("<unknown>");
    }

    let name_off = reader
        .symbols()
        .field_offset("_OBJECT_TYPE", "Name")
        .unwrap_or(0x10);

    match read_unicode_string(reader, obj_type_addr.wrapping_add(name_off)) {
        Ok(name) if !name.is_empty() => name,
        _ => String::from("<unknown>"),
    }
}

/// Read mutant details from the object body (`_KMUTANT`).
fn read_mutant_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    object_body_addr: u64,
    name: String,
) -> Result<MutantInfo> {
    // Read OwnerThread pointer from _KMUTANT.
    let owner_thread: u64 = reader.read_field(object_body_addr, "_KMUTANT", "OwnerThread")?;

    // Read Abandoned flag.
    let abandoned_byte: u8 = reader.read_field(object_body_addr, "_KMUTANT", "Abandoned")?;
    let abandoned = abandoned_byte != 0;

    // Resolve owner PID and TID from _ETHREAD.Cid if thread pointer is valid.
    // _CLIENT_ID is an embedded struct within _ETHREAD at the Cid offset.
    // UniqueProcess is at _CLIENT_ID+0, UniqueThread is at _CLIENT_ID+8.
    let (owner_pid, owner_thread_id) = if owner_thread != 0 {
        let cid_offset = reader
            .symbols()
            .field_offset("_ETHREAD", "Cid")
            .ok_or_else(|| crate::Error::Walker("missing _ETHREAD.Cid offset".into()))?;
        let pid_offset = reader
            .symbols()
            .field_offset("_CLIENT_ID", "UniqueProcess")
            .ok_or_else(|| {
                crate::Error::Walker("missing _CLIENT_ID.UniqueProcess offset".into())
            })?;
        let tid_offset = reader
            .symbols()
            .field_offset("_CLIENT_ID", "UniqueThread")
            .ok_or_else(|| crate::Error::Walker("missing _CLIENT_ID.UniqueThread offset".into()))?;

        let cid_addr = owner_thread.wrapping_add(cid_offset);

        let pid_bytes = reader.read_bytes(cid_addr.wrapping_add(pid_offset), 8)?;
        let pid = u64::from_le_bytes(pid_bytes.try_into().expect("8 bytes"));

        let tid_bytes = reader.read_bytes(cid_addr.wrapping_add(tid_offset), 8)?;
        let tid = u64::from_le_bytes(tid_bytes.try_into().expect("8 bytes"));

        (pid, tid)
    } else {
        (0, 0)
    };

    Ok(MutantInfo {
        name,
        owner_pid,
        owner_thread_id,
        abandoned,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
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

    // _KMUTANT offsets (from preset)
    const KMUTANT_OWNER_THREAD: u64 = 0x28;
    const KMUTANT_ABANDONED: u64 = 0x30;

    // _ETHREAD.Cid offset (from preset)
    const ETHREAD_CID: u64 = 0x620;
    // _CLIENT_ID offsets
    const CID_UNIQUE_PROCESS: u64 = 0x0;
    const CID_UNIQUE_THREAD: u64 = 0x8;

    // _OBJECT_TYPE.Name offset
    const OBJ_TYPE_NAME: u64 = 0x10;

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn make_test_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// Write a `_UNICODE_STRING` (Length, MaxLength, Buffer pointer) at a
    /// physical offset, and the UTF-16LE payload at `str_paddr`.
    fn write_unicode_string(
        ptb: PageTableBuilder,
        unistr_paddr: u64,
        str_vaddr: u64,
        str_paddr: u64,
        text: &str,
    ) -> PageTableBuilder {
        let utf16 = utf16le(text);
        let len = utf16.len() as u16;
        ptb.write_phys(unistr_paddr, &len.to_le_bytes())
            .write_phys(unistr_paddr + 2, &len.to_le_bytes())
            .write_phys_u64(unistr_paddr + 8, str_vaddr)
            .write_phys(str_paddr, &utf16)
    }

    /// Write an `_OBJECT_TYPE` at `type_paddr` with `Name` pointing to a
    /// UTF-16LE string.  Returns the updated `PageTableBuilder`.
    fn write_object_type(
        ptb: PageTableBuilder,
        type_vaddr: u64,
        type_paddr: u64,
        str_vaddr: u64,
        str_paddr: u64,
        type_name: &str,
    ) -> PageTableBuilder {
        let ptb = ptb.map_4k(type_vaddr, type_paddr, flags::WRITABLE);
        write_unicode_string(
            ptb,
            type_paddr + OBJ_TYPE_NAME,
            str_vaddr,
            str_paddr,
            type_name,
        )
    }

    /// Write a named object (name_info + header + body) contiguously starting
    /// at `base_paddr`.  Layout:
    ///   base + 0x00: `_OBJECT_HEADER_NAME_INFO` (0x20 bytes)
    ///   base + 0x20: `_OBJECT_HEADER` (0x30 bytes to Body)
    ///   base + 0x50: Body (object body)
    ///
    /// `type_index` is written into `_OBJECT_HEADER.TypeIndex`.
    /// Returns the virtual address of the object body.
    fn write_named_object(
        ptb: PageTableBuilder,
        base_vaddr: u64,
        base_paddr: u64,
        str_vaddr: u64,
        str_paddr: u64,
        name: &str,
        type_index: u8,
    ) -> (u64, PageTableBuilder) {
        // name_info at base + 0x00
        let ni_paddr = base_paddr;
        let ptb = write_unicode_string(ptb, ni_paddr + NAME_INFO_NAME, str_vaddr, str_paddr, name);

        // header at base + 0x20
        let hdr_paddr = base_paddr + NAME_INFO_SIZE;
        let ptb = ptb
            .write_phys(hdr_paddr + OBJ_HEADER_INFO_MASK, &[0x02]) // NAME_INFO present
            .write_phys(hdr_paddr + OBJ_HEADER_TYPE_INDEX, &[type_index]);

        // body at base + 0x50
        let body_vaddr = base_vaddr + NAME_INFO_SIZE + OBJ_HEADER_BODY;
        (body_vaddr, ptb)
    }

    /// Write an `_OBJECT_DIRECTORY_ENTRY` at `entry_paddr`.
    fn write_dir_entry(
        ptb: PageTableBuilder,
        entry_paddr: u64,
        chain_link: u64,
        object_body: u64,
    ) -> PageTableBuilder {
        ptb.write_phys_u64(entry_paddr, chain_link)
            .write_phys_u64(entry_paddr + 8, object_body)
    }

    /// Set a hash bucket pointer in a directory page.
    fn set_bucket(
        ptb: PageTableBuilder,
        dir_paddr: u64,
        bucket_idx: usize,
        entry_vaddr: u64,
    ) -> PageTableBuilder {
        ptb.write_phys_u64(dir_paddr + (bucket_idx as u64) * 8, entry_vaddr)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Helpers: build synthetic memory for mutant scanning
    // ─────────────────────────────────────────────────────────────────────

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

    /// Build a root directory with a `\BaseNamedObjects` subdirectory
    /// containing one mutant named `mutant_name` owned by `(pid, tid)`.
    fn build_single_mutant(
        mutant_name: &str,
        pid: u64,
        tid: u64,
        abandoned: bool,
    ) -> PageTableBuilder {
        let root_dir_ptr_paddr: u64 = 0x0010_0000;
        let root_dir_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let root_dir_paddr: u64 = 0x0020_0000;

        let bno_obj_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let bno_obj_paddr: u64 = 0x0030_0000;
        let root_entry_vaddr: u64 = 0xFFFF_8000_0020_0C00;
        let root_entry_paddr: u64 = 0x0030_0C00;

        let mutant_obj_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let mutant_obj_paddr: u64 = 0x0040_0000;
        let subdir_entry_vaddr: u64 = 0xFFFF_8000_0030_0C00;
        let subdir_entry_paddr: u64 = 0x0040_0C00;

        let mutant_type_vaddr: u64 = 0xFFFF_8000_0050_0000;
        let mutant_type_paddr: u64 = 0x0060_0000;
        let dir_type_vaddr: u64 = 0xFFFF_8000_0050_1000;
        let dir_type_paddr: u64 = 0x0061_0000;
        let ob_table_paddr: u64 = 0x0070_0000;

        let ethread_vaddr: u64 = 0xFFFF_8000_0060_0000;
        let ethread_paddr: u64 = 0x0080_0000;

        let mutant_type_index: u8 = 17;
        let dir_type_index: u8 = 3;

        let mut ptb = PageTableBuilder::new()
            .map_4k(OBP_ROOT_DIR_OBJ_VADDR, root_dir_ptr_paddr, flags::WRITABLE)
            .write_phys_u64(root_dir_ptr_paddr, root_dir_vaddr)
            .map_4k(root_dir_vaddr, root_dir_paddr, flags::WRITABLE)
            .map_4k(bno_obj_vaddr, bno_obj_paddr, flags::WRITABLE)
            .map_4k(mutant_obj_vaddr, mutant_obj_paddr, flags::WRITABLE)
            .map_4k(OB_TYPE_INDEX_TABLE_VADDR, ob_table_paddr, flags::WRITABLE)
            .map_4k(ethread_vaddr, ethread_paddr, flags::WRITABLE);

        // Type objects
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
            mutant_type_vaddr,
            mutant_type_paddr,
            mutant_type_vaddr + 0x800,
            mutant_type_paddr + 0x800,
            "Mutant",
        );
        ptb = ptb.write_phys_u64(
            ob_table_paddr + u64::from(mutant_type_index) * 8,
            mutant_type_vaddr,
        );

        // BaseNamedObjects directory object
        let (bno_body, ptb2) = write_named_object(
            ptb,
            bno_obj_vaddr,
            bno_obj_paddr,
            bno_obj_vaddr + 0x800,
            bno_obj_paddr + 0x800,
            "BaseNamedObjects",
            dir_type_index,
        );
        ptb = ptb2;
        ptb = ptb.map_4k(root_entry_vaddr, root_entry_paddr, flags::WRITABLE);
        ptb = write_dir_entry(ptb, root_entry_paddr, 0, bno_body);
        ptb = set_bucket(ptb, root_dir_paddr, 0, root_entry_vaddr);

        // Mutant object
        let (mutant_body, ptb2) = write_named_object(
            ptb,
            mutant_obj_vaddr,
            mutant_obj_paddr,
            mutant_obj_vaddr + 0x800,
            mutant_obj_paddr + 0x800,
            mutant_name,
            mutant_type_index,
        );
        ptb = ptb2;
        let body_phys_off = mutant_body - mutant_obj_vaddr;
        ptb = ptb.write_phys_u64(
            mutant_obj_paddr + body_phys_off + KMUTANT_OWNER_THREAD,
            ethread_vaddr,
        );
        ptb = ptb.write_phys(
            mutant_obj_paddr + body_phys_off + KMUTANT_ABANDONED,
            &[u8::from(abandoned)],
        );

        // Link mutant into subdirectory
        ptb = ptb.map_4k(subdir_entry_vaddr, subdir_entry_paddr, flags::WRITABLE);
        ptb = write_dir_entry(ptb, subdir_entry_paddr, 0, mutant_body);
        let bno_body_paddr = bno_obj_paddr + (bno_body - bno_obj_vaddr);
        ptb = set_bucket(ptb, bno_body_paddr, 0, subdir_entry_vaddr);

        // _ETHREAD.Cid
        ptb = ptb
            .write_phys_u64(ethread_paddr + ETHREAD_CID + CID_UNIQUE_PROCESS, pid)
            .write_phys_u64(ethread_paddr + ETHREAD_CID + CID_UNIQUE_THREAD, tid);

        ptb
    }

    // ─────────────────────────────────────────────────────────────────────
    // Tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn walk_mutants_empty() {
        let reader = make_test_reader(build_empty_root());
        let mutants = walk_mutants(&reader).unwrap();
        assert!(mutants.is_empty());
    }

    #[test]
    fn walk_mutants_single() {
        let ptb = build_single_mutant("MyMalwareMutex", 1234, 5678, false);
        let reader = make_test_reader(ptb);
        let mutants = walk_mutants(&reader).unwrap();

        assert_eq!(mutants.len(), 1);
        assert_eq!(mutants[0].name, "MyMalwareMutex");
        assert_eq!(mutants[0].owner_pid, 1234);
        assert_eq!(mutants[0].owner_thread_id, 5678);
        assert!(!mutants[0].abandoned);
    }

    /// walk_mutants: abandoned mutant is correctly read.
    #[test]
    fn walk_mutants_abandoned() {
        let ptb = build_single_mutant("AbandonedMutex", 5678, 9012, true);
        let reader = make_test_reader(ptb);
        let mutants = walk_mutants(&reader).unwrap();

        assert_eq!(mutants.len(), 1);
        assert_eq!(mutants[0].name, "AbandonedMutex");
        assert!(mutants[0].abandoned);
    }

    /// resolve_type_name: slot reads 0 (null obj_type_addr) → returns "<unknown>".
    #[test]
    fn resolve_type_name_null_obj_type_addr_returns_unknown() {
        // Build a reader with ObTypeIndexTable mapped but the slot at index 0 is zero.
        let ob_table_paddr: u64 = 0x0070_1000;

        let ptb = build_empty_root()
            .map_4k(OB_TYPE_INDEX_TABLE_VADDR, ob_table_paddr, flags::WRITABLE)
            // All zeros: slot[0] = 0 (null obj type pointer)
            .write_phys(ob_table_paddr, &[0u8; 4096]);
        let reader = make_test_reader(ptb);

        let name = resolve_type_name(&reader, OB_TYPE_INDEX_TABLE_VADDR, 0);
        assert_eq!(name, "<unknown>", "null pointer slot should return '<unknown>'");
    }

    /// resolve_type_name: slot read fails (unmapped address) → returns "<unknown>".
    #[test]
    fn resolve_type_name_unmapped_table_returns_unknown() {
        let ptb = build_empty_root();
        let reader = make_test_reader(ptb);

        // Use an unmapped table address → read_bytes fails → "<unknown>"
        let name = resolve_type_name(&reader, 0xDEAD_BEEF_CAFE_0000, 5);
        assert_eq!(name, "<unknown>", "unmapped table addr should return '<unknown>'");
    }

    /// walk_directory_recursive: depth >= MAX_DIR_DEPTH guard returns Ok early.
    #[test]
    fn walk_directory_recursive_depth_limit_returns_ok() {
        let ptb = build_empty_root()
            .map_4k(OB_TYPE_INDEX_TABLE_VADDR, 0x0070_2000, flags::WRITABLE)
            .write_phys(0x0070_2000, &[0u8; 4096]);
        let reader = make_test_reader(ptb);

        let mut results = Vec::new();
        // Call with depth = MAX_DIR_DEPTH (8) → should return Ok immediately.
        let ret = walk_directory_recursive(
            &reader,
            0xFFFF_8000_0010_0000, // root dir addr (mapped to empty page from build_empty_root)
            OB_TYPE_INDEX_TABLE_VADDR,
            OBJ_HEADER_BODY,
            MAX_DIR_DEPTH,
            &mut results,
        );
        assert!(ret.is_ok(), "depth == MAX_DIR_DEPTH should return Ok without error");
        assert!(results.is_empty(), "no results should be added when depth limit exceeded");
    }

    /// MutantInfo serializes correctly.
    #[test]
    fn mutant_info_serializes() {
        use crate::MutantInfo;
        let info = MutantInfo {
            name: "TestMutex".to_string(),
            owner_pid: 1234,
            owner_thread_id: 5678,
            abandoned: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"name\":\"TestMutex\""));
        assert!(json.contains("\"owner_pid\":1234"));
        assert!(json.contains("\"abandoned\":false"));
    }

    /// walk_mutants: mutant with owner_thread = 0 → owner_pid and owner_thread_id are 0.
    /// Exercises the `else { (0, 0) }` branch in read_mutant_info.
    #[test]
    fn walk_mutants_no_owner_thread() {
        // Build a single mutant but override the OwnerThread field to 0 after building.
        let root_dir_ptr_paddr: u64 = 0x0010_0000;
        let root_dir_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let root_dir_paddr: u64 = 0x0020_0000;

        let bno_obj_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let bno_obj_paddr: u64 = 0x0030_0000;
        let root_entry_vaddr: u64 = 0xFFFF_8000_0020_0C00;
        let root_entry_paddr: u64 = 0x0030_0C00;

        let mutant_obj_vaddr: u64 = 0xFFFF_8000_0031_0000;
        let mutant_obj_paddr: u64 = 0x0041_0000;
        let subdir_entry_vaddr: u64 = 0xFFFF_8000_0031_0C00;
        let subdir_entry_paddr: u64 = 0x0041_0C00;

        let mutant_type_vaddr: u64 = 0xFFFF_8000_0051_0000;
        let mutant_type_paddr: u64 = 0x0061_0000;
        let dir_type_vaddr: u64 = 0xFFFF_8000_0051_1000;
        let dir_type_paddr: u64 = 0x0062_0000;
        let ob_table_paddr: u64 = 0x0071_0000;

        let mutant_type_index: u8 = 17;
        let dir_type_index: u8 = 3;

        let mut ptb = PageTableBuilder::new()
            .map_4k(OBP_ROOT_DIR_OBJ_VADDR, root_dir_ptr_paddr, flags::WRITABLE)
            .write_phys_u64(root_dir_ptr_paddr, root_dir_vaddr)
            .map_4k(root_dir_vaddr, root_dir_paddr, flags::WRITABLE)
            .map_4k(bno_obj_vaddr, bno_obj_paddr, flags::WRITABLE)
            .map_4k(mutant_obj_vaddr, mutant_obj_paddr, flags::WRITABLE)
            .map_4k(OB_TYPE_INDEX_TABLE_VADDR, ob_table_paddr, flags::WRITABLE)
            .map_4k(ethread_vaddr_unused(), ethread_paddr_unused(), flags::WRITABLE);

        ptb = write_object_type(ptb, dir_type_vaddr, dir_type_paddr, dir_type_vaddr + 0x800, dir_type_paddr + 0x800, "Directory");
        ptb = ptb.write_phys_u64(ob_table_paddr + u64::from(dir_type_index) * 8, dir_type_vaddr);
        ptb = write_object_type(ptb, mutant_type_vaddr, mutant_type_paddr, mutant_type_vaddr + 0x800, mutant_type_paddr + 0x800, "Mutant");
        ptb = ptb.write_phys_u64(ob_table_paddr + u64::from(mutant_type_index) * 8, mutant_type_vaddr);

        let (bno_body, ptb2) = write_named_object(ptb, bno_obj_vaddr, bno_obj_paddr, bno_obj_vaddr + 0x800, bno_obj_paddr + 0x800, "BaseNamedObjects", dir_type_index);
        ptb = ptb2;
        ptb = ptb.map_4k(root_entry_vaddr, root_entry_paddr, flags::WRITABLE);
        ptb = write_dir_entry(ptb, root_entry_paddr, 0, bno_body);
        ptb = set_bucket(ptb, root_dir_paddr, 0, root_entry_vaddr);

        let (mutant_body, ptb2) = write_named_object(ptb, mutant_obj_vaddr, mutant_obj_paddr, mutant_obj_vaddr + 0x800, mutant_obj_paddr + 0x800, "NoOwnerMutex", mutant_type_index);
        ptb = ptb2;
        let body_phys_off = mutant_body - mutant_obj_vaddr;
        // OwnerThread = 0 (no owner)
        ptb = ptb.write_phys_u64(mutant_obj_paddr + body_phys_off + KMUTANT_OWNER_THREAD, 0);
        ptb = ptb.write_phys(mutant_obj_paddr + body_phys_off + KMUTANT_ABANDONED, &[0u8]);

        ptb = ptb.map_4k(subdir_entry_vaddr, subdir_entry_paddr, flags::WRITABLE);
        ptb = write_dir_entry(ptb, subdir_entry_paddr, 0, mutant_body);
        let bno_body_paddr = bno_obj_paddr + (bno_body - bno_obj_vaddr);
        ptb = set_bucket(ptb, bno_body_paddr, 0, subdir_entry_vaddr);

        let reader = make_test_reader(ptb);
        let mutants = walk_mutants(&reader).unwrap();

        assert_eq!(mutants.len(), 1);
        assert_eq!(mutants[0].name, "NoOwnerMutex");
        assert_eq!(mutants[0].owner_pid, 0, "no owner thread → owner_pid should be 0");
        assert_eq!(mutants[0].owner_thread_id, 0);
        assert!(!mutants[0].abandoned);
    }

    fn ethread_vaddr_unused() -> u64 { 0xFFFF_8000_0081_0000 }
    fn ethread_paddr_unused() -> u64 { 0x0091_0000 }

    /// resolve_type_name: valid slot and type with empty name → returns "<unknown>".
    #[test]
    fn resolve_type_name_empty_name_returns_unknown() {
        // Build an _OBJECT_TYPE with a Name _UNICODE_STRING that has Length=0.
        let ob_table_paddr: u64 = 0x0073_0000;
        let type_vaddr: u64 = 0xFFFF_8000_0083_0000;
        let type_paddr: u64 = 0x0083_0000;

        let ptb = build_empty_root()
            .map_4k(OB_TYPE_INDEX_TABLE_VADDR, ob_table_paddr, flags::WRITABLE)
            .map_4k(type_vaddr, type_paddr, flags::WRITABLE)
            // Slot 5 → type_vaddr
            .write_phys_u64(ob_table_paddr + 5 * 8, type_vaddr)
            // _OBJECT_TYPE.Name at type_paddr + 0x10: Length=0, Buffer=0 → empty string
            .write_phys(type_paddr + OBJ_TYPE_NAME, &[0u8; 16]);

        let reader = make_test_reader(ptb);
        let name = resolve_type_name(&reader, OB_TYPE_INDEX_TABLE_VADDR, 5);
        assert_eq!(name, "<unknown>", "empty unicode name should return '<unknown>'");
    }
}
