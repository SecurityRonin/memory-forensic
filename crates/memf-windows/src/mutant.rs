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
    let root_sym_addr = match reader.symbols().symbol_address("ObpRootDirectoryObject") {
        Some(v) => v,
        None => return Ok(Vec::new()),
    };
    let root_dir_addr: u64 = match reader.read_bytes(root_sym_addr, 8) {
        Ok(bytes) => u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")),
        Err(_) => return Ok(Vec::new()),
    };
    if root_dir_addr == 0 {
        return Ok(Vec::new());
    }

    let ob_type_table_addr = reader
        .symbols()
        .symbol_address("ObTypeIndexTable")
        .unwrap_or(0);

    let body_offset = reader
        .symbols()
        .struct_size("_OBJECT_HEADER")
        .unwrap_or(0x30);

    let mut results = Vec::new();
    walk_directory_recursive(
        reader,
        root_dir_addr,
        ob_type_table_addr,
        body_offset,
        0,
        &mut results,
    );
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
) {
    if depth >= MAX_DIR_DEPTH {
        return;
    }

    let entries = walk_directory(reader, dir_addr).unwrap_or_default();
    for (name, body_addr) in entries {
        // The object header lies just before the body
        let header_addr = body_addr.wrapping_sub(body_offset);

        // Read TypeIndex from _OBJECT_HEADER
        let type_index: u8 = reader
            .read_field(header_addr, "_OBJECT_HEADER", "TypeIndex")
            .unwrap_or(0);

        let type_name = resolve_type_name(reader, ob_type_table_addr, type_index);

        if type_name == "Mutant" {
            results.push(read_mutant_info(reader, body_addr, name));
        } else if type_name == "Directory" {
            // Recurse into subdirectory
            walk_directory_recursive(
                reader,
                body_addr,
                ob_type_table_addr,
                body_offset,
                depth + 1,
                results,
            );
        }
    }
}

/// Resolve the object type name from `ObTypeIndexTable[type_index]`.
fn resolve_type_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ob_table_addr: u64,
    type_index: u8,
) -> String {
    if ob_table_addr == 0 {
        return "<unknown>".to_string();
    }
    // ObTypeIndexTable is an array of pointers to _OBJECT_TYPE
    let slot_addr = ob_table_addr + u64::from(type_index) * 8;
    let obj_type_ptr: u64 = match reader.read_bytes(slot_addr, 8) {
        Ok(bytes) => u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")),
        Err(_) => return "<unknown>".to_string(),
    };
    if obj_type_ptr == 0 {
        return "<unknown>".to_string();
    }
    // _OBJECT_TYPE.Name is a _UNICODE_STRING at offset OBJ_TYPE_NAME (0x10)
    let name_off = reader
        .symbols()
        .field_offset("_OBJECT_TYPE", "Name")
        .unwrap_or(0x10);
    let name = read_unicode_string(reader, obj_type_ptr + name_off).unwrap_or_default();
    if name.is_empty() {
        "<unknown>".to_string()
    } else {
        name
    }
}

/// Read mutant details from the object body (`_KMUTANT`).
fn read_mutant_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    object_body_addr: u64,
    name: String,
) -> MutantInfo {
    let owner_thread_off = reader
        .symbols()
        .field_offset("_KMUTANT", "OwnerThread")
        .unwrap_or(0x28);
    let abandoned_off = reader
        .symbols()
        .field_offset("_KMUTANT", "Abandoned")
        .unwrap_or(0x30);

    let owner_thread_ptr: u64 = reader
        .read_bytes(object_body_addr + owner_thread_off, 8)
        .map(|b| u64::from_le_bytes(b[..8].try_into().expect("8")))
        .unwrap_or(0);

    let abandoned: bool = reader
        .read_bytes(object_body_addr + abandoned_off, 1)
        .map(|b| b[0] != 0)
        .unwrap_or(false);

    let (owner_pid, owner_tid) = if owner_thread_ptr != 0 {
        let cid_off = reader
            .symbols()
            .field_offset("_ETHREAD", "Cid")
            .unwrap_or(0x620);
        let pid: u64 = reader
            .read_bytes(owner_thread_ptr + cid_off, 8)
            .map(|b| u64::from_le_bytes(b[..8].try_into().expect("8")))
            .unwrap_or(0);
        let tid: u64 = reader
            .read_bytes(owner_thread_ptr + cid_off + 8, 8)
            .map(|b| u64::from_le_bytes(b[..8].try_into().expect("8")))
            .unwrap_or(0);
        (pid, tid)
    } else {
        (0, 0)
    };

    MutantInfo {
        name,
        owner_pid,
        owner_thread_id: owner_tid,
        abandoned,
    }
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

    // _KMUTANT offsets (from preset)
    const KMUTANT_OWNER_THREAD: u64 = 0x28;
    const KMUTANT_ABANDONED: u64 = 0x30;

    // _ETHREAD.Cid offset (from preset)
    const ETHREAD_CID: u64 = 0x620;
    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn make_isf() -> serde_json::Value {
        IsfBuilder::new()
            // _OBJECT_DIRECTORY: 37 bucket pointers at offset 0
            .add_struct("_OBJECT_DIRECTORY", 37 * 8 + 16)
            .add_field("_OBJECT_DIRECTORY", "HashBuckets", 0, "pointer")
            // _OBJECT_DIRECTORY_ENTRY
            .add_struct("_OBJECT_DIRECTORY_ENTRY", 24)
            .add_field("_OBJECT_DIRECTORY_ENTRY", "ChainLink", 0, "pointer")
            .add_field("_OBJECT_DIRECTORY_ENTRY", "Object", 8, "pointer")
            .add_field("_OBJECT_DIRECTORY_ENTRY", "HashValue", 0x10, "unsigned int")
            // _OBJECT_HEADER_NAME_INFO (size=0x20, Name at 0x10)
            .add_struct("_OBJECT_HEADER_NAME_INFO", 0x20)
            .add_field("_OBJECT_HEADER_NAME_INFO", "Name", 0x10, "pointer")
            // _UNICODE_STRING
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            // _OBJECT_HEADER (size=0x30): Body at 0x30, TypeIndex at 0x18, InfoMask at 0x1a
            .add_struct("_OBJECT_HEADER", 0x30)
            .add_field("_OBJECT_HEADER", "Body", 0x30, "pointer")
            .add_field("_OBJECT_HEADER", "TypeIndex", 0x18, "unsigned char")
            .add_field("_OBJECT_HEADER", "InfoMask", 0x1a, "unsigned char")
            // _OBJECT_TYPE.Name (_UNICODE_STRING) at 0x10
            .add_struct("_OBJECT_TYPE", 0x100)
            .add_field("_OBJECT_TYPE", "Name", 0x10, "pointer")
            // _KMUTANT
            .add_struct("_KMUTANT", 0x40)
            .add_field("_KMUTANT", "OwnerThread", 0x28, "pointer")
            .add_field("_KMUTANT", "Abandoned", 0x30, "unsigned char")
            // _ETHREAD.Cid at 0x620
            .add_struct("_ETHREAD", 0x700)
            .add_field("_ETHREAD", "Cid", 0x620, "pointer")
            // Symbols
            .add_symbol("ObpRootDirectoryObject", OBP_ROOT_DIR_OBJ_VADDR)
            .add_symbol("ObTypeIndexTable", OB_TYPE_INDEX_TABLE_VADDR)
            .build_json()
    }

    fn make_test_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = make_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// Write a named object (name_info + header + body) at `base_vaddr/base_paddr`.
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
        let encoded = utf16le(name);
        let len = encoded.len() as u16;

        let mut obj_page = vec![0u8; 4096];
        // _OBJECT_HEADER_NAME_INFO.Name (_UNICODE_STRING) at +0x10
        obj_page[0x10..0x12].copy_from_slice(&len.to_le_bytes()); // Length
        obj_page[0x12..0x14].copy_from_slice(&len.to_le_bytes()); // MaximumLength
        obj_page[0x18..0x20].copy_from_slice(&str_vaddr.to_le_bytes()); // Buffer
                                                                        // _OBJECT_HEADER at +0x20: InfoMask at +0x1a = 0x02 (NAME_INFO present)
        obj_page[0x20 + 0x1a] = 0x02;
        // TypeIndex at _OBJECT_HEADER + 0x18
        obj_page[0x20 + 0x18] = type_index;

        let mut str_page = vec![0u8; 4096];
        str_page[..encoded.len()].copy_from_slice(&encoded);

        let ptb = ptb
            .map_4k(base_vaddr, base_paddr, flags::WRITABLE)
            .write_phys(base_paddr, &obj_page)
            .write_phys(str_paddr, &str_page);

        // body is at base + 0x20 (header_name_info) + 0x30 (header) = base + 0x50
        let body_vaddr = base_vaddr + 0x50;
        (body_vaddr, ptb)
    }

    /// Write an `_OBJECT_DIRECTORY_ENTRY` at the given physical address.
    fn write_dir_entry(
        ptb: PageTableBuilder,
        entry_paddr: u64,
        chain_link: u64,
        object_body: u64,
    ) -> PageTableBuilder {
        let mut buf = vec![0u8; 24];
        buf[0..8].copy_from_slice(&chain_link.to_le_bytes());
        buf[8..16].copy_from_slice(&object_body.to_le_bytes());
        ptb.write_phys(entry_paddr, &buf)
    }

    /// Set a hash bucket pointer in a directory page.
    fn set_bucket(
        ptb: PageTableBuilder,
        dir_paddr: u64,
        bucket_idx: usize,
        entry_vaddr: u64,
    ) -> PageTableBuilder {
        let off = bucket_idx * 8;
        let mut buf = vec![0u8; 8];
        buf[0..8].copy_from_slice(&entry_vaddr.to_le_bytes());
        ptb.write_phys(dir_paddr + off as u64, &buf)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Helpers: build synthetic memory for mutant scanning
    // ─────────────────────────────────────────────────────────────────────

    /// Build an empty root directory pointed to by `ObpRootDirectoryObject`.
    fn build_empty_root() -> PageTableBuilder {
        // OBP_ROOT_DIR_OBJ_VADDR symbol holds a pointer to ROOT_DIR_VADDR
        const SYM_VADDR: u64 = OBP_ROOT_DIR_OBJ_VADDR;
        const SYM_PADDR: u64 = 0x00B0_0000;
        const ROOT_VADDR: u64 = 0xFFFF_8000_0040_0000;
        const ROOT_PADDR: u64 = 0x0040_0000;

        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&ROOT_VADDR.to_le_bytes());
        let root_page = vec![0u8; 4096]; // empty directory

        PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .map_4k(ROOT_VADDR, ROOT_PADDR, flags::WRITABLE)
            .write_phys(ROOT_PADDR, &root_page)
    }

    /// Build a root directory with a mutant named `mutant_name` owned by `(pid, tid)`.
    /// Uses type_index=4 for "Mutant" (indexed in ObTypeIndexTable at slot 4).
    ///
    /// Memory layout (all strings stored inline in their parent struct's physical page):
    ///   SYM_VADDR      → ROOT_VADDR
    ///   OBJ_TABLE      → slot[4] = MTYPE_VADDR
    ///   MTYPE page:    _OBJECT_TYPE { Name._UNICODE_STRING at +0x10, "Mutant" at +0x100 }
    ///   ROOT page:     bucket[0] = ENTRY_VADDR
    ///   OBJ page:      name_info(+0x00) + header(+0x20) + kmutant_body(+0x50)
    ///                  name string at +0x200, type_index=4, info_mask=0x02
    ///   ENTRY page:    { ChainLink=0, Object=OBJ_VADDR+0x50 }
    ///   ETHREAD page:  Cid at +0x620
    fn build_single_mutant(
        mutant_name: &str,
        pid: u64,
        tid: u64,
        abandoned: bool,
    ) -> PageTableBuilder {
        const SYM_VADDR: u64 = OBP_ROOT_DIR_OBJ_VADDR;
        const SYM_PADDR: u64 = 0x00B1_0000;
        const OBJ_TABLE_VADDR: u64 = OB_TYPE_INDEX_TABLE_VADDR;
        const OBJ_TABLE_PADDR: u64 = 0x00B2_0000;
        const MTYPE_VADDR: u64 = 0xFFFF_8000_0050_0000;
        const MTYPE_PADDR: u64 = 0x0050_0000;
        const ROOT_VADDR: u64 = 0xFFFF_8000_0051_0000;
        const ROOT_PADDR: u64 = 0x0051_0000;
        const OBJ_VADDR: u64 = 0xFFFF_8000_0052_0000;
        const OBJ_PADDR: u64 = 0x0052_0000;
        const ENTRY_VADDR: u64 = 0xFFFF_8000_0053_0000;
        const ENTRY_PADDR: u64 = 0x0053_0000;
        const ETHREAD_VADDR: u64 = 0xFFFF_8000_0054_0000;
        const ETHREAD_PADDR: u64 = 0x0054_0000;

        // String for "Mutant" lives at offset 0x100 within MTYPE page
        let mtype_str_vaddr = MTYPE_VADDR + 0x100;
        let mtype_name_bytes = utf16le("Mutant");
        let mtype_name_len = mtype_name_bytes.len() as u16;
        let mut mtype_page = vec![0u8; 4096];
        // _OBJECT_TYPE.Name (_UNICODE_STRING) at +0x10
        mtype_page[0x10..0x12].copy_from_slice(&mtype_name_len.to_le_bytes());
        mtype_page[0x12..0x14].copy_from_slice(&mtype_name_len.to_le_bytes());
        mtype_page[0x18..0x20].copy_from_slice(&mtype_str_vaddr.to_le_bytes());
        // Inline string at +0x100
        mtype_page[0x100..0x100 + mtype_name_bytes.len()].copy_from_slice(&mtype_name_bytes);

        // Mutant object name string lives at offset 0x200 within OBJ page
        let obj_name_bytes = utf16le(mutant_name);
        let obj_name_len = obj_name_bytes.len() as u16;
        let obj_str_vaddr = OBJ_VADDR + 0x200;
        let mut obj_page = vec![0u8; 4096];
        // _OBJECT_HEADER_NAME_INFO.Name (_UNICODE_STRING) at +0x10
        obj_page[0x10..0x12].copy_from_slice(&obj_name_len.to_le_bytes());
        obj_page[0x12..0x14].copy_from_slice(&obj_name_len.to_le_bytes());
        obj_page[0x18..0x20].copy_from_slice(&obj_str_vaddr.to_le_bytes());
        // _OBJECT_HEADER at +0x20: InfoMask=0x02, TypeIndex=4
        obj_page[0x20 + 0x1a] = 0x02;
        obj_page[0x20 + 0x18] = 4;
        // Inline name string at +0x200
        obj_page[0x200..0x200 + obj_name_bytes.len()].copy_from_slice(&obj_name_bytes);

        // _KMUTANT body at +0x50
        let body_off = 0x50usize;
        if pid != 0 || tid != 0 {
            obj_page[body_off + KMUTANT_OWNER_THREAD as usize
                ..body_off + KMUTANT_OWNER_THREAD as usize + 8]
                .copy_from_slice(&ETHREAD_VADDR.to_le_bytes());
        }
        obj_page[body_off + KMUTANT_ABANDONED as usize] = u8::from(abandoned);

        // _ETHREAD: Cid at +0x620
        let mut ethread_page = vec![0u8; 0x700];
        ethread_page[ETHREAD_CID as usize..ETHREAD_CID as usize + 8]
            .copy_from_slice(&pid.to_le_bytes());
        ethread_page[ETHREAD_CID as usize + 8..ETHREAD_CID as usize + 16]
            .copy_from_slice(&tid.to_le_bytes());

        // sym page: pointer to ROOT_VADDR
        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&ROOT_VADDR.to_le_bytes());

        // ObTypeIndexTable: slot[4] → MTYPE_VADDR
        let mut table_page = vec![0u8; 4096];
        table_page[4 * 8..4 * 8 + 8].copy_from_slice(&MTYPE_VADDR.to_le_bytes());

        // Root directory: bucket[0] → ENTRY_VADDR
        let mut root_page = vec![0u8; 4096];
        root_page[0..8].copy_from_slice(&ENTRY_VADDR.to_le_bytes());

        // Directory entry: { ChainLink=0, Object=OBJ_VADDR+0x50 }
        let body_vaddr = OBJ_VADDR + 0x50;
        let mut entry_page = vec![0u8; 4096];
        entry_page[0..8].copy_from_slice(&0u64.to_le_bytes());
        entry_page[8..16].copy_from_slice(&body_vaddr.to_le_bytes());

        PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .map_4k(OBJ_TABLE_VADDR, OBJ_TABLE_PADDR, flags::WRITABLE)
            .write_phys(OBJ_TABLE_PADDR, &table_page)
            .map_4k(MTYPE_VADDR, MTYPE_PADDR, flags::WRITABLE)
            .write_phys(MTYPE_PADDR, &mtype_page)
            .map_4k(ROOT_VADDR, ROOT_PADDR, flags::WRITABLE)
            .write_phys(ROOT_PADDR, &root_page)
            .map_4k(OBJ_VADDR, OBJ_PADDR, flags::WRITABLE)
            .write_phys(OBJ_PADDR, &obj_page)
            .map_4k(ENTRY_VADDR, ENTRY_PADDR, flags::WRITABLE)
            .write_phys(ENTRY_PADDR, &entry_page)
            .map_4k(ETHREAD_VADDR, ETHREAD_PADDR, flags::WRITABLE)
            .write_phys(ETHREAD_PADDR, &ethread_page)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn walk_mutants_empty() {
        let reader = make_test_reader(build_empty_root());
        let result = walk_mutants(&reader).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn walk_mutants_single() {
        let ptb = build_single_mutant("Evil_Mutex_C2", 1234, 5678, false);
        let reader = make_test_reader(ptb);
        let mutants = walk_mutants(&reader).unwrap();
        assert_eq!(mutants.len(), 1);
        let m = &mutants[0];
        assert_eq!(m.name, "Evil_Mutex_C2");
        assert_eq!(m.owner_pid, 1234);
        assert_eq!(m.owner_thread_id, 5678);
        assert!(!m.abandoned);
    }

    /// walk_mutants: abandoned mutant is correctly read.
    #[test]
    fn walk_mutants_abandoned() {
        let ptb = build_single_mutant("AbandonedMutex", 999, 111, true);
        let reader = make_test_reader(ptb);
        let mutants = walk_mutants(&reader).unwrap();
        assert_eq!(mutants.len(), 1);
        assert!(mutants[0].abandoned);
    }

    /// resolve_type_name: ob_table_addr = 0 → returns "<unknown>".
    #[test]
    fn resolve_type_name_null_obj_type_addr_returns_unknown() {
        let isf = make_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let name = resolve_type_name(&reader, 0, 4);
        assert_eq!(name, "<unknown>");
    }

    /// resolve_type_name: slot read fails (unmapped address) → returns "<unknown>".
    #[test]
    fn resolve_type_name_unmapped_table_returns_unknown() {
        let isf = make_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let name = resolve_type_name(&reader, 0xFFFF_DEAD_0000_0000, 4);
        assert_eq!(name, "<unknown>");
    }

    /// walk_directory_recursive: depth >= MAX_DIR_DEPTH guard returns Ok early.
    #[test]
    fn walk_directory_recursive_depth_limit_returns_ok() {
        let reader = make_test_reader(PageTableBuilder::new());
        let mut results = Vec::new();
        walk_directory_recursive(
            &reader,
            0xFFFF_DEAD_0000_0000,
            0,
            0x30,
            MAX_DIR_DEPTH,
            &mut results,
        );
        assert!(results.is_empty());
    }

    /// MutantInfo serializes correctly.
    #[test]
    fn mutant_info_serializes() {
        let info = MutantInfo {
            name: "TestMutex".to_string(),
            owner_pid: 42,
            owner_thread_id: 84,
            abandoned: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("TestMutex"));
        assert!(json.contains("42"));
    }

    /// walk_mutants: mutant with owner_thread = 0 → owner_pid and owner_thread_id are 0.
    #[test]
    fn walk_mutants_no_owner_thread() {
        // Build a mutant with pid=0, tid=0 (no ETHREAD mapping needed)
        let ptb = build_single_mutant("NoOwnerMutex", 0, 0, false);
        let reader = make_test_reader(ptb);
        let mutants = walk_mutants(&reader).unwrap();
        assert_eq!(mutants.len(), 1);
        assert_eq!(mutants[0].owner_pid, 0);
        assert_eq!(mutants[0].owner_thread_id, 0);
    }

    /// resolve_type_name: valid slot and type with empty name → returns "<unknown>".
    #[test]
    fn resolve_type_name_empty_name_returns_unknown() {
        // ObTypeIndexTable slot 1 → TYPE_VADDR; _OBJECT_TYPE.Name has Length=0
        const TABLE_VADDR: u64 = OB_TYPE_INDEX_TABLE_VADDR;
        const TABLE_PADDR: u64 = 0x00C0_0000;
        const TYPE_VADDR: u64 = 0xFFFF_8000_0060_0000;
        const TYPE_PADDR: u64 = 0x0060_0000;

        let isf = make_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut table_page = vec![0u8; 4096];
        table_page[8..8 + 8].copy_from_slice(&TYPE_VADDR.to_le_bytes());

        // _OBJECT_TYPE with Name Length=0 (empty _UNICODE_STRING)
        let type_page = vec![0u8; 4096];

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(TABLE_VADDR, TABLE_PADDR, flags::WRITABLE)
            .write_phys(TABLE_PADDR, &table_page)
            .map_4k(TYPE_VADDR, TYPE_PADDR, flags::WRITABLE)
            .write_phys(TYPE_PADDR, &type_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let name = resolve_type_name(&reader, TABLE_VADDR, 1);
        assert_eq!(name, "<unknown>");
    }
}
