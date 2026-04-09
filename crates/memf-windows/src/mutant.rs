//! Windows kernel named mutant (mutex) scanner.
//!
//! Walks the kernel Object Manager namespace tree starting from
//! `ObpRootDirectoryObject`, filters for objects whose type name is
//! "Mutant", and extracts name, owner PID/TID, and abandoned status
//! from each `_KMUTANT` body.  Named mutexes are a key DFIR artifact
//! because malware frequently creates them for single-instance execution.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::object_directory::{read_object_name, walk_directory};
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
    todo!()
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
    todo!()
}

/// Resolve the object type name from `ObTypeIndexTable[type_index]`.
fn resolve_type_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ob_table_addr: u64,
    type_index: u8,
) -> String {
    todo!()
}

/// Read mutant details from the object body (`_KMUTANT`).
fn read_mutant_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    object_body_addr: u64,
    name: String,
) -> Result<MutantInfo> {
    todo!()
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
        s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
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
        write_unicode_string(ptb, type_paddr + OBJ_TYPE_NAME, str_vaddr, str_paddr, type_name)
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
        let ptb = write_unicode_string(
            ptb,
            ni_paddr + NAME_INFO_NAME,
            str_vaddr,
            str_paddr,
            name,
        );

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
    // Tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn walk_mutants_empty() {
        // ObpRootDirectoryObject points to a root directory with no entries.
        // No mutant objects → empty result.
        let root_dir_ptr_vaddr = OBP_ROOT_DIR_OBJ_VADDR;
        let root_dir_ptr_paddr: u64 = 0x0010_0000;
        let root_dir_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let root_dir_paddr: u64 = 0x0020_0000;

        let ptb = PageTableBuilder::new()
            // ObpRootDirectoryObject: a pointer to the root _OBJECT_DIRECTORY
            .map_4k(root_dir_ptr_vaddr, root_dir_ptr_paddr, flags::WRITABLE)
            .write_phys_u64(root_dir_ptr_paddr, root_dir_vaddr)
            // Empty root directory (all 37 hash buckets = 0)
            .map_4k(root_dir_vaddr, root_dir_paddr, flags::WRITABLE);

        let reader = make_test_reader(ptb);
        let mutants = walk_mutants(&reader).unwrap();
        assert!(mutants.is_empty());
    }

    #[test]
    fn walk_mutants_single() {
        // Set up: one named mutant "MyMalwareMutex" in \BaseNamedObjects
        // with an owning thread that has PID=1234, TID=5678.

        // ── Address layout ──
        let root_dir_ptr_vaddr = OBP_ROOT_DIR_OBJ_VADDR;
        let root_dir_ptr_paddr: u64 = 0x0010_0000;

        // Root _OBJECT_DIRECTORY
        let root_dir_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let root_dir_paddr: u64 = 0x0020_0000;

        // "BaseNamedObjects" subdirectory — named object (name_info + header + body)
        let bno_obj_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let bno_obj_paddr: u64 = 0x0030_0000;
        let bno_name_str_vaddr: u64 = 0xFFFF_8000_0020_0800;
        let bno_name_str_paddr: u64 = 0x0030_0800;
        // The body of the BaseNamedObjects object IS the subdirectory
        // (its body_vaddr will be computed by write_named_object)

        // Root directory entry pointing to BaseNamedObjects
        let root_entry_vaddr: u64 = 0xFFFF_8000_0020_0C00;
        let root_entry_paddr: u64 = 0x0030_0C00;

        // Mutant object (name_info + header + body)
        let mutant_obj_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let mutant_obj_paddr: u64 = 0x0040_0000;
        let mutant_name_str_vaddr: u64 = 0xFFFF_8000_0030_0800;
        let mutant_name_str_paddr: u64 = 0x0040_0800;

        // Subdirectory entry pointing to mutant
        let subdir_entry_vaddr: u64 = 0xFFFF_8000_0030_0C00;
        let subdir_entry_paddr: u64 = 0x0040_0C00;

        // _OBJECT_TYPE for "Mutant" type
        let mutant_type_vaddr: u64 = 0xFFFF_8000_0050_0000;
        let mutant_type_paddr: u64 = 0x0060_0000;
        let mutant_type_str_vaddr: u64 = 0xFFFF_8000_0050_0800;
        let mutant_type_str_paddr: u64 = 0x0060_0800;
        let mutant_type_index: u8 = 17;

        // _OBJECT_TYPE for "Directory" type (for BaseNamedObjects)
        let dir_type_vaddr: u64 = 0xFFFF_8000_0050_1000;
        let dir_type_paddr: u64 = 0x0061_0000;
        let dir_type_str_vaddr: u64 = 0xFFFF_8000_0050_1800;
        let dir_type_str_paddr: u64 = 0x0061_0800;
        let dir_type_index: u8 = 3;

        // ObTypeIndexTable
        let ob_table_paddr: u64 = 0x0070_0000;

        // _ETHREAD for the owning thread
        let ethread_vaddr: u64 = 0xFFFF_8000_0060_0000;
        let ethread_paddr: u64 = 0x0080_0000;

        // ── Build ──
        let mut ptb = PageTableBuilder::new()
            // ObpRootDirectoryObject pointer
            .map_4k(root_dir_ptr_vaddr, root_dir_ptr_paddr, flags::WRITABLE)
            .write_phys_u64(root_dir_ptr_paddr, root_dir_vaddr)
            // Root directory (empty initially — will set bucket)
            .map_4k(root_dir_vaddr, root_dir_paddr, flags::WRITABLE)
            // BaseNamedObjects pages
            .map_4k(bno_obj_vaddr, bno_obj_paddr, flags::WRITABLE)
            // Mutant pages
            .map_4k(mutant_obj_vaddr, mutant_obj_paddr, flags::WRITABLE)
            // ObTypeIndexTable
            .map_4k(OB_TYPE_INDEX_TABLE_VADDR, ob_table_paddr, flags::WRITABLE)
            // _ETHREAD
            .map_4k(ethread_vaddr, ethread_paddr, flags::WRITABLE);

        // Write _OBJECT_TYPE for "Directory" (type_index = 3)
        ptb = write_object_type(
            ptb,
            dir_type_vaddr,
            dir_type_paddr,
            dir_type_str_vaddr,
            dir_type_str_paddr,
            "Directory",
        );
        ptb = ptb.write_phys_u64(
            ob_table_paddr + u64::from(dir_type_index) * 8,
            dir_type_vaddr,
        );

        // Write _OBJECT_TYPE for "Mutant" (type_index = 17)
        ptb = write_object_type(
            ptb,
            mutant_type_vaddr,
            mutant_type_paddr,
            mutant_type_str_vaddr,
            mutant_type_str_paddr,
            "Mutant",
        );
        ptb = ptb.write_phys_u64(
            ob_table_paddr + u64::from(mutant_type_index) * 8,
            mutant_type_vaddr,
        );

        // Write BaseNamedObjects as a named object of type "Directory"
        let (bno_body_vaddr, ptb2) = write_named_object(
            ptb,
            bno_obj_vaddr,
            bno_obj_paddr,
            bno_name_str_vaddr,
            bno_name_str_paddr,
            "BaseNamedObjects",
            dir_type_index,
        );
        ptb = ptb2;

        // Root directory: entry in bucket 0 → BaseNamedObjects
        ptb = ptb.map_4k(root_entry_vaddr, root_entry_paddr, flags::WRITABLE);
        ptb = write_dir_entry(ptb, root_entry_paddr, 0, bno_body_vaddr);
        ptb = set_bucket(ptb, root_dir_paddr, 0, root_entry_vaddr);

        // Write mutant object "MyMalwareMutex" with type_index = 17
        let (mutant_body_vaddr, ptb2) = write_named_object(
            ptb,
            mutant_obj_vaddr,
            mutant_obj_paddr,
            mutant_name_str_vaddr,
            mutant_name_str_paddr,
            "MyMalwareMutex",
            mutant_type_index,
        );
        ptb = ptb2;

        // Write _KMUTANT fields in the body
        // OwnerThread at body + 0x28 → ethread_vaddr
        ptb = ptb.write_phys_u64(
            mutant_obj_paddr + (mutant_body_vaddr - mutant_obj_vaddr) + KMUTANT_OWNER_THREAD,
            ethread_vaddr,
        );
        // Abandoned = 0 (not abandoned)
        ptb = ptb.write_phys(
            mutant_obj_paddr + (mutant_body_vaddr - mutant_obj_vaddr) + KMUTANT_ABANDONED,
            &[0u8],
        );

        // Subdirectory (BaseNamedObjects body): entry in bucket 0 → mutant
        ptb = ptb.map_4k(subdir_entry_vaddr, subdir_entry_paddr, flags::WRITABLE);
        ptb = write_dir_entry(ptb, subdir_entry_paddr, 0, mutant_body_vaddr);
        // The BaseNamedObjects body is the subdirectory — set bucket 0
        let bno_body_paddr = bno_obj_paddr + (bno_body_vaddr - bno_obj_vaddr);
        ptb = set_bucket(ptb, bno_body_paddr, 0, subdir_entry_vaddr);

        // Write _ETHREAD.Cid: UniqueProcess = 1234, UniqueThread = 5678
        ptb = ptb
            .write_phys_u64(ethread_paddr + ETHREAD_CID + CID_UNIQUE_PROCESS, 1234)
            .write_phys_u64(ethread_paddr + ETHREAD_CID + CID_UNIQUE_THREAD, 5678);

        let reader = make_test_reader(ptb);
        let mutants = walk_mutants(&reader).unwrap();

        assert_eq!(mutants.len(), 1);
        assert_eq!(mutants[0].name, "MyMalwareMutex");
        assert_eq!(mutants[0].owner_pid, 1234);
        assert_eq!(mutants[0].owner_thread_id, 5678);
        assert!(!mutants[0].abandoned);
    }
}
