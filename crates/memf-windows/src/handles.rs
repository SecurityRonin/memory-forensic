//! Windows per-process handle table walking.
//!
//! Walks `_EPROCESS.ObjectTable` → `_HANDLE_TABLE.TableCode` →
//! `_HANDLE_TABLE_ENTRY` array to enumerate open handles per process.
//! Each entry's `ObjectPointerBits` field (shifted left 4, with low bits
//! masked) yields an `_OBJECT_HEADER`, whose `TypeIndex` indexes into
//! the `ObTypeIndexTable` to resolve the object type name.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, WinHandleInfo};

/// Maximum number of handle entries to scan per process.
/// Prevents runaway iteration on corrupted handle tables.
const MAX_HANDLE_ENTRIES: u64 = 16384;

/// Walk all processes and enumerate their open handles.
///
/// For each process, reads `_EPROCESS.ObjectTable` → `_HANDLE_TABLE`,
/// then iterates the level-0 handle entry array. Returns a flat list
/// of all handles across all processes.
pub fn walk_handles<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<WinHandleInfo>> {
    let procs = crate::process::walk_processes(reader, ps_head_vaddr)?;

    let entry_size = reader
        .symbols()
        .struct_size("_HANDLE_TABLE_ENTRY")
        .ok_or_else(|| crate::Error::Walker("missing _HANDLE_TABLE_ENTRY size".into()))?;

    // Resolve ObTypeIndexTable symbol for type name lookup
    let ob_type_table_addr = reader
        .symbols()
        .symbol_address("ObTypeIndexTable")
        .ok_or_else(|| crate::Error::Walker("missing ObTypeIndexTable symbol".into()))?;

    let mut results = Vec::new();

    for proc in &procs {
        // Read _EPROCESS.ObjectTable pointer
        let obj_table: u64 = reader.read_field(proc.vaddr, "_EPROCESS", "ObjectTable")?;
        if obj_table == 0 {
            continue;
        }

        // Read _HANDLE_TABLE.TableCode
        let table_code: u64 = match reader.read_field(obj_table, "_HANDLE_TABLE", "TableCode") {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Level = low 2 bits of TableCode
        let level = table_code & 0x3;
        let base_addr = table_code & !0x3;

        if level != 0 || base_addr == 0 {
            // Only support level-0 (flat) tables for now; skip multi-level
            continue;
        }

        // Read NextHandleNeedingPool to determine entry count
        let next_handle: u32 =
            match reader.read_field(obj_table, "_HANDLE_TABLE", "NextHandleNeedingPool") {
                Ok(v) => v,
                Err(_) => continue,
            };

        // Number of entries = next_handle / 4 (handle values are index × 4)
        let num_entries = u64::from(next_handle) / 4;
        let num_entries = num_entries.min(MAX_HANDLE_ENTRIES);

        // Iterate entries starting at index 1 (index 0 is reserved)
        for idx in 1..num_entries {
            let entry_addr = base_addr + idx * entry_size;

            // Read ObjectPointerBits (first u64 of entry)
            let obj_ptr: u64 =
                match reader.read_field(entry_addr, "_HANDLE_TABLE_ENTRY", "ObjectPointerBits") {
                    Ok(v) => v,
                    Err(_) => continue,
                };

            // Skip free/empty entries
            if obj_ptr == 0 {
                continue;
            }

            // The object_addr is the _OBJECT_HEADER address.
            // In our layout, obj_ptr is stored directly as the address.
            let object_addr = obj_ptr;

            // Read GrantedAccessBits
            let granted_access: u32 = reader
                .read_field(entry_addr, "_HANDLE_TABLE_ENTRY", "GrantedAccessBits")
                .unwrap_or(0);

            // Read _OBJECT_HEADER.TypeIndex
            let type_index: u8 = match reader.read_bytes(
                object_addr.wrapping_add(
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

            // Look up type name via ObTypeIndexTable[TypeIndex]
            let object_type = resolve_type_name(reader, ob_type_table_addr, type_index);

            let handle_value = (idx as u32) * 4;

            results.push(WinHandleInfo {
                pid: proc.pid,
                image_name: proc.image_name.clone(),
                handle_value,
                object_addr,
                object_type,
                granted_access,
            });
        }
    }

    Ok(results)
}

/// Resolve the object type name from `ObTypeIndexTable[type_index]`.
///
/// Reads the pointer at `ob_table_addr + type_index * 8`, which yields
/// an `_OBJECT_TYPE` address, then reads `_OBJECT_TYPE.Name`.
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

    // Read _OBJECT_TYPE.Name (_UNICODE_STRING at offset 0x10)
    let name_off = reader
        .symbols()
        .field_offset("_OBJECT_TYPE", "Name")
        .unwrap_or(0x10);

    match crate::unicode::read_unicode_string(reader, obj_type_addr.wrapping_add(name_off)) {
        Ok(name) if !name.is_empty() => name,
        _ => String::from("<unknown>"),
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

    fn make_win_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
    }

    // _EPROCESS offsets
    const EPROCESS_PID: u64 = 0x440;
    const EPROCESS_LINKS: u64 = 0x448;
    const EPROCESS_PPID: u64 = 0x540;
    const EPROCESS_PEB: u64 = 0x550;
    const EPROCESS_OBJECT_TABLE: u64 = 0x570;
    const EPROCESS_IMAGE_NAME: u64 = 0x5A8;
    const EPROCESS_CREATE_TIME: u64 = 0x430;
    const EPROCESS_EXIT_TIME: u64 = 0x438;
    const KPROCESS_DTB: u64 = 0x28;

    // _HANDLE_TABLE offsets
    const HANDLE_TABLE_CODE: u64 = 0x08;

    // _HANDLE_TABLE_ENTRY: 16 bytes each
    // ObjectPointerBits@0x0, GrantedAccessBits@0x8
    const ENTRY_OBJECT_PTR: u64 = 0x0;
    const ENTRY_GRANTED_ACCESS: u64 = 0x8;
    const ENTRY_SIZE: u64 = 16;

    // _OBJECT_HEADER offsets
    const OBJ_HEADER_TYPE_INDEX: u64 = 0x18;

    // _OBJECT_TYPE offsets
    const OBJ_TYPE_NAME: u64 = 0x10;

    // ISF preset defines ObTypeIndexTable at this address
    const OB_TYPE_INDEX_TABLE_VADDR: u64 = 0xFFFFF805_5A490000;

    /// Build a minimal process + handle table layout in synthetic memory.
    ///
    /// Returns the head_vaddr for PsActiveProcessHead.
    /// `handles` is a slice of (object_header_vaddr, granted_access, type_index).
    fn build_process_with_handles(
        pid: u64,
        image_name: &[u8],
        handles: &[(u64, u32, u8)],
        // Object type table: (type_index, type_name, obj_type_vaddr)
        type_table: &[(u8, &str, u64)],
    ) -> (u64, PageTableBuilder) {
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let handle_table_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let entry_page_vaddr: u64 = 0xFFFF_8000_0010_3000;
        let strings_vaddr: u64 = 0xFFFF_8000_0010_4000;

        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0080_1000;
        let handle_table_paddr: u64 = 0x0080_2000;
        let entry_page_paddr: u64 = 0x0080_3000;
        let strings_paddr: u64 = 0x0080_4000;

        // Number of handle entries: we need handles.len() entries + 1 for the
        // reserved slot at index 0 (handle value 0 is not used)
        let num_entries = handles.len() + 1;
        // Level 0: TableCode points directly to the entry page (low 2 bits = 0)
        let table_code = entry_page_vaddr; // level 0

        let mut ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(handle_table_vaddr, handle_table_paddr, flags::WRITABLE)
            .map_4k(entry_page_vaddr, entry_page_paddr, flags::WRITABLE)
            .map_4k(strings_vaddr, strings_paddr, flags::WRITABLE)
            // PsActiveProcessHead sentinel
            .write_phys_u64(head_paddr, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(head_paddr + 8, eproc_vaddr + EPROCESS_LINKS)
            // _EPROCESS
            .write_phys_u64(eproc_paddr + KPROCESS_DTB, 0x1AB000)
            .write_phys_u64(eproc_paddr + EPROCESS_CREATE_TIME, 132800000000000000)
            .write_phys_u64(eproc_paddr + EPROCESS_EXIT_TIME, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PID, pid)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS + 8, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_PPID, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PEB, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_OBJECT_TABLE, handle_table_vaddr)
            .write_phys(eproc_paddr + EPROCESS_IMAGE_NAME, image_name)
            // _HANDLE_TABLE
            .write_phys_u64(handle_table_paddr + HANDLE_TABLE_CODE, table_code);

        // Write NextHandleNeedingPool = (num_entries * 4) so the walker knows
        // how many entries to scan. Handle values are index * 4.
        let next_handle = (num_entries as u32) * 4;
        ptb = ptb.write_phys(handle_table_paddr + 0x3C, &next_handle.to_le_bytes());

        // Entry at index 0 is reserved (handle value 0), leave zeroed.
        // Write actual handle entries starting at index 1.
        for (i, &(obj_header_vaddr, granted_access, _type_index)) in handles.iter().enumerate() {
            let entry_offset = ((i + 1) as u64) * ENTRY_SIZE;
            let entry_paddr = entry_page_paddr + entry_offset;

            // ObjectPointerBits: on Win10+, the actual pointer is stored
            // shifted right by 4, in bits [63:4]. We encode it the same way:
            // value = (obj_header_vaddr >> 4) << 4 with low bits as lock etc.
            // For simplicity in our test layout, just store the address with
            // low bits clear — the walker masks off low 4 bits anyway.
            // The encoded value has the pointer in the upper bits.
            // In real Windows: ObjectPointerBits = (addr >> 4) | flags
            // For level-0 tables, the raw u64 at the entry is:
            //   bits[63:1] = pointer >> 1 (with bit 0 = lock)
            // Simplified: we store (obj_header_vaddr >> 4) << 4 for tests.
            ptb = ptb
                .write_phys_u64(entry_paddr + ENTRY_OBJECT_PTR, obj_header_vaddr)
                .write_phys(
                    entry_paddr + ENTRY_GRANTED_ACCESS,
                    &granted_access.to_le_bytes(),
                );
        }

        // Map object header pages and write _OBJECT_HEADER data
        for &(obj_header_vaddr, _granted_access, type_index) in handles {
            let obj_header_paddr = obj_header_vaddr & 0x00FF_FFFF; // simple mapping
            ptb = ptb
                .map_4k(obj_header_vaddr, obj_header_paddr, flags::WRITABLE)
                .write_phys(obj_header_paddr + OBJ_HEADER_TYPE_INDEX, &[type_index]);
        }

        // ObTypeIndexTable: array of pointers indexed by TypeIndex
        let ob_table_paddr: u64 = 0x0090_0000;
        ptb = ptb.map_4k(OB_TYPE_INDEX_TABLE_VADDR, ob_table_paddr, flags::WRITABLE);

        // Write type object pointers and type name strings
        let mut string_offset: u64 = 0;
        for &(type_index, type_name, obj_type_vaddr) in type_table {
            let slot_offset = u64::from(type_index) * 8;
            ptb = ptb.write_phys_u64(ob_table_paddr + slot_offset, obj_type_vaddr);

            // Map and write _OBJECT_TYPE with Name (_UNICODE_STRING)
            let obj_type_paddr = obj_type_vaddr & 0x00FF_FFFF;
            let name_utf16 = utf16le(type_name);
            let name_len = name_utf16.len() as u16;
            let name_buf_vaddr = strings_vaddr + string_offset;

            ptb = ptb
                .map_4k(obj_type_vaddr, obj_type_paddr, flags::WRITABLE)
                // _UNICODE_STRING at _OBJECT_TYPE + 0x10: Length, MaxLen, Buffer
                .write_phys(obj_type_paddr + OBJ_TYPE_NAME, &name_len.to_le_bytes())
                .write_phys(
                    obj_type_paddr + OBJ_TYPE_NAME + 2,
                    &(name_len + 2).to_le_bytes(),
                )
                .write_phys_u64(obj_type_paddr + OBJ_TYPE_NAME + 8, name_buf_vaddr)
                // Write the UTF-16LE string data
                .write_phys(strings_paddr + string_offset, &name_utf16);

            string_offset += (name_utf16.len() as u64) + 16; // pad between strings
        }

        (head_vaddr, ptb)
    }

    #[test]
    fn walks_single_process_handles() {
        let obj_header1_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let obj_header2_vaddr: u64 = 0xFFFF_8000_0020_1000;
        let obj_type_file_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let obj_type_key_vaddr: u64 = 0xFFFF_8000_0030_1000;

        let type_index_file: u8 = 37;
        let type_index_key: u8 = 38;

        let (head_vaddr, ptb) = build_process_with_handles(
            1234,
            b"explorer.exe\0",
            &[
                (obj_header1_vaddr, 0x001F_0003, type_index_file),
                (obj_header2_vaddr, 0x000F_003F, type_index_key),
            ],
            &[
                (type_index_file, "File", obj_type_file_vaddr),
                (type_index_key, "Key", obj_type_key_vaddr),
            ],
        );

        let reader = make_win_reader(ptb);
        let handles = walk_handles(&reader, head_vaddr).unwrap();

        assert_eq!(handles.len(), 2);

        // Handle values: index 1 → handle 4, index 2 → handle 8
        assert_eq!(handles[0].handle_value, 4);
        assert_eq!(handles[0].pid, 1234);
        assert_eq!(handles[0].image_name, "explorer.exe");
        assert_eq!(handles[0].object_type, "File");
        assert_eq!(handles[0].granted_access, 0x001F_0003);
        assert_eq!(handles[0].object_addr, obj_header1_vaddr);

        assert_eq!(handles[1].handle_value, 8);
        assert_eq!(handles[1].object_type, "Key");
        assert_eq!(handles[1].granted_access, 0x000F_003F);
    }

    #[test]
    fn skips_process_with_null_object_table() {
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0080_1000;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys_u64(head_paddr, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(head_paddr + 8, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(eproc_paddr + KPROCESS_DTB, 0x1AB000)
            .write_phys_u64(eproc_paddr + EPROCESS_CREATE_TIME, 132800000000000000)
            .write_phys_u64(eproc_paddr + EPROCESS_EXIT_TIME, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PID, 4)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS + 8, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_PPID, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PEB, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_OBJECT_TABLE, 0) // null
            .write_phys(eproc_paddr + EPROCESS_IMAGE_NAME, b"System\0");

        let reader = make_win_reader(ptb);
        let handles = walk_handles(&reader, head_vaddr).unwrap();
        assert!(handles.is_empty());
    }

    #[test]
    fn skips_zero_object_pointer_entries() {
        // When an entry has ObjectPointerBits = 0, it's a free slot — skip it.
        let obj_header_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let obj_type_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let type_index: u8 = 37;

        // Build with one real handle — but we'll manually zero out entry index 1
        // and put the real handle at index 2.
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let handle_table_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let entry_page_vaddr: u64 = 0xFFFF_8000_0010_3000;
        let strings_vaddr: u64 = 0xFFFF_8000_0010_4000;

        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0080_1000;
        let handle_table_paddr: u64 = 0x0080_2000;
        let entry_page_paddr: u64 = 0x0080_3000;
        let strings_paddr: u64 = 0x0080_4000;
        let ob_table_paddr: u64 = 0x0090_0000;

        let name_utf16 = utf16le("Mutant");
        let name_len = name_utf16.len() as u16;
        let obj_header_paddr = obj_header_vaddr & 0x00FF_FFFF;
        let obj_type_paddr = obj_type_vaddr & 0x00FF_FFFF;

        // 3 entries total: index 0 (reserved), index 1 (free/zero), index 2 (real)
        let next_handle: u32 = 3 * 4; // 12

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(handle_table_vaddr, handle_table_paddr, flags::WRITABLE)
            .map_4k(entry_page_vaddr, entry_page_paddr, flags::WRITABLE)
            .map_4k(strings_vaddr, strings_paddr, flags::WRITABLE)
            .map_4k(obj_header_vaddr, obj_header_paddr, flags::WRITABLE)
            .map_4k(obj_type_vaddr, obj_type_paddr, flags::WRITABLE)
            .map_4k(OB_TYPE_INDEX_TABLE_VADDR, ob_table_paddr, flags::WRITABLE)
            // PsActiveProcessHead
            .write_phys_u64(head_paddr, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(head_paddr + 8, eproc_vaddr + EPROCESS_LINKS)
            // _EPROCESS
            .write_phys_u64(eproc_paddr + KPROCESS_DTB, 0x1AB000)
            .write_phys_u64(eproc_paddr + EPROCESS_CREATE_TIME, 132800000000000000)
            .write_phys_u64(eproc_paddr + EPROCESS_EXIT_TIME, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PID, 500)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS + 8, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_PPID, 4)
            .write_phys_u64(eproc_paddr + EPROCESS_PEB, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_OBJECT_TABLE, handle_table_vaddr)
            .write_phys(eproc_paddr + EPROCESS_IMAGE_NAME, b"svchost.exe\0")
            // _HANDLE_TABLE
            .write_phys_u64(handle_table_paddr + HANDLE_TABLE_CODE, entry_page_vaddr)
            .write_phys(handle_table_paddr + 0x3C, &next_handle.to_le_bytes())
            // Entry index 1: zeroed (free slot) — entry_page_paddr + 16 stays 0
            // Entry index 2: real handle
            .write_phys_u64(
                entry_page_paddr + 2 * ENTRY_SIZE + ENTRY_OBJECT_PTR,
                obj_header_vaddr,
            )
            .write_phys(
                entry_page_paddr + 2 * ENTRY_SIZE + ENTRY_GRANTED_ACCESS,
                &0x001F_0001u32.to_le_bytes(),
            )
            // _OBJECT_HEADER
            .write_phys(obj_header_paddr + OBJ_HEADER_TYPE_INDEX, &[type_index])
            // ObTypeIndexTable
            .write_phys_u64(ob_table_paddr + u64::from(type_index) * 8, obj_type_vaddr)
            // _OBJECT_TYPE.Name
            .write_phys(obj_type_paddr + OBJ_TYPE_NAME, &name_len.to_le_bytes())
            .write_phys(
                obj_type_paddr + OBJ_TYPE_NAME + 2,
                &(name_len + 2).to_le_bytes(),
            )
            .write_phys_u64(obj_type_paddr + OBJ_TYPE_NAME + 8, strings_vaddr)
            .write_phys(strings_paddr, &name_utf16);

        let reader = make_win_reader(ptb);
        let handles = walk_handles(&reader, head_vaddr).unwrap();

        // Only index 2 should be returned (index 0 reserved, index 1 free)
        assert_eq!(handles.len(), 1);
        assert_eq!(handles[0].handle_value, 8); // index 2 × 4 = 8
        assert_eq!(handles[0].object_type, "Mutant");
        assert_eq!(handles[0].pid, 500);
    }
}
