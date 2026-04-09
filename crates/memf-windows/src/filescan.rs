//! Windows file object scanning and extraction.
//!
//! Filters handle table entries for "File" object types and reads
//! the underlying `_FILE_OBJECT` structures to extract file name,
//! device name, flags, size, and sharing disposition.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{FileObjectInfo, Result, WinHandleInfo};

/// Maximum number of file objects to return (safety limit).
const MAX_FILE_OBJECTS: usize = 10_000;

/// Walk a list of handles and extract file object information.
///
/// Filters `handles` for entries whose `object_type` is `"File"`,
/// then reads each `_FILE_OBJECT` at the handle's `object_addr` to
/// extract file name, flags, device name, and sharing disposition.
///
/// Returns file objects sorted by file name.
pub fn walk_file_objects<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
    _handles: &[WinHandleInfo],
) -> Result<Vec<FileObjectInfo>> {
    todo!("DFIR-13: implement walk_file_objects")
}

/// Convenience function that combines handle walking with file object extraction.
///
/// Calls `walk_handles` to enumerate all process handles, then passes them
/// to `walk_file_objects`.  Falls back to an empty `Vec` on handle walking failure.
pub fn scan_file_objects<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
) -> Result<Vec<FileObjectInfo>> {
    todo!("DFIR-13: implement scan_file_objects")
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

    // _OBJECT_HEADER offsets (from ISF preset)
    const OBJ_HEADER_BODY: u64 = 0x30;

    // _FILE_OBJECT offsets (from ISF preset)
    const FO_DEVICE_OBJECT: u64 = 0x08;
    const FO_FLAGS: u64 = 0x44;
    const FO_DELETE_PENDING: u64 = 0x48;
    const FO_FILENAME: u64 = 0x58; // _UNICODE_STRING
    const FO_CURRENT_BYTE_OFFSET: u64 = 0x70;
    const FO_SHARED_READ: u64 = 0x78;
    const FO_SHARED_WRITE: u64 = 0x79;
    const FO_SHARED_DELETE: u64 = 0x7A;

    /// Empty handles list should produce an empty Vec.
    #[test]
    fn walk_file_objects_empty_handles() {
        let ptb = PageTableBuilder::new();
        let reader = make_win_reader(ptb);
        let handles: Vec<WinHandleInfo> = Vec::new();

        let result = walk_file_objects(&reader, &handles).unwrap();
        assert!(result.is_empty());
    }

    /// Handles list with no "File" types should produce an empty Vec.
    #[test]
    fn walk_file_objects_no_file_handles() {
        let ptb = PageTableBuilder::new();
        let reader = make_win_reader(ptb);

        let handles = vec![
            WinHandleInfo {
                pid: 4,
                image_name: "System".into(),
                handle_value: 4,
                object_addr: 0xFFFF_8000_0020_0000,
                object_type: "Key".into(),
                granted_access: 0x000F_003F,
            },
            WinHandleInfo {
                pid: 4,
                image_name: "System".into(),
                handle_value: 8,
                object_addr: 0xFFFF_8000_0020_1000,
                object_type: "Mutant".into(),
                granted_access: 0x001F_0001,
            },
        ];

        let result = walk_file_objects(&reader, &handles).unwrap();
        assert!(result.is_empty());
    }

    /// A synthetic _FILE_OBJECT with a file handle should be extracted correctly.
    #[test]
    fn walk_file_objects_with_file() {
        // Layout:
        // _OBJECT_HEADER at 0xFFFF_8000_0020_0000 (paddr 0x0080_0000)
        // _FILE_OBJECT body at _OBJECT_HEADER + 0x30 = 0xFFFF_8000_0020_0030
        // Filename string data at 0xFFFF_8000_0020_1000 (paddr 0x0081_0000)
        let obj_header_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let obj_header_paddr: u64 = 0x0080_0000;
        let file_obj_vaddr = obj_header_vaddr + OBJ_HEADER_BODY;
        let file_obj_paddr = obj_header_paddr + OBJ_HEADER_BODY;

        let strings_vaddr: u64 = 0xFFFF_8000_0020_1000;
        let strings_paddr: u64 = 0x0081_0000;

        // Build the file name: \Windows\System32\config\SYSTEM
        let file_name = "\\Windows\\System32\\config\\SYSTEM";
        let file_name_utf16 = utf16le(file_name);
        let file_name_len = file_name_utf16.len() as u16;

        let ptb = PageTableBuilder::new()
            .map_4k(obj_header_vaddr, obj_header_paddr, flags::WRITABLE)
            .map_4k(strings_vaddr, strings_paddr, flags::WRITABLE)
            // _FILE_OBJECT.FileName (_UNICODE_STRING at file_obj + 0x58)
            .write_phys(file_obj_paddr + FO_FILENAME, &file_name_len.to_le_bytes())
            .write_phys(
                file_obj_paddr + FO_FILENAME + 2,
                &(file_name_len + 2).to_le_bytes(),
            )
            .write_phys_u64(file_obj_paddr + FO_FILENAME + 8, strings_vaddr)
            .write_phys(strings_paddr, &file_name_utf16)
            // _FILE_OBJECT.Flags = 0x40 (FO_CACHE_SUPPORTED)
            .write_phys(file_obj_paddr + FO_FLAGS, &0x40u32.to_le_bytes())
            // _FILE_OBJECT.CurrentByteOffset = 4096
            .write_phys_u64(file_obj_paddr + FO_CURRENT_BYTE_OFFSET, 4096)
            // _FILE_OBJECT.DeletePending = 0
            .write_phys(file_obj_paddr + FO_DELETE_PENDING, &[0u8])
            // _FILE_OBJECT.SharedRead = 1
            .write_phys(file_obj_paddr + FO_SHARED_READ, &[1u8])
            // _FILE_OBJECT.SharedWrite = 0
            .write_phys(file_obj_paddr + FO_SHARED_WRITE, &[0u8])
            // _FILE_OBJECT.SharedDelete = 1
            .write_phys(file_obj_paddr + FO_SHARED_DELETE, &[1u8])
            // _FILE_OBJECT.DeviceObject = 0 (no device for simplicity)
            .write_phys_u64(file_obj_paddr + FO_DEVICE_OBJECT, 0);

        let reader = make_win_reader(ptb);

        let handles = vec![WinHandleInfo {
            pid: 4,
            image_name: "System".into(),
            handle_value: 4,
            object_addr: obj_header_vaddr,
            object_type: "File".into(),
            granted_access: 0x0012_019F,
        }];

        let result = walk_file_objects(&reader, &handles).unwrap();
        assert_eq!(result.len(), 1);

        let fo = &result[0];
        assert_eq!(fo.file_name, "\\Windows\\System32\\config\\SYSTEM");
        assert_eq!(fo.flags, 0x40);
        assert_eq!(fo.size, 4096);
        assert!(!fo.delete_pending);
        assert!(fo.shared_read);
        assert!(!fo.shared_write);
        assert!(fo.shared_delete);
        assert_eq!(fo.access_mask, 0x0012_019F);
        assert_eq!(fo.object_addr, file_obj_vaddr);
        // Device name should be empty since DeviceObject is null
        assert_eq!(fo.device_name, "");
    }

    /// File objects should be returned sorted by file name.
    #[test]
    fn walk_file_objects_sorted_by_name() {
        // Two file objects: "Z:\foo" and "A:\bar" -- should come back sorted
        let obj1_header_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let obj1_header_paddr: u64 = 0x0080_0000;
        let obj1_fo_paddr = obj1_header_paddr + OBJ_HEADER_BODY;
        let obj1_fo_vaddr = obj1_header_vaddr + OBJ_HEADER_BODY;

        let obj2_header_vaddr: u64 = 0xFFFF_8000_0021_0000;
        let obj2_header_paddr: u64 = 0x0082_0000;
        let obj2_fo_paddr = obj2_header_paddr + OBJ_HEADER_BODY;
        let obj2_fo_vaddr = obj2_header_vaddr + OBJ_HEADER_BODY;

        let str1_vaddr: u64 = 0xFFFF_8000_0020_1000;
        let str1_paddr: u64 = 0x0081_0000;
        let str2_vaddr: u64 = 0xFFFF_8000_0021_1000;
        let str2_paddr: u64 = 0x0083_0000;

        let name1 = "Z:\\foo";
        let name2 = "A:\\bar";
        let utf1 = utf16le(name1);
        let utf2 = utf16le(name2);
        let len1 = utf1.len() as u16;
        let len2 = utf2.len() as u16;

        let ptb = PageTableBuilder::new()
            .map_4k(obj1_header_vaddr, obj1_header_paddr, flags::WRITABLE)
            .map_4k(str1_vaddr, str1_paddr, flags::WRITABLE)
            .map_4k(obj2_header_vaddr, obj2_header_paddr, flags::WRITABLE)
            .map_4k(str2_vaddr, str2_paddr, flags::WRITABLE)
            // File object 1: "Z:\foo"
            .write_phys(obj1_fo_paddr + FO_FILENAME, &len1.to_le_bytes())
            .write_phys(obj1_fo_paddr + FO_FILENAME + 2, &(len1 + 2).to_le_bytes())
            .write_phys_u64(obj1_fo_paddr + FO_FILENAME + 8, str1_vaddr)
            .write_phys(str1_paddr, &utf1)
            .write_phys(obj1_fo_paddr + FO_FLAGS, &0u32.to_le_bytes())
            .write_phys_u64(obj1_fo_paddr + FO_CURRENT_BYTE_OFFSET, 0)
            .write_phys(obj1_fo_paddr + FO_DELETE_PENDING, &[0u8])
            .write_phys(obj1_fo_paddr + FO_SHARED_READ, &[0u8])
            .write_phys(obj1_fo_paddr + FO_SHARED_WRITE, &[0u8])
            .write_phys(obj1_fo_paddr + FO_SHARED_DELETE, &[0u8])
            .write_phys_u64(obj1_fo_paddr + FO_DEVICE_OBJECT, 0)
            // File object 2: "A:\bar"
            .write_phys(obj2_fo_paddr + FO_FILENAME, &len2.to_le_bytes())
            .write_phys(obj2_fo_paddr + FO_FILENAME + 2, &(len2 + 2).to_le_bytes())
            .write_phys_u64(obj2_fo_paddr + FO_FILENAME + 8, str2_vaddr)
            .write_phys(str2_paddr, &utf2)
            .write_phys(obj2_fo_paddr + FO_FLAGS, &0u32.to_le_bytes())
            .write_phys_u64(obj2_fo_paddr + FO_CURRENT_BYTE_OFFSET, 0)
            .write_phys(obj2_fo_paddr + FO_DELETE_PENDING, &[0u8])
            .write_phys(obj2_fo_paddr + FO_SHARED_READ, &[0u8])
            .write_phys(obj2_fo_paddr + FO_SHARED_WRITE, &[0u8])
            .write_phys(obj2_fo_paddr + FO_SHARED_DELETE, &[0u8])
            .write_phys_u64(obj2_fo_paddr + FO_DEVICE_OBJECT, 0);

        let reader = make_win_reader(ptb);

        let handles = vec![
            WinHandleInfo {
                pid: 4,
                image_name: "System".into(),
                handle_value: 4,
                object_addr: obj1_header_vaddr,
                object_type: "File".into(),
                granted_access: 0x0012_019F,
            },
            WinHandleInfo {
                pid: 4,
                image_name: "System".into(),
                handle_value: 8,
                object_addr: obj2_header_vaddr,
                object_type: "File".into(),
                granted_access: 0x0012_019F,
            },
        ];

        let result = walk_file_objects(&reader, &handles).unwrap();
        assert_eq!(result.len(), 2);
        // "A:\bar" should come before "Z:\foo"
        assert_eq!(result[0].file_name, "A:\\bar");
        assert_eq!(result[0].object_addr, obj2_fo_vaddr);
        assert_eq!(result[1].file_name, "Z:\\foo");
        assert_eq!(result[1].object_addr, obj1_fo_vaddr);
    }
}
