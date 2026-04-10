//! Windows file object scanning and extraction.
//!
//! Filters handle table entries for "File" object types and reads
//! the underlying `_FILE_OBJECT` structures to extract file name,
//! device name, flags, size, and sharing disposition.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;
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
    reader: &ObjectReader<P>,
    handles: &[WinHandleInfo],
) -> Result<Vec<FileObjectInfo>> {
    // Resolve _OBJECT_HEADER.Body offset to find the _FILE_OBJECT body
    let body_offset = reader
        .symbols()
        .field_offset("_OBJECT_HEADER", "Body")
        .ok_or_else(|| crate::Error::Walker("missing _OBJECT_HEADER.Body offset".into()))?;

    let mut results = Vec::new();

    for handle in handles {
        if handle.object_type != "File" {
            continue;
        }

        if results.len() >= MAX_FILE_OBJECTS {
            break;
        }

        // The handle's object_addr points to the _OBJECT_HEADER.
        // The _FILE_OBJECT body starts at object_addr + Body offset.
        let file_obj_addr = handle.object_addr.wrapping_add(body_offset);

        if let Ok(info) = read_file_object(reader, file_obj_addr, handle.granted_access) {
            results.push(info);
        }
    }

    results.sort_by(|a, b| a.file_name.cmp(&b.file_name));
    Ok(results)
}

/// Convenience function that combines handle walking with file object extraction.
///
/// Calls `walk_handles` to enumerate all process handles, then passes them
/// to `walk_file_objects`.  Falls back to an empty `Vec` on handle walking failure.
pub fn scan_file_objects<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<FileObjectInfo>> {
    let ps_head = reader
        .symbols()
        .symbol_address("PsActiveProcessHead")
        .ok_or_else(|| crate::Error::Walker("missing PsActiveProcessHead symbol".into()))?;

    let Ok(handles) = crate::handles::walk_handles(reader, ps_head) else {
        return Ok(Vec::new());
    };

    walk_file_objects(reader, &handles)
}

/// Read a single `_FILE_OBJECT` at the given virtual address.
fn read_file_object<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    file_obj_addr: u64,
    access_mask: u32,
) -> Result<FileObjectInfo> {
    // Read FileName (_UNICODE_STRING)
    let filename_off = reader
        .symbols()
        .field_offset("_FILE_OBJECT", "FileName")
        .ok_or_else(|| crate::Error::Walker("missing _FILE_OBJECT.FileName offset".into()))?;
    let file_name =
        read_unicode_string(reader, file_obj_addr.wrapping_add(filename_off)).unwrap_or_default();

    // Read Flags (u32)
    let fo_flags: u32 = reader.read_field(file_obj_addr, "_FILE_OBJECT", "Flags")?;

    // Read CurrentByteOffset as file size proxy
    let size: u64 = reader
        .read_field(file_obj_addr, "_FILE_OBJECT", "CurrentByteOffset")
        .unwrap_or(0);

    // Read boolean fields
    let delete_pending: u8 = reader
        .read_field(file_obj_addr, "_FILE_OBJECT", "DeletePending")
        .unwrap_or(0);
    let shared_read: u8 = reader
        .read_field(file_obj_addr, "_FILE_OBJECT", "SharedRead")
        .unwrap_or(0);
    let shared_write: u8 = reader
        .read_field(file_obj_addr, "_FILE_OBJECT", "SharedWrite")
        .unwrap_or(0);
    let shared_delete: u8 = reader
        .read_field(file_obj_addr, "_FILE_OBJECT", "SharedDelete")
        .unwrap_or(0);

    // Read DeviceObject pointer and resolve device name
    let device_ptr: u64 = reader
        .read_field(file_obj_addr, "_FILE_OBJECT", "DeviceObject")
        .unwrap_or(0);
    let device_name = resolve_device_name(reader, device_ptr);

    Ok(FileObjectInfo {
        object_addr: file_obj_addr,
        file_name,
        device_name,
        access_mask,
        flags: fo_flags,
        size,
        delete_pending: delete_pending != 0,
        shared_read: shared_read != 0,
        shared_write: shared_write != 0,
        shared_delete: shared_delete != 0,
    })
}

/// Resolve the device name from a `_DEVICE_OBJECT` pointer.
///
/// Follows `DeviceObject` to `DriverObject`, then reads the driver name.
/// Returns an empty string if the device pointer is null or unreadable.
fn resolve_device_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    device_ptr: u64,
) -> String {
    if device_ptr == 0 {
        return String::new();
    }

    // Read _DEVICE_OBJECT.DriverObject pointer
    let driver_obj: u64 = match reader.read_field(device_ptr, "_DEVICE_OBJECT", "DriverObject") {
        Ok(v) => v,
        Err(_) => return String::new(),
    };

    if driver_obj == 0 {
        return String::new();
    }

    // Read _DRIVER_OBJECT.DriverName (_UNICODE_STRING)
    let Some(name_off) = reader
        .symbols()
        .field_offset("_DRIVER_OBJECT", "DriverName")
    else {
        return String::new();
    };

    read_unicode_string(reader, driver_obj.wrapping_add(name_off)).unwrap_or_default()
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
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
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

    /// scan_file_objects with an unmapped process list returns an empty Vec gracefully.
    ///
    /// Covers scan_file_objects lines 61-74: PsActiveProcessHead is present in the
    /// ISF preset, but the address is unmapped → walk_handles fails → returns Ok([]).
    #[test]
    fn scan_file_objects_no_processes_returns_empty() {
        let ptb = PageTableBuilder::new();
        let reader = make_win_reader(ptb);

        // PsActiveProcessHead is present in the preset at a fixed virtual address,
        // but no memory is mapped there → walk_processes → Err → Ok(Vec::new())
        let result = scan_file_objects(&reader).unwrap();
        assert!(result.is_empty(), "no processes → no file objects");
    }

    /// walk_file_objects with DeviceObject != 0 triggers resolve_device_name.
    ///
    /// Covers resolve_device_name lines 140-162 (non-null device path).
    /// Layout:
    ///   _FILE_OBJECT.DeviceObject → _DEVICE_OBJECT.DriverObject → _DRIVER_OBJECT.DriverName
    #[test]
    fn walk_file_objects_with_device_object_resolves_driver_name() {
        // _DEVICE_OBJECT.DriverObject is at offset 0x08 (from windows_kernel_preset).
        // _DRIVER_OBJECT.DriverName (_UNICODE_STRING) is at offset 0x38.
        // _UNICODE_STRING: Length(u16)+MaxLen(u16) at 0/2, Buffer(ptr) at 8.
        //
        // Addresses (paddr < 0x00FF_FFFF):
        let obj_header_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let obj_header_paddr: u64 = 0x0050_0000;
        let file_obj_paddr  = obj_header_paddr + OBJ_HEADER_BODY;

        let dev_vaddr:  u64 = 0xFFFF_8000_0031_0000;
        let dev_paddr:  u64 = 0x0051_0000;
        let drv_vaddr:  u64 = 0xFFFF_8000_0032_0000;
        let drv_paddr:  u64 = 0x0052_0000;
        let str_vaddr:  u64 = 0xFFFF_8000_0033_0000;
        let str_paddr:  u64 = 0x0053_0000;

        let driver_name = "\\Driver\\disk";
        let name_utf16 = utf16le(driver_name);
        let name_len = name_utf16.len() as u16;

        let ptb = PageTableBuilder::new()
            // _OBJECT_HEADER + _FILE_OBJECT
            .map_4k(obj_header_vaddr, obj_header_paddr, flags::WRITABLE)
            // _FILE_OBJECT.DeviceObject at fo_paddr + 0x08 = dev_vaddr
            .write_phys_u64(file_obj_paddr + FO_DEVICE_OBJECT, dev_vaddr)
            // _FILE_OBJECT.FileName = empty (length = 0 at FO_FILENAME)
            .write_phys(file_obj_paddr + FO_FLAGS, &0u32.to_le_bytes())
            .write_phys(file_obj_paddr + FO_DELETE_PENDING, &[0u8])
            .write_phys(file_obj_paddr + FO_SHARED_READ, &[0u8])
            .write_phys(file_obj_paddr + FO_SHARED_WRITE, &[0u8])
            .write_phys(file_obj_paddr + FO_SHARED_DELETE, &[0u8])
            // _DEVICE_OBJECT
            .map_4k(dev_vaddr, dev_paddr, flags::WRITABLE)
            // _DEVICE_OBJECT.DriverObject at dev_paddr + 0x08 = drv_vaddr
            .write_phys_u64(dev_paddr + 0x08, drv_vaddr)
            // _DRIVER_OBJECT
            .map_4k(drv_vaddr, drv_paddr, flags::WRITABLE)
            // _DRIVER_OBJECT.DriverName (_UNICODE_STRING) at drv_paddr + 0x38
            .write_phys(drv_paddr + 0x38, &name_len.to_le_bytes())               // Length
            .write_phys(drv_paddr + 0x3A, &(name_len + 2).to_le_bytes())          // MaximumLength
            .write_phys_u64(drv_paddr + 0x40, str_vaddr)                          // Buffer ptr
            // String data
            .map_4k(str_vaddr, str_paddr, flags::WRITABLE)
            .write_phys(str_paddr, &name_utf16);

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
        assert_eq!(result.len(), 1, "should find one file object");
        assert_eq!(result[0].device_name, "\\Driver\\disk",
            "device_name should be resolved from driver");
    }
}
