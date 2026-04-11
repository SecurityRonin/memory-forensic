//! Windows kernel Object Directory walker.
//!
//! Enumerates objects in the kernel namespace by walking `_OBJECT_DIRECTORY`
//! hash tables. The kernel Object Manager stores objects in a tree of
//! directories, each using a 37-bucket hash table of `_OBJECT_DIRECTORY_ENTRY`
//! chains. This module finds `_DRIVER_OBJECT` instances under `\Driver`
//! for IRP dispatch table checking.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;
use crate::Result;

/// Number of hash buckets in an `_OBJECT_DIRECTORY`.
const HASH_BUCKET_COUNT: usize = 37;

/// Maximum entries per hash bucket chain (safety limit against corruption).
const MAX_CHAIN_LENGTH: usize = 1024;

/// Size of `_OBJECT_HEADER_CREATOR_INFO` (Windows 10+, InfoMask bit 0x1).
const CREATOR_INFO_SIZE: u64 = 0x20;

/// Read the name of a kernel object from its `_OBJECT_HEADER_NAME_INFO`.
///
/// Given the object body address, walks backwards to `_OBJECT_HEADER`,
/// checks `InfoMask` for the presence of `_OBJECT_HEADER_NAME_INFO`
/// (bit 0x2), and reads the `Name` UNICODE_STRING if present.
pub fn read_object_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    object_body_addr: u64,
) -> Result<String> {
    let body_offset = reader
        .symbols()
        .field_offset("_OBJECT_HEADER", "Body")
        .ok_or_else(|| crate::Error::Walker("missing _OBJECT_HEADER.Body offset".into()))?;
    let header_addr = object_body_addr.wrapping_sub(body_offset);

    let info_mask: u8 = reader.read_field(header_addr, "_OBJECT_HEADER", "InfoMask")?;
    if info_mask & 0x02 == 0 {
        return Ok(String::new());
    }

    let mut name_info_dist = reader
        .symbols()
        .struct_size("_OBJECT_HEADER_NAME_INFO")
        .ok_or_else(|| crate::Error::Walker("missing _OBJECT_HEADER_NAME_INFO size".into()))?;
    if info_mask & 0x01 != 0 {
        name_info_dist += CREATOR_INFO_SIZE;
    }

    let name_info_addr = header_addr.wrapping_sub(name_info_dist);
    let name_offset = reader
        .symbols()
        .field_offset("_OBJECT_HEADER_NAME_INFO", "Name")
        .ok_or_else(|| {
            crate::Error::Walker("missing _OBJECT_HEADER_NAME_INFO.Name offset".into())
        })?;

    Ok(read_unicode_string(reader, name_info_addr.wrapping_add(name_offset)).unwrap_or_default())
}

/// Walk an `_OBJECT_DIRECTORY` hash table and return all entries.
///
/// Iterates all 37 hash buckets, following `_OBJECT_DIRECTORY_ENTRY`
/// chains in each bucket. Returns `(name, object_body_addr)` pairs.
pub fn walk_directory<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    dir_addr: u64,
) -> Result<Vec<(String, u64)>> {
    let bucket_bytes = reader.read_bytes(dir_addr, HASH_BUCKET_COUNT * 8)?;
    let mut entries = Vec::new();

    for bucket_idx in 0..HASH_BUCKET_COUNT {
        let off = bucket_idx * 8;
        let mut entry_ptr =
            u64::from_le_bytes(bucket_bytes[off..off + 8].try_into().expect("8 bytes"));

        let mut chain_len = 0;
        while entry_ptr != 0 && chain_len < MAX_CHAIN_LENGTH {
            let chain_link: u64 =
                reader.read_field(entry_ptr, "_OBJECT_DIRECTORY_ENTRY", "ChainLink")?;
            let object_body: u64 =
                reader.read_field(entry_ptr, "_OBJECT_DIRECTORY_ENTRY", "Object")?;

            if object_body != 0 {
                let name = read_object_name(reader, object_body).unwrap_or_default();
                entries.push((name, object_body));
            }

            entry_ptr = chain_link;
            chain_len += 1;
        }
    }

    Ok(entries)
}

/// Find `\Driver` within the root object directory and return all
/// `_DRIVER_OBJECT` body addresses.
///
/// Walks the root `_OBJECT_DIRECTORY` looking for an entry named "Driver".
/// If found, walks that subdirectory and returns the body addresses of
/// all objects within it (each is a `_DRIVER_OBJECT`).
pub fn walk_driver_objects<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    root_dir_addr: u64,
) -> Result<Vec<u64>> {
    let root_entries = walk_directory(reader, root_dir_addr)?;

    for (name, body_addr) in &root_entries {
        if name == "Driver" {
            let driver_entries = walk_directory(reader, *body_addr)?;
            return Ok(driver_entries.into_iter().map(|(_, addr)| addr).collect());
        }
    }

    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Encode a Rust &str as UTF-16LE bytes.
    fn utf16le_bytes(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn write_named_object(
        buf: &mut [u8],
        obj_offset: usize,
        vaddr_base: u64,
        name: &str,
        str_offset: usize,
    ) -> u64 {
        let utf16 = utf16le_bytes(name);
        let str_len = utf16.len() as u16;
        buf[str_offset..str_offset + utf16.len()].copy_from_slice(&utf16);

        let ni = obj_offset;
        buf[ni + 0x10..ni + 0x12].copy_from_slice(&str_len.to_le_bytes());
        buf[ni + 0x12..ni + 0x14].copy_from_slice(&str_len.to_le_bytes());
        let str_vaddr = vaddr_base + str_offset as u64;
        buf[ni + 0x18..ni + 0x20].copy_from_slice(&str_vaddr.to_le_bytes());

        let hdr = obj_offset + 0x20;
        buf[hdr + 0x1a] = 0x02; // InfoMask = NAME_INFO present (bit 1)

        vaddr_base + (obj_offset + 0x50) as u64
    }

    fn write_dir_entry(
        buf: &mut [u8],
        entry_offset: usize,
        chain_link: u64,
        object_body: u64,
        hash_value: u32,
    ) {
        buf[entry_offset..entry_offset + 8].copy_from_slice(&chain_link.to_le_bytes());
        buf[entry_offset + 8..entry_offset + 16].copy_from_slice(&object_body.to_le_bytes());
        buf[entry_offset + 0x10..entry_offset + 0x14].copy_from_slice(&hash_value.to_le_bytes());
    }

    fn set_bucket(buf: &mut [u8], dir_offset: usize, bucket_idx: usize, entry_vaddr: u64) {
        let off = dir_offset + bucket_idx * 8;
        buf[off..off + 8].copy_from_slice(&entry_vaddr.to_le_bytes());
    }

    fn make_test_reader(pages: &[(u64, u64, &[u8])]) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let mut builder = PageTableBuilder::new();
        for &(vaddr, paddr, data) in pages {
            builder = builder
                .map_4k(vaddr, paddr, flags::WRITABLE)
                .write_phys(paddr, data);
        }
        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    // -------------------------------------------------------------------
    // read_object_name tests
    // -------------------------------------------------------------------

    #[test]
    fn read_name_from_object_header() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut page = vec![0u8; 4096];

        let body_addr = write_named_object(&mut page, 0x100, vaddr, "TestObj", 0x800);

        let reader = make_test_reader(&[(vaddr, paddr, &page)]);
        let name = read_object_name(&reader, body_addr).unwrap();
        assert_eq!(name, "TestObj");
    }

    #[test]
    fn read_name_no_info_returns_empty() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let page = vec![0u8; 4096];

        // Body at 0x100 + 0x30 = 0x130, InfoMask = 0 → no name info
        let body_addr = vaddr + 0x130;

        let reader = make_test_reader(&[(vaddr, paddr, &page)]);
        let name = read_object_name(&reader, body_addr).unwrap();
        assert_eq!(name, "");
    }

    // -------------------------------------------------------------------
    // walk_directory tests
    // -------------------------------------------------------------------

    #[test]
    fn walk_directory_returns_entries_from_different_buckets() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut page = vec![0u8; 4096];

        let dir_addr = vaddr;

        let obj_a_body = write_named_object(&mut page, 0x400, vaddr, "Alpha", 0xA00);
        write_dir_entry(&mut page, 0x200, 0, obj_a_body, 0);
        set_bucket(&mut page, 0, 0, vaddr + 0x200);

        let obj_b_body = write_named_object(&mut page, 0x500, vaddr, "Beta", 0xA40);
        write_dir_entry(&mut page, 0x220, 0, obj_b_body, 0);
        set_bucket(&mut page, 0, 5, vaddr + 0x220);

        let reader = make_test_reader(&[(vaddr, paddr, &page)]);
        let entries = walk_directory(&reader, dir_addr).unwrap();

        assert_eq!(entries.len(), 2);
        let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"Alpha"));
        assert!(names.contains(&"Beta"));
    }

    #[test]
    fn walk_directory_follows_chain_in_same_bucket() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut page = vec![0u8; 4096];

        let dir_addr = vaddr;

        let obj_a_body = write_named_object(&mut page, 0x400, vaddr, "First", 0xA00);
        let obj_b_body = write_named_object(&mut page, 0x500, vaddr, "Second", 0xA40);

        write_dir_entry(&mut page, 0x220, 0, obj_b_body, 0);
        write_dir_entry(&mut page, 0x200, vaddr + 0x220, obj_a_body, 0);
        set_bucket(&mut page, 0, 0, vaddr + 0x200);

        let reader = make_test_reader(&[(vaddr, paddr, &page)]);
        let entries = walk_directory(&reader, dir_addr).unwrap();

        assert_eq!(entries.len(), 2);
        let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"First"));
        assert!(names.contains(&"Second"));
    }

    // -------------------------------------------------------------------
    // walk_driver_objects tests
    // -------------------------------------------------------------------

    #[test]
    fn walk_driver_objects_finds_drivers() {
        let vaddr1: u64 = 0xFFFF_8000_0010_0000;
        let paddr1: u64 = 0x0080_0000;
        let vaddr2: u64 = 0xFFFF_8000_0020_0000;
        let paddr2: u64 = 0x0090_0000;

        let mut page1 = vec![0u8; 4096];
        let mut page2 = vec![0u8; 4096];

        // "Driver" directory object on page2
        let drv_str = utf16le_bytes("Driver");
        let drv_len = drv_str.len() as u16;
        page2[0x800..0x800 + drv_str.len()].copy_from_slice(&drv_str);
        page2[0x10..0x12].copy_from_slice(&drv_len.to_le_bytes());
        page2[0x12..0x14].copy_from_slice(&drv_len.to_le_bytes());
        page2[0x18..0x20].copy_from_slice(&(vaddr2 + 0x800).to_le_bytes());
        page2[0x3a] = 0x02;
        let driver_dir_body = vaddr2 + 0x050;

        // Driver A: "ACPI"
        let acpi_str = utf16le_bytes("ACPI");
        let acpi_len = acpi_str.len() as u16;
        page2[0x880..0x880 + acpi_str.len()].copy_from_slice(&acpi_str);
        page2[0x200 + 0x10..0x200 + 0x12].copy_from_slice(&acpi_len.to_le_bytes());
        page2[0x200 + 0x12..0x200 + 0x14].copy_from_slice(&acpi_len.to_le_bytes());
        page2[0x200 + 0x18..0x200 + 0x20].copy_from_slice(&(vaddr2 + 0x880).to_le_bytes());
        page2[0x220 + 0x1a] = 0x02;
        let drv_a_body = vaddr2 + 0x250;

        // Driver B: "Null"
        let null_str = utf16le_bytes("Null");
        let null_len = null_str.len() as u16;
        page2[0x8C0..0x8C0 + null_str.len()].copy_from_slice(&null_str);
        page2[0x300 + 0x10..0x300 + 0x12].copy_from_slice(&null_len.to_le_bytes());
        page2[0x300 + 0x12..0x300 + 0x14].copy_from_slice(&null_len.to_le_bytes());
        page2[0x300 + 0x18..0x300 + 0x20].copy_from_slice(&(vaddr2 + 0x8C0).to_le_bytes());
        page2[0x320 + 0x1a] = 0x02;
        let drv_b_body = vaddr2 + 0x350;

        write_dir_entry(&mut page2, 0x178, 0, drv_a_body, 0);
        set_bucket(&mut page2, 0x050, 0, vaddr2 + 0x178);
        write_dir_entry(&mut page2, 0x190, 0, drv_b_body, 0);
        set_bucket(&mut page2, 0x050, 3, vaddr2 + 0x190);

        write_dir_entry(&mut page1, 0x200, 0, driver_dir_body, 0);
        set_bucket(&mut page1, 0, 2, vaddr1 + 0x200);

        let reader = make_test_reader(&[(vaddr1, paddr1, &page1), (vaddr2, paddr2, &page2)]);

        let driver_addrs = walk_driver_objects(&reader, vaddr1).unwrap();
        assert_eq!(driver_addrs.len(), 2);
        assert!(driver_addrs.contains(&drv_a_body));
        assert!(driver_addrs.contains(&drv_b_body));
    }

    #[test]
    fn walk_driver_objects_no_driver_dir() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut page = vec![0u8; 4096];

        let obj_body = write_named_object(&mut page, 0x400, vaddr, "ObjectTypes", 0xA00);
        write_dir_entry(&mut page, 0x200, 0, obj_body, 0);
        set_bucket(&mut page, 0, 0, vaddr + 0x200);

        let reader = make_test_reader(&[(vaddr, paddr, &page)]);
        let driver_addrs = walk_driver_objects(&reader, vaddr).unwrap();
        assert!(driver_addrs.is_empty());
    }
}
