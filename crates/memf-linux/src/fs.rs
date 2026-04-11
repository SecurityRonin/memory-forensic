//! Linux mounted filesystem walker.
//!
//! Enumerates mounted filesystems by walking the `mount` linked list
//! from `init_task.nsproxy → mnt_namespace → list`. Each `mount`
//! struct provides the device name, mount point dentry, and filesystem
//! type from the super_block.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, MountInfo, Result};

/// Walk all mounted filesystems visible from init's mount namespace.
///
/// Follows `init_task.nsproxy → mnt_namespace.list` to enumerate
/// `struct mount` entries, reading dev_name, mountpoint, and fs type.
pub fn walk_filesystems<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<MountInfo>> {
    let init_task_addr = reader
        .symbols()
        .symbol_address("init_task")
        .ok_or_else(|| Error::Walker("symbol 'init_task' not found".into()))?;

    let nsproxy_ptr: u64 = reader.read_field(init_task_addr, "task_struct", "nsproxy")?;
    if nsproxy_ptr == 0 {
        return Err(Error::Walker("init_task has NULL nsproxy".into()));
    }

    let mnt_ns_ptr: u64 = reader.read_field(nsproxy_ptr, "nsproxy", "mnt_ns")?;
    if mnt_ns_ptr == 0 {
        return Err(Error::Walker("nsproxy has NULL mnt_ns".into()));
    }

    // mnt_namespace.list is the head of a circular list of mount.mnt_list
    let mount_addrs = reader.walk_list(mnt_ns_ptr, "mount", "mnt_list")?;

    let d_name_offset = reader
        .symbols()
        .field_offset("dentry", "d_name")
        .ok_or_else(|| Error::Walker("dentry.d_name field not found".into()))?;

    let name_in_qstr_offset = reader
        .symbols()
        .field_offset("qstr", "name")
        .ok_or_else(|| Error::Walker("qstr.name field not found".into()))?;

    let mnt_offset = reader
        .symbols()
        .field_offset("mount", "mnt")
        .ok_or_else(|| Error::Walker("mount.mnt field not found".into()))?;

    let mut mounts = Vec::new();

    for &mount_addr in &mount_addrs {
        // Read device name string
        let devname_ptr: u64 = reader.read_field(mount_addr, "mount", "mnt_devname")?;
        let dev_name = if devname_ptr != 0 {
            reader.read_string(devname_ptr, 256).unwrap_or_default()
        } else {
            String::new()
        };

        // Read mount point from dentry → d_name.name
        let mountpoint_ptr: u64 = reader.read_field(mount_addr, "mount", "mnt_mountpoint")?;
        let mount_point = if mountpoint_ptr != 0 {
            read_dentry_name(reader, mountpoint_ptr, d_name_offset, name_in_qstr_offset)
                .unwrap_or_default()
        } else {
            String::new()
        };

        // Read filesystem type: mount.mnt.mnt_sb → super_block.s_type → file_system_type.name
        let sb_ptr: u64 = reader.read_field(mount_addr + mnt_offset, "vfsmount", "mnt_sb")?;
        let fs_type = if sb_ptr != 0 {
            read_fs_type_name(reader, sb_ptr).unwrap_or_default()
        } else {
            String::new()
        };

        mounts.push(MountInfo {
            dev_name,
            mount_point,
            fs_type,
        });
    }

    Ok(mounts)
}

/// Read the name from a dentry's embedded d_name (qstr).
fn read_dentry_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    dentry_ptr: u64,
    d_name_offset: u64,
    name_in_qstr_offset: u64,
) -> Result<String> {
    let name_addr = dentry_ptr + d_name_offset + name_in_qstr_offset;
    let name_raw = reader.read_bytes(name_addr, 8)?;
    let name_ptr = u64::from_le_bytes(name_raw.try_into().unwrap());
    if name_ptr != 0 {
        Ok(reader.read_string(name_ptr, 256)?)
    } else {
        Ok(String::new())
    }
}

/// Read the filesystem type name from a super_block.
fn read_fs_type_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    sb_ptr: u64,
) -> Result<String> {
    let s_type_ptr: u64 = reader.read_field(sb_ptr, "super_block", "s_type")?;
    if s_type_ptr == 0 {
        return Ok(String::new());
    }
    let name_ptr: u64 = reader.read_field(s_type_ptr, "file_system_type", "name")?;
    if name_ptr == 0 {
        return Ok(String::new());
    }
    Ok(reader.read_string(name_ptr, 64)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_test_reader(data: &[u8], vaddr: u64, paddr: u64) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            // task_struct
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_field("task_struct", "nsproxy", 64, "pointer")
            // list_head
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            // nsproxy
            .add_struct("nsproxy", 48)
            .add_field("nsproxy", "mnt_ns", 16, "pointer")
            // mnt_namespace
            .add_struct("mnt_namespace", 32)
            .add_field("mnt_namespace", "list", 0, "list_head")
            // mount
            .add_struct("mount", 256)
            .add_field("mount", "mnt_list", 0, "list_head")
            .add_field("mount", "mnt_devname", 16, "pointer")
            .add_field("mount", "mnt_mountpoint", 24, "pointer")
            .add_field("mount", "mnt", 32, "vfsmount")
            // vfsmount (embedded in mount)
            .add_struct("vfsmount", 32)
            .add_field("vfsmount", "mnt_sb", 0, "pointer")
            // super_block
            .add_struct("super_block", 64)
            .add_field("super_block", "s_type", 0, "pointer")
            // file_system_type
            .add_struct("file_system_type", 64)
            .add_field("file_system_type", "name", 0, "pointer")
            // dentry
            .add_struct("dentry", 64)
            .add_field("dentry", "d_name", 0, "qstr")
            // qstr
            .add_struct("qstr", 16)
            .add_field("qstr", "name", 8, "pointer")
            // symbol
            .add_symbol("init_task", vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_two_mounts() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task: nsproxy at +64
        let nsproxy_addr = vaddr + 0x100;
        data[64..72].copy_from_slice(&nsproxy_addr.to_le_bytes());

        // nsproxy at +0x100: mnt_ns at offset 16
        let mnt_ns_addr = vaddr + 0x180;
        data[0x110..0x118].copy_from_slice(&mnt_ns_addr.to_le_bytes());

        // mnt_namespace at +0x180: list head
        // list.next → mount1.mnt_list, list.prev → mount2.mnt_list
        let ns_list_addr = vaddr + 0x180; // list_head at offset 0 in mnt_namespace
        let mount1_addr = vaddr + 0x200;
        let mount2_addr = vaddr + 0x400;
        let mount1_list = mount1_addr; // mnt_list at offset 0 in mount
        let mount2_list = mount2_addr;
        data[0x180..0x188].copy_from_slice(&mount1_list.to_le_bytes()); // list.next → mount1
        data[0x188..0x190].copy_from_slice(&mount2_list.to_le_bytes()); // list.prev → mount2

        // mount1 at +0x200: rootfs on /
        data[0x200..0x208].copy_from_slice(&mount2_list.to_le_bytes()); // mnt_list.next → mount2
        data[0x208..0x210].copy_from_slice(&ns_list_addr.to_le_bytes()); // mnt_list.prev → ns head
        let devname1_addr = vaddr + 0x300;
        data[0x210..0x218].copy_from_slice(&devname1_addr.to_le_bytes()); // mnt_devname
        let dentry1_addr = vaddr + 0x340;
        data[0x218..0x220].copy_from_slice(&dentry1_addr.to_le_bytes()); // mnt_mountpoint
                                                                         // mnt.mnt_sb at offset 32
        let sb1_addr = vaddr + 0x380;
        data[0x220..0x228].copy_from_slice(&sb1_addr.to_le_bytes()); // mnt.mnt_sb

        // devname1 string at +0x300
        data[0x300..0x308].copy_from_slice(b"/dev/sda");

        // dentry1 at +0x340: d_name.name at qstr offset 8
        let dname1_addr = vaddr + 0x360;
        data[0x348..0x350].copy_from_slice(&dname1_addr.to_le_bytes()); // d_name.name
        data[0x360..0x361].copy_from_slice(b"/");

        // super_block1 at +0x380: s_type pointer
        let fstype1_addr = vaddr + 0x3C0;
        data[0x380..0x388].copy_from_slice(&fstype1_addr.to_le_bytes());

        // file_system_type1 at +0x3C0: name pointer
        let typename1_addr = vaddr + 0x3E0;
        data[0x3C0..0x3C8].copy_from_slice(&typename1_addr.to_le_bytes());
        data[0x3E0..0x3E4].copy_from_slice(b"ext4");

        // mount2 at +0x400: tmpfs on /tmp
        data[0x400..0x408].copy_from_slice(&ns_list_addr.to_le_bytes()); // mnt_list.next → ns head
        data[0x408..0x410].copy_from_slice(&mount1_list.to_le_bytes()); // mnt_list.prev → mount1
        let devname2_addr = vaddr + 0x500;
        data[0x410..0x418].copy_from_slice(&devname2_addr.to_le_bytes()); // mnt_devname
        let dentry2_addr = vaddr + 0x540;
        data[0x418..0x420].copy_from_slice(&dentry2_addr.to_le_bytes()); // mnt_mountpoint
        let sb2_addr = vaddr + 0x580;
        data[0x420..0x428].copy_from_slice(&sb2_addr.to_le_bytes()); // mnt.mnt_sb

        // devname2 string at +0x500
        data[0x500..0x505].copy_from_slice(b"tmpfs");

        // dentry2 at +0x540
        let dname2_addr = vaddr + 0x560;
        data[0x548..0x550].copy_from_slice(&dname2_addr.to_le_bytes());
        data[0x560..0x564].copy_from_slice(b"/tmp");

        // super_block2 at +0x580
        let fstype2_addr = vaddr + 0x5C0;
        data[0x580..0x588].copy_from_slice(&fstype2_addr.to_le_bytes());

        // file_system_type2 at +0x5C0
        let typename2_addr = vaddr + 0x5E0;
        data[0x5C0..0x5C8].copy_from_slice(&typename2_addr.to_le_bytes());
        data[0x5E0..0x5E5].copy_from_slice(b"tmpfs");

        let reader = make_test_reader(&data, vaddr, paddr);
        let mounts = walk_filesystems(&reader).unwrap();

        assert_eq!(mounts.len(), 2);

        assert_eq!(mounts[0].dev_name, "/dev/sda");
        assert_eq!(mounts[0].mount_point, "/");
        assert_eq!(mounts[0].fs_type, "ext4");

        assert_eq!(mounts[1].dev_name, "tmpfs");
        assert_eq!(mounts[1].mount_point, "/tmp");
        assert_eq!(mounts[1].fs_type, "tmpfs");
    }

    #[test]
    fn walk_filesystems_null_nsproxy() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task with nsproxy = NULL
        data[64..72].copy_from_slice(&0u64.to_le_bytes());

        let reader = make_test_reader(&data, vaddr, paddr);
        let result = walk_filesystems(&reader);
        assert!(result.is_err());
    }

    #[test]
    fn missing_init_task_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 8, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_filesystems(&reader);
        assert!(result.is_err());
    }

    // walk_filesystems: mnt_ns_ptr == 0 → Err (exercises line 31-33).
    #[test]
    fn walk_filesystems_null_mnt_ns_returns_error() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // nsproxy at +0x100
        let nsproxy_addr = vaddr + 0x100;
        data[64..72].copy_from_slice(&nsproxy_addr.to_le_bytes());
        // nsproxy.mnt_ns at offset 16 = 0 (null)
        data[0x110..0x118].copy_from_slice(&0u64.to_le_bytes());

        let reader = make_test_reader(&data, vaddr, paddr);
        let result = walk_filesystems(&reader);
        assert!(result.is_err(), "null mnt_ns must return Err");
    }

    // walk_filesystems: mount with devname_ptr=0 and mountpoint_ptr=0 and sb_ptr=0
    // → dev_name="", mount_point="", fs_type="" (exercises null-ptr branches in loop body).
    #[test]
    fn walk_filesystems_all_null_ptrs_in_mount() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task: nsproxy at +0x100
        let nsproxy_addr = vaddr + 0x100;
        data[64..72].copy_from_slice(&nsproxy_addr.to_le_bytes());

        // nsproxy: mnt_ns at offset 16 → mnt_ns at +0x180
        let mnt_ns_addr = vaddr + 0x180;
        data[0x110..0x118].copy_from_slice(&mnt_ns_addr.to_le_bytes());

        // mnt_namespace: list at offset 0 → head
        // list.next → mount1, list.prev → mount1
        let ns_list_addr = vaddr + 0x180;
        let mount1_addr = vaddr + 0x200;
        data[0x180..0x188].copy_from_slice(&mount1_addr.to_le_bytes()); // list.next
        data[0x188..0x190].copy_from_slice(&mount1_addr.to_le_bytes()); // list.prev

        // mount1: mnt_list.next → ns_head, mnt_list.prev → ns_head (single-entry loop)
        data[0x200..0x208].copy_from_slice(&ns_list_addr.to_le_bytes()); // mnt_list.next
        data[0x208..0x210].copy_from_slice(&ns_list_addr.to_le_bytes()); // mnt_list.prev
        // mnt_devname at offset 16 = 0 (null)
        data[0x210..0x218].copy_from_slice(&0u64.to_le_bytes());
        // mnt_mountpoint at offset 24 = 0 (null)
        data[0x218..0x220].copy_from_slice(&0u64.to_le_bytes());
        // mnt.mnt_sb at offset 32 (= mount.mnt at offset 32 + vfsmount.mnt_sb at offset 0) = 0
        data[0x220..0x228].copy_from_slice(&0u64.to_le_bytes());

        let reader = make_test_reader(&data, vaddr, paddr);
        let mounts = walk_filesystems(&reader).unwrap();

        assert_eq!(mounts.len(), 1, "one mount entry expected");
        assert_eq!(mounts[0].dev_name, "", "null devname_ptr → empty string");
        assert_eq!(mounts[0].mount_point, "", "null mountpoint_ptr → empty string");
        assert_eq!(mounts[0].fs_type, "", "null sb_ptr → empty string");
    }

    // read_fs_type_name: s_type_ptr == 0 → fs_type = "" (exercises line 114-115).
    #[test]
    fn walk_filesystems_null_s_type_gives_empty_fs_type() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        let nsproxy_addr = vaddr + 0x100;
        data[64..72].copy_from_slice(&nsproxy_addr.to_le_bytes());

        let mnt_ns_addr = vaddr + 0x180;
        data[0x110..0x118].copy_from_slice(&mnt_ns_addr.to_le_bytes());

        let ns_list_addr = vaddr + 0x180;
        let mount1_addr = vaddr + 0x200;
        data[0x180..0x188].copy_from_slice(&mount1_addr.to_le_bytes());
        data[0x188..0x190].copy_from_slice(&mount1_addr.to_le_bytes());

        data[0x200..0x208].copy_from_slice(&ns_list_addr.to_le_bytes());
        data[0x208..0x210].copy_from_slice(&ns_list_addr.to_le_bytes());
        // devname_ptr = 0, mountpoint_ptr = 0
        data[0x210..0x218].copy_from_slice(&0u64.to_le_bytes());
        data[0x218..0x220].copy_from_slice(&0u64.to_le_bytes());
        // mnt_sb points to a super_block at +0x380; super_block.s_type = 0
        let sb_addr = vaddr + 0x380;
        data[0x220..0x228].copy_from_slice(&sb_addr.to_le_bytes());
        // super_block.s_type at offset 0 = 0 (null)
        data[0x380..0x388].copy_from_slice(&0u64.to_le_bytes());

        let reader = make_test_reader(&data, vaddr, paddr);
        let mounts = walk_filesystems(&reader).unwrap();

        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].fs_type, "", "null s_type_ptr → empty fs_type");
    }

    // read_fs_type_name: name_ptr == 0 → fs_type = "" (exercises line 117-119).
    #[test]
    fn walk_filesystems_null_name_ptr_gives_empty_fs_type() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        let nsproxy_addr = vaddr + 0x100;
        data[64..72].copy_from_slice(&nsproxy_addr.to_le_bytes());

        let mnt_ns_addr = vaddr + 0x180;
        data[0x110..0x118].copy_from_slice(&mnt_ns_addr.to_le_bytes());

        let ns_list_addr = vaddr + 0x180;
        let mount1_addr = vaddr + 0x200;
        data[0x180..0x188].copy_from_slice(&mount1_addr.to_le_bytes());
        data[0x188..0x190].copy_from_slice(&mount1_addr.to_le_bytes());

        data[0x200..0x208].copy_from_slice(&ns_list_addr.to_le_bytes());
        data[0x208..0x210].copy_from_slice(&ns_list_addr.to_le_bytes());
        data[0x210..0x218].copy_from_slice(&0u64.to_le_bytes()); // devname = null
        data[0x218..0x220].copy_from_slice(&0u64.to_le_bytes()); // mountpoint = null
        // sb at +0x380 with valid s_type ptr → file_system_type at +0x3C0 with name_ptr = 0
        let sb_addr = vaddr + 0x380;
        data[0x220..0x228].copy_from_slice(&sb_addr.to_le_bytes());
        let fstype_addr = vaddr + 0x3C0;
        data[0x380..0x388].copy_from_slice(&fstype_addr.to_le_bytes()); // s_type
        // file_system_type.name at offset 0 = 0 (null)
        data[0x3C0..0x3C8].copy_from_slice(&0u64.to_le_bytes());

        let reader = make_test_reader(&data, vaddr, paddr);
        let mounts = walk_filesystems(&reader).unwrap();

        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].fs_type, "", "null name_ptr in file_system_type → empty fs_type");
    }

    // MountInfo struct: Debug + Clone.
    #[test]
    fn mount_info_debug_clone() {
        let m = MountInfo {
            dev_name: "/dev/sda".to_string(),
            mount_point: "/".to_string(),
            fs_type: "ext4".to_string(),
        };
        let cloned = m.clone();
        let dbg = format!("{:?}", cloned);
        assert!(dbg.contains("ext4"));
    }
}
