//! Linux open file descriptor walker.
//!
//! Enumerates open file descriptors by walking `task_struct.files →
//! files_struct.fdt → fdtable.fd[]` for each process in the task list.
//! Each `struct file` pointer in the fd array is dereferenced to read
//! the dentry path name and file position.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, FileDescriptorInfo, Result};

/// Walk open file descriptors for all processes.
///
/// For each process, follows `task_struct.files → files_struct.fdt →
/// fdtable` to find the fd pointer array, then dereferences each
/// non-NULL `struct file *` to read the dentry name and file position.
pub fn walk_files<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<FileDescriptorInfo>> {
    todo!()
}

/// Walk open file descriptors for a single process.
pub fn walk_process_files<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
) -> Result<Vec<FileDescriptorInfo>> {
    todo!()
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
            .add_field("task_struct", "state", 4, "long")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "mm", 48, "pointer")
            .add_field("task_struct", "files", 56, "pointer")
            // list_head
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            // files_struct
            .add_struct("files_struct", 32)
            .add_field("files_struct", "fdt", 0, "pointer")
            // fdtable
            .add_struct("fdtable", 16)
            .add_field("fdtable", "max_fds", 0, "unsigned int")
            .add_field("fdtable", "fd", 8, "pointer")
            // file
            .add_struct("file", 64)
            .add_field("file", "f_path", 0, "path")
            .add_field("file", "f_inode", 16, "pointer")
            .add_field("file", "f_pos", 24, "long long")
            // path — embedded in struct file
            .add_struct("path", 16)
            .add_field("path", "dentry", 8, "pointer")
            // dentry
            .add_struct("dentry", 64)
            .add_field("dentry", "d_name", 0, "qstr")
            .add_field("dentry", "d_inode", 48, "pointer")
            // qstr — contains inline name pointer
            .add_struct("qstr", 16)
            .add_field("qstr", "name", 8, "pointer")
            // inode
            .add_struct("inode", 64)
            .add_field("inode", "i_ino", 0, "unsigned long")
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
    fn walk_single_process_two_fds() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task (PID 1, "bash")
        data[0..4].copy_from_slice(&1u32.to_le_bytes());      // pid
        data[4..12].copy_from_slice(&0i64.to_le_bytes());     // state
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes()); // tasks.next → self
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes()); // tasks.prev → self
        data[32..36].copy_from_slice(b"bash");                   // comm
        data[48..56].copy_from_slice(&0u64.to_le_bytes());       // mm = NULL (irrelevant)
        let files_struct_addr = vaddr + 0x200;
        data[56..64].copy_from_slice(&files_struct_addr.to_le_bytes()); // files

        // files_struct at +0x200
        let fdtable_addr = vaddr + 0x300;
        data[0x200..0x208].copy_from_slice(&fdtable_addr.to_le_bytes()); // fdt

        // fdtable at +0x300
        data[0x300..0x304].copy_from_slice(&3u32.to_le_bytes());  // max_fds = 3
        let fd_array_addr = vaddr + 0x400;
        data[0x308..0x310].copy_from_slice(&fd_array_addr.to_le_bytes()); // fd array

        // fd array at +0x400: [file0_ptr, NULL, file2_ptr]
        let file0_addr = vaddr + 0x500;
        data[0x400..0x408].copy_from_slice(&file0_addr.to_le_bytes()); // fd 0
        data[0x408..0x410].copy_from_slice(&0u64.to_le_bytes());      // fd 1 = NULL (closed)
        let file2_addr = vaddr + 0x600;
        data[0x410..0x418].copy_from_slice(&file2_addr.to_le_bytes()); // fd 2

        // struct file #0 at +0x500: /dev/pts/0
        // f_path.dentry at offset 8 within path (which is at offset 0 in file)
        let dentry0_addr = vaddr + 0x700;
        data[0x508..0x510].copy_from_slice(&dentry0_addr.to_le_bytes()); // f_path.dentry
        let inode0_addr = vaddr + 0x800;
        data[0x510..0x518].copy_from_slice(&inode0_addr.to_le_bytes()); // f_inode
        data[0x518..0x520].copy_from_slice(&0u64.to_le_bytes());       // f_pos = 0

        // dentry #0 at +0x700
        // d_name (qstr) at offset 0, name pointer at qstr offset 8
        let name0_addr = vaddr + 0x780;
        data[0x708..0x710].copy_from_slice(&name0_addr.to_le_bytes()); // d_name.name
        data[0x780..0x78A].copy_from_slice(b"/dev/pts/0");             // name string
        // d_inode at offset 48
        data[0x730..0x738].copy_from_slice(&inode0_addr.to_le_bytes()); // d_inode

        // inode #0 at +0x800
        data[0x800..0x808].copy_from_slice(&4u64.to_le_bytes()); // i_ino = 4

        // struct file #2 at +0x600: /tmp/log
        let dentry2_addr = vaddr + 0x900;
        data[0x608..0x610].copy_from_slice(&dentry2_addr.to_le_bytes()); // f_path.dentry
        let inode2_addr = vaddr + 0xA00;
        data[0x610..0x618].copy_from_slice(&inode2_addr.to_le_bytes()); // f_inode
        data[0x618..0x620].copy_from_slice(&1024u64.to_le_bytes());     // f_pos = 1024

        // dentry #2 at +0x900
        let name2_addr = vaddr + 0x980;
        data[0x908..0x910].copy_from_slice(&name2_addr.to_le_bytes()); // d_name.name
        data[0x980..0x988].copy_from_slice(b"/tmp/log");               // name string
        data[0x930..0x938].copy_from_slice(&inode2_addr.to_le_bytes()); // d_inode

        // inode #2 at +0xA00
        data[0xA00..0xA08].copy_from_slice(&42u64.to_le_bytes()); // i_ino = 42

        let reader = make_test_reader(&data, vaddr, paddr);
        let fds = walk_files(&reader).unwrap();

        assert_eq!(fds.len(), 2);

        assert_eq!(fds[0].pid, 1);
        assert_eq!(fds[0].comm, "bash");
        assert_eq!(fds[0].fd, 0);
        assert_eq!(fds[0].path, "/dev/pts/0");
        assert_eq!(fds[0].inode, Some(4));
        assert_eq!(fds[0].pos, 0);

        assert_eq!(fds[1].fd, 2);
        assert_eq!(fds[1].path, "/tmp/log");
        assert_eq!(fds[1].inode, Some(42));
        assert_eq!(fds[1].pos, 1024);
    }

    #[test]
    fn walk_files_skips_kernel_threads() {
        // Kernel threads have files == NULL — should produce no FDs
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        data[0..4].copy_from_slice(&0u32.to_le_bytes());         // pid = 0
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes()); // tasks.next → self
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes()); // tasks.prev → self
        data[32..41].copy_from_slice(b"swapper/0");
        data[56..64].copy_from_slice(&0u64.to_le_bytes());       // files = NULL

        let reader = make_test_reader(&data, vaddr, paddr);
        let fds = walk_files(&reader).unwrap();

        assert!(fds.is_empty());
    }

    #[test]
    fn walk_process_files_null_files_returns_error() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        data[56..64].copy_from_slice(&0u64.to_le_bytes()); // files = NULL

        let reader = make_test_reader(&data, vaddr, paddr);
        let result = walk_process_files(&reader, vaddr);
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

        let result = walk_files(&reader);
        assert!(result.is_err());
    }
}
