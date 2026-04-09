//! Detect files hidden via dentry unlink (open-but-unlinked file descriptors).
//!
//! A classic rootkit technique is to `unlink()` a file while keeping a file
//! descriptor open. The file disappears from the directory tree (`i_nlink == 0`)
//! but remains accessible via the open fd. This walker scans every process's
//! open fd table looking for file-backed fds whose dentry inode has `i_nlink == 0`.
//!
//! MITRE ATT&CK: T1564.001 — Hide Artifacts: Hidden Files and Directories.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use serde::Serialize;

use crate::Result;

/// Information about a hidden (unlinked but open) file descriptor.
#[derive(Debug, Clone, Serialize)]
pub struct HiddenDentryInfo {
    /// Process ID.
    pub pid: u32,
    /// Process command name (`task_struct.comm`, max 16 chars).
    pub comm: String,
    /// File descriptor number.
    pub fd: u32,
    /// Virtual address of the `struct dentry` in kernel memory.
    pub dentry_addr: u64,
    /// Filename from `dentry->d_name`.
    pub filename: String,
    /// Inode number from `dentry->d_inode->i_ino`.
    pub inode_num: u64,
    /// File size in bytes from `dentry->d_inode->i_size`.
    pub file_size: u64,
    /// Hard link count (`dentry->d_inode->i_nlink`); 0 means the file is unlinked.
    pub nlink: u32,
    /// Whether this hidden dentry is considered suspicious.
    pub is_suspicious: bool,
}

/// Classify whether an open-but-unlinked file descriptor is suspicious.
pub fn classify_hidden_dentry(_nlink: u32, _filename: &str) -> bool {
    todo!("RED: implement classify_hidden_dentry")
}

/// Walk the task list and enumerate all open-but-unlinked file descriptors.
pub fn walk_dentry_cache<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
) -> Result<Vec<HiddenDentryInfo>> {
    todo!("RED: implement walk_dentry_cache")
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // -----------------------------------------------------------------------
    // classify_hidden_dentry unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn classify_hidden_nlink_zero_is_suspicious() {
        assert!(
            classify_hidden_dentry(0, "rootkit.so"),
            "nlink==0 file must be suspicious"
        );
    }

    #[test]
    fn classify_hidden_so_file_suspicious() {
        assert!(
            classify_hidden_dentry(0, "libevil.so"),
            "unlinked .so file must be suspicious"
        );
    }

    #[test]
    fn classify_hidden_nlink_positive_not_suspicious() {
        assert!(
            !classify_hidden_dentry(1, "normal.txt"),
            "file with nlink>0 and no suspicious extension must not be suspicious"
        );
    }

    #[test]
    fn classify_hidden_empty_filename_not_suspicious() {
        assert!(
            !classify_hidden_dentry(0, ""),
            "empty filename (kernel internal) must not be suspicious"
        );
    }

    #[test]
    fn classify_hidden_sh_script_suspicious() {
        assert!(
            classify_hidden_dentry(0, "dropper.sh"),
            "unlinked .sh script must be suspicious"
        );
    }

    #[test]
    fn classify_hidden_py_script_suspicious() {
        assert!(
            classify_hidden_dentry(0, "stage2.py"),
            "unlinked .py script must be suspicious"
        );
    }

    // -----------------------------------------------------------------------
    // walk_dentry_cache integration tests
    // -----------------------------------------------------------------------

    fn make_reader_no_init_task() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    fn make_reader_no_open_files() -> ObjectReader<SyntheticPhysMem> {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;

        let mut data = vec![0u8; 4096];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        let tasks_next = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_next.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_next.to_le_bytes());
        data[32..39].copy_from_slice(b"kthread");
        data[48..56].copy_from_slice(&0u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "files", 48, "pointer")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("init_task", vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_dentry_missing_init_task_returns_empty() {
        let reader = make_reader_no_init_task();
        let result = walk_dentry_cache(&reader).expect("should not error");
        assert!(
            result.is_empty(),
            "missing init_task must yield empty results (graceful degradation)"
        );
    }

    #[test]
    fn walk_dentry_no_open_files_returns_empty() {
        let reader = make_reader_no_open_files();
        let result = walk_dentry_cache(&reader).expect("should not error");
        assert!(
            result.is_empty(),
            "kernel thread with files==NULL must produce no hidden-dentry results"
        );
    }
}
