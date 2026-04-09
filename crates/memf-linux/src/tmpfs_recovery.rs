//! Tmpfs/ramfs inode enumeration for ephemeral file recovery.
//!
//! Walks the kernel `super_blocks` list to find all tmpfs/ramfs superblocks,
//! then enumerates their in-memory inodes via `s_inodes` (`i_sb_list`).
//! Executable or hidden files are flagged as suspicious.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about a file found in an in-memory tmpfs/ramfs filesystem.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TmpfsFileInfo {
    /// Inode number.
    pub inode_number: u64,
    /// Filename recovered from dentry cache (empty if not cached).
    pub filename: String,
    /// File size in bytes.
    pub file_size: u64,
    /// User ID of the file owner.
    pub uid: u32,
    /// Group ID of the file owner.
    pub gid: u32,
    /// File mode (permissions + type bits).
    pub mode: u32,
    /// Last access time (seconds since epoch).
    pub atime_sec: u64,
    /// Last modification time (seconds since epoch).
    pub mtime_sec: u64,
    /// Last status-change time (seconds since epoch).
    pub ctime_sec: u64,
    /// True when the file has the executable bit set or starts with `.` (hidden).
    pub is_suspicious: bool,
}

/// Classify whether a tmpfs file is suspicious.
pub fn classify_tmpfs_file(_filename: &str, _mode: u32) -> bool {
    todo!("classify_tmpfs_file not yet implemented")
}

/// Walk all tmpfs/ramfs inodes across all superblocks in memory.
///
/// Returns `Ok(Vec::new())` when the `super_blocks` symbol or required ISF
/// offsets are absent (graceful degradation).
pub fn walk_tmpfs_files<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
) -> Result<Vec<TmpfsFileInfo>> {
    todo!("walk_tmpfs_files not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_no_symbol_reader() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn classify_executable_tmpfs_file_suspicious() {
        assert!(
            classify_tmpfs_file("script.sh", 0o100_755),
            "executable file must be suspicious"
        );
    }

    #[test]
    fn classify_hidden_file_suspicious() {
        assert!(
            classify_tmpfs_file(".hidden_file", 0o100_644),
            "hidden file must be suspicious"
        );
    }

    #[test]
    fn classify_normal_tmpfs_file_benign() {
        assert!(
            !classify_tmpfs_file("data.bin", 0o100_644),
            "non-executable non-hidden file must not be suspicious"
        );
    }

    #[test]
    fn walk_tmpfs_no_symbol_returns_empty() {
        let reader = make_no_symbol_reader();
        let result = walk_tmpfs_files(&reader).unwrap();
        assert!(result.is_empty(), "no super_blocks symbol → empty vec expected");
    }
}
