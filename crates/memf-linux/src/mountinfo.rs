//! Mount namespace forensics — enumerate mounts from kernel memory.
//!
//! Walks the mount list via `init_task` → `nsproxy` → `mnt_ns` → `list` of
//! `mount` structs and extracts mount point information.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about a single kernel mount entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MountInfo {
    /// Kernel mount id.
    pub mnt_id: u32,
    /// Parent mount id.
    pub parent_id: u32,
    /// Device name string (e.g. "/dev/sda1").
    pub dev_name: String,
    /// Mount root path (best-effort).
    pub mnt_root: String,
    /// Mount flags bitmask.
    pub mnt_flags: u32,
    /// Filesystem type name (e.g. "ext4", "tmpfs").
    pub fs_type: String,
    /// True when the mount exhibits suspicious characteristics.
    pub is_suspicious: bool,
}

/// Classify whether a mount is suspicious.
///
/// Suspicious criteria:
/// - `tmpfs` or `ramfs` at a non-standard path (not `/tmp`, `/run`, `/dev/shm`)
/// - `overlay` or `overlayfs` outside `/var/lib/docker` / `/var/lib/containerd`
pub fn classify_mount(fs_type: &str, dev_name: &str, mnt_root: &str) -> bool {
        todo!()
    }

/// Walk mount list and return all mounted filesystems.
///
/// Returns `Ok(Vec::new())` when `init_task` symbol is absent.
pub fn walk_mounts<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>) -> Result<Vec<MountInfo>> {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_no_symbol_reader() -> ObjectReader<SyntheticPhysMem> {
        todo!()
    }

    #[test]
    fn no_symbol_returns_empty() {
        todo!()
    }

    #[test]
    fn classify_suspicious_tmpfs_mount() {
        todo!()
    }

    #[test]
    fn classify_benign_proc_mount_not_flagged() {
        todo!()
    }

    #[test]
    fn classify_mount_tmpfs_benign_variants() {
        todo!()
    }

    #[test]
    fn classify_mount_overlay_containerd_benign() {
        todo!()
    }

    #[test]
    fn classify_mount_other_fs_type_not_suspicious() {
        todo!()
    }

    // MountInfo struct: instantiation, Clone, Debug, Serialize coverage.
    #[test]
    fn mount_info_struct_clone_debug_serialize() {
        todo!()
    }

    #[test]
    fn mount_info_suspicious_struct() {
        todo!()
    }

    // RED test: walk_mounts with symbol returns MountInfo entries.
    #[test]
    fn walk_mounts_with_symbol_returns_entries() {
        todo!()
    }
}
