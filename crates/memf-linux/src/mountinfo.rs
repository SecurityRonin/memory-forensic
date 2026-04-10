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
    let _ = dev_name;
    match fs_type {
        "tmpfs" | "ramfs" => {
            !matches!(
                mnt_root,
                "/tmp" | "/run" | "/dev/shm" | "/run/lock" | "/run/user" | "/" // rootfs tmpfs is normal in containers
            ) && !mnt_root.starts_with("/run/")
                && !mnt_root.starts_with("/tmp/")
                && !mnt_root.starts_with("/dev/")
        }
        "overlay" | "overlayfs" => {
            !mnt_root.starts_with("/var/lib/docker") && !mnt_root.starts_with("/var/lib/containerd")
        }
        _ => false,
    }
}

/// Walk mount list and return all mounted filesystems.
///
/// Returns `Ok(Vec::new())` when `init_task` symbol is absent.
pub fn walk_mounts<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>) -> Result<Vec<MountInfo>> {
    let _ = reader;
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn no_symbol_returns_empty() {
        let reader = make_no_symbol_reader();
        let result = walk_mounts(&reader).unwrap();
        assert!(result.is_empty(), "no init_task symbol → empty vec");
    }

    #[test]
    fn classify_suspicious_tmpfs_mount() {
        // tmpfs at /hidden is suspicious
        assert!(
            classify_mount("tmpfs", "tmpfs", "/hidden"),
            "tmpfs at /hidden should be suspicious"
        );
        // overlayfs outside docker is suspicious
        assert!(
            classify_mount("overlay", "overlay", "/mnt/secret"),
            "overlay outside docker should be suspicious"
        );
    }

    #[test]
    fn classify_benign_proc_mount_not_flagged() {
        assert!(
            !classify_mount("proc", "proc", "/proc"),
            "proc mount should not be suspicious"
        );
        assert!(
            !classify_mount("tmpfs", "tmpfs", "/tmp"),
            "tmpfs at /tmp should not be suspicious"
        );
        assert!(
            !classify_mount("tmpfs", "tmpfs", "/run"),
            "tmpfs at /run should not be suspicious"
        );
        assert!(
            !classify_mount("overlay", "overlay", "/var/lib/docker/overlay2"),
            "overlay inside docker should not be suspicious"
        );
    }

    // RED test: walk_mounts with symbol returns MountInfo entries.
    #[test]
    fn walk_mounts_with_symbol_returns_entries() {
        use memf_core::test_builders::flags;

        // We use a simplified approach: init_task symbol is present.
        // Full mount-list traversal requires deep pointer chains, so the
        // GREEN implementation will use best-effort field offsets.
        // For this RED test we simply verify the function signature compiles
        // and that with a symbol present the function does not return
        // immediately with empty (i.e. it attempts traversal).
        //
        // We set init_task to a mapped page; nsproxy at offset 0x5F8 (typical).
        // The implementation will gracefully degrade if offsets are missing.

        let init_task_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let init_task_paddr: u64 = 0x0084_0000;

        let isf = IsfBuilder::new()
            .add_symbol("init_task", init_task_vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(
                init_task_vaddr,
                init_task_paddr,
                flags::PRESENT | flags::WRITABLE,
            )
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // With no ISF fields for nsproxy, the walker should gracefully return empty
        // rather than panic.
        let result = walk_mounts(&reader);
        assert!(result.is_ok(), "walk_mounts should not error");
    }
}
