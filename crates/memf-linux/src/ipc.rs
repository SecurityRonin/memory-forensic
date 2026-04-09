//! Linux System V IPC object enumeration.
//!
//! Enumerates shared memory segments, semaphores, and message queues from
//! kernel memory by walking the `shm_ids` and `sem_ids` structures. These
//! IPC mechanisms can be used for covert data exchange between processes
//! and are relevant for detecting process collaboration or C2 channels.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about a System V shared memory segment.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IpcShmInfo {
    /// IPC key used to create/access the segment.
    pub key: u32,
    /// Shared memory identifier.
    pub shmid: u32,
    /// Size of the shared memory segment in bytes.
    pub size: u64,
    /// PID of the last process to operate on the segment.
    pub owner_pid: u32,
    /// PID of the process that created the segment.
    pub creator_pid: u32,
    /// Permission bits (rwxrwxrwx).
    pub permissions: u32,
    /// Number of current attaches.
    pub num_attaches: u32,
}

/// Information about a System V semaphore set.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IpcSemInfo {
    /// IPC key used to create/access the semaphore set.
    pub key: u32,
    /// Semaphore set identifier.
    pub semid: u32,
    /// Number of semaphores in the set.
    pub num_sems: u32,
    /// PID of the owner.
    pub owner_pid: u32,
    /// Permission bits (rwxrwxrwx).
    pub permissions: u32,
}

/// Maximum number of IPC IDs to walk (cycle/runaway protection).
const MAX_IPC_IDS: usize = 32_768;

/// Walk System V shared memory segments via the kernel `shm_ids` structure.
///
/// Returns `Ok(Vec::new())` if the `shm_ids` symbol is not found (profile
/// may not include it).
pub fn walk_shm_segments<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<IpcShmInfo>> {
    todo!()
}

/// Walk System V semaphore sets via the kernel `sem_ids` structure.
///
/// Returns `Ok(Vec::new())` if the `sem_ids` symbol is not found (profile
/// may not include it).
pub fn walk_semaphores<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<IpcSemInfo>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Build an ObjectReader with NO IPC symbols at all — simulates a profile
    /// that does not contain `shm_ids` or `sem_ids`.
    fn make_empty_reader() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let data = vec![0u8; 4096];
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// Build an ObjectReader with IPC struct definitions and a single shared
    /// memory segment laid out in synthetic memory.
    fn make_shm_reader(
        data: &[u8],
        vaddr: u64,
        paddr: u64,
    ) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            // ipc_ids: the top-level container for an IPC namespace
            .add_struct("ipc_ids", 64)
            .add_field("ipc_ids", "in_use", 0, "unsigned int")
            .add_field("ipc_ids", "ipcs_idr", 8, "idr")
            // idr: simplified — we treat it as having a pointer to the
            // radix tree root node
            .add_struct("idr", 32)
            .add_field("idr", "idr_rt", 0, "radix_tree_root")
            // radix_tree_root: simplified single-slot tree for testing
            .add_struct("radix_tree_root", 16)
            .add_field("radix_tree_root", "xa_head", 0, "pointer")
            // kern_ipc_perm: common IPC permission header
            .add_struct("kern_ipc_perm", 64)
            .add_field("kern_ipc_perm", "key", 0, "unsigned int")
            .add_field("kern_ipc_perm", "id", 4, "unsigned int")
            .add_field("kern_ipc_perm", "mode", 8, "unsigned int")
            // shmid_kernel: kernel shared memory descriptor
            .add_struct("shmid_kernel", 128)
            .add_field("shmid_kernel", "shm_perm", 0, "kern_ipc_perm")
            .add_field("shmid_kernel", "shm_segsz", 64, "unsigned long")
            .add_field("shmid_kernel", "shm_cprid", 72, "unsigned int")
            .add_field("shmid_kernel", "shm_lprid", 76, "unsigned int")
            .add_field("shmid_kernel", "shm_nattch", 80, "unsigned int")
            .add_symbol("shm_ids", vaddr)
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
    fn walk_shm_no_symbol() {
        let reader = make_empty_reader();
        let result = walk_shm_segments(&reader).unwrap();
        assert!(result.is_empty(), "no shm_ids symbol should yield empty vec");
    }

    #[test]
    fn walk_sem_no_symbol() {
        let reader = make_empty_reader();
        let result = walk_semaphores(&reader).unwrap();
        assert!(result.is_empty(), "no sem_ids symbol should yield empty vec");
    }

    #[test]
    fn walk_shm_single_segment() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // ipc_ids at offset 0 (vaddr + 0):
        //   in_use (u32 at +0) = 1
        //   ipcs_idr (at +8): idr struct
        //     idr_rt (at +0 within idr = +8 overall): radix_tree_root
        //       xa_head (pointer at +0 within radix_tree_root = +8 overall)
        //         points to shmid_kernel at vaddr + 0x200
        data[0..4].copy_from_slice(&1u32.to_le_bytes()); // in_use = 1

        let shm_kernel_addr = vaddr + 0x200;
        // xa_head pointer at offset 8 (ipc_ids.ipcs_idr.idr_rt.xa_head)
        data[8..16].copy_from_slice(&shm_kernel_addr.to_le_bytes());

        // shmid_kernel at offset 0x200:
        //   shm_perm.key (u32 at +0) = 0xDEAD
        //   shm_perm.id  (u32 at +4) = 42
        //   shm_perm.mode (u32 at +8) = 0o666 = 0x1B6
        //   shm_segsz (u64 at +64) = 65536
        //   shm_cprid (u32 at +72) = 1000
        //   shm_lprid (u32 at +76) = 2000
        //   shm_nattch (u32 at +80) = 3
        let base = 0x200;
        data[base..base + 4].copy_from_slice(&0xDEADu32.to_le_bytes());
        data[base + 4..base + 8].copy_from_slice(&42u32.to_le_bytes());
        data[base + 8..base + 12].copy_from_slice(&0x1B6u32.to_le_bytes());
        data[base + 64..base + 72].copy_from_slice(&65536u64.to_le_bytes());
        data[base + 72..base + 76].copy_from_slice(&1000u32.to_le_bytes());
        data[base + 76..base + 80].copy_from_slice(&2000u32.to_le_bytes());
        data[base + 80..base + 84].copy_from_slice(&3u32.to_le_bytes());

        let reader = make_shm_reader(&data, vaddr, paddr);
        let segments = walk_shm_segments(&reader).unwrap();

        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].key, 0xDEAD);
        assert_eq!(segments[0].shmid, 42);
        assert_eq!(segments[0].size, 65536);
        assert_eq!(segments[0].creator_pid, 1000);
        assert_eq!(segments[0].owner_pid, 2000);
        assert_eq!(segments[0].permissions, 0x1B6);
        assert_eq!(segments[0].num_attaches, 3);
    }
}
