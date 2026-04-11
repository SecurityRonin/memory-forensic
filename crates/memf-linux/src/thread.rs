//! Linux thread walker.
//!
//! Enumerates threads within a process by walking the `thread_group`
//! linked list in `task_struct`. Each thread in a thread group shares
//! the same `tgid` but has a unique `pid` (acting as its TID).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, ProcessState, Result, ThreadInfo};

/// Walk threads for a given process (thread group leader).
///
/// Takes the virtual address of the leader `task_struct` and its `tgid`,
/// then walks the `thread_group` list to enumerate all threads in the group.
/// The leader itself is always included in the results. Results are sorted
/// by TID.
pub fn walk_threads<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    leader_task_addr: u64,
    tgid: u64,
) -> Result<Vec<ThreadInfo>> {
        todo!()
    }

fn read_thread_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
    tgid: u64,
) -> Result<ThreadInfo> {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProcessState;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // task_struct layout for thread tests:
    //   pid         @ 0   (int, 4 bytes)    — acts as TID
    //   state       @ 4   (long, 8 bytes)
    //   tasks       @ 16  (list_head)        — process list (not used here)
    //   comm        @ 32  (char, 16 bytes)
    //   mm          @ 48  (pointer)
    //   real_parent @ 56  (pointer)
    //   tgid        @ 64  (int, 4 bytes)
    //   thread_group@ 72  (list_head, 16 bytes)
    //   total size: 128

    const PID_OFF: usize = 0;
    const STATE_OFF: usize = 4;
    const COMM_OFF: usize = 32;
    const TGID_OFF: usize = 64;
    const THREAD_GROUP_OFF: usize = 72;

    fn build_reader_with_pages(pages: &[(u64, u64, &[u8])]) -> ObjectReader<SyntheticPhysMem> {
        todo!()
    }

    /// Populate a task_struct buffer at given offset within `data`.
    fn write_task(data: &mut [u8], off: usize, pid: u32, tgid: u32, state: i64, comm: &[u8]) {
        todo!()
    }

    /// Set thread_group list_head pointers (next, prev) for a task at `off`.
    fn set_thread_group(data: &mut [u8], off: usize, next: u64, prev: u64) {
        todo!()
    }

    /// Single-threaded process: thread_group list is empty (points back to leader).
    /// Result should have exactly 1 thread (the leader itself).
    #[test]
    fn single_threaded_process() {
        todo!()
    }

    /// Multi-threaded process: leader + 2 worker threads.
    /// All share tgid=100 but have distinct pids (TIDs).
    #[test]
    fn multi_threaded_process() {
        todo!()
    }

    /// Kernel thread with no additional threads (thread_group empty).
    /// Should still return 1 thread — the leader itself.
    #[test]
    fn kernel_thread_no_extra_threads() {
        todo!()
    }
}
