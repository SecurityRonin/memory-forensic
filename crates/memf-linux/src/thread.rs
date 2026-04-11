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
    let mut threads = Vec::new();

    // Always include the leader itself.
    threads.push(read_thread_info(reader, leader_task_addr, tgid)?);

    // Walk the thread_group list for additional threads.
    let thread_group_offset = reader
        .symbols()
        .field_offset("task_struct", "thread_group")
        .ok_or_else(|| Error::Walker("task_struct.thread_group field not found".into()))?;

    let head_vaddr = leader_task_addr + thread_group_offset;
    let sibling_addrs = reader.walk_list(head_vaddr, "task_struct", "thread_group")?;

    for &task_addr in &sibling_addrs {
        if let Ok(info) = read_thread_info(reader, task_addr, tgid) {
            threads.push(info);
        }
    }

    threads.sort_by_key(|t| t.tid);
    Ok(threads)
}

fn read_thread_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
    tgid: u64,
) -> Result<ThreadInfo> {
    let pid: u32 = reader.read_field(task_addr, "task_struct", "pid")?;
    let state: i64 = reader.read_field(task_addr, "task_struct", "state")?;
    let comm = reader.read_field_string(task_addr, "task_struct", "comm", 16)?;

    Ok(ThreadInfo {
        tgid,
        tid: u64::from(pid),
        comm,
        state: ProcessState::from_raw(state),
    })
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

    const PID_OFF: usize = 0;
    const STATE_OFF: usize = 4;
    const COMM_OFF: usize = 32;
    const TGID_OFF: usize = 64;
    const THREAD_GROUP_OFF: usize = 72;

    fn build_reader_with_pages(pages: &[(u64, u64, &[u8])]) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "state", 4, "long")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "mm", 48, "pointer")
            .add_field("task_struct", "real_parent", 56, "pointer")
            .add_field("task_struct", "tgid", 64, "int")
            .add_field("task_struct", "thread_group", 72, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();
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

    fn write_task(data: &mut [u8], off: usize, pid: u32, tgid: u32, state: i64, comm: &[u8]) {
        data[off + PID_OFF..off + PID_OFF + 4].copy_from_slice(&pid.to_le_bytes());
        data[off + STATE_OFF..off + STATE_OFF + 8].copy_from_slice(&state.to_le_bytes());
        data[off + TGID_OFF..off + TGID_OFF + 4].copy_from_slice(&tgid.to_le_bytes());
        let end = (off + COMM_OFF + comm.len()).min(off + COMM_OFF + 16);
        data[off + COMM_OFF..end].copy_from_slice(&comm[..end - off - COMM_OFF]);
    }

    fn set_thread_group(data: &mut [u8], off: usize, next: u64, prev: u64) {
        data[off + THREAD_GROUP_OFF..off + THREAD_GROUP_OFF + 8]
            .copy_from_slice(&next.to_le_bytes());
        data[off + THREAD_GROUP_OFF + 8..off + THREAD_GROUP_OFF + 16]
            .copy_from_slice(&prev.to_le_bytes());
    }

    #[test]
    fn single_threaded_process() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        write_task(&mut data, 0, 1234, 1234, 1, b"nginx");
        let leader_tg = vaddr + THREAD_GROUP_OFF as u64;
        set_thread_group(&mut data, 0, leader_tg, leader_tg);

        let reader = build_reader_with_pages(&[(vaddr, paddr, &data)]);
        let threads = walk_threads(&reader, vaddr, 1234).unwrap();

        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].tgid, 1234);
        assert_eq!(threads[0].tid, 1234);
        assert_eq!(threads[0].comm, "nginx");
        assert_eq!(threads[0].state, ProcessState::Sleeping);
    }

    #[test]
    fn multi_threaded_process() {
        let leader_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let t1_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let t2_vaddr: u64 = 0xFFFF_8000_0030_0000;

        let leader_paddr: u64 = 0x0080_0000;
        let t1_paddr: u64 = 0x0090_0000;
        let t2_paddr: u64 = 0x00A0_0000;

        let mut leader_data = vec![0u8; 4096];
        let mut t1_data = vec![0u8; 4096];
        let mut t2_data = vec![0u8; 4096];

        write_task(&mut leader_data, 0, 100, 100, 0, b"java");
        write_task(&mut t1_data, 0, 101, 100, 1, b"java");
        write_task(&mut t2_data, 0, 102, 100, 2, b"java");

        let leader_tg = leader_vaddr + THREAD_GROUP_OFF as u64;
        let t1_tg = t1_vaddr + THREAD_GROUP_OFF as u64;
        let t2_tg = t2_vaddr + THREAD_GROUP_OFF as u64;

        set_thread_group(&mut leader_data, 0, t1_tg, t2_tg);
        set_thread_group(&mut t1_data, 0, t2_tg, leader_tg);
        set_thread_group(&mut t2_data, 0, leader_tg, t1_tg);

        let reader = build_reader_with_pages(&[
            (leader_vaddr, leader_paddr, &leader_data),
            (t1_vaddr, t1_paddr, &t1_data),
            (t2_vaddr, t2_paddr, &t2_data),
        ]);

        let threads = walk_threads(&reader, leader_vaddr, 100).unwrap();

        assert_eq!(threads.len(), 3);
        assert_eq!(threads[0].tid, 100);
        assert_eq!(threads[0].tgid, 100);
        assert_eq!(threads[0].state, ProcessState::Running);
        assert_eq!(threads[1].tid, 101);
        assert_eq!(threads[1].tgid, 100);
        assert_eq!(threads[1].state, ProcessState::Sleeping);
        assert_eq!(threads[2].tid, 102);
        assert_eq!(threads[2].tgid, 100);
        assert_eq!(threads[2].state, ProcessState::DiskSleep);
        assert!(threads.iter().all(|t| t.comm == "java"));
    }

    #[test]
    fn kernel_thread_no_extra_threads() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        write_task(&mut data, 0, 2, 2, 1, b"kthreadd");
        let leader_tg = vaddr + THREAD_GROUP_OFF as u64;
        set_thread_group(&mut data, 0, leader_tg, leader_tg);

        let reader = build_reader_with_pages(&[(vaddr, paddr, &data)]);
        let threads = walk_threads(&reader, vaddr, 2).unwrap();

        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].tgid, 2);
        assert_eq!(threads[0].tid, 2);
        assert_eq!(threads[0].comm, "kthreadd");
    }
}
