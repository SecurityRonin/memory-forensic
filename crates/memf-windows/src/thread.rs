//! Windows thread walker.
//!
//! Enumerates threads within a process by walking `_KPROCESS.ThreadListHead`,
//! a `_LIST_ENTRY` chain of `_KTHREAD` entries connected via `ThreadListEntry`.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, Result, ThreadState, WinThreadInfo};

/// Walk threads within a given `_EPROCESS`.
///
/// `eproc_addr` is the virtual address of the `_EPROCESS`.
/// The `_KPROCESS` is at offset `Pcb` (offset 0) within `_EPROCESS`.
/// Threads are linked via `_KPROCESS.ThreadListHead` -> `_KTHREAD.ThreadListEntry`.
pub fn walk_threads<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    eproc_addr: u64,
    pid: u64,
) -> Result<Vec<WinThreadInfo>> {
    // _KPROCESS is embedded at _EPROCESS.Pcb (offset 0).
    let pcb_offset = reader
        .symbols()
        .field_offset("_EPROCESS", "Pcb")
        .ok_or_else(|| Error::Walker("missing _EPROCESS.Pcb offset".into()))?;

    // ThreadListHead is within _KPROCESS.
    let thread_list_head_offset = reader
        .symbols()
        .field_offset("_KPROCESS", "ThreadListHead")
        .ok_or_else(|| Error::Walker("missing _KPROCESS.ThreadListHead offset".into()))?;

    let thread_list_head_vaddr = eproc_addr
        .wrapping_add(pcb_offset)
        .wrapping_add(thread_list_head_offset);

    // Walk the circular linked list: ThreadListHead -> _KTHREAD.ThreadListEntry
    let kthread_addrs = reader.walk_list_with(
        thread_list_head_vaddr,
        "_LIST_ENTRY",
        "Flink",
        "_KTHREAD",
        "ThreadListEntry",
    )?;

    kthread_addrs
        .into_iter()
        .map(|kthread_addr| read_thread_info(reader, kthread_addr, pid))
        .collect()
}

/// Read thread info from a single `_KTHREAD`.
///
/// `kthread_addr` is the base virtual address of the `_KTHREAD` structure.
/// Since `_KTHREAD` is embedded as `Tcb` at offset 0 within `_ETHREAD`,
/// `kthread_addr` is also the `_ETHREAD` base address.
fn read_thread_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    kthread_addr: u64,
    pid: u64,
) -> Result<WinThreadInfo> {
    // Read fields from _KTHREAD
    let teb_addr: u64 = reader.read_field(kthread_addr, "_KTHREAD", "Teb")?;
    let start_address: u64 = reader.read_field(kthread_addr, "_KTHREAD", "Win32StartAddress")?;
    let create_time: u64 = reader.read_field(kthread_addr, "_KTHREAD", "CreateTime")?;

    // _ETHREAD base = _KTHREAD base (since Tcb is at offset 0 within _ETHREAD).
    let ethread_addr = kthread_addr;

    // Read TID from _ETHREAD.Cid.UniqueThread.
    // _ETHREAD.Cid is a _CLIENT_ID at offset 0x620.
    // _CLIENT_ID.UniqueThread is at offset 8 within _CLIENT_ID.
    let cid_offset = reader
        .symbols()
        .field_offset("_ETHREAD", "Cid")
        .ok_or_else(|| Error::Walker("missing _ETHREAD.Cid offset".into()))?;

    let tid: u64 = reader.read_field(
        ethread_addr.wrapping_add(cid_offset),
        "_CLIENT_ID",
        "UniqueThread",
    )?;

    // Try to read the State field; fall back to Running if not available.
    let state_raw: u32 = reader
        .read_field(kthread_addr, "_KTHREAD", "State")
        .unwrap_or(0);
    let state = ThreadState::from_raw(state_raw);

    Ok(WinThreadInfo {
        tid,
        pid,
        create_time,
        start_address,
        teb_addr,
        state,
        vaddr: ethread_addr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // Offsets from windows_kernel_preset:
    // _EPROCESS:
    //   Pcb (= _KPROCESS): 0x0
    // _KPROCESS:
    //   ThreadListHead: 0x30 (_LIST_ENTRY, Flink@0, Blink@8)
    // _KTHREAD (size=1536):
    //   Teb: 0xF0 (pointer)
    //   Process: 0x220 (pointer)
    //   ThreadListEntry: 0x2F8 (_LIST_ENTRY, Flink@0, Blink@8)
    //   Win32StartAddress: 0x680 (pointer)
    //   CreateTime: 0x688 (u64)
    // _ETHREAD (size=2048):
    //   Tcb (= _KTHREAD): 0x0
    //   Cid: 0x620 (_CLIENT_ID: UniqueProcess@0, UniqueThread@8)
    // _LIST_ENTRY:
    //   Flink: 0, Blink: 8

    const KPROCESS_THREAD_LIST_HEAD: u64 = 0x30;
    const KTHREAD_TEB: u64 = 0xF0;
    const KTHREAD_THREAD_LIST_ENTRY: u64 = 0x2F8;
    const KTHREAD_WIN32_START_ADDR: u64 = 0x680;
    const KTHREAD_CREATE_TIME: u64 = 0x688;
    const ETHREAD_CID: u64 = 0x620;
    const CLIENT_ID_UNIQUE_THREAD: u64 = 8;

    /// Build an ObjectReader with the windows_kernel_preset symbols and a
    /// configured page table mapping.
    fn make_win_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset();
        let json = isf.build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// Write a _KTHREAD / _ETHREAD structure at the given physical address.
    ///
    /// Since Tcb is at offset 0 within _ETHREAD, the kthread base = ethread base.
    fn write_kthread(
        ptb: PageTableBuilder,
        paddr: u64,
        tid: u64,
        pid: u64,
        teb: u64,
        start_address: u64,
        create_time: u64,
        flink_vaddr: u64,
        blink_vaddr: u64,
    ) -> PageTableBuilder {
        ptb
            // _KTHREAD.Teb at offset 0xF0
            .write_phys_u64(paddr + KTHREAD_TEB, teb)
            // _KTHREAD.Win32StartAddress at offset 0x680
            .write_phys_u64(paddr + KTHREAD_WIN32_START_ADDR, start_address)
            // _KTHREAD.CreateTime at offset 0x688
            .write_phys_u64(paddr + KTHREAD_CREATE_TIME, create_time)
            // _KTHREAD.ThreadListEntry.Flink at offset 0x2F8
            .write_phys_u64(paddr + KTHREAD_THREAD_LIST_ENTRY, flink_vaddr)
            // _KTHREAD.ThreadListEntry.Blink at offset 0x2F8 + 8
            .write_phys_u64(paddr + KTHREAD_THREAD_LIST_ENTRY + 8, blink_vaddr)
            // _ETHREAD.Cid.UniqueProcess at offset 0x620
            .write_phys_u64(paddr + ETHREAD_CID, pid)
            // _ETHREAD.Cid.UniqueThread at offset 0x620 + 8
            .write_phys_u64(paddr + ETHREAD_CID + CLIENT_ID_UNIQUE_THREAD, tid)
    }

    #[test]
    fn walk_single_thread() {
        // One _KTHREAD within an _EPROCESS.
        //
        // Memory layout:
        //   Page 1 (eproc_vaddr): _EPROCESS with _KPROCESS.ThreadListHead
        //   Page 2 (kthread_vaddr): _KTHREAD (1536 bytes, needs 1 page)
        //
        // Circular: ThreadListHead.Flink -> kthread.ThreadListEntry
        //           kthread.ThreadListEntry.Flink -> ThreadListHead

        let eproc_paddr: u64 = 0x0080_0000;
        let kthread_paddr: u64 = 0x0080_1000;

        let eproc_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let kthread_vaddr: u64 = 0xFFFF_8000_0010_1000;

        let thread_list_head_vaddr = eproc_vaddr + KPROCESS_THREAD_LIST_HEAD;
        let kthread_list_entry_vaddr = kthread_vaddr + KTHREAD_THREAD_LIST_ENTRY;

        // ThreadListHead: Flink -> kthread.ThreadListEntry, Blink -> kthread.ThreadListEntry
        let ptb = PageTableBuilder::new()
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(kthread_vaddr, kthread_paddr, flags::WRITABLE)
            // _KPROCESS.ThreadListHead.Flink
            .write_phys_u64(
                eproc_paddr + KPROCESS_THREAD_LIST_HEAD,
                kthread_list_entry_vaddr,
            )
            // _KPROCESS.ThreadListHead.Blink
            .write_phys_u64(
                eproc_paddr + KPROCESS_THREAD_LIST_HEAD + 8,
                kthread_list_entry_vaddr,
            );

        let ptb = write_kthread(
            ptb,
            kthread_paddr,
            8,                       // tid
            4,                       // pid
            0x7FF0_0000_0000,        // teb
            0x7FF6_0000_1000,        // start_address
            132_800_000_000_000_000, // create_time
            thread_list_head_vaddr,  // Flink -> back to head
            thread_list_head_vaddr,  // Blink -> back to head
        );

        let reader = make_win_reader(ptb);
        let threads = walk_threads(&reader, eproc_vaddr, 4).unwrap();

        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].tid, 8);
        assert_eq!(threads[0].pid, 4);
        assert_eq!(threads[0].teb_addr, 0x7FF0_0000_0000);
        assert_eq!(threads[0].start_address, 0x7FF6_0000_1000);
        assert_eq!(threads[0].create_time, 132_800_000_000_000_000);
        assert_eq!(threads[0].vaddr, kthread_vaddr);
    }

    #[test]
    fn walk_two_threads() {
        // Two _KTHREAD entries in circular list within one _EPROCESS.
        //
        // Memory layout:
        //   Page 1 (eproc_vaddr): _EPROCESS with _KPROCESS.ThreadListHead
        //   Page 2 (kthread_a_vaddr): _KTHREAD A (tid=100)
        //   Page 3 (kthread_b_vaddr): _KTHREAD B (tid=200)
        //
        // Circular: ThreadListHead -> A.ThreadListEntry -> B.ThreadListEntry -> ThreadListHead

        let eproc_paddr: u64 = 0x0080_0000;
        let kthread_a_paddr: u64 = 0x0080_1000;
        let kthread_b_paddr: u64 = 0x0080_2000;

        let eproc_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let kthread_a_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let kthread_b_vaddr: u64 = 0xFFFF_8000_0010_2000;

        let thread_list_head_vaddr = eproc_vaddr + KPROCESS_THREAD_LIST_HEAD;
        let a_list_entry_vaddr = kthread_a_vaddr + KTHREAD_THREAD_LIST_ENTRY;
        let b_list_entry_vaddr = kthread_b_vaddr + KTHREAD_THREAD_LIST_ENTRY;

        // ThreadListHead.Flink -> A.ThreadListEntry
        // ThreadListHead.Blink -> B.ThreadListEntry
        let ptb = PageTableBuilder::new()
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(kthread_a_vaddr, kthread_a_paddr, flags::WRITABLE)
            .map_4k(kthread_b_vaddr, kthread_b_paddr, flags::WRITABLE)
            // _KPROCESS.ThreadListHead.Flink -> A
            .write_phys_u64(eproc_paddr + KPROCESS_THREAD_LIST_HEAD, a_list_entry_vaddr)
            // _KPROCESS.ThreadListHead.Blink -> B
            .write_phys_u64(
                eproc_paddr + KPROCESS_THREAD_LIST_HEAD + 8,
                b_list_entry_vaddr,
            );

        // Thread A: tid=100, Flink -> B, Blink -> head
        let ptb = write_kthread(
            ptb,
            kthread_a_paddr,
            100,                     // tid
            42,                      // pid
            0x7FF0_0000_1000,        // teb
            0x7FF6_0000_2000,        // start_address
            132_800_000_100_000_000, // create_time
            b_list_entry_vaddr,      // Flink -> B
            thread_list_head_vaddr,  // Blink -> head
        );

        // Thread B: tid=200, Flink -> head, Blink -> A
        let ptb = write_kthread(
            ptb,
            kthread_b_paddr,
            200,                     // tid
            42,                      // pid
            0x7FF0_0000_2000,        // teb
            0x7FF6_0000_3000,        // start_address
            132_800_000_200_000_000, // create_time
            thread_list_head_vaddr,  // Flink -> head (loop back)
            a_list_entry_vaddr,      // Blink -> A
        );

        let reader = make_win_reader(ptb);
        let threads = walk_threads(&reader, eproc_vaddr, 42).unwrap();

        assert_eq!(threads.len(), 2);

        // Thread A
        assert_eq!(threads[0].tid, 100);
        assert_eq!(threads[0].pid, 42);
        assert_eq!(threads[0].teb_addr, 0x7FF0_0000_1000);
        assert_eq!(threads[0].start_address, 0x7FF6_0000_2000);
        assert_eq!(threads[0].create_time, 132_800_000_100_000_000);
        assert_eq!(threads[0].vaddr, kthread_a_vaddr);

        // Thread B
        assert_eq!(threads[1].tid, 200);
        assert_eq!(threads[1].pid, 42);
        assert_eq!(threads[1].teb_addr, 0x7FF0_0000_2000);
        assert_eq!(threads[1].start_address, 0x7FF6_0000_3000);
        assert_eq!(threads[1].create_time, 132_800_000_200_000_000);
        assert_eq!(threads[1].vaddr, kthread_b_vaddr);
    }

    #[test]
    fn walk_empty_thread_list() {
        // _KPROCESS.ThreadListHead.Flink points back to itself -> empty list.
        let eproc_paddr: u64 = 0x0080_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_0000;

        let thread_list_head_vaddr = eproc_vaddr + KPROCESS_THREAD_LIST_HEAD;

        let ptb = PageTableBuilder::new()
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            // ThreadListHead.Flink -> self (empty)
            .write_phys_u64(
                eproc_paddr + KPROCESS_THREAD_LIST_HEAD,
                thread_list_head_vaddr,
            )
            // ThreadListHead.Blink -> self (empty)
            .write_phys_u64(
                eproc_paddr + KPROCESS_THREAD_LIST_HEAD + 8,
                thread_list_head_vaddr,
            );

        let reader = make_win_reader(ptb);
        let threads = walk_threads(&reader, eproc_vaddr, 4).unwrap();

        assert!(threads.is_empty());
    }
}
