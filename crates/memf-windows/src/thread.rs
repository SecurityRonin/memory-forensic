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
        todo!()
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
        todo!()
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
        todo!()
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
        todo!()
    }

    #[test]
    fn walk_single_thread() {
        todo!()
    }

    #[test]
    fn walk_two_threads() {
        todo!()
    }

    #[test]
    fn walk_empty_thread_list() {
        todo!()
    }
}
