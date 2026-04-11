//! Direct/indirect system call detection for EDR bypass analysis.
//!
//! Detects processes using direct or indirect system call invocations to
//! bypass EDR API hooks. When malware calls Nt* functions directly via the
//! `syscall`/`sysenter` instruction instead of through `ntdll.dll`, it
//! bypasses usermode hooks placed by security products.
//!
//! Key techniques detected:
//! - **Direct syscall**: The `syscall` instruction lives in non-ntdll code
//!   (SysWhispers, HellsGate, Halo's Gate).
//! - **Indirect syscall**: Code jumps into ntdll's `syscall` gadget from a
//!   non-system module to make the return address appear legitimate.
//! - **Heaven's Gate**: 32-bit process transitions to 64-bit mode to invoke
//!   64-bit NT syscalls directly, bypassing WoW64 layer hooks.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{process, thread, DirectSyscallInfo, Result};

/// Classify whether a syscall invocation is suspicious.
///
/// Rules:
/// - A `syscall`/`sysenter` instruction **outside** ntdll.dll is always
///   suspicious (direct syscall from injected or packed code).
/// - An `indirect_syscall` (trampoline through ntdll) is suspicious when
///   the originating module is not a known system DLL.
/// - `heavens_gate` (32-to-64-bit transition) is always suspicious.
/// - A normal syscall inside ntdll with a standard technique is benign.
pub fn classify_syscall_technique(in_ntdll: bool, technique: &str) -> bool {
        todo!()
    }

/// Walk all processes and threads to detect direct/indirect syscall usage.
///
/// For each thread, checks whether the last syscall instruction address
/// falls within ntdll.dll's `.text` section range. Threads where the
/// `syscall`/`sysenter` instruction is outside ntdll are flagged.
///
/// Returns an empty `Vec` if the `PsActiveProcessHead` symbol is missing.
pub fn walk_direct_syscalls<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
) -> Result<Vec<DirectSyscallInfo>> {
        todo!()
    }

/// Attempt to find ntdll.dll's base address and size from the process's
/// PEB LDR module list. Returns `None` if the range cannot be determined.
fn find_ntdll_range<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
    proc: &crate::WinProcessInfo,
) -> Option<(u64, u64)> {
        todo!()
    }

/// Read syscall-related fields from a `_KTHREAD`/`_ETHREAD`.
///
/// Returns `(syscall_address, syscall_number, technique)` or `None` if the
/// fields cannot be read.
fn read_thread_syscall_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ethread_addr: u64,
) -> Option<(u64, u32, String)> {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;

    // -- Classifier unit tests -------------------------------------------

    #[test]
    fn classify_direct_outside_ntdll_suspicious() {
        todo!()
    }

    #[test]
    fn classify_normal_ntdll_benign() {
        todo!()
    }

    #[test]
    fn classify_heavens_gate_suspicious() {
        todo!()
    }

    #[test]
    fn classify_indirect_from_unknown_suspicious() {
        todo!()
    }

    #[test]
    fn classify_unknown_technique_outside_ntdll_suspicious() {
        todo!()
    }

    #[test]
    fn classify_unknown_technique_inside_ntdll_benign() {
        todo!()
    }

    // -- Walker tests ----------------------------------------------------

    #[test]
    fn walk_direct_syscalls_no_symbol_returns_empty() {
        todo!()
    }

    /// Walker with PsActiveProcessHead symbol present but unreadable process list
    /// returns empty (graceful degradation on unreadable memory).
    #[test]
    fn walk_direct_syscalls_with_symbol_unreadable_head() {
        todo!()
    }

    /// Heavens gate is suspicious regardless of ntdll location.
    #[test]
    fn classify_heavens_gate_always_suspicious() {
        todo!()
    }

    /// Direct syscall in ntdll is benign; outside is suspicious.
    #[test]
    fn classify_direct_syscall_ntdll_boundary() {
        todo!()
    }

    /// Indirect syscall is always suspicious regardless of ntdll context.
    #[test]
    fn classify_indirect_syscall_always_suspicious() {
        todo!()
    }

    /// Unknown technique inside ntdll is benign; outside is suspicious.
    #[test]
    fn classify_unknown_technique_boundary() {
        todo!()
    }

    /// Walker with PsActiveProcessHead pointing to an empty circular list
    /// exercises the walk body (process loop) and returns empty.
    #[test]
    fn walk_direct_syscalls_empty_process_list() {
        todo!()
    }

    /// DirectSyscallInfo can be constructed and its fields are accessible.
    #[test]
    fn direct_syscall_info_fields() {
        todo!()
    }

    // -- read_thread_syscall_info tests -------------------------------------

    /// read_thread_syscall_info from unmapped ethread addr returns Some((0, 0, "direct_syscall")).
    /// The function uses unwrap_or(0) so it always returns Some.
    #[test]
    fn read_thread_syscall_info_unmapped_returns_some_zeroes() {
        todo!()
    }

    /// read_thread_syscall_info with a 32-bit (WoW64) Win32StartAddress returns heavens_gate.
    #[test]
    fn read_thread_syscall_info_wow64_address_heavens_gate() {
        todo!()
    }

    /// read_thread_syscall_info with a 64-bit Win32StartAddress returns direct_syscall.
    #[test]
    fn read_thread_syscall_info_64bit_address_direct_syscall() {
        todo!()
    }

    // -- find_ntdll_range tests ------------------------------------------

    /// find_ntdll_range: peb_addr is 0 (proc.peb_addr used internally but
    /// find_ntdll_range reads proc.peb_addr directly) → ldr read fails → None.
    #[test]
    fn find_ntdll_range_null_peb_returns_none() {
        todo!()
    }

    /// find_ntdll_range: PEB readable, Ldr = 0 → returns None.
    #[test]
    fn find_ntdll_range_zero_ldr_returns_none() {
        todo!()
    }

    /// find_ntdll_range: PEB readable, Ldr non-zero but unmapped → walk_list_with fails → None.
    #[test]
    fn find_ntdll_range_unmapped_ldr_returns_none() {
        todo!()
    }

    /// classify_syscall_technique: exhaustive boundary table.
    #[test]
    fn classify_syscall_exhaustive_boundaries() {
        todo!()
    }

    /// DirectSyscallInfo clone works correctly.
    #[test]
    fn direct_syscall_info_clone() {
        todo!()
    }

    /// DirectSyscallInfo serialization includes all expected fields.
    #[test]
    fn direct_syscall_info_serializes() {
        todo!()
    }

    // -- Walk body: process loop with non-zero PEB + thread ---------------
    //
    // Constants from windows_kernel_preset (matching process.rs and thread.rs):
    //   _EPROCESS: ActiveProcessLinks @ 0x448, Peb @ 0x550, Pcb (=_KPROCESS) @ 0
    //   _KPROCESS: DirectoryTableBase @ 0x28, ThreadListHead @ 0x30
    //   _KTHREAD:  ThreadListEntry @ 0x2F8
    //   read_thread_syscall_info defaults: SystemCallNumber @ 0x80, Win32StartAddress @ 0x560

    const EPROCESS_LINKS: u64 = 0x448;
    const EPROCESS_PEB: u64 = 0x550;
    const EPROCESS_PID: u64 = 0x440;
    const EPROCESS_PPID: u64 = 0x540;
    const EPROCESS_DTB: u64 = 0x28;  // within _KPROCESS (= eproc + Pcb=0)
    const EPROCESS_IMAGE: u64 = 0x5A8;
    const KPROCESS_TLH: u64 = 0x30;  // _KPROCESS.ThreadListHead within _EPROCESS
    const KTHREAD_TLE: u64 = 0x2F8;  // _KTHREAD.ThreadListEntry

    /// Walker with a process having peb_addr != 0 but empty thread list:
    /// - exercises lines 70-86 (skip-kernel guard passes, thread walk returns empty)
    /// - ntdll_range = None (PEB is not mapped → find_ntdll_range returns None)
    #[test]
    fn walk_direct_syscalls_process_nonzero_peb_no_threads() {
        todo!()
    }

    /// Walker with a process (peb_addr != 0) and one thread whose Win32StartAddress
    /// is a 64-bit kernel address (> 0xFFFF_FFFF) → classified as direct_syscall.
    /// syscall_addr != 0 so the entry IS pushed. ntdll_range = None (peb not mapped).
    /// Exercises lines 88-121 (thread loop and results push).
    #[test]
    fn walk_direct_syscalls_process_with_thread_direct_syscall() {
        todo!()
    }

    /// Walker where the process PEB is 0: exercises the `if proc.peb_addr == 0 { continue }`
    /// guard (line 70-71) by verifying no entries are produced for a kernel process.
    #[test]
    fn walk_direct_syscalls_process_zero_peb_skipped() {
        todo!()
    }

    /// find_ntdll_range: module list has one entry that is NOT ntdll.dll → returns None.
    /// Exercises the module name comparison loop (L174-199) — non-matching name path.
    #[test]
    fn find_ntdll_range_non_ntdll_module_returns_none() {
        todo!()
    }
}
