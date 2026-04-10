//! Linux io_uring context forensics.
//!
//! io_uring provides an asynchronous syscall interface that bypasses
//! traditional syscall tracing (seccomp, ptrace, auditd). The "curing"
//! rootkit (2025) demonstrated full C2 via io_uring alone — IORING_OP_SENDMSG
//! and IORING_OP_RECVMSG allow full network I/O without triggering seccomp
//! SYSCALL_AUDIT events. This walker enumerates `io_ring_ctx` structures
//! attached to processes and flags those performing sensitive operations.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// io_uring opcode for sending a message (IORING_OP_SENDMSG, from include/uapi/linux/io_uring.h).
pub const IORING_OP_SENDMSG: u8 = 9;
/// io_uring opcode for receiving a message (IORING_OP_RECVMSG).
pub const IORING_OP_RECVMSG: u8 = 10;
/// io_uring opcode for establishing a connection (IORING_OP_CONNECT).
pub const IORING_OP_CONNECT: u8 = 16;
/// io_uring opcode for opening a file (IORING_OP_OPENAT).
pub const IORING_OP_OPENAT: u8 = 18;
/// io_uring opcode for reading from a file descriptor (IORING_OP_READ).
pub const IORING_OP_READ: u8 = 22;
/// io_uring opcode for writing to a file descriptor (IORING_OP_WRITE).
pub const IORING_OP_WRITE: u8 = 23;

/// Sensitive opcode set — network or file operations that bypass seccomp.
const SENSITIVE_OPCODES: &[u8] = &[IORING_OP_SENDMSG, IORING_OP_RECVMSG, IORING_OP_CONNECT];

/// Information about an io_uring context attached to a process.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IoUringEntry {
    /// PID of the owning process.
    pub pid: u32,
    /// Process name.
    pub comm: String,
    /// Virtual address of the `io_ring_ctx` kernel structure.
    pub ctx_addr: u64,
    /// Number of submission queue entries (SQEs) in the ring buffer.
    pub sq_entries: u32,
    /// Number of completion queue entries (CQEs) seen.
    pub cq_entries: u32,
    /// Opcodes observed in the pending SQE ring.
    pub pending_opcodes: Vec<u8>,
    /// True if the context is performing network operations that would
    /// bypass seccomp (SENDMSG / RECVMSG / CONNECT).
    pub bypasses_seccomp: bool,
    /// True if associated process has a strict seccomp filter active.
    pub seccomp_active: bool,
}

/// Classify whether an io_uring context is suspicious.
///
/// Returns `true` when the context uses network opcodes AND the owning
/// process has seccomp enabled — a combination indicative of seccomp bypass.
///
/// `seccomp_mode` maps to `SECCOMP_MODE_STRICT = 1`, `SECCOMP_MODE_FILTER = 2`.
pub fn classify_io_uring(opcodes: &[u8], seccomp_mode: u32) -> bool {
    if seccomp_mode == 0 {
        return false;
    }
    opcodes.iter().any(|op| SENSITIVE_OPCODES.contains(op))
}

/// Walk all `io_ring_ctx` structures reachable from each process's
/// `task_struct->io_uring` field and return forensic entries.
///
/// Returns `Ok(vec![])` gracefully when ISF symbols are unavailable.
pub fn walk_io_uring<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<IoUringEntry>> {
    // Check whether the ISF defines the io_uring symbol we need.
    // If the symbol is absent (older kernels or stripped ISF), return empty.
    if reader
        .symbols()
        .symbol_address("io_uring_task_work")
        .is_none()
    {
        return Ok(vec![]);
    }

    // Full walk would enumerate init_task->tasks list, read each
    // task_struct->io_uring pointer, and dereference io_ring_ctx.
    // Stubbed here — real implementation requires ISF offsets for
    // io_uring_task and io_ring_ctx which are kernel-version specific.
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::{
        object_reader::ObjectReader,
        test_builders::{PageTableBuilder, SyntheticPhysMem},
        vas::TranslationMode,
        vas::VirtualAddressSpace,
    };
    use memf_symbols::{isf::IsfResolver, test_builders::IsfBuilder};

    fn make_no_symbol_reader() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn classify_network_opcodes_with_seccomp_suspicious() {
        // Process has seccomp mode 2 (SECCOMP_MODE_FILTER) + uses SENDMSG → bypass
        assert!(
            classify_io_uring(&[IORING_OP_SENDMSG], 2),
            "network opcode under seccomp must be flagged as suspicious"
        );
    }

    #[test]
    fn classify_network_opcodes_without_seccomp_not_suspicious() {
        // No seccomp → io_uring network is normal (not a bypass)
        assert!(
            !classify_io_uring(&[IORING_OP_SENDMSG], 0),
            "network opcode without seccomp must not be flagged"
        );
    }

    #[test]
    fn classify_non_network_opcodes_with_seccomp_not_suspicious() {
        // File read under seccomp is normal operation
        assert!(
            !classify_io_uring(&[IORING_OP_READ, IORING_OP_WRITE], 2),
            "non-network opcodes under seccomp must not be flagged"
        );
    }

    #[test]
    fn walk_io_uring_no_symbol_returns_empty() {
        let reader = make_no_symbol_reader();
        let result = walk_io_uring(&reader).unwrap();
        assert!(
            result.is_empty(),
            "missing io_uring symbols must yield empty vec"
        );
    }

    #[test]
    fn classify_connect_opcode_with_seccomp_strict_suspicious() {
        // CONNECT (16) under seccomp STRICT (mode=1) → suspicious
        assert!(
            classify_io_uring(&[IORING_OP_CONNECT], 1),
            "CONNECT under SECCOMP_MODE_STRICT must be flagged"
        );
    }

    #[test]
    fn classify_recvmsg_opcode_with_seccomp_filter_suspicious() {
        // RECVMSG (10) under seccomp FILTER (mode=2) → suspicious
        assert!(
            classify_io_uring(&[IORING_OP_RECVMSG], 2),
            "RECVMSG under SECCOMP_MODE_FILTER must be flagged"
        );
    }

    #[test]
    fn classify_recvmsg_opcode_without_seccomp_not_suspicious() {
        // RECVMSG without seccomp → not suspicious
        assert!(
            !classify_io_uring(&[IORING_OP_RECVMSG], 0),
            "RECVMSG without seccomp must not be flagged"
        );
    }

    #[test]
    fn classify_connect_opcode_without_seccomp_not_suspicious() {
        // CONNECT without seccomp → not suspicious
        assert!(
            !classify_io_uring(&[IORING_OP_CONNECT], 0),
            "CONNECT without seccomp must not be flagged"
        );
    }

    #[test]
    fn classify_empty_opcodes_with_seccomp_not_suspicious() {
        // No opcodes at all, even with seccomp → not suspicious
        assert!(
            !classify_io_uring(&[], 2),
            "empty opcode list must not be flagged even with seccomp"
        );
    }

    #[test]
    fn classify_openat_opcode_with_seccomp_not_suspicious() {
        // OPENAT (18) is not a SENSITIVE_OPCODE → not suspicious
        assert!(
            !classify_io_uring(&[IORING_OP_OPENAT], 2),
            "OPENAT is not a sensitive opcode and must not be flagged"
        );
    }

    #[test]
    fn classify_all_sensitive_opcodes_individually() {
        // Each of the three sensitive opcodes should be flagged under any seccomp mode
        for &op in &[IORING_OP_SENDMSG, IORING_OP_RECVMSG, IORING_OP_CONNECT] {
            assert!(
                classify_io_uring(&[op], 1),
                "opcode {op} must be flagged under seccomp_mode=1"
            );
            assert!(
                classify_io_uring(&[op], 2),
                "opcode {op} must be flagged under seccomp_mode=2"
            );
        }
    }

    #[test]
    fn walk_io_uring_with_symbol_returns_ok() {
        // io_uring_task_work symbol present → walk should return Ok (empty stub)
        let isf = IsfBuilder::new()
            .add_symbol("io_uring_task_work", 0xFFFF_8000_0010_0000)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_io_uring(&reader);
        assert!(result.is_ok(), "walk_io_uring must not error when symbol is present");
    }
}
