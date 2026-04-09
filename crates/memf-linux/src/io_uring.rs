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

use crate::{Error, Result};

/// io_uring opcode constants (from include/uapi/linux/io_uring.h).
pub const IORING_OP_SENDMSG: u8 = 9;
pub const IORING_OP_RECVMSG: u8 = 10;
pub const IORING_OP_CONNECT: u8 = 16;
pub const IORING_OP_OPENAT: u8 = 18;
pub const IORING_OP_READ: u8 = 22;
pub const IORING_OP_WRITE: u8 = 23;

/// Sensitive opcode set — network or file operations that bypass seccomp.
const SENSITIVE_OPCODES: &[u8] = &[
    IORING_OP_SENDMSG,
    IORING_OP_RECVMSG,
    IORING_OP_CONNECT,
];

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
pub fn classify_io_uring(opcodes: &[u8], seccomp_mode: u32) -> bool {
    todo!()
}

/// Walk all `io_ring_ctx` structures reachable from each process's
/// `task_struct->io_uring` field and return forensic entries.
///
/// Returns `Ok(vec![])` gracefully when ISF symbols are unavailable.
pub fn walk_io_uring<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<IoUringEntry>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::{
        vas::VirtualAddressSpace,
        vas::TranslationMode,
        test_builders::{PageTableBuilder, SyntheticPhysMem},
        object_reader::ObjectReader,
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
}
