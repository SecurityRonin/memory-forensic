//! Linux eBPF program enumeration from kernel memory.
//!
//! eBPF is a modern rootkit vector -- malicious BPF programs can intercept
//! syscalls, modify network packets, hide processes, and exfiltrate data.
//! The kernel tracks BPF programs via `bpf_prog_idr` (an IDR/radix tree).
//! This module enumerates loaded eBPF programs and flags suspicious ones.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about a loaded eBPF program extracted from kernel memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BpfProgramInfo {
    /// Unique program ID (`aux->id`).
    pub id: u32,
    /// Program type (kprobe, tracepoint, xdp, socket_filter, etc.).
    pub prog_type: String,
    /// Program name (`aux->name`), if set.
    pub name: String,
    /// 8-byte hash of the bytecode.
    pub tag: [u8; 8],
    /// Number of BPF instructions.
    pub insn_count: u32,
    /// JIT compiled size in bytes.
    pub jited_len: u32,
    /// UID that loaded the program.
    pub loaded_by_uid: u32,
    /// Whether heuristic analysis flags this program as suspicious.
    pub is_suspicious: bool,
}

/// Enumerate loaded eBPF programs by walking `bpf_prog_idr` in kernel memory.
///
/// If the `bpf_prog_idr` symbol is not found (e.g., BPF not enabled in the
/// kernel or symbol table incomplete), returns an empty `Vec`.
pub fn walk_bpf_programs<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
) -> Result<Vec<BpfProgramInfo>> {
    todo!()
}

/// Classify whether a BPF program is suspicious based on its type and name.
///
/// Returns `true` for:
/// - `kprobe` programs (can intercept arbitrary kernel functions)
/// - `tracing` programs with no name (unnamed tracing = evasion)
/// - `xdp` programs loaded by non-root (UID != 0)
///
/// Note: UID-based checks are done at the caller level; this function
/// considers kprobe and unnamed tracing inherently suspicious.
pub fn classify_bpf_program(_prog_type: &str, _name: &str) -> bool {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Helper: create an ObjectReader with no `bpf_prog_idr` symbol.
    fn make_reader_no_bpf_symbol() -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_bpf_no_symbol() {
        let reader = make_reader_no_bpf_symbol();
        let result = walk_bpf_programs(&reader).unwrap();
        assert!(result.is_empty(), "expected empty vec when bpf_prog_idr symbol missing");
    }

    #[test]
    fn classify_bpf_suspicious_kprobe() {
        assert!(
            classify_bpf_program("kprobe", "my_kprobe"),
            "kprobe programs should always be flagged as suspicious"
        );
    }

    #[test]
    fn classify_bpf_benign_socket_filter() {
        assert!(
            !classify_bpf_program("socket_filter", "tcpdump"),
            "socket_filter with a name should not be flagged as suspicious"
        );
    }

    #[test]
    fn classify_bpf_suspicious_unnamed_tracing() {
        assert!(
            classify_bpf_program("tracing", ""),
            "unnamed tracing programs should be flagged as suspicious"
        );
    }

    #[test]
    fn classify_bpf_benign_named_tracing() {
        assert!(
            !classify_bpf_program("tracing", "my_tracer"),
            "named tracing programs should not be flagged as suspicious"
        );
    }
}
