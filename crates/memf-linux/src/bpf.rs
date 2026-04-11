//! Linux eBPF program enumeration from kernel memory.
//!
//! eBPF is a modern rootkit vector -- malicious BPF programs can intercept
//! syscalls, modify network packets, hide processes, and exfiltrate data.
//! The kernel tracks BPF programs via `bpf_prog_idr` (an IDR/radix tree).
//! This module enumerates loaded eBPF programs and flags suspicious ones.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, Result};

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

/// Known BPF program type values from the kernel's `enum bpf_prog_type`.
const BPF_PROG_TYPES: &[&str] = &[
    "unspec",
    "socket_filter",
    "kprobe",
    "sched_cls",
    "sched_act",
    "tracepoint",
    "xdp",
    "perf_event",
    "cgroup_skb",
    "cgroup_sock",
    "lwt_in",
    "lwt_out",
    "lwt_xmit",
    "sock_ops",
    "sk_skb",
    "cgroup_device",
    "sk_msg",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "lwt_seg6local",
    "lirc_mode2",
    "sk_reuseport",
    "flow_dissector",
    "cgroup_sysctl",
    "raw_tracepoint_writable",
    "cgroup_sockopt",
    "tracing",
    "struct_ops",
    "ext",
    "lsm",
    "sk_lookup",
    "syscall",
];

/// Convert a raw `bpf_prog_type` enum value to its string name.
fn prog_type_name(raw: u32) -> String {
        todo!()
    }

/// Enumerate loaded eBPF programs by walking `bpf_prog_idr` in kernel memory.
///
/// If the `bpf_prog_idr` symbol is not found (e.g., BPF not enabled in the
/// kernel or symbol table incomplete), returns an empty `Vec`.
pub fn walk_bpf_programs<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<BpfProgramInfo>> {
        todo!()
    }

/// Recursively walk xarray/radix-tree nodes to find `bpf_prog` pointers.
///
/// XArray internal entries have the low bit set; leaf entries are direct
/// pointers to `bpf_prog` structs (aligned, so low bits are 0).
fn walk_idr_entries<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    node_ptr: u64,
    programs: &mut Vec<BpfProgramInfo>,
) -> Result<()> {
        todo!()
    }

/// Read a single `bpf_prog` struct and its associated `bpf_prog_aux`.
fn read_bpf_prog<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    prog_addr: u64,
) -> Result<BpfProgramInfo> {
        todo!()
    }

/// Classify whether a BPF program is suspicious based on its type and name.
///
/// Returns `true` for:
/// - `kprobe` programs (can intercept arbitrary kernel functions)
/// - `tracing` programs with no name (unnamed tracing = evasion)
/// - `raw_tracepoint` programs with no name
/// - `raw_tracepoint_writable` programs (can modify tracepoint args)
///
/// Note: XDP UID-based checks require external context and are done at the
/// caller level when `loaded_by_uid` is available on `BpfProgramInfo`.
pub fn classify_bpf_program(prog_type: &str, name: &str) -> bool {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Helper: create an ObjectReader with no `bpf_prog_idr` symbol.
    fn make_reader_no_bpf_symbol() -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        todo!()
    }

    #[test]
    fn walk_bpf_no_symbol() {
        todo!()
    }

    #[test]
    fn classify_bpf_suspicious_kprobe() {
        todo!()
    }

    #[test]
    fn classify_bpf_benign_socket_filter() {
        todo!()
    }

    #[test]
    fn classify_bpf_suspicious_unnamed_tracing() {
        todo!()
    }

    #[test]
    fn classify_bpf_benign_named_tracing() {
        todo!()
    }

    // --- prog_type_name (private) exercised via walk_bpf + classify paths ---
    // We exercise it indirectly through classify_bpf_program and read_bpf_prog
    // by covering all classify arms.

    #[test]
    fn classify_bpf_raw_tracepoint_unnamed_suspicious() {
        todo!()
    }

    #[test]
    fn classify_bpf_raw_tracepoint_named_benign() {
        todo!()
    }

    #[test]
    fn classify_bpf_raw_tracepoint_writable_always_suspicious() {
        todo!()
    }

    #[test]
    fn classify_bpf_lsm_always_suspicious() {
        todo!()
    }

    #[test]
    fn classify_bpf_xdp_not_suspicious() {
        todo!()
    }

    #[test]
    fn classify_bpf_tracepoint_not_suspicious() {
        todo!()
    }

    #[test]
    fn classify_bpf_sched_cls_not_suspicious() {
        todo!()
    }

    #[test]
    fn classify_bpf_unknown_type_not_suspicious() {
        todo!()
    }

    // --- walk_bpf_programs: symbol present but xa_head resolves to 0 (empty tree) ---

    #[test]
    fn walk_bpf_programs_empty_idr_returns_empty() {
        todo!()
    }

    // --- walk_bpf_programs: symbol present, xa_head non-zero but tagged (retry entry) ---
    // Exercises walk_idr_entries body: a tagged pointer (low bits == 0x1) is neither
    // a node (0x2) nor a clean leaf (0x0), so it is silently skipped → empty result.
    #[test]
    fn walk_bpf_programs_tagged_xa_head_skipped_returns_empty() {
        todo!()
    }

    // --- walk_bpf_programs: xa_head is an xarray node (low bits 0x2) ---
    // Exercises the `is_node` branch in walk_idr_entries: real_addr decoded, slots
    // array iterated. All slots are 0 → no leaf entries → empty result.
    #[test]
    fn walk_bpf_programs_xa_node_all_zero_slots_returns_empty() {
        todo!()
    }

    // --- walk_bpf_programs: xa_head is a leaf pointer (low bits 0x0, > 0x1000) ---
    // Exercises the leaf branch in walk_idr_entries: read_bpf_prog is called.
    // bpf_prog.type field missing → read_bpf_prog returns Err → entry silently skipped.
    #[test]
    fn walk_bpf_programs_leaf_ptr_read_fails_returns_empty() {
        todo!()
    }

    // --- prog_type_name: unknown index returns formatted string ---
    // Exercises the map_or_else branch in prog_type_name for an out-of-range raw value.
    #[test]
    fn classify_bpf_unknown_indexed_type_not_suspicious() {
        todo!()
    }

    // --- walk_bpf_programs: leaf ptr → read_bpf_prog succeeds (exercises prog_type_name) ---
    // Builds a complete synthetic bpf_prog + bpf_prog_aux in memory so that
    // read_bpf_prog completes successfully and a BpfProgramInfo is returned.
    //
    // Memory layout (all padded to page boundaries, physical addresses < 16 MB):
    //   idr page     @ paddr 0x0060_0000 (vaddr 0xFFFF_8800_0060_0000)
    //   bpf_prog     @ paddr 0x0061_0000 (vaddr 0xFFFF_8800_0061_0000)
    //   bpf_prog_aux @ paddr 0x0062_0000 (vaddr 0xFFFF_8800_0062_0000)
    #[test]
    fn walk_bpf_programs_leaf_ptr_success_returns_program() {
        todo!()
    }

    // --- walk_bpf_programs: xa_node with a non-zero retry-tagged slot (low bits 0x1) ---
    // Exercises walk_idr_entries recursion: xa_node slot has value with low bits 0x1
    // (retry / reserved). This is neither a node (0x2) nor a clean leaf (0x0), so
    // it hits the else-if condition `node_ptr & 0x3 == 0` which is false → silently skipped.
    #[test]
    fn walk_bpf_programs_xa_node_retry_slot_skipped() {
        todo!()
    }

    // --- walk_bpf_programs: idr.idr_rt fails, idr.top succeeds (or_else branch) ---
    // Exercises the or_else fallback in walk_bpf_programs (lines 92-97).
    // idr_rt field absent → or_else reads idr.top → also fails (unmapped) → xa_head = 0 → empty.
    #[test]
    fn walk_bpf_programs_idr_top_fallback_zero_returns_empty() {
        todo!()
    }

    // --- prog_type_name: in-bounds entries (exercises all named branches) ---
    // These call the private prog_type_name via walk_bpf; here we test the
    // outer public interface that composes prog_type_name + classify.
    // We exercise prog_type_name's get() Some branch for all in-range values
    // by calling classify_bpf_program with type names returned by it.
    #[test]
    fn bpf_program_info_serializes() {
        todo!()
    }
}
