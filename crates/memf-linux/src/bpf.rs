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
    BPF_PROG_TYPES
        .get(raw as usize)
        .map_or_else(|| format!("unknown({raw})"), |s| (*s).to_string())
}

/// Enumerate loaded eBPF programs by walking `bpf_prog_idr` in kernel memory.
///
/// If the `bpf_prog_idr` symbol is not found (e.g., BPF not enabled in the
/// kernel or symbol table incomplete), returns an empty `Vec`.
pub fn walk_bpf_programs<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<BpfProgramInfo>> {
    // Look up the bpf_prog_idr symbol; if absent, BPF is not available.
    let Some(idr_addr) = reader.symbols().symbol_address("bpf_prog_idr") else {
        return Ok(Vec::new());
    };

    // The IDR stores pointers to bpf_prog structs in a radix tree.
    // Read idr.idr_rt.xa_head to get the root of the xarray/radix tree.
    let xa_head: u64 = reader
        .read_field(idr_addr, "idr", "idr_rt")
        .or_else(|_| {
            // Older kernels: idr.top directly
            reader.read_field::<u64>(idr_addr, "idr", "top")
        })
        .unwrap_or(0);

    if xa_head == 0 {
        return Ok(Vec::new());
    }

    // Walk IDR entries. The IDR is backed by a radix tree / xarray.
    // We attempt to read bpf_prog pointers from the tree nodes.
    let mut programs = Vec::new();
    walk_idr_entries(reader, xa_head, &mut programs)?;

    Ok(programs)
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
    // Safety limit to avoid infinite loops on corrupt memory.
    const MAX_SLOTS: usize = 64;
    const MAX_PROGRAMS: usize = 10_000;

    // XArray tags internal nodes with low bit 2 (xa_is_node).
    let is_node = (node_ptr & 0x3) == 0x2;

    if is_node {
        // Decode the actual node address (clear tag bits).
        let real_addr = node_ptr & !0x3;

        // xa_node.slots is an array of pointers. Read up to MAX_SLOTS.
        let slots_offset = reader
            .symbols()
            .field_offset("xa_node", "slots")
            .unwrap_or(16); // typical offset

        for i in 0..MAX_SLOTS {
            if programs.len() >= MAX_PROGRAMS {
                break;
            }
            let slot_addr = real_addr + slots_offset + (i as u64) * 8;
            let slot_val = {
                let mut buf = [0u8; 8];
                match reader.vas().read_virt(slot_addr, &mut buf) {
                    Ok(()) => u64::from_le_bytes(buf),
                    Err(_) => 0,
                }
            };
            if slot_val == 0 {
                continue;
            }
            walk_idr_entries(reader, slot_val, programs)?;
        }
    } else if node_ptr & 0x3 == 0 && node_ptr > 0x1000 {
        // Leaf pointer — this should be a bpf_prog struct.
        if let Ok(info) = read_bpf_prog(reader, node_ptr) {
            programs.push(info);
        }
    }
    // Other tagged pointers (retry entries, etc.) are skipped.

    Ok(())
}

/// Read a single `bpf_prog` struct and its associated `bpf_prog_aux`.
fn read_bpf_prog<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    prog_addr: u64,
) -> Result<BpfProgramInfo> {
    // bpf_prog.type (enum bpf_prog_type, u32)
    let raw_type: u32 = reader.read_field(prog_addr, "bpf_prog", "type")?;
    let prog_type = prog_type_name(raw_type);

    // bpf_prog.len (number of BPF instructions)
    let insn_count: u32 = reader.read_field(prog_addr, "bpf_prog", "len")?;

    // bpf_prog.jited_len
    let jited_len: u32 = reader
        .read_field(prog_addr, "bpf_prog", "jited_len")
        .unwrap_or(0);

    // bpf_prog.tag (8 bytes)
    let mut tag = [0u8; 8];
    let tag_offset = reader
        .symbols()
        .field_offset("bpf_prog", "tag")
        .ok_or_else(|| Error::Walker("bpf_prog.tag field not found".into()))?;
    if let Ok(bytes) = reader.read_bytes(prog_addr + tag_offset, 8) {
        tag.copy_from_slice(&bytes[..8]);
    }

    // bpf_prog.aux (pointer to bpf_prog_aux)
    let aux_addr: u64 = reader.read_field(prog_addr, "bpf_prog", "aux")?;

    // bpf_prog_aux.id
    let id: u32 = reader
        .read_field(aux_addr, "bpf_prog_aux", "id")
        .unwrap_or(0);

    // bpf_prog_aux.name (BPF_OBJ_NAME_LEN = 16)
    let name = reader
        .read_field_string(aux_addr, "bpf_prog_aux", "name", 16)
        .unwrap_or_default();

    // bpf_prog_aux.uid (kuid_t, effectively u32)
    let loaded_by_uid: u32 = reader
        .read_field(aux_addr, "bpf_prog_aux", "uid")
        .unwrap_or(0);

    let is_suspicious = classify_bpf_program(&prog_type, &name);

    Ok(BpfProgramInfo {
        id,
        prog_type,
        name,
        tag,
        insn_count,
        jited_len,
        loaded_by_uid,
        is_suspicious,
    })
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
    match prog_type {
        // kprobe can hook arbitrary kernel functions — always suspicious.
        "kprobe" => true,

        // Unnamed tracing/raw_tracepoint programs suggest evasion.
        "tracing" | "raw_tracepoint" => name.is_empty(),

        // raw_tracepoint_writable can modify tracepoint arguments — always suspicious.
        "raw_tracepoint_writable" => true,

        // LSM programs can override security decisions.
        "lsm" => true,

        // Everything else (socket_filter, xdp, tracepoint, etc.) is
        // considered benign by default at the type level.
        _ => false,
    }
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
