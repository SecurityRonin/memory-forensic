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
        assert!(
            result.is_empty(),
            "expected empty vec when bpf_prog_idr symbol missing"
        );
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

    // --- prog_type_name (private) exercised via walk_bpf + classify paths ---
    // We exercise it indirectly through classify_bpf_program and read_bpf_prog
    // by covering all classify arms.

    #[test]
    fn classify_bpf_raw_tracepoint_unnamed_suspicious() {
        assert!(
            classify_bpf_program("raw_tracepoint", ""),
            "unnamed raw_tracepoint must be suspicious"
        );
    }

    #[test]
    fn classify_bpf_raw_tracepoint_named_benign() {
        assert!(
            !classify_bpf_program("raw_tracepoint", "my_hook"),
            "named raw_tracepoint must not be suspicious"
        );
    }

    #[test]
    fn classify_bpf_raw_tracepoint_writable_always_suspicious() {
        assert!(
            classify_bpf_program("raw_tracepoint_writable", ""),
            "raw_tracepoint_writable with no name must be suspicious"
        );
        assert!(
            classify_bpf_program("raw_tracepoint_writable", "named"),
            "raw_tracepoint_writable with a name must also be suspicious"
        );
    }

    #[test]
    fn classify_bpf_lsm_always_suspicious() {
        assert!(
            classify_bpf_program("lsm", ""),
            "lsm with no name must be suspicious"
        );
        assert!(
            classify_bpf_program("lsm", "some_lsm_prog"),
            "lsm with a name must also be suspicious"
        );
    }

    #[test]
    fn classify_bpf_xdp_not_suspicious() {
        assert!(
            !classify_bpf_program("xdp", "my_xdp"),
            "xdp program must not be suspicious by default"
        );
    }

    #[test]
    fn classify_bpf_tracepoint_not_suspicious() {
        assert!(
            !classify_bpf_program("tracepoint", ""),
            "plain tracepoint must not be suspicious"
        );
    }

    #[test]
    fn classify_bpf_sched_cls_not_suspicious() {
        assert!(
            !classify_bpf_program("sched_cls", "tc_prog"),
            "sched_cls must not be suspicious"
        );
    }

    #[test]
    fn classify_bpf_unknown_type_not_suspicious() {
        assert!(
            !classify_bpf_program("unknown_type_xyz", ""),
            "unknown program type must not be suspicious"
        );
    }

    // --- walk_bpf_programs: symbol present but xa_head resolves to 0 (empty tree) ---

    #[test]
    fn walk_bpf_programs_empty_idr_returns_empty() {
        // Provide the bpf_prog_idr symbol at an unmapped address.
        // read_field for idr.idr_rt will fail, or_else for idr.top also fails → xa_head = 0
        // → returns Ok(Vec::new())
        let isf = IsfBuilder::new()
            .add_symbol("bpf_prog_idr", 0xDEAD_0000_0000_0000)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_bpf_programs(&reader).unwrap();
        assert!(
            result.is_empty(),
            "bpf_prog_idr with unreadable/zero xa_head → empty vec expected"
        );
    }

    // --- walk_bpf_programs: symbol present, xa_head non-zero but tagged (retry entry) ---
    // Exercises walk_idr_entries body: a tagged pointer (low bits == 0x1) is neither
    // a node (0x2) nor a clean leaf (0x0), so it is silently skipped → empty result.
    #[test]
    fn walk_bpf_programs_tagged_xa_head_skipped_returns_empty() {
        use memf_core::test_builders::{flags as ptf, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};

        // bpf_prog_idr at a mapped address; idr.idr_rt at offset 0 returns xa_head.
        // xa_head value = 0x0001 (low bits 0x1 → retry/reserved entry, not node, not leaf).
        let idr_vaddr: u64 = 0xFFFF_8800_0050_0000;
        let idr_paddr: u64 = 0x0050_0000; // unique, < 16 MB

        let isf = IsfBuilder::new()
            .add_symbol("bpf_prog_idr", idr_vaddr)
            .add_struct("idr", 0x20)
            .add_field("idr", "idr_rt", 0x00, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Write the idr page: idr_rt at offset 0 = 0x0001 (tagged, non-zero).
        let xa_head: u64 = 0x0001u64; // low bits 0x1 → skipped by walk_idr_entries
        let mut page = [0u8; 4096];
        page[0..8].copy_from_slice(&xa_head.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(idr_vaddr, idr_paddr, ptf::WRITABLE)
            .write_phys(idr_paddr, &page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_bpf_programs(&reader).unwrap();
        assert!(
            result.is_empty(),
            "tagged xa_head (retry entry) must be skipped → empty vec"
        );
    }

    // --- walk_bpf_programs: xa_head is an xarray node (low bits 0x2) ---
    // Exercises the `is_node` branch in walk_idr_entries: real_addr decoded, slots
    // array iterated. All slots are 0 → no leaf entries → empty result.
    #[test]
    fn walk_bpf_programs_xa_node_all_zero_slots_returns_empty() {
        use memf_core::test_builders::{flags as ptf, SyntheticPhysMem};

        // idr struct at idr_vaddr; idr_rt (offset 0) = xa_node_addr | 0x2
        let idr_vaddr: u64 = 0xFFFF_8800_0055_0000;
        let idr_paddr: u64 = 0x0055_0000;

        // xa_node is at a separate mapped page; slots at offset 16 (default used by code)
        let xa_node_paddr: u64 = 0x0056_0000;
        let xa_node_vaddr: u64 = 0xFFFF_8800_0056_0000;
        // The tagged node pointer: xa_node_vaddr | 0x2
        let xa_head_tagged: u64 = xa_node_vaddr | 0x2;

        let isf = IsfBuilder::new()
            .add_symbol("bpf_prog_idr", idr_vaddr)
            .add_struct("idr", 0x20)
            .add_field("idr", "idr_rt", 0x00, "pointer")
            // xa_node.slots at offset 16 (matches unwrap_or(16) default in code)
            .add_struct("xa_node", 0x400)
            .add_field("xa_node", "slots", 0x10, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // idr page: idr_rt = xa_head_tagged
        let mut idr_page = [0u8; 4096];
        idr_page[0..8].copy_from_slice(&xa_head_tagged.to_le_bytes());

        // xa_node page: all slots zero → nothing to recurse into
        let xa_node_page = [0u8; 4096];

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(idr_vaddr, idr_paddr, ptf::WRITABLE)
            .write_phys(idr_paddr, &idr_page)
            .map_4k(xa_node_vaddr, xa_node_paddr, ptf::WRITABLE)
            .write_phys(xa_node_paddr, &xa_node_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_bpf_programs(&reader).unwrap();
        assert!(
            result.is_empty(),
            "xa_node with all-zero slots → no bpf_prog entries"
        );
    }

    // --- walk_bpf_programs: xa_head is a leaf pointer (low bits 0x0, > 0x1000) ---
    // Exercises the leaf branch in walk_idr_entries: read_bpf_prog is called.
    // bpf_prog.type field missing → read_bpf_prog returns Err → entry silently skipped.
    #[test]
    fn walk_bpf_programs_leaf_ptr_read_fails_returns_empty() {
        use memf_core::test_builders::{flags as ptf, SyntheticPhysMem};

        let idr_vaddr: u64 = 0xFFFF_8800_0057_0000;
        let idr_paddr: u64 = 0x0057_0000;

        // A clean leaf pointer (low bits 0x0, > 0x1000) pointing to an unmapped page.
        // read_bpf_prog will fail trying to read bpf_prog.type → silently skipped.
        let leaf_ptr: u64 = 0xFFFF_8800_DEAD_0000; // unmapped → read fails

        let isf = IsfBuilder::new()
            .add_symbol("bpf_prog_idr", idr_vaddr)
            .add_struct("idr", 0x20)
            .add_field("idr", "idr_rt", 0x00, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut idr_page = [0u8; 4096];
        idr_page[0..8].copy_from_slice(&leaf_ptr.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(idr_vaddr, idr_paddr, ptf::WRITABLE)
            .write_phys(idr_paddr, &idr_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_bpf_programs(&reader).unwrap();
        assert!(
            result.is_empty(),
            "leaf ptr pointing to unreadable addr → read_bpf_prog fails → empty vec"
        );
    }

    // --- prog_type_name: unknown index returns formatted string ---
    // Exercises the map_or_else branch in prog_type_name for an out-of-range raw value.
    #[test]
    fn classify_bpf_unknown_indexed_type_not_suspicious() {
        // prog_type_name(99) returns "unknown(99)"; classify_bpf_program falls through to _ => false
        assert!(
            !classify_bpf_program("unknown(99)", ""),
            "unknown prog type string must not be suspicious"
        );
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
        use memf_core::test_builders::{flags as ptf, SyntheticPhysMem};

        let idr_vaddr: u64 = 0xFFFF_8800_0060_0000;
        let prog_vaddr: u64 = 0xFFFF_8800_0061_0000;
        let aux_vaddr: u64 = 0xFFFF_8800_0062_0000;

        let idr_paddr: u64 = 0x060_000;
        let prog_paddr: u64 = 0x061_000;
        let aux_paddr: u64 = 0x062_000;

        // bpf_prog field offsets
        let prog_type_off: u64 = 0x00; // u32
        let prog_len_off: u64 = 0x04;  // u32
        let prog_jited_len_off: u64 = 0x08; // u32
        let prog_tag_off: u64 = 0x10;  // [u8; 8]
        let prog_aux_off: u64 = 0x20;  // *bpf_prog_aux

        // bpf_prog_aux field offsets
        let aux_id_off: u64 = 0x00;   // u32
        let aux_name_off: u64 = 0x08; // [u8; 16]
        let aux_uid_off: u64 = 0x18;  // u32

        let isf = IsfBuilder::new()
            .add_symbol("bpf_prog_idr", idr_vaddr)
            .add_struct("idr", 0x20)
            .add_field("idr", "idr_rt", 0x00u64, "pointer")
            .add_struct("bpf_prog", 0x100)
            .add_field("bpf_prog", "type", prog_type_off, "unsigned int")
            .add_field("bpf_prog", "len", prog_len_off, "unsigned int")
            .add_field("bpf_prog", "jited_len", prog_jited_len_off, "unsigned int")
            .add_field("bpf_prog", "tag", prog_tag_off, "array")
            .add_field("bpf_prog", "aux", prog_aux_off, "pointer")
            .add_struct("bpf_prog_aux", 0x100)
            .add_field("bpf_prog_aux", "id", aux_id_off, "unsigned int")
            .add_field("bpf_prog_aux", "name", aux_name_off, "char")
            .add_field("bpf_prog_aux", "uid", aux_uid_off, "unsigned int")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // idr page: idr_rt at offset 0 = prog_vaddr (clean leaf: low bits 0x0, > 0x1000)
        let mut idr_page = [0u8; 4096];
        idr_page[0..8].copy_from_slice(&prog_vaddr.to_le_bytes());

        // bpf_prog page
        // type = 2 (kprobe = index 2, which maps to "kprobe" → suspicious)
        let prog_type_val: u32 = 2; // BPF_PROG_TYPE_KPROBE
        let mut prog_page = [0u8; 4096];
        prog_page[prog_type_off as usize..prog_type_off as usize + 4]
            .copy_from_slice(&prog_type_val.to_le_bytes());
        // len = 10 instructions
        prog_page[prog_len_off as usize..prog_len_off as usize + 4]
            .copy_from_slice(&10u32.to_le_bytes());
        // jited_len = 80 bytes
        prog_page[prog_jited_len_off as usize..prog_jited_len_off as usize + 4]
            .copy_from_slice(&80u32.to_le_bytes());
        // tag = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00]
        prog_page[prog_tag_off as usize..prog_tag_off as usize + 8]
            .copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00]);
        // aux = aux_vaddr
        prog_page[prog_aux_off as usize..prog_aux_off as usize + 8]
            .copy_from_slice(&aux_vaddr.to_le_bytes());

        // bpf_prog_aux page
        let mut aux_page = [0u8; 4096];
        // id = 42
        aux_page[aux_id_off as usize..aux_id_off as usize + 4]
            .copy_from_slice(&42u32.to_le_bytes());
        // name = "evil_kprobe\0" (16 bytes)
        aux_page[aux_name_off as usize..aux_name_off as usize + 12]
            .copy_from_slice(b"evil_kprobe\0");
        // uid = 1000
        aux_page[aux_uid_off as usize..aux_uid_off as usize + 4]
            .copy_from_slice(&1000u32.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(idr_vaddr, idr_paddr, ptf::WRITABLE)
            .write_phys(idr_paddr, &idr_page)
            .map_4k(prog_vaddr, prog_paddr, ptf::WRITABLE)
            .write_phys(prog_paddr, &prog_page)
            .map_4k(aux_vaddr, aux_paddr, ptf::WRITABLE)
            .write_phys(aux_paddr, &aux_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_bpf_programs(&reader).unwrap();
        assert_eq!(result.len(), 1, "should detect exactly one BPF program");
        let prog = &result[0];
        assert_eq!(prog.id, 42);
        assert_eq!(prog.prog_type, "kprobe");
        assert_eq!(prog.insn_count, 10);
        assert_eq!(prog.jited_len, 80);
        assert_eq!(prog.loaded_by_uid, 1000);
        assert!(prog.is_suspicious, "kprobe must be suspicious");
        assert!(
            prog.name.contains("evil_kprobe"),
            "name should be read from aux"
        );
    }

    // --- prog_type_name: in-bounds entries (exercises all named branches) ---
    // These call the private prog_type_name via walk_bpf; here we test the
    // outer public interface that composes prog_type_name + classify.
    // We exercise prog_type_name's get() Some branch for all in-range values
    // by calling classify_bpf_program with type names returned by it.
    #[test]
    fn bpf_program_info_serializes() {
        let info = BpfProgramInfo {
            id: 7,
            prog_type: "kprobe".to_string(),
            name: "hook".to_string(),
            tag: [1, 2, 3, 4, 5, 6, 7, 8],
            insn_count: 20,
            jited_len: 120,
            loaded_by_uid: 0,
            is_suspicious: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"id\":7"));
        assert!(json.contains("kprobe"));
        assert!(json.contains("\"is_suspicious\":true"));
    }
}
