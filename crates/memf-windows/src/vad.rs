//! Windows Virtual Address Descriptor (VAD) tree walker.
//!
//! Traverses the `_EPROCESS.VadRoot` AVL tree of `_MMVAD_SHORT` nodes
//! to enumerate all virtual memory regions for a process. Also provides
//! `walk_malfind` which filters for suspicious private RWX regions.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, WinMalfindInfo, WinVadInfo};

/// `_MMVAD_FLAGS.Protection` is a 5-bit index into the kernel's `MmProtectToValue`
/// table. Its bit position within the VadFlags dword is build-dependent — there is
/// no universal x64 shift. Authoritative source: Volatility x64 vtypes
/// (`_MMVAD_FLAGS.Protection` BitField `start_bit`):
/// - Vista / Win7 (NT 6.0–6.1): bit 11
/// - Win8.0+ (NT 6.2), incl. Server 2012 R2 / build 9600, through Win10/11: bit 3
const VAD_PROTECTION_MASK: u32 = 0x1F; // 5 bits

/// Bit position of `_MMVAD_FLAGS.Protection` for a given OS build (see table above).
/// `None` (build unresolved) defaults to the modern Win8+ layout, which covers
/// every Windows release since 2012.
fn protection_shift(build: Option<u32>) -> u32 {
    match build {
        Some(b) if b < 9200 => 11, // Vista..Win7 RTM/SP1 (pre-Win8 build 9200)
        _ => 3,                    // Win8.0+ and all Win10/11
    }
}

/// Map VAD protection index to a human-readable string.
fn protection_to_string(prot: u32) -> String {
    match prot {
        0 => "PAGE_NOACCESS".into(),
        1 => "PAGE_READONLY".into(),
        2 => "PAGE_EXECUTE".into(),
        3 => "PAGE_EXECUTE_READ".into(),
        4 => "PAGE_READWRITE".into(),
        5 => "PAGE_WRITECOPY".into(),
        6 => "PAGE_EXECUTE_READWRITE".into(),
        7 => "PAGE_EXECUTE_WRITECOPY".into(),
        other => format!("UNKNOWN({other})"),
    }
}

/// Whether a VAD protection value indicates execute+write (suspicious for private regions).
fn is_execute_write(prot: u32) -> bool {
    matches!(prot, 6 | 7) // PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY
}

/// VadFlags.VadType is bits [0:2] (3 bits).
const VAD_TYPE_MASK: u32 = 0x7;

/// Hard upper bound on VAD nodes enumerated per process — a backstop so a corrupt
/// or crafted tree can never make the walk hang. Far above any real process's VAD
/// count (typically a few thousand).
const MAX_VAD_NODES: usize = 10_000_000;

/// Whether a VAD is private (type 0 = VadNone → private allocation).
fn is_private_vad(flags: u32) -> bool {
    (flags & VAD_TYPE_MASK) == 0
}

/// Read the AVL left/right child pointers of a VAD tree node.
///
/// Win8+ (incl. Server 2012 R2) embeds the tree node as
/// `_MMVAD_SHORT.VadNode : _RTL_BALANCED_NODE { Left, Right }` (at offset 0, so
/// the node address is the `_MMVAD_SHORT` base). Win7 exposes `Left`/`Right`
/// directly on `_MMVAD_SHORT`. Use whichever the ISF defines.
fn vad_child_links<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    node_addr: u64,
) -> Result<(u64, u64)> {
    let syms = reader.symbols();
    // Mirrors Volatility3's `get_left_child`/`get_right_child`
    // (volatility3/framework/symbols/windows/extensions/__init__.py). Win7
    // exposes `Left`/`Right` directly on `_MMVAD_SHORT`; Win8+ (incl. Server
    // 2012 R2 / build 9600) nests them in the `VadNode : _RTL_BALANCED_NODE`
    // member at offset 0.
    if syms.field_offset("_MMVAD_SHORT", "Left").is_some() {
        let l = reader.read_field(node_addr, "_MMVAD_SHORT", "Left")?;
        let r = reader.read_field(node_addr, "_MMVAD_SHORT", "Right")?;
        return Ok((l, r));
    }
    let node = node_addr + syms.field_offset("_MMVAD_SHORT", "VadNode").unwrap_or(0);
    let l = reader.read_field(node, "_RTL_BALANCED_NODE", "Left")?;
    let r = reader.read_field(node, "_RTL_BALANCED_NODE", "Right")?;
    Ok((l, r))
}

/// Read the `_MMVAD_FLAGS` bitfield word of a VAD node.
///
/// Win7 exposes a `Flags` member directly on `_MMVAD_SHORT`; Win8+ moves it into
/// the `u` union (`_MMVAD_SHORT.u.VadFlags`). The whole bitfield is a `u32`, so
/// reading 4 bytes at the union offset yields the same word either way.
fn vad_flags<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, node_addr: u64) -> Result<u32> {
    if reader
        .symbols()
        .field_offset("_MMVAD_SHORT", "Flags")
        .is_some()
    {
        return Ok(reader.read_field::<u32>(node_addr, "_MMVAD_SHORT", "Flags")?);
    }
    // Win8+: the flags bitfield moved into the `u` union (`_MMVAD_FLAGS`).
    Ok(reader.read_field::<u32>(node_addr, "_MMVAD_SHORT", "u")?)
}

/// Read a VAD page-number field. On Win8+/Win10 `StartingVpn`/`EndingVpn` are
/// 32-bit (`unsigned long`); a separate `…VpnHigh` byte carries bits 32-39 for
/// regions above 16 TiB (present on Win8.1+). Mirrors Volatility3's
/// `get_start`/`get_end`. Reading the base as `u64` would fuse the two adjacent
/// 32-bit fields, so it must be read as `u32`.
fn read_vpn<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    node_addr: u64,
    low_field: &str,
    high_field: &str,
) -> Result<u64> {
    let low: u32 = reader.read_field(node_addr, "_MMVAD_SHORT", low_field)?;
    let mut vpn = u64::from(low);
    if reader
        .symbols()
        .field_offset("_MMVAD_SHORT", high_field)
        .is_some()
    {
        let high: u8 = reader.read_field(node_addr, "_MMVAD_SHORT", high_field)?;
        vpn |= u64::from(high) << 32;
    }
    Ok(vpn)
}

/// Walk the VAD AVL tree for a process and return all VAD entries.
///
/// `vad_root_vaddr` is the address of `_EPROCESS.VadRoot` (an `_RTL_AVL_TREE`).
pub fn walk_vad_tree<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    vad_root_vaddr: u64,
    pid: u64,
    image_name: &str,
) -> Result<Vec<WinVadInfo>> {
    // Read _RTL_AVL_TREE.Root pointer
    let root: u64 = reader.read_field(vad_root_vaddr, "_RTL_AVL_TREE", "Root")?;

    if root == 0 {
        return Ok(Vec::new());
    }

    // Protection bit position is build-specific; resolve it once for this walk.
    let prot_shift = protection_shift(crate::network::nt_build_number(reader));

    let mut results = Vec::new();
    let mut stack = vec![root];
    // VAD pointers are untrusted: a corrupt or crafted tree can share a child or
    // form a cycle. A visited-set makes the iterative walk process each node once
    // and terminate; `MAX_VAD_NODES` is a hard backstop so the walk can never hang.
    let mut visited: std::collections::HashSet<u64> = std::collections::HashSet::new();

    // Iterative in-order traversal of the AVL tree
    while let Some(node_addr) = stack.pop() {
        if results.len() >= MAX_VAD_NODES {
            break; // cov:unreachable: real VAD counts are far below the 10M backstop
        }
        if node_addr == 0 || !visited.insert(node_addr) {
            continue;
        }

        // Read the AVL child pointers. On Win8+/Server 2012 R2 the tree node is
        // `_MMVAD_SHORT.VadNode` (a `_RTL_BALANCED_NODE` at offset 0); only older
        // builds (Win7) expose `Left`/`Right` directly on `_MMVAD_SHORT`.
        let (left, right) = vad_child_links(reader, node_addr)?;
        let starting_vpn = read_vpn(reader, node_addr, "StartingVpn", "StartingVpnHigh")?;
        let ending_vpn = read_vpn(reader, node_addr, "EndingVpn", "EndingVpnHigh")?;
        let flags_raw: u32 = vad_flags(reader, node_addr)?;

        let protection = (flags_raw >> prot_shift) & VAD_PROTECTION_MASK;
        let is_private = is_private_vad(flags_raw);

        results.push(WinVadInfo {
            pid,
            image_name: image_name.to_string(),
            start_vaddr: starting_vpn << 12,
            end_vaddr: (ending_vpn << 12) | 0xFFF,
            protection,
            protection_str: protection_to_string(protection),
            is_private,
        });

        // Push children for traversal
        if right != 0 {
            stack.push(right);
        }
        if left != 0 {
            stack.push(left);
        }
    }

    Ok(results)
}

/// Detect suspicious private RWX memory regions across all processes.
///
/// Walks processes from `ps_head_vaddr`, then for each with a non-null
/// PEB, traverses its VAD tree looking for private regions with
/// `PAGE_EXECUTE_READWRITE` or `PAGE_EXECUTE_WRITECOPY` protection.
pub fn walk_malfind<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<WinMalfindInfo>> {
    let procs = crate::process::walk_processes(reader, ps_head_vaddr)?;
    let mut results = Vec::new();

    let vad_root_offset = reader
        .symbols()
        .field_offset("_EPROCESS", "VadRoot")
        .ok_or_else(|| crate::Error::MissingField {
            struct_name: "_EPROCESS".into(),
            field_name: "VadRoot".into(),
        })?;

    for proc in &procs {
        if proc.peb_addr == 0 {
            continue; // skip kernel processes
        }

        let vad_root_addr = proc.vaddr.wrapping_add(vad_root_offset);
        let vads = walk_vad_tree(reader, vad_root_addr, proc.pid, &proc.image_name)?;

        for vad in &vads {
            if vad.is_private && is_execute_write(vad.protection) {
                results.push(WinMalfindInfo {
                    pid: vad.pid,
                    image_name: vad.image_name.clone(),
                    start_vaddr: vad.start_vaddr,
                    end_vaddr: vad.end_vaddr,
                    protection_str: vad.protection_str.clone(),
                    first_bytes: Vec::new(), // would read from process VA space
                });
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    // Test fixtures declare layout consts/helpers beside the statements that use
    // them to keep each byte-plan readable; that ordering is intentional here.
    #![allow(clippy::items_after_statements)]
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_win_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    // _MMVAD_SHORT offsets (from ISF preset):
    // Left@0x0, Right@0x8, StartingVpn@0x18, EndingVpn@0x20, Flags@0x30
    const VAD_LEFT: usize = 0x0;
    const VAD_RIGHT: usize = 0x8;
    const VAD_STARTING_VPN: usize = 0x18;
    const VAD_ENDING_VPN: usize = 0x20;
    const VAD_FLAGS: usize = 0x30;

    // _RTL_AVL_TREE: Root@0x0
    const AVL_ROOT: usize = 0x0;

    /// Build a _MMVAD_SHORT node in a byte buffer.
    fn build_vad_node(
        buf: &mut [u8],
        offset: usize,
        left: u64,
        right: u64,
        starting_vpn: u64,
        ending_vpn: u64,
        flags: u32,
    ) {
        buf[offset + VAD_LEFT..offset + VAD_LEFT + 8].copy_from_slice(&left.to_le_bytes());
        buf[offset + VAD_RIGHT..offset + VAD_RIGHT + 8].copy_from_slice(&right.to_le_bytes());
        buf[offset + VAD_STARTING_VPN..offset + VAD_STARTING_VPN + 8]
            .copy_from_slice(&starting_vpn.to_le_bytes());
        buf[offset + VAD_ENDING_VPN..offset + VAD_ENDING_VPN + 8]
            .copy_from_slice(&ending_vpn.to_le_bytes());
        buf[offset + VAD_FLAGS..offset + VAD_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
    }

    /// Encode VadFlags for the Win8+ layout: protection in bits [3:7], type in
    /// bits [0:2] (the preset ISF has no `NtBuildNumber`, so the walker resolves
    /// the default Win8+ protection shift of 3).
    fn make_vad_flags(protection: u32, vad_type: u32) -> u32 {
        (protection << 3) | (vad_type & VAD_TYPE_MASK)
    }

    /// On real Win8+/Server 2012 R2 (build 9600) the `_MMVAD_FLAGS.Protection`
    /// bitfield sits at bits [3:7], not [7:11] — confirmed against Volatility's
    /// win81/win10 x64 vtypes (`Protection` BitField `start_bit = 3`). A
    /// PAGE_EXECUTE_READWRITE region (protection index 6) therefore encodes as
    /// `6 << 3 = 0x30`. The walker must decode it back to index 6 — the malfind
    /// RWX gate (F26 spoolsv injection) depends on this. With the legacy
    /// `shift = 7` this decodes to 0 (PAGE_NOACCESS) and the test fails.
    #[test]
    fn protection_decoded_at_win8_bit_position() {
        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;
        let root_off = 0x100usize;
        let root_vaddr = page_vaddr + root_off as u64;

        let mut page = vec![0u8; 4096];
        page[AVL_ROOT..AVL_ROOT + 8].copy_from_slice(&root_vaddr.to_le_bytes());

        let flags = 6u32 << 3; // Protection index 6 (EXECUTE_READWRITE) at bits [3:7]
        build_vad_node(&mut page, root_off, 0, 0, 0x100, 0x1FF, flags);

        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &page);

        let reader = make_win_reader(ptb);
        let results = walk_vad_tree(&reader, page_vaddr, 1, "evil.exe").unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].protection, 6,
            "EXECUTE_READWRITE index must decode at bit 3 (Win8+ layout)"
        );
        assert_eq!(results[0].protection_str, "PAGE_EXECUTE_READWRITE");
    }

    /// The protection bit position is build-keyed (Volatility x64 vtypes):
    /// Vista/Win7 = bit 11, Win8.0+ (build >= 9200) = bit 3. Unknown build
    /// defaults to the modern Win8+ layout.
    #[test]
    fn protection_shift_is_build_keyed() {
        assert_eq!(protection_shift(Some(7601)), 11); // Win7 SP1
        assert_eq!(protection_shift(Some(9200)), 3); // Win8.0 RTM
        assert_eq!(protection_shift(Some(9600)), 3); // Server 2012 R2
        assert_eq!(protection_shift(Some(19041)), 3); // Win10 20H1
        assert_eq!(protection_shift(None), 3); // build unresolved -> modern
    }

    /// VAD pointers come from untrusted memory: a corrupt/crafted tree can share
    /// a child between two parents (or form a cycle). The walk must visit each
    /// node at most once and terminate. Diamond: root -> {A, B}, A -> C, B -> C.
    /// Without a visited-set, C is enumerated twice (len 5); with it, len 4.
    #[test]
    fn vad_walk_dedups_shared_nodes() {
        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;
        let (root, a, b, c) = (0x100usize, 0x200usize, 0x300usize, 0x400usize);
        let va = |o: usize| page_vaddr + o as u64;

        let mut page = vec![0u8; 4096];
        page[AVL_ROOT..AVL_ROOT + 8].copy_from_slice(&va(root).to_le_bytes());
        let f = make_vad_flags(4, 0); // PAGE_READWRITE
        build_vad_node(&mut page, root, va(a), va(b), 0x10, 0x1F, f);
        build_vad_node(&mut page, a, va(c), 0, 0x20, 0x2F, f);
        build_vad_node(&mut page, b, va(c), 0, 0x30, 0x3F, f);
        build_vad_node(&mut page, c, 0, 0, 0x40, 0x4F, f);

        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &page);
        let reader = make_win_reader(ptb);

        let results = walk_vad_tree(&reader, page_vaddr, 1, "p.exe").unwrap();
        assert_eq!(
            results.len(),
            4,
            "shared child C must be visited once, not twice"
        );
    }

    /// Real Win8+/Server 2012 R2 `_MMVAD_SHORT`: no direct `Left`/`Right`/`Flags`;
    /// the AVL links live in `VadNode` (`_RTL_BALANCED_NODE`) and the flags in the
    /// `u` union. Exercises the VadNode and `u`-union branches of the readers.
    #[test]
    fn walks_win8_vadnode_layout() {
        let isf = IsfBuilder::new()
            .add_struct("_RTL_AVL_TREE", 8)
            .add_field("_RTL_AVL_TREE", "Root", 0, "pointer")
            .add_struct("_RTL_BALANCED_NODE", 0x18)
            .add_field("_RTL_BALANCED_NODE", "Left", 0, "pointer")
            .add_field("_RTL_BALANCED_NODE", "Right", 8, "pointer")
            .add_struct("_MMVAD_SHORT", 0x40)
            .add_field("_MMVAD_SHORT", "VadNode", 0x0, "_RTL_BALANCED_NODE")
            .add_field("_MMVAD_SHORT", "StartingVpn", 0x18, "pointer")
            .add_field("_MMVAD_SHORT", "EndingVpn", 0x20, "pointer")
            .add_field("_MMVAD_SHORT", "u", 0x28, "unsigned long")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;
        let root_off = 0x100usize;
        let root_vaddr = page_vaddr + root_off as u64;

        let mut page = vec![0u8; 4096];
        page[0..8].copy_from_slice(&root_vaddr.to_le_bytes()); // _RTL_AVL_TREE.Root
                                                               // VadNode.Left@0 / Right@8 stay 0 (leaf); StartingVpn@0x18, EndingVpn@0x20.
        page[root_off + 0x18..root_off + 0x20].copy_from_slice(&0x100u64.to_le_bytes());
        page[root_off + 0x20..root_off + 0x28].copy_from_slice(&0x1FFu64.to_le_bytes());
        // u (VadFlags): protection index 6 (EXECUTE_READWRITE) at bits [3:7].
        page[root_off + 0x28..root_off + 0x2C].copy_from_slice(&(6u32 << 3).to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &page);
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_vad_tree(&reader, page_vaddr, 7, "win8.exe").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].protection, 6);
        assert_eq!(results[0].protection_str, "PAGE_EXECUTE_READWRITE");
        assert_eq!(results[0].start_vaddr, 0x100u64 << 12);
    }

    /// Faithful 9600 `_MMVAD_SHORT`: `StartingVpn`/`EndingVpn` are 32-bit
    /// (`unsigned long`) at 0x18/0x1c — ADJACENT. Reading them as `u64` fuses the
    /// two fields, so a region [VPN 0x100, 0x1FF] decodes to a garbage address
    /// (`0x000001FF_00000100 << 12`). The walk must read each VPN as u32.
    #[test]
    fn vpn_fields_are_32bit_on_win8() {
        let isf = IsfBuilder::new()
            .add_struct("_RTL_AVL_TREE", 8)
            .add_field("_RTL_AVL_TREE", "Root", 0, "pointer")
            .add_struct("_RTL_BALANCED_NODE", 0x18)
            .add_field("_RTL_BALANCED_NODE", "Left", 0, "pointer")
            .add_field("_RTL_BALANCED_NODE", "Right", 8, "pointer")
            .add_struct("_MMVAD_SHORT", 0x40)
            .add_field("_MMVAD_SHORT", "VadNode", 0x0, "_RTL_BALANCED_NODE")
            .add_field("_MMVAD_SHORT", "StartingVpn", 0x18, "unsigned long")
            .add_field("_MMVAD_SHORT", "EndingVpn", 0x1c, "unsigned long")
            .add_field("_MMVAD_SHORT", "u", 0x30, "unsigned long")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;
        let root_off = 0x100usize;
        let root_vaddr = page_vaddr + root_off as u64;

        let mut page = vec![0u8; 4096];
        page[0..8].copy_from_slice(&root_vaddr.to_le_bytes());
        // StartingVpn=0x100 (u32@0x18), EndingVpn=0x1FF (u32@0x1c) — adjacent.
        page[root_off + 0x18..root_off + 0x1c].copy_from_slice(&0x100u32.to_le_bytes());
        page[root_off + 0x1c..root_off + 0x20].copy_from_slice(&0x1FFu32.to_le_bytes());
        page[root_off + 0x30..root_off + 0x34].copy_from_slice(&(4u32 << 3).to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &page);
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_vad_tree(&reader, page_vaddr, 7, "win8.exe").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].start_vaddr,
            0x100u64 << 12,
            "StartingVpn must be read as u32"
        );
        assert_eq!(
            results[0].end_vaddr,
            (0x1FFu64 << 12) | 0xFFF,
            "EndingVpn must be read as u32"
        );
    }

    #[test]
    fn walks_simple_vad_tree() {
        // AVL tree with 3 nodes:
        //        B (root)
        //       / \
        //      A   C
        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;

        let root_off = 0x100usize;
        let left_off = 0x200usize;
        let right_off = 0x300usize;

        let root_vaddr = page_vaddr + root_off as u64;
        let left_vaddr = page_vaddr + left_off as u64;
        let right_vaddr = page_vaddr + right_off as u64;

        let mut page = vec![0u8; 4096];

        // _RTL_AVL_TREE at offset 0: Root → root_vaddr
        page[AVL_ROOT..AVL_ROOT + 8].copy_from_slice(&root_vaddr.to_le_bytes());

        // Node B (root): VPN 0x100..0x1FF, PAGE_READWRITE, private
        build_vad_node(
            &mut page,
            root_off,
            left_vaddr,
            right_vaddr,
            0x100,
            0x1FF,
            make_vad_flags(4, 0), // PAGE_READWRITE, VadNone (private)
        );

        // Node A (left): VPN 0x010..0x01F, PAGE_READONLY, mapped
        build_vad_node(
            &mut page,
            left_off,
            0, // no left child
            0, // no right child
            0x010,
            0x01F,
            make_vad_flags(1, 2), // PAGE_READONLY, VadImageMap
        );

        // Node C (right): VPN 0x200..0x2FF, PAGE_EXECUTE_READ, mapped
        build_vad_node(
            &mut page,
            right_off,
            0,
            0,
            0x200,
            0x2FF,
            make_vad_flags(3, 1), // PAGE_EXECUTE_READ, VadWriteWatch
        );

        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &page);

        let reader = make_win_reader(ptb);
        let results = walk_vad_tree(&reader, page_vaddr, 1234, "test.exe").unwrap();

        assert_eq!(results.len(), 3);

        // Verify all nodes found (order may vary due to AVL traversal)
        let vpns: Vec<u64> = results.iter().map(|v| v.start_vaddr >> 12).collect();
        assert!(vpns.contains(&0x010));
        assert!(vpns.contains(&0x100));
        assert!(vpns.contains(&0x200));

        // Check a specific node
        let node_b = results
            .iter()
            .find(|v| v.start_vaddr == 0x100 << 12)
            .unwrap();
        assert_eq!(node_b.pid, 1234);
        assert_eq!(node_b.image_name, "test.exe");
        assert_eq!(node_b.protection_str, "PAGE_READWRITE");
        assert!(node_b.is_private);
    }

    #[test]
    fn empty_vad_tree() {
        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;

        let mut page = vec![0u8; 4096];
        // _RTL_AVL_TREE.Root = 0 (null)
        page[AVL_ROOT..AVL_ROOT + 8].copy_from_slice(&0u64.to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &page);

        let reader = make_win_reader(ptb);
        let results = walk_vad_tree(&reader, page_vaddr, 4, "System").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn single_node_vad_tree() {
        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;

        let root_off = 0x100usize;
        let root_vaddr = page_vaddr + root_off as u64;

        let mut page = vec![0u8; 4096];
        page[AVL_ROOT..AVL_ROOT + 8].copy_from_slice(&root_vaddr.to_le_bytes());

        // Single node: VPN 0x7FFE0..0x7FFEF, PAGE_EXECUTE_READWRITE, private
        build_vad_node(
            &mut page,
            root_off,
            0,
            0,
            0x7FFE0,
            0x7FFEF,
            make_vad_flags(6, 0), // PAGE_EXECUTE_READWRITE, private
        );

        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &page);

        let reader = make_win_reader(ptb);
        let results = walk_vad_tree(&reader, page_vaddr, 500, "cmd.exe").unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].start_vaddr, 0x7FFE0 << 12);
        assert_eq!(results[0].end_vaddr, (0x7FFEF << 12) | 0xFFF);
        assert_eq!(results[0].protection_str, "PAGE_EXECUTE_READWRITE");
        assert!(results[0].is_private);
    }

    #[test]
    fn protection_to_string_covers_all_values() {
        assert_eq!(protection_to_string(0), "PAGE_NOACCESS");
        assert_eq!(protection_to_string(1), "PAGE_READONLY");
        assert_eq!(protection_to_string(2), "PAGE_EXECUTE");
        assert_eq!(protection_to_string(3), "PAGE_EXECUTE_READ");
        assert_eq!(protection_to_string(4), "PAGE_READWRITE");
        assert_eq!(protection_to_string(5), "PAGE_WRITECOPY");
        assert_eq!(protection_to_string(6), "PAGE_EXECUTE_READWRITE");
        assert_eq!(protection_to_string(7), "PAGE_EXECUTE_WRITECOPY");
        assert_eq!(protection_to_string(99), "UNKNOWN(99)");
    }

    #[test]
    fn is_execute_write_identifies_rwx() {
        assert!(!is_execute_write(0)); // NOACCESS
        assert!(!is_execute_write(1)); // READONLY
        assert!(!is_execute_write(4)); // READWRITE (no execute)
        assert!(is_execute_write(6)); // EXECUTE_READWRITE
        assert!(is_execute_write(7)); // EXECUTE_WRITECOPY
    }

    #[test]
    fn is_private_vad_checks_type() {
        assert!(is_private_vad(make_vad_flags(4, 0))); // VadNone = private
        assert!(!is_private_vad(make_vad_flags(4, 1))); // VadWriteWatch
        assert!(!is_private_vad(make_vad_flags(4, 2))); // VadImageMap
    }

    // --- Malfind tests ---

    const EPROCESS_PID: u64 = 0x440;
    const EPROCESS_LINKS: u64 = 0x448;
    const EPROCESS_PPID: u64 = 0x540;
    const EPROCESS_PEB: u64 = 0x550;
    const EPROCESS_IMAGE_NAME: u64 = 0x5A8;
    const EPROCESS_CREATE_TIME: u64 = 0x430;
    const EPROCESS_EXIT_TIME: u64 = 0x438;
    const EPROCESS_VAD_ROOT: u64 = 0x7D8;
    const KPROCESS_DTB: u64 = 0x28;

    #[test]
    fn malfind_detects_rwx_private_region() {
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let vad_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0080_1000;
        let vad_paddr: u64 = 0x0080_2000;

        // Build _EPROCESS
        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(vad_vaddr, vad_paddr, flags::WRITABLE)
            // Sentinel list
            .write_phys_u64(head_paddr, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(head_paddr + 8, eproc_vaddr + EPROCESS_LINKS)
            // _EPROCESS fields
            .write_phys_u64(eproc_paddr + KPROCESS_DTB, 0x1AB000)
            .write_phys_u64(eproc_paddr + EPROCESS_CREATE_TIME, 132800000000000000)
            .write_phys_u64(eproc_paddr + EPROCESS_EXIT_TIME, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PID, 1234)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS + 8, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_PPID, 4)
            .write_phys_u64(eproc_paddr + EPROCESS_PEB, 0x7FFE_0000) // non-null PEB
            .write_phys(eproc_paddr + EPROCESS_IMAGE_NAME, b"malware.exe\0");

        // VadRoot → AVL tree root
        let vad_node_vaddr = vad_vaddr + 0x100;
        let mut vad_page = vec![0u8; 4096];

        // _RTL_AVL_TREE at VadRoot offset within eproc
        // But VadRoot is at eproc_vaddr + 0x7D8, which maps to eproc_paddr + 0x7D8
        // That's beyond our 4K page for eproc... we need another page.
        // Actually eproc is 2048 bytes, so 0x7D8 = 2008, within page.
        let ptb = ptb.write_phys_u64(eproc_paddr + EPROCESS_VAD_ROOT, vad_node_vaddr);

        // Single VAD node: PAGE_EXECUTE_READWRITE, private
        build_vad_node(
            &mut vad_page,
            0x100,
            0,
            0,
            0x400,                // StartingVpn
            0x40F,                // EndingVpn (16 pages)
            make_vad_flags(6, 0), // PAGE_EXECUTE_READWRITE, private
        );

        let ptb = ptb.write_phys(vad_paddr, &vad_page);

        let reader = make_win_reader(ptb);
        let results = walk_malfind(&reader, head_vaddr).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pid, 1234);
        assert_eq!(results[0].image_name, "malware.exe");
        assert_eq!(results[0].start_vaddr, 0x400 << 12);
        assert_eq!(results[0].protection_str, "PAGE_EXECUTE_READWRITE");
    }

    #[test]
    fn malfind_skips_non_rwx_regions() {
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let vad_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0080_1000;
        let vad_paddr: u64 = 0x0080_2000;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(vad_vaddr, vad_paddr, flags::WRITABLE)
            .write_phys_u64(head_paddr, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(head_paddr + 8, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(eproc_paddr + KPROCESS_DTB, 0x1AB000)
            .write_phys_u64(eproc_paddr + EPROCESS_CREATE_TIME, 132800000000000000)
            .write_phys_u64(eproc_paddr + EPROCESS_EXIT_TIME, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PID, 500)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS + 8, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_PPID, 4)
            .write_phys_u64(eproc_paddr + EPROCESS_PEB, 0x7FFE_0000)
            .write_phys(eproc_paddr + EPROCESS_IMAGE_NAME, b"clean.exe\0");

        let vad_node_vaddr = vad_vaddr + 0x100;
        let ptb = ptb.write_phys_u64(eproc_paddr + EPROCESS_VAD_ROOT, vad_node_vaddr);

        let mut vad_page = vec![0u8; 4096];
        // PAGE_READWRITE (not executable) → should not be flagged
        build_vad_node(
            &mut vad_page,
            0x100,
            0,
            0,
            0x400,
            0x40F,
            make_vad_flags(4, 0), // PAGE_READWRITE, private
        );
        let ptb = ptb.write_phys(vad_paddr, &vad_page);

        let reader = make_win_reader(ptb);
        let results = walk_malfind(&reader, head_vaddr).unwrap();
        assert!(results.is_empty());
    }

    // RED: missing _EPROCESS.VadRoot field → MissingField
    #[test]
    fn walk_malfind_missing_eprocess_vad_root_returns_missing_field() {
        // ISF with no _EPROCESS at all → walk_processes will fail first.
        // We need walk_processes to succeed (empty list is OK — walk_malfind
        // skips the VadRoot check when there are no processes). So we need
        // at least one process with peb_addr != 0 to trigger the VadRoot lookup.
        // Build minimal ISF with process walk fields + one process entry, but
        // without _EPROCESS.VadRoot.
        let mut isf_json = IsfBuilder::windows_kernel_preset().build_json();
        if let Some(user_types) = isf_json["user_types"].as_object_mut() {
            if let Some(eprocess) = user_types.get_mut("_EPROCESS") {
                if let Some(fields) = eprocess["fields"].as_object_mut() {
                    fields.remove("VadRoot");
                }
            }
        }
        let resolver = IsfResolver::from_value(&isf_json).unwrap();

        // Build a minimal process list with peb_addr != 0 to trigger the VadRoot lookup.
        const EPROCESS_PID: u64 = 0x440;
        const EPROCESS_LINKS: u64 = 0x448;
        const EPROCESS_PPID: u64 = 0x540;
        const EPROCESS_PEB: u64 = 0x550;
        const EPROCESS_IMAGE_NAME: u64 = 0x5A8;
        const EPROCESS_CREATE_TIME: u64 = 0x430;
        const EPROCESS_EXIT_TIME: u64 = 0x438;
        const KPROCESS_DTB: u64 = 0x28;

        let eproc_paddr: u64 = 0x0080_0000;
        let head_paddr: u64 = 0x0070_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let head_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let eproc_links = eproc_vaddr + EPROCESS_LINKS;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr + 0x1000, eproc_paddr + 0x1000, flags::WRITABLE)
            .write_phys_u64(head_paddr, eproc_links)
            .write_phys_u64(head_paddr + 8, eproc_links)
            .write_phys_u64(eproc_paddr + KPROCESS_DTB, 0x1000)
            .write_phys_u64(eproc_paddr + EPROCESS_CREATE_TIME, 132_800_000_000_000_000)
            .write_phys_u64(eproc_paddr + EPROCESS_EXIT_TIME, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PID, 1234)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS + 8, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_PPID, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PEB, 0x7FFF_0000_0000) // non-zero PEB
            .write_phys(eproc_paddr + EPROCESS_IMAGE_NAME, b"notepad.exe\0");
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_malfind(&reader, head_vaddr);
        assert!(
            matches!(
                result,
                Err(crate::Error::MissingField { ref struct_name, ref field_name })
                if struct_name == "_EPROCESS" && field_name == "VadRoot"
            ),
            "expected MissingField(_EPROCESS.VadRoot), got {result:?}"
        );
    }
}
