//! Windows Virtual Address Descriptor (VAD) tree walker.
//!
//! Traverses the `_EPROCESS.VadRoot` AVL tree of `_MMVAD_SHORT` nodes
//! to enumerate all virtual memory regions for a process. Also provides
//! `walk_malfind` which filters for suspicious private RWX regions.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, WinMalfindInfo, WinVadInfo};

/// VAD protection values (Windows page protection constants encoded in VadFlags).
/// Bits [7:11] of VadFlags contain the protection index.
const VAD_PROTECTION_SHIFT: u32 = 7;
const VAD_PROTECTION_MASK: u32 = 0x1F; // 5 bits

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

/// Whether a VAD is private (type 0 = VadNone → private allocation).
fn is_private_vad(flags: u32) -> bool {
    (flags & VAD_TYPE_MASK) == 0
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
    todo!()
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

    /// Encode VadFlags: protection in bits [7:11], type in bits [0:2].
    fn make_vad_flags(protection: u32, vad_type: u32) -> u32 {
        (protection << VAD_PROTECTION_SHIFT) | (vad_type & VAD_TYPE_MASK)
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
}
