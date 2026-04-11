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
        todo!()
    }

/// Whether a VAD protection value indicates execute+write (suspicious for private regions).
fn is_execute_write(prot: u32) -> bool {
        todo!()
    }

/// VadFlags.VadType is bits [0:2] (3 bits).
const VAD_TYPE_MASK: u32 = 0x7;

/// Whether a VAD is private (type 0 = VadNone → private allocation).
fn is_private_vad(flags: u32) -> bool {
        todo!()
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
        todo!()
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
        todo!()
    }

    /// Encode VadFlags: protection in bits [7:11], type in bits [0:2].
    fn make_vad_flags(protection: u32, vad_type: u32) -> u32 {
        todo!()
    }

    #[test]
    fn walks_simple_vad_tree() {
        todo!()
    }

    #[test]
    fn empty_vad_tree() {
        todo!()
    }

    #[test]
    fn single_node_vad_tree() {
        todo!()
    }

    #[test]
    fn protection_to_string_covers_all_values() {
        todo!()
    }

    #[test]
    fn is_execute_write_identifies_rwx() {
        todo!()
    }

    #[test]
    fn is_private_vad_checks_type() {
        todo!()
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
        todo!()
    }

    #[test]
    fn malfind_skips_non_rwx_regions() {
        todo!()
    }
}
