//! Windows per-process handle table walking.
//!
//! Walks `_EPROCESS.ObjectTable` → `_HANDLE_TABLE.TableCode` →
//! `_HANDLE_TABLE_ENTRY` array to enumerate open handles per process.
//! Each entry's `ObjectPointerBits` field (shifted left 4, with low bits
//! masked) yields an `_OBJECT_HEADER`, whose `TypeIndex` indexes into
//! the `ObTypeIndexTable` to resolve the object type name.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, WinHandleInfo};

/// Maximum number of handle entries to scan per process.
/// Prevents runaway iteration on corrupted handle tables.
const MAX_HANDLE_ENTRIES: u64 = 16384;

/// Walk all processes and enumerate their open handles.
///
/// For each process, reads `_EPROCESS.ObjectTable` → `_HANDLE_TABLE`,
/// then iterates the level-0 handle entry array. Returns a flat list
/// of all handles across all processes.
pub fn walk_handles<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<WinHandleInfo>> {
        todo!()
    }

/// Resolve the object type name from `ObTypeIndexTable[type_index]`.
///
/// Reads the pointer at `ob_table_addr + type_index * 8`, which yields
/// an `_OBJECT_TYPE` address, then reads `_OBJECT_TYPE.Name`.
fn resolve_type_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ob_table_addr: u64,
    type_index: u8,
) -> String {
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

    fn utf16le(s: &str) -> Vec<u8> {
        todo!()
    }

    // _EPROCESS offsets
    const EPROCESS_PID: u64 = 0x440;
    const EPROCESS_LINKS: u64 = 0x448;
    const EPROCESS_PPID: u64 = 0x540;
    const EPROCESS_PEB: u64 = 0x550;
    const EPROCESS_OBJECT_TABLE: u64 = 0x570;
    const EPROCESS_IMAGE_NAME: u64 = 0x5A8;
    const EPROCESS_CREATE_TIME: u64 = 0x430;
    const EPROCESS_EXIT_TIME: u64 = 0x438;
    const KPROCESS_DTB: u64 = 0x28;

    // _HANDLE_TABLE offsets
    const HANDLE_TABLE_CODE: u64 = 0x08;

    // _HANDLE_TABLE_ENTRY: 16 bytes each
    // ObjectPointerBits@0x0, GrantedAccessBits@0x8
    const ENTRY_OBJECT_PTR: u64 = 0x0;
    const ENTRY_GRANTED_ACCESS: u64 = 0x8;
    const ENTRY_SIZE: u64 = 16;

    // _OBJECT_HEADER offsets
    const OBJ_HEADER_TYPE_INDEX: u64 = 0x18;

    // _OBJECT_TYPE offsets
    const OBJ_TYPE_NAME: u64 = 0x10;

    // ISF preset defines ObTypeIndexTable at this address
    const OB_TYPE_INDEX_TABLE_VADDR: u64 = 0xFFFFF805_5A490000;

    /// Build a minimal process + handle table layout in synthetic memory.
    ///
    /// Returns the head_vaddr for PsActiveProcessHead.
    /// `handles` is a slice of (object_header_vaddr, granted_access, type_index).
    fn build_process_with_handles(
        pid: u64,
        image_name: &[u8],
        handles: &[(u64, u32, u8)],
        // Object type table: (type_index, type_name, obj_type_vaddr)
        type_table: &[(u8, &str, u64)],
    ) -> (u64, PageTableBuilder) {
        todo!()
    }

    #[test]
    fn walks_single_process_handles() {
        todo!()
    }

    #[test]
    fn skips_process_with_null_object_table() {
        todo!()
    }

    #[test]
    fn skips_zero_object_pointer_entries() {
        todo!()
    }
}
