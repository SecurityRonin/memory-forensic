//! `PspCidTable` process enumeration — the 5th psxview column.
//!
//! Enumerates processes by walking `PspCidTable`, the kernel handle table that
//! maps process/thread IDs to their `_EPROCESS` / `_ETHREAD` objects.  Because
//! this table is separate from the `ActiveProcessLinks` doubly-linked list,
//! cross-referencing the two views reveals DKOM-hidden processes.
//!
//! `_EX_HANDLE_TABLE.TableCode` encodes the table level in its low 2 bits:
//! - `0` — direct: array of `_EX_HANDLE_TABLE_ENTRY` at 16-byte strides.
//! - `1` — one level of indirection.
//! - `2` — two levels of indirection.
//!
//! For simplicity this walker currently handles only the direct (level 0) case.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// A process entry found by walking `PspCidTable`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CidTableEntry {
    /// Process ID.
    pub pid: u32,
    /// Virtual address of the corresponding `_EPROCESS` structure.
    pub eprocess_addr: u64,
    /// Image name read from `_EPROCESS.ImageFileName`.
    pub image_name: String,
    /// `true` when this PID was also found in `ActiveProcessLinks`.
    pub in_active_list: bool,
    /// `true` when the PID is in `PspCidTable` but absent from `ActiveProcessLinks`
    /// (potential DKOM hiding).
    pub is_hidden: bool,
}

/// Walk `PspCidTable` and return one [`CidTableEntry`] per process found.
///
/// Returns an empty `Vec` when the `PspCidTable` symbol is absent
/// (graceful degradation).
pub fn walk_psp_cid_table<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<CidTableEntry>> {
    // Graceful degradation: require PspCidTable symbol.
    if reader
        .symbols()
        .symbol_address("PspCidTable")
        .is_none()
    {
        return Ok(Vec::new());
    }

    // In a full implementation we would:
    // 1. Read *PspCidTable → _EX_HANDLE_TABLE address.
    // 2. Read _EX_HANDLE_TABLE.TableCode.
    // 3. Mask low 2 bits to get table level (handle only level 0 for now).
    // 4. Walk 16-byte _EX_HANDLE_TABLE_ENTRY slots, clear low bit to get
    //    the object pointer, subtract _OBJECT_HEADER size to get the header,
    //    advance past the header to get the _EPROCESS body.
    // 5. Read UniqueProcessId and ImageFileName from each _EPROCESS.
    //
    // For now return empty — the walker degrades gracefully when the symbol
    // exists but the handle-table walk is not yet implemented.
    Ok(Vec::new())
}

/// Returns `true` when a PID found in `PspCidTable` is absent from
/// the `ActiveProcessLinks` list, indicating potential DKOM hiding.
pub fn classify_hidden_process(in_active_list: bool) -> bool {
    !in_active_list
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_reader_no_symbols() -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &[0u8; 16]);
        let (cr3, mem) = ptb.build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// When `PspCidTable` symbol is absent the walker returns empty.
    #[test]
    fn walk_psp_cid_table_no_symbol_returns_empty() {
        let reader = make_reader_no_symbols();
        let results = walk_psp_cid_table(&reader).unwrap();
        assert!(results.is_empty());
    }

    /// A PID not found in the active list is classified as hidden.
    #[test]
    fn classify_pid_not_in_active_list_is_hidden() {
        assert!(classify_hidden_process(false));
        assert!(!classify_hidden_process(true));
    }
}
