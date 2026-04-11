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
        todo!()
    }

/// Returns `true` when a PID found in `PspCidTable` is absent from
/// the `ActiveProcessLinks` list, indicating potential DKOM hiding.
pub fn classify_hidden_process(in_active_list: bool) -> bool {
        todo!()
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
        todo!()
    }

    /// When `PspCidTable` symbol is absent the walker returns empty.
    #[test]
    fn walk_psp_cid_table_no_symbol_returns_empty() {
        todo!()
    }

    /// A PID not found in the active list is classified as hidden.
    #[test]
    fn classify_pid_not_in_active_list_is_hidden() {
        todo!()
    }
}
