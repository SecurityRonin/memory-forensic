//! Windows SSDT (System Service Descriptor Table) hook detection.
//!
//! Reads `KeServiceDescriptorTable` → `_KSERVICE_TABLE_DESCRIPTOR.Base`
//! to get the SSDT array of i32 relative offsets. For each entry,
//! computes the absolute target address and checks whether it falls
//! within a known kernel module.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, WinDriverInfo, WinSsdtHookInfo};

/// Check the SSDT for hooked system service entries.
///
/// `ssdt_vaddr` is the virtual address of `KeServiceDescriptorTable`.
/// Each SSDT entry is a 32-bit value encoding `(relative_offset << 4) | arg_count`.
/// The absolute target is `Base + (entry >> 4)`.
///
/// Entries that resolve to addresses outside all `known_modules` are
/// flagged as suspicious (potential SSDT hooks).
pub fn check_ssdt_hooks<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ssdt_vaddr: u64,
    known_modules: &[WinDriverInfo],
) -> Result<Vec<WinSsdtHookInfo>> {
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

    // _KSERVICE_TABLE_DESCRIPTOR offsets
    const SSDT_BASE: u64 = 0x0;
    const SSDT_LIMIT: u64 = 0x10;

    /// Build a synthetic SSDT with the given i32 entries.
    /// Returns (ssdt_descriptor_paddr, ssdt_table_paddr, PageTableBuilder).
    fn build_ssdt(
        entries: &[i32],
        ssdt_vaddr: u64,
        ssdt_paddr: u64,
        table_vaddr: u64,
        table_paddr: u64,
    ) -> PageTableBuilder {
        todo!()
    }

    fn ntoskrnl_module(base: u64) -> WinDriverInfo {
        todo!()
    }

    #[test]
    fn detects_ssdt_hook() {
        todo!()
    }

    #[test]
    fn clean_ssdt_no_hooks() {
        todo!()
    }

    #[test]
    fn empty_ssdt() {
        todo!()
    }

    #[test]
    fn negative_offset_entry() {
        todo!()
    }
}
