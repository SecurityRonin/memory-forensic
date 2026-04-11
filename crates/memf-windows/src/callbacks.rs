//! Windows kernel callback enumeration.
//!
//! Reads `PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`,
//! and `PspLoadImageNotifyRoutine` arrays. Each array holds up to 64
//! `_EX_CALLBACK_ROUTINE_BLOCK` pointers (with the low 4 bits used as
//! reference count via `_EX_FAST_REF`). The actual callback function
//! address is obtained by masking off the low nibble.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, WinCallbackInfo, WinDriverInfo};

/// Maximum number of callback slots per array.
const MAX_CALLBACK_SLOTS: usize = 64;

/// Walk all three kernel callback arrays and return registered callbacks.
///
/// For each non-null entry in the three arrays, decodes the
/// `_EX_FAST_REF` pointer (mask off low 4 bits) and resolves the
/// owning module.
pub fn walk_kernel_callbacks<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    process_notify_vaddr: u64,
    thread_notify_vaddr: u64,
    load_image_notify_vaddr: u64,
    known_modules: &[WinDriverInfo],
) -> Result<Vec<WinCallbackInfo>> {
        todo!()
    }

/// Read a single callback array of up to `MAX_CALLBACK_SLOTS` entries.
fn read_callback_array<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    array_vaddr: u64,
    callback_type: &str,
    known_modules: &[WinDriverInfo],
    results: &mut Vec<WinCallbackInfo>,
) -> Result<()> {
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

    fn ntoskrnl_module(base: u64) -> WinDriverInfo {
        todo!()
    }

    fn third_party_module(name: &str, base: u64, size: u64) -> WinDriverInfo {
        todo!()
    }

    /// Build 3 callback arrays on a single 4K page.
    /// Returns the base vaddrs for each array within the page.
    fn build_callback_page(
        process_entries: &[u64],
        thread_entries: &[u64],
        image_entries: &[u64],
        page_vaddr: u64,
        page_paddr: u64,
    ) -> (PageTableBuilder, u64, u64, u64) {
        todo!()
    }

    #[test]
    fn enumerates_callbacks_from_all_three_arrays() {
        todo!()
    }

    #[test]
    fn skips_null_entries_in_callback_arrays() {
        todo!()
    }

    #[test]
    fn identifies_unknown_module_callbacks() {
        todo!()
    }

    #[test]
    fn all_arrays_empty() {
        todo!()
    }
}
