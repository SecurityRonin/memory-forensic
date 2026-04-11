//! Linux syscall table integrity checker.
//!
//! Reads the `sys_call_table` kernel symbol and checks each handler
//! address against the kernel text region (`_stext`..`_etext`).
//! Entries pointing outside this range are flagged as potentially hooked.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, Result, SyscallInfo};

/// Default number of syscall table entries for x86_64.
const DEFAULT_NR_SYSCALLS: u64 = 450;

/// Check the syscall table for hooks.
///
/// Reads `sys_call_table` entries and compares each handler against the
/// `_stext`..`_etext` kernel text range. Returns info for each entry,
/// marking entries outside the text region as potentially hooked.
pub fn check_syscall_table<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<SyscallInfo>> {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_test_reader(
        data: &[u8],
        vaddr: u64,
        paddr: u64,
        nr_syscalls: u64,
        stext: u64,
        etext: u64,
    ) -> ObjectReader<SyntheticPhysMem> {
        todo!()
    }

    #[test]
    fn all_handlers_in_text_region() {
        todo!()
    }

    #[test]
    fn hooked_syscall_detected() {
        todo!()
    }

    #[test]
    fn missing_sys_call_table_symbol() {
        todo!()
    }

    #[test]
    fn uses_default_count_without_nr_syscall_max() {
        todo!()
    }
}
