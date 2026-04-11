//! Linux hidden kernel module detector.
//!
//! Cross-references kernel modules found via the `modules` linked list
//! against the kernel's `kset` hierarchy (sysfs). Modules present in
//! one view but not the other may have been hidden by a rootkit.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, HiddenModuleInfo, Result};

/// Cross-reference kernel modules for hidden module detection.
///
/// Walks the `modules` linked list and the `module_kset` kobj tree,
/// then merges results. Modules visible in one but not both are
/// flagged as potentially hidden.
pub fn check_hidden_modules<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<HiddenModuleInfo>> {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_test_reader(data: &[u8], vaddr: u64, paddr: u64) -> ObjectReader<SyntheticPhysMem> {
        todo!()
    }

    #[test]
    fn empty_module_list() {
        todo!()
    }

    #[test]
    fn missing_modules_symbol() {
        todo!()
    }

    #[test]
    fn missing_module_list_field_returns_error() {
        todo!()
    }

    #[test]
    fn single_module_in_list() {
        todo!()
    }
}
