//! Linux kernel module walker.
//!
//! Enumerates loaded kernel modules by walking the `modules` linked list.
//! Each `struct module` is connected via `list` (`list_head`).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, ModuleInfo, ModuleState, Result};

/// Walk the Linux kernel module list.
pub fn walk_modules<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<ModuleInfo>> {
        todo!()
    }

fn read_module_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    mod_addr: u64,
) -> Result<ModuleInfo> {
        todo!()
    }

fn read_core_layout<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    mod_addr: u64,
) -> Result<(u64, u64)> {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_module_reader(data: &[u8], vaddr: u64, paddr: u64) -> ObjectReader<SyntheticPhysMem> {
        todo!()
    }

    #[test]
    fn walk_two_modules() {
        todo!()
    }

    #[test]
    fn walk_modules_with_legacy_module_core_layout() {
        todo!()
    }

    #[test]
    fn walk_modules_no_layout_fields_skips_module() {
        todo!()
    }

    #[test]
    fn walk_modules_missing_symbol_returns_error() {
        todo!()
    }

    #[test]
    fn empty_module_list() {
        todo!()
    }
}
