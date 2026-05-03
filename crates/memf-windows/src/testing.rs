//! Shared test infrastructure for memf-windows walker tests.
//!
//! Import with: `use crate::testing::*;`

use memf_core::object_reader::ObjectReader;
use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
use memf_core::vas::{TranslationMode, VirtualAddressSpace};
use memf_symbols::isf::IsfResolver;
use memf_symbols::test_builders::IsfBuilder;

/// Build an `ObjectReader` from a pre-populated `IsfBuilder` and `PageTableBuilder`.
pub fn make_reader(
    isf: &IsfBuilder,
    ptb: PageTableBuilder,
) -> ObjectReader<SyntheticPhysMem> {
    let json = isf.build_json();
    let resolver = IsfResolver::from_value(&json).expect("valid ISF");
    let (cr3, mem) = ptb.build();
    let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
    ObjectReader::new(vas, Box::new(resolver))
}

/// Standard Windows ISF with `_EPROCESS` and `_LIST_ENTRY`.
pub fn eprocess_isf() -> IsfBuilder {
    IsfBuilder::new()
        .add_struct("_EPROCESS", 0x700)
        .add_field("_EPROCESS", "UniqueProcessId", 0x2e8, "pointer")
        .add_field("_EPROCESS", "ActiveProcessLinks", 0x2f0, "_LIST_ENTRY")
        .add_field("_EPROCESS", "ImageFileName", 0x450, "char")
        .add_field("_EPROCESS", "CreateTime", 0x458, "unsigned long long")
        .add_field("_EPROCESS", "ExitTime", 0x460, "unsigned long long")
        .add_field("_EPROCESS", "Peb", 0x3f8, "pointer")
        .add_field("_EPROCESS", "InheritedFromUniqueProcessId", 0x3e0, "pointer")
        .add_field("_EPROCESS", "ActiveThreads", 0x5f0, "unsigned long")
        .add_field("_EPROCESS", "WoW64Process", 0x438, "pointer")
        .add_struct("_LIST_ENTRY", 16)
        .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
        .add_field("_LIST_ENTRY", "Blink", 8, "pointer")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_reader_builds_valid_reader() {
        let isf = eprocess_isf();
        let ptb = PageTableBuilder::new();
        let reader = make_reader(&isf, ptb);
        assert_eq!(
            reader.symbols().field_offset("_EPROCESS", "UniqueProcessId"),
            Some(0x2e8)
        );
    }

    #[test]
    fn eprocess_isf_has_active_process_links() {
        let isf = eprocess_isf();
        let ptb = PageTableBuilder::new();
        let reader = make_reader(&isf, ptb);
        assert!(reader
            .symbols()
            .field_offset("_EPROCESS", "ActiveProcessLinks")
            .is_some());
    }
}
