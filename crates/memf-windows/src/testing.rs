//! Shared test infrastructure for memf-windows walker tests.
//!
//! Import with: `use crate::testing::*;`

use memf_core::object_reader::ObjectReader;
use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
use memf_symbols::test_builders::IsfBuilder;

/// Build an `ObjectReader` from a pre-populated `IsfBuilder` and `PageTableBuilder`.
pub fn make_reader(
    _isf: &IsfBuilder,
    _ptb: PageTableBuilder,
) -> ObjectReader<SyntheticPhysMem> {
    todo!("not yet implemented")
}

/// Standard Windows ISF with `_EPROCESS` and `_LIST_ENTRY`.
pub fn eprocess_isf() -> IsfBuilder {
    todo!("not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::PageTableBuilder;

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
