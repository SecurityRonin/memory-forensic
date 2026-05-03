//! Shared test infrastructure for memf-linux walker tests.
//!
//! Import with: `use crate::testing::*;`

use memf_core::object_reader::ObjectReader;
use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
use memf_symbols::test_builders::IsfBuilder;

/// Build an `ObjectReader` from `IsfBuilder` + `PageTableBuilder`.
pub fn make_reader(
    _isf: &IsfBuilder,
    _ptb: PageTableBuilder,
) -> ObjectReader<SyntheticPhysMem> {
    todo!("not yet implemented")
}

/// Standard `task_struct` ISF layout used across Linux walker tests.
pub fn task_struct_isf() -> IsfBuilder {
    todo!("not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::PageTableBuilder;

    #[test]
    fn make_reader_builds_valid_reader() {
        let isf = task_struct_isf();
        let ptb = PageTableBuilder::new();
        let reader = make_reader(&isf, ptb);
        assert_eq!(
            reader.symbols().field_offset("task_struct", "pid"),
            Some(0)
        );
    }

    #[test]
    fn task_struct_isf_has_all_core_fields() {
        let isf = task_struct_isf();
        let ptb = PageTableBuilder::new();
        let reader = make_reader(&isf, ptb);
        for field in &["pid", "state", "tasks", "comm", "mm", "real_parent", "tgid"] {
            assert!(
                reader.symbols().field_offset("task_struct", field).is_some(),
                "missing field: {field}"
            );
        }
    }
}
