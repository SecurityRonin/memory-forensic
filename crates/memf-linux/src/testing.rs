//! Shared test infrastructure for memf-linux walker tests.
//!
//! Import with: `use crate::testing::*;`

use memf_core::object_reader::ObjectReader;
use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
use memf_core::vas::{TranslationMode, VirtualAddressSpace};
use memf_symbols::isf::IsfResolver;
use memf_symbols::test_builders::IsfBuilder;

/// Build an `ObjectReader` from `IsfBuilder` + `PageTableBuilder`.
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

/// Standard `task_struct` ISF layout used across Linux walker tests.
pub fn task_struct_isf() -> IsfBuilder {
    IsfBuilder::new()
        .add_struct("task_struct", 128)
        .add_field("task_struct", "pid", 0, "int")
        .add_field("task_struct", "state", 4, "long")
        .add_field("task_struct", "tasks", 16, "list_head")
        .add_field("task_struct", "comm", 32, "char")
        .add_field("task_struct", "mm", 48, "pointer")
        .add_field("task_struct", "real_parent", 56, "pointer")
        .add_field("task_struct", "tgid", 64, "int")
        .add_field("task_struct", "thread_group", 72, "list_head")
        .add_field("task_struct", "start_time", 88, "unsigned long")
        .add_struct("list_head", 16)
        .add_field("list_head", "next", 0, "pointer")
        .add_field("list_head", "prev", 8, "pointer")
}

#[cfg(test)]
mod tests {
    use super::*;

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
