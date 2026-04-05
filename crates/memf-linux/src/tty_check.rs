//! Linux TTY operations hook detector.
//!
//! Walks the `tty_drivers` list and checks each driver's
//! `tty_operations` function pointers against the kernel text
//! region (`_stext`..`_etext`). Handlers pointing outside this
//! range indicate potential rootkit hooks on TTY devices.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, Result, TtyCheckInfo};

/// Names of `tty_operations` function pointers to check.
const OPS_TO_CHECK: &[(&str, u64)] = &[
    ("open", 0),
    ("close", 8),
    ("write", 16),
    ("ioctl", 48),
];

/// Check TTY driver operations for hooks.
///
/// Walks the `tty_drivers` linked list, reads each driver's
/// `tty_operations` struct, and checks function pointers against
/// the kernel text region.
pub fn check_tty_hooks<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<TtyCheckInfo>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_test_reader(
        data: &[u8],
        vaddr: u64,
        paddr: u64,
        stext: u64,
        etext: u64,
    ) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("tty_driver", 128)
            .add_field("tty_driver", "name", 0, "pointer")
            .add_field("tty_driver", "ops", 16, "pointer")
            .add_field("tty_driver", "tty_drivers", 24, "list_head")
            .add_struct("tty_operations", 128)
            .add_field("tty_operations", "open", 0, "pointer")
            .add_field("tty_operations", "close", 8, "pointer")
            .add_field("tty_operations", "write", 16, "pointer")
            .add_field("tty_operations", "ioctl", 48, "pointer")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("tty_drivers", vaddr + 0x800)
            .add_symbol("_stext", stext)
            .add_symbol("_etext", etext)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, ptflags::WRITABLE)
            .write_phys(paddr, data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn clean_tty_ops_not_hooked() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let stext: u64 = 0xFFFF_8000_0000_0000;
        let etext: u64 = 0xFFFF_8000_00FF_FFFF;
        let mut data = vec![0u8; 4096];

        let handler: u64 = 0xFFFF_8000_0001_0000; // in text region

        // tty_drivers list_head at +0x800 (points to self = empty list → just test setup)
        let drivers_head = vaddr + 0x800;
        data[0x800..0x808].copy_from_slice(&drivers_head.to_le_bytes()); // next = self
        data[0x808..0x810].copy_from_slice(&drivers_head.to_le_bytes()); // prev = self

        let reader = make_test_reader(&data, vaddr, paddr, stext, etext);
        let results = check_tty_hooks(&reader).unwrap();

        // Empty list → no results (but no error either)
        assert!(results.is_empty());
    }

    #[test]
    fn missing_tty_drivers_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("tty_driver", 64)
            .add_field("tty_driver", "name", 0, "pointer")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("_stext", 0xFFFF_8000_0000_0000)
            .add_symbol("_etext", 0xFFFF_8000_00FF_FFFF)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = check_tty_hooks(&reader);
        assert!(result.is_err());
    }
}
