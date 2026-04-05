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
        let mut builder = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            .add_symbol("sys_call_table", vaddr)
            .add_symbol("_stext", stext)
            .add_symbol("_etext", etext);

        if nr_syscalls > 0 {
            builder = builder.add_symbol("__NR_syscall_max", nr_syscalls - 1);
        }

        let isf = builder.build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn all_handlers_in_text_region() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let stext: u64 = 0xFFFF_8000_0000_0000;
        let etext: u64 = 0xFFFF_8000_00FF_FFFF;
        let mut data = vec![0u8; 4096];

        // 3 syscall entries, all within text region
        let handler0: u64 = 0xFFFF_8000_0001_0000;
        let handler1: u64 = 0xFFFF_8000_0002_0000;
        let handler2: u64 = 0xFFFF_8000_0003_0000;
        data[0..8].copy_from_slice(&handler0.to_le_bytes());
        data[8..16].copy_from_slice(&handler1.to_le_bytes());
        data[16..24].copy_from_slice(&handler2.to_le_bytes());

        let reader = make_test_reader(&data, vaddr, paddr, 3, stext, etext);
        let entries = check_syscall_table(&reader).unwrap();

        assert_eq!(entries.len(), 3);
        assert!(!entries[0].hooked);
        assert!(!entries[1].hooked);
        assert!(!entries[2].hooked);
        assert_eq!(entries[0].number, 0);
        assert_eq!(entries[1].number, 1);
        assert_eq!(entries[2].number, 2);
        assert_eq!(entries[0].handler, handler0);
    }

    #[test]
    fn hooked_syscall_detected() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let stext: u64 = 0xFFFF_8000_0000_0000;
        let etext: u64 = 0xFFFF_8000_00FF_FFFF;
        let mut data = vec![0u8; 4096];

        // Handler 0: normal (in text)
        let normal: u64 = 0xFFFF_8000_0001_0000;
        data[0..8].copy_from_slice(&normal.to_le_bytes());

        // Handler 1: hooked! (outside text, points to a module)
        let hooked: u64 = 0xFFFF_C900_1234_5678;
        data[8..16].copy_from_slice(&hooked.to_le_bytes());

        // Handler 2: normal
        data[16..24].copy_from_slice(&normal.to_le_bytes());

        let reader = make_test_reader(&data, vaddr, paddr, 3, stext, etext);
        let entries = check_syscall_table(&reader).unwrap();

        assert_eq!(entries.len(), 3);
        assert!(!entries[0].hooked);
        assert!(entries[1].hooked);
        assert!(!entries[2].hooked);
        assert_eq!(entries[1].handler, hooked);
    }

    #[test]
    fn missing_sys_call_table_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            .add_symbol("_stext", 0xFFFF_8000_0000_0000)
            .add_symbol("_etext", 0xFFFF_8000_00FF_FFFF)
            // No sys_call_table symbol
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = check_syscall_table(&reader);
        assert!(result.is_err());
    }

    #[test]
    fn uses_default_count_without_nr_syscall_max() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let stext: u64 = 0xFFFF_8000_0000_0000;
        let etext: u64 = 0xFFFF_8000_00FF_FFFF;

        // Fill page with a valid handler repeated
        let mut data = vec![0u8; 4096];
        let handler: u64 = 0xFFFF_8000_0001_0000;
        for i in 0..512 {
            let off = i * 8;
            data[off..off + 8].copy_from_slice(&handler.to_le_bytes());
        }

        // nr_syscalls = 0 means no __NR_syscall_max symbol
        let reader = make_test_reader(&data, vaddr, paddr, 0, stext, etext);
        let entries = check_syscall_table(&reader).unwrap();

        // Should use DEFAULT_NR_SYSCALLS but clamp to what fits in one page
        assert_eq!(entries.len(), DEFAULT_NR_SYSCALLS as usize);
    }
}
