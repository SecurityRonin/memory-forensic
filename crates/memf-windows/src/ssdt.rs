//! Windows SSDT (System Service Descriptor Table) hook detection.
//!
//! Reads `KeServiceDescriptorTable` → `_KSERVICE_TABLE_DESCRIPTOR.Base`
//! to get the SSDT array of i32 relative offsets. For each entry,
//! computes the absolute target address and checks whether it falls
//! within a known kernel module.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, WinDriverInfo, WinSsdtHookInfo};

/// Check the SSDT for hooked system service entries.
///
/// `ssdt_vaddr` is the virtual address of `KeServiceDescriptorTable`.
/// Each SSDT entry is a 32-bit value encoding `(relative_offset << 4) | arg_count`.
/// The absolute target is `Base + (entry >> 4)`.
///
/// Entries that resolve to addresses outside all `known_modules` are
/// flagged as suspicious (potential SSDT hooks).
pub fn check_ssdt_hooks<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ssdt_vaddr: u64,
    known_modules: &[WinDriverInfo],
) -> Result<Vec<WinSsdtHookInfo>> {
    // Read _KSERVICE_TABLE_DESCRIPTOR.Base (pointer to i32 array)
    let base: u64 = reader.read_field(ssdt_vaddr, "_KSERVICE_TABLE_DESCRIPTOR", "Base")?;

    // Read _KSERVICE_TABLE_DESCRIPTOR.Limit (number of entries)
    let limit: u32 = reader.read_field(ssdt_vaddr, "_KSERVICE_TABLE_DESCRIPTOR", "Limit")?;

    if limit == 0 {
        return Ok(Vec::new());
    }

    // Read the entire SSDT table (array of i32)
    let table_bytes = reader.read_bytes(base, limit as usize * 4)?;

    let mut results = Vec::with_capacity(limit as usize);

    for i in 0..limit as usize {
        let offset = i * 4;
        let entry =
            i32::from_le_bytes(table_bytes[offset..offset + 4].try_into().expect("4 bytes"));

        // Decode: target = Base + (entry >> 4)
        let relative_offset = entry >> 4; // arithmetic shift preserves sign
                                          // SSDT offsets are signed (can point before table base), so these
                                          // casts through i64 are intentional and correct for kernel addresses.
        #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
        let target_addr = (base as i64).wrapping_add(i64::from(relative_offset)) as u64;

        // Find which module contains the target
        let target_module = known_modules.iter().find_map(|m| {
            if target_addr >= m.base_addr && target_addr < m.base_addr + m.size {
                Some(m.name.clone())
            } else {
                None
            }
        });

        let suspicious = target_module.is_none();

        results.push(WinSsdtHookInfo {
            index: i as u32,
            target_addr,
            target_module,
            suspicious,
        });
    }

    Ok(results)
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
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    // _KSERVICE_TABLE_DESCRIPTOR offsets
    const SSDT_BASE: u64 = 0x0;
    const SSDT_LIMIT: u64 = 0x10;

    /// Build a synthetic SSDT with the given i32 entries.
    /// Returns (ssdt_descriptor_paddr, ssdt_table_paddr, PageTableBuilder).
    fn build_ssdt(
        entries: &[i32],
        ssdt_vaddr: u64,
        ssdt_paddr: u64,
        table_vaddr: u64,
        table_paddr: u64,
    ) -> PageTableBuilder {
        let mut ssdt_page = vec![0u8; 4096];
        // _KSERVICE_TABLE_DESCRIPTOR.Base → table_vaddr
        ssdt_page[SSDT_BASE as usize..SSDT_BASE as usize + 8]
            .copy_from_slice(&table_vaddr.to_le_bytes());
        // _KSERVICE_TABLE_DESCRIPTOR.Limit → number of entries
        ssdt_page[SSDT_LIMIT as usize..SSDT_LIMIT as usize + 4]
            .copy_from_slice(&(entries.len() as u32).to_le_bytes());

        let mut table_page = vec![0u8; 4096];
        for (i, &entry) in entries.iter().enumerate() {
            let offset = i * 4;
            table_page[offset..offset + 4].copy_from_slice(&entry.to_le_bytes());
        }

        PageTableBuilder::new()
            .map_4k(ssdt_vaddr, ssdt_paddr, flags::WRITABLE)
            .map_4k(table_vaddr, table_paddr, flags::WRITABLE)
            .write_phys(ssdt_paddr, &ssdt_page)
            .write_phys(table_paddr, &table_page)
    }

    fn ntoskrnl_module(base: u64) -> WinDriverInfo {
        WinDriverInfo {
            name: "ntoskrnl.exe".into(),
            full_path: r"\SystemRoot\system32\ntoskrnl.exe".into(),
            base_addr: base,
            size: 0x80_0000,
            vaddr: 0,
        }
    }

    #[test]
    fn detects_ssdt_hook() {
        let ssdt_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let ssdt_paddr: u64 = 0x0080_0000;
        let table_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let table_paddr: u64 = 0x0080_1000;

        let ntoskrnl_base = table_vaddr;

        // Entry 0: offset +0x1000 into table base → inside ntoskrnl (clean)
        // Encoded: (0x1000 << 4) | 0 = 0x10000
        let clean_entry = (0x1000i32) << 4;
        // Entry 1: offset +0x90_0000 → beyond ntoskrnl size of 0x80_0000 (hooked!)
        // target = table_vaddr + 0x900000, which is outside [base, base+0x800000)
        let hooked_entry = (0x90_0000i32) << 4;

        let ptb = build_ssdt(
            &[clean_entry, hooked_entry],
            ssdt_vaddr,
            ssdt_paddr,
            table_vaddr,
            table_paddr,
        );

        let reader = make_win_reader(ptb);
        let modules = vec![ntoskrnl_module(ntoskrnl_base)];
        let results = check_ssdt_hooks(&reader, ssdt_vaddr, &modules).unwrap();

        assert_eq!(results.len(), 2);

        // Entry 0: clean
        assert!(!results[0].suspicious);
        assert_eq!(results[0].index, 0);
        assert_eq!(results[0].target_module.as_deref(), Some("ntoskrnl.exe"));

        // Entry 1: hooked
        assert!(results[1].suspicious);
        assert_eq!(results[1].index, 1);
        assert!(results[1].target_module.is_none());
    }

    #[test]
    fn clean_ssdt_no_hooks() {
        let ssdt_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let ssdt_paddr: u64 = 0x0080_0000;
        let table_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let table_paddr: u64 = 0x0080_1000;

        let ntoskrnl_base = table_vaddr;

        // All entries point within ntoskrnl
        let entry0 = (0x100i32) << 4;
        let entry1 = (0x200i32) << 4;
        let entry2 = (0x300i32) << 4;

        let ptb = build_ssdt(
            &[entry0, entry1, entry2],
            ssdt_vaddr,
            ssdt_paddr,
            table_vaddr,
            table_paddr,
        );

        let reader = make_win_reader(ptb);
        let modules = vec![ntoskrnl_module(ntoskrnl_base)];
        let results = check_ssdt_hooks(&reader, ssdt_vaddr, &modules).unwrap();

        assert_eq!(results.len(), 3);
        for r in &results {
            assert!(!r.suspicious);
            assert_eq!(r.target_module.as_deref(), Some("ntoskrnl.exe"));
        }
    }

    #[test]
    fn empty_ssdt() {
        let ssdt_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let ssdt_paddr: u64 = 0x0080_0000;
        let table_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let table_paddr: u64 = 0x0080_1000;

        // Zero entries
        let ptb = build_ssdt(&[], ssdt_vaddr, ssdt_paddr, table_vaddr, table_paddr);

        let reader = make_win_reader(ptb);
        let results = check_ssdt_hooks(&reader, ssdt_vaddr, &[]).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn negative_offset_entry() {
        // Negative offsets are valid (address before table base).
        let ssdt_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let ssdt_paddr: u64 = 0x0080_0000;
        let table_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let table_paddr: u64 = 0x0080_1000;

        // Module covers a range before the table
        let module_base = table_vaddr - 0x10_0000; // 1MB before table
        let module = WinDriverInfo {
            name: "ntoskrnl.exe".into(),
            full_path: r"\SystemRoot\system32\ntoskrnl.exe".into(),
            base_addr: module_base,
            size: 0x20_0000, // 2MB, covers table_vaddr
            vaddr: 0,
        };

        // Entry with negative offset: -0x1000 → table_vaddr - 0x1000 = inside module
        let entry = (-0x1000i32) << 4;

        let ptb = build_ssdt(&[entry], ssdt_vaddr, ssdt_paddr, table_vaddr, table_paddr);

        let reader = make_win_reader(ptb);
        let results = check_ssdt_hooks(&reader, ssdt_vaddr, &[module]).unwrap();

        assert_eq!(results.len(), 1);
        assert!(!results[0].suspicious);
    }
}
