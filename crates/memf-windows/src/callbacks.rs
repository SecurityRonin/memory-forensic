//! Windows kernel callback enumeration.
//!
//! Reads `PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`,
//! and `PspLoadImageNotifyRoutine` arrays. Each array holds up to 64
//! `_EX_CALLBACK_ROUTINE_BLOCK` pointers (with the low 4 bits used as
//! reference count via `_EX_FAST_REF`). The actual callback function
//! address is obtained by masking off the low nibble.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, WinCallbackInfo, WinDriverInfo};

/// Maximum number of callback slots per array.
const MAX_CALLBACK_SLOTS: usize = 64;

/// Walk all three kernel callback arrays and return registered callbacks.
///
/// For each non-null entry in the three arrays, decodes the
/// `_EX_FAST_REF` pointer (mask off low 4 bits) and resolves the
/// owning module.
pub fn walk_kernel_callbacks<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    process_notify_vaddr: u64,
    thread_notify_vaddr: u64,
    load_image_notify_vaddr: u64,
    known_modules: &[WinDriverInfo],
) -> Result<Vec<WinCallbackInfo>> {
    let mut results = Vec::new();

    read_callback_array(reader, process_notify_vaddr, "CreateProcess", known_modules, &mut results)?;
    read_callback_array(reader, thread_notify_vaddr, "CreateThread", known_modules, &mut results)?;
    read_callback_array(reader, load_image_notify_vaddr, "LoadImage", known_modules, &mut results)?;

    Ok(results)
}

/// Read a single callback array of up to `MAX_CALLBACK_SLOTS` entries.
fn read_callback_array<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    array_vaddr: u64,
    callback_type: &str,
    known_modules: &[WinDriverInfo],
    results: &mut Vec<WinCallbackInfo>,
) -> Result<()> {
    let raw = reader.read_bytes(array_vaddr, MAX_CALLBACK_SLOTS * 8)?;

    for i in 0..MAX_CALLBACK_SLOTS {
        let offset = i * 8;
        let entry = u64::from_le_bytes(raw[offset..offset + 8].try_into().expect("8 bytes"));

        if entry == 0 {
            // PspCreateProcessNotifyRoutine is a sparse array — null slots can
            // appear between valid entries, so continue scanning all 64 slots.
            continue;
        }

        let address = entry & !0xF;

        let owning_module = known_modules.iter().find_map(|m| {
            if address >= m.base_addr && address < m.base_addr + m.size {
                Some(m.name.clone())
            } else {
                None
            }
        });

        results.push(WinCallbackInfo {
            callback_type: callback_type.to_string(),
            index: i as u32,
            address,
            owning_module,
        });
    }

    Ok(())
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

    fn ntoskrnl_module(base: u64) -> WinDriverInfo {
        WinDriverInfo {
            name: "ntoskrnl.exe".into(),
            full_path: r"\SystemRoot\system32\ntoskrnl.exe".into(),
            base_addr: base,
            size: 0x80_0000,
            vaddr: 0,
        }
    }

    fn third_party_module(name: &str, base: u64, size: u64) -> WinDriverInfo {
        WinDriverInfo {
            name: name.into(),
            full_path: format!(r"\SystemRoot\system32\drivers\{name}"),
            base_addr: base,
            size,
            vaddr: 0,
        }
    }

    /// Build 3 callback arrays on a single 4K page.
    /// Returns the base vaddrs for each array within the page.
    fn build_callback_page(
        process_entries: &[u64],
        thread_entries: &[u64],
        image_entries: &[u64],
        page_vaddr: u64,
        page_paddr: u64,
    ) -> (PageTableBuilder, u64, u64, u64) {
        let mut page = vec![0u8; 4096];

        let process_off = 0usize;
        for (i, &entry) in process_entries.iter().enumerate() {
            let off = process_off + i * 8;
            page[off..off + 8].copy_from_slice(&entry.to_le_bytes());
        }

        let thread_off = 0x200usize;
        for (i, &entry) in thread_entries.iter().enumerate() {
            let off = thread_off + i * 8;
            page[off..off + 8].copy_from_slice(&entry.to_le_bytes());
        }

        let image_off = 0x400usize;
        for (i, &entry) in image_entries.iter().enumerate() {
            let off = image_off + i * 8;
            page[off..off + 8].copy_from_slice(&entry.to_le_bytes());
        }

        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &page);

        (
            ptb,
            page_vaddr + process_off as u64,
            page_vaddr + thread_off as u64,
            page_vaddr + image_off as u64,
        )
    }

    #[test]
    fn enumerates_callbacks_from_all_three_arrays() {
        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;

        let ntoskrnl_base: u64 = 0xFFFFF800_00000000;
        let av_driver_base: u64 = 0xFFFFF800_01000000;

        let proc_cb1 = (ntoskrnl_base + 0x1000) | 0x7;
        let proc_cb2 = (av_driver_base + 0x500) | 0x3;
        let thread_cb1 = (ntoskrnl_base + 0x2000) | 0x1;

        let (ptb, proc_vaddr, thread_vaddr, image_vaddr) = build_callback_page(
            &[proc_cb1, proc_cb2],
            &[thread_cb1],
            &[],
            page_vaddr,
            page_paddr,
        );

        let reader = make_win_reader(ptb);
        let modules = vec![
            ntoskrnl_module(ntoskrnl_base),
            third_party_module("avkrnl.sys", av_driver_base, 0x10_0000),
        ];

        let results =
            walk_kernel_callbacks(&reader, proc_vaddr, thread_vaddr, image_vaddr, &modules)
                .unwrap();

        assert_eq!(results.len(), 3);

        let proc_cbs: Vec<_> = results.iter().filter(|c| c.callback_type == "CreateProcess").collect();
        assert_eq!(proc_cbs.len(), 2);
        assert_eq!(proc_cbs[0].address, ntoskrnl_base + 0x1000);
        assert_eq!(proc_cbs[0].owning_module.as_deref(), Some("ntoskrnl.exe"));
        assert_eq!(proc_cbs[1].address, av_driver_base + 0x500);
        assert_eq!(proc_cbs[1].owning_module.as_deref(), Some("avkrnl.sys"));

        let thread_cbs: Vec<_> = results.iter().filter(|c| c.callback_type == "CreateThread").collect();
        assert_eq!(thread_cbs.len(), 1);
        assert_eq!(thread_cbs[0].address, ntoskrnl_base + 0x2000);
    }

    #[test]
    fn skips_null_entries_in_callback_arrays() {
        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;

        let ntoskrnl_base: u64 = 0xFFFFF800_00000000;
        let proc_cb1 = (ntoskrnl_base + 0x1000) | 0x5;

        let (ptb, proc_vaddr, thread_vaddr, image_vaddr) =
            build_callback_page(&[proc_cb1, 0], &[0], &[0], page_vaddr, page_paddr);

        let reader = make_win_reader(ptb);
        let modules = vec![ntoskrnl_module(ntoskrnl_base)];

        let results =
            walk_kernel_callbacks(&reader, proc_vaddr, thread_vaddr, image_vaddr, &modules)
                .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].callback_type, "CreateProcess");
    }

    #[test]
    fn identifies_unknown_module_callbacks() {
        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;

        let ntoskrnl_base: u64 = 0xFFFFF800_00000000;
        let rogue_addr: u64 = 0xFFFF_C900_DEAD_0000;
        let rogue_entry = rogue_addr | 0x1;

        let (ptb, proc_vaddr, thread_vaddr, image_vaddr) =
            build_callback_page(&[rogue_entry], &[], &[], page_vaddr, page_paddr);

        let reader = make_win_reader(ptb);
        let modules = vec![ntoskrnl_module(ntoskrnl_base)];

        let results =
            walk_kernel_callbacks(&reader, proc_vaddr, thread_vaddr, image_vaddr, &modules)
                .unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].owning_module.is_none());
        assert_eq!(results[0].address, rogue_addr);
    }

    #[test]
    fn all_arrays_empty() {
        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;

        let (ptb, proc_vaddr, thread_vaddr, image_vaddr) =
            build_callback_page(&[], &[], &[], page_vaddr, page_paddr);

        let reader = make_win_reader(ptb);

        let results =
            walk_kernel_callbacks(&reader, proc_vaddr, thread_vaddr, image_vaddr, &[]).unwrap();

        assert!(results.is_empty());
    }
}
