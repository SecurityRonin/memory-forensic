//! Walk the kernel loaded-module list (`PsLoadedModuleList`) to locate a driver
//! image by name and return its base virtual address.
//!
//! This is the bootstrap for **per-module symbol resolution**: once a driver's
//! base is known (e.g. `tcpip.sys` for `netstat`, `ci.dll`, etc.), its PE header
//! yields the CodeView RSDS PDB id, which resolves that module's own ISF — the
//! symbols the kernel ISF (`ntoskrnl`) does not contain.
//!
//! Unlike [`crate::dll::walk_dlls`] (user-mode `_PEB` → `_PEB_LDR_DATA`), this
//! walks the kernel's `PsLoadedModuleList` (a `_LIST_ENTRY` head over
//! `_KLDR_DATA_TABLE_ENTRY` records) and needs only kernel symbols.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;
use crate::{Error, Result};

/// Find a loaded kernel module (driver) by its `BaseDllName` (case-insensitive,
/// e.g. `"tcpip.sys"`) and return its `DllBase` virtual address.
///
/// Walks `PsLoadedModuleList`. Returns `Ok(None)` when no loaded module matches.
/// Errors only when `PsLoadedModuleList` / the `_KLDR_DATA_TABLE_ENTRY` schema is
/// unavailable, or memory cannot be read.
pub fn find_loaded_module<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    name: &str,
) -> Result<Option<u64>> {
    let head = reader
        .symbols()
        .symbol_address("PsLoadedModuleList")
        .ok_or_else(|| Error::Core(memf_core::Error::MissingSymbol("PsLoadedModuleList".into())))?;

    let name_off = reader
        .symbols()
        .field_offset("_KLDR_DATA_TABLE_ENTRY", "BaseDllName")
        .ok_or_else(|| Error::MissingField {
            struct_name: "_KLDR_DATA_TABLE_ENTRY".into(),
            field_name: "BaseDllName".into(),
        })?;

    let entries = reader.walk_list_with(
        head,
        "_LIST_ENTRY",
        "Flink",
        "_KLDR_DATA_TABLE_ENTRY",
        "InLoadOrderLinks",
    )?;

    for entry in entries {
        let modname = read_unicode_string(reader, entry.wrapping_add(name_off))?;
        if modname.eq_ignore_ascii_case(name) {
            let base: u64 = reader.read_field(entry, "_KLDR_DATA_TABLE_ENTRY", "DllBase")?;
            return Ok(Some(base));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// Lay out a `_KLDR_DATA_TABLE_ENTRY` at `page[off..]`:
    /// InLoadOrderLinks(Flink@0,Blink@8), DllBase@48, BaseDllName(_UNICODE_STRING@88).
    #[allow(clippy::too_many_arguments)]
    fn build_kldr_entry(
        page: &mut [u8],
        off: usize,
        flink: u64,
        blink: u64,
        dll_base: u64,
        name_ptr: u64,
        name_len: u16,
    ) {
        page[off..off + 8].copy_from_slice(&flink.to_le_bytes());
        page[off + 8..off + 16].copy_from_slice(&blink.to_le_bytes());
        page[off + 48..off + 56].copy_from_slice(&dll_base.to_le_bytes());
        // _UNICODE_STRING at +88: Length@0(u16), MaximumLength@2(u16), Buffer@8(u64).
        page[off + 88..off + 90].copy_from_slice(&name_len.to_le_bytes());
        page[off + 90..off + 92].copy_from_slice(&name_len.to_le_bytes());
        page[off + 96..off + 104].copy_from_slice(&name_ptr.to_le_bytes());
    }

    #[test]
    fn finds_tcpip_driver_base_from_psloadedmodulelist() {
        // PsLoadedModuleList (preset symbol VA) is the list head sentinel.
        // head -> ntoskrnl -> tcpip -> head. We must get tcpip's DllBase.
        let head_va = 0xFFFF_F805_5A41_0000u64; // == preset PsLoadedModuleList
        let entries_va = 0xFFFF_F800_AAB0_0000u64;
        let paddr_head = 0x10_0000u64;
        let paddr_entries = 0x11_0000u64;

        let entry_a_va = entries_va; // ntoskrnl, InLoadOrderLinks @ +0
        let entry_b_va = entries_va + 256; // tcpip
        let tcpip_base = 0xFFFF_F800_C0DE_0000u64; // the answer

        let mut head_page = vec![0u8; 4096];
        let mut entries_page = vec![0u8; 4096];

        // Head sentinel _LIST_ENTRY at head_va: Flink -> A, Blink -> B.
        head_page[0..8].copy_from_slice(&entry_a_va.to_le_bytes());
        head_page[8..16].copy_from_slice(&entry_b_va.to_le_bytes());

        // String buffers on the entries page.
        let name_a = utf16le("ntoskrnl.exe");
        let name_b = utf16le("tcpip.sys");
        let str_a_off = 1024usize;
        let str_b_off = 1100usize;
        entries_page[str_a_off..str_a_off + name_a.len()].copy_from_slice(&name_a);
        entries_page[str_b_off..str_b_off + name_b.len()].copy_from_slice(&name_b);

        build_kldr_entry(
            &mut entries_page,
            0, // entry A
            entry_b_va,
            head_va,
            0xFFFF_F805_5A20_0000, // ntoskrnl base
            entries_va + str_a_off as u64,
            name_a.len() as u16,
        );
        build_kldr_entry(
            &mut entries_page,
            256, // entry B
            head_va,
            entry_a_va,
            tcpip_base,
            entries_va + str_b_off as u64,
            name_b.len() as u16,
        );

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(head_va, paddr_head, flags::WRITABLE)
            .map_4k(entries_va, paddr_entries, flags::WRITABLE)
            .write_phys(paddr_head, &head_page)
            .write_phys(paddr_entries, &entries_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let found = find_loaded_module(&reader, "tcpip.sys").expect("walk ok");
        assert_eq!(found, Some(tcpip_base), "must locate tcpip.sys DllBase");

        let missing = find_loaded_module(&reader, "nope.sys").expect("walk ok");
        assert_eq!(missing, None, "absent module returns None");
    }
}
