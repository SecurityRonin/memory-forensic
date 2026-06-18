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

    // The loaded-module entry struct is `_LDR_DATA_TABLE_ENTRY` in real ntoskrnl
    // PDBs (the kernel uses _KLDR internally, but that's the exported symbol);
    // some synthetic/older ISFs name it `_KLDR_DATA_TABLE_ENTRY`. Use whichever
    // the resolver actually carries (both share these field offsets).
    let entry_struct = ["_LDR_DATA_TABLE_ENTRY", "_KLDR_DATA_TABLE_ENTRY"]
        .into_iter()
        .find(|s| reader.symbols().field_offset(s, "BaseDllName").is_some())
        .ok_or_else(|| Error::MissingField {
            struct_name: "_LDR_DATA_TABLE_ENTRY".into(),
            field_name: "BaseDllName".into(),
        })?;

    let name_off = reader
        .symbols()
        .field_offset(entry_struct, "BaseDllName")
        .ok_or_else(|| Error::MissingField {
            struct_name: entry_struct.into(),
            field_name: "BaseDllName".into(),
        })?;

    // Bidirectional (Flink + Blink): a torn-down node breaks the forward chain on
    // live-acquired dumps, orphaning every driver past it from a forward-only walk;
    // the Blink leg recovers them.
    let entries = reader.walk_list_bidirectional(
        head,
        "_LIST_ENTRY",
        "Flink",
        "Blink",
        entry_struct,
        "InLoadOrderLinks",
    )?;

    for entry in entries {
        // Tolerate paged-out entries: a driver whose name buffer is not resident
        // must not abort the search for one (e.g. tcpip.sys) that is.
        let Ok(modname) = read_unicode_string(reader, entry.wrapping_add(name_off)) else {
            continue;
        };
        if modname.eq_ignore_ascii_case(name) {
            let Ok(base) = reader.read_field::<u64>(entry, entry_struct, "DllBase") else {
                continue;
            };
            return Ok(Some(base));
        }
    }
    Ok(None)
}

/// Cap on bytes read from a module image when scanning for its CodeView record.
const MODULE_IMAGE_SCAN_CAP: usize = 4 * 1024 * 1024;

/// Read a loaded module's PE image (at its base VA) and extract its CodeView
/// RSDS PDB identification ([`PdbId`]) — the input to resolving that module's own
/// symbols (e.g. `tcpip.sys` for `netstat`).
///
/// `image_size` is the PE `SizeOfImage` (from the `_KLDR_DATA_TABLE_ENTRY`); the
/// read is capped at [`MODULE_IMAGE_SCAN_CAP`] and done page-by-page so a
/// partially paged-out image (unmapped pages → zero-filled) still yields the RSDS
/// when its page is resident.
pub fn module_pdb_id<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    base_va: u64,
    image_size: u32,
) -> Result<memf_symbols::pe_debug::PdbId> {
    let cap = (image_size as usize).clamp(0x1000, MODULE_IMAGE_SCAN_CAP);
    let mut image = vec![0u8; cap];
    let mut off = 0usize;
    while off < cap {
        let chunk = 0x1000.min(cap - off);
        if let Ok(page) = reader.read_bytes(base_va.wrapping_add(off as u64), chunk) {
            image[off..off + page.len()].copy_from_slice(&page);
        }
        off += chunk;
    }
    // Use the *tolerant* (RSDS-scanning) extractor: a memory-mapped image has its
    // sections at their RVAs (file-offset section mapping no longer applies), so
    // the RVA→file-offset parser cannot locate the CodeView record — scanning can.
    Ok(memf_symbols::pe_debug::extract_pdb_id_tolerant(&image)?)
}

/// Build a ready-to-use [`SymbolResolver`](memf_symbols::SymbolResolver) for a
/// loaded kernel module (e.g. `tcpip.sys`): locate it via `PsLoadedModuleList`,
/// extract its RSDS [`PdbId`], resolve the matching PDB
/// ([`AutoProfile`](memf_symbols::AutoProfile), download/cache), and rebase its
/// RVA symbols by the module's base.
///
/// Returns `Ok(None)` when the module is not loaded. The resulting resolver is
/// intended as a member of a `MultiModuleResolver` alongside the kernel one, so a
/// walker can resolve that module's own symbols (e.g. `TcpPortPool`).
pub fn module_resolver<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    name: &str,
) -> Result<Option<Box<dyn memf_symbols::SymbolResolver>>> {
    let Some(base) = find_loaded_module(reader, name)? else {
        return Ok(None);
    };
    // SizeOfImage is read tolerantly via the cap; a large cap covers any driver.
    let pdb_id = module_pdb_id(reader, base, MODULE_IMAGE_SCAN_CAP as u32)?;
    let auto = memf_symbols::AutoProfile::new()?;
    let inner = auto.from_pdb_id(&pdb_id)?;
    Ok(Some(Box::new(memf_symbols::RebasedResolver::new(
        inner, base,
    ))))
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

    /// Real ntoskrnl PDBs expose the loaded-module entry as `_LDR_DATA_TABLE_ENTRY`,
    /// NOT `_KLDR_DATA_TABLE_ENTRY` (validated on citadeldc01.mem — the kernel ISF
    /// carries only `_LDR_DATA_TABLE_ENTRY`). The walk must pick whichever the ISF
    /// actually defines. With the same field offsets, the byte layout built by
    /// `build_kldr_entry` is valid for either name.
    #[test]
    fn finds_module_when_isf_names_entry_ldr_not_kldr() {
        let head_va = 0xFFFF_F805_5A41_0000u64;
        let entries_va = 0xFFFF_F800_AAB0_0000u64;
        let entry_b_va = entries_va + 256;
        let tcpip_base = 0xFFFF_F800_C0DE_0000u64;

        let mut head_page = vec![0u8; 4096];
        let mut entries_page = vec![0u8; 4096];
        head_page[0..8].copy_from_slice(&entry_b_va.to_le_bytes());
        head_page[8..16].copy_from_slice(&entry_b_va.to_le_bytes());

        let name_b = utf16le("tcpip.sys");
        let str_b_off = 1100usize;
        entries_page[str_b_off..str_b_off + name_b.len()].copy_from_slice(&name_b);
        build_kldr_entry(
            &mut entries_page,
            256,
            head_va,
            head_va,
            tcpip_base,
            entries_va + str_b_off as u64,
            name_b.len() as u16,
        );

        // ISF defines `_LDR_DATA_TABLE_ENTRY` (real-kernel name) — NO `_KLDR`.
        let isf = IsfBuilder::new()
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer")
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            .add_struct("_LDR_DATA_TABLE_ENTRY", 256)
            .add_field(
                "_LDR_DATA_TABLE_ENTRY",
                "InLoadOrderLinks",
                0,
                "_LIST_ENTRY",
            )
            .add_field("_LDR_DATA_TABLE_ENTRY", "DllBase", 48, "pointer")
            .add_field(
                "_LDR_DATA_TABLE_ENTRY",
                "BaseDllName",
                88,
                "_UNICODE_STRING",
            )
            .add_symbol("PsLoadedModuleList", head_va)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(head_va, 0x10_0000, flags::WRITABLE)
            .map_4k(entries_va, 0x11_0000, flags::WRITABLE)
            .write_phys(0x10_0000, &head_page)
            .write_phys(0x11_0000, &entries_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let found = find_loaded_module(&reader, "tcpip.sys").expect("walk ok");
        assert_eq!(
            found,
            Some(tcpip_base),
            "must use _LDR_DATA_TABLE_ENTRY schema"
        );
    }

    /// Minimal PE32+/AMD64 image (one page) with a CodeView RSDS debug record.
    fn build_pe(guid: [u8; 16], age: u32, pdb_name: &str) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew
        let mut pos = 0x80usize;
        buf[pos..pos + 4].copy_from_slice(b"PE\0\0");
        pos += 4;
        buf[pos..pos + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine AMD64
        buf[pos + 2..pos + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
        let opt_size: u16 = 240;
        buf[pos + 16..pos + 18].copy_from_slice(&opt_size.to_le_bytes());
        buf[pos + 18..pos + 20].copy_from_slice(&0x0022u16.to_le_bytes());
        pos += 20;
        let opt = pos;
        buf[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
        buf[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // SizeOfImage
        buf[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
        buf[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        buf[opt + 160..opt + 164].copy_from_slice(&0x200u32.to_le_bytes()); // Debug dir RVA (idx 6)
        buf[opt + 164..opt + 168].copy_from_slice(&28u32.to_le_bytes()); // Debug dir size
                                                                         // IMAGE_DEBUG_DIRECTORY @ 0x200
        let dd = 0x200usize;
        let cv_rva: u32 = 0x220;
        let name = pdb_name.as_bytes();
        let cv_size = (24 + name.len() + 1) as u32;
        buf[dd + 12..dd + 16].copy_from_slice(&2u32.to_le_bytes()); // Type CODEVIEW
        buf[dd + 16..dd + 20].copy_from_slice(&cv_size.to_le_bytes());
        buf[dd + 20..dd + 24].copy_from_slice(&cv_rva.to_le_bytes()); // AddressOfRawData
        buf[dd + 24..dd + 28].copy_from_slice(&cv_rva.to_le_bytes()); // PointerToRawData (RVA 1:1)
                                                                      // RSDS @ 0x220
        let cv = 0x220usize;
        buf[cv..cv + 4].copy_from_slice(b"RSDS");
        buf[cv + 4..cv + 20].copy_from_slice(&guid);
        buf[cv + 20..cv + 24].copy_from_slice(&age.to_le_bytes());
        buf[cv + 24..cv + 24 + name.len()].copy_from_slice(name);
        buf
    }

    #[test]
    fn module_pdb_id_extracts_rsds_from_image() {
        // A tcpip.sys image mapped at its base VA; module_pdb_id reads it and
        // recovers the CodeView RSDS PDB id (the input to per-module symbols).
        let base_va = 0xFFFF_F800_C0DE_0000u64;
        let paddr = 0x12_0000u64;
        let guid = [
            0x4D, 0x22, 0x72, 0x1B, 0xB8, 0x37, 0x92, 0x17, 0x28, 0x20, 0x0E, 0xD8, 0x99, 0x44,
            0x98, 0xB2,
        ];
        let image = build_pe(guid, 1, "tcpip.pdb");

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(base_va, paddr, flags::WRITABLE)
            .write_phys(paddr, &image)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // image_size 0x1000 — one mapped page covering the RSDS at 0x220.
        let id = module_pdb_id(&reader, base_va, 0x1000).expect("extract pdb id");
        assert_eq!(id.pdb_name, "tcpip.pdb");
        assert_eq!(id.age, 1);
        assert!(id.guid.contains("1B72224D"), "guid decoded: {}", id.guid);
    }
}
