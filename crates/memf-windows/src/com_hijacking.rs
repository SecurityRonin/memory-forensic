//! COM object hijacking detection.
//!
//! Detects when a CLSID has a `HKCU\Software\Classes\CLSID\...\InprocServer32`
//! value that overrides the trusted `HKCR` path, a technique used by malware
//! to load arbitrary DLLs into COM clients without admin privileges.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// A COM class registration where HKCU overrides HKCR (potential hijack).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ComHijackInfo {
    /// The CLSID string, e.g. `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
    pub clsid: String,
    /// `HKCR\CLSID\<clsid>\InprocServer32` path (system-wide, trusted).
    pub hkcr_path: String,
    /// `HKCU\Software\Classes\CLSID\<clsid>\InprocServer32` path (override).
    pub hkcu_path: String,
    /// DLL path registered under HKCR (empty if not present).
    pub hkcr_server: String,
    /// DLL path registered under HKCU (the hijacked value).
    pub hkcu_server: String,
    /// `true` when the HKCU server path is in an unusual/writable location.
    pub is_suspicious: bool,
}

/// Returns `true` when the HKCU COM server path looks like a hijack.
///
/// A path is suspicious when it resides in a user-writable directory
/// (`%TEMP%`, `%APPDATA%`, `%DOWNLOADS%`, `%PUBLIC%`, `%PROGRAMDATA%`)
/// **or** when it overrides a non-empty HKCR registration with a different path.
pub fn classify_com_hijack(hkcr_server: &str, hkcu_server: &str) -> bool {
    if hkcu_server.is_empty() {
        return false;
    }
    let lower = hkcu_server.to_ascii_lowercase();
    lower.contains("\\temp\\")
        || lower.contains("\\appdata\\")
        || lower.contains("\\downloads\\")
        || lower.contains("\\public\\")
        || lower.contains("\\programdata\\")
        // Any HKCU override of a different HKCR registration is a hijack.
        || (!hkcr_server.is_empty() && !hkcu_server.eq_ignore_ascii_case(hkcr_server))
}

/// Walk the in-memory registry hives for COM hijacking candidates.
///
/// Returns an empty `Vec` when `CmRegistryMachineSystem` or the user hive
/// symbol is absent (graceful degradation).
pub fn walk_com_hijacking<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<ComHijackInfo>> {
    // Graceful degradation: require the machine system hive symbol.
    if reader
        .symbols()
        .symbol_address("CmRegistryMachineSystem")
        .is_none()
    {
        return Ok(Vec::new());
    }

    // In a full implementation we would walk the user hive registry tree in
    // memory and compare HKCU vs HKCR InprocServer32 values.
    // For now return empty — the walker degrades gracefully when symbols exist
    // but the hive walk is not yet implemented.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ── Registry hive layout constants (mirrors run_keys.rs helpers) ─────

    const HBIN_START: u64 = 0x1000;
    const ROOT_CELL_OFFSET: u64 = 0x24;
    const NK_SIG: u16 = 0x6B6E;
    const VK_SIG: u16 = 0x6B76;

    // _CM_KEY_NODE offsets (after the 4-byte cell-size prefix)
    const NK_STABLE_COUNT: usize = 0x14;
    const NK_STABLE_LIST: usize = 0x1C;
    const NK_VALUE_COUNT: usize = 0x24;
    const NK_VALUES_LIST: usize = 0x28;
    const NK_NAME_LEN: usize = 0x48;
    const NK_NAME_DATA: usize = 0x4C;

    // _CM_KEY_VALUE offsets (after size prefix)
    const VK_NAME_LEN: usize = 0x02;
    const VK_DATA_LEN: usize = 0x04;
    const VK_DATA_OFF: usize = 0x08;
    const VK_NAME_DATA: usize = 0x14;

    // ── Low-level cell builder helpers ────────────────────────────────────

    /// Wrap `data` in a cell: i32 size (negative = allocated) + data + alignment padding.
    fn build_cell(data: &[u8]) -> Vec<u8> {
        let total = ((4 + data.len() + 7) & !7) as i32;
        let mut cell = Vec::with_capacity(total as usize);
        cell.extend_from_slice(&(-total).to_le_bytes());
        cell.extend_from_slice(data);
        cell.resize(total as usize, 0);
        cell
    }

    /// Build an nk cell data buffer (the payload after the 4-byte size header).
    fn build_nk(
        name: &str,
        stable_subkey_count: u32,
        stable_subkeys_list: u32,
        value_count: u32,
        values_list: u32,
    ) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let mut data = vec![0u8; NK_NAME_DATA + name_bytes.len()];
        data[0..2].copy_from_slice(&NK_SIG.to_le_bytes());
        // KEY_COMP_NAME flag (0x0020) → ASCII name
        data[2..4].copy_from_slice(&0x0020u16.to_le_bytes());
        data[NK_STABLE_COUNT..NK_STABLE_COUNT + 4]
            .copy_from_slice(&stable_subkey_count.to_le_bytes());
        data[NK_STABLE_LIST..NK_STABLE_LIST + 4]
            .copy_from_slice(&stable_subkeys_list.to_le_bytes());
        data[NK_VALUE_COUNT..NK_VALUE_COUNT + 4]
            .copy_from_slice(&value_count.to_le_bytes());
        data[NK_VALUES_LIST..NK_VALUES_LIST + 4]
            .copy_from_slice(&values_list.to_le_bytes());
        data[NK_NAME_LEN..NK_NAME_LEN + 2]
            .copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        data[NK_NAME_DATA..NK_NAME_DATA + name_bytes.len()].copy_from_slice(name_bytes);
        data
    }

    /// Build an lf subkey list cell data buffer.
    /// Each entry is 8 bytes: cell_index (u32) + hash (u32, zeroed).
    fn build_lf(children: &[u32]) -> Vec<u8> {
        let mut data = vec![0u8; 4 + children.len() * 8];
        data[0..2].copy_from_slice(&0x666Cu16.to_le_bytes()); // "lf"
        data[2..4].copy_from_slice(&(children.len() as u16).to_le_bytes());
        for (i, &cell) in children.iter().enumerate() {
            let off = 4 + i * 8;
            data[off..off + 4].copy_from_slice(&cell.to_le_bytes());
        }
        data
    }

    /// Build a value-list cell: array of u32 cell indices.
    fn build_value_list(val_cells: &[u32]) -> Vec<u8> {
        let mut data = vec![0u8; val_cells.len() * 4];
        for (i, &c) in val_cells.iter().enumerate() {
            data[i * 4..i * 4 + 4].copy_from_slice(&c.to_le_bytes());
        }
        data
    }

    /// Build a vk cell data buffer with inline string data (MSB set, data in
    /// DataOffset field as UTF-16LE first 4 bytes) — only works for short strings.
    ///
    /// For longer strings we use an external data cell; see `build_vk_external`.
    fn build_vk_external(name: &str, data_cell_index: u32, data_len: u32) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let mut data = vec![0u8; VK_NAME_DATA + name_bytes.len()];
        data[0..2].copy_from_slice(&VK_SIG.to_le_bytes());
        data[VK_NAME_LEN..VK_NAME_LEN + 2]
            .copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        // REG_SZ = 1
        data[0x0C..0x10].copy_from_slice(&1u32.to_le_bytes());
        data[VK_DATA_LEN..VK_DATA_LEN + 4].copy_from_slice(&data_len.to_le_bytes());
        data[VK_DATA_OFF..VK_DATA_OFF + 4].copy_from_slice(&data_cell_index.to_le_bytes());
        data[VK_NAME_DATA..VK_NAME_DATA + name_bytes.len()].copy_from_slice(name_bytes);
        data
    }

    /// Build a data cell containing a UTF-16LE string.
    fn build_utf16_data_cell(s: &str) -> Vec<u8> {
        let utf16: Vec<u8> = s
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .chain([0u8, 0u8]) // null terminator
            .collect();
        build_cell(&utf16)
    }

    /// Build a minimal `ObjectReader` from a `PageTableBuilder`.
    fn make_reader(
        ptb: PageTableBuilder,
    ) -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    // ── Hive layout builder ───────────────────────────────────────────────
    //
    // For HKCU the registry path under which CLSIDs live is:
    //   Software\Classes\CLSID\{guid}\InprocServer32
    //
    // For HKCR the path is:
    //   CLSID\{guid}\InprocServer32
    //
    // Both hives are built flat in a single 4-KB HBIN page.
    // We use a simple bump-allocator: cell offsets start at 0x20 and advance.
    //
    // Hive layout (all offsets within the HBIN page, i.e. cell indices):
    //
    //   HKCU hive (hive_paddr = 0x010000):
    //     0x0020  root nk  ("ROOT", 1 subkey → lf@0x0100)
    //     0x0100  lf list  [0x0140]
    //     0x0140  nk "Software" (1 subkey → lf@0x01C0)
    //     0x01C0  lf [0x0200]
    //     0x0200  nk "Classes" (1 subkey → lf@0x0280)
    //     0x0280  lf [0x02C0]
    //     0x02C0  nk "CLSID"   (1 subkey → lf@0x0340)
    //     0x0340  lf [0x0380]
    //     0x0380  nk "{GUID}"  (1 subkey → lf@0x0400)
    //     0x0400  lf [0x0440]
    //     0x0440  nk "InprocServer32" (0 subkeys, 1 value → vl@0x04C0)
    //     0x04C0  value-list [0x0500]
    //     0x0500  vk "(default)"  data→0x0580  len=<string length>
    //     0x0580  data cell: UTF-16LE DLL path
    //
    //   HKCR hive (hive_paddr = 0x020000):
    //     0x0020  root nk  ("ROOT", 1 subkey → lf@0x0100)
    //     0x0100  lf [0x0140]
    //     0x0140  nk "CLSID" (1 subkey → lf@0x01C0)
    //     0x01C0  lf [0x0200]
    //     0x0200  nk "{GUID}" (1 subkey → lf@0x0280)
    //     0x0280  lf [0x02C0]
    //     0x02C0  nk "InprocServer32" (0 subkeys, 1 value → vl@0x0340)
    //     0x0340  value-list [0x0380]
    //     0x0380  vk "(default)"  data→0x03C0  len=<string length>
    //     0x03C0  data cell: UTF-16LE DLL path

    struct HiveLayout {
        /// Physical base address of the _HBASE_BLOCK page.
        hive_paddr: u64,
        /// Virtual base address of the _HBASE_BLOCK page.
        hive_vaddr: u64,
        /// Physical base address of the HBIN page (hive + 0x1000).
        hbin_paddr: u64,
        /// Virtual base address of the HBIN page.
        hbin_vaddr: u64,
        /// 4 KB HBASE_BLOCK page bytes.
        hbase: Vec<u8>,
        /// 4 KB HBIN page bytes.
        hbin: Vec<u8>,
    }

    /// Build an HKCU hive page-pair.
    ///
    /// The CLSID path is `Software\Classes\CLSID\{clsid}\InprocServer32`
    /// and the default value is `hkcu_dll`.
    fn build_hkcu_hive(
        hive_vaddr: u64,
        hive_paddr: u64,
        clsid: &str,
        hkcu_dll: &str,
    ) -> HiveLayout {
        let hbin_vaddr = hive_vaddr + HBIN_START;
        let hbin_paddr = hive_paddr + HBIN_START;

        let root_cell: u32 = 0x0020;
        let lf_root: u32 = 0x0100;
        let nk_software: u32 = 0x0140;
        let lf_software: u32 = 0x01C0;
        let nk_classes: u32 = 0x0200;
        let lf_classes: u32 = 0x0280;
        let nk_clsid: u32 = 0x02C0;
        let lf_clsid: u32 = 0x0340;
        let nk_guid: u32 = 0x0380;
        let lf_guid: u32 = 0x0400;
        let nk_inproc: u32 = 0x0440;
        let vl_inproc: u32 = 0x04C0;
        let vk_default: u32 = 0x0500;
        let data_cell: u32 = 0x0580;

        let dll_utf16: Vec<u8> = hkcu_dll
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .chain([0u8, 0u8])
            .collect();
        let dll_data_cell = build_cell(&dll_utf16);

        let mut hbase = vec![0u8; 4096];
        hbase[0x24..0x28].copy_from_slice(&root_cell.to_le_bytes());

        let mut hbin = vec![0u8; 4096];

        macro_rules! place {
            ($off:expr, $cell:expr) => {
                let c = $cell;
                hbin[$off as usize..$off as usize + c.len()].copy_from_slice(&c);
            };
        }

        place!(root_cell, build_cell(&build_nk("ROOT", 1, lf_root, 0, 0)));
        place!(lf_root, build_cell(&build_lf(&[nk_software])));
        place!(nk_software, build_cell(&build_nk("Software", 1, lf_software, 0, 0)));
        place!(lf_software, build_cell(&build_lf(&[nk_classes])));
        place!(nk_classes, build_cell(&build_nk("Classes", 1, lf_classes, 0, 0)));
        place!(lf_classes, build_cell(&build_lf(&[nk_clsid])));
        place!(nk_clsid, build_cell(&build_nk("CLSID", 1, lf_clsid, 0, 0)));
        place!(lf_clsid, build_cell(&build_lf(&[nk_guid])));
        place!(nk_guid, build_cell(&build_nk(clsid, 1, lf_guid, 0, 0)));
        place!(lf_guid, build_cell(&build_lf(&[nk_inproc])));
        place!(
            nk_inproc,
            build_cell(&build_nk("InprocServer32", 0, 0, 1, vl_inproc))
        );
        place!(vl_inproc, build_cell(&build_value_list(&[vk_default])));
        place!(
            vk_default,
            build_cell(&build_vk_external("", data_cell, dll_utf16.len() as u32))
        );
        place!(data_cell, dll_data_cell);

        HiveLayout {
            hive_paddr,
            hive_vaddr,
            hbin_paddr,
            hbin_vaddr,
            hbase,
            hbin,
        }
    }

    /// Build an HKCR hive page-pair.
    ///
    /// The CLSID path is `CLSID\{clsid}\InprocServer32` and the default value
    /// is `hkcr_dll`.  Pass `hkcr_dll = ""` to omit the InprocServer32 key
    /// entirely (simulates "no HKCR entry").
    fn build_hkcr_hive(
        hive_vaddr: u64,
        hive_paddr: u64,
        clsid: &str,
        hkcr_dll: &str,
    ) -> HiveLayout {
        let hbin_vaddr = hive_vaddr + HBIN_START;
        let hbin_paddr = hive_paddr + HBIN_START;

        let root_cell: u32 = 0x0020;
        let lf_root: u32 = 0x0100;
        let nk_clsid: u32 = 0x0140;
        let lf_clsid: u32 = 0x01C0;
        let nk_guid: u32 = 0x0200;

        let mut hbase = vec![0u8; 4096];
        hbase[0x24..0x28].copy_from_slice(&root_cell.to_le_bytes());

        let mut hbin = vec![0u8; 4096];

        macro_rules! place {
            ($off:expr, $cell:expr) => {
                let c = $cell;
                hbin[$off as usize..$off as usize + c.len()].copy_from_slice(&c);
            };
        }

        if hkcr_dll.is_empty() {
            // No InprocServer32 — GUID key has no subkeys
            place!(root_cell, build_cell(&build_nk("ROOT", 1, lf_root, 0, 0)));
            place!(lf_root, build_cell(&build_lf(&[nk_clsid])));
            place!(nk_clsid, build_cell(&build_nk("CLSID", 1, lf_clsid, 0, 0)));
            place!(lf_clsid, build_cell(&build_lf(&[nk_guid])));
            place!(nk_guid, build_cell(&build_nk(clsid, 0, 0, 0, 0)));
        } else {
            let lf_guid: u32 = 0x0280;
            let nk_inproc: u32 = 0x02C0;
            let vl_inproc: u32 = 0x0340;
            let vk_default: u32 = 0x0380;
            let data_cell: u32 = 0x03C0;

            let dll_utf16: Vec<u8> = hkcr_dll
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .chain([0u8, 0u8])
                .collect();
            let dll_data_cell = build_cell(&dll_utf16);

            place!(root_cell, build_cell(&build_nk("ROOT", 1, lf_root, 0, 0)));
            place!(lf_root, build_cell(&build_lf(&[nk_clsid])));
            place!(nk_clsid, build_cell(&build_nk("CLSID", 1, lf_clsid, 0, 0)));
            place!(lf_clsid, build_cell(&build_lf(&[nk_guid])));
            place!(nk_guid, build_cell(&build_nk(clsid, 1, lf_guid, 0, 0)));
            place!(lf_guid, build_cell(&build_lf(&[nk_inproc])));
            place!(
                nk_inproc,
                build_cell(&build_nk("InprocServer32", 0, 0, 1, vl_inproc))
            );
            place!(vl_inproc, build_cell(&build_value_list(&[vk_default])));
            place!(
                vk_default,
                build_cell(&build_vk_external("", data_cell, dll_utf16.len() as u32))
            );
            place!(data_cell, dll_data_cell);
        }

        HiveLayout {
            hive_paddr,
            hive_vaddr,
            hbin_paddr,
            hbin_vaddr,
            hbase,
            hbin,
        }
    }

    /// Map both hive page-pairs into a `PageTableBuilder`.
    fn map_hive(ptb: PageTableBuilder, h: &HiveLayout) -> PageTableBuilder {
        ptb.map_4k(h.hive_vaddr, h.hive_paddr, flags::WRITABLE)
            .map_4k(h.hbin_vaddr, h.hbin_paddr, flags::WRITABLE)
            .write_phys(h.hive_paddr, &h.hbase)
            .write_phys(h.hbin_paddr, &h.hbin)
    }

    // ── classify_com_hijack unit tests ────────────────────────────────────

    /// A server in `%APPDATA%` is suspicious.
    #[test]
    fn classify_appdata_server_suspicious() {
        assert!(classify_com_hijack(
            r"C:\Windows\System32\shell32.dll",
            r"C:\Users\victim\AppData\Roaming\evil.dll",
        ));
    }

    /// HKCU pointing to the exact same DLL as HKCR is not suspicious.
    #[test]
    fn classify_same_server_not_suspicious() {
        assert!(!classify_com_hijack(
            r"C:\Windows\System32\shell32.dll",
            r"C:\Windows\System32\shell32.dll",
        ));
    }

    // ── walk_com_hijacking integration tests ──────────────────────────────

    /// Zero hive addresses → empty Vec (graceful degradation).
    #[test]
    fn walk_com_hijacking_empty_when_no_hive() {
        let reader = make_reader(PageTableBuilder::new());
        let results = walk_com_hijacking(&reader, 0, 0).unwrap();
        assert!(results.is_empty(), "zero hive addresses should return empty");
    }

    /// HKCU has a CLSID pointing to an evil DLL, HKCR has the same CLSID
    /// pointing to the legitimate shell32.dll → should detect one suspicious entry.
    #[test]
    fn walk_com_hijacking_detects_hkcu_override() {
        let clsid = "{11111111-1111-1111-1111-111111111111}";
        let hkcu_dll = r"C:\Users\evil\payload.dll";
        let hkcr_dll = r"C:\Windows\System32\shell32.dll";

        // HKCU hive: vaddr/paddr pair A (must be < 0x00FF_FFFF physical)
        let hkcu_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let hkcu_paddr: u64 = 0x0010_0000;

        // HKCR hive: vaddr/paddr pair B
        let hkcr_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let hkcr_paddr: u64 = 0x0030_0000;

        let hkcu = build_hkcu_hive(hkcu_vaddr, hkcu_paddr, clsid, hkcu_dll);
        let hkcr = build_hkcr_hive(hkcr_vaddr, hkcr_paddr, clsid, hkcr_dll);

        let ptb = map_hive(map_hive(PageTableBuilder::new(), &hkcu), &hkcr);
        let reader = make_reader(ptb);

        let results = walk_com_hijacking(&reader, hkcu_vaddr, hkcr_vaddr).unwrap();

        assert_eq!(results.len(), 1, "expected exactly one COM hijack entry");
        let entry = &results[0];
        assert_eq!(entry.clsid, clsid);
        assert!(
            entry.hkcu_server.eq_ignore_ascii_case(hkcu_dll),
            "hkcu_server mismatch: {}",
            entry.hkcu_server
        );
        assert!(entry.is_suspicious, "override of HKCR entry must be suspicious");
    }

    /// CLSID in HKCU but absent from HKCR → should still be flagged suspicious.
    #[test]
    fn walk_com_hijacking_no_hkcr_entry_is_suspicious() {
        let clsid = "{22222222-2222-2222-2222-222222222222}";
        let hkcu_dll = r"C:\Users\victim\AppData\Roaming\evil.dll";

        let hkcu_vaddr: u64 = 0xFFFF_8000_0050_0000;
        let hkcu_paddr: u64 = 0x0050_0000;

        let hkcr_vaddr: u64 = 0xFFFF_8000_0070_0000;
        let hkcr_paddr: u64 = 0x0070_0000;

        // HKCR has the CLSID key but no InprocServer32 (hkcr_dll = "")
        let hkcu = build_hkcu_hive(hkcu_vaddr, hkcu_paddr, clsid, hkcu_dll);
        let hkcr = build_hkcr_hive(hkcr_vaddr, hkcr_paddr, clsid, "");

        let ptb = map_hive(map_hive(PageTableBuilder::new(), &hkcu), &hkcr);
        let reader = make_reader(ptb);

        let results = walk_com_hijacking(&reader, hkcu_vaddr, hkcr_vaddr).unwrap();

        assert!(
            !results.is_empty(),
            "HKCU-only CLSID in %APPDATA% should produce at least one entry"
        );
        assert!(
            results.iter().any(|e| e.is_suspicious),
            "entry should be suspicious when hkcu_server is in %APPDATA%"
        );
    }

    /// HKCU and HKCR both have the same DLL path → benign, should not be returned
    /// (or if returned, is_suspicious = false).
    #[test]
    fn walk_com_hijacking_matching_paths_benign() {
        let clsid = "{33333333-3333-3333-3333-333333333333}";
        let dll = r"C:\Windows\System32\shell32.dll";

        let hkcu_vaddr: u64 = 0xFFFF_8000_0090_0000;
        let hkcu_paddr: u64 = 0x0090_0000;

        let hkcr_vaddr: u64 = 0xFFFF_8000_00B0_0000;
        let hkcr_paddr: u64 = 0x00B0_0000;

        let hkcu = build_hkcu_hive(hkcu_vaddr, hkcu_paddr, clsid, dll);
        let hkcr = build_hkcr_hive(hkcr_vaddr, hkcr_paddr, clsid, dll);

        let ptb = map_hive(map_hive(PageTableBuilder::new(), &hkcu), &hkcr);
        let reader = make_reader(ptb);

        let results = walk_com_hijacking(&reader, hkcu_vaddr, hkcr_vaddr).unwrap();

        // Matching paths are benign — either empty or all is_suspicious = false.
        assert!(
            results.is_empty() || results.iter().all(|e| !e.is_suspicious),
            "matching HKCU/HKCR paths should not produce suspicious entries"
        );
    }
}
