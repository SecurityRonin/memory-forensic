//! COM object hijacking detection.
//!
//! Detects when a CLSID has a `HKCU\Software\Classes\CLSID\...\InprocServer32`
//! value that overrides the trusted `HKCR` path, a technique used by malware
//! to load arbitrary DLLs into COM clients without admin privileges.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::registry;
use crate::Result;

/// Maximum CLSID subkeys to enumerate (safety cap).
const MAX_CLSIDS: usize = 50_000;

// ── Output type ──────────────────────────────────────────────────────────

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

// ── Classification ───────────────────────────────────────────────────────

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

// ── Walker ───────────────────────────────────────────────────────────────

/// Walk the in-memory registry hives for COM hijacking candidates.
///
/// Enumerates all CLSIDs under `HKCU\Software\Classes\CLSID` (in the hive at
/// `hku_hive_addr`), reads each `InprocServer32` default value, looks up the
/// same CLSID in `HKCR\CLSID` (in the hive at `hkcr_hive_addr`), and compares
/// the DLL paths.
///
/// Either address may be `0` to skip that hive (graceful degradation).
pub fn walk_com_hijacking<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hku_hive_addr: u64,
    hkcr_hive_addr: u64,
) -> Result<Vec<ComHijackInfo>> {
    if hku_hive_addr == 0 {
        return Ok(Vec::new());
    }

    let clsid_va = walk_key_path(reader, hku_hive_addr, &["Software", "Classes", "CLSID"]);
    if clsid_va == 0 {
        return Ok(Vec::new());
    }

    let clsid_children = registry::list_subkeys(reader, hku_hive_addr, clsid_va);

    let hkcr_clsid_va = if hkcr_hive_addr != 0 {
        walk_key_path(reader, hkcr_hive_addr, &["CLSID"])
    } else {
        0
    };

    let mut results = Vec::new();

    for (guid_name, guid_va) in clsid_children.iter().take(MAX_CLSIDS) {
        let hkcu_inproc_va =
            registry::find_subkey_by_name(reader, hku_hive_addr, *guid_va, "InprocServer32");
        if hkcu_inproc_va == 0 {
            continue;
        }

        let hkcu_raw = registry::read_value_data(reader, hku_hive_addr, hkcu_inproc_va, "");
        let hkcu_server = decode_utf16le(&hkcu_raw);
        if hkcu_server.is_empty() {
            continue;
        }

        let hkcu_path = format!(r"HKCU\Software\Classes\CLSID\{guid_name}\InprocServer32");

        let (hkcr_server, hkcr_path) = if hkcr_clsid_va != 0 {
            let hkcr_guid_va =
                registry::find_subkey_by_name(reader, hkcr_hive_addr, hkcr_clsid_va, guid_name);
            if hkcr_guid_va != 0 {
                let hkcr_inproc_va = registry::find_subkey_by_name(
                    reader,
                    hkcr_hive_addr,
                    hkcr_guid_va,
                    "InprocServer32",
                );
                if hkcr_inproc_va != 0 {
                    let raw =
                        registry::read_value_data(reader, hkcr_hive_addr, hkcr_inproc_va, "");
                    let srv = decode_utf16le(&raw);
                    let path = format!(r"HKCR\CLSID\{guid_name}\InprocServer32");
                    (srv, path)
                } else {
                    (String::new(), String::new())
                }
            } else {
                (String::new(), String::new())
            }
        } else {
            (String::new(), String::new())
        };

        let is_suspicious = classify_com_hijack(&hkcr_server, &hkcu_server);
        if is_suspicious {
            results.push(ComHijackInfo {
                clsid: guid_name.clone(),
                hkcr_path,
                hkcu_path,
                hkcr_server,
                hkcu_server,
                is_suspicious,
            });
        }
    }

    Ok(results)
}

/// Walk a registry key path component by component from the hive root.
/// Returns the VA of the final key node, or `0` if any component is not found.
fn walk_key_path<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hhive_addr: u64,
    path: &[&str],
) -> u64 {
    let mut current = registry::resolve_root_cell(reader, hhive_addr);
    for &component in path {
        if current == 0 {
            return 0;
        }
        current = registry::find_subkey_by_name(reader, hhive_addr, current, component);
    }
    current
}

/// Decode a raw byte slice as a UTF-16LE string, stopping at the first null.
fn decode_utf16le(raw: &[u8]) -> String {
    if raw.len() < 2 {
        return String::new();
    }
    let words: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&w| w != 0)
        .collect();
    String::from_utf16_lossy(&words)
}
#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use crate::test_hive::CellHive;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ── Cell builder helpers (used by make_reader) ────────────────────────────



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

    /// Build an HKCU CellHive with `Software\Classes\CLSID\{clsid}\InprocServer32`
    /// pointing to `dll`.
    fn make_hkcu_hive(va: u64, clsid: &str, dll: &str) -> CellHive {
        let mut h = CellHive::new(va);
        h.nk(0x020, b"Root",            1, 0x080, 0);
        h.lf(0x080, &[0x0C0]);
        h.nk(0x0C0, b"Software",        1, 0x140, 0);
        h.lf(0x140, &[0x180]);
        h.nk(0x180, b"Classes",         1, 0x200, 0);
        h.lf(0x200, &[0x240]);
        h.nk(0x240, b"CLSID",           1, 0x2C0, 0);
        h.lf(0x2C0, &[0x300]);
        h.nk(0x300, clsid.as_bytes(),   1, 0x380, 0);
        h.lf(0x380, &[0x3C0]);
        h.nk(0x3C0, b"InprocServer32",  0, 0, 0);
        let data = utf16le(dll);
        h.values(0x3C0, 1, 0x440);
        h.value_list(0x440, &[0x480]);
        h.vk(0x480, b"", 1, data.len() as u32, 0x4C0);
        h.data(0x4C0, &data);
        h
    }

    /// Build an HKCR CellHive with `CLSID\{clsid}\InprocServer32` pointing to
    /// `dll`.  Pass `dll = ""` to omit InprocServer32 (the GUID key has no
    /// subkeys), simulating "no HKCR entry".
    fn make_hkcr_hive(va: u64, clsid: &str, dll: &str) -> CellHive {
        let mut h = CellHive::new(va);
        h.nk(0x020, b"Root",          1, 0x080, 0);
        h.lf(0x080, &[0x0C0]);
        h.nk(0x0C0, b"CLSID",         1, 0x140, 0);
        h.lf(0x140, &[0x180]);
        if dll.is_empty() {
            h.nk(0x180, clsid.as_bytes(), 0, 0, 0);
        } else {
            h.nk(0x180, clsid.as_bytes(), 1, 0x200, 0);
            h.lf(0x200, &[0x240]);
            h.nk(0x240, b"InprocServer32", 0, 0, 0);
            let data = utf16le(dll);
            h.values(0x240, 1, 0x2C0);
            h.value_list(0x2C0, &[0x300]);
            h.vk(0x300, b"", 1, data.len() as u32, 0x340);
            h.data(0x340, &data);
        }
        h
    }

    /// Zero hive addresses → empty Vec (graceful degradation).
    #[test]
    fn walk_com_hijacking_empty_when_no_hive() {
        let reader = make_reader(PageTableBuilder::new());
        let results = walk_com_hijacking(&reader, 0, 0).unwrap();
        assert!(
            results.is_empty(),
            "zero hive addresses should return empty"
        );
    }

    /// HKCU has a CLSID pointing to an evil DLL, HKCR has the same CLSID
    /// pointing to the legitimate shell32.dll → should detect one suspicious entry.
    #[test]
    fn walk_com_hijacking_detects_hkcu_override() {
        let clsid = "{11111111-1111-1111-1111-111111111111}";
        let hkcu_dll = r"C:\Users\evil\payload.dll";
        let hkcr_dll = r"C:\Windows\System32\shell32.dll";

        let hkcu = make_hkcu_hive(0x0070_0000, clsid, hkcu_dll);
        let hkcr = make_hkcr_hive(0x0080_0000, clsid, hkcr_dll);
        let r = two_hive_reader(&hkcu, &hkcr);

        let results = walk_com_hijacking(&r, hkcu.hhive_va, hkcr.hhive_va).unwrap();

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

    /// CLSID in HKCU but HKCR GUID has no InprocServer32 → still suspicious.
    #[test]
    fn walk_com_hijacking_no_hkcr_entry_is_suspicious() {
        let clsid = "{22222222-2222-2222-2222-222222222222}";
        let hkcu_dll = r"C:\Users\victim\AppData\Roaming\evil.dll";

        let hkcu = make_hkcu_hive(0x0070_0000, clsid, hkcu_dll);
        let hkcr = make_hkcr_hive(0x0080_0000, clsid, "");
        let r = two_hive_reader(&hkcu, &hkcr);

        let results = walk_com_hijacking(&r, hkcu.hhive_va, hkcr.hhive_va).unwrap();

        assert!(
            !results.is_empty(),
            "HKCU-only CLSID in %APPDATA% should produce at least one entry"
        );
        assert!(
            results.iter().any(|e| e.is_suspicious),
            "entry should be suspicious when hkcu_server is in %APPDATA%"
        );
    }

    /// HKCU and HKCR both have the same DLL path → benign.
    #[test]
    fn walk_com_hijacking_matching_paths_benign() {
        let clsid = "{33333333-3333-3333-3333-333333333333}";
        let dll = r"C:\Windows\System32\shell32.dll";

        let hkcu = make_hkcu_hive(0x0070_0000, clsid, dll);
        let hkcr = make_hkcr_hive(0x0080_0000, clsid, dll);
        let r = two_hive_reader(&hkcu, &hkcr);

        let results = walk_com_hijacking(&r, hkcu.hhive_va, hkcr.hhive_va).unwrap();

        assert!(
            results.is_empty() || results.iter().all(|e| !e.is_suspicious),
            "matching HKCU/HKCR paths should not produce suspicious entries"
        );
    }

    // ── CellHive (HMAP) tests ─────────────────────────────────────────────

    /// Reconstruct the per-cell cellmap ISF — mirrors `cellmap_isf()` in test_hive.rs.
    fn com_cellmap_isf() -> serde_json::Value {
        IsfBuilder::new()
            .add_struct("_HHIVE", 0x800)
            .add_field("_HHIVE", "BaseBlock", 0x10, "pointer")
            .add_field("_HHIVE", "Storage", 0xb8, "char")
            .add_struct("_DUAL", 0x278)
            .add_field("_DUAL", "Map", 0x18, "pointer")
            .add_struct("_HMAP_ENTRY", 0x20)
            .add_field("_HMAP_ENTRY", "PermanentBinAddress", 0x0, "pointer")
            .add_field("_HMAP_ENTRY", "BlockOffset", 0x8, "unsigned long")
            .build_json()
    }

    /// Encode `s` as UTF-16LE with a null terminator.
    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .flat_map(u16::to_le_bytes)
            .chain([0u8, 0u8])
            .collect()
    }

    /// Map all 5 HMAP pages of a CellHive into a `PageTableBuilder` at `pa_base`.
    fn add_hive_pages(ptb: PageTableBuilder, h: &CellHive, pa_base: u64) -> PageTableBuilder {
        let bb_va = h.hhive_va + 0x1000;
        let dir_va = h.hhive_va + 0x2000;
        let table_va = h.hhive_va + 0x3000;

        let mut hh = vec![0u8; 0x1000];
        hh[0x10..0x18].copy_from_slice(&bb_va.to_le_bytes());
        hh[0xb8 + 0x18..0xb8 + 0x18 + 8].copy_from_slice(&dir_va.to_le_bytes());

        let mut dir = vec![0u8; 0x1000];
        dir[0..8].copy_from_slice(&table_va.to_le_bytes());

        let mut table = vec![0u8; 0x1000];
        table[0..8].copy_from_slice(&h.bin_va.to_le_bytes());

        ptb.map_4k(h.hhive_va, pa_base, flags::WRITABLE)
            .write_phys(pa_base, &hh)
            .map_4k(bb_va, pa_base + 0x1000, flags::WRITABLE)
            .write_phys(pa_base + 0x1000, &vec![0u8; 0x1000])
            .map_4k(dir_va, pa_base + 0x2000, flags::WRITABLE)
            .write_phys(pa_base + 0x2000, &dir)
            .map_4k(table_va, pa_base + 0x3000, flags::WRITABLE)
            .write_phys(pa_base + 0x3000, &table)
            .map_4k(h.bin_va, pa_base + 0x4000, flags::WRITABLE)
            .write_phys(pa_base + 0x4000, &h.bin)
    }

    /// Build a single `ObjectReader` with HKCU (PA 0x30_0000) and HKCR
    /// (PA 0x31_0000) both visible in the same VAS.
    fn two_hive_reader(
        hkcu: &CellHive,
        hkcr: &CellHive,
    ) -> ObjectReader<SyntheticPhysMem> {
        let resolver = IsfResolver::from_value(&com_cellmap_isf()).unwrap();
        let ptb = add_hive_pages(PageTableBuilder::new(), hkcu, 0x30_0000);
        let ptb = add_hive_pages(ptb, hkcr, 0x31_0000);
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// HKCU has `Software\Classes\CLSID\{guid}\InprocServer32` pointing to an
    /// AppData path; HKCR has a different (legitimate) path. The flat walker
    /// cannot navigate the HMAP bin layout → returns empty → test fails RED.
    #[test]
    fn com_hijacking_detects_hkcu_override_via_hmap() {
        let guid = "{AB000001-0000-0000-0000-000000000001}";
        let hkcu_dll = r"C:\AppData\evil.dll";
        let hkcr_dll = r"C:\Windows\System32\real.dll";

        // ── HKCU: Software\Classes\CLSID\{guid}\InprocServer32 ──
        let mut hkcu = CellHive::new(0x0050_0000);
        hkcu.nk(0x020, b"Root",            1, 0x080, 0);
        hkcu.lf(0x080, &[0x0C0]);
        hkcu.nk(0x0C0, b"Software",        1, 0x140, 0);
        hkcu.lf(0x140, &[0x180]);
        hkcu.nk(0x180, b"Classes",         1, 0x200, 0);
        hkcu.lf(0x200, &[0x240]);
        hkcu.nk(0x240, b"CLSID",           1, 0x2C0, 0);
        hkcu.lf(0x2C0, &[0x300]);
        hkcu.nk(0x300, guid.as_bytes(),    1, 0x380, 0);
        hkcu.lf(0x380, &[0x3C0]);
        hkcu.nk(0x3C0, b"InprocServer32",  0, 0,     0);
        let hkcu_data = utf16le(hkcu_dll);
        hkcu.values(0x3C0, 1, 0x440);
        hkcu.value_list(0x440, &[0x480]);
        hkcu.vk(0x480, b"", 1, hkcu_data.len() as u32, 0x4C0);
        hkcu.data(0x4C0, &hkcu_data);

        // ── HKCR: CLSID\{guid}\InprocServer32 ──
        let mut hkcr = CellHive::new(0x0060_0000);
        hkcr.nk(0x020, b"Root",            1, 0x080, 0);
        hkcr.lf(0x080, &[0x0C0]);
        hkcr.nk(0x0C0, b"CLSID",           1, 0x140, 0);
        hkcr.lf(0x140, &[0x180]);
        hkcr.nk(0x180, guid.as_bytes(),    1, 0x200, 0);
        hkcr.lf(0x200, &[0x240]);
        hkcr.nk(0x240, b"InprocServer32",  0, 0,     0);
        let hkcr_data = utf16le(hkcr_dll);
        hkcr.values(0x240, 1, 0x2C0);
        hkcr.value_list(0x2C0, &[0x300]);
        hkcr.vk(0x300, b"", 1, hkcr_data.len() as u32, 0x340);
        hkcr.data(0x340, &hkcr_data);

        let r = two_hive_reader(&hkcu, &hkcr);
        let results = walk_com_hijacking(&r, hkcu.hhive_va, hkcr.hhive_va).unwrap();
        assert_eq!(results.len(), 1, "expected one hijack, got {}", results.len());
        assert_eq!(results[0].clsid, guid);
        assert!(results[0].is_suspicious);
    }
}
