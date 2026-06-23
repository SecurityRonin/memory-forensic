//! Amcache evidence-of-execution walker.
//!
//! The Windows Amcache.hve registry hive stores program execution evidence
//! including file paths, SHA1 hashes, timestamps, publisher info, and
//! product names. In memory forensics, the Amcache data lives inside the
//! registry CM structures. This walker reads from the in-memory registry
//! hive structures pointed to by the `_CMHIVE` at the given address.
//!
//! The Amcache hive's `Root\InventoryApplicationFile` key contains child
//! keys, one per tracked executable. Each child key has value cells for:
//! - `LowerCaseLongPath` — full file path
//! - `FileId` — SHA1 hash (prefixed with `0000`)
//! - `Size` — file size in bytes
//! - `LinkDate` — link/compile timestamp
//! - `Publisher` — code-signing publisher
//! - `ProductName` — application product name
//!
//! The `classify_amcache_entry` heuristic flags entries with no publisher,
//! temp/download paths, or other suspicious indicators that may warrant
//! further investigation.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::registry;

/// Maximum number of Amcache entries to enumerate (safety limit).
const MAX_AMCACHE_ENTRIES: usize = 8192;
const _: () = assert!(MAX_AMCACHE_ENTRIES > 0 && MAX_AMCACHE_ENTRIES <= 100_000);

/// Maximum depth when navigating to `Root\InventoryApplicationFile`.
#[allow(dead_code)]
const MAX_NAV_DEPTH: usize = 8;

/// A single Amcache program execution evidence entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AmcacheEntry {
    /// Full file path of the executable.
    pub file_path: String,
    /// SHA1 hash of the file (from the `FileId` value, stripped of `0000` prefix).
    pub sha1_hash: String,
    /// File size in bytes.
    pub file_size: u64,
    /// Link/compile timestamp as a Windows FILETIME (100-ns intervals since 1601-01-01).
    pub link_timestamp: u64,
    /// Code-signing publisher name.
    pub publisher: String,
    /// Application product name.
    pub product_name: String,
    /// Whether this entry looks suspicious based on heuristics.
    pub is_suspicious: bool,
}

/// Classify an Amcache entry as suspicious based on path and publisher heuristics.
///
/// Returns `true` if any of the following conditions are met:
/// - The publisher is empty (unsigned/unknown binary)
/// - The file path contains temp directories (`\Temp\`, `\AppData\`, `\Downloads\`)
/// - The file path is in a user-writable location with no known publisher
///
/// Well-known publishers (e.g., "Microsoft") in standard system paths are
/// considered benign.
pub fn classify_amcache_entry(path: &str, publisher: &str) -> bool {
    // An empty publisher is always suspicious — unsigned or unknown binary.
    if publisher.is_empty() {
        return true;
    }

    // Case-insensitive path check for suspicious locations.
    let path_lower = path.to_ascii_lowercase();

    // Known suspicious directories where untrusted executables often land.
    let suspicious_dirs = [
        r"\temp\",
        r"\appdata\",
        r"\downloads\",
        r"\users\public\",
        r"\programdata\",
        r"\recycle",
    ];

    // Even with a publisher, binaries in temp/download paths are worth flagging
    // if the publisher is not a well-known trusted name.
    let well_known_publishers = [
        "microsoft",
        "mozilla",
        "google",
        "apple",
        "adobe",
        "oracle",
        "vmware",
        "citrix",
        "intel",
    ];

    let publisher_lower = publisher.to_ascii_lowercase();
    let is_trusted_publisher = well_known_publishers
        .iter()
        .any(|known| publisher_lower.contains(known));

    // If the path is in a suspicious directory AND the publisher is not
    // a well-known trusted name, flag it.
    if !is_trusted_publisher && suspicious_dirs.iter().any(|dir| path_lower.contains(dir)) {
        return true;
    }

    false
}

// ── Value decoding helpers ───────────────────────────────────────────────

/// Decode a raw registry value buffer as a UTF-16LE string, stopping at the
/// first NUL (Amcache stores `LowerCaseLongPath`/`FileId`/`Publisher` as REG_SZ).
fn decode_utf16le(raw: &[u8]) -> String {
    let words: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&w| w != 0)
        .collect();
    String::from_utf16_lossy(&words)
}

/// Decode a raw registry value buffer as a `u64`: 8+ bytes → QWORD, 4+ → DWORD
/// (widened), else 0. Amcache `Size` is REG_QWORD and `LinkDate` is REG_DWORD;
/// the length alone disambiguates without needing the value type.
fn decode_u64(raw: &[u8]) -> u64 {
    if raw.len() >= 8 {
        u64::from_le_bytes(raw[..8].try_into().unwrap_or([0; 8]))
    } else if raw.len() >= 4 {
        u64::from(u32::from_le_bytes(raw[..4].try_into().unwrap_or([0; 4])))
    } else {
        0
    }
}

/// Walk the Amcache registry hive from kernel memory.
///
/// `amcache_hive_addr` is the `_CMHIVE`/`_HHIVE` virtual address. Navigates
/// `Root\InventoryApplicationFile` (the file inventory), enumerating each child
/// key as one tracked executable, via the shared HMAP cell-map walkers (which
/// translate cell indices through `_HHIVE.Storage[].Map` and handle
/// `lf`/`lh`/`li`/`ri` subkey lists). Returns an empty `Vec` on a missing hive
/// or absent inventory key (graceful degradation).
///
/// # Errors
///
/// Returns an error only if a shared-walker memory read fails irrecoverably.
pub fn walk_amcache<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    amcache_hive_addr: u64,
) -> crate::Result<Vec<AmcacheEntry>> {
    if amcache_hive_addr == 0 {
        return Ok(Vec::new());
    }

    let root_va = registry::resolve_root_cell(reader, amcache_hive_addr);
    if root_va == 0 {
        return Ok(Vec::new());
    }

    // Navigate to InventoryApplicationFile: a direct child of the hive root on
    // some layouts, otherwise one level under "Root".
    let iaf_va = {
        let direct = registry::find_subkey_by_name(
            reader,
            amcache_hive_addr,
            root_va,
            "InventoryApplicationFile",
        );
        if direct != 0 {
            direct
        } else {
            let root_child =
                registry::find_subkey_by_name(reader, amcache_hive_addr, root_va, "Root");
            if root_child == 0 {
                return Ok(Vec::new());
            }
            registry::find_subkey_by_name(
                reader,
                amcache_hive_addr,
                root_child,
                "InventoryApplicationFile",
            )
        }
    };
    if iaf_va == 0 {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for (_name, child_va) in registry::list_subkeys(reader, amcache_hive_addr, iaf_va)
        .into_iter()
        .take(MAX_AMCACHE_ENTRIES)
    {
        let read_str = |name: &str| -> String {
            decode_utf16le(&registry::read_value_data(
                reader,
                amcache_hive_addr,
                child_va,
                name,
            ))
        };
        let read_num = |name: &str| -> u64 {
            decode_u64(&registry::read_value_data(
                reader,
                amcache_hive_addr,
                child_va,
                name,
            ))
        };

        let file_path = read_str("LowerCaseLongPath");
        let sha1_raw = read_str("FileId");
        // Amcache prepends "0000" to the SHA1 in FileId.
        let sha1_hash = sha1_raw
            .strip_prefix("0000")
            .unwrap_or(&sha1_raw)
            .to_string();
        let file_size = read_num("Size");
        let link_timestamp = read_num("LinkDate");
        let publisher = read_str("Publisher");
        let product_name = read_str("ProductName");
        let is_suspicious = classify_amcache_entry(&file_path, &publisher);

        entries.push(AmcacheEntry {
            file_path,
            sha1_hash,
            file_size,
            link_timestamp,
            publisher,
            product_name,
            is_suspicious,
        });
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    // Test fixtures declare layout consts/helpers beside the statements that use
    // them to keep each byte-plan readable; that ordering is intentional here.
    #![allow(clippy::items_after_statements)]
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Helper: build a minimal reader with no amcache-relevant symbols.
    fn make_empty_reader() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("_CMHIVE", 0x600)
            .add_field("_CMHIVE", "Hive", 0x0, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// No valid hive / symbols missing -> empty Vec, not an error.
    #[test]
    fn walk_amcache_no_symbol() {
        let reader = make_empty_reader();
        let result = walk_amcache(&reader, 0).unwrap();
        assert!(
            result.is_empty(),
            "expected empty Vec when hive address is 0"
        );
    }

    /// Non-zero but unmapped address → empty Vec.
    #[test]
    fn walk_amcache_unmapped_hive_graceful() {
        let reader = make_empty_reader();
        let result = walk_amcache(&reader, 0xDEAD_BEEF_0000).unwrap();
        assert!(result.is_empty());
    }

    // ── classify_amcache_entry: benign cases ─────────────────────────

    /// Entries with well-known publishers (Microsoft, etc.) in standard
    /// system paths should NOT be flagged as suspicious.
    #[test]
    fn classify_amcache_benign() {
        // Microsoft-signed binary in System32
        assert!(
            !classify_amcache_entry(r"C:\Windows\System32\cmd.exe", "Microsoft Corporation"),
            "Microsoft-signed binary in System32 should not be suspicious"
        );

        // Microsoft-signed binary in Program Files
        assert!(
            !classify_amcache_entry(
                r"C:\Program Files\Windows Defender\MsMpEng.exe",
                "Microsoft Corporation"
            ),
            "Microsoft-signed binary in Program Files should not be suspicious"
        );

        // Third-party signed binary in Program Files
        assert!(
            !classify_amcache_entry(
                r"C:\Program Files\Mozilla Firefox\firefox.exe",
                "Mozilla Corporation"
            ),
            "Signed binary from known publisher in Program Files should not be suspicious"
        );
    }

    /// Entries in temp/download/appdata paths with no publisher should be
    /// flagged as suspicious.
    #[test]
    fn classify_amcache_suspicious_temp_path() {
        // Unsigned binary in Temp
        assert!(
            classify_amcache_entry(r"C:\Users\John\AppData\Local\Temp\malware.exe", ""),
            "unsigned binary in Temp should be suspicious"
        );

        // Unsigned binary in Downloads
        assert!(
            classify_amcache_entry(r"C:\Users\John\Downloads\sketch.exe", ""),
            "unsigned binary in Downloads should be suspicious"
        );

        // Unsigned binary in AppData (not Temp subfolder)
        assert!(
            classify_amcache_entry(r"C:\Users\John\AppData\Roaming\evil.exe", ""),
            "unsigned binary in AppData should be suspicious"
        );
    }

    /// Entries with empty publisher, even in system paths, should be
    /// flagged as suspicious (unsigned binaries in unusual locations).
    #[test]
    fn classify_amcache_suspicious_no_publisher() {
        // No publisher in system path
        assert!(
            classify_amcache_entry(r"C:\Windows\System32\unknown.exe", ""),
            "unsigned binary in System32 should be suspicious"
        );

        // No publisher in Program Files
        assert!(
            classify_amcache_entry(r"C:\Program Files\SomeApp\nopub.exe", ""),
            "unsigned binary in Program Files should be suspicious"
        );
    }

    // ── classify_amcache_entry: suspicious directory + untrusted publisher ──

    /// Unknown publisher in temp path should be suspicious (even if non-empty).
    #[test]
    fn classify_amcache_untrusted_publisher_in_temp() {
        assert!(
            classify_amcache_entry(r"C:\Temp\payload.exe", "EvilCorp LLC"),
            "Unknown publisher in \\Temp\\ should be suspicious"
        );
    }

    /// Unknown publisher in Downloads should be suspicious.
    #[test]
    fn classify_amcache_untrusted_publisher_in_downloads() {
        assert!(
            classify_amcache_entry(r"C:\Users\bob\Downloads\tool.exe", "Unknown Software"),
            "Unknown publisher in \\Downloads\\ should be suspicious"
        );
    }

    /// Unknown publisher in AppData should be suspicious.
    #[test]
    fn classify_amcache_untrusted_publisher_in_appdata() {
        assert!(
            classify_amcache_entry(r"C:\Users\bob\AppData\Local\evil.exe", "BadCo"),
            "Unknown publisher in \\AppData\\ should be suspicious"
        );
    }

    /// Known trusted publisher in temp is NOT suspicious (brand-name software).
    #[test]
    fn classify_amcache_trusted_publisher_in_temp_not_suspicious() {
        assert!(
            !classify_amcache_entry(r"C:\Temp\update.exe", "Microsoft Corporation"),
            "Trusted publisher (Microsoft) in temp is not suspicious"
        );
    }

    /// Google binary in temp is not suspicious (trusted publisher).
    #[test]
    fn classify_amcache_google_in_temp_not_suspicious() {
        assert!(
            !classify_amcache_entry(r"C:\Temp\google_update.exe", "Google LLC"),
            "Trusted publisher (Google) in temp is not suspicious"
        );
    }

    /// Unknown publisher in \Recycle path should be suspicious.
    #[test]
    fn classify_amcache_recycle_suspicious() {
        assert!(
            classify_amcache_entry(r"C:\recycle\evil.exe", "MalwareCo"),
            r"Binary in \recycle\ path (no dollar-sign) matches suspicious_dirs"
        );
    }

    /// Unknown publisher in \ProgramData should be suspicious.
    #[test]
    fn classify_amcache_programdata_suspicious() {
        assert!(
            classify_amcache_entry(r"C:\ProgramData\hidden\dropper.exe", "DropperCo"),
            "Unknown publisher in \\ProgramData\\ should be suspicious"
        );
    }

    /// Well-known publisher check is case-insensitive (contains check).
    #[test]
    fn classify_amcache_publisher_case_insensitive() {
        assert!(
            !classify_amcache_entry(r"C:\Temp\adobe_update.exe", "ADOBE Systems"),
            "Adobe in temp with trusted publisher should not be suspicious"
        );
        assert!(
            !classify_amcache_entry(r"C:\Temp\vmtools.exe", "VMware, Inc."),
            "VMware in temp should not be suspicious"
        );
    }

    // ── AmcacheEntry struct and serialization ─────────────────────────

    #[test]
    fn amcache_entry_construction() {
        let entry = AmcacheEntry {
            file_path: r"C:\Windows\System32\cmd.exe".to_string(),
            sha1_hash: "aabbccddeeff00112233445566778899aabbccdd".to_string(),
            file_size: 393216,
            link_timestamp: 130_000_000_000_000_000,
            publisher: "Microsoft Corporation".to_string(),
            product_name: "Microsoft Windows".to_string(),
            is_suspicious: false,
        };
        assert_eq!(entry.file_path, r"C:\Windows\System32\cmd.exe");
        assert!(!entry.is_suspicious);
        assert_eq!(entry.file_size, 393216);
    }

    #[test]
    fn amcache_entry_sha1_strip_prefix() {
        // Test the 0000-prefix stripping logic mirrors the production code
        let sha1_raw = "0000aabbccddeeff001122334455667788991234".to_string();
        let sha1_hash = sha1_raw
            .strip_prefix("0000")
            .unwrap_or(&sha1_raw)
            .to_string();
        assert_eq!(sha1_hash, "aabbccddeeff001122334455667788991234");
    }

    #[test]
    fn amcache_entry_sha1_no_prefix() {
        let sha1_raw = "aabbccddeeff001122334455667788991234".to_string();
        let sha1_hash = sha1_raw
            .strip_prefix("0000")
            .unwrap_or(&sha1_raw)
            .to_string();
        assert_eq!(sha1_hash, "aabbccddeeff001122334455667788991234");
    }

    #[test]
    fn amcache_entry_serialization() {
        let entry = AmcacheEntry {
            file_path: r"C:\Temp\evil.exe".to_string(),
            sha1_hash: "deadbeefdeadbeef".to_string(),
            file_size: 12345,
            link_timestamp: 0,
            publisher: String::new(),
            product_name: String::new(),
            is_suspicious: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"is_suspicious\":true"));
        assert!(json.contains("\"file_size\":12345"));
    }

    // ── classify_amcache_entry: users_public path ────────────────────

    #[test]
    fn classify_amcache_users_public_suspicious() {
        assert!(
            classify_amcache_entry(r"C:\Users\Public\payload.exe", "UnknownCo"),
            r"\users\public\ with unknown publisher should be suspicious"
        );
    }

    // ── AmcacheEntry: clone works ────────────────────────────────────

    #[test]
    fn amcache_entry_clone() {
        let e = AmcacheEntry {
            file_path: r"C:\Windows\System32\cmd.exe".to_string(),
            sha1_hash: "abc123".to_string(),
            file_size: 123,
            link_timestamp: 456,
            publisher: "Microsoft".to_string(),
            product_name: "Windows".to_string(),
            is_suspicious: false,
        };
        let c = e.clone();
        assert_eq!(c.file_path, e.file_path);
        assert_eq!(c.sha1_hash, e.sha1_hash);
    }

    /// RED (flat→HMAP migration): a real cell-map Amcache.hve laid out as
    /// hive-root → `Root` → `InventoryApplicationFile` → one file entry, built
    /// with the shared `CellHive` harness (cells reached via the `_HHIVE`
    /// `Storage[].Map` directory, NOT flat `base + 0x1000 + index`).
    ///
    /// The flat walker reads the root cell from `_HBASE_BLOCK + 0x24` — a zeroed
    /// page on a cell-map hive — so it returns empty. This asserts the entry is
    /// recovered, so it FAILS until `walk_amcache` uses the shared HMAP walker.
    #[test]
    fn walk_amcache_hmap_recovers_inventory_entry() {
        use crate::test_hive::CellHive;
        fn utf16le(s: &str) -> Vec<u8> {
            s.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .chain([0u8, 0u8])
                .collect()
        }
        const REG_SZ_T: u32 = 1;
        const REG_QWORD_T: u32 = 11;

        let path = r"c:\users\rick\appdata\local\temp\evil.exe";
        let sha1 = "1111222233334444555566667777888899990000";
        let publisher = "Evil Corp";

        // Cells are spaced so no nk (needs 0x4C + name_len bytes), lf, vk, or
        // data cell overlaps its neighbour within the 4 KiB bin.
        let mut h = CellHive::new(0x0050_0000);
        h.nk(0x020, b"amcache", 1, 0x0A0, 0);
        h.lf(0x0A0, &[0x120]);
        h.nk(0x120, b"Root", 1, 0x1A0, 0);
        h.lf(0x1A0, &[0x220]);
        h.nk(0x220, b"InventoryApplicationFile", 1, 0x2A0, 0);
        h.lf(0x2A0, &[0x320]);
        // One file-entry key: 0 subkeys, 4 values.
        h.nk(0x320, b"0000file", 0, 0, 0);
        h.values(0x320, 4, 0x3A0);
        h.value_list(0x3A0, &[0x3E0, 0x440, 0x4A0, 0x500]);

        let path_data = utf16le(path);
        h.vk(
            0x3E0,
            b"LowerCaseLongPath",
            REG_SZ_T,
            path_data.len() as u32,
            0x560,
        );
        h.data(0x560, &path_data);

        let fileid_data = utf16le(&format!("0000{sha1}"));
        h.vk(0x440, b"FileId", REG_SZ_T, fileid_data.len() as u32, 0x5C0);
        h.data(0x5C0, &fileid_data);

        let pub_data = utf16le(publisher);
        h.vk(0x4A0, b"Publisher", REG_SZ_T, pub_data.len() as u32, 0x640);
        h.data(0x640, &pub_data);

        h.vk(0x500, b"Size", REG_QWORD_T, 8, 0x680);
        h.data(0x680, &12345u64.to_le_bytes());

        let reader = h.reader();
        let entries = walk_amcache(&reader, h.hhive_va).unwrap();

        assert_eq!(
            entries.len(),
            1,
            "expected 1 amcache entry, got {}",
            entries.len()
        );
        let e = &entries[0];
        assert_eq!(e.file_path, path);
        assert_eq!(e.sha1_hash, sha1, "0000 prefix must be stripped");
        assert_eq!(e.publisher, publisher);
        assert_eq!(e.file_size, 12345);
        assert!(e.is_suspicious, "temp-path exe must be flagged");
    }
}
