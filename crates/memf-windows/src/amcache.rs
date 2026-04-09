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

use crate::unicode::read_unicode_string;

/// Maximum number of Amcache entries to enumerate (safety limit).
const MAX_AMCACHE_ENTRIES: usize = 8192;

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
    todo!()
}

/// Walk the Amcache registry hive from kernel memory.
///
/// Takes the virtual address of the Amcache hive's `_CMHIVE` structure.
/// Reads the `_HHIVE.BaseBlock` to locate the `_HBASE_BLOCK`, then
/// navigates to `Root\InventoryApplicationFile` and reads each child
/// key's value cells.
///
/// Returns an empty `Vec` if the required symbols are not present
/// (graceful degradation).
///
/// # Errors
///
/// Returns an error if memory reads fail after the hive has been
/// located and validated.
pub fn walk_amcache<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    amcache_hive_addr: u64,
) -> crate::Result<Vec<AmcacheEntry>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
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
        assert!(result.is_empty(), "expected empty Vec when hive address is 0");
    }

    /// Entries with well-known publishers (Microsoft, etc.) in standard
    /// system paths should NOT be flagged as suspicious.
    #[test]
    fn classify_amcache_benign() {
        // Microsoft-signed binary in System32
        assert!(
            !classify_amcache_entry(
                r"C:\Windows\System32\cmd.exe",
                "Microsoft Corporation"
            ),
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
}
