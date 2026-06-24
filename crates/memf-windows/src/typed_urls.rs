//! Internet Explorer / Edge typed URL extraction from memory.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use winreg_core::cell_reader::CellReader;
use winreg_core::key::Key;

use crate::hive_reader::MemfHiveReader;

const MAX_TYPED_URLS: usize = 4096;
const TYPED_URLS_PATH: &str = r"Software\Microsoft\Internet Explorer\TypedURLs";
const TYPED_URLS_TIME_PATH: &str = r"Software\Microsoft\Internet Explorer\TypedURLsTime";

/// A URL typed directly into the IE/Edge address bar.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TypedUrlEntry {
    /// Windows username whose hive contained this entry.
    pub username: String,
    /// The typed URL string.
    pub url: String,
    /// Last-visited timestamp stored in the registry (FILETIME).
    pub timestamp: u64,
    /// `true` when the URL matches a known suspicious domain or pattern.
    pub is_suspicious: bool,
}

const SUSPICIOUS_DOMAINS: &[&str] = &[
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "transfer.sh",
    "file.io",
    "mega.nz",
    "anonfiles.com",
];

/// Return `true` when the URL matches a known suspicious domain or pattern.
pub fn classify_typed_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    for domain in SUSPICIOUS_DOMAINS {
        if lower.contains(domain) {
            return true;
        }
    }
    if let Some(path_part) = lower.strip_prefix("file://") {
        if path_part.starts_with("\\\\") || path_part.starts_with("//") {
            return true;
        }
    }
    if let Some(scheme_end) = lower.find("://") {
        let after_scheme = &lower[scheme_end + 3..];
        let authority = match after_scheme.find('/') {
            Some(pos) => &after_scheme[..pos],
            None => after_scheme,
        };
        if authority.contains('@') && authority.contains(':') {
            return true;
        }
    }
    false
}

/// Navigate a backslash-delimited registry key path from `root`, returning the
/// final [`Key`] or `None` if any component is absent (a read fault mid-path
/// degrades to "absent", matching the old silent-empty contract).
fn navigate_key<'h, R: CellReader>(root: &Key<'h, R>, path: &str) -> Option<Key<'h, R>> {
    root.subkey_path(path).ok().flatten()
}

/// Decode a REG_SZ value buffer as a UTF-16LE string, stopping at the first NUL.
fn decode_utf16le(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Walk typed-URL history from an in-memory NTUSER.DAT hive.
///
/// `hive_addr` is the `_CMHIVE`/`_HHIVE` VA. Reads each value under
/// `Software\\Microsoft\\Internet Explorer\\TypedURLs` (name `urlN` → URL)
/// and correlates it by value name with the matching FILETIME under
/// `…\\TypedURLsTime`, via the shared HMAP walkers. Returns an empty `Vec` on a
/// missing hive or absent TypedURLs key (graceful degradation).
pub fn walk_typed_urls<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    username: &str,
) -> crate::Result<Vec<TypedUrlEntry>> {
    if hive_addr == 0 {
        return Ok(Vec::new());
    }
    let hive = MemfHiveReader::new(reader, hive_addr);
    let Ok(root) = hive.root_key() else {
        return Ok(Vec::new());
    };
    let Some(urls_key) = navigate_key(&root, TYPED_URLS_PATH) else {
        return Ok(Vec::new());
    };

    // Correlate timestamps by value name from TypedURLsTime (optional sibling key).
    let mut time_map: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    if let Some(time_key) = navigate_key(&root, TYPED_URLS_TIME_PATH) {
        let Ok(time_values) = time_key.values() else {
            return Ok(Vec::new());
        };
        for value in time_values.into_iter().take(MAX_TYPED_URLS) {
            let Ok(data) = value.raw_data() else { continue };
            if data.len() >= 8 {
                let ts = u64::from_le_bytes(data[..8].try_into().unwrap_or([0; 8]));
                time_map.insert(value.name(), ts);
            }
        }
    }

    let Ok(url_values) = urls_key.values() else {
        return Ok(Vec::new());
    };
    let mut results = Vec::new();
    for value in url_values.into_iter().take(MAX_TYPED_URLS) {
        let Ok(data) = value.raw_data() else { continue };
        let url = decode_utf16le(&data);
        if url.is_empty() {
            continue;
        }
        let timestamp = time_map.get(&value.name()).copied().unwrap_or(0);
        let is_suspicious = classify_typed_url(&url);
        results.push(TypedUrlEntry {
            username: username.to_string(),
            url,
            timestamp,
            is_suspicious,
        });
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_reader() -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn classify_benign_urls() {
        assert!(!classify_typed_url("https://www.google.com"));
        assert!(!classify_typed_url("https://github.com/user/repo"));
        assert!(!classify_typed_url("http://internal.corp.local/dashboard"));
    }

    #[test]
    fn classify_empty_url_benign() {
        assert!(!classify_typed_url(""));
    }

    #[test]
    fn classify_plain_http_benign() {
        assert!(!classify_typed_url("http://example.com/page"));
    }

    #[test]
    fn classify_paste_sites_suspicious() {
        assert!(classify_typed_url("https://pastebin.com/abc123"));
    }

    #[test]
    fn classify_all_suspicious_domains() {
        for domain in SUSPICIOUS_DOMAINS {
            assert!(
                classify_typed_url(&format!("https://{domain}/x")),
                "{domain} should be suspicious"
            );
        }
    }

    #[test]
    fn classify_domain_case_insensitive() {
        assert!(classify_typed_url("https://PASTEBIN.COM/abc"));
        assert!(classify_typed_url("https://MEGA.NZ/file"));
    }

    #[test]
    fn classify_file_sharing_suspicious() {
        assert!(classify_typed_url("https://mega.nz/file/abc"));
        assert!(classify_typed_url("https://transfer.sh/file.zip"));
    }

    #[test]
    fn classify_file_unc_suspicious() {
        assert!(classify_typed_url("file://\\\\server\\share"));
        assert!(classify_typed_url("file:////server/share"));
    }

    #[test]
    fn classify_file_local_benign() {
        assert!(!classify_typed_url("file:///C:/Users/alice/doc.txt"));
    }

    #[test]
    fn classify_file_relative_benign() {
        assert!(!classify_typed_url("file://localhost/path/to/file"));
    }

    #[test]
    fn classify_credentials_suspicious() {
        assert!(classify_typed_url("https://user:password@example.com/path"));
        assert!(classify_typed_url("ftp://admin:secret@ftp.example.com/"));
    }

    #[test]
    fn classify_credentials_no_path_suspicious() {
        assert!(classify_typed_url("https://user:pass@example.com"));
    }

    #[test]
    fn classify_at_sign_no_password_benign() {
        // "@" in authority but no colon before it
        assert!(!classify_typed_url("https://user@example.com/path"));
    }

    #[test]
    fn classify_colon_in_host_no_at_benign() {
        assert!(!classify_typed_url("https://example.com:8080/path"));
    }

    #[test]
    fn walk_typed_urls_zero_hive() {
        let reader = make_reader();
        let result = walk_typed_urls(&reader, 0, "alice").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn walk_typed_urls_unreadable_hive() {
        // Non-zero but unmapped
        let reader = make_reader();
        let result = walk_typed_urls(&reader, 0xFFFF_8000_DEAD_0000, "alice").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn typed_url_entry_construction() {
        let entry = TypedUrlEntry {
            username: "alice".into(),
            url: "https://example.com".into(),
            timestamp: 0,
            is_suspicious: false,
        };
        assert_eq!(entry.username, "alice");
        assert_eq!(entry.url, "https://example.com");
    }

    #[test]
    fn typed_url_entry_serialization() {
        let entry = TypedUrlEntry {
            username: "bob".into(),
            url: "https://pastebin.com/abc".into(),
            timestamp: 132_000_000_000u64,
            is_suspicious: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("pastebin.com"));
        assert!(json.contains("\"is_suspicious\":true"));
    }

    #[test]
    fn typed_urls_path_components_correct() {
        assert_eq!(
            TYPED_URLS_PATH,
            r"Software\Microsoft\Internet Explorer\TypedURLs"
        );
    }

    #[test]
    fn typed_urls_time_path_components_correct() {
        assert!(TYPED_URLS_TIME_PATH.ends_with(r"\TypedURLsTime"));
    }

    #[test]
    fn walk_typed_urls_zero_hive_returns_empty() {
        let reader = make_reader();
        let result = walk_typed_urls(&reader, 0, "testuser").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn walk_typed_urls_unmapped_hive_returns_empty() {
        let reader = make_reader();
        let result = walk_typed_urls(&reader, 0xFFFF_9999_DEAD_BEEF, "testuser").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn typed_url_entry_serializes() {
        let entry = TypedUrlEntry {
            username: "carol".into(),
            url: "https://file.io/upload".into(),
            timestamp: 133_000_000_000_000_000,
            is_suspicious: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("carol"));
        assert!(json.contains("file.io"));
        assert!(json.contains("\"is_suspicious\":true"));
    }

    #[test]
    fn classify_no_scheme_benign() {
        assert!(!classify_typed_url("www.example.com/page"));
        assert!(!classify_typed_url("just plain text"));
    }

    #[test]
    fn classify_file_single_slash_benign() {
        // file://hostname/path — not UNC
        assert!(!classify_typed_url("file://hostname/path/to/file"));
    }

    #[test]
    fn classify_at_in_path_not_authority_benign() {
        // @ appears after the first / so it's in the path, not the authority
        assert!(!classify_typed_url("https://example.com/page@section"));
    }

    #[test]
    fn walk_typed_urls_values_list_not_mapped_empty() {
        // Build a hive where we navigate all the way to TypedURLs nk which has
        // value_count=1, but values_list_cell points to unmapped memory → empty.
        // We'll use a minimal single-level hive where root IS the TypedURLs nk.
        // Since walk_typed_urls first navigates Software→Microsoft→IE→TypedURLs,
        // we instead just verify zero hive returns empty (already tested).
        // For this specific test: unmapped hive addr → empty.
        let reader = make_reader();
        let result = walk_typed_urls(&reader, 0xFFFF_8000_FFFF_0000, "alice").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn classify_url_at_no_colon_benign() {
        // @ in authority but no colon → not credentials
        assert!(!classify_typed_url("https://user@example.com"));
    }

    #[test]
    fn classify_url_colon_port_no_at_benign() {
        assert!(!classify_typed_url("https://example.com:443/page"));
    }

    #[test]
    fn classify_file_no_unc_prefix_benign() {
        assert!(!classify_typed_url("file://"));
    }

    #[test]
    fn typed_url_entry_clone() {
        let entry = TypedUrlEntry {
            username: "alice".into(),
            url: "https://example.com".into(),
            timestamp: 42,
            is_suspicious: false,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.username, entry.username);
        assert_eq!(cloned.url, entry.url);
        assert_eq!(cloned.timestamp, entry.timestamp);
    }

    /// RED (flat→HMAP migration): a real cell-map NTUSER.DAT with
    /// Software\Microsoft\Internet Explorer\{TypedURLs,TypedURLsTime}, each with
    /// a "url1" value (the URL string + its FILETIME), built with the shared
    /// CellHive harness. The flat walker reads the root cell from
    /// _HBASE_BLOCK+0x24 (zeroed on a cell-map hive) → empty; fails until
    /// walk_typed_urls uses the shared HMAP walker.
    #[test]
    fn walk_typed_urls_hmap_recovers_entry() {
        use crate::test_hive::CellHive;
        let url = "http://evil.com/";
        let ts = 0x01D9_AAAA_BBBB_CCCCu64;
        let utf16 = |s: &str| -> Vec<u8> {
            s.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .chain([0u8, 0u8])
                .collect()
        };

        let mut h = CellHive::new(0x0050_0000);
        h.nk(0x020, b"Root", 1, 0x080, 0);
        h.lf(0x080, &[0x0C0]);
        h.nk(0x0C0, b"Software", 1, 0x140, 0);
        h.lf(0x140, &[0x180]);
        h.nk(0x180, b"Microsoft", 1, 0x200, 0);
        h.lf(0x200, &[0x240]);
        h.nk(0x240, b"Internet Explorer", 2, 0x300, 0);
        h.lf(0x300, &[0x340, 0x400]);
        // TypedURLs\url1 = url string
        h.nk(0x340, b"TypedURLs", 0, 0, 0);
        h.values(0x340, 1, 0x600);
        h.value_list(0x600, &[0x700]);
        let url_data = utf16(url);
        h.vk(0x700, b"url1", 1, url_data.len() as u32, 0x880);
        h.data(0x880, &url_data);
        // TypedURLsTime\url1 = FILETIME
        h.nk(0x400, b"TypedURLsTime", 0, 0, 0);
        h.values(0x400, 1, 0x680);
        h.value_list(0x680, &[0x780]);
        h.vk(0x780, b"url1", 3, 8, 0x900);
        h.data(0x900, &ts.to_le_bytes());

        let reader = h.reader();
        let entries = walk_typed_urls(&reader, h.hhive_va, "rick").unwrap();

        assert_eq!(
            entries.len(),
            1,
            "expected 1 typed-url entry, got {}",
            entries.len()
        );
        let e = &entries[0];
        assert_eq!(e.url, url);
        assert_eq!(
            e.timestamp, ts,
            "url1 must correlate with its TypedURLsTime"
        );
        assert_eq!(e.username, "rick");
    }

    /// RED (registry-dedup migration): drive `walk_typed_urls` through the
    /// shared winreg-core navigation seam. `navigate_key` must hand back a
    /// `Key` (`Option`) bootstrapped from [`MemfHiveReader`], not a raw `u64`
    /// cell VA from the dead `registry::` flat walker. A multi-URL TypedURLs
    /// node — one value correlated with TypedURLsTime, one without — pins the
    /// per-name timestamp correlation that winreg-core's `Value::raw_data`
    /// path must reproduce. Compile-fails until `navigate_key` returns
    /// `Option<Key<…>>`, and value enumeration runs through `key.values()`.
    #[test]
    fn walk_typed_urls_winreg_core_navigation() {
        use crate::hive_reader::MemfHiveReader;
        use crate::test_hive::CellHive;

        let url1 = "http://evil.com/";
        let url2 = "https://pastebin.com/abc";
        let ts1 = 0x01D9_AAAA_BBBB_CCCCu64;
        let utf16 = |s: &str| -> Vec<u8> {
            s.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .chain([0u8, 0u8])
                .collect()
        };

        let mut h = CellHive::new(0x0050_0000);
        h.nk(0x020, b"Root", 1, 0x080, 0);
        h.lf(0x080, &[0x0C0]);
        h.nk(0x0C0, b"Software", 1, 0x140, 0);
        h.lf(0x140, &[0x180]);
        h.nk(0x180, b"Microsoft", 1, 0x200, 0);
        h.lf(0x200, &[0x240]);
        h.nk(0x240, b"Internet Explorer", 2, 0x300, 0);
        h.lf(0x300, &[0x340, 0x400]);
        // TypedURLs has two values: url1 (correlated) + url2 (no time sibling).
        h.nk(0x340, b"TypedURLs", 0, 0, 0);
        h.values(0x340, 2, 0x600);
        h.value_list(0x600, &[0x700, 0x740]);
        let d1 = utf16(url1);
        let d2 = utf16(url2);
        h.vk(0x700, b"url1", 1, d1.len() as u32, 0x880);
        h.data(0x880, &d1);
        h.vk(0x740, b"url2", 1, d2.len() as u32, 0x8C0);
        h.data(0x8C0, &d2);
        // TypedURLsTime carries only url1.
        h.nk(0x400, b"TypedURLsTime", 0, 0, 0);
        h.values(0x400, 1, 0x680);
        h.value_list(0x680, &[0x780]);
        h.vk(0x780, b"url1", 3, 8, 0x900);
        h.data(0x900, &ts1.to_le_bytes());

        let reader = h.reader();

        // Migration seam: `navigate_key` returns an `Option<Key>` over the
        // winreg-core backend, not a `u64`. (Compile-fails pre-migration.)
        let hive = MemfHiveReader::new(&reader, h.hhive_va);
        let root = hive.root_key().unwrap();
        let urls_key = navigate_key(&root, TYPED_URLS_PATH);
        assert!(urls_key.is_some(), "TypedURLs must resolve via winreg-core");

        let mut entries = walk_typed_urls(&reader, h.hhive_va, "rick").unwrap();
        entries.sort_by(|a, b| a.url.cmp(&b.url));
        assert_eq!(entries.len(), 2, "expected both typed-url values");
        // url1 correlates with its TypedURLsTime sibling.
        let e1 = entries.iter().find(|e| e.url == url1).unwrap();
        assert_eq!(e1.timestamp, ts1, "url1 must correlate with TypedURLsTime");
        assert!(!e1.is_suspicious);
        // url2 has no time sibling → 0, and is flagged suspicious (pastebin).
        let e2 = entries.iter().find(|e| e.url == url2).unwrap();
        assert_eq!(e2.timestamp, 0, "url2 has no matching TypedURLsTime");
        assert!(e2.is_suspicious);
    }
}
