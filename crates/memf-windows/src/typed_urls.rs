//! Internet Explorer / Edge typed URL extraction from memory.
//!
//! Windows stores URLs manually typed into the IE/Edge address bar in
//! `NTUSER.DAT\Software\Microsoft\Internet Explorer\TypedURLs`. Each
//! value (`url1`, `url2`, ...) is a REG_SZ containing the typed URL.
//! An optional sibling key `TypedURLsTime` holds corresponding 8-byte
//! FILETIME timestamps (`url1`, `url2`, ...).
//!
//! Typed URLs are important evidence for insider threat and data
//! exfiltration investigations because they represent intentional
//! user navigation, not click-throughs or redirects.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// Maximum number of typed URL entries to enumerate (safety limit).
const MAX_TYPED_URLS: usize = 4096;

// ── Hive cell constants (duplicated from registry_keys for encapsulation) ──

/// Offset of `RootCell` (u32) within `_HBASE_BLOCK`.
const HBASE_BLOCK_ROOT_CELL_OFFSET: u64 = 0x24;

/// Offset from `_HBASE_BLOCK` to the first HBIN (cell storage start).
const HBIN_START_OFFSET: u64 = 0x1000;

/// `_CM_KEY_NODE` signature "nk".
const NK_SIGNATURE: u16 = 0x6B6E;

/// Stable subkey count: u32 at offset 0x14 in nk cell data.
const NK_STABLE_SUBKEY_COUNT_OFFSET: usize = 0x14;

/// Stable subkeys list cell index: u32 at offset 0x1C.
const NK_STABLE_SUBKEYS_LIST_OFFSET: usize = 0x1C;

/// Value count: u32 at offset 0x24.
const NK_VALUE_COUNT_OFFSET: usize = 0x24;

/// Values list cell index: u32 at offset 0x28.
const NK_VALUES_LIST_OFFSET: usize = 0x28;

/// Name length: u16 at offset 0x48.
const NK_NAME_LENGTH_OFFSET: usize = 0x48;

/// Name data starts at offset 0x4C.
const NK_NAME_OFFSET: usize = 0x4C;

/// `_CM_KEY_VALUE` signature "vk".
const VK_SIGNATURE: u16 = 0x6B76;

/// Value name length: u16 at offset 0x02.
const VK_NAME_LENGTH_OFFSET: usize = 0x02;

/// Value data length: u32 at offset 0x04.
const VK_DATA_LENGTH_OFFSET: usize = 0x04;

/// Value data offset (cell index): u32 at offset 0x08.
const VK_DATA_OFFSET_OFFSET: usize = 0x08;

/// Value name starts at offset 0x14.
const VK_NAME_OFFSET: usize = 0x14;

/// Maximum subkeys per node (safety limit).
const MAX_SUBKEYS: usize = 4096;

/// Maximum values per key (safety limit).
const MAX_VALUES: usize = 4096;

/// The path components from the hive root to the TypedURLs key.
const TYPED_URLS_PATH: &[&str] = &[
    "Software",
    "Microsoft",
    "Internet Explorer",
    "TypedURLs",
];

/// The path components from the hive root to the TypedURLsTime key.
const TYPED_URLS_TIME_PATH: &[&str] = &[
    "Software",
    "Microsoft",
    "Internet Explorer",
    "TypedURLsTime",
];

/// A single typed URL entry recovered from an NTUSER.DAT hive.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TypedUrlEntry {
    /// Username associated with this NTUSER.DAT hive (from hive path).
    pub username: String,
    /// The URL that was typed into the address bar.
    pub url: String,
    /// Timestamp when the URL was typed (FILETIME, 100-ns since 1601-01-01).
    /// Zero if the TypedURLsTime key is absent or the matching entry is missing.
    pub timestamp: u64,
    /// Whether this URL matches suspicious patterns (paste sites,
    /// file-sharing services, encoded credentials, network file:// paths).
    pub is_suspicious: bool,
}

// ── Suspicious URL classification ────────────────────────────────────

/// Known paste and file-sharing sites frequently used for data exfiltration.
const SUSPICIOUS_DOMAINS: &[&str] = &[
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "transfer.sh",
    "file.io",
    "mega.nz",
    "anonfiles.com",
];

/// Classify a typed URL as suspicious.
///
/// Returns `true` if the URL matches patterns commonly associated with
/// data exfiltration or unauthorized access:
///
/// - Known paste/file-sharing sites (pastebin, mega.nz, transfer.sh, etc.)
/// - `file://` scheme with network path (`file://\\` or `file:////`)
/// - Encoded credentials in the URL (`@` with `:` before it, or `:password@`)
pub fn classify_typed_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();

    // Check for known paste/file-sharing domains.
    for domain in SUSPICIOUS_DOMAINS {
        if lower.contains(domain) {
            return true;
        }
    }

    // file:// with network path (UNC) — e.g. file://\\server\share
    // or file:////server/share
    if lower.starts_with("file://") {
        let path_part = &lower[7..];
        if path_part.starts_with("\\\\") || path_part.starts_with("//") {
            return true;
        }
    }

    // Encoded credentials in URL: user:password@host pattern.
    // Look for "://" followed by something containing "@".
    if let Some(scheme_end) = lower.find("://") {
        let after_scheme = &lower[scheme_end + 3..];
        // Check for @ in the authority part (before the first /)
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

// ── Hive cell helpers ────────────────────────────────────────────────

/// Compute the virtual address of a cell given its cell index.
fn cell_address(hive_addr: u64, cell_index: u32) -> u64 {
    hive_addr
        .wrapping_add(HBIN_START_OFFSET)
        .wrapping_add(cell_index as u64)
}

/// Read cell data from a cell at `cell_vaddr`, skipping the 4-byte size header.
fn read_cell_data<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    cell_vaddr: u64,
) -> crate::Result<Vec<u8>> {
    let size_bytes = reader.read_bytes(cell_vaddr, 4)?;
    let raw_size = i32::from_le_bytes(size_bytes[..4].try_into().unwrap());
    let abs_size = raw_size.unsigned_abs() as usize;
    if abs_size <= 4 {
        return Ok(Vec::new());
    }
    let data_len = (abs_size - 4).min(0x10000);
    reader
        .read_bytes(cell_vaddr.wrapping_add(4), data_len)
        .map_err(Into::into)
}

/// Extract the key name from an nk cell's data bytes (ASCII, compressed).
fn read_key_name(nk_data: &[u8]) -> String {
    if nk_data.len() < NK_NAME_OFFSET + 1 {
        return String::new();
    }
    let name_len = u16::from_le_bytes(
        nk_data[NK_NAME_LENGTH_OFFSET..NK_NAME_LENGTH_OFFSET + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let end = NK_NAME_OFFSET + name_len;
    if end > nk_data.len() {
        return String::new();
    }
    String::from_utf8_lossy(&nk_data[NK_NAME_OFFSET..end]).into_owned()
}

/// Read the value name from a vk cell's data bytes.
fn read_value_name(vk_data: &[u8]) -> String {
    if vk_data.len() < VK_NAME_OFFSET + 1 {
        return String::new();
    }
    let name_len = u16::from_le_bytes(
        vk_data[VK_NAME_LENGTH_OFFSET..VK_NAME_LENGTH_OFFSET + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let end = VK_NAME_OFFSET + name_len;
    if end > vk_data.len() {
        return String::new();
    }
    String::from_utf8_lossy(&vk_data[VK_NAME_OFFSET..end]).into_owned()
}

/// Find a subkey by name (case-insensitive) under a given nk cell.
///
/// Returns the cell index of the matching subkey, or `None`.
fn find_subkey<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    nk_data: &[u8],
    target_name: &str,
) -> crate::Result<Option<u32>> {
    if nk_data.len() < NK_STABLE_SUBKEYS_LIST_OFFSET + 4 {
        return Ok(None);
    }

    let subkey_count = u32::from_le_bytes(
        nk_data[NK_STABLE_SUBKEY_COUNT_OFFSET..NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;

    if subkey_count == 0 {
        return Ok(None);
    }

    let subkeys_list_cell = u32::from_le_bytes(
        nk_data[NK_STABLE_SUBKEYS_LIST_OFFSET..NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .try_into()
            .unwrap(),
    );

    let list_vaddr = cell_address(hive_addr, subkeys_list_cell);
    let list_data = read_cell_data(reader, list_vaddr)?;

    if list_data.len() < 4 {
        return Ok(None);
    }

    let sig = u16::from_le_bytes(list_data[0..2].try_into().unwrap());
    let count = u16::from_le_bytes(list_data[2..4].try_into().unwrap()) as usize;
    let count = count.min(MAX_SUBKEYS);

    match sig {
        // "lf" (0x666C) or "lh" (0x686C): each entry is 8 bytes (cell index + hash).
        0x666C | 0x686C => {
            for i in 0..count {
                let off = 4 + i * 8;
                if off + 4 > list_data.len() {
                    break;
                }
                let child_cell =
                    u32::from_le_bytes(list_data[off..off + 4].try_into().unwrap());
                let child_vaddr = cell_address(hive_addr, child_cell);
                if let Ok(child_nk) = read_cell_data(reader, child_vaddr) {
                    if child_nk.len() >= NK_NAME_OFFSET {
                        let child_sig =
                            u16::from_le_bytes(child_nk[0..2].try_into().unwrap());
                        if child_sig == NK_SIGNATURE {
                            let name = read_key_name(&child_nk);
                            if name.eq_ignore_ascii_case(target_name) {
                                return Ok(Some(child_cell));
                            }
                        }
                    }
                }
            }
        }
        // "li" (0x696C): each entry is 4 bytes (cell index only).
        0x696C => {
            for i in 0..count {
                let off = 4 + i * 4;
                if off + 4 > list_data.len() {
                    break;
                }
                let child_cell =
                    u32::from_le_bytes(list_data[off..off + 4].try_into().unwrap());
                let child_vaddr = cell_address(hive_addr, child_cell);
                if let Ok(child_nk) = read_cell_data(reader, child_vaddr) {
                    if child_nk.len() >= NK_NAME_OFFSET {
                        let child_sig =
                            u16::from_le_bytes(child_nk[0..2].try_into().unwrap());
                        if child_sig == NK_SIGNATURE {
                            let name = read_key_name(&child_nk);
                            if name.eq_ignore_ascii_case(target_name) {
                                return Ok(Some(child_cell));
                            }
                        }
                    }
                }
            }
        }
        // "ri" (0x6972): index of indices.
        0x6972 => {
            for i in 0..count {
                let off = 4 + i * 4;
                if off + 4 > list_data.len() {
                    break;
                }
                let sub_list_cell =
                    u32::from_le_bytes(list_data[off..off + 4].try_into().unwrap());
                let sub_vaddr = cell_address(hive_addr, sub_list_cell);
                let sub_data = read_cell_data(reader, sub_vaddr)?;
                if sub_data.len() < 4 {
                    continue;
                }
                let sub_sig = u16::from_le_bytes(sub_data[0..2].try_into().unwrap());
                let sub_count =
                    u16::from_le_bytes(sub_data[2..4].try_into().unwrap()) as usize;
                let sub_count = sub_count.min(MAX_SUBKEYS);
                let entry_size: usize = match sub_sig {
                    0x666C | 0x686C => 8,
                    0x696C => 4,
                    _ => continue,
                };
                for j in 0..sub_count {
                    let soff = 4 + j * entry_size;
                    if soff + 4 > sub_data.len() {
                        break;
                    }
                    let child_cell =
                        u32::from_le_bytes(sub_data[soff..soff + 4].try_into().unwrap());
                    let child_vaddr = cell_address(hive_addr, child_cell);
                    if let Ok(child_nk) = read_cell_data(reader, child_vaddr) {
                        if child_nk.len() >= NK_NAME_OFFSET {
                            let child_sig =
                                u16::from_le_bytes(child_nk[0..2].try_into().unwrap());
                            if child_sig == NK_SIGNATURE {
                                let name = read_key_name(&child_nk);
                                if name.eq_ignore_ascii_case(target_name) {
                                    return Ok(Some(child_cell));
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    Ok(None)
}

// ── Walk function ────────────────────────────────────────────────────

/// Walk typed URL entries from an NTUSER.DAT registry hive in memory.
///
/// `hive_addr` is the virtual address of the `_HBASE_BLOCK` for an
/// NTUSER.DAT hive. `username` is the account name associated with the
/// hive (extracted from the hive path). The walker navigates:
///
///   1. Root -> `Software\Microsoft\Internet Explorer\TypedURLs`
///   2. Reads `url1`, `url2`, ... REG_SZ values
///   3. Optionally reads `TypedURLsTime` for FILETIME timestamps
///   4. Classifies each URL for suspicious patterns
///
/// Returns `Ok(Vec::new())` if the path does not exist or the hive is
/// unreadable (graceful degradation).
pub fn walk_typed_urls<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    username: &str,
) -> crate::Result<Vec<TypedUrlEntry>> {
    todo!("GREEN phase: implement typed URL extraction from registry hive")
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ── classify_typed_url tests ─────────────────────────────────────

    /// Normal websites should not be flagged.
    #[test]
    fn classify_benign_urls() {
        assert!(!classify_typed_url("https://www.google.com"));
        assert!(!classify_typed_url("https://docs.microsoft.com/en-us/windows/"));
        assert!(!classify_typed_url("http://intranet.corp.local/dashboard"));
    }

    /// Paste sites used for data exfiltration should be flagged.
    #[test]
    fn classify_paste_sites_suspicious() {
        assert!(classify_typed_url("https://pastebin.com/raw/abc123"));
        assert!(classify_typed_url("https://paste.ee/p/xyz789"));
        assert!(classify_typed_url("https://hastebin.com/share/something"));
    }

    /// File-sharing and anonymous upload sites should be flagged.
    #[test]
    fn classify_file_sharing_suspicious() {
        assert!(classify_typed_url("https://transfer.sh/abc/secret.zip"));
        assert!(classify_typed_url("https://file.io/abc123"));
        assert!(classify_typed_url("https://mega.nz/folder/abcdef"));
        assert!(classify_typed_url("https://anonfiles.com/file/leaked.docx"));
    }

    /// file:// URLs with network (UNC) paths should be flagged.
    #[test]
    fn classify_file_unc_suspicious() {
        assert!(classify_typed_url("file://\\\\server\\share\\secrets.xlsx"));
        assert!(classify_typed_url("file:////fileserver/data/export.csv"));
    }

    /// file:// URLs with local paths should NOT be flagged.
    #[test]
    fn classify_file_local_benign() {
        assert!(!classify_typed_url("file:///C:/Users/john/document.pdf"));
        assert!(!classify_typed_url("file:///tmp/test.html"));
    }

    /// URLs with embedded credentials should be flagged.
    #[test]
    fn classify_credentials_suspicious() {
        assert!(classify_typed_url("https://admin:password@internal.corp.local/admin"));
        assert!(classify_typed_url("ftp://user:secret@ftp.example.com/data"));
    }

    /// URLs with @ but no colon in authority (e.g. email-like) should NOT be flagged.
    #[test]
    fn classify_at_sign_no_password_benign() {
        assert!(!classify_typed_url("https://user@example.com/profile"));
    }

    // ── walk_typed_urls tests ────────────────────────────────────────

    /// Empty reader with zero hive_addr → returns empty Vec.
    #[test]
    fn walk_typed_urls_zero_hive() {
        let isf = IsfBuilder::new()
            .add_struct("_CM_KEY_NODE", 0x50)
            .add_field("_CM_KEY_NODE", "Signature", 0x00, "unsigned short")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_typed_urls(&reader, 0, "testuser").unwrap();
        assert!(result.is_empty());
    }

    /// Hive with unreadable root cell → returns empty Vec.
    #[test]
    fn walk_typed_urls_unreadable_hive() {
        let isf = IsfBuilder::new()
            .add_struct("_CM_KEY_NODE", 0x50)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // Non-zero address but no mapped memory → read fails → empty Vec.
        let result = walk_typed_urls(&reader, 0xDEAD_0000, "bob").unwrap();
        assert!(result.is_empty());
    }
}
