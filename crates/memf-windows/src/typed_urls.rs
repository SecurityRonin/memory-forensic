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
const TYPED_URLS_PATH: &[&str] = &["Software", "Microsoft", "Internet Explorer", "TypedURLs"];

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
                let child_cell = u32::from_le_bytes(list_data[off..off + 4].try_into().unwrap());
                let child_vaddr = cell_address(hive_addr, child_cell);
                if let Ok(child_nk) = read_cell_data(reader, child_vaddr) {
                    if child_nk.len() >= NK_NAME_OFFSET {
                        let child_sig = u16::from_le_bytes(child_nk[0..2].try_into().unwrap());
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
                let child_cell = u32::from_le_bytes(list_data[off..off + 4].try_into().unwrap());
                let child_vaddr = cell_address(hive_addr, child_cell);
                if let Ok(child_nk) = read_cell_data(reader, child_vaddr) {
                    if child_nk.len() >= NK_NAME_OFFSET {
                        let child_sig = u16::from_le_bytes(child_nk[0..2].try_into().unwrap());
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
                let sub_list_cell = u32::from_le_bytes(list_data[off..off + 4].try_into().unwrap());
                let sub_vaddr = cell_address(hive_addr, sub_list_cell);
                let sub_data = read_cell_data(reader, sub_vaddr)?;
                if sub_data.len() < 4 {
                    continue;
                }
                let sub_sig = u16::from_le_bytes(sub_data[0..2].try_into().unwrap());
                let sub_count = u16::from_le_bytes(sub_data[2..4].try_into().unwrap()) as usize;
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
                            let child_sig = u16::from_le_bytes(child_nk[0..2].try_into().unwrap());
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
    // Zero hive address is invalid — return empty gracefully.
    if hive_addr == 0 {
        return Ok(Vec::new());
    }

    // Read root cell index from _HBASE_BLOCK at HBASE_BLOCK_ROOT_CELL_OFFSET.
    let root_cell_bytes =
        match reader.read_bytes(hive_addr.wrapping_add(HBASE_BLOCK_ROOT_CELL_OFFSET), 4) {
            Ok(b) => b,
            Err(_) => return Ok(Vec::new()),
        };
    let root_cell_index = u32::from_le_bytes(root_cell_bytes[..4].try_into().unwrap());

    // Read the root nk cell.
    let root_vaddr = cell_address(hive_addr, root_cell_index);
    let root_nk = match read_cell_data(reader, root_vaddr) {
        Ok(d) => d,
        Err(_) => return Ok(Vec::new()),
    };
    if root_nk.len() < 2 {
        return Ok(Vec::new());
    }
    let sig = u16::from_le_bytes(root_nk[0..2].try_into().unwrap());
    if sig != NK_SIGNATURE {
        return Ok(Vec::new());
    }

    // Navigate path: Software\Microsoft\Internet Explorer\TypedURLs
    let mut current_nk = root_nk;
    for component in TYPED_URLS_PATH {
        match find_subkey(reader, hive_addr, &current_nk, component)? {
            Some(cell_idx) => {
                let vaddr = cell_address(hive_addr, cell_idx);
                match read_cell_data(reader, vaddr) {
                    Ok(d) => current_nk = d,
                    Err(_) => return Ok(Vec::new()),
                }
            }
            None => return Ok(Vec::new()),
        }
    }
    // current_nk is now the TypedURLs key nk data.

    // Read values list.
    if current_nk.len() < NK_VALUES_LIST_OFFSET + 4 {
        return Ok(Vec::new());
    }
    let value_count = u32::from_le_bytes(
        current_nk[NK_VALUE_COUNT_OFFSET..NK_VALUE_COUNT_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    if value_count == 0 {
        return Ok(Vec::new());
    }
    let values_list_cell = u32::from_le_bytes(
        current_nk[NK_VALUES_LIST_OFFSET..NK_VALUES_LIST_OFFSET + 4]
            .try_into()
            .unwrap(),
    );

    let vlist_vaddr = cell_address(hive_addr, values_list_cell);
    let vlist_data = match read_cell_data(reader, vlist_vaddr) {
        Ok(d) => d,
        Err(_) => return Ok(Vec::new()),
    };

    // Also try to navigate TypedURLsTime for timestamps.
    // Navigate from root again.
    let mut time_nk_opt: Option<Vec<u8>> = None;
    {
        let root_cell_bytes2 = reader
            .read_bytes(hive_addr.wrapping_add(HBASE_BLOCK_ROOT_CELL_OFFSET), 4)
            .ok();
        if let Some(b) = root_cell_bytes2 {
            let root_cell_index2 = u32::from_le_bytes(b[..4].try_into().unwrap());
            let root_vaddr2 = cell_address(hive_addr, root_cell_index2);
            if let Ok(root_nk2) = read_cell_data(reader, root_vaddr2) {
                let mut cur = root_nk2;
                let mut ok = true;
                for component in TYPED_URLS_TIME_PATH {
                    match find_subkey(reader, hive_addr, &cur, component) {
                        Ok(Some(cell_idx)) => {
                            let va = cell_address(hive_addr, cell_idx);
                            match read_cell_data(reader, va) {
                                Ok(d) => cur = d,
                                Err(_) => {
                                    ok = false;
                                    break;
                                }
                            }
                        }
                        _ => {
                            ok = false;
                            break;
                        }
                    }
                }
                if ok {
                    time_nk_opt = Some(cur);
                }
            }
        }
    }

    // Build a map of value_name -> timestamp from TypedURLsTime.
    let mut time_map: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    if let Some(time_nk) = time_nk_opt {
        if time_nk.len() >= NK_VALUES_LIST_OFFSET + 4 {
            let tc = u32::from_le_bytes(
                time_nk[NK_VALUE_COUNT_OFFSET..NK_VALUE_COUNT_OFFSET + 4]
                    .try_into()
                    .unwrap(),
            ) as usize;
            if tc > 0 {
                let tvc = u32::from_le_bytes(
                    time_nk[NK_VALUES_LIST_OFFSET..NK_VALUES_LIST_OFFSET + 4]
                        .try_into()
                        .unwrap(),
                );
                let tvl_vaddr = cell_address(hive_addr, tvc);
                if let Ok(tvl_data) = read_cell_data(reader, tvl_vaddr) {
                    let tc = tc.min(MAX_TYPED_URLS);
                    for i in 0..tc {
                        let off = i * 4;
                        if off + 4 > tvl_data.len() {
                            break;
                        }
                        let vk_cell =
                            u32::from_le_bytes(tvl_data[off..off + 4].try_into().unwrap());
                        let vk_vaddr = cell_address(hive_addr, vk_cell);
                        if let Ok(vk_data) = read_cell_data(reader, vk_vaddr) {
                            if vk_data.len() >= 2 {
                                let vsig = u16::from_le_bytes(vk_data[0..2].try_into().unwrap());
                                if vsig == VK_SIGNATURE {
                                    let vname = read_value_name(&vk_data);
                                    // Read 8-byte FILETIME value
                                    if vk_data.len() >= VK_DATA_OFFSET_OFFSET + 4 {
                                        let data_len = u32::from_le_bytes(
                                            vk_data
                                                [VK_DATA_LENGTH_OFFSET..VK_DATA_LENGTH_OFFSET + 4]
                                                .try_into()
                                                .unwrap(),
                                        );
                                        let data_cell = u32::from_le_bytes(
                                            vk_data
                                                [VK_DATA_OFFSET_OFFSET..VK_DATA_OFFSET_OFFSET + 4]
                                                .try_into()
                                                .unwrap(),
                                        );
                                        if data_len >= 8 {
                                            let dc_vaddr = cell_address(hive_addr, data_cell);
                                            if let Ok(dc_data) = read_cell_data(reader, dc_vaddr) {
                                                if dc_data.len() >= 8 {
                                                    let ts = u64::from_le_bytes(
                                                        dc_data[0..8].try_into().unwrap(),
                                                    );
                                                    time_map.insert(vname, ts);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Enumerate TypedURLs values.
    let mut results = Vec::new();
    let count = value_count.min(MAX_TYPED_URLS);

    for i in 0..count {
        let off = i * 4;
        if off + 4 > vlist_data.len() {
            break;
        }
        let vk_cell = u32::from_le_bytes(vlist_data[off..off + 4].try_into().unwrap());
        let vk_vaddr = cell_address(hive_addr, vk_cell);
        let vk_data = match read_cell_data(reader, vk_vaddr) {
            Ok(d) => d,
            Err(_) => continue,
        };
        if vk_data.len() < 2 {
            continue;
        }
        let vsig = u16::from_le_bytes(vk_data[0..2].try_into().unwrap());
        if vsig != VK_SIGNATURE {
            continue;
        }

        let value_name = read_value_name(&vk_data);

        // Read the REG_SZ data (UTF-16LE string).
        if vk_data.len() < VK_DATA_OFFSET_OFFSET + 4 {
            continue;
        }
        let data_len_raw = u32::from_le_bytes(
            vk_data[VK_DATA_LENGTH_OFFSET..VK_DATA_LENGTH_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        // Strip the inline-data flag (bit 31).
        let data_len = (data_len_raw & 0x7FFF_FFFF) as usize;
        if data_len < 2 {
            continue;
        }
        let data_cell = u32::from_le_bytes(
            vk_data[VK_DATA_OFFSET_OFFSET..VK_DATA_OFFSET_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        let dc_vaddr = cell_address(hive_addr, data_cell);
        let dc_data = match read_cell_data(reader, dc_vaddr) {
            Ok(d) => d,
            Err(_) => continue,
        };
        if dc_data.len() < 2 {
            continue;
        }
        // Decode UTF-16LE string.
        let str_len = data_len.min(dc_data.len()) & !1; // round down to even
        let utf16_units: Vec<u16> = dc_data[..str_len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        let url = String::from_utf16_lossy(&utf16_units);
        if url.is_empty() {
            continue;
        }

        let timestamp = time_map.get(&value_name).copied().unwrap_or(0);
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
        let isf = IsfBuilder::new()
            .add_struct("_CM_KEY_NODE", 0x50)
            .add_field("_CM_KEY_NODE", "Signature", 0x00, "unsigned short")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    // ── classify_typed_url tests ─────────────────────────────────────

    /// Normal websites should not be flagged.
    #[test]
    fn classify_benign_urls() {
        assert!(!classify_typed_url("https://www.google.com"));
        assert!(!classify_typed_url(
            "https://docs.microsoft.com/en-us/windows/"
        ));
        assert!(!classify_typed_url("http://intranet.corp.local/dashboard"));
    }

    /// Empty URL is benign.
    #[test]
    fn classify_empty_url_benign() {
        assert!(!classify_typed_url(""));
    }

    /// Plain HTTP URL without credentials or suspicious domain is benign.
    #[test]
    fn classify_plain_http_benign() {
        assert!(!classify_typed_url("http://example.com/page"));
    }

    /// Paste sites used for data exfiltration should be flagged.
    #[test]
    fn classify_paste_sites_suspicious() {
        assert!(classify_typed_url("https://pastebin.com/raw/abc123"));
        assert!(classify_typed_url("https://paste.ee/p/xyz789"));
        assert!(classify_typed_url("https://hastebin.com/share/something"));
    }

    /// All suspicious domains are flagged.
    #[test]
    fn classify_all_suspicious_domains() {
        let domains = [
            "pastebin.com",
            "paste.ee",
            "hastebin.com",
            "transfer.sh",
            "file.io",
            "mega.nz",
            "anonfiles.com",
        ];
        for domain in &domains {
            assert!(
                classify_typed_url(&format!("https://{}/test", domain)),
                "Expected {} to be suspicious",
                domain
            );
        }
    }

    /// Domain checks are case-insensitive.
    #[test]
    fn classify_domain_case_insensitive() {
        assert!(classify_typed_url("https://PASTEBIN.COM/raw/abc"));
        assert!(classify_typed_url("HTTPS://Mega.NZ/folder/xyz"));
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

    /// file:// with a relative path (no leading double slash) is benign.
    #[test]
    fn classify_file_relative_benign() {
        assert!(!classify_typed_url("file://localhost/path/to/file"));
    }

    /// URLs with embedded credentials should be flagged.
    #[test]
    fn classify_credentials_suspicious() {
        assert!(classify_typed_url(
            "https://admin:password@internal.corp.local/admin"
        ));
        assert!(classify_typed_url("ftp://user:secret@ftp.example.com/data"));
    }

    /// Credentials in URL without path separator in authority is flagged.
    #[test]
    fn classify_credentials_no_path_suspicious() {
        assert!(classify_typed_url("https://user:pass@host.example.com"));
    }

    /// URLs with @ but no colon in authority (e.g. email-like) should NOT be flagged.
    #[test]
    fn classify_at_sign_no_password_benign() {
        assert!(!classify_typed_url("https://user@example.com/profile"));
    }

    /// URL with colon before @ in domain name part (not credentials) is tricky —
    /// the spec checks authority.contains(':') AND authority.contains('@').
    /// A URL like "https://example.com:8080/path" has no '@' so is benign.
    #[test]
    fn classify_colon_in_host_no_at_benign() {
        assert!(!classify_typed_url("https://example.com:8080/admin"));
        assert!(!classify_typed_url("http://internal.server:9000/api"));
    }

    // ── read_key_name unit tests ──────────────────────────────────────

    #[test]
    fn read_key_name_too_short_returns_empty() {
        let data = vec![0u8; NK_NAME_OFFSET]; // no room for name data
        assert_eq!(read_key_name(&data), "");
    }

    #[test]
    fn read_key_name_valid_ascii() {
        let mut data = vec![0u8; 0x60];
        let name = b"TypedURLs";
        data[NK_NAME_LENGTH_OFFSET] = name.len() as u8;
        data[NK_NAME_LENGTH_OFFSET + 1] = 0;
        data[NK_NAME_OFFSET..NK_NAME_OFFSET + name.len()].copy_from_slice(name);
        assert_eq!(read_key_name(&data), "TypedURLs");
    }

    #[test]
    fn read_key_name_length_overflow_returns_empty() {
        let mut data = vec![0u8; 0x60];
        // Set an impossible name length
        data[NK_NAME_LENGTH_OFFSET] = 0xFF;
        data[NK_NAME_LENGTH_OFFSET + 1] = 0xFF;
        assert_eq!(read_key_name(&data), "");
    }

    // ── read_value_name unit tests ────────────────────────────────────

    #[test]
    fn read_value_name_too_short_returns_empty() {
        let data = vec![0u8; VK_NAME_OFFSET]; // exactly VK_NAME_OFFSET = 0x14 bytes
        assert_eq!(read_value_name(&data), "");
    }

    #[test]
    fn read_value_name_valid() {
        let mut data = vec![0u8; 0x30];
        let name = b"url1";
        data[VK_NAME_LENGTH_OFFSET] = name.len() as u8;
        data[VK_NAME_LENGTH_OFFSET + 1] = 0;
        data[VK_NAME_OFFSET..VK_NAME_OFFSET + name.len()].copy_from_slice(name);
        assert_eq!(read_value_name(&data), "url1");
    }

    #[test]
    fn read_value_name_length_overflow_returns_empty() {
        let mut data = vec![0u8; 0x30];
        data[VK_NAME_LENGTH_OFFSET] = 0xFF;
        data[VK_NAME_LENGTH_OFFSET + 1] = 0xFF;
        assert_eq!(read_value_name(&data), "");
    }

    // ── cell_address unit tests ────────────────────────────────────────

    #[test]
    fn cell_address_basic() {
        let hive: u64 = 0x2000_0000;
        let idx: u32 = 0x300;
        let expected = hive + HBIN_START_OFFSET + idx as u64;
        assert_eq!(cell_address(hive, idx), expected);
    }

    #[test]
    fn cell_address_zero_index() {
        let hive: u64 = 0x3000_0000;
        assert_eq!(cell_address(hive, 0), hive + HBIN_START_OFFSET);
    }

    // ── walk_typed_urls tests ────────────────────────────────────────

    /// Empty reader with zero hive_addr → returns empty Vec.
    #[test]
    fn walk_typed_urls_zero_hive() {
        let reader = make_reader();
        let result = walk_typed_urls(&reader, 0, "testuser").unwrap();
        assert!(result.is_empty());
    }

    /// Hive with unreadable root cell → returns empty Vec.
    #[test]
    fn walk_typed_urls_unreadable_hive() {
        let reader = make_reader();
        // Non-zero address but no mapped memory → read fails → empty Vec.
        let result = walk_typed_urls(&reader, 0xDEAD_0000, "bob").unwrap();
        assert!(result.is_empty());
    }

    // ── TypedUrlEntry struct tests ────────────────────────────────────

    #[test]
    fn typed_url_entry_construction() {
        let entry = TypedUrlEntry {
            username: "alice".to_string(),
            url: "https://pastebin.com/abc".to_string(),
            timestamp: 132_000_000_000_000_000,
            is_suspicious: true,
        };
        assert_eq!(entry.username, "alice");
        assert!(entry.is_suspicious);
        assert!(entry.timestamp > 0);
    }

    #[test]
    fn typed_url_entry_serialization() {
        let entry = TypedUrlEntry {
            username: "bob".to_string(),
            url: "https://www.google.com".to_string(),
            timestamp: 0,
            is_suspicious: false,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"username\":\"bob\""));
        assert!(json.contains("\"is_suspicious\":false"));
        assert!(json.contains("\"timestamp\":0"));
    }

    // ── Constants ─────────────────────────────────────────────────────

    #[test]
    fn typed_url_constants_sane() {
        assert_eq!(HBASE_BLOCK_ROOT_CELL_OFFSET, 0x24);
        assert_eq!(HBIN_START_OFFSET, 0x1000);
        assert_eq!(NK_SIGNATURE, 0x6B6E);
        assert_eq!(VK_SIGNATURE, 0x6B76);
        assert!(MAX_TYPED_URLS > 0);
    }

    #[test]
    fn typed_urls_path_components_correct() {
        assert_eq!(TYPED_URLS_PATH[0], "Software");
        assert_eq!(TYPED_URLS_PATH[1], "Microsoft");
        assert_eq!(TYPED_URLS_PATH[2], "Internet Explorer");
        assert_eq!(TYPED_URLS_PATH[3], "TypedURLs");
    }

    #[test]
    fn typed_urls_time_path_components_correct() {
        assert_eq!(TYPED_URLS_TIME_PATH[0], "Software");
        assert_eq!(TYPED_URLS_TIME_PATH[3], "TypedURLsTime");
    }

    // ── walk_typed_urls body coverage ────────────────────────────────
    //
    // walk_typed_urls reads:
    //   1. hive_addr + HBASE_BLOCK_ROOT_CELL_OFFSET (0x24) → root_cell_index
    //   2. root nk cell at cell_address(hive_addr, root_cell_index)
    //   3. NK_SIGNATURE check
    //   4. Subkey navigation: Software → Microsoft → Internet Explorer → TypedURLs
    //
    // We provide synthetic physical memory so the body is exercised
    // past the zero-guard and the root-cell read.

    use memf_core::test_builders::flags;

    fn make_typed_url_isf() -> serde_json::Value {
        IsfBuilder::new()
            .add_struct("_CM_KEY_NODE", 0x50)
            .add_field("_CM_KEY_NODE", "Signature", 0x00, "unsigned short")
            .build_json()
    }

    /// Hive mapped; root_cell_index = 0 → cell_address = hive + HBIN_START_OFFSET;
    /// the cell page is mapped with data that has raw_size=0 → read_cell_data
    /// returns empty Vec → sig check fails → empty result.
    #[test]
    fn walk_typed_urls_root_cell_zero_index_no_nk() {
        let hive_vaddr: u64 = 0x0020_0000;
        let hive_paddr: u64 = 0x0020_0000;

        // cell_address(hive_vaddr, 0) = hive_vaddr + HBIN_START_OFFSET
        // = 0x0020_0000 + 0x1000 = 0x0021_0000
        let cell_page_vaddr: u64 = hive_vaddr + HBIN_START_OFFSET;
        let cell_page_paddr: u64 = cell_page_vaddr;

        let mut hive_page = vec![0u8; 0x1000];
        // root_cell_index at offset 0x24 = 0
        hive_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());

        // cell page: i32 size = 0 at offset 0 → abs_size=0 → read_cell_data returns empty
        let cell_page = vec![0u8; 0x1000];

        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(cell_page_vaddr, cell_page_paddr, flags::WRITABLE)
            .write_phys(cell_page_paddr, &cell_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_typed_urls(&reader, hive_vaddr, "alice").unwrap();
        assert!(result.is_empty(), "empty/bad nk cell → empty Vec");
    }

    /// Hive mapped; root cell has data but wrong signature → empty Vec.
    #[test]
    fn walk_typed_urls_root_cell_wrong_signature() {
        let hive_vaddr: u64 = 0x0030_0000;
        let hive_paddr: u64 = 0x0030_0000;
        let root_cell_index: u32 = 0x00; // cell at hive + HBIN_START_OFFSET + 0
        let cell_page_vaddr: u64 = hive_vaddr + HBIN_START_OFFSET;
        let cell_page_paddr: u64 = cell_page_vaddr;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x24..0x28].copy_from_slice(&root_cell_index.to_le_bytes());

        let mut cell_page = vec![0u8; 0x1000];
        // allocated cell: size = -128 (0x80)
        let raw_size: i32 = -128i32;
        cell_page[0..4].copy_from_slice(&raw_size.to_le_bytes());
        // data[0..2] = 0xDEAD (not NK_SIGNATURE) → sig check fails
        cell_page[4..6].copy_from_slice(&0xDEADu16.to_le_bytes());

        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(cell_page_vaddr, cell_page_paddr, flags::WRITABLE)
            .write_phys(cell_page_paddr, &cell_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_typed_urls(&reader, hive_vaddr, "bob").unwrap();
        assert!(result.is_empty(), "wrong NK_SIGNATURE → empty Vec");
    }

    /// Hive mapped; root nk cell has NK_SIGNATURE but stable_subkey_count=0
    /// → find_subkey("Software") returns None → empty Vec.
    #[test]
    fn walk_typed_urls_root_nk_no_subkeys() {
        let hive_vaddr: u64 = 0x0040_0000;
        let hive_paddr: u64 = 0x0040_0000;
        let root_cell_index: u32 = 0x00;
        let cell_page_vaddr: u64 = hive_vaddr + HBIN_START_OFFSET;
        let cell_page_paddr: u64 = cell_page_vaddr;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x24..0x28].copy_from_slice(&root_cell_index.to_le_bytes());

        let mut cell_page = vec![0u8; 0x1000];
        let raw_size: i32 = -0x80i32;
        cell_page[0..4].copy_from_slice(&raw_size.to_le_bytes());
        // NK_SIGNATURE at data[0..2]
        cell_page[4..6].copy_from_slice(&NK_SIGNATURE.to_le_bytes());
        // stable_subkey_count at nk_data[NK_STABLE_SUBKEY_COUNT_OFFSET..+4]
        // = data[4 + 0x14 .. 4 + 0x18] = 0 (already zero from initialisation)

        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(cell_page_vaddr, cell_page_paddr, flags::WRITABLE)
            .write_phys(cell_page_paddr, &cell_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_typed_urls(&reader, hive_vaddr, "carol").unwrap();
        assert!(result.is_empty(), "no Software subkey → empty Vec");
    }

    /// Hive mapped; root nk has NK_SIGNATURE and a non-zero stable_subkey_count
    /// pointing to a subkeys list cell that has an unknown list signature →
    /// find_subkey returns None → empty Vec.
    #[test]
    fn walk_typed_urls_unknown_list_signature() {
        let hive_vaddr: u64 = 0x0050_0000;
        let hive_paddr: u64 = 0x0050_0000;
        let root_cell_index: u32 = 0x00;
        let cell_page_vaddr: u64 = hive_vaddr + HBIN_START_OFFSET;
        let cell_page_paddr: u64 = cell_page_vaddr;

        // subkeys_list_cell index = 0x80; it lives at same page offset 0x80
        let subkeys_list_cell: u32 = 0x80;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x24..0x28].copy_from_slice(&root_cell_index.to_le_bytes());

        let mut cell_page = vec![0u8; 0x1000];
        // Root nk cell at offset 0 in cell_page:
        let raw_size: i32 = -0x100i32;
        cell_page[0..4].copy_from_slice(&raw_size.to_le_bytes());
        let nk_off = 4usize;
        cell_page[nk_off..nk_off + 2].copy_from_slice(&NK_SIGNATURE.to_le_bytes());
        // stable_subkey_count = 1 at nk_data[0x14] = cell_page[nk_off + 0x14]
        cell_page[nk_off + NK_STABLE_SUBKEY_COUNT_OFFSET..nk_off + NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        // stable_subkeys_list = subkeys_list_cell at nk_data[0x1C]
        cell_page[nk_off + NK_STABLE_SUBKEYS_LIST_OFFSET..nk_off + NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .copy_from_slice(&subkeys_list_cell.to_le_bytes());

        // List cell at offset subkeys_list_cell in cell_page:
        let list_raw_size: i32 = -0x80i32;
        let lc = subkeys_list_cell as usize;
        cell_page[lc..lc + 4].copy_from_slice(&list_raw_size.to_le_bytes());
        // list sig = 0xFFFF (unknown) → match falls through to `_ => {}`
        cell_page[lc + 4..lc + 6].copy_from_slice(&0xFFFFu16.to_le_bytes());
        // count = 0
        cell_page[lc + 6..lc + 8].copy_from_slice(&0u16.to_le_bytes());

        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(cell_page_vaddr, cell_page_paddr, flags::WRITABLE)
            .write_phys(cell_page_paddr, &cell_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_typed_urls(&reader, hive_vaddr, "dave").unwrap();
        assert!(result.is_empty(), "unknown list sig → Software not found → empty Vec");
    }
}
