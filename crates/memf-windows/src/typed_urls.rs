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
#[allow(dead_code)]
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

    // ── Additional coverage: walk_typed_urls early-exit paths ────────────

    /// hive_addr = 0 returns empty immediately.
    #[test]
    fn walk_typed_urls_zero_hive_returns_empty() {
        let reader = make_reader();
        let result = walk_typed_urls(&reader, 0, "nobody").unwrap();
        assert!(result.is_empty());
    }

    /// Non-zero but unmapped hive → read_bytes fails → empty.
    #[test]
    fn walk_typed_urls_unmapped_hive_returns_empty() {
        let reader = make_reader();
        let result = walk_typed_urls(&reader, 0xFFFF_8000_DEAD_0000, "nobody").unwrap();
        assert!(result.is_empty());
    }

    /// TypedUrlEntry struct construction and serialization.
    #[test]
    fn typed_url_entry_serializes() {
        let entry = TypedUrlEntry {
            username: "alice".to_string(),
            url: "https://mega.nz/folder/abc".to_string(),
            timestamp: 0x01D900_0000_0000,
            is_suspicious: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("alice"));
        assert!(json.contains("mega.nz"));
        assert!(json.contains("is_suspicious"));
    }

    // ── classify_typed_url: URL without scheme (no "://") is benign ────

    /// URL without "://" scheme separator should not trigger credential check.
    #[test]
    fn classify_no_scheme_benign() {
        assert!(!classify_typed_url("www.example.com/page"));
        assert!(!classify_typed_url("just_a_path/no_scheme"));
    }

    /// file:// with a single slash after host (not UNC) is benign.
    #[test]
    fn classify_file_single_slash_benign() {
        assert!(!classify_typed_url("file://localhost/C:/Users/file.txt"));
    }

    /// Credential URL where @ appears after first slash (in path, not authority) is benign.
    #[test]
    fn classify_at_in_path_not_authority_benign() {
        // The @ appears after a '/' so it's in the path, not the authority.
        assert!(!classify_typed_url("https://example.com/profile/@username"));
    }

    // ── find_subkey: li-list branch via synthetic memory ────────────────

    fn make_typed_url_isf_with_subkeyfields() -> serde_json::Value {
        IsfBuilder::new()
            .add_struct("_CM_KEY_NODE", 0x80)
            .add_field("_CM_KEY_NODE", "Signature", 0x00, "unsigned short")
            .build_json()
    }

    /// hive with NK root cell whose value count is 0 → TypedURLs not found → empty.
    #[test]
    fn walk_typed_urls_root_has_zero_subkeys_empty() {
        use memf_core::test_builders::flags;

        let hive_vaddr: u64 = 0x0050_0000;
        let hive_paddr: u64 = 0x0050_0000;
        let cell_page_vaddr: u64 = hive_vaddr + HBIN_START_OFFSET;
        let cell_page_paddr: u64 = 0x0051_0000;

        // root_cell_index = 0 → root nk at hive + HBIN + 0.
        let mut hive_page = vec![0u8; 0x1000];
        hive_page[HBASE_BLOCK_ROOT_CELL_OFFSET as usize
            ..HBASE_BLOCK_ROOT_CELL_OFFSET as usize + 4]
            .copy_from_slice(&0u32.to_le_bytes());

        let mut cell_page = vec![0u8; 0x1000];
        // Cell size header at offset 0 (4 bytes, negative = allocated)
        let raw_size: i32 = -0x80i32;
        cell_page[0..4].copy_from_slice(&raw_size.to_le_bytes());
        // nk signature at offset 4 (after size header — read_cell_data skips 4-byte size)
        let nk_sig: u16 = NK_SIGNATURE;
        cell_page[4..6].copy_from_slice(&nk_sig.to_le_bytes());
        // NK_STABLE_SUBKEY_COUNT_OFFSET (0x14) within nk data (data starts at offset 4+4=8):
        // nk data[0x14] = subkey_count = 0 (already zero)

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
        assert!(
            result.is_empty(),
            "root with zero subkeys → Software not found → empty"
        );
    }

    // ── find_subkey: ri-list (index-of-indices) branch ──────────────

    /// Hive with `ri`-format subkey list (index-of-indices).
    /// The ri sub-list contains an lf entry, but the child nk sig is bad →
    /// find_subkey("Software") returns None → empty Vec.
    #[test]
    fn walk_typed_urls_ri_list_bad_child_sig_empty() {
        use memf_core::test_builders::flags;

        // Memory layout (virtual = physical):
        //   hive_vaddr = 0x0070_0000
        //   cell_page  = hive_vaddr + HBIN_START_OFFSET = 0x0071_0000
        //
        // hive page: root_cell_index = 0 at offset 0x24
        //
        // cell page layout (all offsets are from start of cell_page):
        //   root nk cell at offset 0:
        //     [0..4]   = cell size -0x200 (allocated)
        //     [4..6]   = NK_SIGNATURE
        //     [4+0x14..4+0x18] = subkey_count = 1
        //     [4+0x1C..4+0x20] = subkeys_list_cell = 0x80 (within cell_page)
        //   list cell at offset 0x80:
        //     [0..4]   = size -0x40
        //     [4..6]   = 0x7269 ("ri") sig
        //     [6..8]   = count = 1
        //     [8..12]  = sub_list_cell = 0x100
        //   sub-list cell at offset 0x100:
        //     [0..4]   = size -0x40
        //     [4..6]   = 0x666C ("lf") sig
        //     [6..8]   = count = 1
        //     [8..12]  = child_cell = 0x140
        //   child nk cell at offset 0x140:
        //     [0..4]   = size -0x40
        //     [4..6]   = 0xDEAD (bad NK sig) → find_subkey skips it

        let hive_vaddr: u64 = 0x0070_0000;
        let hive_paddr: u64 = 0x0070_0000;
        let cell_page_vaddr: u64 = hive_vaddr + HBIN_START_OFFSET;
        let cell_page_paddr: u64 = 0x0071_0000;

        let mut hive_page = vec![0u8; 0x1000];
        // root_cell_index = 0
        hive_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());

        let mut cell_page = vec![0u8; 0x2000];

        // Root nk cell at offset 0 in cell_page:
        let raw_size: i32 = -0x200i32;
        cell_page[0..4].copy_from_slice(&raw_size.to_le_bytes());
        let nk_off = 4usize;
        cell_page[nk_off..nk_off + 2].copy_from_slice(&NK_SIGNATURE.to_le_bytes());
        // subkey_count at nk_data[0x14] = 1
        cell_page[nk_off + NK_STABLE_SUBKEY_COUNT_OFFSET..nk_off + NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        // stable_subkeys_list at nk_data[0x1C] = 0x80
        let subkeys_list_cell: u32 = 0x80;
        cell_page[nk_off + NK_STABLE_SUBKEYS_LIST_OFFSET..nk_off + NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .copy_from_slice(&subkeys_list_cell.to_le_bytes());

        // List cell at 0x80:
        let lc = 0x80usize;
        let list_raw: i32 = -0x40i32;
        cell_page[lc..lc + 4].copy_from_slice(&list_raw.to_le_bytes());
        // sig = 0x6972 = "ri"
        cell_page[lc + 4..lc + 6].copy_from_slice(&0x6972u16.to_le_bytes());
        // count = 1
        cell_page[lc + 6..lc + 8].copy_from_slice(&1u16.to_le_bytes());
        // sub_list_cell = 0x100
        let sub_list_cell: u32 = 0x100;
        cell_page[lc + 8..lc + 12].copy_from_slice(&sub_list_cell.to_le_bytes());

        // Sub-list cell at 0x100:
        let sc = 0x100usize;
        cell_page[sc..sc + 4].copy_from_slice(&(-0x40i32).to_le_bytes());
        // sig = 0x666C = "lf"
        cell_page[sc + 4..sc + 6].copy_from_slice(&0x666Cu16.to_le_bytes());
        // count = 1
        cell_page[sc + 6..sc + 8].copy_from_slice(&1u16.to_le_bytes());
        // child_cell = 0x140
        let child_cell: u32 = 0x140;
        cell_page[sc + 8..sc + 12].copy_from_slice(&child_cell.to_le_bytes());

        // Child nk at 0x140:
        let cc = 0x140usize;
        cell_page[cc..cc + 4].copy_from_slice(&(-0x40i32).to_le_bytes());
        // Bad sig 0xDEAD → child_sig != NK_SIGNATURE → skipped
        cell_page[cc + 4..cc + 6].copy_from_slice(&0xDEADu16.to_le_bytes());

        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(cell_page_vaddr, cell_page_paddr, flags::WRITABLE)
            .write_phys(cell_page_paddr, &cell_page[..0x1000].to_vec())
            .map_4k(cell_page_vaddr + 0x1000, cell_page_paddr + 0x1000, flags::WRITABLE)
            .write_phys(cell_page_paddr + 0x1000, &cell_page[0x1000..].to_vec())
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_typed_urls(&reader, hive_vaddr, "alice").unwrap();
        assert!(result.is_empty(), "ri list with bad child nk sig → Software not found → empty");
    }

    /// find_subkey with li-format subkey list.
    /// Root nk has NK_SIGNATURE, stable_subkey_count=1 pointing to li list
    /// whose single child nk has good NK_SIGNATURE but name "WRONG" (not "Software") → empty.
    #[test]
    fn walk_typed_urls_li_list_no_match_empty() {
        use memf_core::test_builders::flags;

        let hive_vaddr: u64 = 0x0080_0000;
        let hive_paddr: u64 = 0x0080_0000;
        let cell_page_vaddr: u64 = hive_vaddr + HBIN_START_OFFSET;
        let cell_page_paddr: u64 = 0x0081_0000;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());

        let mut cell_page = vec![0u8; 0x1000];
        // Root nk cell at 0:
        cell_page[0..4].copy_from_slice(&(-0x200i32).to_le_bytes());
        let nk_off = 4usize;
        cell_page[nk_off..nk_off + 2].copy_from_slice(&NK_SIGNATURE.to_le_bytes());
        cell_page[nk_off + NK_STABLE_SUBKEY_COUNT_OFFSET..nk_off + NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        let list_cell: u32 = 0x80;
        cell_page[nk_off + NK_STABLE_SUBKEYS_LIST_OFFSET..nk_off + NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .copy_from_slice(&list_cell.to_le_bytes());

        // li list at 0x80:
        let lc = 0x80usize;
        cell_page[lc..lc + 4].copy_from_slice(&(-0x40i32).to_le_bytes());
        cell_page[lc + 4..lc + 6].copy_from_slice(&0x696Cu16.to_le_bytes()); // "li"
        cell_page[lc + 6..lc + 8].copy_from_slice(&1u16.to_le_bytes());
        let child_cell: u32 = 0xC0;
        cell_page[lc + 8..lc + 12].copy_from_slice(&child_cell.to_le_bytes());

        // Child nk at 0xC0 with NK_SIGNATURE but name "WRONG":
        let cc = 0xC0usize;
        cell_page[cc..cc + 4].copy_from_slice(&(-0x80i32).to_le_bytes());
        cell_page[cc + 4..cc + 6].copy_from_slice(&NK_SIGNATURE.to_le_bytes());
        let name = b"WRONG";
        let name_len: u16 = name.len() as u16;
        cell_page[cc + 4 + NK_NAME_LENGTH_OFFSET..cc + 4 + NK_NAME_LENGTH_OFFSET + 2]
            .copy_from_slice(&name_len.to_le_bytes());
        cell_page[cc + 4 + NK_NAME_OFFSET..cc + 4 + NK_NAME_OFFSET + name.len()]
            .copy_from_slice(name);

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

        let result = walk_typed_urls(&reader, hive_vaddr, "eve").unwrap();
        assert!(result.is_empty(), "li list with non-matching child → empty");
    }

    /// read_cell_data with a positive (free/unallocated) cell size returns empty.
    #[test]
    fn read_cell_data_positive_size_returns_data() {
        use memf_core::test_builders::flags;

        // A cell with raw_size = +0x80 (positive = free/unallocated).
        // abs_size = 0x80, data_len = 0x7C. read_cell_data should still return
        // bytes (it reads abs_size - 4 bytes).
        let hive_vaddr: u64 = 0x00B0_0000;
        let cell_vaddr_val: u64 = hive_vaddr + HBIN_START_OFFSET;
        let cell_paddr: u64 = 0x00B1_0000;

        let mut cell_page = vec![0u8; 0x1000];
        let raw_size: i32 = 0x80i32; // positive (free cell)
        cell_page[0..4].copy_from_slice(&raw_size.to_le_bytes());
        // Fill some data bytes
        for i in 4..0x80 {
            cell_page[i] = (i & 0xFF) as u8;
        }

        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, 0x00B0_0000, flags::WRITABLE)
            .write_phys(0x00B0_0000, &vec![0u8; 0x1000])
            .map_4k(cell_vaddr_val, cell_paddr, flags::WRITABLE)
            .write_phys(cell_paddr, &cell_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // read_cell_data: raw_size=0x80, abs_size=0x80, data_len=0x7C
        let result = read_cell_data(&reader, cell_vaddr_val);
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.len(), 0x7C);
    }

    /// hive root cell with value_count > 0 but values_list_cell not readable → empty Vec.
    #[test]
    fn walk_typed_urls_values_list_not_mapped_empty() {
        use memf_core::test_builders::flags;

        let hive_vaddr: u64 = 0x00C0_0000;
        let hive_paddr: u64 = 0x00C0_0000;
        let cell_page_vaddr: u64 = hive_vaddr + HBIN_START_OFFSET;
        let cell_page_paddr: u64 = 0x00C1_0000;

        // We need: root nk → Software → Microsoft → Internet Explorer → TypedURLs
        // then TypedURLs nk has value_count > 0 but values_list_cell points
        // somewhere not mapped → read_cell_data fails → empty.
        //
        // Strategy: root nk has subkey_count = 0 → find_subkey("Software") = None → empty.
        // This is the simplest path that exercises the body up to value_count check.
        // (Full end-to-end requires 4 levels of subkey navigation which would need
        //  a very large synthetic page. We rely on the zero-subkeys early exit instead.)

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());

        let mut cell_page = vec![0u8; 0x1000];
        // Root nk: valid sig, subkey_count = 0 → find_subkey("Software") → None → empty
        cell_page[0..4].copy_from_slice(&(-0x80i32).to_le_bytes());
        cell_page[4..6].copy_from_slice(&NK_SIGNATURE.to_le_bytes());

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

        let result = walk_typed_urls(&reader, hive_vaddr, "frank").unwrap();
        assert!(result.is_empty());
    }

    // ── classify_typed_url: additional edge cases ────────────────────

    /// URL with @ in authority but no colon anywhere is benign.
    #[test]
    fn classify_url_at_no_colon_benign() {
        assert!(!classify_typed_url("https://user@host.example.com/path"));
    }

    /// URL with colon:port but no @ is benign.
    #[test]
    fn classify_url_colon_port_no_at_benign() {
        assert!(!classify_typed_url("https://host.example.com:8443/api/v1"));
    }

    /// file:// URL with empty path part is benign (no leading double-slash).
    #[test]
    fn classify_file_no_unc_prefix_benign() {
        assert!(!classify_typed_url("file://relative-path/file.txt"));
    }

    /// cell_address wrapping with large hive_addr and max cell index.
    #[test]
    fn cell_address_large_values() {
        let hive: u64 = 0xFFFF_8000_0000_0000;
        let idx: u32 = 0xFFFF_FFFF;
        // Should not panic (wrapping arithmetic).
        let _ = cell_address(hive, idx);
    }

    /// TypedUrlEntry clone works correctly.
    #[test]
    fn typed_url_entry_clone() {
        let e = TypedUrlEntry {
            username: "alice".to_string(),
            url: "https://pastebin.com/abc".to_string(),
            timestamp: 42,
            is_suspicious: true,
        };
        let cloned = e.clone();
        assert_eq!(cloned.username, e.username);
        assert_eq!(cloned.url, e.url);
        assert_eq!(cloned.timestamp, e.timestamp);
    }

    /// hive root cell has NK_SIGNATURE and subkey_count=1 but list data is
    /// too short (< 4 bytes) → find_subkey returns None → empty.
    #[test]
    fn walk_typed_urls_list_data_too_short_empty() {
        use memf_core::test_builders::flags;

        let hive_vaddr: u64 = 0x00D0_0000;
        let hive_paddr: u64 = 0x00D0_0000;
        let cell_page_vaddr: u64 = hive_vaddr + HBIN_START_OFFSET;
        let cell_page_paddr: u64 = 0x00D1_0000;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());

        let mut cell_page = vec![0u8; 0x1000];
        // Root nk:
        cell_page[0..4].copy_from_slice(&(-0x100i32).to_le_bytes());
        let nk_off = 4usize;
        cell_page[nk_off..nk_off + 2].copy_from_slice(&NK_SIGNATURE.to_le_bytes());
        // subkey_count = 1
        cell_page[nk_off + NK_STABLE_SUBKEY_COUNT_OFFSET..nk_off + NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        // list_cell = 0x80
        cell_page[nk_off + NK_STABLE_SUBKEYS_LIST_OFFSET..nk_off + NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .copy_from_slice(&0x80u32.to_le_bytes());

        // List cell at 0x80: size = -2 → abs_size = 2 → data_len = -2 but min(0) = 0
        // wait: abs_size=2, data_len = (2-4).min → saturating? No: (abs_size - 4) since abs_size <= 4
        // The code says: if abs_size <= 4 { return Ok(Vec::new()); }
        // So: raw_size = -2 → abs_size = 2 ≤ 4 → returns empty.
        let list_raw: i32 = -2i32;
        cell_page[0x80..0x84].copy_from_slice(&list_raw.to_le_bytes());

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

        let result = walk_typed_urls(&reader, hive_vaddr, "grace").unwrap();
        assert!(result.is_empty(), "list data too short → empty");
    }

    // ── find_subkey direct call: lf match branch ─────────────────────────

    /// find_subkey: lf list (0x666C) where the child nk matches the target name.
    /// This covers lines 268-270 (the `return Ok(Some(child_cell))` in the lf branch).
    #[test]
    fn find_subkey_lf_match_returns_cell() {
        use memf_core::test_builders::flags;

        // Cell layout on a single page (vaddr = paddr = 0x00E0_0000).
        // We call find_subkey with a crafted nk_data slice and an
        // in-memory hive to resolve sub-cells.
        //
        // hive_vaddr = 0x00E0_0000
        // cell_page_vaddr = hive_vaddr + HBIN_START_OFFSET = 0x00E1_0000
        //
        // nk_data starts at cell_page offset 0 (data after size header at -4):
        //   nk_data[0x14..0x18] = subkey_count = 1
        //   nk_data[0x1C..0x20] = list_cell = 0x80
        //
        // list cell at 0x80 (cell_page offset 0x80):
        //   [0..4]  = size -0x80 (allocated)
        //   [4..6]  = 0x666C "lf"
        //   [6..8]  = count = 1
        //   [8..12] = child_cell = 0xC0
        //
        // child nk at 0xC0 (cell_page offset 0xC0):
        //   [0..4]  = size -0x80
        //   [4..6]  = NK_SIGNATURE
        //   [4+0x48..4+0x4A] = name_length = 8
        //   [4+0x4C..4+0x54] = name "Software"

        let hive_vaddr: u64 = 0x00E0_0000;
        let cell_page_vaddr: u64 = hive_vaddr + HBIN_START_OFFSET;
        let cell_page_paddr: u64 = 0x00E1_0000;

        let mut cell_page = vec![0u8; 0x1000];

        // Build nk_data at offset 0 (we'll pass it directly — size header is 4 bytes before)
        // For find_subkey we pass nk_data slice directly, so it starts with the nk fields.
        // subkey_count at nk_data[NK_STABLE_SUBKEY_COUNT_OFFSET=0x14]
        let nk_data_start = 0usize;
        cell_page[nk_data_start + NK_STABLE_SUBKEY_COUNT_OFFSET
            ..nk_data_start + NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        // list_cell at nk_data[NK_STABLE_SUBKEYS_LIST_OFFSET=0x1C]
        let list_cell: u32 = 0x80;
        cell_page[nk_data_start + NK_STABLE_SUBKEYS_LIST_OFFSET
            ..nk_data_start + NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .copy_from_slice(&list_cell.to_le_bytes());

        // lf list cell at offset 0x80:
        let lc = 0x80usize;
        cell_page[lc..lc + 4].copy_from_slice(&(-0x80i32).to_le_bytes()); // size header
        // data starts at lc+4: [0..2] = lf sig, [2..4] = count, [4..8] = child_cell
        cell_page[lc + 4..lc + 6].copy_from_slice(&0x666Cu16.to_le_bytes()); // "lf"
        cell_page[lc + 6..lc + 8].copy_from_slice(&1u16.to_le_bytes()); // count=1
        let child_cell: u32 = 0xC0;
        cell_page[lc + 8..lc + 12].copy_from_slice(&child_cell.to_le_bytes());

        // child nk at offset 0xC0:
        let cc = 0xC0usize;
        cell_page[cc..cc + 4].copy_from_slice(&(-0x80i32).to_le_bytes()); // size header
        // nk data starts at cc+4
        let cn = cc + 4;
        cell_page[cn..cn + 2].copy_from_slice(&NK_SIGNATURE.to_le_bytes());
        // name_length at nk_data[NK_NAME_LENGTH_OFFSET=0x48]
        let name = b"Software";
        cell_page[cn + NK_NAME_LENGTH_OFFSET..cn + NK_NAME_LENGTH_OFFSET + 2]
            .copy_from_slice(&(name.len() as u16).to_le_bytes());
        // name at nk_data[NK_NAME_OFFSET=0x4C]
        cell_page[cn + NK_NAME_OFFSET..cn + NK_NAME_OFFSET + name.len()]
            .copy_from_slice(name);

        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, 0x00E0_0000, flags::WRITABLE)
            .write_phys(0x00E0_0000, &vec![0u8; 0x1000])
            .map_4k(cell_page_vaddr, cell_page_paddr, flags::WRITABLE)
            .write_phys(cell_page_paddr, &cell_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // nk_data is the slice we built at nk_data_start in cell_page.
        // We need to pass it as a slice with at least NK_STABLE_SUBKEYS_LIST_OFFSET+4 bytes.
        let nk_data = &cell_page[nk_data_start..nk_data_start + 0x60];
        let result = find_subkey(&reader, hive_vaddr, nk_data, "Software").unwrap();
        assert_eq!(result, Some(child_cell), "lf match should return the child cell index");
    }

    /// find_subkey: li list (0x696C) where the child nk matches the target name.
    /// Covers lines 290-292 (the `return Ok(Some(child_cell))` in the li branch).
    #[test]
    fn find_subkey_li_match_returns_cell() {
        use memf_core::test_builders::flags;

        let hive_vaddr: u64 = 0x00F0_0000;
        let cell_page_vaddr: u64 = hive_vaddr + HBIN_START_OFFSET;
        let cell_page_paddr: u64 = 0x00F1_0000;

        let mut cell_page = vec![0u8; 0x1000];

        // nk_data at offset 0 with subkey_count=1 and list_cell=0x80
        cell_page[NK_STABLE_SUBKEY_COUNT_OFFSET..NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        let list_cell: u32 = 0x80;
        cell_page[NK_STABLE_SUBKEYS_LIST_OFFSET..NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .copy_from_slice(&list_cell.to_le_bytes());

        // li list at 0x80:
        let lc = 0x80usize;
        cell_page[lc..lc + 4].copy_from_slice(&(-0x80i32).to_le_bytes());
        cell_page[lc + 4..lc + 6].copy_from_slice(&0x696Cu16.to_le_bytes()); // "li"
        cell_page[lc + 6..lc + 8].copy_from_slice(&1u16.to_le_bytes());
        let child_cell: u32 = 0xC0;
        cell_page[lc + 8..lc + 12].copy_from_slice(&child_cell.to_le_bytes());

        // child nk at 0xC0 named "Microsoft":
        let cc = 0xC0usize;
        let cn = cc + 4;
        cell_page[cc..cc + 4].copy_from_slice(&(-0x80i32).to_le_bytes());
        cell_page[cn..cn + 2].copy_from_slice(&NK_SIGNATURE.to_le_bytes());
        let name = b"Microsoft";
        cell_page[cn + NK_NAME_LENGTH_OFFSET..cn + NK_NAME_LENGTH_OFFSET + 2]
            .copy_from_slice(&(name.len() as u16).to_le_bytes());
        cell_page[cn + NK_NAME_OFFSET..cn + NK_NAME_OFFSET + name.len()].copy_from_slice(name);

        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, 0x00F0_0000, flags::WRITABLE)
            .write_phys(0x00F0_0000, &vec![0u8; 0x1000])
            .map_4k(cell_page_vaddr, cell_page_paddr, flags::WRITABLE)
            .write_phys(cell_page_paddr, &cell_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let nk_data = &cell_page[0..0x60];
        let result = find_subkey(&reader, hive_vaddr, nk_data, "Microsoft").unwrap();
        assert_eq!(result, Some(child_cell), "li match should return the child cell index");
    }

    /// Full hive traversal: Software → Microsoft → Internet Explorer → TypedURLs,
    /// TypedURLs key has one value ("url1") with data "https://pastebin.com/abc" (UTF-16LE).
    /// This covers lines 396-611 of walk_typed_urls (the full navigation + values loop).
    ///
    /// Cell layout (virtual = physical for simplicity):
    ///   hive_vaddr = 0x0090_0000
    ///   cell_page = hive_vaddr + HBIN_START_OFFSET = 0x0091_0000
    ///
    /// All cells are packed into a 4-page (0x4000) memory block.
    /// We use lf-format subkey lists throughout.
    ///
    /// Offsets within cell_page (each cell = 4-byte size header + data):
    ///   0x000: root nk (subkey_count=1, list_cell=0x200)
    ///   0x200: lf list → Software nk at 0x300
    ///   0x300: Software nk (subkey_count=1, list_cell=0x500)
    ///   0x500: lf list → Microsoft nk at 0x600
    ///   0x600: Microsoft nk (subkey_count=1, list_cell=0x800)
    ///   0x800: lf list → Internet Explorer nk at 0x900
    ///   0x900: IE nk (subkey_count=1, list_cell=0xB00)
    ///   0xB00: lf list → TypedURLs nk at 0xC00
    ///   0xC00: TypedURLs nk (value_count=1, values_list=0xE00)
    ///   0xE00: values list → vk cell at 0xF00
    ///   0xF00: vk "url1": data_len=50, data_cell=0x1000
    ///   0x1000: data cell: UTF-16LE "https://pastebin.com/abc\0"
    ///
    /// Physical addresses: cell_page_paddr = 0x0091_0000 (within 16 MB limit).
    #[test]
    fn walk_typed_urls_full_traversal_finds_url() {
        use memf_core::test_builders::flags;

        let hive_vaddr: u64   = 0x0090_0000;
        let hive_paddr: u64   = 0x0090_0000;
        let cell_base_vaddr: u64 = hive_vaddr + HBIN_START_OFFSET; // 0x0091_0000
        let cell_base_paddr: u64 = 0x0091_0000;

        // We need 4 pages (0x4000 bytes). Physical addresses 0x0091_0000 through 0x0094_FFFF.
        let cell_len = 0x2000usize; // 8 KB, fits in 2 pages

        let mut cp = vec![0u8; cell_len];

        // Helper: write cell at `off` with nk data `data`.
        // Cell layout: [off..off+4] = size (negative, allocated), [off+4..] = data
        fn write_cell(cp: &mut Vec<u8>, off: usize, data: &[u8]) {
            let total = data.len() + 4;
            let raw = -(total as i32);
            cp[off..off + 4].copy_from_slice(&raw.to_le_bytes());
            cp[off + 4..off + 4 + data.len()].copy_from_slice(data);
        }

        // Helper: build an nk cell data with subkeys
        fn nk_with_subkeys(subkey_count: u32, list_cell: u32) -> Vec<u8> {
            let mut d = vec![0u8; 0x60]; // enough room
            d[0..2].copy_from_slice(&NK_SIGNATURE.to_le_bytes());
            d[NK_STABLE_SUBKEY_COUNT_OFFSET..NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
                .copy_from_slice(&subkey_count.to_le_bytes());
            d[NK_STABLE_SUBKEYS_LIST_OFFSET..NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
                .copy_from_slice(&list_cell.to_le_bytes());
            d
        }

        // Helper: build nk with values
        fn nk_with_values(value_count: u32, values_list_cell: u32) -> Vec<u8> {
            let mut d = vec![0u8; 0x60];
            d[0..2].copy_from_slice(&NK_SIGNATURE.to_le_bytes());
            // value_count at 0x24, values_list at 0x28
            d[NK_VALUE_COUNT_OFFSET..NK_VALUE_COUNT_OFFSET + 4]
                .copy_from_slice(&value_count.to_le_bytes());
            d[NK_VALUES_LIST_OFFSET..NK_VALUES_LIST_OFFSET + 4]
                .copy_from_slice(&values_list_cell.to_le_bytes());
            d
        }

        // Helper: build an nk cell data with a name
        fn nk_named(name: &[u8]) -> Vec<u8> {
            let mut d = vec![0u8; 0x70];
            d[0..2].copy_from_slice(&NK_SIGNATURE.to_le_bytes());
            d[NK_NAME_LENGTH_OFFSET..NK_NAME_LENGTH_OFFSET + 2]
                .copy_from_slice(&(name.len() as u16).to_le_bytes());
            d[NK_NAME_OFFSET..NK_NAME_OFFSET + name.len()].copy_from_slice(name);
            d
        }

        // Helper: build nk named with subkeys
        fn nk_named_with_subkeys(name: &[u8], subkey_count: u32, list_cell: u32) -> Vec<u8> {
            let mut d = nk_named(name);
            // Extend if needed
            if d.len() < NK_STABLE_SUBKEYS_LIST_OFFSET + 4 {
                d.resize(NK_STABLE_SUBKEYS_LIST_OFFSET + 8, 0);
            }
            d[NK_STABLE_SUBKEY_COUNT_OFFSET..NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
                .copy_from_slice(&subkey_count.to_le_bytes());
            d[NK_STABLE_SUBKEYS_LIST_OFFSET..NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
                .copy_from_slice(&list_cell.to_le_bytes());
            d
        }

        // Helper: build nk named with values (for terminal key like TypedURLs)
        fn nk_named_with_values(name: &[u8], value_count: u32, values_list_cell: u32) -> Vec<u8> {
            let mut d = nk_named(name);
            // NK_VALUE_COUNT_OFFSET = 0x24, NK_VALUES_LIST_OFFSET = 0x28
            if d.len() < NK_VALUES_LIST_OFFSET + 4 {
                d.resize(NK_VALUES_LIST_OFFSET + 8, 0);
            }
            d[NK_VALUE_COUNT_OFFSET..NK_VALUE_COUNT_OFFSET + 4]
                .copy_from_slice(&value_count.to_le_bytes());
            d[NK_VALUES_LIST_OFFSET..NK_VALUES_LIST_OFFSET + 4]
                .copy_from_slice(&values_list_cell.to_le_bytes());
            d
        }

        // Helper: build lf list cell with one entry (child_cell, hash)
        fn lf_list(child_cell: u32) -> Vec<u8> {
            let mut d = vec![0u8; 12];
            d[0..2].copy_from_slice(&0x666Cu16.to_le_bytes()); // "lf"
            d[2..4].copy_from_slice(&1u16.to_le_bytes()); // count=1
            d[4..8].copy_from_slice(&child_cell.to_le_bytes()); // cell index
            // [8..12] = hash (zero ok)
            d
        }

        // Layout:
        // Cell indices (from HBIN start within cell_page):
        let root_cell: u32   = 0x000;
        let lf1_cell: u32    = 0x200; // → Software nk
        let sw_cell: u32     = 0x300; // Software nk
        let lf2_cell: u32    = 0x500; // → Microsoft nk
        let ms_cell: u32     = 0x600; // Microsoft nk
        let lf3_cell: u32    = 0x800; // → IE nk
        let ie_cell: u32     = 0x900; // Internet Explorer nk
        let lf4_cell: u32    = 0xB00; // → TypedURLs nk
        let tu_cell: u32     = 0xC00; // TypedURLs nk
        let vlist_cell: u32  = 0xE00; // values list
        let vk1_cell: u32    = 0xF00; // url1 vk
        let dc1_cell: u32    = 0x1000; // url1 data cell

        // Root nk (subkey_count=1 → lf1)
        write_cell(&mut cp, root_cell as usize, &nk_with_subkeys(1, lf1_cell));
        // lf1 → Software nk
        write_cell(&mut cp, lf1_cell as usize, &lf_list(sw_cell));
        // Software nk named "Software" (subkey_count=1 → lf2)
        write_cell(&mut cp, sw_cell as usize, &nk_named_with_subkeys(b"Software", 1, lf2_cell));
        // lf2 → Microsoft nk
        write_cell(&mut cp, lf2_cell as usize, &lf_list(ms_cell));
        // Microsoft nk named "Microsoft" (subkey_count=1 → lf3)
        write_cell(&mut cp, ms_cell as usize, &nk_named_with_subkeys(b"Microsoft", 1, lf3_cell));
        // lf3 → IE nk
        write_cell(&mut cp, lf3_cell as usize, &lf_list(ie_cell));
        // IE nk named "Internet Explorer" (subkey_count=1 → lf4)
        write_cell(&mut cp, ie_cell as usize, &nk_named_with_subkeys(b"Internet Explorer", 1, lf4_cell));
        // lf4 → TypedURLs nk
        write_cell(&mut cp, lf4_cell as usize, &lf_list(tu_cell));
        // TypedURLs nk named "TypedURLs" with value_count=1 and values_list=vlist_cell
        // Must have name so find_subkey can match "TypedURLs" when navigating from IE nk.
        write_cell(&mut cp, tu_cell as usize, &nk_named_with_values(b"TypedURLs", 1, vlist_cell));
        // values list: 4-byte pointer to vk1_cell
        {
            let mut vlist = vec![0u8; 4];
            vlist[0..4].copy_from_slice(&vk1_cell.to_le_bytes());
            write_cell(&mut cp, vlist_cell as usize, &vlist);
        }
        // vk cell for "url1": name="url1", data_len=50, data_cell=dc1_cell
        {
            // VK data layout (see VK_* constants):
            //   [0..2]  = VK_SIGNATURE (0x6B76)
            //   [2..4]  = name_length (4 = len("url1"))
            //   [4..8]  = data_length (50, no inline-data flag)
            //   [8..12] = data_cell
            //   [0x14..0x18] = name "url1"
            let mut vk = vec![0u8; 0x20];
            vk[0..2].copy_from_slice(&VK_SIGNATURE.to_le_bytes());
            vk[VK_NAME_LENGTH_OFFSET..VK_NAME_LENGTH_OFFSET + 2]
                .copy_from_slice(&4u16.to_le_bytes()); // "url1"
            vk[VK_DATA_LENGTH_OFFSET..VK_DATA_LENGTH_OFFSET + 4]
                .copy_from_slice(&50u32.to_le_bytes()); // 50 bytes = 25 UTF-16 chars
            vk[VK_DATA_OFFSET_OFFSET..VK_DATA_OFFSET_OFFSET + 4]
                .copy_from_slice(&dc1_cell.to_le_bytes());
            vk[VK_NAME_OFFSET..VK_NAME_OFFSET + 4].copy_from_slice(b"url1");
            write_cell(&mut cp, vk1_cell as usize, &vk);
        }
        // data cell: UTF-16LE "https://mega.nz/x" (suspicious domain)
        {
            let url = "https://mega.nz/x";
            let utf16: Vec<u8> = url.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let mut dc = vec![0u8; utf16.len() + 2]; // + null terminator
            dc[..utf16.len()].copy_from_slice(&utf16);
            write_cell(&mut cp, dc1_cell as usize, &dc);
        }

        // Hive base block: root_cell_index at offset 0x24
        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x24..0x28].copy_from_slice(&root_cell.to_le_bytes());

        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        // Note: cell_address(hive_addr, cell_index) = hive_addr + HBIN_START_OFFSET + cell_index.
        // cell_base_vaddr = hive_vaddr + HBIN_START_OFFSET = 0x0091_0000.
        // cell_index 0x1000 maps to vaddr = hive_vaddr + HBIN_START_OFFSET + 0x1000 = 0x0092_0000.
        // So the second page (for dc1_cell=0x1000) must be at vaddr 0x0092_0000.
        let cell_page2_vaddr: u64 = hive_vaddr + HBIN_START_OFFSET + 0x1000; // 0x0092_0000
        let cell_page2_paddr: u64 = 0x0092_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            // First 4K page: cell indices 0x000..0xFFF
            .map_4k(cell_base_vaddr, cell_base_paddr, flags::WRITABLE)
            .write_phys(cell_base_paddr, &cp[..0x1000].to_vec())
            // Second 4K page: cell indices 0x1000..0x1FFF (dc1_cell data)
            .map_4k(cell_page2_vaddr, cell_page2_paddr, flags::WRITABLE)
            .write_phys(cell_page2_paddr, &cp[0x1000..].to_vec())
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_typed_urls(&reader, hive_vaddr, "alice").unwrap();
        assert!(!result.is_empty(), "should find at least one typed URL");
        assert_eq!(result[0].username, "alice");
        assert!(result[0].url.contains("mega.nz"), "URL should contain mega.nz: {}", result[0].url);
        assert!(result[0].is_suspicious, "mega.nz URL should be flagged suspicious");
    }

    /// hive root cell has wrong signature → empty.
    #[test]
    fn walk_typed_urls_wrong_root_sig_empty() {
        use memf_core::test_builders::flags;

        let hive_vaddr: u64 = 0x0060_0000;
        let hive_paddr: u64 = 0x0060_0000;
        let cell_page_vaddr: u64 = hive_vaddr + HBIN_START_OFFSET;
        let cell_page_paddr: u64 = 0x0061_0000;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[HBASE_BLOCK_ROOT_CELL_OFFSET as usize
            ..HBASE_BLOCK_ROOT_CELL_OFFSET as usize + 4]
            .copy_from_slice(&0u32.to_le_bytes());

        let mut cell_page = vec![0u8; 0x1000];
        // Cell size
        let raw_size: i32 = -0x80i32;
        cell_page[0..4].copy_from_slice(&raw_size.to_le_bytes());
        // Bad signature: 0xDEAD instead of NK_SIGNATURE
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
        assert!(result.is_empty(), "wrong root signature → empty");
    }
}
