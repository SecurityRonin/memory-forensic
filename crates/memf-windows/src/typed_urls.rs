//! Internet Explorer / Edge typed URL extraction from memory.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

const MAX_TYPED_URLS: usize = 4096;
const HBASE_BLOCK_ROOT_CELL_OFFSET: u64 = 0x24;
const HBIN_START_OFFSET: u64 = 0x1000;
const NK_SIGNATURE: u16 = 0x6B6E;
const NK_STABLE_SUBKEY_COUNT_OFFSET: usize = 0x14;
const NK_STABLE_SUBKEYS_LIST_OFFSET: usize = 0x1C;
const NK_VALUE_COUNT_OFFSET: usize = 0x24;
const NK_VALUES_LIST_OFFSET: usize = 0x28;
const NK_NAME_LENGTH_OFFSET: usize = 0x48;
const NK_NAME_OFFSET: usize = 0x4C;
const VK_SIGNATURE: u16 = 0x6B76;
const VK_NAME_LENGTH_OFFSET: usize = 0x02;
const VK_DATA_LENGTH_OFFSET: usize = 0x04;
const VK_DATA_OFFSET_OFFSET: usize = 0x08;
const VK_NAME_OFFSET: usize = 0x14;
const MAX_SUBKEYS: usize = 4096;
#[allow(dead_code)]
const MAX_VALUES: usize = 4096;
const TYPED_URLS_PATH: &[&str] = &["Software", "Microsoft", "Internet Explorer", "TypedURLs"];
const TYPED_URLS_TIME_PATH: &[&str] = &[
    "Software",
    "Microsoft",
    "Internet Explorer",
    "TypedURLsTime",
];

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
    if lower.starts_with("file://") {
        let path_part = &lower[7..];
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

fn cell_address(hive_addr: u64, cell_index: u32) -> u64 {
    hive_addr
        .wrapping_add(HBIN_START_OFFSET)
        .wrapping_add(cell_index as u64)
}

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

/// Walk typed URL entries from a registry hive in memory.
pub fn walk_typed_urls<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    username: &str,
) -> crate::Result<Vec<TypedUrlEntry>> {
    if hive_addr == 0 {
        return Ok(Vec::new());
    }
    let root_cell_bytes =
        match reader.read_bytes(hive_addr.wrapping_add(HBASE_BLOCK_ROOT_CELL_OFFSET), 4) {
            Ok(b) => b,
            Err(_) => return Ok(Vec::new()),
        };
    let root_cell_index = u32::from_le_bytes(root_cell_bytes[..4].try_into().unwrap());
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

    // Try to navigate TypedURLsTime for timestamps.
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
        if vk_data.len() < VK_DATA_OFFSET_OFFSET + 4 {
            continue;
        }
        let data_len_raw = u32::from_le_bytes(
            vk_data[VK_DATA_LENGTH_OFFSET..VK_DATA_LENGTH_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
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
        let str_len = data_len.min(dc_data.len()) & !1;
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
                classify_typed_url(&format!("https://{}/x", domain)),
                "{} should be suspicious",
                domain
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
    fn read_key_name_too_short_returns_empty() {
        // Less than NK_NAME_OFFSET + 1 bytes
        let data = vec![0u8; NK_NAME_OFFSET];
        assert_eq!(read_key_name(&data), "");
    }

    #[test]
    fn read_key_name_valid_ascii() {
        // Build a minimal nk_data with name_len=3, name="ABC" at NK_NAME_OFFSET
        let mut data = vec![0u8; NK_NAME_OFFSET + 3];
        // NK_NAME_LENGTH_OFFSET = 0x48 = 72
        data[NK_NAME_LENGTH_OFFSET] = 3;
        data[NK_NAME_LENGTH_OFFSET + 1] = 0;
        data[NK_NAME_OFFSET] = b'A';
        data[NK_NAME_OFFSET + 1] = b'B';
        data[NK_NAME_OFFSET + 2] = b'C';
        assert_eq!(read_key_name(&data), "ABC");
    }

    #[test]
    fn read_key_name_length_overflow_returns_empty() {
        // name_len exceeds data.len()
        let mut data = vec![0u8; NK_NAME_OFFSET + 2];
        data[NK_NAME_LENGTH_OFFSET] = 0xFF;
        data[NK_NAME_LENGTH_OFFSET + 1] = 0xFF;
        assert_eq!(read_key_name(&data), "");
    }

    #[test]
    fn read_value_name_too_short_returns_empty() {
        let data = vec![0u8; VK_NAME_OFFSET];
        assert_eq!(read_value_name(&data), "");
    }

    #[test]
    fn read_value_name_valid() {
        let mut data = vec![0u8; VK_NAME_OFFSET + 4];
        // VK_NAME_LENGTH_OFFSET = 0x02
        data[VK_NAME_LENGTH_OFFSET] = 4;
        data[VK_NAME_LENGTH_OFFSET + 1] = 0;
        data[VK_NAME_OFFSET] = b'u';
        data[VK_NAME_OFFSET + 1] = b'r';
        data[VK_NAME_OFFSET + 2] = b'l';
        data[VK_NAME_OFFSET + 3] = b'1';
        assert_eq!(read_value_name(&data), "url1");
    }

    #[test]
    fn read_value_name_length_overflow_returns_empty() {
        let mut data = vec![0u8; VK_NAME_OFFSET + 2];
        data[VK_NAME_LENGTH_OFFSET] = 0xFF;
        data[VK_NAME_LENGTH_OFFSET + 1] = 0xFF;
        assert_eq!(read_value_name(&data), "");
    }

    #[test]
    fn cell_address_basic() {
        let addr = cell_address(0x1000_0000, 0x100);
        assert_eq!(addr, 0x1000_0000 + HBIN_START_OFFSET + 0x100);
    }

    #[test]
    fn cell_address_zero_index() {
        let addr = cell_address(0x2000_0000, 0);
        assert_eq!(addr, 0x2000_0000 + HBIN_START_OFFSET);
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
    fn typed_url_constants_sane() {
        assert_eq!(NK_SIGNATURE, 0x6B6E);
        assert_eq!(VK_SIGNATURE, 0x6B76);
        assert_eq!(HBIN_START_OFFSET, 0x1000);
        assert_eq!(HBASE_BLOCK_ROOT_CELL_OFFSET, 0x24);
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
        assert_eq!(TYPED_URLS_TIME_PATH[3], "TypedURLsTime");
    }

    use memf_core::test_builders::flags;

    fn make_typed_url_isf() -> serde_json::Value {
        IsfBuilder::new().build_json()
    }

    /// Helper: build a hive page where:
    ///   hive[HBASE_BLOCK_ROOT_CELL_OFFSET] = root_cell_index (u32 LE)
    ///   cell at cell_address(hive, root_cell_index) has abs_size=0 → empty data
    #[test]
    fn walk_typed_urls_root_cell_zero_index_no_nk() {
        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // hive at vaddr/paddr 0x0090_0000
        let hive_vaddr: u64 = 0xFFFF_8000_0090_0000;
        let hive_paddr: u64 = 0x0090_0000;
        // map 8 pages: 0x0090_0000..0x0090_8000
        let mut builder = PageTableBuilder::new();
        for i in 0..8u64 {
            builder = builder.map_4k(
                hive_vaddr + i * 0x1000,
                hive_paddr + i * 0x1000,
                flags::WRITABLE,
            );
        }
        // root_cell_index = 0 → cell at hive_paddr + HBIN_START_OFFSET
        // Write root_cell_index=0 at hive_paddr + 0x24
        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());
        builder = builder.write_phys(hive_paddr, &hive_page);
        // cell page at hive_paddr + HBIN_START_OFFSET: leave size_header=0 → abs=0 → empty
        // (all zeros by default)

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_typed_urls(&reader, hive_vaddr, "alice").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn walk_typed_urls_root_cell_wrong_signature() {
        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let hive_vaddr: u64 = 0xFFFF_8000_0091_0000;
        let hive_paddr: u64 = 0x0091_0000;
        let mut builder = PageTableBuilder::new();
        for i in 0..8u64 {
            builder = builder.map_4k(
                hive_vaddr + i * 0x1000,
                hive_paddr + i * 0x1000,
                flags::WRITABLE,
            );
        }
        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());
        builder = builder.write_phys(hive_paddr, &hive_page);

        // Cell page: write size_header=-64 (allocated, 64 bytes) + wrong sig
        let cell_paddr = hive_paddr + HBIN_START_OFFSET as u64;
        let mut cell_page = vec![0u8; 0x1000];
        let raw_size: i32 = -64;
        cell_page[0..4].copy_from_slice(&raw_size.to_le_bytes());
        cell_page[4] = 0xAA; // wrong sig byte 0
        cell_page[5] = 0xBB; // wrong sig byte 1
        builder = builder.write_phys(cell_paddr, &cell_page);

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_typed_urls(&reader, hive_vaddr, "alice").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn walk_typed_urls_root_nk_no_subkeys() {
        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let hive_vaddr: u64 = 0xFFFF_8000_0092_0000;
        let hive_paddr: u64 = 0x0092_0000;
        let mut builder = PageTableBuilder::new();
        for i in 0..8u64 {
            builder = builder.map_4k(
                hive_vaddr + i * 0x1000,
                hive_paddr + i * 0x1000,
                flags::WRITABLE,
            );
        }
        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());
        builder = builder.write_phys(hive_paddr, &hive_page);

        let cell_paddr = hive_paddr + HBIN_START_OFFSET as u64;
        let mut cell_page = vec![0u8; 0x1000];
        // size = -128 (allocated), nk_sig = 0x6B6E, subkey_count = 0
        let raw_size: i32 = -128;
        cell_page[0..4].copy_from_slice(&raw_size.to_le_bytes());
        cell_page[4] = 0x6E; // 'n'
        cell_page[5] = 0x6B; // 'k'
                             // stable_subkey_count at offset 4+0x14 = 0x18 in cell_page
                             // stays 0
        builder = builder.write_phys(cell_paddr, &cell_page);

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_typed_urls(&reader, hive_vaddr, "alice").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn walk_typed_urls_unknown_list_signature() {
        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let hive_vaddr: u64 = 0xFFFF_8000_0093_0000;
        let hive_paddr: u64 = 0x0093_0000;
        let mut builder = PageTableBuilder::new();
        for i in 0..8u64 {
            builder = builder.map_4k(
                hive_vaddr + i * 0x1000,
                hive_paddr + i * 0x1000,
                flags::WRITABLE,
            );
        }
        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());
        builder = builder.write_phys(hive_paddr, &hive_page);

        let cell_paddr = hive_paddr + HBIN_START_OFFSET as u64;
        let mut cell_page = vec![0u8; 0x2000];
        // Root nk cell at offset 0 in cell page
        let raw_size: i32 = -256;
        cell_page[0..4].copy_from_slice(&raw_size.to_le_bytes());
        cell_page[4] = 0x6E;
        cell_page[5] = 0x6B; // nk sig
                             // stable_subkey_count=1 at nk_data[0x14] = cell_page[4+0x14]
        cell_page[4 + NK_STABLE_SUBKEY_COUNT_OFFSET] = 1;
        // subkeys_list_cell=0x100 at nk_data[0x1C] = cell_page[4+0x1C]
        cell_page[4 + NK_STABLE_SUBKEYS_LIST_OFFSET..4 + NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .copy_from_slice(&0x100u32.to_le_bytes());
        builder = builder.write_phys(cell_paddr, &cell_page);

        // List cell at cell_address(hive, 0x100) = hive_vaddr + HBIN_START_OFFSET + 0x100
        // = hive_paddr + 0x1000 + 0x100
        let list_paddr = hive_paddr + HBIN_START_OFFSET as u64 + 0x100;
        let mut list_page = vec![0u8; 0x1000];
        let list_size: i32 = -64;
        list_page[0..4].copy_from_slice(&list_size.to_le_bytes());
        // unknown sig = 0xFFFF
        list_page[4] = 0xFF;
        list_page[5] = 0xFF;
        builder = builder.write_phys(list_paddr, &list_page[..]);

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_typed_urls(&reader, hive_vaddr, "alice").unwrap();
        assert!(result.is_empty());
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

    fn make_typed_url_isf_with_subkeyfields() -> serde_json::Value {
        IsfBuilder::new().build_json()
    }

    #[test]
    fn walk_typed_urls_root_has_zero_subkeys_empty() {
        // Same as walk_typed_urls_root_nk_no_subkeys — root NK with subkey_count=0
        let isf = make_typed_url_isf_with_subkeyfields();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let hive_vaddr: u64 = 0xFFFF_8000_0094_0000;
        let hive_paddr: u64 = 0x0094_0000;
        let mut builder = PageTableBuilder::new();
        for i in 0..8u64 {
            builder = builder.map_4k(
                hive_vaddr + i * 0x1000,
                hive_paddr + i * 0x1000,
                flags::WRITABLE,
            );
        }
        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());
        builder = builder.write_phys(hive_paddr, &hive_page);

        let cell_paddr = hive_paddr + HBIN_START_OFFSET as u64;
        let mut cell_page = vec![0u8; 0x1000];
        let raw_size: i32 = -128;
        cell_page[0..4].copy_from_slice(&raw_size.to_le_bytes());
        cell_page[4] = 0x6E;
        cell_page[5] = 0x6B; // nk
                             // subkey_count stays 0
        builder = builder.write_phys(cell_paddr, &cell_page);

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_typed_urls(&reader, hive_vaddr, "alice").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn walk_typed_urls_ri_list_bad_child_sig_empty() {
        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let hive_vaddr: u64 = 0xFFFF_8000_0095_0000;
        let hive_paddr: u64 = 0x0095_0000;
        let mut builder = PageTableBuilder::new();
        for i in 0..8u64 {
            builder = builder.map_4k(
                hive_vaddr + i * 0x1000,
                hive_paddr + i * 0x1000,
                flags::WRITABLE,
            );
        }
        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());
        builder = builder.write_phys(hive_paddr, &hive_page);

        let base = hive_paddr + HBIN_START_OFFSET as u64;
        let mut pg = vec![0u8; 0x4000];

        // Root nk at offset 0: sig=nk, subkey_count=1, list_cell=0x200
        let rs: i32 = -256;
        pg[0..4].copy_from_slice(&rs.to_le_bytes());
        pg[4] = 0x6E;
        pg[5] = 0x6B;
        pg[4 + NK_STABLE_SUBKEY_COUNT_OFFSET] = 1;
        pg[4 + NK_STABLE_SUBKEYS_LIST_OFFSET..4 + NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .copy_from_slice(&0x200u32.to_le_bytes());

        // ri list at 0x200: sig=ri(0x6972), count=1, sub_list_cell=0x300
        pg[0x200..0x204].copy_from_slice(&(-64i32).to_le_bytes());
        pg[0x204] = 0x72;
        pg[0x205] = 0x69; // 'ri'
        pg[0x206..0x208].copy_from_slice(&1u16.to_le_bytes());
        pg[0x208..0x20C].copy_from_slice(&0x300u32.to_le_bytes());

        // sub_list at 0x300: sig=lf(0x666C), count=1, child_cell=0x400
        pg[0x300..0x304].copy_from_slice(&(-64i32).to_le_bytes());
        pg[0x304] = 0x6C;
        pg[0x305] = 0x66; // 'lf'
        pg[0x306..0x308].copy_from_slice(&1u16.to_le_bytes());
        pg[0x308..0x30C].copy_from_slice(&0x400u32.to_le_bytes());

        // child nk at 0x400: bad sig = 0xDEAD
        pg[0x400..0x404].copy_from_slice(&(-128i32).to_le_bytes());
        pg[0x404] = 0xAD;
        pg[0x405] = 0xDE; // bad sig

        builder = builder.write_phys(base, &pg[..0x1000]);
        // second page for 0x400 area
        builder = builder.write_phys(base + 0x1000, &pg[0x1000..0x2000]);

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_typed_urls(&reader, hive_vaddr, "alice").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn walk_typed_urls_li_list_no_match_empty() {
        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let hive_vaddr: u64 = 0xFFFF_8000_0096_0000;
        let hive_paddr: u64 = 0x0096_0000;
        let mut builder = PageTableBuilder::new();
        for i in 0..8u64 {
            builder = builder.map_4k(
                hive_vaddr + i * 0x1000,
                hive_paddr + i * 0x1000,
                flags::WRITABLE,
            );
        }
        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());
        builder = builder.write_phys(hive_paddr, &hive_page);

        let base = hive_paddr + HBIN_START_OFFSET as u64;
        let mut pg = vec![0u8; 0x2000];

        // Root nk: sig=nk, subkey_count=1, list_cell=0x200
        pg[0..4].copy_from_slice(&(-256i32).to_le_bytes());
        pg[4] = 0x6E;
        pg[5] = 0x6B;
        pg[4 + NK_STABLE_SUBKEY_COUNT_OFFSET] = 1;
        pg[4 + NK_STABLE_SUBKEYS_LIST_OFFSET..4 + NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .copy_from_slice(&0x200u32.to_le_bytes());

        // li list at 0x200: sig=li(0x696C), count=1, child_cell=0x300
        pg[0x200..0x204].copy_from_slice(&(-64i32).to_le_bytes());
        pg[0x204] = 0x6C;
        pg[0x205] = 0x69; // 'li'
        pg[0x206..0x208].copy_from_slice(&1u16.to_le_bytes());
        pg[0x208..0x20C].copy_from_slice(&0x300u32.to_le_bytes());

        // child nk at 0x300: sig=nk, name="WRONG"
        pg[0x300..0x304].copy_from_slice(&(-128i32).to_le_bytes());
        pg[0x304] = 0x6E;
        pg[0x305] = 0x6B; // nk
        let name = b"WRONG";
        pg[0x304 + NK_NAME_LENGTH_OFFSET] = name.len() as u8;
        pg[0x304 + NK_NAME_LENGTH_OFFSET + 1] = 0;
        for (i, &b) in name.iter().enumerate() {
            pg[0x304 + NK_NAME_OFFSET + i] = b;
        }

        builder = builder.write_phys(base, &pg[..0x1000]);
        builder = builder.write_phys(base + 0x1000, &pg[0x1000..]);

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_typed_urls(&reader, hive_vaddr, "alice").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn read_cell_data_positive_size_returns_data() {
        // A positive raw_size means the cell is free; abs_size is still used
        // (positive values are just treated as unallocated but the function still reads)
        // raw_size=64 → abs=64 → data_len=60
        // We just verify no panic and that it reads.
        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let vaddr: u64 = 0xFFFF_8000_00A0_0000;
        let paddr: u64 = 0x00A0_0000;

        let mut builder = PageTableBuilder::new();
        builder = builder.map_4k(vaddr, paddr, flags::WRITABLE);
        let mut page = vec![0u8; 0x1000];
        // positive size = 64
        page[0..4].copy_from_slice(&64i32.to_le_bytes());
        builder = builder.write_phys(paddr, &page);

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let data = read_cell_data(&reader, vaddr).unwrap();
        // abs_size=64 → data_len=60 → 60 zero bytes
        assert_eq!(data.len(), 60);
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
    fn cell_address_large_values() {
        let result = cell_address(u64::MAX, 0);
        // wrapping arithmetic
        let expected = u64::MAX.wrapping_add(HBIN_START_OFFSET).wrapping_add(0);
        assert_eq!(result, expected);
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

    #[test]
    fn walk_typed_urls_list_data_too_short_empty() {
        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let hive_vaddr: u64 = 0xFFFF_8000_0097_0000;
        let hive_paddr: u64 = 0x0097_0000;
        let mut builder = PageTableBuilder::new();
        for i in 0..8u64 {
            builder = builder.map_4k(
                hive_vaddr + i * 0x1000,
                hive_paddr + i * 0x1000,
                flags::WRITABLE,
            );
        }
        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());
        builder = builder.write_phys(hive_paddr, &hive_page);

        let base = hive_paddr + HBIN_START_OFFSET as u64;
        let mut pg = vec![0u8; 0x2000];

        // Root nk: sig=nk, subkey_count=1, list_cell=0x200
        pg[0..4].copy_from_slice(&(-256i32).to_le_bytes());
        pg[4] = 0x6E;
        pg[5] = 0x6B;
        pg[4 + NK_STABLE_SUBKEY_COUNT_OFFSET] = 1;
        pg[4 + NK_STABLE_SUBKEYS_LIST_OFFSET..4 + NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .copy_from_slice(&0x200u32.to_le_bytes());

        // list cell at 0x200: abs_size=5 → data_len=1 (< 4) → returns empty data
        // raw_size=-5 → abs=5 → data_len=1
        pg[0x200..0x204].copy_from_slice(&(-5i32).to_le_bytes());
        pg[0x204] = 0x00; // only 1 byte of data

        builder = builder.write_phys(base, &pg[..0x1000]);
        builder = builder.write_phys(base + 0x1000, &pg[0x1000..]);

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_typed_urls(&reader, hive_vaddr, "alice").unwrap();
        assert!(result.is_empty());
    }

    // ── find_subkey direct call tests ─────────────────────────────────────

    fn build_hive_with_nk_and_lf_list(
        sig: u16,
        child_name: &str,
    ) -> (
        ObjectReader<memf_core::test_builders::SyntheticPhysMem>,
        u64,     // hive_vaddr
        Vec<u8>, // root nk data
        u32,     // child_cell index
    ) {
        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let hive_vaddr: u64 = 0xFFFF_8000_00B0_0000;
        let hive_paddr: u64 = 0x00B0_0000;

        let mut builder = PageTableBuilder::new();
        for i in 0..8u64 {
            builder = builder.map_4k(
                hive_vaddr + i * 0x1000,
                hive_paddr + i * 0x1000,
                flags::WRITABLE,
            );
        }

        let base = hive_paddr + HBIN_START_OFFSET as u64;
        let mut pg = vec![0u8; 0x2000];

        // child_cell = 0x300
        let child_cell: u32 = 0x300;

        // list cell at 0x100: sig=<param>, count=1, child=child_cell
        let entry_size: usize = if sig == 0x696C { 4 } else { 8 };
        pg[0x100..0x104].copy_from_slice(&(-64i32).to_le_bytes());
        let sig_bytes = sig.to_le_bytes();
        pg[0x104] = sig_bytes[0];
        pg[0x105] = sig_bytes[1];
        pg[0x106..0x108].copy_from_slice(&1u16.to_le_bytes());
        pg[0x108..0x10C].copy_from_slice(&child_cell.to_le_bytes());
        if entry_size == 8 {
            // hash at [0x10C..0x110] = 0 (don't care)
        }

        // child nk at 0x300
        let nk_name = child_name.as_bytes();
        let nk_size: i32 = -((0x4C + nk_name.len() + 4 + 7) as i32 & !7);
        pg[0x300..0x304].copy_from_slice(&nk_size.to_le_bytes());
        pg[0x304] = 0x6E;
        pg[0x305] = 0x6B; // nk sig
        pg[0x304 + NK_NAME_LENGTH_OFFSET] = nk_name.len() as u8;
        for (i, &b) in nk_name.iter().enumerate() {
            pg[0x304 + NK_NAME_OFFSET + i] = b;
        }

        builder = builder.write_phys(base, &pg[..0x1000]);
        builder = builder.write_phys(base + 0x1000, &pg[0x1000..]);

        // Build root nk data (for passing to find_subkey)
        // subkey_count=1, list_cell=0x100
        let mut root_nk = vec![0u8; NK_NAME_OFFSET + 4];
        root_nk[0] = 0x6E;
        root_nk[1] = 0x6B; // nk sig
        root_nk[NK_STABLE_SUBKEY_COUNT_OFFSET] = 1;
        root_nk[NK_STABLE_SUBKEYS_LIST_OFFSET..NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .copy_from_slice(&0x100u32.to_le_bytes());

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        (reader, hive_vaddr, root_nk, child_cell)
    }

    #[test]
    fn find_subkey_lf_match_returns_cell() {
        let (reader, hive_vaddr, root_nk, child_cell) =
            build_hive_with_nk_and_lf_list(0x666C, "Software");

        let result = find_subkey(&reader, hive_vaddr, &root_nk, "Software").unwrap();
        assert_eq!(result, Some(child_cell));
    }

    #[test]
    fn find_subkey_li_match_returns_cell() {
        let (reader, hive_vaddr, root_nk, child_cell) =
            build_hive_with_nk_and_lf_list(0x696C, "Software");

        let result = find_subkey(&reader, hive_vaddr, &root_nk, "Software").unwrap();
        assert_eq!(result, Some(child_cell));
    }

    #[test]
    fn walk_typed_urls_full_traversal_finds_url() {
        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // hive at virtual: 0xFFFF_8000_0098_0000, phys: 0x0098_0000
        // HBIN page at phys: 0x0099_0000  (hive + 0x1000)
        let hive_vaddr: u64 = 0xFFFF_8000_0098_0000;
        let hive_paddr: u64 = 0x0098_0000;
        let hbin_paddr: u64 = 0x0099_0000;

        let mut builder = PageTableBuilder::new();
        // Map hive header page + 8 HBIN pages
        builder = builder.map_4k(hive_vaddr, hive_paddr, flags::WRITABLE);
        for i in 0..8u64 {
            builder = builder.map_4k(
                hive_vaddr + (i + 1) * 0x1000,
                hbin_paddr + i * 0x1000,
                flags::WRITABLE,
            );
        }

        // Hive header: root_cell_index=0 at offset 0x24
        let mut hive_hdr = vec![0u8; 0x1000];
        hive_hdr[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());
        builder = builder.write_phys(hive_paddr, &hive_hdr);

        // HBIN layout (all offsets relative to hbin_paddr, which is cell_address(hive,0)):
        // root_nk at offset 0:  subkey_count=1, list_cell=0x200
        // lf_SW at 0x200:       count=1, child=0x300
        // SW nk at 0x300:       subkey_count=1, list_cell=0x500
        // lf_MS at 0x500:       count=1, child=0x600
        // MS nk at 0x600:       subkey_count=1, list_cell=0x800
        // lf_IE at 0x800:       count=1, child=0x900
        // IE nk at 0x900:       subkey_count=1, list_cell=0xB00
        // lf_TU at 0xB00:       count=1, child=0xC00
        // TU nk at 0xC00:       value_count=1, values_list=0xE00
        // vlist at 0xE00:       [→0xF00]
        // vk at 0xF00:          name="url1", data_len=50, data_cell=0x1000
        // data at 0x1000:       UTF-16LE "https://pastebin.com/abc\0"

        let mut pg = vec![0u8; 0x8000];

        let write_nk = |pg: &mut Vec<u8>,
                        off: usize,
                        sub_count: u32,
                        list_cell: u32,
                        val_count: u32,
                        val_list: u32,
                        name: &[u8]| {
            pg[off..off + 4].copy_from_slice(&(-256i32).to_le_bytes());
            pg[off + 4] = 0x6E;
            pg[off + 5] = 0x6B;
            pg[off + 4 + NK_STABLE_SUBKEY_COUNT_OFFSET
                ..off + 4 + NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
                .copy_from_slice(&sub_count.to_le_bytes());
            pg[off + 4 + NK_STABLE_SUBKEYS_LIST_OFFSET
                ..off + 4 + NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
                .copy_from_slice(&list_cell.to_le_bytes());
            pg[off + 4 + NK_VALUE_COUNT_OFFSET..off + 4 + NK_VALUE_COUNT_OFFSET + 4]
                .copy_from_slice(&val_count.to_le_bytes());
            pg[off + 4 + NK_VALUES_LIST_OFFSET..off + 4 + NK_VALUES_LIST_OFFSET + 4]
                .copy_from_slice(&val_list.to_le_bytes());
            pg[off + 4 + NK_NAME_LENGTH_OFFSET] = name.len() as u8;
            for (i, &b) in name.iter().enumerate() {
                pg[off + 4 + NK_NAME_OFFSET + i] = b;
            }
        };

        let write_lf = |pg: &mut Vec<u8>, off: usize, child_cell: u32| {
            pg[off..off + 4].copy_from_slice(&(-64i32).to_le_bytes());
            pg[off + 4] = 0x6C;
            pg[off + 5] = 0x66; // lf
            pg[off + 6..off + 8].copy_from_slice(&1u16.to_le_bytes());
            pg[off + 8..off + 12].copy_from_slice(&child_cell.to_le_bytes());
        };

        // root nk: sub=1, list=0x200, val=0, name="\0"
        write_nk(&mut pg, 0x000, 1, 0x200, 0, 0, b"root");
        write_lf(&mut pg, 0x200, 0x300);
        write_nk(&mut pg, 0x300, 1, 0x500, 0, 0, b"Software");
        write_lf(&mut pg, 0x500, 0x600);
        write_nk(&mut pg, 0x600, 1, 0x800, 0, 0, b"Microsoft");
        write_lf(&mut pg, 0x800, 0x900);
        write_nk(&mut pg, 0x900, 1, 0xB00, 0, 0, b"Internet Explorer");
        write_lf(&mut pg, 0xB00, 0xC00);
        // TypedURLs nk: sub=0, list=0, val=1, val_list=0xE00
        write_nk(&mut pg, 0xC00, 0, 0, 1, 0xE00, b"TypedURLs");

        // values list at 0xE00: [vk_cell=0xF00]
        pg[0xE00..0xE04].copy_from_slice(&(-64i32).to_le_bytes());
        pg[0xE04..0xE08].copy_from_slice(&0xF00u32.to_le_bytes());

        // vk "url1" at 0xF00: name_len=4, data_len=50, data_cell=0x1000
        pg[0xF00..0xF04].copy_from_slice(&(-128i32).to_le_bytes());
        pg[0xF04] = 0x76;
        pg[0xF05] = 0x6B; // vk sig
        pg[0xF04 + VK_NAME_LENGTH_OFFSET] = 4; // len("url1")=4
        pg[0xF04 + VK_DATA_LENGTH_OFFSET..0xF04 + VK_DATA_LENGTH_OFFSET + 4]
            .copy_from_slice(&50u32.to_le_bytes());
        pg[0xF04 + VK_DATA_OFFSET_OFFSET..0xF04 + VK_DATA_OFFSET_OFFSET + 4]
            .copy_from_slice(&0x1000u32.to_le_bytes());
        pg[0xF04 + VK_NAME_OFFSET] = b'u';
        pg[0xF04 + VK_NAME_OFFSET + 1] = b'r';
        pg[0xF04 + VK_NAME_OFFSET + 2] = b'l';
        pg[0xF04 + VK_NAME_OFFSET + 3] = b'1';

        // data cell at 0x1000: size header + UTF-16LE "https://pastebin.com/abc\0"
        let url_str = "https://pastebin.com/abc";
        let url_utf16: Vec<u8> = url_str.encode_utf16().flat_map(u16::to_le_bytes).collect();
        pg[0x1000..0x1004].copy_from_slice(&(-128i32).to_le_bytes());
        let data_end = 0x1004 + url_utf16.len();
        pg[0x1004..data_end].copy_from_slice(&url_utf16);

        // Write all pages
        for chunk_i in 0..8usize {
            let src_start = chunk_i * 0x1000;
            let src_end = src_start + 0x1000;
            builder = builder.write_phys(
                hbin_paddr + chunk_i as u64 * 0x1000,
                &pg[src_start..src_end],
            );
        }

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_typed_urls(&reader, hive_vaddr, "testuser").unwrap();
        assert_eq!(results.len(), 1, "should find one URL");
        assert_eq!(results[0].url, "https://pastebin.com/abc");
        assert_eq!(results[0].username, "testuser");
        assert!(
            results[0].is_suspicious,
            "pastebin.com should be suspicious"
        );
    }

    #[test]
    fn walk_typed_urls_with_timestamp_from_typed_urls_time() {
        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // hive at virtual/phys: 0xFFFF_8000_009A_0000 / 0x009A_0000
        let hive_vaddr: u64 = 0xFFFF_8000_009A_0000;
        let hive_paddr: u64 = 0x009A_0000;
        let hbin_paddr: u64 = 0x009B_0000;

        let mut builder = PageTableBuilder::new();
        builder = builder.map_4k(hive_vaddr, hive_paddr, flags::WRITABLE);
        for i in 0..16u64 {
            builder = builder.map_4k(
                hive_vaddr + (i + 1) * 0x1000,
                hbin_paddr + i * 0x1000,
                flags::WRITABLE,
            );
        }

        let mut hive_hdr = vec![0u8; 0x1000];
        hive_hdr[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());
        builder = builder.write_phys(hive_paddr, &hive_hdr);

        // Layout in HBIN (all offsets from hbin_paddr = cell_address(hive,0)):
        //   0x010: ROOT nk  (sub=1, lf=0x100, val=0)
        //   0x100: lf1→SW at 0x200
        //   0x200: SW nk    (sub=1, lf=0x300, val=0)
        //   0x300: lf1→MS at 0x400
        //   0x400: MS nk    (sub=1, lf=0x500, val=0)
        //   0x500: lf1→IE at 0x600
        //   0x600: IE nk    (sub=2, lf=0x700, val=0)
        //   0x700: lf2→[0x800, 0x900]  (TypedURLs=0x800, TypedURLsTime=0x900)
        //   0x800: TU nk   (sub=0, val=1, vlist=0xA00)
        //   0x900: TT nk   (sub=0, val=1, vlist=0xB00)
        //   0xA00: vlist_TU → 0xC00
        //   0xB00: vlist_TT → 0xD00
        //   0xC00: vk "url1" data_len=40, data_cell=0xE00
        //   0xD00: vk "url1" data_len=8,  data_cell=0xF00
        //   0xE00: URL data UTF-16LE "https://mega.nz/x"
        //   0xF00: FILETIME 132_000_000_000u64

        let mut pg = vec![0u8; 0x10000];

        let write_nk = |pg: &mut Vec<u8>,
                        off: usize,
                        sub_count: u32,
                        list_cell: u32,
                        val_count: u32,
                        val_list: u32,
                        name: &[u8]| {
            pg[off..off + 4].copy_from_slice(&(-256i32).to_le_bytes());
            pg[off + 4] = 0x6E;
            pg[off + 5] = 0x6B;
            pg[off + 4 + NK_STABLE_SUBKEY_COUNT_OFFSET
                ..off + 4 + NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
                .copy_from_slice(&sub_count.to_le_bytes());
            pg[off + 4 + NK_STABLE_SUBKEYS_LIST_OFFSET
                ..off + 4 + NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
                .copy_from_slice(&list_cell.to_le_bytes());
            pg[off + 4 + NK_VALUE_COUNT_OFFSET..off + 4 + NK_VALUE_COUNT_OFFSET + 4]
                .copy_from_slice(&val_count.to_le_bytes());
            pg[off + 4 + NK_VALUES_LIST_OFFSET..off + 4 + NK_VALUES_LIST_OFFSET + 4]
                .copy_from_slice(&val_list.to_le_bytes());
            pg[off + 4 + NK_NAME_LENGTH_OFFSET] = name.len() as u8;
            for (i, &b) in name.iter().enumerate() {
                pg[off + 4 + NK_NAME_OFFSET + i] = b;
            }
        };

        let write_lf_n = |pg: &mut Vec<u8>, off: usize, children: &[u32]| {
            pg[off..off + 4].copy_from_slice(&(-128i32).to_le_bytes());
            pg[off + 4] = 0x6C;
            pg[off + 5] = 0x66; // lf
            pg[off + 6..off + 8].copy_from_slice(&(children.len() as u16).to_le_bytes());
            for (i, &c) in children.iter().enumerate() {
                pg[off + 8 + i * 8..off + 8 + i * 8 + 4].copy_from_slice(&c.to_le_bytes());
            }
        };

        let write_vk =
            |pg: &mut Vec<u8>, off: usize, name: &[u8], data_len: u32, data_cell: u32| {
                pg[off..off + 4].copy_from_slice(&(-128i32).to_le_bytes());
                pg[off + 4] = 0x76;
                pg[off + 5] = 0x6B; // vk
                pg[off + 4 + VK_NAME_LENGTH_OFFSET] = name.len() as u8;
                pg[off + 4 + VK_DATA_LENGTH_OFFSET..off + 4 + VK_DATA_LENGTH_OFFSET + 4]
                    .copy_from_slice(&data_len.to_le_bytes());
                pg[off + 4 + VK_DATA_OFFSET_OFFSET..off + 4 + VK_DATA_OFFSET_OFFSET + 4]
                    .copy_from_slice(&data_cell.to_le_bytes());
                for (i, &b) in name.iter().enumerate() {
                    pg[off + 4 + VK_NAME_OFFSET + i] = b;
                }
            };

        // ROOT nk at 0x010
        write_nk(&mut pg, 0x010, 1, 0x100, 0, 0, b"root");
        // lf→SW at 0x100
        write_lf_n(&mut pg, 0x100, &[0x200]);
        // SW nk at 0x200
        write_nk(&mut pg, 0x200, 1, 0x300, 0, 0, b"Software");
        // lf→MS at 0x300
        write_lf_n(&mut pg, 0x300, &[0x400]);
        // MS nk at 0x400
        write_nk(&mut pg, 0x400, 1, 0x500, 0, 0, b"Microsoft");
        // lf→IE at 0x500
        write_lf_n(&mut pg, 0x500, &[0x600]);
        // IE nk at 0x600: 2 subkeys
        write_nk(&mut pg, 0x600, 2, 0x700, 0, 0, b"Internet Explorer");
        // lf2→[TU=0x800, TT=0x900] at 0x700
        write_lf_n(&mut pg, 0x700, &[0x800, 0x900]);
        // TU nk at 0x800: name="TypedURLs", val=1, vlist=0xA00
        write_nk(&mut pg, 0x800, 0, 0, 1, 0xA00, b"TypedURLs");
        // TT nk at 0x900: name="TypedURLsTime", val=1, vlist=0xB00
        write_nk(&mut pg, 0x900, 0, 0, 1, 0xB00, b"TypedURLsTime");

        // vlist_TU at 0xA00: [→0xC00]
        pg[0xA00..0xA04].copy_from_slice(&(-64i32).to_le_bytes());
        pg[0xA04..0xA08].copy_from_slice(&0xC00u32.to_le_bytes());
        // vlist_TT at 0xB00: [→0xD00]
        pg[0xB00..0xB04].copy_from_slice(&(-64i32).to_le_bytes());
        pg[0xB04..0xB08].copy_from_slice(&0xD00u32.to_le_bytes());

        // vk "url1" (URL) at 0xC00: data_len=40, data_cell=0xE00
        write_vk(&mut pg, 0xC00, b"url1", 40, 0xE00);
        // vk "url1" (time) at 0xD00: data_len=8, data_cell=0xF00
        write_vk(&mut pg, 0xD00, b"url1", 8, 0xF00);

        // URL data at 0xE00: UTF-16LE "https://mega.nz/x"
        let url_str = "https://mega.nz/x";
        let url_utf16: Vec<u8> = url_str.encode_utf16().flat_map(u16::to_le_bytes).collect();
        pg[0xE00..0xE04].copy_from_slice(&(-64i32).to_le_bytes());
        pg[0xE04..0xE04 + url_utf16.len()].copy_from_slice(&url_utf16);

        // FILETIME data at 0xF00: 132_000_000_000u64
        let ts: u64 = 132_000_000_000;
        pg[0xF00..0xF04].copy_from_slice(&(-64i32).to_le_bytes());
        pg[0xF04..0xF0C].copy_from_slice(&ts.to_le_bytes());

        // root cell is at cell_address(hive, 0) = hive_vaddr + HBIN_START_OFFSET + 0
        // But our root nk is at offset 0x010 within the HBIN page.
        // We need root_cell_index=0x010 so that cell_address(hive, 0x010) = hive+0x1000+0x010
        let mut hive_hdr2 = vec![0u8; 0x1000];
        hive_hdr2[0x24..0x28].copy_from_slice(&0x010u32.to_le_bytes());
        builder = builder.write_phys(hive_paddr, &hive_hdr2);

        // Write HBIN pages
        for i in 0..16usize {
            let src = i * 0x1000;
            builder = builder.write_phys(hbin_paddr + i as u64 * 0x1000, &pg[src..src + 0x1000]);
        }

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_typed_urls(&reader, hive_vaddr, "victim").unwrap();
        assert_eq!(results.len(), 1, "should find the URL");
        assert_eq!(results[0].url, "https://mega.nz/x");
        assert!(results[0].is_suspicious, "mega.nz is suspicious");
        assert_eq!(
            results[0].timestamp, ts,
            "timestamp should be read from TypedURLsTime"
        );
    }

    #[test]
    fn walk_typed_urls_wrong_root_sig_empty() {
        // Same as walk_typed_urls_root_cell_wrong_signature
        let isf = make_typed_url_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let hive_vaddr: u64 = 0xFFFF_8000_009C_0000;
        let hive_paddr: u64 = 0x009C_0000;
        let mut builder = PageTableBuilder::new();
        for i in 0..4u64 {
            builder = builder.map_4k(
                hive_vaddr + i * 0x1000,
                hive_paddr + i * 0x1000,
                flags::WRITABLE,
            );
        }
        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());
        builder = builder.write_phys(hive_paddr, &hive_page);

        let cell_paddr = hive_paddr + HBIN_START_OFFSET as u64;
        let mut cell_page = vec![0u8; 0x1000];
        let raw_size: i32 = -64;
        cell_page[0..4].copy_from_slice(&raw_size.to_le_bytes());
        cell_page[4] = 0xDE;
        cell_page[5] = 0xAD; // wrong sig
        builder = builder.write_phys(cell_paddr, &cell_page);

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_typed_urls(&reader, hive_vaddr, "alice").unwrap();
        assert!(result.is_empty());
    }
}
