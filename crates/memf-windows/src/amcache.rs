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
// ── Registry cell layout constants (same as registry_keys.rs) ────────

/// Offset of `RootCell` (u32) within `_HBASE_BLOCK`.
const HBASE_BLOCK_ROOT_CELL_OFFSET: u64 = 0x24;

/// Offset from `_HBASE_BLOCK` to the first HBIN (cell storage start).
const HBIN_START_OFFSET: u64 = 0x1000;

/// `_CM_KEY_NODE` signature: "nk" (0x6B6E).
const NK_SIGNATURE: u16 = 0x6B6E;

/// `_CM_KEY_VALUE` signature: "vk" (0x6B76).
const VK_SIGNATURE: u16 = 0x6B76;

// CM_KEY_NODE offsets (relative to cell data start, after 4-byte cell size)
#[allow(dead_code)]
const NK_LAST_WRITE_TIME_OFFSET: usize = 4;
const NK_STABLE_SUBKEY_COUNT_OFFSET: usize = 0x14;
const NK_STABLE_SUBKEYS_LIST_OFFSET: usize = 0x1C;
const NK_VALUE_COUNT_OFFSET: usize = 0x24;
const NK_VALUES_LIST_OFFSET: usize = 0x28;
const NK_NAME_LENGTH_OFFSET: usize = 0x48;
const NK_NAME_OFFSET: usize = 0x4C;

// CM_KEY_VALUE offsets (relative to cell data start)
const VK_NAME_LENGTH_OFFSET: usize = 0x02;
const VK_DATA_LENGTH_OFFSET: usize = 0x04;
const VK_DATA_OFFSET: usize = 0x08;
const VK_TYPE_OFFSET: usize = 0x0C;
const VK_NAME_OFFSET: usize = 0x14;

/// REG_SZ type for string values.
#[allow(dead_code)]
const REG_SZ: u32 = 1;
/// REG_QWORD type for 64-bit integer values.
const REG_QWORD: u32 = 11;
/// REG_DWORD type for 32-bit integer values.
const REG_DWORD: u32 = 4;

/// Read cell data at a given cell index within the hive.
///
/// The cell index is relative to the start of cell storage (HBIN area).
/// Each cell starts with an i32 size (negative = allocated). We skip the
/// 4-byte size prefix and return the cell data.
fn read_cell_data<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_base: u64,
    cell_index: u32,
    max_len: usize,
) -> Option<Vec<u8>> {
    if cell_index == 0 || cell_index == 0xFFFF_FFFF {
        return None;
    }
    let cell_vaddr = hive_base
        .wrapping_add(HBIN_START_OFFSET)
        .wrapping_add(cell_index as u64);

    // Read the 4-byte size field first.
    let size_bytes = reader.read_bytes(cell_vaddr, 4).ok()?;
    let raw_size = i32::from_le_bytes(size_bytes[..4].try_into().ok()?);
    // Negative = allocated cell; absolute value is total cell size including header.
    let data_size = (raw_size.unsigned_abs() as usize).saturating_sub(4);
    let read_len = data_size.min(max_len);
    if read_len == 0 {
        return None;
    }

    reader.read_bytes(cell_vaddr.wrapping_add(4), read_len).ok()
}

/// Read an ASCII key/value name from cell data at the given offset.
fn read_ascii_name(data: &[u8], name_length_offset: usize, name_offset: usize) -> String {
    if data.len() < name_length_offset + 2 {
        return String::new();
    }
    let name_len =
        u16::from_le_bytes([data[name_length_offset], data[name_length_offset + 1]]) as usize;
    if name_offset + name_len > data.len() || name_len == 0 {
        return String::new();
    }
    String::from_utf8_lossy(&data[name_offset..name_offset + name_len]).to_string()
}

/// Navigate from a key node to a named subkey.
///
/// Reads the stable subkeys list and searches for a child whose name
/// matches `target_name` (case-insensitive). Returns the cell index
/// of the matching child key node, or `None`.
fn find_subkey<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_base: u64,
    parent_data: &[u8],
    target_name: &str,
) -> Option<u32> {
    if parent_data.len() < NK_STABLE_SUBKEYS_LIST_OFFSET + 4 {
        return None;
    }
    let subkey_count = u32::from_le_bytes(
        parent_data[NK_STABLE_SUBKEY_COUNT_OFFSET..NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
            .try_into()
            .ok()?,
    );
    if subkey_count == 0 {
        return None;
    }
    let subkeys_list_index = u32::from_le_bytes(
        parent_data[NK_STABLE_SUBKEYS_LIST_OFFSET..NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .try_into()
            .ok()?,
    );

    // The subkeys list cell contains a signature (lf/lh/ri/li, 2 bytes),
    // a count (u16), then pairs of (cell_index: u32, hash: u32).
    let list_data = read_cell_data(reader, hive_base, subkeys_list_index, 0x2000)?;
    if list_data.len() < 4 {
        return None;
    }
    let list_count = u16::from_le_bytes([list_data[2], list_data[3]]) as usize;
    let target_lower = target_name.to_ascii_lowercase();

    // Dispatch on list signature: li (0x696C) uses 4-byte entries (raw cell offset
    // only); lf (0x666C) and lh (0x686C) use 8-byte entries (cell offset + hash).
    let list_sig = u16::from_le_bytes([list_data[0], list_data[1]]);
    let stride = if list_sig == 0x696C { 4 } else { 8 };

    for i in 0..list_count {
        let offset = 4 + i * stride;
        if offset + 4 > list_data.len() {
            break;
        }
        let child_index = u32::from_le_bytes(list_data[offset..offset + 4].try_into().ok()?);

        // Read the child key node to check its name.
        let child_data = read_cell_data(reader, hive_base, child_index, 0x200)?;
        if child_data.len() < 4 {
            continue;
        }
        let sig = u16::from_le_bytes([child_data[0], child_data[1]]);
        if sig != NK_SIGNATURE {
            continue;
        }
        let name = read_ascii_name(&child_data, NK_NAME_LENGTH_OFFSET, NK_NAME_OFFSET);
        if name.to_ascii_lowercase() == target_lower {
            return Some(child_index);
        }
    }

    None
}

/// Read a REG_SZ string value from a value cell's data.
fn read_value_string<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_base: u64,
    vk_data: &[u8],
) -> String {
    if vk_data.len() < VK_NAME_OFFSET {
        return String::new();
    }
    let data_length = u32::from_le_bytes(
        vk_data[VK_DATA_LENGTH_OFFSET..VK_DATA_LENGTH_OFFSET + 4]
            .try_into()
            .unwrap_or([0; 4]),
    );
    // Bit 31 set means data is stored inline in the DataOffset field itself.
    let is_inline = data_length & 0x8000_0000 != 0;
    let real_len = (data_length & 0x7FFF_FFFF) as usize;

    if real_len == 0 {
        return String::new();
    }

    let raw = if is_inline {
        // Inline data: stored in the 4 bytes of the DataOffset field.
        vk_data[VK_DATA_OFFSET..VK_DATA_OFFSET + real_len.min(4)].to_vec()
    } else {
        let data_cell_index = u32::from_le_bytes(
            vk_data[VK_DATA_OFFSET..VK_DATA_OFFSET + 4]
                .try_into()
                .unwrap_or([0; 4]),
        );
        match read_cell_data(reader, hive_base, data_cell_index, real_len) {
            Some(d) => d,
            None => return String::new(),
        }
    };

    // Interpret as UTF-16LE.
    let u16_vec: Vec<u16> = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16_lossy(&u16_vec)
        .trim_end_matches('\0')
        .to_string()
}

/// Read a QWORD (u64) or DWORD (u32, widened) value from a value cell.
fn read_value_u64<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_base: u64,
    vk_data: &[u8],
) -> u64 {
    if vk_data.len() < VK_NAME_OFFSET {
        return 0;
    }
    let value_type = u32::from_le_bytes(
        vk_data[VK_TYPE_OFFSET..VK_TYPE_OFFSET + 4]
            .try_into()
            .unwrap_or([0; 4]),
    );
    let data_length = u32::from_le_bytes(
        vk_data[VK_DATA_LENGTH_OFFSET..VK_DATA_LENGTH_OFFSET + 4]
            .try_into()
            .unwrap_or([0; 4]),
    );
    let is_inline = data_length & 0x8000_0000 != 0;
    let real_len = (data_length & 0x7FFF_FFFF) as usize;

    let raw = if is_inline {
        vk_data[VK_DATA_OFFSET..VK_DATA_OFFSET + real_len.min(4)].to_vec()
    } else {
        let data_cell_index = u32::from_le_bytes(
            vk_data[VK_DATA_OFFSET..VK_DATA_OFFSET + 4]
                .try_into()
                .unwrap_or([0; 4]),
        );
        match read_cell_data(reader, hive_base, data_cell_index, real_len) {
            Some(d) => d,
            None => return 0,
        }
    };

    match value_type {
        REG_QWORD if raw.len() >= 8 => u64::from_le_bytes(raw[..8].try_into().unwrap_or([0; 8])),
        REG_DWORD if raw.len() >= 4 => {
            u32::from_le_bytes(raw[..4].try_into().unwrap_or([0; 4])) as u64
        }
        _ => 0,
    }
}

/// Look up a named value from a key node's value list.
///
/// Returns the raw vk cell data for the matching value, or `None`.
fn find_value<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_base: u64,
    key_data: &[u8],
    target_name: &str,
) -> Option<Vec<u8>> {
    if key_data.len() < NK_VALUES_LIST_OFFSET + 4 {
        return None;
    }
    let value_count = u32::from_le_bytes(
        key_data[NK_VALUE_COUNT_OFFSET..NK_VALUE_COUNT_OFFSET + 4]
            .try_into()
            .ok()?,
    ) as usize;
    if value_count == 0 {
        return None;
    }
    let values_list_index = u32::from_le_bytes(
        key_data[NK_VALUES_LIST_OFFSET..NK_VALUES_LIST_OFFSET + 4]
            .try_into()
            .ok()?,
    );

    // The values list cell is an array of u32 cell indices.
    let list_data = read_cell_data(reader, hive_base, values_list_index, value_count * 4)?;
    let target_lower = target_name.to_ascii_lowercase();

    for i in 0..value_count {
        let offset = i * 4;
        if offset + 4 > list_data.len() {
            break;
        }
        let vk_index = u32::from_le_bytes(list_data[offset..offset + 4].try_into().ok()?);
        let vk_data = read_cell_data(reader, hive_base, vk_index, 0x200)?;
        if vk_data.len() < 4 {
            continue;
        }
        let sig = u16::from_le_bytes([vk_data[0], vk_data[1]]);
        if sig != VK_SIGNATURE {
            continue;
        }
        let name = read_ascii_name(&vk_data, VK_NAME_LENGTH_OFFSET, VK_NAME_OFFSET);
        if name.to_ascii_lowercase() == target_lower {
            return Some(vk_data);
        }
    }

    None
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
    // Zero address means no hive — graceful degradation.
    if amcache_hive_addr == 0 {
        return Ok(Vec::new());
    }

    // Read the BaseBlock pointer from _CMHIVE._HHIVE.BaseBlock.
    // _CMHIVE starts with _HHIVE, and _HHIVE.BaseBlock is at offset 0x10
    // (after Signature u32 @ 0x00, pad, etc.).
    // Try to read it via ISF first; fall back to raw offset.
    let base_block_addr: u64 = match reader.read_field(amcache_hive_addr, "_HHIVE", "BaseBlock") {
        Ok(addr) => addr,
        Err(_) => {
            // Fallback: read pointer at offset 0x10 from hive addr.
            match reader.read_bytes(amcache_hive_addr.wrapping_add(0x10), 8) {
                Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                _ => return Ok(Vec::new()),
            }
        }
    };

    if base_block_addr == 0 {
        return Ok(Vec::new());
    }

    // Read root cell index from _HBASE_BLOCK.
    let root_cell_bytes = match reader.read_bytes(
        base_block_addr.wrapping_add(HBASE_BLOCK_ROOT_CELL_OFFSET),
        4,
    ) {
        Ok(b) if b.len() == 4 => b,
        _ => return Ok(Vec::new()),
    };
    let root_cell = u32::from_le_bytes(root_cell_bytes[..4].try_into().unwrap());
    if root_cell == 0 {
        return Ok(Vec::new());
    }

    let hive_base = base_block_addr;

    // Read root key node.
    let root_data = match read_cell_data(reader, hive_base, root_cell, 0x200) {
        Some(d) if d.len() >= 4 && u16::from_le_bytes([d[0], d[1]]) == NK_SIGNATURE => d,
        _ => return Ok(Vec::new()),
    };

    // Navigate: Root → InventoryApplicationFile
    // First find "Root" if the root key is the hive root, then
    // find "InventoryApplicationFile" under it. In Amcache.hve the
    // root key is typically named "Root" and InventoryApplicationFile
    // is a direct child.
    let iaf_cell =
        if let Some(iaf) = find_subkey(reader, hive_base, &root_data, "InventoryApplicationFile") {
            iaf
        } else if let Some(root_child) = find_subkey(reader, hive_base, &root_data, "Root") {
            // Try one level deeper: Root → InventoryApplicationFile
            let root_child_data = match read_cell_data(reader, hive_base, root_child, 0x200) {
                Some(d) => d,
                None => return Ok(Vec::new()),
            };
            match find_subkey(
                reader,
                hive_base,
                &root_child_data,
                "InventoryApplicationFile",
            ) {
                Some(idx) => idx,
                None => return Ok(Vec::new()),
            }
        } else {
            return Ok(Vec::new());
        };

    // Read the InventoryApplicationFile key node.
    let iaf_data = match read_cell_data(reader, hive_base, iaf_cell, 0x200) {
        Some(d) if d.len() >= NK_STABLE_SUBKEYS_LIST_OFFSET + 4 => d,
        _ => return Ok(Vec::new()),
    };

    // Enumerate child keys (each represents one tracked executable).
    let subkey_count = u32::from_le_bytes(
        iaf_data[NK_STABLE_SUBKEY_COUNT_OFFSET..NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    if subkey_count == 0 {
        return Ok(Vec::new());
    }

    let subkeys_list_index = u32::from_le_bytes(
        iaf_data[NK_STABLE_SUBKEYS_LIST_OFFSET..NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    let list_data = match read_cell_data(reader, hive_base, subkeys_list_index, 0x4000) {
        Some(d) if d.len() >= 4 => d,
        _ => return Ok(Vec::new()),
    };

    let list_count =
        (u16::from_le_bytes([list_data[2], list_data[3]]) as usize).min(MAX_AMCACHE_ENTRIES);

    // Dispatch on list signature: li (0x696C) → 4-byte entries; lf/lh → 8-byte.
    let list_sig = u16::from_le_bytes([list_data[0], list_data[1]]);
    let stride = if list_sig == 0x696C { 4 } else { 8 };

    let mut entries = Vec::with_capacity(list_count);

    for i in 0..list_count {
        let offset = 4 + i * stride;
        if offset + 4 > list_data.len() {
            break;
        }
        let child_index = match list_data[offset..offset + 4].try_into() {
            Ok(b) => u32::from_le_bytes(b),
            Err(_) => continue,
        };

        let child_data = match read_cell_data(reader, hive_base, child_index, 0x400) {
            Some(d) if d.len() >= NK_NAME_OFFSET => d,
            _ => continue,
        };

        let sig = u16::from_le_bytes([child_data[0], child_data[1]]);
        if sig != NK_SIGNATURE {
            continue;
        }

        // Extract values from this child key.
        let file_path = find_value(reader, hive_base, &child_data, "LowerCaseLongPath")
            .map(|vk| read_value_string(reader, hive_base, &vk))
            .unwrap_or_default();

        let sha1_raw = find_value(reader, hive_base, &child_data, "FileId")
            .map(|vk| read_value_string(reader, hive_base, &vk))
            .unwrap_or_default();
        // Strip the "0000" prefix that Amcache prepends to SHA1 hashes.
        let sha1_hash = sha1_raw
            .strip_prefix("0000")
            .unwrap_or(&sha1_raw)
            .to_string();

        let file_size = find_value(reader, hive_base, &child_data, "Size")
            .map(|vk| read_value_u64(reader, hive_base, &vk))
            .unwrap_or(0);

        let link_timestamp = find_value(reader, hive_base, &child_data, "LinkDate")
            .map(|vk| read_value_u64(reader, hive_base, &vk))
            .unwrap_or(0);

        let publisher = find_value(reader, hive_base, &child_data, "Publisher")
            .map(|vk| read_value_string(reader, hive_base, &vk))
            .unwrap_or_default();

        let product_name = find_value(reader, hive_base, &child_data, "ProductName")
            .map(|vk| read_value_string(reader, hive_base, &vk))
            .unwrap_or_default();

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

    // ── read_ascii_name unit tests ────────────────────────────────────

    #[test]
    fn read_ascii_name_empty_data() {
        // Data too short to contain name length at offset
        let data = vec![0u8; 3];
        let result = read_ascii_name(&data, 0, 2);
        assert_eq!(result, "");
    }

    #[test]
    fn read_ascii_name_zero_length() {
        // Name length = 0 → empty string
        let mut data = vec![0u8; 32];
        // name_length_offset=0, so data[0..2] = length=0
        data[0] = 0;
        data[1] = 0;
        let result = read_ascii_name(&data, 0, 2);
        assert_eq!(result, "");
    }

    #[test]
    fn read_ascii_name_valid() {
        // Layout: u16 length at offset 0, name data at offset 2
        let mut data = vec![0u8; 32];
        let name = b"Software";
        data[0] = name.len() as u8;
        data[1] = 0;
        data[2..2 + name.len()].copy_from_slice(name);
        let result = read_ascii_name(&data, 0, 2);
        assert_eq!(result, "Software");
    }

    #[test]
    fn read_ascii_name_overflow_truncated() {
        // Name length larger than available data → empty
        let mut data = vec![0u8; 10];
        data[0] = 100; // length = 100 but data only 10 bytes
        data[1] = 0;
        let result = read_ascii_name(&data, 0, 2);
        assert_eq!(result, "");
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

    // ── Constants correctness ─────────────────────────────────────────

    #[test]
    fn hive_constants_sane() {
        assert_eq!(HBASE_BLOCK_ROOT_CELL_OFFSET, 0x24);
        assert_eq!(HBIN_START_OFFSET, 0x1000);
        assert_eq!(NK_SIGNATURE, 0x6B6E);
        assert_eq!(VK_SIGNATURE, 0x6B76);
    }

    #[test]
    fn max_amcache_entries_reasonable() {
        assert!(MAX_AMCACHE_ENTRIES > 0);
        assert!(MAX_AMCACHE_ENTRIES <= 100_000);
    }

    // ── walk_amcache body coverage ────────────────────────────────────
    //
    // walk_amcache reads:
    //   1. _HHIVE.BaseBlock pointer (via read_field or fallback at +0x10)
    //   2. root_cell from _HBASE_BLOCK + 0x24
    //   3. root nk cell (must have NK_SIGNATURE)
    //   4. subkey navigation: InventoryApplicationFile / Root
    //
    // We provide synthetic physical memory for the first few reads so
    // the walker body is exercised beyond the hive_addr=0 guard.

    use memf_core::test_builders::flags;

    fn make_amcache_isf() -> serde_json::Value {
        // _HHIVE with BaseBlock field at 0x10 so read_field succeeds.
        IsfBuilder::new()
            .add_struct("_HHIVE", 0x200)
            .add_field("_HHIVE", "BaseBlock", 0x10, "pointer")
            .build_json()
    }

    /// Mapped hive; BaseBlock ptr is valid but root_cell = 0 → early return.
    #[test]
    fn walk_amcache_mapped_hive_zero_root_cell() {
        let hive_vaddr: u64 = 0x0020_0000;
        let hive_paddr: u64 = 0x0020_0000;
        let base_block: u64 = 0x0021_0000;
        let base_block_paddr: u64 = 0x0021_0000;

        let mut hive_page = vec![0u8; 0x1000];
        // At offset 0x10: BaseBlock pointer
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        // root_cell at HBASE_BLOCK_ROOT_CELL_OFFSET (0x24) = 0
        bb_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());

        let isf = make_amcache_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_amcache(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty(), "zero root_cell → empty Vec");
    }

    /// Mapped hive; BaseBlock ptr valid; root_cell non-zero but cell data
    /// does not carry NK_SIGNATURE → walk returns empty Vec.
    #[test]
    fn walk_amcache_mapped_hive_bad_nk_signature() {
        let hive_vaddr: u64 = 0x0030_0000;
        let hive_paddr: u64 = 0x0030_0000;
        let base_block: u64 = 0x0031_0000;
        let base_block_paddr: u64 = 0x0031_0000;

        // root_cell = 0x20; cell lives at hive_base + HBIN_START_OFFSET + 0x20
        // = base_block + 0x1000 + 0x20 = 0x0032_0020
        let root_cell_index: u32 = 0x20;
        let cell_vaddr: u64 = base_block + HBIN_START_OFFSET + root_cell_index as u64;
        let cell_paddr: u64 = cell_vaddr; // identity map

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        bb_page[0x24..0x28].copy_from_slice(&root_cell_index.to_le_bytes());

        // Build the cell at cell_vaddr: i32 size + data (without NK_SIGNATURE)
        // size = -16 (allocated cell of 16 bytes)
        let mut cell_page = vec![0u8; 0x1000];
        let cell_offset = (root_cell_index as usize) % 0x1000;
        let raw_size: i32 = -16i32;
        cell_page[cell_offset..cell_offset + 4].copy_from_slice(&raw_size.to_le_bytes());
        // data (12 bytes): all zeros → sig = 0x0000, not NK_SIGNATURE

        let isf = make_amcache_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .map_4k(cell_vaddr & !0xFFF, cell_paddr & !0xFFF, flags::WRITABLE)
            .write_phys(cell_paddr & !0xFFF, &cell_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_amcache(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty(), "bad NK_SIGNATURE → empty Vec");
    }

    // ── find_subkey li-stride test ────────────────────────────────────

    /// `find_subkey` must correctly handle `li` subkey lists (4-byte entries,
    /// no hash word).  We build a synthetic hive in physical memory that
    /// contains:
    ///   • a parent_data NK slice with subkey_count=1 and subkeys_list_index
    ///     pointing to an `li` list cell
    ///   • the `li` list cell on the hbin page with one 4-byte entry pointing
    ///     to a child NK cell
    ///   • the child NK cell named "InventoryApplicationFile"
    /// and verify that find_subkey returns the correct child cell index.
    #[test]
    fn find_subkey_li_stride_finds_child() {
        let hive_base: u64 = 0x00B0_0000;

        let list_cell_index: u32 = 0x100;
        let child_cell_index: u32 = 0x200;

        let hbin_page_vaddr = hive_base + HBIN_START_OFFSET; // 0x00B1_0000
        let hbin_page_paddr: u64 = 0x00B1_0000;

        // parent nk_data: subkey_count=1, subkeys_list_index=list_cell_index
        let mut parent_data = vec![0u8; 0x60];
        parent_data[NK_STABLE_SUBKEY_COUNT_OFFSET..NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        parent_data[NK_STABLE_SUBKEYS_LIST_OFFSET..NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .copy_from_slice(&list_cell_index.to_le_bytes());

        // Build the hbin page.
        // li list cell at offset 0x100:
        //   [i32 size=-12][sig=li 0x696C][count=1][child_cell_index u32]
        //   (no hash word — li entries are 4 bytes each)
        // child NK cell at offset 0x200:
        //   [i32 size=-0x80][nk_data with NK_SIGNATURE, name="InventoryApplicationFile"]
        let mut hbin_page = vec![0u8; 0x1000];

        let list_off = list_cell_index as usize;
        hbin_page[list_off..list_off + 4].copy_from_slice(&(-12i32).to_le_bytes());
        // li sig = 0x696C → LE bytes [0x6C, 0x69]
        hbin_page[list_off + 4] = 0x6C;
        hbin_page[list_off + 5] = 0x69;
        // count = 1
        hbin_page[list_off + 6..list_off + 8].copy_from_slice(&1u16.to_le_bytes());
        // entry[0]: child_cell_index (4 bytes, no hash)
        hbin_page[list_off + 8..list_off + 12].copy_from_slice(&child_cell_index.to_le_bytes());

        let child_off = child_cell_index as usize;
        hbin_page[child_off..child_off + 4].copy_from_slice(&(-0x80i32).to_le_bytes());
        // NK sig = 0x6B6E → bytes [0x6E, 0x6B]
        hbin_page[child_off + 4] = 0x6E;
        hbin_page[child_off + 5] = 0x6B;
        let child_name = b"InventoryApplicationFile";
        hbin_page[child_off + 4 + NK_NAME_LENGTH_OFFSET..child_off + 4 + NK_NAME_LENGTH_OFFSET + 2]
            .copy_from_slice(&(child_name.len() as u16).to_le_bytes());
        hbin_page
            [child_off + 4 + NK_NAME_OFFSET..child_off + 4 + NK_NAME_OFFSET + child_name.len()]
            .copy_from_slice(child_name);

        let isf = make_amcache_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hbin_page_vaddr, hbin_page_paddr, flags::WRITABLE)
            .write_phys(hbin_page_paddr, &hbin_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let found = find_subkey(&reader, hive_base, &parent_data, "InventoryApplicationFile");
        assert_eq!(
            found,
            Some(child_cell_index),
            "find_subkey should locate child via li (4-byte stride) list"
        );

        // Also verify a missing name returns None (no false positives)
        let not_found = find_subkey(&reader, hive_base, &parent_data, "NoSuchKey");
        assert!(
            not_found.is_none(),
            "find_subkey should return None for absent name"
        );
    }

    // ── read_cell_data unit tests ─────────────────────────────────────

    /// read_cell_data returns None for cell_index == 0.
    #[test]
    fn read_cell_data_zero_index_returns_none() {
        let reader = make_empty_reader();
        assert!(read_cell_data(&reader, 0x0020_0000, 0, 256).is_none());
    }

    /// read_cell_data returns None for cell_index == 0xFFFF_FFFF.
    #[test]
    fn read_cell_data_sentinel_index_returns_none() {
        let reader = make_empty_reader();
        assert!(read_cell_data(&reader, 0x0020_0000, 0xFFFF_FFFF, 256).is_none());
    }

    /// read_cell_data returns None when the cell address is unmapped.
    #[test]
    fn read_cell_data_unmapped_returns_none() {
        let reader = make_empty_reader();
        assert!(read_cell_data(&reader, 0xDEAD_BEEF_0000, 0x100, 256).is_none());
    }

    /// read_cell_data returns None when raw_size yields data_size == 0.
    #[test]
    fn read_cell_data_zero_size_returns_none() {
        let hive_base: u64 = 0x0050_0000;
        let hive_paddr: u64 = 0x0050_0000;
        let cell_index: u32 = 0x100;
        let cell_vaddr = hive_base + HBIN_START_OFFSET + cell_index as u64;

        // Allocate a page at hive_base (needed) and cell page.
        let mut hbin_page = vec![0u8; 0x1000];
        let cell_off = (cell_index as usize) % 0x1000;
        // raw_size = -4: absolute = 4, data_size = 4 - 4 = 0 → None
        let raw_size: i32 = -4i32;
        hbin_page[cell_off..cell_off + 4].copy_from_slice(&raw_size.to_le_bytes());

        let isf = make_amcache_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_base, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &vec![0u8; 0x1000])
            .map_4k(cell_vaddr & !0xFFF, cell_vaddr & !0xFFF, flags::WRITABLE)
            .write_phys(cell_vaddr & !0xFFF, &hbin_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        assert!(read_cell_data(&reader, hive_base, cell_index, 256).is_none());
    }

    /// read_cell_data returns data when everything is valid.
    #[test]
    fn read_cell_data_valid_returns_data() {
        let hive_base: u64 = 0x0060_0000;
        let hive_paddr: u64 = 0x0060_0000;
        let cell_index: u32 = 0x100;
        let cell_vaddr = hive_base + HBIN_START_OFFSET + cell_index as u64;

        let mut hbin_page = vec![0u8; 0x1000];
        let cell_off = (cell_index as usize) % 0x1000;
        // raw_size = -20: absolute = 20, data_size = 16
        let raw_size: i32 = -20i32;
        hbin_page[cell_off..cell_off + 4].copy_from_slice(&raw_size.to_le_bytes());
        // Place NK_SIGNATURE bytes in the data area
        let data_off = cell_off + 4;
        hbin_page[data_off] = 0x6E; // 'n'
        hbin_page[data_off + 1] = 0x6B; // 'k'

        let isf = make_amcache_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_base, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &vec![0u8; 0x1000])
            .map_4k(cell_vaddr & !0xFFF, cell_vaddr & !0xFFF, flags::WRITABLE)
            .write_phys(cell_vaddr & !0xFFF, &hbin_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let data = read_cell_data(&reader, hive_base, cell_index, 256);
        assert!(data.is_some());
        let d = data.unwrap();
        assert!(d.len() >= 2);
        assert_eq!(d[0], 0x6E);
        assert_eq!(d[1], 0x6B);
    }

    // ── read_value_u64 REG_DWORD and unknown type ─────────────────────

    /// read_value_u64 returns 0 when vk_data is shorter than VK_NAME_OFFSET.
    #[test]
    fn read_value_u64_short_data_returns_zero() {
        let reader = make_empty_reader();
        let short = vec![0u8; 4]; // VK_NAME_OFFSET = 0x14 > 4
        assert_eq!(read_value_u64(&reader, 0, &short), 0);
    }

    /// read_value_u64 with REG_DWORD inline value returns u32 widened to u64.
    #[test]
    fn read_value_u64_reg_dword_inline() {
        let reader = make_empty_reader();
        let mut vk = vec![0u8; 0x20];
        // value_type = REG_DWORD (4) at VK_TYPE_OFFSET (0x0C)
        vk[VK_TYPE_OFFSET..VK_TYPE_OFFSET + 4].copy_from_slice(&(REG_DWORD as u32).to_le_bytes());
        // data_length = 0x8000_0004 (inline, 4 bytes) at VK_DATA_LENGTH_OFFSET (0x04)
        let inline_len: u32 = 0x8000_0004;
        vk[VK_DATA_LENGTH_OFFSET..VK_DATA_LENGTH_OFFSET + 4]
            .copy_from_slice(&inline_len.to_le_bytes());
        // Inline data at VK_DATA_OFFSET (0x08): value = 0x0000_0042
        let value: u32 = 0x42;
        vk[VK_DATA_OFFSET..VK_DATA_OFFSET + 4].copy_from_slice(&value.to_le_bytes());

        assert_eq!(read_value_u64(&reader, 0, &vk), 0x42u64);
    }

    /// read_value_u64 with unknown type returns 0.
    #[test]
    fn read_value_u64_unknown_type_returns_zero() {
        let reader = make_empty_reader();
        let mut vk = vec![0u8; 0x20];
        // value_type = 99 (unknown) at VK_TYPE_OFFSET
        vk[VK_TYPE_OFFSET..VK_TYPE_OFFSET + 4].copy_from_slice(&99u32.to_le_bytes());
        // data_length inline = 4 bytes
        let inline_len: u32 = 0x8000_0004;
        vk[VK_DATA_LENGTH_OFFSET..VK_DATA_LENGTH_OFFSET + 4]
            .copy_from_slice(&inline_len.to_le_bytes());

        assert_eq!(read_value_u64(&reader, 0, &vk), 0);
    }

    // ── read_value_string inline data path ───────────────────────────

    /// read_value_string returns empty when vk_data is shorter than VK_NAME_OFFSET.
    #[test]
    fn read_value_string_short_data_returns_empty() {
        let reader = make_empty_reader();
        let short = vec![0u8; 4];
        assert_eq!(read_value_string(&reader, 0, &short), "");
    }

    /// read_value_string returns empty when data_length is 0.
    #[test]
    fn read_value_string_zero_length_returns_empty() {
        let reader = make_empty_reader();
        let vk = vec![0u8; 0x20];
        // data_length = 0 → early return
        assert_eq!(read_value_string(&reader, 0, &vk), "");
    }

    /// read_value_string decodes inline UTF-16LE correctly (2 bytes for 'A').
    #[test]
    fn read_value_string_inline_utf16() {
        let reader = make_empty_reader();
        let mut vk = vec![0u8; 0x20];
        // 'A' in UTF-16LE = [0x41, 0x00]
        // data_length = 0x8000_0002 (inline, 2 bytes)
        let inline_len: u32 = 0x8000_0002;
        vk[VK_DATA_LENGTH_OFFSET..VK_DATA_LENGTH_OFFSET + 4]
            .copy_from_slice(&inline_len.to_le_bytes());
        // Inline data at VK_DATA_OFFSET (0x08)
        vk[VK_DATA_OFFSET] = 0x41;
        vk[VK_DATA_OFFSET + 1] = 0x00;

        let result = read_value_string(&reader, 0, &vk);
        assert_eq!(result, "A");
    }

    // ── find_value: no values → returns None ─────────────────────────

    /// find_value returns None when key_data is too short.
    #[test]
    fn find_value_short_key_data_returns_none() {
        let reader = make_empty_reader();
        let short = vec![0u8; 4]; // NK_VALUES_LIST_OFFSET + 4 = 0x2C
        assert!(find_value(&reader, 0, &short, "LowerCaseLongPath").is_none());
    }

    /// find_value returns None when value_count is 0.
    #[test]
    fn find_value_zero_count_returns_none() {
        let reader = make_empty_reader();
        let key_data = vec![0u8; 0x40]; // value_count at NK_VALUE_COUNT_OFFSET = 0
        assert!(find_value(&reader, 0, &key_data, "LowerCaseLongPath").is_none());
    }

    // ── find_subkey: no subkeys → returns None ────────────────────────

    /// find_subkey returns None when parent_data is too short.
    #[test]
    fn find_subkey_short_parent_data_returns_none() {
        let reader = make_empty_reader();
        let short = vec![0u8; 4]; // NK_STABLE_SUBKEYS_LIST_OFFSET + 4 = 0x20
        assert!(find_subkey(&reader, 0, &short, "InventoryApplicationFile").is_none());
    }

    /// find_subkey returns None when subkey_count is 0.
    #[test]
    fn find_subkey_zero_count_returns_none() {
        let reader = make_empty_reader();
        let parent_data = vec![0u8; 0x30]; // subkey_count at NK_STABLE_SUBKEY_COUNT_OFFSET = 0
        assert!(find_subkey(&reader, 0, &parent_data, "InventoryApplicationFile").is_none());
    }

    /// find_subkey: lf list with one entry pointing to a child nk with a matching name.
    /// This covers the inner loop body of find_subkey including the NK_SIGNATURE check
    /// and name comparison.
    #[test]
    fn find_subkey_lf_list_finds_matching_child() {
        // hive_base: the HBASE_BLOCK. HBIN area = hive_base + 0x1000.
        // list cell index = 0x100 → list_vaddr = hive_base + 0x1100
        // child cell index = 0x200 → child_vaddr = hive_base + 0x1200
        // Place list and child on the same 4K HBIN page (both within page at hive_base+0x1000).
        let hive_base: u64 = 0x0090_0000;

        let list_cell_index: u32 = 0x100;
        let child_cell_index: u32 = 0x200;

        let hbin_page_vaddr = hive_base + HBIN_START_OFFSET; // 0x0091_0000
        let hbin_page_paddr: u64 = 0x0091_0000;

        // parent nk_data with subkey_count=1, subkeys_list_index=0x100
        let mut parent_data = vec![0u8; 0x60];
        parent_data[NK_STABLE_SUBKEY_COUNT_OFFSET..NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        parent_data[NK_STABLE_SUBKEYS_LIST_OFFSET..NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .copy_from_slice(&list_cell_index.to_le_bytes());

        // Build the hbin page.
        // list cell at offset 0x100 within page:
        //   [i32 size=-24][sig=lf 0x666C][count=1][child_cell_index][hash=0]
        // child cell at offset 0x200 within page:
        //   [i32 size=-96][nk_data with sig=nk, name="Root"]
        let mut hbin_page = vec![0u8; 0x1000];

        let list_off = list_cell_index as usize;
        hbin_page[list_off..list_off + 4].copy_from_slice(&(-24i32).to_le_bytes());
        // lf sig = [0x6C, 0x66] (0x666C in LE)
        hbin_page[list_off + 4] = 0x6C;
        hbin_page[list_off + 5] = 0x66;
        // count = 1
        hbin_page[list_off + 6..list_off + 8].copy_from_slice(&1u16.to_le_bytes());
        // entry[0]: child_cell_index
        hbin_page[list_off + 8..list_off + 12].copy_from_slice(&child_cell_index.to_le_bytes());
        // hash (ignored)
        hbin_page[list_off + 12..list_off + 16].copy_from_slice(&0u32.to_le_bytes());

        let child_off = child_cell_index as usize;
        // abs_size = NK_NAME_OFFSET + 4 + 4 + 4 = large enough; use 0x80=128
        hbin_page[child_off..child_off + 4].copy_from_slice(&(-0x80i32).to_le_bytes());
        // nk sig = 0x6B6E → bytes [0x6E, 0x6B]
        hbin_page[child_off + 4] = 0x6E;
        hbin_page[child_off + 5] = 0x6B;
        let child_name = b"Root";
        // NK_NAME_LENGTH_OFFSET = 0x48 within nk_data → page offset = child_off + 4 + 0x48
        hbin_page[child_off + 4 + NK_NAME_LENGTH_OFFSET..child_off + 4 + NK_NAME_LENGTH_OFFSET + 2]
            .copy_from_slice(&(child_name.len() as u16).to_le_bytes());
        hbin_page
            [child_off + 4 + NK_NAME_OFFSET..child_off + 4 + NK_NAME_OFFSET + child_name.len()]
            .copy_from_slice(child_name);

        let isf = make_amcache_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hbin_page_vaddr, hbin_page_paddr, flags::WRITABLE)
            .write_phys(hbin_page_paddr, &hbin_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // Should find "Root"
        let result = find_subkey(&reader, hive_base, &parent_data, "Root");
        assert_eq!(
            result,
            Some(child_cell_index),
            "find_subkey should return child_cell_index for 'Root'"
        );

        // Should not find a name that isn't there
        let result2 = find_subkey(&reader, hive_base, &parent_data, "NoSuchKey");
        assert!(
            result2.is_none(),
            "find_subkey should return None for missing name"
        );
    }

    /// read_value_string non-inline path: data is stored in a separate cell.
    /// Covers the `else` branch at line 291 (is_inline == false).
    #[test]
    fn read_value_string_non_inline_utf16() {
        // hive_base + HBIN_START + data_cell_index → data page
        let hive_base: u64 = 0x00A0_0000;
        let data_cell_index: u32 = 0x100;
        let data_page_vaddr = hive_base + HBIN_START_OFFSET; // 0x00A1_0000
        let data_page_paddr: u64 = 0x00A1_0000;

        // String "AB" in UTF-16LE = [0x41, 0x00, 0x42, 0x00] = 4 bytes.
        let utf16_bytes: &[u8] = &[0x41, 0x00, 0x42, 0x00];
        let real_len = utf16_bytes.len();

        // Build vk_data: non-inline, data_length = real_len, data_cell_index.
        let mut vk = vec![0u8; 0x30];
        // data_length (not inline) = real_len
        vk[VK_DATA_LENGTH_OFFSET..VK_DATA_LENGTH_OFFSET + 4]
            .copy_from_slice(&(real_len as u32).to_le_bytes());
        // data_cell_index at VK_DATA_OFFSET
        vk[VK_DATA_OFFSET..VK_DATA_OFFSET + 4].copy_from_slice(&data_cell_index.to_le_bytes());

        // data cell on hbin page at offset data_cell_index:
        // [i32 size = -(4 + real_len)][utf16 bytes]
        let mut data_page = vec![0u8; 0x1000];
        let cell_off = data_cell_index as usize;
        let cell_size: i32 = -((4 + real_len) as i32);
        data_page[cell_off..cell_off + 4].copy_from_slice(&cell_size.to_le_bytes());
        data_page[cell_off + 4..cell_off + 4 + real_len].copy_from_slice(utf16_bytes);

        let isf = make_amcache_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(data_page_vaddr, data_page_paddr, flags::WRITABLE)
            .write_phys(data_page_paddr, &data_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = read_value_string(&reader, hive_base, &vk);
        assert_eq!(result, "AB", "non-inline UTF-16LE should decode to 'AB'");
    }

    /// Mapped hive; root cell has NK_SIGNATURE but no InventoryApplicationFile
    /// or Root subkey → walk returns empty Vec.
    #[test]
    fn walk_amcache_mapped_hive_nk_no_subkeys() {
        let hive_vaddr: u64 = 0x0040_0000;
        let hive_paddr: u64 = 0x0040_0000;
        let base_block: u64 = 0x0041_0000;
        let base_block_paddr: u64 = 0x0041_0000;

        let root_cell_index: u32 = 0x20;
        let cell_page_base: u64 = base_block + HBIN_START_OFFSET; // 0x0042_0000
        let cell_page_paddr: u64 = cell_page_base;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        bb_page[0x24..0x28].copy_from_slice(&root_cell_index.to_le_bytes());

        // Build NK cell at offset root_cell_index within the HBIN page.
        // Cell layout: [i32 size (negative)] [nk data...]
        // nk data: NK_SIGNATURE at [0..2], stable_subkey_count=0 at [0x14..0x18]
        let mut hbin_page = vec![0u8; 0x1000];
        let cell_off = root_cell_index as usize;
        let raw_size: i32 = -0x80i32; // 128-byte allocated cell
        hbin_page[cell_off..cell_off + 4].copy_from_slice(&raw_size.to_le_bytes());
        let nk_data_off = cell_off + 4;
        // NK_SIGNATURE = 0x6B6E
        hbin_page[nk_data_off..nk_data_off + 2].copy_from_slice(&NK_SIGNATURE.to_le_bytes());
        // stable_subkey_count = 0 at nk_data[0x14..0x18] → find_subkey returns None
        // (already zero from vec initialisation)

        let isf = make_amcache_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .map_4k(cell_page_base, cell_page_paddr, flags::WRITABLE)
            .write_phys(cell_page_paddr, &hbin_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_amcache(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty(), "nk with no subkeys → empty Vec");
    }

    // ── read_value_u64: REG_QWORD non-inline path ────────────────────

    /// read_value_u64 with REG_QWORD (11) stored in a separate cell returns u64.
    #[test]
    fn read_value_u64_reg_qword_non_inline() {
        let hive_base: u64 = 0x00B0_0000;
        let data_cell_index: u32 = 0x100;
        let data_page_vaddr = hive_base + HBIN_START_OFFSET;
        let data_page_paddr: u64 = 0x00B1_0000;

        // 8-byte QWORD value = 0x0102030405060708
        let qword_val: u64 = 0x0102_0304_0506_0708;
        let qword_bytes = qword_val.to_le_bytes();

        // data cell
        let mut data_page = vec![0u8; 0x1000];
        let cell_off = data_cell_index as usize;
        let cell_size: i32 = -((4 + 8) as i32);
        data_page[cell_off..cell_off + 4].copy_from_slice(&cell_size.to_le_bytes());
        data_page[cell_off + 4..cell_off + 12].copy_from_slice(&qword_bytes);

        // Build vk_data: non-inline REG_QWORD
        let mut vk = vec![0u8; 0x20];
        // value_type = REG_QWORD (11)
        vk[VK_TYPE_OFFSET..VK_TYPE_OFFSET + 4].copy_from_slice(&11u32.to_le_bytes());
        // data_length = 8 (not inline, no MSB)
        vk[VK_DATA_LENGTH_OFFSET..VK_DATA_LENGTH_OFFSET + 4].copy_from_slice(&8u32.to_le_bytes());
        // data_cell_index at VK_DATA_OFFSET
        vk[VK_DATA_OFFSET..VK_DATA_OFFSET + 4].copy_from_slice(&data_cell_index.to_le_bytes());

        let isf = make_amcache_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(data_page_vaddr, data_page_paddr, flags::WRITABLE)
            .write_phys(data_page_paddr, &data_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = read_value_u64(&reader, hive_base, &vk);
        assert_eq!(
            result, qword_val,
            "REG_QWORD non-inline should return correct u64"
        );
    }

    // ── find_value: VK_SIGNATURE mismatch skipped ───────────────────

    /// find_value with a value list cell where the vk cell has bad sig → skipped → None.
    #[test]
    fn find_value_bad_vk_sig_skipped_returns_none() {
        let hive_base: u64 = 0x00C0_0000;
        let list_cell_index: u32 = 0x100;
        let vk_cell_index: u32 = 0x200;
        let hbin_vaddr = hive_base + HBIN_START_OFFSET;
        let hbin_paddr: u64 = 0x00C1_0000;

        // value list cell: 1 entry = vk_cell_index
        let mut list_page = vec![0u8; 0x1000];
        // list cell at offset 0x100
        let list_off = list_cell_index as usize;
        let list_size: i32 = -((4 + 4) as i32);
        list_page[list_off..list_off + 4].copy_from_slice(&list_size.to_le_bytes());
        list_page[list_off + 4..list_off + 8].copy_from_slice(&vk_cell_index.to_le_bytes());

        // vk cell at offset 0x200 with bad sig
        let vk_off = vk_cell_index as usize;
        let vk_size: i32 = -((4 + 0x20) as i32);
        list_page[vk_off..vk_off + 4].copy_from_slice(&vk_size.to_le_bytes());
        // sig = 0x0000 (bad), rest zeros

        let isf = make_amcache_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hbin_vaddr, hbin_paddr, flags::WRITABLE)
            .write_phys(hbin_paddr, &list_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // Build key_data with value_count=1, values_list_index=list_cell_index
        let mut key_data = vec![0u8; 0x40];
        key_data[NK_VALUE_COUNT_OFFSET..NK_VALUE_COUNT_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        key_data[NK_VALUES_LIST_OFFSET..NK_VALUES_LIST_OFFSET + 4]
            .copy_from_slice(&list_cell_index.to_le_bytes());

        let result = find_value(&reader, hive_base, &key_data, "TestValue");
        assert!(result.is_none(), "bad vk sig should be skipped → None");
    }

    // ── walk_amcache: Root subkey found, IAF not under it → empty ───

    /// walk_amcache finds a "Root" subkey but InventoryApplicationFile is not
    /// a child of Root → returns empty Vec. Exercises the `root_child` branch.
    #[test]
    fn walk_amcache_root_found_iaf_not_found() {
        // Layout:
        //   hive_vaddr = 0x00D0_0000
        //   base_block = 0x00D1_0000
        //   hive_base = base_block (used for cell addressing)
        //   cell storage = hive_base + HBIN_START_OFFSET = 0x00D2_0000
        //
        // Root nk → has subkey "Root" (no IAF under Root) → returns empty.

        let hive_vaddr: u64 = 0x00D0_0000;
        let hive_paddr: u64 = 0x00D0_0000;
        let base_block: u64 = 0x00D1_0000;
        let base_block_paddr: u64 = 0x00D1_0000;
        let cell_page_base: u64 = base_block + HBIN_START_OFFSET; // 0x00D2_0000
        let cell_page_paddr: u64 = cell_page_base;

        // root_cell_index relative to cell_page_base; read_cell_data uses:
        // hive_base + HBIN_START_OFFSET + cell_index
        // where hive_base = base_block = 0x00D1_0000
        // cell_page_base = 0x00D1_0000 + 0x1000 = 0x00D2_0000
        // cell at index 0x20 → vaddr = 0x00D2_0020

        let root_cell_idx: u32 = 0x20;
        let root_child_list_idx: u32 = 0x100;
        let root_child_idx: u32 = 0x180; // the "Root" NK

        // ---- build hive page: BaseBlock pointer at +0x10 ----
        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());

        // ---- build base_block page: root_cell at 0x24 ----
        let mut bb_page = vec![0u8; 0x1000];
        bb_page[0x24..0x28].copy_from_slice(&root_cell_idx.to_le_bytes());

        // ---- build cell page ----
        // All cells are stored here at their index offsets.
        let mut cell_page = vec![0u8; 0x1000];

        // Helper: write cell = [i32 neg size][data] at offset
        fn write_cell(page: &mut Vec<u8>, off: usize, data: &[u8]) {
            let size: i32 = -((4 + data.len()) as i32);
            page[off..off + 4].copy_from_slice(&size.to_le_bytes());
            page[off + 4..off + 4 + data.len()].copy_from_slice(data);
        }

        // Root NK: NK_SIGNATURE, stable_subkey_count=1, subkeys_list=root_child_list_idx
        let mut root_nk = vec![0u8; 0x60];
        root_nk[0..2].copy_from_slice(&NK_SIGNATURE.to_le_bytes());
        // stable_subkey_count at NK_STABLE_SUBKEY_COUNT_OFFSET (0x14)
        root_nk[NK_STABLE_SUBKEY_COUNT_OFFSET..NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        // subkeys list at NK_STABLE_SUBKEYS_LIST_OFFSET (0x1C)
        root_nk[NK_STABLE_SUBKEYS_LIST_OFFSET..NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .copy_from_slice(&root_child_list_idx.to_le_bytes());
        // name_length at NK_NAME_LENGTH_OFFSET (0x48), name at NK_NAME_OFFSET (0x4C)
        let root_name = b"root_hive";
        root_nk[NK_NAME_LENGTH_OFFSET..NK_NAME_LENGTH_OFFSET + 2]
            .copy_from_slice(&(root_name.len() as u16).to_le_bytes());
        // Extend root_nk to hold name
        root_nk.resize(NK_NAME_OFFSET + root_name.len(), 0);
        root_nk[NK_NAME_OFFSET..NK_NAME_OFFSET + root_name.len()].copy_from_slice(root_name);

        write_cell(&mut cell_page, root_cell_idx as usize, &root_nk);

        // List cell (lf): sig=0x666C, count=1, entry[child_idx, hash=0]
        let mut list_data = vec![0u8; 12];
        list_data[0..2].copy_from_slice(&0x666Cu16.to_le_bytes());
        list_data[2..4].copy_from_slice(&1u16.to_le_bytes());
        list_data[4..8].copy_from_slice(&root_child_idx.to_le_bytes());
        write_cell(&mut cell_page, root_child_list_idx as usize, &list_data);

        // "Root" NK: NK_SIGNATURE, no subkeys → find_subkey("IAF") returns None
        let mut root_child_nk = vec![0u8; NK_NAME_OFFSET + 4];
        root_child_nk[0..2].copy_from_slice(&NK_SIGNATURE.to_le_bytes());
        // stable_subkey_count = 0 → find_subkey returns None
        let child_name = b"Root";
        root_child_nk[NK_NAME_LENGTH_OFFSET..NK_NAME_LENGTH_OFFSET + 2]
            .copy_from_slice(&(child_name.len() as u16).to_le_bytes());
        root_child_nk[NK_NAME_OFFSET..NK_NAME_OFFSET + child_name.len()]
            .copy_from_slice(child_name);
        write_cell(&mut cell_page, root_child_idx as usize, &root_child_nk);

        let isf = make_amcache_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .map_4k(cell_page_base, cell_page_paddr, flags::WRITABLE)
            .write_phys(cell_page_paddr, &cell_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_amcache(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty(), "Root found but no IAF → empty Vec");
    }

    // ── read_value_string: non-inline cell read fails → empty ───────

    /// read_value_string non-inline where cell read fails (unmapped) → empty.
    #[test]
    fn read_value_string_non_inline_unmapped_returns_empty() {
        let reader = make_empty_reader();
        let mut vk = vec![0u8; 0x20];
        // data_length = 10 (not inline)
        vk[VK_DATA_LENGTH_OFFSET..VK_DATA_LENGTH_OFFSET + 4].copy_from_slice(&10u32.to_le_bytes());
        // data_cell_index points to unmapped memory
        vk[VK_DATA_OFFSET..VK_DATA_OFFSET + 4].copy_from_slice(&0xDEADu32.to_le_bytes());

        // hive_base = 0 → cell_vaddr = 0 + HBIN_START + 0xDEAD → unmapped
        let result = read_value_string(&reader, 0, &vk);
        assert_eq!(result, "");
    }

    // ── read_value_u64: non-inline cell read fails → 0 ──────────────

    /// read_value_u64 non-inline where cell read fails → 0.
    #[test]
    fn read_value_u64_non_inline_unmapped_returns_zero() {
        let reader = make_empty_reader();
        let mut vk = vec![0u8; 0x20];
        // value_type = REG_QWORD
        vk[VK_TYPE_OFFSET..VK_TYPE_OFFSET + 4].copy_from_slice(&11u32.to_le_bytes());
        // data_length = 8 (not inline)
        vk[VK_DATA_LENGTH_OFFSET..VK_DATA_LENGTH_OFFSET + 4].copy_from_slice(&8u32.to_le_bytes());
        // unmapped cell index
        vk[VK_DATA_OFFSET..VK_DATA_OFFSET + 4].copy_from_slice(&0xDEADu32.to_le_bytes());

        let result = read_value_u64(&reader, 0, &vk);
        assert_eq!(result, 0);
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

    // ── walk_amcache: IAF with one child (no valid NK sig) → empty ───────
    //
    // Build a hive where InventoryApplicationFile is a direct child of root and
    // has one child entry whose cell has a bad NK signature → child skipped → empty Vec.
    // This exercises lines 532-549 (the enumeration loop with sig check).

    fn build_iaf_hive(flat_page: &mut Vec<u8>, child_nk_sig: u16) -> (u64, u32) {
        // Layout within flat_page:
        //   root NK: cell_off = 0x020 → addr = 0x024
        //   root list: cell_off = 0x060 → addr = 0x064
        //   IAF NK: cell_off = 0x0A0 → addr = 0x0A4
        //   IAF list: cell_off = 0x0E0 → addr = 0x0E4
        //   child NK: cell_off = 0x120 → addr = 0x124
        let root_cell_off: u32 = 0x020;
        let root_list_off: u32 = 0x060;
        let iaf_cell_off: u32 = 0x0A0;
        let iaf_list_off: u32 = 0x0E0;
        let child_cell_off: u32 = 0x120;

        let a = |off: u32| (off + 4) as usize; // addr offset in page

        // Root NK: subkey_count=1, list=root_list_off, name len=0
        flat_page[a(root_cell_off) + NK_STABLE_SUBKEY_COUNT_OFFSET
            ..a(root_cell_off) + NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        flat_page[a(root_cell_off) + NK_STABLE_SUBKEYS_LIST_OFFSET
            ..a(root_cell_off) + NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .copy_from_slice(&root_list_off.to_le_bytes());
        // NK_SIGNATURE at root
        flat_page[a(root_cell_off)..a(root_cell_off) + 2]
            .copy_from_slice(&NK_SIGNATURE.to_le_bytes());

        // Root list: lf, count=1, entry[0]=iaf_cell_off
        flat_page[a(root_list_off)] = 0x6C; // 'l'
        flat_page[a(root_list_off) + 1] = 0x66; // 'f'
        flat_page[a(root_list_off) + 2..a(root_list_off) + 4].copy_from_slice(&1u16.to_le_bytes());
        flat_page[a(root_list_off) + 4..a(root_list_off) + 8]
            .copy_from_slice(&iaf_cell_off.to_le_bytes());

        // IAF NK: NK_SIGNATURE, name="InventoryApplicationFile", subkey_count=1, list=iaf_list_off
        flat_page[a(iaf_cell_off)..a(iaf_cell_off) + 2]
            .copy_from_slice(&NK_SIGNATURE.to_le_bytes());
        flat_page[a(iaf_cell_off) + NK_STABLE_SUBKEY_COUNT_OFFSET
            ..a(iaf_cell_off) + NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        flat_page[a(iaf_cell_off) + NK_STABLE_SUBKEYS_LIST_OFFSET
            ..a(iaf_cell_off) + NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .copy_from_slice(&iaf_list_off.to_le_bytes());
        let iaf_name = b"InventoryApplicationFile";
        flat_page
            [a(iaf_cell_off) + NK_NAME_LENGTH_OFFSET..a(iaf_cell_off) + NK_NAME_LENGTH_OFFSET + 2]
            .copy_from_slice(&(iaf_name.len() as u16).to_le_bytes());
        flat_page
            [a(iaf_cell_off) + NK_NAME_OFFSET..a(iaf_cell_off) + NK_NAME_OFFSET + iaf_name.len()]
            .copy_from_slice(iaf_name);

        // IAF list: lf, count=1, entry[0]=child_cell_off
        flat_page[a(iaf_list_off)] = 0x6C;
        flat_page[a(iaf_list_off) + 1] = 0x66;
        flat_page[a(iaf_list_off) + 2..a(iaf_list_off) + 4].copy_from_slice(&1u16.to_le_bytes());
        flat_page[a(iaf_list_off) + 4..a(iaf_list_off) + 8]
            .copy_from_slice(&child_cell_off.to_le_bytes());

        // Child NK: given signature (to control NK_SIGNATURE check)
        flat_page[a(child_cell_off)..a(child_cell_off) + 2]
            .copy_from_slice(&child_nk_sig.to_le_bytes());
        // Make cell big enough: NK_NAME_OFFSET + 4 bytes of name
        // child NK has no values (value_count=0 at NK_VALUE_COUNT_OFFSET)

        (root_cell_off as u64, root_cell_off)
    }

    /// walk_amcache: IAF found directly under root, IAF has one child with bad NK sig
    /// → child skipped → empty Vec. Exercises lines 532-549.
    #[test]
    fn walk_amcache_iaf_child_bad_sig_skipped() {
        let hive_vaddr: u64 = 0x00E0_0000;
        let hive_paddr: u64 = 0x00E0_0000;
        let base_block: u64 = 0x00E1_0000;
        let base_block_paddr: u64 = 0x00E1_0000;
        let cell_page_base: u64 = base_block + HBIN_START_OFFSET; // 0x00E2_0000
        let cell_page_paddr: u64 = cell_page_base;

        let root_cell_off: u32 = 0x020;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        bb_page[0x24..0x28].copy_from_slice(&root_cell_off.to_le_bytes());

        let mut cell_page = vec![0u8; 0x1000];
        build_iaf_hive(&mut cell_page, 0x0000u16); // bad sig for child

        // Build cell sizes (each cell needs a negative i32 size header just before its data)
        // write_cell: at offset off in page, write [i32_neg_size][data]
        // read_cell_data reads: size at cell_vaddr, data at cell_vaddr+4
        // cell_vaddr = hive_base + HBIN_START_OFFSET + cell_index
        // So we write size header at cell_index offset in cell_page
        // The data is already at cell_index+4 offset (which is addr offset)
        // We need to write the size at each cell_index offset
        for off in &[0x020u32, 0x060, 0x0A0, 0x0E0, 0x120] {
            // abs size = 0x80 (allocated 128-byte cell); stored as -0x80
            let size: i32 = -0x80i32;
            cell_page[*off as usize..*off as usize + 4].copy_from_slice(&size.to_le_bytes());
        }

        let isf = make_amcache_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .map_4k(cell_page_base, cell_page_paddr, flags::WRITABLE)
            .write_phys(cell_page_paddr, &cell_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_amcache(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty(), "child with bad NK sig → skipped → empty");
    }

    /// walk_amcache: IAF found directly under root, IAF has one child with valid NK sig
    /// and no values → one entry pushed with all-default fields.
    /// Exercises lines 547-592 (the full value extraction loop).
    #[test]
    fn walk_amcache_iaf_child_valid_nk_no_values_one_entry() {
        let hive_vaddr: u64 = 0x00F0_0000;
        let hive_paddr: u64 = 0x00F0_0000;
        let base_block: u64 = 0x00F1_0000;
        let base_block_paddr: u64 = 0x00F1_0000;
        let cell_page_base: u64 = base_block + HBIN_START_OFFSET; // 0x00F2_0000
        let cell_page_paddr: u64 = cell_page_base;

        let root_cell_off: u32 = 0x020;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        bb_page[0x24..0x28].copy_from_slice(&root_cell_off.to_le_bytes());

        let mut cell_page = vec![0u8; 0x1000];
        build_iaf_hive(&mut cell_page, NK_SIGNATURE); // valid NK sig for child

        // Write size headers
        for off in &[0x020u32, 0x060, 0x0A0, 0x0E0, 0x120] {
            let size: i32 = -0x80i32;
            cell_page[*off as usize..*off as usize + 4].copy_from_slice(&size.to_le_bytes());
        }

        // Make child NK data long enough for NK_NAME_OFFSET (0x4C bytes of nk_data)
        // The nk_data starts at child_cell_off + 4 within cell_page.
        // NK_NAME_OFFSET = 0x4C, so we need at least 0x4C bytes of nk data.
        // With size -0x80, data_size = 0x80 - 4 = 0x7C bytes. 0x7C >= 0x4C. OK.

        let isf = make_amcache_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .map_4k(cell_page_base, cell_page_paddr, flags::WRITABLE)
            .write_phys(cell_page_paddr, &cell_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_amcache(&reader, hive_vaddr).unwrap();
        // One child with valid NK sig, no values → one AmcacheEntry with empty/default fields.
        assert_eq!(result.len(), 1, "valid child NK with no values → one entry");
        assert_eq!(result[0].file_path, "");
        assert_eq!(result[0].sha1_hash, "");
        assert_eq!(result[0].file_size, 0);
        assert_eq!(result[0].link_timestamp, 0);
        assert_eq!(result[0].publisher, "");
        assert!(result[0].is_suspicious, "empty publisher → suspicious");
    }

    /// walk_amcache: IAF found under root, child data too short (< NK_NAME_OFFSET) → continue.
    /// Exercises the `Some(d) if d.len() >= NK_NAME_OFFSET` guard (line 543).
    #[test]
    fn walk_amcache_iaf_child_data_too_short_skipped() {
        // Build hive with child cell that has very small allocated size
        // (abs_size = 8 → data_size = 4, which < NK_NAME_OFFSET=0x4C).
        let hive_vaddr: u64 = 0x00B0_0000;
        let hive_paddr: u64 = 0x00B0_0000;
        let base_block: u64 = 0x00B1_0000;
        let base_block_paddr: u64 = 0x00B1_0000;
        let cell_page_base: u64 = base_block + HBIN_START_OFFSET;
        let cell_page_paddr: u64 = cell_page_base;

        let root_cell_off: u32 = 0x020;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        bb_page[0x24..0x28].copy_from_slice(&root_cell_off.to_le_bytes());

        let mut cell_page = vec![0u8; 0x1000];
        build_iaf_hive(&mut cell_page, NK_SIGNATURE);

        // Write large size headers for all cells except child
        for off in &[0x020u32, 0x060, 0x0A0, 0x0E0] {
            let size: i32 = -0x80i32;
            cell_page[*off as usize..*off as usize + 4].copy_from_slice(&size.to_le_bytes());
        }
        // Child cell at 0x120: very small size → data_size = 4 < NK_NAME_OFFSET
        let size: i32 = -8i32; // abs=8, data=4
        cell_page[0x120..0x124].copy_from_slice(&size.to_le_bytes());

        let isf = make_amcache_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .map_4k(cell_page_base, cell_page_paddr, flags::WRITABLE)
            .write_phys(cell_page_paddr, &cell_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_amcache(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty(), "child data too short → skipped → empty");
    }

    /// walk_amcache: IAF has subkey_count=0 → returns empty Vec immediately.
    /// Exercises the `if subkey_count == 0` guard at line 513.
    #[test]
    fn walk_amcache_iaf_zero_subkeys_returns_empty() {
        // Same layout but IAF NK has subkey_count=0.
        let hive_vaddr: u64 = 0x00C5_0000;
        let hive_paddr: u64 = 0x00C5_0000;
        let base_block: u64 = 0x00C6_0000;
        let base_block_paddr: u64 = 0x00C6_0000;
        let cell_page_base: u64 = base_block + HBIN_START_OFFSET;
        let cell_page_paddr: u64 = cell_page_base;

        let root_cell_off: u32 = 0x020;
        let root_list_off: u32 = 0x060;
        let iaf_cell_off: u32 = 0x0A0;

        let a = |off: u32| (off + 4) as usize;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        bb_page[0x24..0x28].copy_from_slice(&root_cell_off.to_le_bytes());

        let mut cell_page = vec![0u8; 0x1000];

        // Root NK → IAF NK (one subkey)
        cell_page[a(root_cell_off)..a(root_cell_off) + 2]
            .copy_from_slice(&NK_SIGNATURE.to_le_bytes());
        cell_page[a(root_cell_off) + NK_STABLE_SUBKEY_COUNT_OFFSET
            ..a(root_cell_off) + NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        cell_page[a(root_cell_off) + NK_STABLE_SUBKEYS_LIST_OFFSET
            ..a(root_cell_off) + NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .copy_from_slice(&root_list_off.to_le_bytes());

        // Root list → IAF
        cell_page[a(root_list_off)] = 0x6C;
        cell_page[a(root_list_off) + 1] = 0x66;
        cell_page[a(root_list_off) + 2..a(root_list_off) + 4].copy_from_slice(&1u16.to_le_bytes());
        cell_page[a(root_list_off) + 4..a(root_list_off) + 8]
            .copy_from_slice(&iaf_cell_off.to_le_bytes());

        // IAF NK: NK_SIGNATURE, subkey_count=0, IAF name
        cell_page[a(iaf_cell_off)..a(iaf_cell_off) + 2]
            .copy_from_slice(&NK_SIGNATURE.to_le_bytes());
        // subkey_count=0 already (zeros)
        let iaf_name = b"InventoryApplicationFile";
        cell_page
            [a(iaf_cell_off) + NK_NAME_LENGTH_OFFSET..a(iaf_cell_off) + NK_NAME_LENGTH_OFFSET + 2]
            .copy_from_slice(&(iaf_name.len() as u16).to_le_bytes());
        cell_page
            [a(iaf_cell_off) + NK_NAME_OFFSET..a(iaf_cell_off) + NK_NAME_OFFSET + iaf_name.len()]
            .copy_from_slice(iaf_name);

        // Size headers
        for off in &[0x020u32, 0x060, 0x0A0] {
            let size: i32 = -0x80i32;
            cell_page[*off as usize..*off as usize + 4].copy_from_slice(&size.to_le_bytes());
        }

        let isf = make_amcache_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .map_4k(cell_page_base, cell_page_paddr, flags::WRITABLE)
            .write_phys(cell_page_paddr, &cell_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_amcache(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty(), "IAF subkey_count=0 → empty Vec");
    }
}
