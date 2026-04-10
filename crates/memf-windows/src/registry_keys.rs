//! Registry key/value enumeration (printkey equivalent).
//!
//! Walks registry hive cells to enumerate key names, values, and timestamps.
//! Unlike [`super::registry`] which only lists loaded hives, this module reads
//! actual key/value data from the hive's cell storage.
//!
//! ## Hive internals
//!
//! - `hive_addr` is the virtual address of the `_HBASE_BLOCK` (hive header,
//!   typically at `_HHIVE.BaseBlock`).
//! - `_HBASE_BLOCK.RootCell` (offset 0x24, u32) — cell index of root key node.
//! - Cell storage starts at `hive_addr + 0x1000` (first HBIN).
//! - Each cell: `i32` size (negative = allocated), followed by cell data.
//! - Key node (`_CM_KEY_NODE`): Signature `0x6B6E` ("nk"), Flags, LastWriteTime,
//!   SubKeyCount, SubKeys pointer, ValueCount, Values pointer, NameLength, Name.
//! - Value node (`_CM_KEY_VALUE`): Signature `0x6B76` ("vk"), NameLength,
//!   DataLength, DataOffset, Type, Name.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

// ── _HBASE_BLOCK offsets ─────────────────────────────────────────────

/// Offset of `RootCell` (u32) within `_HBASE_BLOCK`.
const HBASE_BLOCK_ROOT_CELL_OFFSET: u64 = 0x24;

/// Offset from `_HBASE_BLOCK` to the first HBIN (cell storage start).
const HBIN_START_OFFSET: u64 = 0x1000;

// ── CM_KEY_NODE ("nk") layout offsets (relative to cell data start) ──

/// Signature: u16 at offset 0 — must be 0x6B6E ("nk").
const NK_SIGNATURE: u16 = 0x6B6E;
/// Flags: u16 at offset 2.
const _NK_FLAGS_OFFSET: usize = 2;
/// LastWriteTime: u64 at offset 4.
const NK_LAST_WRITE_TIME_OFFSET: usize = 4;
/// Number of values: u32 at offset 24 (0x18) — volatile subkey count at 0x18,
/// we actually need values count at 0x28.
/// Corrected: SubKeyCount(stable)@0x10, SubKeyCount(volatile)@0x14 — no.
///
/// Actual _CM_KEY_NODE layout (from Windows internals):
///   0x00: Signature (u16) "nk"
///   0x02: Flags (u16)
///   0x04: LastWriteTime (u64)
///   0x0C: AccessBits (u32)  [Win8+, overlaps Spare]
///   0x10: Parent (u32) — cell index of parent key
///   0x14: SubKeyCounts[0] (u32) — stable subkey count
///   0x18: SubKeyCounts[1] (u32) — volatile subkey count
///   0x1C: SubKeys[0] (u32) — stable subkeys list cell index
///   0x20: SubKeys[1] (u32) — volatile subkeys list cell index
///   0x24: ValueCount (u32)
///   0x28: Values (u32) — cell index of value-list cell
///   0x2C: Security (u32)
///   0x30: Class (u32)
///   0x34: MaxNameLen (u32)
///   0x38: MaxClassLen (u32)
///   0x3C: MaxValueNameLen (u32)
///   0x40: MaxValueDataLen (u32)
///   0x44: WorkVar (u32)
///   0x48: NameLength (u16)
///   0x4A: ClassLength (u16)
///   0x4C: Name (variable, ASCII or UTF-16)
const NK_PARENT_OFFSET: usize = 0x10;
const NK_STABLE_SUBKEY_COUNT_OFFSET: usize = 0x14;
const NK_STABLE_SUBKEYS_LIST_OFFSET: usize = 0x1C;
const NK_VALUE_COUNT_OFFSET: usize = 0x24;
const NK_VALUES_LIST_OFFSET: usize = 0x28;
const NK_NAME_LENGTH_OFFSET: usize = 0x48;
const NK_NAME_OFFSET: usize = 0x4C;

// ── CM_KEY_VALUE ("vk") layout offsets ───────────────────────────────

/// Signature: u16 at offset 0 — must be 0x6B76 ("vk").
const VK_SIGNATURE: u16 = 0x6B76;
/// NameLength: u16 at offset 2.
const VK_NAME_LENGTH_OFFSET: usize = 0x02;
/// DataLength: u32 at offset 4.
const VK_DATA_LENGTH_OFFSET: usize = 0x04;
/// DataOffset: u32 at offset 8 — cell index of data, or inline if DataLength MSB set.
const VK_DATA_OFFSET_OFFSET: usize = 0x08;
/// Type: u32 at offset 12 (0x0C).
const VK_TYPE_OFFSET: usize = 0x0C;
/// Name starts at offset 20 (0x14).
const VK_NAME_OFFSET: usize = 0x14;

// ── Maximum limits ───────────────────────────────────────────────────

/// Maximum recursion depth for key walking.
const MAX_DEPTH: usize = 512;
/// Maximum number of keys to enumerate (safety limit).
const MAX_KEY_COUNT: usize = 100_000;
/// Maximum number of values per key.
const MAX_VALUE_COUNT: usize = 10_000;

// ── Output types ─────────────────────────────────────────────────────

/// Information about a single registry key extracted from a `_CM_KEY_NODE` cell.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegistryKeyInfo {
    /// Full path of the key (e.g., `\CMI-CreateHive{...}\ControlSet001\Services`).
    pub path: String,
    /// Last write time as a Windows FILETIME (100-ns intervals since 1601-01-01).
    pub last_write_time: u64,
    /// Number of (stable) subkeys.
    pub subkey_count: u32,
    /// Number of values attached to this key.
    pub value_count: u32,
}

/// Information about a single registry value extracted from a `_CM_KEY_VALUE` cell.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegistryValueInfo {
    /// Full path of the parent key.
    pub key_path: String,
    /// Value name (empty string for the default value).
    pub name: String,
    /// Human-readable value type (e.g., `"REG_SZ"`, `"REG_DWORD"`).
    pub value_type: String,
    /// Size of the value data in bytes.
    pub data_length: u32,
    /// Short preview of the value data (truncated for display).
    pub data_preview: String,
}

// ── Public API ───────────────────────────────────────────────────────

/// Walk registry keys starting from the root of a hive.
///
/// `hive_addr` is the virtual address of the `_HBASE_BLOCK` (the value
/// stored in `RegistryHive::hive_addr` / `_HHIVE.BaseBlock`).
///
/// Returns all key nodes reachable up to `max_depth` levels deep.
/// Returns an empty `Vec` if the root cell index is zero.
pub fn walk_registry_keys<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    max_depth: usize,
) -> crate::Result<Vec<RegistryKeyInfo>> {
    // Read root cell index from _HBASE_BLOCK
    let root_cell_bytes =
        reader.read_bytes(hive_addr.wrapping_add(HBASE_BLOCK_ROOT_CELL_OFFSET), 4)?;
    let root_cell = u32::from_le_bytes(root_cell_bytes[..4].try_into().unwrap());

    if root_cell == 0 {
        return Ok(Vec::new());
    }

    let depth = max_depth.min(MAX_DEPTH);
    let mut keys = Vec::new();
    walk_key_recursive(
        reader,
        hive_addr,
        root_cell,
        String::new(),
        depth,
        &mut keys,
    )?;
    Ok(keys)
}

/// Read registry values for a specific key identified by its cell offset.
///
/// `hive_addr` is the virtual address of the `_HBASE_BLOCK`.
/// `key_cell_offset` is the cell index of the `_CM_KEY_NODE`.
pub fn read_registry_values<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    key_cell_offset: u32,
) -> crate::Result<Vec<RegistryValueInfo>> {
    let cell_vaddr = cell_address(hive_addr, key_cell_offset);

    // Read enough of the key node to get value count and value list pointer.
    let nk_data = read_cell_data(reader, cell_vaddr)?;

    // Validate nk signature
    let sig = u16::from_le_bytes(nk_data[0..2].try_into().unwrap());
    if sig != NK_SIGNATURE {
        return Err(crate::Error::Walker(format!(
            "expected nk signature 0x{NK_SIGNATURE:04X}, got 0x{sig:04X} at cell offset 0x{key_cell_offset:08X}"
        )));
    }

    let value_count = u32::from_le_bytes(
        nk_data[NK_VALUE_COUNT_OFFSET..NK_VALUE_COUNT_OFFSET + 4]
            .try_into()
            .unwrap(),
    );

    if value_count == 0 {
        return Ok(Vec::new());
    }

    let values_list_cell = u32::from_le_bytes(
        nk_data[NK_VALUES_LIST_OFFSET..NK_VALUES_LIST_OFFSET + 4]
            .try_into()
            .unwrap(),
    );

    // The value list cell contains an array of u32 cell indices (one per value).
    let vl_vaddr = cell_address(hive_addr, values_list_cell);
    let vl_data = read_cell_data(reader, vl_vaddr)?;

    let key_name = read_key_name(&nk_data);
    let count = (value_count as usize).min(MAX_VALUE_COUNT);

    let mut values = Vec::with_capacity(count);
    for i in 0..count {
        let off = i * 4;
        if off + 4 > vl_data.len() {
            break;
        }
        let val_cell = u32::from_le_bytes(vl_data[off..off + 4].try_into().unwrap());
        match read_single_value(reader, hive_addr, val_cell, &key_name) {
            Ok(v) => values.push(v),
            Err(_) => continue, // skip corrupt values
        }
    }

    Ok(values)
}

// ── Internal helpers ─────────────────────────────────────────────────

/// Compute the virtual address of a cell given its cell index.
///
/// Cells are addressed relative to the start of cell storage (HBIN area),
/// which begins at `hive_addr + 0x1000`.
fn cell_address(hive_addr: u64, cell_index: u32) -> u64 {
    hive_addr
        .wrapping_add(HBIN_START_OFFSET)
        .wrapping_add(cell_index as u64)
}

/// Read cell data from a cell at `cell_vaddr`.
///
/// The first 4 bytes are an i32 size (negative = allocated). We skip the
/// size field and return the data portion.
fn read_cell_data<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    cell_vaddr: u64,
) -> crate::Result<Vec<u8>> {
    // Read the cell size (i32)
    let size_bytes = reader.read_bytes(cell_vaddr, 4)?;
    let raw_size = i32::from_le_bytes(size_bytes[..4].try_into().unwrap());

    // Allocated cells have negative size; the absolute value is the total cell
    // size including the 4-byte size field itself.
    let abs_size = raw_size.unsigned_abs() as usize;
    if abs_size <= 4 {
        return Ok(Vec::new());
    }

    let data_len = abs_size - 4;
    // Cap read to prevent runaway reads on corrupt data
    let capped_len = data_len.min(0x10000);
    reader
        .read_bytes(cell_vaddr.wrapping_add(4), capped_len)
        .map_err(Into::into)
}

/// Extract the key name from an nk cell's data bytes.
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

    // Registry key names are typically ASCII (compressed), not UTF-16.
    // The NK_KEY_COMP_NAME flag (0x0020) in Flags indicates compressed ASCII.
    String::from_utf8_lossy(&nk_data[NK_NAME_OFFSET..end]).into_owned()
}

/// Recursively walk key nodes.
fn walk_key_recursive<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    cell_index: u32,
    parent_path: String,
    remaining_depth: usize,
    keys: &mut Vec<RegistryKeyInfo>,
) -> crate::Result<()> {
    if keys.len() >= MAX_KEY_COUNT {
        return Ok(());
    }

    let cell_vaddr = cell_address(hive_addr, cell_index);
    let nk_data = read_cell_data(reader, cell_vaddr)?;

    if nk_data.len() < NK_NAME_OFFSET {
        return Ok(());
    }

    // Validate nk signature
    let sig = u16::from_le_bytes(nk_data[0..2].try_into().unwrap());
    if sig != NK_SIGNATURE {
        return Ok(());
    }

    let key_name = read_key_name(&nk_data);
    let path = if parent_path.is_empty() {
        key_name.clone()
    } else {
        format!("{parent_path}\\{key_name}")
    };

    let last_write_time = u64::from_le_bytes(
        nk_data[NK_LAST_WRITE_TIME_OFFSET..NK_LAST_WRITE_TIME_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    let subkey_count = u32::from_le_bytes(
        nk_data[NK_STABLE_SUBKEY_COUNT_OFFSET..NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    let value_count = u32::from_le_bytes(
        nk_data[NK_VALUE_COUNT_OFFSET..NK_VALUE_COUNT_OFFSET + 4]
            .try_into()
            .unwrap(),
    );

    keys.push(RegistryKeyInfo {
        path: path.clone(),
        last_write_time,
        subkey_count,
        value_count,
    });

    // Recurse into subkeys if depth allows and there are subkeys
    if remaining_depth == 0 || subkey_count == 0 {
        return Ok(());
    }

    let subkeys_list_cell = u32::from_le_bytes(
        nk_data[NK_STABLE_SUBKEYS_LIST_OFFSET..NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .try_into()
            .unwrap(),
    );

    // The subkeys list cell can be an "lf", "lh", "ri", or "li" index node.
    // For simplicity, we handle "lf"/"lh" (most common) and fall back gracefully.
    let sl_vaddr = cell_address(hive_addr, subkeys_list_cell);
    let sl_data = read_cell_data(reader, sl_vaddr)?;

    if sl_data.len() < 4 {
        return Ok(());
    }

    let list_sig = u16::from_le_bytes(sl_data[0..2].try_into().unwrap());
    let list_count = u16::from_le_bytes(sl_data[2..4].try_into().unwrap()) as usize;

    match list_sig {
        // "lf" (0x666C) or "lh" (0x686C): each entry is 8 bytes (cell_index: u32, hash: u32)
        0x666C | 0x686C => {
            for i in 0..list_count {
                if keys.len() >= MAX_KEY_COUNT {
                    break;
                }
                let entry_off = 4 + i * 8;
                if entry_off + 4 > sl_data.len() {
                    break;
                }
                let child_cell =
                    u32::from_le_bytes(sl_data[entry_off..entry_off + 4].try_into().unwrap());
                walk_key_recursive(
                    reader,
                    hive_addr,
                    child_cell,
                    path.clone(),
                    remaining_depth - 1,
                    keys,
                )?;
            }
        }
        // "li" (0x696C): each entry is 4 bytes (cell_index: u32)
        0x696C => {
            for i in 0..list_count {
                if keys.len() >= MAX_KEY_COUNT {
                    break;
                }
                let entry_off = 4 + i * 4;
                if entry_off + 4 > sl_data.len() {
                    break;
                }
                let child_cell =
                    u32::from_le_bytes(sl_data[entry_off..entry_off + 4].try_into().unwrap());
                walk_key_recursive(
                    reader,
                    hive_addr,
                    child_cell,
                    path.clone(),
                    remaining_depth - 1,
                    keys,
                )?;
            }
        }
        // "ri" (0x6972): index of indices — each entry is a cell_index to another lf/lh/li
        0x6972 => {
            for i in 0..list_count {
                if keys.len() >= MAX_KEY_COUNT {
                    break;
                }
                let entry_off = 4 + i * 4;
                if entry_off + 4 > sl_data.len() {
                    break;
                }
                let sub_list_cell =
                    u32::from_le_bytes(sl_data[entry_off..entry_off + 4].try_into().unwrap());
                // Read the sub-list and enumerate its children
                let sub_vaddr = cell_address(hive_addr, sub_list_cell);
                let sub_data = read_cell_data(reader, sub_vaddr)?;
                if sub_data.len() < 4 {
                    continue;
                }
                let sub_sig = u16::from_le_bytes(sub_data[0..2].try_into().unwrap());
                let sub_count = u16::from_le_bytes(sub_data[2..4].try_into().unwrap()) as usize;
                let entry_size = match sub_sig {
                    0x666C | 0x686C => 8,
                    0x696C => 4,
                    _ => continue,
                };
                for j in 0..sub_count {
                    if keys.len() >= MAX_KEY_COUNT {
                        break;
                    }
                    let off = 4 + j * entry_size;
                    if off + 4 > sub_data.len() {
                        break;
                    }
                    let child_cell = u32::from_le_bytes(sub_data[off..off + 4].try_into().unwrap());
                    walk_key_recursive(
                        reader,
                        hive_addr,
                        child_cell,
                        path.clone(),
                        remaining_depth - 1,
                        keys,
                    )?;
                }
            }
        }
        _ => {
            // Unknown list type — skip silently
        }
    }

    Ok(())
}

/// Read a single value node.
fn read_single_value<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    val_cell: u32,
    key_path: &str,
) -> crate::Result<RegistryValueInfo> {
    let vk_vaddr = cell_address(hive_addr, val_cell);
    let vk_data = read_cell_data(reader, vk_vaddr)?;

    if vk_data.len() < VK_NAME_OFFSET {
        return Err(crate::Error::Walker("vk cell too small".into()));
    }

    let sig = u16::from_le_bytes(vk_data[0..2].try_into().unwrap());
    if sig != VK_SIGNATURE {
        return Err(crate::Error::Walker(format!(
            "expected vk signature 0x{VK_SIGNATURE:04X}, got 0x{sig:04X}"
        )));
    }

    let name_length = u16::from_le_bytes(
        vk_data[VK_NAME_LENGTH_OFFSET..VK_NAME_LENGTH_OFFSET + 2]
            .try_into()
            .unwrap(),
    ) as usize;

    let data_length_raw = u32::from_le_bytes(
        vk_data[VK_DATA_LENGTH_OFFSET..VK_DATA_LENGTH_OFFSET + 4]
            .try_into()
            .unwrap(),
    );

    let data_offset = u32::from_le_bytes(
        vk_data[VK_DATA_OFFSET_OFFSET..VK_DATA_OFFSET_OFFSET + 4]
            .try_into()
            .unwrap(),
    );

    let value_type_raw = u32::from_le_bytes(
        vk_data[VK_TYPE_OFFSET..VK_TYPE_OFFSET + 4]
            .try_into()
            .unwrap(),
    );

    let name = if name_length == 0 {
        String::new() // default value
    } else {
        let end = VK_NAME_OFFSET + name_length;
        if end <= vk_data.len() {
            String::from_utf8_lossy(&vk_data[VK_NAME_OFFSET..end]).into_owned()
        } else {
            String::new()
        }
    };

    let value_type = reg_type_name(value_type_raw);

    // DataLength MSB set means data is stored inline in the DataOffset field
    let (actual_data_length, data_preview) = if data_length_raw & 0x8000_0000 != 0 {
        let inline_len = (data_length_raw & 0x7FFF_FFFF).min(4);
        let inline_bytes = data_offset.to_le_bytes();
        let preview = format_data_preview(value_type_raw, &inline_bytes[..inline_len as usize]);
        (inline_len, preview)
    } else if data_length_raw > 0 && data_length_raw < 0x8000_0000 {
        // Data is in a separate cell
        let data_vaddr = cell_address(hive_addr, data_offset);
        match read_cell_data(reader, data_vaddr) {
            Ok(data_cell) => {
                let len = (data_length_raw as usize).min(data_cell.len());
                let preview = format_data_preview(value_type_raw, &data_cell[..len]);
                (data_length_raw, preview)
            }
            Err(_) => (data_length_raw, "<unreadable>".to_string()),
        }
    } else {
        (0, String::new())
    };

    Ok(RegistryValueInfo {
        key_path: key_path.to_string(),
        name,
        value_type,
        data_length: actual_data_length,
        data_preview,
    })
}

/// Convert a registry value type number to its human-readable name.
fn reg_type_name(t: u32) -> String {
    match t {
        0 => "REG_NONE".into(),
        1 => "REG_SZ".into(),
        2 => "REG_EXPAND_SZ".into(),
        3 => "REG_BINARY".into(),
        4 => "REG_DWORD".into(),
        5 => "REG_DWORD_BIG_ENDIAN".into(),
        6 => "REG_LINK".into(),
        7 => "REG_MULTI_SZ".into(),
        8 => "REG_RESOURCE_LIST".into(),
        9 => "REG_FULL_RESOURCE_DESCRIPTOR".into(),
        10 => "REG_RESOURCE_REQUIREMENTS_LIST".into(),
        11 => "REG_QWORD".into(),
        other => format!("REG_UNKNOWN({other})"),
    }
}

/// Format a short preview of value data based on its type.
fn format_data_preview(value_type: u32, data: &[u8]) -> String {
    match value_type {
        // REG_SZ, REG_EXPAND_SZ, REG_LINK
        1 | 2 | 6 => {
            // UTF-16LE string
            if data.len() < 2 {
                return String::new();
            }
            let words: Vec<u16> = data
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&w| w != 0)
                .collect();
            let s = String::from_utf16_lossy(&words);
            if s.len() > 80 {
                format!("{}...", &s[..80])
            } else {
                s
            }
        }
        // REG_DWORD
        4 => {
            if data.len() >= 4 {
                let v = u32::from_le_bytes(data[..4].try_into().unwrap());
                format!("0x{v:08X} ({v})")
            } else {
                format!("{data:02X?}")
            }
        }
        // REG_QWORD
        11 => {
            if data.len() >= 8 {
                let v = u64::from_le_bytes(data[..8].try_into().unwrap());
                format!("0x{v:016X} ({v})")
            } else {
                format!("{data:02X?}")
            }
        }
        // REG_BINARY, REG_NONE, and others: hex preview
        _ => {
            let preview_len = data.len().min(32);
            let hex: Vec<String> = data[..preview_len]
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect();
            let s = hex.join(" ");
            if data.len() > 32 {
                format!("{s}...")
            } else {
                s
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Helper: build a minimal ISF resolver (no kernel symbols needed for
    /// registry_keys since we read raw cell data, not ISF-resolved structs).
    fn make_reader(
        builder: PageTableBuilder,
    ) -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// Build a cell: i32 size (negative = allocated) followed by cell data.
    fn build_cell(data: &[u8]) -> Vec<u8> {
        // Total cell size = 4 (size field) + data.len(), rounded up to 8
        let total = ((4 + data.len() + 7) & !7) as i32;
        let neg_size = -total; // negative = allocated
        let mut cell = Vec::with_capacity(total as usize);
        cell.extend_from_slice(&neg_size.to_le_bytes());
        cell.extend_from_slice(data);
        // Pad to alignment
        cell.resize(total as usize, 0);
        cell
    }

    /// Build an nk (key node) cell data buffer.
    ///
    /// Returns the raw cell data (without the 4-byte size prefix).
    fn build_nk_cell_data(
        name: &str,
        last_write_time: u64,
        stable_subkey_count: u32,
        stable_subkeys_list: u32,
        value_count: u32,
        values_list: u32,
    ) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let total_len = NK_NAME_OFFSET + name_bytes.len();
        let mut data = vec![0u8; total_len];

        // Signature "nk"
        data[0..2].copy_from_slice(&NK_SIGNATURE.to_le_bytes());
        // Flags — set KEY_COMP_NAME (0x0020) for ASCII name
        data[2..4].copy_from_slice(&0x0020u16.to_le_bytes());
        // LastWriteTime
        data[NK_LAST_WRITE_TIME_OFFSET..NK_LAST_WRITE_TIME_OFFSET + 8]
            .copy_from_slice(&last_write_time.to_le_bytes());
        // Parent (unused in these tests)
        data[NK_PARENT_OFFSET..NK_PARENT_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
        // Stable subkey count
        data[NK_STABLE_SUBKEY_COUNT_OFFSET..NK_STABLE_SUBKEY_COUNT_OFFSET + 4]
            .copy_from_slice(&stable_subkey_count.to_le_bytes());
        // Stable subkeys list cell index
        data[NK_STABLE_SUBKEYS_LIST_OFFSET..NK_STABLE_SUBKEYS_LIST_OFFSET + 4]
            .copy_from_slice(&stable_subkeys_list.to_le_bytes());
        // Value count
        data[NK_VALUE_COUNT_OFFSET..NK_VALUE_COUNT_OFFSET + 4]
            .copy_from_slice(&value_count.to_le_bytes());
        // Values list cell index
        data[NK_VALUES_LIST_OFFSET..NK_VALUES_LIST_OFFSET + 4]
            .copy_from_slice(&values_list.to_le_bytes());
        // NameLength
        data[NK_NAME_LENGTH_OFFSET..NK_NAME_LENGTH_OFFSET + 2]
            .copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        // Name
        data[NK_NAME_OFFSET..NK_NAME_OFFSET + name_bytes.len()].copy_from_slice(name_bytes);

        data
    }

    /// Build a vk (value node) cell data buffer.
    fn build_vk_cell_data(
        name: &str,
        value_type: u32,
        data_length: u32,
        data_offset: u32,
    ) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let total_len = VK_NAME_OFFSET + name_bytes.len();
        let mut data = vec![0u8; total_len];

        // Signature "vk"
        data[0..2].copy_from_slice(&VK_SIGNATURE.to_le_bytes());
        // NameLength
        data[VK_NAME_LENGTH_OFFSET..VK_NAME_LENGTH_OFFSET + 2]
            .copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        // DataLength
        data[VK_DATA_LENGTH_OFFSET..VK_DATA_LENGTH_OFFSET + 4]
            .copy_from_slice(&data_length.to_le_bytes());
        // DataOffset (cell index or inline data)
        data[VK_DATA_OFFSET_OFFSET..VK_DATA_OFFSET_OFFSET + 4]
            .copy_from_slice(&data_offset.to_le_bytes());
        // Type
        data[VK_TYPE_OFFSET..VK_TYPE_OFFSET + 4].copy_from_slice(&value_type.to_le_bytes());
        // Name
        data[VK_NAME_OFFSET..VK_NAME_OFFSET + name_bytes.len()].copy_from_slice(name_bytes);

        data
    }

    // ── reg_type_name coverage ──────────────────────────────────────

    #[test]
    fn reg_type_name_all_known() {
        assert_eq!(reg_type_name(0), "REG_NONE");
        assert_eq!(reg_type_name(1), "REG_SZ");
        assert_eq!(reg_type_name(2), "REG_EXPAND_SZ");
        assert_eq!(reg_type_name(3), "REG_BINARY");
        assert_eq!(reg_type_name(4), "REG_DWORD");
        assert_eq!(reg_type_name(5), "REG_DWORD_BIG_ENDIAN");
        assert_eq!(reg_type_name(6), "REG_LINK");
        assert_eq!(reg_type_name(7), "REG_MULTI_SZ");
        assert_eq!(reg_type_name(8), "REG_RESOURCE_LIST");
        assert_eq!(reg_type_name(9), "REG_FULL_RESOURCE_DESCRIPTOR");
        assert_eq!(reg_type_name(10), "REG_RESOURCE_REQUIREMENTS_LIST");
        assert_eq!(reg_type_name(11), "REG_QWORD");
    }

    #[test]
    fn reg_type_name_unknown() {
        let name = reg_type_name(99);
        assert!(
            name.starts_with("REG_UNKNOWN("),
            "unknown type should produce REG_UNKNOWN(N): {name}"
        );
    }

    // ── format_data_preview coverage ────────────────────────────────

    #[test]
    fn format_data_preview_reg_dword() {
        // REG_DWORD (4): 4-byte LE u32 formatted as hex+decimal
        let data = 42u32.to_le_bytes();
        let preview = format_data_preview(4, &data);
        assert!(
            preview.contains("42"),
            "REG_DWORD preview should contain decimal value: {preview}"
        );
        assert!(
            preview.contains("0x"),
            "REG_DWORD preview should contain hex: {preview}"
        );
    }

    #[test]
    fn format_data_preview_reg_dword_short_data() {
        // If data is < 4 bytes, falls through to hex preview
        let data = &[0xABu8];
        let preview = format_data_preview(4, data);
        // Should not panic; hex format applied
        assert!(!preview.is_empty());
    }

    #[test]
    fn format_data_preview_reg_qword() {
        // REG_QWORD (11): 8-byte LE u64
        let data = 0x0102030405060708u64.to_le_bytes();
        let preview = format_data_preview(11, &data);
        assert!(
            preview.contains("0x"),
            "REG_QWORD preview should contain hex: {preview}"
        );
    }

    #[test]
    fn format_data_preview_reg_qword_short_data() {
        // < 8 bytes → hex fallback
        let data = &[0x01u8, 0x02u8];
        let preview = format_data_preview(11, data);
        assert!(!preview.is_empty());
    }

    #[test]
    fn format_data_preview_reg_sz_utf16() {
        // REG_SZ (1): UTF-16LE "Hi"
        let s: Vec<u8> = "Hi"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .chain([0u8, 0u8]) // null terminator
            .collect();
        let preview = format_data_preview(1, &s);
        assert_eq!(preview, "Hi");
    }

    #[test]
    fn format_data_preview_reg_expand_sz() {
        // REG_EXPAND_SZ (2) same decoding as REG_SZ
        let s: Vec<u8> = "%SystemRoot%"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let preview = format_data_preview(2, &s);
        assert_eq!(preview, "%SystemRoot%");
    }

    #[test]
    fn format_data_preview_reg_binary() {
        // REG_BINARY (3): hex dump
        let data = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        let preview = format_data_preview(3, &data);
        assert!(preview.contains("DE"), "binary preview should hex-dump: {preview}");
    }

    #[test]
    fn format_data_preview_reg_binary_truncated_at_32() {
        // More than 32 bytes → preview truncated with "..."
        let data = vec![0xAAu8; 64];
        let preview = format_data_preview(3, &data);
        assert!(
            preview.ends_with("..."),
            "long binary preview should be truncated: {preview}"
        );
    }

    #[test]
    fn format_data_preview_reg_sz_empty_data() {
        // REG_SZ with less than 2 bytes → empty string
        let preview = format_data_preview(1, &[0x41u8]);
        assert!(preview.is_empty(), "single-byte REG_SZ should be empty: {preview}");
    }

    // ── Inline value (MSB set in DataLength) ────────────────────────

    #[test]
    fn read_registry_values_inline_reg_dword() {
        // Build a key with 1 value where DataLength has MSB set (inline data).
        // Inline: DataLength = 0x8000_0004 (4 bytes inline), DataOffset = value 0xDEAD_BEEF

        let hive_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let hive_paddr: u64 = 0x0080_0000;
        let hbin_vaddr: u64 = hive_vaddr + HBIN_START_OFFSET;
        let hbin_paddr: u64 = hive_paddr + HBIN_START_OFFSET as u64;

        let nk_offset: u32 = 0x20;
        let vl_offset: u32 = 0x100;
        let vk_offset: u32 = 0x120;

        // nk cell: 1 value
        let nk_data = build_nk_cell_data("InlineKey", 0, 0, 0, 1, vl_offset);
        let nk_cell = build_cell(&nk_data);

        // value-list: one entry → vk_offset
        let vl_data = vk_offset.to_le_bytes();
        let vl_cell = build_cell(&vl_data);

        // vk cell: "InlineVal", REG_DWORD, DataLength has MSB set (inline 4 bytes)
        // DataOffset = 0x0000_002A (decimal 42) stored inline
        let vk_data = build_vk_cell_data(
            "InlineVal",
            4,                   // REG_DWORD
            0x8000_0004,         // MSB set → 4 inline bytes
            42u32,               // inline value = 42
        );
        let vk_cell = build_cell(&vk_data);

        let mut hbin_page = vec![0u8; 4096];
        hbin_page[nk_offset as usize..nk_offset as usize + nk_cell.len()].copy_from_slice(&nk_cell);
        hbin_page[vl_offset as usize..vl_offset as usize + vl_cell.len()].copy_from_slice(&vl_cell);
        hbin_page[vk_offset as usize..vk_offset as usize + vk_cell.len()].copy_from_slice(&vk_cell);

        let hbase_block = vec![0u8; 4096];

        let ptb = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .map_4k(hbin_vaddr, hbin_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hbase_block)
            .write_phys(hbin_paddr, &hbin_page);

        let reader = make_reader(ptb);
        let values = read_registry_values(&reader, hive_vaddr, nk_offset).unwrap();

        assert_eq!(values.len(), 1);
        assert_eq!(values[0].name, "InlineVal");
        assert_eq!(values[0].value_type, "REG_DWORD");
        // Inline data length should be 4
        assert_eq!(values[0].data_length, 4);
        // Preview should show the inline value (42 = 0x0000002A)
        assert!(
            values[0].data_preview.contains("42") || values[0].data_preview.contains("2A"),
            "preview should show inline value 42: {}",
            values[0].data_preview
        );
    }

    // ── Test 1: Empty hive (root cell = 0) → empty Vec ──────────────

    #[test]
    fn walk_registry_keys_empty_hive() {
        // _HBASE_BLOCK at a known virtual address with RootCell = 0.
        let hive_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let hive_paddr: u64 = 0x0080_0000;

        // _HBASE_BLOCK: zero-filled → RootCell at offset 0x24 = 0
        let hbase_block = vec![0u8; 4096];

        let ptb = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hbase_block);

        let reader = make_reader(ptb);
        let keys = walk_registry_keys(&reader, hive_vaddr, 10).unwrap();
        assert!(keys.is_empty(), "Expected empty Vec for zero root cell");
    }

    // ── Test 2: Single key node ─────────────────────────────────────

    #[test]
    fn walk_registry_keys_single_key() {
        // Memory layout:
        //   Page 0 (vaddr 0xFFFF_8000_0010_0000): _HBASE_BLOCK
        //   Page 1 (vaddr 0xFFFF_8000_0010_1000): HBIN area (cell storage)
        //
        // _HBASE_BLOCK:
        //   RootCell at offset 0x24 = 0x20 (cell index within HBIN)
        //
        // HBIN at hive_addr + 0x1000:
        //   Cell at offset 0x20: nk cell for "CMI-CreateHive{ROOT}"

        let hive_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let hive_paddr: u64 = 0x0080_0000;
        // HBIN page is at hive_vaddr + 0x1000
        let hbin_vaddr: u64 = hive_vaddr + HBIN_START_OFFSET;
        let hbin_paddr: u64 = hive_paddr + HBIN_START_OFFSET as u64;

        // Build _HBASE_BLOCK
        let mut hbase_block = vec![0u8; 4096];
        let root_cell_index: u32 = 0x20;
        hbase_block[0x24..0x28].copy_from_slice(&root_cell_index.to_le_bytes());

        // Build the nk cell at offset 0x20 within HBIN
        let last_write: u64 = 132800000000000000;
        let nk_data = build_nk_cell_data(
            "CMI-CreateHive{ROOT}",
            last_write,
            0, // no subkeys
            0, // no subkeys list
            0, // no values
            0, // no values list
        );
        let nk_cell = build_cell(&nk_data);

        let mut hbin_page = vec![0u8; 4096];
        // Place cell at offset 0x20 within the HBIN page
        hbin_page[0x20..0x20 + nk_cell.len()].copy_from_slice(&nk_cell);

        let ptb = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .map_4k(hbin_vaddr, hbin_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hbase_block)
            .write_phys(hbin_paddr, &hbin_page);

        let reader = make_reader(ptb);
        let keys = walk_registry_keys(&reader, hive_vaddr, 10).unwrap();

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].path, "CMI-CreateHive{ROOT}");
        assert_eq!(keys[0].last_write_time, last_write);
        assert_eq!(keys[0].subkey_count, 0);
        assert_eq!(keys[0].value_count, 0);
    }

    // ── Test 3: Single value with REG_SZ data ──────────────────────

    #[test]
    fn read_registry_values_single_value() {
        // Memory layout:
        //   Page 0: _HBASE_BLOCK (unused for read_registry_values but needed for context)
        //   Page 1: HBIN with nk cell, value-list cell, vk cell, and data cell
        //
        // nk cell at offset 0x20: key "TestKey" with 1 value
        // value-list cell at offset 0x100: [vk_cell_index]
        // vk cell at offset 0x120: "TestValue", REG_SZ, data at offset 0x180
        // data cell at offset 0x180: UTF-16LE "Hello"

        let hive_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let hive_paddr: u64 = 0x0080_0000;
        let hbin_vaddr: u64 = hive_vaddr + HBIN_START_OFFSET;
        let hbin_paddr: u64 = hive_paddr + HBIN_START_OFFSET as u64;

        // Key cell offset (used as the key_cell_offset parameter)
        let nk_offset: u32 = 0x20;
        let vl_offset: u32 = 0x100; // value list cell offset
        let vk_offset: u32 = 0x120; // vk cell offset
        let data_cell_offset: u32 = 0x180; // data cell offset

        // Build nk cell
        let nk_data = build_nk_cell_data(
            "TestKey", 0, 0,         // no subkeys
            0,         // no subkeys list
            1,         // 1 value
            vl_offset, // value list cell
        );
        let nk_cell = build_cell(&nk_data);

        // Build value-list cell: array of one u32 cell index
        let vl_data = vk_offset.to_le_bytes();
        let vl_cell = build_cell(&vl_data);

        // Build vk cell: "TestValue", REG_SZ, data in separate cell
        let data_str = "Hello";
        let data_utf16: Vec<u8> = data_str
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .chain(std::iter::repeat(0).take(2)) // null terminator
            .collect();
        let data_len = data_utf16.len() as u32;

        let vk_data = build_vk_cell_data(
            "TestValue",
            1,                // REG_SZ
            data_len,         // data length (no MSB set = external)
            data_cell_offset, // data cell index
        );
        let vk_cell = build_cell(&vk_data);

        // Build data cell: UTF-16LE "Hello\0"
        let data_cell = build_cell(&data_utf16);

        // Assemble HBIN page
        let mut hbin_page = vec![0u8; 4096];
        hbin_page[nk_offset as usize..nk_offset as usize + nk_cell.len()].copy_from_slice(&nk_cell);
        hbin_page[vl_offset as usize..vl_offset as usize + vl_cell.len()].copy_from_slice(&vl_cell);
        hbin_page[vk_offset as usize..vk_offset as usize + vk_cell.len()].copy_from_slice(&vk_cell);
        hbin_page[data_cell_offset as usize..data_cell_offset as usize + data_cell.len()]
            .copy_from_slice(&data_cell);

        // _HBASE_BLOCK (not strictly needed for read_registry_values but present)
        let hbase_block = vec![0u8; 4096];

        let ptb = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .map_4k(hbin_vaddr, hbin_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hbase_block)
            .write_phys(hbin_paddr, &hbin_page);

        let reader = make_reader(ptb);
        let values = read_registry_values(&reader, hive_vaddr, nk_offset).unwrap();

        assert_eq!(values.len(), 1);
        assert_eq!(values[0].key_path, "TestKey");
        assert_eq!(values[0].name, "TestValue");
        assert_eq!(values[0].value_type, "REG_SZ");
        assert_eq!(values[0].data_length, data_len);
        assert_eq!(values[0].data_preview, "Hello");
    }
}
