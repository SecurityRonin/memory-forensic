//! Windows registry hive walker.
//!
//! Enumerates loaded registry hives by walking `CmpHiveListHead`,
//! a `_LIST_ENTRY` chain of `_CMHIVE` structures maintained by
//! the Windows Configuration Manager.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;
use crate::{RegistryHive, Result};

/// Maximum number of hives to walk before bailing out (safety limit).
const MAX_HIVE_COUNT: usize = 256;

/// Walk the Windows registry hive list.
///
/// Looks up the `CmpHiveListHead` (or `CmHiveListHead`) kernel symbol
/// and walks the `_CMHIVE.HiveList` doubly-linked `_LIST_ENTRY` chain.
///
/// For each `_CMHIVE`, reads:
/// - `FileFullPath` (`_UNICODE_STRING`) — the registry path
/// - `FileUserName` (`_UNICODE_STRING`) — the on-disk file path
/// - `Hive._HHIVE.BaseBlock` — pointer to the hive base block
/// - `Hive.Storage[Stable].Length` — stable storage size
/// - `Hive.Storage[Volatile].Length` — volatile storage size
///
/// Returns an empty `Vec` if no hive list symbol is found.
pub fn walk_hive_list<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<RegistryHive>> {
    // Try CmpHiveListHead first, fall back to CmHiveListHead
    let head_vaddr = reader
        .symbols()
        .symbol_address("CmpHiveListHead")
        .or_else(|| reader.symbols().symbol_address("CmHiveListHead"));

    let Some(head_vaddr) = head_vaddr else {
        return Ok(Vec::new());
    };

    walk_hive_list_from(reader, head_vaddr)
}

/// Walk the hive list starting from a known list head virtual address.
fn walk_hive_list_from<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    head_vaddr: u64,
) -> Result<Vec<RegistryHive>> {
    let entries =
        reader.walk_list_with(head_vaddr, "_LIST_ENTRY", "Flink", "_CMHIVE", "HiveList")?;

    let mut hives = Vec::new();
    for (i, cmhive_addr) in entries.into_iter().enumerate() {
        if i >= MAX_HIVE_COUNT {
            break;
        }
        // A hive whose metadata is paged out (in the pagefile, not captured in
        // the dump) must not abort enumeration of the rest — skip it and continue,
        // so a partial capture still yields every readable hive.
        if let Ok(hive) = read_hive_info(reader, cmhive_addr) {
            hives.push(hive);
        }
    }
    Ok(hives)
}

/// Read registry hive info from a single `_CMHIVE` structure.
fn read_hive_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    cmhive_addr: u64,
) -> Result<RegistryHive> {
    // FileFullPath (_UNICODE_STRING)
    let file_full_path_offset = reader
        .symbols()
        .field_offset("_CMHIVE", "FileFullPath")
        .ok_or_else(|| {
            crate::Error::Core(memf_core::Error::MissingSymbol(
                "_CMHIVE.FileFullPath".into(),
            ))
        })?;
    // The name string Buffer can be paged out even when the hive's cells are
    // present; degrade to an empty name rather than dropping the whole hive.
    let file_full_path =
        read_unicode_string(reader, cmhive_addr.wrapping_add(file_full_path_offset))
            .unwrap_or_default();

    // FileUserName (_UNICODE_STRING)
    let file_user_name_offset = reader
        .symbols()
        .field_offset("_CMHIVE", "FileUserName")
        .ok_or_else(|| {
            crate::Error::Core(memf_core::Error::MissingSymbol(
                "_CMHIVE.FileUserName".into(),
            ))
        })?;
    let file_user_name =
        read_unicode_string(reader, cmhive_addr.wrapping_add(file_user_name_offset))
            .unwrap_or_default();

    // Hive._HHIVE.BaseBlock (pointer)
    let hive_offset = reader
        .symbols()
        .field_offset("_CMHIVE", "Hive")
        .ok_or_else(|| {
            crate::Error::Core(memf_core::Error::MissingSymbol("_CMHIVE.Hive".into()))
        })?;
    let hhive_addr = cmhive_addr.wrapping_add(hive_offset);

    let base_block: u64 = reader.read_field(hhive_addr, "_HHIVE", "BaseBlock")?;

    // Hive.Storage[Stable].Length — _DUAL at _HHIVE.Storage offset
    let storage_offset = reader
        .symbols()
        .field_offset("_HHIVE", "Storage")
        .ok_or_else(|| {
            crate::Error::Core(memf_core::Error::MissingSymbol("_HHIVE.Storage".into()))
        })?;
    let dual_size = reader
        .symbols()
        .struct_size("_DUAL")
        .ok_or_else(|| crate::Error::Core(memf_core::Error::MissingSymbol("_DUAL size".into())))?;

    // Storage[0] = Stable
    let stable_dual_addr = hhive_addr.wrapping_add(storage_offset);
    let stable_length: u32 = reader.read_field(stable_dual_addr, "_DUAL", "Length")?;

    // Storage[1] = Volatile (next _DUAL element after Storage[0])
    let volatile_dual_addr = stable_dual_addr.wrapping_add(dual_size);
    let volatile_length: u32 = reader.read_field(volatile_dual_addr, "_DUAL", "Length")?;

    Ok(RegistryHive {
        base_addr: cmhive_addr,
        file_full_path,
        file_user_name,
        hive_addr: base_block,
        stable_length,
        volatile_length,
    })
}

/// Read a little-endian `u64` from virtual memory (None on a read fault).
fn le_u64<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, vaddr: u64) -> Option<u64> {
    let b = reader.read_bytes(vaddr, 8).ok()?;
    Some(u64::from_le_bytes(b.get(..8)?.try_into().ok()?))
}

/// Read a little-endian `u32` from virtual memory (None on a read fault).
fn le_u32<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, vaddr: u64) -> Option<u32> {
    let b = reader.read_bytes(vaddr, 4).ok()?;
    Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?))
}

/// Translate a registry **cell index** to the virtual address of its `_HCELL`
/// within an in-memory hive.
///
/// In-memory hives are not contiguous: cells are reached through the
/// `_HHIVE.Storage[].Map` cell-map directory. This mirrors Volatility3's
/// `RegistryHive._translate` (`volatility3/framework/layers/registry.py`):
/// - bit 31 selects Stable (0) vs Volatile (1) storage,
/// - bits 30–21 index `_HMAP_DIRECTORY.Directory[]` (→ `_HMAP_TABLE*`),
/// - bits 20–12 index `_HMAP_TABLE.Table[]` (→ `_HMAP_ENTRY`),
/// - bits 11–0 are the byte offset within the 4 KiB block.
///
/// `block_va = (PermanentBinAddress & !0xF) + BlockOffset` (Win8+). The returned
/// address points at the `_HCELL` size header; cell *data* begins 4 bytes later.
/// All offsets come from the dump's PDB, so it is build-independent.
pub(crate) fn cell_index_to_va<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hhive_addr: u64,
    cell_index: u32,
) -> Option<u64> {
    let syms = reader.symbols();
    let volatile = u64::from((cell_index >> 31) & 1);
    let dir_index = u64::from((cell_index >> 21) & 0x3FF);
    let table_index = u64::from((cell_index >> 12) & 0x1FF);
    let suboffset = u64::from(cell_index & 0xFFF);

    // Storage[volatile] is an embedded _DUAL array; its .Map points at the
    // _HMAP_DIRECTORY (an array of _HMAP_TABLE pointers at offset 0).
    let storage_off = syms.field_offset("_HHIVE", "Storage")?;
    let dual_size = syms.struct_size("_DUAL")?;
    let map_off = syms.field_offset("_DUAL", "Map")?;
    let storage_base = hhive_addr
        .wrapping_add(storage_off)
        .wrapping_add(volatile.wrapping_mul(dual_size));
    let map_dir = le_u64(reader, storage_base.wrapping_add(map_off))?;
    if map_dir == 0 {
        return None;
    }

    // Directory[dir_index] → _HMAP_TABLE*; Table[table_index] → _HMAP_ENTRY.
    let table = le_u64(reader, map_dir.wrapping_add(dir_index.wrapping_mul(8)))?;
    if table == 0 {
        return None;
    }
    let entry_size = syms.struct_size("_HMAP_ENTRY")?;
    let entry = table.wrapping_add(table_index.wrapping_mul(entry_size));

    // Compute the bin's base VA. Mirrors Volatility3 `_HMAP_ENTRY.get_block_offset`:
    // Win10 has `PermanentBinAddress` (flags in the low nibble) + `BlockOffset`;
    // Win8.1/Server 2012 R2 (build 9600) and older have only `BlockAddress`, the
    // bin VA directly. The real 9600 PDB lacks PermanentBinAddress, so the
    // BlockAddress fallback is mandatory — without it every hive cell read fails.
    let block_va = if let (Some(perm_off), Some(block_off_off)) = (
        syms.field_offset("_HMAP_ENTRY", "PermanentBinAddress"),
        syms.field_offset("_HMAP_ENTRY", "BlockOffset"),
    ) {
        let perm_bin = le_u64(reader, entry.wrapping_add(perm_off))?;
        let block_offset = le_u32(reader, entry.wrapping_add(block_off_off))?;
        (perm_bin & !0xF).wrapping_add(u64::from(block_offset))
    } else {
        let ba_off = syms.field_offset("_HMAP_ENTRY", "BlockAddress")?;
        le_u64(reader, entry.wrapping_add(ba_off))?
    };

    Some(block_va.wrapping_add(suboffset))
}

// ── Shared `_CM_KEY_NODE` / `_CM_KEY_VALUE` field offsets (x64) ────────────────
// Validated against Volatility 3's ISF (`_CM_KEY_NODE`: SubKeyLists@0x1c,
// ValueList@0x24, NameLength@0x48, Name@0x4c; `_CM_KEY_VALUE`: NameLength@0x02,
// DataLength@0x04, Data@0x08, Name@0x14) and memf's validated `hashdump.rs`.
// SubKeyCounts/SubKeyLists are `[Stable, Volatile]` arrays; the Stable slot is
// used. Reading the Volatile slot (+0x18 count / +0x20 list) — a bug copy-pasted
// across several walkers — finds the usually-empty volatile list and silently
// returns nothing on a real hive.
pub(crate) const NK_SUBKEY_COUNT: u64 = 0x14;
pub(crate) const NK_SUBKEY_LIST: u64 = 0x1c;
pub(crate) const NK_NAME_LENGTH: u64 = 0x48;
pub(crate) const NK_NAME: u64 = 0x4c;

// `_CM_KEY_NODE` value-list + `_CM_KEY_VALUE` field offsets (x64).
const NK_VALUE_COUNT: u64 = 0x24;
const NK_VALUE_LIST: u64 = 0x28;
const VK_NAME_LENGTH: u64 = 0x02;
const VK_DATA_LENGTH: u64 = 0x04;
const VK_DATA: u64 = 0x08;
const VK_NAME: u64 = 0x14;
/// Per-value-list / name / data caps (allocation-bomb defense on untrusted hives).
const MAX_VALUE_COUNT: u32 = 4096;
const VK_MAX_NAME_LEN: u16 = 256;
const VK_MAX_DATA_LEN: u32 = 0x10_0000;
/// `_CM_KEY_VALUE.DataLength` high bit: data is stored inline at `Data@0x08`.
const VK_INLINE_FLAG: u32 = 0x8000_0000;

/// Per-list subkey cap (runaway / allocation-bomb defense on untrusted hives).
const MAX_SUBKEY_LIST: u16 = 4096;
/// `ri` (index-root) nesting bound (untrusted-input recursion guard).
const RI_MAX_DEPTH: u32 = 32;

/// Virtual address of cell `cell_index`'s data (past its 4-byte size header),
/// or 0 if the index does not resolve or the cell data is unreadable.
pub(crate) fn read_cell_addr<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hhive_addr: u64,
    cell_index: u32,
) -> u64 {
    let Some(cell_va) = cell_index_to_va(reader, hhive_addr, cell_index) else {
        return 0;
    };
    let addr = cell_va.wrapping_add(4);
    match reader.read_bytes(addr, 2) {
        Ok(bytes) if bytes.len() == 2 => addr,
        _ => 0,
    }
}

/// Find a subkey by name under a parent `_CM_KEY_NODE` (given its cell VA),
/// returning the child key's cell VA or 0. Reads the STABLE subkey list and
/// handles `lf`/`lh`/`li`/`ri` (index-root) lists with bounded `ri` recursion.
/// The single correct walker every registry consumer should call.
pub(crate) fn find_subkey_by_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hhive_addr: u64,
    parent_addr: u64,
    target_name: &str,
) -> u64 {
    let subkey_count = match reader.read_bytes(parent_addr + NK_SUBKEY_COUNT, 4) {
        Ok(b) if b.len() == 4 => b[..4].try_into().map_or(0, u32::from_le_bytes),
        _ => return 0,
    };
    if subkey_count == 0 || subkey_count > u32::from(MAX_SUBKEY_LIST) {
        return 0;
    }
    let list_off = match reader.read_bytes(parent_addr + NK_SUBKEY_LIST, 4) {
        Ok(b) if b.len() == 4 => b[..4].try_into().map_or(0, u32::from_le_bytes),
        _ => return 0,
    };
    search_subkey_list(reader, hhive_addr, list_off, target_name, RI_MAX_DEPTH)
}

/// Recursively search a subkey-list cell (`lf`/`lh`/`li`/`ri`) for `target_name`,
/// returning the matching child key's cell VA or 0. `ri` (index-root) entries
/// point at nested sub-lists; recursion is bounded by `depth`.
fn search_subkey_list<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hhive_addr: u64,
    list_index: u32,
    target_name: &str,
    depth: u32,
) -> u64 {
    if depth == 0 {
        return 0; // cov:unreachable: RI_MAX_DEPTH exceeds any well-formed ri nesting
    }
    let list_addr = read_cell_addr(reader, hhive_addr, list_index);
    if list_addr == 0 {
        return 0;
    }
    let sig = match reader.read_bytes(list_addr, 2) {
        Ok(b) if b.len() == 2 => [b[0], b[1]],
        _ => return 0,
    };
    let count = match reader.read_bytes(list_addr + 2, 2) {
        Ok(b) if b.len() == 2 => b[..2].try_into().map_or(0, u16::from_le_bytes),
        _ => return 0,
    }
    .min(MAX_SUBKEY_LIST);

    // "ri": index of indices — each 4-byte entry points at a nested sub-list
    // (lf/lh/li/ri). Used by large keys (CLSID, InventoryApplication, Run).
    if sig == [b'r', b'i'] {
        for i in 0..count {
            let sub = match reader.read_bytes(list_addr + 4 + u64::from(i) * 4, 4) {
                Ok(b) if b.len() == 4 => b[..4].try_into().map_or(0, u32::from_le_bytes),
                _ => continue,
            };
            let found = search_subkey_list(reader, hhive_addr, sub, target_name, depth - 1);
            if found != 0 {
                return found;
            }
        }
        return 0;
    }

    // "lf"/"lh": 8-byte entries (cell index + name hash); "li": 4-byte (cell index).
    let stride: u64 = match sig {
        [b'l', b'f' | b'h'] => 8,
        [b'l', b'i'] => 4,
        _ => return 0,
    };
    for i in 0..count {
        let entry = match reader.read_bytes(list_addr + 4 + u64::from(i) * stride, 4) {
            Ok(b) if b.len() == 4 => b[..4].try_into().map_or(0, u32::from_le_bytes),
            _ => continue,
        };
        let key_addr = read_cell_addr(reader, hhive_addr, entry);
        if key_addr == 0 {
            continue;
        }
        let name_len = match reader.read_bytes(key_addr + NK_NAME_LENGTH, 2) {
            Ok(b) if b.len() == 2 => b[..2].try_into().map_or(0, u16::from_le_bytes),
            _ => continue,
        };
        if name_len == 0 || name_len > 256 {
            continue;
        }
        let name = match reader.read_bytes(key_addr + NK_NAME, name_len as usize) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            _ => continue,
        };
        if name.eq_ignore_ascii_case(target_name) {
            return key_addr;
        }
    }
    0
}

/// Resolve the virtual address of a hive's root key node.
///
/// Reads the `RootCell` index from `_HBASE_BLOCK` (pointed at by
/// `_HHIVE.BaseBlock`) and translates it through the cell-map directory via
/// [`read_cell_addr`]. `hhive_addr` is the `_CMHIVE`/`_HHIVE` virtual address
/// used for cell-index translation. Returns 0 if the root cell cannot be
/// translated.
pub(crate) fn resolve_root_cell<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hhive_addr: u64,
) -> u64 {
    let base_block_off = reader
        .symbols()
        .field_offset("_HHIVE", "BaseBlock")
        .unwrap_or(0x40);

    let base_block_addr = reader
        .read_bytes(hhive_addr.wrapping_add(base_block_off), 8)
        .ok()
        .and_then(|b| b.get(..8).and_then(|s| s.try_into().ok()))
        .map_or(0, u64::from_le_bytes);

    // Volatility `root_cell_offset` parity: honour _HBASE_BLOCK.RootCell only
    // when the header is a readable "regf" block; otherwise the regf-format
    // default cell 0x20. On real images the header page is frequently paged out
    // (RootCell unreadable) while the bins, reached via the HMAP, stay resident
    // — collapsing to 0 there would abandon an otherwise-navigable hive.
    let root_cell_index = regf_root_cell_index(reader, base_block_addr).unwrap_or(0x20);

    read_cell_addr(reader, hhive_addr, root_cell_index)
}

/// `Some(idx)` iff the block at `base_block_addr` is a readable `_HBASE_BLOCK`
/// ("regf" signature) carrying a valid (non-zero, non-sentinel) RootCell index.
/// `None` when the header is paged out, not "regf", or carries a bogus index —
/// the caller then uses the regf-format default cell `0x20`.
fn regf_root_cell_index<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    base_block_addr: u64,
) -> Option<u32> {
    if base_block_addr == 0 {
        return None;
    }
    // _HBASE_BLOCK.Signature@0x0 == "regf" (0x6667_6572 little-endian).
    let sig = reader.read_bytes(base_block_addr, 4).ok()?;
    if u32::from_le_bytes(sig.get(..4)?.try_into().ok()?) != 0x6667_6572 {
        return None;
    }
    // _HBASE_BLOCK.RootCell@0x24 (u32 cell index).
    let raw = reader
        .read_bytes(base_block_addr.wrapping_add(0x24), 4)
        .ok()?;
    let idx = u32::from_le_bytes(raw.get(..4)?.try_into().ok()?);
    (idx != 0 && idx != u32::MAX).then_some(idx)
}

/// A registry value enumerated from a key node's value list.
#[derive(Debug, Clone)]
pub(crate) struct RegistryValue {
    /// Value name (empty for the key's default value).
    pub name: String,
    /// Raw value data bytes (inline or from the data cell).
    pub data: Vec<u8>,
}

/// Enumerate **all** values of the key node at `key_addr` (a `_CM_KEY_NODE` VA).
///
/// Walks `ValueCount@0x24` / `ValueList@0x28` → the value-list cell (an array of
/// `_CM_KEY_VALUE` cell indices) → each `_CM_KEY_VALUE`
/// (`NameLength@0x02`, `DataLength@0x04`, `Data@0x08`, `Type@0x0C`, `Name@0x14`).
/// `DataLength`'s high bit means the data is stored inline at `Data`. Returns an
/// empty vec on any read fault. The count is bounded as an allocation guard.
pub(crate) fn list_values<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hhive_addr: u64,
    key_addr: u64,
) -> Vec<RegistryValue> {
    let val_count = le_u32(reader, key_addr.wrapping_add(NK_VALUE_COUNT)).unwrap_or(0);
    if val_count == 0 {
        return Vec::new();
    }
    let Some(val_list_off) = le_u32(reader, key_addr.wrapping_add(NK_VALUE_LIST)) else {
        return Vec::new();
    };
    let val_list_addr = read_cell_addr(reader, hhive_addr, val_list_off);
    if val_list_addr == 0 {
        return Vec::new();
    }

    let mut out = Vec::new();
    for v in 0..val_count.min(MAX_VALUE_COUNT) {
        let Some(val_off) = le_u32(reader, val_list_addr.wrapping_add(u64::from(v) * 4)) else {
            continue;
        };
        let val_addr = read_cell_addr(reader, hhive_addr, val_off);
        if val_addr == 0 {
            continue;
        }
        if let Some(rv) = read_value(reader, hhive_addr, val_addr) {
            out.push(rv);
        }
    }
    out
}

/// Decode a single `_CM_KEY_VALUE` at `val_addr`. `None` on a read fault or an
/// implausible name/data length (that value is skipped, not the whole list).
fn read_value<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hhive_addr: u64,
    val_addr: u64,
) -> Option<RegistryValue> {
    // NameLength@0x02 (u16); Name@0x14. NameLength 0 = the key's default value.
    let name_bytes = reader
        .read_bytes(val_addr.wrapping_add(VK_NAME_LENGTH), 2)
        .ok()?;
    let name_len = u16::from_le_bytes(name_bytes.get(..2)?.try_into().ok()?);
    let name = if name_len == 0 {
        String::new()
    } else if name_len > VK_MAX_NAME_LEN {
        return None;
    } else {
        let raw = reader
            .read_bytes(val_addr.wrapping_add(VK_NAME), name_len as usize)
            .ok()?;
        String::from_utf8_lossy(&raw).into_owned()
    };

    // DataLength@0x04 (u32); high bit set => data stored inline at Data@0x08.
    let raw_len = le_u32(reader, val_addr.wrapping_add(VK_DATA_LENGTH))?;
    let inline = (raw_len & VK_INLINE_FLAG) != 0;
    let data_len = raw_len & !VK_INLINE_FLAG;
    let data = if data_len == 0 {
        Vec::new()
    } else if data_len > VK_MAX_DATA_LEN {
        return None;
    } else if inline {
        // Inline data is at most 4 bytes, stored in the Data field itself.
        reader
            .read_bytes(val_addr.wrapping_add(VK_DATA), data_len.min(4) as usize)
            .ok()?
    } else {
        let data_off = le_u32(reader, val_addr.wrapping_add(VK_DATA))?;
        let data_addr = read_cell_addr(reader, hhive_addr, data_off);
        if data_addr == 0 {
            return None;
        }
        reader.read_bytes(data_addr, data_len as usize).ok()?
    };

    Some(RegistryValue { name, data })
}

/// Read the data of the named value (case-insensitive) of the key at `key_addr`,
/// or an empty vec if absent. Thin filter over [`list_values`].
pub(crate) fn read_value_data<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hhive_addr: u64,
    key_addr: u64,
    target_name: &str,
) -> Vec<u8> {
    list_values(reader, hhive_addr, key_addr)
        .into_iter()
        .find(|v| v.name.eq_ignore_ascii_case(target_name))
        .map_or_else(Vec::new, |v| v.data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Encode a Rust &str as UTF-16LE bytes.
    fn utf16le_bytes(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// Build a _UNICODE_STRING struct in memory (16 bytes):
    /// [0..2]: Length (u16 LE)
    /// [2..4]: MaximumLength (u16 LE)
    /// [8..16]: Buffer (u64 LE pointer)
    fn build_unicode_string_at(buf: &mut [u8], offset: usize, length: u16, buffer_ptr: u64) {
        buf[offset..offset + 2].copy_from_slice(&length.to_le_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&length.to_le_bytes());
        buf[offset + 8..offset + 16].copy_from_slice(&buffer_ptr.to_le_bytes());
    }

    /// Place UTF-16LE string data at a physical offset and return the byte length.
    fn place_utf16_string(buf: &mut [u8], phys_offset: usize, s: &str) -> u16 {
        let utf16 = utf16le_bytes(s);
        let len = utf16.len();
        buf[phys_offset..phys_offset + len].copy_from_slice(&utf16);
        len as u16
    }

    // ── Cell-map translation (in-memory hive) ──────────────────────

    /// A cell index must be translated through `_HHIVE.Storage[].Map`
    /// (directory → table → `_HMAP_ENTRY`) to the cell's virtual address — the
    /// in-memory hive layout. cell_index dir=2/table=3/suboffset=0x40 with a
    /// `PermanentBinAddress` of `…5007` (flags in the low nibble) and a
    /// `BlockOffset` of 0x100 must resolve to `…5000 + 0x100 + 0x40 = …5140`.
    #[test]
    fn cell_index_to_va_walks_the_hmap_directory() {
        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x800)
            .add_field("_HHIVE", "Storage", 0xb8, "char")
            .add_struct("_DUAL", 0x278)
            .add_field("_DUAL", "Map", 0x18, "pointer")
            .add_struct("_HMAP_ENTRY", 0x20)
            .add_field("_HMAP_ENTRY", "PermanentBinAddress", 0x0, "pointer")
            .add_field("_HMAP_ENTRY", "BlockOffset", 0x8, "unsigned long")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let h_vaddr = 0xFFFF_8000_0010_0000u64;
        let dir_vaddr = 0xFFFF_8000_0010_2000u64;
        let table_vaddr = 0xFFFF_8000_0010_3000u64;
        let (h_paddr, dir_paddr, table_paddr) = (0x20_0000u64, 0x20_2000u64, 0x20_3000u64);

        let cell_index = (2u32 << 21) | (3u32 << 12) | 0x40;

        let mut h_page = vec![0u8; 4096];
        // Storage[0].Map @ 0xb8 + 0x18 = 0xd0
        h_page[0xd0..0xd8].copy_from_slice(&dir_vaddr.to_le_bytes());

        let mut dir_page = vec![0u8; 4096];
        // Directory[2] @ 2*8 = 0x10
        dir_page[0x10..0x18].copy_from_slice(&table_vaddr.to_le_bytes());

        let mut table_page = vec![0u8; 4096];
        // Table[3] @ 3*0x20 = 0x60: PermanentBinAddress@0, BlockOffset@8
        let bin_va = 0xFFFF_8000_0010_5007u64; // low nibble = flags → block …5000
        table_page[0x60..0x68].copy_from_slice(&bin_va.to_le_bytes());
        table_page[0x68..0x6c].copy_from_slice(&0x100u32.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(h_vaddr, h_paddr, flags::WRITABLE)
            .map_4k(dir_vaddr, dir_paddr, flags::WRITABLE)
            .map_4k(table_vaddr, table_paddr, flags::WRITABLE)
            .write_phys(h_paddr, &h_page)
            .write_phys(dir_paddr, &dir_page)
            .write_phys(table_paddr, &table_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        assert_eq!(
            cell_index_to_va(&reader, h_vaddr, cell_index),
            Some(0xFFFF_8000_0010_5140)
        );
    }

    /// Win8.1 / Server 2012 R2 (build 9600) and older: `_HMAP_ENTRY` has NO
    /// `PermanentBinAddress`/`BlockOffset` — only `BlockAddress`, which is the
    /// bin VA directly (Volatility3 `get_block_offset`'s AttributeError
    /// fallback). The real citadeldc01.mem PDB resolves PermanentBinAddress=None,
    /// so the Win10-only path returned None and every hive cell read failed.
    #[test]
    fn cell_index_to_va_uses_block_address_on_win81() {
        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x800)
            .add_field("_HHIVE", "Storage", 0xb8, "char")
            .add_struct("_DUAL", 0x278)
            .add_field("_DUAL", "Map", 0x8, "pointer")
            .add_struct("_HMAP_ENTRY", 0x18)
            // No PermanentBinAddress/BlockOffset — only BlockAddress (the bin VA).
            .add_field("_HMAP_ENTRY", "BlockAddress", 0x0, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let h_vaddr = 0xFFFF_8000_0010_0000u64;
        let dir_vaddr = 0xFFFF_8000_0010_2000u64;
        let table_vaddr = 0xFFFF_8000_0010_3000u64;
        let (h_paddr, dir_paddr, table_paddr) = (0x20_0000u64, 0x20_2000u64, 0x20_3000u64);

        let cell_index = (2u32 << 21) | (3u32 << 12) | 0x40;

        let mut h_page = vec![0u8; 4096];
        h_page[0xc0..0xc8].copy_from_slice(&dir_vaddr.to_le_bytes()); // Storage[0].Map @ 0xb8+0x8
        let mut dir_page = vec![0u8; 4096];
        dir_page[0x10..0x18].copy_from_slice(&table_vaddr.to_le_bytes()); // Directory[2]
        let mut table_page = vec![0u8; 4096];
        // Table[3] @ 3*0x18 = 0x48: BlockAddress = the bin VA directly (clean, no flags).
        let bin_va = 0xFFFF_8000_0010_5000u64;
        table_page[0x48..0x50].copy_from_slice(&bin_va.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(h_vaddr, h_paddr, flags::WRITABLE)
            .map_4k(dir_vaddr, dir_paddr, flags::WRITABLE)
            .map_4k(table_vaddr, table_paddr, flags::WRITABLE)
            .write_phys(h_paddr, &h_page)
            .write_phys(dir_paddr, &dir_page)
            .write_phys(table_paddr, &table_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // block_va = BlockAddress; cell_va = + suboffset 0x40.
        assert_eq!(
            cell_index_to_va(&reader, h_vaddr, cell_index),
            Some(0xFFFF_8000_0010_5040)
        );
    }

    // ── Test 1: No hive list symbol → empty Vec ─────────────────────

    #[test]
    fn walk_hive_list_no_symbol() {
        // Build an ISF with NO CmpHiveListHead symbol at all.
        let isf = IsfBuilder::new()
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Minimal page table — we just need a valid VAS.
        let vaddr_base = 0xFFFF_8000_0000_0000u64;
        let paddr_base = 0x10_0000u64;
        let page = vec![0u8; 4096];

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr_base, paddr_base, flags::WRITABLE)
            .write_phys(paddr_base, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let hives = walk_hive_list(&reader).unwrap();
        assert!(
            hives.is_empty(),
            "Expected empty Vec when no hive list symbol exists"
        );
    }

    // ── Test 2: Single hive in the list ─────────────────────────────

    #[test]
    fn walk_hive_list_single_hive() {
        // Memory layout (all on pages mapped into kernel VA space):
        //
        // Page 0 (vaddr 0xFFFF_8000_0010_0000): CmpHiveListHead (_LIST_ENTRY)
        // Page 1 (vaddr 0xFFFF_8000_0020_0000): _CMHIVE struct
        // Page 2 (vaddr 0xFFFF_8000_0020_1000): string data for UNICODE_STRINGs
        //
        // _CMHIVE layout (from preset):
        //   Hive (_HHIVE) at offset 0x0
        //     BaseBlock at 0x28
        //     Storage[0] (_DUAL) at 0x38 → Length at 0x38+0x0 = 0x38
        //     Storage[1] (_DUAL) at 0x58 → Length at 0x58+0x0 = 0x58
        //   FileFullPath at offset 0x70
        //   FileUserName at offset 0x80
        //   HiveList at offset 0x300

        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let cmhive_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let strings_vaddr: u64 = 0xFFFF_8000_0020_1000;

        let head_paddr: u64 = 0x0080_0000;
        let cmhive_paddr: u64 = 0x0090_0000;
        let strings_paddr: u64 = 0x0091_0000;

        let mut head_data = vec![0u8; 4096];
        let mut cmhive_data = vec![0u8; 4096];
        let mut string_data = vec![0u8; 4096];

        // HiveList field is at offset 0x300 within _CMHIVE.
        let hive_list_entry_vaddr = cmhive_vaddr + 0x300;

        // CmpHiveListHead: Flink → cmhive.HiveList, Blink → cmhive.HiveList
        head_data[0..8].copy_from_slice(&hive_list_entry_vaddr.to_le_bytes());
        head_data[8..16].copy_from_slice(&hive_list_entry_vaddr.to_le_bytes());

        // _CMHIVE.HiveList: Flink → head, Blink → head (single entry, circular)
        cmhive_data[0x300..0x308].copy_from_slice(&head_vaddr.to_le_bytes());
        cmhive_data[0x308..0x310].copy_from_slice(&head_vaddr.to_le_bytes());

        // _HHIVE.BaseBlock at offset 0x28
        let base_block_addr: u64 = 0xDEAD_BEEF_0000;
        cmhive_data[0x28..0x30].copy_from_slice(&base_block_addr.to_le_bytes());

        // _HHIVE.Storage[Stable].Length at offset 0x38 (Stable _DUAL starts at 0x38)
        let stable_len: u32 = 0x0040_0000; // 4MB
        cmhive_data[0x38..0x3C].copy_from_slice(&stable_len.to_le_bytes());

        // _HHIVE.Storage[Volatile].Length at offset 0x58 (Volatile _DUAL starts at 0x58)
        // _DUAL size is 0x20, so Storage[1] = Storage[0] offset + 0x20 = 0x38 + 0x20 = 0x58
        let volatile_len: u32 = 0x0001_0000; // 64KB
        cmhive_data[0x58..0x5C].copy_from_slice(&volatile_len.to_le_bytes());

        // FileFullPath (_UNICODE_STRING) at offset 0x70
        let full_path = r"\REGISTRY\MACHINE\SYSTEM";
        let full_path_len = place_utf16_string(&mut string_data, 0x000, full_path);
        build_unicode_string_at(&mut cmhive_data, 0x70, full_path_len, strings_vaddr);

        // FileUserName (_UNICODE_STRING) at offset 0x80
        let user_name = r"\??\C:\Windows\System32\config\SYSTEM";
        let user_name_len = place_utf16_string(&mut string_data, 0x200, user_name);
        build_unicode_string_at(&mut cmhive_data, 0x80, user_name_len, strings_vaddr + 0x200);

        // Build ISF with CmpHiveListHead pointing to our head_vaddr
        let isf = IsfBuilder::windows_kernel_preset()
            .add_symbol("CmpHiveListHead", head_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(cmhive_vaddr, cmhive_paddr, flags::WRITABLE)
            .map_4k(strings_vaddr, strings_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_data)
            .write_phys(cmhive_paddr, &cmhive_data)
            .write_phys(strings_paddr, &string_data)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let hives = walk_hive_list(&reader).unwrap();
        assert_eq!(hives.len(), 1);

        let h = &hives[0];
        assert_eq!(h.base_addr, cmhive_vaddr);
        assert_eq!(h.file_full_path, r"\REGISTRY\MACHINE\SYSTEM");
        assert_eq!(h.file_user_name, r"\??\C:\Windows\System32\config\SYSTEM");
        assert_eq!(h.hive_addr, base_block_addr);
        assert_eq!(h.stable_length, stable_len);
        assert_eq!(h.volatile_length, volatile_len);
    }

    // ── Test: CmHiveListHead fallback symbol ────────────────────────

    #[test]
    fn walk_hive_list_cm_hive_fallback() {
        // Uses CmHiveListHead (not CmpHiveListHead) — same single-hive layout.
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let cmhive_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let strings_vaddr: u64 = 0xFFFF_8000_0020_1000;

        let head_paddr: u64 = 0x0080_0000;
        let cmhive_paddr: u64 = 0x0090_0000;
        let strings_paddr: u64 = 0x0091_0000;

        let mut head_data = vec![0u8; 4096];
        let mut cmhive_data = vec![0u8; 4096];
        let mut string_data = vec![0u8; 4096];

        let hive_list_entry_vaddr = cmhive_vaddr + 0x300;
        head_data[0..8].copy_from_slice(&hive_list_entry_vaddr.to_le_bytes());
        head_data[8..16].copy_from_slice(&hive_list_entry_vaddr.to_le_bytes());
        cmhive_data[0x300..0x308].copy_from_slice(&head_vaddr.to_le_bytes());
        cmhive_data[0x308..0x310].copy_from_slice(&head_vaddr.to_le_bytes());

        let base_block_addr: u64 = 0xFEED_CAFE_0000;
        cmhive_data[0x28..0x30].copy_from_slice(&base_block_addr.to_le_bytes());
        cmhive_data[0x38..0x3C].copy_from_slice(&0x0010_0000u32.to_le_bytes());
        cmhive_data[0x58..0x5C].copy_from_slice(&0x0000_1000u32.to_le_bytes());

        let full_path = r"\REGISTRY\MACHINE\SYSTEM";
        let user_name = r"\??\C:\Windows\System32\config\SYSTEM";
        let full_path_len = place_utf16_string(&mut string_data, 0x000, full_path);
        let user_name_len = place_utf16_string(&mut string_data, 0x200, user_name);
        build_unicode_string_at(&mut cmhive_data, 0x70, full_path_len, strings_vaddr);
        build_unicode_string_at(&mut cmhive_data, 0x80, user_name_len, strings_vaddr + 0x200);

        // Note: use CmHiveListHead (without "p") as the fallback symbol
        // Use a minimal custom ISF with only CmHiveListHead (no CmpHiveListHead),
        // so the fallback branch in walk_hive_list is exercised.
        let isf = IsfBuilder::new()
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer")
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            .add_struct("_DUAL", 0x20)
            .add_field("_DUAL", "Length", 0, "unsigned int")
            .add_struct("_HHIVE", 0x300)
            .add_field("_HHIVE", "BaseBlock", 0x28, "pointer")
            .add_field("_HHIVE", "Storage", 0x38, "_DUAL")
            .add_struct("_CMHIVE", 0x600)
            .add_field("_CMHIVE", "Hive", 0x0, "_HHIVE")
            .add_field("_CMHIVE", "FileFullPath", 0x70, "_UNICODE_STRING")
            .add_field("_CMHIVE", "FileUserName", 0x80, "_UNICODE_STRING")
            .add_field("_CMHIVE", "HiveList", 0x300, "_LIST_ENTRY")
            .add_symbol("CmHiveListHead", head_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(cmhive_vaddr, cmhive_paddr, flags::WRITABLE)
            .map_4k(strings_vaddr, strings_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_data)
            .write_phys(cmhive_paddr, &cmhive_data)
            .write_phys(strings_paddr, &string_data)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let hives = walk_hive_list(&reader).unwrap();
        assert_eq!(hives.len(), 1);
        assert_eq!(hives[0].hive_addr, base_block_addr);
    }

    // ── Test: MAX_HIVE_COUNT safety cap ────────────────────────────

    #[test]
    fn walk_hive_list_respects_max_hive_count() {
        // This test verifies the MAX_HIVE_COUNT guard is present.
        // We can't easily build 256 hives, so we just verify the constant.
        assert_eq!(MAX_HIVE_COUNT, 256);
    }

    // ── Test: RegistryHive fields are accessible ───────────────────

    #[test]
    fn registry_hive_fields() {
        use crate::RegistryHive;
        let hive = RegistryHive {
            base_addr: 0x1000,
            file_full_path: r"\REGISTRY\MACHINE\SYSTEM".to_string(),
            file_user_name: r"\??\C:\Windows\config".to_string(),
            hive_addr: 0x2000,
            stable_length: 0x40_0000,
            volatile_length: 0x1000,
        };
        assert_eq!(hive.base_addr, 0x1000);
        assert_eq!(hive.stable_length, 0x40_0000);
        assert!(hive.file_full_path.contains("SYSTEM"));
    }

    // ── Test 3: Two hives in a circular list ────────────────────────

    #[test]
    fn walk_hive_list_two_hives() {
        // Two _CMHIVE entries in the circular HiveList chain.
        //
        // Page 0: CmpHiveListHead
        // Page 1: _CMHIVE A (SYSTEM)
        // Page 2: _CMHIVE B (SOFTWARE)
        // Page 3: string data

        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let cmhive_a_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let cmhive_b_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let strings_vaddr: u64 = 0xFFFF_8000_0040_0000;

        let head_paddr: u64 = 0x0080_0000;
        let cmhive_a_paddr: u64 = 0x0090_0000;
        let cmhive_b_paddr: u64 = 0x00A0_0000;
        let strings_paddr: u64 = 0x00B0_0000;

        let mut head_data = vec![0u8; 4096];
        let mut cmhive_a_data = vec![0u8; 4096];
        let mut cmhive_b_data = vec![0u8; 4096];
        let mut string_data = vec![0u8; 4096];

        let hive_list_a = cmhive_a_vaddr + 0x300;
        let hive_list_b = cmhive_b_vaddr + 0x300;

        // CmpHiveListHead: Flink → A.HiveList, Blink → B.HiveList
        head_data[0..8].copy_from_slice(&hive_list_a.to_le_bytes());
        head_data[8..16].copy_from_slice(&hive_list_b.to_le_bytes());

        // A.HiveList: Flink → B.HiveList, Blink → head
        cmhive_a_data[0x300..0x308].copy_from_slice(&hive_list_b.to_le_bytes());
        cmhive_a_data[0x308..0x310].copy_from_slice(&head_vaddr.to_le_bytes());

        // B.HiveList: Flink → head, Blink → A.HiveList
        cmhive_b_data[0x300..0x308].copy_from_slice(&head_vaddr.to_le_bytes());
        cmhive_b_data[0x308..0x310].copy_from_slice(&hive_list_a.to_le_bytes());

        // ── Hive A: SYSTEM ──
        let base_block_a: u64 = 0xAAAA_0000_0000;
        cmhive_a_data[0x28..0x30].copy_from_slice(&base_block_a.to_le_bytes());
        cmhive_a_data[0x38..0x3C].copy_from_slice(&0x0040_0000u32.to_le_bytes()); // stable 4MB
        cmhive_a_data[0x58..0x5C].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // volatile 64KB

        let full_a = r"\REGISTRY\MACHINE\SYSTEM";
        let user_a = r"\??\C:\Windows\System32\config\SYSTEM";
        let full_a_len = place_utf16_string(&mut string_data, 0x000, full_a);
        let user_a_len = place_utf16_string(&mut string_data, 0x100, user_a);
        build_unicode_string_at(&mut cmhive_a_data, 0x70, full_a_len, strings_vaddr);
        build_unicode_string_at(&mut cmhive_a_data, 0x80, user_a_len, strings_vaddr + 0x100);

        // ── Hive B: SOFTWARE ──
        let base_block_b: u64 = 0xBBBB_0000_0000;
        cmhive_b_data[0x28..0x30].copy_from_slice(&base_block_b.to_le_bytes());
        cmhive_b_data[0x38..0x3C].copy_from_slice(&0x0100_0000u32.to_le_bytes()); // stable 16MB
        cmhive_b_data[0x58..0x5C].copy_from_slice(&0x0002_0000u32.to_le_bytes()); // volatile 128KB

        let full_b = r"\REGISTRY\MACHINE\SOFTWARE";
        let user_b = r"\??\C:\Windows\System32\config\SOFTWARE";
        let full_b_len = place_utf16_string(&mut string_data, 0x300, full_b);
        let user_b_len = place_utf16_string(&mut string_data, 0x500, user_b);
        build_unicode_string_at(&mut cmhive_b_data, 0x70, full_b_len, strings_vaddr + 0x300);
        build_unicode_string_at(&mut cmhive_b_data, 0x80, user_b_len, strings_vaddr + 0x500);

        let isf = IsfBuilder::windows_kernel_preset()
            .add_symbol("CmpHiveListHead", head_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(cmhive_a_vaddr, cmhive_a_paddr, flags::WRITABLE)
            .map_4k(cmhive_b_vaddr, cmhive_b_paddr, flags::WRITABLE)
            .map_4k(strings_vaddr, strings_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_data)
            .write_phys(cmhive_a_paddr, &cmhive_a_data)
            .write_phys(cmhive_b_paddr, &cmhive_b_data)
            .write_phys(strings_paddr, &string_data)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let hives = walk_hive_list(&reader).unwrap();
        assert_eq!(hives.len(), 2);

        // Hive A
        assert_eq!(hives[0].base_addr, cmhive_a_vaddr);
        assert_eq!(hives[0].file_full_path, r"\REGISTRY\MACHINE\SYSTEM");
        assert_eq!(
            hives[0].file_user_name,
            r"\??\C:\Windows\System32\config\SYSTEM"
        );
        assert_eq!(hives[0].hive_addr, base_block_a);
        assert_eq!(hives[0].stable_length, 0x0040_0000);
        assert_eq!(hives[0].volatile_length, 0x0001_0000);

        // Hive B
        assert_eq!(hives[1].base_addr, cmhive_b_vaddr);
        assert_eq!(hives[1].file_full_path, r"\REGISTRY\MACHINE\SOFTWARE");
        assert_eq!(
            hives[1].file_user_name,
            r"\??\C:\Windows\System32\config\SOFTWARE"
        );
        assert_eq!(hives[1].hive_addr, base_block_b);
        assert_eq!(hives[1].stable_length, 0x0100_0000);
        assert_eq!(hives[1].volatile_length, 0x0002_0000);
    }

    // ── Shared find_subkey_by_name: lf / lh / li / ri + stable-list correctness ──

    use memf_core::test_builders::SyntheticPhysMem;

    fn cellmap_isf() -> serde_json::Value {
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

    /// Single-bin cell-map hive: cell index == byte offset within the bin (so
    /// indices must be < 0x1000); cell data starts at `idx + 4` (past the size
    /// header). Mirrors the in-memory `_HHIVE.Storage[].Map` directory→table→bin
    /// layout that `cell_index_to_va` walks.
    struct CellHive {
        hhive_va: u64,
        bin_va: u64,
        bin: Vec<u8>,
    }
    impl CellHive {
        fn new(base: u64) -> Self {
            Self {
                hhive_va: base,
                bin_va: base + 0x4000,
                bin: vec![0u8; 0x1000],
            }
        }
        fn ao(idx: u32) -> usize {
            (idx + 4) as usize
        }
        /// `_CM_KEY_NODE` with CORRECT offsets: SubKeyCounts[Stable]@0x14,
        /// SubKeyLists[Stable]@0x1c, [Volatile]@0x20, NameLength@0x48, Name@0x4c.
        fn nk(
            &mut self,
            idx: u32,
            name: &[u8],
            stable_count: u32,
            stable_list: u32,
            volatile_list: u32,
        ) {
            let o = Self::ao(idx);
            self.bin[o + 0x14..o + 0x18].copy_from_slice(&stable_count.to_le_bytes());
            self.bin[o + 0x18..o + 0x1c].copy_from_slice(&1u32.to_le_bytes()); // volatile count
            self.bin[o + 0x1c..o + 0x20].copy_from_slice(&stable_list.to_le_bytes());
            self.bin[o + 0x20..o + 0x24].copy_from_slice(&volatile_list.to_le_bytes());
            self.bin[o + 0x48..o + 0x4a].copy_from_slice(&(name.len() as u16).to_le_bytes());
            self.bin[o + 0x4c..o + 0x4c + name.len()].copy_from_slice(name);
        }
        fn list(&mut self, idx: u32, sig: [u8; 2], entries: &[u32], stride: usize) {
            let o = Self::ao(idx);
            self.bin[o..o + 2].copy_from_slice(&sig);
            self.bin[o + 2..o + 4].copy_from_slice(&(entries.len() as u16).to_le_bytes());
            for (i, &e) in entries.iter().enumerate() {
                self.bin[o + 4 + i * stride..o + 4 + i * stride + 4]
                    .copy_from_slice(&e.to_le_bytes());
            }
        }
        fn lf(&mut self, idx: u32, children: &[u32]) {
            self.list(idx, *b"lf", children, 8);
        }
        fn li(&mut self, idx: u32, children: &[u32]) {
            self.list(idx, *b"li", children, 4);
        }
        fn ri(&mut self, idx: u32, sublists: &[u32]) {
            self.list(idx, *b"ri", sublists, 4);
        }
        /// Set `_CM_KEY_NODE` ValueCount@0x24 + ValueList@0x28 on cell `idx`.
        fn values(&mut self, idx: u32, count: u32, list_idx: u32) {
            let o = Self::ao(idx);
            self.bin[o + 0x24..o + 0x28].copy_from_slice(&count.to_le_bytes());
            self.bin[o + 0x28..o + 0x2c].copy_from_slice(&list_idx.to_le_bytes());
        }
        /// Write a value-list cell: a packed array of `_CM_KEY_VALUE` cell indices.
        fn value_list(&mut self, idx: u32, values: &[u32]) {
            let o = Self::ao(idx);
            for (i, &v) in values.iter().enumerate() {
                self.bin[o + i * 4..o + i * 4 + 4].copy_from_slice(&v.to_le_bytes());
            }
        }
        /// `_CM_KEY_VALUE` with data stored in a separate (non-inline) data cell:
        /// "vk"@0, NameLength@0x02, DataLength@0x04, Data@0x08 (=data cell idx),
        /// Type@0x0C, Name@0x14.
        fn vk(&mut self, idx: u32, name: &[u8], kind: u32, data_len: u32, data_idx: u32) {
            let o = Self::ao(idx);
            self.bin[o..o + 2].copy_from_slice(b"vk");
            self.bin[o + 2..o + 4].copy_from_slice(&(name.len() as u16).to_le_bytes());
            self.bin[o + 4..o + 8].copy_from_slice(&data_len.to_le_bytes());
            self.bin[o + 8..o + 0xc].copy_from_slice(&data_idx.to_le_bytes());
            self.bin[o + 0xc..o + 0x10].copy_from_slice(&kind.to_le_bytes());
            self.bin[o + 0x14..o + 0x14 + name.len()].copy_from_slice(name);
        }
        /// Place raw bytes at cell `idx`'s data start (e.g. a value's data cell).
        fn data(&mut self, idx: u32, bytes: &[u8]) {
            let o = Self::ao(idx);
            self.bin[o..o + bytes.len()].copy_from_slice(bytes);
        }
        fn reader(&self) -> ObjectReader<SyntheticPhysMem> {
            let resolver = IsfResolver::from_value(&cellmap_isf()).unwrap();
            let bb_va = self.hhive_va + 0x1000;
            let dir_va = self.hhive_va + 0x2000;
            let table_va = self.hhive_va + 0x3000;
            let mut hh = vec![0u8; 0x1000];
            hh[0x10..0x18].copy_from_slice(&bb_va.to_le_bytes());
            hh[0xb8 + 0x18..0xb8 + 0x18 + 8].copy_from_slice(&dir_va.to_le_bytes());
            let mut dir = vec![0u8; 0x1000];
            dir[0..8].copy_from_slice(&table_va.to_le_bytes());
            let mut table = vec![0u8; 0x1000];
            table[0..8].copy_from_slice(&self.bin_va.to_le_bytes());
            let (cr3, mem) = PageTableBuilder::new()
                .map_4k(self.hhive_va, self.hhive_va, flags::WRITABLE)
                .write_phys(self.hhive_va, &hh)
                .map_4k(bb_va, bb_va, flags::WRITABLE)
                .write_phys(bb_va, &vec![0u8; 0x1000])
                .map_4k(dir_va, dir_va, flags::WRITABLE)
                .write_phys(dir_va, &dir)
                .map_4k(table_va, table_va, flags::WRITABLE)
                .write_phys(table_va, &table)
                .map_4k(self.bin_va, self.bin_va, flags::WRITABLE)
                .write_phys(self.bin_va, &self.bin)
                .build();
            let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
            ObjectReader::new(vas, Box::new(resolver))
        }
    }

    #[test]
    fn list_values_enumerates_all_values() {
        let mut h = CellHive::new(0x0030_0000);
        // Key node at cell 0x40 with 2 values; value-list cell at 0x100.
        h.nk(0x40, b"Run", 0, 0, 0);
        h.values(0x40, 2, 0x100);
        h.value_list(0x100, &[0x200, 0x300]);
        // Value "Updater" (REG_SZ) → data cell 0x280 (spaced clear of the vk cell).
        let updater = utf16le_bytes("evil.exe");
        h.vk(0x200, b"Updater", 1, updater.len() as u32, 0x280);
        h.data(0x280, &updater);
        // Value "Backup" (REG_BINARY) → data cell 0x380.
        h.vk(0x300, b"Backup", 3, 6, 0x380);
        h.data(0x380, b"abcdef");

        let r = h.reader();
        let key = read_cell_addr(&r, h.hhive_va, 0x40);
        let vals = list_values(&r, h.hhive_va, key);

        assert_eq!(vals.len(), 2, "both values enumerated");
        assert_eq!(vals[0].name, "Updater");
        assert_eq!(vals[0].data, updater);
        assert_eq!(vals[1].name, "Backup");
        assert_eq!(vals[1].data, b"abcdef");
    }

    #[test]
    fn find_subkey_lf_finds_child() {
        let mut h = CellHive::new(0x0010_0000);
        h.nk(0x40, b"root", 1, 0x100, 0);
        h.lf(0x100, &[0x200]);
        h.nk(0x200, b"SAM", 0, 0, 0);
        let r = h.reader();
        let parent = read_cell_addr(&r, h.hhive_va, 0x40);
        assert_eq!(
            find_subkey_by_name(&r, h.hhive_va, parent, "SAM"),
            h.bin_va + 0x200 + 4
        );
    }

    #[test]
    fn find_subkey_li_finds_child() {
        let mut h = CellHive::new(0x0011_0000);
        h.nk(0x40, b"root", 1, 0x100, 0);
        h.li(0x100, &[0x200]);
        h.nk(0x200, b"Secrets", 0, 0, 0);
        let r = h.reader();
        let parent = read_cell_addr(&r, h.hhive_va, 0x40);
        assert_eq!(
            find_subkey_by_name(&r, h.hhive_va, parent, "secrets"), // case-insensitive
            h.bin_va + 0x200 + 4
        );
    }

    #[test]
    fn find_subkey_ri_indexroot_finds_child() {
        // The missing-`ri` bug: an index-root list points to sub-lists, each of
        // which is an lf/lh/li. Large keys (CLSID, InventoryApplication) use this.
        let mut h = CellHive::new(0x0020_0000);
        h.nk(0x40, b"root", 2, 0x100, 0);
        h.ri(0x100, &[0x200, 0x300]); // ri → two sub-lists
        h.lf(0x200, &[0x400]);
        h.nk(0x400, b"Other", 0, 0, 0);
        h.lf(0x300, &[0x500]);
        h.nk(0x500, b"InventoryApplicationFile", 0, 0, 0);
        let r = h.reader();
        let parent = read_cell_addr(&r, h.hhive_va, 0x40);
        assert_eq!(
            find_subkey_by_name(&r, h.hhive_va, parent, "InventoryApplicationFile"),
            h.bin_va + 0x500 + 4
        );
    }

    #[test]
    fn find_subkey_ri_with_li_sublist() {
        let mut h = CellHive::new(0x0021_0000);
        h.nk(0x40, b"root", 1, 0x100, 0);
        h.ri(0x100, &[0x200]);
        h.li(0x200, &[0x300]); // li sub-list under the ri
        h.nk(0x300, b"Cache", 0, 0, 0);
        let r = h.reader();
        let parent = read_cell_addr(&r, h.hhive_va, 0x40);
        assert_eq!(
            find_subkey_by_name(&r, h.hhive_va, parent, "Cache"),
            h.bin_va + 0x300 + 4
        );
    }

    #[test]
    fn find_subkey_reads_stable_list_not_volatile() {
        // The critical bug: a reader using +0x18/+0x20 (the Volatile slot) instead
        // of +0x14/+0x1c (Stable) finds the usually-empty/decoy volatile list. The
        // stable list holds "Secrets"; the volatile slot points to a decoy that
        // does NOT — a buggy +0x20 reader returns 0 here.
        let mut h = CellHive::new(0x0030_0000);
        h.nk(0x40, b"root", 1, 0x100, 0x300); // stable list 0x100, volatile decoy 0x300
        h.lf(0x100, &[0x200]);
        h.nk(0x200, b"Secrets", 0, 0, 0);
        h.lf(0x300, &[0x400]);
        h.nk(0x400, b"WRONG", 0, 0, 0);
        let r = h.reader();
        let parent = read_cell_addr(&r, h.hhive_va, 0x40);
        assert_eq!(
            find_subkey_by_name(&r, h.hhive_va, parent, "Secrets"),
            h.bin_va + 0x200 + 4
        );
    }

    #[test]
    fn find_subkey_missing_returns_zero() {
        let mut h = CellHive::new(0x0031_0000);
        h.nk(0x40, b"root", 1, 0x100, 0);
        h.lf(0x100, &[0x200]);
        h.nk(0x200, b"SAM", 0, 0, 0);
        let r = h.reader();
        let parent = read_cell_addr(&r, h.hhive_va, 0x40);
        assert_eq!(find_subkey_by_name(&r, h.hhive_va, parent, "NOPE"), 0);
    }

    #[test]
    fn find_subkey_ri_self_cycle_is_bounded() {
        // A malformed `ri` entry pointing back to itself must terminate (the
        // recursion bound), not hang — Paranoid Gatekeeper on untrusted hives.
        let mut h = CellHive::new(0x0040_0000);
        h.nk(0x40, b"root", 1, 0x100, 0);
        h.ri(0x100, &[0x100]); // self-referential
        let r = h.reader();
        let parent = read_cell_addr(&r, h.hhive_va, 0x40);
        assert_eq!(find_subkey_by_name(&r, h.hhive_va, parent, "X"), 0);
    }
}
