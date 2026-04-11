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
#[allow(dead_code)]
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
        todo!()
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
        todo!()
    }

// ── Internal helpers ─────────────────────────────────────────────────

/// Compute the virtual address of a cell given its cell index.
///
/// Cells are addressed relative to the start of cell storage (HBIN area),
/// which begins at `hive_addr + 0x1000`.
fn cell_address(hive_addr: u64, cell_index: u32) -> u64 {
        todo!()
    }

/// Read cell data from a cell at `cell_vaddr`.
///
/// The first 4 bytes are an i32 size (negative = allocated). We skip the
/// size field and return the data portion.
fn read_cell_data<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    cell_vaddr: u64,
) -> crate::Result<Vec<u8>> {
        todo!()
    }

/// Extract the key name from an nk cell's data bytes.
fn read_key_name(nk_data: &[u8]) -> String {
        todo!()
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
        todo!()
    }

/// Read a single value node.
fn read_single_value<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    val_cell: u32,
    key_path: &str,
) -> crate::Result<RegistryValueInfo> {
        todo!()
    }

/// Convert a registry value type number to its human-readable name.
fn reg_type_name(t: u32) -> String {
        todo!()
    }

/// Format a short preview of value data based on its type.
fn format_data_preview(value_type: u32, data: &[u8]) -> String {
        todo!()
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
        todo!()
    }

    /// Build a cell: i32 size (negative = allocated) followed by cell data.
    fn build_cell(data: &[u8]) -> Vec<u8> {
        todo!()
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
        todo!()
    }

    /// Build a vk (value node) cell data buffer.
    fn build_vk_cell_data(
        name: &str,
        value_type: u32,
        data_length: u32,
        data_offset: u32,
    ) -> Vec<u8> {
        todo!()
    }

    // ── reg_type_name coverage ──────────────────────────────────────

    #[test]
    fn reg_type_name_all_known() {
        todo!()
    }

    #[test]
    fn reg_type_name_unknown() {
        todo!()
    }

    // ── format_data_preview coverage ────────────────────────────────

    #[test]
    fn format_data_preview_reg_dword() {
        todo!()
    }

    #[test]
    fn format_data_preview_reg_dword_short_data() {
        todo!()
    }

    #[test]
    fn format_data_preview_reg_qword() {
        todo!()
    }

    #[test]
    fn format_data_preview_reg_qword_short_data() {
        todo!()
    }

    #[test]
    fn format_data_preview_reg_sz_utf16() {
        todo!()
    }

    #[test]
    fn format_data_preview_reg_expand_sz() {
        todo!()
    }

    #[test]
    fn format_data_preview_reg_binary() {
        todo!()
    }

    #[test]
    fn format_data_preview_reg_binary_truncated_at_32() {
        todo!()
    }

    #[test]
    fn format_data_preview_reg_sz_empty_data() {
        todo!()
    }

    // ── Inline value (MSB set in DataLength) ────────────────────────

    #[test]
    fn read_registry_values_inline_reg_dword() {
        todo!()
    }

    // ── Test 1: Empty hive (root cell = 0) → empty Vec ──────────────

    #[test]
    fn walk_registry_keys_empty_hive() {
        todo!()
    }

    // ── Test 2: Single key node ─────────────────────────────────────

    #[test]
    fn walk_registry_keys_single_key() {
        todo!()
    }

    // ── Test 3: Single value with REG_SZ data ──────────────────────

    #[test]
    fn read_registry_values_single_value() {
        todo!()
    }

    // ── walk_registry_keys: li-format subkey list ───────────────────

    /// Root key with one child via an `li` (0x696C) subkey list — exercises
    /// the `0x696C` branch in `walk_key_recursive`.
    #[test]
    fn walk_registry_keys_li_list_child() {
        todo!()
    }

    // ── walk_registry_keys: ri-format subkey list ───────────────────

    /// Root key with one child via an `ri` (0x6972) sub-index list.
    /// The ri cell points to another lf cell which contains the actual child.
    #[test]
    fn walk_registry_keys_ri_list_child() {
        todo!()
    }

    // ── walk_registry_keys: unknown list type silently skipped ──────

    /// Root key whose subkeys list has an unknown signature — the walker
    /// should skip it silently and return just the root key.
    #[test]
    fn walk_registry_keys_unknown_list_type_skipped() {
        todo!()
    }

    // ── read_registry_values: bad nk signature returns error ────────

    /// read_registry_values on a cell whose first 2 bytes are not "nk"
    /// should return an error (invalid signature).
    #[test]
    fn read_registry_values_bad_nk_signature_returns_error() {
        todo!()
    }

    // ── read_registry_values: value with data_length == 0 ───────────

    /// A value with DataLength = 0 (not inline) produces an empty data_preview
    /// and data_length 0 (the `else` branch in read_single_value).
    #[test]
    fn read_registry_values_zero_data_length() {
        todo!()
    }

    // ── read_registry_values: vk with bad sig skipped ───────────────

    /// If a value cell has bad VK signature, it's skipped (continue in loop).
    #[test]
    fn read_registry_values_bad_vk_signature_skipped() {
        todo!()
    }

    // ── format_data_preview: REG_LINK (type 6) ──────────────────────

    #[test]
    fn format_data_preview_reg_link() {
        todo!()
    }

    // ── format_data_preview: truncated REG_SZ (> 80 chars) ──────────

    #[test]
    fn format_data_preview_reg_sz_long_string_truncated() {
        todo!()
    }

    // ── read_cell_data: zero abs_size (positive raw size = free cell) ──

    /// A cell with positive raw_size (free, abs_size > 0 but data_len check)
    /// still returns data — abs_size > 4 means data_len = abs_size - 4 > 0.
    #[test]
    fn read_cell_data_positive_size_still_read() {
        todo!()
    }

    // ── walk_registry_keys: depth = 0 stops recursion ───────────────

    /// When max_depth is 0, only the root key is returned (no recursion).
    #[test]
    fn walk_registry_keys_depth_zero_stops_at_root() {
        todo!()
    }

    // ── read_registry_values: name_length > available data ──────────

    /// A value cell where name_length extends beyond vk_data → name = "" (fallback).
    #[test]
    fn read_registry_values_name_length_overflow_empty_name() {
        todo!()
    }

    // ── RegistryKeyInfo and RegistryValueInfo struct tests ──────────

    #[test]
    fn registry_key_info_fields() {
        todo!()
    }

    #[test]
    fn registry_value_info_fields() {
        todo!()
    }

    // ── ri list with li sub-list ─────────────────────────────────────

    /// ri list whose sub-entry is an li cell — exercises the inner
    /// `0x696C` branch inside the ri handler.
    #[test]
    fn walk_registry_keys_ri_with_li_sublist() {
        todo!()
    }
}
