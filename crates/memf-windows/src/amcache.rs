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
        todo!()
    }

/// Read an ASCII key/value name from cell data at the given offset.
fn read_ascii_name(data: &[u8], name_length_offset: usize, name_offset: usize) -> String {
        todo!()
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
        todo!()
    }

/// Read a REG_SZ string value from a value cell's data.
fn read_value_string<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_base: u64,
    vk_data: &[u8],
) -> String {
        todo!()
    }

/// Read a QWORD (u64) or DWORD (u32, widened) value from a value cell.
fn read_value_u64<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_base: u64,
    vk_data: &[u8],
) -> u64 {
        todo!()
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
    use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Helper: build a minimal reader with no amcache-relevant symbols.
    fn make_empty_reader() -> ObjectReader<SyntheticPhysMem> {
        todo!()
    }

    /// No valid hive / symbols missing -> empty Vec, not an error.
    #[test]
    fn walk_amcache_no_symbol() {
        todo!()
    }

    /// Non-zero but unmapped address → empty Vec.
    #[test]
    fn walk_amcache_unmapped_hive_graceful() {
        todo!()
    }

    // ── classify_amcache_entry: benign cases ─────────────────────────

    /// Entries with well-known publishers (Microsoft, etc.) in standard
    /// system paths should NOT be flagged as suspicious.
    #[test]
    fn classify_amcache_benign() {
        todo!()
    }

    /// Entries in temp/download/appdata paths with no publisher should be
    /// flagged as suspicious.
    #[test]
    fn classify_amcache_suspicious_temp_path() {
        todo!()
    }

    /// Entries with empty publisher, even in system paths, should be
    /// flagged as suspicious (unsigned binaries in unusual locations).
    #[test]
    fn classify_amcache_suspicious_no_publisher() {
        todo!()
    }

    // ── classify_amcache_entry: suspicious directory + untrusted publisher ──

    /// Unknown publisher in temp path should be suspicious (even if non-empty).
    #[test]
    fn classify_amcache_untrusted_publisher_in_temp() {
        todo!()
    }

    /// Unknown publisher in Downloads should be suspicious.
    #[test]
    fn classify_amcache_untrusted_publisher_in_downloads() {
        todo!()
    }

    /// Unknown publisher in AppData should be suspicious.
    #[test]
    fn classify_amcache_untrusted_publisher_in_appdata() {
        todo!()
    }

    /// Known trusted publisher in temp is NOT suspicious (brand-name software).
    #[test]
    fn classify_amcache_trusted_publisher_in_temp_not_suspicious() {
        todo!()
    }

    /// Google binary in temp is not suspicious (trusted publisher).
    #[test]
    fn classify_amcache_google_in_temp_not_suspicious() {
        todo!()
    }

    /// Unknown publisher in \Recycle path should be suspicious.
    #[test]
    fn classify_amcache_recycle_suspicious() {
        todo!()
    }

    /// Unknown publisher in \ProgramData should be suspicious.
    #[test]
    fn classify_amcache_programdata_suspicious() {
        todo!()
    }

    /// Well-known publisher check is case-insensitive (contains check).
    #[test]
    fn classify_amcache_publisher_case_insensitive() {
        todo!()
    }

    // ── read_ascii_name unit tests ────────────────────────────────────

    #[test]
    fn read_ascii_name_empty_data() {
        todo!()
    }

    #[test]
    fn read_ascii_name_zero_length() {
        todo!()
    }

    #[test]
    fn read_ascii_name_valid() {
        todo!()
    }

    #[test]
    fn read_ascii_name_overflow_truncated() {
        todo!()
    }

    // ── AmcacheEntry struct and serialization ─────────────────────────

    #[test]
    fn amcache_entry_construction() {
        todo!()
    }

    #[test]
    fn amcache_entry_sha1_strip_prefix() {
        todo!()
    }

    #[test]
    fn amcache_entry_sha1_no_prefix() {
        todo!()
    }

    #[test]
    fn amcache_entry_serialization() {
        todo!()
    }

    // ── Constants correctness ─────────────────────────────────────────

    #[test]
    fn hive_constants_sane() {
        todo!()
    }

    #[test]
    fn max_amcache_entries_reasonable() {
        todo!()
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
        todo!()
    }

    /// Mapped hive; BaseBlock ptr is valid but root_cell = 0 → early return.
    #[test]
    fn walk_amcache_mapped_hive_zero_root_cell() {
        todo!()
    }

    /// Mapped hive; BaseBlock ptr valid; root_cell non-zero but cell data
    /// does not carry NK_SIGNATURE → walk returns empty Vec.
    #[test]
    fn walk_amcache_mapped_hive_bad_nk_signature() {
        todo!()
    }

    // ── read_cell_data unit tests ─────────────────────────────────────

    /// read_cell_data returns None for cell_index == 0.
    #[test]
    fn read_cell_data_zero_index_returns_none() {
        todo!()
    }

    /// read_cell_data returns None for cell_index == 0xFFFF_FFFF.
    #[test]
    fn read_cell_data_sentinel_index_returns_none() {
        todo!()
    }

    /// read_cell_data returns None when the cell address is unmapped.
    #[test]
    fn read_cell_data_unmapped_returns_none() {
        todo!()
    }

    /// read_cell_data returns None when raw_size yields data_size == 0.
    #[test]
    fn read_cell_data_zero_size_returns_none() {
        todo!()
    }

    /// read_cell_data returns data when everything is valid.
    #[test]
    fn read_cell_data_valid_returns_data() {
        todo!()
    }

    // ── read_value_u64 REG_DWORD and unknown type ─────────────────────

    /// read_value_u64 returns 0 when vk_data is shorter than VK_NAME_OFFSET.
    #[test]
    fn read_value_u64_short_data_returns_zero() {
        todo!()
    }

    /// read_value_u64 with REG_DWORD inline value returns u32 widened to u64.
    #[test]
    fn read_value_u64_reg_dword_inline() {
        todo!()
    }

    /// read_value_u64 with unknown type returns 0.
    #[test]
    fn read_value_u64_unknown_type_returns_zero() {
        todo!()
    }

    // ── read_value_string inline data path ───────────────────────────

    /// read_value_string returns empty when vk_data is shorter than VK_NAME_OFFSET.
    #[test]
    fn read_value_string_short_data_returns_empty() {
        todo!()
    }

    /// read_value_string returns empty when data_length is 0.
    #[test]
    fn read_value_string_zero_length_returns_empty() {
        todo!()
    }

    /// read_value_string decodes inline UTF-16LE correctly (2 bytes for 'A').
    #[test]
    fn read_value_string_inline_utf16() {
        todo!()
    }

    // ── find_value: no values → returns None ─────────────────────────

    /// find_value returns None when key_data is too short.
    #[test]
    fn find_value_short_key_data_returns_none() {
        todo!()
    }

    /// find_value returns None when value_count is 0.
    #[test]
    fn find_value_zero_count_returns_none() {
        todo!()
    }

    // ── find_subkey: no subkeys → returns None ────────────────────────

    /// find_subkey returns None when parent_data is too short.
    #[test]
    fn find_subkey_short_parent_data_returns_none() {
        todo!()
    }

    /// find_subkey returns None when subkey_count is 0.
    #[test]
    fn find_subkey_zero_count_returns_none() {
        todo!()
    }

    /// find_subkey: lf list with one entry pointing to a child nk with a matching name.
    /// This covers the inner loop body of find_subkey including the NK_SIGNATURE check
    /// and name comparison.
    #[test]
    fn find_subkey_lf_list_finds_matching_child() {
        todo!()
    }

    /// read_value_string non-inline path: data is stored in a separate cell.
    /// Covers the `else` branch at line 291 (is_inline == false).
    #[test]
    fn read_value_string_non_inline_utf16() {
        todo!()
    }

    /// Mapped hive; root cell has NK_SIGNATURE but no InventoryApplicationFile
    /// or Root subkey → walk returns empty Vec.
    #[test]
    fn walk_amcache_mapped_hive_nk_no_subkeys() {
        todo!()
    }

    // ── read_value_u64: REG_QWORD non-inline path ────────────────────

    /// read_value_u64 with REG_QWORD (11) stored in a separate cell returns u64.
    #[test]
    fn read_value_u64_reg_qword_non_inline() {
        todo!()
    }

    // ── find_value: VK_SIGNATURE mismatch skipped ───────────────────

    /// find_value with a value list cell where the vk cell has bad sig → skipped → None.
    #[test]
    fn find_value_bad_vk_sig_skipped_returns_none() {
        todo!()
    }

    // ── walk_amcache: Root subkey found, IAF not under it → empty ───

    /// walk_amcache finds a "Root" subkey but InventoryApplicationFile is not
    /// a child of Root → returns empty Vec. Exercises the `root_child` branch.
    #[test]
    fn walk_amcache_root_found_iaf_not_found() {
        todo!()
    }

    // ── read_value_string: non-inline cell read fails → empty ───────

    /// read_value_string non-inline where cell read fails (unmapped) → empty.
    #[test]
    fn read_value_string_non_inline_unmapped_returns_empty() {
        todo!()
    }

    // ── read_value_u64: non-inline cell read fails → 0 ──────────────

    /// read_value_u64 non-inline where cell read fails → 0.
    #[test]
    fn read_value_u64_non_inline_unmapped_returns_zero() {
        todo!()
    }

    // ── classify_amcache_entry: users_public path ────────────────────

    #[test]
    fn classify_amcache_users_public_suspicious() {
        todo!()
    }

    // ── AmcacheEntry: clone works ────────────────────────────────────

    #[test]
    fn amcache_entry_clone() {
        todo!()
    }

    // ── walk_amcache: IAF with one child (no valid NK sig) → empty ───────
    //
    // Build a hive where InventoryApplicationFile is a direct child of root and
    // has one child entry whose cell has a bad NK signature → child skipped → empty Vec.
    // This exercises lines 532-549 (the enumeration loop with sig check).

    fn build_iaf_hive(flat_page: &mut Vec<u8>, child_nk_sig: u16) -> (u64, u32) {
        todo!()
    }

    /// walk_amcache: IAF found directly under root, IAF has one child with bad NK sig
    /// → child skipped → empty Vec. Exercises lines 532-549.
    #[test]
    fn walk_amcache_iaf_child_bad_sig_skipped() {
        todo!()
    }

    /// walk_amcache: IAF found directly under root, IAF has one child with valid NK sig
    /// and no values → one entry pushed with all-default fields.
    /// Exercises lines 547-592 (the full value extraction loop).
    #[test]
    fn walk_amcache_iaf_child_valid_nk_no_values_one_entry() {
        todo!()
    }

    /// walk_amcache: IAF found under root, child data too short (< NK_NAME_OFFSET) → continue.
    /// Exercises the `Some(d) if d.len() >= NK_NAME_OFFSET` guard (line 543).
    #[test]
    fn walk_amcache_iaf_child_data_too_short_skipped() {
        todo!()
    }

    /// walk_amcache: IAF has subkey_count=0 → returns empty Vec immediately.
    /// Exercises the `if subkey_count == 0` guard at line 513.
    #[test]
    fn walk_amcache_iaf_zero_subkeys_returns_empty() {
        todo!()
    }
}
