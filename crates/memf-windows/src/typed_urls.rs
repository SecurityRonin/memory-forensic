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
        todo!()
    }

// ── Hive cell helpers ────────────────────────────────────────────────

/// Compute the virtual address of a cell given its cell index.
fn cell_address(hive_addr: u64, cell_index: u32) -> u64 {
        todo!()
    }

/// Read cell data from a cell at `cell_vaddr`, skipping the 4-byte size header.
fn read_cell_data<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    cell_vaddr: u64,
) -> crate::Result<Vec<u8>> {
        todo!()
    }

/// Extract the key name from an nk cell's data bytes (ASCII, compressed).
fn read_key_name(nk_data: &[u8]) -> String {
        todo!()
    }

/// Read the value name from a vk cell's data bytes.
fn read_value_name(vk_data: &[u8]) -> String {
        todo!()
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
        todo!()
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
        todo!()
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
        todo!()
    }

    // ── classify_typed_url tests ─────────────────────────────────────

    /// Normal websites should not be flagged.
    #[test]
    fn classify_benign_urls() {
        todo!()
    }

    /// Empty URL is benign.
    #[test]
    fn classify_empty_url_benign() {
        todo!()
    }

    /// Plain HTTP URL without credentials or suspicious domain is benign.
    #[test]
    fn classify_plain_http_benign() {
        todo!()
    }

    /// Paste sites used for data exfiltration should be flagged.
    #[test]
    fn classify_paste_sites_suspicious() {
        todo!()
    }

    /// All suspicious domains are flagged.
    #[test]
    fn classify_all_suspicious_domains() {
        todo!()
    }

    /// Domain checks are case-insensitive.
    #[test]
    fn classify_domain_case_insensitive() {
        todo!()
    }

    /// File-sharing and anonymous upload sites should be flagged.
    #[test]
    fn classify_file_sharing_suspicious() {
        todo!()
    }

    /// file:// URLs with network (UNC) paths should be flagged.
    #[test]
    fn classify_file_unc_suspicious() {
        todo!()
    }

    /// file:// URLs with local paths should NOT be flagged.
    #[test]
    fn classify_file_local_benign() {
        todo!()
    }

    /// file:// with a relative path (no leading double slash) is benign.
    #[test]
    fn classify_file_relative_benign() {
        todo!()
    }

    /// URLs with embedded credentials should be flagged.
    #[test]
    fn classify_credentials_suspicious() {
        todo!()
    }

    /// Credentials in URL without path separator in authority is flagged.
    #[test]
    fn classify_credentials_no_path_suspicious() {
        todo!()
    }

    /// URLs with @ but no colon in authority (e.g. email-like) should NOT be flagged.
    #[test]
    fn classify_at_sign_no_password_benign() {
        todo!()
    }

    /// URL with colon before @ in domain name part (not credentials) is tricky —
    /// the spec checks authority.contains(':') AND authority.contains('@').
    /// A URL like "https://example.com:8080/path" has no '@' so is benign.
    #[test]
    fn classify_colon_in_host_no_at_benign() {
        todo!()
    }

    // ── read_key_name unit tests ──────────────────────────────────────

    #[test]
    fn read_key_name_too_short_returns_empty() {
        todo!()
    }

    #[test]
    fn read_key_name_valid_ascii() {
        todo!()
    }

    #[test]
    fn read_key_name_length_overflow_returns_empty() {
        todo!()
    }

    // ── read_value_name unit tests ────────────────────────────────────

    #[test]
    fn read_value_name_too_short_returns_empty() {
        todo!()
    }

    #[test]
    fn read_value_name_valid() {
        todo!()
    }

    #[test]
    fn read_value_name_length_overflow_returns_empty() {
        todo!()
    }

    // ── cell_address unit tests ────────────────────────────────────────

    #[test]
    fn cell_address_basic() {
        todo!()
    }

    #[test]
    fn cell_address_zero_index() {
        todo!()
    }

    // ── walk_typed_urls tests ────────────────────────────────────────

    /// Empty reader with zero hive_addr → returns empty Vec.
    #[test]
    fn walk_typed_urls_zero_hive() {
        todo!()
    }

    /// Hive with unreadable root cell → returns empty Vec.
    #[test]
    fn walk_typed_urls_unreadable_hive() {
        todo!()
    }

    // ── TypedUrlEntry struct tests ────────────────────────────────────

    #[test]
    fn typed_url_entry_construction() {
        todo!()
    }

    #[test]
    fn typed_url_entry_serialization() {
        todo!()
    }

    // ── Constants ─────────────────────────────────────────────────────

    #[test]
    fn typed_url_constants_sane() {
        todo!()
    }

    #[test]
    fn typed_urls_path_components_correct() {
        todo!()
    }

    #[test]
    fn typed_urls_time_path_components_correct() {
        todo!()
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
        todo!()
    }

    /// Hive mapped; root_cell_index = 0 → cell_address = hive + HBIN_START_OFFSET;
    /// the cell page is mapped with data that has raw_size=0 → read_cell_data
    /// returns empty Vec → sig check fails → empty result.
    #[test]
    fn walk_typed_urls_root_cell_zero_index_no_nk() {
        todo!()
    }

    /// Hive mapped; root cell has data but wrong signature → empty Vec.
    #[test]
    fn walk_typed_urls_root_cell_wrong_signature() {
        todo!()
    }

    /// Hive mapped; root nk cell has NK_SIGNATURE but stable_subkey_count=0
    /// → find_subkey("Software") returns None → empty Vec.
    #[test]
    fn walk_typed_urls_root_nk_no_subkeys() {
        todo!()
    }

    /// Hive mapped; root nk has NK_SIGNATURE and a non-zero stable_subkey_count
    /// pointing to a subkeys list cell that has an unknown list signature →
    /// find_subkey returns None → empty Vec.
    #[test]
    fn walk_typed_urls_unknown_list_signature() {
        todo!()
    }

    // ── Additional coverage: walk_typed_urls early-exit paths ────────────

    /// hive_addr = 0 returns empty immediately.
    #[test]
    fn walk_typed_urls_zero_hive_returns_empty() {
        todo!()
    }

    /// Non-zero but unmapped hive → read_bytes fails → empty.
    #[test]
    fn walk_typed_urls_unmapped_hive_returns_empty() {
        todo!()
    }

    /// TypedUrlEntry struct construction and serialization.
    #[test]
    fn typed_url_entry_serializes() {
        todo!()
    }

    // ── classify_typed_url: URL without scheme (no "://") is benign ────

    /// URL without "://" scheme separator should not trigger credential check.
    #[test]
    fn classify_no_scheme_benign() {
        todo!()
    }

    /// file:// with a single slash after host (not UNC) is benign.
    #[test]
    fn classify_file_single_slash_benign() {
        todo!()
    }

    /// Credential URL where @ appears after first slash (in path, not authority) is benign.
    #[test]
    fn classify_at_in_path_not_authority_benign() {
        todo!()
    }

    // ── find_subkey: li-list branch via synthetic memory ────────────────

    fn make_typed_url_isf_with_subkeyfields() -> serde_json::Value {
        todo!()
    }

    /// hive with NK root cell whose value count is 0 → TypedURLs not found → empty.
    #[test]
    fn walk_typed_urls_root_has_zero_subkeys_empty() {
        todo!()
    }

    // ── find_subkey: ri-list (index-of-indices) branch ──────────────

    /// Hive with `ri`-format subkey list (index-of-indices).
    /// The ri sub-list contains an lf entry, but the child nk sig is bad →
    /// find_subkey("Software") returns None → empty Vec.
    #[test]
    fn walk_typed_urls_ri_list_bad_child_sig_empty() {
        todo!()
    }

    /// find_subkey with li-format subkey list.
    /// Root nk has NK_SIGNATURE, stable_subkey_count=1 pointing to li list
    /// whose single child nk has good NK_SIGNATURE but name "WRONG" (not "Software") → empty.
    #[test]
    fn walk_typed_urls_li_list_no_match_empty() {
        todo!()
    }

    /// read_cell_data with a positive (free/unallocated) cell size returns empty.
    #[test]
    fn read_cell_data_positive_size_returns_data() {
        todo!()
    }

    /// hive root cell with value_count > 0 but values_list_cell not readable → empty Vec.
    #[test]
    fn walk_typed_urls_values_list_not_mapped_empty() {
        todo!()
    }

    // ── classify_typed_url: additional edge cases ────────────────────

    /// URL with @ in authority but no colon anywhere is benign.
    #[test]
    fn classify_url_at_no_colon_benign() {
        todo!()
    }

    /// URL with colon:port but no @ is benign.
    #[test]
    fn classify_url_colon_port_no_at_benign() {
        todo!()
    }

    /// file:// URL with empty path part is benign (no leading double-slash).
    #[test]
    fn classify_file_no_unc_prefix_benign() {
        todo!()
    }

    /// cell_address wrapping with large hive_addr and max cell index.
    #[test]
    fn cell_address_large_values() {
        todo!()
    }

    /// TypedUrlEntry clone works correctly.
    #[test]
    fn typed_url_entry_clone() {
        todo!()
    }

    /// hive root cell has NK_SIGNATURE and subkey_count=1 but list data is
    /// too short (< 4 bytes) → find_subkey returns None → empty.
    #[test]
    fn walk_typed_urls_list_data_too_short_empty() {
        todo!()
    }

    // ── find_subkey direct call: lf match branch ─────────────────────────

    /// find_subkey: lf list (0x666C) where the child nk matches the target name.
    /// This covers lines 268-270 (the `return Ok(Some(child_cell))` in the lf branch).
    #[test]
    fn find_subkey_lf_match_returns_cell() {
        todo!()
    }

    /// find_subkey: li list (0x696C) where the child nk matches the target name.
    /// Covers lines 290-292 (the `return Ok(Some(child_cell))` in the li branch).
    #[test]
    fn find_subkey_li_match_returns_cell() {
        todo!()
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
        todo!()
    }

    // ── walk_typed_urls with TypedURLsTime timestamp lookup ──────────
    //
    // Builds a hive that has BOTH TypedURLs AND TypedURLsTime under
    // "Internet Explorer" so the timestamp path (lines 436-536) is exercised.
    //
    // All cells placed at non-overlapping 0x100-byte-aligned slots in one HBIN page.
    // Slot layout (each 0x100 bytes = size_header(4) + nk/lf payload):
    //
    //   0x010: ROOT nk  (sub=1, lf=0x100)
    //   0x100: lf1→SW   (lf list pointing to 0x200)
    //   0x200: SW nk    (sub=1, lf=0x300)
    //   0x300: lf1→MS   (lf list pointing to 0x400)
    //   0x400: MS nk    (sub=1, lf=0x500)
    //   0x500: lf1→IE   (lf list pointing to 0x600)
    //   0x600: IE nk    (sub=2, lf=0x700)
    //   0x700: lf2→[TU,TT]   (2-entry lf: 0x800, 0x900)
    //   0x800: TU nk   "TypedURLs"   (val=1, vlist=0xA00)
    //   0x900: TT nk   "TypedURLsTime" (val=1, vlist=0xB00)
    //   0xA00: vlist_TU  [→0xC00]
    //   0xB00: vlist_TT  [→0xD00]
    //   0xC00: vk "url1" (URL) → data at 0xE00
    //   0xD00: vk "url1" (time) → data at 0xF00
    //   0xE00: URL data UTF-16LE "https://mega.nz/x"
    //   0xF00: FILETIME data (8 bytes = 132_000_000_000)
    #[test]
    fn walk_typed_urls_with_timestamp_from_typed_urls_time() {
        todo!()
    }

    /// hive root cell has wrong signature → empty.
    #[test]
    fn walk_typed_urls_wrong_root_sig_empty() {
        todo!()
    }
}
