//! UserAssist evidence-of-execution walker.
//!
//! Windows stores program launch counts and last-run timestamps in the
//! NTUSER.DAT registry hive under
//! `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`.
//! Values are ROT13-encoded file paths with a fixed-size binary data
//! structure containing run count and FILETIME.
//!
//! The binary value data (72 bytes on Vista+) has the following layout:
//!   - Offset  4: Run count (u32)
//!   - Offset  8: Focus count (u32)
//!   - Offset 12: Focus time in milliseconds (u32)
//!   - Offset 60: Last run time (u64, FILETIME)

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// Maximum number of UserAssist entries to enumerate (safety limit).
const MAX_USERASSIST_ENTRIES: usize = 4096;

/// Minimum binary data size for a UserAssist value (Vista+ format).
const USERASSIST_DATA_SIZE: usize = 72;

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

/// The path components from the hive root to the UserAssist key.
const USERASSIST_PATH: &[&str] = &[
    "Software",
    "Microsoft",
    "Windows",
    "CurrentVersion",
    "Explorer",
    "UserAssist",
];

/// A single UserAssist entry recovered from the registry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UserAssistEntry {
    /// ROT13-decoded path (executable name or GUID-prefixed path).
    pub name: String,
    /// Number of times the program was run.
    pub run_count: u32,
    /// Number of times the program gained focus.
    pub focus_count: u32,
    /// Last run time as a Windows FILETIME (100-ns intervals since 1601-01-01).
    pub last_run_time: u64,
    /// Total focus time in milliseconds.
    pub focus_time_ms: u32,
    /// Whether this entry matches suspicious patterns (hacking tools,
    /// living-off-the-land binaries from unusual paths, etc.).
    pub is_suspicious: bool,
}

// ── ROT13 ────────────────────────────────────────────────────────────

/// Decode a ROT13-encoded string.
///
/// ROT13 rotates ASCII letters by 13 positions, wrapping around.
/// Non-alphabetic characters pass through unchanged. This is used by
/// Windows to obfuscate UserAssist value names in the registry.
pub fn rot13_decode(s: &str) -> String {
        todo!()
    }

// ── Suspicious classification ────────────────────────────────────────

/// Known offensive/post-exploitation tool names (lowercase for matching).
const SUSPICIOUS_TOOLS: &[&str] = &[
    "mimikatz",
    "psexec",
    "procdump",
    "beacon",
    "cobalt",
    "rubeus",
    "seatbelt",
    "sharpup",
    "sharphound",
    "bloodhound",
    "lazagne",
    "safetykatz",
    "winpeas",
    "linpeas",
    "chisel",
    "plink",
    "ncat",
    "netcat",
    "nc.exe",
    "nc64.exe",
    "whoami",   // not always suspicious, but in UserAssist context it is noteworthy
    "certutil", // frequently abused for downloads
];

/// Script engines and living-off-the-land binaries that are always
/// suspicious in a UserAssist context (indicating interactive use).
const SUSPICIOUS_LOLBINS: &[&str] = &[
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "msiexec.exe",
    "certutil.exe",
    "bitsadmin.exe",
];

/// Classify a decoded UserAssist name as suspicious.
///
/// Returns `true` if the name matches patterns commonly associated with
/// post-exploitation tools, living-off-the-land abuse, or programs run
/// from unusual locations:
///
/// - Known offensive tools: mimikatz, psexec, cobalt strike, etc.
/// - Shell interpreters from unusual paths (not `\Windows\System32\`)
/// - Script engines (wscript, cscript, mshta) -- frequently abused
/// - Encoded command-line launchers
pub fn classify_userassist(name: &str) -> bool {
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

/// List all subkey cell indices under a given nk cell.
fn list_subkeys<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    nk_data: &[u8],
) -> crate::Result<Vec<u32>> {
        todo!()
    }

// ── Walk function ────────────────────────────────────────────────────

/// Walk UserAssist entries from a registry hive loaded in memory.
///
/// `hive_addr` is the virtual address of the `_HBASE_BLOCK` for an
/// NTUSER.DAT hive. The walker navigates:
///   1. Root key -> `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`
///   2. Each GUID subkey -> `Count` subkey
///   3. Each value in `Count`: ROT13-decode the name, parse the 72-byte
///      binary data for run count, focus count, focus time, and last-run FILETIME.
///
/// Returns `Ok(Vec::new())` if required symbols are missing or the path
/// does not exist (graceful degradation).
pub fn walk_userassist<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
) -> crate::Result<Vec<UserAssistEntry>> {
        todo!()
    }

/// Parse a single UserAssist value cell into a `UserAssistEntry`.
///
/// Returns `Ok(None)` if the value data is too small (not Vista+ format)
/// or the value cell is invalid.
fn parse_userassist_value<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    val_cell: u32,
) -> crate::Result<Option<UserAssistEntry>> {
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

    // ── rot13_decode exhaustive tests ────────────────────────────────

    /// Basic ROT13: "Pzq.rkr" decodes to "Cmd.exe".
    #[test]
    fn rot13_decode_basic() {
        todo!()
    }

    /// Non-alpha characters pass through unchanged; letters still rotate.
    /// "P:\\Hfref" (ROT13 of "C:\Users") decodes back to "C:\\Users".
    #[test]
    fn rot13_decode_passthrough() {
        todo!()
    }

    /// ROT13 is its own inverse.
    #[test]
    fn rot13_involutory() {
        todo!()
    }

    /// Empty string decodes to empty string.
    #[test]
    fn rot13_empty_string() {
        todo!()
    }

    /// Digits and punctuation pass through unchanged.
    #[test]
    fn rot13_digits_unchanged() {
        todo!()
    }

    /// ROT13 wraps at alphabet boundaries: 'N'→'A', 'Z'→'M', 'n'→'a', 'z'→'m'.
    #[test]
    fn rot13_boundary_wrap() {
        todo!()
    }

    /// Decode a known ROT13 encoded UserAssist name.
    #[test]
    fn rot13_decode_userassist_known() {
        todo!()
    }

    // ── classify_userassist tests ────────────────────────────────────

    /// Normal Windows programs should not be flagged.
    #[test]
    fn classify_userassist_benign() {
        todo!()
    }

    /// Known offensive/hacking tools must be flagged as suspicious.
    #[test]
    fn classify_userassist_suspicious_tool() {
        todo!()
    }

    /// All known suspicious tools are flagged.
    #[test]
    fn classify_userassist_all_suspicious_tools() {
        todo!()
    }

    /// Script engines and living-off-the-land binaries from unusual
    /// paths should be flagged.
    #[test]
    fn classify_userassist_lolbin_suspicious() {
        todo!()
    }

    /// All LOLBins are flagged.
    #[test]
    fn classify_userassist_all_lolbins_suspicious() {
        todo!()
    }

    /// LOLBins also detected by path component.
    #[test]
    fn classify_userassist_lolbin_path_contains() {
        todo!()
    }

    /// cmd.exe from system32 is NOT suspicious.
    #[test]
    fn classify_userassist_cmd_system32_benign() {
        todo!()
    }

    /// cmd.exe from outside system32 IS suspicious.
    #[test]
    fn classify_userassist_cmd_outside_system32_suspicious() {
        todo!()
    }

    /// powershell.exe from system32 is NOT suspicious.
    #[test]
    fn classify_userassist_powershell_system32_benign() {
        todo!()
    }

    /// powershell.exe from outside system32 IS suspicious.
    #[test]
    fn classify_userassist_powershell_outside_system32_suspicious() {
        todo!()
    }

    /// Empty string is benign.
    #[test]
    fn classify_userassist_empty_benign() {
        todo!()
    }

    // ── read_key_name unit tests ─────────────────────────────────────

    #[test]
    fn read_key_name_too_short() {
        todo!()
    }

    #[test]
    fn read_key_name_valid() {
        todo!()
    }

    #[test]
    fn read_key_name_overflow_returns_empty() {
        todo!()
    }

    // ── read_value_name unit tests ────────────────────────────────────

    #[test]
    fn read_value_name_too_short() {
        todo!()
    }

    #[test]
    fn read_value_name_valid() {
        todo!()
    }

    #[test]
    fn read_value_name_overflow_returns_empty() {
        todo!()
    }

    // ── cell_address unit test ────────────────────────────────────────

    #[test]
    fn cell_address_calculation() {
        todo!()
    }

    #[test]
    fn cell_address_zero_index() {
        todo!()
    }

    // ── walk_userassist tests ────────────────────────────────────────

    /// Empty reader with no relevant symbols → returns empty Vec.
    #[test]
    fn walk_userassist_no_symbol() {
        todo!()
    }

    /// Non-zero but unmapped hive address → returns empty Vec.
    #[test]
    fn walk_userassist_unmapped_hive_graceful() {
        todo!()
    }

    /// Walk body exercises past root-cell read when hive is mapped but root cell is 0.
    ///
    /// Puts a valid `_HBASE_BLOCK` in memory with `RootCell` = 0.
    /// The walker reads the root cell at offset 0x24, gets 0, and returns empty.
    #[test]
    fn walk_userassist_mapped_hive_root_cell_zero_empty() {
        todo!()
    }

    /// Walk body: non-zero root cell pointing into mapped memory with no valid nk signature
    /// exercises the signature check branch and returns empty gracefully.
    #[test]
    fn walk_userassist_root_cell_nonzero_bad_signature_empty() {
        todo!()
    }

    // ── find_subkey unit tests ───────────────────────────────────────

    /// find_subkey returns None when nk_data is too short to contain subkey list offset.
    /// Covers lines 269-270 (nk_data.len() < NK_STABLE_SUBKEYS_LIST_OFFSET + 4).
    #[test]
    fn find_subkey_nk_data_too_short_returns_none() {
        todo!()
    }

    /// find_subkey returns None when subkey_count == 0.
    /// Covers line 279-281 (subkey_count == 0).
    #[test]
    fn find_subkey_zero_subkey_count_returns_none() {
        todo!()
    }

    /// find_subkey with a non-zero subkey_count but unmapped list cell → returns None.
    /// Covers lines 283-296 (list_data.len() < 4).
    #[test]
    fn find_subkey_list_cell_unmapped_returns_none() {
        todo!()
    }

    // ── list_subkeys unit tests ──────────────────────────────────────

    /// list_subkeys returns empty when nk_data too short.
    #[test]
    fn list_subkeys_nk_data_too_short_returns_empty() {
        todo!()
    }

    /// list_subkeys returns empty when subkey_count == 0.
    #[test]
    fn list_subkeys_zero_count_returns_empty() {
        todo!()
    }

    // ── read_cell_data unit tests ────────────────────────────────────

    /// read_cell_data returns empty Vec when abs_size <= 4 (covers line 218).
    /// We map a page with a cell size of exactly 4 (i32 = -4 or +4).
    #[test]
    fn read_cell_data_abs_size_le_4_returns_empty() {
        todo!()
    }

    /// read_cell_data with a negative size (allocated cell) returns data bytes.
    #[test]
    fn read_cell_data_negative_size_returns_data() {
        todo!()
    }

    // ── UserAssistEntry struct tests ─────────────────────────────────

    #[test]
    fn userassist_entry_construction() {
        todo!()
    }

    #[test]
    fn userassist_entry_serialization() {
        todo!()
    }

    // ── Constants ─────────────────────────────────────────────────────

    #[test]
    fn userassist_constants_sane() {
        todo!()
    }

    /// find_subkey: list_data with lf signature, count=0 → None.
    #[test]
    fn find_subkey_lf_list_zero_count_none() {
        todo!()
    }

    /// find_subkey: list_data with li signature, count=0 → None.
    #[test]
    fn find_subkey_li_list_zero_count_none() {
        todo!()
    }

    /// find_subkey: unknown list signature → None (falls to _ => {} arm).
    #[test]
    fn find_subkey_unknown_list_sig_none() {
        todo!()
    }

    /// list_subkeys: lf signature with count=1 returns one cell index.
    /// We use list_cell=0 so cell_address = hive_addr+0x1000+0 = page boundary.
    #[test]
    fn list_subkeys_lf_one_entry() {
        todo!()
    }

    /// list_subkeys: li signature returns cell indices.
    #[test]
    fn list_subkeys_li_entries() {
        todo!()
    }

    /// list_subkeys: unknown list signature → empty result.
    #[test]
    fn list_subkeys_unknown_sig_empty() {
        todo!()
    }

    // ── find_subkey ri arm tests ─────────────────────────────────────

    /// find_subkey: ri signature (0x6972) with a sub-list (lf) pointing to a
    /// matching nk child → returns Some(child_cell).
    ///
    /// Memory layout:
    ///   hive_addr (page0): not read directly here
    ///   hive_addr + 0x1000 + ri_cell  (page1): ri list (4+4 bytes)
    ///   hive_addr + 0x1000 + lf_cell  (page2): lf sub-list (4+12 bytes)
    ///   hive_addr + 0x1000 + nk_cell  (page3): nk child cell
    #[test]
    fn find_subkey_ri_finds_matching_child() {
        todo!()
    }

    /// find_subkey: ri signature with sub-list that has an unknown sig → continues (no match).
    #[test]
    fn find_subkey_ri_unknown_sub_sig_no_match() {
        todo!()
    }

    // ── list_subkeys ri arm tests ────────────────────────────────────

    /// list_subkeys: ri signature with a sub-list (li) containing two cells.
    #[test]
    fn list_subkeys_ri_with_li_sub_list() {
        todo!()
    }

    /// list_subkeys: ri signature with unknown sub-list sig → no cells collected.
    #[test]
    fn list_subkeys_ri_unknown_sub_sig_empty() {
        todo!()
    }

    // ── parse_userassist_value tests ─────────────────────────────────

    /// parse_userassist_value: vk_data too short → Ok(None).
    #[test]
    fn parse_userassist_value_short_vk_data_none() {
        todo!()
    }

    /// parse_userassist_value: valid vk cell size but sig != VK_SIGNATURE → Ok(None).
    #[test]
    fn parse_userassist_value_invalid_vk_sig_none() {
        todo!()
    }

    /// parse_userassist_value: valid vk with data_length < USERASSIST_DATA_SIZE → Ok(None).
    #[test]
    fn parse_userassist_value_data_too_small_none() {
        todo!()
    }

    /// parse_userassist_value: fully valid vk cell with 72-byte data → Ok(Some(entry)).
    ///
    /// Layout uses two cells on the same page (cell index 0 = vk, cell index far enough for data).
    #[test]
    fn parse_userassist_value_valid_entry() {
        todo!()
    }

    /// classify_userassist: lolbin ends_with variant coverage (path ends with lolbin name).
    #[test]
    fn classify_userassist_lolbin_ends_with() {
        todo!()
    }

    /// classify_userassist: path contains /lolbin (Unix-style path).
    #[test]
    fn classify_userassist_lolbin_forward_slash_path() {
        todo!()
    }

    /// rot13_decode: full alphabet test.
    #[test]
    fn rot13_decode_full_alphabet() {
        todo!()
    }

    #[test]
    fn userassist_path_components() {
        todo!()
    }

    // ── walk_userassist full-path integration test ────────────────────
    //
    // Builds a minimal synthetic NTUSER.DAT hive with the full path:
    //   root -> Software -> Microsoft -> Windows -> CurrentVersion ->
    //   Explorer -> UserAssist -> {GUID} -> Count -> value "zvzvxngm.rkr"
    //
    // Layout (all cells on a single 4K HBIN page):
    //   Slot size: 0x80 bytes each
    //   nk cells:    [0] root  [1] Software  [2] Microsoft  [3] Windows
    //                [4] CurrentVersion  [5] Explorer  [6] UserAssist
    //                [7] {GUID}  [8] Count
    //   lf lists:    [0x480..0x800] — 8 lf lists, one per parent nk
    //   values_list: 0x880
    //   vk cell:     0x900
    //   data cell:   0x980
    //
    // Each nk cell at slot N has:
    //   - 4-byte size header (negative = allocated)
    //   - NK_SIGNATURE at [0..2]
    //   - subkey_count=1 at [0x14]
    //   - subkeys_list_cell = lf_list_cell_for_N at [0x1C]
    //   - name at [0x48..], length at [0x48]  (wait: NK_NAME_LENGTH_OFFSET=0x48, NK_NAME_OFFSET=0x4C)
    //
    // The lf list for slot N:
    //   - points to the nk cell at slot N+1 (child)
    //   - sig = "lf" (0x666C), count = 1, entry = (child_cell, hash=0)
    //
    // The {GUID} nk (slot 7) has subkey_count=1, lf→Count nk (slot 8).
    // The Count nk (slot 8) has value_count=1, values_list_cell pointing to values_list.
    // The values_list has one entry: vk_cell.
    // The vk cell: name="zvzvxngm.rkr" (ROT13 of "mimikatz.exe"), data_length=72, data_cell.
    // The data cell: 72 bytes of UA data (run_count=5 at [4], focus_count=2 at [8], etc.)
    //
    // All cell indices are offsets within the HBIN page (< 0x1000).
    #[test]
    fn walk_userassist_full_path_finds_mimikatz() {
        todo!()
    }
}
