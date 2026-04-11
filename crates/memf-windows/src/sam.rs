//! Windows SAM (Security Account Manager) user account extraction.
//!
//! The SAM registry hive (`\REGISTRY\MACHINE\SAM`) stores local user
//! account metadata: usernames, RIDs, account flags, and (encrypted)
//! password hashes. Extracting SAM data from memory enables:
//!
//! - Identifying all local accounts (including hidden/disabled ones)
//! - Detecting recently created accounts (persistence via new user)
//! - Recovering account metadata when disk SAM is locked/encrypted
//!
//! The SAM hive is structured as:
//! `SAM\Domains\Account\Users\<RID>\V` — per-user binary data
//! `SAM\Domains\Account\Users\Names\<username>` — name→RID mapping

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// Maximum number of SAM user entries to walk (safety limit).
const MAX_USERS: usize = 4096;

/// Information about a local user account recovered from the SAM hive.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SamUserInfo {
    /// User account name.
    pub username: String,
    /// Relative Identifier (RID) — unique per-user on the local machine.
    pub rid: u32,
    /// Account flags (USER_ACCOUNT_CONTROL): disabled, locked out, etc.
    pub account_flags: u32,
    /// Whether the account is currently disabled.
    pub is_disabled: bool,
    /// Whether the account has an empty (blank) password hint.
    pub has_empty_password: bool,
    /// Last login time (FILETIME).
    pub last_login_time: u64,
    /// Last password change time (FILETIME).
    pub last_password_change: u64,
    /// Account creation time (FILETIME, from F value).
    pub account_created: u64,
    /// Login count.
    pub login_count: u32,
    /// Whether this account looks suspicious based on heuristics.
    pub is_suspicious: bool,
}

/// Account flag constants from USER_ACCOUNT_CONTROL.
pub const UAC_ACCOUNT_DISABLED: u32 = 0x0001;
/// Account lockout flag (ADS_UF_LOCKOUT).
pub const UAC_LOCKOUT: u32 = 0x0010;
/// Password not required flag (ADS_UF_PASSWD_NOTREQD).
pub const UAC_PASSWORD_NOT_REQUIRED: u32 = 0x0020;
/// Normal user account flag (ADS_UF_NORMAL_ACCOUNT).
pub const UAC_NORMAL_ACCOUNT: u32 = 0x0200;

/// Classify a SAM user account as suspicious.
///
/// Returns `true` for accounts that match patterns of attacker-created
/// persistence accounts:
/// - Username ends with '$' (hidden account convention)
/// - Account has admin-like RID (500) but unusual name
/// - Recently created account with password-not-required flag
/// - Username matches known attack tool default accounts
pub fn classify_sam_user(username: &str, rid: u32, flags: u32) -> bool {
        todo!()
    }

/// Extract local user accounts from the SAM registry hive in memory.
///
/// Reads the SAM hive at `hive_addr` and walks
/// `SAM\Domains\Account\Users` to enumerate user accounts.
/// Returns an empty `Vec` if the hive is unreadable or the path is missing.
pub fn walk_sam_users<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
) -> crate::Result<Vec<SamUserInfo>> {
        todo!()
    }

/// Read a cell address from the flat storage base + cell offset.
fn read_cell_addr<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    cell_off: u32,
) -> u64 {
        todo!()
    }

/// Find a subkey by name under a parent _CM_KEY_NODE.
fn find_subkey_by_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    parent_addr: u64,
    target_name: &str,
) -> u64 {
        todo!()
    }

/// Find the username associated with a RID from the Names subkey.
fn find_name_for_rid<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    names_key: u64,
    target_rid: u32,
) -> String {
        todo!()
    }

/// Read account metadata from the F value of a user's RID key.
/// Returns (flags, last_login, last_pw_change, created, login_count).
fn read_f_value<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    key_addr: u64,
) -> (u32, u64, u64, u64, u32) {
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

    fn make_reader() -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        todo!()
    }

    /// No SAM hive address → empty Vec.
    #[test]
    fn walk_sam_users_no_hive() {
        todo!()
    }

    /// Non-zero but unmapped hive address → empty Vec (graceful degradation).
    #[test]
    fn walk_sam_users_unmapped_hive_graceful() {
        todo!()
    }

    // ── classify_sam_user exhaustive tests ───────────────────────────

    /// Normal Administrator account is not suspicious.
    #[test]
    fn classify_sam_normal_admin() {
        todo!()
    }

    /// "admin" (lowercase) as RID-500 name is also benign.
    #[test]
    fn classify_sam_admin_lowercase_benign() {
        todo!()
    }

    /// Renamed Administrator (RID 500) is suspicious.
    #[test]
    fn classify_sam_renamed_admin() {
        todo!()
    }

    /// RID 500 with weird name is suspicious regardless of flags.
    #[test]
    fn classify_sam_rid500_weird_name_suspicious() {
        todo!()
    }

    /// Hidden account ending with '$' is suspicious.
    #[test]
    fn classify_sam_hidden_account() {
        todo!()
    }

    /// Dollar-sign account that IS a machine$ account is benign.
    #[test]
    fn classify_sam_machine_account_benign() {
        todo!()
    }

    /// Dollar-sign accounts with other suffixes are suspicious.
    #[test]
    fn classify_sam_dollar_not_machine_suspicious() {
        todo!()
    }

    /// Password-not-required on normal account is suspicious.
    #[test]
    fn classify_sam_no_password() {
        todo!()
    }

    /// Password-not-required on non-normal account is NOT suspicious by this flag alone.
    #[test]
    fn classify_sam_no_password_non_normal_not_suspicious() {
        todo!()
    }

    /// Known attack tool account names are suspicious.
    #[test]
    fn classify_sam_known_bad_names() {
        todo!()
    }

    /// Known bad names are case-insensitive.
    #[test]
    fn classify_sam_known_bad_name_case_insensitive() {
        todo!()
    }

    /// Regular user account is not suspicious.
    #[test]
    fn classify_sam_regular_user() {
        todo!()
    }

    /// Regular user with RID > 500 and normal flags is benign.
    #[test]
    fn classify_sam_normal_user_benign() {
        todo!()
    }

    /// Empty username is not suspicious.
    #[test]
    fn classify_sam_empty_benign() {
        todo!()
    }

    /// Empty username with suspicious flags is still benign (early return).
    #[test]
    fn classify_sam_empty_with_flags_benign() {
        todo!()
    }

    // ── UAC constant correctness ───────────────────────────────────────

    #[test]
    fn uac_constants_correct_values() {
        todo!()
    }

    /// Exercises the full hive navigation path: builds a minimal hive with a valid
    /// root NK cell that has subkey_count=0, so find_subkey_by_name("SAM") returns 0.
    /// Covers lines 177-184 (sam_key == 0 branch).
    #[test]
    fn walk_sam_users_root_cell_no_sam_subkey() {
        todo!()
    }

    // ── SamUserInfo construction ──────────────────────────────────────

    #[test]
    fn sam_user_info_fields() {
        todo!()
    }

    #[test]
    fn sam_user_info_disabled_flag() {
        todo!()
    }

    // ── SamUserInfo serialization ─────────────────────────────────────

    #[test]
    fn sam_user_info_serialization() {
        todo!()
    }

    // ── MAX_USERS constant ────────────────────────────────────────────

    #[test]
    fn max_users_constant_reasonable() {
        todo!()
    }

    // ── walk_sam_users body coverage ─────────────────────────────────
    //
    // These tests exercise the walk body past the hive_addr=0 guard by
    // providing minimal synthetic physical memory.  All addresses are
    // kept well below 16 MB so they fit inside the SyntheticPhysMem
    // image that PageTableBuilder allocates.

    /// Hive at a mapped vaddr whose page contains a non-zero BaseBlock
    /// pointer.  Navigation fails gracefully once the BaseBlock page
    /// returns a zero root_cell_off → empty Vec.
    #[test]
    fn walk_sam_users_mapped_hive_base_block_zero_root_cell() {
        todo!()
    }

    /// Hive with a non-zero root_cell_off exercises the storage/flat_base
    /// code path and then cell navigation, which fails (no hbin data) →
    /// empty Vec.
    #[test]
    fn walk_sam_users_mapped_hive_nonzero_root_cell_no_hbin() {
        todo!()
    }

    /// base_block_addr == 0 after reading BaseBlock pointer → early return.
    #[test]
    fn walk_sam_users_base_block_addr_zero_early_return() {
        todo!()
    }

    /// classify_sam_user: dollar-suffix case-insensitive (upper-case trailing '$').
    #[test]
    fn classify_sam_dollar_uppercase_suspicious() {
        todo!()
    }

    /// classify_sam_user: lockout flag alone on a regular account is NOT suspicious.
    #[test]
    fn classify_sam_lockout_flag_alone_not_suspicious() {
        todo!()
    }

    /// classify_sam_user: password-not-required without normal-account flag is NOT suspicious.
    #[test]
    fn classify_sam_password_not_required_without_normal_not_suspicious() {
        todo!()
    }

    /// walk_sam_users: subkey_count == 0 under users_key → returns empty.
    #[test]
    fn walk_sam_users_users_key_zero_subkeys_returns_empty() {
        todo!()
    }

    // ── li-list branch in find_subkey_by_name ────────────────────────
    //
    // Build a hive that makes find_subkey_by_name traverse an `li` list
    // (4-byte per-entry format) rather than `lf`/`lh` (8-byte).
    // If the child key name does NOT match "SAM" the function returns 0
    // and walk_sam_users returns empty.  This exercises the li branch
    // (line ≈ 375) inside find_subkey_by_name.

    /// Hive with `li`-format subkey list and a single child whose name
    /// does NOT match "SAM" → walk returns empty.
    #[test]
    fn walk_sam_users_li_list_no_match_returns_empty() {
        todo!()
    }

    /// Hive with `lh`-format (8-byte entries with hash) subkey list and a
    /// single child whose name matches "SAM". Navigation continues until
    /// find_subkey_by_name("Domains") fails (child has 0 subkeys) → empty.
    #[test]
    fn walk_sam_users_lh_list_sam_found_domains_missing() {
        todo!()
    }

    /// SamUserInfo: all UAC flags can be combined and read back.
    #[test]
    fn sam_user_info_flag_combinations() {
        todo!()
    }

    /// walk_sam_users: subkey_count > MAX_USERS → returns empty (safety limit).
    #[test]
    fn walk_sam_users_subcount_exceeds_max_returns_empty() {
        todo!()
    }

    // ── classify_sam_user: extended coverage ─────────────────────────

    /// Normal account with RID != 500 and no special flags/names is benign.
    #[test]
    fn classify_sam_normal_non500_rid_benign() {
        todo!()
    }

    /// Machine$ suffix alone (exact match "machine$") is NOT suspicious.
    #[test]
    fn classify_sam_exact_machine_dollar_benign() {
        todo!()
    }

    /// A name that contains "machine$" but doesn't end with it IS suspicious.
    #[test]
    fn classify_sam_dollar_not_machine_end_suspicious() {
        todo!()
    }

    /// RID == 500 and username == "Administrator" (case-insensitive) is benign.
    #[test]
    fn classify_sam_rid500_administrator_case_insensitive() {
        todo!()
    }

    /// RID == 500 and username == "ADMIN" (uppercase of "admin") is benign.
    #[test]
    fn classify_sam_rid500_admin_uppercase_benign() {
        todo!()
    }

    /// SamUserInfo: clone works.
    #[test]
    fn sam_user_info_clone() {
        todo!()
    }

    /// root_cell_off == u32::MAX → early return.
    #[test]
    fn walk_sam_users_root_cell_off_max_early_return() {
        todo!()
    }

    // ── classify_sam_user: additional branches ────────────────────────

    /// "$" suffix variants beyond "machine$": "pc$" ends with "$" not "machine$" → suspicious.
    #[test]
    fn classify_sam_pc_dollar_suspicious() {
        todo!()
    }

    /// RID 501 (Guest) with non-special name and no bad flags → benign.
    #[test]
    fn classify_sam_rid_501_guest_benign() {
        todo!()
    }

    /// Password-not-required combined with normal account and dollar suffix
    /// is suspicious on both axes: dollar and flags.
    #[test]
    fn classify_sam_combined_dollar_and_no_password_suspicious() {
        todo!()
    }

    /// A regular name in a larger RID range with only lockout flag → benign.
    #[test]
    fn classify_sam_large_rid_lockout_only_benign() {
        todo!()
    }

    // ── walk_sam_users with valid hive chain — lf list ───────────────
    //
    // Build a complete minimal hive so walk_sam_users reaches the `Users`
    // key and finds subkey_count=0 → returns empty.
    // Layout (virtual = physical throughout):
    //   hive         = 0x00C0_0000
    //   base_block   = 0x00C1_0000
    //   flat_base    = base_block + 0x1000 = 0x00C2_0000
    //
    // We use a two-level lf-list chain:
    //   root NK → lf list → SAM NK (0 subkeys)
    // → find_subkey_by_name("SAM") returns 0 → walk returns empty.

    fn make_full_isf() -> serde_json::Value {
        todo!()
    }

    /// Hive with an lf list under root → SAM NK with 0 subkeys → empty.
    /// Exercises find_subkey_by_name with lf entries and name matching.
    #[test]
    fn walk_sam_users_full_chain_lf_sam_no_domains_empty() {
        todo!()
    }

    /// walk_sam_users: subkey_count > MAX_USERS → early return empty.
    /// Build a hive that reaches the users_key check with count > limit.
    #[test]
    fn walk_sam_users_subcount_over_limit_returns_empty() {
        todo!()
    }

    /// Exercises the Storage fallback: Storage pointer is non-zero.
    /// Cell navigation fails because the hbin area is not fully mapped.
    #[test]
    fn walk_sam_users_storage_ptr_nonzero_graceful() {
        todo!()
    }

    // ── Deep hive chain: root → SAM → Domains → Account → Users → RID ──────
    //
    // Build a full 5-level NK chain so walk_sam_users traverses the inner
    // enumeration loop (lines 228-310), encounters a valid RID key name
    // "000001F4" (hex for 500), finds names_key=0 → username="RID-500", then
    // calls read_f_value with val_count=0 → default flags, and pushes one
    // SamUserInfo into the output Vec.
    //
    // All cell offsets are within a single 4 KB page at flat_base_paddr so
    // addresses stay well below the 16 MB SyntheticPhysMem limit.

    fn build_deep_hive(flat_page: &mut Vec<u8>) {
        todo!()
    }

    /// Full 5-level hive chain: root→SAM→Domains→Account→Users→RID key.
    /// Exercises the inner RID enumeration loop (lines 228-310), finds one
    /// user with RID=500 and names_key=0 (so username="RID-500"), account
    /// flags all zero, and pushes one SamUserInfo.
    #[test]
    fn walk_sam_users_deep_chain_one_rid_user() {
        todo!()
    }

    /// Full 5-level hive chain where Users key has subkey_count > MAX_USERS.
    /// Exercises the guard `subkey_count > MAX_USERS as u32 → return empty`.
    #[test]
    fn walk_sam_users_deep_chain_over_max_users_returns_empty() {
        todo!()
    }

    /// Full 5-level chain where the RID NK's name is "Names" — this key is
    /// skipped by the `eq_ignore_ascii_case("Names")` guard (line 272), so
    /// the resulting Vec is empty even though we enumerated the Users child.
    #[test]
    fn walk_sam_users_deep_chain_names_key_skipped() {
        todo!()
    }

    /// Full 5-level chain where the RID NK name is not valid hex → `from_str_radix` fails,
    /// the key is skipped (line 279 continue), resulting in empty output.
    #[test]
    fn walk_sam_users_deep_chain_invalid_hex_rid_skipped() {
        todo!()
    }

    // ── Extended deep hive: Names subkey + F value ──────────────────────
    //
    // These tests build on build_deep_hive but extend the flat page to include:
    //  - A Names NK under Users (so find_name_for_rid is called)
    //  - A username NK under Names (so the RID→username lookup can succeed)
    //  - A value list + VK "F" cell + data cell for the RID key
    //    (so read_f_value enters its scan loop)
    //
    // Layout of additional cells (beyond the 0x020–0x364 used in build_deep_hive):
    //   names_cell_off = 0x380   names NK (name="Names", 1 subkey)
    //   names_list_off = 0x3C0   lf list for Names subkey
    //   uname_cell_off = 0x400   username NK (name matches RID=500)
    //   uname_vlist_off= 0x440   value list cell for username NK (1 entry)
    //   uname_vk_off   = 0x480   VK cell (default value, type=RID=500=0x1F4)
    //   rid_vlist_off  = 0x4C0   value list cell for RID key (1 entry → F vk)
    //   f_vk_off       = 0x500   VK cell (NameLength=1, Name[0]='F', data_len=0x38)
    //   f_data_off     = 0x540   data cell (0x38 bytes of FILETIME + flags data)
    //   All within a single 4 KB page.

    fn build_extended_hive(flat_page: &mut Vec<u8>) {
        todo!()
    }

    /// Extended 5-level hive with Names subkey and F value — exercises
    /// find_name_for_rid (L411-526) and read_f_value main scan loop (L530-650).
    /// The RID=500 key: username lookup succeeds ("Administrator"), F value read
    /// succeeds with real timestamps and UAC flags.
    #[test]
    fn walk_sam_users_extended_chain_with_names_and_f_value() {
        todo!()
    }

    /// find_name_for_rid: Names key has subkey_count=0 → returns "RID-<rid>".
    /// Tests the early-return path in find_name_for_rid (L424-426).
    #[test]
    fn walk_sam_extended_names_zero_subkeys_fallback_username() {
        todo!()
    }

    /// find_name_for_rid: Names list has an entry but the VK type doesn't match → no username found → "RID-<rid>".
    /// Tests the "no match found" path (L525-526 in find_name_for_rid).
    #[test]
    fn walk_sam_extended_names_vk_type_mismatch_fallback() {
        todo!()
    }

    /// read_f_value: val_count=1 but VK NameLength != 1 → no "F" found → default.
    /// Tests the `if vname_len != 1 { continue }` branch (L575 in read_f_value).
    #[test]
    fn walk_sam_extended_f_vk_wrong_name_len_default_flags() {
        todo!()
    }

    /// read_f_value: VK name is 'G' (not 'F') → continue → returns default.
    /// Tests `if vname != b'F' { continue }` branch (L584).
    #[test]
    fn walk_sam_extended_f_vk_wrong_name_byte_default_flags() {
        todo!()
    }

    /// read_f_value: F value DataLength < 0x38 → returns default.
    /// Tests `if data_len < 0x38 { return default }` branch (L596-598).
    #[test]
    fn walk_sam_extended_f_data_too_short_default_flags() {
        todo!()
    }
}
