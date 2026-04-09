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

use crate::unicode::read_unicode_string;

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
pub const UAC_LOCKOUT: u32 = 0x0010;
pub const UAC_PASSWORD_NOT_REQUIRED: u32 = 0x0020;
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
    if username.is_empty() {
        return false;
    }

    let lower = username.to_ascii_lowercase();

    // Hidden accounts end with '$' (a Windows convention)
    if lower.ends_with('$') && !lower.ends_with("machine$") {
        return true;
    }

    // RID 500 is the built-in Administrator — if renamed to something unusual
    if rid == 500 && lower != "administrator" && lower != "admin" {
        return true;
    }

    // Password not required is suspicious for normal accounts
    if (flags & UAC_PASSWORD_NOT_REQUIRED) != 0 && (flags & UAC_NORMAL_ACCOUNT) != 0 {
        return true;
    }

    // Known attack tool default account names
    const SUSPICIOUS_NAMES: &[&str] = &[
        "defaultaccount0",
        "support_388945a0",
        "svc_admin",
        "backdoor",
        "hacker",
        "test123",
    ];
    if SUSPICIOUS_NAMES.iter().any(|&s| lower == s) {
        return true;
    }

    false
}

/// Extract local user accounts from the SAM registry hive in memory.
///
/// Reads the SAM hive at `hive_addr` and walks
/// `SAM\Domains\Account\Users` to enumerate user accounts.
/// Returns an empty `Vec` if the hive is unreadable or the path is missing.
pub fn walk_sam_users<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
    _hive_addr: u64,
) -> crate::Result<Vec<SamUserInfo>> {
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

    /// No SAM hive address → empty Vec.
    #[test]
    fn walk_sam_users_no_hive() {
        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .add_struct("_CM_KEY_NODE", 0x80)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_sam_users(&reader, 0).unwrap();
        assert!(result.is_empty());
    }

    /// Normal Administrator account is not suspicious.
    #[test]
    fn classify_sam_normal_admin() {
        assert!(!classify_sam_user("Administrator", 500, UAC_NORMAL_ACCOUNT));
    }

    /// Renamed Administrator (RID 500) is suspicious.
    #[test]
    fn classify_sam_renamed_admin() {
        assert!(classify_sam_user("notadmin", 500, UAC_NORMAL_ACCOUNT));
    }

    /// Hidden account ending with '$' is suspicious.
    #[test]
    fn classify_sam_hidden_account() {
        assert!(classify_sam_user("backdoor$", 1001, UAC_NORMAL_ACCOUNT));
    }

    /// Machine account ending with 'MACHINE$' is benign.
    #[test]
    fn classify_sam_machine_account_benign() {
        assert!(!classify_sam_user("WORKSTATION$MACHINE$", 1000, UAC_NORMAL_ACCOUNT));
    }

    /// Password-not-required on normal account is suspicious.
    #[test]
    fn classify_sam_no_password() {
        assert!(classify_sam_user(
            "testuser",
            1002,
            UAC_NORMAL_ACCOUNT | UAC_PASSWORD_NOT_REQUIRED
        ));
    }

    /// Known attack tool account name is suspicious.
    #[test]
    fn classify_sam_known_bad_name() {
        assert!(classify_sam_user("backdoor", 1003, UAC_NORMAL_ACCOUNT));
    }

    /// Regular user account is not suspicious.
    #[test]
    fn classify_sam_regular_user() {
        assert!(!classify_sam_user("john.doe", 1004, UAC_NORMAL_ACCOUNT));
    }

    /// Empty username is not suspicious.
    #[test]
    fn classify_sam_empty_benign() {
        assert!(!classify_sam_user("", 0, 0));
    }
}
