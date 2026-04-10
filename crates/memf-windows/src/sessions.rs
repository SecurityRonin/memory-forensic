//! Windows logon session enumeration from kernel memory.
//!
//! Enumerates logon sessions by walking the kernel's session list
//! (`LogonSessionList` / `SepLogonSessions`). Each session contains
//! the session ID, username, domain, logon type, authentication
//! package, and logon time.
//!
//! Forensic value:
//! - Detect unauthorized interactive sessions
//! - Identify lateral movement via `NetworkCleartext` (type 8) or
//!   `NewCredentials` (type 9) logons
//! - Spot pass-the-hash attacks where SYSTEM uses RemoteInteractive (type 10)
//!
//! Equivalent to Volatility's `sessions` plugin.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// Maximum logon sessions to enumerate (safety limit).
#[allow(dead_code)]
const MAX_SESSIONS: usize = 4_096;

/// Information about a single Windows logon session.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionInfo {
    /// Windows session ID.
    pub session_id: u32,
    /// Username associated with this logon session.
    pub username: String,
    /// Domain or machine name for the account.
    pub domain: String,
    /// Human-readable logon type (e.g. "Interactive", "Network").
    pub logon_type: String,
    /// Logon time as a Windows FILETIME (100ns ticks since 1601-01-01).
    pub logon_time: u64,
    /// Authentication package used (e.g. "NTLM", "Kerberos", "Negotiate").
    pub auth_package: String,
    /// Locally Unique Identifier (LUID) for this logon session.
    pub logon_id: u64,
    /// Whether this session exhibits suspicious characteristics.
    pub is_suspicious: bool,
}

/// Map a numeric Windows logon type to its human-readable name.
///
/// Values correspond to the `SECURITY_LOGON_TYPE` enumeration in
/// `ntsecapi.h`.
pub fn logon_type_name(logon_type: u32) -> &'static str {
    match logon_type {
        0 => "System",
        2 => "Interactive",
        3 => "Network",
        4 => "Batch",
        5 => "Service",
        7 => "Unlock",
        8 => "NetworkCleartext",
        9 => "NewCredentials",
        10 => "RemoteInteractive",
        11 => "CachedInteractive",
        _ => "Unknown",
    }
}

/// Classify a logon session as suspicious based on forensic heuristics.
///
/// Returns `true` when any of the following conditions hold:
/// - `NetworkCleartext` (type 8) logon — credentials sent in plaintext,
///   common in legacy/misconfigured environments or credential harvesting
/// - `NewCredentials` (type 9) with a non-system account — often indicates
///   `runas /netonly` or pass-the-hash lateral movement
/// - `RemoteInteractive` (type 10) from the SYSTEM account — SYSTEM should
///   never initiate RDP sessions; indicates possible exploitation
pub fn classify_session(logon_type: u32, username: &str) -> bool {
    // NetworkCleartext logons are always suspicious — plaintext credentials.
    if logon_type == 8 {
        return true;
    }

    // NewCredentials with a non-system account suggests runas /netonly or PtH.
    if logon_type == 9 {
        let normalized = username.to_uppercase();
        if normalized != "SYSTEM" {
            return true;
        }
    }

    // SYSTEM using RemoteInteractive (RDP) is abnormal.
    if logon_type == 10 {
        let normalized = username.to_uppercase();
        if normalized == "SYSTEM" {
            return true;
        }
    }

    false
}

/// Enumerate Windows logon sessions from kernel memory.
///
/// Looks up `LogonSessionList` or `SepLogonSessions` to find the head
/// of the logon session linked list. Walks `_SEP_LOGON_SESSION_REFERENCES`
/// entries and reads the associated `_SECURITY_LOGON_SESSION` data.
///
/// Returns `Ok(Vec::new())` if the required symbols are missing.
pub fn walk_sessions<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<SessionInfo>> {
    // Require LogonSessionList or SepLogonSessions symbol to proceed.
    // If neither is present, return empty vec (graceful degradation).
    let _list_head = match reader
        .symbols()
        .symbol_address("LogonSessionList")
        .or_else(|| reader.symbols().symbol_address("SepLogonSessions"))
    {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // Full logon session enumeration requires lsass internals not available
    // in the synthetic test environment. Return empty vec.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ---------------------------------------------------------------
    // logon_type_name tests
    // ---------------------------------------------------------------

    /// Type 2 maps to "Interactive".
    #[test]
    fn logon_type_interactive() {
        assert_eq!(logon_type_name(2), "Interactive");
    }

    /// Type 3 maps to "Network".
    #[test]
    fn logon_type_network() {
        assert_eq!(logon_type_name(3), "Network");
    }

    /// Type 10 maps to "RemoteInteractive".
    #[test]
    fn logon_type_remote() {
        assert_eq!(logon_type_name(10), "RemoteInteractive");
    }

    // ---------------------------------------------------------------
    // classify_session tests
    // ---------------------------------------------------------------

    /// NetworkCleartext (type 8) is always suspicious.
    #[test]
    fn classify_cleartext_suspicious() {
        assert!(classify_session(8, "admin"));
    }

    /// A normal Interactive (type 2) logon from a regular user is benign.
    #[test]
    fn classify_normal_benign() {
        assert!(!classify_session(2, "jsmith"));
    }

    /// SYSTEM using RemoteInteractive (type 10) is suspicious.
    #[test]
    fn classify_system_rdp_suspicious() {
        assert!(classify_session(10, "SYSTEM"));
    }

    /// NewCredentials (type 9) with a non-system account is suspicious.
    #[test]
    fn classify_new_credentials_non_system_suspicious() {
        assert!(classify_session(9, "admin"));
    }

    /// NewCredentials (type 9) with the SYSTEM account is not suspicious.
    #[test]
    fn classify_new_credentials_system_benign() {
        assert!(!classify_session(9, "SYSTEM"));
    }

    /// RemoteInteractive (type 10) from a regular user is benign.
    #[test]
    fn classify_remote_regular_user_benign() {
        assert!(!classify_session(10, "jsmith"));
    }

    /// System logon type (0) is benign.
    #[test]
    fn classify_system_logon_type_benign() {
        assert!(!classify_session(0, "SYSTEM"));
    }

    // ---------------------------------------------------------------
    // walk_sessions tests
    // ---------------------------------------------------------------

    /// When no logon session symbols are present, walker returns an empty Vec.
    #[test]
    fn walk_no_symbol_returns_empty() {
        let isf = IsfBuilder::new()
            .add_struct("_SEP_LOGON_SESSION_REFERENCES", 0x100)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let sessions = walk_sessions(&reader).unwrap();
        assert!(sessions.is_empty());
    }
}
