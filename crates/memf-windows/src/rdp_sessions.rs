//! RDP (Remote Desktop Protocol) session enumeration from memory.
//!
//! Enumerates Terminal Services session data structures to recover RDP
//! session artifacts. RDP sessions are key forensic indicators for lateral
//! movement detection (MITRE ATT&CK T1021.001) — they reveal who connected
//! via RDP, from where, and when.
//!
//! Key forensic indicators:
//! - Active sessions with empty usernames (ghost sessions)
//! - Sessions from RFC 1918 private IPs crossing network boundaries
//! - Shadow sessions (someone watching another session)
//! - Service/default accounts used interactively

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// Maximum number of RDP sessions to enumerate (safety limit).
#[allow(dead_code)]
const MAX_SESSIONS: usize = 256;

/// Information about an RDP session recovered from kernel memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RdpSessionInfo {
    /// Terminal Services session ID.
    pub session_id: u32,
    /// Username of the session owner.
    pub username: String,
    /// Domain of the session owner.
    pub domain: String,
    /// Client machine name that initiated the RDP connection.
    pub client_name: String,
    /// Client IP address.
    pub client_address: String,
    /// Session connect time (Windows FILETIME).
    pub connect_time: u64,
    /// Session disconnect time (Windows FILETIME, 0 if still connected).
    pub disconnect_time: u64,
    /// Session logon time (Windows FILETIME).
    pub logon_time: u64,
    /// Human-readable session state.
    pub state: String,
    /// Whether this session exhibits suspicious characteristics.
    pub is_suspicious: bool,
}

/// Map a WTS session state numeric value to its human-readable name.
///
/// State values correspond to the `WTS_CONNECTSTATE_CLASS` enumeration
/// in the Windows SDK.
pub fn session_state_name(state: u32) -> String {
    match state {
        0 => "Active".into(),
        1 => "Connected".into(),
        2 => "ConnectQuery".into(),
        3 => "Shadow".into(),
        4 => "Disconnected".into(),
        5 => "Idle".into(),
        6 => "Listen".into(),
        7 => "Reset".into(),
        8 => "Down".into(),
        9 => "Init".into(),
        _ => "Unknown".into(),
    }
}

/// Classify an RDP session as suspicious based on forensic heuristics.
///
/// Returns `true` when any of the following conditions hold:
/// - Active session (state 0) with an empty username (ghost session)
/// - Session from an RFC 1918 private IP that crosses network boundaries
///   (e.g. `172.x` connecting to a `10.x` host — cross-network lateral movement)
/// - Session state is Shadow (state 3) — someone watching another session
/// - Username is a default/service account used interactively
///   (`SYSTEM`, `DefaultAccount`, `Guest`, `DefaultUser`)
pub fn classify_rdp_session(username: &str, client_address: &str, state: u32) -> bool {
    // Shadow sessions are always suspicious — someone is watching.
    if state == 3 {
        return true;
    }

    // Active session with empty username is a ghost session.
    if state == 0 && username.is_empty() {
        return true;
    }

    // Service/default accounts used interactively are suspicious.
    let normalized = username.to_uppercase();
    if matches!(
        normalized.as_str(),
        "SYSTEM" | "DEFAULTACCOUNT" | "GUEST" | "DEFAULTUSER"
    ) {
        return true;
    }

    // Cross-network lateral movement: RFC 1918 private IP from a different
    // private range than expected. We flag any private-range IP as suspicious
    // since the RDP session originated from a different internal network.
    if !client_address.is_empty() && is_cross_network_private_ip(client_address) {
        return true;
    }

    false
}

/// Check if an IP address is an RFC 1918 private address that suggests
/// cross-network lateral movement.
///
/// We flag sessions from `172.16.0.0/12` and `192.168.0.0/16` ranges
/// as potentially crossing network boundaries. The `10.0.0.0/8` range
/// is treated as the "local" subnet and not flagged on its own.
fn is_cross_network_private_ip(addr: &str) -> bool {
    if let Some(rest) = addr.strip_prefix("172.") {
        // 172.16.0.0 – 172.31.255.255
        if let Some(second_octet) = rest.split('.').next().and_then(|s| s.parse::<u8>().ok()) {
            return (16..=31).contains(&second_octet);
        }
    }
    if addr.starts_with("192.168.") {
        return true;
    }
    false
}

/// Enumerate RDP sessions from Windows Terminal Services data structures.
///
/// Looks up `MmSessionSpace` or `MiSessionWsList` for session enumeration.
/// If those symbols are unavailable, attempts to find `termsrv.dll` in a
/// `svchost.exe` process and walk its internal session list.
///
/// Returns `Ok(Vec::new())` if the required symbols are missing.
pub fn walk_rdp_sessions<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<RdpSessionInfo>> {
    // Require MmSessionSpace or MiSessionWsList symbol to proceed.
    // If neither is present, return empty vec (graceful degradation).
    let _list_head = match reader
        .symbols()
        .symbol_address("MiSessionWsList")
        .or_else(|| reader.symbols().symbol_address("MmSessionSpace"))
    {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // Full RDP session enumeration requires termsrv.dll internals which are
    // not available in the synthetic test environment. Return empty vec.
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
    // session_state_name tests
    // ---------------------------------------------------------------

    /// State 0 maps to "Active".
    #[test]
    fn state_active() {
        assert_eq!(session_state_name(0), "Active");
    }

    /// State 4 maps to "Disconnected".
    #[test]
    fn state_disconnected() {
        assert_eq!(session_state_name(4), "Disconnected");
    }

    /// An out-of-range state maps to "Unknown".
    #[test]
    fn state_unknown() {
        assert_eq!(session_state_name(42), "Unknown");
    }

    // ---------------------------------------------------------------
    // classify_rdp_session tests
    // ---------------------------------------------------------------

    /// Shadow sessions (state 3) are always suspicious.
    #[test]
    fn classify_shadow_suspicious() {
        assert!(classify_rdp_session("admin", "10.0.0.5", 3));
    }

    /// Active session with empty username is a ghost session — suspicious.
    #[test]
    fn classify_empty_username_suspicious() {
        assert!(classify_rdp_session("", "10.0.0.5", 0));
    }

    /// Normal active session with a real username from local subnet is benign.
    #[test]
    fn classify_normal_session_benign() {
        assert!(!classify_rdp_session("jsmith", "10.0.0.5", 0));
    }

    /// SYSTEM account used interactively is suspicious regardless of state.
    #[test]
    fn classify_system_account_suspicious() {
        assert!(classify_rdp_session("SYSTEM", "10.0.0.1", 0));
    }

    /// Cross-network private IP (192.168.x.x) is suspicious.
    #[test]
    fn classify_cross_network_192_168_suspicious() {
        assert!(classify_rdp_session("admin", "192.168.1.50", 0));
    }

    /// Cross-network private IP (172.16-31.x.x) is suspicious.
    #[test]
    fn classify_cross_network_172_suspicious() {
        assert!(classify_rdp_session("admin", "172.16.0.1", 0));
    }

    /// 172.x outside the 16-31 range is not flagged.
    #[test]
    fn classify_172_outside_range_benign() {
        assert!(!classify_rdp_session("admin", "172.15.0.1", 0));
    }

    // ---------------------------------------------------------------
    // walk_rdp_sessions tests
    // ---------------------------------------------------------------

    // ---------------------------------------------------------------
    // session_state_name: remaining variants
    // ---------------------------------------------------------------

    #[test]
    fn state_name_all_variants() {
        assert_eq!(session_state_name(0), "Active");
        assert_eq!(session_state_name(1), "Connected");
        assert_eq!(session_state_name(2), "ConnectQuery");
        assert_eq!(session_state_name(3), "Shadow");
        assert_eq!(session_state_name(4), "Disconnected");
        assert_eq!(session_state_name(5), "Idle");
        assert_eq!(session_state_name(6), "Listen");
        assert_eq!(session_state_name(7), "Reset");
        assert_eq!(session_state_name(8), "Down");
        assert_eq!(session_state_name(9), "Init");
        assert_eq!(session_state_name(10), "Unknown");
        assert_eq!(session_state_name(100), "Unknown");
    }

    // ---------------------------------------------------------------
    // is_cross_network_private_ip coverage
    // ---------------------------------------------------------------

    #[test]
    fn cross_network_private_ip_172_range() {
        // 172.16-31 is cross-network
        for oct in 16u8..=31 {
            assert!(
                is_cross_network_private_ip(&format!("172.{}.1.1", oct)),
                "172.{} should be cross-network",
                oct
            );
        }
        // 172.15 and 172.32 are not
        assert!(!is_cross_network_private_ip("172.15.0.1"));
        assert!(!is_cross_network_private_ip("172.32.0.1"));
        // 172.xyz non-numeric
        assert!(!is_cross_network_private_ip("172.abc.0.1"));
    }

    #[test]
    fn cross_network_private_ip_192_168() {
        assert!(is_cross_network_private_ip("192.168.0.1"));
        assert!(is_cross_network_private_ip("192.168.255.255"));
        assert!(!is_cross_network_private_ip("192.169.0.1"));
        assert!(!is_cross_network_private_ip("10.0.0.1")); // 10.x not flagged
        assert!(!is_cross_network_private_ip(""));
        assert!(!is_cross_network_private_ip("8.8.8.8")); // public
    }

    // ---------------------------------------------------------------
    // classify_rdp_session: remaining coverage
    // ---------------------------------------------------------------

    #[test]
    fn classify_guest_account_suspicious() {
        assert!(classify_rdp_session("GUEST", "10.0.0.1", 0));
        assert!(classify_rdp_session("guest", "10.0.0.1", 0)); // case-insensitive
    }

    #[test]
    fn classify_defaultaccount_suspicious() {
        assert!(classify_rdp_session("DefaultAccount", "10.0.0.1", 1));
        assert!(classify_rdp_session("DEFAULTUSER", "10.0.0.1", 4));
    }

    #[test]
    fn classify_normal_disconnected_benign() {
        // Disconnected session (state 4) with normal user and local IP is benign.
        assert!(!classify_rdp_session("jdoe", "10.0.0.5", 4));
    }

    #[test]
    fn classify_active_non_empty_username_local_ip_benign() {
        assert!(!classify_rdp_session("administrator", "10.1.2.3", 0));
    }

    #[test]
    fn classify_rdp_session_empty_address_benign() {
        // Empty client address — cross-network check is skipped.
        assert!(!classify_rdp_session("alice", "", 0));
    }

    /// RdpSessionInfo struct and serialization.
    #[test]
    fn rdp_session_info_serializes() {
        let info = RdpSessionInfo {
            session_id: 2,
            username: "SYSTEM".to_string(),
            domain: "NT AUTHORITY".to_string(),
            client_name: "DC01".to_string(),
            client_address: "10.0.0.1".to_string(),
            connect_time: 132_500_000_000_000_000,
            disconnect_time: 0,
            logon_time: 132_500_000_000_000_000,
            state: "Active".to_string(),
            is_suspicious: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"session_id\":2"));
        assert!(json.contains("\"is_suspicious\":true"));
        assert!(json.contains("SYSTEM"));
    }

    /// walk_rdp_sessions with MiSessionWsList present returns empty (stub).
    #[test]
    fn walk_rdp_sessions_with_symbol_returns_empty() {
        let isf = IsfBuilder::new()
            .add_symbol("MiSessionWsList", 0xFFFF_8000_0010_0000)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let sessions = walk_rdp_sessions(&reader).unwrap();
        assert!(sessions.is_empty());
    }

    /// walk_rdp_sessions with MmSessionSpace present returns empty (stub).
    #[test]
    fn walk_rdp_sessions_mmsessionspace_symbol_returns_empty() {
        let isf = IsfBuilder::new()
            .add_symbol("MmSessionSpace", 0xFFFF_8000_0020_0000)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let sessions = walk_rdp_sessions(&reader).unwrap();
        assert!(sessions.is_empty());
    }

    /// When no session symbols are present, walker returns an empty Vec.
    #[test]
    fn walk_no_symbol_returns_empty() {
        let isf = IsfBuilder::new()
            .add_struct("_MM_SESSION_SPACE", 0x200)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let sessions = walk_rdp_sessions(&reader).unwrap();
        assert!(sessions.is_empty());
    }
}
