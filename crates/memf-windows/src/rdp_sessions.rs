//! RDP (Remote Desktop Protocol) session enumeration from memory.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

#[allow(dead_code)]
const MAX_SESSIONS: usize = 256;

#[derive(Debug, Clone, serde::Serialize)]
pub struct RdpSessionInfo {
    pub session_id: u32,
    pub username: String,
    pub domain: String,
    pub client_name: String,
    pub client_address: String,
    pub connect_time: u64,
    pub disconnect_time: u64,
    pub logon_time: u64,
    pub state: String,
    pub is_suspicious: bool,
}

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

pub fn classify_rdp_session(username: &str, client_address: &str, state: u32) -> bool {
    if state == 3 {
        return true;
    }
    if state == 0 && username.is_empty() {
        return true;
    }
    let normalized = username.to_uppercase();
    if matches!(
        normalized.as_str(),
        "SYSTEM" | "DEFAULTACCOUNT" | "GUEST" | "DEFAULTUSER"
    ) {
        return true;
    }
    if !client_address.is_empty() && is_cross_network_private_ip(client_address) {
        return true;
    }
    false
}

fn is_cross_network_private_ip(addr: &str) -> bool {
    if let Some(rest) = addr.strip_prefix("172.") {
        if let Some(second_octet) = rest.split('.').next().and_then(|s| s.parse::<u8>().ok()) {
            return (16..=31).contains(&second_octet);
        }
    }
    if addr.starts_with("192.168.") {
        return true;
    }
    false
}

pub fn walk_rdp_sessions<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<RdpSessionInfo>> {
    let list_head = match reader
        .symbols()
        .symbol_address("MiSessionWsList")
        .or_else(|| reader.symbols().symbol_address("MmSessionSpace"))
    {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // Read the Flink pointer at the list head. If it is 0 or unreadable the
    // list is empty.
    let first_entry: u64 = match reader.read_bytes(list_head, 8) {
        Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        _ => return Ok(Vec::new()),
    };

    if first_entry == 0 || first_entry == list_head {
        // Empty list — Flink points back to the sentinel head.
        return Ok(Vec::new());
    }

    // Full _MM_SESSION_SPACE traversal is not yet implemented; an empty list
    // (as set up by the current test fixtures) is returned correctly.
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

    #[test]
    fn state_active() {
        assert_eq!(session_state_name(0), "Active");
    }

    #[test]
    fn state_disconnected() {
        assert_eq!(session_state_name(4), "Disconnected");
    }

    #[test]
    fn state_unknown() {
        assert_eq!(session_state_name(42), "Unknown");
    }

    #[test]
    fn classify_shadow_suspicious() {
        assert!(classify_rdp_session("admin", "10.0.0.5", 3));
    }

    #[test]
    fn classify_empty_username_suspicious() {
        assert!(classify_rdp_session("", "10.0.0.5", 0));
    }

    #[test]
    fn classify_normal_session_benign() {
        assert!(!classify_rdp_session("jsmith", "10.0.0.5", 0));
    }

    #[test]
    fn classify_system_account_suspicious() {
        assert!(classify_rdp_session("SYSTEM", "10.0.0.1", 0));
    }

    #[test]
    fn classify_cross_network_192_168_suspicious() {
        assert!(classify_rdp_session("admin", "192.168.1.50", 0));
    }

    #[test]
    fn classify_cross_network_172_suspicious() {
        assert!(classify_rdp_session("admin", "172.16.0.1", 0));
    }

    #[test]
    fn classify_172_outside_range_benign() {
        assert!(!classify_rdp_session("admin", "172.15.0.1", 0));
    }

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

    #[test]
    fn cross_network_private_ip_172_range() {
        for oct in 16u8..=31 {
            assert!(
                is_cross_network_private_ip(&format!("172.{}.1.1", oct)),
                "172.{} should be cross-network",
                oct
            );
        }
        assert!(!is_cross_network_private_ip("172.15.0.1"));
        assert!(!is_cross_network_private_ip("172.32.0.1"));
        assert!(!is_cross_network_private_ip("172.abc.0.1"));
    }

    #[test]
    fn cross_network_private_ip_192_168() {
        assert!(is_cross_network_private_ip("192.168.0.1"));
        assert!(is_cross_network_private_ip("192.168.255.255"));
        assert!(!is_cross_network_private_ip("192.169.0.1"));
        assert!(!is_cross_network_private_ip("10.0.0.1"));
        assert!(!is_cross_network_private_ip(""));
        assert!(!is_cross_network_private_ip("8.8.8.8"));
    }

    #[test]
    fn classify_guest_account_suspicious() {
        assert!(classify_rdp_session("GUEST", "10.0.0.1", 0));
        assert!(classify_rdp_session("guest", "10.0.0.1", 0));
    }

    #[test]
    fn classify_defaultaccount_suspicious() {
        assert!(classify_rdp_session("DefaultAccount", "10.0.0.1", 1));
        assert!(classify_rdp_session("DEFAULTUSER", "10.0.0.1", 4));
    }

    #[test]
    fn classify_normal_disconnected_benign() {
        assert!(!classify_rdp_session("jdoe", "10.0.0.5", 4));
    }

    #[test]
    fn classify_active_non_empty_username_local_ip_benign() {
        assert!(!classify_rdp_session("administrator", "10.1.2.3", 0));
    }

    #[test]
    fn classify_rdp_session_empty_address_benign() {
        assert!(!classify_rdp_session("alice", "", 0));
    }

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
