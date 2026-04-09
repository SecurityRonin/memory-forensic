//! Process SID enumeration for privilege escalation detection.
//!
//! Extracts Security Identifier (SID) information for each process,
//! showing which user/group security context a process runs under.
//! Essential for identifying privilege escalation — if a user-spawned
//! process runs as SYSTEM, that is suspicious. Equivalent to
//! Volatility's `getsids` plugin. MITRE ATT&CK T1078/T1134.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{ProcessSidInfo, Result};

/// Map a well-known SID string to its human-readable name.
///
/// Returns `Some(name)` for recognised Windows built-in SIDs,
/// `None` for domain/user-specific SIDs that require SAM lookup.
pub fn well_known_sid(sid: &str) -> Option<&'static str> {
    match sid {
        "S-1-5-18" => Some("SYSTEM"),
        "S-1-5-19" => Some("LOCAL SERVICE"),
        "S-1-5-20" => Some("NETWORK SERVICE"),
        "S-1-5-32-544" => Some("Administrators"),
        "S-1-5-32-545" => Some("Users"),
        "S-1-5-32-555" => Some("Remote Desktop Users"),
        "S-1-1-0" => Some("Everyone"),
        "S-1-5-7" => Some("ANONYMOUS LOGON"),
        _ => None,
    }
}

/// Determine whether a process running under a given SID is suspicious.
///
/// A process is flagged as suspicious if:
/// - It is **not** a known system process (csrss, lsass, services,
///   svchost, smss) but runs as SYSTEM (`S-1-5-18`).
/// - Its SID is ANONYMOUS LOGON (`S-1-5-7`) regardless of process name.
pub fn classify_process_sid(process_name: &str, sid: &str) -> bool {
    const SYSTEM_PROCS: &[&str] = &["csrss.exe", "lsass.exe", "services.exe", "svchost.exe", "smss.exe"];

    // Any process running as ANONYMOUS LOGON is suspicious
    if sid == "S-1-5-7" {
        return true;
    }

    // Non-system process running as SYSTEM is suspicious
    if sid == "S-1-5-18" {
        let lower = process_name.to_ascii_lowercase();
        if !SYSTEM_PROCS.iter().any(|&p| lower == p) {
            return true;
        }
    }

    false
}

/// Walk the process list and extract SID information for each process.
///
/// For each process, reads `_EPROCESS.Token` (masked `_EX_FAST_REF`),
/// then reads the `_TOKEN.UserAndGroups` SID, resolves well-known SIDs,
/// reads the integrity level, and classifies suspiciousness.
pub fn walk_getsids<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
    _process_list_head: u64,
) -> Result<Vec<ProcessSidInfo>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // well_known_sid unit tests
    // ---------------------------------------------------------------

    #[test]
    fn sid_system() {
        assert_eq!(well_known_sid("S-1-5-18"), Some("SYSTEM"));
    }

    #[test]
    fn sid_local_service() {
        assert_eq!(well_known_sid("S-1-5-19"), Some("LOCAL SERVICE"));
    }

    #[test]
    fn sid_network_service() {
        assert_eq!(well_known_sid("S-1-5-20"), Some("NETWORK SERVICE"));
    }

    #[test]
    fn sid_administrators() {
        assert_eq!(well_known_sid("S-1-5-32-544"), Some("Administrators"));
    }

    #[test]
    fn sid_users() {
        assert_eq!(well_known_sid("S-1-5-32-545"), Some("Users"));
    }

    #[test]
    fn sid_remote_desktop_users() {
        assert_eq!(well_known_sid("S-1-5-32-555"), Some("Remote Desktop Users"));
    }

    #[test]
    fn sid_everyone() {
        assert_eq!(well_known_sid("S-1-1-0"), Some("Everyone"));
    }

    #[test]
    fn sid_anonymous_logon() {
        assert_eq!(well_known_sid("S-1-5-7"), Some("ANONYMOUS LOGON"));
    }

    #[test]
    fn sid_unknown() {
        assert_eq!(
            well_known_sid("S-1-5-21-1234567890-987654321-111222333-500"),
            None,
        );
    }

    // ---------------------------------------------------------------
    // classify_process_sid unit tests
    // ---------------------------------------------------------------

    #[test]
    fn classify_unexpected_system_suspicious() {
        // A random user process running as SYSTEM is suspicious
        assert!(
            classify_process_sid("malware.exe", "S-1-5-18"),
            "non-system process as SYSTEM should be suspicious"
        );
    }

    #[test]
    fn classify_svchost_system_benign() {
        // svchost.exe running as SYSTEM is expected
        assert!(
            !classify_process_sid("svchost.exe", "S-1-5-18"),
            "svchost as SYSTEM should not be suspicious"
        );
    }

    #[test]
    fn classify_csrss_system_benign() {
        // csrss.exe running as SYSTEM is expected
        assert!(
            !classify_process_sid("csrss.exe", "S-1-5-18"),
            "csrss as SYSTEM should not be suspicious"
        );
    }

    #[test]
    fn classify_lsass_system_benign() {
        assert!(
            !classify_process_sid("lsass.exe", "S-1-5-18"),
            "lsass as SYSTEM should not be suspicious"
        );
    }

    #[test]
    fn classify_services_system_benign() {
        assert!(
            !classify_process_sid("services.exe", "S-1-5-18"),
            "services.exe as SYSTEM should not be suspicious"
        );
    }

    #[test]
    fn classify_smss_system_benign() {
        assert!(
            !classify_process_sid("smss.exe", "S-1-5-18"),
            "smss as SYSTEM should not be suspicious"
        );
    }

    #[test]
    fn classify_anonymous_suspicious() {
        // ANONYMOUS LOGON is always suspicious
        assert!(
            classify_process_sid("svchost.exe", "S-1-5-7"),
            "ANONYMOUS LOGON should always be suspicious"
        );
    }

    #[test]
    fn classify_normal_user_benign() {
        // Normal user SID is not suspicious
        assert!(
            !classify_process_sid("explorer.exe", "S-1-5-21-1234567890-987654321-111222333-1001"),
            "normal user SID should not be suspicious"
        );
    }

    #[test]
    fn classify_case_insensitive() {
        // SVCHOST.EXE (uppercase) running as SYSTEM should not be suspicious
        assert!(
            !classify_process_sid("SVCHOST.EXE", "S-1-5-18"),
            "classification should be case-insensitive"
        );
    }

    // ---------------------------------------------------------------
    // walk_getsids integration test
    // ---------------------------------------------------------------

    #[test]
    fn walk_no_procs_returns_empty() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let head_paddr: u64 = 0x0080_0000;

        // Empty circular list: head points to itself
        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .write_phys_u64(head_paddr, head_vaddr)       // Flink → self
            .write_phys_u64(head_paddr + 8, head_vaddr);  // Blink → self

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_getsids(&reader, head_vaddr).unwrap();
        assert!(
            results.is_empty(),
            "empty process list should return empty SID list"
        );
    }

    #[test]
    fn process_sid_info_serializes() {
        let info = ProcessSidInfo {
            pid: 4,
            process_name: "System".into(),
            user_sid: "S-1-5-18".into(),
            sid_name: "SYSTEM".into(),
            integrity_level: "System".into(),
            is_suspicious: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":4"));
        assert!(json.contains("\"user_sid\":\"S-1-5-18\""));
        assert!(json.contains("\"sid_name\":\"SYSTEM\""));
        assert!(json.contains("\"is_suspicious\":false"));
    }
}
