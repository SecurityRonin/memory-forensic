//! Process SID enumeration for privilege escalation detection.
//!
//! Extracts Security Identifier (SID) information for each process,
//! showing which user/group security context a process runs under.
//! Essential for identifying privilege escalation — if a user-spawned
//! process runs as SYSTEM, that is suspicious. Equivalent to
//! Volatility's `getsids` plugin. MITRE ATT&CK T1078/T1134.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::token::sid_to_string;
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

/// Well-known Windows Mandatory Label SIDs and their integrity level names.
const INTEGRITY_LEVELS: &[(&str, &str)] = &[
    ("S-1-16-0", "Untrusted"),
    ("S-1-16-4096", "Low"),
    ("S-1-16-8192", "Medium"),
    ("S-1-16-8448", "MediumPlus"),
    ("S-1-16-12288", "High"),
    ("S-1-16-16384", "System"),
    ("S-1-16-20480", "Protected"),
    ("S-1-16-28672", "Secure"),
];

/// Resolve an integrity-level SID to a human-readable label.
///
/// Returns the label name (e.g. `"System"`, `"High"`, `"Medium"`) or
/// `"Unknown"` if the SID is not a recognised mandatory label.
fn integrity_level_name(sid: &str) -> &'static str {
    for &(s, name) in INTEGRITY_LEVELS {
        if sid == s {
            return name;
        }
    }
    "Unknown"
}

/// Read a raw SID at the given virtual address and return its string form.
///
/// Follows the same layout as `_SID`: Revision (u8), SubAuthorityCount (u8),
/// IdentifierAuthority (6 bytes), SubAuthority array (count x u32).
/// Returns an empty string if the read fails or the SID is malformed.
fn read_sid_at<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, sid_ptr: u64) -> String {
    if sid_ptr == 0 {
        return String::new();
    }

    // Revision (u8 @ 0x0)
    let Ok(rev_bytes) = reader.read_bytes(sid_ptr, 1) else {
        return String::new();
    };
    let revision = rev_bytes[0];

    // SubAuthorityCount (u8 @ 0x1)
    let Ok(count_bytes) = reader.read_bytes(sid_ptr + 1, 1) else {
        return String::new();
    };
    let sub_count = count_bytes[0] as usize;
    if sub_count > 15 {
        return String::new();
    }

    // IdentifierAuthority (6 bytes @ 0x2)
    let Ok(auth_bytes) = reader.read_bytes(sid_ptr + 2, 6) else {
        return String::new();
    };
    let mut authority = [0u8; 6];
    authority.copy_from_slice(&auth_bytes[..6]);

    if sub_count == 0 {
        return sid_to_string(revision, &authority, &[]);
    }

    // SubAuthority array (sub_count x u32 @ 0x8)
    let Ok(sub_bytes) = reader.read_bytes(sid_ptr + 8, sub_count * 4) else {
        return String::new();
    };
    let sub_authorities: Vec<u32> = (0..sub_count)
        .map(|i| {
            let off = i * 4;
            u32::from_le_bytes(sub_bytes[off..off + 4].try_into().expect("4 bytes"))
        })
        .collect();

    sid_to_string(revision, &authority, &sub_authorities)
}

/// Read the user SID from a `_TOKEN` address.
///
/// Follows `_TOKEN.UserAndGroups` -> `_SID_AND_ATTRIBUTES[0].Sid` -> `_SID`.
fn read_token_user_sid<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    token_addr: u64,
) -> String {
    let user_and_groups: u64 = match reader.read_field(token_addr, "_TOKEN", "UserAndGroups") {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    if user_and_groups == 0 {
        return String::new();
    }

    let sid_ptr: u64 = match reader.read_field(user_and_groups, "_SID_AND_ATTRIBUTES", "Sid") {
        Ok(v) => v,
        Err(_) => return String::new(),
    };

    read_sid_at(reader, sid_ptr)
}

/// Read the integrity level SID from a `_TOKEN`.
///
/// The integrity level is stored as the last entry in the `_TOKEN.UserAndGroups`
/// array, at index `_TOKEN.UserAndGroupCount - 1`, but more reliably it can be
/// found via `_TOKEN.IntegrityLevelIndex`. We read `UserAndGroupCount` and the
/// `_SID_AND_ATTRIBUTES` entry size to index into the array.
///
/// Falls back to reading the last group if `IntegrityLevelIndex` is unavailable.
fn read_integrity_level<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    token_addr: u64,
) -> String {
    // Try to get IntegrityLevelIndex first
    let integrity_index: u32 =
        match reader.read_field(token_addr, "_TOKEN", "IntegrityLevelIndex") {
            Ok(v) => v,
            Err(_) => {
                // Fall back: read UserAndGroupCount - 1 as the integrity entry index
                let count: u32 =
                    match reader.read_field(token_addr, "_TOKEN", "UserAndGroupCount") {
                        Ok(v) if v > 0 => v,
                        _ => return String::new(),
                    };
                count - 1
            }
        };

    let user_and_groups: u64 = match reader.read_field(token_addr, "_TOKEN", "UserAndGroups") {
        Ok(v) if v != 0 => v,
        _ => return String::new(),
    };

    // Each _SID_AND_ATTRIBUTES entry is 16 bytes on x64 (Sid ptr + Attributes u32 + padding)
    let sa_size = reader
        .symbols()
        .struct_size("_SID_AND_ATTRIBUTES")
        .unwrap_or(16) as u64;

    let entry_addr = user_and_groups.wrapping_add(u64::from(integrity_index) * sa_size);

    let sid_ptr: u64 = match reader.read_field(entry_addr, "_SID_AND_ATTRIBUTES", "Sid") {
        Ok(v) => v,
        Err(_) => return String::new(),
    };

    read_sid_at(reader, sid_ptr)
}

/// Walk the process list and extract SID information for each process.
///
/// For each process, reads `_EPROCESS.Token` (masked `_EX_FAST_REF`),
/// then reads the `_TOKEN.UserAndGroups` SID, resolves well-known SIDs,
/// reads the integrity level, and classifies suspiciousness.
pub fn walk_getsids<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    process_list_head: u64,
) -> Result<Vec<ProcessSidInfo>> {
    let procs = crate::process::walk_processes(reader, process_list_head)?;
    let mut results = Vec::new();

    for proc in &procs {
        // Read _EPROCESS.Token (_EX_FAST_REF — mask low 4 bits)
        let token_raw: u64 = match reader.read_field(proc.vaddr, "_EPROCESS", "Token") {
            Ok(v) => v,
            Err(_) => continue,
        };
        let token_addr = token_raw & !0xF;
        if token_addr == 0 {
            continue;
        }

        // Read user SID
        let user_sid = read_token_user_sid(reader, token_addr);

        // Resolve well-known SID name
        let sid_name = if user_sid.is_empty() {
            String::new()
        } else {
            well_known_sid(&user_sid)
                .map(String::from)
                .unwrap_or_else(|| user_sid.clone())
        };

        // Read integrity level
        let integrity_sid = read_integrity_level(reader, token_addr);
        let integrity_level = if integrity_sid.is_empty() {
            "Unknown".to_string()
        } else {
            integrity_level_name(&integrity_sid).to_string()
        };

        // Classify suspiciousness
        let is_suspicious = if user_sid.is_empty() {
            false
        } else {
            classify_process_sid(&proc.image_name, &user_sid)
        };

        // Truncate pid from u64 to u32 (PIDs fit in u32 on Windows)
        let pid = proc.pid as u32;

        results.push(ProcessSidInfo {
            pid,
            process_name: proc.image_name.clone(),
            user_sid,
            sid_name,
            integrity_level,
            is_suspicious,
        });
    }

    Ok(results)
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
