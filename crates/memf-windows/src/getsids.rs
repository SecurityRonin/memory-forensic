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
    const SYSTEM_PROCS: &[&str] = &[
        "csrss.exe",
        "lsass.exe",
        "services.exe",
        "svchost.exe",
        "smss.exe",
    ];

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
    let integrity_index: u32 = match reader.read_field(token_addr, "_TOKEN", "IntegrityLevelIndex")
    {
        Ok(v) => v,
        Err(_) => {
            // Fall back: read UserAndGroupCount - 1 as the integrity entry index
            let count: u32 = match reader.read_field(token_addr, "_TOKEN", "UserAndGroupCount") {
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
            !classify_process_sid(
                "explorer.exe",
                "S-1-5-21-1234567890-987654321-111222333-1001"
            ),
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

    #[test]
    fn classify_network_service_benign() {
        // Network service SID is not in our suspicious list, but it's not
        // ANONYMOUS LOGON and not SYSTEM, so it's benign.
        assert!(
            !classify_process_sid("svchost.exe", "S-1-5-20"),
            "NETWORK SERVICE SID should not be suspicious"
        );
    }

    #[test]
    fn classify_administrator_sid_benign() {
        // Administrators group SID — not suspicious.
        assert!(
            !classify_process_sid("explorer.exe", "S-1-5-32-544"),
            "Administrators group SID should not be suspicious"
        );
    }

    // ---------------------------------------------------------------
    // integrity_level_name tests (via public classify_process_sid path)
    // ---------------------------------------------------------------

    #[test]
    fn integrity_level_untrusted() {
        assert_eq!(integrity_level_name("S-1-16-0"), "Untrusted");
    }

    #[test]
    fn integrity_level_low() {
        assert_eq!(integrity_level_name("S-1-16-4096"), "Low");
    }

    #[test]
    fn integrity_level_medium() {
        assert_eq!(integrity_level_name("S-1-16-8192"), "Medium");
    }

    #[test]
    fn integrity_level_medium_plus() {
        assert_eq!(integrity_level_name("S-1-16-8448"), "MediumPlus");
    }

    #[test]
    fn integrity_level_high() {
        assert_eq!(integrity_level_name("S-1-16-12288"), "High");
    }

    #[test]
    fn integrity_level_system() {
        assert_eq!(integrity_level_name("S-1-16-16384"), "System");
    }

    #[test]
    fn integrity_level_protected() {
        assert_eq!(integrity_level_name("S-1-16-20480"), "Protected");
    }

    #[test]
    fn integrity_level_secure() {
        assert_eq!(integrity_level_name("S-1-16-28672"), "Secure");
    }

    #[test]
    fn integrity_level_unknown() {
        assert_eq!(integrity_level_name("S-1-16-99999"), "Unknown");
    }

    #[test]
    fn integrity_level_empty() {
        assert_eq!(integrity_level_name(""), "Unknown");
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
            .write_phys_u64(head_paddr, head_vaddr) // Flink → self
            .write_phys_u64(head_paddr + 8, head_vaddr); // Blink → self

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

    // ---------------------------------------------------------------
    // read_token_user_sid coverage
    // ---------------------------------------------------------------

    /// read_token_user_sid: _TOKEN.UserAndGroups == 0 → returns empty string.
    #[test]
    fn read_token_user_sid_user_and_groups_zero() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let token_vaddr: u64 = 0xFFFF_8000_00C0_0000;
        let token_paddr: u64 = 0x00C0_0000;

        // Token page: UserAndGroups at offset 0x80 = 0 (null pointer).
        let token_page = vec![0u8; 0x1000]; // all zeros

        let isf = IsfBuilder::new()
            .add_struct("_TOKEN", 0x200)
            .add_field("_TOKEN", "UserAndGroups", 0x80, "pointer")
            .add_struct("_SID_AND_ATTRIBUTES", 0x10)
            .add_field("_SID_AND_ATTRIBUTES", "Sid", 0x00, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(token_vaddr, token_paddr, flags::WRITABLE)
            .write_phys(token_paddr, &token_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = read_token_user_sid(&reader, token_vaddr);
        assert_eq!(result, "", "UserAndGroups == 0 should return empty string");
    }

    /// read_token_user_sid: valid UserAndGroups and Sid pointer → returns SID string.
    #[test]
    fn read_token_user_sid_valid_path() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Addresses:
        //   token_vaddr: _TOKEN with UserAndGroups at +0x80 → ug_vaddr
        //   ug_vaddr: _SID_AND_ATTRIBUTES with Sid at +0x00 → sid_vaddr
        //   sid_vaddr: S-1-5-18 (SYSTEM)
        let token_vaddr: u64  = 0xFFFF_8000_00C1_0000;
        let ug_vaddr: u64     = 0xFFFF_8000_00C2_0000;
        let sid_vaddr: u64    = 0xFFFF_8000_00C3_0000;

        let token_paddr: u64  = 0x00C1_0000;
        let ug_paddr: u64     = 0x00C2_0000;
        let sid_paddr: u64    = 0x00C3_0000;

        let mut token_page = vec![0u8; 0x1000];
        token_page[0x80..0x88].copy_from_slice(&ug_vaddr.to_le_bytes());

        let mut ug_page = vec![0u8; 0x1000];
        ug_page[0x00..0x08].copy_from_slice(&sid_vaddr.to_le_bytes()); // Sid at +0

        // S-1-5-18 SID
        let mut sid_page = vec![0u8; 0x1000];
        sid_page[0] = 1; // Revision
        sid_page[1] = 1; // SubAuthorityCount
        sid_page[2..8].copy_from_slice(&[0, 0, 0, 0, 0, 5]);
        sid_page[8..12].copy_from_slice(&18u32.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("_TOKEN", 0x200)
            .add_field("_TOKEN", "UserAndGroups", 0x80, "pointer")
            .add_struct("_SID_AND_ATTRIBUTES", 0x10)
            .add_field("_SID_AND_ATTRIBUTES", "Sid", 0x00, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(token_vaddr, token_paddr, flags::WRITABLE)
            .map_4k(ug_vaddr,    ug_paddr,    flags::WRITABLE)
            .map_4k(sid_vaddr,   sid_paddr,   flags::WRITABLE)
            .write_phys(token_paddr, &token_page)
            .write_phys(ug_paddr,    &ug_page)
            .write_phys(sid_paddr,   &sid_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = read_token_user_sid(&reader, token_vaddr);
        assert_eq!(result, "S-1-5-18", "should return SYSTEM SID");
    }

    // ---------------------------------------------------------------
    // read_integrity_level coverage
    // ---------------------------------------------------------------

    /// read_integrity_level: IntegrityLevelIndex path (ISF has the field).
    /// Token has IntegrityLevelIndex = 0, UserAndGroups → entry at index 0 → SID.
    #[test]
    fn read_integrity_level_via_integrity_index() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let token_vaddr: u64  = 0xFFFF_8000_00D0_0000;
        let ug_vaddr: u64     = 0xFFFF_8000_00D1_0000;
        let sid_vaddr: u64    = 0xFFFF_8000_00D2_0000;

        let token_paddr: u64  = 0x00D0_0000;
        let ug_paddr: u64     = 0x00D1_0000;
        let sid_paddr: u64    = 0x00D2_0000;

        // _TOKEN:
        //   IntegrityLevelIndex at +0x90 = 0 (u32)
        //   UserAndGroups at +0x80 → ug_vaddr
        let mut token_page = vec![0u8; 0x1000];
        token_page[0x80..0x88].copy_from_slice(&ug_vaddr.to_le_bytes());
        token_page[0x90..0x94].copy_from_slice(&0u32.to_le_bytes()); // index 0

        // _SID_AND_ATTRIBUTES[0] at ug_vaddr+0 (sa_size=0x10): Sid → sid_vaddr
        let mut ug_page = vec![0u8; 0x1000];
        ug_page[0x00..0x08].copy_from_slice(&sid_vaddr.to_le_bytes());

        // SID S-1-16-12288 (High integrity)
        let mut sid_page = vec![0u8; 0x1000];
        sid_page[0] = 1; // Revision
        sid_page[1] = 1; // SubAuthorityCount
        sid_page[2..8].copy_from_slice(&[0, 0, 0, 0, 0, 16]);
        sid_page[8..12].copy_from_slice(&12288u32.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("_TOKEN", 0x200)
            .add_field("_TOKEN", "IntegrityLevelIndex", 0x90, "unsigned long")
            .add_field("_TOKEN", "UserAndGroups", 0x80, "pointer")
            .add_struct("_SID_AND_ATTRIBUTES", 0x10)
            .add_field("_SID_AND_ATTRIBUTES", "Sid", 0x00, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(token_vaddr, token_paddr, flags::WRITABLE)
            .map_4k(ug_vaddr,    ug_paddr,    flags::WRITABLE)
            .map_4k(sid_vaddr,   sid_paddr,   flags::WRITABLE)
            .write_phys(token_paddr, &token_page)
            .write_phys(ug_paddr,    &ug_page)
            .write_phys(sid_paddr,   &sid_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = read_integrity_level(&reader, token_vaddr);
        assert_eq!(result, "S-1-16-12288", "should return High integrity SID");
    }

    /// read_integrity_level: fallback path via UserAndGroupCount when IntegrityLevelIndex absent.
    #[test]
    fn read_integrity_level_via_usergroup_count_fallback() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // No IntegrityLevelIndex field → fall back to UserAndGroupCount - 1.
        // UserAndGroupCount = 2, so integrity_index = 1.
        // Entry at ug_vaddr + 1 * sa_size (0x10) has Sid → sid_vaddr.
        let token_vaddr: u64  = 0xFFFF_8000_00E0_0000;
        let ug_vaddr: u64     = 0xFFFF_8000_00E1_0000;
        let sid_vaddr: u64    = 0xFFFF_8000_00E2_0000;

        let token_paddr: u64  = 0x00E0_0000;
        let ug_paddr: u64     = 0x00E1_0000;
        let sid_paddr: u64    = 0x00E2_0000;

        let mut token_page = vec![0u8; 0x1000];
        // UserAndGroupCount at +0x88 = 2
        token_page[0x88..0x8C].copy_from_slice(&2u32.to_le_bytes());
        // UserAndGroups at +0x80
        token_page[0x80..0x88].copy_from_slice(&ug_vaddr.to_le_bytes());

        // _SID_AND_ATTRIBUTES[1] at ug_vaddr + 0x10 (sa_size=0x10): Sid → sid_vaddr
        let mut ug_page = vec![0u8; 0x1000];
        ug_page[0x10..0x18].copy_from_slice(&sid_vaddr.to_le_bytes());

        // S-1-16-8192 (Medium)
        let mut sid_page = vec![0u8; 0x1000];
        sid_page[0] = 1;
        sid_page[1] = 1;
        sid_page[2..8].copy_from_slice(&[0, 0, 0, 0, 0, 16]);
        sid_page[8..12].copy_from_slice(&8192u32.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("_TOKEN", 0x200)
            // No IntegrityLevelIndex field → Err → fallback.
            .add_field("_TOKEN", "UserAndGroupCount", 0x88, "unsigned long")
            .add_field("_TOKEN", "UserAndGroups", 0x80, "pointer")
            .add_struct("_SID_AND_ATTRIBUTES", 0x10)
            .add_field("_SID_AND_ATTRIBUTES", "Sid", 0x00, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(token_vaddr, token_paddr, flags::WRITABLE)
            .map_4k(ug_vaddr,    ug_paddr,    flags::WRITABLE)
            .map_4k(sid_vaddr,   sid_paddr,   flags::WRITABLE)
            .write_phys(token_paddr, &token_page)
            .write_phys(ug_paddr,    &ug_page)
            .write_phys(sid_paddr,   &sid_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = read_integrity_level(&reader, token_vaddr);
        assert_eq!(result, "S-1-16-8192", "fallback path should yield Medium integrity SID");
    }

    // ---------------------------------------------------------------
    // read_sid_at tests via mapped memory
    // ---------------------------------------------------------------

    fn make_base_reader() -> memf_core::object_reader::ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let (cr3, mem) = PageTableBuilder::new().build();
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// read_sid_at with sid_ptr == 0 returns empty string.
    #[test]
    fn read_sid_at_null_ptr_returns_empty() {
        let reader = make_base_reader();
        let result = read_sid_at(&reader, 0);
        assert_eq!(result, "");
    }

    /// read_sid_at with unmapped memory returns empty string.
    #[test]
    fn read_sid_at_unmapped_returns_empty() {
        let reader = make_base_reader();
        let result = read_sid_at(&reader, 0xFFFF_8000_DEAD_0000);
        assert_eq!(result, "");
    }

    /// read_sid_at with a valid SID in mapped memory returns the expected string.
    #[test]
    fn read_sid_at_valid_system_sid() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // S-1-5-18 (SYSTEM):
        //   Revision=1, SubAuthorityCount=1, Authority=[0,0,0,0,0,5], SubAuth=[18]
        let sid_vaddr: u64 = 0xFFFF_8000_0090_0000;
        let sid_paddr: u64 = 0x0090_0000;

        let mut page = [0u8; 4096];
        page[0] = 1; // Revision
        page[1] = 1; // SubAuthorityCount
        page[2..8].copy_from_slice(&[0, 0, 0, 0, 0, 5]); // NT Authority
        // SubAuthority[0] = 18 at offset 8
        page[8..12].copy_from_slice(&18u32.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sid_vaddr, sid_paddr, flags::WRITABLE)
            .write_phys(sid_paddr, &page)
            .build();

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = read_sid_at(&reader, sid_vaddr);
        assert_eq!(result, "S-1-5-18");
    }

    /// read_sid_at with SubAuthorityCount == 0 returns string without sub-authorities.
    #[test]
    fn read_sid_at_zero_sub_authority_count() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let sid_vaddr: u64 = 0xFFFF_8000_0091_0000;
        let sid_paddr: u64 = 0x0091_0000;

        let mut page = [0u8; 4096];
        page[0] = 1; // Revision
        page[1] = 0; // SubAuthorityCount = 0
        page[2..8].copy_from_slice(&[0, 0, 0, 0, 0, 1]); // authority = 1 (World Authority)

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sid_vaddr, sid_paddr, flags::WRITABLE)
            .write_phys(sid_paddr, &page)
            .build();

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = read_sid_at(&reader, sid_vaddr);
        // S-1-1 (no sub-authorities)
        assert_eq!(result, "S-1-1");
    }

    /// read_sid_at with SubAuthorityCount > 15 returns empty string (invalid).
    #[test]
    fn read_sid_at_excessive_sub_authority_count_returns_empty() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let sid_vaddr: u64 = 0xFFFF_8000_0092_0000;
        let sid_paddr: u64 = 0x0092_0000;

        let mut page = [0u8; 4096];
        page[0] = 1;  // Revision
        page[1] = 16; // SubAuthorityCount = 16 > 15 → invalid

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sid_vaddr, sid_paddr, flags::WRITABLE)
            .write_phys(sid_paddr, &page)
            .build();

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = read_sid_at(&reader, sid_vaddr);
        assert_eq!(result, "", "excessive SubAuthorityCount should return empty");
    }

    /// read_sid_at with a high-authority SID (top 2 bytes of authority non-zero)
    /// formats authority as hex.
    #[test]
    fn read_sid_at_high_authority_hex_format() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let sid_vaddr: u64 = 0xFFFF_8000_0093_0000;
        let sid_paddr: u64 = 0x0093_0000;

        let mut page = [0u8; 4096];
        page[0] = 1; // Revision
        page[1] = 0; // SubAuthorityCount = 0
        // High authority: first byte non-zero (authority >= 0x1_0000_0000)
        page[2] = 0x00;
        page[3] = 0x01; // authority[1] = 1 → auth_value = 0x0001_0000_0000
        page[4..8].copy_from_slice(&[0, 0, 0, 0]);

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sid_vaddr, sid_paddr, flags::WRITABLE)
            .write_phys(sid_paddr, &page)
            .build();

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = read_sid_at(&reader, sid_vaddr);
        // auth_value = 0x000100000000 >= 0x1_0000_0000 → hex format
        assert!(result.starts_with("S-1-0x"), "expected hex authority format, got: {result}");
    }

    /// read_sid_at for S-1-5-21-... (domain SID with 4 sub-authorities).
    #[test]
    fn read_sid_at_domain_sid_four_sub_authorities() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let sid_vaddr: u64 = 0xFFFF_8000_0094_0000;
        let sid_paddr: u64 = 0x0094_0000;

        let mut page = [0u8; 4096];
        page[0] = 1; // Revision
        page[1] = 4; // 4 sub-authorities
        page[2..8].copy_from_slice(&[0, 0, 0, 0, 0, 5]); // NT Authority
        // Sub-authorities: 21, 100, 200, 500
        page[8..12].copy_from_slice(&21u32.to_le_bytes());
        page[12..16].copy_from_slice(&100u32.to_le_bytes());
        page[16..20].copy_from_slice(&200u32.to_le_bytes());
        page[20..24].copy_from_slice(&500u32.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sid_vaddr, sid_paddr, flags::WRITABLE)
            .write_phys(sid_paddr, &page)
            .build();

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = read_sid_at(&reader, sid_vaddr);
        assert_eq!(result, "S-1-5-21-100-200-500");
    }

    // ---------------------------------------------------------------
    // well_known_sid completeness checks
    // ---------------------------------------------------------------

    #[test]
    fn well_known_sid_all_covered() {
        // Verify every entry in the match arm is reachable and correct.
        assert!(well_known_sid("S-1-5-18").is_some());
        assert!(well_known_sid("S-1-5-19").is_some());
        assert!(well_known_sid("S-1-5-20").is_some());
        assert!(well_known_sid("S-1-5-32-544").is_some());
        assert!(well_known_sid("S-1-5-32-545").is_some());
        assert!(well_known_sid("S-1-5-32-555").is_some());
        assert!(well_known_sid("S-1-1-0").is_some());
        assert!(well_known_sid("S-1-5-7").is_some());
        // Non-matching
        assert!(well_known_sid("S-1-99-99").is_none());
    }

    // ---------------------------------------------------------------
    // classify_process_sid edge cases
    // ---------------------------------------------------------------

    /// LSASS.EXE (all-caps variant) as SYSTEM is still benign.
    #[test]
    fn classify_lsass_upper_case_benign() {
        assert!(!classify_process_sid("LSASS.EXE", "S-1-5-18"));
    }

    /// An empty process name with SYSTEM SID is suspicious.
    #[test]
    fn classify_empty_process_name_system_suspicious() {
        assert!(classify_process_sid("", "S-1-5-18"));
    }

    /// ANONYMOUS LOGON is suspicious even for known system processes.
    #[test]
    fn classify_lsass_anonymous_suspicious() {
        assert!(classify_process_sid("lsass.exe", "S-1-5-7"));
    }

    // ---------------------------------------------------------------
    // integrity_level_name exhaustive tests
    // ---------------------------------------------------------------

    #[test]
    fn integrity_levels_all_entries() {
        let cases = [
            ("S-1-16-0", "Untrusted"),
            ("S-1-16-4096", "Low"),
            ("S-1-16-8192", "Medium"),
            ("S-1-16-8448", "MediumPlus"),
            ("S-1-16-12288", "High"),
            ("S-1-16-16384", "System"),
            ("S-1-16-20480", "Protected"),
            ("S-1-16-28672", "Secure"),
            ("S-1-16-99999", "Unknown"),
        ];
        for (sid, expected) in &cases {
            assert_eq!(
                integrity_level_name(sid),
                *expected,
                "SID {sid} should map to {expected}"
            );
        }
    }

    // ---------------------------------------------------------------
    // walk_getsids with a real EPROCESS+TOKEN+SID chain
    // ---------------------------------------------------------------

    /// walk_getsids: one process "malware.exe" with Token → UserAndGroups → S-1-5-18 (SYSTEM).
    ///
    /// Covers walk_getsids lines 222-269 (walk body: token read, SID extraction,
    /// well_known_sid resolution, integrity level, classify, results.push).
    ///
    /// Memory layout:
    ///   head_vaddr (process list head): Flink → eproc+0x448
    ///   eproc_vaddr:
    ///     [0x28] DirectoryTableBase = eproc_paddr
    ///     [0x440] UniqueProcessId = 1234
    ///     [0x448] ActiveProcessLinks.Flink = head_vaddr (sentinel)
    ///     [0x4B8] Token = token_vaddr
    ///     [0x540] InheritedFromUniqueProcessId = 0
    ///     [0x5A8] ImageFileName = "malware.exe\0"
    ///   token_vaddr:
    ///     [0x88] UserAndGroupCount = 1
    ///     [0x90] UserAndGroups = ug_vaddr
    ///   ug_vaddr (_SID_AND_ATTRIBUTES[0]):
    ///     [0x00] Sid = sid_vaddr
    ///   sid_vaddr (S-1-5-18):
    ///     Revision=1, SubAuthorityCount=1, Auth=[0,0,0,0,0,5], SubAuth=[18]
    #[test]
    fn walk_getsids_one_process_system_sid_is_suspicious() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // All paddrs < 0x00FF_FFFF (SyntheticPhysMem limit)
        let head_vaddr:  u64 = 0xFFFF_8000_00F0_0000;
        let head_paddr:  u64 = 0x00F0_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_00F1_0000;
        let eproc_paddr: u64 = 0x00F2_0000; // Use a different paddr for CR3
        let token_vaddr: u64 = 0xFFFF_8000_00F3_0000;
        let token_paddr: u64 = 0x00F3_0000;
        let ug_vaddr:    u64 = 0xFFFF_8000_00F4_0000;
        let ug_paddr:    u64 = 0x00F4_0000;
        let sid_vaddr:   u64 = 0xFFFF_8000_00F5_0000;
        let sid_paddr:   u64 = 0x00F5_0000;

        // _EPROCESS.ActiveProcessLinks is at 0x448 (Flink at +0, Blink at +8).
        // head.Flink → eproc+0x448 = eproc_vaddr + 0x448
        let eproc_links_vaddr = eproc_vaddr + 0x448;

        // head page: Flink = eproc+0x448
        let mut head_page = vec![0u8; 0x1000];
        head_page[0x00..0x08].copy_from_slice(&eproc_links_vaddr.to_le_bytes()); // Flink
        head_page[0x08..0x10].copy_from_slice(&eproc_links_vaddr.to_le_bytes()); // Blink

        // eproc page
        let mut eproc_page = vec![0u8; 0x1000];
        // _KPROCESS.DirectoryTableBase at eproc+0x28 (Pcb is at +0, so kproc=eproc)
        eproc_page[0x28..0x30].copy_from_slice(&(eproc_paddr as u64).to_le_bytes());
        // UniqueProcessId at +0x440
        eproc_page[0x440..0x448].copy_from_slice(&1234u64.to_le_bytes());
        // ActiveProcessLinks.Flink at +0x448 = head_vaddr (sentinel → stop)
        eproc_page[0x448..0x450].copy_from_slice(&head_vaddr.to_le_bytes());
        eproc_page[0x450..0x458].copy_from_slice(&head_vaddr.to_le_bytes());
        // Token at +0x4B8 = token_vaddr (low bits clear)
        eproc_page[0x4B8..0x4C0].copy_from_slice(&token_vaddr.to_le_bytes());
        // InheritedFromUniqueProcessId at +0x540
        eproc_page[0x540..0x548].copy_from_slice(&0u64.to_le_bytes());
        // Peb at +0x550 = 0 (no PEB)
        // ImageFileName at +0x5A8 = "malware.exe\0"
        let img_name = b"malware.exe\0";
        eproc_page[0x5A8..0x5A8 + img_name.len()].copy_from_slice(img_name);

        // token page
        let mut token_page = vec![0u8; 0x1000];
        // UserAndGroupCount at +0x88 = 1
        token_page[0x88..0x8C].copy_from_slice(&1u32.to_le_bytes());
        // UserAndGroups at +0x90 = ug_vaddr
        token_page[0x90..0x98].copy_from_slice(&ug_vaddr.to_le_bytes());

        // ug page (_SID_AND_ATTRIBUTES[0]): Sid at +0x00 = sid_vaddr
        let mut ug_page = vec![0u8; 0x1000];
        ug_page[0x00..0x08].copy_from_slice(&sid_vaddr.to_le_bytes());

        // sid page: S-1-5-18 (SYSTEM)
        let mut sid_page = vec![0u8; 0x100];
        sid_page[0] = 1; // Revision
        sid_page[1] = 1; // SubAuthorityCount
        sid_page[2..8].copy_from_slice(&[0, 0, 0, 0, 0, 5]); // NT Authority
        sid_page[8..12].copy_from_slice(&18u32.to_le_bytes()); // SubAuthority[0] = 18

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(head_vaddr,  head_paddr,  flags::WRITABLE)
            .write_phys(head_paddr, &head_page)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys(eproc_paddr, &eproc_page)
            .map_4k(token_vaddr, token_paddr, flags::WRITABLE)
            .write_phys(token_paddr, &token_page)
            .map_4k(ug_vaddr,    ug_paddr,    flags::WRITABLE)
            .write_phys(ug_paddr, &ug_page)
            .map_4k(sid_vaddr,   sid_paddr,   flags::WRITABLE)
            .write_phys(sid_paddr, &sid_page)
            .build();

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_getsids(&reader, head_vaddr).unwrap();
        assert_eq!(results.len(), 1, "should find one process");

        let proc = &results[0];
        assert_eq!(proc.pid, 1234);
        assert_eq!(proc.process_name, "malware.exe");
        assert_eq!(proc.user_sid, "S-1-5-18");
        assert_eq!(proc.sid_name, "SYSTEM");
        assert!(proc.is_suspicious, "non-system process as SYSTEM should be suspicious");
    }
}
