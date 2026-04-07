//! Windows process token and privilege extraction.
//!
//! Reads `_EPROCESS.Token` → `_TOKEN.Privileges` →
//! `_SEP_TOKEN_PRIVILEGES.Enabled/Present` to enumerate
//! process privileges. The `Token` field is an `_EX_FAST_REF`,
//! so the low 4 bits must be masked off.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, WinTokenInfo};

/// Convert raw SID components to the standard string representation.
///
/// Format: `S-{Revision}-{IdentifierAuthority}-{Sub1}-{Sub2}-...`
///
/// The `IdentifierAuthority` is a 6-byte big-endian value. When the top
/// two bytes are zero, it displays as decimal (e.g. `5` for NT Authority);
/// otherwise as `0x` hex.
pub fn sid_to_string(
    revision: u8,
    identifier_authority: &[u8; 6],
    sub_authorities: &[u32],
) -> String {
    use std::fmt::Write;

    let auth_value = u64::from(identifier_authority[0]) << 40
        | u64::from(identifier_authority[1]) << 32
        | u64::from(identifier_authority[2]) << 24
        | u64::from(identifier_authority[3]) << 16
        | u64::from(identifier_authority[4]) << 8
        | u64::from(identifier_authority[5]);

    let mut s = if auth_value >= 0x1_0000_0000 {
        format!("S-{revision}-0x{auth_value:012X}")
    } else {
        format!("S-{revision}-{auth_value}")
    };
    for &sub in sub_authorities {
        write!(s, "-{sub}").expect("write to String");
    }
    s
}

/// Read the user SID from a `_TOKEN` address.
///
/// Follows `_TOKEN.UserAndGroups` → `_SID_AND_ATTRIBUTES[0].Sid` → `_SID`
/// and formats the result as a string like `S-1-5-18`.
/// Returns an empty string if any pointer in the chain is null.
fn read_user_sid<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    token_addr: u64,
) -> String {
    // Read _TOKEN.UserAndGroups pointer
    let user_and_groups: u64 = match reader.read_field(token_addr, "_TOKEN", "UserAndGroups") {
        Ok(v) => v,
        Err(_) => return String::new(),
    };

    if user_and_groups == 0 {
        return String::new();
    }

    // Read first _SID_AND_ATTRIBUTES.Sid pointer (index 0 = token user)
    let sid_ptr: u64 = match reader.read_field(user_and_groups, "_SID_AND_ATTRIBUTES", "Sid") {
        Ok(v) => v,
        Err(_) => return String::new(),
    };

    if sid_ptr == 0 {
        return String::new();
    }

    // Read _SID.Revision (u8 at offset 0x0)
    let Ok(rev_bytes) = reader.read_bytes(sid_ptr, 1) else {
        return String::new();
    };
    let revision = rev_bytes[0];

    // Read _SID.SubAuthorityCount (u8 at offset 0x1)
    let Ok(count_bytes) = reader.read_bytes(sid_ptr + 1, 1) else {
        return String::new();
    };
    let sub_count = count_bytes[0] as usize;

    if sub_count > 15 {
        // SID can have at most 15 sub-authorities
        return String::new();
    }

    // Read _SID.IdentifierAuthority (6 bytes at offset 0x2)
    let Ok(auth_bytes) = reader.read_bytes(sid_ptr + 2, 6) else {
        return String::new();
    };
    let mut authority = [0u8; 6];
    authority.copy_from_slice(&auth_bytes[..6]);

    // Read _SID.SubAuthority array (sub_count × u32 at offset 0x8)
    if sub_count == 0 {
        return sid_to_string(revision, &authority, &[]);
    }

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

/// Well-known Windows privilege LUID values and their names.
/// The privilege bitmask uses bit positions corresponding to LUID values.
const PRIVILEGE_NAMES: &[(u32, &str)] = &[
    (2, "SeCreateTokenPrivilege"),
    (3, "SeAssignPrimaryTokenPrivilege"),
    (4, "SeLockMemoryPrivilege"),
    (5, "SeIncreaseQuotaPrivilege"),
    (7, "SeTcbPrivilege"),
    (8, "SeSecurityPrivilege"),
    (9, "SeTakeOwnershipPrivilege"),
    (10, "SeLoadDriverPrivilege"),
    (11, "SeSystemProfilePrivilege"),
    (12, "SeSystemtimePrivilege"),
    (13, "SeProfileSingleProcessPrivilege"),
    (14, "SeIncreaseBasePriorityPrivilege"),
    (15, "SeCreatePagefilePrivilege"),
    (16, "SeCreatePermanentPrivilege"),
    (17, "SeBackupPrivilege"),
    (18, "SeRestorePrivilege"),
    (19, "SeShutdownPrivilege"),
    (20, "SeDebugPrivilege"),
    (21, "SeAuditPrivilege"),
    (22, "SeSystemEnvironmentPrivilege"),
    (23, "SeChangeNotifyPrivilege"),
    (24, "SeRemoteShutdownPrivilege"),
    (25, "SeUndockPrivilege"),
    (28, "SeManageVolumePrivilege"),
    (29, "SeImpersonatePrivilege"),
    (30, "SeCreateGlobalPrivilege"),
    (33, "SeIncreaseWorkingSetPrivilege"),
    (34, "SeTimeZonePrivilege"),
    (35, "SeCreateSymbolicLinkPrivilege"),
];

/// Decode a privilege bitmask into human-readable names.
pub fn decode_privileges(enabled: u64) -> Vec<String> {
    PRIVILEGE_NAMES
        .iter()
        .filter(|(bit, _)| (enabled >> bit) & 1 == 1)
        .map(|(_, name)| (*name).to_string())
        .collect()
}

/// Walk all processes and extract their token privileges.
///
/// For each process, reads `_EPROCESS.Token` (masked `_EX_FAST_REF`),
/// then reads `_TOKEN.Privileges.Enabled` and `_TOKEN.Privileges.Present`.
pub fn walk_tokens<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<WinTokenInfo>> {
    let procs = crate::process::walk_processes(reader, ps_head_vaddr)?;
    let mut results = Vec::new();

    let priv_offset = reader
        .symbols()
        .field_offset("_TOKEN", "Privileges")
        .ok_or_else(|| crate::Error::Walker("missing _TOKEN.Privileges offset".into()))?;

    let present_off = reader
        .symbols()
        .field_offset("_SEP_TOKEN_PRIVILEGES", "Present")
        .ok_or_else(|| {
            crate::Error::Walker("missing _SEP_TOKEN_PRIVILEGES.Present offset".into())
        })?;

    let enabled_off = reader
        .symbols()
        .field_offset("_SEP_TOKEN_PRIVILEGES", "Enabled")
        .ok_or_else(|| {
            crate::Error::Walker("missing _SEP_TOKEN_PRIVILEGES.Enabled offset".into())
        })?;

    for proc in &procs {
        // Read _EPROCESS.Token (_EX_FAST_REF)
        let token_raw: u64 = reader.read_field(proc.vaddr, "_EPROCESS", "Token")?;
        let token_addr = token_raw & !0xF; // mask off EX_FAST_REF low nibble

        if token_addr == 0 {
            continue;
        }

        // Read _TOKEN.Privileges._SEP_TOKEN_PRIVILEGES
        let priv_base = token_addr.wrapping_add(priv_offset);

        let present_bytes = reader.read_bytes(priv_base.wrapping_add(present_off), 8)?;
        let privileges_present = u64::from_le_bytes(present_bytes.try_into().expect("8 bytes"));

        let enabled_bytes = reader.read_bytes(priv_base.wrapping_add(enabled_off), 8)?;
        let privileges_enabled = u64::from_le_bytes(enabled_bytes.try_into().expect("8 bytes"));

        let privilege_names = decode_privileges(privileges_enabled);
        let user_sid = read_user_sid(reader, token_addr);

        results.push(WinTokenInfo {
            pid: proc.pid,
            image_name: proc.image_name.clone(),
            privileges_enabled,
            privileges_present,
            privilege_names,
            session_id: 0, // requires _MM_SESSION_SPACE traversal
            user_sid,
        });
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_win_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    const EPROCESS_PID: u64 = 0x440;
    const EPROCESS_LINKS: u64 = 0x448;
    const EPROCESS_PPID: u64 = 0x540;
    const EPROCESS_PEB: u64 = 0x550;
    const EPROCESS_TOKEN: u64 = 0x4B8;
    const EPROCESS_IMAGE_NAME: u64 = 0x5A8;
    const EPROCESS_CREATE_TIME: u64 = 0x430;
    const EPROCESS_EXIT_TIME: u64 = 0x438;
    const KPROCESS_DTB: u64 = 0x28;

    // _TOKEN offsets
    const TOKEN_PRIVILEGES: u64 = 0x40;
    // _SEP_TOKEN_PRIVILEGES offsets within _TOKEN.Privileges
    const SEP_PRESENT: u64 = 0x0;
    const SEP_ENABLED: u64 = 0x8;

    #[test]
    fn decode_privileges_maps_known_bits() {
        // SeDebugPrivilege = bit 20, SeLoadDriverPrivilege = bit 10
        let enabled = (1u64 << 20) | (1u64 << 10);
        let names = decode_privileges(enabled);
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"SeDebugPrivilege".to_string()));
        assert!(names.contains(&"SeLoadDriverPrivilege".to_string()));
    }

    #[test]
    fn decode_privileges_empty_bitmask() {
        let names = decode_privileges(0);
        assert!(names.is_empty());
    }

    #[test]
    fn extracts_token_from_process() {
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let token_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0080_1000;
        let token_paddr: u64 = 0x0080_2000;

        // Token pointer: _EX_FAST_REF — low 4 bits are ref count
        let token_ex_fast_ref = token_vaddr | 0x7;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(token_vaddr, token_paddr, flags::WRITABLE)
            // Sentinel
            .write_phys_u64(head_paddr, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(head_paddr + 8, eproc_vaddr + EPROCESS_LINKS)
            // _EPROCESS
            .write_phys_u64(eproc_paddr + KPROCESS_DTB, 0x1AB000)
            .write_phys_u64(eproc_paddr + EPROCESS_CREATE_TIME, 132800000000000000)
            .write_phys_u64(eproc_paddr + EPROCESS_EXIT_TIME, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PID, 4444)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS + 8, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_PPID, 4)
            .write_phys_u64(eproc_paddr + EPROCESS_PEB, 0x7FFE_0000)
            .write_phys_u64(eproc_paddr + EPROCESS_TOKEN, token_ex_fast_ref)
            .write_phys(eproc_paddr + EPROCESS_IMAGE_NAME, b"pwsh.exe\0");

        // _TOKEN.Privileges (at token + 0x40)
        // Present: SeDebugPrivilege (bit 20) + SeChangeNotifyPrivilege (bit 23)
        let present: u64 = (1 << 20) | (1 << 23);
        // Enabled: only SeChangeNotifyPrivilege
        let enabled: u64 = 1 << 23;

        let ptb = ptb
            .write_phys_u64(token_paddr + TOKEN_PRIVILEGES + SEP_PRESENT, present)
            .write_phys_u64(token_paddr + TOKEN_PRIVILEGES + SEP_ENABLED, enabled);

        let reader = make_win_reader(ptb);
        let results = walk_tokens(&reader, head_vaddr).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pid, 4444);
        assert_eq!(results[0].image_name, "pwsh.exe");
        assert_eq!(results[0].privileges_present, present);
        assert_eq!(results[0].privileges_enabled, enabled);
        assert_eq!(results[0].privilege_names.len(), 1);
        assert!(results[0]
            .privilege_names
            .contains(&"SeChangeNotifyPrivilege".to_string()));
        // Token page has UserAndGroups at offset 0x90 — uninitialized = 0 → empty SID
        assert_eq!(results[0].user_sid, "");
    }

    #[test]
    fn skips_process_with_null_token() {
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0080_1000;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys_u64(head_paddr, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(head_paddr + 8, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(eproc_paddr + KPROCESS_DTB, 0x1AB000)
            .write_phys_u64(eproc_paddr + EPROCESS_CREATE_TIME, 132800000000000000)
            .write_phys_u64(eproc_paddr + EPROCESS_EXIT_TIME, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PID, 4)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS + 8, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_PPID, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PEB, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_TOKEN, 0) // null token
            .write_phys(eproc_paddr + EPROCESS_IMAGE_NAME, b"System\0");

        let reader = make_win_reader(ptb);
        let results = walk_tokens(&reader, head_vaddr).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn sid_to_string_local_system() {
        // S-1-5-18 = NT AUTHORITY\SYSTEM
        let authority = [0u8, 0, 0, 0, 0, 5]; // NT Authority (value 5)
        let sub_authorities = [18u32]; // SYSTEM
        assert_eq!(sid_to_string(1, &authority, &sub_authorities), "S-1-5-18");
    }

    #[test]
    fn sid_to_string_domain_admin() {
        // S-1-5-21-{domain RIDs}-500 = domain Administrator
        let authority = [0u8, 0, 0, 0, 0, 5];
        let sub_authorities = [21u32, 1234567890, 987654321, 111222333, 500];
        assert_eq!(
            sid_to_string(1, &authority, &sub_authorities),
            "S-1-5-21-1234567890-987654321-111222333-500"
        );
    }

    #[test]
    fn sid_to_string_high_authority_uses_hex() {
        // If top 2 bytes of authority are non-zero, display as 0x hex
        let authority = [1u8, 0, 0, 0, 0, 0]; // value = 0x010000000000
        let sub_authorities = [42u32];
        assert_eq!(
            sid_to_string(1, &authority, &sub_authorities),
            "S-1-0x010000000000-42"
        );
    }

    #[test]
    fn extracts_user_sid_from_token() {
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let token_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let sa_vaddr: u64 = 0xFFFF_8000_0010_3000; // _SID_AND_ATTRIBUTES array
        let sid_vaddr: u64 = sa_vaddr + 0x100; // _SID data

        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0080_1000;
        let token_paddr: u64 = 0x0080_2000;
        let sa_paddr: u64 = 0x0080_3000;
        let sid_paddr: u64 = sa_paddr + 0x100;

        let token_ex_fast_ref = token_vaddr | 0x7;

        // Build _SID for S-1-5-18 (LOCAL SYSTEM)
        let mut sid_data = vec![0u8; 64];
        sid_data[0] = 1; // Revision
        sid_data[1] = 1; // SubAuthorityCount
        // IdentifierAuthority@0x2: [0, 0, 0, 0, 0, 5] = NT Authority
        sid_data[7] = 5;
        // SubAuthority[0]@0x8: 18 (SYSTEM)
        sid_data[8..12].copy_from_slice(&18u32.to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(token_vaddr, token_paddr, flags::WRITABLE)
            .map_4k(sa_vaddr, sa_paddr, flags::WRITABLE)
            // Sentinel
            .write_phys_u64(head_paddr, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(head_paddr + 8, eproc_vaddr + EPROCESS_LINKS)
            // _EPROCESS
            .write_phys_u64(eproc_paddr + KPROCESS_DTB, 0x1AB000)
            .write_phys_u64(eproc_paddr + EPROCESS_CREATE_TIME, 132800000000000000)
            .write_phys_u64(eproc_paddr + EPROCESS_EXIT_TIME, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PID, 4)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS + 8, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_PPID, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PEB, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_TOKEN, token_ex_fast_ref)
            .write_phys(eproc_paddr + EPROCESS_IMAGE_NAME, b"System\0")
            // _TOKEN: Privileges
            .write_phys_u64(token_paddr + TOKEN_PRIVILEGES + SEP_PRESENT, 1 << 23)
            .write_phys_u64(token_paddr + TOKEN_PRIVILEGES + SEP_ENABLED, 1 << 23)
            // _TOKEN: UserAndGroupCount@0x88, UserAndGroups@0x90
            .write_phys(token_paddr + 0x88, &1u32.to_le_bytes())
            .write_phys_u64(token_paddr + 0x90, sa_vaddr)
            // _SID_AND_ATTRIBUTES[0]: Sid@0x0 → sid_vaddr
            .write_phys_u64(sa_paddr, sid_vaddr)
            // _SID data
            .write_phys(sid_paddr, &sid_data);

        let reader = make_win_reader(ptb);
        let results = walk_tokens(&reader, head_vaddr).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pid, 4);
        assert_eq!(results[0].user_sid, "S-1-5-18");
    }
}
