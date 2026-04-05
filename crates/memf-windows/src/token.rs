//! Windows process token and privilege extraction.
//!
//! Reads `_EPROCESS.Token` → `_TOKEN.Privileges` →
//! `_SEP_TOKEN_PRIVILEGES.Enabled/Present` to enumerate
//! process privileges. The `Token` field is an `_EX_FAST_REF`,
//! so the low 4 bits must be masked off.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, WinTokenInfo};

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
    todo!()
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
}
