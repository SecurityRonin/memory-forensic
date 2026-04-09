//! NTLM SSP credential extraction from LSASS memory.
//!
//! The NTLM Security Support Provider caches NT and LM hashes in LSASS
//! memory under `msv1_0.dll` (the MSV1_0 authentication package). These
//! hashes can be used directly for Pass-the-Hash attacks.
//!
//! This module provides:
//! - `NtlmCredentialInfo` struct for recovered NTLM credential metadata
//! - `walk_ntlm_credentials` — graceful-degradation stub (RED phase)
//!   returning empty when msv1_0/lsasrv symbols are absent
//!
//! A full implementation requires walking `msv1_0!NlpMsv1_0LogonSessionList`
//! → `MSV1_0_LIST_62` / `MSV1_0_LIST_63` structures, decrypting the
//! stored NT hash using the LSASS session key (derived from `lsasrv!lsaKey`).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// NTLM credentials for a logon session recovered from LSASS memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NtlmCredentialInfo {
    /// Logon session identifier (LUID).
    pub logon_id: u64,
    /// Username associated with this logon session.
    pub username: String,
    /// Domain or computer name.
    pub domain: String,
    /// 16-byte NT hash (MD4 of the UTF-16LE password).
    pub nt_hash: Vec<u8>,
    /// 16-byte LM hash (often all-zeros or absent on modern Windows).
    pub lm_hash: Vec<u8>,
    /// True if these are credentials for a privileged account cached unexpectedly.
    pub is_suspicious: bool,
}

/// Classify NTLM credentials as suspicious.
///
/// Suspicious criteria:
/// - Privileged account (Administrator, SYSTEM-level account) credentials
///   cached in a non-interactive or service logon session
/// - LM hash present (non-empty, non-zero) — indicates legacy/weak credential storage
/// - NT hash matches known weak or common passwords (e.g. "aad3b435..." = empty password)
pub fn classify_ntlm_credential(username: &str, nt_hash: &[u8], lm_hash: &[u8]) -> bool {
    // Empty/null NT hash (aad3b435b51404eeaad3b435b51404ee = LM hash of empty password)
    // or NT hash of empty password (31d6cfe0d16ae931b73c59d7e0c089c0)
    let empty_nt: [u8; 16] = [
        0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0,
        0x89, 0xc0,
    ];

    // LM hash present (non-zero): indicates password < 15 chars stored in legacy format
    let lm_present = lm_hash.iter().any(|&b| b != 0);

    // Known empty-password NT hash
    let empty_password = nt_hash.len() == 16 && nt_hash == empty_nt;

    // High-value account by name
    let privileged = username.eq_ignore_ascii_case("administrator")
        || username.eq_ignore_ascii_case("admin")
        || username.to_ascii_lowercase().contains("svc_")
        || username.to_ascii_lowercase().starts_with("svc");

    lm_present || empty_password || privileged
}

/// Walk LSASS memory for cached NTLM credentials.
///
/// Returns `Ok(Vec::new())` when `NlpMsv1_0LogonSessionList` or related
/// `msv1_0.dll` symbols are absent from the symbol table (graceful degradation).
pub fn walk_ntlm_credentials<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<NtlmCredentialInfo>> {
    // Graceful degradation: require NlpMsv1_0LogonSessionList symbol
    if reader
        .symbols()
        .symbol_address("NlpMsv1_0LogonSessionList")
        .is_none()
    {
        return Ok(Vec::new());
    }

    // Full implementation pending msv1_0 struct definitions and LSASS key decryption.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An "Administrator" account credential is always flagged as high-value.
    #[test]
    fn classify_administrator_credentials_suspicious() {
        let nt_hash = vec![0xAAu8; 16]; // arbitrary non-empty hash
        let lm_hash = vec![0u8; 16];
        assert!(classify_ntlm_credential("Administrator", &nt_hash, &lm_hash));
    }

    /// Without NlpMsv1_0LogonSessionList symbol, walker returns empty.
    #[test]
    fn walk_ntlm_credentials_no_symbol_returns_empty() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &[0u8; 16]);
        let (cr3, mem) = ptb.build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_ntlm_credentials(&reader).unwrap();
        assert!(results.is_empty());
    }
}
