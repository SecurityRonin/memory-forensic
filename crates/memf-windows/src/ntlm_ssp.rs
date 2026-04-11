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
        todo!()
    }

/// Walk LSASS memory for cached NTLM credentials.
///
/// Returns `Ok(Vec::new())` when `NlpMsv1_0LogonSessionList` or related
/// `msv1_0.dll` symbols are absent from the symbol table (graceful degradation).
pub fn walk_ntlm_credentials<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<NtlmCredentialInfo>> {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;

    /// An "Administrator" account credential is always flagged as high-value.
    #[test]
    fn classify_administrator_credentials_suspicious() {
        todo!()
    }

    /// "admin" (case-insensitive) is flagged as privileged.
    #[test]
    fn classify_admin_account_suspicious() {
        todo!()
    }

    /// LM hash present (any non-zero byte) → suspicious.
    #[test]
    fn classify_lm_hash_present_suspicious() {
        todo!()
    }

    /// Empty-password NT hash → suspicious.
    #[test]
    fn classify_empty_password_nt_hash_suspicious() {
        todo!()
    }

    /// Service account (starts with "svc_") → suspicious.
    #[test]
    fn classify_svc_account_suspicious() {
        todo!()
    }

    /// Regular non-privileged account with strong hash → benign.
    #[test]
    fn classify_regular_user_benign() {
        todo!()
    }

    /// NtlmCredentialInfo serializes correctly.
    #[test]
    fn ntlm_credential_info_serializes() {
        todo!()
    }

    /// Without NlpMsv1_0LogonSessionList symbol, walker returns empty.
    #[test]
    fn walk_ntlm_credentials_no_symbol_returns_empty() {
        todo!()
    }
}
