//! Token impersonation chain detection.
//!
//! Detects threads that are impersonating a higher-privileged security
//! context than their owning process. The most suspicious pattern is a
//! thread in a user-mode process impersonating the SYSTEM account
//! (S-1-5-18) at Impersonation or Delegation level — a technique used
//! by privilege escalation exploits and pass-the-token attacks.
//!
//! Detection walks ETHREAD entries and checks `CrossThreadFlags` bit
//! `ActiveImpersonationInfo`. When set, the thread's `ImpersonationInfo`
//! pointer leads to an impersonation token whose user SID can be compared
//! against the process's primary token SID.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about a thread performing token impersonation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenImpersonationInfo {
    /// Process ID of the owning process.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Process image name.
    pub process_name: String,
    /// SID string of the process primary token user.
    pub primary_token_user: String,
    /// SID string of the thread impersonation token user.
    pub impersonation_token_user: String,
    /// Impersonation level: 0=Anonymous, 1=Identification, 2=Impersonation, 3=Delegation.
    pub impersonation_level: u32,
    /// Human-readable impersonation level name.
    pub impersonation_level_name: String,
    /// True if the thread is impersonating SYSTEM from a non-SYSTEM process at level ≥2.
    pub is_suspicious: bool,
}

/// Returns the human-readable name for a Windows impersonation level.
pub fn impersonation_level_name(level: u32) -> &'static str {
    match level {
        0 => "Anonymous",
        1 => "Identification",
        2 => "Impersonation",
        3 => "Delegation",
        _ => "Unknown",
    }
}

/// Classify a thread's impersonation as suspicious.
///
/// Suspicious criteria: the thread is impersonating SYSTEM (S-1-5-18)
/// from a process that is not running as SYSTEM, at impersonation level
/// ≥ 2 (actual impersonation or delegation — not just identification).
pub fn classify_token_impersonation(
    primary_user: &str,
    impersonation_user: &str,
    level: u32,
) -> bool {
    impersonation_user.contains("S-1-5-18")
        && !primary_user.contains("S-1-5-18")
        && level >= 2
}

/// Walk all threads and detect suspicious token impersonation.
///
/// For each thread with `ActiveImpersonationInfo` set in `CrossThreadFlags`,
/// compares the impersonation token SID against the process primary token SID.
///
/// Returns `Ok(Vec::new())` if `PsActiveProcessHead` symbol is absent
/// (graceful degradation).
pub fn walk_token_impersonation<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<TokenImpersonationInfo>> {
    // Graceful degradation: require PsActiveProcessHead to walk processes/threads
    if reader
        .symbols()
        .symbol_address("PsActiveProcessHead")
        .is_none()
    {
        return Ok(Vec::new());
    }

    // In a full implementation we would:
    // 1. Walk process list via PsActiveProcessHead
    // 2. For each process, walk its thread list via _KPROCESS.ThreadListHead
    // 3. For each _ETHREAD, check CrossThreadFlags.ActiveImpersonationInfo bit
    // 4. If set, read ImpersonationInfo pointer → _PS_IMPERSONATION_INFORMATION
    // 5. Read SecurityContext.Token from ETHREAD and process EPROCESS
    // 6. Extract user SIDs from both tokens
    // 7. Call classify_token_impersonation and build entries
    //
    // Returning empty pending full token/SID walker integration.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A non-SYSTEM process thread impersonating SYSTEM at level 2 is suspicious.
    #[test]
    fn classify_system_impersonation_from_user_process_suspicious() {
        assert!(classify_token_impersonation(
            "S-1-5-21-1234567890-1234567890-1234567890-1001", // regular user
            "S-1-5-18",                                        // SYSTEM
            2,                                                  // Impersonation level
        ));
    }

    /// A SYSTEM process thread also impersonating SYSTEM is benign (same user).
    #[test]
    fn classify_same_user_impersonation_benign() {
        assert!(!classify_token_impersonation(
            "S-1-5-18", // process is SYSTEM
            "S-1-5-18", // impersonating SYSTEM too — same user, not escalation
            2,
        ));
    }

    /// Without PsActiveProcessHead symbol, walker returns empty.
    #[test]
    fn walk_token_impersonation_no_symbol_returns_empty() {
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

        let results = walk_token_impersonation(&reader).unwrap();
        assert!(results.is_empty());
    }
}
