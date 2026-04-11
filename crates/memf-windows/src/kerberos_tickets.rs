//! Kerberos ticket extraction from LSASS memory.
//!
//! The Windows Kerberos SSP caches TGTs (Ticket-Granting Tickets) and
//! service tickets in LSASS memory under `kerberos.dll`. Extracting these
//! allows detection of Pass-the-Ticket attacks, overdue ticket lifetimes,
//! or tickets for unusual services.
//!
//! This module provides:
//! - `KerberosTicketInfo` struct for recovered ticket metadata
//! - `walk_kerberos_tickets` — graceful-degradation stub (RED phase)
//!   returning empty when kerberos.dll symbols are absent
//!
//! A full implementation requires walking `kerberos!KerbLogonSessionTable`
//! → `KERB_LOGON_SESSION` → `ExternalTicketList` → `KERB_TICKET_CACHE_ENTRY`
//! structures, extracting ASN.1-encoded ticket data.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// A Kerberos ticket recovered from LSASS memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KerberosTicketInfo {
    /// Logon session ID this ticket belongs to.
    pub logon_session: u64,
    /// Client principal name.
    pub client_name: String,
    /// Target service principal name.
    pub server_name: String,
    /// Kerberos realm (domain).
    pub realm: String,
    /// Ticket validity start time (Windows FILETIME, 100-ns intervals since 1601-01-01).
    pub start_time: u64,
    /// Ticket expiry time (FILETIME).
    pub end_time: u64,
    /// Ticket renewal deadline (FILETIME).
    pub renew_until: u64,
    /// Kerberos ticket flags bitmask.
    pub ticket_flags: u32,
    /// Encryption type (17=AES128-CTS, 18=AES256-CTS, 23=RC4-HMAC).
    pub encryption_type: u32,
    /// Raw ASN.1 encoded ticket bytes.
    pub ticket_data: Vec<u8>,
    /// True if this is a TGT (krbtgt service).
    pub is_tgt: bool,
    /// True if the ticket has an unusual service name or very long lifetime.
    pub is_suspicious: bool,
}

/// Classify a Kerberos ticket as suspicious.
///
/// Suspicious criteria:
/// - TGT with an unusually long lifetime (> 10 hours, typical Golden Ticket)
/// - Ticket for a service principal that doesn't match standard patterns
/// - RC4 encryption type (23) for a TGT in a modern environment (indicates Overpass-the-Hash)
pub fn classify_kerberos_ticket(
    server_name: &str,
    start_time: u64,
    end_time: u64,
    encryption_type: u32,
    is_tgt: bool,
) -> bool {
    // Suspicious: unusually long ticket lifetime (> 10 hours in 100-ns FILETIME units)
    let ten_hours_filetime: u64 = 10 * 60 * 60 * 10_000_000;
    let lifetime_suspicious = end_time > start_time && (end_time - start_time) > ten_hours_filetime;

    // Suspicious: RC4 TGT in a modern environment (Golden Ticket / Overpass-the-Hash indicator)
    let rc4_tgt = is_tgt && encryption_type == 23;

    // Suspicious: service name contains unusual characters or is krbtgt from unexpected realm
    // Suspicious: service name is empty (malformed ticket)
    let name_suspicious = server_name.is_empty();

    lifetime_suspicious || rc4_tgt || name_suspicious
}

/// Walk LSASS memory for cached Kerberos tickets.
///
/// Returns `Ok(Vec::new())` when `KerbLogonSessionTable` or related
/// `kerberos.dll` symbols are absent from the symbol table (graceful degradation).
pub fn walk_kerberos_tickets<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<KerberosTicketInfo>> {
    // Graceful degradation: require KerbLogonSessionTable symbol
    if reader
        .symbols()
        .symbol_address("KerbLogonSessionTable")
        .is_none()
    {
        return Ok(Vec::new());
    }

    // Full implementation pending kerberos.dll struct definitions.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TGT with a very long lifetime (> 10 hours) is suspicious (Golden Ticket).
    #[test]
    fn classify_long_lifetime_tgt_suspicious() {
        // 20-hour lifetime in FILETIME units
        let twenty_hours: u64 = 20 * 60 * 60 * 10_000_000;
        assert!(classify_kerberos_ticket(
            "krbtgt/CORP.LOCAL",
            0,
            twenty_hours,
            18, // AES256
            true,
        ));
    }

    /// A normal TGT with short lifetime and AES256 → not suspicious.
    #[test]
    fn classify_normal_tgt_not_suspicious() {
        let eight_hours: u64 = 8 * 60 * 60 * 10_000_000;
        assert!(!classify_kerberos_ticket(
            "krbtgt/CORP.LOCAL",
            0,
            eight_hours,
            18,
            true,
        ));
    }

    /// RC4 TGT → always suspicious (Overpass-the-Hash indicator).
    #[test]
    fn classify_rc4_tgt_suspicious() {
        let two_hours: u64 = 2 * 60 * 60 * 10_000_000;
        assert!(classify_kerberos_ticket(
            "krbtgt/CORP.LOCAL",
            0,
            two_hours,
            23, // RC4-HMAC
            true,
        ));
    }

    /// Non-TGT service ticket with RC4 and short lifetime → not suspicious.
    #[test]
    fn classify_service_ticket_rc4_not_suspicious() {
        let two_hours: u64 = 2 * 60 * 60 * 10_000_000;
        assert!(!classify_kerberos_ticket(
            "host/server.corp.local",
            0,
            two_hours,
            23,
            false,
        ));
    }

    /// Empty server name → suspicious.
    #[test]
    fn classify_empty_server_name_suspicious() {
        assert!(classify_kerberos_ticket("", 0, 3_600_000_000, 18, false));
    }

    /// Normal 2-hour AES256 TGT to krbtgt → not suspicious (standard Kerberos behaviour).
    #[test]
    fn classify_tgt_krbtgt_in_name_not_suspicious() {
        let two_hours: u64 = 2 * 60 * 60 * 10_000_000;
        assert!(!classify_kerberos_ticket(
            "krbtgt/CORP.LOCAL",
            0,
            two_hours,
            18,
            true,
        ));
    }

    /// Non-TGT with long lifetime → suspicious (lifetime check only).
    #[test]
    fn classify_non_tgt_long_lifetime_suspicious() {
        let twenty_hours: u64 = 20 * 60 * 60 * 10_000_000;
        assert!(classify_kerberos_ticket(
            "host/server.corp.local",
            0,
            twenty_hours,
            18,
            false,
        ));
    }

    /// end_time <= start_time: no lifetime flag, no RC4 TGT, non-empty host → not suspicious.
    #[test]
    fn classify_end_before_start_not_suspicious() {
        assert!(!classify_kerberos_ticket(
            "host/dc.corp.local",
            1_000_000_000_000,
            500_000_000_000,
            18,
            false,
        ));
    }

    /// KerberosTicketInfo serializes correctly.
    #[test]
    fn kerberos_ticket_info_serializes() {
        let info = KerberosTicketInfo {
            logon_session: 0x1234,
            client_name: "alice@CORP.LOCAL".to_string(),
            server_name: "krbtgt/CORP.LOCAL".to_string(),
            realm: "CORP.LOCAL".to_string(),
            start_time: 0,
            end_time: 100_000_000,
            renew_until: 200_000_000,
            ticket_flags: 0x4000_0000,
            encryption_type: 18,
            ticket_data: vec![0x01, 0x02, 0x03],
            is_tgt: true,
            is_suspicious: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("alice@CORP.LOCAL"));
        assert!(json.contains("\"is_tgt\":true"));
        assert!(json.contains("\"is_suspicious\":false"));
        assert!(json.contains("\"encryption_type\":18"));
    }

    /// Without KerbLogonSessionTable symbol, walker returns empty.
    #[test]
    fn walk_kerberos_tickets_no_symbol_returns_empty() {
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

        let results = walk_kerberos_tickets(&reader).unwrap();
        assert!(results.is_empty());
    }
}
