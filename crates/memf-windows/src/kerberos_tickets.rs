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
        todo!()
    }

/// Walk LSASS memory for cached Kerberos tickets.
///
/// Returns `Ok(Vec::new())` when `KerbLogonSessionTable` or related
/// `kerberos.dll` symbols are absent from the symbol table (graceful degradation).
pub fn walk_kerberos_tickets<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<KerberosTicketInfo>> {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;

    /// A TGT with a very long lifetime (> 10 hours) is suspicious (Golden Ticket).
    #[test]
    fn classify_long_lifetime_tgt_suspicious() {
        todo!()
    }

    /// A normal TGT with short lifetime and AES256 → not suspicious.
    #[test]
    fn classify_normal_tgt_not_suspicious() {
        todo!()
    }

    /// RC4 TGT → always suspicious (Overpass-the-Hash indicator).
    #[test]
    fn classify_rc4_tgt_suspicious() {
        todo!()
    }

    /// Non-TGT service ticket with RC4 and short lifetime → not suspicious.
    #[test]
    fn classify_service_ticket_rc4_not_suspicious() {
        todo!()
    }

    /// Empty server name → suspicious.
    #[test]
    fn classify_empty_server_name_suspicious() {
        todo!()
    }

    /// Normal 2-hour AES256 TGT to krbtgt → not suspicious (standard Kerberos behaviour).
    #[test]
    fn classify_tgt_krbtgt_in_name_not_suspicious() {
        todo!()
    }

    /// Non-TGT with long lifetime → suspicious (lifetime check only).
    #[test]
    fn classify_non_tgt_long_lifetime_suspicious() {
        todo!()
    }

    /// end_time <= start_time: no lifetime flag, no RC4 TGT, non-empty host → not suspicious.
    #[test]
    fn classify_end_before_start_not_suspicious() {
        todo!()
    }

    /// KerberosTicketInfo serializes correctly.
    #[test]
    fn kerberos_ticket_info_serializes() {
        todo!()
    }

    /// Without KerbLogonSessionTable symbol, walker returns empty.
    #[test]
    fn walk_kerberos_tickets_no_symbol_returns_empty() {
        todo!()
    }
}
