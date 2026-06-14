//! WDigest SSP credential extraction from LSASS memory.
//!
//! The WDigest Security Support Provider maintains a doubly-linked list of
//! logon session entries (`l_LogSessList`) in LSASS process memory. On
//! Windows 7, 8, and Server 2008R2/2012, and on any Windows version where
//! `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential`
//! is set to 1, the password field of each entry is stored as cleartext UTF-16LE.
//!
//! On Windows 8.1 and later (default configuration), Microsoft added symmetric
//! encryption of the WDigest password field using a per-boot 3DES key stored in
//! lsass. This walker returns the raw encrypted bytes in that case; decryption
//! requires the LSASS session key (not yet implemented — out of scope for a
//! read-only dump walker).
//!
//! # Attribution
//!
//! Structure offsets and list-walk algorithm adapted from:
//!   Benjamin Delpy & Vincent Le Toux, Mimikatz `sekurlsa::wdigest` (MIT License)
//!   <https://github.com/gentilkiwi/mimikatz>
//!   Independently re-implemented in Rust for read-only forensic dump analysis.
//!
//! # Forensic guarantee
//!
//! This walker is read-only — it reads from a memory dump and modifies no state.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, WdigestCredentialInfo};

/// Maximum list entries to visit before aborting (cycle protection).
const MAX_ITERATIONS: usize = 10_000;

/// Walk the WDigest `l_LogSessList` doubly-linked list in LSASS memory.
///
/// # Arguments
/// * `reader` — object reader backed by the full physical dump
/// * `lsass_cr3` — CR3 value of the LSASS process (page table root)
/// * `l_log_sess_list_vaddr` — virtual address of `l_LogSessList` in wdigest.dll VA space
pub fn walk_wdigest<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
    lsass_cr3: u64,
    l_log_sess_list_vaddr: u64,
) -> Result<Vec<WdigestCredentialInfo>> {
    // Switch to LSASS process address space
    let proc_reader = reader.with_cr3(lsass_cr3);
    let vas = proc_reader.vas();

    // Read head Flink → first entry
    let mut ptr_buf = [0u8; 8];
    vas.read_virt(l_log_sess_list_vaddr, &mut ptr_buf)
        .map_err(crate::Error::Core)?;
    let mut current = u64::from_le_bytes(ptr_buf);

    let mut results = Vec::new();
    let mut iterations = 0usize;

    while current != l_log_sess_list_vaddr {
        if iterations >= MAX_ITERATIONS {
            break;
        }
        iterations += 1;

        // Read username at current+0x30
        let username_bytes = read_unicode_string_raw(vas, current + 0x30).unwrap_or_default();
        // Read domain at current+0x40
        let domain_bytes = read_unicode_string_raw(vas, current + 0x40).unwrap_or_default();
        // Read password (raw) at current+0x58
        let password_bytes = read_unicode_string_raw(vas, current + 0x58).unwrap_or_default();

        // Skip entries with empty username
        if !username_bytes.is_empty() {
            let username = decode_utf16le_or_none(&username_bytes).unwrap_or_default();
            let domain = decode_utf16le_or_none(&domain_bytes).unwrap_or_default();

            let (password, password_encrypted) = if password_bytes.is_empty() {
                (None, None)
            } else if let Some(plain) = decode_utf16le_or_none(&password_bytes) {
                (Some(plain), None)
            } else {
                (None, Some(password_bytes))
            };

            if !username.is_empty() {
                results.push(WdigestCredentialInfo {
                    username,
                    domain,
                    password,
                    password_encrypted,
                });
            }
        }

        // Advance: read Flink at current+0x00
        vas.read_virt(current, &mut ptr_buf)
            .map_err(crate::Error::Core)?;
        current = u64::from_le_bytes(ptr_buf);
    }

    Ok(results)
}

// ── helpers (used by the real implementation in GREEN) ───────────────────────

/// Read a `_UNICODE_STRING` at `us_vaddr` and return the raw byte buffer.
///
/// Layout (x64):
///   +0x00  Length        u16   byte count of string data
///   +0x02  MaximumLength u16
///   +0x04  _padding      u32
///   +0x08  Buffer        u64   pointer to UTF-16LE data
fn read_unicode_string_raw<P: PhysicalMemoryProvider>(
    vas: &memf_core::vas::VirtualAddressSpace<P>,
    us_vaddr: u64,
) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    vas.read_virt(us_vaddr, &mut len_buf)
        .map_err(crate::Error::Core)?;
    let len = u16::from_le_bytes(len_buf) as usize;

    if len == 0 {
        return Ok(Vec::new());
    }

    let mut ptr_buf = [0u8; 8];
    vas.read_virt(us_vaddr + 8, &mut ptr_buf)
        .map_err(crate::Error::Core)?;
    let buf_ptr = u64::from_le_bytes(ptr_buf);

    if buf_ptr == 0 {
        return Ok(Vec::new());
    }

    let mut data = vec![0u8; len];
    vas.read_virt(buf_ptr, &mut data)
        .map_err(crate::Error::Core)?;
    Ok(data)
}

/// Decode raw bytes as UTF-16LE if every code unit is a valid Unicode scalar.
/// Returns `Some(String)` for plaintext, `None` for encrypted/binary data.
fn decode_utf16le_or_none(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 || bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    // Reject surrogate pairs or lone surrogates (0xD800–0xDFFF)
    if units.iter().any(|&u| (0xD800..=0xDFFF).contains(&u)) {
        return None;
    }
    String::from_utf16(&units).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: encode a &str as UTF-16LE bytes
    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    // Helper: build a UNICODE_STRING at `addr` pointing to `str_addr`, string = `s`
    // Returns (unicode_string_bytes_16, string_bytes)
    fn make_unicode_string(str_addr: u64, s: &str) -> (Vec<u8>, Vec<u8>) {
        let str_bytes = utf16le(s);
        let len = str_bytes.len() as u16;
        let mut us = vec![0u8; 16];
        us[0..2].copy_from_slice(&len.to_le_bytes()); // Length
        us[2..4].copy_from_slice(&len.to_le_bytes()); // MaximumLength
        us[8..16].copy_from_slice(&str_addr.to_le_bytes()); // Buffer pointer
        (us, str_bytes)
    }

    #[test]
    fn walk_wdigest_empty_list_returns_nothing() {
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let list_head_addr: u64 = 0x1000;
        let cr3: u64 = PageTableBuilder::CR3;

        // Build page tables + memory with just the list head pointing to itself
        let mut head_page = vec![0u8; 0x1000];
        head_page[0..8].copy_from_slice(&list_head_addr.to_le_bytes()); // Flink = self
        head_page[8..16].copy_from_slice(&list_head_addr.to_le_bytes()); // Blink = self

        let head_paddr: u64 = 0x0010_0000;

        let (built_cr3, mem) = PageTableBuilder::new()
            .map_4k(list_head_addr, head_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_page)
            .build();

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).expect("valid ISF");
        let vas = VirtualAddressSpace::new(mem, built_cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_wdigest(&reader, cr3, list_head_addr).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn walk_wdigest_one_plaintext_entry() {
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let list_head_addr: u64 = 0x1000;
        let entry_addr: u64 = 0x2000;
        let username_str: u64 = 0x3000;
        let domain_str: u64 = 0x3100;
        let password_str: u64 = 0x3200;

        let (us_username, username_bytes) = make_unicode_string(username_str, "alice");
        let (us_domain, domain_bytes) = make_unicode_string(domain_str, "CORP");
        let (us_password, password_bytes) = make_unicode_string(password_str, "S3cr3t!");

        // Page 0x1000: list head
        let mut head_page = vec![0u8; 0x1000];
        head_page[0..8].copy_from_slice(&entry_addr.to_le_bytes()); // Flink → entry
        head_page[8..16].copy_from_slice(&entry_addr.to_le_bytes()); // Blink → entry

        // Page 0x2000: the entry
        let mut entry_page = vec![0u8; 0x1000];
        entry_page[0..8].copy_from_slice(&list_head_addr.to_le_bytes()); // Flink → head (end)
        entry_page[8..16].copy_from_slice(&list_head_addr.to_le_bytes()); // Blink → head
        entry_page[0x30..0x40].copy_from_slice(&us_username);
        entry_page[0x40..0x50].copy_from_slice(&us_domain);
        entry_page[0x58..0x68].copy_from_slice(&us_password);

        // Page 0x3000: string data
        let mut str_page = vec![0u8; 0x1000];
        str_page[0x000..username_bytes.len()].copy_from_slice(&username_bytes);
        str_page[0x100..0x100 + domain_bytes.len()].copy_from_slice(&domain_bytes);
        str_page[0x200..0x200 + password_bytes.len()].copy_from_slice(&password_bytes);

        let head_paddr: u64 = 0x0010_0000;
        let entry_paddr: u64 = 0x0020_0000;
        let str_paddr: u64 = 0x0030_0000;

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(0x1000, head_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_page)
            .map_4k(0x2000, entry_paddr, flags::WRITABLE)
            .write_phys(entry_paddr, &entry_page)
            .map_4k(0x3000, str_paddr, flags::WRITABLE)
            .write_phys(str_paddr, &str_page)
            .build();

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).expect("valid ISF");
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_wdigest(&reader, cr3, list_head_addr).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].username, "alice");
        assert_eq!(results[0].domain, "CORP");
        assert_eq!(results[0].password.as_deref(), Some("S3cr3t!"));
        assert!(results[0].password_encrypted.is_none());
    }
}
