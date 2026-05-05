//! Windows Credential Manager credential extraction from LSASS memory.
//!
//! The Windows Credential Manager stores encrypted credential blobs in the
//! user profile (`%APPDATA%\Microsoft\Credentials\`). When a user is logged
//! in, the Credential Manager SSP in LSASS decrypts and caches these entries
//! in a `_KIWI_CREDMAN_LIST_ENTRY` linked list in LSASS process memory.
//!
//! This walker reads those in-memory (already-decrypted) entries directly from
//! the LSASS dump, recovering the plaintext credentials that were loaded for
//! the active logon session.
//!
//! # Attribution
//!
//! Structure layout reverse-engineered and documented by:
//!   Benjamin Delpy & Vincent Le Toux, Mimikatz `sekurlsa::credman` (MIT License)
//!   <https://github.com/gentilkiwi/mimikatz>
//!   Offsets independently re-implemented in Rust for read-only forensic analysis.
//!
//! # Forensic guarantee
//!
//! Read-only — no live process access, no Win32 API calls, no state modification.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{CredManEntry, Result};

/// Maximum list entries to visit before aborting (cycle protection).
const MAX_ITERATIONS: usize = 10_000;

/// Walk the Credential Manager `_KIWI_CREDMAN_LIST_ENTRY` doubly-linked list
/// in LSASS memory.
///
/// # Arguments
/// * `reader` — object reader backed by the full physical dump
/// * `lsass_cr3` — CR3 value of the LSASS process (page table root)
/// * `credman_list_head_vaddr` — virtual address of the list head in LSASS VA space
pub fn walk_credman<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
    lsass_cr3: u64,
    credman_list_head_vaddr: u64,
) -> Result<Vec<CredManEntry>> {
    let proc_reader = reader.with_cr3(lsass_cr3);
    let vas = proc_reader.vas();

    let mut ptr_buf = [0u8; 8];
    vas.read_virt(credman_list_head_vaddr, &mut ptr_buf)
        .map_err(crate::Error::Core)?;
    let mut current = u64::from_le_bytes(ptr_buf);

    let mut results = Vec::new();
    let mut iterations = 0usize;

    while current != credman_list_head_vaddr {
        if iterations >= MAX_ITERATIONS {
            break;
        }
        iterations += 1;

        // Username at current+0x60
        let username_bytes =
            read_unicode_string_raw(vas, current + 0x60).unwrap_or_default();
        // Password at current+0x80
        let password_bytes =
            read_unicode_string_raw(vas, current + 0x80).unwrap_or_default();
        // Target/Server at current+0xA0
        let target_bytes =
            read_unicode_string_raw(vas, current + 0xA0).unwrap_or_default();

        if !username_bytes.is_empty() {
            if let Some(username) = decode_utf16le_or_none(&username_bytes) {
                if !username.is_empty() {
                    let target = decode_utf16le_or_none(&target_bytes)
                        .unwrap_or_default();

                    let (password, credential_blob) = if password_bytes.is_empty() {
                        (None, None)
                    } else if let Some(plain) = decode_utf16le_or_none(&password_bytes) {
                        (Some(plain), None)
                    } else {
                        (None, Some(password_bytes))
                    };

                    results.push(CredManEntry {
                        target,
                        username,
                        password,
                        credential_blob,
                    });
                }
            }
        }

        // Advance: read Flink at current+0x00
        vas.read_virt(current, &mut ptr_buf)
            .map_err(crate::Error::Core)?;
        current = u64::from_le_bytes(ptr_buf);
    }

    Ok(results)
}

// ── helpers ──────────────────────────────────────────────────────────────────

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
    if units.iter().any(|&u| (0xD800..=0xDFFF).contains(&u)) {
        return None;
    }
    String::from_utf16(&units).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
    }

    fn make_unicode_string(str_addr: u64, s: &str) -> (Vec<u8>, Vec<u8>) {
        let str_bytes = utf16le(s);
        let len = str_bytes.len() as u16;
        let mut us = vec![0u8; 16];
        us[0..2].copy_from_slice(&len.to_le_bytes());
        us[2..4].copy_from_slice(&len.to_le_bytes());
        us[8..16].copy_from_slice(&str_addr.to_le_bytes());
        (us, str_bytes)
    }

    #[test]
    fn walk_credman_empty_list_returns_nothing() {
        let list_head: u64 = 0x1000;

        let mut head_page = vec![0u8; 0x1000];
        // Self-referencing list head (Flink = Blink = self)
        head_page[0..8].copy_from_slice(&list_head.to_le_bytes());
        head_page[8..16].copy_from_slice(&list_head.to_le_bytes());

        let head_paddr: u64 = 0x0010_0000;

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(list_head, head_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_page)
            .build();

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).expect("valid ISF");
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_credman(&reader, cr3, list_head).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn walk_credman_one_entry() {
        let list_head: u64 = 0x1000;
        let entry_addr: u64 = 0x2000;
        let username_str: u64 = 0x3000;
        let password_str: u64 = 0x3100;
        let target_str: u64 = 0x3200;

        let (us_username, username_bytes) = make_unicode_string(username_str, "jdoe");
        let (us_password, password_bytes) = make_unicode_string(password_str, "Vault!Pass1");
        let (us_target, target_bytes) = make_unicode_string(target_str, "https://intranet.corp");

        // Page 0x1000: list head — Flink → entry
        let mut head_page = vec![0u8; 0x1000];
        head_page[0..8].copy_from_slice(&entry_addr.to_le_bytes());
        head_page[8..16].copy_from_slice(&entry_addr.to_le_bytes());

        // Page 0x2000: the _KIWI_CREDMAN_LIST_ENTRY
        let mut entry_page = vec![0u8; 0x1000];
        // Flink at +0x00 → back to list_head (terminates walk)
        entry_page[0x00..0x08].copy_from_slice(&list_head.to_le_bytes());
        entry_page[0x08..0x10].copy_from_slice(&list_head.to_le_bytes());
        // Username UNICODE_STRING at +0x60
        entry_page[0x60..0x70].copy_from_slice(&us_username);
        // Password UNICODE_STRING at +0x80
        entry_page[0x80..0x90].copy_from_slice(&us_password);
        // Target UNICODE_STRING at +0xA0
        entry_page[0xA0..0xB0].copy_from_slice(&us_target);

        // Page 0x3000: string data
        let mut str_page = vec![0u8; 0x1000];
        str_page[0x000..0x000 + username_bytes.len()].copy_from_slice(&username_bytes);
        str_page[0x100..0x100 + password_bytes.len()].copy_from_slice(&password_bytes);
        str_page[0x200..0x200 + target_bytes.len()].copy_from_slice(&target_bytes);

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

        let result = walk_credman(&reader, cr3, list_head).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].username, "jdoe");
        assert_eq!(result[0].password.as_deref(), Some("Vault!Pass1"));
        assert_eq!(result[0].target, "https://intranet.corp");
        assert!(result[0].credential_blob.is_none());
    }
}
