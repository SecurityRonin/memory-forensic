//! Firefox saved-password forensics walker.
//!
//! Firefox's password manager persists credentials in `logins.json` in the
//! user profile directory. When Firefox is running, the JSON file is read into
//! process heap memory. This walker scans `firefox.exe` process VADs for that
//! JSON content and extracts the NSS-encrypted credential blobs for forensic
//! analysis.
//!
//! # Encryption note
//!
//! The `encryptedUsername` and `encryptedPassword` fields are base64-encoded
//! NSS `SecItem` blobs. They are encrypted with the NSS key database key
//! (`key4.db`), derived from the master password (empty string by default).
//! Decryption is out of scope for this read-only walker; blobs are returned
//! as-is for offline analysis.
//!
//! # Attribution
//!
//! Firefox `logins.json` format: Mozilla Foundation, LoginStore
//! <https://searchfox.org/mozilla-central/source/toolkit/components/passwordmgr/LoginStore.sys.mjs>
//! (MPL-2.0; JSON field names are a public API, no code copied)
//!
//! # Forensic guarantee
//!
//! Read-only — no live process access, no Win32 API calls, no state modification.

use std::collections::HashSet;

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use regex::Regex;

use crate::{
    process::walk_processes,
    types::FirefoxCredentialInfo,
    vad::walk_vad_tree,
    Result,
};

/// Maximum bytes read from a single VAD region.
///
/// Caps memory consumption when a large anonymous mapping is encountered.
const MAX_REGION_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Walk committed, writeable VAD regions of all `firefox.exe` processes in the
/// dump and extract NSS-encrypted credential blobs from logins.json content.
///
/// # Arguments
///
/// * `reader` — kernel-space `ObjectReader` (uses kernel CR3 / symbol table).
/// * `ps_head_vaddr` — virtual address of `PsActiveProcessHead`.
pub fn walk_firefox_credentials<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<FirefoxCredentialInfo>> {
    let procs = walk_processes(reader, ps_head_vaddr)?;

    let firefox_procs: Vec<_> = procs
        .iter()
        .filter(|p| p.image_name.eq_ignore_ascii_case("firefox.exe"))
        .collect();

    if firefox_procs.is_empty() {
        return Ok(Vec::new());
    }

    let vad_root_offset = reader
        .symbols()
        .field_offset("_EPROCESS", "VadRoot")
        .ok_or_else(|| crate::Error::Walker("missing _EPROCESS.VadRoot offset".into()))?;

    let mut results = Vec::new();
    let mut seen: HashSet<(u64, String, String)> = HashSet::new(); // (pid, enc_user, enc_pass)

    for proc in firefox_procs {
        if proc.cr3 == 0 || proc.peb_addr == 0 {
            continue;
        }

        let vad_root_addr = proc.vaddr.wrapping_add(vad_root_offset);
        let vads = match walk_vad_tree(reader, vad_root_addr, proc.pid, &proc.image_name) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let proc_reader = reader.with_cr3(proc.cr3);

        for vad in &vads {
            // Only scan private, writable (not execute) regions — these are heap pages.
            if !vad.is_private || !vad.protection_str.contains("READWRITE") {
                continue;
            }
            if vad.protection_str.contains("EXECUTE") {
                continue;
            }

            let region_size = (vad.end_vaddr.saturating_sub(vad.start_vaddr) + 1)
                .min(MAX_REGION_BYTES as u64) as usize;

            if region_size == 0 {
                continue;
            }

            let bytes = match proc_reader.read_bytes(vad.start_vaddr, region_size) {
                Ok(b) => b,
                Err(_) => continue,
            };

            for (origin, ufield, pfield, enc_user, enc_pass) in scan_firefox_region(&bytes) {
                let key = (proc.pid, enc_user.clone(), enc_pass.clone());
                if seen.insert(key) {
                    results.push(FirefoxCredentialInfo {
                        pid: proc.pid,
                        origin,
                        username_field: ufield,
                        password_field: pfield,
                        encrypted_username: enc_user,
                        encrypted_password: enc_pass,
                    });
                }
            }
        }
    }

    Ok(results)
}

/// Scan raw bytes from a memory region for Firefox logins.json credential entries.
///
/// Returns `(origin, username_field, password_field, encrypted_username, encrypted_password)`
/// tuples for every credential entry found in the buffer.
///
/// Uses a two-pass approach:
/// 1. Find `encryptedUsername`/`encryptedPassword` pairs close together.
/// 2. For each pair, scan a surrounding window for `hostname`/`origin`,
///    `usernameField`, and `passwordField`.
pub(crate) fn scan_firefox_region(data: &[u8]) -> Vec<(String, String, String, String, String)> {
    let text = match std::str::from_utf8(data) {
        Ok(s) => s.to_owned(),
        Err(_) => String::from_utf8_lossy(data).into_owned(),
    };

    // Match encryptedUsername and encryptedPassword that appear close together.
    let cred_re = match Regex::new(
        r#""encryptedUsername"\s*:\s*"([A-Za-z0-9+/=]{10,})"[^}]{0,500}"encryptedPassword"\s*:\s*"([A-Za-z0-9+/=]{10,})""#,
    ) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let origin_re = match Regex::new(r#""(?:hostname|origin)"\s*:\s*"([^"]+)""#) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let ufield_re = match Regex::new(r#""usernameField"\s*:\s*"([^"]*)""#) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let pfield_re = match Regex::new(r#""passwordField"\s*:\s*"([^"]*)""#) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();

    for caps in cred_re.captures_iter(&text) {
        let enc_user = caps[1].to_string();
        let enc_pass = caps[2].to_string();

        // Determine the byte offset of this match in the text.
        let match_start = caps.get(0).map_or(0, |m| m.start());

        // For context fields (hostname, usernameField, passwordField), scan the
        // 1000-char window *before* the encryptedUsername match.  This avoids
        // picking up fields belonging to a later entry when entries are close.
        // We use the *last* match inside this backwards window so that we pick
        // the one closest (and therefore most likely belonging) to this entry.
        let back_start = match_start.saturating_sub(1000);
        let back_window = &text[back_start..match_start];

        let origin = origin_re
            .captures_iter(back_window)
            .last()
            .map(|m| m[1].to_string())
            .unwrap_or_default();

        let ufield = ufield_re
            .captures_iter(back_window)
            .last()
            .map(|m| m[1].to_string())
            .unwrap_or_default();

        let pfield = pfield_re
            .captures_iter(back_window)
            .last()
            .map(|m| m[1].to_string())
            .unwrap_or_default();

        out.push((origin, ufield, pfield, enc_user, enc_pass));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_firefox_region_empty_returns_nothing() {
        assert!(scan_firefox_region(b"").is_empty());
    }

    #[test]
    fn scan_firefox_region_no_pattern_returns_nothing() {
        assert!(scan_firefox_region(b"hello world random bytes no json").is_empty());
    }

    #[test]
    fn scan_firefox_region_extracts_credential_fields() {
        let json = br#"{"id":1,"hostname":"https://example.com","httpRealm":null,"formSubmitURL":"https://example.com","usernameField":"email","passwordField":"pwd","encryptedUsername":"MIIEJKlaSVjhA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789==","encryptedPassword":"MIIEJKlaSVjhB1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=="}"#;
        let results = scan_firefox_region(json);
        assert_eq!(results.len(), 1, "expected 1 credential");
        let (origin, ufield, pfield, enc_user, enc_pass) = &results[0];
        assert_eq!(origin, "https://example.com");
        assert_eq!(ufield, "email");
        assert_eq!(pfield, "pwd");
        assert!(enc_user.starts_with("MIIEJKlaSVjhA"));
        assert!(enc_pass.starts_with("MIIEJKlaSVjhB"));
    }

    #[test]
    fn scan_firefox_region_multiple_entries() {
        let json = format!(
            r#"{{"hostname":"https://site1.com","usernameField":"u","passwordField":"p","encryptedUsername":"AAAA1234567890abcdef==","encryptedPassword":"BBBB1234567890abcdef=="}}xxx{{"hostname":"https://site2.com","usernameField":"u2","passwordField":"p2","encryptedUsername":"CCCC1234567890abcdef==","encryptedPassword":"DDDD1234567890abcdef=="}}"#
        );
        let results = scan_firefox_region(json.as_bytes());
        assert_eq!(results.len(), 2);
        let origins: Vec<_> = results.iter().map(|(o, _, _, _, _)| o.as_str()).collect();
        assert!(origins.contains(&"https://site1.com"));
        assert!(origins.contains(&"https://site2.com"));
    }
}
