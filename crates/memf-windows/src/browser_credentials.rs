//! Browser credential forensics walker.
//!
//! Scans Chromium-based browser root process heap regions for plaintext
//! credential records that the browser's password manager writes to committed,
//! writeable heap pages.
//!
//! Supported browsers (all Chromium-based, share the same credential layout):
//! `msedge.exe`, `chrome.exe`, `brave.exe`, `opera.exe`, `vivaldi.exe`,
//! `chromium.exe`.
//!
//! # Memory layout
//!
//! The browser's credential manager transiently materialises saved passwords in
//! the form:
//!
//! ```text
//! <alpha-prefix>https?<SP><username><SP><password><SP><NUL>
//! ```
//!
//! Each credential record is typically preceded (in the same region) by a URL
//! record of the form:
//!
//! ```text
//! <NUL><NUL><NUL><url-chars>https?<SP><username><SP><password>
//! ```
//!
//! # Attribution
//!
//! Technique originally documented and demonstrated (C#) by:
//!   L1v1ng0ffTh3L4N, "EdgeSavedPasswordsDumper" (2024)
//!   <https://github.com/L1v1ng0ffTh3L4N/EdgeSavedPasswordsDumper>
//!   (MIT License; regex patterns independently re-implemented in Rust for
//!   read-only forensic analysis of memory dumps)
//!
//! # Forensic guarantee
//!
//! This walker only reads bytes from a memory dump — it opens no live process,
//! calls no Win32 API, and modifies no state.

use std::collections::HashSet;

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use regex::Regex;

use crate::{
    process::walk_processes,
    types::BrowserCredentialInfo,
    vad::walk_vad_tree,
    Result,
};

/// Chromium-based browser process names whose credential layout is supported.
///
/// All entries share the same Chromium password manager codebase and therefore
/// the same in-memory credential record format. Root-process detection is
/// performed per entry so child processes of one browser are not confused with
/// those of another.
pub const CHROMIUM_BROWSERS: &[&str] = &[
    "msedge.exe",
    "chrome.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "chromium.exe",
];

/// Maximum bytes read from a single VAD region.
///
/// Caps memory consumption when a large anonymous mapping is encountered.
const MAX_REGION_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Walk committed, writeable heap regions of the root Chromium-based browser
/// process(es) in the dump and extract any plaintext credential records.
///
/// # Root process selection
///
/// Chromium spawns many child processes under the same executable name.
/// Saved passwords reside only in the **root** (browser) process — the one
/// whose parent PID does not belong to another process of the same image name.
/// Root detection is performed independently for each browser in
/// [`CHROMIUM_BROWSERS`], so multiple browsers can coexist in the same dump.
///
/// # Arguments
///
/// * `reader` — kernel-space `ObjectReader` (uses kernel CR3 / symbol table).
/// * `ps_head_vaddr` — virtual address of `PsActiveProcessHead`.
pub fn walk_browser_credentials<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<BrowserCredentialInfo>> {
    let procs = walk_processes(reader, ps_head_vaddr)?;

    // For each supported browser, find the root process(es) independently.
    let mut root_procs = Vec::new();
    for &browser in CHROMIUM_BROWSERS {
        let browser_pids: HashSet<u64> = procs
            .iter()
            .filter(|p| p.image_name.eq_ignore_ascii_case(browser))
            .map(|p| p.pid)
            .collect();

        for p in procs.iter().filter(|p| {
            p.image_name.eq_ignore_ascii_case(browser) && !browser_pids.contains(&p.ppid)
        }) {
            root_procs.push(p);
        }
    }

    let vad_root_offset = reader
        .symbols()
        .field_offset("_EPROCESS", "VadRoot")
        .ok_or_else(|| crate::Error::Walker("missing _EPROCESS.VadRoot offset".into()))?;

    let mut results = Vec::new();
    let mut seen: HashSet<(u64, String, String)> = HashSet::new(); // (pid, username, password)

    for proc in root_procs {
        if proc.cr3 == 0 || proc.peb_addr == 0 {
            continue;
        }

        // Walk VAD tree using the kernel reader.
        let vad_root_addr = proc.vaddr.wrapping_add(vad_root_offset);
        let vads = match walk_vad_tree(reader, vad_root_addr, proc.pid, &proc.image_name) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Create a reader that uses this process's page table for VA translation.
        let proc_reader = reader.with_cr3(proc.cr3);

        for vad in &vads {
            // Only scan private, writable (not execute) regions — these are heap pages.
            if !vad.is_private || !vad.protection_str.contains("READWRITE") {
                continue;
            }
            // Skip if protection includes EXECUTE (e.g., PAGE_EXECUTE_READWRITE).
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
                Err(_) => continue, // region may be paged out in the dump
            };

            for (url, username, password) in scan_region(&bytes) {
                let key = (proc.pid, username.clone(), password.clone());
                if seen.insert(key) {
                    results.push(BrowserCredentialInfo {
                        pid: proc.pid,
                        image_name: proc.image_name.clone(),
                        url,
                        username,
                        password,
                    });
                }
            }
        }
    }

    Ok(results)
}

/// Scan raw bytes from a memory region for Edge credential records.
///
/// Returns `(url, username, password)` tuples. `url` is empty when the URL
/// pattern did not match in the same buffer.
///
/// # Pattern source
///
/// Adapted from the regex in:
///   L1v1ng0ffTh3L4N, "EdgeSavedPasswordsDumper"
///   <https://github.com/L1v1ng0ffTh3L4N/EdgeSavedPasswordsDumper>
pub(crate) fn scan_region(data: &[u8]) -> Vec<(String, String, String)> {
    // Convert to UTF-8 with lossy replacement; NUL bytes are preserved as-is.
    let text = String::from_utf8_lossy(data);

    // Credential record pattern:
    //   <alpha>https?<SP><username>{3,20}<SP><password>{6,40}<SP><NUL>
    let cred_re = match Regex::new(
        r"(?-u)[a-zA-Z]https?[ ]([a-zA-Z0-9\-_\.@?]{3,20})[ ]([a-zA-Z0-9!#$%^&*()\-+=\[\]{};:<>?/~\t ]{6,40})[ ]\x00",
    ) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();

    for caps in cred_re.captures_iter(&text) {
        let username = caps[1].to_string();
        let password = caps[2].trim_end().to_string();

        // URL record pattern:
        //   <NUL><NUL><NUL><url_chars>https?<SP><username><SP><password>
        let url_pat = format!(
            r"(?-u)\x00\x00\x00([A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)https?[ ]{}[ ]{}",
            regex::escape(&username),
            regex::escape(&password),
        );

        let url = Regex::new(&url_pat)
            .ok()
            .and_then(|re| re.captures(&text))
            .map(|m| m[1].to_string())
            .unwrap_or_default();

        out.push((url, username, password));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chromium_browsers_includes_all_supported() {
        assert!(CHROMIUM_BROWSERS.contains(&"msedge.exe"));
        assert!(CHROMIUM_BROWSERS.contains(&"chrome.exe"));
        assert!(CHROMIUM_BROWSERS.contains(&"brave.exe"));
        assert!(CHROMIUM_BROWSERS.contains(&"opera.exe"));
        assert!(CHROMIUM_BROWSERS.contains(&"vivaldi.exe"));
        assert!(CHROMIUM_BROWSERS.contains(&"chromium.exe"));
    }

    #[test]
    fn scan_region_empty_returns_nothing() {
        assert!(scan_region(b"").is_empty());
    }

    #[test]
    fn scan_region_no_pattern_returns_nothing() {
        assert!(scan_region(b"hello world this is random text with no credentials").is_empty());
    }

    #[test]
    fn scan_region_extracts_username_and_password() {
        // Minimal credential record: B + https + SP + username + SP + password + SP + NUL
        let mut buf = Vec::new();
        buf.extend_from_slice(b"Bhttps admin Secret123! \x00");
        let results = scan_region(&buf);
        assert_eq!(results.len(), 1, "expected 1 credential match");
        let (url, username, password) = &results[0];
        assert_eq!(username, "admin");
        assert_eq!(password, "Secret123!");
        assert_eq!(url, "", "no URL pattern in buffer");
    }

    #[test]
    fn scan_region_extracts_url_when_present() {
        // URL record immediately before credential record:
        //   NUL NUL NUL <url_chars> https SP <username> SP <password>
        //   <alpha> https SP <username> SP <password> SP NUL
        let mut buf = Vec::new();
        buf.extend_from_slice(b"\x00\x00\x00example.com/https admin MyPass1! ");
        buf.extend_from_slice(b"Bhttps admin MyPass1! \x00");
        let results = scan_region(&buf);
        assert_eq!(results.len(), 1);
        let (url, username, password) = &results[0];
        assert_eq!(username, "admin");
        assert_eq!(password, "MyPass1!");
        assert_eq!(url, "example.com/");
    }

    #[test]
    fn scan_region_multiple_credentials() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"Bhttps alice Passw0rd! \x00");
        buf.extend_from_slice(b"Bhttps bob Hunter2!! \x00");
        let results = scan_region(&buf);
        assert_eq!(results.len(), 2);
        let usernames: Vec<_> = results.iter().map(|(_, u, _)| u.as_str()).collect();
        assert!(usernames.contains(&"alice"));
        assert!(usernames.contains(&"bob"));
    }
}
