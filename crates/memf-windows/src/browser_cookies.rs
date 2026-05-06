//! Browser session cookie forensics walker.
//!
//! Scans heap memory of Chromium-based browsers and Firefox for plaintext
//! cookie records that reside transiently in committed heap pages during
//! active browser sessions.
//!
//! Two scanning strategies are used:
//!
//! 1. **HTTP `Set-Cookie` header pattern** — browsers hold raw HTTP response
//!    headers in heap during network I/O.  Format:
//!    `Set-Cookie: <name>=<value>[; <attr>...]`
//!
//! 2. **Netscape cookie-jar format** — both Chromium and Firefox serialise
//!    cookie stores in the classic tab-delimited format used by libcurl and
//!    Netscape.  Format:
//!    `<domain>\t(TRUE|FALSE)\t<path>\t(TRUE|FALSE)\t<expiry>\t<name>\t<value>`
//!
//! # Supported processes
//!
//! Chromium family (see [`COOKIE_BROWSERS`]) plus `firefox.exe`.
//!
//! # Forensic guarantee
//!
//! Read-only scan of memory dump bytes — no live process interaction.

use std::collections::HashSet;

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use regex::Regex;

use crate::{
    process::walk_processes,
    types::BrowserCookieInfo,
    vad::walk_vad_tree,
    Result,
};

/// Browser process names whose heap is scanned for cookie records.
pub const COOKIE_BROWSERS: &[&str] = &[
    "msedge.exe",
    "chrome.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "chromium.exe",
    "firefox.exe",
];

/// Maximum bytes read from a single VAD region.
const MAX_REGION_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Scan raw bytes from one heap region for browser cookie records.
///
/// Returns `(domain, name, value, path)` tuples.
pub(crate) fn scan_cookie_region(data: &[u8]) -> Vec<(String, String, String, Option<String>)> {
    let text = String::from_utf8_lossy(data);
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    let mut out: Vec<(String, String, String, Option<String>)> = Vec::new();

    // Pattern 1: HTTP Set-Cookie header (case-insensitive)
    let set_cookie_re = match Regex::new(
        r"(?i)Set-Cookie:\s{0,4}([A-Za-z0-9_\-\.]{1,64})=([^\r\n;]{1,512})(?:;[^\r\n]*)?"
    ) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let path_re = match Regex::new(r"(?i);\s*Path=([^\r\n;]+)") {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let domain_attr_re = match Regex::new(r"(?i);\s*Domain=([^\r\n;]{1,128})") {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    for caps in set_cookie_re.captures_iter(&text) {
        let name = caps[1].to_string();
        let value = caps[2].trim_end().to_string();
        let full_match = caps[0].to_string();

        let domain = domain_attr_re
            .captures(&full_match)
            .map(|m| m[1].trim().to_string())
            .unwrap_or_default();

        let path = path_re
            .captures(&full_match)
            .map(|m| m[1].trim().to_string());

        let key = (domain.clone(), name.clone(), value.clone());
        if seen.insert(key) {
            out.push((domain, name, value, path));
        }
    }

    // Pattern 2: Netscape cookie-jar format
    let netscape_re = match Regex::new(
        r"(\.[A-Za-z0-9\-\.]{3,128})\t(TRUE|FALSE)\t(/[^\t\r\n]{0,256})\t(TRUE|FALSE)\t(\d{1,15})\t([^\t\r\n\x00]{1,128})\t([^\t\r\n\x00]{1,511})"
    ) {
        Ok(r) => r,
        Err(_) => return out,
    };

    for caps in netscape_re.captures_iter(&text) {
        let domain = caps[1].to_string();
        let path = Some(caps[3].to_string());
        let name = caps[6].to_string();
        let value = caps[7].to_string();

        let key = (domain.clone(), name.clone(), value.clone());
        if seen.insert(key) {
            out.push((domain, name, value, path));
        }
    }

    out
}

/// Walk heap regions of browser processes and extract session cookie records.
pub fn walk_browser_cookies<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<BrowserCookieInfo>> {
    let procs = walk_processes(reader, ps_head_vaddr)?;

    // Include all browser processes — Firefox and Chrome both materialise
    // cookies in multiple processes, so we do not restrict to root only.
    let browser_procs: Vec<_> = procs
        .iter()
        .filter(|p| {
            COOKIE_BROWSERS
                .iter()
                .any(|&b| p.image_name.eq_ignore_ascii_case(b))
        })
        .collect();

    let vad_root_offset = reader
        .symbols()
        .field_offset("_EPROCESS", "VadRoot")
        .ok_or_else(|| crate::Error::Walker("missing _EPROCESS.VadRoot offset".into()))?;

    let mut results = Vec::new();
    let mut seen: HashSet<(u64, String, String, String)> = HashSet::new();

    for proc in browser_procs {
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
            // Only scan private, writable (not execute) regions — heap pages.
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

            for (domain, name, value, path) in scan_cookie_region(&bytes) {
                let key = (proc.pid, domain.clone(), name.clone(), value.clone());
                if seen.insert(key) {
                    results.push(BrowserCookieInfo {
                        pid: proc.pid,
                        image_name: proc.image_name.clone(),
                        domain,
                        name,
                        value,
                        path,
                    });
                }
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_browsers_includes_firefox_and_chromium() {
        assert!(COOKIE_BROWSERS.contains(&"firefox.exe"));
        assert!(COOKIE_BROWSERS.contains(&"chrome.exe"));
        assert!(COOKIE_BROWSERS.contains(&"msedge.exe"));
        assert!(COOKIE_BROWSERS.contains(&"brave.exe"));
        assert!(COOKIE_BROWSERS.contains(&"opera.exe"));
        assert!(COOKIE_BROWSERS.contains(&"vivaldi.exe"));
        assert!(COOKIE_BROWSERS.contains(&"chromium.exe"));
    }

    #[test]
    fn scan_empty_returns_nothing() {
        assert!(scan_cookie_region(b"").is_empty());
    }

    #[test]
    fn scan_set_cookie_header_extracts_name_value() {
        let data = b"Set-Cookie: session_id=abc123xyz; Path=/; HttpOnly\r\n";
        let results = scan_cookie_region(data);
        assert_eq!(results.len(), 1, "expected 1 cookie match");
        let (_, name, value, _) = &results[0];
        assert_eq!(name, "session_id");
        assert_eq!(value, "abc123xyz");
    }

    #[test]
    fn scan_set_cookie_with_domain_attribute() {
        let data = b"Set-Cookie: auth=tok789; Domain=.example.com; Path=/api; Secure\r\n";
        let results = scan_cookie_region(data);
        assert_eq!(results.len(), 1, "expected 1 cookie match");
        let (domain, name, value, _) = &results[0];
        assert_eq!(domain, ".example.com");
        assert_eq!(name, "auth");
        assert_eq!(value, "tok789");
    }

    #[test]
    fn scan_netscape_format_extracts_cookie() {
        let data =
            b".github.com\tTRUE\t/\tFALSE\t9999999999\tuser_session\tsecretvalue999\n";
        let results = scan_cookie_region(data);
        assert_eq!(results.len(), 1, "expected 1 netscape cookie match");
        let (domain, name, value, path) = &results[0];
        assert_eq!(domain, ".github.com");
        assert_eq!(name, "user_session");
        assert_eq!(value, "secretvalue999");
        assert_eq!(path.as_deref(), Some("/"));
    }

    #[test]
    fn scan_multiple_cookies_returns_all() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"Set-Cookie: token_a=val1; Path=/\r\n");
        buf.extend_from_slice(b"Set-Cookie: token_b=val2; Path=/api\r\n");
        let results = scan_cookie_region(&buf);
        assert_eq!(results.len(), 2, "expected 2 cookie matches");
        let names: Vec<_> = results.iter().map(|(_, n, _, _)| n.as_str()).collect();
        assert!(names.contains(&"token_a"));
        assert!(names.contains(&"token_b"));
    }
}
