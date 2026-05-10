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
    types::BrowserCookieInfo,
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

/// Scan raw bytes from one heap region for browser cookie records.
///
/// Returns `(domain, name, value, path, encrypted)` tuples. The `encrypted`
/// flag is `true` for Chrome v10/v20 AES-GCM blobs whose value is not yet
/// decrypted (key material unavailable at scan time).
pub(crate) fn scan_cookie_region(data: &[u8]) -> Vec<(String, String, String, Option<String>, bool)> {
    let text = String::from_utf8_lossy(data);
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    let mut out: Vec<(String, String, String, Option<String>, bool)> = Vec::new();

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
            out.push((domain, name, value, path, false));
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
            out.push((domain, name, value, path, false));
        }
    }

    // Pattern 3: Chrome v10/v20 AES-GCM encrypted cookie blobs (binary scan).
    // Wire format: prefix(3) + nonce(12) + ciphertext — minimum 16 bytes.
    let mut i = 0;
    while i + 15 < data.len() {
        let prefix = &data[i..i + 3];
        if prefix == b"v10" || prefix == b"v20" {
            let tag = if prefix == b"v10" { "(v10-encrypted)" } else { "(v20-encrypted)" };
            let key = (String::new(), "(encrypted)".to_string(), tag.to_string());
            if seen.insert(key) {
                out.push((String::new(), "(encrypted)".to_string(), tag.to_string(), None, true));
            }
            i += 15; // step past prefix + nonce
        } else {
            i += 1;
        }
    }

    out
}

/// Walk heap regions of browser processes and extract session cookie records.
pub fn walk_browser_cookies<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<BrowserCookieInfo>> {
    let wr = crate::heap_walker::for_each_heap_region(
        reader,
        ps_head_vaddr,
        |proc| COOKIE_BROWSERS.iter().any(|b| proc.image_name.eq_ignore_ascii_case(b)),
        |bytes, proc| {
            scan_cookie_region(bytes)
                .into_iter()
                .map(|(domain, name, value, path, encrypted)| BrowserCookieInfo {
                    pid: proc.pid,
                    image_name: proc.image_name.clone(),
                    domain,
                    name,
                    value,
                    path,
                    encrypted,
                })
                .collect()
        },
        |info: &BrowserCookieInfo| (info.pid, info.domain.clone(), info.name.clone(), info.value.clone()),
    )?;
    Ok(wr.items)
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
        let (_, name, value, _, _) = &results[0];
        assert_eq!(name, "session_id");
        assert_eq!(value, "abc123xyz");
    }

    #[test]
    fn scan_set_cookie_with_domain_attribute() {
        let data = b"Set-Cookie: auth=tok789; Domain=.example.com; Path=/api; Secure\r\n";
        let results = scan_cookie_region(data);
        assert_eq!(results.len(), 1, "expected 1 cookie match");
        let (domain, name, value, _, _) = &results[0];
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
        let (domain, name, value, path, _) = &results[0];
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
        let names: Vec<_> = results.iter().map(|(_, n, _, _, _)| n.as_str()).collect();
        assert!(names.contains(&"token_a"));
        assert!(names.contains(&"token_b"));
    }

    #[test]
    fn scan_cookie_region_detects_v10_prefix() {
        // 3-byte "v10" prefix + 12-byte nonce + padding
        let mut data = vec![0u8; 100];
        data[0..3].copy_from_slice(b"v10");
        let results = scan_cookie_region(&data);
        assert!(!results.is_empty(), "v10 cookie should be detected");
    }
}
