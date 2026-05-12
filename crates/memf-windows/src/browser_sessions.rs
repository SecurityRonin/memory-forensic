//! Browser session tab URL forensics walker.
//!
//! Scans heap memory of Chromium-based browsers and Firefox for URL strings
//! that represent currently open tab navigation entries.  These exist
//! transiently in committed heap pages and are lost when the browser exits or
//! the system is rebooted.
//!
//! # Scanning strategy
//!
//! Plain-text URL scan using the pattern `https?://[^\x00-\x1f\x7f\s]{4,512}`.
//! Browsers hold URL strings in heap throughout the session lifetime — in
//! navigation history vectors, tab model objects, and renderer state.  A
//! single pass over committed private heap pages yields the live tab set with
//! high recall and acceptable precision (duplicates are deduplicated).
//!
//! # Supported processes
//!
//! Chromium family plus `firefox.exe` (see [`SESSION_BROWSERS`]).
//!
//! # Forensic guarantee
//!
//! Read-only scan of memory dump bytes — no live process interaction.

use std::collections::HashSet;

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use regex::Regex;

use crate::{
    types::BrowserSessionEntry,
    Result,
};

/// Browser process names whose heap is scanned for open-tab URL records.
pub const SESSION_BROWSERS: &[&str] = &[
    "msedge.exe",
    "chrome.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "chromium.exe",
    "firefox.exe",
];

/// Scan raw bytes from one heap region for browser URL strings.
///
/// Returns `(url, source_hint)` pairs where `source_hint` describes the
/// scan pattern that matched (e.g. `"url-scan"`).
pub(crate) fn scan_session_region(data: &[u8]) -> Vec<(String, String)> {
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        // Fall back to lossy conversion — URLs are ASCII/UTF-8
        Err(_) => return scan_session_region_lossy(data),
    };

    let url_re = match Regex::new(
        r"https?://[^\x00-\x1f\x7f\s]{4,512}"
    ) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<(String, String)> = Vec::new();

    for m in url_re.find_iter(text) {
        let url = m.as_str().trim_end_matches(|c: char| !c.is_alphanumeric() && c != '/').to_string();
        if url.len() < 10 {
            continue;
        }
        if seen.insert(url.clone()) {
            out.push((url, "url-scan".to_string()));
        }
    }

    out
}

fn scan_session_region_lossy(data: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(data).into_owned();

    let url_re = match Regex::new(
        r"https?://[^\x00-\x1f\x7f\s]{4,512}"
    ) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<(String, String)> = Vec::new();

    for m in url_re.find_iter(&text) {
        let url = m.as_str().trim_end_matches(|c: char| !c.is_alphanumeric() && c != '/').to_string();
        if url.len() < 10 {
            continue;
        }
        if seen.insert(url.clone()) {
            out.push((url, "url-scan".to_string()));
        }
    }

    out
}

/// Walk heap regions of browser processes and extract open-tab URL records.
pub fn walk_browser_sessions<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<BrowserSessionEntry>> {
    let wr = crate::heap_walker::for_each_heap_region(
        reader,
        ps_head_vaddr,
        |proc| SESSION_BROWSERS.iter().any(|b| proc.image_name.eq_ignore_ascii_case(b)),
        |bytes, proc| {
            scan_session_region(bytes)
                .into_iter()
                .map(|(url, source_hint)| BrowserSessionEntry {
                    pid: proc.pid,
                    image_name: proc.image_name.clone(),
                    url,
                    source_hint,
                })
                .collect()
        },
        |info: &BrowserSessionEntry| (info.pid, info.url.clone()),
    )?;
    Ok(wr.items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_browsers_includes_chrome_firefox_edge() {
        assert!(SESSION_BROWSERS.contains(&"chrome.exe"));
        assert!(SESSION_BROWSERS.contains(&"firefox.exe"));
        assert!(SESSION_BROWSERS.contains(&"msedge.exe"));
        assert!(SESSION_BROWSERS.contains(&"brave.exe"));
    }

    #[test]
    fn scan_empty_returns_nothing() {
        assert!(scan_session_region(b"").is_empty());
    }

    #[test]
    fn scan_http_url_extracted() {
        let data = b"some heap bytes before https://example.com/path?q=1 and more after";
        let results = scan_session_region(data);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "https://example.com/path?q=1");
        assert_eq!(results[0].1, "url-scan");
    }

    #[test]
    fn scan_http_scheme_extracted() {
        let data = b"http://example.org/page";
        let results = scan_session_region(data);
        assert_eq!(results.len(), 1);
        assert!(results[0].0.starts_with("http://"));
    }

    #[test]
    fn scan_multiple_urls_deduped() {
        let data = b"https://a.com/x https://a.com/x https://b.com/y";
        let results = scan_session_region(data);
        assert_eq!(results.len(), 2, "duplicate URL should be deduplicated");
        let urls: Vec<_> = results.iter().map(|(u, _)| u.as_str()).collect();
        assert!(urls.contains(&"https://a.com/x"));
        assert!(urls.contains(&"https://b.com/y"));
    }

    #[test]
    fn scan_short_url_rejected() {
        // "https://x.c" is 11 bytes, but after trimming trailing non-alnum it
        // may collapse to less than 10 — test an obviously too-short case
        let data = b"https://x";
        let results = scan_session_region(data);
        assert!(results.is_empty(), "sub-minimum URLs must be rejected");
    }

    #[test]
    fn scan_url_stripped_of_trailing_garbage() {
        // Null byte or control char terminates the URL match in the regex;
        // trailing punctuation like ')' that ends a sentence should be stripped
        let data = b"(see https://example.com/page)";
        let results = scan_session_region(data);
        assert!(!results.is_empty());
        assert!(!results[0].0.ends_with(')'), "trailing ')' must be stripped");
    }

    #[test]
    fn scan_null_byte_boundary_handled() {
        let mut data = b"https://good.example.com/ok\x00garbage".to_vec();
        data.extend_from_slice(b"https://second.example.com/page");
        let results = scan_session_region(&data);
        assert!(results.iter().any(|(u, _)| u.contains("good.example.com")));
    }
}
