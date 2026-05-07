//! Authentication session token forensics walker.
//!
//! Scans process heap memory for authentication tokens that applications hold
//! in memory during active sessions. Covers JWTs, OAuth Bearer tokens, and
//! provider-specific token formats.
//!
//! This capability has no equivalent in Volatility 3, pypykatz, or MemProcFS
//! — those tools focus on Windows credential structures; this walker targets
//! modern application-layer authentication material.
//!
//! # Token types detected
//!
//! - **JWT** (`eyJ*.*.*`) — JSON Web Tokens used by OAuth2/OIDC, API auth
//! - **Bearer** — OAuth2 access tokens in `Authorization: Bearer` headers
//! - **GitHub PAT** (`ghp_*`, `github_pat_*`) — GitHub personal access tokens
//! - **GitLab PAT** (`glpat-*`) — GitLab personal access tokens
//! - **Slack** (`xoxb-*`, `xoxp-*`) — Slack bot/user tokens
//! - **AWS STS** — Temporary AWS session tokens (AQOD/AQIA prefix)
//! - **Generic** — `access_token`/`refresh_token` JSON field values
//!
//! # Forensic guarantee
//!
//! Read-only. No live process access, no Win32 API calls, no state modification.

use std::collections::HashSet;
use std::sync::OnceLock;

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{
    types::SessionTokenInfo,
    Result,
};

struct TokenPattern {
    label: &'static str,
    re: regex::Regex,
    use_capture: bool,
}

static TOKEN_PATTERNS: OnceLock<Vec<TokenPattern>> = OnceLock::new();

fn token_patterns() -> &'static [TokenPattern] {
    TOKEN_PATTERNS.get_or_init(|| {
        vec![
            TokenPattern {
                label: "Jwt",
                re: regex::Regex::new(JWT_PATTERN).expect("JWT_PATTERN is valid"),
                use_capture: false,
            },
            TokenPattern {
                label: "Bearer",
                re: regex::Regex::new(BEARER_PATTERN).expect("BEARER_PATTERN is valid"),
                use_capture: true,
            },
            TokenPattern {
                label: "GitHub",
                re: regex::Regex::new(GITHUB_PATTERN).expect("GITHUB_PATTERN is valid"),
                use_capture: false,
            },
            TokenPattern {
                label: "GitLab",
                re: regex::Regex::new(GITLAB_PATTERN).expect("GITLAB_PATTERN is valid"),
                use_capture: false,
            },
            TokenPattern {
                label: "Slack",
                re: regex::Regex::new(SLACK_PATTERN).expect("SLACK_PATTERN is valid"),
                use_capture: false,
            },
            TokenPattern {
                label: "AwsSts",
                re: regex::Regex::new(AWS_STS_PATTERN).expect("AWS_STS_PATTERN is valid"),
                use_capture: false,
            },
            TokenPattern {
                label: "GenericAccessToken",
                re: regex::Regex::new(GENERIC_TOKEN_PATTERN)
                    .expect("GENERIC_TOKEN_PATTERN is valid"),
                use_capture: true,
            },
        ]
    })
}

/// Walk committed, writable heap regions of ALL processes in the dump and
/// extract any authentication tokens found as strings.
///
/// # Arguments
///
/// * `reader` — kernel-space `ObjectReader` (uses kernel CR3 / symbol table).
/// * `ps_head_vaddr` — virtual address of `PsActiveProcessHead`.
pub fn walk_session_tokens<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<SessionTokenInfo>> {
    let wr = crate::heap_walker::for_each_heap_region(
        reader,
        ps_head_vaddr,
        |_proc| true,
        |bytes, proc| scan_for_tokens(bytes, proc.pid, &proc.image_name),
        |info: &SessionTokenInfo| (info.pid, info.token_value.clone()),
    )?;
    Ok(wr.items)
}

// JWT: three base64url segments separated by dots, header starts with eyJ ({"  in base64)
const JWT_PATTERN: &str = r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}";

// Bearer token in Authorization header or JSON
const BEARER_PATTERN: &str = r"[Bb]earer ([A-Za-z0-9\-._~+/]{20,})";

// GitHub PAT (classic: ghp_, fine-grained: github_pat_)
const GITHUB_PATTERN: &str = r"(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})";

// GitLab PAT
const GITLAB_PATTERN: &str = r"glpat-[A-Za-z0-9_-]{20}";

// Slack tokens
const SLACK_PATTERN: &str = r"xox[bpoas]-[0-9A-Za-z-]{10,}";

// AWS STS temporary token (longer than AKIA access key, starts with AQOD/AQIA/IQoJ etc.)
const AWS_STS_PATTERN: &str = r"(?:AQOD|AQIA|IQoJ|IQoI)[A-Za-z0-9+/=]{100,}";

// Generic access_token / refresh_token in JSON
const GENERIC_TOKEN_PATTERN: &str =
    r#"["'](?:access_token|refresh_token|id_token)["']\s*:\s*["']([A-Za-z0-9\-._~+/=]{20,})["']"#;

/// Scan raw bytes for authentication token patterns.
///
/// Returns one [`SessionTokenInfo`] per unique token value found in `data`.
/// For patterns with capture groups (Bearer, Generic), the captured group
/// value is used; for patterns without (JWT, GitHub, GitLab, Slack, AWS STS),
/// the full match is used.
pub(crate) fn scan_for_tokens(data: &[u8], pid: u64, process_name: &str) -> Vec<SessionTokenInfo> {
    let text = String::from_utf8_lossy(data);

    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();

    for tp in token_patterns() {
        for caps in tp.re.captures_iter(&text) {
            let value = if tp.use_capture {
                caps.get(1).map(|m| m.as_str().to_string())
            } else {
                caps.get(0).map(|m| m.as_str().to_string())
            };

            let Some(token_value) = value else { continue };

            if seen.insert(token_value.clone()) {
                out.push(SessionTokenInfo {
                    pid,
                    process_name: process_name.to_string(),
                    token_type: tp.label.to_string(),
                    token_value,
                });
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMMY_PID: u64 = 1234;
    const DUMMY_PROC: &str = "test.exe";

    #[test]
    fn scan_empty_returns_nothing() {
        assert!(scan_for_tokens(b"", DUMMY_PID, DUMMY_PROC).is_empty());
    }

    #[test]
    fn scan_no_tokens_returns_nothing() {
        assert!(scan_for_tokens(b"hello world no auth here", DUMMY_PID, DUMMY_PROC).is_empty());
    }

    #[test]
    fn scan_detects_jwt() {
        // Real JWT structure: three base64url segments
        let data = b"Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaWF0IjoxNzAwMDAwMDAwfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let results = scan_for_tokens(data, DUMMY_PID, DUMMY_PROC);
        assert!(!results.is_empty(), "should detect JWT");
        assert!(results.iter().any(|t| t.token_type == "Jwt" || t.token_type == "Bearer"));
    }

    #[test]
    fn scan_detects_github_pat() {
        let data = b"git remote set-url origin https://ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij@github.com/org/repo";
        let results = scan_for_tokens(data, DUMMY_PID, DUMMY_PROC);
        assert!(!results.is_empty(), "should detect GitHub PAT");
        assert!(results.iter().any(|t| t.token_type == "GitHub"));
        assert!(results.iter().any(|t| t.token_value.starts_with("ghp_")));
    }

    #[test]
    fn scan_detects_slack_token() {
        let data = b"token=xoxb-123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx";
        let results = scan_for_tokens(data, DUMMY_PID, DUMMY_PROC);
        assert!(!results.is_empty(), "should detect Slack token");
        assert!(results.iter().any(|t| t.token_type == "Slack"));
    }

    #[test]
    fn scan_detects_generic_access_token() {
        let data = br#"{"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9abcdefghijklmnopqrstuvwxyz0123456789","token_type":"Bearer"}"#;
        let results = scan_for_tokens(data, DUMMY_PID, DUMMY_PROC);
        assert!(!results.is_empty(), "should detect access_token JSON field");
    }

    #[test]
    fn scan_deduplicates_same_token_multiple_occurrences() {
        // Same JWT appears twice in the buffer
        let jwt = b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let mut data = Vec::new();
        data.extend_from_slice(jwt);
        data.extend_from_slice(b" some data ");
        data.extend_from_slice(jwt);
        let results = scan_for_tokens(&data, DUMMY_PID, DUMMY_PROC);
        let jwt_results: Vec<_> = results.iter().filter(|t| t.token_type == "Jwt").collect();
        assert_eq!(jwt_results.len(), 1, "duplicate JWT should be deduplicated");
    }

    #[test]
    fn scan_for_tokens_called_twice_is_consistent() {
        let data = b"Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaWF0IjoxNzAwMDAwMDAwfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let r1 = scan_for_tokens(data, DUMMY_PID, DUMMY_PROC);
        let r2 = scan_for_tokens(data, DUMMY_PID, DUMMY_PROC);
        assert_eq!(r1.len(), r2.len(), "second call must return same number of results");
        for (t1, t2) in r1.iter().zip(r2.iter()) {
            assert_eq!(t1.token_type, t2.token_type, "token_type must be identical across calls");
            assert_eq!(t1.token_value, t2.token_value, "token_value must be identical across calls");
        }
    }
}
