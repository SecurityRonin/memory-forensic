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

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{
    process::walk_processes,
    types::SessionTokenInfo,
    vad::walk_vad_tree,
    Result,
};

/// Maximum bytes read from a single VAD region.
const MAX_REGION_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

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
    let procs = walk_processes(reader, ps_head_vaddr)?;

    let vad_root_offset = reader
        .symbols()
        .field_offset("_EPROCESS", "VadRoot")
        .ok_or_else(|| crate::Error::Walker("missing _EPROCESS.VadRoot offset".into()))?;

    let mut results = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new(); // (pid, token_value)

    for proc in &procs {
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

            for token in scan_for_tokens(&bytes, proc.pid, &proc.image_name) {
                let key = (token.pid, token.token_value.clone());
                if seen.insert(key) {
                    results.push(token);
                }
            }
        }
    }

    Ok(results)
}

/// Scan raw bytes for authentication token patterns.
///
/// Returns one [`SessionTokenInfo`] per unique token value found in `data`.
/// For patterns with capture groups (Bearer, Generic), the captured group
/// value is used; for patterns without (JWT, GitHub, GitLab, Slack, AWS STS),
/// the full match is used.
pub(crate) fn scan_for_tokens(data: &[u8], pid: u64, process_name: &str) -> Vec<SessionTokenInfo> {
    // Stub: not yet implemented — returns empty vec so RED tests fail.
    let _ = (data, pid, process_name);
    vec![]
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
}
