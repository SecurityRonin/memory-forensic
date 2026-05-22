//! PPID spoofing detection (MITRE ATT&CK T1134.004).
//!
//! Checks known Windows system processes against their expected parent
//! process names. When `svchost.exe` is not a child of `services.exe`, or
//! `lsass.exe` is not a child of `wininit.exe`, it is a strong signal of
//! process injection via PPID spoofing.

use crate::{WinPpidSpoofInfo, WinProcessInfo};

/// Detect PPID spoofing by comparing each process's actual parent against
/// the expected parent list for known system processes.
///
/// Returns one entry per suspicious process (parent name not in allowed set).
pub fn check_ppid_spoof(_procs: &[WinProcessInfo]) -> Vec<WinPpidSpoofInfo> {
    vec![] // RED: not implemented
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u64, ppid: u64, name: &str) -> WinProcessInfo {
        WinProcessInfo {
            pid,
            ppid,
            image_name: name.to_string(),
            create_time: 0,
            exit_time: 0,
            cr3: 0,
            peb_addr: if name.eq_ignore_ascii_case("system") { 0 } else { 1 },
            vaddr: 0,
            thread_count: 1,
            is_wow64: false,
            handle_count: 0,
            session_id: 0,
        }
    }

    #[test]
    fn svchost_with_correct_parent_not_flagged() {
        let procs = vec![
            proc(4, 0, "System"),
            proc(500, 4, "wininit.exe"),
            proc(600, 500, "services.exe"),
            proc(1200, 600, "svchost.exe"),
        ];
        let hits = check_ppid_spoof(&procs);
        assert!(hits.is_empty(), "clean svchost.exe must not be flagged");
    }

    #[test]
    fn svchost_wrong_parent_flagged() {
        let procs = vec![
            proc(4, 0, "System"),
            proc(800, 4, "explorer.exe"),
            proc(1200, 800, "svchost.exe"),
        ];
        let hits = check_ppid_spoof(&procs);
        assert_eq!(hits.len(), 1, "svchost.exe with explorer parent must be flagged");
        assert_eq!(hits[0].pid, 1200);
        assert_eq!(hits[0].name, "svchost.exe");
        assert!(
            hits[0].parent_name.eq_ignore_ascii_case("explorer.exe"),
            "parent_name must be explorer.exe, got {}",
            hits[0].parent_name
        );
        assert!(hits[0].expected_parents.iter().any(|p| p == "services.exe"));
    }

    #[test]
    fn lsass_wrong_parent_flagged() {
        let procs = vec![
            proc(4, 0, "System"),
            proc(600, 4, "services.exe"),
            proc(700, 600, "lsass.exe"),
        ];
        let hits = check_ppid_spoof(&procs);
        assert_eq!(hits.len(), 1, "lsass.exe with services.exe parent must be flagged");
        assert_eq!(hits[0].pid, 700);
        assert!(hits[0].expected_parents.iter().any(|p| p == "wininit.exe"));
    }

    #[test]
    fn lsass_correct_parent_not_flagged() {
        let procs = vec![
            proc(4, 0, "System"),
            proc(500, 4, "wininit.exe"),
            proc(700, 500, "lsass.exe"),
        ];
        let hits = check_ppid_spoof(&procs);
        assert!(hits.is_empty(), "lsass.exe with wininit.exe parent must not be flagged");
    }

    #[test]
    fn unknown_process_not_checked() {
        let procs = vec![
            proc(4, 0, "System"),
            proc(800, 4, "explorer.exe"),
            proc(1400, 800, "calc.exe"),
        ];
        let hits = check_ppid_spoof(&procs);
        assert!(hits.is_empty(), "unknown process must not be flagged");
    }

    #[test]
    fn unknown_ppid_flagged() {
        let procs = vec![
            proc(4, 0, "System"),
            proc(1200, 9999, "svchost.exe"),
        ];
        let hits = check_ppid_spoof(&procs);
        assert_eq!(hits.len(), 1, "svchost.exe with missing ppid must be flagged");
        assert_eq!(hits[0].parent_name, "UNKNOWN");
    }

    #[test]
    fn smss_with_system_parent_not_flagged() {
        let procs = vec![
            proc(4, 0, "System"),
            proc(300, 4, "smss.exe"),
        ];
        let hits = check_ppid_spoof(&procs);
        assert!(hits.is_empty(), "smss.exe child of System must not be flagged");
    }

    #[test]
    fn smss_wrong_parent_flagged() {
        let procs = vec![
            proc(4, 0, "System"),
            proc(800, 4, "explorer.exe"),
            proc(300, 800, "smss.exe"),
        ];
        let hits = check_ppid_spoof(&procs);
        assert_eq!(hits.len(), 1, "smss.exe with non-System parent must be flagged");
        assert!(hits[0].expected_parents.iter().any(|p| p == "system"));
    }

    #[test]
    fn dllhost_allows_both_svchost_and_services_parents() {
        let procs_via_svchost = vec![
            proc(4, 0, "System"),
            proc(600, 4, "services.exe"),
            proc(700, 600, "svchost.exe"),
            proc(1400, 700, "dllhost.exe"),
        ];
        assert!(check_ppid_spoof(&procs_via_svchost).is_empty());

        let procs_via_services = vec![
            proc(4, 0, "System"),
            proc(600, 4, "services.exe"),
            proc(1400, 600, "dllhost.exe"),
        ];
        assert!(check_ppid_spoof(&procs_via_services).is_empty());
    }

    #[test]
    fn multiple_spoofs_all_reported() {
        let procs = vec![
            proc(4, 0, "System"),
            proc(800, 4, "explorer.exe"),
            proc(1200, 800, "svchost.exe"),
            proc(1300, 800, "lsass.exe"),
        ];
        let hits = check_ppid_spoof(&procs);
        assert_eq!(hits.len(), 2, "both svchost and lsass spoofs must be reported");
    }

    #[test]
    fn case_insensitive_matching() {
        let procs = vec![
            proc(4, 0, "System"),
            proc(600, 4, "Services.EXE"),
            proc(1200, 600, "SvcHost.exe"),
        ];
        let hits = check_ppid_spoof(&procs);
        assert!(hits.is_empty(), "case-insensitive parent match must not flag");
    }
}
