//! PPID spoofing detection (MITRE ATT&CK T1134.004).
//!
//! Checks known Windows system processes against their expected parent
//! process names. When `svchost.exe` is not a child of `services.exe`, or
//! `lsass.exe` is not a child of `wininit.exe`, it is a strong signal of
//! process injection via PPID spoofing.
//!
//! The parent-process rule table lives in `forensicnomicon::processes` so it
//! can be reused across crates without duplication.

use crate::{WinPpidSpoofInfo, WinProcessInfo};
use forensicnomicon::processes;

/// Detect PPID spoofing by comparing each process's actual parent against
/// the expected parent list for known system processes.
///
/// Returns one entry per suspicious process (parent name not in allowed set).
/// Entries carry a `confidence` field: `High` for tightly-constrained system
/// processes, `Low` for COM Surrogate and other broad-spawner patterns where a
/// violation is suspicious but not definitive.
pub fn check_ppid_spoof(procs: &[WinProcessInfo]) -> Vec<WinPpidSpoofInfo> {
    let pid_to_name: std::collections::HashMap<u64, &str> = procs
        .iter()
        .map(|p| (p.pid, p.image_name.as_str()))
        .collect();

    let mut results = Vec::new();

    for proc in procs {
        let name_lower = proc.image_name.to_ascii_lowercase();
        let Some((allowed, confidence)) = processes::expected_parents(&name_lower) else {
            continue; // untracked process — no rule to evaluate
        };

        let parent_lower = pid_to_name
            .get(&proc.ppid)
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_else(|| "unknown".to_string());

        if !allowed.iter().any(|a| *a == parent_lower.as_str()) {
            results.push(WinPpidSpoofInfo {
                pid: proc.pid,
                ppid: proc.ppid,
                name: proc.image_name.clone(),
                parent_name: pid_to_name
                    .get(&proc.ppid)
                    .map(|s| (*s).to_string())
                    .unwrap_or_else(|| "UNKNOWN".to_string()),
                expected_parents: allowed.iter().map(|s| (*s).to_string()).collect(),
                confidence,
            });
        }
    }

    results
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
            peb_addr: if name.eq_ignore_ascii_case("system") {
                0
            } else {
                1
            },
            vaddr: 0,
            thread_count: 1,
            is_wow64: false,
            handle_count: 0,
            session_id: 0,
        }
    }

    /// A complete, clean Windows boot chain covering all tracked processes so
    /// individual tests can extend it without accidentally producing stray hits.
    ///
    /// PIDs (stable across tests):
    ///   4    System
    ///   300  smss.exe      (ppid=4   → system ✓)
    ///   500  wininit.exe   (ppid=300 → smss.exe ✓)
    ///   600  services.exe  (ppid=500 → wininit.exe ✓)
    ///   510  csrss.exe     (ppid=300 → smss.exe ✓)
    ///   511  winlogon.exe  (ppid=300 → smss.exe ✓)
    ///   530  userinit.exe  (ppid=511 → winlogon.exe ✓)
    ///   540  explorer.exe  (ppid=530 → userinit.exe ✓)
    fn baseline() -> Vec<WinProcessInfo> {
        vec![
            proc(4, 0, "System"),
            proc(300, 4, "smss.exe"),
            proc(500, 300, "wininit.exe"),
            proc(600, 500, "services.exe"),
            proc(510, 300, "csrss.exe"),
            proc(511, 300, "winlogon.exe"),
            proc(530, 511, "userinit.exe"),
            proc(540, 530, "explorer.exe"),
        ]
    }

    #[test]
    fn svchost_with_correct_parent_not_flagged() {
        let mut procs = baseline();
        procs.push(proc(1200, 600, "svchost.exe")); // services(600) → svchost ✓
        let hits = check_ppid_spoof(&procs);
        assert!(hits.is_empty(), "clean svchost.exe must not be flagged");
    }

    #[test]
    fn svchost_wrong_parent_flagged() {
        // svchost spawned under explorer (baseline pid 540) — only svchost is flagged.
        let mut procs = baseline();
        procs.push(proc(1200, 540, "svchost.exe"));
        let hits = check_ppid_spoof(&procs);
        assert_eq!(
            hits.len(),
            1,
            "svchost.exe with explorer parent must be flagged"
        );
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
        // lsass under services.exe (600) is a spoof; only lsass is flagged.
        let mut procs = baseline();
        procs.push(proc(700, 600, "lsass.exe"));
        let hits = check_ppid_spoof(&procs);
        assert_eq!(
            hits.len(),
            1,
            "lsass.exe with services.exe parent must be flagged"
        );
        assert_eq!(hits[0].pid, 700);
        assert!(hits[0].expected_parents.iter().any(|p| p == "wininit.exe"));
    }

    #[test]
    fn lsass_correct_parent_not_flagged() {
        let mut procs = baseline();
        procs.push(proc(700, 500, "lsass.exe")); // wininit(500) → lsass ✓
        let hits = check_ppid_spoof(&procs);
        assert!(
            hits.is_empty(),
            "lsass.exe with wininit.exe parent must not be flagged"
        );
    }

    #[test]
    fn unknown_process_not_checked() {
        // calc.exe is not in any rule; baseline ensures no other tracked process fires.
        let mut procs = baseline();
        procs.push(proc(1400, 540, "calc.exe")); // explorer(540) → calc (untracked)
        let hits = check_ppid_spoof(&procs);
        assert!(hits.is_empty(), "unknown process must not be flagged");
    }

    #[test]
    fn unknown_ppid_flagged() {
        // svchost with a ppid that resolves to nothing → "UNKNOWN" parent → flagged.
        let procs = vec![proc(4, 0, "System"), proc(1200, 9999, "svchost.exe")];
        let hits = check_ppid_spoof(&procs);
        assert_eq!(
            hits.len(),
            1,
            "svchost.exe with missing ppid must be flagged"
        );
        assert_eq!(hits[0].parent_name, "UNKNOWN");
    }

    #[test]
    fn smss_with_system_parent_not_flagged() {
        let procs = vec![proc(4, 0, "System"), proc(300, 4, "smss.exe")];
        let hits = check_ppid_spoof(&procs);
        assert!(
            hits.is_empty(),
            "smss.exe child of System must not be flagged"
        );
    }

    #[test]
    fn smss_wrong_parent_flagged() {
        // Use an untracked process (notepad) as the wrong parent so only smss fires.
        let procs = vec![
            proc(4, 0, "System"),
            proc(800, 4, "notepad.exe"), // untracked
            proc(300, 800, "smss.exe"),
        ];
        let hits = check_ppid_spoof(&procs);
        assert_eq!(
            hits.len(),
            1,
            "smss.exe with non-System parent must be flagged"
        );
        assert!(hits[0].expected_parents.iter().any(|p| p == "system"));
    }

    #[test]
    fn dllhost_allows_both_svchost_and_services_parents() {
        // via svchost — full baseline + svchost(700 under services 600) + dllhost under svchost
        let mut procs_via_svchost = baseline();
        procs_via_svchost.push(proc(700, 600, "svchost.exe"));
        procs_via_svchost.push(proc(1400, 700, "dllhost.exe"));
        assert!(check_ppid_spoof(&procs_via_svchost).is_empty());

        // via services — dllhost directly under services(600)
        let mut procs_via_services = baseline();
        procs_via_services.push(proc(1400, 600, "dllhost.exe"));
        assert!(check_ppid_spoof(&procs_via_services).is_empty());
    }

    #[test]
    fn multiple_spoofs_all_reported() {
        // Use an untracked parent so only the two spoofed processes fire, not explorer.
        let mut procs = baseline();
        procs.push(proc(900, 540, "notepad.exe")); // explorer(540) → notepad (untracked)
        procs.push(proc(1200, 900, "svchost.exe")); // notepad → svchost = spoof
        procs.push(proc(1300, 900, "lsass.exe")); // notepad → lsass  = spoof
        let hits = check_ppid_spoof(&procs);
        assert_eq!(
            hits.len(),
            2,
            "both svchost and lsass spoofs must be reported"
        );
    }

    #[test]
    fn case_insensitive_matching() {
        // Mixed-case names must still match the expected-parent table correctly.
        let procs = vec![
            proc(4, 0, "System"),
            proc(300, 4, "smss.exe"),
            proc(500, 300, "WinInit.EXE"), // smss → wininit ✓ (case-insensitive)
            proc(600, 500, "Services.EXE"), // wininit → services ✓
            proc(1200, 600, "SvcHost.exe"), // services → svchost ✓
        ];
        let hits = check_ppid_spoof(&procs);
        assert!(
            hits.is_empty(),
            "case-insensitive parent match must not flag"
        );
    }

    #[test]
    fn svchost_spoof_has_high_confidence() {
        use forensicnomicon::processes::SpoofConfidence;
        let mut procs = baseline();
        procs.push(proc(1200, 540, "svchost.exe")); // explorer(540) → svchost = spoof
        let hits = check_ppid_spoof(&procs);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].confidence, SpoofConfidence::High);
    }

    #[test]
    fn lsass_spoof_has_high_confidence() {
        use forensicnomicon::processes::SpoofConfidence;
        let mut procs = baseline();
        procs.push(proc(700, 600, "lsass.exe")); // services(600) → lsass = spoof
        let hits = check_ppid_spoof(&procs);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].confidence, SpoofConfidence::High);
    }

    #[test]
    fn dllhost_unknown_parent_has_low_confidence() {
        // dllhost.exe spawned by an arbitrary user app → Low confidence alert,
        // not silently ignored. This is the COM Surrogate case.
        use forensicnomicon::processes::SpoofConfidence;
        let mut procs = baseline();
        procs.push(proc(900, 540, "notepad.exe")); // explorer → notepad (untracked)
        procs.push(proc(1400, 900, "dllhost.exe")); // notepad → dllhost = low-conf
        let hits = check_ppid_spoof(&procs);
        assert_eq!(
            hits.len(),
            1,
            "dllhost with unlisted parent must emit a low-confidence hit"
        );
        assert_eq!(hits[0].confidence, SpoofConfidence::Low);
    }

    #[test]
    fn dllhost_known_parents_not_flagged() {
        // explorer.exe (540 in baseline) is a legitimate dllhost spawner.
        let mut procs_explorer = baseline();
        procs_explorer.push(proc(1400, 540, "dllhost.exe"));
        assert!(check_ppid_spoof(&procs_explorer).is_empty());

        // mmc.exe is untracked (not flagged itself) and also a legitimate dllhost spawner.
        let mut procs_mmc = baseline();
        procs_mmc.push(proc(810, 540, "mmc.exe")); // explorer → mmc (untracked)
        procs_mmc.push(proc(1400, 810, "dllhost.exe")); // mmc → dllhost ✓
        assert!(check_ppid_spoof(&procs_mmc).is_empty());
    }
}
