//! [`IntoForensicEvents`] implementations for Windows walker output types.

use memf_correlate::event::{Entity, Finding, ForensicEvent, Severity};
use memf_correlate::mitre::MitreAttackId;
use memf_correlate::traits::IntoForensicEvents;

use crate::types::WinProcessInfo;

/// Suspicious image names that are often spoofed by malware (T1036 - Masquerading).
const SPOOFABLE_NAMES: &[&str] = &[
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "winlogon.exe",
    "services.exe",
    "smss.exe",
    "wininit.exe",
];

/// Processes with these PIDs are kernel/system and should never have a non-zero PPID
/// other than the System process (pid 4) or Idle (pid 0).
const SYSTEM_PIDS: &[u64] = &[0, 4];

impl IntoForensicEvents for WinProcessInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        let mut severity = Severity::Info;
        let mut finding = Finding::Other("process_enumerated".into());
        let mut mitre: Vec<MitreAttackId> = Vec::new();
        let mut confidence = 0.5f64;

        if self.image_name.trim().is_empty() {
            severity = Severity::High;
            finding = Finding::DefenseEvasion;
            mitre.push(MitreAttackId::new("T1564").expect("valid id"));
            confidence = 0.9;
        } else if self.thread_count == 0 && !SYSTEM_PIDS.contains(&self.pid) {
            severity = Severity::Medium;
            finding = Finding::DefenseEvasion;
            mitre.push(MitreAttackId::new("T1564").expect("valid id"));
            confidence = 0.75;
        } else if SPOOFABLE_NAMES.contains(&self.image_name.to_lowercase().as_str()) {
            finding = Finding::Other("spoofable_name".into());
            confidence = 0.4;
        }

        vec![ForensicEvent::builder()
            .source_walker("win_process")
            .entity(Entity::Process {
                pid: self.pid as u32,
                name: self.image_name.clone(),
                ppid: Some(self.ppid as u32),
            })
            .finding(finding)
            .severity(severity)
            .confidence(confidence)
            .mitre_attack(mitre)
            .build()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_process(pid: u64, ppid: u64, name: &str, threads: u32) -> WinProcessInfo {
        WinProcessInfo {
            pid,
            ppid,
            image_name: name.to_string(),
            create_time: 0,
            exit_time: 0,
            cr3: 0x1000,
            peb_addr: 0,
            vaddr: 0xFFFF_8000_0000_0000,
            thread_count: threads,
            is_wow64: false,
        }
    }

    #[test]
    fn normal_process_produces_one_info_event() {
        let proc = make_process(1234, 4, "notepad.exe", 3);
        let events = proc.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Info);
        assert_eq!(events[0].source_walker, "win_process");
    }

    #[test]
    fn empty_image_name_produces_high_severity_defense_evasion() {
        let proc = make_process(999, 4, "", 2);
        let events = proc.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::High);
        assert!(matches!(events[0].finding, Finding::DefenseEvasion));
        assert_eq!(events[0].mitre_attack[0].as_str(), "T1564");
    }

    #[test]
    fn zero_thread_count_non_system_produces_medium_event() {
        let proc = make_process(1234, 4, "explorer.exe", 0);
        let events = proc.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Medium);
        assert!(matches!(events[0].finding, Finding::DefenseEvasion));
    }

    #[test]
    fn system_pid_with_zero_threads_is_not_flagged() {
        // PID 4 (System) legitimately has 0 threads in some memory images.
        let proc = make_process(4, 0, "System", 0);
        let events = proc.into_forensic_events();
        assert_eq!(events[0].severity, Severity::Info);
    }

    #[test]
    fn spoofable_name_process_is_noted_at_info_level() {
        let proc = make_process(5678, 900, "svchost.exe", 5);
        let events = proc.into_forensic_events();
        assert_eq!(events.len(), 1);
        // svchost by itself is not suspicious without tree context — just noted.
        assert_eq!(events[0].confidence, 0.4);
    }

    #[test]
    fn entity_contains_correct_pid_and_ppid() {
        let proc = make_process(42, 4, "cmd.exe", 1);
        let events = proc.into_forensic_events();
        match &events[0].entity {
            Entity::Process { pid, ppid, name } => {
                assert_eq!(*pid, 42u32);
                assert_eq!(*ppid, Some(4u32));
                assert_eq!(name, "cmd.exe");
            }
            other => panic!("expected Process entity, got {other:?}"),
        }
    }

    #[test]
    fn high_severity_event_is_suspicious() {
        let proc = make_process(999, 4, "", 2);
        let events = proc.into_forensic_events();
        assert!(events[0].is_suspicious());
    }

    #[test]
    fn info_severity_event_is_not_suspicious() {
        let proc = make_process(1234, 4, "notepad.exe", 3);
        let events = proc.into_forensic_events();
        assert!(!events[0].is_suspicious());
    }
}
