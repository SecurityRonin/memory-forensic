//! [`IntoForensicEvents`] implementations for Linux walker output types.

use memf_correlate::event::{Entity, Finding, ForensicEvent, Severity};
use memf_correlate::mitre::MitreAttackId;
use memf_correlate::traits::IntoForensicEvents;

use crate::types::VmaInfo;

impl IntoForensicEvents for VmaInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        let (severity, finding, mitre, confidence) = if self.flags.exec && self.flags.write && !self.file_backed {
            // RWX anonymous mapping — classic shellcode/injection pattern (T1055)
            (
                Severity::High,
                Finding::ProcessHollowing,
                vec![MitreAttackId::new("T1055").expect("valid id")],
                0.9f64,
            )
        } else if self.flags.exec && !self.file_backed {
            // Executable anonymous mapping — JIT or shellcode, less certain (T1055)
            (
                Severity::Medium,
                Finding::DefenseEvasion,
                vec![MitreAttackId::new("T1055").expect("valid id")],
                0.6f64,
            )
        } else {
            (Severity::Info, Finding::Other("vma_enumerated".into()), vec![], 0.3f64)
        };

        vec![ForensicEvent::builder()
            .source_walker("linux_vma")
            .entity(Entity::Process {
                pid: self.pid as u32,
                name: self.comm.clone(),
                ppid: None,
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
    use crate::types::VmaFlags;

    fn make_vma(pid: u64, comm: &str, exec: bool, write: bool, file_backed: bool) -> VmaInfo {
        VmaInfo {
            pid,
            comm: comm.to_string(),
            start: 0x7f00_0000_0000,
            end: 0x7f00_0001_0000,
            flags: VmaFlags { read: true, write, exec, shared: false },
            pgoff: 0,
            file_backed,
        }
    }

    #[test]
    fn rwx_anonymous_vma_produces_high_severity_malfind() {
        let vma = make_vma(1234, "bash", true, true, false);
        let events = vma.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::High);
        assert!(matches!(events[0].finding, Finding::ProcessHollowing | Finding::DefenseEvasion));
        assert!(!events[0].mitre_attack.is_empty());
    }

    #[test]
    fn executable_anonymous_vma_produces_medium_event() {
        // exec + no write + no file backing: suspicious but less so (JIT, shellcode)
        let vma = make_vma(1234, "python3", true, false, false);
        let events = vma.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert!(events[0].severity >= Severity::Medium);
    }

    #[test]
    fn read_only_file_backed_vma_is_info() {
        let vma = make_vma(1234, "cat", false, false, true);
        let events = vma.into_forensic_events();
        assert_eq!(events[0].severity, Severity::Info);
    }

    #[test]
    fn rwx_vma_mitre_id_is_process_injection() {
        let vma = make_vma(999, "evil", true, true, false);
        let events = vma.into_forensic_events();
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1055"), "expected T1055 (Process Injection), got {ids:?}");
    }

    #[test]
    fn entity_contains_pid_and_comm() {
        let vma = make_vma(42, "sh", true, true, false);
        let events = vma.into_forensic_events();
        match &events[0].entity {
            Entity::Process { pid, name, .. } => {
                assert_eq!(*pid, 42u32);
                assert_eq!(name, "sh");
            }
            other => panic!("expected Process entity, got {other:?}"),
        }
    }

    #[test]
    fn source_walker_is_linux_vma() {
        let vma = make_vma(1, "init", false, false, true);
        let events = vma.into_forensic_events();
        assert_eq!(events[0].source_walker, "linux_vma");
    }

    #[test]
    fn rwx_anonymous_vma_is_suspicious() {
        let vma = make_vma(1234, "bash", true, true, false);
        let events = vma.into_forensic_events();
        assert!(events[0].is_suspicious());
    }

    #[test]
    fn info_vma_is_not_suspicious() {
        let vma = make_vma(1234, "cat", false, false, true);
        let events = vma.into_forensic_events();
        assert!(!events[0].is_suspicious());
    }
}
