//! [`IntoForensicEvents`] implementations for Linux walker output types.

use memf_correlate::event::{Entity, Finding, ForensicEvent, Severity};
use memf_correlate::mitre::MitreAttackId;
use memf_correlate::traits::IntoForensicEvents;

use crate::types::{ConnectionInfo, ModuleInfo, ModuleState, ProcessInfo, ProcessState, VmaInfo};

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

impl IntoForensicEvents for ProcessInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        let (severity, finding, mitre, confidence) = if self.comm.is_empty() {
            // Blank comm — hidden / name-erased process (T1564)
            (
                Severity::High,
                Finding::DefenseEvasion,
                vec![MitreAttackId::new("T1564").expect("valid id")],
                0.9f64,
            )
        } else if self.state == ProcessState::Zombie {
            // Zombie process — possible evasion indicator (T1564)
            (
                Severity::Medium,
                Finding::DefenseEvasion,
                vec![MitreAttackId::new("T1564").expect("valid id")],
                0.7f64,
            )
        } else if self.cr3.is_none() && self.ppid != 0 {
            // Kernel thread with non-zero ppid — suspicious kthread
            (
                Severity::Medium,
                Finding::Other("suspicious_kthread".into()),
                vec![],
                0.6f64,
            )
        } else {
            (Severity::Info, Finding::Other("process_enumerated".into()), vec![], 0.4f64)
        };

        vec![ForensicEvent::builder()
            .source_walker("linux_process")
            .entity(Entity::Process {
                pid: self.pid as u32,
                name: self.comm.clone(),
                ppid: Some(self.ppid as u32),
            })
            .finding(finding)
            .severity(severity)
            .confidence(confidence)
            .mitre_attack(mitre)
            .build()]
    }
}

impl IntoForensicEvents for ConnectionInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        let is_loopback = self.remote_addr == "127.0.0.1"
            || self.remote_addr == "::1"
            || self.remote_addr.is_empty();

        let (severity, finding, mitre, confidence) =
            if matches!(self.remote_port, 4444 | 1337 | 31337) {
                // Classic C2 ports (T1071)
                (
                    Severity::High,
                    Finding::NetworkBeaconing,
                    vec![MitreAttackId::new("T1071").expect("valid id")],
                    0.8f64,
                )
            } else if self.pid.is_none() {
                // No owning process — hidden connection (T1095)
                (
                    Severity::High,
                    Finding::DefenseEvasion,
                    vec![MitreAttackId::new("T1095").expect("valid id")],
                    0.85f64,
                )
            } else if self.remote_port == 0 && !is_loopback {
                // Port 0 with non-loopback remote — suspicious beaconing (T1071)
                (
                    Severity::Medium,
                    Finding::NetworkBeaconing,
                    vec![MitreAttackId::new("T1071").expect("valid id")],
                    0.6f64,
                )
            } else {
                (Severity::Info, Finding::Other("connection_enumerated".into()), vec![], 0.4f64)
            };

        let src = format!("{}:{}", self.local_addr, self.local_port)
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        let dst = format!("{}:{}", self.remote_addr, self.remote_port)
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());

        vec![ForensicEvent::builder()
            .source_walker("linux_connection")
            .entity(Entity::Connection {
                src,
                dst,
                proto: memf_correlate::event::Protocol::Tcp,
            })
            .finding(finding)
            .severity(severity)
            .confidence(confidence)
            .mitre_attack(mitre)
            .build()]
    }
}

impl IntoForensicEvents for ModuleInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        let (severity, finding, mitre, confidence) = if self.name.is_empty() {
            // Blank module name — hidden kernel module (T1014)
            (
                Severity::High,
                Finding::DefenseEvasion,
                vec![MitreAttackId::new("T1014").expect("valid id")],
                0.9f64,
            )
        } else if matches!(self.state, ModuleState::Going) {
            // Module unloading during scan — possible hide-by-unload evasion (T1014)
            (
                Severity::Medium,
                Finding::DefenseEvasion,
                vec![MitreAttackId::new("T1014").expect("valid id")],
                0.6f64,
            )
        } else {
            (Severity::Info, Finding::Other("module_enumerated".into()), vec![], 0.3f64)
        };

        vec![ForensicEvent::builder()
            .source_walker("linux_module")
            .entity(Entity::Module { name: self.name.clone(), base: self.base_addr, size: self.size })
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
    use crate::types::{ConnectionState, Protocol as LinuxProtocol, VmaFlags};

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

    // -----------------------------------------------------------------------
    // ProcessInfo tests
    // -----------------------------------------------------------------------

    fn make_process(pid: u64, ppid: u64, comm: &str, state: ProcessState, cr3: Option<u64>) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            comm: comm.to_string(),
            state,
            vaddr: 0xffff_8880_0000_0000,
            cr3,
            start_time: 12_345_678,
        }
    }

    #[test]
    fn zombie_process_is_medium_defense_evasion() {
        let p = make_process(1234, 1, "defunct", ProcessState::Zombie, Some(0x1000));
        let events = p.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Medium);
        assert!(matches!(events[0].finding, Finding::DefenseEvasion));
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1564"), "expected T1564, got {ids:?}");
        assert!((events[0].confidence - 0.7).abs() < 1e-9);
    }

    #[test]
    fn empty_comm_is_high_severity() {
        let p = make_process(999, 1, "", ProcessState::Running, Some(0x2000));
        let events = p.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::High);
        assert!(matches!(events[0].finding, Finding::DefenseEvasion));
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1564"), "expected T1564, got {ids:?}");
        assert!((events[0].confidence - 0.9).abs() < 1e-9);
    }

    #[test]
    fn normal_process_is_info() {
        let p = make_process(42, 1, "bash", ProcessState::Running, Some(0x3000));
        let events = p.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Info);
    }

    #[test]
    fn process_entity_has_correct_pid_ppid_comm() {
        let p = make_process(77, 5, "sshd", ProcessState::Sleeping, Some(0x4000));
        let events = p.into_forensic_events();
        assert_eq!(events[0].source_walker, "linux_process");
        match &events[0].entity {
            Entity::Process { pid, name, ppid } => {
                assert_eq!(*pid, 77u32);
                assert_eq!(name, "sshd");
                assert_eq!(*ppid, Some(5u32));
            }
            other => panic!("expected Process entity, got {other:?}"),
        }
    }

    #[test]
    fn info_process_is_not_suspicious() {
        let p = make_process(100, 1, "nginx", ProcessState::Sleeping, Some(0x5000));
        let events = p.into_forensic_events();
        assert!(!events[0].is_suspicious());
    }

    // -----------------------------------------------------------------------
    // ConnectionInfo tests
    // -----------------------------------------------------------------------

    fn make_conn(remote_addr: &str, remote_port: u16, pid: Option<u64>) -> ConnectionInfo {
        ConnectionInfo {
            protocol: LinuxProtocol::Tcp,
            local_addr: "192.168.1.10".to_string(),
            local_port: 54321,
            remote_addr: remote_addr.to_string(),
            remote_port,
            state: ConnectionState::Established,
            pid,
        }
    }

    #[test]
    fn c2_port_connection_is_high_beaconing() {
        for port in [4444u16, 1337, 31337] {
            let c = make_conn("10.0.0.1", port, Some(100));
            let events = c.into_forensic_events();
            assert_eq!(events.len(), 1, "port {port}");
            assert_eq!(events[0].severity, Severity::High, "port {port}");
            assert!(matches!(events[0].finding, Finding::NetworkBeaconing), "port {port}");
            let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
            assert!(ids.contains(&"T1071"), "expected T1071 for port {port}, got {ids:?}");
            assert!((events[0].confidence - 0.8).abs() < 1e-9, "port {port}");
        }
    }

    #[test]
    fn no_owning_pid_is_high_defense_evasion() {
        let c = make_conn("8.8.8.8", 443, None);
        let events = c.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::High);
        assert!(matches!(events[0].finding, Finding::DefenseEvasion));
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1095"), "expected T1095, got {ids:?}");
        assert!((events[0].confidence - 0.85).abs() < 1e-9);
    }

    #[test]
    fn normal_connection_is_info() {
        let c = make_conn("93.184.216.34", 443, Some(200));
        let events = c.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Info);
        assert!(matches!(events[0].finding, Finding::Other(_)));
    }

    #[test]
    fn connection_entity_has_correct_src_dst() {
        let c = make_conn("10.0.0.1", 4444, Some(42));
        let events = c.into_forensic_events();
        assert_eq!(events[0].source_walker, "linux_connection");
        match &events[0].entity {
            Entity::Connection { src, dst, .. } => {
                assert_eq!(src.port(), 54321);
                assert_eq!(dst.port(), 4444);
                assert_eq!(dst.ip().to_string(), "10.0.0.1");
            }
            other => panic!("expected Connection entity, got {other:?}"),
        }
    }

    #[test]
    fn hidden_connection_is_suspicious() {
        let c = make_conn("8.8.8.8", 443, None);
        let events = c.into_forensic_events();
        assert!(events[0].is_suspicious());
    }

    // -----------------------------------------------------------------------
    // ModuleInfo tests
    // -----------------------------------------------------------------------

    fn make_module(name: &str, state: ModuleState) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            base_addr: 0xffff_c000_0000_0000,
            size: 0x4000,
            state,
        }
    }

    #[test]
    fn live_named_module_is_info() {
        let m = make_module("ext4", ModuleState::Live);
        let events = m.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Info);
    }

    #[test]
    fn going_state_module_is_medium_defense_evasion() {
        // MODULE_STATE_GOING during scan — possible unload-to-hide evasion (T1014)
        let m = make_module("rootkit", ModuleState::Going);
        let events = m.into_forensic_events();
        assert_eq!(events[0].severity, Severity::Medium);
        assert!(matches!(events[0].finding, Finding::DefenseEvasion));
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1014"), "expected T1014");
    }

    #[test]
    fn empty_name_module_is_high() {
        // Blank module name — hidden kernel module (T1014)
        let m = make_module("", ModuleState::Live);
        let events = m.into_forensic_events();
        assert_eq!(events[0].severity, Severity::High);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1014"), "expected T1014");
    }

    #[test]
    fn module_source_walker_is_linux_module() {
        let m = make_module("xfs", ModuleState::Live);
        let events = m.into_forensic_events();
        assert_eq!(events[0].source_walker, "linux_module");
    }
}
