//! [`IntoForensicEvents`] implementations for Linux walker output types.

use memf_correlate::event::{Entity, Finding, ForensicEvent, Severity};
use memf_correlate::mitre::MitreAttackId;
use memf_correlate::traits::IntoForensicEvents;

use crate::types::{
    AuditTamperInfo, ConnectionInfo, ContainerEscapeCorrelateInfo, CpuPinningInfo, FdAbuseInfo,
    FdAbuseType, FuseAbuseInfo, HiddenProcessInfo, ModuleInfo, ModuleState, ProcessInfo,
    ProcessState, SharedMemAnomalyInfo, UserNsEscalationInfo, VdsoTamperInfo, VmaInfo,
};

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

// ---------------------------------------------------------------------------
// Batch 1: proc_hidden, vdso_tamper, user_ns_escalation, netlink_audit, cpu_pinning
// ---------------------------------------------------------------------------

impl IntoForensicEvents for HiddenProcessInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        let (severity, finding, mitre, confidence) =
            if self.present_in_pid_ns && !self.present_in_task_list {
                // Visible in PID namespace but not in task list — classic DKOM rootkit (T1014)
                (
                    Severity::Critical,
                    Finding::DefenseEvasion,
                    vec![MitreAttackId::new("T1014").expect("valid id")],
                    0.95f64,
                )
            } else if self.present_in_pid_hash && !self.present_in_task_list {
                // In PID hash but not task list — partial DKOM (T1014)
                (
                    Severity::High,
                    Finding::DefenseEvasion,
                    vec![MitreAttackId::new("T1014").expect("valid id")],
                    0.85f64,
                )
            } else if self.present_in_task_list && !self.present_in_pid_ns {
                // In task list but not PID namespace — namespace hiding (T1014)
                (
                    Severity::High,
                    Finding::DefenseEvasion,
                    vec![MitreAttackId::new("T1014").expect("valid id")],
                    0.8f64,
                )
            } else {
                (Severity::Info, Finding::Other("process_enumerated".into()), vec![], 0.3f64)
            };

        vec![ForensicEvent::builder()
            .source_walker("linux_proc_hidden")
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

impl IntoForensicEvents for VdsoTamperInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        let (severity, finding, mitre, confidence) =
            if self.differs_from_canonical && self.diff_byte_count > 16 {
                // Large vDSO diff — likely patched syscall stubs (T1055)
                (
                    Severity::Critical,
                    Finding::ProcessHollowing,
                    vec![MitreAttackId::new("T1055").expect("valid id")],
                    0.95f64,
                )
            } else if self.differs_from_canonical {
                // Small vDSO diff — possible targeted patch (T1055)
                (
                    Severity::High,
                    Finding::DefenseEvasion,
                    vec![MitreAttackId::new("T1055").expect("valid id")],
                    0.8f64,
                )
            } else {
                (Severity::Info, Finding::Other("vdso_clean".into()), vec![], 0.3f64)
            };

        vec![ForensicEvent::builder()
            .source_walker("linux_vdso_tamper")
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

impl IntoForensicEvents for UserNsEscalationInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        let (severity, finding, mitre, confidence) =
            if self.has_cap_sys_admin && self.owner_uid != self.process_uid {
                // CAP_SYS_ADMIN mapped for a different UID — privilege escalation (T1611)
                (
                    Severity::Critical,
                    Finding::DefenseEvasion,
                    vec![MitreAttackId::new("T1611").expect("valid id")],
                    0.9f64,
                )
            } else if self.ns_depth > 3 {
                // Deeply nested user namespace — evasion technique (T1611)
                (
                    Severity::High,
                    Finding::DefenseEvasion,
                    vec![MitreAttackId::new("T1611").expect("valid id")],
                    0.7f64,
                )
            } else if self.has_cap_sys_admin && self.owner_uid == 0 {
                // Root-owned namespace with CAP_SYS_ADMIN (T1548)
                (
                    Severity::Medium,
                    Finding::DefenseEvasion,
                    vec![MitreAttackId::new("T1548").expect("valid id")],
                    0.6f64,
                )
            } else {
                (Severity::Info, Finding::Other("user_ns_enumerated".into()), vec![], 0.3f64)
            };

        vec![ForensicEvent::builder()
            .source_walker("linux_user_ns")
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

impl IntoForensicEvents for AuditTamperInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        let (severity, finding, mitre, confidence) = if self.audit_globally_disabled {
            // Audit subsystem globally disabled — Defense Evasion (T1562)
            (
                Severity::Critical,
                Finding::DefenseEvasion,
                vec![MitreAttackId::new("T1562").expect("valid id")],
                0.95f64,
            )
        } else if !self.suppressed_pids.is_empty() {
            // PIDs excluded from auditing — targeted evasion (T1562)
            (
                Severity::High,
                Finding::DefenseEvasion,
                vec![MitreAttackId::new("T1562").expect("valid id")],
                0.85f64,
            )
        } else if self.backlog_limit < 64 {
            // Very low backlog limit — audit log flooding / evasion (T1562)
            (
                Severity::Medium,
                Finding::DefenseEvasion,
                vec![MitreAttackId::new("T1562").expect("valid id")],
                0.6f64,
            )
        } else {
            (Severity::Info, Finding::Other("audit_enumerated".into()), vec![], 0.3f64)
        };

        vec![ForensicEvent::builder()
            .source_walker("linux_netlink_audit")
            .entity(Entity::File { path: "kernel:audit".into() })
            .finding(finding)
            .severity(severity)
            .confidence(confidence)
            .mitre_attack(mitre)
            .build()]
    }
}

impl IntoForensicEvents for CpuPinningInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        let (severity, finding, mitre, confidence) =
            if self.pinned_cpu_count == 1 && self.cpu_time_ns > 1_000_000_000 {
                // Single CPU affinity with high CPU consumption — cryptominer pattern (T1496)
                (
                    Severity::High,
                    Finding::Other("cryptomining_suspected".into()),
                    vec![MitreAttackId::new("T1496").expect("valid id")],
                    0.8f64,
                )
            } else if self.sched_policy == 3 || self.sched_policy == 5 {
                // SCHED_BATCH or SCHED_IDLE — stealth scheduling (T1496)
                (
                    Severity::Medium,
                    Finding::Other("stealth_scheduling".into()),
                    vec![MitreAttackId::new("T1496").expect("valid id")],
                    0.5f64,
                )
            } else {
                (Severity::Info, Finding::Other("cpu_pinning_enumerated".into()), vec![], 0.3f64)
            };

        vec![ForensicEvent::builder()
            .source_walker("linux_cpu_pinning")
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

// ---------------------------------------------------------------------------
// Batch 2: container_escape, timerfd_signalfd, shared_mem_anomaly, fuse_abuse
// ---------------------------------------------------------------------------

impl IntoForensicEvents for ContainerEscapeCorrelateInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        let (severity, finding, mitre, confidence) =
            if self.has_host_mounts && self.in_non_init_pid_ns {
                // Host filesystem mounts visible from within a container (T1611)
                (
                    Severity::Critical,
                    Finding::DefenseEvasion,
                    vec![MitreAttackId::new("T1611").expect("valid id")],
                    0.9f64,
                )
            } else if self.cap_sys_admin && self.in_non_init_pid_ns {
                // CAP_SYS_ADMIN inside a container namespace (T1611)
                (
                    Severity::High,
                    Finding::DefenseEvasion,
                    vec![MitreAttackId::new("T1611").expect("valid id")],
                    0.8f64,
                )
            } else if self.pid_ns_differs_from_cgroup_ns {
                // PID/cgroup namespace mismatch — suspicious escape attempt (T1611)
                (
                    Severity::High,
                    Finding::DefenseEvasion,
                    vec![MitreAttackId::new("T1611").expect("valid id")],
                    0.75f64,
                )
            } else {
                (Severity::Info, Finding::Other("container_enumerated".into()), vec![], 0.3f64)
            };

        vec![ForensicEvent::builder()
            .source_walker("linux_container_escape")
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

impl IntoForensicEvents for FdAbuseInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        let (severity, finding, mitre, confidence) =
            if self.fd_type == FdAbuseType::SignalFd && self.signal_mask & (1u64 << 15) != 0 {
                // signalfd intercepting SIGTERM — Defense Evasion (T1205)
                (
                    Severity::High,
                    Finding::DefenseEvasion,
                    vec![MitreAttackId::new("T1205").expect("valid id")],
                    0.8f64,
                )
            } else if self.fd_type == FdAbuseType::TimerFd && self.interval_ns < 1_000_000_000 {
                // Sub-second timerfd interval — potential beaconing (T1071)
                (
                    Severity::Medium,
                    Finding::NetworkBeaconing,
                    vec![MitreAttackId::new("T1071").expect("valid id")],
                    0.5f64,
                )
            } else if self.is_cross_process_shared {
                // Cross-process fd sharing — covert channel (T1071)
                (
                    Severity::Medium,
                    Finding::DefenseEvasion,
                    vec![MitreAttackId::new("T1071").expect("valid id")],
                    0.6f64,
                )
            } else {
                (Severity::Info, Finding::Other("fd_enumerated".into()), vec![], 0.3f64)
            };

        vec![ForensicEvent::builder()
            .source_walker("linux_timerfd_signalfd")
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

impl IntoForensicEvents for SharedMemAnomalyInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        let (severity, finding, mitre, confidence) =
            if self.is_memfd && self.is_executable {
                // Executable memfd — in-memory code execution (T1027)
                (
                    Severity::Critical,
                    Finding::ProcessHollowing,
                    vec![MitreAttackId::new("T1027").expect("valid id")],
                    0.9f64,
                )
            } else if self.has_elf_header && self.is_executable {
                // Executable shared region with ELF header — process injection (T1055)
                (
                    Severity::High,
                    Finding::ProcessHollowing,
                    vec![MitreAttackId::new("T1055").expect("valid id")],
                    0.85f64,
                )
            } else if self.is_cross_uid {
                // Cross-UID shared memory — possible privilege escalation vector (T1055)
                (
                    Severity::Medium,
                    Finding::DefenseEvasion,
                    vec![MitreAttackId::new("T1055").expect("valid id")],
                    0.6f64,
                )
            } else {
                (Severity::Info, Finding::Other("shared_mem_enumerated".into()), vec![], 0.3f64)
            };

        vec![ForensicEvent::builder()
            .source_walker("linux_shared_mem")
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

impl IntoForensicEvents for FuseAbuseInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        let (severity, finding, mitre, confidence) = if self.is_over_sensitive_path {
            // FUSE mounted over /proc, /sys, /etc — Hide Artifacts (T1564)
            (
                Severity::High,
                Finding::DefenseEvasion,
                vec![MitreAttackId::new("T1564").expect("valid id")],
                0.9f64,
            )
        } else if self.daemon_is_root && self.allow_other {
            // Root FUSE daemon with allow_other — privilege escalation risk (T1564)
            (
                Severity::Medium,
                Finding::DefenseEvasion,
                vec![MitreAttackId::new("T1564").expect("valid id")],
                0.6f64,
            )
        } else {
            (Severity::Info, Finding::Other("fuse_mount_enumerated".into()), vec![], 0.3f64)
        };

        vec![ForensicEvent::builder()
            .source_walker("linux_fuse")
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

    // -----------------------------------------------------------------------
    // HiddenProcessInfo tests
    // -----------------------------------------------------------------------

    fn make_hidden_process(
        pid: u64,
        comm: &str,
        present_in_pid_ns: bool,
        present_in_task_list: bool,
        present_in_pid_hash: bool,
    ) -> HiddenProcessInfo {
        HiddenProcessInfo {
            pid,
            comm: comm.to_string(),
            present_in_pid_ns,
            present_in_task_list,
            present_in_pid_hash,
        }
    }

    #[test]
    fn pid_ns_only_process_is_critical_rootkit() {
        let h = make_hidden_process(1234, "rootkit", true, false, false);
        let events = h.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Critical);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1014"), "expected T1014, got {ids:?}");
        assert!((events[0].confidence - 0.95).abs() < 1e-9);
        assert!(matches!(events[0].finding, Finding::DefenseEvasion));
    }

    #[test]
    fn task_list_only_process_is_high() {
        let h = make_hidden_process(999, "ghost", false, true, false);
        let events = h.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::High);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1014"), "expected T1014, got {ids:?}");
        assert!((events[0].confidence - 0.8).abs() < 1e-9);
    }

    #[test]
    fn pid_hash_without_task_list_is_high() {
        let h = make_hidden_process(555, "hidden", false, false, true);
        let events = h.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::High);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1014"), "expected T1014, got {ids:?}");
        assert!((events[0].confidence - 0.85).abs() < 1e-9);
    }

    #[test]
    fn all_structures_present_is_info() {
        let h = make_hidden_process(100, "normal", true, true, true);
        let events = h.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Info);
    }

    #[test]
    fn source_walker_is_linux_proc_hidden() {
        let h = make_hidden_process(1, "init", true, true, true);
        let events = h.into_forensic_events();
        assert_eq!(events[0].source_walker, "linux_proc_hidden");
    }

    // -----------------------------------------------------------------------
    // VdsoTamperInfo tests
    // -----------------------------------------------------------------------

    fn make_vdso(
        pid: u64,
        comm: &str,
        differs: bool,
        diff_byte_count: usize,
    ) -> VdsoTamperInfo {
        VdsoTamperInfo {
            pid,
            comm: comm.to_string(),
            vdso_base: 0x7fff_f000_0000,
            vdso_size: 0x2000,
            differs_from_canonical: differs,
            diff_byte_count,
        }
    }

    #[test]
    fn large_vdso_diff_is_critical() {
        let v = make_vdso(1234, "evil", true, 32);
        let events = v.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Critical);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1055"), "expected T1055, got {ids:?}");
        assert!((events[0].confidence - 0.95).abs() < 1e-9);
        assert!(matches!(events[0].finding, Finding::ProcessHollowing));
    }

    #[test]
    fn small_vdso_diff_is_high() {
        let v = make_vdso(2345, "sneaky", true, 8);
        let events = v.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::High);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1055"), "expected T1055, got {ids:?}");
        assert!((events[0].confidence - 0.8).abs() < 1e-9);
        assert!(matches!(events[0].finding, Finding::DefenseEvasion));
    }

    #[test]
    fn clean_vdso_is_info() {
        let v = make_vdso(42, "bash", false, 0);
        let events = v.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Info);
    }

    #[test]
    fn tampered_vdso_has_t1055() {
        let v = make_vdso(77, "sshd", true, 100);
        let events = v.into_forensic_events();
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1055"), "expected T1055 for tampered vDSO, got {ids:?}");
    }

    #[test]
    fn source_walker_is_linux_vdso_tamper() {
        let v = make_vdso(1, "init", false, 0);
        let events = v.into_forensic_events();
        assert_eq!(events[0].source_walker, "linux_vdso_tamper");
    }

    // -----------------------------------------------------------------------
    // UserNsEscalationInfo tests
    // -----------------------------------------------------------------------

    fn make_user_ns(
        pid: u64,
        comm: &str,
        ns_depth: u32,
        owner_uid: u32,
        process_uid: u32,
        has_cap_sys_admin: bool,
    ) -> UserNsEscalationInfo {
        UserNsEscalationInfo {
            pid,
            comm: comm.to_string(),
            ns_depth,
            owner_uid,
            process_uid,
            has_cap_sys_admin,
            is_suspicious: false,
        }
    }

    #[test]
    fn cap_sys_admin_with_different_uid_is_critical() {
        let u = make_user_ns(1234, "evil", 1, 0, 1000, true);
        let events = u.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Critical);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1611"), "expected T1611, got {ids:?}");
        assert!((events[0].confidence - 0.9).abs() < 1e-9);
    }

    #[test]
    fn deep_namespace_nesting_is_high() {
        let u = make_user_ns(555, "nested", 5, 1000, 1000, false);
        let events = u.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::High);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1611"), "expected T1611, got {ids:?}");
        assert!((events[0].confidence - 0.7).abs() < 1e-9);
    }

    #[test]
    fn root_owned_cap_admin_is_medium() {
        // owner_uid == 0 && has_cap_sys_admin && owner_uid == process_uid → Medium T1548
        let u = make_user_ns(777, "daemon", 1, 0, 0, true);
        let events = u.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Medium);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1548"), "expected T1548, got {ids:?}");
        assert!((events[0].confidence - 0.6).abs() < 1e-9);
    }

    #[test]
    fn normal_namespace_is_info() {
        let u = make_user_ns(100, "bash", 1, 1000, 1000, false);
        let events = u.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Info);
    }

    #[test]
    fn source_walker_is_linux_user_ns() {
        let u = make_user_ns(1, "init", 0, 0, 0, false);
        let events = u.into_forensic_events();
        assert_eq!(events[0].source_walker, "linux_user_ns");
    }

    // -----------------------------------------------------------------------
    // AuditTamperInfo tests
    // -----------------------------------------------------------------------

    fn make_audit(
        audit_enabled: bool,
        backlog_limit: u32,
        suppressed_pids: Vec<u64>,
        audit_globally_disabled: bool,
    ) -> AuditTamperInfo {
        AuditTamperInfo {
            audit_enabled,
            backlog_limit,
            suppressed_pids,
            suppressed_uids: vec![],
            audit_globally_disabled,
        }
    }

    #[test]
    fn globally_disabled_audit_is_critical() {
        let a = make_audit(false, 256, vec![], true);
        let events = a.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Critical);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1562"), "expected T1562, got {ids:?}");
        assert!((events[0].confidence - 0.95).abs() < 1e-9);
    }

    #[test]
    fn suppressed_pid_is_high() {
        let a = make_audit(true, 256, vec![1234], false);
        let events = a.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::High);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1562"), "expected T1562, got {ids:?}");
        assert!((events[0].confidence - 0.85).abs() < 1e-9);
    }

    #[test]
    fn low_backlog_limit_is_medium() {
        let a = make_audit(true, 32, vec![], false);
        let events = a.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Medium);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1562"), "expected T1562, got {ids:?}");
        assert!((events[0].confidence - 0.6).abs() < 1e-9);
    }

    #[test]
    fn normal_audit_is_info() {
        let a = make_audit(true, 256, vec![], false);
        let events = a.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Info);
    }

    #[test]
    fn source_walker_is_linux_netlink_audit() {
        let a = make_audit(true, 256, vec![], false);
        let events = a.into_forensic_events();
        assert_eq!(events[0].source_walker, "linux_netlink_audit");
    }

    // -----------------------------------------------------------------------
    // CpuPinningInfo tests
    // -----------------------------------------------------------------------

    fn make_cpu_pinning(
        pid: u64,
        comm: &str,
        pinned_cpu_count: u32,
        total_cpu_count: u32,
        sched_policy: u32,
        cpu_time_ns: u64,
    ) -> CpuPinningInfo {
        CpuPinningInfo {
            pid,
            comm: comm.to_string(),
            pinned_cpu_count,
            total_cpu_count,
            sched_policy,
            cpu_time_ns,
        }
    }

    #[test]
    fn single_cpu_pinned_with_high_cpu_time_is_high() {
        let c = make_cpu_pinning(1234, "miner", 1, 8, 0, 2_000_000_000);
        let events = c.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::High);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1496"), "expected T1496, got {ids:?}");
        assert!((events[0].confidence - 0.8).abs() < 1e-9);
    }

    #[test]
    fn batch_scheduling_is_medium() {
        let c = make_cpu_pinning(2345, "bgworker", 4, 8, 3, 100_000_000);
        let events = c.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Medium);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1496"), "expected T1496, got {ids:?}");
        assert!((events[0].confidence - 0.5).abs() < 1e-9);
    }

    #[test]
    fn normal_process_is_info_cpu() {
        let c = make_cpu_pinning(42, "bash", 4, 8, 0, 50_000_000);
        let events = c.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Info);
    }

    #[test]
    fn source_walker_is_linux_cpu_pinning() {
        let c = make_cpu_pinning(1, "init", 4, 8, 0, 0);
        let events = c.into_forensic_events();
        assert_eq!(events[0].source_walker, "linux_cpu_pinning");
    }

    // -----------------------------------------------------------------------
    // ContainerEscapeCorrelateInfo tests
    // -----------------------------------------------------------------------

    fn make_container_escape(
        pid: u64,
        comm: &str,
        pid_ns_differs_from_cgroup_ns: bool,
        has_host_mounts: bool,
        cap_sys_admin: bool,
        in_non_init_pid_ns: bool,
    ) -> ContainerEscapeCorrelateInfo {
        ContainerEscapeCorrelateInfo {
            pid,
            comm: comm.to_string(),
            pid_ns_differs_from_cgroup_ns,
            has_host_mounts,
            cap_sys_admin,
            cap_sys_ptrace: false,
            in_non_init_pid_ns,
        }
    }

    #[test]
    fn host_mounts_in_container_is_critical() {
        let c = make_container_escape(1234, "evil", false, true, false, true);
        let events = c.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Critical);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1611"), "expected T1611, got {ids:?}");
        assert!((events[0].confidence - 0.9).abs() < 1e-9);
    }

    #[test]
    fn cap_sys_admin_in_container_is_high() {
        let c = make_container_escape(2345, "priv", false, false, true, true);
        let events = c.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::High);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1611"), "expected T1611, got {ids:?}");
        assert!((events[0].confidence - 0.8).abs() < 1e-9);
    }

    #[test]
    fn pid_cgroup_ns_mismatch_is_high() {
        let c = make_container_escape(3456, "ns_mismatch", true, false, false, false);
        let events = c.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::High);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1611"), "expected T1611, got {ids:?}");
        assert!((events[0].confidence - 0.75).abs() < 1e-9);
    }

    #[test]
    fn normal_container_process_is_info() {
        let c = make_container_escape(100, "nginx", false, false, false, true);
        let events = c.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Info);
    }

    #[test]
    fn source_walker_is_linux_container_escape() {
        let c = make_container_escape(1, "init", false, false, false, false);
        let events = c.into_forensic_events();
        assert_eq!(events[0].source_walker, "linux_container_escape");
    }

    // -----------------------------------------------------------------------
    // FdAbuseInfo tests
    // -----------------------------------------------------------------------

    fn make_fd_abuse(
        pid: u64,
        comm: &str,
        fd_type: FdAbuseType,
        signal_mask: u64,
        interval_ns: u64,
        is_cross_process_shared: bool,
    ) -> FdAbuseInfo {
        FdAbuseInfo {
            pid,
            comm: comm.to_string(),
            fd_type,
            signal_mask,
            interval_ns,
            is_cross_process_shared,
        }
    }

    #[test]
    fn sigterm_intercepting_signalfd_is_high() {
        // SIGTERM = signal 15, bit 15 = 1u64 << 15
        let f = make_fd_abuse(1234, "evil", FdAbuseType::SignalFd, 1u64 << 15, 0, false);
        let events = f.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::High);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1205"), "expected T1205, got {ids:?}");
        assert!((events[0].confidence - 0.8).abs() < 1e-9);
    }

    #[test]
    fn subsecond_timerfd_is_medium() {
        let f = make_fd_abuse(2345, "beacon", FdAbuseType::TimerFd, 0, 500_000_000, false);
        let events = f.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Medium);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1071"), "expected T1071, got {ids:?}");
        assert!((events[0].confidence - 0.5).abs() < 1e-9);
    }

    #[test]
    fn cross_process_eventfd_is_medium() {
        let f = make_fd_abuse(3456, "shared", FdAbuseType::EventFd, 0, 5_000_000_000, true);
        let events = f.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Medium);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1071"), "expected T1071, got {ids:?}");
        assert!((events[0].confidence - 0.6).abs() < 1e-9);
    }

    #[test]
    fn normal_timerfd_is_info() {
        let f = make_fd_abuse(42, "cron", FdAbuseType::TimerFd, 0, 60_000_000_000, false);
        let events = f.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Info);
    }

    #[test]
    fn source_walker_is_linux_timerfd_signalfd() {
        let f = make_fd_abuse(1, "init", FdAbuseType::TimerFd, 0, 0, false);
        let events = f.into_forensic_events();
        assert_eq!(events[0].source_walker, "linux_timerfd_signalfd");
    }

    // -----------------------------------------------------------------------
    // SharedMemAnomalyInfo tests
    // -----------------------------------------------------------------------

    fn make_shared_mem(
        pid: u64,
        comm: &str,
        is_memfd: bool,
        is_executable: bool,
        is_cross_uid: bool,
        has_elf_header: bool,
    ) -> SharedMemAnomalyInfo {
        SharedMemAnomalyInfo {
            pid,
            comm: comm.to_string(),
            shm_base: 0x7f00_0000_0000,
            shm_size: 0x1000,
            is_memfd,
            is_executable,
            is_cross_uid,
            has_elf_header,
        }
    }

    #[test]
    fn executable_memfd_is_critical() {
        let s = make_shared_mem(1234, "loader", true, true, false, false);
        let events = s.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Critical);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1027"), "expected T1027, got {ids:?}");
        assert!((events[0].confidence - 0.9).abs() < 1e-9);
        assert!(matches!(events[0].finding, Finding::ProcessHollowing));
    }

    #[test]
    fn executable_region_with_elf_header_is_high() {
        let s = make_shared_mem(2345, "injector", false, true, false, true);
        let events = s.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::High);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1055"), "expected T1055, got {ids:?}");
        assert!((events[0].confidence - 0.85).abs() < 1e-9);
        assert!(matches!(events[0].finding, Finding::ProcessHollowing));
    }

    #[test]
    fn cross_uid_shared_mem_is_medium() {
        let s = make_shared_mem(3456, "ipc", false, false, true, false);
        let events = s.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Medium);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1055"), "expected T1055, got {ids:?}");
        assert!((events[0].confidence - 0.6).abs() < 1e-9);
        assert!(matches!(events[0].finding, Finding::DefenseEvasion));
    }

    #[test]
    fn normal_shared_mem_is_info() {
        let s = make_shared_mem(42, "postgres", false, false, false, false);
        let events = s.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Info);
    }

    #[test]
    fn source_walker_is_linux_shared_mem() {
        let s = make_shared_mem(1, "init", false, false, false, false);
        let events = s.into_forensic_events();
        assert_eq!(events[0].source_walker, "linux_shared_mem");
    }

    // -----------------------------------------------------------------------
    // FuseAbuseInfo tests
    // -----------------------------------------------------------------------

    fn make_fuse(
        pid: u64,
        comm: &str,
        mount_point: &str,
        is_over_sensitive_path: bool,
        daemon_is_root: bool,
        allow_other: bool,
    ) -> FuseAbuseInfo {
        FuseAbuseInfo {
            pid,
            comm: comm.to_string(),
            mount_point: mount_point.to_string(),
            is_over_sensitive_path,
            daemon_is_root,
            allow_other,
        }
    }

    #[test]
    fn fuse_over_sensitive_path_is_high() {
        let f = make_fuse(1234, "fusermount", "/proc", true, false, false);
        let events = f.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::High);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1564"), "expected T1564, got {ids:?}");
        assert!((events[0].confidence - 0.9).abs() < 1e-9);
    }

    #[test]
    fn root_fuse_with_allow_other_is_medium() {
        let f = make_fuse(2345, "sshfs", "/mnt/data", false, true, true);
        let events = f.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Medium);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1564"), "expected T1564, got {ids:?}");
        assert!((events[0].confidence - 0.6).abs() < 1e-9);
    }

    #[test]
    fn normal_fuse_mount_is_info() {
        let f = make_fuse(42, "sshfs", "/home/user/remote", false, false, false);
        let events = f.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Info);
    }

    #[test]
    fn source_walker_is_linux_fuse() {
        let f = make_fuse(1, "fusermount", "/mnt", false, false, false);
        let events = f.into_forensic_events();
        assert_eq!(events[0].source_walker, "linux_fuse");
    }
}
