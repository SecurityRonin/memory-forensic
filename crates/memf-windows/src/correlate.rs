//! [`IntoForensicEvents`] implementations for Windows walker output types.

use memf_correlate::event::{Entity, Finding, ForensicEvent, Severity};
use memf_correlate::mitre::MitreAttackId;
use memf_correlate::traits::IntoForensicEvents;

use crate::types::{WinConnectionInfo, WinDriverInfo, WinHollowingInfo, WinMalfindInfo, WinProcessInfo, WinTokenInfo};

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

impl IntoForensicEvents for WinDriverInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        let suspicious_path = self.full_path.is_empty()
            || (!self.full_path.starts_with("\\SystemRoot\\")
                && !self.full_path.starts_with("\\Windows\\"));

        let (severity, finding, confidence) = if suspicious_path {
            (Severity::High, Finding::DefenseEvasion, 0.85f64)
        } else {
            (Severity::Info, Finding::Other("driver_loaded".into()), 0.5f64)
        };

        let mitre = if suspicious_path {
            vec![MitreAttackId::new("T1014").expect("valid id")]
        } else {
            vec![]
        };

        vec![ForensicEvent::builder()
            .source_walker("win_driver")
            .entity(Entity::Driver {
                name: self.name.clone(),
                base: self.base_addr,
            })
            .finding(finding)
            .severity(severity)
            .confidence(confidence)
            .mitre_attack(mitre)
            .build()]
    }
}

impl IntoForensicEvents for WinMalfindInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        let has_execute = self.protection_str.contains("EXECUTE");
        let has_mz = self.first_bytes.starts_with(&[0x4D, 0x5A]);

        let (severity, finding, confidence) = if has_execute && has_mz {
            (Severity::Critical, Finding::ProcessHollowing, 0.95f64)
        } else if has_execute {
            (Severity::High, Finding::ProcessHollowing, 0.8f64)
        } else {
            (Severity::Info, Finding::Other("vad_region".into()), 0.4f64)
        };

        let mitre = if has_execute {
            vec![MitreAttackId::new("T1055").expect("valid id")]
        } else {
            vec![]
        };

        vec![ForensicEvent::builder()
            .source_walker("win_malfind")
            .entity(Entity::Process {
                pid: self.pid as u32,
                name: self.image_name.clone(),
                ppid: None,
            })
            .finding(finding)
            .severity(severity)
            .confidence(confidence)
            .mitre_attack(mitre)
            .build()]
    }
}

impl IntoForensicEvents for WinHollowingInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        let (severity, finding, confidence) = if self.suspicious {
            (Severity::Critical, Finding::ProcessHollowing, 0.9f64)
        } else if !self.has_mz || !self.has_pe {
            (Severity::Medium, Finding::DefenseEvasion, 0.65f64)
        } else {
            (Severity::Info, Finding::Other("process_checked".into()), 0.5f64)
        };

        let mitre = if self.suspicious || !self.has_mz || !self.has_pe {
            vec![MitreAttackId::new("T1055").expect("valid id")]
        } else {
            vec![]
        };

        vec![ForensicEvent::builder()
            .source_walker("win_hollowing")
            .entity(Entity::Process {
                pid: self.pid as u32,
                name: self.image_name.clone(),
                ppid: None,
            })
            .finding(finding)
            .severity(severity)
            .confidence(confidence)
            .mitre_attack(mitre)
            .build()]
    }
}

impl IntoForensicEvents for WinConnectionInfo {
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
            } else if self.pid == 0 {
                // No owning process — hidden connection (T1095)
                (
                    Severity::High,
                    Finding::DefenseEvasion,
                    vec![MitreAttackId::new("T1095").expect("valid id")],
                    0.85f64,
                )
            } else if self.remote_port == 0 && !is_loopback {
                // Port 0 with non-loopback remote — suspicious (T1071)
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
            .source_walker("windows_connection")
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

impl IntoForensicEvents for WinTokenInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        const SE_DEBUG_PRIVILEGE: u64 = 1 << 20;

        let (severity, finding, mitre, confidence) =
            if self.privileges_enabled & SE_DEBUG_PRIVILEGE != 0 {
                // SeDebugPrivilege enabled — token manipulation (T1134)
                (
                    Severity::High,
                    Finding::DefenseEvasion,
                    vec![MitreAttackId::new("T1134").expect("valid id")],
                    0.85f64,
                )
            } else if self.user_sid == "S-1-5-18" && self.pid != 4 {
                // SYSTEM SID in non-System process — privilege escalation (T1078)
                (
                    Severity::High,
                    Finding::DefenseEvasion,
                    vec![MitreAttackId::new("T1078").expect("valid id")],
                    0.9f64,
                )
            } else {
                (Severity::Info, Finding::Other("token_enumerated".into()), vec![], 0.4f64)
            };

        vec![ForensicEvent::builder()
            .source_walker("windows_token")
            .entity(Entity::Process {
                pid: self.pid as u32,
                name: self.image_name.clone(),
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

    // ── WinDriverInfo tests ────────────────────────────────────────────────

    fn make_driver(name: &str, full_path: &str, base_addr: u64) -> WinDriverInfo {
        WinDriverInfo {
            name: name.to_string(),
            full_path: full_path.to_string(),
            base_addr,
            size: 0x1000,
            vaddr: 0xFFFF_8000_1234_0000,
        }
    }

    #[test]
    fn unknown_path_driver_produces_high_severity() {
        let driver = make_driver("evil.sys", "\\Device\\HarddiskVolume3\\evil.sys", 0xFFFF_8001_0000);
        let events = driver.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::High);
        assert!(matches!(events[0].finding, Finding::DefenseEvasion));
        assert_eq!(events[0].mitre_attack[0].as_str(), "T1014");
        assert!((events[0].confidence - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn empty_path_driver_produces_high_severity() {
        let driver = make_driver("mystery.sys", "", 0xFFFF_8002_0000);
        let events = driver.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::High);
        assert!(matches!(events[0].finding, Finding::DefenseEvasion));
        assert_eq!(events[0].mitre_attack[0].as_str(), "T1014");
    }

    #[test]
    fn system_root_driver_is_info() {
        let driver = make_driver(
            "ntfs.sys",
            "\\SystemRoot\\system32\\DRIVERS\\ntfs.sys",
            0xFFFF_8003_0000,
        );
        let events = driver.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Info);
        assert!((events[0].confidence - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn driver_entity_has_correct_name_and_base() {
        let driver = make_driver("ntfs.sys", "\\SystemRoot\\system32\\DRIVERS\\ntfs.sys", 0xFFFF_8003_0000);
        let events = driver.into_forensic_events();
        match &events[0].entity {
            Entity::Driver { name, base } => {
                assert_eq!(name, "ntfs.sys");
                assert_eq!(*base, 0xFFFF_8003_0000u64);
            }
            other => panic!("expected Driver entity, got {other:?}"),
        }
    }

    // ── WinMalfindInfo tests ───────────────────────────────────────────────

    fn make_malfind(pid: u64, name: &str, prot: &str, first_bytes: Vec<u8>) -> WinMalfindInfo {
        WinMalfindInfo {
            pid,
            image_name: name.to_string(),
            start_vaddr: 0x0040_0000,
            end_vaddr: 0x0041_0000,
            protection_str: prot.to_string(),
            first_bytes,
        }
    }

    #[test]
    fn execute_readwrite_with_mz_is_critical() {
        let mz_bytes = vec![0x4D, 0x5A, 0x90, 0x00];
        let info = make_malfind(1234, "svchost.exe", "PAGE_EXECUTE_READWRITE", mz_bytes);
        let events = info.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Critical);
        assert!(matches!(events[0].finding, Finding::ProcessHollowing));
        assert_eq!(events[0].mitre_attack[0].as_str(), "T1055");
        assert!((events[0].confidence - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn execute_only_without_mz_is_high() {
        let info = make_malfind(1234, "svchost.exe", "PAGE_EXECUTE_READ", vec![0x00, 0x01, 0x02]);
        let events = info.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::High);
        assert!(matches!(events[0].finding, Finding::ProcessHollowing));
        assert_eq!(events[0].mitre_attack[0].as_str(), "T1055");
        assert!((events[0].confidence - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn non_execute_region_is_info() {
        let info = make_malfind(1234, "notepad.exe", "PAGE_READWRITE", vec![0x00]);
        let events = info.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Info);
        assert!((events[0].confidence - 0.4).abs() < f64::EPSILON);
    }

    #[test]
    fn critical_malfind_is_suspicious() {
        let mz_bytes = vec![0x4D, 0x5A, 0x90, 0x00];
        let info = make_malfind(1234, "svchost.exe", "PAGE_EXECUTE_READWRITE", mz_bytes);
        let events = info.into_forensic_events();
        assert!(events[0].is_suspicious());
    }

    #[test]
    fn malfind_entity_has_pid_and_name() {
        let info = make_malfind(9999, "lsass.exe", "PAGE_EXECUTE_READWRITE", vec![0x4D, 0x5A]);
        let events = info.into_forensic_events();
        match &events[0].entity {
            Entity::Process { pid, name, .. } => {
                assert_eq!(*pid, 9999u32);
                assert_eq!(name, "lsass.exe");
            }
            other => panic!("expected Process entity, got {other:?}"),
        }
    }

    // ── WinHollowingInfo tests ─────────────────────────────────────────────

    fn make_hollowing(
        pid: u64,
        name: &str,
        has_mz: bool,
        has_pe: bool,
        suspicious: bool,
        reason: &str,
    ) -> WinHollowingInfo {
        WinHollowingInfo {
            pid,
            image_name: name.to_string(),
            image_base: 0x0040_0000,
            has_mz,
            has_pe,
            pe_size_of_image: 0x1000,
            ldr_size_of_image: 0x1000,
            suspicious,
            reason: reason.to_string(),
        }
    }

    #[test]
    fn suspicious_hollowing_is_critical() {
        let info = make_hollowing(1234, "svchost.exe", true, true, true, "pe size mismatch");
        let events = info.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Critical);
        assert!(matches!(events[0].finding, Finding::ProcessHollowing));
        assert_eq!(events[0].mitre_attack[0].as_str(), "T1055");
        assert!((events[0].confidence - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn missing_mz_header_is_medium() {
        let info = make_hollowing(5678, "explorer.exe", false, true, false, "");
        let events = info.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Medium);
        assert!(matches!(events[0].finding, Finding::DefenseEvasion));
        assert_eq!(events[0].mitre_attack[0].as_str(), "T1055");
        assert!((events[0].confidence - 0.65).abs() < f64::EPSILON);
    }

    #[test]
    fn clean_process_is_info() {
        let info = make_hollowing(1111, "notepad.exe", true, true, false, "");
        let events = info.into_forensic_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Info);
        assert!((events[0].confidence - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn suspicious_hollowing_is_suspicious_event() {
        let info = make_hollowing(1234, "svchost.exe", true, true, true, "pe size mismatch");
        let events = info.into_forensic_events();
        assert!(events[0].is_suspicious());
    }

    // -----------------------------------------------------------------------
    // WinConnectionInfo tests
    // -----------------------------------------------------------------------

    fn make_win_conn(remote_addr: &str, remote_port: u16, pid: u64) -> WinConnectionInfo {
        WinConnectionInfo {
            protocol: "TCPv4".to_string(),
            local_addr: "192.168.1.5".to_string(),
            local_port: 49200,
            remote_addr: remote_addr.to_string(),
            remote_port,
            state: crate::types::WinTcpState::Established,
            pid,
            process_name: "chrome.exe".to_string(),
            create_time: 0,
        }
    }

    #[test]
    fn win_c2_port_connection_is_high_beaconing() {
        for port in [4444u16, 1337, 31337] {
            let c = make_win_conn("10.0.0.1", port, 100);
            let events = c.into_forensic_events();
            assert_eq!(events.len(), 1, "port {port}");
            assert_eq!(events[0].severity, Severity::High, "port {port}");
            assert!(matches!(events[0].finding, Finding::NetworkBeaconing), "port {port}");
            let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
            assert!(ids.contains(&"T1071"), "expected T1071 for port {port}");
        }
    }

    #[test]
    fn win_no_owning_pid_is_high_defense_evasion() {
        let c = make_win_conn("8.8.8.8", 443, 0);
        let events = c.into_forensic_events();
        assert_eq!(events[0].severity, Severity::High);
        assert!(matches!(events[0].finding, Finding::DefenseEvasion));
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1095"), "expected T1095");
    }

    #[test]
    fn win_normal_connection_is_info() {
        let c = make_win_conn("93.184.216.34", 443, 200);
        let events = c.into_forensic_events();
        assert_eq!(events[0].severity, Severity::Info);
        assert!(matches!(events[0].finding, Finding::Other(_)));
    }

    #[test]
    fn win_connection_source_walker_is_windows_connection() {
        let c = make_win_conn("1.2.3.4", 80, 42);
        let events = c.into_forensic_events();
        assert_eq!(events[0].source_walker, "windows_connection");
    }

    // -----------------------------------------------------------------------
    // WinTokenInfo tests
    // -----------------------------------------------------------------------

    fn make_token(pid: u64, image_name: &str, privileges_enabled: u64, user_sid: &str) -> WinTokenInfo {
        WinTokenInfo {
            pid,
            image_name: image_name.to_string(),
            privileges_enabled,
            privileges_present: privileges_enabled,
            privilege_names: vec![],
            session_id: 1,
            user_sid: user_sid.to_string(),
        }
    }

    #[test]
    fn sedebug_privilege_enabled_is_high_token_manipulation() {
        // SeDebugPrivilege = bit 20
        let t = make_token(999, "evil.exe", 1 << 20, "S-1-5-1000");
        let events = t.into_forensic_events();
        assert_eq!(events[0].severity, Severity::High);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1134"), "expected T1134");
    }

    #[test]
    fn system_sid_in_user_process_is_high_privilege_escalation() {
        // pid != 4 (not System process itself), SID = S-1-5-18 (SYSTEM)
        let t = make_token(1234, "notepad.exe", 0, "S-1-5-18");
        let events = t.into_forensic_events();
        assert_eq!(events[0].severity, Severity::High);
        let ids: Vec<&str> = events[0].mitre_attack.iter().map(|m| m.as_str()).collect();
        assert!(ids.contains(&"T1078"), "expected T1078");
    }

    #[test]
    fn normal_token_is_info() {
        let t = make_token(500, "svchost.exe", 0, "S-1-5-20");
        let events = t.into_forensic_events();
        assert_eq!(events[0].severity, Severity::Info);
    }

    #[test]
    fn token_source_walker_is_windows_token() {
        let t = make_token(42, "lsass.exe", 0, "S-1-5-18");
        let events = t.into_forensic_events();
        assert_eq!(events[0].source_walker, "windows_token");
    }
}
