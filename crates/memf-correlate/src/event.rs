//! ForensicEvent model, Entity, Finding, Severity, and Protocol types.

use crate::mitre::MitreAttackId;
use serde::Serialize;
use std::fmt;
use std::net::SocketAddr;

/// A single forensic event produced by a walker's analysis.
///
/// Represents a finding tied to a specific entity, with optional temporal
/// context, MITRE ATT&CK mapping, and confidence scoring.
#[derive(Debug, Clone, Serialize)]
pub struct ForensicEvent {
    /// When the event occurred (if determinable from the memory image).
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
    /// The walker that produced this event.
    pub source_walker: &'static str,
    /// The entity this event relates to.
    pub entity: Entity,
    /// What was found.
    pub finding: Finding,
    /// How severe the finding is.
    pub severity: Severity,
    /// Associated MITRE ATT&CK technique IDs.
    pub mitre_attack: Vec<MitreAttackId>,
    /// Confidence score in the range `[0.0, 1.0]`.
    pub confidence: f64,
    /// Raw bytes backing this finding (e.g. suspicious PE header).
    pub raw_evidence: Vec<u8>,
}

impl ForensicEvent {
    /// Returns a new [`ForensicEventBuilder`].
    pub fn builder() -> ForensicEventBuilder {
        ForensicEventBuilder::default()
    }

    /// Returns `true` if severity >= High **or** confidence >= 0.8.
    pub fn is_suspicious(&self) -> bool {
        self.severity >= Severity::High || self.confidence >= 0.8
    }
}

/// Fluent builder for [`ForensicEvent`].
#[derive(Debug, Default)]
pub struct ForensicEventBuilder {
    timestamp: Option<chrono::DateTime<chrono::Utc>>,
    source_walker: Option<&'static str>,
    entity: Option<Entity>,
    finding: Option<Finding>,
    severity: Option<Severity>,
    mitre_attack: Vec<MitreAttackId>,
    confidence: Option<f64>,
    raw_evidence: Vec<u8>,
}

impl ForensicEventBuilder {
    /// Set the source walker name.
    pub fn source_walker(mut self, walker: &'static str) -> Self {
        self.source_walker = Some(walker);
        self
    }

    /// Set the entity.
    pub fn entity(mut self, entity: Entity) -> Self {
        self.entity = Some(entity);
        self
    }

    /// Set the finding.
    pub fn finding(mut self, finding: Finding) -> Self {
        self.finding = Some(finding);
        self
    }

    /// Set the severity.
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Set the timestamp.
    pub fn timestamp(mut self, ts: chrono::DateTime<chrono::Utc>) -> Self {
        self.timestamp = Some(ts);
        self
    }

    /// Set the confidence score (clamped to `[0.0, 1.0]`).
    pub fn confidence(mut self, c: f64) -> Self {
        self.confidence = Some(c);
        self
    }

    /// Set the raw evidence bytes.
    pub fn raw_evidence(mut self, evidence: Vec<u8>) -> Self {
        self.raw_evidence = evidence;
        self
    }

    /// Set the MITRE ATT&CK IDs.
    pub fn mitre_attack(mut self, ids: Vec<MitreAttackId>) -> Self {
        self.mitre_attack = ids;
        self
    }

    /// Build the [`ForensicEvent`], consuming the builder.
    ///
    /// # Panics
    ///
    /// Panics if `source_walker`, `entity`, `finding`, or `severity` were not set.
    pub fn build(self) -> ForensicEvent {
        let confidence = self.confidence.unwrap_or(0.5).clamp(0.0, 1.0);
        ForensicEvent {
            timestamp: self.timestamp,
            source_walker: self.source_walker.expect("source_walker is required"),
            entity: self.entity.expect("entity is required"),
            finding: self.finding.expect("finding is required"),
            severity: self.severity.expect("severity is required"),
            mitre_attack: self.mitre_attack,
            confidence,
            raw_evidence: self.raw_evidence,
        }
    }
}

// ---------------------------------------------------------------------------
// Entity
// ---------------------------------------------------------------------------

/// An entity observed in a memory image.
#[derive(Debug, Clone, Serialize)]
pub enum Entity {
    /// A process.
    Process {
        /// Process identifier.
        pid: u32,
        /// Process name.
        name: String,
        /// Parent process identifier.
        ppid: Option<u32>,
    },
    /// A thread.
    Thread {
        /// Thread identifier.
        tid: u32,
        /// Owning process identifier.
        owning_pid: u32,
    },
    /// A loaded module / shared library.
    Module {
        /// Module name.
        name: String,
        /// Base virtual address.
        base: u64,
        /// Size in bytes.
        size: u64,
    },
    /// A network connection.
    Connection {
        /// Source address.
        src: SocketAddr,
        /// Destination address.
        dst: SocketAddr,
        /// Transport protocol.
        proto: Protocol,
    },
    /// A kernel-mode driver.
    Driver {
        /// Driver name.
        name: String,
        /// Base virtual address.
        base: u64,
    },
    /// A registry key (Windows).
    RegistryKey {
        /// Full registry path.
        path: String,
    },
    /// A file reference.
    File {
        /// File path.
        path: String,
    },
}

impl fmt::Display for Entity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Process { pid, name, .. } => write!(f, "Process({name}/{pid})"),
            Self::Thread { tid, owning_pid } => {
                write!(f, "Thread({tid} owned by {owning_pid})")
            }
            Self::Module { name, base, .. } => write!(f, "Module({name} @ {base:#x})"),
            Self::Connection { src, dst, proto } => {
                write!(f, "Connection({proto} {src} -> {dst})")
            }
            Self::Driver { name, base } => write!(f, "Driver({name} @ {base:#x})"),
            Self::RegistryKey { path } => write!(f, "RegistryKey({path})"),
            Self::File { path } => write!(f, "File({path})"),
        }
    }
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

/// Transport-layer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMP.
    Icmp,
    /// Unknown or unsupported protocol.
    Unknown,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "Tcp"),
            Self::Udp => write!(f, "Udp"),
            Self::Icmp => write!(f, "Icmp"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// Severity classification for a forensic finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    /// Informational — no immediate concern.
    Info,
    /// Low severity.
    Low,
    /// Medium severity.
    Medium,
    /// High severity.
    High,
    /// Critical severity.
    Critical,
}

impl Severity {
    /// Returns a numeric weight for this severity level.
    pub fn weight(self) -> u32 {
        match self {
            Self::Info => 1,
            Self::Low => 5,
            Self::Medium => 15,
            Self::High => 40,
            Self::Critical => 100,
        }
    }
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

/// The type of suspicious finding detected.
#[derive(Debug, Clone, Serialize)]
pub enum Finding {
    /// Process hollowing (T1055.012).
    ProcessHollowing,
    /// C2 beaconing behavior.
    NetworkBeaconing,
    /// Credential theft or dumping.
    CredentialAccess,
    /// Privilege escalation attempt.
    PrivilegeEscalation,
    /// Persistence mechanism installed.
    PersistenceMechanism,
    /// Defense evasion technique.
    DefenseEvasion,
    /// Lateral movement activity.
    LateralMovement,
    /// Custom / unclassified finding.
    Other(String),
}

impl Finding {
    /// Returns a human-readable display name.
    pub fn display_name(&self) -> &str {
        match self {
            Self::ProcessHollowing => "Process Hollowing",
            Self::NetworkBeaconing => "Network Beaconing",
            Self::CredentialAccess => "Credential Access",
            Self::PrivilegeEscalation => "Privilege Escalation",
            Self::PersistenceMechanism => "Persistence Mechanism",
            Self::DefenseEvasion => "Defense Evasion",
            Self::LateralMovement => "Lateral Movement",
            Self::Other(s) => s,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    // --- Severity::weight() tests ---

    #[test]
    fn severity_info_weight_is_1() {
        assert_eq!(Severity::Info.weight(), 1);
    }

    #[test]
    fn severity_low_weight_is_5() {
        assert_eq!(Severity::Low.weight(), 5);
    }

    #[test]
    fn severity_medium_weight_is_15() {
        assert_eq!(Severity::Medium.weight(), 15);
    }

    #[test]
    fn severity_high_weight_is_40() {
        assert_eq!(Severity::High.weight(), 40);
    }

    #[test]
    fn severity_critical_weight_is_100() {
        assert_eq!(Severity::Critical.weight(), 100);
    }

    // --- Severity ordering tests ---

    #[test]
    fn severity_critical_greater_than_high() {
        assert!(Severity::Critical > Severity::High);
    }

    #[test]
    fn severity_high_greater_than_medium() {
        assert!(Severity::High > Severity::Medium);
    }

    #[test]
    fn severity_medium_greater_than_low() {
        assert!(Severity::Medium > Severity::Low);
    }

    #[test]
    fn severity_low_greater_than_info() {
        assert!(Severity::Low > Severity::Info);
    }

    // --- ForensicEvent::builder() tests ---

    #[test]
    fn builder_creates_event_with_defaults() {
        let event = ForensicEvent::builder()
            .source_walker("pslist")
            .entity(Entity::Process {
                pid: 4,
                name: "System".into(),
                ppid: None,
            })
            .finding(Finding::DefenseEvasion)
            .severity(Severity::High)
            .build();

        assert_eq!(event.source_walker, "pslist");
        assert_eq!(event.severity, Severity::High);
        assert!(event.timestamp.is_none());
        assert!(event.mitre_attack.is_empty());
        assert!((event.confidence - 0.5).abs() < f64::EPSILON); // default confidence
        assert!(event.raw_evidence.is_empty());
    }

    #[test]
    fn builder_sets_all_fields() {
        let ts = chrono::Utc::now();
        let event = ForensicEvent::builder()
            .source_walker("netscan")
            .entity(Entity::Connection {
                src: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8080),
                dst: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 443),
                proto: Protocol::Tcp,
            })
            .finding(Finding::NetworkBeaconing)
            .severity(Severity::Medium)
            .timestamp(ts)
            .confidence(0.9)
            .raw_evidence(vec![0xDE, 0xAD])
            .build();

        assert_eq!(event.timestamp, Some(ts));
        assert!((event.confidence - 0.9).abs() < f64::EPSILON);
        assert_eq!(event.raw_evidence, vec![0xDE, 0xAD]);
    }

    // --- Confidence clamping tests ---

    #[test]
    fn confidence_clamps_above_1() {
        let event = ForensicEvent::builder()
            .source_walker("test")
            .entity(Entity::Process {
                pid: 1,
                name: "test".into(),
                ppid: None,
            })
            .finding(Finding::Other("test".into()))
            .severity(Severity::Info)
            .confidence(1.5)
            .build();

        assert!((event.confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn confidence_clamps_below_0() {
        let event = ForensicEvent::builder()
            .source_walker("test")
            .entity(Entity::Process {
                pid: 1,
                name: "test".into(),
                ppid: None,
            })
            .finding(Finding::Other("test".into()))
            .severity(Severity::Info)
            .confidence(-0.5)
            .build();

        assert!(event.confidence.abs() < f64::EPSILON);
    }

    // --- Entity display tests ---

    #[test]
    fn entity_process_display() {
        let entity = Entity::Process {
            pid: 4,
            name: "System".into(),
            ppid: None,
        };
        assert_eq!(format!("{entity}"), "Process(System/4)");
    }

    #[test]
    fn entity_thread_display() {
        let entity = Entity::Thread {
            tid: 100,
            owning_pid: 4,
        };
        assert_eq!(format!("{entity}"), "Thread(100 owned by 4)");
    }

    #[test]
    fn entity_module_display() {
        let entity = Entity::Module {
            name: "ntdll.dll".into(),
            base: 0x7FF0_0000,
            size: 0x1000,
        };
        assert_eq!(format!("{entity}"), "Module(ntdll.dll @ 0x7ff00000)");
    }

    #[test]
    fn entity_connection_display() {
        let entity = Entity::Connection {
            src: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8080),
            dst: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 443),
            proto: Protocol::Tcp,
        };
        assert_eq!(
            format!("{entity}"),
            "Connection(Tcp 127.0.0.1:8080 -> 10.0.0.1:443)"
        );
    }

    #[test]
    fn entity_driver_display() {
        let entity = Entity::Driver {
            name: "fltMgr.sys".into(),
            base: 0xFFFF_8000,
        };
        assert_eq!(format!("{entity}"), "Driver(fltMgr.sys @ 0xffff8000)");
    }

    #[test]
    fn entity_registry_key_display() {
        let entity = Entity::RegistryKey {
            path: r"HKLM\Software\Test".into(),
        };
        assert_eq!(format!("{entity}"), r"RegistryKey(HKLM\Software\Test)");
    }

    #[test]
    fn entity_file_display() {
        let entity = Entity::File {
            path: "/etc/shadow".into(),
        };
        assert_eq!(format!("{entity}"), "File(/etc/shadow)");
    }

    // --- Finding::display_name() tests ---

    #[test]
    fn finding_process_hollowing_display_name() {
        assert_eq!(Finding::ProcessHollowing.display_name(), "Process Hollowing");
    }

    #[test]
    fn finding_network_beaconing_display_name() {
        assert_eq!(Finding::NetworkBeaconing.display_name(), "Network Beaconing");
    }

    #[test]
    fn finding_credential_access_display_name() {
        assert_eq!(
            Finding::CredentialAccess.display_name(),
            "Credential Access"
        );
    }

    #[test]
    fn finding_privilege_escalation_display_name() {
        assert_eq!(
            Finding::PrivilegeEscalation.display_name(),
            "Privilege Escalation"
        );
    }

    #[test]
    fn finding_persistence_mechanism_display_name() {
        assert_eq!(
            Finding::PersistenceMechanism.display_name(),
            "Persistence Mechanism"
        );
    }

    #[test]
    fn finding_defense_evasion_display_name() {
        assert_eq!(Finding::DefenseEvasion.display_name(), "Defense Evasion");
    }

    #[test]
    fn finding_lateral_movement_display_name() {
        assert_eq!(Finding::LateralMovement.display_name(), "Lateral Movement");
    }

    #[test]
    fn finding_other_display_name() {
        assert_eq!(
            Finding::Other("Custom finding".into()).display_name(),
            "Custom finding"
        );
    }

    // --- ForensicEvent::is_suspicious() tests ---

    #[test]
    fn is_suspicious_when_severity_high() {
        let event = ForensicEvent::builder()
            .source_walker("test")
            .entity(Entity::Process {
                pid: 1,
                name: "test".into(),
                ppid: None,
            })
            .finding(Finding::ProcessHollowing)
            .severity(Severity::High)
            .confidence(0.3)
            .build();

        assert!(event.is_suspicious());
    }

    #[test]
    fn is_suspicious_when_severity_critical() {
        let event = ForensicEvent::builder()
            .source_walker("test")
            .entity(Entity::Process {
                pid: 1,
                name: "test".into(),
                ppid: None,
            })
            .finding(Finding::ProcessHollowing)
            .severity(Severity::Critical)
            .confidence(0.1)
            .build();

        assert!(event.is_suspicious());
    }

    #[test]
    fn is_suspicious_when_confidence_high() {
        let event = ForensicEvent::builder()
            .source_walker("test")
            .entity(Entity::Process {
                pid: 1,
                name: "test".into(),
                ppid: None,
            })
            .finding(Finding::ProcessHollowing)
            .severity(Severity::Low)
            .confidence(0.8)
            .build();

        assert!(event.is_suspicious());
    }

    #[test]
    fn not_suspicious_when_low_severity_and_low_confidence() {
        let event = ForensicEvent::builder()
            .source_walker("test")
            .entity(Entity::Process {
                pid: 1,
                name: "test".into(),
                ppid: None,
            })
            .finding(Finding::ProcessHollowing)
            .severity(Severity::Low)
            .confidence(0.3)
            .build();

        assert!(!event.is_suspicious());
    }

    #[test]
    fn not_suspicious_medium_severity_moderate_confidence() {
        let event = ForensicEvent::builder()
            .source_walker("test")
            .entity(Entity::Process {
                pid: 1,
                name: "test".into(),
                ppid: None,
            })
            .finding(Finding::ProcessHollowing)
            .severity(Severity::Medium)
            .confidence(0.79)
            .build();

        assert!(!event.is_suspicious());
    }

    // --- Serialization tests ---

    #[test]
    fn forensic_event_serializes_to_json() {
        let event = ForensicEvent::builder()
            .source_walker("pslist")
            .entity(Entity::Process {
                pid: 4,
                name: "System".into(),
                ppid: None,
            })
            .finding(Finding::ProcessHollowing)
            .severity(Severity::High)
            .confidence(0.95)
            .build();

        let json = serde_json::to_string(&event).expect("serialization should succeed");
        assert!(!json.is_empty());

        // Verify it's valid JSON by parsing it back
        let value: serde_json::Value =
            serde_json::from_str(&json).expect("should be valid JSON");
        assert!(value.is_object());
    }

    #[test]
    fn protocol_display() {
        assert_eq!(format!("{}", Protocol::Tcp), "Tcp");
        assert_eq!(format!("{}", Protocol::Udp), "Udp");
        assert_eq!(format!("{}", Protocol::Icmp), "Icmp");
        assert_eq!(format!("{}", Protocol::Unknown), "Unknown");
    }
}
