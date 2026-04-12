//! Conversion traits for producing forensic events from walker output.

use crate::event::ForensicEvent;

/// Trait for types that can produce a list of [`ForensicEvent`]s.
///
/// Implement this on walker output structs to enable automatic
/// correlation and reporting.
pub trait IntoForensicEvents {
    /// Consume this value and produce forensic events.
    fn into_forensic_events(self) -> Vec<ForensicEvent>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::*;
    use crate::mitre::MitreAttackId;

    /// A mock walker output for testing the trait.
    struct MockWalkerOutput {
        suspicious_pids: Vec<u32>,
    }

    impl IntoForensicEvents for MockWalkerOutput {
        fn into_forensic_events(self) -> Vec<crate::event::ForensicEvent> {
            self.suspicious_pids
                .into_iter()
                .map(|pid| {
                    ForensicEvent::builder()
                        .source_walker("mock_walker")
                        .entity(Entity::Process {
                            pid,
                            name: format!("proc_{pid}"),
                            ppid: Some(1),
                        })
                        .finding(Finding::ProcessHollowing)
                        .severity(Severity::High)
                        .confidence(0.95)
                        .mitre_attack(vec![MitreAttackId::new("T1055").unwrap()])
                        .build()
                })
                .collect()
        }
    }

    #[test]
    fn mock_walker_produces_events() {
        let output = MockWalkerOutput {
            suspicious_pids: vec![100, 200, 300],
        };
        let events = output.into_forensic_events();
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn mock_walker_events_have_correct_source() {
        let output = MockWalkerOutput {
            suspicious_pids: vec![42],
        };
        let events = output.into_forensic_events();
        assert_eq!(events[0].source_walker, "mock_walker");
    }

    #[test]
    fn mock_walker_events_have_mitre_ids() {
        let output = MockWalkerOutput {
            suspicious_pids: vec![42],
        };
        let events = output.into_forensic_events();
        assert_eq!(events[0].mitre_attack.len(), 1);
        assert_eq!(events[0].mitre_attack[0].as_str(), "T1055");
    }

    #[test]
    fn empty_walker_output_produces_no_events() {
        let output = MockWalkerOutput {
            suspicious_pids: vec![],
        };
        let events = output.into_forensic_events();
        assert!(events.is_empty());
    }
}
