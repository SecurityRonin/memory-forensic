//! Unified forensic event timeline.
//!
//! Merges all [`ForensicEvent`]s from multiple walkers into a single
//! chronologically-ordered stream, with filtering by severity, entity PID,
//! MITRE tactic, and walker source.

use crate::event::{ForensicEvent, Severity};

/// A sorted, filterable timeline of forensic events.
pub struct Timeline {
    /// Events ordered by `timestamp` (None-timestamp events sort last).
    entries: Vec<ForensicEvent>,
}

impl Timeline {
    /// Build a timeline from an unsorted collection of events.
    ///
    /// Events with a `timestamp` are sorted ascending; events without one
    /// are appended after all timestamped events, preserving their relative order.
    pub fn from_events(mut events: Vec<ForensicEvent>) -> Self {
        events.sort_by(|a, b| match (a.timestamp, b.timestamp) {
            (Some(ta), Some(tb)) => ta.cmp(&tb),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });
        Self { entries: events }
    }

    /// Return all events in chronological order.
    pub fn entries(&self) -> &[ForensicEvent] {
        &self.entries
    }

    /// Return only events at or above `min_severity`.
    pub fn filter_by_severity(&self, min: Severity) -> Vec<&ForensicEvent> {
        self.entries.iter().filter(|e| e.severity >= min).collect()
    }

    /// Return only events whose entity is a Process with the given `pid`.
    pub fn filter_by_pid(&self, pid: u32) -> Vec<&ForensicEvent> {
        self.entries
            .iter()
            .filter(|e| matches!(&e.entity, crate::event::Entity::Process { pid: p, .. } if *p == pid))
            .collect()
    }

    /// Return only events from a specific walker (matched by `source_walker`).
    pub fn filter_by_walker(&self, walker: &str) -> Vec<&ForensicEvent> {
        self.entries.iter().filter(|e| e.source_walker == walker).collect()
    }

    /// Return only events that have at least one MITRE ATT&CK ID.
    pub fn filter_mapped(&self) -> Vec<&ForensicEvent> {
        self.entries.iter().filter(|e| !e.mitre_attack.is_empty()).collect()
    }

    /// Total number of events in the timeline.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the timeline contains no events.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    use crate::event::{Entity, Finding, ForensicEvent};
    use crate::mitre::MitreAttackId;

    fn make_event(walker: &'static str, severity: Severity, pid: u32, ts_secs: Option<i64>) -> ForensicEvent {
        let mut b = ForensicEvent::builder()
            .source_walker(walker)
            .entity(Entity::Process { pid, name: format!("proc_{pid}"), ppid: None })
            .finding(Finding::Other("test".into()))
            .severity(severity)
            .confidence(0.5);
        if let Some(s) = ts_secs {
            b = b.timestamp(chrono::DateTime::from_timestamp(s, 0).unwrap().with_timezone(&Utc));
        }
        b.build()
    }

    fn make_mitre_event(walker: &'static str, severity: Severity, pid: u32) -> ForensicEvent {
        ForensicEvent::builder()
            .source_walker(walker)
            .entity(Entity::Process { pid, name: "evil".into(), ppid: None })
            .finding(Finding::ProcessHollowing)
            .severity(severity)
            .confidence(0.9)
            .mitre_attack(vec![MitreAttackId::new("T1055").unwrap()])
            .build()
    }

    #[test]
    fn empty_timeline_has_zero_len() {
        let t = Timeline::from_events(vec![]);
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn events_sorted_by_timestamp_ascending() {
        let events = vec![
            make_event("w1", Severity::Info, 1, Some(300)),
            make_event("w2", Severity::Info, 2, Some(100)),
            make_event("w3", Severity::Info, 3, Some(200)),
        ];
        let t = Timeline::from_events(events);
        let timestamps: Vec<i64> = t.entries().iter()
            .filter_map(|e| e.timestamp.map(|ts| ts.timestamp()))
            .collect();
        assert_eq!(timestamps, vec![100, 200, 300]);
    }

    #[test]
    fn events_without_timestamp_sort_last() {
        let events = vec![
            make_event("w1", Severity::Info, 1, None),
            make_event("w2", Severity::Info, 2, Some(100)),
        ];
        let t = Timeline::from_events(events);
        assert_eq!(t.entries()[0].timestamp.unwrap().timestamp(), 100);
        assert!(t.entries()[1].timestamp.is_none());
    }

    #[test]
    fn filter_by_severity_returns_at_or_above() {
        let events = vec![
            make_event("w", Severity::Info, 1, Some(1)),
            make_event("w", Severity::Medium, 2, Some(2)),
            make_event("w", Severity::High, 3, Some(3)),
            make_event("w", Severity::Critical, 4, Some(4)),
        ];
        let t = Timeline::from_events(events);
        let high_plus = t.filter_by_severity(Severity::High);
        assert_eq!(high_plus.len(), 2);
        for e in &high_plus {
            assert!(e.severity >= Severity::High);
        }
    }

    #[test]
    fn filter_by_pid_returns_matching_process_events() {
        let events = vec![
            make_event("w", Severity::Info, 42, Some(1)),
            make_event("w", Severity::High, 99, Some(2)),
            make_event("w", Severity::Info, 42, Some(3)),
        ];
        let t = Timeline::from_events(events);
        let pid42 = t.filter_by_pid(42);
        assert_eq!(pid42.len(), 2);
    }

    #[test]
    fn filter_by_walker_returns_only_that_source() {
        let events = vec![
            make_event("win_process", Severity::Info, 1, Some(1)),
            make_event("linux_vma", Severity::High, 2, Some(2)),
            make_event("win_process", Severity::Medium, 3, Some(3)),
        ];
        let t = Timeline::from_events(events);
        let win = t.filter_by_walker("win_process");
        assert_eq!(win.len(), 2);
        assert!(win.iter().all(|e| e.source_walker == "win_process"));
    }

    #[test]
    fn filter_mapped_returns_only_events_with_mitre_ids() {
        let events = vec![
            make_event("w", Severity::Info, 1, Some(1)),
            make_mitre_event("w", Severity::High, 2),
            make_event("w", Severity::Medium, 3, Some(3)),
            make_mitre_event("w", Severity::Critical, 4),
        ];
        let t = Timeline::from_events(events);
        let mapped = t.filter_mapped();
        assert_eq!(mapped.len(), 2);
        assert!(mapped.iter().all(|e| !e.mitre_attack.is_empty()));
    }

    #[test]
    fn timeline_preserves_all_events() {
        let n = 50;
        let events: Vec<_> = (0..n)
            .map(|i| make_event("w", Severity::Info, i as u32, Some(i as i64)))
            .collect();
        let t = Timeline::from_events(events);
        assert_eq!(t.len(), n);
    }
}
