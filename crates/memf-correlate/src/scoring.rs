//! Threat scoring engine that aggregates [`ForensicEvent`]s per entity into ranked scores.

use crate::event::{Entity, Finding, ForensicEvent, Severity};

/// Severity weights used for scoring.
fn severity_weight(severity: Severity) -> f64 {
    todo!("implement severity_weight")
}

/// Entity key used for grouping events.
fn entity_key(entity: &Entity) -> Option<String> {
    todo!("implement entity_key")
}

/// A threat score for a single entity.
pub struct EntityScore {
    /// The entity key (e.g. `"{pid}"`, `"module:{name}"`, `"{src}->{dst}"`).
    pub entity_key: String,
    /// The aggregated threat score.
    pub score: f64,
    /// The contributing forensic events.
    pub findings: Vec<ForensicEvent>,
}

/// Aggregates [`ForensicEvent`]s into per-entity threat scores.
pub struct ScoringEngine {
    events: Vec<ForensicEvent>,
}

impl ScoringEngine {
    /// Create a new engine from a list of events.
    pub fn new(events: Vec<ForensicEvent>) -> Self {
        todo!("implement ScoringEngine::new")
    }

    /// Score all entities and return them sorted descending by score.
    pub fn score_all(&self) -> Vec<EntityScore> {
        todo!("implement score_all")
    }

    /// Return references to the top `n` highest-scoring entities.
    pub fn top_n(&self, n: usize) -> Vec<&EntityScore> {
        todo!("implement top_n")
    }

    /// Return the score for a specific PID, or `None` if the PID has no events.
    pub fn score_for_pid(&self, pid: u32) -> Option<f64> {
        todo!("implement score_for_pid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    use crate::event::{Entity, Finding, ForensicEvent, Protocol, Severity};

    fn proc_event(pid: u32, finding: Finding, severity: Severity, confidence: f64) -> ForensicEvent {
        ForensicEvent::builder()
            .source_walker("test_walker")
            .entity(Entity::Process {
                pid,
                name: format!("proc_{pid}"),
                ppid: None,
            })
            .finding(finding)
            .severity(severity)
            .confidence(confidence)
            .build()
    }

    fn conn_event(src_port: u16, dst_port: u16, finding: Finding, severity: Severity, confidence: f64) -> ForensicEvent {
        ForensicEvent::builder()
            .source_walker("test_walker")
            .entity(Entity::Connection {
                src: SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), src_port),
                dst: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), dst_port),
                proto: Protocol::Tcp,
            })
            .finding(finding)
            .severity(severity)
            .confidence(confidence)
            .build()
    }

    #[test]
    fn empty_events_returns_empty_scores() {
        let engine = ScoringEngine::new(vec![]);
        let scores = engine.score_all();
        assert!(scores.is_empty());
    }

    #[test]
    fn single_high_event_scores_correctly() {
        // High = 5.0 weight, confidence 0.8 → 5.0 × 0.8 = 4.0
        let engine = ScoringEngine::new(vec![
            proc_event(100, Finding::ProcessHollowing, Severity::High, 0.8),
        ]);
        let scores = engine.score_all();
        assert_eq!(scores.len(), 1);
        let diff = (scores[0].score - 4.0).abs();
        assert!(diff < 1e-9, "expected 4.0 but got {}", scores[0].score);
    }

    #[test]
    fn multiple_events_for_same_pid_accumulate() {
        // Two events for pid 42: High/0.5 = 2.5, Medium/1.0 = 2.0 → total 4.5
        let engine = ScoringEngine::new(vec![
            proc_event(42, Finding::DefenseEvasion, Severity::High, 0.5),
            proc_event(42, Finding::CredentialAccess, Severity::Medium, 1.0),
        ]);
        let scores = engine.score_all();
        assert_eq!(scores.len(), 1);
        let expected = 5.0 * 0.5 + 2.0 * 1.0;
        let diff = (scores[0].score - expected).abs();
        assert!(diff < 1e-9, "expected {expected} but got {}", scores[0].score);
    }

    #[test]
    fn critical_event_scores_highest() {
        // Critical/1.0 → 10.0 × 1.0 = 10.0
        let engine = ScoringEngine::new(vec![
            proc_event(1, Finding::ProcessHollowing, Severity::Critical, 1.0),
        ]);
        let scores = engine.score_all();
        assert_eq!(scores.len(), 1);
        let diff = (scores[0].score - 10.0).abs();
        assert!(diff < 1e-9, "expected 10.0 but got {}", scores[0].score);
    }

    #[test]
    fn hollowing_plus_beaconing_applies_multiplier() {
        // ProcessHollowing (High/1.0 = 5.0) + NetworkBeaconing (High/1.0 = 5.0)
        // base = 10.0, × 2.0 amplifier = 20.0
        let engine = ScoringEngine::new(vec![
            proc_event(99, Finding::ProcessHollowing, Severity::High, 1.0),
            proc_event(99, Finding::NetworkBeaconing, Severity::High, 1.0),
        ]);
        let scores = engine.score_all();
        assert_eq!(scores.len(), 1);
        let diff = (scores[0].score - 20.0).abs();
        assert!(diff < 1e-9, "expected 20.0 but got {}", scores[0].score);
    }

    #[test]
    fn score_all_sorted_descending() {
        let engine = ScoringEngine::new(vec![
            proc_event(1, Finding::DefenseEvasion, Severity::Info, 1.0),    // 0.5
            proc_event(2, Finding::ProcessHollowing, Severity::Critical, 1.0), // 10.0
            proc_event(3, Finding::CredentialAccess, Severity::Medium, 1.0),  // 2.0
        ]);
        let scores = engine.score_all();
        assert_eq!(scores.len(), 3);
        assert!(scores[0].score >= scores[1].score, "not sorted descending: {} >= {}", scores[0].score, scores[1].score);
        assert!(scores[1].score >= scores[2].score, "not sorted descending: {} >= {}", scores[1].score, scores[2].score);
    }

    #[test]
    fn top_n_returns_at_most_n() {
        let engine = ScoringEngine::new(vec![
            proc_event(1, Finding::DefenseEvasion, Severity::Info, 1.0),
            proc_event(2, Finding::ProcessHollowing, Severity::Critical, 1.0),
            proc_event(3, Finding::CredentialAccess, Severity::Medium, 1.0),
            proc_event(4, Finding::LateralMovement, Severity::High, 1.0),
            proc_event(5, Finding::PersistenceMechanism, Severity::High, 1.0),
        ]);
        let top = engine.top_n(2);
        assert_eq!(top.len(), 2);
    }

    #[test]
    fn score_for_pid_returns_none_for_unknown() {
        let engine = ScoringEngine::new(vec![
            proc_event(1, Finding::DefenseEvasion, Severity::Info, 1.0),
        ]);
        assert!(engine.score_for_pid(9999).is_none());
    }

    #[test]
    fn score_for_pid_returns_correct_score() {
        // pid 42: High/0.5 = 2.5
        let engine = ScoringEngine::new(vec![
            proc_event(42, Finding::DefenseEvasion, Severity::High, 0.5),
        ]);
        let score = engine.score_for_pid(42).expect("pid 42 should have a score");
        let diff = (score - 2.5).abs();
        assert!(diff < 1e-9, "expected 2.5 but got {score}");
    }

    #[test]
    fn events_with_connection_entity_grouped_separately() {
        // Process pid 7 and a Connection should produce 2 separate entity scores
        let engine = ScoringEngine::new(vec![
            proc_event(7, Finding::NetworkBeaconing, Severity::High, 1.0),
            conn_event(8080, 443, Finding::NetworkBeaconing, Severity::High, 1.0),
        ]);
        let scores = engine.score_all();
        assert_eq!(scores.len(), 2);
        let keys: Vec<&str> = scores.iter().map(|s| s.entity_key.as_str()).collect();
        assert!(keys.contains(&"7"), "expected key '7', got: {keys:?}");
        assert!(keys.iter().any(|k| k.contains("->")), "expected a connection key with '->'");
    }
}
