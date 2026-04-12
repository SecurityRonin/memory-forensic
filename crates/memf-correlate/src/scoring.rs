//! Threat scoring engine that aggregates [`ForensicEvent`]s per entity into ranked scores.

use std::collections::HashMap;

use crate::event::{Entity, Finding, ForensicEvent, Severity};

/// Return the scoring weight for a severity level.
fn severity_weight(severity: Severity) -> f64 {
    match severity {
        Severity::Critical => 10.0,
        Severity::High => 5.0,
        Severity::Medium => 2.0,
        Severity::Info | Severity::Low => 0.5,
    }
}

/// Return a stable string key for an entity, or `None` for entities we don't score.
fn entity_key(entity: &Entity) -> Option<String> {
    match entity {
        Entity::Process { pid, .. } => Some(pid.to_string()),
        Entity::Connection { src, dst, .. } => Some(format!("{src}->{dst}")),
        Entity::Module { name, .. } => Some(format!("module:{name}")),
        Entity::Driver { name, .. } => Some(format!("driver:{name}")),
        Entity::RegistryKey { path } => Some(format!("reg:{path}")),
        Entity::File { path } => Some(format!("file:{path}")),
        Entity::Thread { .. } => None,
    }
}

/// Check whether the set of findings for an entity contains a given finding variant.
fn has_finding(findings: &[ForensicEvent], target: &Finding) -> bool {
    findings.iter().any(|e| matches_finding(&e.finding, target))
}

fn matches_finding(a: &Finding, b: &Finding) -> bool {
    std::mem::discriminant(a) == std::mem::discriminant(b)
}

/// Compute the combinatorial amplifier for a set of findings.
fn amplifier(events: &[ForensicEvent]) -> f64 {
    let has_hollowing = has_finding(events, &Finding::ProcessHollowing);
    let has_beaconing = has_finding(events, &Finding::NetworkBeaconing);
    let has_evasion = has_finding(events, &Finding::DefenseEvasion);

    // Multiple amplifiers can apply; use the highest one.
    let mut mult = 1.0_f64;
    if has_hollowing && has_beaconing {
        mult = mult.max(2.0);
    }
    if has_hollowing && has_evasion {
        mult = mult.max(1.5);
    }
    if has_beaconing && has_evasion {
        mult = mult.max(1.5);
    }
    mult
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
    scores: Vec<EntityScore>,
}

impl ScoringEngine {
    /// Create a new engine from a list of events.
    pub fn new(events: Vec<ForensicEvent>) -> Self {
        // Group events by entity key (skip entities with no key).
        let mut groups: HashMap<String, Vec<ForensicEvent>> = HashMap::new();
        for event in events {
            if let Some(key) = entity_key(&event.entity) {
                groups.entry(key).or_default().push(event);
            }
        }

        // Compute score per group.
        let mut scores: Vec<EntityScore> = groups
            .into_iter()
            .map(|(key, evts)| {
                let base: f64 = evts
                    .iter()
                    .map(|e| severity_weight(e.severity) * e.confidence)
                    .sum();
                let amp = amplifier(&evts);
                EntityScore {
                    entity_key: key,
                    score: base * amp,
                    findings: evts,
                }
            })
            .collect();

        // Sort descending by score.
        scores.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        Self { scores }
    }

    /// Score all entities, sorted descending by score.
    pub fn score_all(&self) -> Vec<EntityScore> {
        // Re-derive from the stored sorted list — clone findings.
        self.scores
            .iter()
            .map(|s| EntityScore {
                entity_key: s.entity_key.clone(),
                score: s.score,
                findings: s.findings.clone(),
            })
            .collect()
    }

    /// Return references to the top `n` highest-scoring entities.
    pub fn top_n(&self, n: usize) -> Vec<&EntityScore> {
        self.scores.iter().take(n).collect()
    }

    /// Return the score for a specific PID, or `None` if the PID has no events.
    pub fn score_for_pid(&self, pid: u32) -> Option<f64> {
        let key = pid.to_string();
        self.scores.iter().find(|s| s.entity_key == key).map(|s| s.score)
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
