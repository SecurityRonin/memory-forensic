//! Process tree builder and orphan detector from [`ForensicEvent`]s.

use crate::event::ForensicEvent;

/// A node in the process tree.
pub struct ProcessNode {
    /// Process identifier.
    pub pid: u32,
    /// Process name.
    pub name: String,
    /// Parent process identifier, if known.
    pub ppid: Option<u32>,
    /// Child process nodes.
    pub children: Vec<ProcessNode>,
    /// Forensic events associated with this process.
    pub events: Vec<ForensicEvent>,
    /// Aggregated threat score for this process.
    pub threat_score: f64,
}

/// A tree of processes built from forensic events.
pub struct ProcessTree {
    roots: Vec<ProcessNode>,
}

impl ProcessTree {
    /// Build a process tree from a collection of forensic events.
    pub fn from_events(events: Vec<ForensicEvent>) -> Self {
        todo!("implement ProcessTree::from_events")
    }

    /// Return the root nodes of the tree (processes with no parent or ppid = 0).
    pub fn roots(&self) -> &[ProcessNode] {
        todo!("implement roots")
    }

    /// Find a node by PID, searching the entire tree.
    pub fn find_pid(&self, pid: u32) -> Option<&ProcessNode> {
        todo!("implement find_pid")
    }

    /// Return nodes that have a ppid set but whose parent PID is not present in any event.
    pub fn orphaned_nodes(&self) -> Vec<&ProcessNode> {
        todo!("implement orphaned_nodes")
    }

    /// Walk from roots, following the child with the highest threat score at each step.
    pub fn highest_threat_path(&self) -> Vec<&ProcessNode> {
        todo!("implement highest_threat_path")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    use crate::event::{Entity, Finding, ForensicEvent, Protocol, Severity};

    fn proc_event(pid: u32, ppid: Option<u32>, finding: Finding, severity: Severity, confidence: f64) -> ForensicEvent {
        ForensicEvent::builder()
            .source_walker("test_walker")
            .entity(Entity::Process {
                pid,
                name: format!("proc_{pid}"),
                ppid,
            })
            .finding(finding)
            .severity(severity)
            .confidence(confidence)
            .build()
    }

    fn conn_event(src_port: u16, dst_port: u16) -> ForensicEvent {
        ForensicEvent::builder()
            .source_walker("test_walker")
            .entity(Entity::Connection {
                src: SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), src_port),
                dst: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), dst_port),
                proto: Protocol::Tcp,
            })
            .finding(Finding::NetworkBeaconing)
            .severity(Severity::High)
            .confidence(0.9)
            .build()
    }

    #[test]
    fn empty_events_gives_empty_tree() {
        let tree = ProcessTree::from_events(vec![]);
        assert!(tree.roots().is_empty());
    }

    #[test]
    fn single_process_with_no_ppid_is_root() {
        let tree = ProcessTree::from_events(vec![
            proc_event(1, None, Finding::Other("x".into()), Severity::Info, 0.5),
        ]);
        let roots = tree.roots();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].pid, 1);
    }

    #[test]
    fn child_process_attaches_under_parent() {
        // pid 1 is the parent, pid 2 has ppid = 1
        let tree = ProcessTree::from_events(vec![
            proc_event(1, None, Finding::Other("x".into()), Severity::Info, 0.5),
            proc_event(2, Some(1), Finding::Other("x".into()), Severity::Info, 0.5),
        ]);
        let roots = tree.roots();
        assert_eq!(roots.len(), 1, "should have exactly one root");
        assert_eq!(roots[0].pid, 1);
        assert_eq!(roots[0].children.len(), 1);
        assert_eq!(roots[0].children[0].pid, 2);
    }

    #[test]
    fn deep_tree_three_levels() {
        // 1 → 2 → 3
        let tree = ProcessTree::from_events(vec![
            proc_event(1, None, Finding::Other("x".into()), Severity::Info, 0.5),
            proc_event(2, Some(1), Finding::Other("x".into()), Severity::Info, 0.5),
            proc_event(3, Some(2), Finding::Other("x".into()), Severity::Info, 0.5),
        ]);
        let roots = tree.roots();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].pid, 1);
        assert_eq!(roots[0].children.len(), 1);
        assert_eq!(roots[0].children[0].pid, 2);
        assert_eq!(roots[0].children[0].children.len(), 1);
        assert_eq!(roots[0].children[0].children[0].pid, 3);
    }

    #[test]
    fn orphaned_node_has_ppid_but_parent_missing() {
        // pid 99 claims ppid = 1 but pid 1 is not in any event
        let tree = ProcessTree::from_events(vec![
            proc_event(99, Some(1), Finding::Other("x".into()), Severity::Info, 0.5),
        ]);
        let orphans = tree.orphaned_nodes();
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].pid, 99);
    }

    #[test]
    fn find_pid_returns_correct_node() {
        let tree = ProcessTree::from_events(vec![
            proc_event(1, None, Finding::Other("x".into()), Severity::Info, 0.5),
            proc_event(2, Some(1), Finding::Other("x".into()), Severity::Info, 0.5),
            proc_event(3, Some(2), Finding::Other("x".into()), Severity::Info, 0.5),
        ]);
        let node = tree.find_pid(3).expect("pid 3 should exist");
        assert_eq!(node.pid, 3);
    }

    #[test]
    fn find_pid_returns_none_for_unknown() {
        let tree = ProcessTree::from_events(vec![
            proc_event(1, None, Finding::Other("x".into()), Severity::Info, 0.5),
        ]);
        assert!(tree.find_pid(9999).is_none());
    }

    #[test]
    fn events_attached_to_correct_process_node() {
        // pid 1 gets 2 events, pid 2 gets 1 event
        let tree = ProcessTree::from_events(vec![
            proc_event(1, None, Finding::ProcessHollowing, Severity::High, 0.9),
            proc_event(1, None, Finding::DefenseEvasion, Severity::Medium, 0.7),
            proc_event(2, Some(1), Finding::NetworkBeaconing, Severity::High, 0.8),
        ]);
        let node1 = tree.find_pid(1).expect("pid 1 should exist");
        assert_eq!(node1.events.len(), 2, "pid 1 should have 2 events");
        let node2 = tree.find_pid(2).expect("pid 2 should exist");
        assert_eq!(node2.events.len(), 1, "pid 2 should have 1 event");
    }

    #[test]
    fn non_process_entities_are_excluded_from_tree() {
        // Connection events should not produce ProcessNodes
        let tree = ProcessTree::from_events(vec![
            proc_event(1, None, Finding::Other("x".into()), Severity::Info, 0.5),
            conn_event(8080, 443),
        ]);
        // Only pid 1 should be in the tree
        let roots = tree.roots();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].pid, 1);
        assert!(tree.find_pid(8080).is_none(), "connection src port should not be a pid node");
    }

    #[test]
    fn highest_threat_path_follows_highest_score_children() {
        // Tree: 1 → {2 (low threat), 3 (high threat)} → 4
        // Path should be: 1 → 3 → 4
        let events = vec![
            // pid 1: root, low-scoring
            proc_event(1, None, Finding::Other("x".into()), Severity::Info, 0.5),
            // pid 2: low-scoring child of 1
            proc_event(2, Some(1), Finding::Other("x".into()), Severity::Info, 0.5),
            // pid 3: high-scoring child of 1
            proc_event(3, Some(1), Finding::ProcessHollowing, Severity::Critical, 1.0),
            // pid 4: child of 3
            proc_event(4, Some(3), Finding::NetworkBeaconing, Severity::High, 1.0),
        ];
        let tree = ProcessTree::from_events(events);
        let path = tree.highest_threat_path();
        let pids: Vec<u32> = path.iter().map(|n| n.pid).collect();
        // pid 1 → pid 3 → pid 4
        assert_eq!(pids, vec![1, 3, 4], "path was: {pids:?}");
    }
}
