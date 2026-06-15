//! Magic GID detection — identifies processes controlled by LD_PRELOAD rootkits.
//!
//! Father rootkit (github.com/mav8557/Father) grants GID 7823 to processes
//! it controls via its accept() hook. Scanning /proc/<pid>/status for
//! supplementary GIDs that match known rootkit magic values is a reliable
//! indicator even when the process is hidden from readdir.

/// Magic GID used by the Father rootkit to mark controlled processes.
pub const FATHER_MAGIC_GID: u32 = 7823;

/// Known rootkit magic GIDs to watch for.
///
/// Each entry is `(gid, rootkit_name)`.
pub const KNOWN_MAGIC_GIDS: &[(u32, &str)] = &[(7823, "Father")];

/// Returns `Some(rootkit_name)` if the GID is a known rootkit magic GID,
/// or `None` if it is not recognised.
pub fn classify_magic_gid(gid: u32) -> Option<&'static str> {
    KNOWN_MAGIC_GIDS
        .iter()
        .find(|&&(known_gid, _)| known_gid == gid)
        .map(|&(_, name)| name)
}

/// Returns `true` if any GID in the list is a known rootkit magic GID.
pub fn has_magic_gid(gids: &[u32]) -> bool {
    gids.iter().any(|&g| classify_magic_gid(g).is_some())
}

/// A finding produced when a process carries a known rootkit magic GID.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MagicGidFinding {
    /// Process ID.
    pub pid: u32,
    /// Process name (`task_struct.comm`, max 16 chars).
    pub comm: String,
    /// The magic GID that triggered this finding.
    pub magic_gid: u32,
    /// Name of the rootkit associated with the magic GID.
    pub rootkit_name: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_father_magic_gid_returns_some() {
        assert_eq!(classify_magic_gid(7823), Some("Father"));
    }

    #[test]
    fn classify_normal_gid_returns_none() {
        assert_eq!(classify_magic_gid(1000), None);
    }

    #[test]
    fn classify_zero_gid_returns_none() {
        assert_eq!(classify_magic_gid(0), None);
    }

    #[test]
    fn has_magic_gid_true_when_present() {
        assert!(has_magic_gid(&[1000, 7823]));
    }

    #[test]
    fn has_magic_gid_false_when_absent() {
        assert!(!has_magic_gid(&[1000, 2000]));
    }

    #[test]
    fn has_magic_gid_empty_slice_is_false() {
        assert!(!has_magic_gid(&[]));
    }

    #[test]
    fn magic_gid_finding_fields_constructible() {
        let finding = MagicGidFinding {
            pid: 1234,
            comm: "evil".to_string(),
            magic_gid: 7823,
            rootkit_name: "Father",
        };
        assert_eq!(finding.pid, 1234);
        assert_eq!(finding.comm, "evil");
        assert_eq!(finding.magic_gid, 7823);
        assert_eq!(finding.rootkit_name, "Father");
    }

    #[test]
    fn magic_gid_finding_serializes_to_json() {
        let finding = MagicGidFinding {
            pid: 42,
            comm: "rootkit".to_string(),
            magic_gid: 7823,
            rootkit_name: "Father",
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("\"pid\":42"));
        assert!(json.contains("\"magic_gid\":7823"));
        assert!(json.contains("\"rootkit_name\":\"Father\""));
    }

    #[test]
    fn magic_gid_finding_clone_and_debug() {
        let finding = MagicGidFinding {
            pid: 99,
            comm: "sh".to_string(),
            magic_gid: 7823,
            rootkit_name: "Father",
        };
        let cloned = finding.clone();
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("Father"));
    }

    #[test]
    fn father_magic_gid_constant_matches_known_table() {
        let found = KNOWN_MAGIC_GIDS
            .iter()
            .any(|&(gid, name)| gid == FATHER_MAGIC_GID && name == "Father");
        assert!(found, "FATHER_MAGIC_GID must appear in KNOWN_MAGIC_GIDS");
    }
}
