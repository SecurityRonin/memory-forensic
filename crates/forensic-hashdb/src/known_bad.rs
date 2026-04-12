use crate::types::BadFileInfo;
#[cfg(test)]
use crate::types::BadFileSource;
use std::collections::HashMap;

/// Provenance-tracked malware hash lookup database.
///
/// Phase 1: backed by a `HashMap` (exact matching, zero false positives).
/// Phase 2 (future): `might_be_malicious` will be backed by an XOR filter
/// pre-screen, but the public API will remain unchanged.
pub struct KnownBadDb {
    entries: HashMap<[u8; 32], BadFileInfo>,
}

impl KnownBadDb {
    /// Construct from an iterator of `(sha256, info)` pairs.
    pub fn from_entries(iter: impl IntoIterator<Item = ([u8; 32], BadFileInfo)>) -> Self {
        Self {
            entries: iter.into_iter().collect(),
        }
    }

    /// Fast pre-screen. Returns `true` if the hash MIGHT be in the database.
    ///
    /// No false negatives. Phase 1: backed by `HashMap` (no false positives
    /// either). Phase 2 will swap in an XOR filter pre-screen.
    pub fn might_be_malicious(&self, sha256: &[u8; 32]) -> bool {
        self.entries.contains_key(sha256)
    }

    /// Exact lookup with full provenance. Returns `None` if definitely not present.
    pub fn lookup(&self, sha256: &[u8; 32]) -> Option<&BadFileInfo> {
        self.entries.get(sha256)
    }

    /// Number of entries in the database.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_info(sha256: [u8; 32], source: BadFileSource) -> BadFileInfo {
        BadFileInfo {
            sha256,
            source,
            malware_family: Some("TestFamily".to_string()),
            tags: vec!["test".to_string()],
        }
    }

    #[test]
    fn known_bad_lookup_hit_returns_info() {
        let sha = [0x42u8; 32];
        let info = make_info(sha, BadFileSource::MalwareBazaar);
        let db = KnownBadDb::from_entries([(sha, info)]);
        let result = db.lookup(&sha);
        assert!(result.is_some());
        assert_eq!(result.unwrap().sha256, sha);
    }

    #[test]
    fn known_bad_lookup_miss_returns_none() {
        let sha = [0x42u8; 32];
        let info = make_info(sha, BadFileSource::VirusShare);
        let db = KnownBadDb::from_entries([(sha, info)]);
        assert!(db.lookup(&[0x99u8; 32]).is_none());
    }

    #[test]
    fn known_bad_might_be_malicious_hit_returns_true() {
        let sha = [0x11u8; 32];
        let info = make_info(sha, BadFileSource::Malshare);
        let db = KnownBadDb::from_entries([(sha, info)]);
        assert!(db.might_be_malicious(&sha));
    }

    #[test]
    fn known_bad_might_be_malicious_miss_returns_false() {
        let sha = [0x11u8; 32];
        let info = make_info(sha, BadFileSource::AlienVaultOtx);
        let db = KnownBadDb::from_entries([(sha, info)]);
        assert!(!db.might_be_malicious(&[0x22u8; 32]));
    }

    #[test]
    fn known_bad_empty_db() {
        let db = KnownBadDb::from_entries([]);
        assert!(db.is_empty());
        assert_eq!(db.len(), 0);
        assert!(db.lookup(&[0x00u8; 32]).is_none());
        assert!(!db.might_be_malicious(&[0x00u8; 32]));
    }

    #[test]
    fn bad_file_info_source_custom() {
        let sha = [0xddu8; 32];
        let info = BadFileInfo {
            sha256: sha,
            source: BadFileSource::Custom("my-internal-feed"),
            malware_family: None,
            tags: vec![],
        };
        let db = KnownBadDb::from_entries([(sha, info)]);
        let result = db.lookup(&sha).unwrap();
        assert_eq!(result.source, BadFileSource::Custom("my-internal-feed"));
    }
}
