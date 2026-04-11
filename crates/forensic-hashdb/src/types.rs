/// Source database a known-bad hash came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BadFileSource {
    MalwareBazaar,
    VirusShare,
    Malshare,
    AlienVaultOtx,
    Custom(&'static str),
}

/// Provenance record for a known-bad file hash.
#[derive(Debug, Clone)]
pub struct BadFileInfo {
    pub sha256: [u8; 32],
    pub source: BadFileSource,
    pub malware_family: Option<String>,
    pub tags: Vec<String>,
}

/// A known-vulnerable or known-malicious Windows driver.
#[derive(Debug, Clone)]
pub struct DriverInfo {
    pub name: &'static str,
    pub sha256: [u8; 32],
    pub cves: &'static [&'static str],
    pub description: &'static str,
}
