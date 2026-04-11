use std::path::Path;

use memmap2::Mmap;

/// Error type for `KnownGoodDb` operations.
#[derive(Debug)]
pub enum KnownGoodError {
    Io(std::io::Error),
    InvalidFileSize { bytes: u64 },
}

impl std::fmt::Display for KnownGoodError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::InvalidFileSize { bytes } => {
                write!(f, "file size {bytes} is not a multiple of 32 bytes")
            }
        }
    }
}

impl std::error::Error for KnownGoodError {}

impl From<std::io::Error> for KnownGoodError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Zero-false-positive known-good file hash database.
///
/// Backed by a memory-mapped binary file containing sorted 32-byte SHA-256
/// hashes. Binary search provides exact matching — no probabilistic structure,
/// making it safe for forensic exclusion decisions.
pub struct KnownGoodDb {
    /// `None` when the file is empty (zero hashes).
    mmap: Option<Mmap>,
}

impl KnownGoodDb {
    /// Open a binary file containing sorted 32-byte SHA-256 hashes.
    /// File must be a multiple of 32 bytes.
    pub fn open(path: &Path) -> Result<Self, KnownGoodError> {
        let file = std::fs::File::open(path)?;
        let meta = file.metadata()?;
        let bytes = meta.len();
        if bytes % 32 != 0 {
            return Err(KnownGoodError::InvalidFileSize { bytes });
        }
        if bytes == 0 {
            return Ok(Self { mmap: None });
        }
        // SAFETY: file is opened read-only; caller is responsible for not
        // modifying the file while this mapping is live (standard mmap contract).
        let mmap = unsafe { memmap2::MmapOptions::new().map(&file)? };
        Ok(Self { mmap: Some(mmap) })
    }

    /// Returns `true` iff the hash is present in the database.
    /// Zero false positives — safe for forensic exclusion decisions.
    pub fn is_known_good(&self, sha256: &[u8; 32]) -> bool {
        let Some(ref mmap) = self.mmap else {
            return false;
        };
        let count = mmap.len() / 32;
        let data = mmap.as_ref();
        let mut lo = 0usize;
        let mut hi = count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let entry: &[u8; 32] = data[mid * 32..(mid + 1) * 32].try_into().unwrap();
            match entry.cmp(sha256) {
                std::cmp::Ordering::Equal => return true,
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        false
    }

    /// Number of hashes in the database.
    pub fn len(&self) -> usize {
        self.mmap.as_ref().map_or(0, |m| m.len() / 32)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_sorted_hashes(hashes: &mut Vec<[u8; 32]>) -> tempfile::NamedTempFile {
        hashes.sort();
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for h in hashes.iter() {
            f.write_all(h).unwrap();
        }
        f
    }

    #[test]
    fn known_good_exact_hit_returns_true() {
        let mut hashes: Vec<[u8; 32]> = vec![[0xaau8; 32], [0xbbu8; 32], [0xccu8; 32]];
        let f = write_sorted_hashes(&mut hashes);
        let db = KnownGoodDb::open(f.path()).unwrap();
        assert!(db.is_known_good(&[0xaau8; 32]));
    }

    #[test]
    fn known_good_miss_returns_false() {
        let mut hashes: Vec<[u8; 32]> = vec![[0xaau8; 32], [0xbbu8; 32]];
        let f = write_sorted_hashes(&mut hashes);
        let db = KnownGoodDb::open(f.path()).unwrap();
        assert!(!db.is_known_good(&[0xccu8; 32]));
    }

    #[test]
    fn known_good_empty_db_returns_false() {
        let mut hashes: Vec<[u8; 32]> = vec![];
        let f = write_sorted_hashes(&mut hashes);
        let db = KnownGoodDb::open(f.path()).unwrap();
        assert!(!db.is_known_good(&[0x01u8; 32]));
    }

    #[test]
    fn known_good_invalid_file_size_returns_error() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&[0u8; 31]).unwrap(); // 31 bytes — not a multiple of 32
        let result = KnownGoodDb::open(f.path());
        assert!(
            matches!(result, Err(KnownGoodError::InvalidFileSize { bytes: 31 })),
            "expected InvalidFileSize error"
        );
    }

    #[test]
    fn known_good_first_entry_found() {
        let mut hashes: Vec<[u8; 32]> = vec![[0x01u8; 32], [0x80u8; 32], [0xffu8; 32]];
        let f = write_sorted_hashes(&mut hashes);
        let db = KnownGoodDb::open(f.path()).unwrap();
        // After sort, 0x01 is first
        assert!(db.is_known_good(&[0x01u8; 32]));
    }

    #[test]
    fn known_good_last_entry_found() {
        let mut hashes: Vec<[u8; 32]> = vec![[0x01u8; 32], [0x80u8; 32], [0xffu8; 32]];
        let f = write_sorted_hashes(&mut hashes);
        let db = KnownGoodDb::open(f.path()).unwrap();
        // After sort, 0xff is last
        assert!(db.is_known_good(&[0xffu8; 32]));
    }

    #[test]
    fn known_good_len_correct() {
        let mut hashes: Vec<[u8; 32]> = vec![[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]];
        let f = write_sorted_hashes(&mut hashes);
        let db = KnownGoodDb::open(f.path()).unwrap();
        assert_eq!(db.len(), 3);
    }
}
