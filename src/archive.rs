use anyhow::{bail, Context, Result};
use std::io::Read;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

/// Magic bytes for zip (PK local file header).
const ZIP_MAGIC: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

/// Magic bytes for an empty zip (PK end-of-central-directory only).
const ZIP_EMPTY_MAGIC: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];

/// Magic bytes for 7z.
const SEVENZ_MAGIC: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// Known dump file extensions (prioritized during archive extraction).
const DUMP_EXTENSIONS: &[&str] = &[
    "dmp", "vmem", "raw", "lime", "mem", "vmss", "vmsn", "core", "img",
];

/// Result of resolving a dump path — the original file or extracted from an archive.
pub enum ResolvedDump {
    /// Path points directly to a dump file.
    Direct(PathBuf),
    /// Dump was extracted from an archive to a temp file.
    Extracted(NamedTempFile),
}

impl ResolvedDump {
    pub fn path(&self) -> &Path {
        match self {
            Self::Direct(p) => p,
            Self::Extracted(t) => t.path(),
        }
    }
}

/// If `path` is a zip or 7z archive (detected by magic bytes), extract the best
/// dump candidate to a temp file. Otherwise return the path unchanged.
pub fn resolve_dump(path: &Path) -> Result<ResolvedDump> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut magic = [0u8; 6];
    let n = file.read(&mut magic)?;

    if n >= 4 && (magic[..4] == ZIP_MAGIC || magic[..4] == ZIP_EMPTY_MAGIC) {
        return extract_from_zip(path).map(ResolvedDump::Extracted);
    }
    if n >= 6 && magic[..6] == SEVENZ_MAGIC {
        return extract_from_7z(path).map(ResolvedDump::Extracted);
    }

    Ok(ResolvedDump::Direct(path.to_path_buf()))
}

fn extract_from_zip(path: &Path) -> Result<NamedTempFile> {
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    let entries: Vec<(String, u64)> = (0..archive.len())
        .filter_map(|i| {
            let entry = archive.by_index(i).ok()?;
            if entry.is_dir() {
                return None;
            }
            Some((entry.name().to_string(), entry.size()))
        })
        .collect();

    let best = pick_best_entry(&entries)
        .context("archive contains no extractable files")?
        .to_string();

    let mut src = archive.by_name(&best)?;
    let mut tmp = NamedTempFile::new()?;
    std::io::copy(&mut src, &mut tmp)?;
    Ok(tmp)
}

fn extract_from_7z(path: &Path) -> Result<NamedTempFile> {
    let mut reader = sevenz_rust::SevenZReader::open(path, sevenz_rust::Password::empty())
        .map_err(|e| anyhow::anyhow!("failed to open 7z archive: {e}"))?;

    let entries: Vec<(String, u64)> = reader
        .archive()
        .files
        .iter()
        .filter(|e| !e.is_directory && e.has_stream)
        .map(|e| (e.name.clone(), e.size))
        .collect();

    let best = pick_best_entry(&entries)
        .context("archive contains no extractable files")?
        .to_string();

    let mut tmp = NamedTempFile::new()?;
    let mut found = false;
    reader
        .for_each_entries(|entry, rd| {
            if entry.name == best {
                std::io::copy(rd, &mut tmp).map_err(sevenz_rust::Error::io)?;
                found = true;
                return Ok(false); // stop iteration
            }
            Ok(true) // continue
        })
        .map_err(|e| anyhow::anyhow!("7z extraction failed: {e}"))?;

    if !found {
        bail!("entry {best:?} not found in 7z archive");
    }
    Ok(tmp)
}

/// Pick the best filename from a list of (name, uncompressed_size) entries.
/// Prefers files with known dump extensions; falls back to largest.
fn pick_best_entry(entries: &[(String, u64)]) -> Option<&str> {
    // Prefer entries with known dump extensions, pick largest among those.
    let dump_candidates: Vec<&(String, u64)> = entries
        .iter()
        .filter(|(name, _)| {
            Path::new(name)
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|ext| DUMP_EXTENSIONS.contains(&ext))
        })
        .collect();

    let best = if dump_candidates.is_empty() {
        // Fallback: largest file by uncompressed size.
        entries.iter().max_by_key(|(_, size)| *size)?
    } else {
        dump_candidates.into_iter().max_by_key(|(_, size)| *size)?
    };

    Some(&best.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // --- pick_best_entry ---

    #[test]
    fn pick_best_entry_prefers_dump_extension() {
        let entries = vec![
            ("readme.txt".to_string(), 1000),
            ("memory.dmp".to_string(), 500),
        ];
        assert_eq!(pick_best_entry(&entries), Some("memory.dmp"));
    }

    #[test]
    fn pick_best_entry_largest_among_dump_extensions() {
        let entries = vec![
            ("small.dmp".to_string(), 100),
            ("large.vmem".to_string(), 9000),
        ];
        assert_eq!(pick_best_entry(&entries), Some("large.vmem"));
    }

    #[test]
    fn pick_best_entry_falls_back_to_largest() {
        let entries = vec![
            ("small.bin".to_string(), 100),
            ("large.bin".to_string(), 9000),
        ];
        assert_eq!(pick_best_entry(&entries), Some("large.bin"));
    }

    #[test]
    fn pick_best_entry_empty_returns_none() {
        let entries: Vec<(String, u64)> = vec![];
        assert_eq!(pick_best_entry(&entries), None);
    }

    // --- resolve_dump passthrough ---

    #[test]
    fn non_archive_returns_direct() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"not an archive at all").unwrap();
        let result = resolve_dump(tmp.path()).unwrap();
        assert!(matches!(result, ResolvedDump::Direct(_)));
        assert_eq!(result.path(), tmp.path());
    }

    // --- zip extraction ---

    #[test]
    fn zip_extracts_dump_file() {
        let zip_file = create_test_zip(&[("memdump.dmp", &[0xDE, 0xAD, 0xBE, 0xEF])]);
        let result = resolve_dump(zip_file.path()).unwrap();
        assert!(matches!(result, ResolvedDump::Extracted(_)));
        let mut content = Vec::new();
        std::fs::File::open(result.path())
            .unwrap()
            .read_to_end(&mut content)
            .unwrap();
        assert_eq!(content, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn zip_prefers_dump_extension_over_largest() {
        let big_txt = vec![0u8; 1000];
        let small_dmp = vec![0xAB; 100];
        let zip_file = create_test_zip(&[("notes.txt", &big_txt), ("memory.dmp", &small_dmp)]);
        let result = resolve_dump(zip_file.path()).unwrap();
        assert!(matches!(result, ResolvedDump::Extracted(_)));
        let meta = std::fs::metadata(result.path()).unwrap();
        assert_eq!(meta.len(), 100);
    }

    #[test]
    fn zip_empty_archive_errors() {
        let zip_file = create_test_zip(&[]);
        let result = resolve_dump(zip_file.path());
        assert!(result.is_err());
    }

    // --- 7z extraction ---

    #[test]
    fn sevenz_extracts_dump_file() {
        let archive = create_test_7z(&[("memdump.dmp", &[0xCA, 0xFE])]);
        let result = resolve_dump(archive.path()).unwrap();
        assert!(matches!(result, ResolvedDump::Extracted(_)));
        let mut content = Vec::new();
        std::fs::File::open(result.path())
            .unwrap()
            .read_to_end(&mut content)
            .unwrap();
        assert_eq!(content, [0xCA, 0xFE]);
    }

    #[test]
    fn sevenz_invalid_archive_errors() {
        let mut tmp = tempfile::Builder::new().suffix(".7z").tempfile().unwrap();
        // Valid magic but truncated/corrupt body
        tmp.write_all(&SEVENZ_MAGIC).unwrap();
        tmp.write_all(b"garbage_not_valid_7z_data").unwrap();
        let result = resolve_dump(tmp.path());
        assert!(result.is_err());
    }

    // --- test helpers ---

    fn create_test_zip(files: &[(&str, &[u8])]) -> NamedTempFile {
        let tmp = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
        let file = std::fs::File::create(tmp.path()).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        for (name, data) in files {
            writer
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap();
        tmp
    }

    fn create_test_7z(files: &[(&str, &[u8])]) -> NamedTempFile {
        let tmp = tempfile::Builder::new().suffix(".7z").tempfile().unwrap();
        let mut writer = sevenz_rust::SevenZWriter::create(tmp.path()).unwrap();
        for (name, data) in files {
            let mut entry = sevenz_rust::SevenZArchiveEntry::new();
            entry.name = name.to_string();
            entry.has_stream = true;
            writer
                .push_archive_entry(entry, Some(std::io::Cursor::new(data.to_vec())))
                .unwrap();
        }
        writer.finish().unwrap();
        tmp
    }
}
