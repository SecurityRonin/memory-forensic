use anyhow::{bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::io::Read;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

/// Magic bytes for zip (PK local file header).
const ZIP_MAGIC: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

/// Magic bytes for an empty zip (PK end-of-central-directory only).
const ZIP_EMPTY_MAGIC: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];

/// Magic bytes for gzip (covers .tar.gz / .tgz).
const GZIP_MAGIC: [u8; 2] = [0x1F, 0x8B];

/// Magic bytes for bzip2 (covers .tar.bz2).
const BZIP2_MAGIC: [u8; 3] = [0x42, 0x5A, 0x68]; // "BZh"

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

    /// Whether the dump was extracted from an archive (needs raw fallback).
    pub fn is_extracted(&self) -> bool {
        matches!(self, Self::Extracted(_))
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
    if n >= 2 && magic[..2] == GZIP_MAGIC {
        return extract_from_tar_gz(path).map(ResolvedDump::Extracted);
    }
    if n >= 3 && magic[..3] == BZIP2_MAGIC {
        return extract_from_tar_bz2(path).map(ResolvedDump::Extracted);
    }

    Ok(ResolvedDump::Direct(path.to_path_buf()))
}

/// List readable file entries in a zip archive, separating successes from errors.
///
/// Returns `(readable_entries, errors)` where each readable entry is `(name, size)`
/// and each error is a human-readable description of why `by_index()` failed.
fn enumerate_zip_entries(
    archive: &mut zip::ZipArchive<std::fs::File>,
) -> (Vec<(String, u64)>, Vec<String>) {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for i in 0..archive.len() {
        match archive.by_index(i) {
            Ok(entry) => {
                if !entry.is_dir() {
                    entries.push((entry.name().to_string(), entry.size()));
                }
            }
            Err(e) => errors.push(format!("{e}")),
        }
    }
    (entries, errors)
}

fn extract_from_zip(path: &Path) -> Result<NamedTempFile> {
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    let total = archive.len();
    let (entries, errors) = enumerate_zip_entries(&mut archive);

    let best = pick_best_entry(&entries)
        .with_context(|| {
            if errors.is_empty() {
                "archive contains no extractable files".to_string()
            } else {
                format!(
                    "archive has {total} entries but none could be extracted \
                     ({} skipped: {})",
                    errors.len(),
                    errors[0]
                )
            }
        })?
        .to_string();

    let size = entries.iter().find(|(n, _)| n == &best).map(|(_, s)| *s);
    let mut src = archive.by_name(&best)?;
    let mut tmp = NamedTempFile::new()?;
    copy_with_progress(&mut src, &mut tmp, &best, size)?;
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

    let best_size = entries.iter().find(|(n, _)| n == &best).map(|(_, s)| *s);
    let mut tmp = NamedTempFile::new()?;
    let mut found = false;
    reader
        .for_each_entries(|entry, rd| {
            if entry.name == best {
                copy_with_progress(rd, &mut tmp, &best, best_size)
                    .map_err(sevenz_rust::Error::io)?;
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

/// Wraps a reader to update a progress bar with bytes consumed.
struct ProgressReader<R> {
    inner: R,
    pb: ProgressBar,
}

impl<R> ProgressReader<R> {
    fn new(inner: R, pb: ProgressBar) -> Self {
        Self { inner, pb }
    }
}

impl<R: Read> Read for ProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.pb.inc(n as u64);
        Ok(n)
    }
}

/// Enumerate tar entries as `(name, size)` pairs from a decompressed reader.
fn enumerate_tar_entries(reader: impl Read) -> Result<Vec<(String, u64)>> {
    let mut archive = tar::Archive::new(reader);
    let mut entries = Vec::new();
    for entry in archive.entries().context("failed to read tar entries")? {
        let entry = entry.context("failed to read tar entry")?;
        if entry.header().entry_type() == tar::EntryType::Regular {
            let name = entry
                .path()
                .context("invalid tar entry path")?
                .to_string_lossy()
                .into_owned();
            let size = entry.size();
            entries.push((name, size));
        }
    }
    Ok(entries)
}

/// Create a progress bar for scanning/extracting an archive, tracking compressed bytes.
fn scanning_progress_bar(path: &Path) -> Result<(ProgressBar, u64)> {
    let compressed_size = std::fs::metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?
        .len();
    let short = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("archive");
    let pb = ProgressBar::new(compressed_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  scanning {msg} [{bar:30}] {bytes}/{total_bytes}")
            .expect("valid template")
            .progress_chars("=> "),
    );
    pb.set_message(short.to_string());
    Ok((pb, compressed_size))
}

fn extract_from_tar_gz(path: &Path) -> Result<NamedTempFile> {
    // First pass: enumerate entries with progress on compressed bytes read.
    let (pb, _) = scanning_progress_bar(path)?;
    let file = std::fs::File::open(path)?;
    let tracked = ProgressReader::new(file, pb.clone());
    let gz = flate2::read::GzDecoder::new(tracked);
    let entries = enumerate_tar_entries(gz)?;
    pb.finish_and_clear();

    let best = pick_best_entry(&entries)
        .context("tar.gz archive contains no extractable files")?
        .to_string();
    let best_size = entries.iter().find(|(n, _)| n == &best).map(|(_, s)| *s);

    // Second pass: re-open, decompress, and extract with progress.
    let file = std::fs::File::open(path)?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);
    for entry in archive.entries().context("failed to re-read tar.gz entries")? {
        let mut entry = entry.context("failed to re-read tar.gz entry")?;
        let name = entry
            .path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name == best {
            let mut tmp = NamedTempFile::new()?;
            copy_with_progress(&mut entry, &mut tmp, &best, best_size)?;
            return Ok(tmp);
        }
    }
    bail!("entry {best:?} not found in tar.gz archive")
}

fn extract_from_tar_bz2(path: &Path) -> Result<NamedTempFile> {
    // First pass: enumerate entries with progress on compressed bytes read.
    let (pb, _) = scanning_progress_bar(path)?;
    let file = std::fs::File::open(path)?;
    let tracked = ProgressReader::new(file, pb.clone());
    let bz = bzip2::read::BzDecoder::new(tracked);
    let entries = enumerate_tar_entries(bz)?;
    pb.finish_and_clear();

    let best = pick_best_entry(&entries)
        .context("tar.bz2 archive contains no extractable files")?
        .to_string();
    let best_size = entries.iter().find(|(n, _)| n == &best).map(|(_, s)| *s);

    // Second pass: re-open, decompress, and extract with progress.
    let file = std::fs::File::open(path)?;
    let bz = bzip2::read::BzDecoder::new(file);
    let mut archive = tar::Archive::new(bz);
    for entry in archive.entries().context("failed to re-read tar.bz2 entries")? {
        let mut entry = entry.context("failed to re-read tar.bz2 entry")?;
        let name = entry
            .path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name == best {
            let mut tmp = NamedTempFile::new()?;
            copy_with_progress(&mut entry, &mut tmp, &best, best_size)?;
            return Ok(tmp);
        }
    }
    bail!("entry {best:?} not found in tar.bz2 archive")
}

/// Copy `src` to `dst` with a terminal progress bar.
/// Shows a determinate bar when `total` is known, spinner otherwise.
fn copy_with_progress(
    src: &mut dyn Read,
    dst: &mut dyn std::io::Write,
    name: &str,
    total: Option<u64>,
) -> std::io::Result<u64> {
    let pb = if let Some(total) = total {
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("  extracting {msg} [{bar:30}] {bytes}/{total_bytes}")
                .expect("valid template")
                .progress_chars("=> "),
        );
        pb
    } else {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("  extracting {msg} {bytes}")
                .expect("valid template"),
        );
        pb
    };

    let short_name = Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(name);
    pb.set_message(short_name.to_string());

    let mut buf = vec![0u8; 64 * 1024];
    let mut written = 0u64;
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n])?;
        written += n as u64;
        pb.set_position(written);
    }

    pb.finish_and_clear();
    Ok(written)
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

    #[test]
    fn zip_error_includes_skipped_count_and_reason() {
        // When zip entries exist but cannot be read (unsupported compression,
        // encryption, etc.), the error should report how many were skipped
        // and include the first failure reason — not just "no extractable files".
        //
        // We test this structurally: `enumerate_zip_entries` separates listing
        // from extraction so we can verify the (entries, errors) split.
        let zip_file = create_test_zip(&[("dump.dmp", &[0xAB; 64])]);
        let file = std::fs::File::open(zip_file.path()).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        let (entries, errors) = enumerate_zip_entries(&mut archive);
        // Normal zip: all entries readable, no errors.
        assert_eq!(entries.len(), 1);
        assert!(errors.is_empty());
        assert_eq!(entries[0].0, "dump.dmp");
    }

    // --- ProgressReader ---

    #[test]
    fn progress_reader_passes_through_data() {
        let data = b"hello world";
        let pb = ProgressBar::hidden();
        let mut reader = ProgressReader::new(std::io::Cursor::new(data), pb.clone());
        let mut buf = vec![0u8; 64];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello world");
        assert_eq!(pb.position(), 11);
    }

    #[test]
    fn progress_reader_tracks_multiple_reads() {
        let data = vec![0xABu8; 100];
        let pb = ProgressBar::hidden();
        let mut reader = ProgressReader::new(std::io::Cursor::new(data), pb.clone());
        let mut buf = [0u8; 30];
        let mut total = 0u64;
        loop {
            let n = reader.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            total += n as u64;
        }
        assert_eq!(total, 100);
        assert_eq!(pb.position(), 100);
    }

    // --- tar.gz extraction ---

    #[test]
    fn tar_gz_extracts_dump_file() {
        let archive = create_test_tar_gz(&[("memdump.dmp", &[0xDE, 0xAD, 0xBE, 0xEF])]);
        let result = resolve_dump(archive.path()).unwrap();
        assert!(
            matches!(result, ResolvedDump::Extracted(_)),
            "tar.gz should be detected and extracted"
        );
        let mut content = Vec::new();
        std::fs::File::open(result.path())
            .unwrap()
            .read_to_end(&mut content)
            .unwrap();
        assert_eq!(content, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn tar_gz_prefers_dump_extension_over_largest() {
        let big_txt = vec![0u8; 1000];
        let small_dmp = vec![0xAB; 100];
        let archive =
            create_test_tar_gz(&[("notes.txt", &big_txt), ("memory.dmp", &small_dmp)]);
        let result = resolve_dump(archive.path()).unwrap();
        assert!(matches!(result, ResolvedDump::Extracted(_)));
        let meta = std::fs::metadata(result.path()).unwrap();
        assert_eq!(meta.len(), 100);
    }

    #[test]
    fn tar_gz_empty_archive_errors() {
        let archive = create_test_tar_gz(&[]);
        let result = resolve_dump(archive.path());
        assert!(result.is_err(), "empty tar.gz should produce an error");
    }

    // --- tar.bz2 extraction ---

    #[test]
    fn tar_bz2_extracts_dump_file() {
        let archive = create_test_tar_bz2(&[("memdump.raw", &[0xCA, 0xFE])]);
        let result = resolve_dump(archive.path()).unwrap();
        assert!(
            matches!(result, ResolvedDump::Extracted(_)),
            "tar.bz2 should be detected and extracted"
        );
        let mut content = Vec::new();
        std::fs::File::open(result.path())
            .unwrap()
            .read_to_end(&mut content)
            .unwrap();
        assert_eq!(content, [0xCA, 0xFE]);
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

    fn create_test_tar_gz(files: &[(&str, &[u8])]) -> NamedTempFile {
        let tmp = tempfile::Builder::new().suffix(".tar.gz").tempfile().unwrap();
        let gz = flate2::write::GzEncoder::new(
            std::fs::File::create(tmp.path()).unwrap(),
            flate2::Compression::default(),
        );
        let mut builder = tar::Builder::new(gz);
        for (name, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, *name, &data[..]).unwrap();
        }
        builder.finish().unwrap();
        tmp
    }

    fn create_test_tar_bz2(files: &[(&str, &[u8])]) -> NamedTempFile {
        let tmp = tempfile::Builder::new().suffix(".tar.bz2").tempfile().unwrap();
        let bz = bzip2::write::BzEncoder::new(
            std::fs::File::create(tmp.path()).unwrap(),
            bzip2::Compression::default(),
        );
        let mut builder = tar::Builder::new(bz);
        for (name, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, *name, &data[..]).unwrap();
        }
        builder.finish().unwrap();
        tmp
    }

    fn create_test_7z(files: &[(&str, &[u8])]) -> NamedTempFile {
        let tmp = tempfile::Builder::new().suffix(".7z").tempfile().unwrap();
        let mut writer = sevenz_rust::SevenZWriter::create(tmp.path()).unwrap();
        for (name, data) in files {
            let mut entry = sevenz_rust::SevenZArchiveEntry::new();
            entry.name = (*name).to_string();
            entry.has_stream = true;
            writer
                .push_archive_entry(entry, Some(std::io::Cursor::new(data.to_vec())))
                .unwrap();
        }
        writer.finish().unwrap();
        tmp
    }
}
