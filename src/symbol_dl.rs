//! ISF symbol auto-download from the community server.
//!
//! Cache directory: `~/.cache/memf/symbols/`
//! Server: see [`forensicnomicon::toolchain::VOLATILITY3_VOLATILITY3_ISF_SERVER`]
//! URL pattern: `<server>/windows/<pdb_name>/<GUID><AGE>.json.xz`

use std::path::{Path, PathBuf};

use forensicnomicon::toolchain::VOLATILITY3_ISF_SERVER;

/// Returns the default ISF cache directory (`~/.cache/memf/symbols/`).
pub fn default_cache_dir() -> PathBuf {
    dirs_next_cache().join("memf/symbols")
}

/// Returns a cache directory rooted at `base` (for testing without touching `~/.cache`).
pub fn cache_dir_for_testing(base: &Path) -> PathBuf {
    base.join("memf/symbols")
}

/// Create the cache directory (and all parents) if it does not exist.
pub fn ensure_cache_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    Ok(())
}

/// Build the full ISF download URL for a given PDB name + GUID + age.
///
/// `guid` must be an uppercase hex string without hyphens (32 chars).
/// `age` is the PDB age (decimal).
pub fn build_isf_url(pdb_name: &str, guid: &str, age: u32) -> String {
    format!("{VOLATILITY3_ISF_SERVER}/windows/{pdb_name}/{guid}{age}.json.xz")
}

/// Returns the filename used to cache an ISF for a given pdb+guid+age.
pub fn cache_filename(pdb_name: &str, guid: &str, age: u32) -> String {
    format!("{pdb_name}-{guid}{age}.json")
}

/// Check if an ISF is already cached; returns the path if so.
pub fn find_cached(cache_dir: &Path, pdb_name: &str, guid: &str, age: u32) -> Option<PathBuf> {
    let path = cache_dir.join(cache_filename(pdb_name, guid, age));
    if path.is_file() { Some(path) } else { None }
}

/// Download an ISF from the community server, decompress it, and store it in `cache_dir`.
/// Returns the path to the cached `.json` file on success.
pub fn download_isf(
    cache_dir: &Path,
    pdb_name: &str,
    guid: &str,
    age: u32,
) -> anyhow::Result<PathBuf> {
    let url = build_isf_url(pdb_name, guid, age);
    let resp = ureq::get(&url)
        .call()
        .map_err(|e| anyhow::anyhow!("ISF download failed for {url}: {e}"))?;

    // Check HTTP status before reading the body — a 404 body is HTML, not XZ,
    // and would produce a confusing "XZ decompression failed" error otherwise.
    let status = resp.status();
    if status != 200 {
        anyhow::bail!("ISF server returned HTTP {status} for {url}\nHint: check the PDB GUID/age match the dump's kernel version.");
    }

    let compressed = resp
        .into_body()
        .read_to_vec()
        .map_err(|e| anyhow::anyhow!("failed to read ISF response body from {url}: {e}"))?;

    // Decompress .xz stream → raw JSON bytes
    let mut json_bytes = Vec::new();
    lzma_rs::xz_decompress(&mut compressed.as_slice(), &mut json_bytes)
        .map_err(|e| anyhow::anyhow!("XZ decompression failed for {url}: {e}"))?;

    ensure_cache_dir(cache_dir)?;
    let dest = cache_dir.join(cache_filename(pdb_name, guid, age));
    // Write atomically: write to a temp file then rename, so a partial download
    // never leaves a corrupt cache entry that would be served on the next run.
    let tmp = dest.with_extension("json.tmp");
    std::fs::write(&tmp, &json_bytes)
        .map_err(|e| anyhow::anyhow!("failed to write temp ISF to {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &dest)
        .map_err(|e| anyhow::anyhow!("failed to install ISF to {}: {e}", dest.display()))?;
    Ok(dest)
}

/// Discover a cached ISF or auto-download one, searching `cache_dir` first.
///
/// `allow_network` gates the phone-home: when `false` (offline mode) a cache
/// miss returns an error instead of reaching the ISF community server. A cache
/// hit always resolves regardless of `allow_network`.
pub fn resolve_isf(
    cache_dir: &Path,
    pdb_name: &str,
    guid: &str,
    age: u32,
    allow_network: bool,
) -> anyhow::Result<PathBuf> {
    if let Some(cached) = find_cached(cache_dir, pdb_name, guid, age) {
        return Ok(cached);
    }
    if !allow_network {
        anyhow::bail!(
            "{pdb_name} not in symbol cache and network download disabled (offline mode)\n\
             Hint: run `memf symserver <dump>` while online to populate the cache, then retry."
        );
    }
    download_isf(cache_dir, pdb_name, guid, age)
}

// ---------------------------------------------------------------------------
// Platform-agnostic cache base directory
// ---------------------------------------------------------------------------

fn dirs_next_cache() -> PathBuf {
    // Replicate XDG_CACHE_HOME / macOS ~/Library/Caches without pulling in `dirs`.
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join("Library/Caches");
        }
    }
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(xdg);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".cache");
    }
    PathBuf::from(".cache")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_dl_cache_dir_is_created() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = cache_dir_for_testing(tmp.path());
        ensure_cache_dir(&cache).unwrap();
        assert!(cache.exists());
    }

    #[test]
    fn test_symbol_dl_build_isf_url_win10_19041() {
        let url = build_isf_url("ntkrnlmp.pdb", "81BC5C377C525081645F9958F209C527", 1);
        assert!(url.contains("ntkrnlmp.pdb"), "url={url}");
        assert!(url.contains("81BC5C"), "url={url}");
    }

    #[test]
    fn test_symbol_dl_build_isf_url_format() {
        let url = build_isf_url("ntoskrnl.exe.pdb", "AABBCC001", 2);
        assert!(url.starts_with("https://"), "must be https: {url}");
        assert!(url.contains("ntoskrnl.exe.pdb"), "must contain pdb name: {url}");
        assert!(url.ends_with(".json.xz"), "must end with .json.xz: {url}");
    }

    #[test]
    fn test_symbol_dl_cache_key_stable() {
        let k1 = cache_filename("ntkrnlmp.pdb", "GUID123", 1);
        let k2 = cache_filename("ntkrnlmp.pdb", "GUID123", 1);
        assert_eq!(k1, k2);
        let k3 = cache_filename("ntkrnlmp.pdb", "GUID456", 1);
        assert_ne!(k1, k3);
    }

    #[test]
    fn test_find_cached_returns_none_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let result = find_cached(tmp.path(), "ntkrnlmp.pdb", "DEADBEEF", 1);
        assert!(result.is_none());
    }

    #[test]
    fn test_find_cached_returns_path_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let name = cache_filename("ntkrnlmp.pdb", "DEADBEEF", 1);
        let file = tmp.path().join(&name);
        std::fs::write(&file, b"{}").unwrap();
        let result = find_cached(tmp.path(), "ntkrnlmp.pdb", "DEADBEEF", 1);
        assert_eq!(result, Some(file));
    }

    #[test]
    #[ignore = "requires network access to ISF community server"]
    fn test_download_isf_fetches_and_decompresses() {
        let tmp = tempfile::tempdir().unwrap();
        // Windows 10 19041 ntkrnlmp — real GUID from a known dump
        let path = download_isf(
            tmp.path(),
            "ntkrnlmp.pdb",
            "81BC5C377C525081645F9958F209C5271",
            1,
        )
        .expect("download should succeed");
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"symbols\""), "ISF must have symbols key");
    }

    /// Offline mode (`allow_network = false`) with an empty cache returns an
    /// error WITHOUT attempting the network download — deterministic, runs with
    /// no network available (no `#[ignore]`).
    #[test]
    fn test_resolve_isf_offline_cache_miss_errors_without_network() {
        let tmp = tempfile::tempdir().unwrap();
        let result = resolve_isf(tmp.path(), "ntkrnlmp.pdb", "DEADBEEF", 1, false);
        assert!(
            result.is_err(),
            "offline cache-miss must error, not phone home"
        );
        let msg = result.err().unwrap().to_string();
        assert!(
            msg.contains("offline"),
            "error should explain offline mode, got: {msg}"
        );
    }

    /// Offline mode still serves a cache HIT — disabling the network must not
    /// disable using symbols already on disk.
    #[test]
    fn test_resolve_isf_offline_cache_hit_returns_cached() {
        let tmp = tempfile::tempdir().unwrap();
        let name = cache_filename("ntkrnlmp.pdb", "CAFEBABE", 1);
        let file = tmp.path().join(&name);
        std::fs::write(&file, b"{}").unwrap();
        let result = resolve_isf(tmp.path(), "ntkrnlmp.pdb", "CAFEBABE", 1, false)
            .expect("cache hit must resolve even offline");
        assert_eq!(result, file);
    }
}
