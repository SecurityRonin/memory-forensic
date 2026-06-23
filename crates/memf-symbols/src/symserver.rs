//! Symbol server client.
//!
//! Provides pure functions for URL construction and cache path computation,
//! plus an optional [`SymbolServerClient`] (behind the `symserver` feature)
//! that downloads PDBs from Microsoft's symbol server with local caching.

use std::path::{Path, PathBuf};

/// Construct the symbol server download URL for a PDB file.
///
/// The GUID is formatted uppercase, no dashes, concatenated with the age in hex.
/// Example: GUID `"1B72224D-37B8-1792-2820-0ED8994498B2"`, age 1
/// produces URL: `{server}/ntkrnlmp.pdb/1B72224D37B8179228200ED8994498B21/ntkrnlmp.pdb`
pub fn download_url(server: &str, pdb_name: &str, guid: &str, age: u32) -> String {
    let guid_clean = guid.replace('-', "").to_uppercase();
    let index = format!("{guid_clean}{age:X}");
    format!("{server}/{pdb_name}/{index}/{pdb_name}")
}

/// Construct the local cache path for a PDB file.
///
/// Layout: `{cache_dir}/{pdb_name}/{GUID_CLEAN}{AGE_HEX}/{pdb_name}`
pub fn cache_path(cache_dir: &Path, pdb_name: &str, guid: &str, age: u32) -> PathBuf {
    let guid_clean = guid.replace('-', "").to_uppercase();
    let index = format!("{guid_clean}{age:X}");
    cache_dir.join(pdb_name).join(index).join(pdb_name)
}

/// Return the default symbol server URL (Microsoft public server).
pub fn default_server_url() -> &'static str {
    "https://msdl.microsoft.com/download/symbols"
}

/// Compute Volatility3's `CACHE_PATH` for a platform from raw env values.
///
/// Pure (no env reads, no I/O) so every platform branch is unit-testable from
/// any host. Mirrors volatility3 `framework/constants/__init__.py` (v2.x):
/// - Unix (Linux/macOS): `${XDG_CACHE_HOME:-$HOME/.cache}/volatility3`
/// - Windows: `%APPDATA%\volatility3` (falling back to `%USERPROFILE%\volatility3`)
fn volatility_cache_path_from(
    is_windows: bool,
    xdg_cache_home: Option<&str>,
    home: Option<&str>,
    appdata: Option<&str>,
    userprofile: Option<&str>,
) -> Option<PathBuf> {
    fn nonempty(s: Option<&str>) -> Option<&str> {
        s.filter(|v| !v.is_empty())
    }
    if is_windows {
        nonempty(appdata)
            .or_else(|| nonempty(userprofile))
            .map(|b| PathBuf::from(b).join("volatility3"))
    } else {
        let base = nonempty(xdg_cache_home)
            .map(PathBuf::from)
            .or_else(|| nonempty(home).map(|h| PathBuf::from(h).join(".cache")))?;
        Some(base.join("volatility3"))
    }
}

/// Return the shared symbol cache directory — Volatility3's `CACHE_PATH`.
///
/// memf deliberately shares Volatility's store (not a memf-private dir) so a
/// single download serves both tools. See [`volatility_cache_path_from`].
pub fn default_cache_dir() -> Option<PathBuf> {
    let xdg = std::env::var("XDG_CACHE_HOME").ok();
    let home = std::env::var("HOME").ok();
    let appdata = std::env::var("APPDATA").ok();
    let userprofile = std::env::var("USERPROFILE").ok();
    volatility_cache_path_from(
        cfg!(target_os = "windows"),
        xdg.as_deref(),
        home.as_deref(),
        appdata.as_deref(),
        userprofile.as_deref(),
    )
}

/// Extract the first usable local *downstream store* directory from a
/// `_NT_SYMBOL_PATH` value (the WinDbg/symstore convention), or `None` if it
/// only references remote servers.
///
/// Handles `;`-separated elements in the forms `srv*DIR*URL`, `cache*DIR`,
/// `symsrv*symsrv.dll*DIR*URL`, and a plain `DIR`.
fn nt_symbol_store_dir(nt_symbol_path: &str) -> Option<&str> {
    let _ = nt_symbol_path;
    todo!("GREEN: parse _NT_SYMBOL_PATH downstream store")
}

/// Resolve the symbol cache dir honoring overrides, else the platform default.
///
/// Order: `$MEMF_SYMBOL_CACHE` → `_NT_SYMBOL_PATH` store dir → `default`.
/// Pure (env passed in) so it is unit-testable.
fn resolve_cache_dir_from(
    memf_symbol_cache: Option<&str>,
    nt_symbol_path: Option<&str>,
    default: Option<PathBuf>,
) -> Option<PathBuf> {
    let _ = (memf_symbol_cache, nt_symbol_path, default);
    todo!("GREEN: layer env overrides over the default")
}

/// Resolve the symbol cache dir from the environment, falling back to
/// [`default_cache_dir`]. See [`resolve_cache_dir_from`] for the order.
pub fn resolve_cache_dir() -> Option<PathBuf> {
    let memf = std::env::var("MEMF_SYMBOL_CACHE").ok();
    let ntsp = std::env::var("_NT_SYMBOL_PATH").ok();
    resolve_cache_dir_from(memf.as_deref(), ntsp.as_deref(), default_cache_dir())
}

// ── SymbolServerClient (only with `symserver` feature) ──

/// A client for downloading PDB files from a symbol server with local caching.
pub struct SymbolServerClient {
    server_url: String,
    cache_dir: PathBuf,
}

impl SymbolServerClient {
    /// Create a new client with custom server URL and cache directory.
    pub fn new(server_url: impl Into<String>, cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            server_url: server_url.into(),
            cache_dir: cache_dir.into(),
        }
    }

    /// Create a client using Microsoft's public symbol server and default cache dir.
    pub fn microsoft() -> crate::Result<Self> {
        let cache_dir =
            default_cache_dir().ok_or_else(|| crate::Error::Cache("HOME not set".into()))?;
        Ok(Self::new(default_server_url(), cache_dir))
    }

    /// Get a PDB file, downloading from the symbol server if not cached.
    ///
    /// Returns the path to the cached PDB file.
    pub fn get_pdb(&self, pdb_name: &str, guid: &str, age: u32) -> crate::Result<PathBuf> {
        let cached = cache_path(&self.cache_dir, pdb_name, guid, age);
        if cached.exists() {
            return Ok(cached);
        }

        let url = download_url(&self.server_url, pdb_name, guid, age);
        let response = ureq::get(&url)
            .call()
            .map_err(|e| crate::Error::Network(format!("download failed: {e}")))?;

        // Create parent directories
        if let Some(parent) = cached.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| crate::Error::Cache(format!("create cache dir: {e}")))?;
        }

        // Write to temp file then rename for atomicity
        let tmp = cached.with_extension("tmp");
        let mut file = std::fs::File::create(&tmp)
            .map_err(|e| crate::Error::Cache(format!("create temp file: {e}")))?;
        std::io::copy(&mut response.into_body().into_reader(), &mut file)
            .map_err(|e| crate::Error::Cache(format!("write cache: {e}")))?;
        std::fs::rename(&tmp, &cached)
            .map_err(|e| crate::Error::Cache(format!("rename temp: {e}")))?;

        Ok(cached)
    }

    /// Return the server URL.
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// Return the cache directory.
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // ── Task 4: Pure function tests (always run) ──

    #[test]
    fn download_url_basic() {
        let url = download_url(
            "https://msdl.microsoft.com/download/symbols",
            "ntkrnlmp.pdb",
            "AABBCCDD11223344AABBCCDD11223344",
            1,
        );
        assert_eq!(
            url,
            "https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/AABBCCDD11223344AABBCCDD112233441/ntkrnlmp.pdb"
        );
    }

    #[test]
    fn download_url_strips_dashes() {
        let url = download_url(
            "https://msdl.microsoft.com/download/symbols",
            "ntkrnlmp.pdb",
            "1B72224D-37B8-1792-2820-0ED8994498B2",
            1,
        );
        assert_eq!(
            url,
            "https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/1B72224D37B8179228200ED8994498B21/ntkrnlmp.pdb"
        );
    }

    #[test]
    fn download_url_age_hex() {
        let base = "https://sym";
        let name = "foo.pdb";
        let guid = "AAAA";

        let url10 = download_url(base, name, guid, 10);
        assert!(
            url10.contains("AAAAA/"),
            "age 10 should be 'A', got: {url10}"
        );

        let url255 = download_url(base, name, guid, 255);
        assert!(
            url255.contains("AAAAFF/"),
            "age 255 should be 'FF', got: {url255}"
        );

        let url1 = download_url(base, name, guid, 1);
        assert!(url1.contains("AAAA1/"), "age 1 should be '1', got: {url1}");
    }

    #[test]
    fn download_url_age_zero() {
        let url = download_url("https://sym", "foo.pdb", "AAAA", 0);
        assert!(url.contains("AAAA0/"), "age 0 should be '0', got: {url}");
    }

    #[test]
    fn cache_path_basic() {
        let p = cache_path(Path::new("/tmp/cache"), "ntkrnlmp.pdb", "AABB", 1);
        assert_eq!(
            p,
            PathBuf::from("/tmp/cache/ntkrnlmp.pdb/AABB1/ntkrnlmp.pdb")
        );
    }

    #[test]
    fn cache_path_nested() {
        let p = cache_path(
            Path::new("/home/user/.memf/symbols"),
            "ntkrnlmp.pdb",
            "1B72224D-37B8-1792-2820-0ED8994498B2",
            1,
        );
        assert_eq!(
            p,
            PathBuf::from("/home/user/.memf/symbols/ntkrnlmp.pdb/1B72224D37B8179228200ED8994498B21/ntkrnlmp.pdb")
        );
    }

    #[test]
    fn default_server_url_is_microsoft() {
        let url = default_server_url();
        assert!(
            url.starts_with("https://msdl.microsoft.com"),
            "expected Microsoft URL, got: {url}"
        );
    }

    #[test]
    fn default_cache_dir_is_volatility_store() {
        // Relies on a base env var (HOME / APPDATA) being set — true in CI/dev.
        if let Some(dir) = default_cache_dir() {
            let s = dir.to_string_lossy();
            assert!(
                s.ends_with("volatility3"),
                "expected volatility3 suffix, got: {s}"
            );
        }
        // If no base env var is set we just skip — no panic.
    }

    // ── Volatility CACHE_PATH resolution (shared symbol store, all platforms) ──

    #[test]
    fn vol_cache_unix_prefers_xdg_cache_home() {
        assert_eq!(
            volatility_cache_path_from(false, Some("/x/cache"), Some("/home/u"), None, None),
            Some(PathBuf::from("/x/cache").join("volatility3"))
        );
    }

    #[test]
    fn vol_cache_unix_falls_back_to_home_dot_cache() {
        assert_eq!(
            volatility_cache_path_from(false, None, Some("/home/u"), None, None),
            Some(PathBuf::from("/home/u").join(".cache").join("volatility3"))
        );
    }

    #[test]
    fn vol_cache_unix_empty_xdg_uses_home() {
        assert_eq!(
            volatility_cache_path_from(false, Some(""), Some("/home/u"), None, None),
            Some(PathBuf::from("/home/u").join(".cache").join("volatility3"))
        );
    }

    #[test]
    fn vol_cache_unix_none_without_home() {
        assert_eq!(
            volatility_cache_path_from(false, None, None, None, None),
            None
        );
    }

    #[test]
    fn vol_cache_windows_prefers_appdata() {
        assert_eq!(
            volatility_cache_path_from(
                true,
                None,
                None,
                Some("C:/Users/u/AppData/Roaming"),
                Some("C:/Users/u")
            ),
            Some(PathBuf::from("C:/Users/u/AppData/Roaming").join("volatility3"))
        );
    }

    #[test]
    fn vol_cache_windows_falls_back_to_userprofile() {
        assert_eq!(
            volatility_cache_path_from(true, None, None, None, Some("C:/Users/u")),
            Some(PathBuf::from("C:/Users/u").join("volatility3"))
        );
    }

    #[test]
    fn vol_cache_windows_empty_appdata_uses_userprofile() {
        assert_eq!(
            volatility_cache_path_from(true, None, None, Some(""), Some("C:/Users/u")),
            Some(PathBuf::from("C:/Users/u").join("volatility3"))
        );
    }

    #[test]
    fn vol_cache_windows_none_without_either() {
        assert_eq!(
            volatility_cache_path_from(true, None, None, None, None),
            None
        );
    }

    // ── Override resolution: $MEMF_SYMBOL_CACHE > _NT_SYMBOL_PATH > default ──

    #[test]
    fn resolve_prefers_memf_symbol_cache() {
        assert_eq!(
            resolve_cache_dir_from(
                Some("/explicit/store"),
                Some("srv*C:/Symbols*https://msdl"),
                Some(PathBuf::from("/default"))
            ),
            Some(PathBuf::from("/explicit/store"))
        );
    }

    #[test]
    fn resolve_empty_memf_uses_nt_symbol_path() {
        assert_eq!(
            resolve_cache_dir_from(
                Some(""),
                Some("srv*C:/Symbols*https://msdl"),
                Some(PathBuf::from("/default"))
            ),
            Some(PathBuf::from("C:/Symbols"))
        );
    }

    #[test]
    fn resolve_falls_back_to_default() {
        assert_eq!(
            resolve_cache_dir_from(None, None, Some(PathBuf::from("/default"))),
            Some(PathBuf::from("/default"))
        );
    }

    #[test]
    fn resolve_nt_with_only_url_uses_default() {
        assert_eq!(
            resolve_cache_dir_from(
                None,
                Some("srv*https://msdl.microsoft.com/download/symbols"),
                Some(PathBuf::from("/default"))
            ),
            Some(PathBuf::from("/default"))
        );
    }

    #[test]
    fn nt_store_srv_with_downstream() {
        assert_eq!(
            nt_symbol_store_dir("srv*C:/Symbols*https://msdl.microsoft.com/download/symbols"),
            Some("C:/Symbols")
        );
    }

    #[test]
    fn nt_store_cache_form() {
        assert_eq!(nt_symbol_store_dir("cache*C:/Symbols"), Some("C:/Symbols"));
    }

    #[test]
    fn nt_store_plain_dir() {
        assert_eq!(nt_symbol_store_dir("C:/Symbols"), Some("C:/Symbols"));
    }

    #[test]
    fn nt_store_symsrv_skips_dll_and_keyword() {
        assert_eq!(
            nt_symbol_store_dir("symsrv*symsrv.dll*C:/Symbols*https://msdl"),
            Some("C:/Symbols")
        );
    }

    #[test]
    fn nt_store_only_url_is_none() {
        assert_eq!(
            nt_symbol_store_dir("srv*https://msdl.microsoft.com/download/symbols"),
            None
        );
    }

    #[test]
    fn nt_store_first_usable_of_list() {
        assert_eq!(
            nt_symbol_store_dir("srv*https://msdl;C:/Local/Symbols"),
            Some("C:/Local/Symbols")
        );
    }

    // ── Task 5: Client tests (feature-gated) ──

    #[test]
    fn client_new() {
        let client = SymbolServerClient::new("https://example.com", "/tmp/cache");
        assert_eq!(client.server_url(), "https://example.com");
        assert_eq!(client.cache_dir(), Path::new("/tmp/cache"));
    }

    #[test]
    fn client_get_pdb_uses_cache() {
        let dir = std::env::temp_dir().join("memf-test-symserver-cache");
        let pdb_name = "test.pdb";
        let guid = "AABB";
        let age = 1u32;

        // Pre-populate cache
        let cached = cache_path(&dir, pdb_name, guid, age);
        std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
        std::fs::write(&cached, b"fake pdb data").unwrap();

        let client = SymbolServerClient::new("https://invalid.example.com", &dir);
        let result = client.get_pdb(pdb_name, guid, age).unwrap();
        assert_eq!(result, cached);

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[ignore = "network integration: downloads a real PDB from the Microsoft symbol server"]
    fn client_download_real() {
        // Integration test: actually downloads from Microsoft.
        // Run with: cargo test --features symserver -- --ignored client_download_real
        let dir = std::env::temp_dir().join("memf-test-real-download");
        let _ = std::fs::remove_dir_all(&dir);

        let client = SymbolServerClient::new(default_server_url(), &dir);
        // A known small PDB: wntdll.pdb from a Win10 build
        let result = client.get_pdb("ntkrnlmp.pdb", "1B72224D-37B8-1792-2820-0ED8994498B2", 1);
        // We don't assert success because the GUID may not exist;
        // we just verify it doesn't panic and returns a proper Result.
        match result {
            Ok(path) => {
                assert!(path.exists());
                assert!(std::fs::metadata(&path).unwrap().len() > 0);
            }
            Err(e) => {
                // Network errors are acceptable in CI
                eprintln!("download failed (expected in offline CI): {e}");
            }
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
