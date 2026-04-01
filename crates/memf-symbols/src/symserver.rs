//! Symbol server client.
//!
//! Provides pure functions for URL construction and cache path computation,
//! plus an optional `SymbolServerClient` (behind the `symserver` feature)
//! that downloads PDBs from Microsoft's symbol server with local caching.

use std::path::{Path, PathBuf};

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
        assert!(url10.contains("AAAAA/"), "age 10 should be 'A', got: {url10}");

        let url255 = download_url(base, name, guid, 255);
        assert!(url255.contains("AAAAFF/"), "age 255 should be 'FF', got: {url255}");

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
        assert_eq!(p, PathBuf::from("/tmp/cache/ntkrnlmp.pdb/AABB1/ntkrnlmp.pdb"));
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
    fn default_cache_dir_uses_home() {
        // This test relies on HOME being set (true in CI and dev).
        if let Some(dir) = default_cache_dir() {
            let s = dir.to_string_lossy();
            assert!(s.ends_with(".memf/symbols"), "expected .memf/symbols suffix, got: {s}");
        }
        // If HOME is not set we just skip — no panic.
    }

    // ── Task 5: Client tests (feature-gated) ──

    #[cfg(feature = "symserver")]
    #[test]
    fn client_new() {
        let client = SymbolServerClient::new("https://example.com", "/tmp/cache");
        assert_eq!(client.server_url(), "https://example.com");
        assert_eq!(client.cache_dir(), Path::new("/tmp/cache"));
    }

    #[cfg(feature = "symserver")]
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

    #[cfg(feature = "symserver")]
    #[test]
    #[ignore]
    fn client_download_real() {
        // Integration test: actually downloads from Microsoft.
        // Run with: cargo test --features symserver -- --ignored client_download_real
        let dir = std::env::temp_dir().join("memf-test-real-download");
        let _ = std::fs::remove_dir_all(&dir);

        let client = SymbolServerClient::new(default_server_url(), &dir);
        // A known small PDB: wntdll.pdb from a Win10 build
        let result = client.get_pdb(
            "ntkrnlmp.pdb",
            "1B72224D-37B8-1792-2820-0ED8994498B2",
            1,
        );
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
