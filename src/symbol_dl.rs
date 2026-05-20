//! ISF symbol auto-download from the community server.

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

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
        // Must be a valid HTTP URL pointing at the community ISF server
        assert!(url.starts_with("https://"), "must be https: {url}");
        assert!(url.contains("ntoskrnl.exe.pdb"), "must contain pdb name: {url}");
        assert!(url.ends_with(".json.xz"), "must end with .json.xz: {url}");
    }

    #[test]
    fn test_symbol_dl_cache_key_stable() {
        // Same inputs → same cache key every time (deterministic)
        let k1 = cache_filename("ntkrnlmp.pdb", "GUID123", 1);
        let k2 = cache_filename("ntkrnlmp.pdb", "GUID123", 1);
        assert_eq!(k1, k2);
        // Different GUID → different key
        let k3 = cache_filename("ntkrnlmp.pdb", "GUID456", 1);
        assert_ne!(k1, k3);
    }
}
