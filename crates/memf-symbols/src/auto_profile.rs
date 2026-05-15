//! Automatic profile resolution for Windows kernel memory dumps.
//!
//! [`AutoProfile`] orchestrates PDB acquisition: it accepts a PDB identity,
//! a raw PE image, or a physical memory dump, and returns a [`SymbolResolver`]
//! backed by the matching PDB file.

use std::path::PathBuf;

use crate::pe_debug::{extract_pdb_id, PdbId};
use crate::pdb_resolver::PdbResolver;
use crate::symserver::{self, SymbolServerClient};
use crate::SymbolResolver;

/// Automatic symbol profile resolver for Windows kernels.
///
/// Locates and loads the correct PDB file given a kernel PDB identity,
/// a PE binary, or a physical memory dump.
pub struct AutoProfile {
    /// Local directory used as the PDB cache.
    pub(crate) cache_dir: PathBuf,
}

impl AutoProfile {
    /// Create an `AutoProfile` using the default cache directory (`~/.memf/symbols/`).
    pub fn new() -> crate::Result<Self> {
        let cache_dir = crate::symserver::default_cache_dir()
            .ok_or_else(|| crate::Error::Cache("HOME not set".into()))?;
        Ok(Self { cache_dir })
    }

    /// Create an `AutoProfile` with a custom cache directory.
    pub fn with_cache_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            cache_dir: dir.into(),
        }
    }

    /// Resolve a [`SymbolResolver`] for the given PDB identity.
    ///
    /// Checks the local cache first. If the PDB is not cached, downloads it
    /// from the Microsoft symbol server and writes it to the cache directory.
    pub fn from_pdb_id(&self, pdb_id: &PdbId) -> crate::Result<Box<dyn SymbolResolver>> {
        let cached = symserver::cache_path(
            &self.cache_dir,
            &pdb_id.pdb_name,
            &pdb_id.guid,
            pdb_id.age,
        );

        if !cached.exists() {
            let client = SymbolServerClient::new(
                symserver::default_server_url(),
                &self.cache_dir,
            );
            client.get_pdb(&pdb_id.pdb_name, &pdb_id.guid, pdb_id.age)?;
        }

        let resolver = PdbResolver::from_path(&cached)?;
        Ok(Box::new(resolver))
    }

    /// Resolve a [`SymbolResolver`] by parsing the PDB identity from a PE binary.
    ///
    /// Extracts the PDB identity from `pe_bytes` then delegates to [`from_pdb_id`].
    ///
    /// [`from_pdb_id`]: AutoProfile::from_pdb_id
    pub fn from_pe_bytes(&self, pe_bytes: &[u8]) -> crate::Result<Box<dyn SymbolResolver>> {
        let pdb_id = extract_pdb_id(pe_bytes)?;
        self.from_pdb_id(&pdb_id)
    }

    /// Resolve a [`SymbolResolver`] by scanning physical memory for the kernel.
    ///
    /// Scans `mem` for ntoskrnl.exe, extracts its PDB identity, then delegates
    /// to [`from_pdb_id`].
    ///
    /// [`from_pdb_id`]: AutoProfile::from_pdb_id
    pub fn from_dump<P: memf_format::PhysicalMemoryProvider>(
        &self,
        mem: &P,
    ) -> crate::Result<Box<dyn SymbolResolver>> {
        let pdb_id = crate::kernel_scanner::scan_for_kernel(mem)?;
        self.from_pdb_id(&pdb_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pdb_id() -> PdbId {
        PdbId {
            guid: "1B72224D-37B8-1792-2820-0ED8994498B2".into(),
            age: 1,
            pdb_name: "ntkrnlmp.pdb".into(),
        }
    }

    /// AutoProfile::with_cache_dir stores the provided path.
    #[test]
    fn with_cache_dir_stores_path() {
        let tmp = tempfile::tempdir().unwrap();
        let profile = AutoProfile::with_cache_dir(tmp.path());
        assert_eq!(profile.cache_dir, tmp.path());
    }

    /// Stub returns an error when cache is empty and no network is available.
    #[test]
    fn from_pdb_id_returns_error_when_cache_empty_and_no_network() {
        let tmp = tempfile::tempdir().unwrap();
        let profile = AutoProfile::with_cache_dir(tmp.path());
        let result = profile.from_pdb_id(&test_pdb_id());
        assert!(result.is_err(), "expected error from stub, got Ok");
    }

    /// Garbage PE bytes produce a Malformed error (from extract_pdb_id).
    #[test]
    fn from_pe_bytes_propagates_malformed_error() {
        let tmp = tempfile::tempdir().unwrap();
        let profile = AutoProfile::with_cache_dir(tmp.path());
        let result = profile.from_pe_bytes(b"not a PE");
        assert!(
            matches!(result, Err(crate::Error::Malformed(_))),
            "expected Malformed error, got: {}",
            result.err().map(|e| e.to_string()).unwrap_or_default()
        );
    }

    /// RED test: when a cached PDB file exists the real implementation should
    /// attempt to open it (yielding Pdb/Malformed on a zero-byte file), NOT
    /// NotFound.  The stub returns NotFound, so this test FAILS in RED.
    #[test]
    fn from_pdb_id_uses_cached_pdb_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let pdb_id = test_pdb_id();

        // Pre-populate the cache with a zero-byte file at the expected path.
        let cached = crate::symserver::cache_path(
            tmp.path(),
            &pdb_id.pdb_name,
            &pdb_id.guid,
            pdb_id.age,
        );
        std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
        std::fs::write(&cached, b"").unwrap();

        let profile = AutoProfile::with_cache_dir(tmp.path());
        let result = profile.from_pdb_id(&pdb_id);

        // With a real implementation the cache-hit path opens the file and
        // gets Pdb or Malformed (zero-byte PDB).  The stub returns NotFound,
        // which is neither — so this assertion fails in RED.
        assert!(
            matches!(
                result,
                Err(crate::Error::Pdb(_)) | Err(crate::Error::Malformed(_))
            ),
            "expected Pdb or Malformed (cache-hit path), got: {}",
            result.err().map(|e| e.to_string()).unwrap_or_default()
        );
    }
}
