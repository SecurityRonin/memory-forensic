//! Integration tests using real memory dumps.
//!
//! These tests require the `MEMF_TEST_DATA` environment variable
//! to point to a directory containing test dumps. They are `#[ignore]`d
//! by default and run with:
//!
//! ```bash
//! MEMF_TEST_DATA=/path/to/dumps cargo test --test real_data -- --ignored
//! ```

use std::path::{Path, PathBuf};

fn test_data_dir() -> Option<PathBuf> {
    std::env::var("MEMF_TEST_DATA").ok().map(PathBuf::from)
}

/// Helper to check if a specific test file exists in the test data directory.
fn test_file(name: &str) -> Option<PathBuf> {
    let dir = test_data_dir()?;
    let path = dir.join(name);
    if path.exists() {
        Some(path)
    } else {
        None
    }
}

/// Check for the Total Recall zip in the default test data location.
fn total_recall_zip() -> Option<PathBuf> {
    // Check in test data dir first, then common local paths.
    if let Some(p) = test_file("TOTAL_RECALL_memory_forensics_CHALLENGE.zip") {
        return Some(p);
    }
    let local = Path::new("tests/data/TOTAL_RECALL_memory_forensics_CHALLENGE.zip");
    if local.exists() {
        Some(local.to_path_buf())
    } else {
        None
    }
}

#[test]
#[ignore = "requires real dump: set MEMF_TEST_DATA"]
fn avml_lime_real_dump() {
    let dir = test_data_dir().expect("MEMF_TEST_DATA not set");
    let dump = dir.join("avml.lime");
    if !dump.exists() {
        eprintln!("Skipping: {} not found", dump.display());
        return;
    }

    let provider = memf_format::open_dump(&dump).unwrap();
    assert_eq!(provider.format_name(), "LiME");
    assert!(provider.total_size() > 1_000_000_000, "expected > 1GB");
    println!(
        "Opened {} ranges, {} total bytes",
        provider.ranges().len(),
        provider.total_size()
    );
}

#[test]
#[ignore = "requires real strings file: set MEMF_TEST_DATA"]
fn classify_real_strings_file() {
    let dir = test_data_dir().expect("MEMF_TEST_DATA not set");
    let strings_file = dir.join("memory-strings.ascii");
    if !strings_file.exists() {
        eprintln!("Skipping: {} not found", strings_file.display());
        return;
    }

    let mut strings = memf_strings::from_file::from_strings_file(&strings_file).unwrap();
    println!("Loaded {} strings", strings.len());

    memf_strings::classify::classify_strings(&mut strings);
    let classified = strings.iter().filter(|s| !s.categories.is_empty()).count();
    #[allow(clippy::cast_precision_loss)]
    let pct = (classified as f64 / strings.len() as f64) * 100.0;
    println!(
        "Classified {} of {} strings ({:.1}%)",
        classified,
        strings.len(),
        pct
    );

    assert!(
        classified > 0,
        "expected at least some strings to be classified"
    );
}

/// Locate the SecurityNik crash dump (`.dmp`) in the test data dir.
fn securitynik_dmp() -> Option<PathBuf> {
    test_file("SECURITYNIK-WIN-20231116-235706.dmp")
}

/// Validate the VA-aware kernel locator + tolerant RSDS scanner end-to-end
/// against the real SecurityNik PAGEDU64 dump.
///
/// Ground truth (sidecar JSON): regNtCr3 = 0x1AE000, pdbGuid =
/// 9DC3FC69-B1CA-4B34-707E-BC57FD1D6126, pdbName = ntkrnlmp.pdb, pdbAge = 1.
///
/// The dump maps the kernel high (phys 0x1_0040_0000), so the legacy 1-128 MiB
/// physical scan misses; this exercises the DTB fallback path.
#[test]
#[ignore = "requires SecurityNik .dmp: set MEMF_TEST_DATA"]
fn securitynik_kernel_locator_matches_ground_truth() {
    let Some(dump) = securitynik_dmp() else {
        eprintln!("Skipping: SECURITYNIK-WIN-20231116-235706.dmp not found");
        return;
    };

    let provider = memf_format::open_dump(&dump).expect("open crash dump");

    // The crash-dump header must carry the kernel CR3 (DirectoryTableBase).
    let meta = provider.metadata().expect("crash dump exposes metadata");
    assert_eq!(meta.cr3, Some(0x1AE000), "embedded CR3 / DTB");

    let pdb_id = memf_symbols::scan_for_kernel(&provider)
        .expect("scan_for_kernel should locate the kernel via DTB fallback");

    assert_eq!(pdb_id.guid, "9DC3FC69-B1CA-4B34-707E-BC57FD1D6126");
    assert_eq!(pdb_id.pdb_name, "ntkrnlmp.pdb");
    assert_eq!(pdb_id.age, 1);
    println!(
        "SecurityNik kernel: {} {} age {}",
        pdb_id.pdb_name, pdb_id.guid, pdb_id.age
    );
}

#[test]
#[ignore = "requires Total Recall zip (Deflate64, 1.3 GB)"]
fn deflate64_zip_entries_are_readable() {
    let path = total_recall_zip().expect("Total Recall zip not found");
    let file = std::fs::File::open(&path).unwrap();
    let mut archive = zip::ZipArchive::new(file).unwrap();

    // Verify we can access entry metadata — requires Deflate64 support.
    let mut found_dmp = false;
    for i in 0..archive.len() {
        let entry = archive
            .by_index(i)
            .expect("entry should be readable with deflate64 support");
        if Path::new(entry.name())
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("dmp"))
        {
            found_dmp = true;
            assert!(entry.size() > 1_000_000_000, "expected > 1 GB crash dump");
        }
    }
    assert!(found_dmp, "archive should contain a .dmp file");
}
