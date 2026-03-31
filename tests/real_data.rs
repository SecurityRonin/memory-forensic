//! Integration tests using real memory dumps.
//!
//! These tests require the `MEMF_TEST_DATA` environment variable
//! to point to a directory containing test dumps. They are `#[ignore]`d
//! by default and run with:
//!
//! ```bash
//! MEMF_TEST_DATA=/path/to/dumps cargo test --test real_data -- --ignored
//! ```

use std::path::PathBuf;

fn test_data_dir() -> Option<PathBuf> {
    std::env::var("MEMF_TEST_DATA").ok().map(PathBuf::from)
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
