//! A directly-provided raw `.mem` dump (not extracted from an archive) must open
//! for analysis. Raw-format opening is decoupled from `is_extracted()`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use predicates::prelude::*;

/// `memf info` on a raw flat dump given directly on disk succeeds — it must NOT
/// reject it with "unknown dump format" just because it did not come out of an
/// archive. A page of zeros is a valid (if empty) raw physical memory image.
#[test]
fn info_opens_a_direct_raw_dump() {
    let tmp = tempfile::Builder::new().suffix(".mem").tempfile().unwrap();
    std::fs::write(tmp.path(), vec![0u8; 0x1000]).unwrap();

    Command::cargo_bin("mem4n6")
        .unwrap()
        .args(["info"])
        .arg(tmp.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Format").or(predicate::str::contains("Raw")));
}
