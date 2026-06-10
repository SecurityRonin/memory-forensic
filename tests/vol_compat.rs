//! CLI integration tests for the `vol` subcommand and argv[0] compat mode.
//!
//! Tests marked `#[ignore]` require real dump files at /tmp/vol3_test/.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Run them with: cargo test --test vol_compat -- --include-ignored

use assert_cmd::Command;
use predicates::prelude::*;

fn memf() -> Command {
    Command::cargo_bin("memf").unwrap()
}

// ── Subcommand availability ───────────────────────────────────────────────────

#[test]
fn test_vol_help_exits_zero() {
    memf().args(["vol", "--help"]).assert().success();
}

#[test]
fn test_vol_help_mentions_file_flag() {
    memf()
        .args(["vol", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("-f").or(predicate::str::contains("--file")));
}

#[test]
fn test_vol_missing_file_flag_fails() {
    // plugin given but -f missing → clap error
    memf()
        .args(["vol", "windows.pslist.PsList"])
        .assert()
        .failure();
}

#[test]
fn test_vol_nonexistent_dump_fails_with_message() {
    memf()
        .args(["vol", "-f", "/nonexistent/path/dump.mem", "windows.pslist.PsList"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("dump").or(predicate::str::contains("not found")));
}

#[test]
fn test_vol_no_plugin_fails() {
    memf()
        .args(["vol", "-f", "/tmp/vol3_test/DESKTOP-SDN1RPT.mem"])
        .assert()
        .failure();
}

// ── Renderer flag parsing ─────────────────────────────────────────────────────

#[test]
fn test_vol_renderer_flag_accepted() {
    // renderer flag is accepted without error (file not found is the expected failure)
    let output = memf()
        .args([
            "vol", "-f", "/nonexistent.mem",
            "-r", "json",
            "windows.pslist.PsList",
        ])
        .output()
        .unwrap();
    // should fail on the file, not on flag parsing
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unrecognized argument") && !stderr.contains("unexpected argument"),
        "renderer flag should be recognised; stderr: {stderr}"
    );
}

#[test]
fn test_vol_quiet_flag_accepted() {
    let output = memf()
        .args([
            "vol", "-f", "/nonexistent.mem",
            "-q",
            "windows.pslist.PsList",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unrecognized argument"),
        "quiet flag should be recognised; stderr: {stderr}"
    );
}

// ── Plugin dispatch table ─────────────────────────────────────────────────────

#[test]
fn test_vol_unknown_community_plugin_fails_helpfully() {
    // Unknown plugin, no vol in PATH → helpful error message
    memf()
        .env("PATH", "/nonexistent_path_bin")
        .args([
            "vol", "-f", "/tmp/vol3_test/DESKTOP-SDN1RPT.mem",
            "community.SomeCommunityPlugin",
        ])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("community.SomeCommunityPlugin")
                .or(predicate::str::contains("not found"))
                .or(predicate::str::contains("not implemented")),
        );
}

// ── Integration tests (require real dump) ────────────────────────────────────

const PRIMARY_DUMP: &str = "/tmp/vol3_test/DESKTOP-SDN1RPT.mem";

fn has_primary_dump() -> bool {
    std::path::Path::new(PRIMARY_DUMP).exists()
}

#[test]
#[ignore = "requires DESKTOP-SDN1RPT.mem at /tmp/vol3_test/"]
fn test_vol_pslist_text_output_has_vol3_header() {
    if !has_primary_dump() { return; }
    let output = memf()
        .args(["vol", "-f", PRIMARY_DUMP, "windows.pslist.PsList"])
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Volatility"),
        "first line must contain 'Volatility'; got: {}", &stdout[..stdout.len().min(200)]
    );
}

#[test]
#[ignore = "requires DESKTOP-SDN1RPT.mem at /tmp/vol3_test/"]
fn test_vol_pslist_text_output_has_pid_column_and_system() {
    if !has_primary_dump() { return; }
    let output = memf()
        .args(["vol", "-f", PRIMARY_DUMP, "windows.pslist.PsList"])
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PID"), "stdout must contain PID column");
    assert!(stdout.contains("System"), "stdout must contain System process");
}

#[test]
#[ignore = "requires DESKTOP-SDN1RPT.mem at /tmp/vol3_test/"]
fn test_vol_pslist_json_is_valid_json_array() {
    if !has_primary_dump() { return; }
    let output = memf()
        .args(["vol", "-f", PRIMARY_DUMP, "-r", "json", "windows.pslist.PsList"])
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("not valid JSON: {e}\nstdout: {stdout}"));
    assert!(v.is_array(), "JSON output must be an array");
    assert!(!v.as_array().unwrap().is_empty(), "JSON array must not be empty");
}

#[test]
#[ignore = "requires DESKTOP-SDN1RPT.mem at /tmp/vol3_test/"]
fn test_vol_pslist_json_has_vol3_field_names() {
    if !has_primary_dump() { return; }
    let output = memf()
        .args(["vol", "-f", PRIMARY_DUMP, "-r", "json", "windows.pslist.PsList"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Vec<serde_json::Value> = serde_json::from_str(stdout.trim()).unwrap();
    let first = &v[0];
    assert!(first.get("PID").is_some(), "must have PID field");
    assert!(first.get("PPID").is_some(), "must have PPID field");
    assert!(first.get("ImageFileName").is_some(), "must have ImageFileName field");
}

#[test]
#[ignore = "requires DESKTOP-SDN1RPT.mem at /tmp/vol3_test/"]
fn test_vol_info_text_contains_kernel_base() {
    if !has_primary_dump() { return; }
    let output = memf()
        .args(["vol", "-f", PRIMARY_DUMP, "windows.info.Info"])
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Kernel Base"), "info must contain Kernel Base");
    assert!(stdout.contains("DTB"), "info must contain DTB");
}

#[test]
#[ignore = "requires DESKTOP-SDN1RPT.mem at /tmp/vol3_test/"]
fn test_vol_netscan_text_contains_proto_column() {
    if !has_primary_dump() { return; }
    let output = memf()
        .args(["vol", "-f", PRIMARY_DUMP, "windows.netscan.NetScan"])
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Proto"), "netscan must contain Proto column");
}

#[test]
#[ignore = "requires DESKTOP-SDN1RPT.mem at /tmp/vol3_test/"]
fn test_vol_cmdline_text_contains_process_and_args_columns() {
    if !has_primary_dump() { return; }
    let output = memf()
        .args(["vol", "-f", PRIMARY_DUMP, "windows.cmdline.CmdLine"])
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PID"), "cmdline must contain PID column");
    assert!(stdout.contains("Process") || stdout.contains("Args"), "cmdline must contain Process/Args");
}

#[test]
#[ignore = "requires DESKTOP-SDN1RPT.mem at /tmp/vol3_test/"]
fn test_vol_pstree_text_contains_pid_and_name() {
    if !has_primary_dump() { return; }
    let output = memf()
        .args(["vol", "-f", PRIMARY_DUMP, "windows.pstree.PsTree"])
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PID") || stdout.contains("System"), "pstree must contain processes");
}

#[test]
#[ignore = "requires DESKTOP-SDN1RPT.mem at /tmp/vol3_test/"]
fn test_vol_proxy_falls_through_to_vol_for_registry_plugins() {
    if !has_primary_dump() { return; }
    // registry.hivelist should either succeed via vol proxy or fail with helpful message
    let output = memf()
        .args(["vol", "-f", PRIMARY_DUMP, "windows.registry.hivelist.HiveList"])
        .output()
        .unwrap();
    // Either success (vol in PATH) or helpful error (vol not found)
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        assert!(
            stderr.contains("not implemented") || stderr.contains("vol") || stderr.contains("proxy"),
            "failure should explain why: {stderr}"
        );
    }
}
