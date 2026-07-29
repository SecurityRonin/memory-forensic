//! Native SAM hashdump integration tests against the real DFIR-Madness
//! "Szechuan Sauce" memory images (env-gated; skip cleanly when absent).
//!
//! Oracle: Volatility 3 `windows.hashdump.Hashdump` on the same images
//! (tier-1 independent validator). The decrypt path is canonical /
//! build-independent, so parity with vol3 — never self-authored offsets —
//! is the correctness bar.
//!
//! Environment (point at the extracted `/tmp` copies, never `~/src`):
//!   SZECHUAN_DC_MEM  -> citadeldc01.mem            (Server 2012 R2, build 9600)
//!   SZECHUAN_DC_ISF  -> matching decompressed ISF JSON for DC01
//!   SZECHUAN_WS_MEM  -> DESKTOP-SDN1RPT.mem        (Windows 10, build 19041)
//!   SZECHUAN_WS_ISF  -> matching decompressed ISF JSON for the workstation
//!
//! Run with:
//!   SZECHUAN_DC_MEM=/tmp/szechuan-extracted/citadeldc01.mem \
//!   SZECHUAN_DC_ISF=/tmp/dc_isf.json \
//!   SZECHUAN_WS_MEM=/tmp/szechuan-extracted/DESKTOP-SDN1RPT.mem \
//!   SZECHUAN_WS_ISF=/tmp/ws_isf.json \
//!   cargo test --test hashdump_real -- --ignored
#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use std::path::PathBuf;

fn env_path(var: &str) -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var(var).ok()?);
    p.exists().then_some(p)
}

fn mem4n6() -> Command {
    Command::cargo_bin("mem4n6").unwrap()
}

/// DC01 (build 9600): the SAM `Users` RID subkeys are resident, so native
/// hashdump must recover the union-answer-key hashes byte-for-byte, matching
/// `vol -f citadeldc01.mem windows.hashdump.Hashdump`:
///   Administrator  rid 500  NT f56a8399599f1be040128b1dd9623c29
///   Guest          rid 501  NT 31d6cfe0d16ae931b73c59d7e0c089c0 (empty pw)
#[test]
#[ignore = "requires real dump: set SZECHUAN_DC_MEM + SZECHUAN_DC_ISF"]
fn dc01_native_hashdump_matches_vol3() {
    let (Some(mem), Some(isf)) = (env_path("SZECHUAN_DC_MEM"), env_path("SZECHUAN_DC_ISF")) else {
        eprintln!("skipping: SZECHUAN_DC_MEM / SZECHUAN_DC_ISF not set");
        return;
    };

    let out = mem4n6()
        .args(["hashdump"])
        .arg(&mem)
        .args(["--symbols"])
        .arg(&isf)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).into_owned();

    assert!(
        stdout.contains("Administrator"),
        "DC01 hashdump missing Administrator row:\n{stdout}"
    );
    assert!(
        stdout.contains("f56a8399599f1be040128b1dd9623c29"),
        "DC01 Administrator NT hash (union key) not recovered:\n{stdout}"
    );
    // Guest is a blank-password account (empty NT hash) — vol3 parity.
    assert!(
        stdout.contains("31d6cfe0d16ae931b73c59d7e0c089c0"),
        "DC01 Guest empty NT hash not recovered:\n{stdout}"
    );
}

/// Workstation (build 19041): the symbol-free `_CMHIVE` locator must find the
/// SYSTEM and SAM hives on 19041 too (parity with `vol windows.registry.
/// hivelist`, which lists both). NOTE — vol3 `windows.hashdump.Hashdump` on
/// THIS memory image returns ZERO rows because the SAM
/// `\Domains\Account\Users` child-list cell is paged out (confirmed with
/// `vol ... windows.registry.printkey ... --key "SAM\Domains\Account\Users"`,
/// which lists no RID subkeys). So the recoverable-from-memory ground truth on
/// the workstation is EMPTY, and native parity means: locate both hives, then
/// report the paged-out cause loudly rather than fabricate a row that is not in
/// the dump. We therefore assert the locator succeeds and the fail-loud
/// diagnostic names the cause — not a `ricksanchez` hash the image does not
/// contain.
#[test]
#[ignore = "requires real dump: set SZECHUAN_WS_MEM + SZECHUAN_WS_ISF"]
fn ws_native_hashdump_locates_hives_and_reports_paged_out() {
    let (Some(mem), Some(isf)) = (env_path("SZECHUAN_WS_MEM"), env_path("SZECHUAN_WS_ISF")) else {
        eprintln!("skipping: SZECHUAN_WS_MEM / SZECHUAN_WS_ISF not set");
        return;
    };

    let out = mem4n6()
        .args(["hashdump"])
        .arg(&mem)
        .args(["--symbols"])
        .arg(&isf)
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).into_owned();

    // The symbol-free locator ran and found both hives on 19041 (cross-build),
    // and fail-loud named the empty cause (paged-out Users child-list) — the
    // signal that separates "genuinely none" from "locator/decryptor failed".
    assert!(
        stderr.to_lowercase().contains("located")
            && stderr.to_lowercase().contains("sam")
            && stderr.to_lowercase().contains("system"),
        "WS hashdump should report locating SAM+SYSTEM hives:\n{stderr}"
    );
    assert!(
        stderr.to_lowercase().contains("paged out")
            || stderr.to_lowercase().contains("not resident"),
        "WS hashdump should name the paged-out cause of the empty result:\n{stderr}"
    );
}
