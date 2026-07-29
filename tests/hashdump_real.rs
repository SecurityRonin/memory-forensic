//! Native SAM hashdump integration tests against the real DFIR-Madness
//! "Szechuan Sauce" memory images (env-gated; skip cleanly when absent).
//!
//! Oracle: Volatility 3 `windows.hashdump.Hashdump` / `windows.registry.hivelist`
//! on the same images (tier-1 independent validator). The decrypt path is
//! canonical / build-independent, so parity with vol3 — never self-authored
//! offsets — is the correctness bar.
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

/// Workstation (build 19041) — symbol-free locator parity on the build that was
/// broken. The symbol-free `_CMHIVE` scan must find the SYSTEM and SAM hive VAs
/// on 19041, matching `vol windows.registry.hivelist`:
///   SYSTEM  0xcf0476a73000
///   SAM     0xcf047a411000
/// (memf reports the full canonical form `0xffffcf04...`; the low-48-bit hex vol
/// prints is the shared substring asserted here.)
#[test]
#[ignore = "requires real dump: set SZECHUAN_WS_MEM + SZECHUAN_WS_ISF"]
fn ws_symbol_free_hivescan_matches_vol3_hivelist() {
    let (Some(mem), Some(isf)) = (env_path("SZECHUAN_WS_MEM"), env_path("SZECHUAN_WS_ISF")) else {
        eprintln!("skipping: SZECHUAN_WS_MEM / SZECHUAN_WS_ISF not set");
        return;
    };

    let out = mem4n6()
        .args(["hivescan"])
        .arg(&mem)
        .args(["--symbols"])
        .arg(&isf)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).into_owned();

    assert!(
        stdout.contains("cf0476a73000"),
        "WS hivescan missing SYSTEM hive VA (vol hivelist 0xcf0476a73000):\n{stdout}"
    );
    assert!(
        stdout.contains("cf047a411000"),
        "WS hivescan missing SAM hive VA (vol hivelist 0xcf047a411000):\n{stdout}"
    );
}

/// Workstation (build 19041) — fail-loud, never silent-empty. vol3
/// `windows.hashdump.Hashdump` on THIS image also returns ZERO rows: the SAM
/// hive bins are paged out (its `_HMAP_TABLE` at 0xffffcf047a3fb000 does not
/// translate — confirmed with `translate-va`; vol's own `printkey` on
/// `SAM\Domains\Account\Users` shows no timestamp and no RID children). So the
/// recoverable-from-memory ground truth on the workstation is EMPTY, and the
/// native path must say so loudly — locate the hives by signature, then name the
/// paged-out cause — rather than fabricate a `ricksanchez` row the dump does not
/// contain or silently print nothing.
#[test]
#[ignore = "requires real dump: set SZECHUAN_WS_MEM + SZECHUAN_WS_ISF"]
fn ws_native_hashdump_fails_loud_on_paged_out_sam() {
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
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).into_owned();

    // No fabricated rows (parity with vol3's empty result on this image): no line
    // carries a 32-hex-digit NT/LM hash.
    assert!(
        !stdout
            .lines()
            .any(|l| l.chars().filter(char::is_ascii_hexdigit).count() >= 32),
        "WS hashdump must not fabricate hash rows for a paged-out SAM:\n{stdout}"
    );
    // Fail-loud: the scan located hives, and the cause of the empty result is named.
    assert!(
        stderr.to_lowercase().contains("located"),
        "WS hashdump should report that hives were located by the scan:\n{stderr}"
    );
    assert!(
        stderr.to_lowercase().contains("paged out")
            || stderr.to_lowercase().contains("not resident"),
        "WS hashdump should name the paged-out cause, not fail silently:\n{stderr}"
    );
}
