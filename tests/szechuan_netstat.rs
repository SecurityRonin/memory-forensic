//! Real-image netstat owner→PID attribution tests (DFIR Madness "Szechuan
//! Sauce" memory images), env-gated so they skip cleanly when the dumps and
//! their matching ISF symbol files are absent — like the fleet's other
//! oracle-gated tests. The large `.mem` images are never committed.
//!
//! Set both the dump and its ISF for each host:
//!   SZECHUAN_WS_MEM / SZECHUAN_WS_ISF  — DESKTOP-SDN1RPT (Win10 2004, build 19041)
//!   SZECHUAN_DC_MEM / SZECHUAN_DC_ISF  — CITADEL-DC01     (Server 2012 R2, build 9600)
//!
//! Ground truth (tier-2: real image, owners independently confirmed by
//! `windows.pslist` — vol3 `windows.netscan` itself renders `-` for these
//! established endpoints on 19041, so pslist is the oracle here):
//!   * WS  203.78.103.109:443 has two established `_TCP_ENDPOINT`s — the
//!     coreupdater C2 beacon (local port 50875 → PID 8324) and a powershell
//!     C2 (local port 50972 → PID 3316).
//!   * DC01 203.78.103.109:443 → coreupdater.exe PID 3644 (already attributed).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use std::path::Path;

fn mem4n6() -> Command {
    Command::cargo_bin("mem4n6").unwrap()
}

/// Resolve a `(dump, isf)` env pair, returning `None` (skip) when either is
/// unset or points at a missing file.
fn env_pair(mem_key: &str, isf_key: &str) -> Option<(String, String)> {
    let mem = std::env::var(mem_key).ok()?;
    let isf = std::env::var(isf_key).ok()?;
    (Path::new(&mem).exists() && Path::new(&isf).exists()).then_some((mem, isf))
}

/// Run `mem4n6 net <dump> --symbols <isf> --output json` and parse the
/// newline-delimited JSON rows.
fn net_rows(mem: &str, isf: &str) -> Vec<serde_json::Value> {
    let out = mem4n6()
        .args(["net", mem, "--symbols", isf, "--output", "json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "`net` failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .map(|l| serde_json::from_str(l).expect("each row is valid JSON"))
        .collect()
}

fn is_c2(r: &serde_json::Value) -> bool {
    r["remote_addr"] == "203.78.103.109"
}

fn name_of(r: &serde_json::Value) -> &str {
    r["process_name"].as_str().unwrap_or("")
}

/// DEFECT 1: on build 19041 the established `_TCP_ENDPOINT` owner pointer was
/// read at the wrong offset, so every C2 beacon row came back with PID 0. The
/// owner must resolve to the pslist-confirmed owning process.
#[test]
fn ws_19041_netstat_attributes_c2_owner_pid() {
    let Some((mem, isf)) = env_pair("SZECHUAN_WS_MEM", "SZECHUAN_WS_ISF") else {
        eprintln!("skip: set SZECHUAN_WS_MEM and SZECHUAN_WS_ISF");
        return;
    };
    let rows = net_rows(&mem, &isf);
    let c2: Vec<_> = rows.iter().filter(|r| is_c2(r)).collect();
    assert!(
        c2.len() >= 2,
        "expected the two 203.78.103.109:443 C2 endpoints, got {}",
        c2.len()
    );

    // No established C2 row may be left unattributed (PID 0) — the owner pointer
    // is present and points to a live _EPROCESS for both.
    for r in &c2 {
        let pid = r["pid"].as_i64().unwrap_or(0);
        assert_ne!(
            pid, 0,
            "C2 row local_port {} has PID 0 — 19041 owner attribution broken: {r}",
            r["local_port"]
        );
    }

    // The coreupdater beacon must attribute to coreupdater.exe PID 8324.
    let core = c2
        .iter()
        .find(|r| name_of(r).starts_with("coreupdater"))
        .expect("a 203.78.103.109 C2 row must attribute to coreupdater (pslist PID 8324)");
    assert_eq!(
        core["pid"].as_i64().unwrap(),
        8324,
        "coreupdater C2 owner PID must be 8324 (pslist): {core}"
    );
}

/// Recovery guard: locks the 19041 `_TCP_ENDPOINT` overlay/scan — the C2
/// connection itself must always be recovered (independent of owner
/// attribution). Passes before and after the owner-offset fix.
#[test]
fn ws_19041_netstat_recovers_c2_connection() {
    let Some((mem, isf)) = env_pair("SZECHUAN_WS_MEM", "SZECHUAN_WS_ISF") else {
        eprintln!("skip: set SZECHUAN_WS_MEM and SZECHUAN_WS_ISF");
        return;
    };
    let rows = net_rows(&mem, &isf);
    let c2 = rows.iter().filter(|r| is_c2(r)).count();
    assert!(
        c2 >= 1,
        "203.78.103.109 C2 connection must be recovered on the WS image"
    );
}

/// Regression guard: DC01 (build 9600) already attributes the coreupdater C2
/// owner. The 19041 fix must not disturb the modern-family 9600 overlay.
#[test]
fn dc01_9600_netstat_attributes_coreupdater_pid_3644() {
    let Some((mem, isf)) = env_pair("SZECHUAN_DC_MEM", "SZECHUAN_DC_ISF") else {
        eprintln!("skip: set SZECHUAN_DC_MEM and SZECHUAN_DC_ISF");
        return;
    };
    let rows = net_rows(&mem, &isf);
    let core = rows
        .iter()
        .find(|r| is_c2(r) && name_of(r).starts_with("coreupdater"))
        .expect("DC01 coreupdater C2 row must be present");
    assert_eq!(
        core["pid"].as_i64().unwrap(),
        3644,
        "DC01 coreupdater C2 owner PID must remain 3644: {core}"
    );
}
