# Vol3 CLI Compatibility Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make `memf` a drop-in superset of `vol` — existing scripts change nothing (symlink) or change `vol` → `memf vol` (subcommand), all 105 Windows plugins covered natively, proxy for community/unmapped plugins.

**Architecture:**
- New `vol` subcommand in `src/main.rs` that parses vol3-compatible flags (`-f`, `-r`, `-q`, `-v`, `-o`, `-s`, `-p`)
- `src/vol_compat.rs` — plugin dispatch table + vol3-format output + proxy exec
- `src/symbol_dl.rs` — ISF JSON auto-download from community server, caches in `~/.cache/memf/symbols/`
- argv[0] detection: if binary called as `vol`, skip clap subcommand and go directly to vol compat mode

**Tech Stack:** Rust, clap 4 (derive), ureq 3 (HTTP), assert_cmd (CLI testing), serde_json

**Vol3 text output format** (must match exactly for pipe compatibility):
```
Volatility 3 Framework 2.28.0\n
\n
Col1\tCol2\tCol3\n
\n
val1\tval2\tval3\n
```

**Plugin coverage classification:**
- **native:routing** (25) — already implemented in memf, just need dispatch wiring
- **native:new** (80+) — need new Rust implementation (future sessions, proxy in meantime)
- **proxy** — exec real `vol` binary; if not found, exit 1 with helpful error

---

## Task 1: Add `assert_cmd` for CLI testing

**Files:**
- Modify: `Cargo.toml` (workspace.dependencies + memf dev-dependencies)

**Step 1: Write the failing test**

```rust
// tests/vol_compat.rs
use assert_cmd::Command;

#[test]
fn test_vol_help_exits_zero() {
    Command::cargo_bin("memf")
        .unwrap()
        .args(["vol", "--help"])
        .assert()
        .success();
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test vol_compat test_vol_help_exits_zero 2>&1 | tail -5`
Expected: FAIL — `assert_cmd` not found OR `vol` subcommand not found

**Step 3: Add `assert_cmd` to Cargo.toml**

In `[workspace.dependencies]`:
```toml
assert_cmd = "2"
```

In memf package `[dev-dependencies]` section (create it):
```toml
[dev-dependencies]
assert_cmd.workspace = true
tempfile.workspace = true
```

**Step 4: Run test again — should still fail (vol subcommand not yet implemented)**

Run: `cargo test --test vol_compat test_vol_help_exits_zero 2>&1 | tail -5`
Expected: FAIL — "unexpected argument 'vol'" from clap

**Step 5: Commit RED**

```bash
git add Cargo.toml Cargo.lock tests/vol_compat.rs
git commit -m "test(cli): RED — vol subcommand CLI tests (assert_cmd)"
```

---

## Task 2: Vol subcommand skeleton (args only, no dispatch)

**Files:**
- Modify: `src/main.rs` — add `Vol` variant to `Commands` + argv[0] detection + forward to stub

**Step 1: Write additional RED tests**

Add to `tests/vol_compat.rs`:
```rust
#[test]
fn test_vol_missing_required_file_flag() {
    // vol with no -f flag should fail
    Command::cargo_bin("memf")
        .unwrap()
        .args(["vol", "windows.pslist.PsList"])
        .assert()
        .failure();
}

#[test]
fn test_vol_nonexistent_dump_fails() {
    Command::cargo_bin("memf")
        .unwrap()
        .args(["vol", "-f", "/nonexistent/dump.mem", "windows.pslist.PsList"])
        .assert()
        .failure();
}

#[test]
fn test_vol_version_header_in_stdout() {
    // When vol succeeds, stdout starts with "Volatility 3 Framework"
    // Use a known-good dump + already-implemented plugin for this
    // (Mark as #[ignore] if no dump available in CI)
    // ... (see task 5 for the full integration version)
}
```

**Step 2: Implement `Vol` command in `src/main.rs`**

Add to `Commands` enum:
```rust
/// Volatility3-compatible interface — drop-in replacement for `vol`.
/// Accepts the same flags as `vol`; maps known plugins to native memf
/// implementations; proxies the rest to the real `vol` binary.
#[command(name = "vol", override_usage = "memf vol [OPTIONS] PLUGIN [PLUGIN_ARGS...]")]
Vol {
    /// Memory dump file (vol3 -f flag).
    #[arg(short = 'f', long = "file", required = true)]
    file: PathBuf,

    /// Output renderer: text (default), json, csv, pretty, html, xlsx.
    #[arg(short = 'r', long = "renderer", default_value = "text")]
    renderer: VolRenderer,

    /// Output directory for files produced by plugins.
    #[arg(short = 'o', long = "output-dir")]
    output_dir: Option<PathBuf>,

    /// Suppress progress output.
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// Increase verbosity (repeatable: -v -v -v).
    #[arg(short = 'v', long = "verbosity", action = clap::ArgAction::Count)]
    verbosity: u8,

    /// Semi-colon separated symbol directories.
    #[arg(short = 's', long = "symbol-dirs")]
    symbol_dirs: Vec<PathBuf>,

    /// Semi-colon separated plugin directories.
    #[arg(short = 'p', long = "plugin-dirs")]
    plugin_dirs: Vec<PathBuf>,

    /// Plugin name followed by optional plugin-specific arguments.
    /// e.g.: windows.pslist.PsList --pid 1234
    #[arg(trailing_var_arg = true, required = true)]
    plugin_args: Vec<String>,
},
```

Add renderer enum:
```rust
#[derive(Clone, Copy, clap::ValueEnum)]
enum VolRenderer {
    Text,
    Json,
    #[value(name = "csv")]
    Csv,
    Pretty,
    Html,
    Xlsx,
    #[value(name = "dote")]
    Dot,
}
```

Add argv[0] detection in `main()` (BEFORE `Cli::parse()`):
```rust
fn main() -> Result<()> {
    // argv[0] detection: if invoked as `vol` (via symlink), prepend "vol" to args
    let args_os: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let binary_name = std::path::Path::new(&args_os[0])
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("memf");
    
    let effective_args: Vec<std::ffi::OsString> = if binary_name == "vol" {
        // Invoked as `vol -f dump plugin` → rewrite to `memf vol -f dump plugin`
        let mut a = vec![args_os[0].clone()]; // keep argv[0]
        a.push("vol".into());
        a.extend_from_slice(&args_os[1..]);
        a
    } else {
        args_os
    };

    tracing_subscriber::fmt()...
    
    let cli = Cli::parse_from(effective_args);
    // ...
}
```

Add stub handler in `main()` match:
```rust
Commands::Vol { file, renderer, output_dir, quiet, verbosity, symbol_dirs, plugin_dirs, plugin_args } => {
    vol_compat::run_vol_plugin(&file, renderer, output_dir.as_deref(), quiet, verbosity, &symbol_dirs, &plugin_dirs, &plugin_args)
}
```

Create `src/vol_compat.rs` with stub:
```rust
pub fn run_vol_plugin(
    dump: &std::path::Path,
    renderer: crate::VolRenderer,
    output_dir: Option<&std::path::Path>,
    quiet: bool,
    verbosity: u8,
    symbol_dirs: &[std::path::PathBuf],
    plugin_dirs: &[std::path::PathBuf],
    plugin_args: &[String],
) -> anyhow::Result<()> {
    if !dump.exists() {
        anyhow::bail!("dump file not found: {}", dump.display());
    }
    let plugin = plugin_args.first().map(|s| s.as_str()).unwrap_or("");
    anyhow::bail!("plugin not yet implemented: {plugin} — install `vol` for proxy support");
}
```

**Step 3: Run tests — should pass**

Run: `cargo test --test vol_compat 2>&1 | tail -10`
Expected: `test_vol_help_exits_zero` PASS, `test_vol_missing_required_file_flag` PASS, `test_vol_nonexistent_dump_fails` PASS

**Step 4: Commit GREEN**

```bash
git add src/main.rs src/vol_compat.rs
git commit -m "feat(cli): GREEN — vol subcommand skeleton + argv[0] detection"
```

---

## Task 3: Plugin dispatch table + vol proxy

**Files:**
- Modify: `src/vol_compat.rs` — full dispatch table + proxy exec

**Step 1: Write RED tests**

Add to `tests/vol_compat.rs`:
```rust
#[test]
fn test_vol_unknown_plugin_exits_nonzero_without_vol_binary() {
    // If `vol` is not in PATH, unknown plugin should fail with clear message
    Command::cargo_bin("memf")
        .unwrap()
        .env("PATH", "/nonexistent")  // no vol in path
        .args(["vol", "-f", "/tmp/vol3_test/DESKTOP-SDN1RPT.mem",
               "community.SomePlugin"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("community.SomePlugin"));
}

#[test]
fn test_vol_dispatch_table_covers_all_105_plugins() {
    // The dispatch table must have an entry for every plugin in ALL_WINDOWS_PLUGINS
    // This is a compile-time test via const assertions or a runtime registry check
    // Verify by checking DISPATCH_TABLE.len() >= 105
    assert!(vol_compat::DISPATCH_TABLE.len() >= 105,
        "dispatch table covers {} plugins, need >= 105", vol_compat::DISPATCH_TABLE.len());
}
```

**Step 2: Implement dispatch table in `src/vol_compat.rs`**

```rust
use std::collections::HashMap;

pub enum PluginDispatch {
    /// Route to a native memf command function
    Native(&'static str),
    /// Proxy to external `vol` binary
    Proxy,
}

pub static DISPATCH_TABLE: &[(&str, PluginDispatch)] = &[
    // ── process & thread ─────────────────────────────────────────────────────
    ("windows.pslist.PsList",              PluginDispatch::Native("ps")),
    ("windows.psscan.PsScan",              PluginDispatch::Native("ps:scan")),
    ("windows.pstree.PsTree",              PluginDispatch::Native("ps:tree")),
    ("windows.psxview.PsXView",            PluginDispatch::Native("check:psxview")),
    ("windows.cmdline.CmdLine",            PluginDispatch::Native("ps:cmdline")),
    ("windows.cmdscan.CmdScan",            PluginDispatch::Proxy),
    ("windows.envars.Envars",              PluginDispatch::Native("ps:envvars")),
    ("windows.sessions.Sessions",          PluginDispatch::Proxy),
    ("windows.joblinks.JobLinks",          PluginDispatch::Proxy),
    ("windows.debugregisters.DebugRegisters", PluginDispatch::Proxy),
    ("windows.privileges.Privs",           PluginDispatch::Native("ps:privileges")),
    ("windows.getsids.GetSIDs",            PluginDispatch::Proxy),
    ("windows.getservicesids.GetServiceSIDs", PluginDispatch::Proxy),
    ("windows.threads.Threads",            PluginDispatch::Native("ps:threads")),
    ("windows.thrdscan.ThrdScan",          PluginDispatch::Native("ps:threads")),
    ("windows.suspended_threads.SuspendedThreads", PluginDispatch::Proxy),
    ("windows.suspicious_threads.SuspiciousThreads", PluginDispatch::Proxy),
    ("windows.orphan_kernel_threads.Threads", PluginDispatch::Proxy),
    ("windows.memmap.Memmap",              PluginDispatch::Proxy),
    // ── DLLs, modules, drivers ──────────────────────────────────────────────
    ("windows.dlllist.DllList",            PluginDispatch::Native("ps:dlls")),
    ("windows.ldrmodules.LdrModules",      PluginDispatch::Native("check:ldrmodules")),
    ("windows.modules.Modules",            PluginDispatch::Native("sys")),
    ("windows.modscan.ModScan",            PluginDispatch::Proxy),
    ("windows.unloadedmodules.UnloadedModules", PluginDispatch::Proxy),
    ("windows.driverscan.DriverScan",      PluginDispatch::Proxy),
    ("windows.driverirp.DriverIrp",        PluginDispatch::Native("check:irp")),
    ("windows.drivermodule.DriverModule",  PluginDispatch::Proxy),
    ("windows.verinfo.VerInfo",            PluginDispatch::Proxy),
    // ── handles, objects ────────────────────────────────────────────────────
    ("windows.handles.Handles",            PluginDispatch::Native("handles")),
    ("windows.mutantscan.MutantScan",      PluginDispatch::Proxy),
    ("windows.symlinkscan.SymlinkScan",    PluginDispatch::Proxy),
    ("windows.poolscanner.PoolScanner",    PluginDispatch::Proxy),
    ("windows.bigpools.BigPools",          PluginDispatch::Proxy),
    ("windows.desktops.Desktops",          PluginDispatch::Proxy),
    ("windows.deskscan.DeskScan",          PluginDispatch::Proxy),
    ("windows.windows.Windows",            PluginDispatch::Proxy),
    ("windows.windowstations.WindowStations", PluginDispatch::Proxy),
    // ── network ─────────────────────────────────────────────────────────────
    ("windows.netscan.NetScan",            PluginDispatch::Native("net")),
    ("windows.netstat.NetStat",            PluginDispatch::Native("net")),
    // ── file system ─────────────────────────────────────────────────────────
    ("windows.filescan.FileScan",          PluginDispatch::Proxy),
    ("windows.mftscan.MFTScan",            PluginDispatch::Proxy),
    ("windows.mftscan.ADS",                PluginDispatch::Proxy),
    ("windows.mftscan.ResidentData",       PluginDispatch::Proxy),
    ("windows.dumpfiles.DumpFiles",        PluginDispatch::Proxy),
    // ── kernel structures ───────────────────────────────────────────────────
    ("windows.ssdt.SSDT",                  PluginDispatch::Native("check:ssdt")),
    ("windows.callbacks.Callbacks",        PluginDispatch::Native("check:callbacks")),
    ("windows.kpcrs.KPCRs",               PluginDispatch::Proxy),
    ("windows.timers.Timers",              PluginDispatch::Proxy),
    ("windows.devicetree.DeviceTree",      PluginDispatch::Proxy),
    ("windows.consoles.Consoles",          PluginDispatch::Proxy),
    ("windows.crashinfo.Crashinfo",        PluginDispatch::Proxy),
    ("windows.statistics.Statistics",      PluginDispatch::Proxy),
    ("windows.virtmap.VirtMap",            PluginDispatch::Proxy),
    ("windows.mbrscan.MBRScan",            PluginDispatch::Proxy),
    ("windows.shimcachemem.ShimcacheMem",  PluginDispatch::Proxy),
    // ── VAD / virtual memory ─────────────────────────────────────────────────
    ("windows.vadinfo.VadInfo",            PluginDispatch::Native("ps:vad")),
    ("windows.vadwalk.VadWalk",            PluginDispatch::Native("ps:vad")),
    ("windows.vadregexscan.VadRegExScan",  PluginDispatch::Proxy),
    ("windows.vadyarascan.VadYaraScan",    PluginDispatch::Proxy),
    // ── malware detection ────────────────────────────────────────────────────
    ("windows.malfind.Malfind",            PluginDispatch::Native("check:malfind")),
    ("windows.hollowprocesses.HollowProcesses", PluginDispatch::Native("check:hollowing")),
    ("windows.processghosting.ProcessGhosting", PluginDispatch::Proxy),
    ("windows.etwpatch.EtwPatch",          PluginDispatch::Proxy),
    ("windows.skeleton_key_check.Skeleton_Key_Check", PluginDispatch::Proxy),
    ("windows.svcdiff.SvcDiff",            PluginDispatch::Proxy),
    ("windows.direct_system_calls.DirectSystemCalls", PluginDispatch::Proxy),
    ("windows.indirect_system_calls.IndirectSystemCalls", PluginDispatch::Proxy),
    ("windows.unhooked_system_calls.unhooked_system_calls", PluginDispatch::Proxy),
    ("windows.strings.Strings",            PluginDispatch::Native("strings")),
    ("windows.pe_symbols.PESymbols",       PluginDispatch::Proxy),
    ("windows.iat.IAT",                    PluginDispatch::Proxy),
    ("windows.pedump.PEDump",              PluginDispatch::Native("procdump")),
    // ── malware.* aliases ────────────────────────────────────────────────────
    ("windows.malware.malfind.Malfind",    PluginDispatch::Native("check:malfind")),
    ("windows.malware.hollowprocesses.HollowProcesses", PluginDispatch::Native("check:hollowing")),
    ("windows.malware.processghosting.ProcessGhosting", PluginDispatch::Proxy),
    ("windows.malware.ldrmodules.LdrModules", PluginDispatch::Native("check:ldrmodules")),
    ("windows.malware.pebmasquerade.PebMasquerade", PluginDispatch::Proxy),
    ("windows.malware.psxview.PsXView",   PluginDispatch::Native("check:psxview")),
    ("windows.malware.svcdiff.SvcDiff",   PluginDispatch::Proxy),
    ("windows.malware.skeleton_key_check.Skeleton_Key_Check", PluginDispatch::Proxy),
    ("windows.malware.drivermodule.DriverModule", PluginDispatch::Proxy),
    ("windows.malware.suspicious_threads.SuspiciousThreads", PluginDispatch::Proxy),
    ("windows.malware.direct_system_calls.DirectSystemCalls", PluginDispatch::Proxy),
    ("windows.malware.indirect_system_calls.IndirectSystemCalls", PluginDispatch::Proxy),
    ("windows.malware.unhooked_system_calls.UnhookedSystemCalls", PluginDispatch::Proxy),
    // ── credentials / hashes ────────────────────────────────────────────────
    ("windows.hashdump.Hashdump",          PluginDispatch::Proxy),
    ("windows.cachedump.Cachedump",        PluginDispatch::Proxy),
    ("windows.lsadump.Lsadump",            PluginDispatch::Proxy),
    // ── registry ────────────────────────────────────────────────────────────
    ("windows.registry.hivelist.HiveList",     PluginDispatch::Proxy),
    ("windows.registry.hivescan.HiveScan",     PluginDispatch::Proxy),
    ("windows.registry.printkey.PrintKey",     PluginDispatch::Proxy),
    ("windows.registry.hashdump.Hashdump",     PluginDispatch::Proxy),
    ("windows.registry.cachedump.Cachedump",   PluginDispatch::Proxy),
    ("windows.registry.lsadump.Lsadump",       PluginDispatch::Proxy),
    ("windows.registry.amcache.Amcache",       PluginDispatch::Proxy),
    ("windows.registry.certificates.Certificates", PluginDispatch::Proxy),
    ("windows.registry.getcellroutine.GetCellRoutine", PluginDispatch::Proxy),
    ("windows.registry.scheduled_tasks.ScheduledTasks", PluginDispatch::Proxy),
    ("windows.registry.userassist.UserAssist", PluginDispatch::Proxy),
    // ── services / tasks ────────────────────────────────────────────────────
    ("windows.svcscan.SvcScan",            PluginDispatch::Proxy),
    ("windows.svclist.SvcList",            PluginDispatch::Proxy),
    ("windows.scheduled_tasks.ScheduledTasks", PluginDispatch::Proxy),
    // ── info & misc ─────────────────────────────────────────────────────────
    ("windows.info.Info",                  PluginDispatch::Native("info")),
    ("windows.amcache.Amcache",            PluginDispatch::Proxy),
    ("windows.truecrypt.Passphrase",       PluginDispatch::Proxy),
];
```

Proxy execution:
```rust
fn proxy_to_vol(plugin_args: &[String], dump: &Path, extra_args: &[&str]) -> anyhow::Result<()> {
    let vol_path = which_vol().ok_or_else(|| {
        anyhow::anyhow!(
            "Plugin '{}' is not natively implemented in memf and `vol` is not in PATH.\n\
             Install volatility3 (`pip install volatility3`) for proxy support,\n\
             or wait for native implementation in a future memf release.",
            plugin_args.first().map(|s| s.as_str()).unwrap_or("(unknown)")
        )
    })?;
    
    let status = std::process::Command::new(vol_path)
        .args(extra_args)
        .args(plugin_args)
        .status()
        .context("failed to exec vol")?;
    
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}
```

**Step 3: Run tests**

Run: `cargo test --test vol_compat 2>&1 | tail -10`
Expected: All passing

**Step 4: Commit GREEN**

```bash
git commit -m "feat(cli): GREEN — vol plugin dispatch table + proxy exec"
```

---

## Task 4: Native plugin wiring — pslist, netscan, info

**Files:**
- Modify: `src/vol_compat.rs` — implement `dispatch_native()` routing actual memf commands

**Step 1: Write RED integration tests**

```rust
// tests/vol_compat.rs  (add, marked #[ignore] by default, run with --include-ignored)
#[test]
#[ignore = "requires DESKTOP-SDN1RPT.mem at /tmp/vol3_test/"]
fn test_vol_pslist_produces_pid_column() {
    Command::cargo_bin("memf")
        .unwrap()
        .args(["vol", "-f", "/tmp/vol3_test/DESKTOP-SDN1RPT.mem",
               "windows.pslist.PsList"])
        .assert()
        .success()
        .stdout(predicates::str::contains("PID"))
        .stdout(predicates::str::contains("System"));
}

#[test]
#[ignore = "requires DESKTOP-SDN1RPT.mem at /tmp/vol3_test/"]
fn test_vol_info_produces_kernel_base() {
    Command::cargo_bin("memf")
        .unwrap()
        .args(["vol", "-f", "/tmp/vol3_test/DESKTOP-SDN1RPT.mem",
               "windows.info.Info"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Kernel Base"));
}

#[test]
#[ignore = "requires DESKTOP-SDN1RPT.mem at /tmp/vol3_test/"]
fn test_vol_json_renderer_produces_json_array() {
    let output = Command::cargo_bin("memf")
        .unwrap()
        .args(["vol", "-f", "/tmp/vol3_test/DESKTOP-SDN1RPT.mem",
               "-r", "json", "windows.pslist.PsList"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Must be valid JSON array
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert!(parsed.is_array());
}

#[test]
#[ignore = "requires DESKTOP-SDN1RPT.mem at /tmp/vol3_test/"]  
fn test_vol_text_header_matches_vol3_format() {
    let output = Command::cargo_bin("memf")
        .unwrap()
        .args(["vol", "-f", "/tmp/vol3_test/DESKTOP-SDN1RPT.mem",
               "windows.pslist.PsList"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let first_line = stdout.lines().next().unwrap_or("");
    assert!(first_line.contains("Volatility"),
        "first line should contain 'Volatility', got: {first_line:?}");
}
```

**Step 2: Implement native routing for pslist/info/netscan/handles/modules/check**

In `src/vol_compat.rs`:

```rust
fn dispatch_native(
    native_key: &str,
    dump: &Path,
    plugin_args: &[String],    // plugin name is [0], plugin-specific args follow
    renderer: VolRenderer,
    output_dir: Option<&Path>,
    quiet: bool,
    symbol_dirs: &[PathBuf],
) -> anyhow::Result<()> {
    // Parse plugin-specific flags from plugin_args[1..]
    let plugin_flags = PluginFlags::parse(&plugin_args[1..]);
    
    // Print vol3-compatible version header
    if !quiet {
        print_vol_header();
    }
    
    match native_key {
        "ps" | "ps:scan" => {
            let rows = collect_ps(dump, symbol_dirs, &plugin_flags)?;
            emit_pslist(rows, renderer)
        }
        "ps:tree" => {
            let rows = collect_ps(dump, symbol_dirs, &plugin_flags)?;
            emit_pstree(rows, renderer)
        }
        "ps:cmdline" => {
            let rows = collect_ps_cmdline(dump, symbol_dirs, &plugin_flags)?;
            emit_cmdline(rows, renderer)
        }
        "ps:dlls" => {
            let rows = collect_dlls(dump, symbol_dirs, &plugin_flags)?;
            emit_dlllist(rows, renderer)
        }
        "ps:envvars" => {
            let rows = collect_envvars(dump, symbol_dirs, &plugin_flags)?;
            emit_envvars(rows, renderer)
        }
        "ps:privileges" => {
            let rows = collect_privileges(dump, symbol_dirs, &plugin_flags)?;
            emit_privs(rows, renderer)
        }
        "ps:threads" => {
            let rows = collect_threads(dump, symbol_dirs, &plugin_flags)?;
            emit_threads(rows, renderer)
        }
        "ps:vad" => {
            let rows = collect_vad(dump, symbol_dirs, &plugin_flags)?;
            emit_vadinfo(rows, renderer)
        }
        "net" => {
            let rows = collect_net(dump, symbol_dirs, &plugin_flags)?;
            emit_netscan(rows, renderer)
        }
        "sys" => {
            let rows = collect_modules(dump, symbol_dirs, &plugin_flags)?;
            emit_modules(rows, renderer)
        }
        "handles" => {
            let rows = collect_handles(dump, symbol_dirs, &plugin_flags)?;
            emit_handles(rows, renderer)
        }
        "check:ssdt" => emit_check_result(collect_ssdt(dump, symbol_dirs)?, renderer),
        "check:callbacks" => emit_check_result(collect_callbacks(dump, symbol_dirs)?, renderer),
        "check:malfind" => emit_check_result(collect_malfind(dump, symbol_dirs, &plugin_flags)?, renderer),
        "check:ldrmodules" => emit_check_result(collect_ldrmodules(dump, symbol_dirs, &plugin_flags)?, renderer),
        "check:hollowing" => emit_check_result(collect_hollowing(dump, symbol_dirs)?, renderer),
        "check:psxview" => emit_check_result(collect_psxview(dump, symbol_dirs)?, renderer),
        "check:irp" => emit_check_result(collect_irp(dump, symbol_dirs)?, renderer),
        "info" => emit_info(collect_info(dump)?, renderer),
        "strings" => emit_strings(collect_strings(dump, &plugin_flags)?, renderer),
        "procdump" => run_procdump(dump, symbol_dirs, &plugin_flags, output_dir),
        _ => anyhow::bail!("unhandled native key: {native_key}"),
    }
}
```

Vol3-compatible text emission (example for pslist):
```rust
fn emit_pslist(rows: Vec<PsRow>, renderer: VolRenderer) -> anyhow::Result<()> {
    match renderer {
        VolRenderer::Text => {
            // Vol3 exact format: blank line, tab headers, blank line, data rows
            println!();
            println!("PID\tPPID\tImageFileName\tOffset(V)\tThreads\tHandles\tSessionId\tWow64\tCreateTime\tExitTime\tFile output");
            println!();
            for row in &rows {
                println!("{}\t{}\t{}\t0x{:016x}\t{}\t{}\t{}\t{}\t{}\t{}\tDisabled",
                    row.pid, row.ppid, row.name, row.offset,
                    row.threads, row.handles.map_or("-".to_string(), |h| h.to_string()),
                    row.session_id.map_or("N/A".to_string(), |s| s.to_string()),
                    row.wow64,
                    row.create_time.map_or("N/A".to_string(), |t| format_vol_time(t)),
                    row.exit_time.map_or("N/A".to_string(), |t| format_vol_time(t)),
                );
            }
            Ok(())
        }
        VolRenderer::Json => {
            let json: Vec<serde_json::Value> = rows.iter().map(|r| {
                serde_json::json!({
                    "PID": r.pid, "PPID": r.ppid, "ImageFileName": r.name,
                    "Offset(V)": r.offset, "Threads": r.threads,
                    "Handles": r.handles, "SessionId": r.session_id,
                    "Wow64": r.wow64,
                    "CreateTime": r.create_time.map(format_vol_iso),
                    "ExitTime": r.exit_time.map(format_vol_iso),
                    "File output": "Disabled",
                    "__children": []
                })
            }).collect();
            println!("{}", serde_json::to_string_pretty(&json)?);
            Ok(())
        }
        VolRenderer::Csv => {
            println!("PID,PPID,ImageFileName,Offset(V),Threads,Handles,SessionId,Wow64,CreateTime,ExitTime");
            for row in &rows { /* ... */ }
            Ok(())
        }
        _ => anyhow::bail!("renderer not yet supported: use text, json, or csv"),
    }
}
```

**Step 3: Run ignored integration tests**

Run: `cargo test --test vol_compat -- --include-ignored 2>&1 | tail -20`
Expected: All pass (pslist contains PID, System; info contains Kernel Base)

**Step 4: Commit GREEN**

```bash
git commit -m "feat(cli): GREEN — native plugin wiring for pslist/net/info/handles/check"
```

---

## Task 5: Symbol auto-download

**Files:**
- Create: `src/symbol_dl.rs` — ISF JSON download + local cache
- Modify: `src/vol_compat.rs` — call symbol_dl before dispatching

**Step 1: Write RED tests**

```rust
// tests/vol_compat.rs (unit tests for symbol_dl)
#[test]
fn test_symbol_dl_cache_dir_is_created() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = symbol_dl::cache_dir_for_testing(tmp.path());
    symbol_dl::ensure_cache_dir(&cache).unwrap();
    assert!(cache.exists());
}

#[test]
fn test_symbol_dl_build_isf_url_win10_19041() {
    let url = symbol_dl::build_isf_url("ntkrnlmp.pdb", "81BC5C377C525081645F9958F209C527", 1);
    assert!(url.contains("ntkrnlmp.pdb"), "url={url}");
    assert!(url.contains("81BC5C"), "url={url}");
}
```

**Step 2: Implement `src/symbol_dl.rs`**

ISF community server: `https://isf-server.code.digitalpolice.ca/`
URL pattern: `https://isf-server.code.digitalpolice.ca/windows/ntkrnlmp.pdb/GUID-AGE.json.xz`

```rust
pub fn auto_download_symbols(metadata: &DumpMetadata) -> anyhow::Result<PathBuf> {
    // 1. Check ~/.cache/memf/symbols/ for existing ISF
    // 2. Extract PDB GUID from metadata
    // 3. Try ISF server download
    // 4. Fallback: try msdl.microsoft.com for PDB + convert
    // 5. Cache result
}
```

**Step 3: Wire into dispatch flow**

In `run_vol_plugin()`, before dispatching:
```rust
let symbols = if symbol_dirs.is_empty() {
    // Auto-download
    match symbol_dl::auto_download_symbols(&dump_metadata) {
        Ok(path) => vec![path],
        Err(e) => {
            if !quiet { eprintln!("WARNING: symbol auto-download failed: {e}"); }
            vec![]
        }
    }
} else {
    symbol_dirs.to_vec()
};
```

**Step 4: Run tests**

Run: `cargo test --test vol_compat test_symbol_dl 2>&1 | tail -10`
Expected: All pass

**Step 5: Commit GREEN**

```bash
git commit -m "feat(cli): GREEN — symbol auto-download from ISF community server"
```

---

## Task 6: Catalogue test update + dumpfiles fix

**Files:**
- Modify: `python/volatility3-memf/tests/_catalogue.py` — mark dumpfiles as needs_args=True

**Step 1:** The background test showed `windows.dumpfiles.DumpFiles` produces a traceback on the primary dump without `--dump-dir`. Mark it:

```python
_p("windows.dumpfiles.DumpFiles",         needs_args=True),  # vol3 bug: traceback without --dump-dir
```

**Step 2:** Verify fix

Run: `python -m pytest "tests/test_vol3_comprehensive.py::TestAllStandardPluginsOnPrimaryDump::test_no_crash" -k "dumpfiles" -v`
Expected: 0 selected (not in STANDARD_PLUGINS anymore)

**Step 3: Commit**

```bash
git add tests/_catalogue.py
git commit -m "fix(python): mark dumpfiles as needs_args (vol3 traceback without --dump-dir)"
```

---

## Implementation Order

1. Task 6 first (quick Python fix, unblock clean test run)
2. Task 1 (add assert_cmd)
3. Task 2 (vol subcommand skeleton + argv[0])
4. Task 3 (dispatch table + proxy)
5. Task 4 (native wiring for already-implemented plugins)
6. Task 5 (symbol auto-download)

## Native Implementation Backlog (future sessions)

These 80+ plugins need new Rust implementations in `memf-windows`:
- Registry: hivelist, hivescan, printkey, amcache, certificates, userassist, scheduled_tasks, getcellroutine
- Credentials: hashdump, cachedump, lsadump
- Kernel objects: sessions, desktops, windows, windowstations, consoles, kpcrs, timers, devicetree
- Scanning: modscan, driverscan, filescan, mftscan, poolscanner, mutantscan, symlinkscan
- Malware: processghosting, etwpatch, skeleton_key, svcdiff, direct_syscalls, indirect_syscalls
- Misc: verinfo, bigpools, virtmap, mbrscan, shimcachemem, truecrypt, cmdscan, getsids
- VAD analysis: vadregexscan, vadyarascan
- PE: pe_symbols, iat
- Services: svcscan, svclist
