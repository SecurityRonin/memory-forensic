//! Volatility3 CLI compatibility layer.
//!
//! Provides the dispatch table mapping vol3 plugin names to native memf
//! command keys, plus proxy execution when no native implementation exists.

use std::path::{Path, PathBuf};

/// Vol3 framework version string emitted on stdout before every result set.
pub const VOL3_BANNER: &str = "Volatility 3 Framework 2.28.0";

/// How a vol3 plugin name is handled.
#[derive(Debug, Clone, Copy)]
pub enum PluginRoute {
    /// Route to the native memf command identified by this key.
    Native(&'static str),
    /// Proxy to the external `vol` binary; not yet implemented natively.
    Proxy,
}

/// Full dispatch table: (vol3_plugin_name, route).
/// Every officially-known plugin appears here; unknown plugins are proxied.
pub static DISPATCH: &[(&str, PluginRoute)] = &[
    // ── process & thread ─────────────────────────────────────────────────
    ("windows.pslist.PsList",              PluginRoute::Native("ps")),
    ("windows.psscan.PsScan",              PluginRoute::Native("ps")),
    ("windows.pstree.PsTree",              PluginRoute::Native("ps:tree")),
    ("windows.psxview.PsXView",            PluginRoute::Native("check:psxview")),
    ("windows.cmdline.CmdLine",            PluginRoute::Native("ps:cmdline")),
    ("windows.cmdscan.CmdScan",            PluginRoute::Proxy),
    ("windows.envars.Envars",              PluginRoute::Native("ps:envvars")),
    ("windows.sessions.Sessions",          PluginRoute::Proxy),
    ("windows.joblinks.JobLinks",          PluginRoute::Proxy),
    ("windows.debugregisters.DebugRegisters", PluginRoute::Proxy),
    ("windows.privileges.Privs",           PluginRoute::Native("ps:privileges")),
    ("windows.getsids.GetSIDs",            PluginRoute::Proxy),
    ("windows.getservicesids.GetServiceSIDs", PluginRoute::Proxy),
    ("windows.threads.Threads",            PluginRoute::Native("ps:threads")),
    ("windows.thrdscan.ThrdScan",          PluginRoute::Native("ps:threads")),
    ("windows.suspended_threads.SuspendedThreads", PluginRoute::Proxy),
    ("windows.suspicious_threads.SuspiciousThreads", PluginRoute::Proxy),
    ("windows.orphan_kernel_threads.Threads", PluginRoute::Proxy),
    ("windows.memmap.Memmap",              PluginRoute::Proxy),
    // ── DLLs, modules, drivers ──────────────────────────────────────────
    ("windows.dlllist.DllList",            PluginRoute::Native("ps:dlls")),
    ("windows.ldrmodules.LdrModules",      PluginRoute::Native("check:ldrmodules")),
    ("windows.modules.Modules",            PluginRoute::Native("sys")),
    ("windows.modscan.ModScan",            PluginRoute::Proxy),
    ("windows.unloadedmodules.UnloadedModules", PluginRoute::Proxy),
    ("windows.driverscan.DriverScan",      PluginRoute::Proxy),
    ("windows.driverirp.DriverIrp",        PluginRoute::Native("check:irp")),
    ("windows.drivermodule.DriverModule",  PluginRoute::Proxy),
    ("windows.verinfo.VerInfo",            PluginRoute::Proxy),
    // ── handles, objects ────────────────────────────────────────────────
    ("windows.handles.Handles",            PluginRoute::Native("handles")),
    ("windows.mutantscan.MutantScan",      PluginRoute::Proxy),
    ("windows.symlinkscan.SymlinkScan",    PluginRoute::Proxy),
    ("windows.poolscanner.PoolScanner",    PluginRoute::Proxy),
    ("windows.bigpools.BigPools",          PluginRoute::Proxy),
    ("windows.desktops.Desktops",          PluginRoute::Proxy),
    ("windows.deskscan.DeskScan",          PluginRoute::Proxy),
    ("windows.windows.Windows",            PluginRoute::Proxy),
    ("windows.windowstations.WindowStations", PluginRoute::Proxy),
    // ── network ─────────────────────────────────────────────────────────
    ("windows.netscan.NetScan",            PluginRoute::Native("net")),
    ("windows.netstat.NetStat",            PluginRoute::Native("net")),
    // ── file system ─────────────────────────────────────────────────────
    ("windows.filescan.FileScan",          PluginRoute::Proxy),
    ("windows.mftscan.MFTScan",            PluginRoute::Proxy),
    ("windows.mftscan.ADS",                PluginRoute::Proxy),
    ("windows.mftscan.ResidentData",       PluginRoute::Proxy),
    ("windows.dumpfiles.DumpFiles",        PluginRoute::Proxy),
    // ── kernel structures ───────────────────────────────────────────────
    ("windows.ssdt.SSDT",                  PluginRoute::Native("check:ssdt")),
    ("windows.callbacks.Callbacks",        PluginRoute::Native("check:callbacks")),
    ("windows.kpcrs.KPCRs",               PluginRoute::Proxy),
    ("windows.timers.Timers",              PluginRoute::Proxy),
    ("windows.devicetree.DeviceTree",      PluginRoute::Proxy),
    ("windows.consoles.Consoles",          PluginRoute::Proxy),
    ("windows.crashinfo.Crashinfo",        PluginRoute::Proxy),
    ("windows.statistics.Statistics",      PluginRoute::Proxy),
    ("windows.virtmap.VirtMap",            PluginRoute::Proxy),
    ("windows.mbrscan.MBRScan",            PluginRoute::Proxy),
    ("windows.shimcachemem.ShimcacheMem",  PluginRoute::Proxy),
    // ── VAD / virtual memory ─────────────────────────────────────────────
    ("windows.vadinfo.VadInfo",            PluginRoute::Native("ps:vad")),
    ("windows.vadwalk.VadWalk",            PluginRoute::Native("ps:vad")),
    ("windows.vadregexscan.VadRegExScan",  PluginRoute::Proxy),
    ("windows.vadyarascan.VadYaraScan",    PluginRoute::Proxy),
    // ── malware detection ────────────────────────────────────────────────
    ("windows.malfind.Malfind",            PluginRoute::Native("check:malfind")),
    ("windows.hollowprocesses.HollowProcesses", PluginRoute::Native("check:hollowing")),
    ("windows.processghosting.ProcessGhosting", PluginRoute::Proxy),
    ("windows.etwpatch.EtwPatch",          PluginRoute::Proxy),
    ("windows.skeleton_key_check.Skeleton_Key_Check", PluginRoute::Proxy),
    ("windows.svcdiff.SvcDiff",            PluginRoute::Proxy),
    ("windows.direct_system_calls.DirectSystemCalls", PluginRoute::Proxy),
    ("windows.indirect_system_calls.IndirectSystemCalls", PluginRoute::Proxy),
    ("windows.unhooked_system_calls.unhooked_system_calls", PluginRoute::Proxy),
    ("windows.strings.Strings",            PluginRoute::Native("strings")),
    ("windows.pe_symbols.PESymbols",       PluginRoute::Proxy),
    ("windows.iat.IAT",                    PluginRoute::Proxy),
    ("windows.pedump.PEDump",              PluginRoute::Native("procdump")),
    // ── malware.* aliases ────────────────────────────────────────────────
    ("windows.malware.malfind.Malfind",    PluginRoute::Native("check:malfind")),
    ("windows.malware.hollowprocesses.HollowProcesses", PluginRoute::Native("check:hollowing")),
    ("windows.malware.processghosting.ProcessGhosting", PluginRoute::Proxy),
    ("windows.malware.ldrmodules.LdrModules", PluginRoute::Native("check:ldrmodules")),
    ("windows.malware.pebmasquerade.PebMasquerade", PluginRoute::Proxy),
    ("windows.malware.psxview.PsXView",   PluginRoute::Native("check:psxview")),
    ("windows.malware.svcdiff.SvcDiff",   PluginRoute::Proxy),
    ("windows.malware.skeleton_key_check.Skeleton_Key_Check", PluginRoute::Proxy),
    ("windows.malware.drivermodule.DriverModule", PluginRoute::Proxy),
    ("windows.malware.suspicious_threads.SuspiciousThreads", PluginRoute::Proxy),
    ("windows.malware.direct_system_calls.DirectSystemCalls", PluginRoute::Proxy),
    ("windows.malware.indirect_system_calls.IndirectSystemCalls", PluginRoute::Proxy),
    ("windows.malware.unhooked_system_calls.UnhookedSystemCalls", PluginRoute::Proxy),
    // ── credentials / hashes ────────────────────────────────────────────
    ("windows.hashdump.Hashdump",          PluginRoute::Proxy),
    ("windows.cachedump.Cachedump",        PluginRoute::Proxy),
    ("windows.lsadump.Lsadump",            PluginRoute::Proxy),
    // ── registry ────────────────────────────────────────────────────────
    ("windows.registry.hivelist.HiveList",     PluginRoute::Proxy),
    ("windows.registry.hivescan.HiveScan",     PluginRoute::Proxy),
    ("windows.registry.printkey.PrintKey",     PluginRoute::Proxy),
    ("windows.registry.hashdump.Hashdump",     PluginRoute::Proxy),
    ("windows.registry.cachedump.Cachedump",   PluginRoute::Proxy),
    ("windows.registry.lsadump.Lsadump",       PluginRoute::Proxy),
    ("windows.registry.amcache.Amcache",       PluginRoute::Proxy),
    ("windows.registry.certificates.Certificates", PluginRoute::Proxy),
    ("windows.registry.getcellroutine.GetCellRoutine", PluginRoute::Proxy),
    ("windows.registry.scheduled_tasks.ScheduledTasks", PluginRoute::Proxy),
    ("windows.registry.userassist.UserAssist", PluginRoute::Proxy),
    // ── services / tasks ────────────────────────────────────────────────
    ("windows.svcscan.SvcScan",            PluginRoute::Proxy),
    ("windows.svclist.SvcList",            PluginRoute::Proxy),
    ("windows.scheduled_tasks.ScheduledTasks", PluginRoute::Proxy),
    // ── info & misc ─────────────────────────────────────────────────────
    ("windows.info.Info",                  PluginRoute::Native("info")),
    ("windows.amcache.Amcache",            PluginRoute::Proxy),
    ("windows.truecrypt.Passphrase",       PluginRoute::Proxy),
    // ── yarascan (top-level) ─────────────────────────────────────────────
    ("yarascan.YaraScan",                  PluginRoute::Proxy),
];

/// Look up a plugin name in the dispatch table.
pub fn find_route(plugin: &str) -> Option<PluginRoute> {
    DISPATCH.iter().find(|(name, _)| *name == plugin).map(|(_, r)| *r)
}

/// Parse a `--pid N` flag out of plugin-specific trailing args.
pub fn parse_pid(plugin_args: &[String]) -> Option<u64> {
    let mut iter = plugin_args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--pid" {
            return iter.next().and_then(|v| v.parse().ok());
        }
        if let Some(val) = arg.strip_prefix("--pid=") {
            return val.parse().ok();
        }
    }
    None
}

/// Exec the real `vol` binary with the same arguments.
/// Returns an error if `vol` is not found in PATH.
pub fn proxy_to_vol(
    dump: &Path,
    renderer: crate::VolRenderer,
    output_dir: Option<&Path>,
    quiet: bool,
    symbol_dirs: &[PathBuf],
    plugin_dirs: &[PathBuf],
    plugin_args: &[String],
) -> anyhow::Result<()> {
    let plugin_name = plugin_args.first().map(|s| s.as_str()).unwrap_or("(unknown)");

    let mut cmd = std::process::Command::new("vol");
    cmd.arg("-f").arg(dump);

    // Forward renderer if non-default
    match renderer {
        crate::VolRenderer::Json  => { cmd.args(["-r", "json"]); }
        crate::VolRenderer::Csv   => { cmd.args(["-r", "csv"]); }
        crate::VolRenderer::Pretty => { cmd.args(["-r", "pretty"]); }
        crate::VolRenderer::Html  => { cmd.args(["-r", "html"]); }
        crate::VolRenderer::Xlsx  => { cmd.args(["-r", "xlsx"]); }
        crate::VolRenderer::Dot   => { cmd.args(["-r", "dote"]); }
        crate::VolRenderer::Text  => {}  // default, omit
    }
    if let Some(od) = output_dir {
        cmd.arg("-o").arg(od);
    }
    if quiet {
        cmd.arg("-q");
    }
    for sd in symbol_dirs {
        cmd.arg("-s").arg(sd);
    }
    for pd in plugin_dirs {
        cmd.arg("-p").arg(pd);
    }
    cmd.args(plugin_args);

    let result = cmd.status();
    match result {
        Ok(status) => {
            if !status.success() {
                std::process::exit(status.code().unwrap_or(1));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!(
                "Plugin '{plugin_name}' is not natively implemented in memf \
                 and `vol` was not found in PATH.\n\
                 Install volatility3 (`pip install volatility3`) to enable proxy support,\n\
                 or wait for native implementation in a future memf release."
            )
        }
        Err(e) => anyhow::bail!("failed to exec vol: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_windows::{WinConnectionInfo, WinProcessInfo, WinTcpState};

    fn make_proc() -> WinProcessInfo {
        WinProcessInfo {
            pid: 4,
            ppid: 0,
            image_name: "System".into(),
            create_time: 133_000_000_000_000_000,
            exit_time: 0,
            cr3: 0x1000,
            peb_addr: 0,
            vaddr: 0xffff808012340000,
            thread_count: 158,
            is_wow64: false,
            handle_count: 2000,
            session_id: 0,
        }
    }

    fn make_conn() -> WinConnectionInfo {
        WinConnectionInfo {
            protocol: "TCPv4".into(),
            local_addr: "192.168.1.1".into(),
            local_port: 54321,
            remote_addr: "8.8.8.8".into(),
            remote_port: 443,
            state: WinTcpState::Established,
            pid: 1234,
            process_name: "chrome.exe".into(),
            create_time: 133_000_000_000_000_000,
            offset: 0xffff80001234abcd,
        }
    }

    #[test]
    fn test_format_vol3_filetime_zero_is_null_str() {
        assert_eq!(format_vol3_filetime(0), "N/A");
    }

    #[test]
    fn test_format_vol3_filetime_has_microsecond_precision() {
        // FILETIME 133497474451234560 ≈ 2024-01-15 10:30:45.123456 UTC
        let s = format_vol3_filetime(133_497_474_451_234_560);
        // Must contain a decimal point and have exactly 6 fractional digits
        let dot_pos = s.find('.').expect("must contain '.'");
        assert_eq!(s.len() - dot_pos - 1, 6, "must have 6 decimal places: {s}");
    }

    #[test]
    fn test_vol3_processes_json_has_vol3_field_names() {
        let json = vol3_processes_json(&[make_proc()]);
        assert!(json.contains("\"ImageFileName\""), "missing ImageFileName: {json}");
        assert!(json.contains("\"Offset(V)\""), "missing Offset(V): {json}");
        assert!(json.contains("\"SessionId\""), "missing SessionId: {json}");
        assert!(json.contains("\"Handles\""), "missing Handles: {json}");
        assert!(json.contains("\"Wow64\""), "missing Wow64: {json}");
        assert!(json.contains("\"__children\""), "missing __children: {json}");
        assert!(json.contains("\"PPID\""), "missing PPID: {json}");
    }

    #[test]
    fn test_vol3_processes_json_no_native_column_names() {
        let json = vol3_processes_json(&[make_proc()]);
        assert!(!json.contains("\"image_name\""), "must not have snake_case field: {json}");
        assert!(!json.contains("\"eprocess\""), "must not have eprocess: {json}");
        assert!(!json.contains("\"session_id\""), "must not have snake_case session_id: {json}");
    }

    #[test]
    fn test_vol3_processes_text_header_has_vol3_columns() {
        let text = vol3_processes_text(&[]);
        assert!(text.contains("PID"), "missing PID: {text}");
        assert!(text.contains("ImageFileName"), "missing ImageFileName: {text}");
        assert!(text.contains("Offset(V)"), "missing Offset(V): {text}");
        assert!(text.contains("SessionId"), "missing SessionId: {text}");
    }

    #[test]
    fn test_vol3_connections_json_has_vol3_field_names() {
        let json = vol3_connections_json(&[make_conn()]);
        assert!(json.contains("\"Offset\""), "missing Offset: {json}");
        assert!(json.contains("\"Proto\""), "missing Proto: {json}");
        assert!(json.contains("\"ForeignAddr\""), "missing ForeignAddr: {json}");
        assert!(json.contains("\"ForeignPort\""), "missing ForeignPort: {json}");
        assert!(json.contains("\"LocalAddr\""), "missing LocalAddr: {json}");
        assert!(json.contains("\"State\""), "missing State: {json}");
    }
}
