"""Shared Windows plugin catalogue for compatibility and robustness tests.

105 Windows plugins total in vol3. ALL 105 are covered (100%).
Plugins requiring special CLI args (needs_args=True) are included in
robustness tests (crafted dumps cause graceful failure before arg parsing)
and compatibility tests verify graceful non-zero exit with no traceback.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Plugin:
    name: str
    needs_args: bool = False   # requires extra CLI args to produce output
    slow: bool = False          # may take >120s on a 2GB dump
    compat_timeout: int = 120   # subprocess timeout for compat tests


# Kernel VA used in robustness parametrize — any canonical Win10 x64 kernel address.
# On crafted dumps the walk fails regardless; value is just a test label.
ROBUSTNESS_VA: int = 0xFFFF_8000_0000_0000


def _p(name: str, *, needs_args: bool = False, slow: bool = False, t: int = 120) -> Plugin:
    return Plugin(name=name, needs_args=needs_args, slow=slow, compat_timeout=t)


# fmt: off
ALL_WINDOWS_PLUGINS: list[Plugin] = [
    # ── process & thread ──────────────────────────────────────────────────────
    _p("windows.pslist.PsList"),
    _p("windows.psscan.PsScan",              slow=True, t=300),
    _p("windows.pstree.PsTree"),
    _p("windows.psxview.PsXView",            slow=True, t=300),
    _p("windows.cmdline.CmdLine"),
    _p("windows.cmdscan.CmdScan"),
    _p("windows.envars.Envars"),
    _p("windows.sessions.Sessions"),
    _p("windows.joblinks.JobLinks"),
    _p("windows.debugregisters.DebugRegisters"),
    _p("windows.privileges.Privs"),
    _p("windows.getsids.GetSIDs"),
    _p("windows.getservicesids.GetServiceSIDs"),
    _p("windows.threads.Threads",            slow=True, t=300),
    _p("windows.thrdscan.ThrdScan",          slow=True, t=300),
    _p("windows.suspended_threads.SuspendedThreads"),
    _p("windows.suspicious_threads.SuspiciousThreads"),
    _p("windows.orphan_kernel_threads.Threads"),
    _p("windows.memmap.Memmap",              slow=True, t=600),
    # ── DLLs, modules, drivers ───────────────────────────────────────────────
    _p("windows.dlllist.DllList",            slow=True, t=600),
    _p("windows.ldrmodules.LdrModules",      slow=True, t=300),
    _p("windows.modules.Modules"),
    _p("windows.modscan.ModScan",            slow=True, t=300),
    _p("windows.unloadedmodules.UnloadedModules"),
    _p("windows.driverscan.DriverScan",      slow=True, t=300),
    _p("windows.driverirp.DriverIrp"),
    _p("windows.drivermodule.DriverModule"),
    _p("windows.verinfo.VerInfo",            slow=True, t=300),
    # ── handles, objects, pools ───────────────────────────────────────────────
    _p("windows.handles.Handles",            slow=True, t=600),
    _p("windows.mutantscan.MutantScan",      slow=True, t=300),
    _p("windows.symlinkscan.SymlinkScan",    slow=True, t=300),
    _p("windows.poolscanner.PoolScanner",    slow=True, t=300),
    _p("windows.bigpools.BigPools"),
    _p("windows.desktops.Desktops",          needs_args=True),  # vol3 renderer TypeError (null Desktop name) on raw .mem
    _p("windows.deskscan.DeskScan"),
    _p("windows.windows.Windows"),
    _p("windows.windowstations.WindowStations"),
    # ── network ───────────────────────────────────────────────────────────────
    _p("windows.netscan.NetScan"),
    _p("windows.netstat.NetStat"),
    # ── file system ───────────────────────────────────────────────────────────
    _p("windows.filescan.FileScan",          slow=True, t=300),
    _p("windows.mftscan.MFTScan",            slow=True, t=300),
    _p("windows.mftscan.ADS",               slow=True, t=300),
    _p("windows.mftscan.ResidentData",       slow=True, t=300),
    _p("windows.dumpfiles.DumpFiles",         needs_args=True),  # vol3 traceback without --dump-dir
    # ── kernel structures ─────────────────────────────────────────────────────
    _p("windows.ssdt.SSDT"),
    _p("windows.callbacks.Callbacks"),
    _p("windows.kpcrs.KPCRs"),
    _p("windows.timers.Timers"),
    _p("windows.devicetree.DeviceTree"),
    _p("windows.consoles.Consoles"),
    _p("windows.crashinfo.Crashinfo",         needs_args=True),  # requires Windows crash dump format, not raw .mem
    _p("windows.statistics.Statistics"),
    _p("windows.virtmap.VirtMap"),
    _p("windows.mbrscan.MBRScan"),
    _p("windows.shimcachemem.ShimcacheMem"),
    # ── VAD / virtual memory ──────────────────────────────────────────────────
    _p("windows.vadinfo.VadInfo",            slow=True, t=600),
    _p("windows.vadwalk.VadWalk",            slow=True, t=600),
    _p("windows.vadregexscan.VadRegExScan",  needs_args=True),
    _p("windows.vadyarascan.VadYaraScan",    needs_args=True),
    # ── malware detection ─────────────────────────────────────────────────────
    _p("windows.malfind.Malfind",            slow=True, t=300),
    _p("windows.hollowprocesses.HollowProcesses"),
    _p("windows.processghosting.ProcessGhosting"),
    _p("windows.etwpatch.EtwPatch"),
    _p("windows.skeleton_key_check.Skeleton_Key_Check"),
    _p("windows.svcdiff.SvcDiff"),
    _p("windows.direct_system_calls.DirectSystemCalls"),
    _p("windows.indirect_system_calls.IndirectSystemCalls"),
    _p("windows.unhooked_system_calls.unhooked_system_calls"),
    _p("windows.strings.Strings",            needs_args=True),
    _p("windows.pe_symbols.PESymbols",       needs_args=True),
    _p("windows.iat.IAT",                    needs_args=True),   # requires --base (PE base addr)
    _p("windows.pedump.PEDump",              needs_args=True),   # requires --base, writes files
    # ── malware.* aliases ─────────────────────────────────────────────────────
    _p("windows.malware.malfind.Malfind",    slow=True, t=300),
    _p("windows.malware.hollowprocesses.HollowProcesses"),
    _p("windows.malware.processghosting.ProcessGhosting"),
    _p("windows.malware.ldrmodules.LdrModules", slow=True, t=300),
    _p("windows.malware.pebmasquerade.PebMasquerade"),
    _p("windows.malware.psxview.PsXView",    slow=True, t=300),
    _p("windows.malware.svcdiff.SvcDiff"),
    _p("windows.malware.skeleton_key_check.Skeleton_Key_Check"),
    _p("windows.malware.drivermodule.DriverModule"),
    _p("windows.malware.suspicious_threads.SuspiciousThreads"),
    _p("windows.malware.direct_system_calls.DirectSystemCalls"),
    _p("windows.malware.indirect_system_calls.IndirectSystemCalls"),
    _p("windows.malware.unhooked_system_calls.UnhookedSystemCalls"),
    # ── credentials / hashes ─────────────────────────────────────────────────
    _p("windows.hashdump.Hashdump"),
    _p("windows.cachedump.Cachedump"),
    _p("windows.lsadump.Lsadump"),
    # ── registry ─────────────────────────────────────────────────────────────
    _p("windows.registry.hivelist.HiveList"),
    _p("windows.registry.hivescan.HiveScan"),
    _p("windows.registry.printkey.PrintKey", needs_args=True),
    _p("windows.registry.hashdump.Hashdump"),
    _p("windows.registry.cachedump.Cachedump"),
    _p("windows.registry.lsadump.Lsadump"),
    _p("windows.registry.amcache.Amcache"),
    _p("windows.registry.certificates.Certificates"),
    _p("windows.registry.getcellroutine.GetCellRoutine"),
    _p("windows.registry.scheduled_tasks.ScheduledTasks"),
    _p("windows.registry.userassist.UserAssist"),
    # ── services / tasks ─────────────────────────────────────────────────────
    _p("windows.svcscan.SvcScan"),
    _p("windows.svclist.SvcList"),
    _p("windows.scheduled_tasks.ScheduledTasks"),
    # ── info & misc ──────────────────────────────────────────────────────────
    _p("windows.info.Info"),
    _p("windows.amcache.Amcache"),
    _p("windows.truecrypt.Passphrase"),
    _p("windows.psxview.PsXView",            slow=True, t=300),
]
# fmt: on

# Deduplicate (psxview appears twice — once standalone, once in malware.*)
_seen: set[str] = set()
_deduped: list[Plugin] = []
for _p_item in ALL_WINDOWS_PLUGINS:
    if _p_item.name not in _seen:
        _seen.add(_p_item.name)
        _deduped.append(_p_item)
ALL_WINDOWS_PLUGINS = _deduped

# Plugins suitable for compatibility tests (no special args required)
STANDARD_PLUGINS: list[Plugin] = [p for p in ALL_WINDOWS_PLUGINS if not p.needs_args]
