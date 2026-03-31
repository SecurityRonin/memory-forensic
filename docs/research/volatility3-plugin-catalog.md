# Volatility 3 Complete Plugin Catalog (v2.28.0)

> Competitive analysis reference for building a memory forensics superset tool.
> Source: Volatility3 GitHub `develop` branch + ReadTheDocs v2.28.0 + community3 repo.
> Date compiled: 2026-04-01

---

## Table of Contents

1. [Core / OS-Agnostic Plugins](#1-core--os-agnostic-plugins)
2. [Windows Plugins](#2-windows-plugins)
3. [Linux Plugins](#3-linux-plugins)
4. [macOS Plugins](#4-macos-plugins)
5. [Community / Third-Party Plugins](#5-community--third-party-plugins)
6. [Volatility 2 Plugins NOT Ported to V3](#6-volatility-2-plugins-not-ported-to-v3)
7. [Gap Analysis Summary](#7-gap-analysis-summary)

---

## 1. Core / OS-Agnostic Plugins

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `banners.Banners` | Scans for OS version banners in memory | Raw byte scanning for known banner strings |
| `configwriter.ConfigWriter` | Outputs current plugin configuration | Framework config tree |
| `frameworkinfo.FrameworkInfo` | Displays framework version and info | Framework metadata |
| `isfinfo.IsfInfo` | Displays Intermediate Symbol Format file info | ISF JSON metadata |
| `layerwriter.LayerWriter` | Writes out a memory layer (raw dump extraction) | Translation layer stack |
| `regexscan.RegExScan` | Regex-based scanning across memory | Raw memory bytes |
| `timeliner.Timeliner` | Aggregates timestamps from all plugins into timeline | Calls `generate_timeline()` on all TimeLinerInterface plugins |
| `vmscan.VmScan` | Scans for virtual machine control structures | VM control structures |
| `yarascan.YaraScan` | YARA rule scanning across memory | Raw memory bytes, process address spaces |

---

## 2. Windows Plugins

### 2.1 Process Analysis

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `windows.pslist.PsList` | Lists active processes via linked list traversal | `_EPROCESS` doubly-linked list (ActiveProcessLinks) via `PsActiveProcessHead` |
| `windows.psscan.PsScan` | Pool-tag scanning for process objects (finds hidden/terminated) | `_EPROCESS` pool allocations, pool tag `Proc` |
| `windows.pstree.PsTree` | Displays process parent-child tree | `_EPROCESS.InheritedFromUniqueProcessId` |
| `windows.cmdline.CmdLine` | Lists command-line arguments per process | `_EPROCESS` -> `_PEB` -> `ProcessParameters` -> `CommandLine` (UNICODE_STRING) |
| `windows.envars.Envars` | Lists environment variables per process | `_EPROCESS` -> `_PEB` -> `ProcessParameters` -> `Environment` block |
| `windows.getsids.GetSIDs` | Lists process token SIDs | `_EPROCESS` -> `_TOKEN` -> SID array |
| `windows.privileges.Privs` | Lists process token privileges | `_EPROCESS` -> `_TOKEN` -> `_SEP_TOKEN_PRIVILEGES` |
| `windows.sessions.Sessions` | Lists logon sessions | `_MM_SESSION_SPACE`, `_EPROCESS.Session` |
| `windows.handles.Handles` | Lists open handles per process | `_EPROCESS` -> `ObjectTable` -> `_HANDLE_TABLE` -> `_HANDLE_TABLE_ENTRY` |
| `windows.joblinks.JobLinks` | Lists process job object relationships | `_EPROCESS` -> `_EJOB` linked list |
| `windows.memmap.Memmap` | Lists process virtual-to-physical memory mappings | Page tables, `_EPROCESS` -> `DirectoryTableBase` |
| `windows.kpcrs.KPCRs` | Lists Kernel Processor Control Regions | `_KPCR` structures per CPU |
| `windows.debugregisters.DebugRegisters` | Shows debug register values | `_KTHREAD` -> debug registers (DR0-DR7) |
| `windows.psxview.PsXView` | Cross-references multiple process enumeration methods | `_EPROCESS` list, pool scan, session list, CSRSS handles, PspCidTable |

### 2.2 DLL / Module Analysis

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `windows.dlllist.DllList` | Lists loaded DLLs per process | `_EPROCESS` -> `_PEB` -> `_PEB_LDR_DATA` -> `InLoadOrderModuleList` (`_LDR_DATA_TABLE_ENTRY`) |
| `windows.ldrmodules.LdrModules` | Cross-references PEB loader lists with VADs | `_PEB_LDR_DATA` (InLoad, InInit, InMem order lists) vs `_MMVAD` tree |
| `windows.modules.Modules` | Lists loaded kernel modules | `_KLDR_DATA_TABLE_ENTRY` from `PsLoadedModuleList` |
| `windows.modscan.ModScan` | Scans for kernel module objects (finds unlinked) | `_LDR_DATA_TABLE_ENTRY` pool allocations |
| `windows.unloadedmodules.UnloadedModules` | Lists recently unloaded kernel modules | `MmUnloadedDrivers` array |
| `windows.verinfo.VerInfo` | Extracts PE version information from loaded modules | PE `VS_VERSION_INFO` resource |
| `windows.pe_symbols.PESymbols` | Extracts PE export symbols | PE export directory table |
| `windows.pedump.PEDump` | Dumps PE files from process memory | PE headers, section table |
| `windows.iat.IAT` | Lists Import Address Table entries | PE IAT/IDT structures |

### 2.3 Thread Analysis

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `windows.thrdscan.ThrdScan` | Scans for thread objects in memory | `_ETHREAD` pool allocations, pool tag `Thrd` |
| `windows.threads.Threads` | Lists threads per process | `_EPROCESS` -> `ThreadListHead` -> `_ETHREAD` |
| `windows.suspicious_threads.SuspiciousThreads` | Detects threads with suspicious characteristics | `_ETHREAD` -> `StartAddress`, `Win32StartAddress`, `_MMVAD` |
| `windows.suspended_threads.SuspendedThreads` | Lists suspended threads (may indicate injection) | `_KTHREAD.SuspendCount`, `_KTHREAD.State` |
| `windows.orphan_kernel_threads.OrphanKernelThreads` | Finds kernel threads not backed by a module | `_ETHREAD.StartAddress` vs module ranges |

### 2.4 Memory / VAD Analysis

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `windows.vadinfo.VadInfo` | Displays detailed VAD information per process | `_EPROCESS` -> `VadRoot` -> `_MMVAD` / `_MMVAD_SHORT` balanced tree |
| `windows.vadwalk.VadWalk` | Walks the VAD tree showing all entries | `_MMVAD` AVL tree traversal |
| `windows.malfind.Malfind` | Detects injected/suspicious code (RWX pages, PE headers in non-image VADs) | `_MMVAD` -> Protection flags, `_MMVAD.FirstPrototypePte`, memory content scanning |
| `windows.vadyarascan.VadYaraScan` | YARA scanning within process VADs | `_MMVAD` address ranges |
| `windows.vadregexscan.VadRegexScan` | Regex scanning within process VADs | `_MMVAD` address ranges |

### 2.5 Malware Detection (windows.malware.*)

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `windows.malware.malfind.Malfind` | (Relocated) Detects injected code in process memory | `_MMVAD` protection, PE headers in anonymous regions |
| `windows.malware.hollowprocesses.HollowProcesses` | Detects process hollowing (PE header mismatches) | `_MMVAD` -> mapped file vs actual PE in memory |
| `windows.malware.processghosting.ProcessGhosting` | Detects process ghosting technique | `_EPROCESS` -> `_FILE_OBJECT` -> `DeletePending`/`DeleteAccess` flags |
| `windows.malware.ldrmodules.LdrModules` | (Relocated) Cross-references PEB loader lists with VADs | `_PEB_LDR_DATA` 3x module lists vs `_MMVAD` |
| `windows.malware.psxview.PsXView` | (Relocated) Cross-references multiple process lists | Multiple enumeration sources |
| `windows.malware.direct_system_calls.DirectSystemCalls` | Detects direct syscall stubs in non-ntdll memory | `_MMVAD` + syscall instruction pattern scanning |
| `windows.malware.indirect_system_calls.IndirectSystemCalls` | Detects indirect syscall trampolines | JMP-to-syscall pattern scanning in non-standard regions |
| `windows.malware.unhooked_system_calls.UnhookedSystemCalls` | Finds syscalls bypassing EDR hooks | Compares ntdll on-disk vs in-memory for detoured functions |
| `windows.malware.drivermodule.DriverModule` | Compares driver objects to loaded modules | `_DRIVER_OBJECT.DriverStart` vs `_KLDR_DATA_TABLE_ENTRY` ranges |
| `windows.malware.skeleton_key_check.SkeletonKeyCheck` | Detects Skeleton Key (Mimikatz) in LSASS | Pattern scanning in lsass.exe memory for known patches |
| `windows.malware.suspicious_threads.SuspiciousThreads` | (Relocated) Threads with anomalous start addresses | `_ETHREAD` start vs module ranges |
| `windows.malware.svcdiff.SvcDiff` | Compares service registry entries to in-memory services | Registry `HKLM\SYSTEM\...\Services` vs `_SERVICE_RECORD` |
| `windows.malware.pebmasquerade.PEBMasquerade` | Detects PEB masquerading (process name spoofing) | `_PEB` -> `ProcessParameters.ImagePathName` vs `_EPROCESS.ImageFileName` |

### 2.6 Kernel / Driver Analysis

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `windows.ssdt.SSDT` | Lists System Service Descriptor Table entries | `KeServiceDescriptorTable`, `KeServiceDescriptorTableShadow` |
| `windows.callbacks.Callbacks` | Lists kernel notification callbacks | `PsSetCreateProcessNotifyRoutine`, `PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine`, `CmRegisterCallback`, shutdown callbacks, bugcheck callbacks, filesystem notification |
| `windows.driverscan.DriverScan` | Scans for driver objects | `_DRIVER_OBJECT` pool allocations, pool tag `Driv` |
| `windows.driverirp.DriverIrp` | Lists IRP Major Function handlers per driver | `_DRIVER_OBJECT` -> `MajorFunction[]` array (IRP_MJ_*) |
| `windows.devicetree.DeviceTree` | Shows device object hierarchy | `_DRIVER_OBJECT` -> `DeviceObject` -> `AttachedDevice` chain |
| `windows.timers.Timers` | Lists kernel timers | `_KTIMER` structures via `KiTimerTableListHead` |
| `windows.etwpatch.ETWPatch` | Detects ETW (Event Tracing for Windows) patching/tampering | ETW provider structures, `EtwpEventWriteFull` patches |

### 2.7 Network Analysis

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `windows.netscan.NetScan` | Scans for network connection objects | Pool tag scanning for `TcpL` (TCP listener), `TcpE` (TCP endpoint), `UdpA` (UDP endpoint) -> `_TCP_LISTENER`, `_TCP_ENDPOINT`, `_UDP_ENDPOINT` |
| `windows.netstat.NetStat` | Lists active network connections via kernel structures | `tcpip.sys` -> `PartitionTable` -> `_TCB_TABLE` -> connection entries |

### 2.8 File System Artifacts

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `windows.filescan.FileScan` | Scans for file objects in memory | `_FILE_OBJECT` pool allocations, pool tag `Fil\xe5` |
| `windows.dumpfiles.DumpFiles` | Extracts files from memory (via file objects or VADs) | `_FILE_OBJECT` -> `_SECTION_OBJECT_POINTERS` -> `DataSectionObject`/`ImageSectionObject`/`SharedCacheMap` |
| `windows.mftscan.MFTScan` | Scans for MFT (Master File Table) entries | NTFS `_MFT_ENTRY` (FILE0 signature), `$STANDARD_INFORMATION`, `$FILE_NAME`, `$DATA` attributes |
| `windows.symlinkscan.SymlinkScan` | Scans for symbolic link objects | `_OBJECT_SYMBOLIC_LINK` pool allocations |
| `windows.mutantscan.MutantScan` | Scans for mutex/mutant objects | `_KMUTANT` pool allocations, pool tag `Muta` |

### 2.9 Registry Analysis

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `windows.registry.hivelist.HiveList` | Lists loaded registry hives | `_CMHIVE` linked list via `CmpHiveListHead` |
| `windows.registry.hivescan.HiveScan` | Scans for registry hive objects | `_CMHIVE` pool allocations, `regf` signature |
| `windows.registry.printkey.PrintKey` | Prints registry key values | `_CM_KEY_NODE` -> `_CM_KEY_VALUE` cells |
| `windows.registry.userassist.UserAssist` | Parses UserAssist (program execution tracking) | `NTUSER.DAT` -> `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` -> ROT13 encoded entries |
| `windows.registry.amcache.Amcache` | Parses Amcache.hve (application compatibility cache) | `Amcache.hve` -> `Root\InventoryApplicationFile` and `Root\File` keys |
| `windows.registry.getcellroutine.GetCellRoutine` | Checks for hooked registry GetCellRoutine | `_CMHIVE.GetCellRoutine` function pointer |
| `windows.registry.hashdump.Hashdump` | Dumps NTLM hashes from SAM | `SAM` hive -> `SAM\Domains\Account\Users` + `SYSTEM` hive bootkey |
| `windows.registry.lsadump.Lsadump` | Dumps LSA secrets | `SECURITY` hive -> `Policy\Secrets` + `SYSTEM` hive bootkey |
| `windows.registry.cachedump.Cachedump` | Dumps cached domain credentials | `SECURITY` hive -> `Cache\NL$n` entries |
| `windows.registry.scheduled_tasks.ScheduledTasks` | Extracts scheduled tasks from registry | `SOFTWARE` hive -> `Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache` |
| `windows.shimcachemem.ShimcacheMem` | Extracts Shimcache (Application Compatibility Cache) from memory | In-memory `SHIM_CACHE_ENTRY` structures (not registry-based) |

### 2.10 Service Analysis

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `windows.svcscan.SvcScan` | Scans for Windows service records | `_SERVICE_RECORD` structures in services.exe memory |
| `windows.svclist.SvcList` | Lists services via service database | `_SERVICE_RECORD` linked list |
| `windows.svcdiff.SvcDiff` | Compares in-memory services vs registry | `_SERVICE_RECORD` vs `HKLM\SYSTEM\...\Services` registry keys |
| `windows.getservicesids.GetServiceSIDs` | Lists service SIDs | Service name -> SID computation |

### 2.11 GUI / Desktop Analysis

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `windows.deskscan.DeskScan` | Scans for desktop objects | `tagDESKTOP` structures in `win32k.sys` session space |
| `windows.desktops.Desktops` | Lists desktop objects and their attributes | `tagDESKTOP` -> heap, hooks, threads |
| `windows.windowstations.WindowStations` | Lists window station objects | `tagWINDOWSTATION` structures |
| `windows.windows.Windows` | Lists window objects (HWNDs) | `tagWND` structures in desktop heap |

### 2.12 Credential Recovery

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `windows.hashdump.Hashdump` | Dumps NTLM password hashes | SAM + SYSTEM registry hives |
| `windows.lsadump.Lsadump` | Dumps LSA secrets (service account passwords, etc.) | SECURITY + SYSTEM registry hives |
| `windows.cachedump.Cachedump` | Dumps cached domain logon credentials | SECURITY hive `NL$` entries |

### 2.13 Miscellaneous Windows

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `windows.info.Info` | Shows OS version, build, kernel base, etc. | `_KDDEBUGGER_DATA64`, `_DBGKD_GET_VERSION64` |
| `windows.crashinfo.Crashinfo` | Parses crash dump header information | `_DUMP_HEADER` / `_DUMP_HEADER64` |
| `windows.bigpools.BigPools` | Lists big page pool allocations | `nt!PoolBigPageTable` -> `_POOL_TRACKER_BIG_PAGES` |
| `windows.poolscanner.PoolScanner` | Generic pool tag scanner framework | Pool headers + pool tags |
| `windows.strings.Strings` | Maps strings output back to owning processes | `_EPROCESS` address space + physical offsets |
| `windows.virtmap.VirtMap` | Lists virtual address map for the kernel | Kernel page tables |
| `windows.mbrscan.MBRScan` | Scans for MBR structures | Master Boot Record (sector 0) patterns |
| `windows.cmdscan.CmdScan` | Scans for command history buffers (cmd.exe) | `_COMMAND_HISTORY` structures in conhost.exe |
| `windows.consoles.Consoles` | Scans for console information and screen buffers | `_CONSOLE_INFORMATION` structures in conhost.exe |
| `windows.truecrypt.TrueCrypt` | Scans for TrueCrypt encryption keys | TrueCrypt volume header patterns in memory |
| `windows.scheduled_tasks.ScheduledTasks` | Lists scheduled tasks from memory | Task Scheduler data structures |
| `windows.amcache.Amcache` | Parses Amcache application execution records | Amcache.hve registry hive |

---

## 3. Linux Plugins

### 3.1 Process Analysis

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `linux.pslist.PsList` | Lists active processes | `task_struct` linked list via `init_task.tasks` |
| `linux.psscan.PsScan` | Scans for process structures (finds hidden/terminated) | `task_struct` pattern scanning |
| `linux.pstree.PsTree` | Displays process parent-child tree | `task_struct.parent`, `task_struct.children` |
| `linux.psaux.PsAux` | Lists processes with command-line arguments (ps aux) | `task_struct` -> `mm_struct` -> `arg_start`/`arg_end` |
| `linux.pscallstack.PsCallStack` | Shows per-process kernel call stacks | `task_struct.stack` -> stack frames |
| `linux.kthreads.Kthreads` | Lists kernel threads | `task_struct` with `mm == NULL` |
| `linux.pidhashtable.PIDHashTable` | Enumerates processes via PID hash table | `pid_hash[]` -> `upid` -> `task_struct` |
| `linux.ptrace.Ptrace` | Lists ptrace relationships (debugger/debuggee) | `task_struct.ptrace`, `task_struct.ptraced` list |
| `linux.capabilities.Capabilities` | Lists process capabilities | `task_struct` -> `cred` -> `cap_effective`, `cap_permitted`, `cap_inheritable` |

### 3.2 Memory Analysis

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `linux.proc.Maps` (proc_maps) | Lists process memory mappings | `task_struct` -> `mm_struct` -> `vm_area_struct` linked list/maple tree |
| `linux.elfs.Elfs` | Lists ELF files mapped in process memory | `vm_area_struct` -> ELF header detection |
| `linux.malfind.Malfind` | Detects injected/suspicious code regions | `vm_area_struct` flags (VM_EXEC + VM_WRITE), anonymous RWX |
| `linux.vmaregexscan.VmaRegexScan` | Regex scanning in VMA regions | `vm_area_struct` address ranges |
| `linux.vmayarascan.VmaYaraScan` | YARA scanning in VMA regions | `vm_area_struct` address ranges |
| `linux.pagecache.PageCache` | Extracts page cache contents | `address_space` -> radix tree / xarray of `struct page` |

### 3.3 Kernel Module Analysis

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `linux.lsmod.Lsmod` | Lists loaded kernel modules | `modules` list -> `struct module` linked list |
| `linux.hidden_modules.Hidden_modules` | Detects hidden kernel modules | `modules` list vs `kobject` tree vs section mappings |
| `linux.modxview.Modxview` | Cross-references multiple module enumeration methods | Multiple module lists comparison |
| `linux.module_extract.ModuleExtract` | Extracts kernel module binaries from memory | `struct module` -> core/init sections |
| `linux.kallsyms.Kallsyms` | Recovers kernel symbol table from memory | `kallsyms_*` tables |

### 3.4 Rootkit / Malware Detection (linux.malware.*)

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `linux.malware.check_syscall.Check_syscall` | Checks syscall table for hooks | `sys_call_table[]` entries vs kernel text range |
| `linux.malware.check_idt.Check_idt` | Checks IDT entries for hooks | Interrupt Descriptor Table (`idt_table[]`) |
| `linux.malware.check_afinfo.Check_afinfo` | Checks network protocol `*_afinfo` for hooks | `tcp4_seq_afinfo`, `udp_seq_afinfo` function pointers |
| `linux.malware.check_modules.Check_modules` | Compares `modules` list vs `sysfs` | `struct module` list vs `/sys/module` kobject tree |
| `linux.malware.check_creds.Check_creds` | Checks for shared credential structures | `task_struct.cred` reference counting anomalies |
| `linux.malware.hidden_modules.Hidden_modules` | (Relocated) Detects hidden kernel modules | Multiple module enumeration comparison |
| `linux.malware.keyboard_notifiers.Keyboard_notifiers` | Checks keyboard notifier callbacks (keylogger detection) | `keyboard_notifier_list` -> callback addresses |
| `linux.malware.malfind.Malfind` | (Relocated) Suspicious memory regions | `vm_area_struct` analysis |
| `linux.malware.modxview.Modxview` | (Relocated) Module cross-view detection | Multiple module lists |
| `linux.malware.netfilter.Netfilter` | Checks netfilter hooks | `nf_hook_entries` per protocol/hook point |
| `linux.malware.tty_check.tty_check` | Checks for hooked TTY operations | `tty_struct` -> `tty_operations` function pointers |
| `linux.malware.process_spoofing.ProcessSpoofing` | Detects process name/argument spoofing | `task_struct.comm` vs actual argv |

### 3.5 Network Analysis

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `linux.sockstat.Sockstat` | Lists socket information per process | `task_struct` -> `files_struct` -> `socket` -> `sock` |
| `linux.sockscan.SockScan` | Scans for socket structures | `struct sock` pattern scanning |
| `linux.ip.IP` | Lists IP routing and interface information | `net_device`, routing tables |
| `linux.netfilter.Netfilter` | Lists netfilter hooks and rules | `nf_hook_entries`, `xt_table` |

### 3.6 Shell / User Activity

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `linux.bash.Bash` | Recovers bash command history from process memory | bash `history_list` -> `HIST_ENTRY` structures |
| `linux.envars.Envars` | Lists process environment variables | `task_struct` -> `mm_struct` -> `env_start`/`env_end` |
| `linux.tty_check.tty_check` | Checks TTY device hooks | `tty_struct` -> `tty_operations` |

### 3.7 File System

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `linux.lsof.Lsof` | Lists open file descriptors per process | `task_struct` -> `files_struct` -> `fdtable` -> `file` -> `dentry` -> `inode` |
| `linux.mountinfo.MountInfo` | Lists mount points | `mount` structures, `mnt_namespace` |
| `linux.iomem.IOMem` | Lists IO memory regions | `resource` tree (`iomem_resource`) |

### 3.8 Kernel Internals

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `linux.kmsg.Kmsg` | Reads kernel message buffer (dmesg) | `log_buf` / `printk_ringbuffer` (varies by kernel version) |
| `linux.boottime.Boottime` | Shows system boot time | `timekeeper` structure |
| `linux.vmcoreinfo.VMCoreInfo` | Dumps vmcoreinfo metadata | `vmcoreinfo_data` |
| `linux.library_list.LibraryList` | Lists shared libraries loaded per process | `link_map` structures via `r_debug` |
| `linux.ebpf.EBPF` | Enumerates loaded eBPF programs (rootkit detection) | `bpf_prog_aux` -> `bpf_prog` structures |

### 3.9 Kernel Tracing

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `linux.tracing.ftrace.Ftrace` | Detects ftrace function hooks | `ftrace_ops_list`, function trace hooks |
| `linux.tracing.perf_events.PerfEvents` | Lists perf event subscriptions | `perf_event` structures |
| `linux.tracing.tracepoints.Tracepoints` | Lists active tracepoints | `tracepoint` structures, `__tracepoint_*` |

### 3.10 Graphics

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `linux.graphics.fbdev.Fbdev` | Extracts framebuffer device contents (screenshots) | `fb_info` -> `struct fb_fix_screeninfo`, `struct fb_var_screeninfo` |

---

## 4. macOS Plugins

### 4.1 Process Analysis

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `mac.pslist.PsList` | Lists active processes | `proc` structure linked list via `allproc` |
| `mac.pstree.PsTree` | Displays process tree | `proc.p_pptr` parent pointers |
| `mac.psaux.PsAux` | Lists processes with arguments | `proc` -> argument area |
| `mac.bash.Bash` | Recovers bash command history | bash `history_list` in process memory |
| `mac.lsof.Lsof` | Lists open files per process | `proc` -> `filedesc` -> `fileproc` -> `vnode` |

### 4.2 Kernel Analysis

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `mac.lsmod.Lsmod` | Lists loaded kernel extensions (kexts) | `kmod_info_t` linked list |
| `mac.check_syscall.Check_syscall` | Checks for syscall table hooks | `sysent[]` entries vs kernel text |
| `mac.check_sysctl.Check_sysctl` | Checks for sysctl hook functions | `sysctl_oid_list` -> handler function pointers |
| `mac.check_trap_table.Check_trap_table` | Checks Mach trap table for hooks | `mach_trap_table[]` entries |
| `mac.kauth_listeners.Kauth_listeners` | Lists Kauth (Kernel Authorization) listener callbacks | `kauth_scope` -> `kauth_listener` |
| `mac.kauth_scopes.Kauth_scopes` | Lists registered Kauth scopes | `kauth_scope` structures |
| `mac.trustedbsd.Trustedbsd` | Lists TrustedBSD MAC policy modules | MAC framework policy list |
| `mac.dmesg.Dmesg` | Reads kernel message buffer | `msgbufp` -> `msgbuf` |

### 4.3 Network

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `mac.ifconfig.Ifconfig` | Lists network interfaces | `ifnet` structures via `ifnet_head` |
| `mac.netstat.Netstat` | Lists active network connections | `inpcb` (Internet Protocol Control Block) hash tables |
| `mac.socket_filters.Socket_filters` | Lists socket filter hooks | `socket` -> `so_filt` -> `sflt_filter` |

### 4.4 File System

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `mac.mount.Mount` | Lists mounted file systems | `mount` structures via `mountlist` |
| `mac.list_files.List_Files` | Lists cached files from vnode cache | `vnode` structures, name cache |
| `mac.vfsevents.VfsEvents` | Lists VFS event watchers (e.g., fsevents) | `fsevent_handle` structures |
| `mac.proc_maps.Proc_Maps` | Lists process memory mappings | `proc` -> `task` -> `vm_map` -> `vm_map_entry` |

### 4.5 Timers and Events

| Plugin | Description | Data Structures |
|--------|-------------|-----------------|
| `mac.timers.Timers` | Lists kernel call-out timers | `callout_queue` / `thread_call_*` |
| `mac.kevents.Kevents` | Lists kernel event subscriptions per process | `kqueue` -> `knote` structures |
| `mac.malfind.Malfind` | Detects injected code in process memory | `vm_map_entry` permissions analysis |

---

## 5. Community / Third-Party Plugins

> Source: `volatilityfoundation/community3` repo, plugin contests, and notable independent repos.

### 5.1 Credential Recovery

| Plugin | Author/Source | Description |
|--------|--------------|-------------|
| `pypykatz` | SkelSec | Mimikatz-equivalent: extracts NTLM hashes, Kerberos tickets, DPAPI keys from LSASS memory |
| `openssh_session_keys` | Community3 | Recovers OpenSSH session encryption keys for SSH traffic decryption |
| `keepass` | forensicxlab | KeePass master password recovery (CVE-2023-32784) |
| `filevault2` | Community3 | Apple FileVault 2 Volume Master Key extraction |
| `keychaindump` | Vol2 only | macOS keychain password extraction (NOT ported to V3) |

### 5.2 Malware / EDR Analysis

| Plugin | Author/Source | Description |
|--------|--------------|-------------|
| `imgmalfind` | Community3 | Reveals modifications to mapped PE image files (section tampering) |
| `autoruns` | Community3 (tomchop port) | Enumerates persistence mechanisms (ASEPs) |
| `hollowfind` | Community3 | Advanced process hollowing detection |
| `procinjectfind` | Community3 | Examines each memory region for injection indicators |
| `masqueradeprocess` | Community3 | Compares PE OriginalFileName vs running process name |
| `directsyscalls` | Community3 | Syscall stub detection in shellcode memory |
| `apihash` | Community3 | Scans for API hash resolution patterns in suspicious memory |
| `packerlist` | Community3 | Detects indicators of packed processes |
| `edrity` | Community3 | Live-system basic EDR capabilities via Volatility |

### 5.3 Artifact Recovery

| Plugin | Author/Source | Description |
|--------|--------------|-------------|
| `prefetch` | forensicxlab | Extracts and parses Windows Prefetch files from memory (XP-Win11) |
| `anydesk` | forensicxlab | Extracts AnyDesk trace files from memory |
| `evtx` | Community3 | Extracts Windows Event Log (evtx) entries from physical memory |
| `dnscache` | Community3 | Extracts Windows DNS resolver cache |
| `ads` | forensicxlab | Alternate Data Stream detection from MFT entries in memory |
| `inodes` | forensicxlab | Extended inode metadata from Linux file descriptors |

### 5.4 Container / Cloud

| Plugin | Author/Source | Description |
|--------|--------------|-------------|
| `volatility-docker` | Community3 | Docker container forensics from memory |
| `cloud_storage_layer` | Community3 | Analyze memory images directly from S3/GCS buckets |

### 5.5 GUI / Visualization

| Plugin | Author/Source | Description |
|--------|--------------|-------------|
| `volatility_explorer` | Community3 | GUI like Process Explorer but from memory dumps |
| `struct_analyzer` | Community3 | Graphical kernel structure viewer |
| `winobjgui` | Community3 | WinObj-style kernel object browser |
| `filescan_gui` | Community3 | Windows Explorer-style file browser from memory |

### 5.6 Memory Layer Extensions

| Plugin | Author/Source | Description |
|--------|--------------|-------------|
| `hibernation_layer` | Community3 | hiberfile.sys conversion/support for V3 |
| `apisearch` | Community3 | Identifies pointers to DLL-exported APIs in process memory |

---

## 6. Volatility 2 Plugins NOT Ported to V3

These are significant capabilities present in Volatility 2 that have NO equivalent in Volatility 3 as of v2.28.0.

### 6.1 Windows (Vol2-only)

| Vol2 Plugin | Description | Impact |
|-------------|-------------|--------|
| `apihooks` | Detects inline API hooks (IAT, EAT, inline) | **HIGH** - Critical for rootkit/malware detection |
| `atoms` / `atomscan` | Lists global atom table entries | MEDIUM - Used for DDE/clipboard forensics |
| `clipboard` | Extracts clipboard contents | MEDIUM - Useful for user activity reconstruction |
| `editbox` | Extracts text from Windows edit controls | LOW-MEDIUM - Niche but useful |
| `eventhooks` | Lists SetWinEventHook entries | MEDIUM - Malware hook detection |
| `gahti` | Lists USER handle type information | LOW |
| `gditimers` | Lists GDI timer callbacks | MEDIUM - Malware persistence vector |
| `messagehooks` | Lists SetWindowsHookEx hooks | **HIGH** - Keylogger/malware detection |
| `screenshot` | Captures desktop screenshot from memory | **HIGH** - Visual evidence |
| `userhandles` | Lists per-process USER object handles | LOW-MEDIUM |
| `bioskbd` | Reads BIOS keyboard buffer | LOW - Pre-boot password recovery |
| `connections` / `connscan` | XP/2003 network connection structures | LOW - Legacy OS only |
| `dlldump` | Dumps DLL from process memory | **HIGH** - Now partially covered by pedump |
| `dumpcerts` | Extracts X.509 certificates | MEDIUM |
| `evtlogs` | Parses legacy .evt event logs | LOW - Legacy (pre-Vista) |
| `heaps` | Lists process heap allocations | MEDIUM - Advanced malware analysis |
| `hibinfo` | Hibernation file metadata | LOW |
| `iehistory` | Internet Explorer browsing history | MEDIUM - Legacy browser forensics |
| `imagecopy` / `imageinfo` | Memory image metadata/conversion | LOW - Replaced by info + layerwriter |
| `kdbgscan` | Scans for KDBG structures | LOW - Replaced by banners/automagic |
| `multiscan` | Combined pool-tag scan | LOW - Replaced by poolscanner |
| `notepad` | Extracts Notepad.exe contents | MEDIUM - User activity |
| `objtypescan` | Scans for OBJECT_TYPE structures | LOW |
| `patcher` | Patches memory (live modification) | LOW - Offensive, not forensic |
| `patchguard` | PatchGuard analysis | MEDIUM |
| `pooltracker` | Pool usage statistics | LOW |
| `procdump` | Dumps process executable | MEDIUM - Partially covered by pedump |
| `raw2dmp` | Converts raw to crash dump format | LOW |
| `sockets` / `sockscan` | XP/2003 socket structures | LOW - Legacy |
| `tcaudit` | Audit file cache | LOW |
| `impscan` | Scans for imported functions | MEDIUM - Partially covered by iat |
| `shellbags` | Registry shellbags (folder view settings with timestamps) | **HIGH** - Key forensic artifact |
| `shimcache` | Application compatibility cache from registry | **HIGH** - Key forensic artifact (Note: shimcachemem exists but parses memory, not registry) |
| `shutdown` | Last shutdown time from registry | LOW-MEDIUM |
| `auditpol` | Audit policy from registry | LOW |
| `vboxinfo` / `vmwareinfo` | VM metadata extraction | LOW-MEDIUM |
| `win10cookie` | Windows 10 cookie extraction | LOW |
| `volshell` | Interactive Python shell for memory analysis | MEDIUM - Interactive analysis |

### 6.2 Linux (Vol2-only)

| Vol2 Plugin | Description | Impact |
|-------------|-------------|--------|
| `apihooks` | Detects inline function hooks | **HIGH** |
| `arp` | ARP cache table | MEDIUM |
| `bash_hash` | Bash hash table (path cache) | LOW-MEDIUM |
| `check_evt_arm` | ARM event handler checks | LOW - Architecture specific |
| `check_fops` | Checks file operation hooks | **HIGH** - Rootkit detection |
| `check_inline_kernel` | Checks for inline kernel code patches | **HIGH** - Rootkit detection |
| `check_syscall_arm` | ARM syscall table check | LOW - Architecture specific |
| `cpuinfo` | CPU information | LOW |
| `dentry_cache` | Dentry cache enumeration | MEDIUM |
| `dmesg` | Kernel messages (now exists as kmsg) | Ported (as kmsg) |
| `dump_map` | Dumps process memory maps | MEDIUM - Partially covered |
| `enumerate_files` | Enumerates cached files | MEDIUM |
| `find_file` | Finds files in memory | MEDIUM |
| `flags` | Process flags | LOW |
| `getcwd` | Current working directory per process | MEDIUM |
| `ifconfig` | Network interface configuration | MEDIUM (exists in mac, not linux v3) |
| `info_regs` | CPU register state | MEDIUM |
| `kernel_opened_files` | Kernel-opened files | MEDIUM |
| `ld_env` | LD_PRELOAD environment variable check | **HIGH** - Rootkit detection |
| `ldrmodules` | Cross-references module lists | MEDIUM |
| `libc_env` | libc environment inspection | MEDIUM |
| `librarydump` | Dumps shared libraries from memory | MEDIUM |
| `lime` | LiME format support | LOW |
| `linux_strings` | Memory strings | LOW - Covered by yarascan/regexscan |
| `linux_truecrypt` | TrueCrypt key recovery | LOW-MEDIUM |
| `linux_volshell` | Interactive shell | MEDIUM |
| `list_raw` | Raw socket listing | LOW-MEDIUM |
| `mount_cache` | Mount cache entries | LOW |
| `netscan` / `netstat` | Network connections | MEDIUM - Partially covered by sockstat/sockscan |
| `pkt_queues` | Packet queue analysis | MEDIUM |
| `plthook` | PLT (Procedure Linkage Table) hook detection | **HIGH** - Rootkit detection |
| `proc_maps_rb` | Process maps via red-black tree | LOW - Merged into proc.Maps |
| `procdump` | Dumps process memory | MEDIUM |
| `process_hollow` | Process hollowing detection | MEDIUM |
| `process_info` | Detailed process info | LOW |
| `process_stack` | Process stack analysis | MEDIUM |
| `psenv` | Process environment (detailed) | LOW - Covered by envars |
| `pslist_cache` | Process list from dcache | MEDIUM |
| `psxview` | Cross-reference process views | MEDIUM |
| `recover_filesystem` | Recovers filesystem from memory | **HIGH** |
| `route_cache` | Routing cache | LOW-MEDIUM |
| `sk_buff_cache` | Socket buffer cache analysis | MEDIUM |
| `slab_info` | SLAB allocator information | MEDIUM |
| `threads` | Thread listing | MEDIUM |
| `tmpfs` | tmpfs file recovery | **HIGH** |
| `vma_cache` | VMA cache analysis | LOW |

### 6.3 macOS (Vol2-only)

| Vol2 Plugin | Description | Impact |
|-------------|-------------|--------|
| `adiummsgs` | Adium chat messages | LOW - Obsolete app |
| `apihooks` / `apihooks_kernel` | User/kernel API hook detection | **HIGH** |
| `arp` | ARP cache | MEDIUM |
| `bash_env` / `bash_hash` | Bash environment and hash table | LOW-MEDIUM |
| `calendar` | Calendar.app events | LOW-MEDIUM |
| `check_fop` | File operation hook detection | **HIGH** |
| `check_mig_table` | Mach MIG table integrity check | **HIGH** |
| `check_syscall_shadow` | Shadow syscall table check | **HIGH** |
| `compressed_swap` | Compressed swap analysis | MEDIUM |
| `contacts` | Contacts.app data | LOW-MEDIUM |
| `dead_procs` / `dead_sockets` / `dead_vnodes` | Dead/freed structure recovery | MEDIUM |
| `devfs` | Device filesystem analysis | LOW-MEDIUM |
| `dlyd_maps` | dyld (dynamic linker) maps | MEDIUM |
| `dump_files` / `dump_map` | File/memory dumping | MEDIUM |
| `gkextmap` | Gatekeeper kext mapping | MEDIUM |
| `interest_handlers` | IOKit interest handler hooks | MEDIUM |
| `ip_filters` | IP filter hooks | **HIGH** |
| `keychaindump` | Keychain password extraction | **HIGH** |
| `ldrmodules` | Library cross-reference | MEDIUM |
| `librarydump` | Library binary extraction | MEDIUM |
| `list_zones` | Mach zone allocator info | MEDIUM |
| `lsmod_iokit` | IOKit kext listing | MEDIUM |
| `machine_info` | Machine/hardware info | LOW |
| `memdump` / `moddump` / `procdump` | Memory/module/process dumping | MEDIUM |
| `netconns` | Network connections (alternative) | LOW |
| `notesapp` | Notes.app data | LOW-MEDIUM |
| `notifiers` | IOKit notifier callbacks | MEDIUM |
| `orphan_threads` | Orphaned thread detection | MEDIUM |
| `pgrp_hash_table` / `pid_hash_table` / `session_hash_table` | Hash table process enumeration | MEDIUM |
| `print_boot_cmdline` | Boot command-line arguments | LOW |
| `psenv` / `pstasks` | Process environment/Mach tasks | MEDIUM |
| `psxview` | Cross-reference process enumeration | MEDIUM |
| `recover_filesystem` | Filesystem recovery from memory | **HIGH** |
| `route` | Routing table | LOW-MEDIUM |
| `threads` / `threads_simple` | Thread analysis | MEDIUM |
| `version` | OS version info | LOW |

---

## 7. Gap Analysis Summary

### 7.1 Critical V2 Capabilities Missing from V3

These represent the highest-priority gaps for a superset tool:

1. **API Hook Detection** (Windows/Linux/Mac `apihooks`) - Inline, IAT, EAT hook detection
2. **Shellbags** (Windows `shellbags`) - Folder access timestamps
3. **Shimcache from Registry** (Windows `shimcache` - registry-based, not memory-based)
4. **Screenshot Capture** (Windows `screenshot`) - Desktop rendering from GDI
5. **Message Hooks** (Windows `messagehooks`) - SetWindowsHookEx detection
6. **Filesystem Recovery** (Linux/Mac `recover_filesystem`) - Full filesystem reconstruction
7. **tmpfs Recovery** (Linux `tmpfs`) - RAM-disk file recovery
8. **Keychain Dump** (Mac `keychaindump`) - macOS keychain extraction
9. **check_fops** (Linux/Mac) - File operation table integrity
10. **PLT Hook Detection** (Linux `plthook`) - GOT/PLT hook detection
11. **check_inline_kernel** (Linux) - Inline kernel patching detection
12. **Process/Library/Module Dumping** (All OS) - `procdump`, `dlldump`, `moddump`, `librarydump`
13. **LD_PRELOAD Detection** (Linux `ld_env`) - Preload-based rootkit detection
14. **MIG Table Check** (Mac `check_mig_table`) - Mach MIG integrity
15. **Shadow Syscall Table** (Mac `check_syscall_shadow`) - macOS shadow syscall detection

### 7.2 Capabilities That Are V3-Only (Not in V2)

V3 introduces these capabilities not present in V2:

1. **eBPF Program Detection** (`linux.ebpf`) - Modern rootkit detection
2. **ETW Patch Detection** (`windows.etwpatch`) - EDR evasion detection
3. **Direct/Indirect Syscall Detection** (`windows.malware.direct_system_calls`, `indirect_system_calls`) - Modern EDR bypass detection
4. **Process Ghosting Detection** (`windows.malware.processghosting`)
5. **PEB Masquerade Detection** (`windows.malware.pebmasquerade`)
6. **Skeleton Key Check** (`windows.malware.skeleton_key_check`)
7. **Unhooked System Calls** (`windows.malware.unhooked_system_calls`)
8. **Ftrace/Tracepoint Detection** (`linux.tracing.*`)
9. **Page Cache Recovery** (`linux.pagecache`)
10. **Framebuffer Extraction** (`linux.graphics.fbdev`)
11. **GetCellRoutine Hook Detection** (`windows.registry.getcellroutine`)
12. **Kernel Call Stack Recovery** (`linux.pscallstack`)
13. **Process Spoofing Detection** (`linux.malware.process_spoofing`)
14. **VFS Events** (`mac.vfsevents`) - Already existed in V2 actually
15. **Shimcache from Memory** (`windows.shimcachemem`) - Memory-based approach (new)
16. **Debug Registers** (`windows.debugregisters`)
17. **Orphan Kernel Threads** (`windows.orphan_kernel_threads`)
18. **IAT Parsing** (`windows.iat`)
19. **VAD Regex Scan** (`windows.vadregexscan`)
20. **SvcList** (`windows.svclist`) - Separate from svcscan
21. **Boot Time** (`linux.boottime`)
22. **Socket Scanning** (`linux.sockscan`)
23. **VMCoreInfo** (`linux.vmcoreinfo`)

### 7.3 Total Plugin Counts

| Category | V3 Official | V3 Malware Subcategory | V3 Total | V2 Total | Community V3 |
|----------|-------------|----------------------|----------|----------|-------------|
| **Windows** | ~65 | 14 | ~79 | ~65 | ~20+ |
| **Linux** | ~35 | 13 | ~48 | ~75 | ~5 |
| **macOS** | ~23 | 0 | ~23 | ~65 | ~2 |
| **Core** | 9 | - | 9 | ~5 | ~5 |
| **Total** | ~132 | 27 | ~159 | ~210 | ~32+ |

### 7.4 Superset Tool Target

To build a true superset, the tool must implement:
- All ~159 V3 official plugins
- All ~15 critical V2-only gaps
- All notable community capabilities (~32 plugins)
- Novel capabilities not in either version

**Estimated total plugin-equivalent capabilities needed: ~210+**
