# DFIR Enhancement Design — 2026-04-10

## Executive Summary

This document proposes four dimensions of enhancement to the `memory-forensic` Rust toolkit:

1. **Walker Coverage Gaps** — 28 new walkers (13 Linux, 15 Windows) targeting modern attack techniques not yet covered: io_uring abuse, vDSO tampering, CLR heap forensics, APC injection, fiber/FLS abuse, DKOM detection, and more.
2. **Cross-Artifact Correlation Engine** — A new `memf-correlate` crate providing a unified incident timeline, per-process threat scoring, process-tree correlation, and graph-based lateral-movement detection.
3. **Output/Integration Layer** — A new `memf-export` crate for STIX 2.1 bundle export, MITRE ATT&CK technique tagging, YARA rule synthesis, Sigma rule generation, and multi-format reporting (JSON/CSV/SARIF).
4. **New Platform Support** — A `memf-macos` crate skeleton for macOS memory forensics and container/cloud-native extensions in `memf-linux`.

Total new walker count: **28** (Dimension A) + **10** macOS stubs (Dimension D) + **4** container walkers (Dimension D) = **42 new modules**.

---

## Dimension A: Walker Coverage Gaps

### Priority 1 (High Impact, Low Complexity)

#### A1. Linux: `walk_io_uring`
- **File**: `crates/memf-linux/src/io_uring.rs`
- **Forensic value**: io_uring provides an asynchronous syscall interface that bypasses traditional syscall tracing (seccomp, ptrace, audit). Attackers use io_uring SQEs to perform file I/O, network operations, and even process creation without triggering seccomp filters. The curing rootkit (2025) demonstrated full C2 via io_uring alone.
- **Detection approach**: Walk `task_struct->io_uring_task->ctx_list` to enumerate `io_ring_ctx` structures. Extract submission queue entries (SQEs) and completion queue entries (CQEs) from shared ring buffers. Flag processes with io_uring contexts that have network opcodes (`IORING_OP_SENDMSG`, `IORING_OP_RECVMSG`, `IORING_OP_CONNECT`) or file opcodes on sensitive paths (`/etc/shadow`, `/proc/*/mem`). Cross-reference with seccomp profiles — a process with strict seccomp but active io_uring network ops is a strong indicator.
- **MITRE ATT&CK**: T1059.004 (Command and Scripting Interpreter: Unix Shell), T1071.001 (Application Layer Protocol: Web), T1014 (Rootkit)

#### A2. Linux: `walk_vdso_tamper`
- **File**: `crates/memf-linux/src/vdso_tamper.rs`
- **Forensic value**: The vDSO (virtual Dynamic Shared Object) and vsyscall page are kernel-mapped into every process's address space. Attackers can overwrite vDSO code to inject shellcode that executes in every process context without modifying the process binary itself.
- **Detection approach**: Read the vDSO ELF from kernel memory (`vdso_image_64`/`vdso_image_32`). For each process, read the vDSO mapping from the process VAS and compare byte-for-byte against the kernel's canonical copy. Any deviation indicates tampering. Also check vsyscall page permissions — it should be execute-only on modern kernels; RWX indicates manipulation.
- **MITRE ATT&CK**: T1055.009 (Process Injection: Proc Memory), T1574 (Hijack Execution Flow)

#### A3. Linux: `walk_proc_hidden`
- **File**: `crates/memf-linux/src/proc_hidden.rs`
- **Forensic value**: Process hiding is a hallmark of rootkits. Beyond the existing `psxview` cross-reference, this walker specifically targets three hiding techniques: (a) task_struct unlinked from `tasks` list but still on `pid_hash`/`pid_namespace` radix tree, (b) `getdents` hook hiding `/proc/<pid>` entries, (c) PID namespace manipulation.
- **Detection approach**: Walk `pid_namespace->idr` (radix tree of all allocated PIDs) and compare against `init_task->tasks` linked list and the `pid_hash` table. Any PID present in one source but absent from another is flagged. Additionally, compare process count from `nr_threads` kernel counter against actual enumeration count.
- **MITRE ATT&CK**: T1014 (Rootkit), T1564.001 (Hide Artifacts: Hidden Files and Directories)

#### A4. Linux: `walk_user_namespace_escalation`
- **File**: `crates/memf-linux/src/user_ns_escalation.rs`
- **Forensic value**: User namespaces are a common privilege escalation vector. Unprivileged users can create user namespaces where they are root, then exploit kernel vulnerabilities from that elevated context. CVE-2022-0185, CVE-2023-2598, and many others use this vector.
- **Detection approach**: Walk `user_namespace` structures via `task_struct->nsproxy->user_ns`. Flag processes where: (a) the user_ns owner UID differs from the real UID of the process creator, (b) nested namespace depth exceeds a threshold (>3), (c) a non-root process owns a user_namespace with `CAP_SYS_ADMIN` mapped. Cross-reference with capabilities walker output.
- **MITRE ATT&CK**: T1611 (Escape to Host), T1548.001 (Abuse Elevation Control Mechanism: Setuid/Setgid)

#### A5. Windows: `walk_apc_injection`
- **File**: `crates/memf-windows/src/apc_injection.rs`
- **Forensic value**: APC (Asynchronous Procedure Call) injection is used by sophisticated malware (e.g., DoublePulsar, AtomBombing variant) to execute code in remote threads. Kernel APCs bypass user-mode hooks entirely.
- **Detection approach**: Walk `KTHREAD->ApcState.ApcListHead[KernelMode]` and `KTHREAD->ApcState.ApcListHead[UserMode]` for each thread. Extract `KAPC->KernelRoutine`, `KAPC->RundownRoutine`, `KAPC->NormalRoutine` function pointers. Flag APCs where: (a) NormalRoutine points to unbacked memory (not in any loaded module), (b) KernelRoutine points to non-standard addresses, (c) the APC targets a thread in a different process than the APC's originating context.
- **MITRE ATT&CK**: T1055.004 (Process Injection: Asynchronous Procedure Call)

#### A6. Windows: `walk_clr_heap`
- **File**: `crates/memf-windows/src/clr_heap.rs`
- **Forensic value**: .NET/CLR in-memory execution (e.g., Cobalt Strike's `execute-assembly`, SharpShooter, Covenant) loads .NET assemblies directly into memory. These leave artifacts in the CLR heap but no files on disk.
- **Detection approach**: Scan process memory for the CLR DAC (Data Access Component) structures. Locate `AppDomain` objects via the CLR's internal heap. For each AppDomain, walk the `Assembly` list and extract: assembly name, module metadata (MVID), loaded types, and method IL byte arrays. Flag assemblies with no corresponding file on disk (the `IsDynamic` flag or missing `GetFiles()` path). Extract PE headers from in-memory assemblies for YARA scanning.
- **MITRE ATT&CK**: T1620 (Reflective Code Loading), T1059.001 (Command and Scripting Interpreter: PowerShell)

#### A7. Windows: `walk_fiber_fls`
- **File**: `crates/memf-windows/src/fiber_fls.rs`
- **Forensic value**: Fibers (cooperative user-mode threads) and Fiber Local Storage (FLS) are abused for evasion. Fiber-based shellcode loaders (e.g., Ekko, Nighthawk) convert threads to fibers to manipulate execution context and evade call-stack analysis. FLS callbacks execute during fiber deletion — a persistence mechanism.
- **Detection approach**: Walk `TEB->NtTib.FiberData` for each thread. If non-null, the thread has been converted to a fiber. Extract `FIBER->FiberContext` (saved register state) and check if RIP/RSP point to unbacked memory. Walk FLS callback table (`PEB->FlsCallback`) and flag entries pointing outside loaded modules. Compare fiber stack base/limit against known module ranges.
- **MITRE ATT&CK**: T1055 (Process Injection), T1027.013 (Obfuscated Files: Encrypted/Encoded File)

#### A8. Windows: `walk_dkom_detect`
- **File**: `crates/memf-windows/src/dkom_detect.rs`
- **Forensic value**: Direct Kernel Object Manipulation (DKOM) is used by rootkits to unlink processes, threads, and drivers from kernel lists. This is a dedicated integrity-check walker that goes beyond `psxview`.
- **Detection approach**: Cross-reference multiple kernel data structures for consistency: (a) `PsActiveProcessHead` linked list vs. `PspCidTable` handle table vs. session process lists vs. CSR process list, (b) `PsLoadedModuleList` vs. `MmLoadedUserImageList` vs. `KeLoaderBlock->LoadOrderListHead`, (c) `OBJECT_HEADER->TypeIndex` validation (check for type-index rewriting attacks). For each inconsistency, report which structure is missing the entry and the suspected hiding technique.
- **MITRE ATT&CK**: T1014 (Rootkit), T1562.001 (Impair Defenses: Disable or Modify Tools)

### Priority 2 (High Impact, Medium Complexity)

#### A9. Linux: `walk_netlink_audit`
- **File**: `crates/memf-linux/src/netlink_audit.rs`
- **Forensic value**: The Linux audit subsystem uses netlink sockets for kernel-to-userspace communication. Attackers tamper with audit rules, suppress specific event types, or kill the audit daemon. Audit log manipulation is a key anti-forensics technique.
- **Detection approach**: Walk `audit_filter_list` arrays (one per audit filter type: USER, TASK, EXIT, etc.). Extract each `audit_entry` with its field/op/value tuples and flags. Flag: (a) rules that exclude specific PIDs or UIDs from auditing (`-a exclude,always -F pid=<attacker_pid>`), (b) `audit_enabled` kernel variable set to 0 (auditing globally disabled), (c) `audit_backlog_limit` set suspiciously low (log overflow = lost events), (d) netlink socket connected to audit multicast group with non-standard PID (eavesdropping on audit events).
- **MITRE ATT&CK**: T1562.012 (Impair Defenses: Disable or Modify Linux Audit System), T1070.002 (Indicator Removal: Clear Linux or Mac System Logs)

#### A10. Linux: `walk_udev_netlink`
- **File**: `crates/memf-linux/src/udev_netlink.rs`
- **Forensic value**: udev rules execute arbitrary commands on device events. Attackers can inject malicious udev rules for persistence or privilege escalation. Netlink socket monitoring reveals which processes receive device events.
- **Detection approach**: Walk `udev_rules` structures in memory to extract loaded rules and their associated commands (`RUN+=` directives). Flag rules that: (a) execute binaries from tmp/world-writable directories, (b) match overly broad device patterns, (c) were added recently (via timestamp comparison). Enumerate netlink sockets bound to `NETLINK_KOBJECT_UEVENT` group and cross-reference with expected udevd/systemd PIDs.
- **MITRE ATT&CK**: T1546.004 (Event Triggered Execution: Unix Shell Configuration Modification), T1547 (Boot or Logon Autostart Execution)

#### A11. Linux: `walk_timerfd_signalfd`
- **File**: `crates/memf-linux/src/timerfd_signalfd.rs`
- **Forensic value**: timerfd, signalfd, and eventfd file descriptors are used by sophisticated implants for covert timing channels, signal interception, and inter-process signaling. A process with a signalfd intercepting SIGTERM/SIGKILL is attempting to resist termination.
- **Detection approach**: Walk each process's file descriptor table and identify timerfd/signalfd/eventfd entries via `file->f_op` pointing to `timerfd_fops`/`signalfd_fops`/`eventfd_fops`. For signalfd: extract the signal mask and flag if it includes SIGTERM (15), SIGKILL (9), or SIGSTOP (19). For timerfd: extract interval/expiration and flag sub-second periodic timers (potential beacon). For eventfd: identify cross-process eventfd sharing via same `struct eventfd_ctx` pointer in multiple processes (covert IPC).
- **MITRE ATT&CK**: T1205.002 (Traffic Signaling: Socket Filters), T1071 (Application Layer Protocol)

#### A12. Linux: `walk_shared_mem_anomaly`
- **File**: `crates/memf-linux/src/shared_mem_anomaly.rs`
- **Forensic value**: Shared memory (shmem/mmap MAP_SHARED/memfd_create) is abused for fileless payload staging, process injection via shared mappings, and covert IPC. memfd_create with MFD_CLOEXEC creates anonymous file descriptors frequently used by fileless malware.
- **Detection approach**: Walk `/proc/<pid>/maps` equivalent in kernel memory (via `vm_area_struct` chain). Flag: (a) memfd regions (`vm_file->f_path` pointing to memfd filesystem) with execute permission, (b) shared anonymous mappings (`MAP_SHARED|MAP_ANONYMOUS`) shared between processes with different UIDs, (c) POSIX shared memory segments (`/dev/shm` backed) containing ELF headers or shellcode patterns. Cross-reference with existing IPC walker for SysV shm.
- **MITRE ATT&CK**: T1055.009 (Process Injection: Proc Memory), T1027.011 (Obfuscated Files: Fileless Storage)

#### A13. Linux: `walk_container_breakout`
- **File**: `crates/memf-linux/src/container_breakout.rs`
- **Forensic value**: Container escapes are a critical cloud threat. Indicators include: processes that transition between cgroup namespaces, mount namespace manipulation, and access to host resources from container contexts.
- **Detection approach**: For each process, compare `nsproxy` fields against init_task: (a) flag processes whose PID namespace differs from their cgroup namespace (cgroup escape), (b) detect processes with mount namespace showing host filesystem mounts (`/`, `/etc`, `/var`) while in a non-init PID namespace, (c) detect `nsenter`-like behavior where a process's namespace set is a mix from different containers. Flag `CAP_SYS_ADMIN` + `CAP_SYS_PTRACE` in non-init user namespaces.
- **MITRE ATT&CK**: T1611 (Escape to Host), T1610 (Deploy Container)

#### A14. Windows: `walk_tls_callbacks`
- **File**: `crates/memf-windows/src/tls_callbacks.rs`
- **Forensic value**: TLS (Thread Local Storage) callbacks execute before the main entry point of a PE. Malware uses TLS callbacks for anti-debugging, unpacking, and executing payloads before security tools hook the entry point.
- **Detection approach**: For each loaded module, parse the PE header and locate the TLS directory (`IMAGE_DIRECTORY_ENTRY_TLS`). Walk the `AddressOfCallBacks` array. Flag: (a) callbacks pointing outside the module's own address range, (b) modules with unusually many TLS callbacks (>3), (c) TLS callbacks in DLLs that don't typically use TLS (cross-reference against known clean module database). Extract callback code bytes for YARA scanning.
- **MITRE ATT&CK**: T1055.001 (Process Injection: Dynamic-link Library Injection), T1106 (Native API)

#### A15. Windows: `walk_section_object`
- **File**: `crates/memf-windows/src/section_object.rs`
- **Forensic value**: Section objects (memory-mapped files) are used for process hollowing, transacted hollowing, and phantom DLL loading. Orphaned or suspicious section objects indicate injection or evasion.
- **Detection approach**: Walk `SECTION_OBJECT` structures via the object manager namespace and handle tables. For each section: extract backing file, size, protection attributes, and mapped processes. Flag: (a) image sections not backed by a file on disk, (b) sections mapped with `SEC_NO_CHANGE` that differ from their backing file (transacted hollowing), (c) section objects with `PAGE_EXECUTE_READWRITE` protection, (d) sections mapped into multiple unrelated processes (potential shared-memory injection).
- **MITRE ATT&CK**: T1055.012 (Process Injection: Process Hollowing), T1574 (Hijack Execution Flow)

#### A16. Windows: `walk_job_object`
- **File**: `crates/memf-windows/src/job_object.rs`
- **Forensic value**: Job objects group processes and impose restrictions. Malware uses job objects to: (a) prevent child processes from escaping a job (ensuring persistence tree survives), (b) restrict CPU/memory to evade resource-based detection, (c) abuse `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` semantics. AppContainer sandboxes rely on job objects — escape indicators are forensically relevant.
- **Detection approach**: Walk the kernel's job object list (`PsJobType` via object directory). For each `EJOB`: extract process list, limit flags, UI restrictions, and security attributes. Flag: (a) jobs with `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK` (processes can silently leave sandbox), (b) jobs containing processes from different user contexts, (c) nested job hierarchies (used to bypass restrictions).
- **MITRE ATT&CK**: T1055 (Process Injection), T1548 (Abuse Elevation Control Mechanism)

#### A17. Windows: `walk_cfg_bypass`
- **File**: `crates/memf-windows/src/cfg_bypass.rs`
- **Forensic value**: Control Flow Guard (CFG) is a mitigation against control-flow hijacking. Attackers disable CFG by: (a) overwriting the CFG bitmap, (b) calling `NtSetInformationVirtualMemory` to disable CFG on specific pages, (c) corrupting the CFG dispatch function pointer.
- **Detection approach**: Read `ntdll!LdrSystemDllInitBlock->CfgBitMap` and validate its integrity. For each process, check `PEB->ProcessParameters->Flags` for CFG-disabled indicators. Walk VAD entries and flag executable regions where CFG was explicitly disabled (`MM_MEMTYPE_PRIVATE` with `PAGE_TARGETS_NO_UPDATE`). Compare `nt!guard_check_icall` function pointer against its expected value in the kernel image.
- **MITRE ATT&CK**: T1211 (Exploitation for Defense Evasion), T1562 (Impair Defenses)

#### A18. Windows: `walk_wow64_anomaly`
- **File**: `crates/memf-windows/src/wow64_anomaly.rs`
- **Forensic value**: WoW64 (Windows 32-bit on Windows 64-bit) provides a compatibility layer that attackers abuse. "Heaven's Gate" technique transitions from 32-bit to 64-bit code to evade 32-bit hooks. WoW64 APC injection and WoW64 syscall rewiring are also used.
- **Detection approach**: For each WoW64 process (identified by `PEB32` presence): (a) check if `wow64cpu!CpuSimulate` dispatch table has been tampered with, (b) verify `wow64.dll`, `wow64cpu.dll`, `wow64win.dll` are loaded from expected paths, (c) detect 64-bit code segments in 32-bit process address space (far call to CS=0x33 is the Heaven's Gate signature), (d) compare the WoW64 syscall stub against expected patterns.
- **MITRE ATT&CK**: T1055 (Process Injection), T1106 (Native API)

#### A19. Windows: `walk_ntsetsysinfo`
- **File**: `crates/memf-windows/src/ntsetsysinfo.rs`
- **Forensic value**: `NtSetSystemInformation` with specific information classes can: load unsigned drivers (`SystemLoadAndCallImage`), modify kernel memory (`SystemKernelDebuggerInformation`), and tamper with system configuration. This is a privileged API abuse vector.
- **Detection approach**: Scan kernel memory for `NtSetSystemInformation` call traces by examining thread kernel stacks. Walk the `KTHREAD->KernelStack` for each thread and search for return addresses into `NtSetSystemInformation` dispatcher. Flag calls with dangerous information classes: `SystemLoadAndCallImage` (0x26), `SystemUnloadImage` (0x27), `SystemExtendServiceTableInformation` (0x26). Also check `CI.dll` state for code integrity bypass indicators.
- **MITRE ATT&CK**: T1068 (Exploitation for Privilege Escalation), T1562.001 (Impair Defenses: Disable or Modify Tools)

### Priority 3 (Medium Impact, High Complexity)

#### A20. Linux: `walk_msr_forensics`
- **File**: `crates/memf-linux/src/msr_forensics.rs`
- **Forensic value**: Model-Specific Registers (MSRs) control CPU behavior. Rootkits modify MSR_LSTAR (syscall entry point), MSR_IA32_SYSENTER_EIP, IA32_APIC_BASE, and debug control MSRs. These are deep hardware-level persistence/evasion mechanisms.
- **Detection approach**: If the memory image includes CPU register state (crash dumps, hypervisor snapshots): read MSR_LSTAR and compare against `entry_SYSCALL_64` symbol address, read MSR_IA32_SYSENTER_EIP and compare against expected 32-bit syscall entry, check IA32_DEBUGCTL for Branch Trace Store (BTS) manipulation, verify IA32_FEATURE_CONTROL for virtualization-based rootkit indicators (VMX already enabled unexpectedly).
- **MITRE ATT&CK**: T1014 (Rootkit), T1542 (Pre-OS Boot)

#### A21. Linux: `walk_fuse_abuse`
- **File**: `crates/memf-linux/src/fuse_abuse.rs`
- **Forensic value**: FUSE (Filesystem in Userspace) allows user-mode filesystem implementations. Attackers use FUSE to: create fake /proc entries hiding processes, intercept file reads to serve trojanized content, or create covert storage channels.
- **Detection approach**: Walk `super_block` list for FUSE filesystems (`s_type->name == "fuse"` or `"fuseblk"`). For each FUSE mount: extract the owning process (`fc->connected`, `fc->user_id`), mount point, and max_read/max_write parameters. Flag: (a) FUSE mounts over sensitive paths (`/proc`, `/sys`, `/etc`), (b) FUSE daemons running as root, (c) FUSE connections with `allow_other` flag (exposes filesystem to all users).
- **MITRE ATT&CK**: T1564 (Hide Artifacts), T1036 (Masquerading)

#### A22. Linux: `walk_landlock`
- **File**: `crates/memf-linux/src/landlock.rs`
- **Forensic value**: Landlock is a Linux security module for unprivileged sandboxing. Forensically, absence of expected Landlock rules on security-sensitive processes may indicate sandbox escape or policy bypass. Presence of Landlock on unexpected processes may indicate an attacker restricting their own process to evade heuristic detection.
- **Detection approach**: Walk `task_struct->security` for Landlock domain pointers. Extract `landlock_ruleset` and its rules (filesystem access rights per path hierarchy). Report: (a) processes expected to be sandboxed but lacking Landlock domains, (b) Landlock rulesets that grant broad `LANDLOCK_ACCESS_FS_EXECUTE` permissions, (c) processes with nested Landlock domains (domain stacking — used legitimately but can indicate evasion).
- **MITRE ATT&CK**: T1562.001 (Impair Defenses), T1480 (Execution Guardrails)

#### A23. Windows: `walk_token_escalation_chain`
- **File**: `crates/memf-windows/src/token_escalation_chain.rs`
- **Forensic value**: Token privilege escalation chains involve: creating a token with SeImpersonatePrivilege, impersonating a SYSTEM token via named pipe or potato exploit, then using that token to spawn elevated processes. Detecting the full chain is more valuable than detecting individual token states.
- **Detection approach**: For each process and thread, walk token history: (a) compare `TOKEN->Privileges.Present` vs `TOKEN->Privileges.Enabled` (recently enabled dangerous privileges), (b) trace `TOKEN->ParentTokenId` chain to find the original token, (c) detect impersonation level escalation (`SecurityIdentification` -> `SecurityImpersonation` -> `SecurityDelegation`), (d) flag tokens with `SeImpersonatePrivilege` + `SeAssignPrimaryTokenPrivilege` enabled (potato attack signature). Cross-reference with existing `token_impersonation` walker findings.
- **MITRE ATT&CK**: T1134.001 (Access Token Manipulation: Token Impersonation/Theft), T1134.002 (Create Process with Token)

#### A24. Windows: `walk_appcontainer_escape`
- **File**: `crates/memf-windows/src/appcontainer_escape.rs`
- **Forensic value**: AppContainer is the sandbox for UWP apps and Microsoft Edge. Escapes allow sandboxed processes to access resources outside their container. Broker process manipulation, handle duplication, and capability abuse are common vectors.
- **Detection approach**: Identify AppContainer processes via `TOKEN->AppContainerSid`. For each: (a) enumerate capabilities granted (`TOKEN->Capabilities`) and flag overly broad ones, (b) check for handles to objects outside the AppContainer's object namespace, (c) detect broker process handle leaks (high-privilege handles duplicated into AppContainer process), (d) identify AppContainer processes that have spawned non-AppContainer children (breakout indicator).
- **MITRE ATT&CK**: T1611 (Escape to Host), T1548 (Abuse Elevation Control Mechanism)

#### A25. Windows: `walk_wsl_artifacts`
- **File**: `crates/memf-windows/src/wsl_artifacts.rs`
- **Forensic value**: WSL (Windows Subsystem for Linux) creates a hybrid execution environment. Attackers use WSL to: run Linux malware on Windows hosts, bypass Windows security tools (EDR/AV), access Windows filesystems from Linux context via `/mnt/c/`.
- **Detection approach**: Detect WSL processes (`LxssManager` service, `wsl.exe`, `wslhost.exe`). Walk Pico provider structures to enumerate Linux processes running under WSL. For each: extract the ELF binary path, environment variables, and network connections. Flag: (a) WSL processes accessing sensitive Windows paths, (b) WSL network connections to external hosts, (c) WSL processes spawned by unexpected parent processes (lateral movement via WSL).
- **MITRE ATT&CK**: T1059.004 (Command and Scripting Interpreter: Unix Shell), T1106 (Native API)

#### A26. Windows: `walk_heap_spray`
- **File**: `crates/memf-windows/src/heap_spray.rs`
- **Forensic value**: Heap spray is used in exploitation to place shellcode at predictable addresses. While less common with modern mitigations (ASLR, CFG), it remains relevant for browser exploits, document exploits (Office/PDF), and kernel pool spraying.
- **Detection approach**: For each process, scan the default process heap and any additional heaps (`PEB->ProcessHeaps`). Detect: (a) large numbers of same-sized allocations (>1000 allocations of identical size), (b) heap regions containing NOP sleds (`0x90909090` or equivalent), (c) heap allocations containing patterns consistent with ROP gadget addresses (addresses within ntdll/kernel32 range repeated), (d) total heap committed size anomalies (>1GB in a process that shouldn't need it).
- **MITRE ATT&CK**: T1203 (Exploitation for Client Execution), T1190 (Exploit Public-Facing Application)

#### A27. Linux: `walk_cpu_pinning`
- **File**: `crates/memf-linux/src/cpu_pinning.rs`
- **Forensic value**: Cryptominers and some implants use CPU affinity pinning (`sched_setaffinity`) to bind to specific cores, avoiding detection by load-balancing heuristics. Combined with nice/ionice manipulation, this is a resource-abuse indicator.
- **Detection approach**: Walk `task_struct->cpus_mask` (or `cpus_allowed` on older kernels) for each process. Flag: (a) processes pinned to a single CPU core while being CPU-intensive (`utime` + `stime` high), (b) processes with `sched_policy` set to `SCHED_BATCH` or `SCHED_IDLE` (attempting to hide CPU usage), (c) process groups where all members are pinned to the same core set (coordinated mining).
- **MITRE ATT&CK**: T1496 (Resource Hijacking)

#### A28. Windows: `walk_supply_chain`
- **File**: `crates/memf-windows/src/supply_chain.rs`
- **Forensic value**: Supply chain attacks load trojanized versions of legitimate libraries. Detection requires comparing loaded module metadata against known-good baselines.
- **Detection approach**: For each loaded DLL, extract: (a) PE authenticode signature and verify certificate chain (flag unsigned or self-signed modules in processes that normally load only signed DLLs), (b) version info resource and compare against known version databases, (c) section entropy analysis (high entropy `.text` section indicates packing/encryption unusual for legitimate DLLs), (d) import table anomalies (legitimate DLL name but imports inconsistent with its known functionality). Integrate with PE version info walker for enhanced coverage.
- **MITRE ATT&CK**: T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain), T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking)

---

## Dimension B: Cross-Artifact Correlation Engine

### Architecture

A new crate `memf-correlate` that consumes typed output from all walkers and produces correlated intelligence.

```
                     +------------------+
                     |   memf-linux     |---+
                     +------------------+   |
                                            |   +-------------------+    +------------------+
                     +------------------+   +-->|  memf-correlate   |--->|   memf-export    |
                     |  memf-windows    |---+   | (correlation eng) |    | (STIX/YARA/etc)  |
                     +------------------+   |   +-------------------+    +------------------+
                                            |          |
                     +------------------+   |          v
                     |   memf-macos     |---+   +-------------+
                     +------------------+       | Timeline DB  |
                                                | (in-memory)  |
                                                +-------------+
```

### Components

#### B1. Unified Event Model (`memf-correlate/src/event.rs`)
```rust
pub struct ForensicEvent {
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub source_walker: &'static str,
    pub entity: Entity,          // Process, Thread, Module, Connection, etc.
    pub finding: Finding,        // What was found
    pub severity: Severity,      // Info, Low, Medium, High, Critical
    pub mitre_attack: Vec<MitreAttackId>,
    pub confidence: f64,         // 0.0 - 1.0
    pub raw_evidence: Vec<u8>,   // Optionally, raw bytes for YARA/export
}

pub enum Entity {
    Process { pid: u32, name: String, ppid: Option<u32> },
    Thread { tid: u32, owning_pid: u32 },
    Module { name: String, base: u64, size: u64 },
    Connection { src: SocketAddr, dst: SocketAddr, proto: Protocol },
    Driver { name: String, base: u64 },
    RegistryKey { path: String },
    File { path: String },
}
```

#### B2. Threat Scoring Engine (`memf-correlate/src/scoring.rs`)
- Each walker emits `ForensicEvent` with individual severity and confidence.
- The scoring engine aggregates events per entity (primarily per-process):
  - **Additive scoring**: Each finding adds to the entity's threat score, weighted by severity and confidence.
  - **Combinatorial amplifiers**: Certain finding combinations multiply the score (e.g., process hollowing + network beaconing + credential access = 3x multiplier).
  - **Baseline deviation**: Compare against a "known good" profile if provided (e.g., expected services list).
- Output: Ranked list of entities by threat score, with contributing findings.

Scoring formula:
```
entity_score = sum(event.severity_weight * event.confidence) * combinatorial_multiplier
```

Where:
- `severity_weight`: Info=1, Low=5, Medium=15, High=40, Critical=100
- `combinatorial_multiplier`: 1.0 base, +0.5 for each MITRE tactic represented beyond the first (multi-tactic activity is more suspicious)

#### B3. Process Tree Correlator (`memf-correlate/src/process_tree.rs`)
- Build a full process tree from `process` walker output.
- For each node, aggregate all walker findings for that PID and its descendants.
- Detect: (a) anomalous parent-child relationships (e.g., `svchost.exe` spawning `cmd.exe`), (b) process tree depth anomalies (deep chains suggest living-off-the-land), (c) orphaned process subtrees (parent died but children persist — indicator of process injection or double-fork daemonization).

#### B4. Lateral Movement Detector (`memf-correlate/src/lateral_movement.rs`)
- Cross-correlate:
  - `rdp_sessions` walker (inbound RDP)
  - `network` walker (SMB/WinRM/SSH connections)
  - `kerberos_tickets` / `ntlm_ssp` (credential use)
  - `scheduled_tasks` / `service` (remote execution)
  - `psxview` (hidden processes on endpoints)
- Build a directed graph of host-to-host movement with timestamps.
- Flag: credential use followed by remote service creation within a time window.

#### B5. Timeline Engine (`memf-correlate/src/timeline.rs`)
- Merge all timestamped events into a single unified timeline.
- Support: absolute timestamps, relative ordering (before/after), and wall-clock alignment.
- Output: Sorted event stream with optional filtering by entity, severity, MITRE tactic, or time window.
- Format: Compatible with Plaso/log2timeline supertimeline format for integration with existing DFIR toolchains.

### Data Flow

1. Each walker's `walk_*` function returns `Vec<WalkerOutput>` (platform-specific).
2. A new `into_forensic_events()` trait method on each walker converts output to `Vec<ForensicEvent>`.
3. All `ForensicEvent`s feed into the correlation engine.
4. The correlation engine runs: timeline construction -> process tree building -> threat scoring -> lateral movement detection.
5. Correlated output is passed to `memf-export` for final rendering.

### Implementation Plan

| Phase | Component | Effort | Dependencies |
|-------|-----------|--------|--------------|
| 1 | `ForensicEvent` model + trait | 1 week | None |
| 2 | `into_forensic_events()` for existing walkers (top 20) | 2 weeks | Phase 1 |
| 3 | Timeline engine | 1 week | Phase 1 |
| 4 | Process tree correlator | 1 week | Phase 2 |
| 5 | Threat scoring engine | 1 week | Phase 2 |
| 6 | Lateral movement detector | 2 weeks | Phases 3-5 |

---

## Dimension C: Output/Integration Layer

A new crate `memf-export` consuming `ForensicEvent` streams and producing external-tool-compatible output.

### STIX 2.1 Export (`memf-export/src/stix.rs`)

Map `ForensicEvent` entities to STIX 2.1 objects:

| ForensicEvent Entity | STIX 2.1 Object | Notes |
|----------------------|------------------|-------|
| Process | `process` SCO | PID, name, command_line, parent_ref |
| Module | `file` SCO + `software` SCO | Hashes, name, version |
| Connection | `network-traffic` SCO | src/dst, protocols |
| File | `file` SCO | Path, hashes, size |
| RegistryKey | `windows-registry-key` SCO | Key path, values |
| Finding (malicious) | `indicator` SDO | Pattern in STIX patterning language |
| Finding (technique) | `attack-pattern` SDO | MITRE ATT&CK reference |
| Correlation | `relationship` SRO | Links indicators to observables |

Bundle structure:
- One `identity` SDO for the analysis tool.
- One `report` SDO per analysis session.
- `observed-data` SDOs grouping related SCOs.
- `indicator` SDOs with STIX patterns derived from findings.
- `relationship` SROs linking indicators to attack-patterns and observed-data.

Output: JSON file conforming to STIX 2.1 specification (OASIS standard).

### MITRE ATT&CK Tagging (`memf-export/src/mitre.rs`)

- Maintain a mapping table from walker name + finding type to ATT&CK technique IDs.
- Support Enterprise ATT&CK matrix (Windows, Linux, macOS).
- Each `ForensicEvent` carries `Vec<MitreAttackId>` populated at walker emit time.
- Export: ATT&CK Navigator JSON layer file showing technique coverage and hit counts. This enables direct import into ATT&CK Navigator for visual analysis.

Mapping structure:
```rust
pub struct MitreAttackId {
    pub tactic: &'static str,       // e.g., "defense-evasion"
    pub technique: &'static str,    // e.g., "T1055"
    pub sub_technique: Option<&'static str>, // e.g., "004"
    pub name: &'static str,         // e.g., "Asynchronous Procedure Call"
}
```

### YARA Synthesis (`memf-export/src/yara_synth.rs`)

When a walker detects suspicious bytes (injected code, shellcode, packed sections):

1. Extract the raw byte sequence from the finding's `raw_evidence` field.
2. Generate a YARA rule:
   - `strings`: Unique byte sequences (avoiding common prologues), with wildcards for polymorphic regions.
   - `condition`: Size constraints + string match + optional PE/ELF header check.
   - `meta`: Source walker, MITRE technique, confidence score, timestamp.
3. De-duplicate: If multiple findings produce overlapping byte sequences, merge into a single rule with OR conditions.
4. Output: `.yar` file with all synthesized rules, ready for scanning other memory images or disk artifacts.

### Platform Integrations

#### Velociraptor VQL Artifacts (`memf-export/src/velociraptor.rs`)
- Generate VQL artifact YAML files that invoke `memory-forensic` as an external tool.
- Each walker maps to a VQL artifact with parameters for filtering.
- Output includes VQL for result parsing and display.

#### Sigma Rule Generation (`memf-export/src/sigma.rs`)
- For findings that have SIEM-correlatable indicators (process names, command lines, network connections, registry keys):
  - Generate Sigma rules in YAML format.
  - Map to appropriate log sources (`process_creation`, `network_connection`, `registry_event`).
  - Include `level`, `tags` (MITRE), and `falsepositives` fields.

#### Report Formats (`memf-export/src/report.rs`)
- **JSON**: Full structured output, machine-readable.
- **CSV**: Flat table format for spreadsheet analysis, one row per finding.
- **SARIF**: Static Analysis Results Interchange Format — for integration with GitHub Advanced Security, Azure DevOps, and other code scanning platforms. Map findings to SARIF `result` objects with `ruleId` (MITRE technique), `message`, and `locations`.
- **HTML**: Standalone report with embedded CSS, sortable tables, and threat score visualization (no JS dependencies for portability in air-gapped environments).

### Implementation Plan

| Phase | Component | Effort | Dependencies |
|-------|-----------|--------|--------------|
| 1 | `ForensicEvent` -> JSON/CSV export | 1 week | Dimension B Phase 1 |
| 2 | MITRE ATT&CK mapping table + Navigator export | 1 week | Phase 1 |
| 3 | STIX 2.1 bundle export | 2 weeks | Phase 1 |
| 4 | YARA synthesis engine | 2 weeks | Phase 1 |
| 5 | Sigma rule generation | 1 week | Phase 2 |
| 6 | SARIF export | 1 week | Phase 1 |
| 7 | Velociraptor VQL generation | 1 week | Phase 1 |
| 8 | HTML report generator | 1 week | Phases 1-2 |

---

## Dimension D: New Platform Support

### macOS Memory Forensics (`memf-macos` crate)

#### Architecture

New crate: `crates/memf-macos/` following the same `WalkerPlugin` trait pattern as Linux/Windows.

macOS kernel (XNU) combines Mach and BSD subsystems. Memory forensics must walk both Mach data structures (tasks, threads, ports) and BSD structures (processes, files, sockets).

Key challenge: macOS uses a hybrid kernel with zone allocator (`zalloc`) for most kernel objects. Walker implementations must understand zone-based allocation to enumerate objects.

#### Proposed Walkers (10 stubs for Phase 1)

##### D1. `walk_mach_ports`
- **File**: `crates/memf-macos/src/mach_ports.rs`
- **Forensic value**: Mach ports are the IPC primitive in XNU. Task ports grant full control over a process (read/write memory, manipulate threads). Malware steals task ports for injection. The `task_for_pid()` and `processor_set_tasks()` APIs expose task ports.
- **Detection approach**: Walk `ipc_space` for each task. Enumerate port rights (`MACH_PORT_RIGHT_SEND`, `MACH_PORT_RIGHT_RECEIVE`). Flag: (a) non-root processes holding send rights to other tasks' task ports, (b) processes with receive rights on `host_priv` or `host_security` ports, (c) unusual port name-to-capability mappings.
- **MITRE ATT&CK**: T1055 (Process Injection), T1068 (Exploitation for Privilege Escalation)

##### D2. `walk_kext_forensics`
- **File**: `crates/memf-macos/src/kext_forensics.rs`
- **Forensic value**: Kernel extensions (kexts) are macOS kernel modules. Despite Apple's deprecation push, malicious kexts remain a rootkit vector on older systems and when SIP is disabled.
- **Detection approach**: Walk `kmod_info` linked list from `kmod` kernel symbol. For each kext: extract name, version, load address, size, and dependencies. Flag: (a) kexts not signed by Apple or known vendors, (b) kexts loaded from non-standard paths (outside `/System/Library/Extensions/` or `/Library/Extensions/`), (c) kexts with hooks into the Mach trap table or BSD syscall table.
- **MITRE ATT&CK**: T1547.006 (Boot or Logon Autostart Execution: Kernel Modules and Extensions), T1014 (Rootkit)

##### D3. `walk_dyld_cache`
- **File**: `crates/memf-macos/src/dyld_cache.rs`
- **Forensic value**: The dyld shared cache contains most system libraries pre-linked into a single file. Attackers can: inject into the shared cache, hook dyld stub helpers, or tamper with `dyld_all_image_infos` to hide loaded libraries.
- **Detection approach**: Locate `dyld_all_image_infos` in each process. Walk the image list and compare against the shared cache table of contents. Flag: (a) images loaded outside the shared cache that shadow cached libraries, (b) `dyld_all_image_infos->notification` function pointer tampering, (c) images with load addresses that conflict with shared cache regions.
- **MITRE ATT&CK**: T1574.006 (Hijack Execution Flow: Dynamic Linker Hijacking), T1055.001 (Dynamic-link Library Injection)

##### D4. `walk_xpc_services`
- **File**: `crates/memf-macos/src/xpc_services.rs`
- **Forensic value**: XPC (cross-process communication) services are pervasive in macOS. Abused XPC services (especially privileged helpers) are a privilege escalation vector. Malware can also create malicious XPC services for persistence.
- **Detection approach**: Enumerate launchd-managed XPC services via `launchd`'s internal job list in memory. For each: extract service name, owning bundle, entitlements, and Mach port. Flag: (a) XPC services with overly broad entitlements, (b) services communicating with unexpected clients, (c) XPC services whose on-disk plist has been modified (comparing memory state vs. expected).
- **MITRE ATT&CK**: T1543.004 (Create or Modify System Process: Launch Daemon), T1559 (Inter-Process Communication)

##### D5. `walk_launchd_persistence`
- **File**: `crates/memf-macos/src/launchd_persistence.rs`
- **Forensic value**: LaunchAgents and LaunchDaemons are the primary persistence mechanism on macOS. Memory forensics can reveal loaded jobs including those whose plist files have been deleted.
- **Detection approach**: Walk launchd's internal job dictionary. Extract: label, program path, arguments, environment, run-at-load flag, keep-alive conditions, and Mach port registrations. Flag: (a) jobs with `ProgramArguments` pointing to tmp/hidden paths, (b) jobs with `WatchPaths` on sensitive directories, (c) jobs loaded but with no corresponding plist on disk (fileless persistence).
- **MITRE ATT&CK**: T1543.004 (Create or Modify System Process: Launch Daemon), T1547.011 (Plist Modification)

##### D6. `walk_sip_status`
- **File**: `crates/memf-macos/src/sip_status.rs`
- **Forensic value**: System Integrity Protection (SIP) restricts root's ability to modify protected system files and kernel extensions. Disabling SIP is a prerequisite for many macOS rootkits.
- **Detection approach**: Read `csr_get_active_config()` result from kernel memory (stored in boot-args or NVRAM-derived kernel variable). Decode CSR flags: `CSR_ALLOW_UNTRUSTED_KEXTS`, `CSR_ALLOW_UNRESTRICTED_FS`, `CSR_ALLOW_TASK_FOR_PID`, `CSR_ALLOW_KERNEL_DEBUGGER`, etc. Flag any non-default (non-zero) CSR configuration. Also check for AMFI (Apple Mobile File Integrity) policy overrides.
- **MITRE ATT&CK**: T1562.001 (Impair Defenses: Disable or Modify Tools), T1553.006 (Subvert Trust Controls: Code Signing Policy Modification)

##### D7. `walk_endpoint_security`
- **File**: `crates/memf-macos/src/endpoint_security.rs`
- **Forensic value**: The EndpointSecurity framework (ES) replaced the deprecated kauth/OpenBSM interfaces. Attackers may: unregister ES clients, crash the ES subsystem, or exploit ES client vulnerabilities. Detecting ES bypass is critical.
- **Detection approach**: Enumerate registered ES clients in kernel memory. For each: extract client process, subscribed event types, and mute sets. Flag: (a) expected ES clients (EDR agents) that are missing, (b) ES clients with broad `es_mute_set` entries (muting their own process or attacker processes from monitoring), (c) ES event types with no subscribers (monitoring gaps).
- **MITRE ATT&CK**: T1562.001 (Impair Defenses: Disable or Modify Tools)

##### D8. `walk_iokit_drivers`
- **File**: `crates/memf-macos/src/iokit_drivers.rs`
- **Forensic value**: IOKit drivers are the macOS equivalent of Windows device drivers. Malicious IOKit drivers or IOKit client abuse can provide kernel-level access.
- **Detection approach**: Walk the IORegistry plane starting from `IORegistryEntry::getRegistryRoot()`. Enumerate all driver classes, their properties, and user clients. Flag: (a) IOKit drivers not matching known Apple driver classes, (b) IOUserClient connections from unexpected processes (e.g., a user process directly communicating with a disk controller driver), (c) drivers with unusual matching dictionaries.
- **MITRE ATT&CK**: T1547.006 (Boot or Logon Autostart Execution: Kernel Modules and Extensions)

##### D9. `walk_macos_process`
- **File**: `crates/memf-macos/src/process.rs`
- **Forensic value**: Core process enumeration for macOS, walking both Mach task structures and BSD `proc` structures.
- **Detection approach**: Walk `allproc` list (BSD proc list) and `tasks` queue (Mach task list). Cross-reference for hidden processes. Extract: PID, PPID, UID, executable path, code signature info, sandbox profile, and entitlements.
- **MITRE ATT&CK**: T1057 (Process Discovery)

##### D10. `walk_macos_network`
- **File**: `crates/memf-macos/src/network.rs`
- **Forensic value**: Network connection enumeration from XNU kernel structures.
- **Detection approach**: Walk `tcbinfo`/`udbinfo` hash tables (same BSD socket layer as FreeBSD). Extract: local/remote addresses, state, owning PID, send/receive buffer contents. Flag connections matching IOC patterns.
- **MITRE ATT&CK**: T1071 (Application Layer Protocol)

### Container/Cloud-Native Forensics

Extensions to `memf-linux` for container-aware analysis.

#### D11. `walk_docker_layers`
- **File**: `crates/memf-linux/src/docker_layers.rs`
- **Forensic value**: Docker container overlay filesystem layers reveal: image provenance, runtime modifications (files written after container start), and evidence of container escape (writes to lower layers).
- **Detection approach**: Walk overlay filesystem mount structures. For each overlay mount: extract lower dirs (image layers), upper dir (container writable layer), and merged view. Identify: (a) files in upper dir that shadow lower-dir binaries (trojanized replacements), (b) SUID binaries created in upper dir, (c) device files created in upper dir (potential escape vector).
- **MITRE ATT&CK**: T1610 (Deploy Container), T1611 (Escape to Host)

#### D12. `walk_k8s_pod`
- **File**: `crates/memf-linux/src/k8s_pod.rs`
- **Forensic value**: Kubernetes pod forensics from host memory. Identifies pod boundaries, service account tokens, and inter-pod communication.
- **Detection approach**: Identify Kubernetes-managed containers by: (a) cgroup paths containing `/kubepods/`, (b) environment variables (`KUBERNETES_SERVICE_HOST`, `KUBERNETES_PORT`), (c) mounted service account tokens (`/var/run/secrets/kubernetes.io/`). Extract and decode service account JWTs from process memory. Flag: (a) pods with `hostPID`/`hostNetwork`/`hostIPC` (security boundaries weakened), (b) service account tokens with cluster-admin privileges, (c) pods running as root (UID 0).
- **MITRE ATT&CK**: T1552.007 (Unsecured Credentials: Container API), T1611 (Escape to Host)

#### D13. `walk_oci_runtime`
- **File**: `crates/memf-linux/src/oci_runtime.rs`
- **Forensic value**: OCI runtimes (runc, crun, kata) manage container lifecycle. Runtime process state reveals container configurations including security profiles.
- **Detection approach**: Identify OCI runtime processes (`runc`, `crun`). Extract the OCI runtime spec (`config.json`) from process memory or `/run/` filesystem. Parse: (a) seccomp profiles (which syscalls are allowed), (b) capabilities granted, (c) namespace configuration, (d) mount propagation settings. Flag containers with privileged mode, all capabilities, or no seccomp profile.
- **MITRE ATT&CK**: T1610 (Deploy Container), T1611 (Escape to Host)

#### D14. `walk_ebpf_container_escape`
- **File**: `crates/memf-linux/src/ebpf_container_escape.rs`
- **Forensic value**: eBPF programs can be used for container escape when `CAP_BPF` or `CAP_SYS_ADMIN` is available. This extends the existing `ebpf_progs` walker with container-escape-specific heuristics.
- **Detection approach**: Cross-reference eBPF programs (from existing walker) with container context. Flag: (a) eBPF programs loaded by containerized processes (non-init PID namespace), (b) `BPF_PROG_TYPE_KPROBE`/`BPF_PROG_TYPE_TRACEPOINT` programs from containers (kernel instrumentation from container context), (c) eBPF programs accessing `bpf_probe_read_kernel` helper from container context (reading host kernel memory).
- **MITRE ATT&CK**: T1611 (Escape to Host), T1014 (Rootkit)

### Implementation Plan

| Phase | Component | Effort | Dependencies |
|-------|-----------|--------|--------------|
| 1 | `memf-macos` crate skeleton + `WalkerPlugin` trait impl | 1 week | None |
| 2 | `walk_macos_process` + `walk_macos_network` (core walkers) | 2 weeks | Phase 1 |
| 3 | `walk_mach_ports` + `walk_sip_status` | 2 weeks | Phase 2 |
| 4 | `walk_kext_forensics` + `walk_iokit_drivers` | 2 weeks | Phase 2 |
| 5 | `walk_dyld_cache` + `walk_launchd_persistence` | 2 weeks | Phase 2 |
| 6 | `walk_xpc_services` + `walk_endpoint_security` | 2 weeks | Phase 3 |
| 7 | Container walkers (Docker/K8s/OCI/eBPF-escape) in `memf-linux` | 3 weeks | None (extends existing crate) |

---

## Implementation Sequencing

### Phase 1: Foundation (Weeks 1-4)
**Focus**: High-impact walkers + correlation model

1. Implement Priority 1 Linux walkers: `io_uring`, `vdso_tamper`, `proc_hidden`, `user_ns_escalation` (4 walkers)
2. Implement Priority 1 Windows walkers: `apc_injection`, `clr_heap`, `fiber_fls`, `dkom_detect` (4 walkers)
3. Define `ForensicEvent` model in `memf-correlate` crate skeleton
4. Add `into_forensic_events()` trait to existing walkers (start with top 10)

**Rationale**: These 8 walkers cover the most actively exploited gaps (io_uring rootkits, .NET in-memory execution, APC injection, DKOM). The correlation model enables all subsequent integration work.

### Phase 2: Extended Coverage + Export (Weeks 5-10)
**Focus**: Priority 2 walkers + output layer

1. Implement Priority 2 Linux walkers: `netlink_audit`, `udev_netlink`, `timerfd_signalfd`, `shared_mem_anomaly`, `container_breakout` (5 walkers)
2. Implement Priority 2 Windows walkers: `tls_callbacks`, `section_object`, `job_object`, `cfg_bypass`, `wow64_anomaly`, `ntsetsysinfo` (6 walkers)
3. Build `memf-export` with JSON/CSV, MITRE ATT&CK mapping, and STIX 2.1 export
4. Implement threat scoring engine and process tree correlator

**Rationale**: Broadens detection surface while enabling actionable output. STIX 2.1 and ATT&CK mapping provide immediate integration value for SOC teams.

### Phase 3: Advanced Detection + YARA (Weeks 11-16)
**Focus**: Priority 3 walkers + YARA synthesis + lateral movement

1. Implement Priority 3 walkers: `msr_forensics`, `fuse_abuse`, `landlock`, `token_escalation_chain`, `appcontainer_escape`, `wsl_artifacts`, `heap_spray`, `cpu_pinning`, `supply_chain` (9 walkers)
2. YARA synthesis engine
3. Sigma rule generation
4. Lateral movement detector in correlation engine
5. SARIF + HTML report output

**Rationale**: Priority 3 walkers are higher complexity but target advanced adversary techniques. YARA synthesis enables sharing discovered IOCs across the broader DFIR community.

### Phase 4: macOS + Container (Weeks 17-26)
**Focus**: New platform support

1. `memf-macos` crate with core walkers (process, network, Mach ports, SIP status)
2. Extended macOS walkers (kext, IOKit, dyld, launchd, XPC, EndpointSecurity)
3. Container-aware walkers in `memf-linux` (Docker layers, K8s pod, OCI runtime, eBPF escape)
4. Velociraptor VQL artifact generation

**Rationale**: macOS and container support extend the tool's applicability to the full modern enterprise environment. Saved for last because it requires the most new infrastructure (XNU struct definitions, Mach-O parsing).

### Summary Timeline

| Phase | Weeks | New Walkers | New Crates | Key Deliverables |
|-------|-------|-------------|------------|------------------|
| 1 | 1-4 | 8 | `memf-correlate` (skeleton) | Priority 1 walkers, ForensicEvent model |
| 2 | 5-10 | 11 | `memf-export` | Priority 2 walkers, STIX/ATT&CK/JSON output |
| 3 | 11-16 | 9 | — | Priority 3 walkers, YARA/Sigma, lateral movement |
| 4 | 17-26 | 14 | `memf-macos` | macOS forensics, container forensics, VQL |
| **Total** | **26** | **42** | **3 new crates** | Full DFIR enhancement suite |

---

## Appendix: Walker Inventory Additions

### `crates/memf-linux/src/` (13 new walkers)
| # | File | Walker | Priority |
|---|------|--------|----------|
| 1 | `io_uring.rs` | `walk_io_uring` | P1 |
| 2 | `vdso_tamper.rs` | `walk_vdso_tamper` | P1 |
| 3 | `proc_hidden.rs` | `walk_proc_hidden` | P1 |
| 4 | `user_ns_escalation.rs` | `walk_user_ns_escalation` | P1 |
| 5 | `netlink_audit.rs` | `walk_netlink_audit` | P2 |
| 6 | `udev_netlink.rs` | `walk_udev_netlink` | P2 |
| 7 | `timerfd_signalfd.rs` | `walk_timerfd_signalfd` | P2 |
| 8 | `shared_mem_anomaly.rs` | `walk_shared_mem_anomaly` | P2 |
| 9 | `container_breakout.rs` | `walk_container_breakout` | P2 |
| 10 | `msr_forensics.rs` | `walk_msr_forensics` | P3 |
| 11 | `fuse_abuse.rs` | `walk_fuse_abuse` | P3 |
| 12 | `landlock.rs` | `walk_landlock` | P3 |
| 13 | `cpu_pinning.rs` | `walk_cpu_pinning` | P3 |

### `crates/memf-windows/src/` (15 new walkers)
| # | File | Walker | Priority |
|---|------|--------|----------|
| 1 | `apc_injection.rs` | `walk_apc_injection` | P1 |
| 2 | `clr_heap.rs` | `walk_clr_heap` | P1 |
| 3 | `fiber_fls.rs` | `walk_fiber_fls` | P1 |
| 4 | `dkom_detect.rs` | `walk_dkom_detect` | P1 |
| 5 | `tls_callbacks.rs` | `walk_tls_callbacks` | P2 |
| 6 | `section_object.rs` | `walk_section_object` | P2 |
| 7 | `job_object.rs` | `walk_job_object` | P2 |
| 8 | `cfg_bypass.rs` | `walk_cfg_bypass` | P2 |
| 9 | `wow64_anomaly.rs` | `walk_wow64_anomaly` | P2 |
| 10 | `ntsetsysinfo.rs` | `walk_ntsetsysinfo` | P2 |
| 11 | `token_escalation_chain.rs` | `walk_token_escalation_chain` | P3 |
| 12 | `appcontainer_escape.rs` | `walk_appcontainer_escape` | P3 |
| 13 | `wsl_artifacts.rs` | `walk_wsl_artifacts` | P3 |
| 14 | `heap_spray.rs` | `walk_heap_spray` | P3 |
| 15 | `supply_chain.rs` | `walk_supply_chain` | P3 |

### `crates/memf-macos/src/` (10 new walkers)
| # | File | Walker | Priority |
|---|------|--------|----------|
| 1 | `process.rs` | `walk_macos_process` | P1 |
| 2 | `network.rs` | `walk_macos_network` | P1 |
| 3 | `mach_ports.rs` | `walk_mach_ports` | P1 |
| 4 | `sip_status.rs` | `walk_sip_status` | P1 |
| 5 | `kext_forensics.rs` | `walk_kext_forensics` | P2 |
| 6 | `iokit_drivers.rs` | `walk_iokit_drivers` | P2 |
| 7 | `dyld_cache.rs` | `walk_dyld_cache` | P2 |
| 8 | `launchd_persistence.rs` | `walk_launchd_persistence` | P2 |
| 9 | `xpc_services.rs` | `walk_xpc_services` | P3 |
| 10 | `endpoint_security.rs` | `walk_endpoint_security` | P3 |

### `crates/memf-linux/src/` (4 container walkers, additive to above)
| # | File | Walker | Priority |
|---|------|--------|----------|
| 1 | `docker_layers.rs` | `walk_docker_layers` | P2 |
| 2 | `k8s_pod.rs` | `walk_k8s_pod` | P2 |
| 3 | `oci_runtime.rs` | `walk_oci_runtime` | P2 |
| 4 | `ebpf_container_escape.rs` | `walk_ebpf_container_escape` | P2 |

### New Crates
| Crate | Purpose |
|-------|---------|
| `memf-correlate` | Cross-artifact correlation engine, threat scoring, timeline, lateral movement |
| `memf-export` | STIX 2.1, MITRE ATT&CK, YARA synthesis, Sigma, SARIF, JSON/CSV/HTML |
| `memf-macos` | macOS XNU kernel memory forensic walkers |
