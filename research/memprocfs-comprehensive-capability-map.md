# MemProcFS Comprehensive Capability Map

> **Author**: Ulf Frisk | **License**: AGPL-3.0 (core), proprietary plugins
> **Latest Version**: v5.17.0 (2026-02-22) | **GitHub Stars**: ~4.1k
> **Platforms**: Windows, Linux (x64, aarch64), macOS (Apple Silicon only)
> **Limitation**: Analyzes Windows memory images ONLY (not Linux/macOS memory)

---

## 1. Supported Memory Dump Formats (via LeechCore)

| Format | Extension | Notes |
|--------|-----------|-------|
| Raw linear memory dump | `.raw`, `.bin`, `.mem` | Default if no header detected; min 16MB |
| Microsoft Full Crash Dump | `.dmp` | Includes Active Memory and Full Bitmap variants |
| Windows Hibernation File | `hiberfil.sys` | Win10+ only |
| Full ELF Core Dump | `.elf`, `.core` | Used by VirtualBox |
| LiME v1 Dump | `.lime` | Common Linux acquisition format |
| VMware Memory Save | `.vmem` + `.vmss`/`.vmsn` | Both files needed for full parsing |
| Proxmox Memory Dump | | Added in recent releases |
| Hyper-V Saved State | `.bin` / `.vsv` | Via dedicated LeechCore device |

**File options**: Files default to read-only static mode. Can override with `volatile=1` for live/changing files and `rw=1` for read-write mode.

---

## 2. Physical Memory Acquisition Methods (LeechCore Devices)

### 2.1 Hardware-Based (PCIe DMA)

| Device | Interface | Speed | 64-bit | PCIe TLP |
|--------|-----------|-------|--------|----------|
| ZDMA (FPGA) | Thunderbolt3 | 1000 MB/s | Yes | Yes |
| GBOX (FPGA) | OCuLink | 400 MB/s | Yes | Yes |
| LeetDMA (FPGA) | USB-C | 190 MB/s | Yes | Yes |
| CaptainDMA M2 (FPGA) | USB-C | 190 MB/s | Yes | Yes |
| CaptainDMA 4.1th (FPGA) | USB-C | 190 MB/s | Yes | Yes |
| CaptainDMA 75T (FPGA) | USB-C | 200 MB/s | Yes | Yes |
| CaptainDMA 100T (FPGA) | USB-C | 220 MB/s | Yes | Yes |
| AC701/FT601 (FPGA) | USB3 | ~150 MB/s | Yes | Yes |
| USB3380 | USB3 | Slower | 4GB native* | No |

*USB3380 reads only 4GB natively; full memory requires kernel module (KMD) injection.

FPGA devices support full read-write access to physical memory. Linux FPGA caps at ~90 MB/s vs ~150 MB/s on Windows.

### 2.2 Software-Based

| Device | Type | Volatile | Write | Linux |
|--------|------|----------|-------|-------|
| File (all formats above) | File | No | No | Yes |
| WinPMEM | Driver-based live | Yes | No | No |
| DumpIt /LIVEKD | Comae live memory | Yes | No | No |
| LiveKd | Live kernel debug | Yes | No | No |
| LiveCloudKd | Hyper-V VM introspection | Yes | Yes | No |
| QEMU | VM live memory | Yes | Yes | No |
| VMware | VM live memory | Yes | Yes | No |
| TotalMeltdown | CVE-2018-1038 exploit | Yes | Yes | No |
| Hyper-V Saved State | VM saved state file | No | No | No |
| FPGA/RawUDP | Network-attached FPGA | Yes | Yes | Yes |
| iLO/RawTCP | HP iLO BMC interface | Yes | No | Yes |
| libmicrovmi | Hypervisor-agnostic (Xen, KVM, VirtualBox, QEMU) | Yes | Varies | Yes |

### 2.3 Remote Acquisition (LeechAgent)

- Windows-only agent service for remote memory acquisition
- Connection secured with mutually-authenticated Kerberos by default
- Compressed data transfer (works over high-latency, low-bandwidth links)
- Authenticates against Local Administrators group membership
- Supports remote Python script execution on the agent
- Linux LeechAgent support via gRPC added in v5.15 (LeechCore v2.21)

---

## 3. Virtual Filesystem (FUSE/Dokany) — Complete Directory Tree

The VFS is the core interface. On Windows it mounts via Dokany; on Linux via FUSE. Everything is also accessible via API without mounting.

### 3.1 Root-Level Directories

```
/
├── conf/                   # Configuration & status
├── forensic/               # Forensic sub-system (batch analysis)
│   ├── csv/                # CSV export of all forensic data
│   ├── files/              # Kernel pool + handle file recovery
│   ├── findevil/           # FindEvil malware detection results
│   ├── json/               # JSON export of forensic data
│   ├── ntfs/               # NTFS MFT reconstruction from memory
│   ├── prefetch/           # Windows Prefetch file parsing
│   ├── timeline/           # Multi-source activity timelines
│   ├── web/                # Web browser artifact extraction
│   └── yara/               # YARA scan results
├── misc/                   # Miscellaneous system modules
│   ├── bitlocker/          # BitLocker key recovery
│   ├── eventlog/           # Windows Event Log (.evtx) extraction
│   ├── phys2virt/          # Physical-to-virtual address translation
│   ├── procinfo/           # Process information summary
│   ├── search/             # Memory search engine
│   │   ├── bin/            # Binary pattern search
│   │   └── yara/           # Per-process YARA scanning
│   └── view/               # Memory viewer
├── name/                   # Processes listed by name
├── pid/                    # Processes listed by PID
├── registry/               # Full Windows registry browsing
├── sys/                    # System-wide information
│   ├── certificates/       # System certificates in memory
│   ├── drivers/            # Loaded kernel drivers
│   ├── memory/             # Physical memory map & info
│   ├── net/                # Active network connections
│   ├── objects/            # Named kernel object manager entries
│   ├── pool/               # Kernel pool allocations & tags
│   ├── proc/               # System-wide process listing
│   ├── services/           # Windows services enumeration
│   ├── syscall/            # System call table (SSDT)
│   ├── sysinfo/            # OS version, build, hostname, etc.
│   ├── tasks/              # Scheduled tasks
│   └── users/              # User account information
└── vm/                     # Detected virtual machines (hidden by default)
    └── <vm-name>/          # Full recursive MemProcFS mount per VM
```

### 3.2 Per-Process Files (under `/name/<proc>/` or `/pid/<PID>/`)

#### Base Files
| File | Description |
|------|-------------|
| `dtb.txt` | Directory Table Base (CR3) in physical address space (writable) |
| `dtb-kernel.txt` | Kernel-mode DTB (if different from dtb.txt) |
| `dtb-user.txt` | User-mode DTB |
| `memory.vmem` | Full virtual memory of the process as a flat file |
| `name.txt` | Process name (max 15 chars) |
| `name-long.txt` | Complete process name |
| `pid.txt` | Process ID |
| `ppid.txt` | Parent Process ID |
| `state.txt` | EPROCESS state (0 = active) |
| `time-create.txt` | Process creation timestamp |
| `time-exit.txt` | Process exit timestamp (terminated only) |
| `win-cmdline.txt` | Command line arguments |
| `win-curdir.txt` | Current working directory |
| `win-environment.txt` | Environment variables |
| `win-eprocess.txt` | Virtual address of EPROCESS struct |
| `win-path.txt` | Kernel path of the process executable |
| `win-peb.txt` | Virtual address of PEB |
| `win-peb32.txt` | 32-bit PEB (WoW64 processes) |
| `win-title.txt` | Window title |

#### Sub-Directories
| Directory | Contents |
|-----------|----------|
| `console/` | Console output buffer recovery |
| `files/handles/` | Files reconstructed from open process file handles |
| `files/modules/` | Reconstructed PE modules (.exe, .dll, .sys) |
| `files/vads/` | Files reconstructed from VAD entries |
| `handles/` | Open handles (files, registry keys, mutexes, etc.) |
| `heaps/` | Process heap information |
| `memmap/` | Detailed memory map (verbose VAD with page-level info) |
| `minidump/` | Auto-generated process minidump |
| `modules/` | Loaded modules with full details (see below) |
| `phys2virt/` | Physical-to-virtual address lookup |
| `procstruct/` | Raw kernel structures (EPROCESS, etc.) |
| `py/` | Python plugin root for per-process plugins |
| `search/bin/` | Binary pattern search in process memory |
| `search/yara/` | YARA rule scanning in process memory |
| `threads/` | Thread listing with details |
| `token/` | Process security token information |
| `virt2phys/` | Virtual-to-physical address translation |
| `vmemd/` | Virtual memory descriptor information |

#### Module Detail Files (under `modules/<module>/`)
| File | Description |
|------|-------------|
| `base.txt` | Base virtual address |
| `debuginfo.txt` | PDB debug information |
| `dirdata.txt` | PE data directories |
| `entry.txt` | Entry point address |
| `export/` | Exported functions |
| `import/` | Imported functions |
| `pefile.dll` | Reconstructed PE file |
| `sections.txt` | PE section information |
| `size.txt` | Module size |
| `versioninfo.txt` | Version information |

---

## 4. FindEvil — Malware Detection Engine

**Requires**: `-forensic` mode (levels 1-4) | **OS Target**: 64-bit Windows 10/11 only | **Scope**: User-mode malware only

### 4.1 Core Detection Types

| Detection | Severity | Description |
|-----------|----------|-------------|
| `PE_INJECT` | CRITICAL | Valid PE (DLL/EXE) in private (non-image) VAD with executable pages |
| `PEB_MASQ` | HIGH | PEB masquerading — altered process name/path in PEB |
| `PE_NOLINK` | HIGH | DLL in image VAD but missing from PEB/Ldr module lists (cf. Volatility ldrmodules) |
| `PE_PATCHED` | HIGH | Executable pages modified post-load (detected via prototype PTE analysis) |
| `PE_HDR_SPOOF` | MEDIUM | PE header employs known spoofing technique |
| `PROC_NOLINK` | CRITICAL | Process missing from EPROCESS doubly-linked list (DKOM unlinking) |
| `PROC_BASEADDR` | HIGH | Process hollowing (PEB.ImageBaseAddress != EPROCESS.SectionBaseAddress) |
| `PROC_PARENT` | MEDIUM | Well-known process with unexpected parent PID |
| `PRIVATE_RWX` | HIGH | Private memory region with RWX permissions (code injection indicator) |
| `PRIVATE_RX` | MEDIUM | Private memory with RX permissions (JIT may cause FPs) |
| `NOIMAGE_RWX` | HIGH | Non-image memory with RWX permissions |
| `NOIMAGE_RX` | MEDIUM | Non-image memory with RX permissions |
| `UM_APC` | HIGH | User-mode APC hook detected (common injection technique) |
| `HIGH_ENTROPY` | MEDIUM | Memory region with high entropy (packed/encrypted payloads) |
| `AV_DETECT` | VARIES | Windows Defender detection from the analyzed system |
| `TIME_CHANGE` | LOW | System clock set backwards before boot time |
| `LOW_ALIGN_PE` | MEDIUM | Low Alignment PE file (everything mapped into single section) |

### 4.2 Thread-Based Detections (THREAD_*)

| Sub-Type | Description |
|----------|-------------|
| `NO_IMAGE` | Thread not started in image memory |
| `PRIVATE_MEMORY` | Thread started in private memory |
| `BAD_MODULE` | Thread started in module without legitimate entry point |
| `LOAD_LIBRARY` | Thread starting point is kernel32.dll!LoadLibrary |
| `SYSTEM_IMPERSONATION` | Thread impersonates SYSTEM token |
| `NO_RTLUSERTHREADSTART` | Thread startup is not ntdll!RtlUserThreadStart |

### 4.3 YARA-Based Detections (YR_*)

Requires `-license-accept-elastic-license-2-0` to enable built-in Elastic Security rules.

| Type | Description |
|------|-------------|
| `YR_TROJAN` | Trojan/malware match |
| `YR_VULNDRIVER` | Known vulnerable driver (BYOVD) |
| `YR_HACKTOOL` | Offensive security tool |
| `YR_EXPLOIT` | Exploit code |
| `YR_SHELLCODE` | Shellcode patterns |
| `YR_ROOTKIT` | Rootkit signatures |
| `YR_RANSOMWARE` | Ransomware indicators |
| `YR_WIPER` | Wiper malware |
| `YR_BACKDOOR` | Backdoor/RAT (may be legit remote management) |
| `YR_GENERIC` | Other Yara rule classes |

### 4.4 FindEvil Output Files

| File | Description |
|------|-------------|
| `findevil.txt` | Main results with all detections |
| `readme.txt` | README with detection type explanations |
| `yara.txt` | Detailed YARA detection information |
| `yara_rules.txt` | The specific YARA rules that triggered |

---

## 5. Forensic Sub-System (Batch Analysis)

Enabled via `-forensic <1-4>`:

| Level | Behavior |
|-------|----------|
| 1 | In-memory only SQLite database |
| 2 | Temporary SQLite database (deleted on exit) |
| 3 | Temporary SQLite database (kept on exit) |
| 4 | Well-known path SQLite database (kept on exit) |

Reads the entire dump sequentially in one pass, performs multiple analyses in parallel, stores results in SQLite.

### 5.1 Forensic Modules

| Module | Description |
|--------|-------------|
| `forensic/csv/` | CSV export of: network, NTFS MFT, process, registry, scheduled tasks, threading, web timelines |
| `forensic/json/` | JSON export of all forensic data |
| `forensic/files/` | File recovery from kernel pool + process handles |
| `forensic/findevil/` | FindEvil malware detection (see Section 4) |
| `forensic/ntfs/` | NTFS MFT reconstruction; small files may be recoverable from MFT resident data |
| `forensic/prefetch/` | Windows Prefetch file parsing (execution history) |
| `forensic/timeline/` | Multi-source timelines: process, registry, NTFS, threads, network, tasks, web |
| `forensic/web/` | Browser artifact extraction |
| `forensic/yara/` | System-wide YARA scan results |

### 5.2 Timeline Types Generated

- NTFS MFT timeline (file creation/modification/access)
- Process timeline (creation/exit)
- Registry timeline (key last-write times)
- Thread timeline
- Network timeline
- Scheduled Tasks timeline
- Web activity timeline
- **Joined "super" timeline** combining all sources

---

## 6. Symbol Server Integration (PDB)

- Downloads PDB files from Microsoft Symbol Server automatically
- First-run EULA acceptance popup (or `-disable-symbolserver-confirm`)
- Local symbol cache directory configurable via `conf/config_symbolcache.txt`
- Symbol server URL configurable via `conf/config_symbolserver.txt`
- Manual PDB download supported for air-gapped/offline systems (Windows only)
- PDB sub-system provides kernel structure offsets (e.g., `_EPROCESS.Token`)
- Exposed via API: `VmmPdb.symbol_address()`, `VmmPdb.type_size()`, `VmmPdb.type_child_offset()`

---

## 7. API Capabilities

### 7.1 Supported Languages

| Language | Distribution | Platform |
|----------|-------------|----------|
| C/C++ | `vmmdll.h` header | Windows, Linux, macOS |
| C# | NuGet `Vmmsharp` | Windows |
| Java | JAR | Windows, Linux |
| Python | pip `memprocfs` (CPython C extension) | Windows, Linux (x64, aarch64) |
| Rust | crate `memprocfs` on crates.io | Windows, Linux, macOS |
| Go | 3rd-party `go-memprocfs` | Cross-platform |

**macOS limitation**: Only C/C++ and Rust APIs supported (no Python/Java yet).

### 7.2 Core API Functions

| Category | Key Functions |
|----------|--------------|
| **Initialization** | Open from file, FPGA, live memory, remote agent |
| **Physical Memory** | `memory.read()`, `memory.write()`, scatter read/write |
| **Virtual Memory** | `process.memory.read()`, `process.memory.write()`, scatter |
| **Scatter Read** | `mem_scatter()` — batch multiple reads into one efficient call; 1 byte to 1GB per read |
| **Process Enumeration** | `process_list()`, `process(pid)`, `process("name")` |
| **Module Info** | `process.module_list()`, exports, imports, sections, PE reconstruction |
| **Map Data** | PTE map, VAD map, heap map, thread map, handle map, unloaded module map |
| **Kernel Info** | Kernel modules, drivers, devices, PFN database |
| **Network** | Active network connections |
| **Registry** | `reg_hive_list()`, `reg_key()`, `reg_value()`, subkey enumeration, raw hive memory |
| **PDB Symbols** | Symbol address lookup, type sizes, struct member offsets |
| **Search** | Binary pattern search (up to 16M search terms), YARA scanning |
| **VFS Access** | `vfs.list()`, `vfs.read()`, `vfs.write()` — full filesystem access without mounting |
| **Virtual Machines** | VM enumeration, VM memory read, recursive sub-VM analysis |
| **Memory Callback** | Memory read callback API (C/C++ only, added v5.13) |
| **Callstack** | x64 user-mode callstack parsing (added v5.13) |
| **Logging** | Optional logging callback (added v5.17) |

### 7.3 Python-Specific API Classes

```
memprocfs (package)
  └── Vmm (base object)
        ├── VmmMap (info maps: net, users, services, pool, PFN, etc.)
        ├── VmmVfs (virtual file system access)
        ├── VmmKernel (kernel info)
        │     └── VmmPhysicalMemory
        ├── VmmProcess
        │     ├── VmmMap (process maps: VAD, PTE, heap, thread, handle, unloaded modules)
        │     ├── VmmVirtualMemory
        │     │     └── VmmScatterMemory
        │     └── VmmModule
        │           ├── VmmMap (module maps: data dirs, exports, imports, sections)
        │           └── VmmPdb (PDB debug symbols)
        ├── VmmVirtualMachine
        ├── VmmRegHive
        │     ├── VmmRegMemory (raw hive memory)
        │     ├── VmmRegKey
        │     └── VmmRegValue
        ├── RegUtil (registry utility helpers)
        └── CONSTANTS (FLAG_NOCACHE, FLAG_ZEROPAD_ON_FAIL, etc.)
```

### 7.4 Memory Read Flags

| Flag | Purpose |
|------|---------|
| `FLAG_NOCACHE` | Force read from acquisition device (bypass cache) |
| `FLAG_ZEROPAD_ON_FAIL` | Zero-pad failed reads instead of error |
| `FLAG_FORCECACHE_READ` | Force use of cache only |
| `FLAG_NOPAGING` | Do not retrieve from pagefile/compressed memory |
| `FLAG_NOPAGING_IO` | Skip paged memory that requires additional I/O |

---

## 8. Performance Features

| Feature | Description |
|---------|-------------|
| **Multi-threading** | Parallel analysis tasks during forensic mode; multi-threaded page table walking |
| **Read caches** | Transparent caching layer for repeated memory accesses |
| **Scatter Read/Write** | Batch multiple non-contiguous reads into one efficient device call (reduces latency) |
| **PTE quality threshold** | Configurable (`-debug-pte-quality-threshold`, default=32) for speed vs. accuracy tradeoff |
| **Sequential forensic scan** | Single-pass sequential read of entire dump with parallel analysis (cache-friendly) |
| **Cache refresh** | Force refresh of process list and all caches via API or conf files |
| **Compressed remote transfer** | LeechAgent uses compressed + encrypted Kerberos connections |
| **FPGA DMA throughput** | Up to 1000 MB/s with Thunderbolt3 ZDMA hardware |

---

## 9. Windows-Specific Features (Exhaustive)

### 9.1 Kernel & System

| Feature | Location |
|---------|----------|
| System info (OS version, build, hostname) | `sys/sysinfo/` |
| Loaded kernel drivers | `sys/drivers/` |
| Kernel device objects | `sys/objects/` |
| Named kernel objects (object manager) | `sys/objects/` |
| System call table (SSDT) | `sys/syscall/` |
| Kernel pool allocations & tags | `sys/pool/` |
| Physical memory map | `sys/memory/` |
| PFN (Page Frame Number) database | API only |
| System certificates in memory | `sys/certificates/` |

### 9.2 Process Analysis

| Feature | Location |
|---------|----------|
| Process enumeration (by PID, name) | `pid/`, `name/` |
| Full command lines | per-process `win-cmdline.txt` |
| Environment variables | per-process `win-environment.txt` |
| Current working directory | per-process `win-curdir.txt` |
| Window titles | per-process `win-title.txt` |
| EPROCESS struct access | per-process `win-eprocess.txt`, `procstruct/` |
| Process creation/exit timestamps | per-process time files |
| Process security tokens | per-process `token/` |
| DTB/CR3 override (writable) | per-process `dtb.txt` |
| User-mode callstack parsing | API (v5.13+) |

### 9.3 Memory Structures

| Feature | Location |
|---------|----------|
| Virtual Address Descriptors (VADs) | `memmap/`, `files/vads/` |
| Page Table Entries (PTEs) | `memmap/` (verbose) |
| Heap enumeration | `heaps/` |
| Handle table (files, keys, mutexes, etc.) | `handles/` |
| Thread listing with CPU registers | `threads/` |
| Minidump auto-generation | `minidump/` |
| Full virtual address space as flat file | `memory.vmem` |

### 9.4 Registry

| Feature | Location |
|---------|----------|
| Full registry hive enumeration | `registry/` |
| Browse keys and values | `registry/` (full path navigation) |
| Key last-write timestamps | Available on all keys |
| Raw hive memory access | API: `VmmRegHive.memory` |
| Orphan key/value recovery | Via registry API |
| MRUListEx expansion | `RegUtil.mrulistex_expand()` |
| `regsecrets` plugin (pypykatz) | NTLM hash extraction, mimikatz-like |

### 9.5 Network

| Feature | Location |
|---------|----------|
| Active network connections | `sys/net/` |
| DNS cache parsing | Added v5.15 |

### 9.6 Services & Tasks

| Feature | Location |
|---------|----------|
| Windows services enumeration | `sys/services/` |
| Scheduled tasks | `sys/tasks/` |

### 9.7 Event Logs

| Feature | Location |
|---------|----------|
| Windows Event Log extraction (.evtx) | `misc/eventlog/` |

### 9.8 Disk & Storage

| Feature | Location |
|---------|----------|
| BitLocker key recovery | `misc/bitlocker/` |
| NTFS MFT reconstruction from memory | `forensic/ntfs/` |
| File recovery from kernel pool | `forensic/files/` |
| File recovery from process handles | per-process `files/handles/` |
| File recovery from VADs | per-process `files/vads/` |
| PE module reconstruction | per-process `files/modules/` |
| Prefetch file parsing | `forensic/prefetch/` |

### 9.9 Virtual Machines (Hyper-V Focus)

| Feature | Details |
|---------|---------|
| Hyper-V VM detection & parsing | Full VMs, containers, sandboxes, WSL2 |
| Windows Hypervisor Platform VMs | VMware/VirtualBox running on Hyper-V |
| Secure Kernel / Credential Guard | Introspection of isolated secure kernel |
| Recursive MemProcFS mount | Each VM gets a full VFS under `/vm/<name>/` |
| VM detection from dump files | Parse VMs from host memory dumps |
| Live VM introspection | Via LiveCloudKd, VMware device |

---

## 10. Linux-Specific Features

| Feature | Details |
|---------|---------|
| MemProcFS runs on Linux | x64 and aarch64 (RPi4) |
| FUSE mount support | Mount VFS natively on Linux |
| Linux LeechAgent (gRPC) | Remote acquisition from Linux hosts (v5.15+) |
| FPGA DMA support on Linux | ~90 MB/s max (vs 150 MB/s on Windows) |
| libmicrovmi integration | Hypervisor-agnostic introspection (Xen, KVM, VirtualBox, QEMU) |

**Critical limitation**: MemProcFS cannot analyze Linux memory dumps. It only analyzes Windows memory images regardless of the host OS.

---

## 11. Unique Features (Competitive Differentiators)

These features distinguish MemProcFS from Volatility and other memory forensics tools:

### 11.1 Virtual Filesystem Paradigm
No other major memory forensics tool exposes all artifacts as a mountable filesystem. This enables:
- Point-and-click analysis with any file browser
- Use of standard tools (hex editors, grep, Python scripts, WinDbg, IDA Pro)
- Transparent per-process `memory.vmem` flat files for direct disassembly
- Auto-generated minidumps openable in debuggers

### 11.2 Live Read-Write Memory Access
Unique ability to both read AND write to live memory via:
- FPGA PCIe DMA hardware (up to 1000 MB/s)
- LiveCloudKd (Hyper-V VMs)
- QEMU and VMware live connections

### 11.3 Transparent VM Nesting
Detects and recursively mounts VMs as full MemProcFS instances under `/vm/`. No other tool provides this level of seamless VM introspection from a host dump.

### 11.4 NTFS MFT Reconstruction from Memory
Parses NTFS MFT entries from physical memory, recovers small files from MFT resident data, generates full file system trees with timestamps.

### 11.5 Remote Incident Response
LeechAgent enables:
- Secure remote memory analysis over Kerberos
- Compressed transfer over high-latency links
- Remote Python script execution
- Full MemProcFS analysis of remote machines

### 11.6 Integrated FindEvil Engine
Single-pass malware triage combining PTE analysis, VAD analysis, thread analysis, YARA scanning, and AV detection correlation — no equivalent exists in Volatility as a unified detection engine.

### 11.7 Scatter Read API
Unique performance API that batches multiple non-contiguous memory reads into a single device call, critical for FPGA DMA performance.

### 11.8 Full MemProcFS via SMB (tcp/445)
Remote filesystem access over standard SMB protocol — mount a remote machine's memory as a network share.

### 11.9 ARM64 Windows Memory Analysis
Support for analyzing ARM64 Windows memory dumps (Apple Silicon era), configurable via `-arch arm64`.

### 11.10 Automatic PDB Resolution
Seamless Microsoft Symbol Server integration for automatic kernel structure resolution — no manual ISF/symbol table generation needed (unlike Volatility).

### 11.11 Console Buffer Recovery
Per-process console output buffer extraction (`console/` directory) — unique to MemProcFS.

### 11.12 DNS Cache Parsing
Direct extraction of DNS resolver cache from memory (added v5.15).

---

## 12. Plugin Architecture

### 12.1 Core Plugins (Built-in)
All VFS directories are implemented as native C plugins internally. Source is in `vmm/modules/m_*.c`.

### 12.2 External Plugin Types

| Type | Language | Description |
|------|----------|-------------|
| Native plugins | C/C++ | Full access, highest performance |
| Native plugins | Rust | Full access via crate |
| Embedded plugins | Python | Loaded into MemProcFS Python subsystem |

### 12.3 Notable Non-Core Plugins (MemProcFS-plugins repo)

| Plugin | Description |
|--------|-------------|
| `pym_regsecrets` (pypykatz) | NTLM hash extraction, mimikatz-like credential recovery |

Disable Python plugins with `-disable-python`. Disable YARA with `-disable-yara`.

---

## 13. Version History (Recent)

| Version | Date | Key Additions |
|---------|------|---------------|
| v5.9.0 | 2024-03-03 | — |
| v5.10.0 | 2024-07-11 | — |
| v5.11.4 | 2024-09-08 | Windows 11 24H2 support, named _SECTION objects in VAD map, sysinfo module, eventlog module, prefetch parsing, binary search API (16M terms) |
| v5.12.0 | 2024-10-09 | New Kernel Objects/Drivers/Devices APIs, FindEvil signature updates |
| v5.13.0 | 2024-11-26 | Console module, file recovery improvements (sizes, signing info), memory callback API (C/C++), x64 user-mode callstack parsing |
| v5.14.0 | 2025-01-16 | macOS support (Apple Silicon), Linux clang build support |
| v5.15.0 | 2025-06-22 | Linux LeechAgent (gRPC), FindEvil HIGH_ENTROPY detection, DNS cache parsing |
| v5.16.0 | 2025-10-05 | Windows 11 25H2 support |
| v5.17.0 | 2026-02-22 | Windows 11 26H1 support, improved registry parsing, refresh API options, logging callback API, non-ASCII file path support |

---

## 14. Command Line Options (Complete)

| Option | Description |
|--------|-------------|
| `-device <path\|type>` | Memory source (file path, `fpga`, `pmem`, `vmware`, etc.) |
| `-remote <host>` | Connect to remote LeechAgent |
| `-forensic <1-4>` | Enable forensic mode at specified level |
| `-arch <x86\|x86pae\|x64\|arm64>` | CPU architecture override |
| `-disable-python` | Disable Python plugin subsystem |
| `-disable-yara` | Disable YARA scanning subsystem |
| `-disable-symbolserver-confirm` | Skip symbol server EULA popup |
| `-license-accept-elastic-license-2-0` | Enable Elastic YARA rules |
| `-debug-pte-quality-threshold <N>` | PTE quality threshold (default 32) |
| `-vm` | Enable VM detection |
| `-vm-basic` | Basic VM detection |
| `-vm-nested` | Nested VM detection |
| `-mount <letter:>` | Mount drive letter (Windows/Dokany) |
| `-mount <path>` | FUSE mount point (Linux) |

---

## 15. Ecosystem & Companion Projects

| Project | Description |
|---------|-------------|
| [MemProcFS](https://github.com/ufrisk/MemProcFS) | Core memory analysis engine |
| [LeechCore](https://github.com/ufrisk/LeechCore) | Physical memory acquisition library |
| [PCILeech](https://github.com/ufrisk/pcileech) | PCIe DMA attack toolkit |
| [pcileech-fpga](https://github.com/ufrisk/pcileech-fpga) | FPGA firmware for DMA devices |
| [MemProcFS-plugins](https://github.com/ufrisk/MemProcFS-plugins) | Non-core plugin repository |
| [MemProcFS-Analyzer](https://github.com/LETHAL-FORENSICS/MemProcFS-Analyzer) | Automated forensic analysis wrapper (3rd party) |
| [LiveCloudKd](https://github.com/gerhart01/LiveCloudKd) | Hyper-V live introspection |

---

## Sources

- [MemProcFS GitHub Repository](https://github.com/ufrisk/MemProcFS)
- [MemProcFS Wiki](https://github.com/ufrisk/MemProcFS/wiki)
- [MemProcFS Wiki - FindEvil](https://github.com/ufrisk/MemProcFS/wiki/FS_FindEvil)
- [MemProcFS Wiki - Command Line](https://github.com/ufrisk/MemProcFS/wiki/_CommandLine)
- [MemProcFS Wiki - VM](https://github.com/ufrisk/MemProcFS/wiki/VM)
- [MemProcFS Wiki - Forensic](https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic)
- [MemProcFS Wiki - Process](https://github.com/ufrisk/MemProcFS/wiki/FS_Process)
- [MemProcFS Wiki - Python API](https://github.com/ufrisk/MemProcFS/wiki/API_Python)
- [LeechCore GitHub Repository](https://github.com/ufrisk/LeechCore)
- [LeechCore Wiki - Device File](https://github.com/ufrisk/LeechCore/wiki/Device_File)
- [MemProcFS-plugins Repository](https://github.com/ufrisk/MemProcFS-plugins)
- [MemProcFS GitHub Releases](https://github.com/ufrisk/MemProcFS/releases)
- [MemProcFS Rust Crate (docs.rs)](https://docs.rs/memprocfs)
- [MemProcFS Python Package (PyPI)](https://pypi.org/project/memprocfs/)
- [Eric Capuano - VMware Memory Analysis with MemProcFS](https://blog.ecapuano.com/p/vmware-memory-analysis-with-memprocfs)
- [Pen Test Partners - Mounting Memory with MemProcFS](https://www.pentestpartners.com/security-blog/mounting-memory-with-memprocfs-for-advanced-memory-forensics/)
- [CyberEngage - FindEvil Plugin Analysis](https://medium.com/@cyberengage.org/part-3-code-injection-how-to-detect-it-and-finding-evil-in-memory-with-memprocfs-findevil-plugin-308e7024fefc)
- [Ulf Frisk on X - macOS support announcement](https://x.com/UlfFrisk/status/1879797821932724268)
