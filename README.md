[![Stars](https://img.shields.io/github/stars/SecurityRonin/memory-forensic?style=flat-square)](https://github.com/SecurityRonin/memory-forensic/stargazers)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/memory-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/memory-forensic/actions/workflows/ci.yml)
[![Rust 1.75+](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg)](#install)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

# memory-forensic

**Walk any memory dump. Find what's hidden. One binary, zero setup.**

`memory-forensic` is a Rust library and toolkit that reads LiME, AVML, Windows crash dumps, and six other formats, then walks processes, threads, modules, network connections, and injected memory — from a single static binary you compile once and copy anywhere.

```bash
cargo install memory-forensic
memf ps memdump.lime --symbols linux.json --tree
```

**[Full documentation →](https://securityronin.github.io/memory-forensic/)**

---

## Install

**Cargo**
```bash
cargo install memory-forensic
```

**From source**
```bash
git clone https://github.com/SecurityRonin/memory-forensic.git
cd memory-forensic
cargo build --release
./target/release/memf --help
```

---

## Quick Reference

```bash
# Show dump format and physical memory ranges
memf info memdump.dmp

# Process tree with threads and DLLs
memf ps memdump.dmp --symbols ntkrnlmp.json --tree --threads --dlls

# Network connections (json / csv / table)
memf net memdump.dmp --symbols ntkrnlmp.json --output json

# Kernel integrity checks (SSDT, IDT, callbacks, hooks)
memf check memdump.dmp --symbols ntkrnlmp.json --ssdt --callbacks

# Linux syscall hook and malfind scan
memf check memdump.lime --symbols linux.json --hooks --malfind

# String extraction with YARA rules
memf strings memdump.dmp --rules ./yara-rules/ --min-length 8

# Hash lookup against NSRL (known-good) and MalwareBazaar (known-bad)
memf hash memdump.dmp --lookup

# Extract framebuffer screenshot from live memory dump
memf framebuf memdump.dmp --symbols linux.json --png screen.png

# Recover files from tmpfs mounts + detect memfd fileless ELF execution
memf check memdump.lime --symbols linux.json --tmpfs-recovery --memfd

# Detect EDR bypass: direct syscalls, ETW patching, AMSI/DSE bypass
memf check memdump.dmp --symbols ntkrnlmp.json --direct-syscalls --etw-patch --amsi-bypass

# Novel kernel interface abuse: io_uring, netfilter hooks, perf_event
memf check memdump.lime --symbols linux.json --io-uring --netfilter --perf-event

# Cross-artifact ATT&CK correlation across all walkers
memf correlate memdump.dmp --symbols ntkrnlmp.json --output json
```

Symbol files are ISF JSON, compatible with Volatility 3 symbol packs.

---

## Verify kernel integrity — hooks invisible from the OS

```bash
# SSDT, IDT, ftrace, LSM, and kernel callback checks in one pass
memf check memdump.lime --symbols linux.json --hooks --idt --syscalls
```

```
[HOOK]  sys_call_table[59]  execve  → 0xffffffffc0a2f3d0  (outside kernel text)
[HOOK]  ftrace_ops[0]  target: vfs_read  → 0xffffffffc0a2f410  (module: libymv_ko)
[HOOK]  security_inode_getattr  → 0xffffffffc0a2f450  (LSM hook patched)
```

Three hook types — syscall table, ftrace, and LSM — all resolving into the same kernel module. Cross-referencing the module list confirms it is not in the known-good set.

---

## LD_PRELOAD rootkit behavioral analysis

Name-pattern matching misses recompiled or renamed rootkit variants. ELF dynamic symbol analysis catches them regardless of name:

```bash
memf check memdump.lime --symbols linux.json --elf-hooks
```

```
[ROOTKIT] /tmp/.x/libhider.so  signals=[elf.hooks.process_hiding, elf.hooks.pam_credential_theft]
  exports: readdir64, getdents64, pam_get_item, pam_authenticate
  MITRE: T1014 (Rootkit), T1556.003 (Modify Authentication Process)
  loaded in 100% of processes (23/23)

[ROOTKIT] /tmp/.x/libhider.so  .rodata match: "UID:%d:" (Father PAM hook format string, weight=90)
```

`memf-linux` scans every library mapped in process memory for:
- **Hook table matching** — 17 libc/syscall symbols known to be intercepted by rootkits (readdir64, getdents64, pam_get_item, write, …) classified against the forensicnomicon signal taxonomy
- **Libc shadow exports** — libraries that export a function with the same name as a libc symbol intercept all callers at link time
- **Father-class string artifacts** — format strings baked into `.rodata` (e.g. `UID:%d:`, `silly.txt`) that survive binary stripping and name changes
- **Global prevalence** — libraries loaded in ≥90% of processes are flagged as likely LD_PRELOAD injections

---

## DPAPI secrets and credential extraction

```bash
# Extract DPAPI master keys from LSASS g_MasterKeyCache linked list
memf check memdump.dmp --symbols ntkrnlmp.json --dpapi-keys

# Detect Chrome cookies (v10/v20 encrypted blobs) from heap memory
memf check memdump.dmp --symbols ntkrnlmp.json --browser-cookies
```

```
[DPAPI] GUID={A1B2C3D4-...}  blob_len=680  source=lsass.exe
[COOKIE] msedge.exe  domain=.github.com  name=user_session  value=secretvalue...
[COOKIE] chrome.exe  (v10-encrypted)  — key material required for decryption
```

The Windows credential walkers cover:
- **DPAPI master keys** — walks `g_MasterKeyCache` linked list in LSASS, extracts GUID + encrypted blob for every cached master key
- **Chrome v10/v20 cookies** — binary scan of Chromium heap for AES-GCM encrypted cookie blobs (prefix `v10`/`v20` + 12-byte nonce); decrypted when key material is available
- **SAM/NTLM hashes**, **Kerberos tickets**, **BitLocker keys**, **LSA secrets** — full credential suite

---

## Framebuffer screenshot extraction

```bash
memf framebuf memdump.dmp --symbols ntkrnlmp.json --png screen.png
```

Extracts the framebuffer from a live or hibernation memory dump and writes it as a PNG. Works on both Linux (DRM/KMS `drm_framebuffer` walker) and Windows (session framebuffer via `win32k` pool scan). Useful for capturing the screen state at the moment of acquisition without booting the image.

---

## Recover files that never touched disk

Attackers using tmpfs or `memfd_create(2)` leave no filesystem artifacts — the binary exists only in RAM.

```bash
# Recover inodes and file content from Linux tmpfs/ramfs mounts
memf check memdump.lime --symbols linux.json --tmpfs-recovery

# Detect ELF binaries running from anonymous memfd file descriptors
memf check memdump.lime --symbols linux.json --memfd
```

```
[TMPFS] /tmp/.x (dev=tmpfs)  3 inodes recovered
  inode 12: ELF x86_64  size=847KB  sha256=deadbeef...  (no disk copy)
  inode 13: config.sh   size=1.2KB  content recovered
  inode 14: keys.txt    size=512B   content recovered

[MEMFD] pid=2341 (python3)  fd=4  name=""  size=3.4MB  ELF x86_64
  No path on disk — binary executed entirely from anonymous memory.
  MITRE: T1620 (Reflective Code Loading)
```

tmpfs recovery walks the kernel `vfsmount` table and reconstructs inode content from page-cache pages. memfd detection walks every process's open file descriptor table and flags anonymous inodes created with `memfd_create(2)`.

---

## Detect EDR evasion and log suppression

Modern offensive tooling patches Windows security instrumentation in memory to evade detection without touching disk.

```bash
# Direct syscalls — Syswhispers/Hell's Gate bypass Win32 API entirely
memf check memdump.dmp --symbols ntkrnlmp.json --direct-syscalls

# ETW patching — log suppression via ret/xor at ETW write functions
memf check memdump.dmp --symbols ntkrnlmp.json --etw-patch

# AMSI bypass — script-scanning suppression via amsi.dll patch
memf check memdump.dmp --symbols ntkrnlmp.json --amsi-bypass

# DSE bypass — Driver Signature Enforcement disabled for unsigned drivers
memf check memdump.dmp --symbols ntkrnlmp.json --dse-bypass
```

```
[DIRECT-SYSCALL] powershell.exe (PID 4412)  stub at 0x7ff800a1000
  mov r10,rcx / mov eax,0x3c / syscall  — NtCreateThreadEx bypassing ntdll
  MITRE: T1055.012 (Process Injection: Process Hollowing)

[ETW-PATCH] svchost.exe (PID 1200)  EtwEventWrite → ret at offset +0
  Expected: 4C 8B DC  Got: C3 90 90  (patched to immediate return)
  MITRE: T1562.006 (Impair Defenses: Indicator Blocking)

[AMSI-BYPASS] powershell.exe (PID 4412)  AmsiScanBuffer → xor eax,eax / ret
  MITRE: T1562.001 (Impair Defenses: Disable or Modify Tools)

[DSE-BYPASS] g_CiEnabled=0  CipInitialize patch detected
  MITRE: T1014 (Rootkit), T1553.006 (Subvert Trust Controls)
```

---

## Novel Linux kernel interface abuse

Beyond classic syscall hooks, modern rootkits abuse newer kernel subsystems. `memory-forensic` covers all three:

```bash
memf check memdump.lime --symbols linux.json --io-uring --netfilter --perf-event
```

```
[IO_URING] pid=3311 (malware)  ring at 0x7f0000000000  ops=1024 pending
  SQPOLL thread pinned to cpu=0  — I/O continues without process context
  MITRE: T1071 (Application Layer Protocol)

[NETFILTER] NF_INET_PRE_ROUTING hook[0] → 0xffffffffc0b31240 (outside kernel text)
  Module not in module list — DKOM-hidden or manually unmapped
  MITRE: T1014 (Rootkit)

[PERF-EVENT] pid=1 (systemd)  type=HARDWARE  cpu=-1  overflow_handler patched
  → 0xffffffffc0b31500
  MITRE: T1056 (Input Capture)
```

---

## Container escape indicators

```bash
memf check memdump.lime --symbols linux.json --container-escape
```

```
[CONTAINER-ESCAPE] pid=8801 (bash)  shares host user namespace
  uid_map: 0 0 4294967295  (full host UID range — privileged mapping)
  cgroup: /  (host root cgroup, not namespaced)
  mount ns: host  (same as pid 1)
  MITRE: T1611 (Escape to Host)
```

Walks user, mount, PID, net, and cgroup namespaces for every process and flags processes that should be isolated but share host-level namespaces — the structural signature of a container escape regardless of how it was achieved.

---

## Cross-artifact ATT&CK correlation

`memf-correlate` joins findings from all walkers into a timeline, scores anomalies by severity, and maps each to MITRE ATT&CK techniques without running walkers one at a time:

```bash
memf correlate memdump.dmp --symbols ntkrnlmp.json --output json > findings.json
```

```json
{
  "technique": "T1055.012",
  "name": "Process Hollowing",
  "severity": "critical",
  "evidence": [
    { "source": "vad",       "detail": "svchost.exe VAD 0x140000–0x160000 RWX, no backing file" },
    { "source": "ldrmodules","detail": "module in VAD but absent from InLoadOrderList" },
    { "source": "iat_hooks", "detail": "CreateRemoteThread IAT entry patched → 0x14001a30" }
  ],
  "process": { "name": "svchost.exe", "pid": 1200, "ppid": 508 }
}
```

No other open-source memory forensics tool produces ATT&CK-tagged cross-artifact findings from raw memory. Process, network, module, hook, and credential walker results are correlated by process and time before scoring.

---

## Supported Memory Formats

| Format | Source | Auto-detected |
|---|---|---|
| LiME (`.lime`) | Linux kernel module | Yes |
| AVML v2 | Azure AVML | Yes |
| ELF Core | QEMU, `gcore` | Yes |
| Windows Crash Dump (`.dmp`) | DumpIt, WinDbg | Yes |
| Hiberfil.sys | Windows hibernate / fast startup | Yes |
| VMware State (`.vmss`, `.vmsn`) | VMware Workstation / ESXi | Yes |
| kdump / diskdump | `makedumpfile` | Yes |
| Raw / flat | Any fallback | Yes |

Format is detected from file headers — no flags required.

---

## What's Different

Every alternative either requires Python, is Windows-only, or is unmaintained.

| | memory-forensic | Volatility 3 | MemProcFS | Rekall |
|--|:-:|:-:|:-:|:-:|
| Runs on Linux / macOS | ✅ | ✅ | partial | ✅ |
| Single static binary | ✅ | — | — | — |
| ISF symbol pack compatible | ✅ | ✅ | — | — |
| Library API (use in your tools) | ✅ | — | ✅ | — |
| Linux + Windows walkers | ✅ | ✅ | Windows-first | ✅ |
| ELF behavioral rootkit analysis | ✅ | — | — | — |
| tmpfs / ramfs file recovery | ✅ | — | — | — |
| memfd fileless execution detection | ✅ | — | — | — |
| Direct syscall / EDR bypass detection | ✅ | — | — | — |
| ETW / AMSI / DSE bypass detection | ✅ | — | — | — |
| io_uring / netfilter / perf\_event abuse | ✅ | — | — | — |
| Container escape indicators | ✅ | — | — | — |
| Cross-artifact ATT&CK correlation | ✅ | — | — | — |
| Actively maintained | ✅ | ✅ | ✅ | — |
| Free & open source | ✅ | ✅ | ✅ | ✅ |

---

## Library Usage

```rust
use memf_format::open;
use memf_core::vas::{TranslationMode, VirtualAddressSpace};
use memf_core::object_reader::ObjectReader;
use memf_symbols::isf::IsfResolver;

// Open any supported format — detected from file headers
let dump = open("memdump.dmp")?;
let symbols = IsfResolver::from_file("ntkrnlmp.json")?;

// Walk the x86_64 4-level page table
let vas = VirtualAddressSpace::new(dump.clone(), TranslationMode::X64, cr3);
let reader = ObjectReader::new(vas, Box::new(symbols));

// Walk EPROCESS list
for proc in reader.eprocess_list()? {
    println!("{} (PID {})", proc.image_name()?, proc.pid()?);
}
```

---

## Crate Layout

<details>
<summary>Show crate layout</summary>

| Crate | Purpose |
|---|---|
| [`memf-format`](crates/memf-format/) | Format detection and physical memory providers. Parsers for LiME, AVML, ELF Core, Windows Crash Dump, hiberfil.sys, VMware state, kdump, and raw flat images. |
| [`memf-core`](crates/memf-core/) | Page table walking (x86_64 4-level/5-level, AArch64, x86 PAE/non-PAE), high-level `ObjectReader` for kernel struct traversal, pagefile access, LZO decompression. |
| [`memf-linux`](crates/memf-linux/) | Linux kernel walkers: `task_struct` process list, network connections, kernel modules, open files, eBPF programs, ftrace/IDT/syscall hook detection, namespace and cgroup enumeration, DKOM-hidden process detection, container escape indicators, **ELF dynamic symbol analysis and LD_PRELOAD rootkit behavioral fingerprinting**, **library global prevalence detection**, and ~45 additional walkers. |
| [`memf-windows`](crates/memf-windows/) | Windows NT kernel walkers: `EPROCESS`/`ETHREAD` enumeration, DLL and driver lists, handle tables, network sockets, pool tag scanning, callback tables, SSDT, ETW, clipboard, DNS cache, Kerberos tickets, **DPAPI master key extraction from LSASS `g_MasterKeyCache`**, **Chrome v10/v20 AES-GCM encrypted cookie detection**, BitLocker keys, SAM/NTLM hashes, injected memory detection, and ~55 additional walkers. |
| [`memf-dpapi`](crates/memf-dpapi/) | Windows DPAPI decryption: master key blob parsing, Chrome `Local State` key decryption, v10/v20 AES-GCM cookie value decryption. |
| [`memf-framebuffer`](crates/memf-framebuffer/) | Framebuffer screenshot extraction: Linux DRM/KMS `drm_framebuffer` walker and Windows session framebuffer scanner, output as PNG. |
| [`memf-strings`](crates/memf-strings/) | String extraction (ASCII, UTF-8, UTF-16LE) with regex classification into IoC categories: URLs, IP addresses, domains, registry keys, crypto wallet addresses, private keys, shell commands. |
| [`memf-symbols`](crates/memf-symbols/) | Symbol resolution from ISF JSON, BTF (Linux), and PDB files. Includes a symbol server client for on-demand PDB retrieval. |
| [`memf-correlate`](crates/memf-correlate/) | Cross-artifact correlation with MITRE ATT&CK technique tagging, process tree reconstruction, anomaly scoring, and timeline generation. |
| [`forensic-hashdb`](crates/forensic-hashdb/) | Zero-FP hash databases: NSRL/CIRCL known-good lookup, MalwareBazaar/VirusShare known-bad lookup, and embedded loldrivers.io vulnerable Windows driver hashes. |

</details>

```toml
# Use individual crates in your own tooling
[dependencies]
memf-core    = "0.1"
memf-linux   = "0.1"
memf-windows = "0.1"
```

---

## Used By

[RapidTriage](https://github.com/SecurityRonin/RapidTriage) — the `rt memf` subcommand drives memory acquisition and triage reporting directly from this workspace.

---

## Acknowledgements

**Andrew Case** and the Volatility Foundation whose ISF format and plugin architecture this project is symbol-compatible with.

**Brendan Dolan-Gavitt** whose research on DKOM and VAD-based process hiding informed the hidden process detection walkers.

The Rust [binrw](https://github.com/jam1garner/binrw) team for making binary format parsing declarative and safe.

---

[Privacy Policy](https://securityronin.github.io/memory-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/memory-forensic/terms/) · © 2026 Security Ronin Ltd.
