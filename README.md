[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/memory-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/memory-forensic/actions/workflows/ci.yml)
[![Rust 1.75+](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg)](#install)
[![unsafe: bounded](https://img.shields.io/badge/unsafe-bounded%20(mmap%20only)-green.svg)](#trust-but-verify)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

# memory-forensic

**A memory forensics toolkit that profiles Windows kernels itself — and is cross-checked, process-for-process, against Volatility 3.**

`memf` reads every common dump format (LiME, AVML, ELF core, Windows crash dumps, hibernation files, VMware save-states, kdump, raw…) and walks processes, threads, modules, network connections, and injected memory — from **one static binary** you compile once and copy anywhere, with **no Python, no runtime, no pre-staged symbol catalog**. On Windows it builds its own profile: locate `ntoskrnl` in physical memory, read its PDB GUID from the CodeView record, resolve the matching Volatility-3 ISF, recover the kernel base under modern KASLR, and reconstruct `PsActiveProcessHead` from the symbol table — the same self-profiling chain Volatility 3 and MemProcFS use, reimplemented in Rust.

Because the bar for an evidence tool is *correctness*, the process walker is cross-checked against an **independent reference implementation** — Volatility 3 — on a real 2 GB Windows 10 image (a reference agreeing is strong evidence, not proof; the raw bytes are the ground truth):

| `windows.pslist` on DESKTOP-SDN1RPT.mem | memf vs Volatility 3 |
|---|---|
| Processes matched | **94 / 94 shared PIDs — exact PID, PPID, name, create-time** |
| Missed (vol3 found, memf did not) | **0** |
| False positives (memf found, vol3 did not) | **0** |

memf matches Volatility 3 **exactly** — including recovering 11 processes orphaned by a live-acquisition smear via a bidirectional `ActiveProcessLinks` walk. A second independent oracle (MemProcFS) is [in progress](docs/validation.md#multi-oracle-in-progress). See [`docs/validation.md`](docs/validation.md) for the full differential and reproduction steps.

## Quick start

Not yet on crates.io — build from source (single static binary, ~one command):

```bash
git clone https://github.com/SecurityRonin/memory-forensic.git
cd memory-forensic && cargo build --release
./target/release/memf --help
```

```bash
# Inspect any dump — format, ranges, embedded metadata (no symbols needed)
memf info win10.mem

# Windows process tree. The ISF is resolved from the kernel's own PDB GUID;
# raw .mem dumps take the page-table base via --cr3 (crash dumps carry their own).
memf ps --symbols ntkrnlmp.json --cr3 0x1ad000 --tree win10.mem

# Linux process tree from a LiME capture
memf ps --symbols linux.json --tree memdump.lime

# Air-gapped lab? Never touch the network for symbols:
memf ps --symbols ntkrnlmp.json --offline win10.mem
```

Symbol files are ISF JSON — the **same packs Volatility 3 uses**, so an existing symbol cache works as-is.

---

## Why memf

| | **memf** | Volatility 3 | MemProcFS |
|---|---|---|---|
| Deploy | Rust · **single static binary** | Python · interpreter + deps | C(+Rust) · libraries |
| Windows self-profiling (scan → PDB GUID → symbols) | ✅ | ✅ | ✅ |
| Header-less DTB via the boot low stub + page-granular kernel base | ✅ | self-ref PML4 + image scan | ✅ low stub |
| Offline / air-gapped symbol mode | ✅ `--offline` | ISF pack or network | symbols / network |
| Panic-free on untrusted dumps (`unsafe`-deny, no `unwrap`/`expect`) | ✅ | — | — |
| Cross-checked against Volatility 3 | ✅ ([`docs/validation.md`](docs/validation.md)) | — (the reference) | — |

memf is, to our knowledge, the only **Rust** implementation of the full dump → kernel-scan → PDB-GUID → symbol-resolution → DTB chain. The technique lineage — WinDbg's symbol server, Brendan Dolan-Gavitt's `pdbparse`, Rekall, Volatility 3, and Ulf Frisk's MemProcFS — is well established; memf reimplements it clean-room and proves the result against the reference. The boot low-stub / `PROCESSOR_START_BLOCK` anchor follows [Alex Ionescu's REcon 2017 *Getting Physical*](http://publications.alex-ionescu.com/Recon/ReconBru%202017%20-%20Getting%20Physical%20with%20USB%20Type-C,%20Windows%2010%20RAM%20Forensics%20and%20UEFI%20Attacks.pdf).

---

## Install

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
memf ps --symbols ntkrnlmp.json --tree --threads --dlls memdump.dmp

# Network connections (json / csv / table)
memf net --symbols ntkrnlmp.json --output json memdump.dmp

# Kernel integrity checks (SSDT, IDT, callbacks, hooks)
memf check --symbols ntkrnlmp.json --ssdt --callbacks memdump.dmp

# Linux syscall hook and malfind scan
memf check --symbols linux.json --hooks --malfind memdump.lime

# String extraction with YARA rules
memf strings --rules ./yara-rules/ --min-length 8 memdump.dmp

# Hash lookup against NSRL (known-good) and MalwareBazaar (known-bad)
memf hash --lookup memdump.dmp

# Extract framebuffer screenshot from live memory dump
memf framebuf --symbols linux.json --png screen.png memdump.dmp

# Recover files from tmpfs mounts + detect memfd fileless ELF execution
memf check --symbols linux.json --tmpfs-recovery --memfd memdump.lime

# Detect EDR bypass: direct syscalls, ETW patching, AMSI/DSE bypass
memf check --symbols ntkrnlmp.json --direct-syscalls --etw-patch --amsi-bypass memdump.dmp

# Novel kernel interface abuse: io_uring, netfilter hooks, perf_event
memf check --symbols linux.json --io-uring --netfilter --perf-event memdump.lime

# Cross-artifact ATT&CK correlation across all walkers
memf correlate --symbols ntkrnlmp.json --output json memdump.dmp
```

Symbol files are ISF JSON, compatible with Volatility 3 symbol packs.

---

## Verify kernel integrity — hooks invisible from the OS

```bash
# SSDT, IDT, ftrace, LSM, and kernel callback checks in one pass
memf check --symbols linux.json --hooks --idt --syscalls memdump.lime
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
memf check --symbols linux.json --elf-hooks memdump.lime
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
memf check --symbols ntkrnlmp.json --dpapi-keys memdump.dmp

# Detect Chrome cookies (v10/v20 encrypted blobs) from heap memory
memf check --symbols ntkrnlmp.json --browser-cookies memdump.dmp
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
memf framebuf --symbols ntkrnlmp.json --png screen.png memdump.dmp
```

Extracts the framebuffer from a live or hibernation memory dump and writes it as a PNG. Works on both Linux (DRM/KMS `drm_framebuffer` walker) and Windows (session framebuffer via `win32k` pool scan). Useful for capturing the screen state at the moment of acquisition without booting the image.

---

## Recover files that never touched disk

Attackers using tmpfs or `memfd_create(2)` leave no filesystem artifacts — the binary exists only in RAM.

```bash
# Recover inodes and file content from Linux tmpfs/ramfs mounts
memf check --symbols linux.json --tmpfs-recovery memdump.lime

# Detect ELF binaries running from anonymous memfd file descriptors
memf check --symbols linux.json --memfd memdump.lime
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
memf check --symbols ntkrnlmp.json --direct-syscalls memdump.dmp

# ETW patching — log suppression via ret/xor at ETW write functions
memf check --symbols ntkrnlmp.json --etw-patch memdump.dmp

# AMSI bypass — script-scanning suppression via amsi.dll patch
memf check --symbols ntkrnlmp.json --amsi-bypass memdump.dmp

# DSE bypass — Driver Signature Enforcement disabled for unsigned drivers
memf check --symbols ntkrnlmp.json --dse-bypass memdump.dmp
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
memf check --symbols linux.json --io-uring --netfilter --perf-event memdump.lime
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
memf check --symbols linux.json --container-escape memdump.lime
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
memf correlate --symbols ntkrnlmp.json --output json memdump.dmp > findings.json
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

Process, network, module, hook, and credential walker results are correlated by process and time before scoring — producing ATT&CK-tagged findings rather than per-walker output that an analyst must join manually.

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

The nearest alternatives are **Volatility 3** (Python, plugin architecture), **MemProcFS** (Rust, primarily Windows), and **Rekall** (Python, unmaintained). The comparison below reflects each tool's official core and known plugin repository.

### Parity — capabilities shared with mature tools

| | memory-forensic | Volatility 3 | MemProcFS | Rekall |
|--|:-:|:-:|:-:|:-:|
| Linux + Windows kernel walkers | ✅ | ✅ | Windows-first | ✅ |
| Process, module, network enumeration | ✅ | ✅ | ✅ | ✅ |
| Injected memory detection | ✅ | ✅ | ✅ | ✅ |
| ISF symbol pack compatible | ✅ | ✅ | — | — |
| Runs on Linux / macOS | ✅ | ✅ | partial | ✅ |
| Actively maintained | ✅ | ✅ | ✅ | — |
| Free & open source | ✅ | ✅ | ✅ | ✅ |

### Capabilities absent from other tools' official distributions

| | memory-forensic | Volatility 3 | MemProcFS | Rekall |
|--|:-:|:-:|:-:|:-:|
| Single static binary — no Python, no runtime | ✅ | — | — | — |
| Windows auto-profile (no symbol file needed) | ✅ | — | — | — |
| Library API for embedding in Rust tools | ✅ | — | ✅ | — |
| ELF behavioral rootkit fingerprinting | ✅ | — | — | — |
| tmpfs / ramfs file recovery | ✅ | — | — | — |
| memfd fileless execution detection | ✅ | — | — | — |
| Direct syscall / EDR bypass detection | ✅ | plugin? | — | — |
| ETW / AMSI / DSE bypass detection | ✅ | plugin? | — | — |
| io_uring / netfilter / perf\_event abuse | ✅ | — | — | — |
| Container escape indicators | ✅ | — | — | — |
| DPAPI keys + Chrome cookie extraction | ✅ | plugin? | — | — |
| Shellbags folder-access evidence from memory ‡ | ✅ | — | — | — |
| Framebuffer screenshot | ✅ | plugin? | — | — |
| Cross-artifact ATT&CK correlation | ✅ | — | — | — |
| Safe output — RFC 4180, formula-injection guard, bidi-strip | ✅ | — | — | — |

> **`plugin?`** — Capability may exist in the Volatility 3 community ecosystem but is absent from the official core and plugin repository at time of writing. Verify before concluding.
>
> **‡ Shellbags from memory** — Volatility 2 recovered shellbags from RAM (the community `shellbags` plugin, Kovar then Lo); Volatility 3 never re-ported it, so memory-only shellbag recovery regressed across the vol2→vol3 transition. memf walks `Shell\BagMRU` directly in the in-memory `UsrClass.dat`/`NTUSER.DAT` hive — restoring the vol2-era capability for the RAM-only case (no disk acquired), or to corroborate the on-disk hive. The usual route when disk *is* available is to mount the image and run SBECmd / RegRipper on the hive file; the memory walk collapses the dump-the-hive-then-parse two-step into one. Validation is **tier-2**: ground truth derived with `regipy` on the hive extracted from `citadeldc01.mem` — no published third-party shellbag answer key exists for the Szechuan case, so this is a self-derived oracle (real tool + real image), not a third-party key. See [`docs/plans/2026-06-24-shellbags-rewrite.md`](docs/plans/2026-06-24-shellbags-rewrite.md).

---

## Trust but verify

A tool that parses **untrusted, attacker-controllable** memory images has to refuse to lie and refuse to crash. memf is built to that bar:

- **Panic-free on hostile input.** Production code denies `unwrap`/`expect`/`panic!` and unchecked indexing (`clippy::unwrap_used`/`expect_used` = deny); every length, offset, and pointer read is bounds-checked and degrades gracefully — a smeared process list returns what it found, it does not abort.
- **Memory-safe by default.** `unsafe_code = "deny"` workspace-wide; the only `unsafe` is the bounded `memmap2` mapping of the dump, individually justified — hence the *bounded (mmap only)* badge rather than *forbidden*.
- **Validated against an independent oracle, not just our own fixtures.** The Windows process walker is diffed against Volatility 3 on a real 2 GB Win10 image — exact agreement on every shared process, zero false positives ([`docs/validation.md`](docs/validation.md)).
- **Safe output.** Every channel (table/CSV/JSON) applies RFC 4180 quoting, a spreadsheet formula-injection guard, and bidi/control-character stripping before attacker-controlled strings reach your terminal or pipeline.

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
| [`memf-symbols`](crates/memf-symbols/) | Symbol resolution from ISF JSON, BTF (Linux), and PDB files. Includes `AutoProfile` — zero-config Windows kernel struct resolution: scans the dump for ntoskrnl, fetches the exact PDB from `msdl.microsoft.com`, parses it, returns a `SymbolResolver`. No symbol file required. |
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

[issen](https://github.com/SecurityRonin/issen) — the `issen memf` subcommand drives memory acquisition and triage reporting directly from this workspace.

---

## Acknowledgements

**[Andrew Case](https://www.linkedin.com/in/andrewcase)** and the **[Volatility Foundation](https://volatilityfoundation.org/)** whose ISF format and plugin architecture this project is symbol-compatible with.

**[Brendan Dolan-Gavitt](https://www.cs.columbia.edu/~brendan/)** whose research on DKOM and VAD-based process hiding informed the hidden process detection walkers.

**[Ulf Frisk / MemProcFS](https://github.com/ufrisk/MemProcFS)** whose filesystem-as-memory-interface model and forensic mode design influenced how this library surfaces recovered artefacts.

**[jam1garner](https://github.com/jam1garner)** for [binrw](https://github.com/jam1garner/binrw) — declarative binary format parsing that makes the format layer safe and readable.

**[S12](https://medium.com/@s12deff)** — the writeup *[Kernel Dynamic Offset Resolution Using PDB Symbols](https://medium.com/@s12deff/kernel-dynamic-offset-resolution-using-pdb-symbols-b0aaa499ac25)* which documented the full chain of scanning a dump for the ntoskrnl PE, extracting the CodeView PDB GUID, and fetching the matching PDB from `msdl.microsoft.com` at runtime. This technique directly inspired the `AutoProfile` implementation in `memf-symbols`.

**[Alex Ionescu](https://www.alex-ionescu.com/)** — *[Getting Physical With USB Type-C: Windows 10 RAM Forensics and UEFI Attacks](http://publications.alex-ionescu.com/Recon/ReconBru%202017%20-%20Getting%20Physical%20with%20USB%20Type-C,%20Windows%2010%20RAM%20Forensics%20and%20UEFI%20Attacks.pdf)* (REcon Brussels 2017), which documented that the HAL's `HalpLowStub` is the undocumented `PROCESSOR_START_BLOCK` — the low-physical-memory anchor (signature-scanned in `0x1000–0x100000`) carrying the kernel CR3/DTB and a kernel-VA hint. This is the basis for `find_low_stub` and the header-less DTB / kernel-base recovery in `memf-symbols`.

**[Microsoft Symbol Server](https://learn.microsoft.com/en-us/windows/win32/debug/using-symsrv)** (`msdl.microsoft.com`) for hosting public PDB files for every Windows kernel build, the upstream that makes runtime symbol resolution possible without pre-staged symbol files.

---

[Privacy Policy](https://securityronin.github.io/memory-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/memory-forensic/terms/) · © 2026 Security Ronin Ltd.
