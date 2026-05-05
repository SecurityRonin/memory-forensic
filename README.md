[![Stars](https://img.shields.io/github/stars/SecurityRonin/memory-forensic?style=flat-square)](https://github.com/SecurityRonin/memory-forensic/stargazers)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/memory-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/memory-forensic/actions/workflows/ci.yml)
[![Rust 1.75+](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg)](#install)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

# memory-forensic

**Walk any memory dump. Find what's hidden. No Python required.**

Volatility works. It also needs Python, a virtual environment, a compatible plugin version, and ISF symbol files in the right directory. Every examiner knows the setup tax.

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

## Three Things You Do With This

### Hunt hidden processes — what the rootkit doesn't want you to see

```bash
# Cross-view analysis: task_struct list vs scheduler runqueue vs PID namespace
memf check memdump.lime --symbols linux.json --hidden-procs
```

```
[HIDDEN]  PID 977  "top"   ppid=941  seen: task_list  missing: /proc, sched_runqueue
[HIDDEN]  PID 939  "sh"    ppid=937  seen: task_list  missing: /proc
[HIDDEN]  PID 941  "bash"  ppid=940  seen: task_list  missing: /proc
```

Three processes hidden by the rootkit — all children of the attacker's SSH shell. The cross-view discrepancy is the finding. No manual grep, no Python diff.

### Detect injected code — RWX regions not backed by a file

```bash
# Private RWX memory cross-referenced against the PEB module list
memf malfind memdump.dmp --symbols ntkrnlmp.json --output json \
  | jq '.[] | select(.score > 0.7)'
```

```json
{
  "pid": 1234, "process": "svchost.exe",
  "vad_start": "0x7fff4a000000", "size": 4096,
  "protection": "PAGE_EXECUTE_READWRITE",
  "mapped_file": null,
  "mz_header": true,
  "score": 0.92,
  "note": "private RWX region with MZ header — no backing file"
}
```

False positives are suppressed by cross-referencing the PEB's `InMemoryOrderModuleList` — if the region is a known module, it is not flagged.

### Verify kernel integrity — hooks invisible from the OS

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
| Runs on Linux / macOS | ✓ | ✓ | partial | ✓ |
| No Python runtime | ✓ | — | ✓ | — |
| Single static binary | ✓ | — | — | — |
| ISF symbol pack compatible | ✓ | ✓ | — | — |
| Library API (use in your tools) | ✓ | — | ✓ | — |
| Linux + Windows walkers | ✓ | ✓ | Windows-first | ✓ |
| Actively maintained | ✓ | ✓ | ✓ | — |
| Free & open source | ✓ | ✓ | ✓ | ✓ |

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
```

Symbol files are ISF JSON, compatible with Volatility 3 symbol packs.

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
| [`memf-linux`](crates/memf-linux/) | Linux kernel walkers: `task_struct` process list, network connections, kernel modules, open files, eBPF programs, ftrace/IDT/syscall hook detection, namespace and cgroup enumeration, DKOM-hidden process detection, container escape indicators, and ~40 additional walkers. |
| [`memf-windows`](crates/memf-windows/) | Windows NT kernel walkers: `EPROCESS`/`ETHREAD` enumeration, DLL and driver lists, handle tables, network sockets, pool tag scanning, callback tables, SSDT, ETW, clipboard, DNS cache, Kerberos tickets, DPAPI keys, BitLocker keys, SAM/NTLM hashes, injected memory detection, and ~50 additional walkers. |
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
