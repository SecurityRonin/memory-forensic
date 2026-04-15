[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=for-the-badge)](LICENSE) [![Rust](https://img.shields.io/badge/rust-1.75+-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org) [![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey?style=for-the-badge)](https://github.com/SecurityRonin/memory-forensic) [![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ff69b4?style=for-the-badge&logo=github-sponsors)](https://github.com/sponsors/h4x0r)

# memory-forensic

Parse LiME, AVML, crash dumps, ELF core, kdump, hiberfil.sys, and VMware snapshots — then walk processes, threads, modules, network connections, and injected memory — entirely in Rust, with no Python or Volatility dependency.

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

Format is detected automatically from file headers — no flags required.

## What You Can Extract

**Windows** — processes, threads, DLLs, drivers, handles, network connections, SSDT hooks, kernel callbacks, clipboard contents, DNS cache, Kerberos tickets, DPAPI keys, BitLocker keys, NTLM/SAM hashes, ETW patches, AMSI bypasses, pool tag scans, injected memory regions, PEB masquerade detection, COM hijacking, heap spray detection, APC injection, and more.

**Linux** — processes, kernel modules, network connections, open files, environment variables, mount points, namespaces, cgroups, BPF programs, eBPF hooks, ftrace tampering, IDT/syscall hook detection, DKOM-hidden processes, kernel timer abuse, `ld_preload` artifacts, memfd backdoors, container escape indicators, and more.

**Cross-platform** — strings with IoC classification (URLs, IPs, domains, registry keys, crypto addresses, private keys, shell commands, YARA matches), hash lookups against NSRL/CIRCL known-good, MalwareBazaar/VirusShare known-bad, and loldrivers.io vulnerable driver hashes, plus MITRE ATT&CK-tagged cross-artifact correlation and timeline reconstruction.

## Quick Start

```bash
# Show dump format and physical memory ranges
memf info memdump.dmp

# List all Windows processes with threads (ISF symbol file required)
memf ps memdump.dmp --symbols ntkrnlmp.json --threads

# Process tree with DLLs for a single PID
memf ps memdump.dmp --symbols ntkrnlmp.json --tree --dlls --pid 1234

# Network connections (table / json / csv output)
memf net memdump.dmp --symbols ntkrnlmp.json --output json

# Integrity checks: SSDT hooks and kernel callbacks
memf check memdump.dmp --symbols ntkrnlmp.json --ssdt --callbacks

# Linux syscall hook and malfind scan
memf check memdump.lime --symbols linux.json --hooks --malfind

# String extraction with YARA rules, minimum length 8
memf strings memdump.dmp --rules ./yara-rules/ --min-length 8
```

Symbol files are ISF JSON (compatible with Volatility 3 symbol packs) or PDB. The `--cr3` flag lets you supply a page-table root manually for LiME/AVML dumps where auto-detection fails.

## Library Usage

```rust
use memf_format::open;
use memf_core::vas::{TranslationMode, VirtualAddressSpace};
use memf_core::object_reader::ObjectReader;
use memf_symbols::isf::IsfSymbols;

// Open any supported format — detected from file headers
let dump = open("memdump.dmp")?;

// Load an ISF symbol file
let symbols = IsfSymbols::from_file("ntkrnlmp.json")?;

// Walk the x86_64 4-level page table
let vas = VirtualAddressSpace::new(dump.clone(), TranslationMode::X64, cr3);
let reader = ObjectReader::new(vas, symbols);

// Walk EPROCESS list and print process names and PIDs
for proc in reader.eprocess_list()? {
    println!("{} (PID {})", proc.image_name()?, proc.pid()?);
}
```

<details>
<summary>Crate layout</summary>

| Crate | Purpose |
|---|---|
| `memf-format` | Format detection and physical memory providers. Parsers for LiME, AVML, ELF Core, Windows Crash Dump, hiberfil.sys, VMware state, kdump, and raw flat images. |
| `memf-core` | Page table walking (x86_64 4-level/5-level, AArch64, x86 PAE/non-PAE), high-level `ObjectReader` for kernel struct traversal, pagefile access, LZO decompression. |
| `memf-linux` | Linux kernel walkers: `task_struct` process list, network connections, kernel modules, open files, eBPF/BPF programs, ftrace/IDT/syscall hook detection, namespace and cgroup enumeration, DKOM-hidden process detection, container escape indicators, and ~40 additional analysis plugins. |
| `memf-windows` | Windows NT kernel walkers: `EPROCESS`/`ETHREAD` enumeration, DLL and driver lists, handle tables, network sockets, pool tag scanning, callback tables, SSDT, ETW, clipboard, DNS cache, Kerberos tickets, DPAPI keys, BitLocker keys, SAM/NTLM hashes, injected memory detection, and ~50 additional plugins. |
| `memf-strings` | String extraction (ASCII, UTF-8, UTF-16LE) with regex and YARA classification into IoC categories: URLs, IP addresses, domains, registry keys, crypto addresses, private keys, shell commands. |
| `memf-symbols` | Symbol resolution from ISF JSON, BTF (Linux), and PDB files. Includes a symbol server client for on-demand PDB retrieval. |
| `memf-correlate` | Cross-artifact correlation with MITRE ATT&CK technique tagging, process tree reconstruction, anomaly scoring, and timeline generation. |
| `forensic-hashdb` | Zero-FP hash databases: NSRL/CIRCL known-good lookup, MalwareBazaar/VirusShare known-bad lookup, and embedded loldrivers.io vulnerable Windows driver hashes. |

</details>

## Used By

[RapidTriage](https://github.com/SecurityRonin/RapidTriage) — the `rt memf` subcommand drives live-response memory acquisition and triage reporting directly from this workspace.

## Contributing

This project follows strict TDD. For every change:

1. **RED** — write a failing test that defines the expected behavior, commit it, confirm it fails.
2. **GREEN** — write the minimal implementation to make the test pass, commit it separately, confirm it passes.
3. **REFACTOR** — clean up while keeping tests green.

Pull requests that arrive as a single "add feature + tests" commit will be asked to split. The failing-test commit is the verifiable proof that tests were written first.

## License

Apache-2.0. See [LICENSE](LICENSE).

Sponsor this work: [github.com/sponsors/h4x0r](https://github.com/sponsors/h4x0r)
