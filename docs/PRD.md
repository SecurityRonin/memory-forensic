# mem4n6 — Product Requirements

*Reverse-written from a same-session read of the repo (2026-07-24): `Cargo.toml`
(workspace + all nine members), each crate's `lib.rs`, `README.md`,
`docs/validation.md`, and `git log`. Every current-state claim is grounded in that
read; the load-bearing decisions live as ADRs [0001](decisions/0001-layered-memf-workspace-by-navigation-primitive.md)–[0010](decisions/0010-msrv-floor-and-dual-release-pipeline.md)
under [`docs/decisions/`](decisions/). This documents what the code does today, not
a forward plan.*

## Executive Summary

`mem4n6` is a memory-forensics CLI that reads any common memory-dump format and
walks Windows and Linux kernel structures — processes, threads, modules, network
connections, injected/hooked memory, credentials — from **one static binary** with
no Python, no runtime, and no pre-staged symbol catalog. On Windows it profiles the
kernel from the dump itself (scan `ntoskrnl` → read PDB GUID → resolve the matching
Volatility-3 ISF → recover the KASLR kernel base and DTB → reconstruct
`PsActiveProcessHead`), the same self-profiling chain Volatility 3 and MemProcFS
use, reimplemented clean-room in Rust.

Because the bar for an evidence tool is correctness, the process walker is
cross-checked process-for-process against an **independent reference implementation**
(Volatility 3) on a real 2 GB Windows 10 dump: 94/94 shared PIDs exact on PID, PPID,
name, and create-time, with zero misses and zero false positives
([`docs/validation.md`](validation.md)).

## 1. Problem

Memory analysis in the field is gated by deployment friction and trust:

- **Deployment.** The dominant tools carry runtimes an evidence workstation may not
  have — Volatility 3 needs a Python interpreter and dependency tree; MemProcFS is
  C/C++ libraries; MemNixFS is a C++ filesystem mount. On an air-gapped or
  locked-down workstation, standing these up is itself the obstacle.
- **Symbols.** Windows kernel offsets vary per build, so a walker needs a per-image
  profile. Bundling a catalog is stale by construction; hand-picking a profile
  burdens the analyst.
- **Trust.** An evidence tool's output must be defensible. A walker validated only
  against dumps its own author constructed inherits the author's blind spots.

## 2. Users and their use case

- **DFIR analysts / incident responders** triaging a captured memory image who need
  a process tree, network connections, and injection/hook findings *now*, often on a
  workstation they cannot freely install software on.
- **Malware / threat analysts** hunting EDR-bypass and kernel-abuse techniques
  (direct syscalls, ETW patching, AMSI/DSE bypass, io_uring/netfilter/perf_event
  abuse, syscall-table / ftrace / LSM hooks) that are invisible from the live OS.
- **Rust DFIR developers** who want a specific memf library layer (page-table
  walking, symbol resolution, a dump-format reader) without the whole CLI.

The fastest path is one command: `mem4n6 ps --symbols <isf.json> <dump>` — the DTB
and kernel base are recovered from the dump, so a raw `.mem` needs no `--cr3`.

## 3. What it does (shipped)

Driven by the `mem4n6` subcommands (`src/main.rs`, README Quick Reference):

- **`info`** — dump format, physical ranges, embedded metadata; no symbols needed.
- **`ps`** — Windows/Linux process tree, optionally with threads and DLLs; a
  bidirectional `ActiveProcessLinks` walk recovers processes past a live-acquisition
  smear.
- **`net`** — network connections (table/json/csv).
- **`check`** — kernel-integrity and technique detection: SSDT/IDT/callbacks/hooks,
  ftrace/LSM/syscall hooks, malfind, tmpfs recovery + memfd fileless-ELF detection,
  EDR-bypass (direct syscalls / ETW-patch / AMSI-DSE), novel kernel-interface abuse
  (io_uring/netfilter/perf_event).
- **`strings`** — extraction with IoC classification and YARA rules.
- **`hash`** — lookups against known-good/known-bad hash sources.
- **`framebuf`** — recover a framebuffer screenshot from a Linux dump.
- **`correlate`** — cross-artifact ATT&CK correlation over all walkers, emitting the
  normalized `forensicnomicon::report` model via `memf-correlate`.

Windows credential material (SAM, LSA secrets, cached domain credentials, hashdump)
is decrypted with the audited RustCrypto stack and read through fleet
`winreg-core`/`winreg-format` hive navigation (ADR 0008, ADR 0009).

## 4. Supported artifact family

- **Dump containers** (`memf-format`, confidence-scored inventory detection, ADR
  0005): LiME, AVML, ELF core, Windows crash dumps, hibernation files, VMware
  save-states, kdump, raw.
- **Address translation** (`memf-core`): x86_64 4-/5-level, AArch64, x86 PAE/non-PAE.
- **Symbols** (`memf-symbols`): Volatility-3-compatible ISF JSON; Linux BTF (kernel
  5.2+); Windows PDB auto-profile from the symbol server, with `--offline`.
- **OS structures**: Windows kernel objects (`memf-windows`) and Linux kernel objects
  (`memf-linux`).

## 5. Scope / non-goals

- **Not a live-system agent.** mem4n6 analyzes a captured dump, not a running host.
- **Not a Volatility replacement across every plugin.** The validated, native surface
  is the process/kernel-object walk and the detection checks above; full DKOM-hidden
  processes (unlinked in both list directions) are out of scope for the linked-list
  walk and belong to pool-tag scanning (`psscan`, tracked separately —
  `docs/validation.md`).
- **No bundled symbol catalog.** Profiles are resolved from the dump / ISF, never
  shipped in the binary (ADR 0006).
- **No capability feature-gating.** Every build reads the full breadth of evidence;
  configurability is run-time flags, not conditional compilation (ADR 0009).
- **Memory mounting lives elsewhere.** Presenting a dump as a browsable filesystem is
  4n6mount's job; memf provides the walker libraries it consumes (ADR 0001; 4n6mount
  ADR 0003).

## 6. Validation approach

Correctness is proven differentially against independent reference tools on real
dumps, not against self-authored fixtures (ADR 0007). Volatility 3 is the primary
oracle (exact PID-set match on the DFIR Madness Case 001 Windows 10 dump); MemProcFS
is the second oracle (done 2026-06-14 — its 77-process list is a clean subset).
`docs/validation.md` carries the
result and the exact reproduce commands; `docs/steelman-vs-reference-tools.md` argues
the comparison fairly. Reference agreement is strong evidence, not proof — the raw
bytes are the ground truth, and divergences are investigated against them.

## 7. Non-functional posture

- **One static binary** — Linux release builds are static-PIE (musl), copy-anywhere;
  macOS and Windows builds alongside, with a SHA-256 `checksums.txt` (README Install).
- **Panic-free by lint + fuzzed** — `unwrap_used`/`expect_used` denied workspace-wide,
  one fuzz target per dump format, on the premise that dumps are untrusted input
  (ADR 0004).
- **`unsafe` bounded** — denied workspace-wide with two justified mmap allow sites
  (ADR 0003); the README badge reads "unsafe: bounded (mmap only)", not
  "unsafe-forbidden".
- **Low library MSRV (1.75)** for the publishable `memf-*` crates, dev toolchain
  pinned separately at 1.96.0; libraries publish via release-plz, the binary via a
  signed `v[0-9]*` tag (ADR 0010).
