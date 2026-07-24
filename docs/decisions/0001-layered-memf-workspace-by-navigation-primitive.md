# 1. Layered memf-* workspace organized by memory navigation primitive

Date: 2026-07-24
Status: Accepted

## Context

Memory forensics on a raw dump is a chain of distinct concerns: decode the dump
container to an addressable page stream, resolve symbols, translate virtual to
physical addresses, walk OS kernel objects, then carve and correlate. Fusing
these into one crate would force a consumer that only needs page-table walking
(e.g. 4n6mount's memory mount) to compile the Windows crypto stack and the YARA
scanner, and would couple the OS-agnostic hardware layer to Windows/Linux
specifics.

The fleet constitution (`~/src/ronin-issen/CLAUDE.md`, "Multi-Repo Architecture")
already fixes the layer model: CONTAINER (page stream) → PAGING (VA→PA) → OS
STRUCTURE (EPROCESS/kernel objects) → PARSER/ORCHESTRATION, with the memory path
navigating by `PID → EPROCESS → VA → PA`.

## Decision

Split the repo into nine workspace members, each owning one layer of the memory
navigation primitive (`Cargo.toml` members list; crate `lib.rs` headers):

- `memf-format` — CONTAINER: physical-dump format parsers → `PhysicalMemoryProvider`
  page stream (LiME/AVML/ELF-core/crash-dump/hiberfil/kdump/raw).
- `memf-symbols` — KNOWLEDGE: `SymbolResolver` over ISF JSON + BTF, plus the
  Windows auto-profile chain.
- `memf-core` — PAGING: `VirtualAddressSpace` page-table walking (x86_64 4/5-level,
  AArch64, PAE) + `ObjectReader` symbol-driven struct traversal. OS-agnostic.
- `memf-windows` / `memf-linux` — OS STRUCTURE: kernel-object walkers, depending on
  `memf-core` + `memf-symbols`, never on each other.
- `memf-carve` — memory artifact carving (Plane-V) over a process VA space.
- `memf-correlate` — the cross-artifact `ForensicEvent`/ATT&CK model.
- `memf-session` — the analysis bootstrap (OS detect + DTB + list-head) as a library.

`mem4n6` (the root binary crate) is the only member that wires all layers into a
user-facing CLI.

## Consequences

A consumer depends on exactly the layer it needs; `memf-core` stays OS-agnostic and
independently reusable. The layering must remain acyclic — `memf-core` may not
import an OS crate, and the OS crates may not import each other — which constrains
where shared helpers live. The split also enables independent per-crate SemVer
publishing via release-plz (ADR 0010). Extracting `memf-session` from the binary's
`src/os_detect.rs` (commits `e36fe20`/`d324ef3`) is a direct instance: the bootstrap
became a library so 4n6mount could drive it without the CLI.
