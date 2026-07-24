# 8. Prefer our own fleet crates; delete hand-rolled parsers once a fleet crate exists

Date: 2026-07-24
Status: Accepted

## Context

memf-windows needs to parse artifacts that are not memory-specific: registry hives,
prefetch files, event logs, shell items, ZIP archives, and to carve regions. The
fleet has a binding "prefer our own crates" rule (`~/src/ronin-issen/CLAUDE.md`) —
use a SecurityRonin crate where one exists, migrate off third-party and off
hand-rolled duplicates, and route carving through the shared `forensic-carve`
contract rather than reinventing it (DRY across the ecosystem, not just the repo).

## Decision

Delegate every non-memory artifact concern to the fleet crate that owns it, and
delete the in-repo duplicate:

- Registry hives → `winreg-core`/`winreg-format` (`MemfHiveReader`). The `amcache`,
  `com_hijacking`, `run_keys`, `sam`, `cachedump`, `lsadump`, and `hashdump`
  walkers were all migrated off in-repo hive walking (commits `9d2251f`…`9e02b9e`),
  and the orphaned flat `nk/vk/lf` walker was deleted for the dedup payoff
  (`f28b0df`).
- Prefetch → `prefetch-core`; event logs → `winevt-core`; shell items →
  `shellitem`; ZIP reads → `zip-forensic-core` (pure-Rust, replacing a C-FFI reader,
  `f9f6ad3`).
- Carving → the shared `forensic-carve` sweep engine; `memf-carve` supplies only the
  memory-specific `VaRegionSource` over a process VA space and does not reimplement
  detection (`crates/memf-carve/src/lib.rs`). `forensic-hashdb` was likewise split
  out to its own repo (`e2c94ae`).
- `winevt-core` moved from a cross-repo path dep to the published registry version
  once available (`Cargo.toml` comment).

## Consequences

A fix in a fleet crate benefits memf and every sibling at once; memf carries less
bespoke parsing surface to fuzz and maintain. The dependency graph is wider but each
edge is an audited fleet crate. The cost is release coupling — a breaking change in
`winreg-core` or `forensic-carve` ripples here — managed by preferring published
registry versions over path deps and by the release-plz cadence (ADR 0010).
