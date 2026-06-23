# Registry Flat-Module Migration Plan

**Status:** planned · **Branch:** `fix/memf-shared-registry-walker` · **Date:** 2026-06-23

## Executive Summary

Six memf-windows registry modules navigate hives with a **flat addressing model**
(`hive_addr + cell_index`, root cell at `hive_addr + 0x24`). In-memory hives are
**not** contiguous — their bins are scattered and reached through the `_HHIVE`
HMAP cell map — so these modules have **never worked on a real in-memory hive**.
Their unit tests pass only because the synthetic fixtures are laid out flat too
(the same "LZNT1 trap" the audit exists to catch).

The fix is to migrate every flat module onto the **shared HMAP walker** in
`registry.rs` plus the **root-cell fix** already landed for `hashdump`
(regf-check + `0x20` fallback — RED `615bbb9` / GREEN `6e224dd`). That fix is
Tier-1 validated: `issen memory citadeldc01.mem --command creds` recovers the
Administrator + Guest NT hashes **byte-for-byte identical to Volatility
`windows.hashdump`**. `hashdump` is therefore the working reference pattern; the
remaining modules follow it.

**Before any module can migrate there is a shared-infrastructure gap to close
(Phase 0).** Do Phase 0 first; it is the enabler all four migrations depend on.

## Background — the bug class

In-memory hive navigation requires three layers, all HMAP-correct and already
present in `registry.rs`:

- `cell_index_to_va(reader, hhive_addr, cell_index)` — translate a cell index to
  its VA via `_HHIVE.Storage[].Map -> Directory[] -> Table[] -> _HMAP_ENTRY`
  (mirrors Volatility `RegistryHive._translate`).
- `read_cell_addr(reader, hhive_addr, cell_index)` — cell data VA (past the
  4-byte `_HCELL` size header).
- `find_subkey_by_name(reader, hhive_addr, parent_VA, name) -> child_VA` —
  lf/lh/li/ri subkey-list search with correct `_CM_KEY_NODE` offsets.

The flat modules ignore all of this and compute `hive_addr + cell_index`
directly. They must be rewritten to call the shared primitives.

## Phase 0 — shared-infrastructure gap (do first)

Two helpers needed by the modules live in `hashdump.rs`, not the shared module,
and one capability does not exist at all. Land Phase 0 as its own TDD commits.

1. **Move `resolve_root_cell` to `registry.rs`** (the fixed version with
   `regf_root_cell_index`). Make it `pub(crate)`; update `hashdump` to call the
   shared version. Move its tests + the `CellMapHive` harness pieces they need.
2. **Move `read_value_data` to `registry.rs`** (`pub(crate)`) — reads a single
   *named* value of a key. Update `hashdump` callers.
3. **Add a shared value ENUMERATOR** — there is no way to list *all* values of a
   key today, and `run_keys`/`amcache` require it. Add
   `list_values(reader, hhive_addr, key_VA) -> Vec<(name, kind, data)>`:
   walk `_CM_KEY_NODE.ValueCount`/`.ValueList` (the value-list cell is an array
   of `_CM_KEY_VALUE` cell indices), then for each `_CM_KEY_VALUE` read
   `NameLength@0x02`, `DataLength@0x04`, `Data@0x08`, `Name@0x14` (REG_SZ inline
   vs. data-cell pointer per the high bit of DataLength). Bound the count
   (allocation-bomb defense). Validate against Volatility `printkey` on a real
   hive.

## Migration order (one module per TDD cycle)

Smallest clean walker-swap first; each migration validated end-to-end against
Volatility on a **real dump** (Tier-1), not synthetic fixtures.

| # | Module | Size | Flat surface | Hive (resident on) | Volatility oracle |
|---|---|---|---|---|---|
| 1 | `run_keys` | 481 L | 3 priv walkers (`find_key_cell`/`cell_vaddr`/`read_cell`) + needs value-enum | SOFTWARE, NTUSER (WS) | `printkey --key 'Microsoft\Windows\CurrentVersion\Run'` |
| 2 | `shimcache` | 325 L | 1 flat ref | SYSTEM AppCompatCache (WS) | `printkey` on the AppCompatCache key |
| 3 | `amcache` | 2019 L | 36 inlined flat refs | Amcache.hve (WS) | `windows.registry.amcache` |
| 4 | `com_hijacking` | 900 L | 5 priv walkers | HKU/HKCR CLSID (WS) | `printkey` on CLSID\…\InprocServer32 |

Each module migration:

1. Replace flat root-cell read (`hive_addr + 0x24`) with the shared
   `resolve_root_cell(reader, hhive_addr)`.
2. Replace flat `cell_vaddr`/`read_cell` with `read_cell_addr` /
   `cell_index_to_va`.
3. Replace the private subkey walker with `find_subkey_by_name`.
4. Replace value reads with the shared `read_value_data` / `list_values`.
5. Delete the now-dead private flat walkers.
6. Update the synthetic fixtures that baked in the flat layout (they asserted the
   bug — like the `resolve_root_cell_*_returns_zero` tests did for `hashdump`).
7. **Validate vs Volatility on a real dump** and reconcile output.

## Deferred — credential modules (`lsadump`, `sam`, `cachedump`)

These are MIXED (already partly on the shared walker: 34/36/21 shared uses, but
194/252/104 flat refs remain) **and** crypto-blocked: `cachedump` (DCC2/NL$KM)
and `lsadump` (LSA secrets, `LsaProtectMemory`) need decryption that is **out of
scope** (dual-use; do NOT implement crypto here — `cachedump` must fail loud, not
fabricate). Migrate only their *navigation* (flat -> HMAP) when the benign four
are done; leave decryption as a separate, explicitly-framed task.

## Discipline

- **Strict TDD** — separate gitsign-signed RED then GREEN commits per change.
  `export GITSIGN_CREDENTIAL_CACHE="$HOME/Library/Caches/sigstore/gitsign/cache.sock"`
- **Paranoid Gatekeeper** — panic-free bounds-checked reads, cap every
  length/count field, `clippy -D warnings`, 100% line coverage (cover the
  defensive paths; `// cov:unreachable` only for genuinely-unreachable guards),
  `cargo fmt --check`.
- **Doer-Checker / Tier-1 validation** — validate every module against Volatility
  on a real dump, never only against self-authored synthetic fixtures.

## Repro / setup

- Real dumps: `/tmp/szechuan-extracted/` — `DESKTOP-SDN1RPT.mem` (workstation,
  build 19041), `citadeldc01.mem` (DC, build 9600). If `/tmp` was cleared by a
  reboot, re-extract per `docs/corpus-catalog.md` (one-time per online session).
- Symbol PDBs are cached at `~/.cache/volatility3` (shared with Volatility).
- End-to-end `issen` validation: temporarily add `[patch.crates-io]` to
  `issen/Cargo.toml` pointing
  `memf-core/format/symbols/linux/windows/strings/correlate` + `forensic-hashdb`
  at `~/src/memory-forensic/crates/<crate>`, `cargo build -p issen-cli --bin
  issen`, run `issen memory <dump> --command <…>`, then **revert the patch**.
- Reference working path (already passing): `issen memory
  /tmp/szechuan-extracted/citadeldc01.mem --command creds` →
  Administrator `f56a8399599f1be040128b1dd9623c29` (matches Volatility).

## Source of truth

- Findings: `docs/correctness-audit-2026-06-23.md` (the 37-finding audit).
- Live task state: the auto-loaded memory note
  `project_memf_correctness_audit.md` → `NEXT-PASS PLAN` (item 1b mirrors this
  plan; items 2-3 cover the rate-limited and DFIR-framed re-runs).
