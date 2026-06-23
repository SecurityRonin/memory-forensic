# Shellbags rewrite — BagMRU via the HMAP cell map

## Outcome — COMPLETE (memf-windows), tier-2 validation OWED (issen)

Replaced the non-functional shellbags walker (treated `hive_addr` as a key node,
read `SubKeyLists`/`ValueList` as raw VA pointers, never reached `Shell\BagMRU`,
so it silent-emptied on every real hive) with a real HMAP-cell-map walker built
on the shared `registry::` API (`resolve_root_cell`, `find_subkey_by_name`,
`list_subkeys`, `list_values`).

`walk_shellbags` now:
1. `resolve_root_cell` → navigate down `Shell\BagMRU` via either
   `Local Settings\Software\Microsoft\Windows\Shell\BagMRU` (UsrClass.dat) or
   `Software\Microsoft\Windows\Shell\BagMRU` (NTUSER.DAT).
2. Recurse the BagMRU tree: each numbered subkey `N` is a folder whose name comes
   from the parent node's **value** `N` (a shell item, parsed by
   `parse_shell_item`), whose slot `LastWriteTime` is the subkey nk's own.

Commits: `683a3c3...` RED (`test(...): shellbags must walk BagMRU via the HMAP
cell map`) + GREEN. Synthetic `CellHive` tests cover single-level recovery and
nested recursion (`Desktop\Downloads`). The three old raw-VA-model unit tests were
removed (they validated the broken pointer walk); the two pure edge-case guards
(max-depth, zero-addr) were adapted to the new signature.

## Tier-2 oracle (validated, reproducible) — issen test OWED

No vol3 shellbags plugin exists, so the oracle is **extract the hive from memory,
parse on disk with an independent tool**. Confirmed working on a local dump.

**Image:** `citadeldc01.mem` — *Case 001, The Stolen Szechuan Sauce* (James Smith /
DFIRMadness), rehosted as CyberDefenders Lab #31. Win2012R2 x64 DC, captured
2020-09-19 04:39:59 UTC.
- https://dfirmadness.com/the-stolen-szechuan-sauce/ ·
  https://cyberdefenders.org/blueteam-ctf-challenges/szechuan-sauce/ (zip pw `cyberdefenders.org`)
- Local `citadeldc01.mem`: MD5 `0623f97fc80c12aa508ed9926b2ec04e`,
  SHA1 `23ccf0f209871cb9140bc55f5304e123a1ab7adb`.

**Resident hive:** the Administrator `UsrClass.dat` at VA **`0xc001f1e94000`** has a
fully-resident, populated BagMRU (107 rows, depth 5, 27 shell items). The other 3
UsrClass copies + DESKTOP-SDN1RPT's UsrClass are paged out (whole hive absent —
`printkey` shows `-` LWT, 0 children). NTUSER BagMRUs are thin (1–2 children).

**Reproduce the answer key** (regipy 6.2.1, MIT — independent of any memf dep):
```bash
# vol3 hivelist --dump aborts on the first paged-out UsrClass and has no offset
# filter, so dump the one resident hive directly with a 5-line read loop:
PYTHONPATH=~/src/_refs/volatility3 python3 /tmp/dump_hive.py \
  /tmp/szechuan-extracted/citadeldc01.mem 0xc001f1e94000 \
  /tmp/szechuan-oracle/UsrClass_Administrator_resident.dat   # → 204 KB regf hive
regipy-plugins-run /tmp/szechuan-oracle/UsrClass_Administrator_resident.dat \
  -o /tmp/szechuan-oracle/shellbags_result.json -p usrclass_shellbag_plugin
```

**Answer-key highlights** (27 items; per-node `reg_path` + `name` + `shell_type`
+ creation/access/modification FILETIMEs — enough for node-by-node cross-check):

| reg_path | name | type | mod (UTC) |
|---|---|---|---|
| BagMRU | My Computer | Root Folder | — |
| BagMRU\0 | C:\ | Volume | — |
| BagMRU\0\0 | FileShare | Directory | 2020-09-18T04:48:12 |
| BagMRU\0\0\0 → child | New folder → **Secret** | Directory | 2020-09-18T22:29:36 |
| BagMRU\0\0\2 | Administrator | Directory | 2020-09-17T16:46:26 |
| BagMRU\0\2 | **FTK Imager** | Directory | 2020-09-13T03:02:50 |
| BagMRU\0 | E:\ | Volume | — |

`FileShare\Secret` and FTK Imager independently match the documented attack
narrative (iblue.team / dfirmadness answer key), so the parse is meaningful.

**Why the test lives in issen, not here:** a real-dump test needs the bootstrap
(DTB/CR3 + kernel-base + ISF resolution) that `issen_mem::dispatch::build_reader`
owns; memf-windows alone cannot open a `.mem`. Add an env-gated
`crates/issen-mem/tests/szechuan_shellbags.rs` (mirroring `szechuan_lsadump.rs`):
`walk_hive_list` → match the UsrClass hive by VA `0xc001f1e94000` →
`memf_windows::shellbags::walk_shellbags` → assert the recovered path set contains
`FileShare`, `Secret`, `FTK Imager`, `Administrator` and the count is in range.
Same release-coupling caveat as shimcache/lsadump: needs published memf-windows
(≥ 0.2.3) or a local `[patch.crates-io]`.

Tier label: **tier-2** — real tool (regipy) on a real public image, ground truth
derivable from the capture + corroborated by the documented scenario, but the
image was self-selected. A second disk parser (RegRipper `shellbags` / SBECmd
agreeing on the same extracted `.dat`) would harden it toward tier-1.
