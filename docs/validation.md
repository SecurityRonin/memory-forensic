# Validation against real dumps + independent reference tools

memf is validated against genuine memory images, cross-checked against
**independent reference implementations** rather than its own fixtures or any
single tool treated as absolute truth. Volatility 3 is the first such reference;
MemProcFS is the planned second (see *Multi-oracle* below). A reference
implementation agreeing is strong evidence, not proof — divergences are
investigated against the raw bytes, which are the real ground truth.

## Windows pslist — DFIR Madness Case 001, DESKTOP-SDN1RPT (Windows 10)

Raw `.mem` dump (2 GB), live-acquired. memf runs its **native** EPROCESS walker
(not the Volatility passthrough) and is diffed against `vol windows.pslist`.

### Result (2026-06-14)

| Metric | Value |
|---|---|
| Volatility 3 `windows.pslist` | 95 entries (94 unique PIDs) |
| memf native `ps` | **95 entries (94 unique PIDs)** |
| PIDs in both | **94 / 94 — exact PID, PPID, name, create-time** |
| **Missed (vol3-only)** | **0** |
| **False positives (memf-only)** | **0** |

memf matches Volatility 3 **exactly**, including the duplicate `pid 4096`
empty-name rundown entry that both tools report (the 94-unique / 95-entry
discrepancy is that smeared duplicate, present in the dump itself).

### How the full list is recovered (no crash-dump header, with a smear)

1. **DTB** — recovered from the boot low stub (`PROCESSOR_START_BLOCK`):
   `0x1ad000`, matching vol3. No `--cr3` required.
2. **Kernel base** — page-granular under modern KASLR: `0xfffff80162a14000`,
   matching vol3 exactly.
3. **`PsActiveProcessHead`** — reconstructed from the ISF symbol RVA + kernel
   base (`base + 0xc1e060`).
4. **Bidirectional list walk** — `ActiveProcessLinks` is enumerated forward
   (Flink) **and** backward (Blink), unioned. A single live-acquisition smear (a
   torn-down `pid 4096` whose forward Flink reads 0 and whose Blink holds the
   non-canonical user-half value `0x5a289000`) breaks a forward-only walk after
   84 processes; the 11 processes beyond it remain reachable from the head via
   Blink and are recovered. The walk terminates on null / non-canonical links
   rather than faulting.

A process unlinked from **both** directions (full DKOM hiding) is out of scope
for the linked-list walk and is the job of pool-tag scanning (`psscan`, tracked
separately).

### Reproduce

```sh
# Reference (Volatility 3, ISF auto-downloaded from the symbol server):
vol -r json -f DESKTOP-SDN1RPT.mem windows.pslist.PsList > oracle.json

# memf native walker — zero extra knowledge required (DTB + ISF both resolved
# from the dump; --symbols points at the same ISF vol3 uses):
memf ps --symbols ntkrnlmp_81BC5C37.json --output json DESKTOP-SDN1RPT.mem > memf.json

# Compare PID sets: 0 memf-only, 0 vol3-only.
```

## Multi-oracle (in progress)

A single competitor is not ground truth. The plan is to corroborate every
finding against **at least two independent implementations** plus the raw bytes:

- **Volatility 3** — done (above).
- **MemProcFS** (Ulf Frisk) — a C/Rust engine with a different code lineage, so
  agreement is genuinely independent. **Status (2026-06-14): blocked on this
  macOS arm64 host** — `pip install memprocfs` fails to build the `memprocfs` /
  `leechcorepyc` native wheels, and the prebuilt macOS binary needs macFUSE (a
  kernel extension) to mount. The clean path is a **Linux** box: the upstream
  `MemProcFS_files…linux_aarch64` / `linux_x64` and `LeechCore` prebuilt releases
  run without a source build; mount `DESKTOP-SDN1RPT.mem` and diff `proc.txt` /
  the `windows.psscan` equivalent against memf. Tracked as the second-oracle
  step. (memf is already reconciled with Volatility 3 on *two* independent
  methods — pslist 95/95 and psscan 95/95, 0 FP — so this adds a third
  independent tool, not a missing correctness check.)
- **Published case ground truth** — the DFIR Madness write-up documents the
  incident's process activity, and the paired disk image carries the on-disk
  executables, giving a non-tool cross-reference.

Corpus provenance and hashes: see the fleet catalog
`issen/docs/corpus-catalog.md` and `issen/tests/data/README.md` (DFIR Madness
"The Case of the Stolen Szechuan Sauce", Case 001).
