# Validation against real dumps + Volatility 3 oracle

memf is validated against genuine memory images with **Volatility 3 as the
independent oracle**, not only synthetic fixtures. This document records the
reproducible differential runs.

## Windows pslist — DFIR Madness Case 001, DESKTOP-SDN1RPT (Windows 10)

Raw `.mem` dump (2 GB), live-acquired. memf runs its **native** EPROCESS walker
(not the Volatility passthrough) and is compared to `vol windows.pslist`.

### Result (2026-06-14)

| Metric | Value |
|---|---|
| Volatility 3 `windows.pslist` | 95 processes |
| memf native `ps` | 84 processes |
| PIDs in common | 83 |
| **False positives (memf-only)** | **0 (100% precision)** |
| Name / PPID / create-time agreement on shared PIDs | exact (the one `pid 4096` empty-name rundown entry excepted) |
| Missed (vol3-only) | 11 |

The 11 missed processes (ShellExperienceHost, RuntimeBroker ×3, FTK Imager,
msinfo32, WmiPrvSE, audiodg, …) are **all the processes after an acquisition
smear**: a torn-down EPROCESS (`pid 4096`, empty name, at VA `0xffffbe8e78a40080`)
whose `ActiveProcessLinks.Flink` was captured as `0` and whose `Blink`
(`0x5a289000`) is a non-canonical user-space value. The on-disk bytes really are
zero (confirmed by reading the translated physical page), so memf reads the dump
faithfully; the forward linked-list walk terminates there by construction. The
oracle itself shows the smear — it lists **two** `pid 4096` empty-name entries.

Recovering the orphans behind the smear requires **pool-tag scanning** (the
`psscan` technique: scan for `Proc`/`Pr\xe9` pool allocations rather than
following `ActiveProcessLinks`). That is tracked as the next enhancement; the
linked-list walker is correct and complete for the reachable list.

### What this validates

- **Header-less auto-profiling** on a raw `.mem`: low-stub DTB recovery
  (`0x1ad000`, matches vol3), **page-granular** kernel-base discovery
  (`0xfffff80162a14000`, matches vol3 exactly — modern KASLR is not 2 MiB
  aligned), and `PsActiveProcessHead` reconstruction from the ISF symbol RVA
  (`base + 0xc1e060`).
- **x86-64 4-level VA translation** and **`_EPROCESS` field decoding**
  (UniqueProcessId, InheritedFromUniqueProcessId, ImageFileName, CreateTime,
  ActiveThreads, Pcb→DirectoryTableBase) — 83/83 shared entries agree with vol3.
- **Smear tolerance**: the walk returns the 84 reachable processes instead of
  hard-erroring on the null link.

### Reproduce

```sh
# Oracle (Volatility 3, ISF auto-downloaded from the symbol server):
vol -r json -f DESKTOP-SDN1RPT.mem windows.pslist.PsList > oracle.json

# memf native walker (raw dump opened via the archive, DTB + ISF supplied):
#   - DTB 0x1ad000 is what the low stub recovers automatically
#   - the ISF is the same one vol3 resolves: ntkrnlmp.pdb/81BC5C37...-1
memf ps --symbols ntkrnlmp_81BC5C37.json --cr3 0x1ad000 --output json \
    DESKTOP-SDN1RPT-memory.zip > memf.json

# Compare PID sets: 0 memf-only, 11 vol3-only (all behind the smear).
```

Corpus provenance and hashes: see the fleet catalog
`issen/docs/corpus-catalog.md` and `issen/tests/data/README.md` (DFIR Madness
"The Case of the Stolen Szechuan Sauce", Case 001).
