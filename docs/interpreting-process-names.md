# Interpreting process names

## A 14-character process name is not a truncation bug

`ps` may report `coreupdater.ex` for a process whose executable on disk is
`coreupdater.exe`. That is the evidence, reported verbatim. Nothing was lost by
the reader.

Windows stores the process name in

```c
UCHAR ImageFileName[15];   // _EPROCESS
```

and the kernel NUL-terminates it, **reserving the final byte for the
terminator**. The field therefore carries at most **14 characters**, and any
longer executable name is truncated by Windows when the field is populated —
before any forensic tool sees it.

### Confirmed in the artifact, not inferred

From the DFIR Madness Case-001 memory image (`citadeldc01.mem`), PID 3644:

| offset | bytes | inside the `_EPROCESS` for PID 3644? |
|---|---|---|
| `0x02082cb38` | `coreupdater.ex\0` | **yes** — PID present as a `u64` within ±0x400 |
| `0x0195086ea` | `coreupdater.exe\0` | no — a different structure |

The `_EPROCESS` copy is 14 characters plus a NUL, filling all 15 bytes. The full
name does exist in the dump, but in a structure unrelated to that process object.

### What this means for an examiner

- **The short name is a faithful observation.** Cite it as what
  `_EPROCESS.ImageFileName` contained, not as the filename on disk.
- **It is not a unique identifier.** Any two executables sharing their first 14
  characters are indistinguishable here — see the collision table below.
- **The full path is elsewhere.** `SeAuditProcessCreationInfo.ImageFileName`
  holds the NT path; `RTL_USER_PROCESS_PARAMETERS.ImagePathName` and
  `CommandLine` hold the launch path and arguments (both reachable through the
  PEB, so they need the process address space).
- **Corroborate before naming a file.** A filesystem or registry artifact from
  the same host will give the untruncated name; the memory field alone will not.

## Different executables collide in this field

Truncation is lossy, so distinct filenames can share one stored value:

| executable | length | stored in `ImageFileName` |
|---|---|---|
| `MicrosoftEdgeUpdate.exe` | 23 | `MicrosoftEdgeU` |
| `MicrosoftEdgeUpdateCore.exe` | 27 | `MicrosoftEdgeU` |
| `coreupdaterupdater.exe` | 22 | `coreupdaterupd` |
| `coreupdaterupdater2.exe` | 23 | `coreupdaterupd` |

The first pair is not contrived: those are two real, separately signed Microsoft
binaries that this field cannot tell apart.

Two consequences follow.

**The stored value often is not recognisable as a filename.** `MicrosoftEdgeU`
has lost its extension entirely. An examiner who does not know the 14-byte limit
gets no cue that anything was cut — unlike `coreupdater.ex`, where the mangled
`.ex` hints at it.

**It is a masquerading vector.** An attacker who names a binary so that its first
14 characters match a legitimate process produces an identical `ImageFileName`.
A process list alone cannot separate them, and the collision needs no trickery
beyond choosing a long enough name.

So for any process whose stored name is exactly 14 characters — the tell that
truncation may have occurred — treat the name as a **prefix**, not an identity,
and resolve it against the full path (`SeAuditProcessCreationInfo.ImageFileName`,
`RTL_USER_PROCESS_PARAMETERS.ImagePathName`) or against a filesystem artifact
before attributing behaviour to a named program.

### Why we do not "fix" it

Rewriting `coreupdater.ex` to `coreupdater.exe` because the longer name is
expected would fabricate evidence — the tool would be reporting a value that is
not in the dump. The field is reported as found; fuller names are surfaced as
separate, attributed enrichment.

### Same shape elsewhere

Linux `task_struct.comm` is `char[16]` with the same reserve-a-byte behaviour
(15 usable characters), so long process names truncate there too. Treat any
fixed-size kernel name field as a candidate: check the raw bytes before
concluding a parser is at fault.
