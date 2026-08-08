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
- **It is not a reliable identifier for names of 15+ characters.** Two different
  executables whose first 14 characters match are indistinguishable in this
  field.
- **The full path is elsewhere.** `SeAuditProcessCreationInfo.ImageFileName`
  holds the NT path; `RTL_USER_PROCESS_PARAMETERS.ImagePathName` and
  `CommandLine` hold the launch path and arguments (both reachable through the
  PEB, so they need the process address space).
- **Corroborate before naming a file.** A filesystem or registry artifact from
  the same host will give the untruncated name; the memory field alone will not.

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
