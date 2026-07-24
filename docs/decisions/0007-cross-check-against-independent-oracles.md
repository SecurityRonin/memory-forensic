# 7. Correctness validated against independent reference tools, not self-authored fixtures

Date: 2026-07-24
Status: Accepted

## Context

For an evidence tool the bar is correctness, and tests an author writes against
fixtures the author generated inherit the author's blind spots (the fleet
Doer-Checker / Evidence-Based-Rigor discipline). A memory walker is exactly the case
where an independent oracle exists: mature reference implementations (Volatility 3,
MemProcFS) already decode the same dumps.

## Decision

Validate the walkers differentially against independent reference implementations on
real dumps, treating a reference's agreement as strong evidence and the raw bytes as
the ground truth (`docs/validation.md`; `docs/steelman-vs-reference-tools.md`):

- Primary oracle: Volatility 3 `windows.pslist` on the DFIR Madness Case 001
  DESKTOP-SDN1RPT 2 GB Windows 10 dump — mem4n6's **native** EPROCESS walker (not a
  Volatility passthrough) is diffed PID-for-PID: 94/94 shared PIDs exact on PID,
  PPID, name, create-time; 0 missed; 0 false positives, including the 11 processes
  recovered past a live-acquisition smear via a bidirectional `ActiveProcessLinks`
  walk.
- Second oracle (done, 2026-06-14): MemProcFS, whose 77-process list is confirmed a
  clean subset of memf's with zero MemProcFS-only processes (`docs/validation.md`).
- The `docs/validation.md` entry records the exact reproduce commands so a third
  party can re-run the diff.

## Consequences

A regression that diverges from Volatility 3 is caught by a real differential, not
by a fixture the code was tuned to pass. The README comparison table states
capabilities as facts and lets the *measured* diff carry the standing, per the
no-self-grade rule. Divergences (e.g. the 94-unique/95-entry smeared-duplicate) are
investigated against the raw bytes rather than papered over. The cost is a
real-dump corpus and the reference tools installed, so the differential is a
separate, corpus-gated job (`MEMF_TEST_DATA`), not a bytes-only CI gate.
