# 5. Confidence-scored inventory plugin registry for dump-format detection

Date: 2026-07-24
Status: Accepted

## Context

`mem4n6` must accept "every common dump format" from a single `mem4n6 info <dump>`
with no `--format` flag — the secure/zero-config default the fleet UX standard
demands. Formats overlap (a raw dump has no magic; a crash dump and a hiberfil both
have distinct headers), so detection must resolve ambiguity honestly rather than
silently pick the first match. Bytes may also arrive from a generic reader (a byte
source, not a path), e.g. 4n6mount's memory mount.

## Decision

Register each format as an `inventory`-collected `&'static dyn FormatPlugin`
(`crates/memf-format/src/lib.rs:171,189`). Detection reads the first 4096 bytes and
asks every plugin for a confidence score 0–100 (`pick_plugin`, `lib.rs:294`); a
score ≥ 80 wins immediately, otherwise the highest score ≥ 50 wins, and a **tie at
the top** — two plugins at the same highest score ≥ 50 — is a **loud**
`ambiguous format` error (`Error::AmbiguousFormat`, `lib.rs:19`), never a silent
guess (a 70-vs-55 pair is not ambiguous — 70 wins). When nothing reaches 50, the
best score ≥ the fallback floor is accepted (20 on the normal path); if nothing
qualifies, `unknown format`. The raw plugin deliberately scores 5, below the
normal floor of 20, so it never shadows a recognized format and is rejected on the
default path; a caller that genuinely wants raw-as-last-resort opts in via
`open_source_with_raw_fallback` (`lib.rs:254`), which lowers the fallback floor
to 1 so raw's 5 qualifies. Path-based `open_dump` and reader-based `open_source`
share one `open_dump_inner`/`open_source_inner` core so detection logic lives once.

## Consequences

Adding a format is a self-contained `inventory::submit!` with a scoring function —
no central match arm to edit. Ambiguity surfaces as an error the analyst can act on
(fail-loud), and raw never masquerades as a structured format. The scoring cutoffs
(80 immediate, 50 accept, 20 normal fallback floor / 1 raw-fallback, 5 raw) are
tuned constants that a pathological near-collision could still trip; the top-tie
`ambiguous` error is the backstop that keeps such a case honest rather than
silently wrong.
