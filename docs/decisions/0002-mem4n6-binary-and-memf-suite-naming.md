# 2. `mem4n6` binary with a `memf-*` multi-crate suite prefix

Date: 2026-07-24
Status: Accepted

## Context

This repo is a multi-crate PARSER/domain suite, not a single-format reader. The
fleet naming grammar (`~/src/ronin-issen/CLAUDE.md`, "Crate naming grammar")
distinguishes Pattern A (single-format repos: `<x>-core` + `<x>-forensic`) from
Pattern B (multi-crate suites, decomposed by concern with a short, distinctive,
self-describing prefix — e.g. `memf-*`, `winevt-*`). Front-end binaries follow the
`<x>4n6` convention (`br4n6`, `ev4n6`, `disk4n6`), where the *binary* is `<x>4n6`
and the *crate* carries a role suffix.

The binary was originally named `memf`; the crate that carries the CLI is the root
`mem4n6` package.

## Decision

Adopt the Pattern-B suite prefix `memf-` for every library member (`memf-format`,
`memf-core`, `memf-windows`, …) — a distinctive short prefix that stands alone on
crates.io — and name the user-facing binary `mem4n6` per the `<x>4n6` convention.
There is deliberately no `memory-forensic` *crate*; the repo name is the umbrella
only. The rename `memf` → `mem4n6` landed in commit `e0cb356` ("rename: memf CLI ->
mem4n6 (fleet *4n6 convention)"), with the test fixup in `899a74e`
(`cargo_bin("memf")` → `"mem4n6"`).

## Consequences

The crate namespace reads correctly bare on crates.io and in `cargo add`; the
binary name matches its siblings so an analyst who knows `disk4n6`/`ev4n6` predicts
`mem4n6`. The rename was a one-time cost (binary name, tests, README, Homebrew
formula class); doing it before wide adoption avoided a post-publish crates.io
rename (which is irreversible after the 72h window). Docstrings and
`docs/validation.md` still contain the historical `memf` invocation in some places
— a residual of the rename, harmless because both names refer to the same tool.
