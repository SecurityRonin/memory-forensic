# 10. Low MSRV library floor with a dual library+binary release pipeline

Date: 2026-07-24
Status: Accepted

## Context

This repo is both a set of publishable `memf-*` libraries and a shipped `mem4n6`
binary. The fleet MSRV policy (`~/src/ronin-issen/CLAUDE.md`) separates the dev
toolchain (pin to current stable) from the declared MSRV (a downstream promise):
published libraries keep a low, CI-verified MSRV floor, while apps declare the
pinned toolchain. Releases must be automated and reviewed, and library-crate
publishing goes through release-plz, not a hand-cut version bump — but a subtle tag
collision exists because release-plz cuts per-crate `<crate>-vX.Y.Z` tags while the
binary release fires on a `v*` tag.

## Decision

- Declare `rust-version = "1.75"` at the workspace level so every published
  `memf-*` library keeps a low, broadly-consumable floor
  (`Cargo.toml [workspace.package]`), while `rust-toolchain.toml` pins the dev
  toolchain to `1.96.0` — the two are intentionally different numbers.
- Publish libraries via release-plz (PR-based, on merge to `main`): `release-plz.toml`
  drives per-crate SemVer from conventional commits (commit `7f1fb87`).
- Ship the `mem4n6` binary + crates.io publish on a signed `v[0-9]*` tag, **not**
  `v*` — because `v*` would wrongly match release-plz's `<crate>-vX.Y.Z` tags for
  any crate whose name starts with `v` (commit `fedd5a3`). The complementary control
  sets `git_tag_name = "<crate>-vX.Y.Z"` in `release-plz.toml` so its tags never
  collide with the bare binary `vX.Y.Z` tags (commit `bde3059`).

## Consequences

Third-party consumers can depend on a `memf-*` library from an older toolchain; the
CI MSRV job guards the declared floor while development uses newer-Rust ergonomics.
Releases are reviewable checkpoints (a merged release PR for libraries; a signed tag
for the binary) rather than hand-typed bumps. The dual-tag scheme needs *both*
controls in place — the `v[0-9]*` trigger and the prefixed `git_tag_name` — or a
library tag fires a binary build (or vice versa); this is documented so the pairing
is not silently dropped on a future edit.

## Amendment (2026-11-04): floor raised to 1.89

The floor drifted from 1.75 to 1.87/1.88 before this amendment without this ADR
being updated; it is now **1.89** for every `memf-*` library except
`memf-strings`, `memf-windows` and `memf-carve` (which depends on `memf-windows`),
which declare **1.95**.

Cause: `yara-x` moved from `~1.7` to `~1.22.1`, because the 1.7 line sat on
wasmtime 36, which has no fix for RUSTSEC-2026-0315, 0325-0327, 0353-0364, 0422
and 0423, and pulled `zip` 5 (RUSTSEC-2026-0367/0368/0369/0429). yara-x 1.22.1
requires Rust 1.95 (hence 1.95 for its two users) and also `uuid >= 1.28` (Rust
1.89) and `thiserror >= 2.0.21` (Rust 1.77). The workspace has a single lockfile,
so those versions are what every member's MSRV job builds against, and the
lower floors (1.75 / 1.87 / 1.88) failed.

A consumer depending on one `memf-*` crate alone may still build it on an older
toolchain by resolving older `uuid`/`thiserror` versions; the declared floor is
what this workspace verifies, not a measured minimum for every possible
resolution. Alternatives considered: per-member MSRV resolution in fleet-ci, or
moving the yara-x crates into their own workspace.
