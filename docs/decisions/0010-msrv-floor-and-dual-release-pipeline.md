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
CI MSRV job guards the 1.75 promise while development uses newer-Rust ergonomics.
Releases are reviewable checkpoints (a merged release PR for libraries; a signed tag
for the binary) rather than hand-typed bumps. The dual-tag scheme needs *both*
controls in place — the `v[0-9]*` trigger and the prefixed `git_tag_name` — or a
library tag fires a binary build (or vice versa); this is documented so the pairing
is not silently dropped on a future edit.
