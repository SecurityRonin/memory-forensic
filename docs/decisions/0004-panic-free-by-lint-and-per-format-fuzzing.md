# 4. Panic-free by lint plus per-format fuzzing on untrusted dumps

Date: 2026-07-24
Status: Accepted

## Context

A memory dump is untrusted, attacker-controllable input: header fields, page
offsets, list links, and record counts can all be crafted to drive a naive parser
out of bounds or into a panic. The fleet Paranoid Gatekeeper standard
(`~/src/ronin-issen/CLAUDE.md`) requires such parsers to never panic and to be
fuzzed per parsed structure, with the static lint posture as the compile-time
partner to the runtime fuzzer.

## Decision

Deny the panic lints workspace-wide and fuzz each dump format:

- `[workspace.lints.clippy]` sets `unwrap_used = "deny"` and `expect_used = "deny"`
  (with `correctness`/`suspicious` denied), commented in `Cargo.toml`: "Panic-free:
  memory dumps are untrusted, attacker-controllable input (Paranoid Gatekeeper)."
- `fuzz/fuzz_targets/` carries one target per container format that parses raw
  bytes: `fuzz_crashdump.rs`, `fuzz_hiberfil.rs`, `fuzz_kdump.rs`, `fuzz_lime.rs`.
- The kernel-object walkers terminate on null / non-canonical links rather than
  faulting — see `docs/validation.md`, where a smeared `pid 4096` with a
  non-canonical Blink is walked past without a crash.

## Consequences

Present-robustness is proven two ways: the lints make an `unwrap`/`expect` panic
unreachable by construction, and the fuzzers exercise the claim empirically over
mutated inputs. Per the fleet robustness-wording rule, the README leads with the
measured evidence and qualifies the claim as "panic-free by lint" (commit
`b623582`) rather than a bare unprovable "panic-free" absolute. Tests may still
`unwrap` via the standard `#[cfg(test)]` allow. The cost is that every parsing path
must thread `Result`/`Option` (no ergonomic `unwrap` shortcut) and each new dump
format must ship its own fuzz target before it is considered done.
