# 6. Self-profiling Windows symbol chain over Volatility-3 ISF, with an offline mode

Date: 2026-07-24
Status: Accepted

## Context

Walking a Windows kernel needs symbol offsets that vary per build. Bundling a
symbol catalog for every Windows version is impractical and stale by construction;
requiring a hand-picked profile burdens the analyst. Volatility 3 and MemProcFS
solve this by profiling the kernel from the dump itself. An evidence workstation may
also be air-gapped, so a symbol path that always reaches the network is unusable
there.

## Decision

Build the profile from the dump at run time, reusing the Volatility-3-compatible
ISF JSON format so an existing symbol cache works as-is:

1. Scan physical memory for `ntoskrnl`, read its PDB GUID from the CodeView record,
   resolve the matching Volatility-3 ISF (`memf-symbols` `AutoProfile`,
   `crates/memf-symbols/src/lib.rs`; downloader in `src/symbol_dl.rs`).
2. Recover the kernel base page-granularly under modern KASLR and reconstruct
   `PsActiveProcessHead` from the ISF symbol RVA + base (`docs/validation.md`).
3. Recover the DTB header-lessly from the boot low stub (`PROCESSOR_START_BLOCK`),
   following Alex Ionescu's REcon 2017 anchor cited in the README, so a raw `.mem`
   needs no `--cr3`.
4. Offer `--offline` so symbol resolution never touches the network (README Quick
   start), and support ISF plus BTF (Linux, kernel 5.2+) via one `SymbolResolver`
   trait.

## Consequences

An examiner points `--symbols` at the same ISF pack Volatility 3 uses and gets a
walk with zero extra knowledge; the air-gapped case is a first-class mode, not a
degraded one. Reusing ISF rather than inventing a symbol format keeps the tool
interoperable with the established ecosystem and makes the cross-oracle diff (ADR
0007) apples-to-apples. Full DKOM-hidden processes (unlinked in both directions) are
out of scope for the list walk and are deferred to pool-tag scanning. The full
chain — dump → kernel-scan → PDB-GUID → symbol-resolution → DTB — is implemented
clean-room in Rust (`memf-symbols`, `memf-windows`).
