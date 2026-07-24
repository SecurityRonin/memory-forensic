# 3. `unsafe_code = "deny"` workspace-wide with a bounded per-site mmap allow

Date: 2026-07-24
Status: Accepted

## Context

The fleet default is `unsafe_code = "forbid"` — a provable, badge-able "zero places
a crafted input can corrupt memory" (`~/src/ronin-issen/CLAUDE.md`, the unsafe
cost-benefit law). `forbid` cannot be locally overridden. A handful of memf paths
legitimately need one bounded `unsafe`: memory-mapping a pagefile so its bytes can
be read positionally without copying the whole file.

## Decision

Set `unsafe_code = "deny"` (not `forbid`) at the workspace level, and grant a
justified per-site `#[allow(unsafe_code)]` only where the mmap actually happens.
The two allow sites are in `crates/memf-core/src/pagefile.rs` (lines 44 and 89);
every other `unsafe` in the workspace remains a hard error. The `[workspace.lints]`
comment in `Cargo.toml` records the rationale inline: "unsafe is denied
workspace-wide, not forbidden: a handful of crates legitimately need one bounded
mmap site (memf-core::pagefile) … `deny` (not `forbid`) is what makes the local
override possible."

## Consequences

`rg 'allow(unsafe_code)'` is the complete audit surface — two pure-Rust, no-C-FFI
mmap sites, the smaller liability class the fleet accepts for perf. The tool cannot
wear an "unsafe-forbidden" badge; the README badge is honestly "unsafe: bounded
(mmap only)" instead, matching the fleet rule against over-claiming. The trade is
that memory-mapping a pagefile shifts the memory-safety burden to a human at those
two sites, accepted for the zero-copy positioned-read benefit over an untrusted but
locally-sourced pagefile.
