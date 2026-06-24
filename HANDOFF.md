# memory-forensic — working handoff (2026-06-24)

HEAD `eb50f9a`, pushed, clean tree. gitsign daemon live (socket
`$HOME/Library/Caches/sigstore/gitsign/cache.sock` — export `GITSIGN_CREDENTIAL_CACHE`).

## Done this push series (validated on citadeldc01.mem vs vol3)
- **Windows netscan — full parity**: `scan_tcp_endpoints` (51), `scan_udp_endpoints`
  (19511), `scan_tcp_listeners` (123), IPv6/dual-stack, freed-pool offset-dedup, the
  `_LOCAL_ADDRESS` double-vs-single deref fix (correct `::1`/`127.0.0.1`/`fe80` addrs),
  CLI wiring (cmd_net/vol-net/timeline → symbol-free scanners + UDP+listeners).
- **Shellbags-from-memory** verified (27 folders, regipy oracle match).
- **DNS increment 1**: `module_section_range` → shared `crate::pe` module.

## Plan docs (docs/plans/2026-06-24-*.md)
- `dns-cache-walker.md` — increments 2-4 (find Dnscache svchost → locate g_HashTable
  via dnsrslvr `.data` scan → walk rewrite + CLI subcommand). ORACLE HARD (no vol3 DNS
  plugin, no MemProcFS binary; validate by recovering plausible domains from Szechuan).
- `fleet-dry-audit.md` — ranked DRY findings (below).
- `network-listeners-udp-ipv6.md`, `shellbags-rewrite.md` — done, kept for provenance.

## DRY roadmap (ranked, all independently shippable)
1. **[BUG] hand-rolled RC4** in `hashdump.rs::rc4_crypt` → use the `rc4` crate. Quick,
   golden-vector-guarded.
2. **[LARGE] registry CellReader unification** — memf reimplements ~2400 LoC of
   nk/vk/lf parsing winreg-core/winreg-format own. Add a `CellReader` trait to
   winreg-core; memf supplies the HMAP backend. Cross-repo, multi-step, own effort.
3. **[CLEAN] prefetch.rs → prefetch-core** delegation.
4. **[LOW] PE offset decoders** (dup 3× in pe.rs/iat_hooks/hollowing) → forensicnomicon.
5. **[QUICK] pure registry helpers** (rot13, value decoders) share now.
6. **[CLEAN] dpapi-core/dpapi-forensic split** — new `~/src/dpapi-forensic` repo
   (ntfs-forensic template): core/ (blob/decrypt/chrome from memf + new masterkey.rs)
   + forensic/ (auditor + dpapi4n6 CLI); memf depends on dpapi-core, keeps LSASS
   `dpapi_keys.rs`. (Finding 3b in the audit doc.)
- Correctly NOT shared: live-kernel-struct walkers, container provider trait.

## issen e2e (uncommitted, testing-only — DO NOT COMMIT/PUSH to issen)
- `~/src/issen/Cargo.toml` has a local `[patch.crates-io]` → `../memory-forensic/crates/*`.
- `~/src/issen/crates/issen-mem/tests/zz_scratch_netscan.rs` scratch validator.
- e2e: `SZECHUAN_DC_MEM=/tmp/szechuan-extracted/citadeldc01.mem cargo test -p issen-mem --test <name> -- --ignored --nocapture`.
- Tier-2 tests `szechuan_netscan.rs`/`szechuan_shellbags.rs` owed once memf-windows is
  published (compile against a release, not the local patch).

## Gotchas
- rtk clippy summary LIES — verify real exit: `rtk proxy cargo clippy -p <crate> --all-targets -- -D warnings`.
- Strict TDD: separate RED + GREEN commits. `memf` CLI symbol auto-download is
  sandbox-blocked (vol3 ISF cache under the mise python install); issen `build_reader`
  resolves symbols fine.
- Re-extract dumps to /tmp from `tests/data/dfirmadness-szechuan-sauce` if /tmp cleared.
