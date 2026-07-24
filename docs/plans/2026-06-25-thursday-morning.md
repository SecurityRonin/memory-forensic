# Thursday morning plan — 2026-06-25

> Picks up from the Wed 2026-06-24 session. Honest ledger of what's validated vs
> owed: `~/src/issen/docs/validation.md`. Resume context: `/pickup`.

## Where we are (Wed EOD)

**Pushed + CI-green:** `memory-forensic` (`eb9cd14` — CellReader backend + shellbags
migration onto winreg-core + DNS plan doc), `dpapi-forensic` (`c7c52f7` — masterkey).
**Published:** winreg-core 0.1.1, forensicnomicon 0.10.0, dpapi-core 0.1.0, dpapi-forensic 0.1.0.

**Local, NOT pushed:** `issen` main — **52 commits ahead of origin** (the gamma deck +
`issen-archive` + timeline-query Phase 1 + the ingest format fixes + the validation ledger).
Now unblocked: gamma is merged.

**Standing constraint (issen):** the uncommitted `[patch.crates-io]` in the repo-root
`Cargo.toml` and the untracked `crates/issen-mem/tests/zz_scratch_netscan.rs` are
testing-only — they MUST stay uncommitted. Stage only your files; never `git add -A`.
Lock-lag: the patched build needs `cargo update -p winreg-core --precise 0.1.1`.

---

## NOW — push issen with an honest ledger

1. **Refresh `~/src/issen/docs/validation.md`** (the merges left it stale):
   - Promote the **Timeline query (Phase 1)** row from "IN-PROGRESS" to a tier-2 entry —
     it landed (`c892f13`); oracle = raw SQL on `g1-rerun/dc01.duckdb`, the typed layer
     reproduces the deck numbers (RegistryModify 195485 / FileCreate 111240; LogonSuccess
     2540; ip=10.42.85.115 → 197).
   - Re-confirm the **Shellbags** row as CONFIRMED — the regipy 27-folder e2e passed
     post-migration (FileShare\Secret, E:\FTK Imager…); the gamma/timeline merges appear to
     have reverted the earlier "CONFIRMED" edit.
   - Commit staging ONLY `docs/validation.md`.
2. **Push issen** (`git push origin main`). Watch issen CI to green — a clean checkout runs
   the new `issen-archive` security tests (zip-slip refused, 7z vs system-7z oracle, bomb
   bound) and the whole crate for the first time on CI. If CI hits the winreg-core lock,
   the committed lock needs `0.1.1`.

## PUBLISH

3. **dpapi-core 0.1.1** — `masterkey.rs` is in the repo but `0.1.0` is the published crate,
   so the master-key derivation isn't reachable by consumers yet. Bump version, `cargo
   publish -p dpapi-core`. (Impacket-anchored: 682a9b89 / 742ab02b — already validated.)

## BUILD (forward work, gated subagent teams, worktree-isolated for issen)

4. **Finish the memf registry-parser dedup (highest value).** Only *shellbags* migrated to
   `MemfHiveReader`/winreg-core. Migrate the remaining consumers — `amcache`, `shimcache`,
   `sam`, `run_keys`, `com_hijacking`, `userassist`, `typed_urls`, `cachedump`, `hashdump`,
   `lsadump` — then delete the now-dead nk/vk/lf parser in `registry.rs` (~2,400 LoC).
   Behavior-preserving: each consumer's tests stay green; re-run the relevant Szechuan e2e
   per consumer. The CellReader foundation is already merged + dual-backend-proven.
5. **DNS walker, increments 2-4 (still NOT validated).** `dns_cache.rs` hardcodes the wrong
   2012R2 layout (Ttl@20 vs real dwTTL@24; Data-as-pointer vs inline pbData) and the walker
   is unbuilt. Build it with **code-constant offsets** (not symbol-driven `read_field` — no
   user-mode dnsrslvr PDB is available) per `docs/plans/2026-06-24-dns-cache-walker.md`;
   enter the Dnscache svchost AS (cr3), heuristic `.data` scan for `g_HashTable`, walk
   `_HASHRECORD`→DNS_RECORD. Validate vs the **MemProcFS 18-entry oracle** on
   `citadeldc01.mem`. Fail-loud on the kernel-vs-usermode symbol miss (not silent-empty).
6. **Timeline query Phase 2+.** Intent verbs (`logons`/`files`/`persistence`/`hosts`), the
   guarded read-only `--sql` escape hatch + the small filter DSL, DuckDB input mode for
   `frequency`/`session`, and finish the deck migration (`grep -c 'duckdb ' gamma-script.md`
   → 0). Validate each against `g1-rerun/dc01.duckdb` (raw-SQL oracle).
7. **dpapi step-2.** On-disk auditor (Chrome/Edge `Login Data` + cookie key, Credential
   Manager, Vault, Wi-Fi) + the `dpapi4n6` CLI, on top of the merged `masterkey`. Impacket
   as the oracle; refuse rather than fabricate where RSA domain-backup isn't implemented.

## CLEANUP

8. **netscan census** — promote TCP 51 / UDP 19511 / listeners 123 (vs vol3) from the
   forbidden `zz_scratch_netscan.rs` into a committed env-gated differential test. Today
   only the per-connection C2/malfind assertions are committed; the census is OWED.
9. **Small:** forensicnomicon LICENSE — the file exists on the remote but GitHub isn't
   classifying it (badge shows none); confirm/replace with the standard Apache-2.0 text
   (tangled with the concurrent KaC README work, so coordinate). Fix the 2 pre-existing
   `issen-mem` szechuan-test `items_after_statements` clippy lints (const-before-let).

---

## Process notes (hard-won)

- **Gated subagent teams**: implement (strict TDD, separate RED+GREEN commits) → spec
  review → quality/security review → adversarial verify. Commit local, NO push.
  **Orchestrator independently re-verifies the load-bearing claim before merging** — the
  gate is not infallible (this session a verify agent validated the wrong artifact; the
  backstop caught it). Worktree-isolate any issen work (active workshop on main).
- gitsign daemon for subagent commits (`GITSIGN_CREDENTIAL_CACHE`).
- `rtk` clippy summary LIES — verify the real cargo exit (`rtk proxy ... | grep -c '^error'`).
- Crypto/codec validation: anchor to an independent oracle on real data (impacket,
  Volatility 3, MemProcFS, regipy, system 7z), never a self-authored fixture (the LZNT1 trap).

---

## STATUS — 2026-06-25 execution run (checkpoint)

**Two hard blockers, both user-only:**
1. **gitsign re-auth** — the Sigstore OIDC token expired mid-session; the credential-cache
   daemon (PID 62640) is up but empty, so every signed commit now hangs on an interactive
   browser OIDC flow. One interactive Sigstore sign-in re-seeds the daemon → all queued
   commits flow. (Confirmed by two agents + a timed-out test: exit 124.)
2. **push** — `git push origin main` (63 commits, pre-flight-green) is blocked by the
   harness default-branch guard; needs explicit authorization or a PR.

**Per-item status:**
- **#1 validation refresh** — ✅ DONE, merged to issen main. Timeline-query Phase 1 promoted
  to tier-2 CONFIRMED (6 real-DB tests pass: histogram 195485/111240, LogonSuccess 2540,
  ip 10.42.85.115→197, injection-bound); Shellbags re-confirmed.
- **lock-lag** — ✅ DONE, merged. Committed Cargo.lock re-resolved to winreg-core 0.1.1 +
  pruned patch-leaked entries (backtrace/addr2line/…); verified by a clean published-deps build.
- **#2 push** — ⛔ BLOCKED (see above). Staged + pre-flight green.
- **#4 memf registry dedup** — 4/9 consumers DONE+verified (RED→GREEN, 0 residual `registry::`,
  clippy 0): typed_urls, userassist, amcache, com_hijacking (branch
  `feat/registry-dedup-typedurls`). run_keys RED authored + verified-failing but the commit is
  BLOCKED (recoverable as a modified file); winreg-core `ri` support CONFIRMED (recurses
  RootIndex). Remaining (all need commits): run_keys GREEN → cachedump/sam/lsadump → hashdump →
  delete registry.rs (~1,331 LoC, KEEP `walk_hive_list`). Order + per-consumer oracle in the
  driver below. **CORRECTNESS CAVEAT:** the dedup fixes the buggy trio's wrong-`_CM_KEY`-offset
  navigation *by construction* (winreg-core has the correct offsets), but cachedump/lsadump's
  **encrypted-as-plaintext fabrication** (no NL$KM / LSA-key decryption) is a SEPARATE CRITICAL
  bug the dedup does NOT close — validate those against CellHive known-cells, NOT impacket
  secretsdump; track the decryption fix as its own item.
- **#5 DNS walker** — 📋 SCOPED + ready (driver below). Correct 2012R2 offsets confirmed vs
  MemProcFS: `dwTTL@0x18` (current `Ttl@20` is the bug), inline pbData for A/AAAA. 4-increment
  TDD (bootstrap→CR3 switch→.data scan→hardcoded-offset walk); fail-loud reversal of silent-empty;
  MemProcFS `m_sys_netdns` 18-entry oracle on citadeldc01.mem (DC only — WS cache empty).
- **#6 timeline Phase 2** — 📋 SCOPED + ready (driver below). SMALLER than it looked: the deck is
  already ~native (16/19 `duckdb`-matching lines are Phase-1 commands; 2 are the `dc01.duckdb`
  filename; only line 1327 needs the new `persistence` verb). Build = 4 intent verbs
  (logons/files/persistence/hosts) + read-only `--sql` guard + small filter DSL, each with a
  raw-SQL oracle test vs g1-rerun/dc01.duckdb.
- **#7 dpapi step-2** — 4/5 decoders DONE + impacket-re-verified by orchestrator (refuse-don't-
  fabricate confirmed each): Local State cookie-key, Credential Manager, Vault (committed);
  Wi-Fi PSK (GREEN staged + verified, commit BLOCKED). CLI is the only remaining deliverable
  (needs commits). Branch `feat/dpapi-step2` in ~/src/dpapi-forensic.
- **#8 netscan census** — ⏸ QUEUED (needs commits).
- **#3 dpapi-core 0.1.1 publish** — ⏸ QUEUED (needs commit + publish).
- **#9a forensicnomicon LICENSE** — ✅ DONE on local branch `chore/license-canonical` (restored
  verbatim canonical Apache-2.0, md5 3b83ef96…). **Fleet-wide finding:** every repo's LICENSE
  (shared md5 c6fc9971, 188 lines) is a *reworded* Apache-2.0 with altered Work/Derivative-Works/
  Contribution definitions → GitHub classifies ALL as NOASSERTION. One canonical-text swap per
  repo fixes it fleet-wide.
- **#9b issen-mem clippy** — ✅ DONE on local branch `chore/issen-mem-clippy` (items_after_statements
  hoisted in szechuan_shellbags/lsadump tests).

**Also landed this session (outside this plan):** the dfirmadness zip-ingest feature — `issen
ingest DC01-E01.zip` now cracks the inner E01 (inner-container recursion + ratio bomb-cap),
validated 727,393 events / ip 10.42.85.115→197 matching the bare-E01 ingest. Merged to issen main.

**Driver plans (full file:line detail, written this run):** `$CLAUDE_JOB_DIR/tmp/{memf-registry-
dedup-plan,dns-walker-plan,timeline-phase2-plan}.md` — copy into this repo before the job tmp is
reclaimed if they're needed long-term.

**Resume order once gitsign is re-auth'd:** commit run_keys GREEN → cachedump/sam/lsadump
(navigation-fix, CellHive oracle) → hashdump (triple-hive, biggest) → delete registry.rs →
full memf-windows test → real-data e2e (regipy/RegRipper/impacket per consumer) → merge memf;
commit dpapi Wi-Fi GREEN → CLI; then #5, #6, #8, #3; merge the two `chore/*` local branches; push.
