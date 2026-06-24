# DNS resolver-cache walker (audit HIGH, network item 5)

> **For Claude:** strict TDD. The cache lives in **user-mode** (dnsrslvr.dll's heap
> inside the Dnscache svchost), so the walker must context-switch (`with_cr3`).
> The current `dns_cache.rs` resolves `g_HashTable` from the **kernel** ISF and
> silent-empties on every real dump — the bug this replaces. Tier-1 oracle is hard
> (see below); validate by recovering plausible domains on a real dump.

## The bug

`crates/memf-windows/src/dns_cache.rs::walk_dns_cache` calls
`reader.symbols().symbol_address("g_HashTable")` — a **kernel** symbol that never
exists (g_HashTable is a *user-mode* dnsrslvr.dll global). It returns `Ok(empty)`
and has **zero callers** in the repo. The DNS resolver cache (the host's recently
resolved domains — prime C2/exfil-endpoint evidence) is never recovered.

## Authoritative references

- **Rekall** `rekall-core/rekall/plugins/windows/dns.py` (`WinDNSCache`): the
  canonical algorithm — `_find_svchost_vad`, `SwitchProcessContext`,
  `dnsrslvr!g_HashTable`, and the `_verify_hash_table` heap heuristic.
- **MemProcFS** `vmm/modules/m_sys_netdns.c`: find svchost via `-s Dnscache`
  cmdline (fast) or `dnsrslvr.dll` loaded; resolve `g_HashTable`/`g_HashTableSize`
  from the dnsrslvr.dll PDB, else **the largest allocation in the topmost heap**.

## Structure (x64)

Hash table = an **array of `DNS_HASHTABLE_ENTRY*`** in dnsrslvr's heap. Two layouts:

| field | pre-Win10 | Win10 |
|---|---|---|
| `DNS_HASHTABLE_ENTRY.List` (_LIST_ENTRY) | 0x0 | 0x8 |
| `DNS_HASHTABLE_ENTRY.Name` (ptr → UNICODE_STRING/wide) | 0x8 | 0x38 |
| `DNS_HASHTABLE_ENTRY.Record` (ptr → DNS_RECORD) | 0x18 | 0x58 |

`DNS_RECORD`: `Next`@0 (ptr → DNS_RECORD), `Name`@8 (ptr → wide str), `Type`@16
(u16 enum), `DataLength`@18 (u16), `Data`@0x20. Type **A** → `Data` = 4-byte IPv4;
**AAAA** → 16-byte IPv6; **CNAME**/PTR/NS → `Data` = ptr → wide string. (memf's
existing `read_record_data` already branches A/AAAA/CNAME — reuse/realign it.)

DNS_TYPES: A=1, NS=2, CNAME=5, SOA=6, PTR=12, AAAA=28, SRV=33 (subset suffices).

## Bootstrap (all enablers already in memf)

1. **Find the Dnscache svchost** — `process::walk_processes`; for each
   `svchost.exe`, check `cmdline::walk_cmdlines` for `-s Dnscache` (fast path), or
   `dll::walk_dlls` for a loaded `dnsrslvr.dll` (fallback). Both already exist.
2. **Context switch** — `cr3 = read_field(eproc, "_KPROCESS", "DirectoryTableBase")`;
   `let proc = reader.with_cr3(cr3)` (the `iat_hooks.rs` pattern).
3. **dnsrslvr.dll base** — from the step-1 `walk_dlls` result.

## Locating `g_HashTable` (no dnsrslvr symbols → heuristic)

memf has no user-mode module PDBs, so scan for the table (Rekall/MemProcFS fallback):
- Get dnsrslvr.dll's `.data` range via **`module_section_range`** (currently
  `fn` in `shimcache.rs:28` — **extract to a shared `pe` module / `pub(crate)`**;
  the shimcache plan flagged this for the second caller, which is now DNS).
- Scan `.data` (8-byte stride) for a pointer P such that `*P` is a candidate hash
  table: an array of pointers where every non-null entry points to a
  `DNS_HASHTABLE_ENTRY` whose `Name` ptr dereferences to a **readable wide string**
  (a plausible domain). `_verify_hash_table` heuristic: length ~1600..4800 bytes,
  ≥1 non-null entry, all non-null entries point into mapped memory. (MemProcFS's
  "largest topmost-heap allocation" is the alternative if a heap walker is added —
  but the `.data`-pointer scan avoids needing one.)

## Walk

For each non-null bucket → `DNS_HASHTABLE_ENTRY`: read `Name` (wide str) + walk the
`Record` → `DNS_RECORD` `Next` chain; per record emit `{name, type, ttl, data}`
(A/AAAA/CNAME decoded). Bound the bucket count + per-bucket list length.

## TDD increments

1. **Extract `module_section_range`** to a shared `pe` module (`pub(crate)`), keep
   shimcache working (RED: a test calling it from outside shimcache; GREEN: move).
2. **`find_dnscache_svchost`** — synthetic: an `svchost.exe` _EPROCESS with
   `-s Dnscache` cmdline (and/or dnsrslvr.dll in the module list) → returns its
   eproc + cr3 + dnsrslvr base. RED/GREEN.
3. **`locate_dns_hashtable`** — synthetic dnsrslvr `.data` with a g_HashTable
   pointer → verified table. RED/GREEN.
4. **`walk_dns_cache` rewrite** — wire 2+3 + the bucket/record walk; realign the
   structs to DNS_HASHTABLE_ENTRY/DNS_RECORD (both layouts). Reuse the existing
   `read_wide_string`/`read_record_data`. Delete the kernel-symbol bootstrap.
   Add a caller in `src/main.rs` (a `dns`/`dnscache` subcommand) — it currently
   has **zero callers**.

## Oracle (HARD — no easy tier-1)

- vol3 has **no** DNS plugin. MemProcFS (`m_sys_netdns`) is not installed as a
  binary here; Rekall `dns.py` and a vol2 `dnscache` plugin are Python2 (deprecated).
- **Pragmatic validation:** run the finished walker on the Szechuan dumps and
  cross-check recovered domains against the documented attack (C2 domains,
  Windows-update/telemetry noise). Tier-2/3 (self-derived), not a third-party key.
  Stronger: build MemProcFS and diff `m_sys_netdns`, or mint a VM (nslookup known
  domains → capture RAM → the queried domains are the answer key).
- Record the owed tier-2 test (`issen` `szechuan_dnscache.rs`) once a method is
  chosen, mirroring `szechuan_lsadump.rs`.
