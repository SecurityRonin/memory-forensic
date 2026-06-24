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

---

## Oracle FOUND (2026-06-24) — was "ORACLE HARD", now solved

**Independent tier-2 oracle: MemProcFS v5.17.8 `m_sys_netdns`.** Recovers a populated
**18-entry DNS resolver cache** from the Szechuan **DC** dump `citadeldc01.mem`
(Windows 6.3.9600 / Server 2012 R2) — a genuine answer key for `dns_cache.rs`.

Prebuilt Linux aarch64 binaries on disk at `~/mpfs_validation/mpfs/` (ELF aarch64 — runs
inside a Linux aarch64 podman container, not native macOS). Reproduce (start `podman machine`
first; the dump must live under `$HOME`, podman does NOT map `/tmp`):

```bash
cp /tmp/szechuan-extracted/citadeldc01.mem ~/mpfs_validation/citadeldc01.mem
podman run --rm --device /dev/fuse --cap-add SYS_ADMIN \
  -v ~/mpfs_validation/mpfs:/mpfs:ro -v ~/mpfs_validation/citadeldc01.mem:/dump.mem:ro \
  --platform linux/arm64 ubuntu:22.04 bash -c '
  apt-get update -qq >/dev/null 2>&1
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libfuse2 libusb-1.0-0 fuse ca-certificates >/dev/null 2>&1
  mkdir -p /mnt/mpfs; cd /mpfs
  ./memprocfs -device /dump.mem -mount /mnt/mpfs -forensic 1 >/tmp/mpfs.log 2>&1 &
  for i in $(seq 1 70); do [ -e /mnt/mpfs/forensic/csv/netdns.csv ] && break; sleep 2; done
  sleep 18; cat /mnt/mpfs/forensic/csv/netdns.csv; fusermount -u /mnt/mpfs'
```

Answer key holds the SDN1RPT victim A-record, the DC's own SRV/A/CNAME records, and benign
MS/Akamai/edge resolutions (e.g. `ieonline.microsoft.com → any.edge.bing.com → 204.79.197.200`,
`go.microsoft.com → …edgekey.net → e11290.dspg.akamaiedge.net → 23.57.58.91`). Full CSV columns:
`Address,Type,Flags,TTL,Name,Data`.

**Two caveats before trusting an end-to-end match:**
1. **Validate against the DC, not the workstation.** SDN1RPT's dump has dnsrslvr.dll loaded but
   `g_HashTable` is EMPTY (0 entries, MemProcFS-confirmed). Only `citadeldc01` is populated.
2. **Struct-layout drift.** citadeldc01 is **Server 2012 R2 (6.3.9600)**, but `dns_cache.rs`
   hardcodes `DNS_CACHE_ENTRY{Next@0,Name@8,Type@16,Ttl@20,DataLength@24,Data@32}`. Those offsets
   come from PDB symbols that differ across Windows builds — confirm the walker resolves the
   2012R2 dnsrslvr.dll symbols (MemProcFS needed the MS symbol server, reachable in-container),
   or also test a Win10 populated-cache image. vol3 has NO DNS plugin (confirmed). The published
   Szechuan writeups do NOT analyze the DNS cache (all 17 scanned) — their IOCs come from pcap/disk.

Provenance: MemProcFS v5.17.8 binary sha256 `1c4f98ba…28d6bf8`, vmm.so `bd1806fa…592258`,
release `MemProcFS_files_and_binaries_v5.17.8-linux_aarch64-20260611.tar.gz`.

---

## STRUCT LAYOUT CORRECTED (2026-06-24 de-risk) — current dns_cache.rs is WRONG for 2012R2

De-risk team finding, **independently confirmed against the code**. The existing
`dns_cache.rs` would not work on real 2012R2 data; build increments 2-4 on the
corrected model below, not the current assumptions.

**Authoritative layout** (from MemProcFS `m_sys_netdns.c`, which demonstrably parses
citadeldc01 / 6.3.9600; cross-checked vs Rekall `dns.py`, mnemonic `dnscache`):
- Per-record `DNS_RECORD64`: `vaFLink@0`, `vaName@8` (ptr → UTF-16 string, no UNICODE_STRING),
  `wType@16` (u16), `wDataLength@18` (u16), `dwFlags@20` (u32), `dwTTL@24` (u32),
  `dwReserved@28`, `pbData[16] INLINE @32`.
- **A (1):** 4 IP bytes are **inline** at +32. **AAAA (28):** 16 inline bytes at +32.
- **CNAME/PTR/NS (2,3,5,12,33,39):** read an 8-byte **pointer from pbData[0]** (`*(rec+32)`),
  then a wide string there.
- Hash table = bare **pointer-array** (size from the separate `g_HashTableSize` global, not
  an embedded field); each slot → `_HASHRECORD` (a `_LIST_ENTRY` chains hash-records via
  `oFlink`; `oDNS` → the DNS_RECORD chain).

**memf's current (wrong) assumptions** — `DNS_CACHE_ENTRY{Next@0, Name@8, Type@16, Ttl@20,
DataLength@24, Data@32-as-pointer}`, hash table with embedded `BucketCount@0`+`Buckets@8`:
- **TTL @20 is wrong** → reads `dwFlags`; real `dwTTL@24`.
- **DataLength @24 is wrong** → real `wDataLength@18`.
- **Data-as-pointer is wrong for A/AAAA** → `pbData` is **inline**; memf derefs IP bytes as a
  VA → garbage/failure. (CNAME/PTR may *accidentally* work — they really are a pointer at +32.)
- Hash-table shape wrong (no `_HASHRECORD`/`_LIST_ENTRY` indirection; no `g_HashTableSize`).
- `Next@0`, `Name@8` (UTF-16 via ptr), `Type@16` — these three are CORRECT.

**ARCHITECTURE DECISION for increments 2-4 (the key correction):**
1. **Use CODE CONSTANTS for the ≤9600 x64 record offsets — read raw bytes at fixed offsets,
   NOT `read_field("DNS_CACHE_ENTRY", …)`.** dns_cache.rs is 100% symbol-driven with no
   fallback, but **no symbol store memf loads provides user-mode dnsrslvr.dll types** — the
   offsets only ever materialize via the test `IsfBuilder`, which encodes the wrong layout
   (green tests against a self-authored wrong fixture = the LZNT1 trap). MemProcFS/Rekall pull
   these from the dnsrslvr **PDB**; memf has no user-mode-PDB loader, so carry the pre-Win10
   layout as constants (and a Win10 variant if needed). Gate by build: ≤9600 / ≤22000 / ≥22621
   (Win11 = 16-byte pointer stride).
2. **`g_HashTable` is a USER-MODE global** — must enter the Dnscache svchost address space
   (find `svchost.exe -s Dnscache` / dnsrslvr.dll module → `_KPROCESS.DirectoryTableBase` cr3
   → `reader.with_cr3`). Looking it up via the KERNEL ISF resolver returns `None` and today
   that silently becomes `Ok(empty)` — **fix to FAIL LOUD** (bootstrap-failure ≠ artifact-not-found).
3. Locate `g_HashTable` via the Rekall/MemProcFS **heuristic** (.data scan for a pointer to a
   plausible bucket array; recover size separately) since no PDB is available; validate
   (length band, ≥1 non-null, all non-null slots mapped).
4. Walk: slot → `_HASHRECORD` (`oFlink` chain, `oDNS` → record) → DNS_RECORD chain via `FLink@0`,
   reading the corrected inline/pointer `pbData` per type.

Validate the rewrite against the MemProcFS 18-entry answer key (the DC, not the empty
workstation cache).
