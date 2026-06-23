# Shimcache Rewrite Implementation Plan

> **For Claude:** strict TDD (RED then GREEN, separate commits) per increment.

**Goal:** Replace the non-functional `g_ShimCache`-symbol walker (depends on a
fabricated symbol + `_SHIM_CACHE_HEADER`/`_SHIM_CACHE_ENTRY` types that exist in
no Windows kernel/ISF, so it silently returns empty on every real dump) with
Volatility's `ahcache.sys` `.data`-section scan.

**Scope (YAGNI):** Win8.1+/Win10 **x64** only — the fleet corpus is build 9600
(Win2012R2) and 19041 (Win10). XP/Vista/Win7 and x86 finders are explicitly out
of scope; document the `NotImplemented` path loudly (fail-loud, do not silent-empty).

**Validated oracle (tier-2 positive available):** Volatility 3
`windows.shimcachemem.ShimcacheMem` on `DESKTOP-SDN1RPT.mem` recovers **10**
entries (`C:\Windows\SysWOW64\DllHost.exe`, FTK Imager paths, …). The current
memf walker returns 0 — a demonstrable bug this rewrite fixes.

---

## Reference (authoritative)

- `~/src/_refs/volatility3/volatility3/framework/plugins/windows/shimcachemem.py`
  → `find_shimcache_win_8_or_later`.
- `~/src/_refs/volatility3/volatility3/framework/symbols/windows/extensions/shimcache.py`
  → `SHIM_CACHE_ENTRY`, `SHIM_CACHE_HANDLE`, `RTL_AVL_TABLE` validation + properties.
- `~/src/_refs/.../symbols/windows/shimcache/shimcache-win10-x64.json` → offsets.

## Algorithm (Win8.1+/Win10 x64)

1. Resolve the `ahcache.sys` module base — `kernel_modules::find_loaded_module`.
   (Win8.0 used ntoskrnl; 8.1+ moved the cache to `ahcache.sys`.)
2. Get `ahcache.sys`'s `.data` and `PAGE` section virtual ranges (PE section
   headers) — **new helper `module_section_range` (increment 1)**.
3. Scan `.data` at 8-byte stride. At each offset read a `u64` pointer; treat its
   target as a `SHIM_CACHE_HANDLE` and validate.
4. `SHIM_CACHE_HANDLE` (16 B): `eresource`@0x0 (ptr), `rtl_avl_table`@0x8 (ptr).
   Validity: `rtl_avl_table` passes `RTL_AVL_TABLE::is_valid(page_start,page_end)`.
5. `RTL_AVL_TABLE` (104 B) `is_valid`: `BalancedRoot.Parent`@0x10 == avl_offset
   (self-ref); `CompareRoutine`@0x48 and `AllocateRoutine`@0x50 both within
   `[PAGE_start, PAGE_end]`; Allocate/Compare/Free(@0x58) pointers all distinct.
6. List head = `SHIM_CACHE_ENTRY` at `rtl_avl_offset + 0x68` (avl size). Walk its
   `_LIST_ENTRY` (Flink@0x0) chain until back to head.
7. Per `SHIM_CACHE_ENTRY` (48 B): `ListEntry`@0x0; `Path`(_UNICODE_STRING:
   Length@0x0/Buffer@0x8)@0x18 → UTF-16LE path; `ListEntryDetail`@0x28 → ptr to
   `SHIM_CACHE_ENTRY_DETAIL`: `LastModified`@0x8 (FILETIME); exec_flag from the
   blob at `BlobBuffer`@0x18 (`BlobSize`@0x10 bytes, u32 → bool).

## memf infrastructure mapping

- ahcache.sys base: `kernel_modules::find_loaded_module(reader, "ahcache.sys")`.
- reads: `ObjectReader::read_bytes` (bounds-checked), `unicode::read_unicode_string`.
- PE section parse: **build `module_section_range`** (DOS `e_lfanew`@0x3C → PE
  NumberOfSections@+6 / SizeOfOptionalHeader@+0x14 → 40-byte section headers:
  Name[8]@0, VirtualSize@8, VirtualAddress@0xC). Flag for extraction to a shared
  `pe` module if a second caller appears (currently only shimcache → keep local).

## TDD increments (one RED + one GREEN commit each)

1. **`module_section_range`** — synthetic in-memory PE (DOS+PE+`.data`/`PAGE`
   section headers); RED asserts it returns the right (va,size); GREEN parses.
2. **`RTL_AVL_TABLE` validation + handle scan** — synthetic ahcache `.data` with a
   planted valid handle→avl→PAGE-resident routines; RED finds the head, GREEN scans.
3. **`SHIM_CACHE_ENTRY` list walk + parse** — synthetic LRU list of 2–3 entries
   (Path + ListEntryDetail.LastModified); RED recovers paths+times, GREEN walks.
4. **exec_flag via blob** — entry with BlobBuffer→u32; RED asserts flag, GREEN reads.
5. **Wire `walk_shimcache`** — replace the `g_ShimCache` body; delete the
   fabricated `_SHIM_CACHE_HEADER`/`_SHIM_CACHE_ENTRY` ISF deps + their synthetic
   tests; loud `NotImplemented` for unsupported OS/arch (no silent-empty).
6. **tier-2 validation (issen)** — env-gated `szechuan_shimcache.rs`: reconcile
   `walk_shimcache` against Volatility's 10 entries on `DESKTOP-SDN1RPT.mem`
   (path set + count). This is the positive oracle com_hijacking/amcache lacked.

## Fixes folded in (audit findings)

- exec_flag = `InsertFlags & 0x2` / blob bool (not `!= 0`).
- Path at +0x18 (not the old hardcoded +0x10); LastModified nested in ListEntryDetail.
- No fabricated symbol dependence; fail-loud on unsupported OS.
