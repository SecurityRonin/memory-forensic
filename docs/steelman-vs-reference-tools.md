# Steelman: `memf-symbols` vs Volatility 2/3, Rekall, MemProcFS

> **Clean-room / licensing notice.** Volatility 2 & 3 ship under the Volatility
> Software License 1.0, Rekall under GPLv2, and MemProcFS under
> AGPL/GPL-family terms. **No code from any of these tools has been or may be
> copied into this repository.** This document cites the reference
> implementations purely to describe the *techniques* (algorithms and
> heuristics) they use, so that we can reimplement those techniques
> independently. Every code reference below is a citation for an algorithm, not
> a source to copy. All file:line references point at the locally cloned
> reference trees under `~/src/_refs/`.

---

## Executive Summary

**Our two core kernel-discovery algorithms are sound and closely track the
authoritative tools.** The header-less DTB discovery in
`kernel_scanner.rs::enumerate_self_ref_pml4s` is the same self-referential-PML4
technique as Volatility 3's `DtbSelfReferential`
(`volatility3/framework/automagic/windows.py:41-131`), and our physical RSDS
sweep `scan_physical_for_kernel_rsds` is the same physical-layer CodeView scan
as Volatility 3's `PDBUtility.scan` / pdbscan
(`volatility3/framework/automagic/pdbscan.py`). On the real Case 001 DC dump
both succeed: 41 self-ref PML4 candidates at index `0x1ED`, kernel DTB
`0x1a7000`, and a recovered `ntkrnlmp.pdb` GUID. The algorithm class is correct.

**The single most important gap is that we never recover the kernel base
*virtual* address (the "kernel virtual offset", KVO).** Every reference tool
treats kernel-base-VA recovery as a distinct, mandatory step *after* the
GUID/profile is known, because **symbols in the PDB/ISF are stored as RVAs
(offsets from the image base), not absolute VAs.** Our
`scan_physical_for_kernel_rsds` returns only the `PdbId` (GUID + age + name) and
our `SymbolResolver::symbol_address` (`memf-symbols/src/pdb_resolver.rs:334`,
`memf-symbols/src/isf.rs:151`) returns the **raw RVA** from the symbol map with
no base added. So when `memf ps` resolves `PsActiveProcessHead` it gets the bare
RVA `0x2b00a0` and tries to walk a list head at virtual address
`0x00000000002b00a0` — a user-space-looking, unmapped address. That is exactly
the observed failure:

```
windows ps walk failed: page not present at virtual address 0x00000000002b00a0
```

`0x2b00a0` is `PsActiveProcessHead`'s **RVA**; the real VA is
`kernel_base_va + 0x2b00a0` (on x64 a canonical `0xFFFF_F80x_xxxx_xxxx`
address). **The fix is to recover the kernel base VA and add it to every symbol
RVA before dereferencing.** This is a missing step, not a broken algorithm.

### Verdict on our algorithms

| Algorithm | Verdict |
|---|---|
| Self-ref DTB discovery (`enumerate_self_ref_pml4s`) | **ALIGNED** with vol3 `DtbSelfReferential` (with refinements to adopt — §3) |
| Header-less DTB discriminator (`scan_for_kernel_dtb` / `locate_pe_via_dtb`) | **ALIGNED** — same MZ-then-RSDS validation as MemProcFS `FindNtosScan64` |
| Profile/GUID recovery (`scan_physical_for_kernel_rsds`) | **ALIGNED** with vol3 pdbscan physical RSDS scan |
| **Kernel base VA (KVO) recovery** | **MISSING** — the cause of the `0x2b00a0` ps failure |
| 4-level + large-page translation (`translate_va`) | **WEAKER** — confirm 2 MiB / 1 GiB large-page handling matches vol3 `Intel._PAGE_BIT_PSE` |
| EPROCESS list-walk (`walk_list_with`) | **WEAKER** — bounded counter only; no `seen`-set loop detection or sentinel flag like vol3 `list_walk` |

---

## Algorithm-by-Algorithm Comparison

Legend: **ALIGNED** (we match the reference technique), **WEAKER** (correct but
less robust than the reference), **MISSING** (the reference does this and we do
not).

### 1. DTB discovery (Directory Table Base / CR3)

| Tool | Technique (cited) |
|---|---|
| **Vol 2** | DTB comes from `KDBG` (the debugger data block) once KDBG is located. `get_kdbg` scans for the `KDBG` `OwnerTag` pool tag, or bounces via the `_KPCR` on x86 (`volatility/win32/tasks.py:34-83`; `volatility/plugins/kdbgscan.py:69-100`). The Idle/System process DTB is then read from the located structures. |
| **Vol 3** | Header-less self-referential PML4 scan: `PageMapScanner` runs `DtbSelfReferential` tests over the physical layer (`automagic/windows.py:41-131`). For each page it looks for a pointer back into the same page (`ptr & mask == page_addr`), requiring the present bit (`ptr & 0x01`), rejecting entries with the reserved bit set (`reserved_bits=0x80`), and — for randomized layouts — requiring **exactly one** self-reference in the page (`len(ref_pages) == 1`, line 84) whose index falls in `valid_range` (x64 fixed `[0x1ED]` for 2012 R2-era, `range(0x100,0x1FF)` for randomized 1607+). |
| **Rekall** | DTB harvested by scanning for `_EPROCESS` candidates and reading `Pcb.DirectoryTableBase`, then *verifying* each by building an address space and reflecting through `_KUSER_SHARED_DATA` and `ThreadListHead` (`plugins/windows/common.py:134-190`, `WinFindDTB.dtb_eprocess_hits` / `VerifyHit` / `TestEProcess`). |
| **MemProcFS** | Robust C heuristics that scan low physical memory for the System-process DTB and validate by attempting a kernel-base scan through it (`vmm/vmmwininit.c`, `VmmWinInit_FindNtosScan64` walks `pSystemProcess->paDTB`). |
| **Ours** | `enumerate_self_ref_pml4s` (`kernel_scanner.rs:258-296`): for each candidate PML4 page, treat it as self-referencing if `is_self_ref(SELF_MAP_INDEX=0x1ED)` **or** any index in `0x100..0x200` self-references; then `scan_for_kernel_dtb` (`:389`) picks the candidate whose page tables map an ntkrnlmp/ntoskrnl PE with a valid RSDS. |

**Verdict: ALIGNED.** We use vol3's exact class of technique and additionally
disambiguate with a kernel-PE validation (closer to MemProcFS). **Steelman
improvements:** adopt vol3's three precision rules we currently lack — the
`len(ref_pages) == 1` "exactly one self-ref" rule, the reserved-bit (`0x80`)
early reject, and the `0x1a0000`–`0x1b0000` physical prior for randomized
layouts (§3).

### 2. Kernel base / profile (GUID) recovery

| Tool | Technique (cited) |
|---|---|
| **Vol 2** | Profile is a *prebuilt* class chosen by KDBG version block; no GUID-from-RSDS step. Kernel base read from `KDBG.KernBase`. |
| **Vol 3** | Two separable results: (a) the **GUID/profile** from a CodeView `RSDS` record found by `PDBUtility.pdbname_scan` over a layer; (b) the **kernel virtual offset (KVO)** computed separately — see §4. `_method_offset`/`method_module_offset` scans the *physical* layer for the `\SystemRoot\system32\nt` module-path string and the `MZ`/`KDBG` anchors, derives a candidate VA, then confirms it via `check_kernel_offset` reading `MZ` at that VA and re-scanning for the kernel PDB name (`automagic/pdbscan.py:296-393`). |
| **Rekall** | Profile chosen by `guess_profile.py` heuristics; kernel base from the verified address space. |
| **MemProcFS** | `VmmWinInit_FindNtosScan64` (`vmmwininit.c:516-560`) walks the System DTB's page tables (large-page pass then small-page pass), reads each candidate region, and accepts a base when the page begins with `MZ` (`0x5a4d`) **and** contains the `POOLCODE` tag (`0x45444F434C4F4F50`) — optionally confirming the module name is `ntoskrnl.exe`. The returned `vaBase + p` **is** the kernel base VA. |
| **Ours** | `scan_physical_for_kernel_rsds` (`kernel_scanner.rs:106-136`) sweeps physical ranges for a kernel-named CodeView RSDS and returns a `PdbId` (GUID/age/name) **only**. `locate_pe_via_dtb` (`:321`) does find a kernel PE *via the DTB* and therefore *transiently knows the VA where it found it* — but that VA is discarded; only the GUID is returned. |

**Verdict: WEAKER / partially MISSING.** We recover the GUID correctly but
**throw away the kernel base VA we already computed inside `locate_pe_via_dtb`.**
**Steelman improvement:** have the DTB-based locator return the *virtual
address* at which it found the ntoskrnl `MZ`/RSDS, exactly as MemProcFS returns
`vaBase + p`. This is the §4 fix.

### 3. `PsActiveProcessHead` resolution

| Tool | Technique (cited) |
|---|---|
| **Vol 2** | `PsActiveProcessHead` is read from the located **KDBG** structure (`KDBG.PsActiveProcessHead`), which already holds an absolute VA — no RVA-to-VA math needed because KDBG stores live pointers (`win32/tasks.py:85-89`, `pslist` → `get_kdbg(addr_space).processes()`). |
| **Vol 3** | Symbol RVA from the ISF **plus the KVO**: vol3 sets `kernel_virtual_offset` on the layer (`pdbscan.py:151-172 set_kernel_virtual_offset`) and the symbol table is rebased to it, so `module.get_symbol("PsActiveProcessHead").address` resolves to `KVO + RVA`. The list is then walked with `list_walk` (`extensions/__init__.py:1079`). |
| **Rekall** | Resolves `PsActiveProcessHead` against the kernel module loaded at its verified base (base + symbol offset). |
| **MemProcFS** | `PDB_GetSymbolAddress(PDB_HANDLE_KERNEL, "PsActiveProcessHead", &vaPsActiveProcessHead)` (`vmmwininit.c:190-196`), where the kernel PDB handle is anchored at the recovered `H->vmm.kernel.vaBase` (`:704`); `PE_GetProcAddress` returns `vaBase + rva`. |
| **Ours** | `walk_processes(reader, ps_head_vaddr)` (`memf-windows/src/process.rs:17`) is handed whatever `symbol_address("PsActiveProcessHead")` returns. That resolver (`pdb_resolver.rs:334`, `isf.rs:151`) returns the **bare RVA** with no base. Hence `ps_head_vaddr == 0x2b00a0`. |

**Verdict: MISSING (the base add).** Every reference resolves
`PsActiveProcessHead` to an absolute VA; we feed the walker an RVA.
**Steelman improvement:** rebase all symbol lookups by the recovered KVO (§4)
before they leave `ObjectReader`.

### 4. EPROCESS list-walk

| Tool | Technique (cited) |
|---|---|
| **Vol 2** | `get_kdbg(addr_space).processes()` walks `ActiveProcessLinks` from `PsActiveProcessHead` (`win32/tasks.py:85`). |
| **Vol 3** | `list_walk` (`extensions/__init__.py:1079-1128`): computes `relative_child_offset(member)` for `ActiveProcessLinks` (from the ISF, **not hardcoded**), supports `forward`/`backward` (Flink/Blink) and a `sentinel` flag, and detects cycles with a `seen` set seeded with the head: `seen = {self.vol.offset}` / `while link.vol.offset not in seen` (lines 1115-1128). Each hop subtracts the relative offset to recover the `_EPROCESS` base (container-of). |
| **Rekall** | Walks the list and cross-validates membership via `psxview`-style reflection (`TestEProcess`, `plugins/windows/common.py:159-178`). |
| **MemProcFS** | Walks `ActiveProcessLinks` with bounds and validity checks per node, tolerant of unmapped/DKOM-corrupted links. |
| **Ours** | `walk_list_with` (`object_reader.rs:147-185`): reads `ActiveProcessLinks`/`Flink` offsets **from the symbol table** (good — not hardcoded), does container-of by subtracting `list_offset`, terminates on return-to-head, and bounds the loop with `MAX_LIST_ITERATIONS`. |

**Verdict: WEAKER.** We match the offset-from-ISF discipline and container-of
math, but our loop guard is **only** a fixed counter plus head-equality. A
DKOM-corrupted or partially-overwritten list that loops *without* passing
through the head walks `MAX_LIST_ITERATIONS` full iterations (re-reading the
same nodes) before erroring, and can emit duplicate `_EPROCESS` entries.
**Steelman improvement:** add a vol3-style `seen` set seeded with the head
offset and break on revisit (§5).

### 5. Large-page address translation

| Tool | Technique (cited) |
|---|---|
| **Vol 3** | `Intel`/`WindowsIntel32e` honors the Page Size Extension bit: `_PAGE_BIT_PSE = 7`, `_PAGE_PAT_LARGE` at bit 12 (`layers/intel.py`), so a PDE/PDPTE with PSE set terminates translation early and the low bits of the VA index *into* the 2 MiB / 1 GiB page rather than a lower table. The kernel and much of the System DTB are mapped with 2 MiB large pages, so a walker that ignores PSE mistranslates kernel-half VAs. |
| **MemProcFS** | Has explicit large-page and small-page passes (`VmmWinInit_FindNtosScan64_LargePageWalk` vs `_SmallPageWalk`, `vmmwininit.c:445/408`) precisely because the kernel may be mapped either way. |
| **Ours** | `translate_va` (`kernel_scanner.rs:474`) implements 4-level paging; large-page (PSE bit 7) early-termination handling must be confirmed present for both the kernel-base scan *and* the EPROCESS walk. |

**Verdict: WEAKER (verify).** If `translate_va` does not early-terminate on the
PSE bit at the PDPTE (1 GiB) and PDE (2 MiB) levels, any kernel-half VA that is
large-page mapped — which includes `PsActiveProcessHead` on many builds — will
translate to the wrong physical page even once the KVO is correct.
**Steelman improvement:** assert PSE handling at PDPTE and PDE levels mirrors
vol3 `_PAGE_BIT_PSE`, and add a fixture that maps the list head behind a 2 MiB
large page.

---

## Validated Refinements to Adopt (DTB discovery)

These are precision rules the references already apply that would reduce our 41
candidates toward a single correct DTB. Each is cited.

1. **"Exactly one self-reference per page" rule.** Vol3 collects every
   self-referencing index in a page into `ref_pages` and accepts the page only
   when `len(ref_pages) == 1`
   (`automagic/windows.py:84-86`). The real DTB is extremely unlikely to point
   to itself at more than one index, so a page with multiple self-refs is noise.
   Our `enumerate_self_ref_pml4s` currently accepts on the *first* self-ref it
   finds; switching to "collect all, require exactly one, and require that one's
   index be in the valid range" should sharply cut the 41-candidate set.

2. **Reserved-bit early reject.** Vol3's x64 `DtbSelfReferential` uses
   `reserved_bits = 0x80` (`windows.py:108-120`) and rejects any candidate
   entry with that bit set (`if (ptr & self.reserved_bits) ...` at `:74`), since
   a valid top-level PML4 self-map entry does not set it. We do not currently
   test this bit.

3. **Physical-range prior for randomized self-ref.** For 1607+ randomized
   self-map layouts, vol3 documents that the DTB physical offset "was always
   within the range of `0x1a0000` to `0x1b0000`" and scans only those pages
   first (`windows.py:11-14` and the `test_sets` region-scan in
   `automagic/windows.py`). Our recovered DTB `0x1a7000` sits squarely in that
   window — confirming the prior. Prioritizing this band would let us *rank* the
   41 candidates instead of treating them equally.

4. **Region-prioritized scan order.** Vol3's `WindowsIntelStacker.test_sets`
   runs the scan over ordered `(description, tests, sections)` tuples so the
   high-probability physical regions are searched before a full sweep
   (`automagic/windows.py`). Adopting the same ordering makes our scan both
   faster and more deterministic in its first hit.

---

## The Kernel-Base-VA Fix (next RED → GREEN task)

**Problem restated.** Profile/GUID recovery works; the EPROCESS walk fails
because symbol RVAs are dereferenced without a base. We must recover the kernel
base VA (KVO) and rebase symbols by it.

**Reference algorithm (cited).** The cleanest model is **MemProcFS
`VmmWinInit_FindNtosScan64`** (`vmm/vmmwininit.c:516-560`), which is exactly what
our `locate_pe_via_dtb` already half-does:

1. Walk the recovered kernel DTB's page tables over the kernel VA range
   (x64: `0xFFFFF800'00000000` upward), large-page pass then small-page pass.
2. For each mapped region/page, accept it as the kernel base when the page
   begins with `MZ` (`0x5a4d`) **and** the image contains the `POOLCODE` tag
   (`0x45444F434C4F4F50`) — optionally confirming the module name is
   `ntoskrnl.exe`.
3. The **virtual address** at which this PE was found *is* the kernel base VA
   (`return vaBase + p`).

Vol3 expresses the same idea differently: it derives a candidate kernel VA from
the physical anchor scan, then `check_kernel_offset` reads `MZ` at that VA and
re-scans for the kernel PDB name to confirm
(`automagic/pdbscan.py:361-393`), and finally records it via
`set_kernel_virtual_offset` so the symbol table is rebased
(`pdbscan.py:151-172`).

**What we are missing, precisely.** `scan_physical_for_kernel_rsds` returns
`Option<PdbId>` — the GUID only. But `locate_pe_via_dtb` (`kernel_scanner.rs:321`)
*already translates a kernel VA → finds the ntoskrnl `MZ`/RSDS via the DTB*. It
has the kernel base VA in hand at the moment of the match and discards it.

**The fix (RED → GREEN):**

- **RED:** add a failing test asserting that header-less kernel recovery on a
  DTB fixture (kernel mapped at a canonical `0xFFFF_F80x_…` VA) returns **both**
  the `PdbId` **and** the kernel base VA, and that
  `kvo + rva(PsActiveProcessHead)` equals the fixture's planted head VA (not the
  bare RVA). Mirror the existing `build_dtb_fixture` tests in
  `kernel_scanner.rs` (`map_kernel_under_pml4`, `securitynik_guid`).
- **GREEN:** change `locate_pe_via_dtb` to return the matched kernel **base
  VA** alongside the `PdbId` (e.g. `Option<(PdbId, u64 /* kvo */)>`), thread it
  up through `scan_for_kernel` / `scan_for_kernel_via_dtb`, and store it as the
  layer's KVO. Then make `ObjectReader::required_symbol` /
  `symbol_address` return `kvo + rva` instead of the bare RVA — the single
  structural fix that makes `PsActiveProcessHead` (and every other symbol)
  resolve to an absolute VA. After this, `ps_head_vaddr` becomes
  `kvo + 0x2b00a0` (a canonical kernel VA) and the page-present error
  disappears.

**Secure-by-design note.** Rebasing belongs **inside** `ObjectReader`, not at
each call site. If `walk_processes` and every other walker must remember to add
the base, one forgotten call site silently dereferences an RVA. Make
`symbol_address` return an absolute VA by construction (carry the KVO in the
reader and add it once), so a caller *cannot* obtain an un-rebased symbol — the
same discipline MemProcFS gets from `PE_GetProcAddress` always returning
`vaBase + rva`.

---

## EPROCESS Walk Hardening

Beyond the base fix, harden the walk to match the references' robustness on
DKOM-tampered lists:

1. **`seen`-set loop detection.** Add a `HashSet<u64>` of visited link offsets,
   seeded with the head, and break on revisit — vol3's
   `seen = {self.vol.offset}` / `while link.vol.offset not in seen`
   (`extensions/__init__.py:1115-1128`). This catches a corrupted list that
   cycles without passing the head, which our pure counter + head-equality guard
   (`object_reader.rs:168-184`) does not, and prevents duplicate `_EPROCESS`
   emission.

2. **Keep the bounded `MAX_LIST_ITERATIONS` backstop** as defense-in-depth (it
   already exists) — but it is a safety net, not the primary terminator.

3. **Offsets always from the ISF, never hardcoded.** We already read
   `ActiveProcessLinks` and `Flink` offsets via the symbol table
   (`object_reader.rs:155-163`), matching vol3's `relative_child_offset`. Keep
   this — do not regress to literal offsets when adding the rebase.

4. **Per-node validity / sentinel awareness.** Like vol3's `sentinel` flag and
   MemProcFS's per-node checks, validate each translated `_EPROCESS` VA before
   reading fields (`is_valid`/translation check) and degrade gracefully
   (skip-and-continue) rather than aborting the whole walk on one unmapped node,
   so a single tampered entry does not blank the entire process list.

5. **Cross-check (future).** Rekall's `TestEProcess` reflects through
   `ThreadListHead` to validate a walked `_EPROCESS`
   (`plugins/windows/common.py:159-178`); a later `psxview`-style cross-source
   (list-walk vs pool-scan) reconciliation would surface DKOM-hidden processes.
   Not required for the base fix, noted for the roadmap.

---

## Citations Index

| Ref | Path (under `~/src/_refs/`) | Key lines |
|---|---|---|
| Vol3 DtbSelfReferential | `volatility3/.../automagic/windows.py` | 41-131 (esp. 84-86 `len(ref_pages)==1`, 108/120 `reserved_bits`/`valid_range`) |
| Vol3 pdbscan KVO | `volatility3/.../automagic/pdbscan.py` | 151-172 `set_kernel_virtual_offset`, 296-393 `_method_offset`/`check_kernel_offset` |
| Vol3 large pages | `volatility3/.../layers/intel.py` | `_PAGE_BIT_PSE = 7`, `_PAGE_PAT_LARGE` |
| Vol3 list_walk | `volatility3/.../symbols/windows/extensions/__init__.py` | 1079-1128 |
| Vol2 KDBG/pslist | `volatility/win32/tasks.py` | 34-89 |
| Vol2 kdbgscan | `volatility/plugins/kdbgscan.py` | 69-100 |
| Rekall WinFindDTB | `rekall/.../plugins/windows/common.py` | 134-190 |
| MemProcFS FindNtos | `MemProcFS/vmm/vmmwininit.c` | 190-196, 516-560, 674-704 |
| Ours kernel_scanner | `crates/memf-symbols/src/kernel_scanner.rs` | 106-136, 258-296, 321, 389-474 |
| Ours symbol resolvers | `crates/memf-symbols/src/{pdb_resolver.rs:334, isf.rs:151}` | — |
| Ours list-walk | `crates/memf-core/src/object_reader.rs` | 147-185 |
| Ours ps walker | `crates/memf-windows/src/process.rs` | 17-36 |
