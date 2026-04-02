# Phase 3F-A: Pagefile & Swapfile Overlay Support — Design Spec

## Overview

Extend the `VirtualAddressSpace` page table walker in `memf-core` to resolve paged-out virtual memory by cross-referencing `pagefile.sys` and `swapfile.sys`. Currently, when a PTE has bit 0 (Present) clear, the walker returns `Error::PageNotPresent`. Phase 3F-A adds transparent fallback to pagefile/swapfile sources, recovering memory that was evicted from physical RAM at the time of acquisition.

**Scope:** Pagefile PTEs + transition pages. Prototype PTEs (shared memory sections, bit 10) are deferred to Phase 3F-B.

**Crate:** `memf-core` (virtual address translation layer). No changes to `memf-format`.

## PTE Decoder

When the x86_64 page table walker encounters a PTE with bit 0 (Present) clear at the final PT level (4K pages), the remaining bits encode one of several states. Phase 3F-A handles four:

### Demand-Zero PTE

```
All 64 bits = 0
```

The page was never materialized. Return a zeroed 4KB page. This is common for BSS segments and freshly-allocated anonymous memory.

### Transition PTE

```
Bit 0:      0 (not present)
Bit 11:     1 (transition)
Bits 12-51: Physical page frame number (PFN)
```

The page is still in physical RAM — it's being written to the pagefile or is on the standby/modified list. Read directly from the physical memory provider using `PFN * 0x1000`. No pagefile needed.

### Prototype PTE

```
Bit 0:      0 (not present)
Bit 10:     1 (prototype)
```

References a shared memory section (`_SECTION` -> `_CONTROL_AREA` -> `_SUBSECTION`). Requires kernel symbol resolution and object traversal. Return `Error::PrototypePte(vaddr)` — deferred to Phase 3F-B.

### Pagefile PTE

```
Bit 0:      0 (not present)
Bits 1-4:   Pagefile number (0 = pagefile.sys, 1-15 = additional pagefiles)
Bit 10:     0 (not prototype)
Bit 11:     0 (not transition)
Bits 12-51: Page offset within the pagefile (byte offset = page_offset * 0x1000)
```

The page was evicted to a pagefile. Extract the pagefile number and page offset, then look up the page in the attached pagefile source.

### Decode Priority

At the PT level, when `pte & PRESENT == 0`:

1. `pte == 0` → demand zero
2. `pte & (1 << 11) != 0` → transition (extract PFN from bits 12-51)
3. `pte & (1 << 10) != 0` → prototype PTE (`Error::PrototypePte`)
4. Otherwise → pagefile PTE (extract pagefile_num from bits 1-4, page_offset from bits 12-51)

Note: This decode order applies only at the final PT level (4K pages). Non-present entries at PML4, PDPT, and PD levels remain `Error::PageNotPresent` — those levels don't use pagefile/transition encoding.

## PagefileSource Trait & Implementations

### Trait

```rust
/// A source of paged-out memory pages (pagefile.sys, swapfile.sys, etc.).
pub trait PagefileSource: Send + Sync {
    /// Which pagefile number this source handles (0 = pagefile.sys, 1-15 = secondary).
    fn pagefile_number(&self) -> u8;

    /// Read a 4KB page at the given page offset.
    /// Returns Ok(None) if the offset is beyond the file's page count.
    fn read_page(&self, page_offset: u64) -> Result<Option<[u8; 4096]>>;
}
```

Lives in `memf-core/src/pagefile.rs`.

### PagefileProvider (pagefile.sys)

```rust
pub struct PagefileProvider {
    mmap: memmap2::Mmap,
    pagefile_num: u8,
    page_count: u64,
}
```

- **Constructor:** `PagefileProvider::open(path: &Path, pagefile_num: u8) -> Result<Self>` — open file, mmap, compute `page_count = file_len / 0x1000`.
- **read_page:** `byte_offset = page_offset * 0x1000`. If `page_offset >= page_count`, return `Ok(None)`. Otherwise, copy 4096 bytes from mmap into a `[u8; 4096]` array.
- **pagefile_number:** Returns the configured `pagefile_num`.
- **Dependency:** `memmap2` crate.

pagefile.sys is a flat file — no headers, no compression. Each page occupies exactly 4096 bytes at its natural offset.

### SwapfileProvider (swapfile.sys)

```rust
pub struct SwapfileProvider {
    mmap: memmap2::Mmap,
    /// Maps page offset → (file_offset, compressed_size).
    /// Pages with compressed_size == 0x1000 are stored uncompressed.
    index: HashMap<u64, (u64, u32)>,
}
```

- **Constructor:** `SwapfileProvider::open(path: &Path) -> Result<Self>` — mmap the file, verify SM header magic (`0x534D` at offset 0), parse the region/page table to build the index. Fail-fast if SM magic doesn't match or index is unparseable.
- **read_page:** Look up `page_offset` in index. If not found, return `Ok(None)`. If `compressed_size == 0x1000`, return raw bytes. Otherwise, decompress with `lzxpress::data::decompress()`.
- **pagefile_number:** Always returns `2` (Windows convention for the virtual store backing file).
- **Dependencies:** `memmap2`, `lzxpress`.

**SM Header Format:**

The swapfile.sys Store Manager format is partially documented through reverse engineering (Windows Internals 7th ed., community research). The header structure:

```
Offset 0x00: u16 magic = 0x534D ("SM")
Offset 0x02: u16 version
Offset 0x04: u32 page_size (usually 0x1000)
Offset 0x08: u64 region_table_offset
Offset 0x10: u32 region_count
```

Each region entry describes a contiguous run of compressed pages with their file offsets and sizes. If the SM format proves more complex than expected in practice, the SwapfileProvider constructor returns an error and the VAS operates without swapfile support — graceful degradation.

## VAS Integration

### TranslationResult (internal enum)

```rust
/// Internal result of page table walk — not exposed publicly.
enum TranslationResult {
    /// Page is in physical memory at this address.
    Physical(u64),
    /// Page is demand-zero (all zeroes).
    DemandZero,
    /// Page is in a pagefile.
    PagefileEntry { pagefile_num: u8, page_offset: u64 },
    /// Page is a transition page (still in physical memory at this PFN-derived address).
    Transition(u64),
    /// Page uses a prototype PTE (Phase 3F-B).
    Prototype,
}
```

### Modified VirtualAddressSpace struct

```rust
pub struct VirtualAddressSpace<P: PhysicalMemoryProvider> {
    physical: P,
    page_table_root: u64,
    mode: TranslationMode,
    pagefiles: Vec<Box<dyn PagefileSource>>,  // new — empty by default
}
```

### Builder method

```rust
/// Attach a pagefile source for resolving paged-out memory.
/// Multiple sources can be attached (one per pagefile number).
pub fn with_pagefile(mut self, source: Box<dyn PagefileSource>) -> Self {
    self.pagefiles.push(source);
    self
}
```

### virt_to_phys() behavior

`virt_to_phys()` remains the public API returning `Result<u64>`. It resolves:

- `TranslationResult::Physical(addr)` → `Ok(addr)`
- `TranslationResult::Transition(addr)` → `Ok(addr)`
- `TranslationResult::DemandZero` → `Err(Error::PageNotPresent(vaddr))` (no physical address exists)
- `TranslationResult::PagefileEntry { .. }` → `Err(Error::PagedOut { vaddr, pagefile_num, page_offset })` (always — `virt_to_phys` cannot resolve a pagefile entry to a physical address regardless of whether pagefiles are attached)
- `TranslationResult::Prototype` → `Err(Error::PrototypePte(vaddr))`

### read_virt() behavior (the key change)

`read_virt()` uses `TranslationResult` internally to serve pages from any source:

- `Physical(addr)` / `Transition(addr)` → read from physical provider (existing behavior)
- `DemandZero` → fill buffer slice with zeroes (no I/O)
- `PagefileEntry { num, offset }` → find matching `PagefileSource` in `self.pagefiles` by `pagefile_number()`, call `read_page(offset)`. If no matching source → `Error::PagedOut { vaddr, pagefile_num, page_offset }`
- `Prototype` → `Error::PrototypePte(vaddr)`

Cross-page reads continue to work: each 4K-aligned chunk within a `read_virt()` call independently resolves via the walk, so a single read can span physical pages, pagefile pages, and demand-zero pages seamlessly.

## Error Variants

Two new variants added to `memf_core::Error`:

```rust
/// Page is in a pagefile that was not provided.
#[error("page at {vaddr:#018x} paged out to pagefile {pagefile_num} offset {page_offset:#x}")]
PagedOut {
    /// Virtual address of the faulting page.
    vaddr: u64,
    /// Pagefile number (0 = pagefile.sys, 1-15 = secondary).
    pagefile_num: u8,
    /// Page offset within the pagefile.
    page_offset: u64,
},

/// Page uses a prototype PTE (shared section, not yet supported).
#[error("prototype PTE at {0:#018x} (not yet supported)")]
PrototypePte(u64),
```

The existing `Error` enum should be annotated `#[non_exhaustive]` to avoid semver concerns when adding future variants.

## Dependencies

### New

| Crate | Version | Purpose | Used by |
|-------|---------|---------|---------|
| `memmap2` | latest | Memory-mapped file I/O | `PagefileProvider`, `SwapfileProvider` |
| `lzxpress` | (already in workspace) | Xpress decompression | `SwapfileProvider` |

### Unchanged

- `memf-format` — already a dependency (for `PhysicalMemoryProvider` trait)
- `memf-symbols` — already a dependency (for `SymbolResolver` trait)

## File Structure

```
crates/memf-core/
├── src/
│   ├── lib.rs              # MODIFY: add PagedOut + PrototypePte error variants,
│   │                       #         add #[non_exhaustive], pub mod pagefile
│   ├── vas.rs              # MODIFY: TranslationResult enum, PTE decoder,
│   │                       #         pagefiles field + builder, read_virt fallback
│   ├── pagefile.rs         # CREATE: PagefileSource trait, PagefileProvider,
│   │                       #         SwapfileProvider
│   ├── test_builders.rs    # MODIFY: map_pagefile_pte, map_transition_pte,
│   │                       #         map_demand_zero, map_prototype_pte,
│   │                       #         MockPagefileSource
│   └── object_reader.rs    # NO CHANGE
├── Cargo.toml              # MODIFY: add memmap2, lzxpress dependencies
```

No changes to `memf-format`, `memf-linux`, `memf-windows`, `memf-strings`, or the `memf` CLI binary.

## Backward Compatibility

- `VirtualAddressSpace::new()` — signature unchanged, `pagefiles` defaults to empty `Vec`
- `virt_to_phys()` — return type unchanged. Transition pages now resolve instead of erroring (behavior improvement, not break). Demand-zero and pagefile PTEs continue to error via `PageNotPresent` when no pagefiles attached (same behavior as today for callers not using pagefiles).
- `read_virt()` — return type unchanged. Same improvement: transition and demand-zero pages now resolve transparently.
- New error variants — the Error enum gains `PagedOut` and `PrototypePte`. Adding `#[non_exhaustive]` makes this a one-time semver allowance.
- All existing tests continue to pass unchanged (no pagefiles attached = existing behavior).

## Testing Strategy

### Unit tests (synthetic, in vas.rs and pagefile.rs)

| # | Test | What it verifies |
|---|------|-----------------|
| 1 | `demand_zero_pte_returns_zeroed_page` | PTE == 0 → `read_virt()` fills buffer with zeroes |
| 2 | `transition_pte_reads_from_physical` | Bit 11 set → resolves to physical PFN, reads data |
| 3 | `pagefile_pte_with_provider_reads_page` | Bits 1-4 + 12-51 → routes to MockPagefileSource, returns correct data |
| 4 | `pagefile_pte_without_provider_returns_paged_out` | No pagefiles attached → `Error::PagedOut` with correct metadata |
| 5 | `prototype_pte_returns_error` | Bit 10 set → `Error::PrototypePte` |
| 6 | `mixed_pages_cross_boundary_read` | `read_virt()` spanning physical + pagefile + demand-zero pages |
| 7 | `pagefile_number_routing` | PTE pagefile_num 0 vs 1 → routes to correct provider |
| 8 | `pagefile_out_of_range_offset` | `read_page()` returns `None` → error propagation |
| 9 | `pagefile_provider_open_and_read` | `PagefileProvider::open()` + `read_page()` with known offset |
| 10 | `pagefile_provider_out_of_range` | Offset beyond file → `Ok(None)` |
| 11 | `pagefile_provider_number` | `pagefile_number()` returns configured value |
| 12 | `swapfile_provider_valid_sm_header` | Parse SM header, build index, read compressed page |
| 13 | `swapfile_provider_decompress_xpress` | Compressed page → correct decompressed content |
| 14 | `swapfile_provider_invalid_magic` | Bad magic → construction error |
| 15 | `swapfile_provider_corrupted_index` | Truncated/corrupt index → construction error |
| 16 | `virt_to_phys_transition_resolves` | `virt_to_phys()` returns physical address for transition PTEs |
| 17 | `virt_to_phys_demand_zero_errors` | `virt_to_phys()` returns `PageNotPresent` for demand-zero (no phys addr) |
| 18 | `virt_to_phys_pagefile_errors_paged_out` | `virt_to_phys()` returns `PagedOut` for pagefile PTEs |

### Integration tests (real data, `#[ignore]`)

| # | Test | Data |
|---|------|------|
| 19 | Walk known process page tables, verify pagefile pages resolve | `DESKTOP-SDN1RPT.mem` + `pagefile.sys` |
| 20 | Count recovered vs. PagedOut vs. PrototypePte pages | Same data |
| 21 | Transition page physical addresses match PTE PFN | Same data |

Gated behind `MEMF_TEST_DATA` env var.

### No real-data swapfile test

The DFIR Madness test data does not include `swapfile.sys`. SwapfileProvider gets unit tests with synthetic SM data only. Real-data testing deferred until a swapfile.sys sample is obtained.

## Out of Scope

- **Prototype PTEs** (shared memory sections, bit 10) — Phase 3F-B
- **CLI `--pagefile` flag** — follow-up task after 3F-A merges
- **Linux swap partition support** — different format entirely, future phase
- **Multiple pagefile.sys files** — the architecture supports it (pagefile numbers 0-15), but testing only covers single pagefile
- **Page table entry caching** — noted as a future optimization, not part of this spec
