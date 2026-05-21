# Windows Auto-Profile Design

**Date**: 2026-05-15  
**Status**: Approved  
**Crate**: `memf-symbols` (no new crate)  
**Feature gate**: `symserver` (existing)

## Problem

Windows kernel walkers in `memf-windows` need a `Box<dyn SymbolResolver>` populated with struct layouts for `_EPROCESS`, `_ETHREAD`, `_KTHREAD`, etc. Today tests use a hardcoded ISF preset. Real analysis requires the correct offsets for the exact kernel build in the dump — offsets shift between every Windows update.

## Approach

Chain the existing `memf-symbols` building blocks into a single `AutoProfile` orchestrator. No new crate. No ISF writer. The downloaded PDB file *is* the cache.

**Inspiration**: [core-jmp.org/2026/05/no-more-hardcoded-kernel-offsets](https://core-jmp.org/2026/05/no-more-hardcoded-kernel-offsets-turning-microsoft-pdb-symbols-into-a-runtime-byovd-superpower/) — same workflow, pure Rust, offline dump context.

## Architecture

```
Physical dump
     │
     ▼
kernel_scanner::scan_for_kernel(phys_mem)
     │  MZ scan → PE parse → CodeView RSDS → PdbId
     │  fallback: AutoProfile::with_pe_bytes(bytes)
     ▼
symserver::cache_path(cache_dir, pdb_name, guid, age)
     │  exists? ──yes──► PdbResolver::from_path(cached)
     │  no
     ▼
SymbolServerClient::get_pdb(pdb_name, guid, age)   [symserver feature]
     │  download → write to cache
     ▼
PdbResolver::from_path(cached_pdb)
     │  parse structs + symbols via `pdb` crate
     ▼
Box<dyn SymbolResolver>
```

## New Files

### `crates/memf-symbols/src/kernel_scanner.rs`

Scans physical memory pages for the Windows kernel PE.

```rust
pub fn scan_for_kernel<P: PhysicalMemoryProvider>(
    mem: &P,
) -> crate::Result<PdbId>
```

Algorithm:
1. Read physical pages in 0x1000-aligned chunks, looking for `MZ` (`4D 5A`) at page boundaries
2. Validate as PE: check `e_lfanew`, `PE\0\0` signature, `Machine == IMAGE_FILE_MACHINE_AMD64` (0x8664)
3. Scan the debug directory for a CodeView `RSDS` record (`52 53 44 53`)
4. Confirm it's a kernel image: `pdb_name` contains `ntkrnl`, `ntoskrnl`, or `ntkrnlmp`
5. Call `pe_debug::extract_pdb_id()` on the matched page range
6. Return `PdbId` on first match; `Error::NotFound` if no kernel found

**Scan window**: physical addresses `0x0010_0000` – `0x0800_0000` (1 MB–128 MB). The kernel always loads in low physical RAM on x64 Windows.

### `crates/memf-symbols/src/auto_profile.rs`

Orchestrates the full chain.

```rust
pub struct AutoProfile {
    cache_dir: PathBuf,
}

impl AutoProfile {
    /// Use default cache dir (~/.memf/symbols/).
    pub fn new() -> crate::Result<Self>;

    /// Use explicit cache dir (useful in tests).
    pub fn with_cache_dir(dir: impl Into<PathBuf>) -> Self;

    /// Auto-detect kernel from dump, download PDB if needed, return resolver.
    #[cfg(feature = "symserver")]
    pub fn from_dump<P: PhysicalMemoryProvider>(
        &self,
        mem: &P,
    ) -> crate::Result<Box<dyn SymbolResolver>>;

    /// Bypass kernel scan — caller provides raw PE bytes of ntoskrnl.exe.
    /// Useful when scan fails or PE is extracted separately.
    #[cfg(feature = "symserver")]
    pub fn from_pe_bytes(
        &self,
        pe_bytes: &[u8],
    ) -> crate::Result<Box<dyn SymbolResolver>>;

    /// Resolve from a pre-known PdbId (skips PE parsing entirely).
    #[cfg(feature = "symserver")]
    pub fn from_pdb_id(
        &self,
        pdb_id: &PdbId,
    ) -> crate::Result<Box<dyn SymbolResolver>>;
}
```

Internal flow for `from_dump`:
1. `kernel_scanner::scan_for_kernel(mem)` → `PdbId`
2. `symserver::cache_path(cache_dir, ...)` — if exists, skip to step 4
3. `SymbolServerClient::get_pdb(...)` — download, write to cache
4. `PdbResolver::from_path(cached_pdb)` — parse
5. Return `Box::new(resolver)`

`from_pe_bytes` skips step 1; `from_pdb_id` skips steps 1–2 (goes straight to cache check).

## Module Exports

Add to `crates/memf-symbols/src/lib.rs`:

```rust
pub mod auto_profile;
pub mod kernel_scanner;
```

## Cargo.toml Changes

`memf-symbols` already has the `symserver` feature with `ureq`. No new dependencies. `memf-format` is already a dev-dependency for tests; make it a regular dependency (behind `symserver` feature) so `kernel_scanner` can accept `PhysicalMemoryProvider`.

## Error Handling

- `kernel_scanner` returns `Error::NotFound("kernel PE not found in physical memory")` after exhausting the scan window — caller should retry with `from_pe_bytes`
- Download failures: `Error::Network(...)` — caller can catch and use a stale cache or fallback ISF
- PDB parse failures: `Error::Pdb(...)` — should not happen for valid Microsoft PDBs

## Testing

### `kernel_scanner` tests (no network, no `symserver` feature)
- `scan_finds_kernel_pe` — synthetic physical memory with a minimal PE + RSDS record at a known page → returns correct `PdbId`
- `scan_skips_non_pe_pages` — garbage pages before valid PE → still finds kernel
- `scan_returns_not_found_on_empty_memory` — all-zero pages → `Error::NotFound`
- `scan_rejects_non_amd64_pe` — x86 PE → not matched, scan continues
- `scan_rejects_non_kernel_pdb_name` — valid PE with `PdbId.pdb_name = "notepad.pdb"` → skipped

### `auto_profile` tests (no network)
- `from_pe_bytes_produces_resolver` — real ntoskrnl bytes (fixture) or synthetic PE with RSDS + pre-seeded cached PDB → returns working `SymbolResolver`
- `from_pdb_id_uses_cached_pdb` — pre-seeded PDB in temp cache dir → no network call, returns resolver
- `from_pdb_id_returns_error_when_not_cached` — empty cache dir + no network → `Error::Network` or `Error::NotFound`

### Integration test (opt-in, `#[ignore]`)
- `from_dump_downloads_real_pdb` — requires internet + a Windows dump fixture → downloads `ntkrnlmp.pdb`, verifies `_EPROCESS.UniqueProcessId` offset is non-zero

## Sequence: Fitting into Walkers

Existing walker call site (today — hardcoded ISF):
```rust
let resolver = IsfResolver::from_value(&windows_kernel_preset().build_json())?;
let reader = ObjectReader::new(vas, Box::new(resolver));
```

After auto-profile:
```rust
let profile = AutoProfile::new()?;
let resolver = profile.from_dump(&phys_mem)?;  // or fallback to ISF preset
let reader = ObjectReader::new(vas, Box::new(resolver));
```

The `SymbolResolver` trait is unchanged. No walker code changes.

## Known Limitations

- **Scan window is heuristic**: 1 MB–128 MB covers all known x64 Windows kernel load addresses, but could theoretically miss an unusual system.
- **Requires internet on first run** (or pre-cached PDB). Offline environments must pre-seed the cache.
- **No EWF/compressed dump support**: `PhysicalMemoryProvider` handles decompression; `kernel_scanner` just calls `mem.read()`.
- **Single-kernel assumption**: scanning stops at the first valid kernel PE. Multi-kernel VMs are not considered.
