# Phase 3A: Dump Format Providers -- Design Spec

**Date**: 2026-04-01
**Status**: Approved
**Scope**: Add Windows crash dump, hiberfil.sys, VMware .vmss/.vmsn, and kdump format providers to `memf-format`. Extend `PhysicalMemoryProvider` with optional dump metadata (CR3, process list head, etc.).

---

## Goal

Add 4 new format provider files to `memf-format`, bringing the total supported formats from 4 to 8. This unlocks Windows memory analysis (Phase 3B+) and improves Linux coverage (kdump). Each provider follows the existing pattern: implement `PhysicalMemoryProvider` + `FormatPlugin`, register via `inventory::submit!`, include a test builder.

## Architecture

All providers live in `crates/memf-format/src/` alongside the existing `lime.rs`, `avml.rs`, `elf_core.rs`, and `raw.rs`. Each is a single file implementing both traits. A new `DumpMetadata` struct surfaces header-embedded fields (CR3, PsActiveProcessHead) that downstream crates need for Windows analysis.

## Approach

Write all parsers from scratch in pure Rust. No external parser crates (not kdmp-parser-rs). New compression dependencies are all pure Rust: `rust-lzxpress`, `flate2` (miniz_oxide backend), `ruzstd`. LZO decompression for kdump is deferred (uncommon in practice).

---

## 1. DumpMetadata Trait Extension

### Types

```rust
/// Machine architecture identified from a dump header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineType {
    /// x86_64 / AMD64 (machine image type 0x8664).
    Amd64,
    /// x86 / i386 (machine image type 0x014C).
    I386,
    /// AArch64 / ARM64 (machine image type 0xAA64).
    Aarch64,
}

/// Optional metadata extracted from dump file headers.
///
/// Windows crash dumps embed analysis-critical fields directly in the header:
/// CR3 (page table root), PsActiveProcessHead (EPROCESS list), and
/// PsLoadedModuleList (driver list). These let downstream crates bootstrap
/// kernel walking without symbol resolution.
#[derive(Debug, Clone, Default)]
pub struct DumpMetadata {
    /// Page table root physical address (CR3 / DirectoryTableBase).
    pub cr3: Option<u64>,
    /// Machine architecture.
    pub machine_type: Option<MachineType>,
    /// OS major and minor version from the dump header.
    pub os_version: Option<(u32, u32)>,
    /// Number of processors.
    pub num_processors: Option<u32>,
    /// Virtual address of PsActiveProcessHead (EPROCESS linked list head).
    pub ps_active_process_head: Option<u64>,
    /// Virtual address of PsLoadedModuleList (loaded driver list head).
    pub ps_loaded_module_list: Option<u64>,
    /// Virtual address of KdDebuggerDataBlock.
    pub kd_debugger_data_block: Option<u64>,
    /// System time at dump creation (Windows FILETIME, 100ns intervals since 1601-01-01).
    pub system_time: Option<u64>,
    /// Human-readable dump sub-type (e.g., "Full", "Kernel", "Bitmap").
    pub dump_type: Option<String>,
}
```

### Trait Change

Add a default method to the existing `PhysicalMemoryProvider` trait:

```rust
pub trait PhysicalMemoryProvider: Send + Sync {
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize>;
    fn ranges(&self) -> &[PhysicalRange];
    fn total_size(&self) -> u64 { /* existing default */ }
    fn format_name(&self) -> &str;

    /// Optional metadata extracted from the dump header.
    /// Returns `None` for formats that carry no metadata (Raw, LiME, AVML).
    fn metadata(&self) -> Option<DumpMetadata> { None }
}
```

Existing providers are unaffected (they inherit the default `None`).

---

## 2. Windows Crash Dump Provider (`win_crashdump.rs`)

### Formats Handled

| DumpType | Name | Layout |
|----------|------|--------|
| 0x01 | Full memory dump | Run-based: `_PHYSICAL_MEMORY_DESCRIPTOR` with run array |
| 0x02 | Kernel summary dump | Bitmap-based: `_SUMMARY_DUMP` with page bitmap |
| 0x05 | Bitmap dump | Bitmap-based: newer bitmap format |

All three share the same `_DUMP_HEADER64` (8192 bytes) or `_DUMP_HEADER` (4096 bytes for 32-bit).

### Detection

| Variant | Offset 0x0 | Offset 0x4 | Confidence |
|---------|-----------|-----------|------------|
| 64-bit | `PAGE` (0x45474150) | `DU64` (0x34365544) | 95 |
| 32-bit | `PAGE` (0x45474150) | `DUMP` (0x504D5544) | 95 |

### Header Parsing (64-bit)

Read `_DUMP_HEADER64` (8192 bytes):
- Offset 0x010: `DirectoryTableBase` (u64) -- CR3
- Offset 0x020: `PsLoadedModuleList` (u64)
- Offset 0x028: `PsActiveProcessHead` (u64)
- Offset 0x030: `MachineImageType` (u32)
- Offset 0x034: `NumberProcessors` (u32)
- Offset 0x080: `KdDebuggerDataBlock` (u64)
- Offset 0x088: `PhysicalMemoryBlockBuffer` -- contains `_PHYSICAL_MEMORY_DESCRIPTOR`
- Offset 0xF98: `DumpType` (u32)
- Offset 0xFA8: `SystemTime` (u64)

### Physical Memory Descriptor (at header + 0x88)

```
NumberOfRuns: u32 (offset 0x00)
_padding:    u32 (offset 0x04)
NumberOfPages: u64 (offset 0x08)
Runs[]:      PhysMemRun[] (offset 0x10, each 16 bytes)
```

Each `PhysMemRun`: `BasePage: u64, PageCount: u64`. Physical address = `BasePage * 0x1000`.

### File Layout (run-based, DumpType 0x01)

Data starts at offset `header_pages * PAGE_SIZE` (page 2 for 64-bit = 0x2000, page 1 for 32-bit = 0x1000). Runs are stored sequentially in the file. To find a physical address:

1. Binary search runs for the containing run
2. Compute `page_in_run = paddr / PAGE_SIZE - run.base_page`
3. Compute `file_offset = run_data_start + page_in_run * PAGE_SIZE`

Where `run_data_start` is the cumulative sum of all preceding runs' page counts times PAGE_SIZE, plus the header size.

### File Layout (bitmap, DumpType 0x02/0x05)

A `_SUMMARY_DUMP` header follows the main header. Contains a bitmap where bit N indicates physical page N is present. Pages stored sequentially after the bitmap -- page N's position is determined by counting set bits before N (popcount).

For the `_SUMMARY_DUMP`:
- Offset 0x00: `ValidDump` (u32) -- must be `DUMP` (0x504D5544)
- Offset 0x04: `HeaderSize` (u32) -- total summary header size
- Offset 0x08: `BitmapSize` (u32) -- number of bits
- Offset 0x0C: `Pages` (u32) -- number of present pages (= popcount of bitmap)
- After header: bitmap bytes, then page data

### Internal Types

```rust
struct PhysMemRun {
    base_page: u64,
    page_count: u64,
}

enum CrashDumpLayout {
    /// Run-based (DumpType 0x01). Runs stored sequentially.
    RunBased {
        runs: Vec<PhysMemRun>,
        /// Cumulative file offset where each run's data begins.
        run_file_offsets: Vec<u64>,
    },
    /// Bitmap-based (DumpType 0x02/0x05). Popcount indexing.
    Bitmap {
        /// The raw bitmap bytes.
        bitmap: Vec<u8>,
        /// File offset where page data starts (after bitmap).
        data_start: u64,
    },
}

pub struct CrashDumpProvider {
    data: Vec<u8>,
    layout: CrashDumpLayout,
    ranges: Vec<PhysicalRange>,
    metadata: DumpMetadata,
    is_64bit: bool,
}
```

### read_phys

- **Run-based**: Binary search `runs` for the containing run. Compute file offset from `run_file_offsets[i]` plus the page offset within the run.
- **Bitmap**: Check if bit `paddr / PAGE_SIZE` is set. If not, return 0. Otherwise, count set bits before that position to get the page index, compute `data_start + page_index * PAGE_SIZE`.
- Gaps return 0 bytes (consistent with existing providers).

### 32-bit Support

Same logic with smaller header (4096 bytes instead of 8192), 32-bit fields for CR3/pointers, 8-byte runs (u32 BasePage + u32 PageCount). Detect via `DUMP` at offset 0x4 instead of `DU64`.

### Test Builder

```rust
pub struct CrashDumpBuilder {
    runs: Vec<(u64, Vec<u8>)>,  // (base_page, data)
    is_64bit: bool,
    dump_type: u32,
}

impl CrashDumpBuilder {
    pub fn new() -> Self;
    pub fn is_64bit(self, v: bool) -> Self;
    pub fn dump_type(self, t: u32) -> Self;
    pub fn add_run(self, base_page: u64, data: &[u8]) -> Self;
    pub fn build(self) -> Vec<u8>;
}
```

The builder constructs a valid `_DUMP_HEADER64` with correct runs, metadata, and sequential page data. For bitmap type, it generates the bitmap from the runs.

---

## 3. Hiberfil.sys Provider (`hiberfil.rs`)

### Detection

| Signature | Bytes (LE) | Confidence |
|-----------|-----------|------------|
| `hibr` | 0x72626968 | 90 |
| `wake` | 0x656B6177 | 90 |
| `RSTR` | 0x52545352 | 85 |
| `HORM` | 0x4D524F48 | 85 |

RSTR and HORM get slightly lower confidence because they indicate a resume-in-progress or special mode -- the file may be incomplete.

### Decompression Strategy

Eager decompression. Parse the file, decompress all Xpress blocks, build a `HashMap<u64, Vec<u8>>` mapping physical page frame numbers to raw 4096-byte page data. This matches AVML's pattern of decompressing upfront in `from_bytes`.

Hibernation files are typically 2-4 GB compressed. Decompressed, the page map holds only the pages that were saved (not all of physical memory), so memory usage is bounded.

### Header Parsing

Read `PO_MEMORY_IMAGE` from page 0. The header size varies by Windows version (96-296+ bytes). Key fields:
- Offset 0x00: `Signature` (4 bytes)
- Offset 0x54 (32-bit) or 0x60 (64-bit): `TotalPages`
- Offset 0x58 (32-bit) or 0x68 (64-bit): `FirstTablePage`

Determine 32-bit vs 64-bit by checking `LengthSelf` field (offset 0x0C) -- values <= 168 are 32-bit, larger are 64-bit.

### CR3 Extraction

`_KPROCESSOR_STATE` lives on page 1 (offset 0x1000). CR3 is at a version-dependent offset within this structure. For 64-bit systems, it is typically at offset 0x28 within the processor state (SpecialRegisters.Cr3).

### Legacy Format (pre-Win8)

1. `FirstTablePage` points to a page containing a compressed page map
2. Compressed data blocks start with `\x81\x81xpress` (8-byte signature)
3. Block header (at signature + 8):
   - Byte 0: `NumPages - 1`
   - Bytes 1-4: `(CompressedDataSize * 4) - 1`
4. Compressed payload follows at offset 0x20 from block start
5. Decompress with Xpress LZ77 (via `rust-lzxpress`)
6. Decompressed output contains `NumPages` contiguous 4096-byte pages
7. The page map provides the physical page number for each decompressed page

### Modern Format (Win8+)

1. `FirstBootRestorePage` and `FirstKernelRestorePage` fields in the header
2. Boot section at `FirstBootRestorePage * 0x1000`
3. Kernel section at `FirstKernelRestorePage * 0x1000`
4. Each section contains "compression sets" with headers describing:
   - Number of page descriptors
   - Compression algorithm (Xpress LZ77 or Xpress LZ77+Huffman)
   - Compressed data size
5. Decompress each set, extract pages by page descriptor

### Compression

Both Xpress LZ77 and Xpress LZ77+Huffman are supported by the `rust-lzxpress` crate. No additional compression crates needed.

### Internal Types

```rust
pub struct HiberfilProvider {
    /// Physical page number -> raw 4096-byte page data.
    pages: HashMap<u64, Vec<u8>>,
    ranges: Vec<PhysicalRange>,
    metadata: DumpMetadata,
}
```

### read_phys

1. Compute `pfn = addr / PAGE_SIZE` and `offset_in_page = addr % PAGE_SIZE`
2. Look up `pages.get(&pfn)`
3. If found, copy from `page[offset_in_page..]` into buf
4. If not found, return 0 (page not in hibernation file)

### Test Builder

```rust
pub struct HiberfilBuilder {
    pages: Vec<(u64, Vec<u8>)>,  // (pfn, page_data)
    legacy: bool,                 // true = legacy format, false = modern
}

impl HiberfilBuilder {
    pub fn new() -> Self;
    pub fn legacy(self, v: bool) -> Self;
    pub fn add_page(self, pfn: u64, data: &[u8; 4096]) -> Self;
    pub fn build(self) -> Vec<u8>;
}
```

The builder constructs a valid hiberfil.sys with the `hibr` signature, a minimal PO_MEMORY_IMAGE header, and Xpress-compressed page data blocks.

---

## 4. VMware State Provider (`vmware.rs`)

### Formats Handled

`.vmss` (suspend state) and `.vmsn` (snapshot state). Both use the same group/tag binary structure.

`.vmem` files are raw flat memory and are handled by the existing Raw provider. No separate provider needed.

### Detection

| Magic (LE u32) | Confidence |
|----------------|------------|
| 0xBED2BED0 | 85 |
| 0xBAD1BAD1 | 85 |
| 0xBED2BED2 | 85 |
| 0xBED3BED3 | 85 |

### Group/Tag Structure

File layout:
```
Offset 0x0: _VMWARE_HEADER (12 bytes)
  - Magic: u32
  - Unknown: u32
  - GroupCount: u32
Offset 0xC: Groups[GroupCount] (80 bytes each)
  - Name: char[64] (null-terminated)
  - TagsOffset: u64 (absolute file offset to tag array)
```

Each group contains a chain of tags:
```
_VMWARE_TAG (variable size):
  - Flags: u8 (lower bits encode data size category)
  - NameLength: u8
  - Name: char[NameLength]
  - Indices: variable (from Flags encoding)
  - Data: variable
```

Tag terminator: `Flags == 0`.

### Memory Extraction

Physical memory is stored as data payloads within tags in the `memory` or `mainmem` group. The tags describe physical address ranges and contain raw page data.

### CR3 and CPU State

CPU registers are tags within the `cpu` group:
- `cpu/CR[0][3]` -- CR3 (DirectoryTableBase)
- `cpu/CR[0][0]` -- CR0
- `cpu/CR[0][4]` -- CR4

The `[0]` index refers to CPU 0.

### Internal Types

```rust
struct VmwareGroup {
    name: String,
    tags_offset: u64,
}

struct MemoryRegion {
    paddr: u64,
    file_offset: u64,
    size: u64,
}

pub struct VmwareStateProvider {
    data: Vec<u8>,
    regions: Vec<MemoryRegion>,
    ranges: Vec<PhysicalRange>,
    metadata: DumpMetadata,
}
```

### read_phys

Linear scan (or binary search if sorted) of `regions` for the containing region. Compute file offset, copy data. Return 0 for gaps.

### Test Builder

```rust
pub struct VmwareStateBuilder {
    memory_regions: Vec<(u64, Vec<u8>)>,  // (paddr, data)
    cr3: Option<u64>,
}

impl VmwareStateBuilder {
    pub fn new() -> Self;
    pub fn add_region(self, paddr: u64, data: &[u8]) -> Self;
    pub fn cr3(self, cr3: u64) -> Self;
    pub fn build(self) -> Vec<u8>;
}
```

Constructs a valid .vmss with the group/tag structure, memory data, and CPU state tags.

---

## 5. kdump Provider (`kdump.rs`)

### Formats Handled

| Signature | Format |
|-----------|--------|
| `KDUMP   ` (8 bytes) | kdump-compressed (makedumpfile) |
| `DISKDUMP` (8 bytes) | Legacy diskdump |

### Detection

Match the 8-byte signature at offset 0. Confidence: 90.

### Decompression Strategy

Lazy decompression with LRU page cache. kdump files are accessed sparsely during analysis. Decompress individual pages on demand in `read_phys` and cache recently accessed pages.

Cache size: 1024 pages (4 MB) by default. This keeps memory bounded while providing good hit rates for sequential and locality-heavy access patterns.

### File Layout

```
Block 0:        disk_dump_header (1 block)
Block 1..S:     kdump_sub_header (sub_hdr_size blocks)
Block S+1..B1:  1st bitmap (bitmap_blocks blocks)
Block B1+1..B2: 2nd bitmap (bitmap_blocks blocks)
Block B2+1..:   page_desc[] array (24 bytes each, block-aligned)
After descs:    compressed page data (NOT block-aligned)
```

### Header Parsing

`disk_dump_header`:
- Offset 0x00: `signature` (8 bytes) -- `KDUMP   ` or `DISKDUMP`
- Offset 0x08: `header_version` (i32)
- Offset 0x0C: `utsname` (390 bytes -- 6 fields of 65 chars)
- After `utsname` + alignment: `block_size` (i32), `sub_hdr_size` (i32), `bitmap_blocks` (u32)

`kdump_sub_header`:
- `phys_base` (unsigned long)
- `start_pfn_64` / `end_pfn_64` (u64, version >= 6)
- `max_mapnr_64` (u64, version >= 6)

### Bitmaps

Two bitmaps, each `bitmap_blocks * block_size` bytes:
- **1st bitmap**: PFNs that exist in the system (valid memory)
- **2nd bitmap**: PFNs actually present in the dump file

### Page Descriptors

`page_desc` (24 bytes):
- `offset`: i64 -- file offset of compressed page data
- `size`: u32 -- compressed size in bytes
- `flags`: u32 -- compression method
- `page_flags`: u64 -- kernel page flags

Indexed by the bit position in the 2nd bitmap. To find the page_desc for PFN N:
1. Check bit N in 2nd bitmap. If unset, page not in dump.
2. Count set bits before N = descriptor index
3. Read `page_desc` at `desc_table_offset + index * 24`

### Compression Flags

| Flag | Value | Crate |
|------|-------|-------|
| `ZLIB` | 0x01 | `flate2` (miniz_oxide) |
| `LZO` | 0x02 | Deferred (return error) |
| `SNAPPY` | 0x04 | `snap` (already in workspace) |
| `ZSTD` | 0x20 | `ruzstd` |
| none (flags=0, size=block_size) | -- | Uncompressed (raw copy) |

LZO support is deferred. If a page has `flags & 0x02`, return `Error::Decompression("LZO not yet supported")`.

### Flattened Format

kdump files transported over SSH use a flattened format:
- Signature: `makedumpfile` (16 bytes) at offset 0
- Followed by `makedumpfile_data_header` records: `offset: i64, buf_size: i64`
- Each record says "copy buf_size bytes to offset in the reconstructed file"

If the flattened signature is detected, reconstruct the standard layout in memory first, then parse normally.

### Internal Types

```rust
struct PageDesc {
    offset: i64,
    size: u32,
    flags: u32,
    page_flags: u64,
}

pub struct KdumpProvider {
    data: Vec<u8>,
    block_size: u32,
    /// Page descriptor for each dumped PFN. Indexed by sequential position
    /// in the 2nd bitmap (not by PFN directly).
    page_descs: Vec<PageDesc>,
    /// 2nd bitmap: which PFNs are present in the dump.
    bitmap: Vec<u8>,
    /// Total number of PFNs the bitmap covers.
    max_pfn: u64,
    ranges: Vec<PhysicalRange>,
    /// LRU cache: PFN -> decompressed 4096-byte page.
    /// Uses Mutex (not RefCell) to satisfy the Sync bound on PhysicalMemoryProvider.
    page_cache: std::sync::Mutex<lru::LruCache<u64, Vec<u8>>>,
}
```

### read_phys

1. Compute `pfn = addr / block_size` and `offset_in_page = addr % block_size`
2. Check LRU cache. If hit, copy and return.
3. Check 2nd bitmap bit for `pfn`. If unset, return 0.
4. Count set bits before `pfn` to get descriptor index.
5. Read `page_descs[index]`.
6. Read compressed data from `data[desc.offset..desc.offset + desc.size]`.
7. Decompress based on `desc.flags`.
8. Insert decompressed page into LRU cache.
9. Copy from decompressed page into `buf`.

### Test Builder

```rust
pub struct KdumpBuilder {
    pages: Vec<(u64, Vec<u8>)>,  // (pfn, uncompressed_page_data)
    compression: u32,             // compression flag to use (0x01=zlib, 0x04=snappy, etc.)
    block_size: u32,
}

impl KdumpBuilder {
    pub fn new() -> Self;
    pub fn block_size(self, bs: u32) -> Self;
    pub fn compression(self, flags: u32) -> Self;
    pub fn add_page(self, pfn: u64, data: &[u8]) -> Self;
    pub fn build(self) -> Vec<u8>;
}
```

The builder constructs a valid kdump file with proper headers, bitmaps, compressed page data, and page descriptors.

---

## 6. New Dependencies

Add to `crates/memf-format/Cargo.toml`:

| Crate | Version | Purpose | Pure Rust |
|-------|---------|---------|-----------|
| `rust-lzxpress` | latest | Xpress LZ77 + Huffman decompression (hiberfil.sys) | Yes |
| `flate2` | 1.x | zlib inflate (kdump ZLIB pages). Uses miniz_oxide backend. | Yes |
| `ruzstd` | latest | Zstandard decompression (kdump ZSTD pages) | Yes |
| `lru` | 0.12 | LRU cache for kdump lazy page decompression | Yes |

The `snap` crate (Snappy) is already a workspace dependency.

Add to `Cargo.toml` (workspace `[workspace.dependencies]`):

```toml
rust-lzxpress = "0.2"
flate2 = { version = "1", default-features = false, features = ["miniz_oxide"] }
ruzstd = "0.7"
lru = "0.12"
```

---

## 7. Files Changed

### Create

| File | Responsibility |
|------|---------------|
| `crates/memf-format/src/win_crashdump.rs` | Windows full/kernel/bitmap crash dump provider |
| `crates/memf-format/src/hiberfil.rs` | Windows hibernation file provider |
| `crates/memf-format/src/vmware.rs` | VMware .vmss/.vmsn state file provider |
| `crates/memf-format/src/kdump.rs` | Linux makedumpfile/diskdump provider |

### Modify

| File | Change |
|------|--------|
| `crates/memf-format/src/lib.rs` | Add `DumpMetadata`, `MachineType`, `metadata()` default method, 4 new `mod` declarations |
| `crates/memf-format/src/test_builders.rs` | Add `CrashDumpBuilder`, `HiberfilBuilder`, `VmwareStateBuilder`, `KdumpBuilder` |
| `crates/memf-format/Cargo.toml` | Add `rust-lzxpress`, `flate2`, `ruzstd`, `lru` dependencies |
| `Cargo.toml` (workspace root) | Add new workspace dependencies |

### Unchanged

All existing provider files (`lime.rs`, `avml.rs`, `elf_core.rs`, `raw.rs`) and all other crates are unchanged. The `metadata()` default method addition is backward-compatible.

---

## 8. Testing Strategy

Each provider requires:

| Test Category | Description |
|---------------|-------------|
| **Probe correct magic** | probe() returns expected confidence for valid headers |
| **Probe wrong format** | probe() returns 0 for unrelated formats |
| **Probe short header** | probe() returns 0 for truncated input |
| **Single region read** | Write known data, read back, verify match |
| **Multi-region read** | Multiple runs/segments with gaps between them |
| **Gap read returns zero** | Read from unmapped address returns 0 bytes read |
| **Empty buffer read** | read_phys with empty buf returns 0 |
| **Metadata extraction** | Verify CR3, machine type, dump type from header |
| **Format name** | format_name() returns correct string |
| **Plugin registration** | Plugin is discoverable via inventory and open_dump() |

Format-specific tests:

| Provider | Additional Tests |
|----------|-----------------|
| **CrashDump** | Run-based and bitmap layouts; 32-bit and 64-bit headers; popcount correctness |
| **Hiberfil** | Legacy and modern format paths; Xpress decompression round-trip |
| **VMware** | Group/tag parsing; CR3 extraction from cpu group; multi-region memory |
| **kdump** | zlib, snappy, zstd decompression; uncompressed pages; bitmap bit counting; LRU cache behavior; LZO returns clean error |

Test builders compress data during `build()`, so tests verify the full round-trip: build synthetic dump -> parse -> read_phys -> verify data matches.

---

## 9. Error Handling

The existing `Error::Decompression(String)` variant covers all compression failures. The existing `Error::Corrupt(String)` covers header validation failures.

New error cases:
- `Error::Decompression("LZO not yet supported")` for kdump LZO pages
- `Error::Corrupt("not a Windows crash dump")` for PAGE without valid DU64/DUMP
- `Error::Corrupt("unsupported DumpType: {n}")` for unknown dump types (e.g., 0x09)
- `Error::Corrupt("hiberfil signature zeroed")` when the signature has been wiped

No new error variants needed. The existing `Error` enum is sufficient.

---

## 10. Constraints

- `#![deny(unsafe_code)]` -- no unsafe in any new code
- All new code must pass `cargo clippy --workspace -- -D warnings`
- All providers must be `Send + Sync` (required by `PhysicalMemoryProvider` trait bound)
- kdump's LRU cache uses `Mutex<LruCache>` (not `RefCell`) to satisfy the `Sync` bound on `PhysicalMemoryProvider`.
- Page size constant: `const PAGE_SIZE: u64 = 4096;` (shared across providers)
