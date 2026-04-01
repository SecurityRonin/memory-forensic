# Memory Dump Format Binary Specifications

Reference for implementing Rust parsers. All offsets in hex, all sizes in bytes unless noted.

---

## 1. Windows Full Crash Dump (.dmp) -- 64-bit

### Detection

| Offset | Size | Value | ASCII |
|--------|------|-------|-------|
| 0x0 | 4 | `0x45474150` | `PAGE` |
| 0x4 | 4 | `0x34365544` | `DU64` |

The 32-bit variant uses `PAGE` + `DUMP` (`0x504D5544`).

### `_DUMP_HEADER64` (8192 bytes = 2 pages)

| Offset | Size | Type | Field |
|--------|------|------|-------|
| 0x000 | 4 | u32 | `Signature` = `0x45474150` ("PAGE") |
| 0x004 | 4 | u32 | `ValidDump` = `0x34365544` ("DU64") |
| 0x008 | 4 | u32 | `MajorVersion` |
| 0x00C | 4 | u32 | `MinorVersion` |
| 0x010 | 8 | u64 | `DirectoryTableBase` (CR3 -- page table root) |
| 0x018 | 8 | u64 | `PfnDataBase` |
| 0x020 | 8 | u64 | `PsLoadedModuleList` |
| 0x028 | 8 | u64 | `PsActiveProcessHead` |
| 0x030 | 4 | u32 | `MachineImageType` (0x8664 = AMD64) |
| 0x034 | 4 | u32 | `NumberProcessors` |
| 0x038 | 4 | u32 | `BugCheckCode` |
| 0x040 | 32 | u64[4] | `BugCheckParameter[0..3]` |
| 0x080 | 8 | u64 | `KdDebuggerDataBlock` |
| 0x088 | 700 | struct | `PhysicalMemoryBlockBuffer` (see below) |
| 0x348 | 3000 | u8[3000] | `ContextRecord` |
| 0xF00 | 152 | struct | `Exception` (EXCEPTION_RECORD64) |
| 0xF98 | 4 | u32 | `DumpType` |
| 0xFA0 | 8 | u64 | `RequiredDumpSpace` |
| 0xFA8 | 8 | u64 | `SystemTime` (FILETIME) |
| 0xFB0 | 128 | char[128] | `Comment` |

### `DumpType` values

| Value | Meaning |
|-------|---------|
| 0x01 | Full memory dump (run-based) |
| 0x02 | Kernel summary dump |
| 0x05 | Bitmap/sparse dump (BMP) |
| 0x06 | Sparse kernel dump |
| 0x09 | Newer WinDbg format |

### `_PHYSICAL_MEMORY_DESCRIPTOR` (at header + 0x88)

| Offset | Size | Type | Field |
|--------|------|------|-------|
| 0x00 | 4 | u32 | `NumberOfRuns` |
| 0x04 | 4 | u32 | (padding on 64-bit) |
| 0x08 | 8 | u64 | `NumberOfPages` (total pages across all runs) |
| 0x10 | N*16 | struct[] | `Run[NumberOfRuns]` |

### `_PHYSICAL_MEMORY_RUN` (64-bit variant, 16 bytes each)

| Offset | Size | Type | Field |
|--------|------|------|-------|
| 0x00 | 8 | u64 | `BasePage` (starting page frame number) |
| 0x08 | 8 | u64 | `PageCount` (number of contiguous pages) |

Physical address = `BasePage * 0x1000`.

### Mapping physical addresses to file offsets (DumpType 0x01)

Data starts immediately after the header (page 2 for 64-bit, page 1 for 32-bit).

```
file_offset = headerpages * PAGE_SIZE    // initial cursor
for each run in runs:
    // run data spans [file_offset .. file_offset + run.PageCount * PAGE_SIZE)
    // physical range: [run.BasePage * PAGE_SIZE .. (run.BasePage + run.PageCount) * PAGE_SIZE)
    file_offset += run.PageCount * PAGE_SIZE
```

To translate a physical address `pa`:
1. Find the run where `run.BasePage <= pa/PAGE_SIZE < run.BasePage + run.PageCount`
2. `page_offset_in_run = pa/PAGE_SIZE - run.BasePage`
3. `file_offset = data_start_of_run + page_offset_in_run * PAGE_SIZE`

Where `data_start_of_run` is the cumulative sum of all preceding runs' page counts, plus `headerpages`, all multiplied by `PAGE_SIZE`.

### Bitmap Dump (DumpType 0x05) -- `_SUMMARY_DUMP`

For bitmap dumps, a `_SUMMARY_DUMP` / `_SUMMARY_DUMP64` header follows the main dump header.

| Field | Type | Description |
|-------|------|-------------|
| `ValidDump` | u32 | Must be `0x504D5544` = "DUMP" (or `PMUD` reversed) |
| `HeaderSize` | u32 | Full size of the summary header |
| `BitmapSize` | u32 | Number of bits in bitmap |
| `Pages` | u32 | Number of pages present (= popcount of bitmap) |
| Bitmap | u8[] | Follows immediately; bit N = 1 means page N is present |

Pages are stored sequentially in the file after the bitmap. Only pages whose corresponding bit is set appear in the file. Page N's file position is determined by counting set bits before position N in the bitmap.

### `_DUMP_HEADER` (32-bit, 4096 bytes = 1 page)

| Offset | Size | Type | Field |
|--------|------|------|-------|
| 0x000 | 4 | u32 | `Signature` = `0x45474150` ("PAGE") |
| 0x004 | 4 | u32 | `ValidDump` = `0x504D5544` ("DUMP") |
| 0x008 | 4 | u32 | `MajorVersion` |
| 0x00C | 4 | u32 | `MinorVersion` |
| 0x010 | 4 | u32 | `DirectoryTableBase` (CR3) |
| 0x014 | 4 | u32 | `PfnDataBase` |
| 0x018 | 4 | u32 | `PsLoadedModuleList` |
| 0x01C | 4 | u32 | `PsActiveProcessHead` |
| 0x020 | 4 | u32 | `MachineImageType` (0x14C = i386) |
| 0x024 | 4 | u32 | `NumberProcessors` |
| 0x028 | 4 | u32 | `BugCheckCode` |
| 0x02C | 16 | u32[4] | `BugCheckParameter[0..3]` |
| 0x060 | 4 | u32 | `KdDebuggerDataBlock` |
| 0x064 | var | struct | `PhysicalMemoryBlockBuffer` |
| 0x320 | 1200 | u8[] | `ContextRecord` |
| 0x7D0 | var | struct | `Exception` (EXCEPTION_RECORD32) |

32-bit `_PHYSICAL_MEMORY_RUN` uses `u32` fields (8 bytes each entry).

---

## 2. Windows Kernel Crash Dump

Uses the same `_DUMP_HEADER` / `_DUMP_HEADER64` structure as full dumps. The difference is purely in content scope:

- **Full dump** (`DumpType=0x01`): Contains ALL physical memory pages. The `_PHYSICAL_MEMORY_DESCRIPTOR` covers the entire physical address space.
- **Kernel dump** (`DumpType=0x02`): Contains only kernel-mode pages. Uses `_SUMMARY_DUMP` with a bitmap indicating which pages are present.
- **Bitmap kernel dump** (`DumpType=0x05`): Same as kernel but uses the newer bitmap format instead of run-based layout. Bitmap granularity = 1 page (4 KiB).

The header format, signature bytes, and physical-to-file mapping logic are identical -- only the set of included pages differs. For kernel dumps, user-mode pages are omitted, so the bitmap will have gaps for user-space regions.

### Page translation

Virtual-to-physical translation requires walking the page tables using `DirectoryTableBase` (CR3) from the header. The page table walker is the same regardless of dump type -- the difference is only which physical pages are available.

---

## 3. Hiberfil.sys (Windows Hibernation File)

### Detection / Signatures

| Signature | ASCII | Meaning |
|-----------|-------|---------|
| `0x72626968` | `hibr` | Active hibernation file (exploitable) |
| `0x656B6177` | `wake` | System resuming (may be partially overwritten) |
| `0x52545352` | `RSTR` | Restore in progress |
| `0x4D524F48` | `HORM` | Hibernate Once Resume Many (IoT/Enterprise) |

If signature is zeroed out, brute-force search for Xpress signatures is needed.

### `PO_MEMORY_IMAGE` Header (Windows XP/2003 32-bit, 168 bytes)

| Offset | Size | Type | Field |
|--------|------|------|-------|
| 0x00 | 4 | char[4] | `Signature` ("hibr"/"wake"/"RSTR") |
| 0x04 | 4 | u32 | `Version` |
| 0x08 | 4 | u32 | `Checksum` |
| 0x0C | 4 | u32 | `LengthSelf` (size of this struct) |
| 0x10 | 4 | u32 | `PageSelf` (page number of header) |
| 0x14 | 4 | u32 | `PageSize` (always 0x1000) |
| 0x18 | 4 | u32 | `ImageType` |
| 0x1C | 4 | - | Padding |
| 0x20 | 8 | u64 | `SystemTime` (FILETIME) |
| 0x28 | 8 | u64 | `InterruptTime` |
| 0x30 | 4 | u32 | `FeatureFlags` |
| 0x34 | 1 | u8 | `HiberFlags` |
| 0x35 | 3 | u8[3] | Spare |
| 0x38 | 4 | u32 | `NoHiberPtes` |
| 0x3C | 4 | u32 | `HiberVa` |
| 0x40 | 8 | u64 | `HiberPte` |
| 0x48 | 4 | u32 | `NoFreePages` |
| 0x4C | 4 | u32 | `FreeMapCheck` |
| 0x50 | 4 | u32 | `WakeCheck` |
| 0x54 | 4 | u32 | `TotalPages` |
| 0x58 | 4 | u32 | `FirstTablePage` |
| 0x5C | 4 | u32 | `LastFilePage` |
| 0x60 | 72 | struct | `PerfInfo` (PO_HIBER_PERF) |

### Header size by Windows version

| Version | Architecture | PO_MEMORY_IMAGE Size |
|---------|-------------|---------------------|
| Win 2000 SP4 | 32-bit | 96 bytes |
| XP/2003 | 32-bit | 168 bytes |
| XP/2003 | 64-bit | 192 bytes |
| Vista SP0 | 32-bit | 224 bytes |
| Vista SP1 | 32-bit | 240 bytes |
| Win 7 SP0 | 64-bit | 296 bytes |
| Win 8+ | 64-bit | varies (modern format) |

### Key 64-bit differences (XP/2003 64-bit, 192 bytes)

Pointers widen to 8 bytes: `PageSelf` (offset 0x10, 8 bytes), `HiberVa` (offset 0x40, 8 bytes), `HiberPte` (offset 0x48, 8 bytes), `TotalPages` (offset 0x60, 8 bytes), `FirstTablePage` (offset 0x68, 8 bytes), `LastFilePage` (offset 0x70, 8 bytes).

### Page layout (legacy format, pre-Win8)

| Page(s) | Content |
|---------|---------|
| 0 | `PO_MEMORY_IMAGE` header |
| 1 | Processor State (`_KPROCESSOR_STATE`, contains CR3) |
| 2-5 | Unknown/reserved |
| 6 | Compressed page map of first hibernated memory block |
| 7+ | Compressed page data of first hibernated memory block |

### Compressed page data block (legacy)

| Offset | Size | Description |
|--------|------|-------------|
| 0x00 | 8 | Signature: `\x81\x81xpress` |
| 0x08 | 1 | `NumPages - 1` (number of pages in this block minus one) |
| 0x09 | 4 | `(CompressedDataSize * 4) - 1` |
| 0x0D | 19 | Unknown/padding |
| 0x20 | var | LZ XPRESS compressed data |
| ... | var | 8-byte alignment padding |

To decode: `CompressedDataSize = (raw_value / 4) + 1`

### Modern format (Windows 8+)

Windows 8 introduced a new structure. Key changes:

- **"Table pages" and "XPRESS sets" replaced by "restoration sets"** containing many "compression sets".
- The header gains `FirstBootRestorePage` and `FirstKernelRestorePage` fields.
- Memory is divided into two sections:
  - **Boot section** (offset = `FirstBootRestorePage * 0x1000`, count = `NumPagesForLoader`)
  - **Kernel section** (offset = `FirstKernelRestorePage * 0x1000`, count = `PerfInfo.KernelPagesProcessed`)

### Compression set structure (modern format)

Each compression set has a header describing:
- Number of page descriptors
- Compression algorithm used (Xpress LZ77 or Xpress LZ77+Huffman)
- Size of compressed concatenated pages

Page descriptors follow the header and describe where individual pages reside in the decompressed output.

### Compression algorithms

| Algorithm | Description | Reference |
|-----------|-------------|-----------|
| **Xpress (LZ77)** | Microsoft Xpress LZ77 Decompression | MS-XCA spec |
| **Xpress Huffman (LZ77+Huffman)** | Microsoft Xpress LZ77+Huffman | MS-XCA spec |

Both are documented in the Microsoft [MS-XCA] specification as part of the Interoperability program.

### Extracting physical memory from hiberfil.sys

1. Read `PO_MEMORY_IMAGE` header, validate signature
2. For legacy: follow `FirstTablePage` to locate compressed page map entries
3. For modern: follow `FirstBootRestorePage` and `FirstKernelRestorePage`
4. Each compressed block contains an Xpress signature (`\x81\x81xpress`)
5. Decompress with LZ77 or LZ77+Huffman to recover raw pages
6. Page map entries provide the physical page number for each decompressed page

---

## 4. VMware (.vmem + .vmss/.vmsn)

### .vmem files

Confirmed: `.vmem` files are **raw flat physical memory dumps**. They contain a contiguous image of the guest VM's physical memory starting at physical address 0. No header, no metadata -- pure raw bytes.

- File offset N corresponds to physical address N
- Size of file = amount of RAM assigned to the VM
- Can be analyzed directly as a raw memory image

### .vmss / .vmsn files

`.vmss` = saved state (suspend), `.vmsn` = snapshot state.

These contain physical memory plus metadata (CPU state, VM config, screen thumbnails).

### `_VMWARE_HEADER` (12 bytes at offset 0)

| Offset | Size | Type | Field |
|--------|------|------|-------|
| 0x0 | 4 | u32 | `Magic` |
| 0x4 | 4 | u32 | (unknown/padding) |
| 0x8 | 4 | u32 | `GroupCount` |
| 0xC | var | struct[] | `Groups[GroupCount]` |

### Magic values for detection

| Value | Hex |
|-------|-----|
| Valid | `0xBED2BED0` |
| Valid | `0xBAD1BAD1` |
| Valid | `0xBED2BED2` |
| Valid | `0xBED3BED3` |

### `_VMWARE_GROUP` (80 bytes each)

| Offset | Size | Type | Field |
|--------|------|------|-------|
| 0x00 | 64 | char[64] | `Name` (UTF-8, null-terminated) |
| 0x40 | 8 | u64 | `TagsOffset` (absolute file offset to tags array) |

Common group names: `cpu`, `memory`, `mainmem`, `display`, `ide`, etc.

### `_VMWARE_TAG` (variable size)

| Offset | Size | Type | Field |
|--------|------|------|-------|
| 0x0 | 1 | u8 | `Flags` (encodes data length in lower bits) |
| 0x1 | 1 | u8 | `NameLength` |
| 0x2 | var | char[] | `Name` (NameLength bytes, UTF-8) |
| ... | var | u8[] | Indices (from Flags) |
| ... | var | u8[] | Data payload |

Tag terminator: a tag with `Flags == 0` marks the end of a group's tag list.

### Extracting CPU state / CR3

CPU registers are stored as tags within the `cpu` group:

| Tag path | Description |
|----------|-------------|
| `cpu/CR[0][3]` | **CR3** (page directory base) |
| `cpu/CR[0][0]` | CR0 |
| `cpu/CR[0][4]` | CR4 |
| `cpu/rip[0]` | Instruction pointer |
| `cpu/eflags[0]` | EFLAGS/RFLAGS |
| `cpu/GDTR[0][0]` | GDT limit |
| `cpu/GDTR[0][1]` | GDT base |
| `cpu/IDTR[0][0]` | IDT limit |
| `cpu/IDTR[0][1]` | IDT base |

The index `[0]` refers to CPU 0. Multi-processor VMs have `[1]`, `[2]`, etc.

### Extracting physical memory from .vmss/.vmsn

Physical memory runs are stored as tags within the `memory` or `mainmem` group. The data payload of the memory tags contains the raw physical pages. The runs describe which physical address ranges are present, similar to crash dump runs.

For forensic analysis, the recommended approach is to use the `vmss2core` VMware utility to convert to a raw dump, or parse the group/tag structure to extract memory data directly.

---

## 5. Linux kdump (makedumpfile)

### Detection

| Signature | Hex bytes | Format |
|-----------|-----------|--------|
| `KDUMP   ` | `4B 44 55 4D 50 20 20 20` | kdump-compressed |
| `DISKDUMP` | `44 49 53 4B 44 55 4D 50` | legacy diskdump |

Signature is 8 bytes (`SIG_LEN = 8`), padded with spaces.

### File layout

```
Offset                          Content
+------------------------------------------+ 0x0
|  main header (disk_dump_header)          |  1 block
+------------------------------------------+ block_size
|  sub header (kdump_sub_header)           |  sub_hdr_size blocks
+------------------------------------------+ block_size * (1 + sub_hdr_size)
|  1st-bitmap                              |  bitmap_blocks blocks
+------------------------------------------+ block_size * (1 + sub_hdr_size + bitmap_blocks)
|  2nd-bitmap                              |  bitmap_blocks blocks (block-aligned)
+------------------------------------------+ block_size * (1 + sub_hdr_size + 2*bitmap_blocks)
|  page_desc[0] (pfn 0)                   |  block-aligned
|  page_desc[1] (pfn 1)                   |
|  ...                                     |
|  page_desc[Z]                            |
+------------------------------------------+
|  page data (pfn 0)                       |  NOT block-aligned
|  page data (pfn 1)                       |
|  ...                                     |
|  page data (pfn Z)                       |
+------------------------------------------+
|  erase info (optional)                   |
+------------------------------------------+
```

### `struct disk_dump_header`

| Offset | Size | Type | Field |
|--------|------|------|-------|
| 0x00 | 8 | char[8] | `signature` = `"KDUMP   "` |
| 0x08 | 4 | i32 | `header_version` |
| 0x0C | 390 | struct | `utsname` (new_utsname: 6 fields x 65 chars) |
| 0x192 | 8/16 | struct | `timestamp` (struct timeval: sec + usec) |
| varies | 4 | u32 | `status` (flags: 0=completed, 1=incomplete, 8=compressed) |
| varies | 4 | i32 | `block_size` (typically 4096) |
| varies | 4 | i32 | `sub_hdr_size` (blocks) |
| varies | 4 | u32 | `bitmap_blocks` (blocks) |
| varies | 4 | u32 | `max_mapnr` (OBSOLETE, 32-bit only) |
| varies | 4 | u32 | `total_ram_blocks` |
| varies | 4 | u32 | `device_blocks` |
| varies | 4 | u32 | `written_blocks` |
| varies | 4 | u32 | `current_cpu` |
| varies | 4 | i32 | `nr_cpus` |

Note: `struct new_utsname` is 390 bytes (6 fields of 65 chars: sysname, nodename, release, version, machine, domainname).

Note: The exact byte offsets after `utsname` depend on platform alignment. Use the `block_size` field to locate subsequent sections by block number.

### `struct kdump_sub_header`

| Field | Type | Description | Min version |
|-------|------|-------------|-------------|
| `phys_base` | unsigned long | Physical base for relocatable kernels | v0 |
| `dump_level` | i32 | makedumpfile -d option value | v1+ |
| `split` | i32 | Split dump indicator | v2+ |
| `start_pfn` | unsigned long | Start PFN (OBSOLETE, 32-bit) | v2+ |
| `end_pfn` | unsigned long | End PFN (OBSOLETE, 32-bit) | v2+ |
| `offset_vmcoreinfo` | u64 | Offset to vmcoreinfo | v3+ |
| `size_vmcoreinfo` | u64 | Size of vmcoreinfo | v3+ |
| `offset_note` | u64 | Offset to ELF note | v4+ |
| `size_note` | u64 | Size of ELF note | v4+ |
| `offset_eraseinfo` | u64 | Offset to erase info | v5+ |
| `size_eraseinfo` | u64 | Size of erase info | v5+ |
| `start_pfn_64` | u64 | Start PFN (full 64-bit) | v6+ |
| `end_pfn_64` | u64 | End PFN (full 64-bit) | v6+ |
| `max_mapnr_64` | u64 | Max map number (full 64-bit) | v6+ |

### `struct page_desc` (page descriptor, 24 bytes on 64-bit)

| Offset | Size | Type | Field |
|--------|------|------|-------|
| 0x00 | 8 | i64 (off_t) | `offset` -- file offset of page data |
| 0x08 | 4 | u32 | `size` -- size of this page's data in file |
| 0x0C | 4 | u32 | `flags` -- compression flags |
| 0x10 | 8 | u64 | `page_flags` -- kernel page flags |

### Compression flags (`page_desc.flags`)

| Flag | Value | Algorithm |
|------|-------|-----------|
| `DUMP_DH_COMPRESSED_ZLIB` | `0x01` | zlib |
| `DUMP_DH_COMPRESSED_LZO` | `0x02` | LZO |
| `DUMP_DH_COMPRESSED_SNAPPY` | `0x04` | Snappy |
| `DUMP_DH_COMPRESSED_INCOMPLETE` | `0x08` | Dump is incomplete |
| `DUMP_DH_EXCLUDED_VMEMMAP` | `0x10` | Unused vmemmap pages excluded |
| `DUMP_DH_COMPRESSED_ZSTD` | `0x20` | Zstandard (zstd) |

If `flags == 0` and `size == block_size`, the page is uncompressed (stored raw).
If `page_desc.offset == 0` and `DUMP_DH_COMPRESSED_INCOMPLETE` is set in the dump header status, the page was lost due to ENOSPC.

### Bitmaps

Two bitmaps follow the sub-header:
- **1st bitmap**: Indicates which PFNs exist in the system (valid memory)
- **2nd bitmap**: Indicates which PFNs are actually dumped (present in file)

Each bitmap is `bitmap_blocks * block_size` bytes. Bit N being set means PFN N is valid/present.

### Reading a specific physical page

1. Parse `disk_dump_header` to get `block_size`, `sub_hdr_size`, `bitmap_blocks`
2. Calculate page descriptor table offset: `block_size * (1 + sub_hdr_size + 2 * bitmap_blocks)`
3. Check 2nd bitmap: is PFN's bit set? If not, page was excluded
4. Count set bits before the target PFN in the 2nd bitmap = index into page_desc array
5. Read `page_desc` at: `page_desc_offset + index * sizeof(page_desc)`
6. Read compressed data at `page_desc.offset` for `page_desc.size` bytes
7. Decompress according to `page_desc.flags`

### Flattened format (for SSH transport)

When transported over SSH, kdump uses a flattened format:

| Offset | Size | Content |
|--------|------|---------|
| 0x0 | 4096 | `makedumpfile_header` (flat header) |
| 0x1000+ | var | `makedumpfile_data_header` blocks |

The `makedumpfile_data_header` records the original offset and size of each data block so the receiver can reconstruct the original format.

### `struct makedumpfile_header` (flattened)

| Field | Type | Description |
|-------|------|-------------|
| `signature` | char[16] | `"makedumpfile"` |
| `type` | i64 | Format type (1 = flattened) |
| `version` | i64 | Version |

### `struct makedumpfile_data_header` (flattened)

| Field | Type | Description |
|-------|------|-------------|
| `offset` | i64 | Original offset in the non-flat file |
| `buf_size` | i64 | Size of data following this header |

To reconstruct: read each `makedumpfile_data_header`, copy `buf_size` bytes to `offset` in the output file.

---

## Summary: Magic Bytes Quick Reference

| Format | Offset | Bytes (LE hex) | ASCII | Notes |
|--------|--------|---------------|-------|-------|
| Win64 crash dump | 0x0 | `50 41 47 45` | `PAGE` | + ValidDump `DU64` at +4 |
| Win32 crash dump | 0x0 | `50 41 47 45` | `PAGE` | + ValidDump `DUMP` at +4 |
| Bitmap summary | +0x2000 | `44 55 4D 50` | `DUMP` | a.k.a. `PMUD` reversed |
| Hiberfil.sys | 0x0 | `68 69 62 72` | `hibr` | Or `wake`/`RSTR`/`HORM` |
| Xpress block | var | `81 81 78 70 72 65 73 73` | `\x81\x81xpress` | In hiberfil compressed data |
| VMware .vmss/.vmsn | 0x0 | `D0 BE D2 BE` | - | `0xBED2BED0` LE |
| VMware .vmss/.vmsn | 0x0 | `B1 BA D1 BA` | - | `0xBAD1BAD1` LE |
| VMware .vmss/.vmsn | 0x0 | `D2 BE D2 BE` | - | `0xBED2BED2` LE |
| VMware .vmss/.vmsn | 0x0 | `D3 BE D3 BE` | - | `0xBED3BED3` LE |
| VMware .vmem | 0x0 | (none) | - | Raw flat memory, no header |
| kdump compressed | 0x0 | `4B 44 55 4D 50 20 20 20` | `KDUMP   ` | 8-byte signature |
| Legacy diskdump | 0x0 | `44 49 53 4B 44 55 4D 50` | `DISKDUMP` | Predecessor format |

---

## Existing Rust Parsers (reference implementations)

| Crate | Formats | Repository |
|-------|---------|------------|
| `kdmp-parser` | Windows crash dumps (all DumpTypes) | [0vercl0k/kdmp-parser-rs](https://github.com/0vercl0k/kdmp-parser-rs) |

---

## Sources

- [Volatility Foundation Wiki -- Crash Address Space](https://github.com/volatilityfoundation/volatility/wiki/Crash-Address-Space)
- [Volatility3 crash.py source](https://volatility3.readthedocs.io/en/latest/_modules/volatility3/framework/layers/crash.html)
- [Volatility Foundation -- VMware Snapshot File](https://github.com/volatilityfoundation/volatility/wiki/VMware-Snapshot-File)
- [MoVP II -- VMware Snapshot and Saved State Analysis](https://volatilityfoundation.org/movp-ii-1-3-vmware-snapshot-and-saved-state-analysis/)
- [libhibr -- Windows Hibernation File format spec](https://github.com/libyal/libhibr/blob/main/documentation/Windows%20Hibernation%20File%20(hiberfil.sys)%20format.asciidoc)
- [ForensicXLab -- Modern Windows Hibernation file analysis](https://www.forensicxlab.com/blog/hibernation)
- [makedumpfile IMPLEMENTATION doc](https://github.com/makedumpfile/makedumpfile/blob/master/IMPLEMENTATION)
- [makedumpfile diskdump_mod.h](https://github.com/makedumpfile/makedumpfile/blob/master/diskdump_mod.h)
- [libkdumpfile diskdump.c](https://github.com/ptesarik/libkdumpfile/blob/tip/src/kdumpfile/diskdump.c)
- [Oracle Linux Blog -- What's Inside a Linux Kernel Core Dump](https://blogs.oracle.com/linux/whats-inside-a-linux-kernel-core-dump)
- [nforest/dumplib DMPTemplate.bt](https://github.com/nforest/dumplib/blob/master/DMPTemplate.bt)
- [kdmp-parser-rs](https://github.com/0vercl0k/kdmp-parser-rs)
- [Microsoft windows-docs-rs DUMP_HEADER64](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Diagnostics/Debug/struct.DUMP_HEADER64.html)
- [Gynvael Coldwind -- Asking MEMORY.DMP and Volatility to make up](https://gynvael.coldwind.pl/?lang=en&id=762)
- [Forensic Focus -- Memory Dump Formats](https://www.forensicfocus.com/articles/memory-dump-formats/)
