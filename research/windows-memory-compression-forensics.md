# Windows Memory Compression for Forensics: Technical Deep Dive

## 1. Windows Memory Compression Store Architecture

### Overview

Windows 10 (since build 10525, August 2015) introduced memory compression managed by the
**Store Manager** kernel component. When the memory manager detects pressure, it compresses
infrequently-used pages via the Xpress algorithm and stores them in an in-RAM **virtual store**
backed by the `MemCompression.exe` process, rather than immediately paging to disk.

### Key Kernel Structures (all undocumented)

```
nt!SmGlobals (global symbol)
  └── SMKM_STORE_MGR (offset 0x0 from SmGlobals)
        ├── sGlobalTree (B+tree: SM_PAGE_KEY → store index)
        └── SMKM_STORE_METADATA[32][32] (2D array, each element → one store)
              └── SMKM_STORE
                    ├── PagesTree (B+tree: SM_PAGE_KEY → chunk key / region key)
                    ├── ChunkMetaData → SMHP_CHUNK_METADATA
                    │     ├── aChunkPointer[2D] → page records
                    │     ├── dwVectorSize
                    │     ├── dwPageRecordsPerChunk
                    │     ├── dwPageRecordSize
                    │     └── dwChunkPageHeaderSize
                    ├── SmkmStore → embedded ST_STORE
                    │     └── ST_DATA_MGR
                    │           ├── dwRegionIndexMask
                    │           └── dwRegionSizeMask
                    ├── RegionSizeMask / RegionIndexMask
                    ├── CompressionAlgorithm (WORD, typically COMPRESS_ALGORITHM_XPRESS=3)
                    ├── CompressedRegionPtrArray → array of region VAs
                    ├── OwnerProcess → EPROCESS of MemCompression
                    └── StoreOwnerProcess
```

### Compression Store Internals

- Each compressed page is stored in one or more **16-byte aligned chunks** within a region.
- Compressed pages are indexed via **B+trees**: leaf entries map `SM_PAGE_KEY → value` pairs.
- B+tree nodes contain: `cEntries` (u16), `cLevel` (u8), `fLeaf` (u8), child pointers,
  and either `LeafEntry{k,v}` or `NodeEntry{k, vaChild}` arrays.
- Each `_ST_PAGE_RECORD` contains: `Key` (region key compound value) and `CompressedSize`.

### SM_PAGE_KEY Calculation

The page key is computed from the software PTE when a page is identified as being in the
compressed store (not hardware-resident, not in transition, not prototype):

```
// x64 (build >= 17134 / RS4 / 1803+):
PageFileNumber = (pte >> 12) & 0x0f
PageFileOffset = (pte >> 32) ^ (!(pte & 0x10) ? InvalidPteMask : 0)
SM_PAGE_KEY    = (PageFileNumber << 0x1c) | PageFileOffset

// Pre-1803:
PageFileNumber = (pte >> 1) & 0x0f
// offset calculation is the same
```

The `SwizzleBit` (bit 4 of the PTE) controls XOR deobfuscation with `nt!MiState->Hardware.InvalidPteMask`.

### Decompression Pipeline (5-step process from MemProcFS)

1. **SmkmStoreIndex**: Use `vaKeyToStoreTree` B+tree to map `dwPageKey → store index`
2. **SmkmStoreMetadata**: Decode store index → indices into 32x32 `SMKM_STORE_METADATA` array → get `vaSmkmStore`
3. **SmkmStoreAndPageRecord**: Read `SMKM_STORE`, search its `PagesTree` B+tree for `dwPageKey → dwRegionKey`, decode region key into chunk array index + offset to find `vaPageRecord`
4. **CompressedRegionData**: Read `_ST_PAGE_RECORD`, use `RegionIndexMask` to decode key → region pointer array index → region VA + offset → get compressed data address and size
5. **DecompressPage**: Read compressed bytes from `MemCompression` process VA space, decompress:
   - If `cbCompressedData == 0x1000`: page is uncompressed, memcpy
   - If `cbCompressedData == 0`: zero page
   - If build >= 26100 (Win11 24H2+): **LZ4** decompression
   - Else: **COMPRESS_ALGORITHM_XPRESS** (Plain LZ77) via `RtlDecompressBufferEx`

### Critical Discovery: Windows 11 24H2 Switched to LZ4

MemProcFS source (mm_win.c, line ~1018) shows that starting from build 26100 (Windows 11
24H2), Microsoft switched from Xpress/LZ77 to **LZ4** for memory compression. This is a
significant change that forensic tools must handle.

---

## 2. How MemProcFS Implements Decompression

### Source: `vmm/mm/mm_win.c` (1592 lines, 65.1KB)

**Author**: Ulf Frisk (pcileech@frizk.net), Copyright 2019-2026

### Key Data Structures

```c
typedef struct tdMMWIN_MEMCOMPRESS_OFFSET {
    BOOL _fValid;
    BOOL _fProcessedTry;
    WORD _Size;
    struct {
        WORD PagesTree;                  // B+tree root for page key → region key
        WORD SmkmStore;                  // Offset to embedded ST_STORE
        WORD ChunkMetaData;              // SMHP_CHUNK_METADATA offset
        WORD RegionSizeMask;             // For decoding region keys
        WORD RegionIndexMask;            // For decoding region keys
        WORD CompressionAlgorithm;       // WORD: typically 3 (XPRESS)
        WORD CompressedRegionPtrArray;   // Array of region VAs
        WORD OwnerProcess;               // EPROCESS ptr of MemCompression
    } SMKM_STORE;
} MMWIN_MEMCOMPRESS_OFFSET;

typedef struct tdMMWIN_MEMCOMPRESS_CONTEXT {
    QWORD vaEPROCESS;          // MemCompression EPROCESS
    DWORD dwPid;               // MemCompression PID
    DWORD dwPageFileNumber;    // Virtual store's page file number
    DWORD dwInvalidPteMask;    // Top 32-bits of nt!MiState->Hardware.InvalidPteMask
    BOOL fValid;
    BOOL fInitialized;
    QWORD vaSmGlobals;         // nt!SmGlobals kernel address
    QWORD vaKeyToStoreTree;    // Global B+tree for key → store mapping
    MMWIN_MEMCOMPRESS_OFFSET O;
} MMWIN_MEMCOMPRESS_CONTEXT;
```

### Version-Specific Offsets (x64)

| Field                      | 1607   | 1703   | 1709-1909 | 2004+  | 24H2+  |
|----------------------------|--------|--------|-----------|--------|--------|
| PagesTree                  | 0x50   | 0x50   | 0x50      | 0x50   | 0x50   |
| ChunkMetaData              | 0x110  | 0x110  | 0x110     | 0x110  | 0x110  |
| SmkmStore                  | 0x370  | 0x370  | 0x370     | 0x370  | 0x370  |
| RegionSizeMask             | 0x374  | 0x374  | 0x374     | 0x374  | 0x374  |
| RegionIndexMask            | 0x378  | 0x378  | 0x378     | 0x378  | 0x378  |
| CompressionAlgorithm       | 0x420  | 0x420  | 0x430     | 0x430  | 0 (N/A)|
| CompressedRegionPtrArray   | 0x1778 | 0x1828 | 0x1848    | 0x1848 | 0x1b70 |
| OwnerProcess               | 0x18E8 | 0x1988 | 0x19A8    | 0x19B8 | 0x1d08 |

### B+Tree Implementation

```c
typedef struct td_BTREE_LEAF_ENTRY {
    DWORD k;       // key (SM_PAGE_KEY or sub-key)
    DWORD v;       // value (store index or region key)
} _BTREE_LEAF_ENTRY;

typedef struct td_BTREE64 {
    WORD cEntries;
    BYTE cLevel;
    BYTE fLeaf;
    DWORD _Filler;
    QWORD vaLeftChild;
    union {
        _BTREE_LEAF_ENTRY LeafEntries[0];
        _BTREE_NODE_ENTRY64 NodeEntries[0];
    };
} _BTREE64;
```

### Main Entry Point

```c
BOOL MmWin_MemCompress(H, pProcess, va, pte, pbPage, fVmmRead)
{
    dwPageKey = MMWINX64_PTE_PAGE_KEY_COMPRESSED(H, pte);
    if(build >= 26100) dwPageKey &= 0x0fffffff;  // 24H2 mask

    result = MmWin_MemCompress1_SmkmStoreIndex(H, ctx)
          && MmWin_MemCompress2_SmkmStoreMetadata64(H, ctx)
          && MmWin_MemCompress3_SmkmStoreAndPageRecord64(H, ctx)
          && MmWin_MemCompress4_CompressedRegionData(H, ctx)
          && MmWin_MemCompress5_DecompressPage(H, ctx, pbPage);
}
```

---

## 3. SmGlobals / SmSuperContext Structures

### Required Kernel Symbols

| Symbol | Purpose |
|--------|---------|
| `nt!SmGlobals` | Entry point to Store Manager. Contains SMKM_STORE_MGR at offset 0x0. Located via PDB or disassembly of kernel functions that reference it. |
| `nt!MiState` | Contains `Hardware.InvalidPteMask` needed for PTE swizzle deobfuscation |
| `nt!MmPagingFile` | Array of paging file structures; needed to identify virtual store page file number |
| `nt!PsLoadedModuleList` | For kernel module enumeration |
| `nt!MmPfnDatabase` | Page Frame Number database for transition page resolution |

### SmGlobals Layout

- `SmGlobals` at offset 0x0 contains both `SMKM_STORE_MGR` and `SMKM` overlapping.
- Viewed as a 2D array: `SmGlobals[32][32]` of `SMKM_STORE_METADATA` pointers.
- Each row pointer leads to 32 `SMKM_STORE_METADATA` elements.
- The `sGlobalTree` within `SMKM_STORE_MGR` is the first B+tree to traverse.

### Note on SmSuperContext

The term "SmSuperContext" does not appear in publicly available documentation or MemProcFS
source. The closest equivalent is the `SMKM_STORE_MGR` structure at SmGlobals, which
serves as the super-context for all store operations. Some internal Microsoft
documentation may use "SmSuperContext" as an alias.

---

## 4. Pagefile.sys and Swapfile.sys Integration

### Pagefile.sys

- **Format**: No header/magic; raw 4KB page frames at sequential offsets
- **Purpose**: Traditional demand paging for Win32 processes
- **Max**: Up to 16 pagefiles supported; typically 1 in use
- **Forensic access**: Locked during OS operation; parse via raw filesystem (TSK) or forensic imager
- **Integration with compression**: When the compression store itself is under memory pressure,
  compressed pages can be paged out TO the pagefile. So the pagefile may contain both
  uncompressed paged-out pages AND compressed store data.

### Swapfile.sys

- **Format**: Similar to pagefile; raw page data
- **Purpose**: UWP/Modern app suspend/resume — writes entire private working set in one operation
- **Introduced**: Windows 8
- **Size**: Typically 256MB, managed alongside pagefile
- **Forensic value**: Contains suspended UWP app state including browser data, email clients

### Virtual Store Page File Number

The compression store itself is assigned a "virtual page file number" that doesn't
correspond to a real file on disk. When MemProcFS encounters a PTE with this page file
number, it routes to the compression store rather than a physical pagefile. This number
is determined during initialization via `MmWin_MemCompress_InitializeVirtualStorePageFileNumber`.

---

## 5. Implementation Strategy for Safe Rust

### Existing Rust Crates

| Crate | Author | Algorithms | Status |
|-------|--------|------------|--------|
| `rust-lzxpress` | **Magnet Forensics** | Plain LZ77, LZ77+Huffman, LZNT1 | Active, 25+ stars |
| `lz4_flex` / `lz4` | Community | LZ4 (needed for Win11 24H2+) | Mature |

The `rust-lzxpress` crate ([GitHub](https://github.com/MagnetForensics/rust-lzxpress))
provides all three Xpress variants needed for pre-24H2 Windows memory decompression.
It is written by the same company (Magnet Forensics) that makes forensic tools, so
it is specifically designed for this use case.

**Note**: LZNT1 performance is ~2x slower than native ntdll `RtlDecompressBuffer` and
~50% slower than equivalent C. This is acceptable for forensic analysis (not real-time).

### What Needs to Be Written in Rust

1. **B+tree parser** — Walk the SMKM B+tree structures in raw memory dumps
   - 32-bit and 64-bit variants
   - Handle leaf vs. node entries
   - Key comparison and child traversal

2. **SMKM_STORE structure parser** — Version-aware offset tables
   - Support builds 14393 through 26100+
   - Parse SMKM_STORE_METADATA 32x32 arrays
   - Decode compound values (store index, chunk key, region key)

3. **SM_PAGE_KEY calculator** — PTE → page key conversion
   - Handle SwizzleBit deobfuscation
   - Build-specific PageFileNumber extraction (pre/post RS4)
   - 24H2 page key masking (& 0x0fffffff)

4. **Compression store navigator** — Orchestration layer
   - Step 1-4 of the decompression pipeline
   - Read from MemCompression process virtual address space
   - Page record parsing and region offset calculation

5. **Decompression dispatch** — Route to correct algorithm
   - Build < 26100: `rust-lzxpress` Plain LZ77 (COMPRESS_ALGORITHM_XPRESS)
   - Build >= 26100: `lz4` crate
   - Handle uncompressed (0x1000 bytes) and zero pages

6. **PDB symbol resolver** — Find SmGlobals and MiState addresses
   - Parse ntoskrnl.exe PDB for symbol offsets
   - Or pattern-scan kernel image for known code sequences

### Architecture Recommendation

```
memf-compress/
├── src/
│   ├── lib.rs
│   ├── btree.rs          — B+tree traversal (generic over 32/64-bit)
│   ├── store.rs          — SMKM_STORE parsing with version dispatch
│   ├── page_key.rs       — PTE → SM_PAGE_KEY calculation
│   ├── decompress.rs     — Xpress LZ77 / LZ4 decompression dispatch
│   ├── offsets.rs        — Version-specific offset tables
│   └── navigator.rs      — 5-step orchestration pipeline
├── Cargo.toml            — deps: rust-lzxpress, lz4_flex, thiserror
```

### Safety Considerations

- All memory reads from dumps are fallible — use `Result<T, E>` everywhere
- B+tree traversal needs loop protection (MemProcFS limits to 4 iterations depth)
- Validate kernel addresses before dereferencing (`VMM_KADDR64_16` equivalent)
- Compressed data size validation: must be <= 0x1000 bytes
- Zero-copy where possible: compressed data can be read into stack buffers

---

## 6. Forensic Impact: What Compressed Memory Unlocks

### Artifacts Hidden in Compressed Pages

When tools cannot read compressed pages, the following artifacts go undetected:

- **Network connections**: MemProcFS found 5 additional closed network connections that
  Volatility's netscan missed in testing (from memory-forensics-tool-landscape survey).
  Closed/TIME_WAIT connections are prime candidates for compression since their data
  structures become cold quickly.

- **Process memory**: Module paths, loaded DLL information, and process environment
  blocks that are paged to the compression store.

- **Kernel driver paths**: "Drivers loaded on the system are enumerated, but several
  paths to the files on disk are paged out to the compression store. These missing
  paths could very well be the evil you were hunting!" (Mandiant/FireEye)

- **Registry data**: Hive cells for infrequently-accessed keys.

- **Credential material**: LSASS heap pages under memory pressure.

### Quantitative Estimates

From the dfir.ru analysis of the 2018 Lone Wolf Scenario (16GB RAM, Win10 RS3):
- The compressed store contained significant numbers of pages with PE headers (MZ signature)
- The exact count was estimated by scanning for compressed LZ77-encoded MZ signatures
  at 16-byte aligned boundaries within the MemCompression process space
- No published percentage is universally agreed upon, but practitioners report that
  **10-40% of total virtual pages** may reside in the compression store under
  moderate memory pressure, depending on workload

### Tools That Currently Cannot Read Compressed Pages

- **Volatility 2/3** (stock): Cannot decompress. Mandiant's win10_volatility fork
  added support for builds 1607-1809 but is no longer maintained for newer builds.
- **Rekall**: Same limitation as stock Volatility.
- **WinDbg**: Can read compressed pages on live systems via kernel debugging.
- **MemProcFS**: Full support including Win11 24H2 LZ4.

### Conclusion

Supporting memory compression decompression is a **critical differentiator** for any
forensic tool targeting Windows 10/11. Without it, a forensic examiner is performing
analysis on an incomplete view of memory, potentially missing the exact artifacts
(network connections, loaded modules, credential data) that matter most in an
investigation.

---

## References

1. Mandiant/FireEye FLARE Team, "Finding Evil in Windows 10 Compressed Memory, Part One"
   https://cloud.google.com/blog/topics/threat-intelligence/finding-evil-in-windows-ten-compressed-memory-part-one

2. FireEye, "Finding Evil in Windows 10 Compressed Memory, Part Two: Virtual Store Deep Dive"
   https://www.fireeye.fr/blog/threat-research/2019/08/finding-evil-in-windows-ten-compressed-memory-part-two.html

3. Sardar & Stancill, BlackHat USA 2019 White Paper, "Extracting Compressed Pages from the Windows 10 Virtual Store"
   https://i.blackhat.com/USA-19/Thursday/us-19-Sardar-Paging-All-Windows-Geeks-Finding-Evil-In-Windows-10-Compressed-Memory-wp.pdf

4. Maxim Suhanov (dfir.ru), "Memory compression and forensics"
   https://dfir.ru/2018/09/08/memory-compression-and-forensics/

5. Microsoft [MS-XCA], "Xpress Compression Algorithm" specification
   https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/a8b7cb0a-92a6-4187-a23b-5e14273b96f8

6. Magnet Forensics, `rust-lzxpress` crate
   https://github.com/MagnetForensics/rust-lzxpress

7. MemProcFS source code (mm_win.c)
   https://github.com/ufrisk/MemProcFS/blob/master/vmm/mm/mm_win.c

8. aleksost/MemoryDecompression tool and NTNU Master Thesis
   https://github.com/aleksost/MemoryDecompression
   https://ntnuopen.ntnu.no/ntnu-xmlui/handle/11250/2626390

9. Pen Test Partners, "Mounting memory with MemProcFS for advanced memory forensics"
   https://www.pentestpartners.com/security-blog/mounting-memory-with-memprocfs-for-advanced-memory-forensics/

10. Mandiant win10_volatility fork
    https://github.com/mandiant/win10_volatility
