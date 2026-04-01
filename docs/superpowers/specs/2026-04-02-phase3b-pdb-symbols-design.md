# Phase 3B: PDB Symbol Resolution — Design Spec

> Approved design for extending the `memf-symbols` crate with Windows PDB parsing,
> symbol server integration, and PE debug info extraction.

## Goal

Add a `PdbResolver` backend to `memf-symbols` that parses Windows PDB files and
implements the existing `SymbolResolver` trait. Include a symbol server client for
downloading PDBs from Microsoft's public symbol server, local caching, and PE debug
info extraction to identify which PDB corresponds to a kernel image.

## Architecture

```
[PE header in dump] → extract GUID+age+pdb_name
                           ↓
[Symbol Server] → download PDB → cache locally
                           ↓
[PDB file] → pdb crate → intermediate types → PdbResolver (impl SymbolResolver)
```

Three new modules in `memf-symbols`:
- `pdb_resolver.rs` — PDB parsing + SymbolResolver implementation
- `symserver.rs` — Symbol server client + local cache
- `pe_debug.rs` — PE/COFF debug info extraction (CodeView RSDS)

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `pdb` | 0.8 | PDB file parsing (TPI, symbols, address map) |
| `ureq` | 3 | Synchronous HTTP client for symbol server |
| `goblin` | 0.9 (existing) | PE header parsing for debug info extraction |

## Module: `pdb_resolver`

### Intermediate Types (test boundary)

```rust
struct PdbParsedData {
    structs: Vec<PdbStruct>,
    symbols: Vec<PdbSymbol>,
}

struct PdbStruct {
    name: String,
    size: u64,
    fields: Vec<PdbField>,
}

struct PdbField {
    name: String,
    offset: u64,
    type_name: String,
}

struct PdbSymbol {
    name: String,
    rva: u32,
}
```

### PdbResolver

- `from_path(path: &Path) -> Result<Self>` — parse PDB file
- `from_parsed(data: PdbParsedData) -> Self` — build from pre-parsed data (testable)
- Implements `SymbolResolver` with backend_name `"PDB"`
- `struct_count()`, `symbol_count()` accessors
- `pdb_info()` → returns GUID + age if available

### PDB Parsing

Uses `pdb` crate:
1. Open PDB via `pdb::PDB::open()`
2. Read `type_information()` → iterate types, collect Class/Union with FieldList members
3. Handle FieldList continuation (large structs split across multiple records)
4. Read `global_symbols()` + `address_map()` → collect Public symbols with RVAs
5. Convert to `PdbParsedData`, then `PdbResolver`

### Type Resolution

- Follow `TypeIndex` references to resolve field type names
- Handle pointer types (show as `*target_name`)
- Handle typedefs, const, volatile (follow chain to underlying type)
- Handle bitfields (report byte offset of containing field)
- Handle nested structs (include as type name reference)

## Module: `symserver`

### SymbolServerClient

```rust
struct SymbolServerClient {
    server_url: String,
    cache_dir: PathBuf,
}
```

- `new(server_url, cache_dir)` — constructor
- `default()` — Microsoft server + `~/.memf/symbols/`
- `get_pdb(pdb_name, guid, age) -> Result<PathBuf>` — check cache, download if missing
- `download_url(pdb_name, guid, age) -> String` — pure, testable URL construction
- `cache_path(pdb_name, guid, age) -> PathBuf` — pure, testable path construction

### URL Format

```
{server}/{pdb_name}/{GUID_HEX_NO_DASHES}{AGE_HEX}/{pdb_name}
```

GUID hex: uppercase, no dashes. Age hex: lowercase, no leading zeros (except age=0 → "0").

### Cache Layout

```
~/.memf/symbols/
  ntkrnlmp.pdb/
    1B72224D37B8179228200ED8994498B21/
      ntkrnlmp.pdb
```

## Module: `pe_debug`

### CodeView RSDS Extraction

```rust
struct PdbId {
    guid: String,    // hex with dashes
    age: u32,
    pdb_name: String,
}
```

- `extract_pdb_id(pe_bytes: &[u8]) -> Result<PdbId>` — parse PE, find debug directory, read RSDS record
- Uses `goblin` crate for PE parsing
- Returns error if no CodeView debug info present

## Test Strategy

The PDB MSF container format is too complex to synthesize in tests. Test boundary is
at the intermediate types:

| Layer | Testable? | Strategy |
|-------|-----------|----------|
| Intermediate → PdbResolver | Full TDD | Pure conversion, no I/O |
| PDB file → Intermediate | `#[ignore]` integration | Real .pdb file required |
| URL/path construction | Full TDD | Pure functions |
| HTTP download | `#[ignore]` integration | Real network required |
| PE debug extraction | Full TDD | Synthetic PE via goblin test builders |

### Windows Kernel ISF Preset

Add `IsfBuilder::windows_kernel_preset()` with common NT kernel structures
(_EPROCESS, _KTHREAD, _LIST_ENTRY, _UNICODE_STRING, _PEB) for downstream
Phase 3C testing. This uses the existing ISF infrastructure — no PDB needed.

## Error Handling

New error variants in `memf_symbols::Error`:
- `Pdb(String)` — PDB parsing errors (wraps `pdb::Error` display)
- `Network(String)` — symbol server HTTP errors
- `Cache(String)` — local cache I/O errors

## Non-Goals

- Async symbol server (sync with `ureq` is sufficient for CLI tool)
- PDB writing/modification
- DWARF debug info (future phase)
- Compressed PDB (`.pd_` CAB format) decompression (future)
