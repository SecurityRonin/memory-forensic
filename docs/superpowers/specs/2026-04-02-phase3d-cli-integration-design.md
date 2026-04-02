# Phase 3D: End-to-End CLI Integration — Design Spec

> Approved design for making the memf CLI functional for Linux, Windows, and
> (future) macOS memory dumps. Wires the walkers from memf-linux and memf-windows
> into CLI subcommands with OS auto-detection and CR3 extraction.

## Goal

Make `memf ps`, `memf modules`, and `memf netstat` functional end-to-end. Add
Windows-specific commands (`memf threads`, `memf dlls`). Implement OS
auto-detection (Linux, Windows, macOS) and CR3 extraction so users don't need
to specify the OS or page table root manually.

## Architecture

```
[dump file] → memf-format (open_dump → PhysicalMemoryProvider + DumpMetadata)
                    ↓
[OS detection] → examine metadata + symbols → OsProfile { Linux, Windows, MacOs }
                    ↓
[CR3 extraction] → Windows: metadata.cr3
                   Linux: swapper_pg_dir + KASLR → physical
                   Manual: --cr3 flag
                    ↓
[VirtualAddressSpace] → memf-core (page table walking)
                    ↓
[ObjectReader] → memf-core (kernel object reading)
                    ↓
[Walker dispatch] → Linux: memf-linux walkers
                    Windows: memf-windows walkers
                    ↓
[Output formatting] → table / json / csv
```

## Module: `src/os_detect.rs`

### OsProfile

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsProfile {
    Linux,
    Windows,
    MacOs,
}
```

### AnalysisContext

```rust
pub struct AnalysisContext {
    pub os: OsProfile,
    pub cr3: u64,
    pub kaslr_offset: u64,                    // 0 for Windows, or if no KASLR
    pub ps_active_process_head: Option<u64>,   // Windows only (from metadata)
    pub ps_loaded_module_list: Option<u64>,     // Windows only (from metadata)
}
```

### Detection Logic

`detect_os(metadata: Option<&DumpMetadata>, symbols: &dyn SymbolResolver) -> Result<OsProfile>`

Priority order:
1. If `metadata.machine_type` is `Some(Amd64 | I386)` AND `metadata.cr3` is `Some(_)` → **Windows** (crash dumps always have both)
2. If symbols contain `init_task` symbol → **Linux**
3. If symbols contain `_EPROCESS` struct → **Windows**
4. Else → error: "cannot determine OS; provide --os linux|windows"

macOS detection (future): symbols contain `allproc` or `kernel_map`.

### CR3 Extraction

`extract_cr3(os: OsProfile, metadata: Option<&DumpMetadata>, symbols: &dyn SymbolResolver, provider: &dyn PhysicalMemoryProvider) -> Result<u64>`

**Windows:** `metadata.cr3.ok_or("crash dump missing CR3")`

**Linux:**
1. Get `swapper_pg_dir` symbol virtual address from resolver
2. Compute KASLR offset via `detect_kaslr_offset(provider, symbols)`
3. `cr3_phys = swapper_pg_dir_vaddr + kaslr_offset - KERNEL_MAP_BASE`
   where `KERNEL_MAP_BASE = 0xFFFF_FFFF_8000_0000`

**macOS:** Not implemented; bail with helpful message.

### Manual Override

`--cr3 <hex_addr>` flag on all analysis commands. Bypasses auto-extraction.
The existing bail message says `"Use memf ps --cr3 <addr> when available."` —
this fulfills that promise.

## CLI Changes

### Enhanced `memf info`

Show DumpMetadata when available:

```
Format:     Windows Crash Dump
Type:       Full Memory
Machine:    AMD64
CR3:        0x001ab000
PsActiveProcessHead: 0xfffff80234567890
PsLoadedModuleList:  0xfffff80234568000
Processors: 4
OS Version: 10.0

Total size: 8.00 GB
Ranges:     1
```

No `--symbols` needed — purely from dump header metadata.

### Updated Commands

All analysis commands gain:
- `--cr3 <addr>` — manual CR3 override (parsed as hex with optional `0x` prefix)

#### `memf ps`

- Detect OS, extract CR3
- Linux: `memf_linux::process::walk_processes(&reader)` (uses `init_task` symbol)
- Windows: `memf_windows::process::walk_processes(&reader, ps_head)` (uses `PsActiveProcessHead`)
- Table columns: PID, PPID, Name, Create Time, CR3

#### `memf modules`

- Linux: `memf_linux::modules::walk_modules(&reader)` → kernel modules
- Windows: `memf_windows::driver::walk_drivers(&reader, module_list)` → loaded drivers
- Table columns: Name, Base Address, Size, Path

#### `memf netstat`

- Linux: `memf_linux::network::walk_connections(&reader)`
- Windows: bail with "Windows network connections not yet supported (Phase 3E)"
- macOS: bail with "macOS network connections not yet supported"
- Table columns: Proto, Local Address, Remote Address, State, PID

### New Commands

#### `memf threads`

- Windows only (for now)
- Optional `--pid <pid>` filter
- Walks all processes, then walks threads for each
- Table columns: TID, PID, Image, Start Address, State, Create Time

#### `memf dlls`

- Windows only
- Required `--pid <pid>` — which process's DLLs to list
- Finds the process, uses its CR3 + PEB to walk DLLs
- Table columns: Name, Base Address, Size, Load Order, Path

## Symbol Loading Enhancement

Extend `load_symbols()`:

```rust
fn load_symbols(path: Option<&Path>) -> Result<Box<dyn SymbolResolver>> {
    // If path points to a .pdb file → PdbResolver::from_path()
    // If path points to a .json file → IsfResolver::from_path()
    // If path is a directory → discover ISF files (existing behavior)
    // Else → error
}
```

This uses the existing `PdbResolver` from Phase 3B.

## ISF Preset Extension

Add `swapper_pg_dir` symbol to `linux_process_preset()` in
`memf-symbols/src/test_builders.rs`. This is needed for Linux CR3 extraction
tests. Use address `0xFFFF_FFFF_8200_0000` (typical kernel text segment).

## Output Formatting

All commands support `--output table|json|csv` (existing `OutputFormat` enum).

Extract reusable formatting helpers for the new data types:

- `format_hex(val: u64) -> String` — `format!("{:#014x}", val)`
- `format_filetime(ft: u64) -> String` — Convert Windows FILETIME to human-readable
- Process/thread/driver/DLL formatters for each output mode

Table output uses `comfy-table` (existing dependency).
JSON output uses NDJSON (one object per line, existing pattern).
CSV output uses simple `println!` with proper escaping (existing pattern).

## Test Strategy

| Component | Strategy |
|-----------|----------|
| `OsProfile` enum | Unit: Display + equality |
| `detect_os` | Unit: metadata → Windows, symbols → Linux, both empty → error |
| `extract_cr3` Windows | Unit: metadata with CR3 → returns it |
| `extract_cr3` Linux | Unit: ISF with `swapper_pg_dir` + mock KASLR → correct physical |
| `cmd_info` metadata | Integration: CrashDumpBuilder → verify metadata fields printed |
| Output formatters | Unit: pass pre-built walker types → verify formatted strings |
| `load_symbols` PDB | Unit: .pdb extension → PdbResolver dispatched |
| `--cr3` parsing | Unit: hex parsing with/without `0x` prefix |
| CLI argument parsing | Clap built-in validation |

Full end-to-end tests (dump → walkers → output) require synthetic dumps with
valid page tables + kernel structures. These are complex to build at the CLI level
and provide limited value over the existing walker-level tests. Defer full e2e
CLI testing to when real dump fixtures are available.

## Error Handling

Use `anyhow` throughout (CLI layer). Walker errors propagate up with context:

```
Error: failed to walk processes
  Caused by: core error: page not present at 0xdeadbeef
```

For unsupported OS/command combinations, return clear messages:
- "Windows network connections not yet supported (scheduled for Phase 3E)"
- "macOS memory analysis not yet supported"
- "memf threads requires a Windows memory dump"

## Non-Goals

- Windows network connections (TCP/IP partition walking — Phase 3E)
- macOS walkers (future phase)
- Automatic PDB download from Microsoft symbol server (Phase 3E)
- Timeline generation across artifacts (Phase 3E)
- VAD tree walking (Phase 3E)
- Handle table walking (Phase 3E)
