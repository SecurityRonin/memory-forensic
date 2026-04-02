# Phase 3E: RapidTriage Memory Forensic Integration — Design Spec

## Overview

Integrate memory forensic analysis into RapidTriage's existing TUI (rt-navigator) so that a single forensic workbench handles both filesystem artifacts and memory dumps. The memory-forensic crates remain as external library dependencies; RapidTriage consumes them to analyze memory dumps found inside UAC collections.

**Key decision:** No standalone memf TUI. RapidTriage is the single forensic UI. The `memf` CLI remains for non-interactive use.

## Architecture

### Dependency Model

RapidTriage adds memory-forensic crates as workspace git dependencies:

```toml
# RapidTriage Cargo.toml (workspace root)
[workspace.dependencies]
memf-format = { git = "https://github.com/SecurityRonin/memory-forensic", branch = "main" }
memf-core   = { git = "https://github.com/SecurityRonin/memory-forensic", branch = "main" }
memf-symbols = { git = "https://github.com/SecurityRonin/memory-forensic", branch = "main" }
memf-linux  = { git = "https://github.com/SecurityRonin/memory-forensic", branch = "main" }
memf-windows = { git = "https://github.com/SecurityRonin/memory-forensic", branch = "main" }
memf-strings = { git = "https://github.com/SecurityRonin/memory-forensic", branch = "main" }
```

rt-navigator depends on these crates to run walkers and format providers.

### UAC Memory Dump Detection

UAC collections may contain a `memory_dump/` directory with files like `avml.lime`, `*.dmp`, `*.vmem`, `*.raw`. These dumps may also be compressed as `.zip` or `.7z` archives. The existing UAC parsing pipeline (in rt-parser-uac) is extended to:

1. Scan `memory_dump/` for dump files — both raw and compressed (`.zip`, `.7z`)
2. If compressed, decompress to a temp directory before probing
3. Probe for recognized formats using `memf_format::open_dump()`
4. If a valid dump is found, run OS detection via `memf_core::os_detect`
5. Run applicable walkers (processes, network, modules, DLLs/libs)
6. Populate memory forensic fields in `InvestigationData`

**Decompression:** The decompression step lives in the RapidTriage UAC pipeline (not in memf-format), since it's an artifact handling concern. memf-format's `open_dump()` always receives a path to an uncompressed file. Supported archive formats: `.zip` (via `zip` crate) and `.7z` (via `sevenz-rust` crate). If the archive contains multiple files, the pipeline probes each one until a recognized dump format is found.

If no memory dump is present in the collection, the memory fields remain empty and memory-related views are hidden from the sidebar.

### What Stays in memory-forensic

- All library crates: memf-format, memf-core, memf-symbols, memf-linux, memf-windows, memf-strings
- The `memf` CLI binary for standalone non-interactive use (`memf ps`, `memf net`, `memf mod`, `memf lib`, `memf info`, `memf strings`)
- No TUI code

### What Lives in RapidTriage

- Memory forensic TUI panels (WorkbenchView variants)
- Network anomaly detection engine (4 patterns)
- Dashboard layout with process timeline + network volume strip
- Cross-correlation between filesystem and memory artifacts

## Data Layer

### Extended InvestigationData

```rust
pub struct InvestigationData {
    // ... existing fields (timeline, mft_tree, network, processes, etc.) ...

    // Memory forensic fields (populated if UAC contains a memory dump)
    pub memory_info: Option<MemoryDumpInfo>,
    pub memory_processes: Vec<MemProcessEntry>,
    pub memory_connections: Vec<MemConnectionEntry>,
    pub memory_modules: Vec<MemModuleEntry>,
    pub memory_libraries: Vec<MemLibraryEntry>,
    pub memory_threads: Vec<MemThreadEntry>,
    pub network_flags: Option<NetworkFlagSummary>,
}
```

### Unified Memory Types

These wrap OS-specific walker output into a common shape for the TUI:

```rust
pub struct MemProcessEntry {
    pub pid: u64,
    pub ppid: u64,
    pub name: String,
    pub create_time: Option<chrono::NaiveDateTime>,
    pub cr3: u64,
    pub vaddr: u64,
    pub flags: Vec<ProcessFlag>,
}

pub struct MemConnectionEntry {
    pub protocol: Protocol,         // TCP or UDP
    pub local_addr: SocketAddr,
    pub remote_addr: Option<SocketAddr>,
    pub state: ConnectionState,
    pub pid: u64,
    pub flag_labels: Vec<String>,   // C2-PORT, FANOUT, FANIN, OUTLIER, SCATTER
}

pub struct MemModuleEntry {
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub path: Option<String>,
}

pub struct MemLibraryEntry {
    pub pid: u64,
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub path: Option<String>,
}

pub struct MemThreadEntry {
    pub tid: u64,
    pub pid: u64,
    pub state: Option<String>,
    pub start_address: u64,
    pub create_time: Option<chrono::NaiveDateTime>,
}
```

### MemoryDumpInfo

```rust
pub struct MemoryDumpInfo {
    pub os: OsProfile,              // Linux, Windows, MacOs
    pub arch: String,               // AMD64, x86, ARM64
    pub dump_format: String,        // LiME, AVML, CrashDump, VMware, Raw, etc.
    pub dump_path: PathBuf,
    pub physical_memory_size: Option<u64>,
}
```

### NetworkFlagSummary

Pre-computed at load time:

```rust
pub struct NetworkFlagSummary {
    pub total_connections: usize,
    pub flagged_count: usize,
    pub max_fanout_ip: Option<(IpAddr, usize)>,
    pub max_fanin_port: Option<(u16, usize)>,
    pub max_conns_pid: Option<(u64, usize)>,
    pub max_unique_ips_pid: Option<(u64, usize)>,
}
```

## Network Anomaly Detection

### Four Metric Patterns

All four are computed over the memory dump's connection list:

1. **Fan-out per remote IP** -- How many connections go to the same remote IP. High fan-out to a single IP suggests C2 beaconing or data exfiltration.
2. **Fan-in per local port** -- How many inbound connections hit the same local port. High fan-in suggests the machine is serving (legitimate or backdoor).
3. **Connections per PID** -- How many connections a single process owns. A PID with disproportionate connections is suspicious.
4. **Unique remote IPs per PID** -- How many distinct remote IPs a process communicates with. High scatter suggests scanning or botnet behavior.

### Flagging Algorithm

**Statistical outlier + suspicious port floor:**

For each metric, compute the mean and standard deviation across all entities (IPs, ports, PIDs). Flag any entity where `value > mean + 2 * stddev`.

Additionally, always flag connections to known-suspicious ports regardless of volume. The suspicious port list is sourced from SIGMA rules and common C2 frameworks:

```
4444, 4445, 5555, 5556, 8443, 8080, 9090, 1337, 31337, 6666, 6667,
4443, 2222, 3389 (from non-standard source), 1234, 12345, 54321
```

This list will be maintained as a const array, sourced from the existing SIGMA-based port database already in RapidTriage's `investigation/alerts/network.rs` (which was built in Phase 2 of the alert system).

### Flag Labels

Each flagged connection gets one or more labels:
- `C2-PORT` -- remote port matches known-suspicious list
- `FANOUT(n)` -- remote IP has n total connections (statistical outlier)
- `FANIN(n)` -- local port receives n inbound connections (statistical outlier)
- `HIGH-PID(n)` -- owning PID has n total connections (statistical outlier)
- `SCATTER(n)` -- owning PID contacts n unique remote IPs (statistical outlier)

## TUI Layout

### Split Dashboard Layout

The main screen is divided into three regions:

```
+---------------------------+---------------------------+
| PROCESSES (32)            | NETWORK (148)             |
| creation timeline chart   | volume bars per IP        |
| compact process list      | summary + flagged-only    |
+============ blue accent border ======================+
| VIEWS   | DETAIL                                     |
| > Proc  | (full content for selected view)           |
|   Net   | process info, connections, libs, hex dump   |
|   Mod   |                                             |
|   Lib   |                                             |
|   Sum   |                                             |
+---------+---------------------------------------------+
| j/k:scroll Tab:panel 1-5:view 0:overview f:full q:quit|
+---------------------------------------------------------+
```

**Top strip (~40%):** Process panel (left) and Network panel (right) side by side, always visible. Process panel shows a time-axis bar chart of creation times plus a compact process list. Network panel shows horizontal volume bars per remote IP plus the summary line (`148 conns | 5 flagged | fan-out:47 | fan-in:203`). Only flagged connections shown in compact view.

**Bottom area (~60%):** Left sidebar for view navigation (Proc/Net/Mod/Lib/Sum), right side shows full detail for the selected view. Selecting a process in the top strip updates the bottom detail to show that process's info.

**Footer:** Context-sensitive keybinding hints, changes based on focused region.

### View Modes

- **Default:** Split dashboard (top strip + bottom detail) as described above
- **Fullscreen (`f`):** Bottom detail expands to fill the entire screen, top strip hidden
- **Overview (`0`):** 2x2 grid showing all four data types simultaneously (proc, net, mod, summary)

## New WorkbenchView Variants

Added to RapidTriage's existing `WorkbenchView` enum:

```rust
pub enum WorkbenchView {
    // ... existing variants ...
    MemProcesses,    // Full process table with thread drill-down
    MemNetwork,      // Full connection table with anomaly flags
    MemModules,      // Kernel modules + drivers (unified)
    MemLibraries,    // Per-process loaded libraries (DLLs/.so)
}
```

Each variant gets a dedicated `draw_mem_*()` function in `views/` following the existing pattern (no trait abstraction -- matches current codebase style).

### Sidebar Behavior

When a memory dump is present, the sidebar shows memory-specific views alongside (or replacing) the existing views. The exact sidebar composition depends on what data is available:

- **UAC with memory dump:** Full sidebar (existing views + memory views)
- **UAC without memory dump:** Existing sidebar only, memory views hidden
- **Standalone memory dump:** Memory views only (future: `rt-navigator --memdump path.dmp`)

## Keybindings

Vim-inspired, non-modal, with discoverable footer bar:

| Key | Action |
|-----|--------|
| `j/k` | Scroll up/down in focused region |
| `h/l` | Collapse/expand or navigate columns |
| `Tab` | Cycle focus: proc strip -> net strip -> detail |
| `1-5` | Jump to sidebar view by number |
| `0` | Toggle overview (2x2 grid) |
| `f` | Toggle fullscreen on bottom detail |
| `Enter` | Drill into selected item (threads, hex, connections) |
| `Esc` | Back up one drill level |
| `/` | Open search prompt |
| `q` | Quit |
| `?` | Show full keybinding help overlay |

### Cross-Panel Linking

- Selecting a process in the top-left strip highlights it and updates the bottom detail
- Selecting a flagged connection in the top-right strip jumps bottom detail to MemNetwork filtered to that connection's PID
- Clicking a PID in the network view cross-references the process list

### Event Flow

`App::handle_event()` checks global keys first (quit, Tab, number keys), then delegates to the focused region. Each region handler returns:
- `Consumed` -- event handled
- `Ignored` -- pass to next handler
- `Action(AppAction)` -- request cross-panel operation (e.g., "focus PID 892 in detail")

## Process Timeline Chart

The process creation timeline is a vertical bar chart where:
- X-axis: time (from earliest to latest `create_time`)
- Y-axis: number of processes created in each time bucket
- Color coding:
  - Gray (`#565f89`): normal background activity
  - Blue (`#7aa2f7`): boot-time process creation
  - Amber (`#e0af68`): bursts of process creation (statistical outlier in time bucketing)
  - Red (`#f7768e`): flagged processes (late creation, name masquerading, orphaned PPID)

Rendered using ratatui's `BarChart` or custom block characters in a `Canvas` widget.

## Network Volume Chart

Horizontal volume bars showing connection count per entity:
- Each bar represents a remote IP or local port
- Width proportional to connection count
- Color coding matches flag severity:
  - Red: C2-PORT or high fan-out
  - Amber: high fan-in or outlier
  - Gray: normal

Below the bars: one-line summary with aggregate metrics.

## Testing Strategy

### Test Data Corpus

| File | OS | Format | Purpose |
|------|----|--------|---------|
| `uac-vbox-linux-*.tar.gz` (existing) | Linux | UAC with AVML/LiME | End-to-end UAC integration |
| `cyberspace2024_mem.dmp` | Win x64 | Crash dump | Windows crash dump provider |
| `cridex.vmem` | WinXP x86 | VMware .vmem | Network anomaly detection (banking trojan) |
| Total Recall 2024 | Win11 | Crash dump | Modern Windows version coverage |
| 13Cubed CTF | Win10 x64 | Unknown | Windows 10 coverage |

Note: Test dumps may be stored compressed (`.zip`, `.7z`). The `csctf-2024_forensics_memory.zip` contains `mem.dmp` (2 GB uncompressed). Tests that use compressed dumps also exercise the decompression pipeline.

### Test Levels

1. **Unit tests:** Network anomaly detection algorithm (flagging thresholds, edge cases)
2. **Unit tests:** Unified type conversion from OS-specific walker output
3. **Unit tests:** Archive decompression (`.zip`, `.7z`) with valid and invalid contents
4. **Integration tests:** UAC pipeline with memory dump detection, decompression, and extraction
5. **Real-data tests:** Run against test corpus dumps, verify process/connection counts match expected values (marked `#[ignore]` for CI, run manually)

## Decomposition into Sub-Projects

This spec covers the full integration, but implementation should be broken into sub-projects:

### 3E-A: Core Integration + Data Layer
- Add memf workspace dependencies to RapidTriage
- Extend InvestigationData with memory fields
- Implement UAC memory dump detection and walker invocation
- Add unified memory types
- Tests: unit tests for type conversion, integration test with real UAC dump

### 3E-B: Network Anomaly Detection
- Implement 4-metric flagging algorithm
- Integrate with existing alert system
- Suspicious port floor (reuse SIGMA-sourced list)
- Tests: unit tests with synthetic connection data, real-data test with cridex.vmem

### 3E-C: Memory TUI Panels
- Add WorkbenchView variants (MemProcesses, MemNetwork, MemModules, MemLibraries)
- Implement draw functions for each view
- Wire into sidebar and view dispatch
- Tests: rendering tests with mock data

### 3E-D: Dashboard Enhancement
- Implement top-strip layout (proc timeline + net volume side by side)
- Process creation timeline bar chart
- Network volume horizontal bars
- Cross-panel linking (select in strip -> update detail)
- Focus cycling with Tab
- Footer hint bar

### 3E-E: Advanced Features (Future)
- Hex dump / memory viewer
- Process memory map / VAD tree visualization
- Timeline view (unified filesystem + memory events)
- String search within TUI
- Exporting filtered results
- Mouse support
- Standalone mode (`rt-navigator --memdump path.dmp`)

## Out of Scope (For Now)

- Registry hive extraction from memory (future: integrate with winreg-forensic)
- Live memory acquisition
- Differential analysis (comparing two dumps)
- Remote analysis over network
