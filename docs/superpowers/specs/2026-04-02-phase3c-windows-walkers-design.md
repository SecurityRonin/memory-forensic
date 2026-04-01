# Phase 3C: Windows Process & Module Walkers — Design Spec

> Approved design for creating the `memf-windows` crate with Windows NT kernel
> structure walkers for process, thread, driver, and DLL enumeration.

## Goal

Add a `memf-windows` crate that walks Windows NT kernel data structures in
physical memory dumps, mirroring `memf-linux` for the Windows ecosystem. Uses
the `ObjectReader` from `memf-core` with PDB/ISF symbol resolution from
`memf-symbols` to enumerate processes, threads, loaded drivers, and per-process
DLLs.

## Architecture

```
[Windows crash dump] → memf-format (CR3 + PsActiveProcessHead from metadata)
                           ↓
[PDB symbols]        → memf-symbols (struct layouts for _EPROCESS, _KTHREAD, etc.)
                           ↓
[ObjectReader]       → memf-core (virtual memory reads via page table walking)
                           ↓
[memf-windows]       → process/thread/driver/DLL walkers → output types
```

## Prerequisites

- **Phase 3A**: Windows crash dump provider with `DumpMetadata` (CR3, PsActiveProcessHead)
- **Phase 3B**: PDB resolver and `windows_kernel_preset()` ISF builder

## ObjectReader Extension

The existing `walk_list` in `memf-core` hardcodes Linux `list_head.next`. Windows
uses `_LIST_ENTRY.Flink`. Add a generic method:

```rust
/// Walk a doubly-linked list using configurable struct/field names.
///
/// `head_vaddr` is the address of the list head entry.
/// `list_struct` is the name of the list node struct (e.g., "list_head" or "_LIST_ENTRY").
/// `next_field` is the name of the forward pointer field (e.g., "next" or "Flink").
/// `container_struct` is the struct containing the embedded list node.
/// `list_field` is the field name of the embedded list node in the container.
pub fn walk_list_with(
    &self,
    head_vaddr: u64,
    list_struct: &str,
    next_field: &str,
    container_struct: &str,
    list_field: &str,
) -> Result<Vec<u64>>
```

The existing `walk_list` becomes a thin wrapper calling `walk_list_with` with
`"list_head"` and `"next"`.

## Module: `types`

Output types for Windows forensic walkers:

```rust
pub struct WinProcessInfo {
    pub pid: u64,
    pub ppid: u64,
    pub image_name: String,       // ImageFileName (15 chars max)
    pub create_time: u64,         // FILETIME (100ns since 1601-01-01)
    pub exit_time: u64,           // 0 if still running
    pub cr3: u64,                 // DirectoryTableBase
    pub peb_addr: u64,            // PEB virtual address
    pub vaddr: u64,               // _EPROCESS virtual address
    pub thread_count: u32,        // number of threads enumerated
    pub is_wow64: bool,           // 32-bit process on 64-bit OS
}

pub struct WinThreadInfo {
    pub tid: u64,                 // Cid.UniqueThread
    pub pid: u64,                 // owning process
    pub create_time: u64,         // CreateTime FILETIME
    pub start_address: u64,       // Win32StartAddress
    pub teb_addr: u64,            // Thread Environment Block
    pub state: ThreadState,
    pub vaddr: u64,               // _ETHREAD virtual address
}

pub enum ThreadState {
    Initialized,                  // 0
    Ready,                        // 1
    Running,                      // 2
    Standby,                      // 3
    Terminated,                   // 4
    Waiting,                      // 5
    Transition,                   // 6
    DeferredReady,                // 7
    GateWaitObsolete,             // 8
    WaitingForProcessInSwap,      // 9
    Unknown(u32),
}

pub struct WinDriverInfo {
    pub name: String,             // BaseDllName
    pub full_path: String,        // FullDllName
    pub base_addr: u64,           // DllBase
    pub size: u64,                // SizeOfImage
    pub vaddr: u64,               // _KLDR_DATA_TABLE_ENTRY vaddr
}

pub struct WinDllInfo {
    pub name: String,             // BaseDllName
    pub full_path: String,        // FullDllName
    pub base_addr: u64,           // DllBase
    pub size: u64,                // SizeOfImage
    pub load_order: u32,          // position in InLoadOrderModuleList
}
```

## Module: `process`

### `walk_processes`

Walk the `_EPROCESS` doubly-linked list via `ActiveProcessLinks`:

1. Get `PsActiveProcessHead` from dump metadata or symbol address
2. Walk `_LIST_ENTRY` chain: `head.Flink → ... → head` (circular)
3. For each `_EPROCESS`: container_of by subtracting `ActiveProcessLinks` offset
4. Read: `UniqueProcessId`, `InheritedFromUniqueProcessId`, `ImageFileName`,
   `CreateTime`, `ExitTime`, `Pcb.DirectoryTableBase`, `Peb`
5. Sort by PID, return `Vec<WinProcessInfo>`

### Hidden process detection (cross-reference)

Two list walks for the same data:
- **ActiveProcessLinks** (standard doubly-linked list)
- **SessionProcessLinks** (if available, for cross-reference)

Processes in one list but not the other indicate DKOM (Direct Kernel Object
Manipulation) hiding. This is a detection signal, not a walker responsibility —
expose both lists and let downstream compare.

## Module: `thread`

### `walk_threads`

Walk threads within a given `_EPROCESS`:

1. From `_EPROCESS`, read `Pcb` (which is `_KPROCESS` at offset 0)
2. Walk `_KPROCESS.ThreadListHead` via `_LIST_ENTRY`
3. Each entry is `_KTHREAD.ThreadListEntry` — container_of to get `_KTHREAD`
4. Read: `Cid.UniqueThread`, `CreateTime`, `Win32StartAddress`, `Teb`, `State`
5. Return `Vec<WinThreadInfo>`

## Module: `driver`

### `walk_drivers`

Walk loaded kernel drivers via `PsLoadedModuleList`:

1. Get `PsLoadedModuleList` from dump metadata or symbol address
2. Walk `_LIST_ENTRY` chain through `_KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks`
3. Read: `BaseDllName` (UNICODE_STRING), `FullDllName` (UNICODE_STRING),
   `DllBase`, `SizeOfImage`
4. Return `Vec<WinDriverInfo>`

### UNICODE_STRING reading

Add helper to read Windows `_UNICODE_STRING`:
```rust
fn read_unicode_string(reader: &ObjectReader<P>, vaddr: u64) -> Result<String>
```
Reads `Length` (u16), `Buffer` (pointer), then reads `Length` bytes of UTF-16LE
from `Buffer` and converts to Rust `String`.

## Module: `dll`

### `walk_dlls`

Walk DLLs for a specific process:

1. From `_EPROCESS`, read `Peb` pointer
2. From `_PEB`, read `Ldr` pointer → `_PEB_LDR_DATA`
3. Walk `InLoadOrderModuleList` via `_LIST_ENTRY`
4. Each entry is `_LDR_DATA_TABLE_ENTRY.InLoadOrderLinks`
5. Read: `BaseDllName`, `FullDllName`, `DllBase`, `SizeOfImage`
6. Return `Vec<WinDllInfo>`

Note: DLL walking requires the process's own page table (CR3 from
`DirectoryTableBase`) since PEB and LDR live in user-mode virtual address space.

## ISF Preset Extension

Extend `windows_kernel_preset()` in `memf-symbols/test_builders.rs` with
additional structs needed for walkers:

- `_KLDR_DATA_TABLE_ENTRY` (driver list entries)
- `_PEB_LDR_DATA` (PEB loader data)
- `_LDR_DATA_TABLE_ENTRY` (DLL list entries)
- `_KPROCESS` needs `ThreadListHead` field
- `_ETHREAD` needs `Tcb`, `Cid` fields

## Test Strategy

Same boundary as `memf-linux`: synthetic physical memory via `PageTableBuilder`
with ISF symbols from `windows_kernel_preset()`.

| Component | Strategy |
|-----------|----------|
| `walk_list_with` | Unit test with synthetic memory, same as `walk_list` |
| Output types | `from_raw` + `Display` for enums |
| Process walker | Synthetic `_EPROCESS` chain in memory |
| Thread walker | Synthetic `_KTHREAD` chain within process |
| Driver walker | Synthetic `_KLDR_DATA_TABLE_ENTRY` chain |
| DLL walker | Synthetic PEB → LDR → `_LDR_DATA_TABLE_ENTRY` chain |
| UNICODE_STRING | Synthetic UTF-16LE strings in memory |
| Integration | Cross-crate: crash dump → metadata → walker |

## Error Handling

Reuse `memf-windows::Error` pattern from `memf-linux`:
- `Core(memf_core::Error)` — memory read failures
- `Symbol(memf_symbols::Error)` — missing symbols
- `Walker(String)` — walker-specific errors

## Non-Goals

- Network connections (Windows TCP/IP partitions are complex — Phase 3D)
- Registry hive walking from memory (Phase 3E)
- VAD (Virtual Address Descriptor) tree walking (Phase 3E)
- Handle table walking (Phase 3E)
