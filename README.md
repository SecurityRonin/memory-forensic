# memf

A pure-Rust memory forensics framework. Reads physical memory dumps, walks Linux kernel structures, extracts strings, and classifies indicators of compromise.

Zero `unsafe` code. Apache-2.0 licensed. 140+ tests.

## Why memf

**For incident responders** who need to triage memory dumps from Linux servers. You point `memf` at a LiME, AVML, or ELF core dump and get processes, network connections, kernel modules, and classified strings in seconds.

**For forensic developers** who want a library they control. Every component is a separate crate with a clean trait boundary. Swap out the symbol resolver, add a new dump format, or write a custom string classifier without touching the rest of the codebase.

**No C dependencies for core functionality.** The framework compiles on any platform Rust supports. YARA-X integration is the only native dependency, and only when you need rule-based string matching.

### How it compares

| Capability | memf | Volatility3 | MemProcFS |
|---|---|---|---|
| Language | Rust (memory safe) | Python | C/C++ |
| License | Apache-2.0 | Volatility Software License | AGPL-3.0 |
| Dump formats | LiME, AVML, ELF core, Raw | 10+ | 10+ |
| Linux process walking | Yes | Yes | Yes |
| Network connections | Yes | Yes | Yes |
| Kernel modules | Yes | Yes | Yes |
| KASLR detection | Yes | Yes | Yes |
| String classification | YARA-X + regex (12 categories) | yarascan plugin | No |
| Symbol backends | ISF JSON, BTF | ISF JSON | PDB |
| Page table walking | x86_64 (4KB/2MB/1GB) | x86_64, ARM64, x86 | x86_64, ARM64 |
| `unsafe` code | None | N/A (Python) | Extensive |

memf covers Linux analysis today. Windows support, rootkit detection, and file reconstruction are in active development.

## Quick start

### Install from source

```bash
git clone https://github.com/SecurityRonin/memory-forensic.git
cd memory-forensic
cargo build --release
```

The binary lands at `target/release/memf`.

### Inspect a memory dump

```bash
# Show format, size, and physical memory ranges
memf info server.lime

# Output:
# Format:     LiME
# Total size: 8589934592 bytes (8.00 GB)
# Ranges:     3
#
# ┌───┬────────────────┬────────────────┬──────────┐
# │ # │ Start          │ End            │ Size     │
# ├───┼────────────────┼────────────────┼──────────┤
# │ 0 │ 0x000000001000 │ 0x00000009f000 │ 632.00KB │
# │ 1 │ 0x000000100000 │ 0x00007fff0000 │  2.00 GB │
# │ 2 │ 0x000100000000 │ 0x000280000000 │  6.00 GB │
# └───┴────────────────┴────────────────┴──────────┘
```

### Extract and classify strings

```bash
# From a memory dump (ASCII + UTF-16LE, min length 4)
memf strings server.lime --output table

# From a pre-extracted strings file
memf strings --from-file memory-strings.ascii --output json

# With custom YARA rules
memf strings server.lime --rules ./yara-rules/ --output csv
```

String classification identifies 12 indicator categories: URLs, IPv4 addresses, email addresses, Unix paths, Windows paths, registry keys, cryptocurrency addresses, PEM private keys, base64 blobs, and shell commands. YARA rules add unlimited custom patterns on top.

### List processes (requires ISF symbols)

```bash
memf ps server.lime --symbols linux-6.1.0.json --output table
```

### List kernel modules

```bash
memf modules server.lime --symbols linux-6.1.0.json
```

### List network connections

```bash
memf netstat server.lime --symbols linux-6.1.0.json
```

### Output formats

Every subcommand supports `--output table` (default), `--output json` (NDJSON, one object per line), and `--output csv`.

## Architecture

```
memf (CLI binary)
 ├── memf-format    Physical memory providers (LiME, AVML, ELF core, Raw)
 ├── memf-symbols   Symbol resolution (ISF JSON, BTF)
 ├── memf-core      Virtual address translation + object reader
 ├── memf-linux     Linux kernel walkers (processes, modules, network)
 └── memf-strings   String extraction + classification (regex, YARA-X)
```

### Crate responsibilities

**memf-format** reads raw bytes from dump files. Each format implements `PhysicalMemoryProvider`, which provides `read_phys(addr, buf)` and `ranges()`. The `open_dump()` function auto-detects the format using a plugin scoring system powered by the `inventory` crate.

**memf-symbols** resolves kernel struct layouts and symbol addresses. The `SymbolResolver` trait abstracts over ISF JSON (Volatility3 format) and BTF (Linux kernel's built-in type info). You get field offsets, struct sizes, and symbol virtual addresses.

**memf-core** handles x86_64 4-level page table walking and kernel object reading. `VirtualAddressSpace` translates virtual addresses to physical. `ObjectReader` reads typed fields from kernel structs, follows pointers, and walks circular linked lists with cycle detection.

**memf-linux** walks kernel data structures. Process enumeration follows the `task_struct` linked list from `init_task`. Module enumeration walks the `modules` list. Network enumeration scans `tcp_hashinfo.ehash` hash buckets. KASLR offset detection scans for the `"Linux version "` banner in physical memory.

**memf-strings** extracts ASCII and UTF-16LE strings from physical memory in 64KB chunks with overlap handling for cross-boundary strings. The `classify_strings()` pipeline runs all registered classifiers (regex patterns + optional YARA rules) and tags each string with matching categories and confidence scores.

### Plugin system

Format providers and string classifiers register through Rust's `inventory` crate at compile time. Adding a new format:

```rust
use memf_format::{FormatPlugin, PhysicalMemoryProvider};

pub struct MyFormat { /* ... */ }

impl PhysicalMemoryProvider for MyFormat { /* ... */ }

pub struct MyPlugin;
impl FormatPlugin for MyPlugin {
    fn name(&self) -> &str { "MyFormat" }
    fn probe(&self, data: &[u8]) -> u8 { /* return 0-100 confidence */ }
    fn open(&self, data: Vec<u8>) -> memf_format::Result<Box<dyn PhysicalMemoryProvider>> { /* ... */ }
}

inventory::submit!(Box::new(MyPlugin) as Box<dyn FormatPlugin>);
```

### Symbol files

memf reads ISF JSON files compatible with Volatility3's symbol packs. Generate them from a Linux kernel with debug info:

```bash
# Using Volatility3's dwarf2json
dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) > symbols.json

# Point memf at the file
memf ps dump.lime --symbols symbols.json

# Or at a directory of symbol files
memf ps dump.lime --symbols /path/to/symbols/

# Or set the environment variable
export MEMF_SYMBOLS_PATH=/path/to/symbols/
memf ps dump.lime
```

## Supported dump formats

| Format | Source | Detection |
|---|---|---|
| **LiME** | [LiME kernel module](https://github.com/504ensicsLabs/LiME) | Magic bytes `EMiL` (0x4C694D45) |
| **AVML** | [Microsoft AVML](https://github.com/microsoft/avml) | Magic bytes `AVML` + version 2 |
| **ELF core** | QEMU, libvirt, crash dumps | ELF header + PT_LOAD segments |
| **Raw** | dd, /dev/mem, various tools | Fallback (flat memory image) |

Format detection is automatic. `open_dump()` probes each registered plugin and selects the highest-confidence match.

## Building and testing

```bash
# Build
cargo build --release

# Run all tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p memf-format
cargo test -p memf-linux

# Run with real dump data
MEMF_TEST_DATA=/path/to/dumps cargo test --test real_data -- --ignored

# Lint
cargo clippy --workspace -- -D warnings
```

## Project status

**Stable and tested:** Format detection, string extraction, regex + YARA classification, ISF/BTF symbol resolution, x86_64 page table walking, Linux process/module/network enumeration, KASLR detection.

**In development:** Windows dump formats (crashdump, hiberfil.sys, VMware VMSS/VMSN), Windows kernel walking, ARM64 page tables, rootkit detection, file reconstruction from VADs, credential extraction, FUSE virtual filesystem.

## License

Apache-2.0. See [LICENSE](LICENSE) for details.
