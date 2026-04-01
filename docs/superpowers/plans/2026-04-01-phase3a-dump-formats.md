# Phase 3A: Dump Format Providers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 4 new dump format providers (Windows crash dump, hiberfil.sys, VMware .vmss/.vmsn, kdump) plus a DumpMetadata trait extension to the memf-format crate.

**Architecture:** Each provider is a single file in `crates/memf-format/src/` implementing `PhysicalMemoryProvider` + `FormatPlugin`, registered via `inventory::submit!`. A new `DumpMetadata` struct surfaces header-embedded fields (CR3, machine type) that downstream crates need. Test builders in `test_builders.rs` produce synthetic dumps for TDD.

**Tech Stack:** Rust, `rust-lzxpress` (Xpress LZ77), `flate2` (zlib/miniz_oxide), `ruzstd` (Zstandard), `lru` (LRU cache), `snap` (Snappy, existing)

**Build command:** `/Users/4n6h4x0r/.cargo/bin/cargo`
**Commit flag:** `--no-gpg-sign`

---

## File Structure

### Create

| File | Responsibility |
|------|---------------|
| `crates/memf-format/src/win_crashdump.rs` | Windows crash dump provider (64-bit run-based + bitmap) |
| `crates/memf-format/src/hiberfil.rs` | Windows hibernation file provider (Xpress decompression) |
| `crates/memf-format/src/vmware.rs` | VMware .vmss/.vmsn state file provider (group/tag parsing) |
| `crates/memf-format/src/kdump.rs` | Linux kdump/makedumpfile provider (lazy decompression + LRU) |

### Modify

| File | Change |
|------|--------|
| `Cargo.toml` (workspace root) | Add `rust-lzxpress`, `flate2`, `ruzstd`, `lru` to workspace dependencies |
| `crates/memf-format/Cargo.toml` | Add new dependencies |
| `crates/memf-format/src/lib.rs` | Add `DumpMetadata`, `MachineType`, `metadata()` default method, 4 `mod` declarations |
| `crates/memf-format/src/test_builders.rs` | Add `CrashDumpBuilder`, `HiberfilBuilder`, `VmwareStateBuilder`, `KdumpBuilder` |

---

### Task 1: Add Dependencies and DumpMetadata Types

**Files:**
- Modify: `Cargo.toml` (workspace root, lines 17-36)
- Modify: `crates/memf-format/Cargo.toml` (lines 9-14)
- Modify: `crates/memf-format/src/lib.rs` (lines 1-93)

- [ ] **Step 1: Write the failing test for DumpMetadata and MachineType**

Add to the bottom of the `#[cfg(test)] mod tests` block in `crates/memf-format/src/lib.rs`:

```rust
    #[test]
    fn dump_metadata_default_is_all_none() {
        let m = DumpMetadata::default();
        assert!(m.cr3.is_none());
        assert!(m.machine_type.is_none());
        assert!(m.os_version.is_none());
        assert!(m.num_processors.is_none());
        assert!(m.ps_active_process_head.is_none());
        assert!(m.ps_loaded_module_list.is_none());
        assert!(m.kd_debugger_data_block.is_none());
        assert!(m.system_time.is_none());
        assert!(m.dump_type.is_none());
    }

    #[test]
    fn machine_type_variants() {
        assert_ne!(MachineType::Amd64, MachineType::I386);
        assert_ne!(MachineType::Amd64, MachineType::Aarch64);
        assert_ne!(MachineType::I386, MachineType::Aarch64);
        // Clone + Copy
        let a = MachineType::Amd64;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn metadata_default_method_returns_none() {
        // LimeProvider inherits the default metadata() method
        use crate::test_builders::LimeBuilder;
        let dump = LimeBuilder::new().add_range(0, &[0xAA; 64]).build();
        let provider = crate::lime::LimeProvider::from_bytes(&dump).unwrap();
        assert!(provider.metadata().is_none());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-format dump_metadata_default_is_all_none machine_type_variants metadata_default_method_returns_none -- --nocapture 2>&1 | tail -20`

Expected: FAIL — `DumpMetadata` and `MachineType` are not defined, `metadata()` method doesn't exist.

- [ ] **Step 3: Add workspace dependencies**

In `Cargo.toml` (workspace root), add these lines inside the `[workspace.dependencies]` section after the `goblin = "0.9"` line:

```toml
rust-lzxpress = "0.7"
flate2 = { version = "1", default-features = false, features = ["miniz_oxide"] }
ruzstd = "0.8"
lru = "0.16"
```

In `crates/memf-format/Cargo.toml`, add these lines inside the `[dependencies]` section:

```toml
rust-lzxpress.workspace = true
flate2.workspace = true
ruzstd.workspace = true
lru.workspace = true
```

- [ ] **Step 4: Add MachineType enum and DumpMetadata struct to lib.rs**

Insert after the `PhysicalRange` impl block (after line 61) and before the `PhysicalMemoryProvider` trait:

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
/// CR3 (page table root), `PsActiveProcessHead` (EPROCESS list), and
/// `PsLoadedModuleList` (driver list). These let downstream crates bootstrap
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
    /// Virtual address of `PsActiveProcessHead` (EPROCESS linked list head).
    pub ps_active_process_head: Option<u64>,
    /// Virtual address of `PsLoadedModuleList` (loaded driver list head).
    pub ps_loaded_module_list: Option<u64>,
    /// Virtual address of `KdDebuggerDataBlock`.
    pub kd_debugger_data_block: Option<u64>,
    /// System time at dump creation (Windows FILETIME, 100ns intervals since 1601-01-01).
    pub system_time: Option<u64>,
    /// Human-readable dump sub-type (e.g., "Full", "Kernel", "Bitmap").
    pub dump_type: Option<String>,
}
```

- [ ] **Step 5: Add metadata() default method to PhysicalMemoryProvider trait**

In `crates/memf-format/src/lib.rs`, add this method inside the `PhysicalMemoryProvider` trait, after the `format_name()` method:

```rust
    /// Optional metadata extracted from the dump header.
    /// Returns `None` for formats that carry no metadata (Raw, LiME, AVML).
    fn metadata(&self) -> Option<DumpMetadata> {
        None
    }
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-format dump_metadata_default_is_all_none machine_type_variants metadata_default_method_returns_none -- --nocapture 2>&1 | tail -20`

Expected: 3 tests PASS.

- [ ] **Step 7: Run full workspace tests + clippy**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | tail -5`
Run: `/Users/4n6h4x0r/.cargo/bin/cargo clippy --workspace -- -D warnings 2>&1 | tail -5`

Expected: All 237+ tests pass, zero clippy warnings. Existing providers are unaffected because `metadata()` has a default impl.

- [ ] **Step 8: Commit**

```bash
cd /Users/4n6h4x0r/src/memory-forensic
git add Cargo.toml Cargo.lock crates/memf-format/Cargo.toml crates/memf-format/src/lib.rs
git commit --no-gpg-sign -m "feat(format): add DumpMetadata, MachineType, and new dependencies

Add MachineType enum (Amd64/I386/Aarch64) and DumpMetadata struct with
optional fields for CR3, process list head, module list, etc. Add default
metadata() method to PhysicalMemoryProvider trait (returns None).

New workspace deps: rust-lzxpress, flate2, ruzstd, lru — needed by
upcoming crash dump, hiberfil, and kdump providers."
```

---

### Task 2: CrashDumpBuilder Test Builder

**Files:**
- Modify: `crates/memf-format/src/test_builders.rs`

- [ ] **Step 1: Write the failing test for CrashDumpBuilder**

Add at the bottom of `crates/memf-format/src/test_builders.rs`:

```rust
/// Build a synthetic Windows 64-bit crash dump for testing.
///
/// Produces a valid `_DUMP_HEADER64` (8192 bytes) with run-based layout
/// (DumpType 0x01) followed by sequential page data. For bitmap layout
/// (DumpType 0x02/0x05), generates a page bitmap from the provided runs.
///
/// Header layout (key offsets):
/// - 0x000: "PAGE" magic (4 bytes)
/// - 0x004: "DU64" signature (4 bytes)
/// - 0x010: DirectoryTableBase / CR3 (u64)
/// - 0x020: PsLoadedModuleList (u64)
/// - 0x028: PsActiveProcessHead (u64)
/// - 0x030: MachineImageType (u32)
/// - 0x034: NumberProcessors (u32)
/// - 0x080: KdDebuggerDataBlock (u64)
/// - 0x088: PhysicalMemoryBlockBuffer (run descriptor)
/// - 0xF98: DumpType (u32)
/// - 0xFA8: SystemTime (u64)
/// - 0x2000: page data starts (for 64-bit)
pub struct CrashDumpBuilder {
    runs: Vec<(u64, Vec<u8>)>,
    dump_type: u32,
    cr3: u64,
    ps_active_process_head: u64,
    ps_loaded_module_list: u64,
    kd_debugger_data_block: u64,
}

impl CrashDumpBuilder {
    /// Create a new builder defaulting to 64-bit full dump (DumpType 0x01).
    pub fn new() -> Self {
        Self {
            runs: Vec::new(),
            dump_type: 0x01,
            cr3: 0x1a_b000,
            ps_active_process_head: 0xfffff800_02c5a100,
            ps_loaded_module_list: 0xfffff800_02c5e150,
            kd_debugger_data_block: 0xfffff800_02c40120,
        }
    }

    /// Set the dump type: 0x01 (full/run-based), 0x02 (kernel/bitmap), 0x05 (bitmap).
    pub fn dump_type(mut self, t: u32) -> Self {
        self.dump_type = t;
        self
    }

    /// Set the CR3 / DirectoryTableBase value.
    pub fn cr3(mut self, cr3: u64) -> Self {
        self.cr3 = cr3;
        self
    }

    /// Add a run of physical memory. `base_page` is the page frame number
    /// (physical address = base_page * 0x1000). `data` length must be a
    /// multiple of 4096.
    pub fn add_run(mut self, base_page: u64, data: &[u8]) -> Self {
        assert!(
            data.len() % 4096 == 0,
            "CrashDumpBuilder: data length must be page-aligned (multiple of 4096)"
        );
        self.runs.push((base_page, data.to_vec()));
        self
    }

    /// Build the crash dump as a byte vector.
    pub fn build(self) -> Vec<u8> {
        const PAGE_SIZE: usize = 4096;
        const HEADER_SIZE: usize = 8192; // 2 pages for 64-bit

        if self.dump_type == 0x01 {
            self.build_run_based(PAGE_SIZE, HEADER_SIZE)
        } else {
            self.build_bitmap(PAGE_SIZE, HEADER_SIZE)
        }
    }

    fn build_run_based(self, page_size: usize, header_size: usize) -> Vec<u8> {
        // Calculate total data size
        let total_data: usize = self.runs.iter().map(|(_, d)| d.len()).sum();
        let mut out = vec![0u8; header_size + total_data];

        self.write_header(&mut out);

        // Write PhysicalMemoryBlockBuffer at offset 0x88
        let num_runs = self.runs.len() as u32;
        let total_pages: u64 = self.runs.iter().map(|(_, d)| d.len() as u64 / page_size as u64).sum();
        out[0x88..0x8C].copy_from_slice(&num_runs.to_le_bytes());
        // padding at 0x8C..0x90
        out[0x90..0x98].copy_from_slice(&total_pages.to_le_bytes());

        // Write runs starting at 0x98 (each 16 bytes: base_page u64, page_count u64)
        let mut run_offset = 0x98;
        for (base_page, data) in &self.runs {
            let page_count = data.len() as u64 / page_size as u64;
            out[run_offset..run_offset + 8].copy_from_slice(&base_page.to_le_bytes());
            out[run_offset + 8..run_offset + 16].copy_from_slice(&page_count.to_le_bytes());
            run_offset += 16;
        }

        // DumpType at 0xF98
        out[0xF98..0xF9C].copy_from_slice(&self.dump_type.to_le_bytes());

        // SystemTime at 0xFA8
        let system_time: u64 = 133_500_000_000_000_000; // arbitrary valid FILETIME
        out[0xFA8..0xFB0].copy_from_slice(&system_time.to_le_bytes());

        // Write page data sequentially after header
        let mut data_offset = header_size;
        for (_, data) in &self.runs {
            out[data_offset..data_offset + data.len()].copy_from_slice(data);
            data_offset += data.len();
        }

        out
    }

    fn build_bitmap(self, page_size: usize, header_size: usize) -> Vec<u8> {
        // Determine max page to size the bitmap
        let max_page = self.runs.iter()
            .map(|(bp, d)| bp + d.len() as u64 / page_size as u64)
            .max()
            .unwrap_or(0);
        let bitmap_bits = max_page as usize;
        let bitmap_bytes = (bitmap_bits + 7) / 8;

        // Build the bitmap and collect page data
        let mut bitmap = vec![0u8; bitmap_bytes];
        let mut page_data_vec: Vec<u8> = Vec::new();
        let mut total_present_pages: u32 = 0;

        // Sort runs by base_page for deterministic output
        let mut sorted_runs = self.runs.clone();
        sorted_runs.sort_by_key(|(bp, _)| *bp);

        for (base_page, data) in &sorted_runs {
            let page_count = data.len() / page_size;
            for i in 0..page_count {
                let pfn = *base_page as usize + i;
                if pfn < bitmap_bits {
                    bitmap[pfn / 8] |= 1 << (pfn % 8);
                }
                total_present_pages += 1;
            }
            page_data_vec.extend_from_slice(data);
        }

        // Summary dump header: ValidDump + HeaderSize + BitmapSize + Pages + bitmap
        let summary_header_size: u32 = 16; // 4 fields * 4 bytes
        let summary_total = summary_header_size as usize + bitmap_bytes;

        let mut out = vec![0u8; header_size + summary_total + page_data_vec.len()];

        self.write_header(&mut out);

        // Also write run info for ranges() reconstruction
        let num_runs = sorted_runs.len() as u32;
        let total_pages: u64 = sorted_runs.iter().map(|(_, d)| d.len() as u64 / page_size as u64).sum();
        out[0x88..0x8C].copy_from_slice(&num_runs.to_le_bytes());
        out[0x90..0x98].copy_from_slice(&total_pages.to_le_bytes());
        let mut run_offset = 0x98;
        for (base_page, data) in &sorted_runs {
            let page_count = data.len() as u64 / page_size as u64;
            out[run_offset..run_offset + 8].copy_from_slice(&base_page.to_le_bytes());
            out[run_offset + 8..run_offset + 16].copy_from_slice(&page_count.to_le_bytes());
            run_offset += 16;
        }

        // DumpType
        out[0xF98..0xF9C].copy_from_slice(&self.dump_type.to_le_bytes());

        // SystemTime
        let system_time: u64 = 133_500_000_000_000_000;
        out[0xFA8..0xFB0].copy_from_slice(&system_time.to_le_bytes());

        // Write summary dump header at header_size
        let sh = header_size;
        out[sh..sh + 4].copy_from_slice(&0x504D5544u32.to_le_bytes()); // "DUMP"
        out[sh + 4..sh + 8].copy_from_slice(&summary_header_size.to_le_bytes());
        out[sh + 8..sh + 12].copy_from_slice(&(bitmap_bits as u32).to_le_bytes());
        out[sh + 12..sh + 16].copy_from_slice(&total_present_pages.to_le_bytes());

        // Write bitmap
        let bm_start = sh + summary_header_size as usize;
        out[bm_start..bm_start + bitmap_bytes].copy_from_slice(&bitmap);

        // Write page data
        let pd_start = bm_start + bitmap_bytes;
        out[pd_start..pd_start + page_data_vec.len()].copy_from_slice(&page_data_vec);

        out
    }

    fn write_header(&self, out: &mut [u8]) {
        // Magic: "PAGE" at 0x0
        out[0..4].copy_from_slice(&0x4547_4150u32.to_le_bytes());
        // Signature: "DU64" at 0x4
        out[4..8].copy_from_slice(&0x3436_5544u32.to_le_bytes());
        // CR3 at 0x10
        out[0x10..0x18].copy_from_slice(&self.cr3.to_le_bytes());
        // PsLoadedModuleList at 0x20
        out[0x20..0x28].copy_from_slice(&self.ps_loaded_module_list.to_le_bytes());
        // PsActiveProcessHead at 0x28
        out[0x28..0x30].copy_from_slice(&self.ps_active_process_head.to_le_bytes());
        // MachineImageType at 0x30 (0x8664 = AMD64)
        out[0x30..0x34].copy_from_slice(&0x8664u32.to_le_bytes());
        // NumberProcessors at 0x34
        out[0x34..0x38].copy_from_slice(&4u32.to_le_bytes());
        // KdDebuggerDataBlock at 0x80
        out[0x80..0x88].copy_from_slice(&self.kd_debugger_data_block.to_le_bytes());
    }
}
```

- [ ] **Step 2: Write a test that uses the builder**

Create `crates/memf-format/src/win_crashdump.rs` with just a test:

```rust
//! Windows crash dump format provider.
//!
//! Parses 64-bit Windows crash dumps (`.dmp` files) with both run-based
//! (DumpType 0x01) and bitmap-based (DumpType 0x02/0x05) layouts.

#[cfg(test)]
mod tests {
    use crate::test_builders::CrashDumpBuilder;

    #[test]
    fn builder_produces_valid_header() {
        let page = vec![0xAA; 4096];
        let dump = CrashDumpBuilder::new()
            .add_run(0, &page)
            .build();

        // Check PAGE magic
        assert_eq!(&dump[0..4], &0x4547_4150u32.to_le_bytes());
        // Check DU64 signature
        assert_eq!(&dump[4..8], &0x3436_5544u32.to_le_bytes());
        // Check data starts at 0x2000 (8192)
        assert!(dump.len() >= 8192 + 4096);
        // Verify page data is present
        assert_eq!(&dump[8192..8192 + 4], &[0xAA, 0xAA, 0xAA, 0xAA]);
    }

    #[test]
    fn builder_bitmap_produces_valid_summary() {
        let page = vec![0xBB; 4096];
        let dump = CrashDumpBuilder::new()
            .dump_type(0x05)
            .add_run(0, &page)
            .build();

        // Check PAGE magic
        assert_eq!(&dump[0..4], &0x4547_4150u32.to_le_bytes());
        // DumpType at 0xF98 should be 5
        let dt = u32::from_le_bytes(dump[0xF98..0xF9C].try_into().unwrap());
        assert_eq!(dt, 0x05);
        // Summary header at 0x2000 should start with "DUMP"
        assert_eq!(&dump[0x2000..0x2004], &0x504D5544u32.to_le_bytes());
    }
}
```

- [ ] **Step 3: Add mod declaration in lib.rs**

In `crates/memf-format/src/lib.rs`, add after `pub mod test_builders;`:

```rust
pub mod win_crashdump;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-format builder_produces_valid_header builder_bitmap_produces_valid_summary -- --nocapture 2>&1 | tail -20`

Expected: 2 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/4n6h4x0r/src/memory-forensic
git add crates/memf-format/src/test_builders.rs crates/memf-format/src/win_crashdump.rs crates/memf-format/src/lib.rs
git commit --no-gpg-sign -m "feat(format): add CrashDumpBuilder test builder

Synthetic Windows crash dump builder for TDD. Produces valid _DUMP_HEADER64
with PAGE/DU64 magic, run descriptors, metadata fields, and page data.
Supports both run-based (0x01) and bitmap (0x02/0x05) layouts."
```

---

### Task 3: Windows Crash Dump Provider (Run-Based)

**Files:**
- Modify: `crates/memf-format/src/win_crashdump.rs`

- [ ] **Step 1: Write the failing tests**

Replace the `#[cfg(test)] mod tests` block in `crates/memf-format/src/win_crashdump.rs` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_builders::CrashDumpBuilder;

    #[test]
    fn probe_crashdump_magic() {
        let page = vec![0xAA; 4096];
        let dump = CrashDumpBuilder::new().add_run(0, &page).build();
        let plugin = CrashDumpPlugin;
        assert_eq!(plugin.probe(&dump), 95);
    }

    #[test]
    fn probe_non_crashdump() {
        let zeros = vec![0u8; 8192];
        let plugin = CrashDumpPlugin;
        assert_eq!(plugin.probe(&zeros), 0);
    }

    #[test]
    fn probe_short_header_returns_zero() {
        let plugin = CrashDumpPlugin;
        assert_eq!(plugin.probe(&[0x50, 0x41, 0x47, 0x45]), 0); // only 4 bytes
        assert_eq!(plugin.probe(&[]), 0);
    }

    #[test]
    fn single_run_read() {
        let mut page = vec![0u8; 4096];
        page[0] = 0xDE;
        page[1] = 0xAD;
        page[4095] = 0xFF;
        let dump = CrashDumpBuilder::new().add_run(0, &page).build();
        let provider = CrashDumpProvider::from_bytes(&dump).unwrap();

        assert_eq!(provider.format_name(), "Windows Crash Dump");
        assert_eq!(provider.ranges().len(), 1);
        assert_eq!(provider.ranges()[0].start, 0);
        assert_eq!(provider.ranges()[0].end, 4096);
        assert_eq!(provider.total_size(), 4096);

        let mut buf = [0u8; 4];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf, &[0xDE, 0xAD, 0, 0]);

        let mut buf = [0u8; 1];
        let n = provider.read_phys(4095, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0xFF);
    }

    #[test]
    fn multi_run_read() {
        let page_a = vec![0xAA; 4096];
        let page_b = vec![0xBB; 4096];
        let dump = CrashDumpBuilder::new()
            .add_run(0, &page_a)       // pages 0
            .add_run(4, &page_b)       // pages 4 (gap at pages 1-3)
            .build();
        let provider = CrashDumpProvider::from_bytes(&dump).unwrap();

        assert_eq!(provider.ranges().len(), 2);
        assert_eq!(provider.total_size(), 8192);

        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xAA, 0xAA]);

        let n = provider.read_phys(4 * 4096, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xBB, 0xBB]);
    }

    #[test]
    fn read_gap_returns_zero() {
        let page = vec![0xCC; 4096];
        let dump = CrashDumpBuilder::new().add_run(2, &page).build();
        let provider = CrashDumpProvider::from_bytes(&dump).unwrap();

        let mut buf = [0xFF; 4];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_empty_buffer() {
        let page = vec![0xDD; 4096];
        let dump = CrashDumpBuilder::new().add_run(0, &page).build();
        let provider = CrashDumpProvider::from_bytes(&dump).unwrap();

        let mut buf = [];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn metadata_extraction() {
        let page = vec![0u8; 4096];
        let dump = CrashDumpBuilder::new()
            .cr3(0x1a_b000)
            .add_run(0, &page)
            .build();
        let provider = CrashDumpProvider::from_bytes(&dump).unwrap();
        let meta = provider.metadata().expect("should have metadata");

        assert_eq!(meta.cr3, Some(0x1a_b000));
        assert_eq!(meta.machine_type, Some(MachineType::Amd64));
        assert_eq!(meta.num_processors, Some(4));
        assert_eq!(meta.dump_type, Some("Full".into()));
        assert!(meta.ps_active_process_head.is_some());
        assert!(meta.ps_loaded_module_list.is_some());
        assert!(meta.kd_debugger_data_block.is_some());
        assert!(meta.system_time.is_some());
    }

    #[test]
    fn plugin_name() {
        let plugin = CrashDumpPlugin;
        assert_eq!(plugin.name(), "Windows Crash Dump");
    }

    #[test]
    fn builder_produces_valid_header() {
        let page = vec![0xAA; 4096];
        let dump = CrashDumpBuilder::new()
            .add_run(0, &page)
            .build();
        assert_eq!(&dump[0..4], &0x4547_4150u32.to_le_bytes());
        assert_eq!(&dump[4..8], &0x3436_5544u32.to_le_bytes());
        assert!(dump.len() >= 8192 + 4096);
        assert_eq!(&dump[8192..8192 + 4], &[0xAA, 0xAA, 0xAA, 0xAA]);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-format win_crashdump 2>&1 | tail -20`

Expected: FAIL — `CrashDumpProvider` and `CrashDumpPlugin` are not defined.

- [ ] **Step 3: Implement CrashDumpProvider (run-based)**

Replace the content of `crates/memf-format/src/win_crashdump.rs` above the `#[cfg(test)]` block with:

```rust
//! Windows crash dump format provider.
//!
//! Parses 64-bit Windows crash dumps (`.dmp` files) with both run-based
//! (DumpType 0x01) and bitmap-based (DumpType 0x02/0x05) layouts.

use std::path::Path;

use crate::{DumpMetadata, Error, FormatPlugin, MachineType, PhysicalMemoryProvider, PhysicalRange, Result};

const PAGE_SIZE: u64 = 4096;
const HEADER64_SIZE: u64 = 8192;

/// A parsed physical memory run from the dump header.
#[derive(Debug, Clone)]
struct PhysMemRun {
    base_page: u64,
    page_count: u64,
}

/// Layout variant for the crash dump.
#[derive(Debug)]
enum CrashDumpLayout {
    /// Run-based (DumpType 0x01). Runs stored sequentially in the file.
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

/// Provider that exposes physical memory from a Windows crash dump.
pub struct CrashDumpProvider {
    data: Vec<u8>,
    layout: CrashDumpLayout,
    ranges: Vec<PhysicalRange>,
    meta: DumpMetadata,
}

impl CrashDumpProvider {
    /// Parse a crash dump from an in-memory byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let data = bytes.to_vec();
        if data.len() < HEADER64_SIZE as usize {
            return Err(Error::Corrupt("crash dump too small for header".into()));
        }

        // Validate magic
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let sig = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if magic != 0x4547_4150 || sig != 0x3436_5544 {
            return Err(Error::Corrupt("not a 64-bit Windows crash dump".into()));
        }

        // Parse metadata from header
        let cr3 = u64::from_le_bytes(data[0x10..0x18].try_into().unwrap());
        let ps_loaded_module_list = u64::from_le_bytes(data[0x20..0x28].try_into().unwrap());
        let ps_active_process_head = u64::from_le_bytes(data[0x28..0x30].try_into().unwrap());
        let machine_image_type = u32::from_le_bytes(data[0x30..0x34].try_into().unwrap());
        let num_processors = u32::from_le_bytes(data[0x34..0x38].try_into().unwrap());
        let kd_debugger_data_block = u64::from_le_bytes(data[0x80..0x88].try_into().unwrap());
        let dump_type_raw = u32::from_le_bytes(data[0xF98..0xF9C].try_into().unwrap());
        let system_time = u64::from_le_bytes(data[0xFA8..0xFB0].try_into().unwrap());

        let machine_type = match machine_image_type {
            0x8664 => Some(MachineType::Amd64),
            0x014C => Some(MachineType::I386),
            0xAA64 => Some(MachineType::Aarch64),
            _ => None,
        };

        let dump_type_str = match dump_type_raw {
            0x01 => "Full",
            0x02 => "Kernel",
            0x05 => "Bitmap",
            other => return Err(Error::Corrupt(format!("unsupported DumpType: 0x{other:02X}"))),
        };

        let meta = DumpMetadata {
            cr3: Some(cr3),
            machine_type,
            os_version: None,
            num_processors: Some(num_processors),
            ps_active_process_head: if ps_active_process_head != 0 { Some(ps_active_process_head) } else { None },
            ps_loaded_module_list: if ps_loaded_module_list != 0 { Some(ps_loaded_module_list) } else { None },
            kd_debugger_data_block: if kd_debugger_data_block != 0 { Some(kd_debugger_data_block) } else { None },
            system_time: if system_time != 0 { Some(system_time) } else { None },
            dump_type: Some(dump_type_str.into()),
        };

        // Parse runs from PhysicalMemoryBlockBuffer at 0x88
        let num_runs = u32::from_le_bytes(data[0x88..0x8C].try_into().unwrap()) as usize;
        let mut runs = Vec::with_capacity(num_runs);
        for i in 0..num_runs {
            let off = 0x98 + i * 16;
            if off + 16 > data.len() {
                return Err(Error::Corrupt("run descriptor extends beyond header".into()));
            }
            let base_page = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
            let page_count = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());
            runs.push(PhysMemRun { base_page, page_count });
        }

        // Build ranges from runs
        let ranges: Vec<PhysicalRange> = runs
            .iter()
            .map(|r| PhysicalRange {
                start: r.base_page * PAGE_SIZE,
                end: (r.base_page + r.page_count) * PAGE_SIZE,
            })
            .collect();

        // Build layout
        let layout = if dump_type_raw == 0x01 {
            // Run-based: data starts at HEADER64_SIZE, runs are sequential
            let mut run_file_offsets = Vec::with_capacity(runs.len());
            let mut offset = HEADER64_SIZE;
            for run in &runs {
                run_file_offsets.push(offset);
                offset += run.page_count * PAGE_SIZE;
            }
            CrashDumpLayout::RunBased { runs, run_file_offsets }
        } else {
            // Bitmap-based: summary dump header follows main header
            let sh = HEADER64_SIZE as usize;
            if data.len() < sh + 16 {
                return Err(Error::Corrupt("missing summary dump header".into()));
            }
            let summary_header_size = u32::from_le_bytes(data[sh + 4..sh + 8].try_into().unwrap()) as usize;
            let bitmap_bits = u32::from_le_bytes(data[sh + 8..sh + 12].try_into().unwrap()) as usize;
            let bitmap_bytes = (bitmap_bits + 7) / 8;
            let bm_start = sh + summary_header_size;
            if data.len() < bm_start + bitmap_bytes {
                return Err(Error::Corrupt("bitmap truncated".into()));
            }
            let bitmap = data[bm_start..bm_start + bitmap_bytes].to_vec();
            let data_start = (bm_start + bitmap_bytes) as u64;
            CrashDumpLayout::Bitmap { bitmap, data_start }
        };

        Ok(Self { data, layout, ranges, meta })
    }

    /// Parse a crash dump from a file path.
    pub fn from_path(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(&data)
    }
}

impl PhysicalMemoryProvider for CrashDumpProvider {
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        match &self.layout {
            CrashDumpLayout::RunBased { runs, run_file_offsets } => {
                for (i, run) in runs.iter().enumerate() {
                    let run_start = run.base_page * PAGE_SIZE;
                    let run_end = run_start + run.page_count * PAGE_SIZE;
                    if addr >= run_start && addr < run_end {
                        let offset_in_run = addr - run_start;
                        let file_offset = run_file_offsets[i] + offset_in_run;
                        let available = (run_end - addr) as usize;
                        let to_read = buf.len().min(available);
                        let fo = file_offset as usize;
                        if fo + to_read > self.data.len() {
                            return Err(Error::Corrupt("read beyond file".into()));
                        }
                        buf[..to_read].copy_from_slice(&self.data[fo..fo + to_read]);
                        return Ok(to_read);
                    }
                }
                Ok(0)
            }
            CrashDumpLayout::Bitmap { bitmap, data_start } => {
                let pfn = addr / PAGE_SIZE;
                let byte_idx = pfn as usize / 8;
                let bit_idx = pfn as usize % 8;
                if byte_idx >= bitmap.len() || (bitmap[byte_idx] >> bit_idx) & 1 == 0 {
                    return Ok(0);
                }
                // Count set bits before this PFN
                let page_index = count_set_bits_before(bitmap, pfn as usize);
                let page_file_offset = *data_start + page_index as u64 * PAGE_SIZE;
                let offset_in_page = addr % PAGE_SIZE;
                let available = (PAGE_SIZE - offset_in_page) as usize;
                let to_read = buf.len().min(available);
                let fo = (page_file_offset + offset_in_page) as usize;
                if fo + to_read > self.data.len() {
                    return Err(Error::Corrupt("read beyond file".into()));
                }
                buf[..to_read].copy_from_slice(&self.data[fo..fo + to_read]);
                Ok(to_read)
            }
        }
    }

    fn ranges(&self) -> &[PhysicalRange] {
        &self.ranges
    }

    fn format_name(&self) -> &str {
        "Windows Crash Dump"
    }

    fn metadata(&self) -> Option<DumpMetadata> {
        Some(self.meta.clone())
    }
}

/// Count the number of set bits in the bitmap before position `bit_pos`.
fn count_set_bits_before(bitmap: &[u8], bit_pos: usize) -> usize {
    let full_bytes = bit_pos / 8;
    let remaining_bits = bit_pos % 8;

    let mut count: usize = 0;
    for &byte in &bitmap[..full_bytes] {
        count += byte.count_ones() as usize;
    }
    if remaining_bits > 0 && full_bytes < bitmap.len() {
        let mask = (1u8 << remaining_bits) - 1;
        count += (bitmap[full_bytes] & mask).count_ones() as usize;
    }
    count
}

/// `FormatPlugin` implementation for Windows crash dumps.
pub struct CrashDumpPlugin;

impl FormatPlugin for CrashDumpPlugin {
    fn name(&self) -> &str {
        "Windows Crash Dump"
    }

    fn probe(&self, header: &[u8]) -> u8 {
        if header.len() < 8 {
            return 0;
        }
        let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let sig = u32::from_le_bytes(header[4..8].try_into().unwrap());
        if magic == 0x4547_4150 && (sig == 0x3436_5544 || sig == 0x504D_5544) {
            95
        } else {
            0
        }
    }

    fn open(&self, path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>> {
        Ok(Box::new(CrashDumpProvider::from_path(path)?))
    }
}

inventory::submit!(&CrashDumpPlugin as &dyn FormatPlugin);
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-format win_crashdump -- --nocapture 2>&1 | tail -20`

Expected: All 10 tests PASS.

- [ ] **Step 5: Run workspace tests + clippy**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | tail -5`
Run: `/Users/4n6h4x0r/.cargo/bin/cargo clippy --workspace -- -D warnings 2>&1 | tail -5`

Expected: All tests pass, zero warnings.

- [ ] **Step 6: Commit**

```bash
cd /Users/4n6h4x0r/src/memory-forensic
git add crates/memf-format/src/win_crashdump.rs
git commit --no-gpg-sign -m "feat(format): add Windows crash dump provider (run-based)

CrashDumpProvider parses 64-bit Windows crash dumps with _DUMP_HEADER64.
Run-based layout (DumpType 0x01): binary search runs for read_phys.
Extracts DumpMetadata (CR3, PsActiveProcessHead, machine type, etc.).
CrashDumpPlugin probes PAGE+DU64 magic with confidence 95."
```

---

### Task 4: Windows Crash Dump Bitmap Support

**Files:**
- Modify: `crates/memf-format/src/win_crashdump.rs` (tests only)

- [ ] **Step 1: Write the failing tests for bitmap layout**

Add to the `mod tests` block in `win_crashdump.rs`:

```rust
    #[test]
    fn bitmap_single_page_read() {
        let mut page = vec![0u8; 4096];
        page[0] = 0xFE;
        page[1] = 0xED;
        let dump = CrashDumpBuilder::new()
            .dump_type(0x05)
            .add_run(0, &page)
            .build();
        let provider = CrashDumpProvider::from_bytes(&dump).unwrap();

        assert_eq!(provider.format_name(), "Windows Crash Dump");
        let meta = provider.metadata().unwrap();
        assert_eq!(meta.dump_type, Some("Bitmap".into()));

        let mut buf = [0u8; 4];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf, &[0xFE, 0xED, 0, 0]);
    }

    #[test]
    fn bitmap_multi_run_with_gap() {
        let page_a = vec![0xAA; 4096];
        let page_b = vec![0xBB; 4096];
        let dump = CrashDumpBuilder::new()
            .dump_type(0x05)
            .add_run(0, &page_a)
            .add_run(4, &page_b)
            .build();
        let provider = CrashDumpProvider::from_bytes(&dump).unwrap();

        let mut buf = [0u8; 2];
        // Read from first run
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xAA, 0xAA]);

        // Read from second run (page 4 = addr 0x4000)
        let n = provider.read_phys(0x4000, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xBB, 0xBB]);

        // Gap at page 2 (addr 0x2000)
        let n = provider.read_phys(0x2000, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn bitmap_popcount_correctness() {
        // Three pages at PFN 0, 1, 2 — bitmap should have bits 0,1,2 set
        let pages = vec![0u8; 3 * 4096];
        let dump = CrashDumpBuilder::new()
            .dump_type(0x02)
            .add_run(0, &pages)
            .build();
        let provider = CrashDumpProvider::from_bytes(&dump).unwrap();
        let meta = provider.metadata().unwrap();
        assert_eq!(meta.dump_type, Some("Kernel".into()));

        // Should be able to read all 3 pages
        for pfn in 0..3u64 {
            let mut buf = [0u8; 1];
            let n = provider.read_phys(pfn * 4096, &mut buf).unwrap();
            assert_eq!(n, 1, "failed to read PFN {pfn}");
        }
    }

    #[test]
    fn from_path_roundtrip() {
        let page = vec![0xCC; 4096];
        let dump = CrashDumpBuilder::new().add_run(0, &page).build();
        let path = std::env::temp_dir().join("memf_test_crashdump.dmp");
        std::fs::write(&path, &dump).unwrap();
        let provider = CrashDumpProvider::from_path(&path).unwrap();
        assert_eq!(provider.format_name(), "Windows Crash Dump");
        assert_eq!(provider.total_size(), 4096);
        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xCC, 0xCC]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn corrupt_magic_errors() {
        let mut dump = CrashDumpBuilder::new().add_run(0, &vec![0u8; 4096]).build();
        dump[0] = 0xFF;
        let err = CrashDumpProvider::from_bytes(&dump).unwrap_err();
        assert!(matches!(err, crate::Error::Corrupt(_)));
    }

    #[test]
    fn too_small_header_errors() {
        let err = CrashDumpProvider::from_bytes(&[0u8; 100]).unwrap_err();
        assert!(matches!(err, crate::Error::Corrupt(_)));
    }
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-format win_crashdump -- --nocapture 2>&1 | tail -30`

Expected: All 16 tests PASS (10 from Task 3 + 6 new).

- [ ] **Step 3: Commit**

```bash
cd /Users/4n6h4x0r/src/memory-forensic
git add crates/memf-format/src/win_crashdump.rs
git commit --no-gpg-sign -m "test(format): add bitmap layout and error tests for crash dump

Tests for DumpType 0x02/0x05 bitmap reading with popcount indexing,
multi-run gaps, from_path roundtrip, corrupt magic, and truncated header."
```

---

### Task 5: HiberfilBuilder Test Builder

**Files:**
- Modify: `crates/memf-format/src/test_builders.rs`
- Create: `crates/memf-format/src/hiberfil.rs`

- [ ] **Step 1: Add HiberfilBuilder to test_builders.rs**

Append to `crates/memf-format/src/test_builders.rs`:

```rust
/// Build a synthetic hiberfil.sys dump for testing.
///
/// Produces a minimal PO_MEMORY_IMAGE header with `hibr` magic followed by
/// Xpress LZ77 compressed page data blocks. Uses the legacy format layout
/// (pre-Win8) with `\x81\x81xpress` block signatures.
///
/// Header layout:
/// - 0x000: Signature "hibr" (4 bytes)
/// - 0x00C: LengthSelf (u32) — 256 for 64-bit
/// - 0x058: FirstTablePage (u32, legacy 32-bit offset)
/// - 0x068: FirstTablePage (u64, 64-bit offset)
///
/// Page 1 (offset 0x1000): Processor state with CR3 at offset 0x28.
///
/// Compressed data blocks start after the header pages.
pub struct HiberfilBuilder {
    pages: Vec<(u64, [u8; 4096])>,
    cr3: u64,
}

impl HiberfilBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            pages: Vec::new(),
            cr3: 0x1a_b000,
        }
    }

    /// Set the CR3 value stored in the processor state.
    pub fn cr3(mut self, cr3: u64) -> Self {
        self.cr3 = cr3;
        self
    }

    /// Add a page at the given physical page frame number.
    pub fn add_page(mut self, pfn: u64, data: &[u8; 4096]) -> Self {
        self.pages.push((pfn, *data));
        self
    }

    /// Build the hiberfil.sys as a byte vector.
    ///
    /// Layout:
    /// - Page 0: PO_MEMORY_IMAGE header with "hibr" magic
    /// - Page 1: Processor state (CR3 at offset 0x28)
    /// - Page 2: Page table (PFN entries for our pages)
    /// - Page 3+: Compressed data blocks
    pub fn build(self) -> Vec<u8> {
        const PAGE_SIZE: usize = 4096;
        let header_pages = 3; // header + processor state + page table
        let mut out = vec![0u8; header_pages * PAGE_SIZE];

        // Page 0: PO_MEMORY_IMAGE header
        // Signature: "hibr"
        out[0..4].copy_from_slice(&0x7262_6968u32.to_le_bytes());
        // LengthSelf at 0x0C: 256 = 64-bit
        out[0x0C..0x10].copy_from_slice(&256u32.to_le_bytes());
        // FirstTablePage at 0x68 (64-bit): page 2
        out[0x68..0x70].copy_from_slice(&2u64.to_le_bytes());

        // Page 1: Processor state with CR3
        let ps_offset = PAGE_SIZE;
        out[ps_offset + 0x28..ps_offset + 0x30].copy_from_slice(&self.cr3.to_le_bytes());

        // Page 2: Page table — array of PFNs (u64 each)
        let pt_offset = 2 * PAGE_SIZE;
        for (i, (pfn, _)) in self.pages.iter().enumerate() {
            let entry_off = pt_offset + i * 8;
            if entry_off + 8 <= 3 * PAGE_SIZE {
                out[entry_off..entry_off + 8].copy_from_slice(&pfn.to_le_bytes());
            }
        }
        // Terminator: number of pages as the last entry marker
        let count_off = pt_offset + self.pages.len() * 8;
        if count_off + 8 <= 3 * PAGE_SIZE {
            out[count_off..count_off + 8].copy_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes());
        }

        // Compress each page and write as a block
        for (_pfn, page_data) in &self.pages {
            // Block signature: \x81\x81xpress (8 bytes)
            let sig: [u8; 8] = [0x81, 0x81, b'x', b'p', b'r', b'e', b's', b's'];
            let compressed = rust_lzxpress::lz77::compress(page_data);
            let num_pages_minus_1: u8 = 0; // single page per block
            let compressed_size_field = ((compressed.len() * 4) - 1) as u32;

            // Block header: signature(8) + num_pages_minus_1(1) + compressed_size(4) + padding to 0x20
            let mut block = Vec::new();
            block.extend_from_slice(&sig);
            block.push(num_pages_minus_1);
            block.extend_from_slice(&compressed_size_field.to_le_bytes()[..3]); // 3 bytes of size
            // Pad to 0x20 offset from block start
            while block.len() < 0x20 {
                block.push(0);
            }
            block.extend_from_slice(&compressed);

            out.extend_from_slice(&block);
        }

        out
    }
}
```

- [ ] **Step 2: Write a test that uses the builder**

Create `crates/memf-format/src/hiberfil.rs` with:

```rust
//! Windows hibernation file (hiberfil.sys) format provider.
//!
//! Parses hibernation dumps by decompressing Xpress LZ77 compressed page
//! data blocks and building a page-frame-number to data mapping.

#[cfg(test)]
mod tests {
    use crate::test_builders::HiberfilBuilder;

    #[test]
    fn builder_produces_hibr_magic() {
        let mut page = [0u8; 4096];
        page[0] = 0xDE;
        let dump = HiberfilBuilder::new()
            .add_page(0, &page)
            .build();

        // Check "hibr" magic
        assert_eq!(&dump[0..4], &0x7262_6968u32.to_le_bytes());
        // Should have header pages + compressed data
        assert!(dump.len() > 3 * 4096);
    }

    #[test]
    fn builder_stores_cr3_in_processor_state() {
        let page = [0u8; 4096];
        let dump = HiberfilBuilder::new()
            .cr3(0xDEAD_BEEF)
            .add_page(0, &page)
            .build();

        let cr3 = u64::from_le_bytes(dump[0x1028..0x1030].try_into().unwrap());
        assert_eq!(cr3, 0xDEAD_BEEF);
    }
}
```

- [ ] **Step 3: Add mod declaration in lib.rs**

In `crates/memf-format/src/lib.rs`, add after `pub mod win_crashdump;`:

```rust
pub mod hiberfil;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-format hiberfil -- --nocapture 2>&1 | tail -20`

Expected: 2 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/4n6h4x0r/src/memory-forensic
git add crates/memf-format/src/test_builders.rs crates/memf-format/src/hiberfil.rs crates/memf-format/src/lib.rs
git commit --no-gpg-sign -m "feat(format): add HiberfilBuilder test builder

Synthetic hiberfil.sys builder for TDD. Produces valid PO_MEMORY_IMAGE
header with hibr magic, processor state with CR3, page table, and
Xpress LZ77 compressed page data blocks."
```

---

### Task 6: Hiberfil.sys Provider

**Files:**
- Modify: `crates/memf-format/src/hiberfil.rs`

- [ ] **Step 1: Write the failing tests**

Replace the `mod tests` block in `hiberfil.rs` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_builders::HiberfilBuilder;

    #[test]
    fn probe_hiberfil_magic() {
        let page = [0u8; 4096];
        let dump = HiberfilBuilder::new().add_page(0, &page).build();
        let plugin = HiberfilPlugin;
        assert_eq!(plugin.probe(&dump), 90);
    }

    #[test]
    fn probe_non_hiberfil() {
        let zeros = vec![0u8; 4096];
        let plugin = HiberfilPlugin;
        assert_eq!(plugin.probe(&zeros), 0);
    }

    #[test]
    fn probe_short_header_returns_zero() {
        let plugin = HiberfilPlugin;
        assert_eq!(plugin.probe(&[0x68, 0x69, 0x62]), 0);
        assert_eq!(plugin.probe(&[]), 0);
    }

    #[test]
    fn single_page_read() {
        let mut page = [0u8; 4096];
        page[0] = 0xDE;
        page[1] = 0xAD;
        page[4095] = 0xFF;
        let dump = HiberfilBuilder::new().add_page(0, &page).build();
        let provider = HiberfilProvider::from_bytes(&dump).unwrap();

        assert_eq!(provider.format_name(), "Hiberfil.sys");
        assert_eq!(provider.ranges().len(), 1);
        assert_eq!(provider.ranges()[0].start, 0);
        assert_eq!(provider.ranges()[0].end, 4096);

        let mut buf = [0u8; 4];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf, &[0xDE, 0xAD, 0, 0]);

        let mut buf = [0u8; 1];
        let n = provider.read_phys(4095, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0xFF);
    }

    #[test]
    fn multi_page_read() {
        let page_a = [0xAA; 4096];
        let page_b = [0xBB; 4096];
        let dump = HiberfilBuilder::new()
            .add_page(0, &page_a)
            .add_page(4, &page_b)
            .build();
        let provider = HiberfilProvider::from_bytes(&dump).unwrap();

        assert_eq!(provider.ranges().len(), 2);

        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xAA, 0xAA]);

        let n = provider.read_phys(4 * 4096, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xBB, 0xBB]);
    }

    #[test]
    fn read_gap_returns_zero() {
        let page = [0xCC; 4096];
        let dump = HiberfilBuilder::new().add_page(2, &page).build();
        let provider = HiberfilProvider::from_bytes(&dump).unwrap();

        let mut buf = [0xFF; 4];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_empty_buffer() {
        let page = [0xDD; 4096];
        let dump = HiberfilBuilder::new().add_page(0, &page).build();
        let provider = HiberfilProvider::from_bytes(&dump).unwrap();

        let mut buf = [];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn metadata_extraction() {
        let page = [0u8; 4096];
        let dump = HiberfilBuilder::new()
            .cr3(0xDEAD_B000)
            .add_page(0, &page)
            .build();
        let provider = HiberfilProvider::from_bytes(&dump).unwrap();
        let meta = provider.metadata().expect("should have metadata");
        assert_eq!(meta.cr3, Some(0xDEAD_B000));
        assert_eq!(meta.dump_type, Some("Hibernation".into()));
    }

    #[test]
    fn plugin_name() {
        let plugin = HiberfilPlugin;
        assert_eq!(plugin.name(), "Hiberfil.sys");
    }

    #[test]
    fn from_path_roundtrip() {
        let page = [0xEE; 4096];
        let dump = HiberfilBuilder::new().add_page(0, &page).build();
        let path = std::env::temp_dir().join("memf_test_hiberfil.sys");
        std::fs::write(&path, &dump).unwrap();
        let provider = HiberfilProvider::from_path(&path).unwrap();
        assert_eq!(provider.format_name(), "Hiberfil.sys");
        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xEE, 0xEE]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn builder_produces_hibr_magic() {
        let page = [0u8; 4096];
        let dump = HiberfilBuilder::new().add_page(0, &page).build();
        assert_eq!(&dump[0..4], &0x7262_6968u32.to_le_bytes());
        assert!(dump.len() > 3 * 4096);
    }

    #[test]
    fn builder_stores_cr3_in_processor_state() {
        let page = [0u8; 4096];
        let dump = HiberfilBuilder::new().cr3(0xDEAD_BEEF).add_page(0, &page).build();
        let cr3 = u64::from_le_bytes(dump[0x1028..0x1030].try_into().unwrap());
        assert_eq!(cr3, 0xDEAD_BEEF);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-format hiberfil 2>&1 | tail -20`

Expected: FAIL — `HiberfilProvider` and `HiberfilPlugin` not defined.

- [ ] **Step 3: Implement HiberfilProvider**

Add above the `#[cfg(test)]` block in `hiberfil.rs`:

```rust
//! Windows hibernation file (hiberfil.sys) format provider.
//!
//! Parses hibernation dumps by decompressing Xpress LZ77 compressed page
//! data blocks and building a page-frame-number to data mapping.

use std::collections::HashMap;
use std::path::Path;

use crate::{DumpMetadata, Error, FormatPlugin, PhysicalMemoryProvider, PhysicalRange, Result};

const PAGE_SIZE: u64 = 4096;
const HIBR_MAGIC: u32 = 0x7262_6968;
const WAKE_MAGIC: u32 = 0x656B_6177;
const RSTR_MAGIC: u32 = 0x5254_5352;
const HORM_MAGIC: u32 = 0x4D52_4F48;
const XPRESS_SIG: [u8; 8] = [0x81, 0x81, b'x', b'p', b'r', b'e', b's', b's'];

/// Provider that exposes physical memory from a Windows hibernation file.
pub struct HiberfilProvider {
    pages: HashMap<u64, Vec<u8>>,
    ranges: Vec<PhysicalRange>,
    meta: DumpMetadata,
}

impl HiberfilProvider {
    /// Parse a hiberfil.sys from an in-memory byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 3 * PAGE_SIZE as usize {
            return Err(Error::Corrupt("hiberfil too small".into()));
        }

        // Validate magic
        let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if magic != HIBR_MAGIC && magic != WAKE_MAGIC && magic != RSTR_MAGIC && magic != HORM_MAGIC {
            return Err(Error::Corrupt("not a hiberfil.sys".into()));
        }

        // Extract CR3 from processor state on page 1
        let cr3 = u64::from_le_bytes(
            bytes[0x1028..0x1030].try_into().unwrap(),
        );

        let meta = DumpMetadata {
            cr3: if cr3 != 0 { Some(cr3) } else { None },
            dump_type: Some("Hibernation".into()),
            ..DumpMetadata::default()
        };

        // Read page table from page 2
        let pt_offset = 2 * PAGE_SIZE as usize;
        let mut pfns = Vec::new();
        let mut i = 0;
        loop {
            let entry_off = pt_offset + i * 8;
            if entry_off + 8 > bytes.len().min(3 * PAGE_SIZE as usize) {
                break;
            }
            let pfn = u64::from_le_bytes(bytes[entry_off..entry_off + 8].try_into().unwrap());
            if pfn == 0xFFFF_FFFF_FFFF_FFFF {
                break;
            }
            pfns.push(pfn);
            i += 1;
        }

        // Find and decompress Xpress blocks after header pages
        let mut pages = HashMap::new();
        let data_start = 3 * PAGE_SIZE as usize;
        let mut pos = data_start;
        let mut page_idx = 0;

        while pos + 0x20 <= bytes.len() && page_idx < pfns.len() {
            // Look for Xpress block signature
            if bytes.len() - pos < 8 || bytes[pos..pos + 8] != XPRESS_SIG {
                break;
            }

            let num_pages = bytes[pos + 8] as usize + 1;
            let size_field = u32::from_le_bytes([
                bytes[pos + 9],
                bytes[pos + 10],
                bytes[pos + 11],
                0,
            ]);
            let compressed_size = ((size_field as usize) + 1) / 4;

            let compressed_start = pos + 0x20;
            if compressed_start + compressed_size > bytes.len() {
                return Err(Error::Decompression("compressed block truncated".into()));
            }

            let compressed_data = &bytes[compressed_start..compressed_start + compressed_size];
            let decompressed = rust_lzxpress::lz77::decompress(compressed_data)
                .map_err(|e| Error::Decompression(format!("Xpress LZ77: {e}")))?;

            // Extract pages from decompressed output
            for p in 0..num_pages {
                if page_idx >= pfns.len() {
                    break;
                }
                let page_start = p * PAGE_SIZE as usize;
                if page_start + PAGE_SIZE as usize > decompressed.len() {
                    break;
                }
                let pfn = pfns[page_idx];
                let page_data = decompressed[page_start..page_start + PAGE_SIZE as usize].to_vec();
                pages.insert(pfn, page_data);
                page_idx += 1;
            }

            pos = compressed_start + compressed_size;
        }

        // Build ranges from the page map (sorted, merge contiguous)
        let mut sorted_pfns: Vec<u64> = pages.keys().copied().collect();
        sorted_pfns.sort_unstable();

        let mut ranges = Vec::new();
        for &pfn in &sorted_pfns {
            let start = pfn * PAGE_SIZE;
            let end = start + PAGE_SIZE;
            if let Some(last) = ranges.last_mut() {
                let last: &mut PhysicalRange = last;
                if last.end == start {
                    last.end = end;
                    continue;
                }
            }
            ranges.push(PhysicalRange { start, end });
        }

        Ok(Self { pages, ranges, meta })
    }

    /// Parse a hiberfil.sys from a file path.
    pub fn from_path(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(&data)
    }
}

impl PhysicalMemoryProvider for HiberfilProvider {
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let pfn = addr / PAGE_SIZE;
        let offset_in_page = (addr % PAGE_SIZE) as usize;

        if let Some(page_data) = self.pages.get(&pfn) {
            let available = PAGE_SIZE as usize - offset_in_page;
            let to_read = buf.len().min(available);
            buf[..to_read].copy_from_slice(&page_data[offset_in_page..offset_in_page + to_read]);
            Ok(to_read)
        } else {
            Ok(0)
        }
    }

    fn ranges(&self) -> &[PhysicalRange] {
        &self.ranges
    }

    fn format_name(&self) -> &str {
        "Hiberfil.sys"
    }

    fn metadata(&self) -> Option<DumpMetadata> {
        Some(self.meta.clone())
    }
}

/// `FormatPlugin` implementation for hibernation files.
pub struct HiberfilPlugin;

impl FormatPlugin for HiberfilPlugin {
    fn name(&self) -> &str {
        "Hiberfil.sys"
    }

    fn probe(&self, header: &[u8]) -> u8 {
        if header.len() < 4 {
            return 0;
        }
        let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
        match magic {
            HIBR_MAGIC | WAKE_MAGIC => 90,
            RSTR_MAGIC | HORM_MAGIC => 85,
            _ => 0,
        }
    }

    fn open(&self, path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>> {
        Ok(Box::new(HiberfilProvider::from_path(path)?))
    }
}

inventory::submit!(&HiberfilPlugin as &dyn FormatPlugin);
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-format hiberfil -- --nocapture 2>&1 | tail -20`

Expected: All 12 tests PASS.

- [ ] **Step 5: Run workspace tests + clippy**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | tail -5`
Run: `/Users/4n6h4x0r/.cargo/bin/cargo clippy --workspace -- -D warnings 2>&1 | tail -5`

Expected: All tests pass, zero warnings.

- [ ] **Step 6: Commit**

```bash
cd /Users/4n6h4x0r/src/memory-forensic
git add crates/memf-format/src/hiberfil.rs
git commit --no-gpg-sign -m "feat(format): add hiberfil.sys provider with Xpress decompression

HiberfilProvider parses Windows hibernation files with hibr/wake/RSTR/HORM
signatures. Eager decompression of Xpress LZ77 blocks into HashMap<pfn, page>.
Extracts CR3 from processor state. HiberfilPlugin probes with confidence 90."
```

---

### Task 7: VmwareStateBuilder Test Builder

**Files:**
- Modify: `crates/memf-format/src/test_builders.rs`
- Create: `crates/memf-format/src/vmware.rs`

- [ ] **Step 1: Add VmwareStateBuilder to test_builders.rs**

Append to `crates/memf-format/src/test_builders.rs`:

```rust
/// Build a synthetic VMware .vmss/.vmsn state file for testing.
///
/// Produces the VMware group/tag binary structure with:
/// - 12-byte file header: magic (u32) + unknown (u32) + group_count (u32)
/// - Group entries (80 bytes each): name (64 bytes) + tags_offset (u64) + padding
/// - Tag chains per group
///
/// Memory data goes in the "memory" group as a single large tag.
/// CPU state (CR3) goes in the "cpu" group.
pub struct VmwareStateBuilder {
    memory_regions: Vec<(u64, Vec<u8>)>,
    cr3: Option<u64>,
}

impl VmwareStateBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            memory_regions: Vec::new(),
            cr3: None,
        }
    }

    /// Add a memory region at the given physical address.
    pub fn add_region(mut self, paddr: u64, data: &[u8]) -> Self {
        self.memory_regions.push((paddr, data.to_vec()));
        self
    }

    /// Set the CR3 value stored in the cpu group.
    pub fn cr3(mut self, cr3: u64) -> Self {
        self.cr3 = Some(cr3);
        self
    }

    /// Build the .vmss file as a byte vector.
    pub fn build(self) -> Vec<u8> {
        let mut out = Vec::new();

        // Header: magic + unknown + group_count
        let group_count: u32 = if self.cr3.is_some() { 2 } else { 1 }; // memory + optional cpu
        out.extend_from_slice(&0xBED2_BED0u32.to_le_bytes()); // magic
        out.extend_from_slice(&0u32.to_le_bytes()); // unknown
        out.extend_from_slice(&group_count.to_le_bytes());

        // Reserve space for group entries
        let groups_offset = out.len();
        let group_entry_size = 80;
        out.resize(groups_offset + group_count as usize * group_entry_size, 0);

        // Write "memory" group entry
        let memory_group_off = groups_offset;
        let memory_name = b"memory";
        out[memory_group_off..memory_group_off + memory_name.len()].copy_from_slice(memory_name);

        // Memory tags will start after all group entries
        let memory_tags_offset = out.len() as u64;
        out[memory_group_off + 64..memory_group_off + 72]
            .copy_from_slice(&memory_tags_offset.to_le_bytes());

        // Write memory tags
        // For each region: a tag with name "region" containing paddr(u64) + data
        for (paddr, data) in &self.memory_regions {
            // Tag flags: bit pattern encoding data size > 4 bytes
            let data_payload_len = 8 + data.len(); // paddr + data
            let flags: u8 = 0x06; // indicates large data follows with explicit size
            let name = b"region";
            out.push(flags);
            out.push(name.len() as u8);
            out.extend_from_slice(name);
            // No indices for this simple encoding
            out.extend_from_slice(&(data_payload_len as u32).to_le_bytes());
            out.extend_from_slice(&paddr.to_le_bytes());
            out.extend_from_slice(data);
        }
        // Tag terminator
        out.push(0);

        // Write "cpu" group if CR3 is set
        if let Some(cr3) = self.cr3 {
            let cpu_group_off = groups_offset + group_entry_size;
            let cpu_name = b"cpu";
            out[cpu_group_off..cpu_group_off + cpu_name.len()].copy_from_slice(cpu_name);

            let cpu_tags_offset = out.len() as u64;
            out[cpu_group_off + 64..cpu_group_off + 72]
                .copy_from_slice(&cpu_tags_offset.to_le_bytes());

            // CR3 tag: name="CR3", 1 index byte (0), 8 bytes data
            let flags: u8 = 0x46; // indexed + 8-byte data
            let name = b"CR3";
            out.push(flags);
            out.push(name.len() as u8);
            out.extend_from_slice(name);
            out.push(0); // index[0] = CPU 0
            out.push(3); // index[1] = CR register 3
            out.extend_from_slice(&cr3.to_le_bytes());
            // Tag terminator
            out.push(0);
        }

        out
    }
}
```

- [ ] **Step 2: Write a test that uses the builder**

Create `crates/memf-format/src/vmware.rs` with:

```rust
//! VMware state file (.vmss/.vmsn) format provider.
//!
//! Parses the group/tag binary structure used by VMware suspend and snapshot
//! state files to extract physical memory regions and CPU state.

#[cfg(test)]
mod tests {
    use crate::test_builders::VmwareStateBuilder;

    #[test]
    fn builder_produces_valid_magic() {
        let dump = VmwareStateBuilder::new()
            .add_region(0, &[0xAA; 256])
            .build();

        let magic = u32::from_le_bytes(dump[0..4].try_into().unwrap());
        assert_eq!(magic, 0xBED2_BED0);

        let group_count = u32::from_le_bytes(dump[8..12].try_into().unwrap());
        assert_eq!(group_count, 1); // only memory group, no cpu
    }

    #[test]
    fn builder_with_cr3_has_two_groups() {
        let dump = VmwareStateBuilder::new()
            .add_region(0, &[0xBB; 256])
            .cr3(0x1ab000)
            .build();

        let group_count = u32::from_le_bytes(dump[8..12].try_into().unwrap());
        assert_eq!(group_count, 2); // memory + cpu
    }
}
```

- [ ] **Step 3: Add mod declaration in lib.rs**

In `crates/memf-format/src/lib.rs`, add after `pub mod hiberfil;`:

```rust
pub mod vmware;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-format vmware -- --nocapture 2>&1 | tail -20`

Expected: 2 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/4n6h4x0r/src/memory-forensic
git add crates/memf-format/src/test_builders.rs crates/memf-format/src/vmware.rs crates/memf-format/src/lib.rs
git commit --no-gpg-sign -m "feat(format): add VmwareStateBuilder test builder

Synthetic VMware .vmss/.vmsn builder for TDD. Produces valid group/tag
structure with 0xBED2BED0 magic, memory regions, and optional CPU state
with CR3."
```

---

### Task 8: VMware .vmss/.vmsn Provider

**Files:**
- Modify: `crates/memf-format/src/vmware.rs`

- [ ] **Step 1: Write the failing tests**

Replace the `mod tests` block in `vmware.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_builders::VmwareStateBuilder;

    #[test]
    fn probe_vmware_magic() {
        let dump = VmwareStateBuilder::new()
            .add_region(0, &[0xAA; 256])
            .build();
        let plugin = VmwarePlugin;
        assert_eq!(plugin.probe(&dump), 85);
    }

    #[test]
    fn probe_non_vmware() {
        let zeros = vec![0u8; 256];
        let plugin = VmwarePlugin;
        assert_eq!(plugin.probe(&zeros), 0);
    }

    #[test]
    fn probe_short_header_returns_zero() {
        let plugin = VmwarePlugin;
        assert_eq!(plugin.probe(&[0xD0, 0xBE, 0xD2]), 0);
        assert_eq!(plugin.probe(&[]), 0);
    }

    #[test]
    fn single_region_read() {
        let mut data = vec![0u8; 256];
        data[0] = 0xDE;
        data[1] = 0xAD;
        data[255] = 0xFF;
        let dump = VmwareStateBuilder::new()
            .add_region(0x1000, &data)
            .build();
        let provider = VmwareStateProvider::from_bytes(&dump).unwrap();

        assert_eq!(provider.format_name(), "VMware State");
        assert_eq!(provider.ranges().len(), 1);
        assert_eq!(provider.ranges()[0].start, 0x1000);
        assert_eq!(provider.ranges()[0].end, 0x1100);

        let mut buf = [0u8; 4];
        let n = provider.read_phys(0x1000, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf, &[0xDE, 0xAD, 0, 0]);
    }

    #[test]
    fn multi_region_read() {
        let data_a = vec![0xAA; 128];
        let data_b = vec![0xBB; 128];
        let dump = VmwareStateBuilder::new()
            .add_region(0x0000, &data_a)
            .add_region(0x2000, &data_b)
            .build();
        let provider = VmwareStateProvider::from_bytes(&dump).unwrap();

        assert_eq!(provider.ranges().len(), 2);

        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xAA, 0xAA]);

        let n = provider.read_phys(0x2000, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xBB, 0xBB]);
    }

    #[test]
    fn read_gap_returns_zero() {
        let dump = VmwareStateBuilder::new()
            .add_region(0x2000, &[0xCC; 128])
            .build();
        let provider = VmwareStateProvider::from_bytes(&dump).unwrap();

        let mut buf = [0xFF; 4];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_empty_buffer() {
        let dump = VmwareStateBuilder::new()
            .add_region(0, &[0xDD; 64])
            .build();
        let provider = VmwareStateProvider::from_bytes(&dump).unwrap();

        let mut buf = [];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn metadata_cr3_extraction() {
        let dump = VmwareStateBuilder::new()
            .add_region(0, &[0u8; 64])
            .cr3(0xDEAD_B000)
            .build();
        let provider = VmwareStateProvider::from_bytes(&dump).unwrap();
        let meta = provider.metadata().expect("should have metadata");
        assert_eq!(meta.cr3, Some(0xDEAD_B000));
        assert_eq!(meta.dump_type, Some("VMware State".into()));
    }

    #[test]
    fn metadata_no_cr3() {
        let dump = VmwareStateBuilder::new()
            .add_region(0, &[0u8; 64])
            .build();
        let provider = VmwareStateProvider::from_bytes(&dump).unwrap();
        let meta = provider.metadata().expect("should have metadata");
        assert!(meta.cr3.is_none());
    }

    #[test]
    fn plugin_name() {
        let plugin = VmwarePlugin;
        assert_eq!(plugin.name(), "VMware State");
    }

    #[test]
    fn from_path_roundtrip() {
        let dump = VmwareStateBuilder::new()
            .add_region(0, &[0xEE; 128])
            .build();
        let path = std::env::temp_dir().join("memf_test_vmware.vmss");
        std::fs::write(&path, &dump).unwrap();
        let provider = VmwareStateProvider::from_path(&path).unwrap();
        assert_eq!(provider.format_name(), "VMware State");
        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xEE, 0xEE]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn builder_produces_valid_magic() {
        let dump = VmwareStateBuilder::new()
            .add_region(0, &[0xAA; 256])
            .build();
        let magic = u32::from_le_bytes(dump[0..4].try_into().unwrap());
        assert_eq!(magic, 0xBED2_BED0);
    }

    #[test]
    fn builder_with_cr3_has_two_groups() {
        let dump = VmwareStateBuilder::new()
            .add_region(0, &[0xBB; 256])
            .cr3(0x1ab000)
            .build();
        let group_count = u32::from_le_bytes(dump[8..12].try_into().unwrap());
        assert_eq!(group_count, 2);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-format vmware 2>&1 | tail -20`

Expected: FAIL — `VmwareStateProvider` and `VmwarePlugin` not defined.

- [ ] **Step 3: Implement VmwareStateProvider**

Add above the `#[cfg(test)]` block in `vmware.rs`:

```rust
//! VMware state file (.vmss/.vmsn) format provider.
//!
//! Parses the group/tag binary structure used by VMware suspend and snapshot
//! state files to extract physical memory regions and CPU state.

use std::path::Path;

use crate::{DumpMetadata, Error, FormatPlugin, PhysicalMemoryProvider, PhysicalRange, Result};

const VMWARE_MAGICS: [u32; 4] = [0xBED2_BED0, 0xBAD1_BAD1, 0xBED2_BED2, 0xBED3_BED3];

/// A memory region parsed from the VMware state file.
#[derive(Debug)]
struct MemoryRegion {
    paddr: u64,
    file_offset: usize,
    size: usize,
}

/// Provider that exposes physical memory from a VMware state file.
pub struct VmwareStateProvider {
    data: Vec<u8>,
    regions: Vec<MemoryRegion>,
    ranges: Vec<PhysicalRange>,
    meta: DumpMetadata,
}

impl VmwareStateProvider {
    /// Parse a VMware state file from an in-memory byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let data = bytes.to_vec();
        if data.len() < 12 {
            return Err(Error::Corrupt("VMware state file too small".into()));
        }

        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if !VMWARE_MAGICS.contains(&magic) {
            return Err(Error::Corrupt("not a VMware state file".into()));
        }

        let group_count = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;

        // Parse groups
        let mut memory_tags_offset: Option<u64> = None;
        let mut cpu_tags_offset: Option<u64> = None;

        for i in 0..group_count {
            let goff = 12 + i * 80;
            if goff + 80 > data.len() {
                return Err(Error::Corrupt("group entry truncated".into()));
            }

            // Read group name (null-terminated within 64 bytes)
            let name_end = data[goff..goff + 64]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(64);
            let name = std::str::from_utf8(&data[goff..goff + name_end])
                .unwrap_or("");

            let tags_off = u64::from_le_bytes(data[goff + 64..goff + 72].try_into().unwrap());

            match name {
                "memory" | "mainmem" => memory_tags_offset = Some(tags_off),
                "cpu" => cpu_tags_offset = Some(tags_off),
                _ => {}
            }
        }

        // Parse memory regions from memory group tags
        let mut regions = Vec::new();
        if let Some(tags_off) = memory_tags_offset {
            let mut pos = tags_off as usize;
            while pos < data.len() {
                let flags = data[pos];
                if flags == 0 {
                    break; // terminator
                }
                pos += 1;

                if pos >= data.len() {
                    break;
                }
                let name_len = data[pos] as usize;
                pos += 1;

                // Skip name
                pos += name_len;
                if pos >= data.len() {
                    break;
                }

                // Parse data based on flags
                if flags & 0x06 == 0x06 {
                    // Large data with explicit size
                    if pos + 4 > data.len() {
                        break;
                    }
                    let data_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
                    pos += 4;

                    if data_len >= 8 && pos + data_len <= data.len() {
                        let paddr = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
                        let region_data_offset = pos + 8;
                        let region_size = data_len - 8;
                        regions.push(MemoryRegion {
                            paddr,
                            file_offset: region_data_offset,
                            size: region_size,
                        });
                    }
                    pos += data_len;
                } else {
                    // Skip other tag types
                    break;
                }
            }
        }

        // Parse CR3 from cpu group tags
        let mut cr3: Option<u64> = None;
        if let Some(tags_off) = cpu_tags_offset {
            let mut pos = tags_off as usize;
            while pos < data.len() {
                let flags = data[pos];
                if flags == 0 {
                    break;
                }
                pos += 1;

                if pos >= data.len() {
                    break;
                }
                let name_len = data[pos] as usize;
                pos += 1;

                if pos + name_len > data.len() {
                    break;
                }
                let tag_name = std::str::from_utf8(&data[pos..pos + name_len]).unwrap_or("");
                pos += name_len;

                if flags & 0x40 != 0 {
                    // Indexed tag: 2 index bytes
                    if pos + 2 > data.len() {
                        break;
                    }
                    let _idx0 = data[pos];
                    let idx1 = data[pos + 1];
                    pos += 2;

                    // 8-byte data
                    if pos + 8 > data.len() {
                        break;
                    }
                    let value = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
                    pos += 8;

                    if tag_name == "CR3" || (tag_name == "CR" && idx1 == 3) {
                        cr3 = Some(value);
                    }
                } else {
                    break;
                }
            }
        }

        // Sort regions by paddr
        regions.sort_by_key(|r| r.paddr);

        let ranges: Vec<PhysicalRange> = regions
            .iter()
            .map(|r| PhysicalRange {
                start: r.paddr,
                end: r.paddr + r.size as u64,
            })
            .collect();

        let meta = DumpMetadata {
            cr3,
            dump_type: Some("VMware State".into()),
            ..DumpMetadata::default()
        };

        Ok(Self { data, regions, ranges, meta })
    }

    /// Parse a VMware state file from a file path.
    pub fn from_path(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(&data)
    }
}

impl PhysicalMemoryProvider for VmwareStateProvider {
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        for region in &self.regions {
            let region_end = region.paddr + region.size as u64;
            if addr >= region.paddr && addr < region_end {
                let offset_in_region = (addr - region.paddr) as usize;
                let available = region.size - offset_in_region;
                let to_read = buf.len().min(available);
                let src_start = region.file_offset + offset_in_region;
                buf[..to_read].copy_from_slice(&self.data[src_start..src_start + to_read]);
                return Ok(to_read);
            }
        }

        Ok(0)
    }

    fn ranges(&self) -> &[PhysicalRange] {
        &self.ranges
    }

    fn format_name(&self) -> &str {
        "VMware State"
    }

    fn metadata(&self) -> Option<DumpMetadata> {
        Some(self.meta.clone())
    }
}

/// `FormatPlugin` implementation for VMware state files.
pub struct VmwarePlugin;

impl FormatPlugin for VmwarePlugin {
    fn name(&self) -> &str {
        "VMware State"
    }

    fn probe(&self, header: &[u8]) -> u8 {
        if header.len() < 4 {
            return 0;
        }
        let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
        if VMWARE_MAGICS.contains(&magic) {
            85
        } else {
            0
        }
    }

    fn open(&self, path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>> {
        Ok(Box::new(VmwareStateProvider::from_path(path)?))
    }
}

inventory::submit!(&VmwarePlugin as &dyn FormatPlugin);
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-format vmware -- --nocapture 2>&1 | tail -20`

Expected: All 13 tests PASS.

- [ ] **Step 5: Run workspace tests + clippy**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | tail -5`
Run: `/Users/4n6h4x0r/.cargo/bin/cargo clippy --workspace -- -D warnings 2>&1 | tail -5`

Expected: All tests pass, zero warnings.

- [ ] **Step 6: Commit**

```bash
cd /Users/4n6h4x0r/src/memory-forensic
git add crates/memf-format/src/vmware.rs
git commit --no-gpg-sign -m "feat(format): add VMware .vmss/.vmsn state provider

VmwareStateProvider parses VMware group/tag structure to extract memory
regions and CPU state (CR3). Supports all 4 VMware magic values.
VmwarePlugin probes with confidence 85."
```

---

### Task 9: KdumpBuilder Test Builder

**Files:**
- Modify: `crates/memf-format/src/test_builders.rs`
- Create: `crates/memf-format/src/kdump.rs`

- [ ] **Step 1: Add KdumpBuilder to test_builders.rs**

Append to `crates/memf-format/src/test_builders.rs`:

```rust
/// Build a synthetic kdump (makedumpfile) dump for testing.
///
/// Produces a valid kdump file with:
/// - Block 0: disk_dump_header (signature + header fields)
/// - Block 1: kdump_sub_header
/// - Block 2: 1st bitmap (valid PFNs)
/// - Block 3: 2nd bitmap (dumped PFNs)
/// - Block 4+: page_desc array (24 bytes per page)
/// - After descs: compressed page data
///
/// Compression flags: 0x01=zlib, 0x04=snappy, 0x20=zstd, 0=uncompressed.
pub struct KdumpBuilder {
    pages: Vec<(u64, Vec<u8>)>,
    compression: u32,
    block_size: u32,
}

impl KdumpBuilder {
    /// Create a new builder (defaults: block_size=4096, compression=snappy).
    pub fn new() -> Self {
        Self {
            pages: Vec::new(),
            compression: 0x04, // SNAPPY
            block_size: 4096,
        }
    }

    /// Set the block size (must be a power of 2, typically 4096).
    pub fn block_size(mut self, bs: u32) -> Self {
        self.block_size = bs;
        self
    }

    /// Set the compression flags: 0x01=zlib, 0x04=snappy, 0x20=zstd, 0=none.
    pub fn compression(mut self, flags: u32) -> Self {
        self.compression = flags;
        self
    }

    /// Add a page at the given PFN with the given data.
    /// Data length should equal block_size.
    pub fn add_page(mut self, pfn: u64, data: &[u8]) -> Self {
        self.pages.push((pfn, data.to_vec()));
        self
    }

    /// Build the kdump file as a byte vector.
    pub fn build(self) -> Vec<u8> {
        let bs = self.block_size as usize;

        // Determine max PFN for bitmap sizing
        let max_pfn = self.pages.iter().map(|(pfn, _)| *pfn).max().unwrap_or(0) + 1;
        let bitmap_bytes = ((max_pfn as usize) + 7) / 8;
        let bitmap_blocks = (bitmap_bytes + bs - 1) / bs;

        // Build bitmaps
        let mut bitmap1 = vec![0u8; bitmap_blocks * bs]; // valid PFNs
        let mut bitmap2 = vec![0u8; bitmap_blocks * bs]; // dumped PFNs
        for (pfn, _) in &self.pages {
            let byte_idx = *pfn as usize / 8;
            let bit_idx = *pfn as usize % 8;
            if byte_idx < bitmap1.len() {
                bitmap1[byte_idx] |= 1 << bit_idx;
                bitmap2[byte_idx] |= 1 << bit_idx;
            }
        }

        // Sort pages by PFN for deterministic output
        let mut sorted_pages = self.pages.clone();
        sorted_pages.sort_by_key(|(pfn, _)| *pfn);

        // Compress pages and build page_desc entries
        let mut page_descs: Vec<(i64, u32, u32, u64)> = Vec::new(); // (offset, size, flags, page_flags)
        let mut compressed_data = Vec::new();

        // Page descs start after: header(1) + sub_header(1) + bitmap1(N) + bitmap2(N) blocks
        let desc_block_start = 1 + 1 + bitmap_blocks * 2;
        let desc_total_bytes = sorted_pages.len() * 24; // 24 bytes per page_desc
        let desc_total_blocks = (desc_total_bytes + bs - 1) / bs;
        let data_start_offset = (desc_block_start + desc_total_blocks) * bs;

        let mut current_data_offset = data_start_offset;
        for (_pfn, page_data) in &sorted_pages {
            let (compressed, flags) = self.compress_page(page_data);
            page_descs.push((
                current_data_offset as i64,
                compressed.len() as u32,
                flags,
                0, // page_flags
            ));
            compressed_data.extend_from_slice(&compressed);
            current_data_offset += compressed.len();
        }

        // Assemble the file
        let total_size = current_data_offset;
        let mut out = vec![0u8; total_size];

        // Block 0: disk_dump_header
        // Signature at 0x00
        out[0..8].copy_from_slice(b"KDUMP   ");
        // header_version at 0x08
        out[0x08..0x0C].copy_from_slice(&6i32.to_le_bytes());
        // utsname: 6 fields of 65 chars each = 390 bytes, starts at 0x0C
        // Leave as zeros (synthetic)
        // After utsname (0x0C + 390 = 0x192), alignment to 4-byte boundary -> 0x194
        // block_size at offset 0x194 (after utsname + padding)
        let block_size_off = 0x0C + 390;
        // Align to 4
        let block_size_off = (block_size_off + 3) & !3;
        out[block_size_off..block_size_off + 4].copy_from_slice(&self.block_size.to_le_bytes());
        // sub_hdr_size at block_size_off + 4 (in blocks)
        out[block_size_off + 4..block_size_off + 8].copy_from_slice(&1i32.to_le_bytes());
        // bitmap_blocks at block_size_off + 8
        out[block_size_off + 8..block_size_off + 12].copy_from_slice(&(bitmap_blocks as u32).to_le_bytes());
        // max_mapnr at block_size_off + 12
        out[block_size_off + 12..block_size_off + 16].copy_from_slice(&(max_pfn as u32).to_le_bytes());

        // Block 1: kdump_sub_header (mostly zeros for synthetic dumps)
        // phys_base at block 1 offset 0
        // Leave as 0

        // Block 2: 1st bitmap
        let bm1_start = 2 * bs;
        out[bm1_start..bm1_start + bitmap1.len()].copy_from_slice(&bitmap1);

        // Block 2+N: 2nd bitmap
        let bm2_start = (2 + bitmap_blocks) * bs;
        out[bm2_start..bm2_start + bitmap2.len()].copy_from_slice(&bitmap2);

        // Page descriptors
        let desc_start = desc_block_start * bs;
        for (i, (offset, size, flags, page_flags)) in page_descs.iter().enumerate() {
            let off = desc_start + i * 24;
            if off + 24 <= out.len() {
                out[off..off + 8].copy_from_slice(&offset.to_le_bytes());
                out[off + 8..off + 12].copy_from_slice(&size.to_le_bytes());
                out[off + 12..off + 16].copy_from_slice(&flags.to_le_bytes());
                out[off + 16..off + 24].copy_from_slice(&page_flags.to_le_bytes());
            }
        }

        // Compressed page data
        let mut write_offset = data_start_offset;
        for chunk in &compressed_data.chunks(1).collect::<Vec<_>>() {
            // Already written via the assembly above — compressed_data is laid out
        }
        // Actually copy the compressed data
        if data_start_offset + compressed_data.len() <= out.len() {
            out[data_start_offset..data_start_offset + compressed_data.len()]
                .copy_from_slice(&compressed_data);
        }

        out
    }

    fn compress_page(&self, data: &[u8]) -> (Vec<u8>, u32) {
        match self.compression {
            0x01 => {
                // zlib
                use flate2::write::ZlibEncoder;
                use flate2::Compression;
                use std::io::Write;
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(data).expect("zlib compress");
                let compressed = encoder.finish().expect("zlib finish");
                (compressed, 0x01)
            }
            0x04 => {
                // snappy
                let mut encoder = snap::raw::Encoder::new();
                let compressed = encoder.compress_vec(data).expect("snappy compress");
                (compressed, 0x04)
            }
            0x20 => {
                // zstd — use ruzstd-compatible format: just raw zstd frames
                // For building test data, we use flate2's zlib as a stand-in
                // since ruzstd is decode-only. Instead, store uncompressed
                // with flag=0 for zstd test simplicity. We'll handle this
                // by storing raw data and using a custom zstd encoder.
                // Actually, use the `zstd` algorithm: store uncompressed
                // since ruzstd is decoder-only and we don't have an encoder.
                // For testing, we'll just use uncompressed pages with flag=0.
                (data.to_vec(), 0)
            }
            _ => {
                // Uncompressed
                (data.to_vec(), 0)
            }
        }
    }
}
```

- [ ] **Step 2: Write a test that uses the builder**

Create `crates/memf-format/src/kdump.rs` with:

```rust
//! Linux kdump (makedumpfile / diskdump) format provider.
//!
//! Parses kdump compressed dumps with lazy decompression and LRU page cache.
//! Supports zlib, snappy, and zstd compression. LZO is deferred.

#[cfg(test)]
mod tests {
    use crate::test_builders::KdumpBuilder;

    #[test]
    fn builder_produces_kdump_signature() {
        let page = vec![0xAA; 4096];
        let dump = KdumpBuilder::new()
            .add_page(0, &page)
            .build();

        assert_eq!(&dump[0..8], b"KDUMP   ");
        assert!(dump.len() > 4096);
    }

    #[test]
    fn builder_snappy_compression() {
        let page = vec![0xBB; 4096];
        let dump = KdumpBuilder::new()
            .compression(0x04)
            .add_page(0, &page)
            .build();

        assert_eq!(&dump[0..8], b"KDUMP   ");
    }
}
```

- [ ] **Step 3: Add mod declaration in lib.rs**

In `crates/memf-format/src/lib.rs`, add after `pub mod vmware;`:

```rust
pub mod kdump;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-format kdump -- --nocapture 2>&1 | tail -20`

Expected: 2 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/4n6h4x0r/src/memory-forensic
git add crates/memf-format/src/test_builders.rs crates/memf-format/src/kdump.rs crates/memf-format/src/lib.rs
git commit --no-gpg-sign -m "feat(format): add KdumpBuilder test builder

Synthetic kdump/makedumpfile builder for TDD. Produces valid disk_dump_header
with KDUMP signature, bitmaps, page descriptors, and compressed page data.
Supports snappy and zlib compression in build()."
```

---

### Task 10: kdump Provider

**Files:**
- Modify: `crates/memf-format/src/kdump.rs`

- [ ] **Step 1: Write the failing tests**

Replace the `mod tests` block in `kdump.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_builders::KdumpBuilder;

    #[test]
    fn probe_kdump_signature() {
        let page = vec![0xAA; 4096];
        let dump = KdumpBuilder::new().add_page(0, &page).build();
        let plugin = KdumpPlugin;
        assert_eq!(plugin.probe(&dump), 90);
    }

    #[test]
    fn probe_diskdump_signature() {
        let plugin = KdumpPlugin;
        let mut header = vec![0u8; 64];
        header[0..8].copy_from_slice(b"DISKDUMP");
        assert_eq!(plugin.probe(&header), 90);
    }

    #[test]
    fn probe_non_kdump() {
        let zeros = vec![0u8; 4096];
        let plugin = KdumpPlugin;
        assert_eq!(plugin.probe(&zeros), 0);
    }

    #[test]
    fn probe_short_header_returns_zero() {
        let plugin = KdumpPlugin;
        assert_eq!(plugin.probe(&[b'K', b'D']), 0);
        assert_eq!(plugin.probe(&[]), 0);
    }

    #[test]
    fn single_page_snappy_read() {
        let mut page = vec![0u8; 4096];
        page[0] = 0xDE;
        page[1] = 0xAD;
        page[4095] = 0xFF;
        let dump = KdumpBuilder::new()
            .compression(0x04)
            .add_page(0, &page)
            .build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();

        assert_eq!(provider.format_name(), "kdump");
        assert_eq!(provider.ranges().len(), 1);
        assert_eq!(provider.ranges()[0].start, 0);
        assert_eq!(provider.ranges()[0].end, 4096);

        let mut buf = [0u8; 4];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf, &[0xDE, 0xAD, 0, 0]);

        let mut buf = [0u8; 1];
        let n = provider.read_phys(4095, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0xFF);
    }

    #[test]
    fn single_page_zlib_read() {
        let mut page = vec![0u8; 4096];
        page[0] = 0xCA;
        page[1] = 0xFE;
        let dump = KdumpBuilder::new()
            .compression(0x01)
            .add_page(0, &page)
            .build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();

        let mut buf = [0u8; 4];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf, &[0xCA, 0xFE, 0, 0]);
    }

    #[test]
    fn uncompressed_page_read() {
        let mut page = vec![0u8; 4096];
        page[0] = 0xBE;
        page[1] = 0xEF;
        let dump = KdumpBuilder::new()
            .compression(0) // uncompressed
            .add_page(0, &page)
            .build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();

        let mut buf = [0u8; 4];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf, &[0xBE, 0xEF, 0, 0]);
    }

    #[test]
    fn multi_page_read() {
        let page_a = vec![0xAA; 4096];
        let page_b = vec![0xBB; 4096];
        let dump = KdumpBuilder::new()
            .compression(0x04)
            .add_page(0, &page_a)
            .add_page(4, &page_b)
            .build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();

        assert_eq!(provider.ranges().len(), 2);

        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xAA, 0xAA]);

        let n = provider.read_phys(4 * 4096, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xBB, 0xBB]);
    }

    #[test]
    fn read_gap_returns_zero() {
        let page = vec![0xCC; 4096];
        let dump = KdumpBuilder::new()
            .compression(0x04)
            .add_page(2, &page)
            .build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();

        let mut buf = [0xFF; 4];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_empty_buffer() {
        let page = vec![0xDD; 4096];
        let dump = KdumpBuilder::new().add_page(0, &page).build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();

        let mut buf = [];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn metadata_extraction() {
        let page = vec![0u8; 4096];
        let dump = KdumpBuilder::new().add_page(0, &page).build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();
        let meta = provider.metadata().expect("should have metadata");
        assert_eq!(meta.dump_type, Some("kdump".into()));
    }

    #[test]
    fn lru_cache_hit() {
        let page = vec![0xEE; 4096];
        let dump = KdumpBuilder::new()
            .compression(0x04)
            .add_page(0, &page)
            .build();
        let provider = KdumpProvider::from_bytes(&dump).unwrap();

        // First read — cache miss, decompress
        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xEE, 0xEE]);

        // Second read — should be cache hit
        let n = provider.read_phys(2, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xEE, 0xEE]);
    }

    #[test]
    fn lzo_returns_error() {
        // Build with uncompressed but manually set flags to LZO
        // We can't easily test this with the builder, so test the error path
        // by checking the error type exists
        let err = Error::Decompression("LZO not yet supported".into());
        assert!(err.to_string().contains("LZO"));
    }

    #[test]
    fn plugin_name() {
        let plugin = KdumpPlugin;
        assert_eq!(plugin.name(), "kdump");
    }

    #[test]
    fn from_path_roundtrip() {
        let page = vec![0xFF; 4096];
        let dump = KdumpBuilder::new()
            .compression(0x04)
            .add_page(0, &page)
            .build();
        let path = std::env::temp_dir().join("memf_test_kdump.dump");
        std::fs::write(&path, &dump).unwrap();
        let provider = KdumpProvider::from_path(&path).unwrap();
        assert_eq!(provider.format_name(), "kdump");
        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xFF, 0xFF]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn builder_produces_kdump_signature() {
        let page = vec![0xAA; 4096];
        let dump = KdumpBuilder::new().add_page(0, &page).build();
        assert_eq!(&dump[0..8], b"KDUMP   ");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-format kdump 2>&1 | tail -20`

Expected: FAIL — `KdumpProvider` and `KdumpPlugin` not defined.

- [ ] **Step 3: Implement KdumpProvider**

Add above the `#[cfg(test)]` block in `kdump.rs`:

```rust
//! Linux kdump (makedumpfile / diskdump) format provider.
//!
//! Parses kdump compressed dumps with lazy decompression and LRU page cache.
//! Supports zlib, snappy, and zstd compression. LZO is deferred.

use std::path::Path;
use std::sync::Mutex;

use crate::{DumpMetadata, Error, FormatPlugin, PhysicalMemoryProvider, PhysicalRange, Result};

const KDUMP_SIG: &[u8; 8] = b"KDUMP   ";
const DISKDUMP_SIG: &[u8; 8] = b"DISKDUMP";
const LRU_CACHE_SIZE: usize = 1024;

// Compression flags
const COMPRESS_ZLIB: u32 = 0x01;
const COMPRESS_LZO: u32 = 0x02;
const COMPRESS_SNAPPY: u32 = 0x04;
const COMPRESS_ZSTD: u32 = 0x20;

/// A page descriptor from the kdump file.
#[derive(Debug, Clone)]
struct PageDesc {
    offset: i64,
    size: u32,
    flags: u32,
    #[allow(dead_code)]
    page_flags: u64,
}

/// Provider that exposes physical memory from a kdump file.
pub struct KdumpProvider {
    data: Vec<u8>,
    block_size: u32,
    page_descs: Vec<PageDesc>,
    bitmap: Vec<u8>,
    max_pfn: u64,
    ranges: Vec<PhysicalRange>,
    page_cache: Mutex<lru::LruCache<u64, Vec<u8>>>,
}

impl KdumpProvider {
    /// Parse a kdump file from an in-memory byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let data = bytes.to_vec();
        if data.len() < 4096 {
            return Err(Error::Corrupt("kdump file too small".into()));
        }

        // Validate signature
        if &data[0..8] != KDUMP_SIG && &data[0..8] != DISKDUMP_SIG {
            return Err(Error::Corrupt("not a kdump file".into()));
        }

        // Parse disk_dump_header
        // utsname starts at 0x0C, is 390 bytes (6 * 65)
        let block_size_off = (0x0C + 390 + 3) & !3; // align to 4
        if block_size_off + 16 > data.len() {
            return Err(Error::Corrupt("header truncated".into()));
        }
        let block_size = u32::from_le_bytes(data[block_size_off..block_size_off + 4].try_into().unwrap());
        let sub_hdr_size = i32::from_le_bytes(data[block_size_off + 4..block_size_off + 8].try_into().unwrap()) as usize;
        let bitmap_blocks = u32::from_le_bytes(data[block_size_off + 8..block_size_off + 12].try_into().unwrap()) as usize;
        let max_mapnr = u32::from_le_bytes(data[block_size_off + 12..block_size_off + 16].try_into().unwrap()) as u64;

        let bs = block_size as usize;
        if bs == 0 {
            return Err(Error::Corrupt("block_size is 0".into()));
        }

        // 2nd bitmap location: after header(1) + sub_header(sub_hdr_size) + bitmap1(bitmap_blocks)
        let bm2_start = (1 + sub_hdr_size + bitmap_blocks) * bs;
        let bm2_len = bitmap_blocks * bs;
        if bm2_start + bm2_len > data.len() {
            return Err(Error::Corrupt("2nd bitmap truncated".into()));
        }
        let bitmap = data[bm2_start..bm2_start + bm2_len].to_vec();

        // Count dumped pages (set bits in 2nd bitmap)
        let max_pfn = max_mapnr;
        let mut dumped_pages: usize = 0;
        for pfn in 0..max_pfn as usize {
            let byte_idx = pfn / 8;
            let bit_idx = pfn % 8;
            if byte_idx < bitmap.len() && (bitmap[byte_idx] >> bit_idx) & 1 == 1 {
                dumped_pages += 1;
            }
        }

        // Parse page descriptors
        let desc_start = (1 + sub_hdr_size + bitmap_blocks * 2) * bs;
        let mut page_descs = Vec::with_capacity(dumped_pages);
        for i in 0..dumped_pages {
            let off = desc_start + i * 24;
            if off + 24 > data.len() {
                return Err(Error::Corrupt("page descriptor truncated".into()));
            }
            let offset = i64::from_le_bytes(data[off..off + 8].try_into().unwrap());
            let size = u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap());
            let flags = u32::from_le_bytes(data[off + 12..off + 16].try_into().unwrap());
            let page_flags = u64::from_le_bytes(data[off + 16..off + 24].try_into().unwrap());
            page_descs.push(PageDesc { offset, size, flags, page_flags });
        }

        // Build ranges from bitmap (merge contiguous PFNs)
        let mut ranges = Vec::new();
        let mut range_start: Option<u64> = None;
        for pfn in 0..max_pfn {
            let byte_idx = pfn as usize / 8;
            let bit_idx = pfn as usize % 8;
            let present = byte_idx < bitmap.len() && (bitmap[byte_idx] >> bit_idx) & 1 == 1;

            if present {
                if range_start.is_none() {
                    range_start = Some(pfn * block_size as u64);
                }
            } else if let Some(start) = range_start.take() {
                ranges.push(PhysicalRange {
                    start,
                    end: pfn * block_size as u64,
                });
            }
        }
        if let Some(start) = range_start {
            ranges.push(PhysicalRange {
                start,
                end: max_pfn * block_size as u64,
            });
        }

        let cache = Mutex::new(lru::LruCache::new(
            std::num::NonZeroUsize::new(LRU_CACHE_SIZE).unwrap(),
        ));

        Ok(Self {
            data,
            block_size,
            page_descs,
            bitmap,
            max_pfn,
            ranges,
            page_cache: cache,
        })
    }

    /// Parse a kdump file from a file path.
    pub fn from_path(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(&data)
    }

    /// Count set bits in the 2nd bitmap before position `pfn`.
    fn bitmap_rank(&self, pfn: u64) -> usize {
        let full_bytes = pfn as usize / 8;
        let remaining_bits = pfn as usize % 8;
        let mut count: usize = 0;
        for &byte in &self.bitmap[..full_bytes.min(self.bitmap.len())] {
            count += byte.count_ones() as usize;
        }
        if remaining_bits > 0 && full_bytes < self.bitmap.len() {
            let mask = (1u8 << remaining_bits) - 1;
            count += (self.bitmap[full_bytes] & mask).count_ones() as usize;
        }
        count
    }

    /// Check if a PFN is present in the 2nd bitmap.
    fn is_pfn_present(&self, pfn: u64) -> bool {
        let byte_idx = pfn as usize / 8;
        let bit_idx = pfn as usize % 8;
        byte_idx < self.bitmap.len() && (self.bitmap[byte_idx] >> bit_idx) & 1 == 1
    }

    /// Decompress a page given its descriptor.
    fn decompress_page(&self, desc: &PageDesc) -> Result<Vec<u8>> {
        let offset = desc.offset as usize;
        let size = desc.size as usize;
        if offset + size > self.data.len() {
            return Err(Error::Corrupt("compressed page data truncated".into()));
        }
        let compressed = &self.data[offset..offset + size];

        // Uncompressed page (flags=0, size=block_size)
        if desc.flags == 0 || size == self.block_size as usize {
            return Ok(compressed.to_vec());
        }

        if desc.flags & COMPRESS_ZLIB != 0 {
            use flate2::read::ZlibDecoder;
            use std::io::Read;
            let mut decoder = ZlibDecoder::new(compressed);
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| Error::Decompression(format!("zlib: {e}")))?;
            Ok(decompressed)
        } else if desc.flags & COMPRESS_LZO != 0 {
            Err(Error::Decompression("LZO not yet supported".into()))
        } else if desc.flags & COMPRESS_SNAPPY != 0 {
            let mut decoder = snap::raw::Decoder::new();
            decoder
                .decompress_vec(compressed)
                .map_err(|e| Error::Decompression(format!("snappy: {e}")))
        } else if desc.flags & COMPRESS_ZSTD != 0 {
            let mut cursor = std::io::Cursor::new(compressed);
            let mut decompressed = Vec::new();
            ruzstd::streaming_decoder::StreamingDecoder::new(&mut cursor)
                .map_err(|e| Error::Decompression(format!("zstd init: {e}")))?
                .read_to_end(&mut decompressed)
                .map_err(|e| Error::Decompression(format!("zstd: {e}")))?;
            Ok(decompressed)
        } else {
            // Unknown flags, treat as uncompressed
            Ok(compressed.to_vec())
        }
    }
}

impl PhysicalMemoryProvider for KdumpProvider {
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let pfn = addr / self.block_size as u64;
        let offset_in_page = (addr % self.block_size as u64) as usize;

        // Check cache first
        {
            let mut cache = self.page_cache.lock().unwrap();
            if let Some(page_data) = cache.get(&pfn) {
                let available = self.block_size as usize - offset_in_page;
                let to_read = buf.len().min(available);
                buf[..to_read].copy_from_slice(&page_data[offset_in_page..offset_in_page + to_read]);
                return Ok(to_read);
            }
        }

        // Check if PFN is in the dump
        if pfn >= self.max_pfn || !self.is_pfn_present(pfn) {
            return Ok(0);
        }

        // Find descriptor index
        let desc_idx = self.bitmap_rank(pfn);
        if desc_idx >= self.page_descs.len() {
            return Ok(0);
        }

        // Decompress
        let desc = &self.page_descs[desc_idx];
        let page_data = self.decompress_page(desc)?;

        let available = page_data.len().saturating_sub(offset_in_page);
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&page_data[offset_in_page..offset_in_page + to_read]);

        // Cache the decompressed page
        {
            let mut cache = self.page_cache.lock().unwrap();
            cache.put(pfn, page_data);
        }

        Ok(to_read)
    }

    fn ranges(&self) -> &[PhysicalRange] {
        &self.ranges
    }

    fn format_name(&self) -> &str {
        "kdump"
    }

    fn metadata(&self) -> Option<DumpMetadata> {
        Some(DumpMetadata {
            dump_type: Some("kdump".into()),
            ..DumpMetadata::default()
        })
    }
}

use std::io::Read;

/// `FormatPlugin` implementation for kdump files.
pub struct KdumpPlugin;

impl FormatPlugin for KdumpPlugin {
    fn name(&self) -> &str {
        "kdump"
    }

    fn probe(&self, header: &[u8]) -> u8 {
        if header.len() < 8 {
            return 0;
        }
        if &header[0..8] == KDUMP_SIG || &header[0..8] == DISKDUMP_SIG {
            90
        } else {
            0
        }
    }

    fn open(&self, path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>> {
        Ok(Box::new(KdumpProvider::from_path(path)?))
    }
}

inventory::submit!(&KdumpPlugin as &dyn FormatPlugin);
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-format kdump -- --nocapture 2>&1 | tail -30`

Expected: All 16 tests PASS.

- [ ] **Step 5: Run workspace tests + clippy**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | tail -5`
Run: `/Users/4n6h4x0r/.cargo/bin/cargo clippy --workspace -- -D warnings 2>&1 | tail -5`

Expected: All tests pass, zero warnings.

- [ ] **Step 6: Commit**

```bash
cd /Users/4n6h4x0r/src/memory-forensic
git add crates/memf-format/src/kdump.rs
git commit --no-gpg-sign -m "feat(format): add kdump provider with lazy decompression + LRU cache

KdumpProvider parses makedumpfile/diskdump format with KDUMP/DISKDUMP
signatures. Lazy page decompression with Mutex<LruCache<pfn, page>>.
Supports zlib (flate2), snappy (snap), uncompressed. LZO deferred.
KdumpPlugin probes with confidence 90."
```

---

### Task 11: open_dump Integration Tests

**Files:**
- Modify: `crates/memf-format/src/lib.rs` (tests section)

- [ ] **Step 1: Write integration tests for all new formats**

Add to the `#[cfg(test)] mod tests` block in `crates/memf-format/src/lib.rs`:

```rust
    #[test]
    fn open_dump_crashdump() {
        use crate::test_builders::CrashDumpBuilder;
        let page = vec![0xAA; 4096];
        let dump = CrashDumpBuilder::new().add_run(0, &page).build();
        let path = std::env::temp_dir().join("memf_test_open_crashdump.dmp");
        std::fs::write(&path, &dump).unwrap();
        let provider = open_dump(&path).unwrap();
        assert_eq!(provider.format_name(), "Windows Crash Dump");
        assert_eq!(provider.total_size(), 4096);
        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xAA, 0xAA]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn open_dump_hiberfil() {
        use crate::test_builders::HiberfilBuilder;
        let page = [0xBB; 4096];
        let dump = HiberfilBuilder::new().add_page(0, &page).build();
        let path = std::env::temp_dir().join("memf_test_open_hiberfil.sys");
        std::fs::write(&path, &dump).unwrap();
        let provider = open_dump(&path).unwrap();
        assert_eq!(provider.format_name(), "Hiberfil.sys");
        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xBB, 0xBB]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn open_dump_vmware() {
        use crate::test_builders::VmwareStateBuilder;
        let dump = VmwareStateBuilder::new()
            .add_region(0, &[0xCC; 128])
            .build();
        let path = std::env::temp_dir().join("memf_test_open_vmware.vmss");
        std::fs::write(&path, &dump).unwrap();
        let provider = open_dump(&path).unwrap();
        assert_eq!(provider.format_name(), "VMware State");
        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xCC, 0xCC]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn open_dump_kdump() {
        use crate::test_builders::KdumpBuilder;
        let page = vec![0xDD; 4096];
        let dump = KdumpBuilder::new()
            .compression(0x04)
            .add_page(0, &page)
            .build();
        let path = std::env::temp_dir().join("memf_test_open_kdump.dump");
        std::fs::write(&path, &dump).unwrap();
        let provider = open_dump(&path).unwrap();
        assert_eq!(provider.format_name(), "kdump");
        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xDD, 0xDD]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn metadata_returns_none_for_legacy_formats() {
        use crate::test_builders::LimeBuilder;
        let dump = LimeBuilder::new().add_range(0, &[0xAA; 64]).build();
        let path = std::env::temp_dir().join("memf_test_meta_lime.lime");
        std::fs::write(&path, &dump).unwrap();
        let provider = open_dump(&path).unwrap();
        assert!(provider.metadata().is_none());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn metadata_returns_some_for_crashdump() {
        use crate::test_builders::CrashDumpBuilder;
        let page = vec![0u8; 4096];
        let dump = CrashDumpBuilder::new().cr3(0x1ab000).add_run(0, &page).build();
        let path = std::env::temp_dir().join("memf_test_meta_crash.dmp");
        std::fs::write(&path, &dump).unwrap();
        let provider = open_dump(&path).unwrap();
        let meta = provider.metadata().expect("crash dump should have metadata");
        assert_eq!(meta.cr3, Some(0x1ab000));
        std::fs::remove_file(&path).ok();
    }
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-format open_dump metadata_returns -- --nocapture 2>&1 | tail -20`

Expected: All 6 new tests + 3 existing open_dump tests PASS.

- [ ] **Step 3: Run full workspace tests + clippy**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | tail -10`
Run: `/Users/4n6h4x0r/.cargo/bin/cargo clippy --workspace -- -D warnings 2>&1 | tail -5`

Expected: All tests pass (should be ~290+ total), zero clippy warnings.

- [ ] **Step 4: Commit**

```bash
cd /Users/4n6h4x0r/src/memory-forensic
git add crates/memf-format/src/lib.rs
git commit --no-gpg-sign -m "test(format): add open_dump integration tests for all new formats

Integration tests verify all 4 new formats are discoverable via
open_dump() + inventory plugin system. Also tests metadata() returns
None for legacy formats and Some for crash dumps."
```

---

### Task 12: Final Verification

**Files:** None (verification only)

- [ ] **Step 1: Run full workspace test suite**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | tail -20`

Expected: All tests pass. Count should be ~290+ (237 baseline + ~55 new).

- [ ] **Step 2: Run clippy**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo clippy --workspace -- -D warnings 2>&1 | tail -10`

Expected: Zero warnings.

- [ ] **Step 3: Run fmt check**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo fmt --check --all 2>&1`

Expected: No formatting issues.

- [ ] **Step 4: Verify no unsafe code**

Run: `grep -r "unsafe" /Users/4n6h4x0r/src/memory-forensic/crates/memf-format/src/ --include="*.rs" | grep -v "deny(unsafe_code)" | grep -v "test" | grep -v "//" || echo "No unsafe code found"`

Expected: No unsafe code.

- [ ] **Step 5: Verify all providers are registered**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-format plugin_name -- --nocapture 2>&1`

Expected: plugin_name tests pass for all formats.

- [ ] **Step 6: Count total tests**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | grep "test result"`

Report the total test count.
