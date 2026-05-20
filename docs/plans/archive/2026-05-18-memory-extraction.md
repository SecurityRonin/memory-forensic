# Memory Extraction Implementation Plan

**Goal:** Add `procdump`, `moddump`, and `dumpfiles` (mapped-file enumeration) to `memf-windows`.

**Architecture:** New walker `walkers/moddump.rs` with a `MemReader` trait for testability.
The core value is `reconstruct_pe` (pure function, fully unit-testable) which converts
an in-memory PE image to disk-format by remapping sections. Everything else is thin
wiring over `ObjectReader::read_bytes`.

**Key types available:**
- `WinProcessInfo { cr3, peb_addr, image_name, ... }`
- `WinDllInfo { base_addr, size, name, full_path, ... }`
- `WinDriverInfo { base_addr, size, name, ... }`
- `ObjectReader<P>::read_bytes(vaddr, len) -> memf_core::Result<Vec<u8>>`

---

## Task 1: moddump.rs skeleton + Cargo dep + RED tests

**Files:**
- Modify: `crates/memf-windows/Cargo.toml`
- Create: `crates/memf-windows/src/walkers/moddump.rs`
- Modify: `crates/memf-windows/src/walkers/lib.rs` (or wherever walkers are exported)

**Step 1: Add goblin to memf-windows**

In `crates/memf-windows/Cargo.toml` under `[dependencies]`:
```toml
goblin = { workspace = true }
```

**Step 2: Create skeleton moddump.rs**

```rust
//! Process and module memory extraction.
//!
//! `moddump` reads a DLL or EXE from process virtual memory and optionally
//! reconstructs a loadable PE. `procdump` extracts a process's main executable.
//! `dumpfiles` enumerates file-backed VAD regions.

use memf_format::PhysicalMemoryProvider;
use memf_core::object_reader::ObjectReader;

use crate::types::{WinDllInfo, WinDriverInfo, WinProcessInfo, WinVadInfo};

/// A module or process image extracted from memory.
#[derive(Debug, Clone)]
pub struct ModuleDump {
    /// Name of the extracted module.
    pub name: String,
    /// Virtual base address in the source address space.
    pub base_addr: u64,
    /// Raw bytes as read from virtual memory.
    pub raw_bytes: Vec<u8>,
    /// PE reconstructed to disk-format section layout, if successful.
    pub reconstructed: Option<Vec<u8>>,
}

/// A file-backed VAD region (mapped file in process memory).
#[derive(Debug, Clone)]
pub struct MappedFileRegion {
    /// Start virtual address of the mapping.
    pub start_vaddr: u64,
    /// End virtual address of the mapping (inclusive).
    pub end_vaddr: u64,
    /// File path if resolved (from FileObject.FileName); empty string if unknown.
    pub file_path: String,
    /// Memory protection flags.
    pub protection: u32,
}

/// Internal reader abstraction — lets tests inject a fake without building real page tables.
pub(crate) trait MemReader {
    fn read_region(&self, vaddr: u64, len: usize) -> crate::Result<Vec<u8>>;
}

impl<P: PhysicalMemoryProvider> MemReader for ObjectReader<P> {
    fn read_region(&self, vaddr: u64, len: usize) -> crate::Result<Vec<u8>> {
        Ok(self.read_bytes(vaddr, len)?)
    }
}

/// Read raw bytes from a virtual address range.
pub fn dump_memory_region<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    vaddr: u64,
    size: usize,
) -> crate::Result<Vec<u8>> {
    dump_region_inner(reader, vaddr, size)
}

fn dump_region_inner(reader: &impl MemReader, vaddr: u64, size: usize) -> crate::Result<Vec<u8>> {
    reader.read_region(vaddr, size)
}

/// Extract a DLL or module image from process virtual memory.
pub fn moddump<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    dll: &WinDllInfo,
) -> crate::Result<ModuleDump> {
    moddump_inner(reader, &dll.name, dll.base_addr, dll.size as usize)
}

/// Extract a kernel driver image from kernel virtual memory.
pub fn moddump_driver<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    drv: &WinDriverInfo,
) -> crate::Result<ModuleDump> {
    moddump_inner(reader, &drv.name, drv.base_addr, drv.size as usize)
}

fn moddump_inner(
    reader: &impl MemReader,
    name: &str,
    base_addr: u64,
    size: usize,
) -> crate::Result<ModuleDump> {
    let _ = (reader, name, base_addr, size);
    Err(crate::Error::WalkFailed {
        walker: "moddump",
        reason: "not implemented".into(),
    })
}

/// Extract the main executable image of a process.
///
/// `dlls` must be the DLL list for this process (from `walk_dlls` or `walk_ldr_modules`).
/// The main executable is the first entry in load order (load_order == 0).
pub fn procdump<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    process: &WinProcessInfo,
    dlls: &[WinDllInfo],
) -> crate::Result<ModuleDump> {
    procdump_inner(reader, process, dlls)
}

fn procdump_inner(
    reader: &impl MemReader,
    process: &WinProcessInfo,
    dlls: &[WinDllInfo],
) -> crate::Result<ModuleDump> {
    let _ = (reader, process, dlls);
    Err(crate::Error::WalkFailed {
        walker: "procdump",
        reason: "not implemented".into(),
    })
}

/// Enumerate file-backed VAD regions (what files are mapped into a process).
///
/// Returns only VAD entries that are not private allocations.
/// File paths are not resolved here (requires traversing Subsection/FileObject chain);
/// callers needing paths should use the full VAD walk with file resolution.
pub fn list_mapped_files(vads: &[WinVadInfo]) -> Vec<MappedFileRegion> {
    vads.iter()
        .filter(|v| !v.is_private)
        .map(|v| MappedFileRegion {
            start_vaddr: v.start_vaddr,
            end_vaddr: v.end_vaddr,
            file_path: String::new(),
            protection: v.protection,
        })
        .collect()
}

/// Convert an in-memory PE image to disk-format by remapping sections.
///
/// Windows loads PE files with sections mapped to VirtualAddress offsets
/// (page-aligned). This function reads section headers, copies section data
/// from their virtual positions, and writes them to disk-aligned offsets
/// matching PointerToRawData — producing a PE that tools like PE-bear or
/// Ghidra can load without manual fixup.
///
/// Returns `Err(WalkFailed)` if the input is not a recognisable PE.
pub fn reconstruct_pe(in_memory: &[u8]) -> crate::Result<Vec<u8>> {
    let _ = in_memory;
    Err(crate::Error::WalkFailed {
        walker: "reconstruct_pe",
        reason: "not implemented".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WinVadInfo;

    // ── MemReader fake ──────────────────────────────────────────────────────

    struct FakeReader {
        base: u64,
        data: Vec<u8>,
    }

    impl FakeReader {
        fn new(base: u64, data: Vec<u8>) -> Self {
            Self { base, data }
        }
    }

    impl MemReader for FakeReader {
        fn read_region(&self, vaddr: u64, len: usize) -> crate::Result<Vec<u8>> {
            if vaddr < self.base {
                return Ok(vec![0u8; len]);
            }
            let off = (vaddr - self.base) as usize;
            if off >= self.data.len() {
                return Ok(vec![0u8; len]);
            }
            let n = len.min(self.data.len() - off);
            let mut out = vec![0u8; len];
            out[..n].copy_from_slice(&self.data[off..off + n]);
            Ok(out)
        }
    }

    // ── build_memory_pe helper ──────────────────────────────────────────────
    // Produces a minimal in-memory PE with two sections at page-aligned offsets.
    // Section 0 (.text)  : VirtualAddress=0x1000, VirtualSize=0x200, data=0xCC
    // Section 1 (.data)  : VirtualAddress=0x2000, VirtualSize=0x100, data=0xDD
    // Headers occupy 0x400 bytes (file-aligned) at offset 0.
    // Total buffer: 0x3000 bytes.
    fn build_memory_pe() -> Vec<u8> {
        let mut buf = vec![0u8; 0x3000];

        // DOS header
        buf[0] = b'M'; buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew

        let pe = 0x80usize;
        // PE sig
        buf[pe..pe+4].copy_from_slice(b"PE\0\0");
        // COFF: AMD64, 2 sections, SizeOfOptionalHeader=240
        buf[pe+4..pe+6].copy_from_slice(&0x8664u16.to_le_bytes());
        buf[pe+6..pe+8].copy_from_slice(&2u16.to_le_bytes());  // NumberOfSections
        buf[pe+16..pe+18].copy_from_slice(&240u16.to_le_bytes());
        buf[pe+18..pe+20].copy_from_slice(&0x0022u16.to_le_bytes());

        let opt = pe + 20;
        // PE32+ optional header
        buf[opt..opt+2].copy_from_slice(&0x020Bu16.to_le_bytes());
        buf[opt+32..opt+36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        buf[opt+36..opt+40].copy_from_slice(&0x200u32.to_le_bytes());  // FileAlignment
        buf[opt+56..opt+60].copy_from_slice(&0x4000u32.to_le_bytes()); // SizeOfImage
        buf[opt+60..opt+64].copy_from_slice(&0x400u32.to_le_bytes());  // SizeOfHeaders
        buf[opt+108..opt+112].copy_from_slice(&16u32.to_le_bytes());   // NumberOfRvaAndSizes

        // Section headers at pe+20+240 = pe+260 = 0x80+260 = 0x184
        let sh = opt + 240;

        // .text: VA=0x1000, VSize=0x200, PtrToRaw=0x400, RawSize=0x200
        buf[sh..sh+8].copy_from_slice(b".text\0\0\0");
        buf[sh+8..sh+12].copy_from_slice(&0x200u32.to_le_bytes());   // VirtualSize
        buf[sh+12..sh+16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        buf[sh+16..sh+20].copy_from_slice(&0x200u32.to_le_bytes());  // SizeOfRawData
        buf[sh+20..sh+24].copy_from_slice(&0x400u32.to_le_bytes());  // PointerToRawData

        // .data: VA=0x2000, VSize=0x100, PtrToRaw=0x600, RawSize=0x200
        buf[sh+40..sh+48].copy_from_slice(b".data\0\0\0");
        buf[sh+40+8..sh+40+12].copy_from_slice(&0x100u32.to_le_bytes());  // VirtualSize
        buf[sh+40+12..sh+40+16].copy_from_slice(&0x2000u32.to_le_bytes()); // VirtualAddress
        buf[sh+40+16..sh+40+20].copy_from_slice(&0x200u32.to_le_bytes());  // SizeOfRawData
        buf[sh+40+20..sh+40+24].copy_from_slice(&0x600u32.to_le_bytes());  // PointerToRawData

        // Section data at their VirtualAddress positions (in-memory layout)
        buf[0x1000..0x1200].fill(0xCC); // .text
        buf[0x2000..0x2100].fill(0xDD); // .data

        buf
    }

    // ── reconstruct_pe tests (RED — function returns WalkFailed stub) ────────

    #[test]
    fn reconstruct_pe_fails_on_empty_input() {
        let result = reconstruct_pe(b"");
        assert!(result.is_err());
    }

    #[test]
    fn reconstruct_pe_fails_on_garbage() {
        let result = reconstruct_pe(b"GARBAGE_NOT_A_PE");
        assert!(result.is_err());
    }

    #[test]
    fn reconstruct_pe_remaps_text_section_to_disk_offset() {
        // After reconstruction: .text bytes (0xCC) should appear at PointerToRawData=0x400.
        let mem_pe = build_memory_pe();
        let disk = reconstruct_pe(&mem_pe).expect("reconstruct_pe should succeed on valid PE");
        // .text data starts at PointerToRawData=0x400
        assert!(
            disk.len() > 0x600,
            "output too small: {} bytes", disk.len()
        );
        assert_eq!(disk[0x400], 0xCC, ".text data not at PointerToRawData=0x400");
    }

    #[test]
    fn reconstruct_pe_remaps_data_section_to_disk_offset() {
        let mem_pe = build_memory_pe();
        let disk = reconstruct_pe(&mem_pe).expect("reconstruct_pe should succeed");
        assert_eq!(disk[0x600], 0xDD, ".data data not at PointerToRawData=0x600");
    }

    #[test]
    fn reconstruct_pe_preserves_dos_header() {
        let mem_pe = build_memory_pe();
        let disk = reconstruct_pe(&mem_pe).expect("reconstruct_pe should succeed");
        assert_eq!(&disk[0..2], b"MZ");
        // e_lfanew preserved
        let e_lfanew = u32::from_le_bytes([disk[0x3C], disk[0x3D], disk[0x3E], disk[0x3F]]);
        assert_eq!(e_lfanew, 0x80);
    }

    // ── dump_region_inner tests ─────────────────────────────────────────────

    #[test]
    fn dump_region_inner_reads_correct_bytes() {
        let data = (0u8..=255).collect::<Vec<_>>();
        let reader = FakeReader::new(0x1000, data.clone());
        let result = dump_region_inner(&reader, 0x1000, 16).unwrap();
        assert_eq!(result, &data[..16]);
    }

    #[test]
    fn dump_region_inner_returns_zeros_for_unmapped() {
        let reader = FakeReader::new(0x5000, vec![0xAB; 0x100]);
        let result = dump_region_inner(&reader, 0x1000, 8).unwrap();
        assert_eq!(result, vec![0u8; 8]);
    }

    // ── moddump_inner tests ─────────────────────────────────────────────────

    #[test]
    fn moddump_inner_returns_error_on_stub() {
        let reader = FakeReader::new(0x1000, vec![0u8; 0x100]);
        let result = moddump_inner(&reader, "test.dll", 0x1000, 0x100);
        assert!(result.is_err(), "stub should return error");
    }

    // ── procdump_inner tests ────────────────────────────────────────────────

    #[test]
    fn procdump_inner_returns_error_on_stub() {
        let reader = FakeReader::new(0x1000, vec![0u8; 0x100]);
        let process = WinProcessInfo {
            pid: 4,
            ppid: 0,
            image_name: "System".into(),
            create_time: 0,
            exit_time: 0,
            cr3: 0,
            peb_addr: 0,
            vaddr: 0,
            thread_count: 1,
            is_wow64: false,
        };
        let result = procdump_inner(&reader, &process, &[]);
        assert!(result.is_err());
    }

    // ── list_mapped_files tests ─────────────────────────────────────────────

    #[test]
    fn list_mapped_files_excludes_private_vads() {
        let vads = vec![
            WinVadInfo { pid: 1, image_name: "test".into(), start_vaddr: 0x1000, end_vaddr: 0x1FFF, protection: 4, protection_str: "RW".into(), is_private: true },
            WinVadInfo { pid: 1, image_name: "test".into(), start_vaddr: 0x2000, end_vaddr: 0x2FFF, protection: 2, protection_str: "RO".into(), is_private: false },
        ];
        let mapped = list_mapped_files(&vads);
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].start_vaddr, 0x2000);
    }

    #[test]
    fn list_mapped_files_empty_on_all_private() {
        let vads = vec![
            WinVadInfo { pid: 1, image_name: "p".into(), start_vaddr: 0, end_vaddr: 0xFFF, protection: 4, protection_str: "RW".into(), is_private: true },
        ];
        assert!(list_mapped_files(&vads).is_empty());
    }
}
```

**Step 3: Export in lib.rs**

Find where walkers are re-exported in `crates/memf-windows/src/walkers/lib.rs` or `crates/memf-windows/src/lib.rs` and add:
```rust
pub mod moddump;
pub use moddump::{ModuleDump, MappedFileRegion, dump_memory_region, moddump, moddump_driver, procdump, list_mapped_files, reconstruct_pe};
```

**Step 4: Run tests — confirm RED**

```bash
cargo test -p memf-windows moddump 2>&1 | tail -20
```

Expected failures:
- `reconstruct_pe_remaps_text_section_to_disk_offset` — FAIL
- `reconstruct_pe_remaps_data_section_to_disk_offset` — FAIL
- `reconstruct_pe_preserves_dos_header` — FAIL
- `moddump_inner_returns_error_on_stub` — PASS (stub returns error as expected)
- `procdump_inner_returns_error_on_stub` — PASS

Expected passes: all non-reconstruct_pe tests, plus the stub tests.

**Step 5: RED commit**

```bash
git add crates/memf-windows/Cargo.toml crates/memf-windows/src/walkers/moddump.rs crates/memf-windows/src/lib.rs
git commit --no-gpg-sign -m "test(red): moddump — process/module extraction + reconstruct_pe tests"
```

---

## Task 2: Implement reconstruct_pe (GREEN)

**Files:**
- Modify: `crates/memf-windows/src/walkers/moddump.rs`

**Step 1: Implement reconstruct_pe**

```rust
pub fn reconstruct_pe(in_memory: &[u8]) -> crate::Result<Vec<u8>> {
    // Parse DOS header
    if in_memory.len() < 0x40 || &in_memory[0..2] != b"MZ" {
        return Err(crate::Error::WalkFailed {
            walker: "reconstruct_pe",
            reason: "not a PE image (no MZ header)".into(),
        });
    }
    let e_lfanew = u32::from_le_bytes([
        in_memory[0x3C], in_memory[0x3D], in_memory[0x3E], in_memory[0x3F],
    ]) as usize;
    if e_lfanew + 24 > in_memory.len() || &in_memory[e_lfanew..e_lfanew+4] != b"PE\0\0" {
        return Err(crate::Error::WalkFailed {
            walker: "reconstruct_pe",
            reason: "not a valid PE (missing PE signature)".into(),
        });
    }

    // COFF header
    let num_sections = u16::from_le_bytes([in_memory[e_lfanew+6], in_memory[e_lfanew+7]]) as usize;
    let opt_size = u16::from_le_bytes([in_memory[e_lfanew+20], in_memory[e_lfanew+21]]) as usize;

    // Section headers start after PE sig (4) + COFF (20) + optional header
    let sh_offset = e_lfanew + 24 + opt_size;
    if sh_offset + num_sections * 40 > in_memory.len() {
        return Err(crate::Error::WalkFailed {
            walker: "reconstruct_pe",
            reason: "section headers out of bounds".into(),
        });
    }

    // Determine output size: max(PointerToRawData + SizeOfRawData) across sections
    let mut out_size = sh_offset + num_sections * 40;
    for i in 0..num_sections {
        let s = sh_offset + i * 40;
        let ptr_raw = u32::from_le_bytes([in_memory[s+20], in_memory[s+21], in_memory[s+22], in_memory[s+23]]) as usize;
        let raw_sz  = u32::from_le_bytes([in_memory[s+16], in_memory[s+17], in_memory[s+18], in_memory[s+19]]) as usize;
        out_size = out_size.max(ptr_raw + raw_sz);
    }

    // Copy headers verbatim
    let mut out = vec![0u8; out_size];
    let header_sz = (sh_offset + num_sections * 40).min(in_memory.len());
    out[..header_sz].copy_from_slice(&in_memory[..header_sz]);

    // Copy each section from its VirtualAddress in the in-memory image
    // to PointerToRawData in the output
    for i in 0..num_sections {
        let s = sh_offset + i * 40;
        let virt_addr = u32::from_le_bytes([in_memory[s+12], in_memory[s+13], in_memory[s+14], in_memory[s+15]]) as usize;
        let virt_size = u32::from_le_bytes([in_memory[s+8],  in_memory[s+9],  in_memory[s+10], in_memory[s+11]]) as usize;
        let ptr_raw   = u32::from_le_bytes([in_memory[s+20], in_memory[s+21], in_memory[s+22], in_memory[s+23]]) as usize;
        let raw_sz    = u32::from_le_bytes([in_memory[s+16], in_memory[s+17], in_memory[s+18], in_memory[s+19]]) as usize;

        if ptr_raw == 0 || raw_sz == 0 {
            continue; // BSS or uninitialized section
        }

        // Copy min(VirtualSize, SizeOfRawData) bytes from in_memory[virt_addr..]
        let copy_len = virt_size.min(raw_sz);
        let src_end = virt_addr.saturating_add(copy_len).min(in_memory.len());
        let actual = src_end.saturating_sub(virt_addr);
        if actual > 0 && ptr_raw + actual <= out.len() {
            out[ptr_raw..ptr_raw + actual].copy_from_slice(&in_memory[virt_addr..virt_addr + actual]);
        }
    }

    Ok(out)
}
```

**Step 2: Run tests**

```bash
cargo test -p memf-windows moddump 2>&1 | tail -20
```

Expected: `reconstruct_pe_*` tests now PASS. moddump/procdump stubs still fail.

**Step 3: GREEN commit**

```bash
git add crates/memf-windows/src/walkers/moddump.rs
git commit --no-gpg-sign -m "feat(green): reconstruct_pe — remap in-memory PE sections to disk layout"
```

---

## Task 3: Implement moddump_inner and procdump_inner (GREEN)

**Files:**
- Modify: `crates/memf-windows/src/walkers/moddump.rs`

**Step 1: Implement moddump_inner**

```rust
fn moddump_inner(
    reader: &impl MemReader,
    name: &str,
    base_addr: u64,
    size: usize,
) -> crate::Result<ModuleDump> {
    let raw_bytes = reader.read_region(base_addr, size)?;
    let reconstructed = reconstruct_pe(&raw_bytes).ok();
    Ok(ModuleDump {
        name: name.to_string(),
        base_addr,
        raw_bytes,
        reconstructed,
    })
}
```

**Step 2: Implement procdump_inner**

```rust
fn procdump_inner(
    reader: &impl MemReader,
    process: &WinProcessInfo,
    dlls: &[WinDllInfo],
) -> crate::Result<ModuleDump> {
    // The main executable is load_order == 0 (first in InLoadOrderModuleList)
    let exe = dlls
        .iter()
        .min_by_key(|d| d.load_order)
        .ok_or_else(|| crate::Error::WalkFailed {
            walker: "procdump",
            reason: format!("no DLLs found for PID {}", process.pid),
        })?;
    moddump_inner(reader, &exe.name, exe.base_addr, exe.size as usize)
}
```

**Step 3: Update tests — moddump/procdump now succeed**

Add two GREEN tests alongside the existing RED stubs (those can be removed):

```rust
#[test]
fn moddump_inner_returns_correct_name_and_bytes() {
    let pe = build_memory_pe();
    let reader = FakeReader::new(0x7FF0_0000, pe.clone());
    let result = moddump_inner(&reader, "test.dll", 0x7FF0_0000, pe.len()).unwrap();
    assert_eq!(result.name, "test.dll");
    assert_eq!(result.base_addr, 0x7FF0_0000);
    assert_eq!(result.raw_bytes.len(), pe.len());
    assert!(result.reconstructed.is_some(), "valid PE should be reconstructed");
}

#[test]
fn procdump_inner_picks_lowest_load_order() {
    let pe = build_memory_pe();
    let reader = FakeReader::new(0x4000_0000, pe.clone());
    let process = WinProcessInfo {
        pid: 100, ppid: 4, image_name: "notepad.exe".into(),
        create_time: 0, exit_time: 0, cr3: 0,
        peb_addr: 0, vaddr: 0, thread_count: 2, is_wow64: false,
    };
    let dlls = vec![
        WinDllInfo { name: "ntdll.dll".into(), full_path: "".into(), base_addr: 0x5000_0000, size: 0x200, load_order: 2 },
        WinDllInfo { name: "notepad.exe".into(), full_path: "".into(), base_addr: 0x4000_0000, size: pe.len() as u64, load_order: 0 },
    ];
    let result = procdump_inner(&reader, &process, &dlls).unwrap();
    assert_eq!(result.name, "notepad.exe");
    assert_eq!(result.base_addr, 0x4000_0000);
}
```

**Step 4: Run full walker tests**

```bash
cargo test -p memf-windows moddump 2>&1 | tail -20
cargo test -p memf-windows 2>&1 | tail -5
```

Expected: all moddump tests pass, full suite passes.

**Step 5: GREEN commit**

```bash
git add crates/memf-windows/src/walkers/moddump.rs
git commit --no-gpg-sign -m "feat(green): moddump + procdump — extract PE images from process VA space"
```
