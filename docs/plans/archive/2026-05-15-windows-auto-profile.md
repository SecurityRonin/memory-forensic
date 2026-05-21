# Windows Auto-Profile Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `AutoProfile::from_dump()` to `memf-symbols` so Windows walkers can resolve kernel struct offsets automatically from any dump, without hardcoded values.

**Architecture:** `kernel_scanner` scans physical pages for the ntoskrnl PE and extracts its `PdbId`; `auto_profile` chains that into a symserver download + `PdbResolver`; the caller gets a `Box<dyn SymbolResolver>` ready to drop into `ObjectReader`. The downloaded PDB is cached in `~/.memf/symbols/` so subsequent runs skip the network.

**Tech Stack:** `pdb` crate (PDB parsing), `goblin` (PE parsing), `ureq` (HTTP, behind `symserver` feature), `memf-format::PhysicalMemoryProvider` (dump abstraction), existing `pe_debug`, `symserver`, `pdb_resolver` modules.

**Design doc:** `docs/plans/2026-05-15-windows-auto-profile-design.md`

---

## Task 1: Add memf-format dependency + create kernel_scanner skeleton

**Files:**
- Modify: `crates/memf-symbols/Cargo.toml`
- Create: `crates/memf-symbols/src/kernel_scanner.rs`
- Modify: `crates/memf-symbols/src/lib.rs`

**Step 1: Add memf-format to memf-symbols Cargo.toml**

In `crates/memf-symbols/Cargo.toml`, add under `[dependencies]`:

```toml
memf-format = { workspace = true }
```

**Step 2: Write failing tests in kernel_scanner.rs**

Create `crates/memf-symbols/src/kernel_scanner.rs`:

```rust
//! Kernel PE scanner for Windows physical memory dumps.
//!
//! Scans physical pages for the ntoskrnl.exe MZ header and extracts
//! the PDB identification (GUID + age + filename) from its CodeView
//! debug directory.

use memf_format::PhysicalMemoryProvider;

use crate::pe_debug::PdbId;

/// Physical address range to scan for the kernel (1 MiB – 128 MiB).
/// The Windows kernel always loads within this window on x64 systems.
const SCAN_START: u64 = 0x0010_0000;
const SCAN_END: u64 = 0x0800_0000;
const PAGE_SIZE: usize = 0x1000;

/// Scan physical memory for ntoskrnl.exe and extract its PDB identification.
///
/// Searches page-aligned addresses from 1 MiB to 128 MiB for a valid
/// AMD64 PE image whose CodeView record identifies it as an ntoskrnl variant.
/// Returns `Error::NotFound` if no kernel PE is found in the scan window.
pub fn scan_for_kernel<P: PhysicalMemoryProvider>(mem: &P) -> crate::Result<PdbId> {
    let _ = mem;
    Err(crate::Error::NotFound("not implemented".into()))
}

/// Check whether a PDB filename looks like an ntoskrnl variant.
pub(crate) fn is_kernel_pdb_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("ntkrnl") || lower.contains("ntoskrnl")
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_format::{PhysicalRange, Result as FmtResult};

    /// Minimal in-memory PhysicalMemoryProvider for tests.
    struct FakeMem {
        data: Vec<u8>,
        base: u64,
    }

    impl FakeMem {
        fn new(base: u64, data: Vec<u8>) -> Self {
            Self { data, base }
        }
    }

    impl PhysicalMemoryProvider for FakeMem {
        fn read_phys(&self, addr: u64, buf: &mut [u8]) -> FmtResult<usize> {
            if addr < self.base {
                return Ok(0);
            }
            let off = (addr - self.base) as usize;
            if off >= self.data.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.data.len() - off);
            buf[..n].copy_from_slice(&self.data[off..off + n]);
            Ok(n)
        }

        fn ranges(&self) -> &[PhysicalRange] {
            &[]
        }

        fn format_name(&self) -> &str {
            "fake"
        }
    }

    /// Build a minimal AMD64 PE with a CodeView RSDS debug directory
    /// at the given base address in a flat Vec<u8>.
    fn build_kernel_pe(pdb_name: &str, guid: [u8; 16], age: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];

        // DOS header: MZ signature + e_lfanew = 0x40
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());

        // PE signature at 0x40
        buf[0x40..0x44].copy_from_slice(b"PE\0\0");

        // COFF header: Machine = 0x8664 (AMD64)
        buf[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
        // NumberOfSections = 0, SizeOfOptionalHeader
        buf[0x46..0x48].copy_from_slice(&0u16.to_le_bytes());
        buf[0x4c..0x4e].copy_from_slice(&0xf0u16.to_le_bytes()); // SizeOfOptionalHeader

        // Optional header: Magic = 0x20b (PE32+)
        buf[0x58..0x5a].copy_from_slice(&0x020bu16.to_le_bytes());

        // DataDirectory[6] = Debug directory (RVA=0x200, size=28)
        // DataDirectory starts at offset 0x70 in the optional header (0x58 + 0x18)
        let dd_offset = 0x58 + 0x60 + 6 * 8; // image optional header + 6 data dirs
        buf[dd_offset..dd_offset + 4].copy_from_slice(&0x200u32.to_le_bytes()); // RVA
        buf[dd_offset + 4..dd_offset + 8].copy_from_slice(&28u32.to_le_bytes()); // size

        // IMAGE_DEBUG_DIRECTORY at RVA 0x200 (we'll treat RVA == file offset for simplicity)
        // Type = 2 (IMAGE_DEBUG_TYPE_CODEVIEW)
        buf[0x200 + 12..0x200 + 16].copy_from_slice(&2u32.to_le_bytes());
        // SizeOfData (RSDS record size)
        let rsds_size = (4 + 16 + 4 + pdb_name.len() + 1) as u32;
        buf[0x200 + 16..0x200 + 20].copy_from_slice(&rsds_size.to_le_bytes());
        // AddressOfRawData / PointerToRawData = 0x240
        buf[0x200 + 20..0x200 + 24].copy_from_slice(&0x240u32.to_le_bytes());
        buf[0x200 + 24..0x200 + 28].copy_from_slice(&0x240u32.to_le_bytes());

        // CodeView RSDS record at 0x240
        buf[0x240..0x244].copy_from_slice(b"RSDS");
        buf[0x244..0x254].copy_from_slice(&guid);
        buf[0x254..0x258].copy_from_slice(&age.to_le_bytes());
        let name_bytes = pdb_name.as_bytes();
        buf[0x258..0x258 + name_bytes.len()].copy_from_slice(name_bytes);
        // null terminator already zeroed

        buf
    }

    #[test]
    fn is_kernel_pdb_name_accepts_variants() {
        assert!(is_kernel_pdb_name("ntoskrnl.pdb"));
        assert!(is_kernel_pdb_name("ntkrnlmp.pdb"));
        assert!(is_kernel_pdb_name("ntkrnlpa.pdb"));
        assert!(is_kernel_pdb_name("NTOSKRNL.PDB")); // case insensitive
    }

    #[test]
    fn is_kernel_pdb_name_rejects_others() {
        assert!(!is_kernel_pdb_name("notepad.pdb"));
        assert!(!is_kernel_pdb_name("hal.pdb"));
        assert!(!is_kernel_pdb_name(""));
    }

    #[test]
    fn scan_returns_not_found_on_empty_memory() {
        let mem = FakeMem::new(0, vec![0u8; 0x100]);
        let result = scan_for_kernel(&mem);
        assert!(matches!(result, Err(crate::Error::NotFound(_))));
    }

    #[test]
    fn scan_finds_kernel_pe_at_scan_start() {
        let guid = [
            0x1B, 0x72, 0x22, 0x4D, 0x37, 0xB8, 0x17, 0x92,
            0x28, 0x20, 0x0E, 0xD8, 0x99, 0x44, 0x98, 0xB2,
        ];
        let age = 1u32;
        let pe = build_kernel_pe("ntkrnlmp.pdb", guid, age);
        // Place the PE at exactly SCAN_START
        let mem = FakeMem::new(SCAN_START, pe);
        let pdb_id = scan_for_kernel(&mem).expect("should find kernel PE");
        assert_eq!(pdb_id.pdb_name, "ntkrnlmp.pdb");
        assert_eq!(pdb_id.age, age);
        assert!(pdb_id.guid.contains("1B72224D"));
    }

    #[test]
    fn scan_skips_pages_before_valid_pe() {
        let guid = [0xAA; 16];
        let pe = build_kernel_pe("ntoskrnl.pdb", guid, 2);
        // Place garbage before the PE, kernel at SCAN_START + 0x2000
        let offset = 0x2000usize;
        let mut data = vec![0xCC_u8; offset];
        data.extend_from_slice(&pe);
        let mem = FakeMem::new(SCAN_START, data);
        let pdb_id = scan_for_kernel(&mem).expect("should find kernel PE after garbage");
        assert_eq!(pdb_id.pdb_name, "ntoskrnl.pdb");
    }

    #[test]
    fn scan_rejects_non_amd64_pe() {
        let guid = [0xBB; 16];
        let mut pe = build_kernel_pe("ntoskrnl.pdb", guid, 1);
        // Patch Machine field to x86 (0x014c)
        pe[0x44..0x46].copy_from_slice(&0x014cu16.to_le_bytes());
        let mem = FakeMem::new(SCAN_START, pe);
        let result = scan_for_kernel(&mem);
        assert!(matches!(result, Err(crate::Error::NotFound(_))));
    }

    #[test]
    fn scan_rejects_non_kernel_pdb_name() {
        let guid = [0xCC; 16];
        let pe = build_kernel_pe("notepad.pdb", guid, 1);
        let mem = FakeMem::new(SCAN_START, pe);
        let result = scan_for_kernel(&mem);
        assert!(matches!(result, Err(crate::Error::NotFound(_))));
    }
}
```

**Step 3: Add module to lib.rs**

In `crates/memf-symbols/src/lib.rs`, add:

```rust
pub mod kernel_scanner;
```

**Step 4: Run tests to confirm RED**

```bash
cargo test -p memf-symbols 2>&1 | grep -E "FAILED|error|kernel_scanner"
```

Expected: compile error or test failures — `scan_for_kernel` stubs return `NotFound` so `scan_finds_kernel_pe_at_scan_start` and `scan_skips_pages_before_valid_pe` FAIL; the `is_kernel_pdb_name` and `scan_returns_not_found_on_empty_memory` and `scan_rejects_*` tests PASS.

**Step 5: RED commit**

```bash
git add crates/memf-symbols/Cargo.toml crates/memf-symbols/src/kernel_scanner.rs crates/memf-symbols/src/lib.rs
git commit --no-gpg-sign -m "test(red): kernel_scanner — scan physical memory for ntoskrnl PE"
```

---

## Task 2: Implement kernel_scanner

**Files:**
- Modify: `crates/memf-symbols/src/kernel_scanner.rs`

**Step 1: Replace the stub with the real implementation**

Replace the `scan_for_kernel` function body:

```rust
pub fn scan_for_kernel<P: PhysicalMemoryProvider>(mem: &P) -> crate::Result<PdbId> {
    let mut page = vec![0u8; PAGE_SIZE];

    let mut addr = SCAN_START;
    while addr < SCAN_END {
        let n = mem.read_phys(addr, &mut page).unwrap_or(0);
        if n < 2 {
            addr += PAGE_SIZE as u64;
            continue;
        }

        // Fast reject: check MZ signature
        if page[0] != b'M' || page[1] != b'Z' {
            addr += PAGE_SIZE as u64;
            continue;
        }

        // Try to read enough to parse the PE and extract PDB id.
        // Read up to 2 MiB starting at this page (most kernels are < 10 MiB
        // but the debug directory is near the start of the image).
        let mut pe_buf = vec![0u8; 0x10_0000]; // 1 MiB window
        let read = mem.read_phys(addr, &mut pe_buf).unwrap_or(0);
        if read < 0x100 {
            addr += PAGE_SIZE as u64;
            continue;
        }
        pe_buf.truncate(read);

        // Validate AMD64 PE
        if !is_amd64_pe(&pe_buf) {
            addr += PAGE_SIZE as u64;
            continue;
        }

        // Extract PDB id — skip non-kernel or broken PEs
        match crate::pe_debug::extract_pdb_id(&pe_buf) {
            Ok(pdb_id) if is_kernel_pdb_name(&pdb_id.pdb_name) => return Ok(pdb_id),
            _ => {}
        }

        addr += PAGE_SIZE as u64;
    }

    Err(crate::Error::NotFound(
        "kernel PE not found in physical memory scan window (1 MiB–128 MiB)".into(),
    ))
}

/// Quick AMD64 PE validation: checks DOS header, e_lfanew, PE signature, Machine.
fn is_amd64_pe(buf: &[u8]) -> bool {
    if buf.len() < 0x60 {
        return false;
    }
    // e_lfanew at 0x3c
    let e_lfanew = u32::from_le_bytes(buf[0x3c..0x40].try_into().unwrap()) as usize;
    if e_lfanew + 6 > buf.len() {
        return false;
    }
    // PE\0\0 signature
    if &buf[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return false;
    }
    // Machine == IMAGE_FILE_MACHINE_AMD64 (0x8664)
    let machine = u16::from_le_bytes(buf[e_lfanew + 4..e_lfanew + 6].try_into().unwrap());
    machine == 0x8664
}
```

**Step 2: Run tests — expect GREEN**

```bash
cargo test -p memf-symbols kernel_scanner 2>&1 | tail -15
```

Expected: all 7 `kernel_scanner` tests pass.

**Step 3: Run full suite**

```bash
cargo test -p memf-symbols 2>&1 | tail -5
```

Expected: all tests pass, 0 failures.

**Step 4: GREEN commit**

```bash
git add crates/memf-symbols/src/kernel_scanner.rs
git commit --no-gpg-sign -m "feat(green): kernel_scanner — scan physical pages for ntoskrnl PE + PdbId"
```

---

## Task 3: Write auto_profile tests (RED)

**Files:**
- Create: `crates/memf-symbols/src/auto_profile.rs`
- Modify: `crates/memf-symbols/src/lib.rs`

**Step 1: Create auto_profile.rs with stub + tests**

```rust
//! High-level Windows kernel profile resolution.
//!
//! Chains kernel PE scanning → PDB download/cache → `PdbResolver` into a
//! single `AutoProfile` entry point.

use std::path::{Path, PathBuf};

use crate::pe_debug::{extract_pdb_id, PdbId};
use crate::pdb_resolver::PdbResolver;
use crate::symserver::{self, SymbolServerClient};
use crate::SymbolResolver;

/// Orchestrates automatic Windows kernel profile resolution.
///
/// On first use, downloads the correct `ntoskrnl.pdb` from Microsoft's
/// symbol server and caches it in `cache_dir`. Subsequent runs load from
/// the cache without network access.
pub struct AutoProfile {
    cache_dir: PathBuf,
}

impl AutoProfile {
    /// Create with the default cache directory (`~/.memf/symbols/`).
    pub fn new() -> crate::Result<Self> {
        let cache_dir = symserver::default_cache_dir()
            .ok_or_else(|| crate::Error::Cache("HOME not set".into()))?;
        Ok(Self { cache_dir })
    }

    /// Create with an explicit cache directory (useful in tests).
    pub fn with_cache_dir(dir: impl Into<PathBuf>) -> Self {
        Self { cache_dir: dir.into() }
    }

    /// Resolve a profile from a pre-known `PdbId`.
    ///
    /// Checks the local cache first. Downloads from Microsoft's symbol server
    /// if not cached. Returns a `SymbolResolver` backed by the parsed PDB.
    pub fn from_pdb_id(&self, pdb_id: &PdbId) -> crate::Result<Box<dyn SymbolResolver>> {
        let _ = pdb_id;
        Err(crate::Error::NotFound("not implemented".into()))
    }

    /// Resolve a profile from a raw ntoskrnl.exe PE image.
    ///
    /// Parses the PE debug directory to extract the `PdbId`, then delegates
    /// to `from_pdb_id`.
    pub fn from_pe_bytes(&self, pe_bytes: &[u8]) -> crate::Result<Box<dyn SymbolResolver>> {
        let pdb_id = extract_pdb_id(pe_bytes)?;
        self.from_pdb_id(&pdb_id)
    }

    /// Resolve a profile by scanning a physical memory dump for ntoskrnl.
    ///
    /// Falls back gracefully: if the scan fails the caller should retry with
    /// `from_pe_bytes` or `from_pdb_id`.
    pub fn from_dump<P: memf_format::PhysicalMemoryProvider>(
        &self,
        mem: &P,
    ) -> crate::Result<Box<dyn SymbolResolver>> {
        let pdb_id = crate::kernel_scanner::scan_for_kernel(mem)?;
        self.from_pdb_id(&pdb_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Seed a pre-built PdbResolver (from PdbParsedData) as a fake cached PDB
    /// by writing a minimal PDB stub that the resolver can load.
    ///
    /// Since we don't want network calls in unit tests, we instead test
    /// `from_pdb_id` by pre-seeding the cache with a real PDB fixture,
    /// or by testing the cache-path logic and error path independently.

    #[test]
    fn with_cache_dir_stores_path() {
        let tmp = TempDir::new().unwrap();
        let profile = AutoProfile::with_cache_dir(tmp.path());
        assert_eq!(profile.cache_dir, tmp.path());
    }

    #[test]
    fn from_pdb_id_returns_error_when_cache_empty_and_no_network() {
        // With an empty cache dir and symserver disabled (we don't call
        // SymbolServerClient here), from_pdb_id must not panic.
        // It should return an error (either NotFound or Network).
        let tmp = TempDir::new().unwrap();
        let profile = AutoProfile::with_cache_dir(tmp.path());
        let pdb_id = PdbId {
            guid: "1B72224D-37B8-1792-2820-0ED8994498B2".into(),
            age: 1,
            pdb_name: "ntkrnlmp.pdb".into(),
        };
        let result = profile.from_pdb_id(&pdb_id);
        assert!(result.is_err(), "must error when cache empty and no download");
    }

    #[test]
    fn from_pe_bytes_propagates_malformed_error() {
        let tmp = TempDir::new().unwrap();
        let profile = AutoProfile::with_cache_dir(tmp.path());
        // Garbage bytes — not a PE
        let result = profile.from_pe_bytes(b"not a PE");
        assert!(matches!(result, Err(crate::Error::Malformed(_))));
    }

    #[test]
    fn from_pdb_id_uses_cached_pdb_when_present() {
        // Pre-seed the cache with a minimal real PDB file.
        // Use the pdb_resolver test fixture if available; otherwise skip.
        // This test proves the cache-hit path runs without network.
        //
        // We use PdbResolver::from_bytes with an empty-ish synthetic PDB.
        // If the pdb crate rejects a zero-byte file, skip gracefully.
        let tmp = TempDir::new().unwrap();
        let pdb_id = PdbId {
            guid: "AABBCCDD-1122-3344-5566-778899AABBCC".into(),
            age: 1,
            pdb_name: "ntoskrnl.pdb".into(),
        };
        let cached = symserver::cache_path(tmp.path(), &pdb_id.pdb_name, &pdb_id.guid, pdb_id.age);
        fs::create_dir_all(cached.parent().unwrap()).unwrap();
        // Write a valid minimal PDB — use an actually-parseable PDB fixture
        // from the pdb_resolver test. If we don't have one, just verify the
        // cache-path is checked (error will be Pdb, not Network).
        fs::write(&cached, b"").unwrap(); // zero-byte placeholder

        let profile = AutoProfile::with_cache_dir(tmp.path());
        let result = profile.from_pdb_id(&pdb_id);
        // With a zero-byte cached file: PDB parse error, NOT a network error.
        // This proves the cache-hit path was taken (no download attempted).
        assert!(
            matches!(result, Err(crate::Error::Pdb(_)) | Err(crate::Error::Malformed(_))),
            "expected Pdb/Malformed parse error from cached stub, got: {result:?}"
        );
    }

    #[test]
    #[ignore = "requires internet + Windows dump fixture"]
    fn from_dump_downloads_real_pdb_integration() {
        // Run manually: cargo test -p memf-symbols -- --ignored
        // Requires: a Windows physical memory dump at /tmp/win.dmp
        use memf_format::open_dump;
        let dump = open_dump("/tmp/win.dmp").expect("dump not found");
        let profile = AutoProfile::new().expect("HOME not set");
        let resolver = profile.from_dump(dump.as_ref()).expect("auto-profile failed");
        let pid_offset = resolver
            .field_offset("_EPROCESS", "UniqueProcessId")
            .expect("UniqueProcessId not found");
        assert!(pid_offset > 0, "UniqueProcessId offset should be non-zero");
    }
}
```

**Step 2: Add module to lib.rs**

```rust
pub mod auto_profile;
```

**Step 3: Run tests — confirm RED**

```bash
cargo test -p memf-symbols auto_profile 2>&1 | tail -20
```

Expected: compile error (`not implemented` stub means `from_pdb_id_returns_error_when_cache_empty` might pass accidentally, but `from_pdb_id_uses_cached_pdb_when_present` will also pass since both hit the stub error). The important thing is that it compiles and the structure is correct.

**Step 4: RED commit**

```bash
git add crates/memf-symbols/src/auto_profile.rs crates/memf-symbols/src/lib.rs
git commit --no-gpg-sign -m "test(red): auto_profile — cache-hit path, PE error propagation, no-network error"
```

---

## Task 4: Implement auto_profile

**Files:**
- Modify: `crates/memf-symbols/src/auto_profile.rs`

**Step 1: Replace the `from_pdb_id` stub**

```rust
pub fn from_pdb_id(&self, pdb_id: &PdbId) -> crate::Result<Box<dyn SymbolResolver>> {
    let cached = symserver::cache_path(&self.cache_dir, &pdb_id.pdb_name, &pdb_id.guid, pdb_id.age);

    if !cached.exists() {
        // Download from Microsoft symbol server
        let client = SymbolServerClient::new(
            symserver::default_server_url(),
            &self.cache_dir,
        );
        client.get_pdb(&pdb_id.pdb_name, &pdb_id.guid, pdb_id.age)?;
    }

    let resolver = PdbResolver::from_path(&cached)?;
    Ok(Box::new(resolver))
}
```

**Step 2: Run tests**

```bash
cargo test -p memf-symbols auto_profile 2>&1 | tail -20
```

Expected:
- `with_cache_dir_stores_path` — PASS
- `from_pe_bytes_propagates_malformed_error` — PASS  
- `from_pdb_id_returns_error_when_cache_empty_and_no_network` — PASS (network error since no internet in test)
- `from_pdb_id_uses_cached_pdb_when_present` — PASS (Pdb/Malformed error from zero-byte stub, proves cache-hit path)
- `from_dump_downloads_real_pdb_integration` — IGNORED

**Step 3: Run full suite**

```bash
cargo test -p memf-symbols 2>&1 | tail -5
```

Expected: all tests pass.

**Step 4: GREEN commit**

```bash
git add crates/memf-symbols/src/auto_profile.rs
git commit --no-gpg-sign -m "feat(green): auto_profile — AutoProfile::from_dump/from_pe_bytes/from_pdb_id"
```

---

## Task 5: Wire AutoProfile into memf-symbols public API + docs

**Files:**
- Modify: `crates/memf-symbols/src/lib.rs`

**Step 1: Re-export AutoProfile at crate root**

In `crates/memf-symbols/src/lib.rs`, add:

```rust
pub use auto_profile::AutoProfile;
pub use kernel_scanner::scan_for_kernel;
```

**Step 2: Add doc example to lib.rs module doc**

Extend the module-level doc comment:

```rust
//! ## Windows auto-profile (requires `symserver` feature)
//!
//! ```no_run
//! use memf_symbols::AutoProfile;
//!
//! # fn example() -> memf_symbols::Result<()> {
//! // Scan a physical dump, download the matching PDB, return a resolver.
//! // let dump = memf_format::open_dump("win10.dmp")?;
//! // let resolver = AutoProfile::new()?.from_dump(dump.as_ref())?;
//! // let pid_off = resolver.field_offset("_EPROCESS", "UniqueProcessId");
//! # Ok(())
//! # }
//! ```
```

**Step 3: Run full workspace test**

```bash
cargo test 2>&1 | tail -5
```

Expected: all tests pass, 0 failures.

**Step 4: Final commit**

```bash
git add crates/memf-symbols/src/lib.rs
git commit --no-gpg-sign -m "feat: re-export AutoProfile + scan_for_kernel at memf-symbols crate root"
```

---

## Execution Checklist

- [ ] Task 1: Cargo.toml + kernel_scanner.rs skeleton + RED commit
- [ ] Task 2: Implement scan_for_kernel + GREEN commit
- [ ] Task 3: auto_profile.rs skeleton + RED commit
- [ ] Task 4: Implement AutoProfile::from_pdb_id + GREEN commit
- [ ] Task 5: Public API re-exports + final commit

## Testing the full flow manually

After all tasks are complete, run the integration test with a real dump:

```bash
# Requires a Windows dump at /tmp/win.dmp and internet access
cargo test -p memf-symbols -- --ignored --nocapture
```

To pre-seed the symbol cache without a dump (for offline use):

```bash
# Download manually: GUID from `ewfverify` or WinDbg `.sympath` output
curl -L "https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/1B72224D37B8179228200ED8994498B21/ntkrnlmp.pdb" \
  -o ~/.memf/symbols/ntkrnlmp.pdb/1B72224D37B8179228200ED8994498B21/ntkrnlmp.pdb
```
