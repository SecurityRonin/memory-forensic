# Phase 3F-A: Pagefile & Swapfile Overlay — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the VirtualAddressSpace page table walker in memf-core to transparently resolve paged-out virtual memory using pagefile.sys and swapfile.sys sources.

**Architecture:** When the x86_64 walker encounters a non-present PTE at the PT level, a new PTE decoder classifies it as demand-zero, transition, prototype, or pagefile. A `PagefileSource` trait backed by mmap'd providers supplies the paged-out data. `read_virt()` transparently routes each 4K chunk to the correct source (physical RAM, pagefile, or demand-zero fill).

**Tech Stack:** Rust, `memmap2` (memory-mapped file I/O), `rust-lzxpress` (Xpress decompression for swapfile.sys, already in workspace), `thiserror` (existing).

---

## File Structure

```
crates/memf-core/
├── src/
│   ├── lib.rs              # MODIFY: add PagedOut + PrototypePte error variants,
│   │                       #         add #[non_exhaustive], pub mod pagefile
│   ├── vas.rs              # MODIFY: TranslationResult enum, PTE decoder,
│   │                       #         pagefiles field + builder, read_virt fallback
│   ├── pagefile.rs         # CREATE: PagefileSource trait, PagefileProvider,
│   │                       #         SwapfileProvider
│   ├── test_builders.rs    # MODIFY: map_pagefile_pte, map_transition_pte,
│   │                       #         map_demand_zero, map_prototype_pte,
│   │                       #         MockPagefileSource
│   └── object_reader.rs    # NO CHANGE
├── Cargo.toml              # MODIFY: add memmap2, rust-lzxpress dependencies
```

---

### Task 1: Add Dependencies and Error Variants

**Files:**
- Modify: `crates/memf-core/Cargo.toml`
- Modify: `crates/memf-core/src/lib.rs`

This task adds the `memmap2` and `rust-lzxpress` dependencies to `memf-core` and extends the `Error` enum with `PagedOut` and `PrototypePte` variants. Also adds `#[non_exhaustive]` to the Error enum and declares `pub mod pagefile`.

- [ ] **Step 1: Write failing tests for new error variants**

Add to the bottom of the `#[cfg(test)] mod tests` block in `crates/memf-core/src/lib.rs`:

```rust
    #[test]
    fn error_display_paged_out() {
        let e = Error::PagedOut {
            vaddr: 0xFFFF_8000_0000_2000,
            pagefile_num: 0,
            page_offset: 0x1234,
        };
        let msg = e.to_string();
        assert!(msg.contains("0xffff800000002000"));
        assert!(msg.contains("pagefile 0"));
        assert!(msg.contains("0x1234"));
    }

    #[test]
    fn error_display_prototype_pte() {
        let e = Error::PrototypePte(0xFFFF_8000_DEAD_0000);
        let msg = e.to_string();
        assert!(msg.contains("0xffff8000dead0000"));
        assert!(msg.contains("prototype PTE"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-core --lib -- error_display_paged_out error_display_prototype_pte 2>&1`
Expected: FAIL — `PagedOut` and `PrototypePte` variants don't exist yet.

- [ ] **Step 3: Add dependencies to Cargo.toml**

In `crates/memf-core/Cargo.toml`, add to `[dependencies]`:

```toml
memmap2.workspace = true
rust-lzxpress.workspace = true
```

- [ ] **Step 4: Add error variants and pagefile module declaration**

In `crates/memf-core/src/lib.rs`:

1. Add `#[non_exhaustive]` attribute above the `Error` enum.
2. Add two new variants after `ListCycle`:

```rust
    /// Page is in a pagefile that was not provided.
    #[error("page at {vaddr:#018x} paged out to pagefile {pagefile_num} offset {page_offset:#x}")]
    PagedOut {
        /// Virtual address of the faulting page.
        vaddr: u64,
        /// Pagefile number (0 = pagefile.sys, 1-15 = secondary).
        pagefile_num: u8,
        /// Page offset within the pagefile.
        page_offset: u64,
    },

    /// Page uses a prototype PTE (shared section, not yet supported).
    #[error("prototype PTE at {0:#018x} (not yet supported)")]
    PrototypePte(u64),
```

3. Add `pub mod pagefile;` after the existing module declarations (after `pub mod vas;`).

- [ ] **Step 5: Create empty pagefile module**

Create `crates/memf-core/src/pagefile.rs`:

```rust
//! Pagefile and swapfile sources for resolving paged-out memory.
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-core --lib 2>&1`
Expected: All tests pass including the two new ones. Existing tests remain green.

- [ ] **Step 7: Commit**

```bash
git add crates/memf-core/Cargo.toml crates/memf-core/src/lib.rs crates/memf-core/src/pagefile.rs
git commit --no-gpg-sign -m "feat(core): add PagedOut + PrototypePte error variants and pagefile module

Add #[non_exhaustive] to Error enum. Add memmap2 and rust-lzxpress deps."
```

---

### Task 2: PagefileSource Trait and MockPagefileSource

**Files:**
- Modify: `crates/memf-core/src/pagefile.rs`
- Modify: `crates/memf-core/src/test_builders.rs`

This task creates the `PagefileSource` trait and a `MockPagefileSource` test helper.

- [ ] **Step 1: Write failing tests for MockPagefileSource**

Add to the bottom of the `#[cfg(test)] mod tests` block in `crates/memf-core/src/test_builders.rs`:

```rust
    #[test]
    fn mock_pagefile_source_read_page() {
        use crate::pagefile::PagefileSource;

        let mut page_data = [0xABu8; 4096];
        page_data[0] = 0x42;
        let mock = MockPagefileSource::new(0, vec![(0x10, page_data)]);
        assert_eq!(mock.pagefile_number(), 0);
        let page = mock.read_page(0x10).unwrap().unwrap();
        assert_eq!(page[0], 0x42);
        assert_eq!(page[1], 0xAB);
    }

    #[test]
    fn mock_pagefile_source_missing_page() {
        use crate::pagefile::PagefileSource;

        let mock = MockPagefileSource::new(1, vec![]);
        assert_eq!(mock.pagefile_number(), 1);
        assert!(mock.read_page(0x999).unwrap().is_none());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-core --lib -- mock_pagefile_source 2>&1`
Expected: FAIL — `MockPagefileSource` doesn't exist yet.

- [ ] **Step 3: Implement PagefileSource trait**

In `crates/memf-core/src/pagefile.rs`:

```rust
//! Pagefile and swapfile sources for resolving paged-out memory.

use crate::Result;

/// A source of paged-out memory pages (pagefile.sys, swapfile.sys, etc.).
pub trait PagefileSource: Send + Sync {
    /// Which pagefile number this source handles (0 = pagefile.sys, 1-15 = secondary).
    fn pagefile_number(&self) -> u8;

    /// Read a 4KB page at the given page offset.
    /// Returns `Ok(None)` if the offset is beyond the file's page count.
    fn read_page(&self, page_offset: u64) -> Result<Option<[u8; 4096]>>;
}
```

- [ ] **Step 4: Implement MockPagefileSource in test_builders.rs**

Add at the end of `crates/memf-core/src/test_builders.rs` (before the `#[cfg(test)]` module):

```rust
/// Mock pagefile source for testing pagefile PTE resolution.
pub struct MockPagefileSource {
    pagefile_num: u8,
    pages: std::collections::HashMap<u64, [u8; 4096]>,
}

impl MockPagefileSource {
    /// Create a mock with the given pagefile number and pre-loaded pages.
    /// Each tuple is `(page_offset, page_data)`.
    pub fn new(pagefile_num: u8, pages: Vec<(u64, [u8; 4096])>) -> Self {
        Self {
            pagefile_num,
            pages: pages.into_iter().collect(),
        }
    }
}

impl crate::pagefile::PagefileSource for MockPagefileSource {
    fn pagefile_number(&self) -> u8 {
        self.pagefile_num
    }

    fn read_page(&self, page_offset: u64) -> crate::Result<Option<[u8; 4096]>> {
        Ok(self.pages.get(&page_offset).copied())
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-core --lib -- mock_pagefile_source 2>&1`
Expected: Both tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/memf-core/src/pagefile.rs crates/memf-core/src/test_builders.rs
git commit --no-gpg-sign -m "feat(core): add PagefileSource trait and MockPagefileSource test helper"
```

---

### Task 3: PageTableBuilder Non-Present PTE Helpers

**Files:**
- Modify: `crates/memf-core/src/test_builders.rs`

This task extends `PageTableBuilder` with methods to inject non-present PTEs: demand-zero, transition, prototype, and pagefile PTEs. These are needed by all subsequent VAS tests.

- [ ] **Step 1: Write failing tests for new PTE builder methods**

Add to the `#[cfg(test)] mod tests` block in `crates/memf-core/src/test_builders.rs`:

```rust
    #[test]
    fn page_table_builder_map_demand_zero() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_demand_zero(vaddr)
            .build();
        // Walk to the PT level and verify PTE == 0
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pml4e = mem.read_u64(cr3 + pml4_idx * 8);
        assert_ne!(pml4e & flags::PRESENT, 0, "PML4 entry should be present");
        let pdpt_base = pml4e & PageTableBuilder::ADDR_MASK;
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pdpte = mem.read_u64(pdpt_base + pdpt_idx * 8);
        assert_ne!(pdpte & flags::PRESENT, 0, "PDPT entry should be present");
        let pd_base = pdpte & PageTableBuilder::ADDR_MASK;
        let pd_idx = (vaddr >> 21) & 0x1FF;
        let pde = mem.read_u64(pd_base + pd_idx * 8);
        assert_ne!(pde & flags::PRESENT, 0, "PD entry should be present");
        let pt_base = pde & PageTableBuilder::ADDR_MASK;
        let pt_idx = (vaddr >> 12) & 0x1FF;
        let pte = mem.read_u64(pt_base + pt_idx * 8);
        assert_eq!(pte, 0, "demand-zero PTE must be all zeros");
    }

    #[test]
    fn page_table_builder_map_transition_pte() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let pfn: u64 = 0x800; // PFN 0x800 = paddr 0x80_0000
        let (cr3, mem) = PageTableBuilder::new()
            .map_transition(vaddr, pfn)
            .build();
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pml4e = mem.read_u64(cr3 + pml4_idx * 8);
        let pdpt_base = pml4e & PageTableBuilder::ADDR_MASK;
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pdpte = mem.read_u64(pdpt_base + pdpt_idx * 8);
        let pd_base = pdpte & PageTableBuilder::ADDR_MASK;
        let pd_idx = (vaddr >> 21) & 0x1FF;
        let pde = mem.read_u64(pd_base + pd_idx * 8);
        let pt_base = pde & PageTableBuilder::ADDR_MASK;
        let pt_idx = (vaddr >> 12) & 0x1FF;
        let pte = mem.read_u64(pt_base + pt_idx * 8);
        // Bit 0 clear (not present), bit 11 set (transition), PFN in bits 12-51
        assert_eq!(pte & 1, 0, "PRESENT must be clear");
        assert_ne!(pte & (1 << 11), 0, "TRANSITION bit must be set");
        assert_eq!((pte >> 12) & 0xF_FFFF_FFFF, pfn, "PFN must match");
    }

    #[test]
    fn page_table_builder_map_pagefile_pte() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let pagefile_num: u8 = 0;
        let page_offset: u64 = 0x5678;
        let (cr3, mem) = PageTableBuilder::new()
            .map_pagefile(vaddr, pagefile_num, page_offset)
            .build();
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pml4e = mem.read_u64(cr3 + pml4_idx * 8);
        let pdpt_base = pml4e & PageTableBuilder::ADDR_MASK;
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pdpte = mem.read_u64(pdpt_base + pdpt_idx * 8);
        let pd_base = pdpte & PageTableBuilder::ADDR_MASK;
        let pd_idx = (vaddr >> 21) & 0x1FF;
        let pde = mem.read_u64(pd_base + pd_idx * 8);
        let pt_base = pde & PageTableBuilder::ADDR_MASK;
        let pt_idx = (vaddr >> 12) & 0x1FF;
        let pte = mem.read_u64(pt_base + pt_idx * 8);
        // Bit 0 clear, bits 1-4 = pagefile_num, bit 10 clear, bit 11 clear, bits 12-51 = page_offset
        assert_eq!(pte & 1, 0, "PRESENT must be clear");
        assert_eq!((pte >> 1) & 0xF, pagefile_num as u64, "pagefile_num");
        assert_eq!(pte & (1 << 10), 0, "prototype bit must be clear");
        assert_eq!(pte & (1 << 11), 0, "transition bit must be clear");
        assert_eq!((pte >> 12) & 0xF_FFFF_FFFF, page_offset, "page_offset");
    }

    #[test]
    fn page_table_builder_map_prototype_pte() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_prototype(vaddr)
            .build();
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pml4e = mem.read_u64(cr3 + pml4_idx * 8);
        let pdpt_base = pml4e & PageTableBuilder::ADDR_MASK;
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pdpte = mem.read_u64(pdpt_base + pdpt_idx * 8);
        let pd_base = pdpte & PageTableBuilder::ADDR_MASK;
        let pd_idx = (vaddr >> 21) & 0x1FF;
        let pde = mem.read_u64(pd_base + pd_idx * 8);
        let pt_base = pde & PageTableBuilder::ADDR_MASK;
        let pt_idx = (vaddr >> 12) & 0x1FF;
        let pte = mem.read_u64(pt_base + pt_idx * 8);
        assert_eq!(pte & 1, 0, "PRESENT must be clear");
        assert_ne!(pte & (1 << 10), 0, "PROTOTYPE bit must be set");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-core --lib -- page_table_builder_map_demand_zero page_table_builder_map_transition page_table_builder_map_pagefile page_table_builder_map_prototype 2>&1`
Expected: FAIL — methods don't exist yet.

- [ ] **Step 3: Implement the builder methods**

Add to the `impl PageTableBuilder` block in `crates/memf-core/src/test_builders.rs`, after the existing `map_1g` method:

```rust
    /// Set up page table entries so the final PT level entry for `vaddr` is 0 (demand-zero).
    /// Upper levels (PML4, PDPT, PD) are present; the PT entry itself is zero.
    pub fn map_demand_zero(mut self, vaddr: u64) -> Self {
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pd_idx = (vaddr >> 21) & 0x1FF;

        // Ensure PML4 -> PDPT
        let pml4e_addr = self.cr3 + pml4_idx * 8;
        let mut pml4e = self.mem.read_u64(pml4e_addr);
        if pml4e & flags::PRESENT == 0 {
            let pdpt_page = self.alloc_page();
            pml4e = pdpt_page | flags::PRESENT | flags::WRITABLE;
            self.mem.write_u64(pml4e_addr, pml4e);
        }
        let pdpt_base = pml4e & Self::ADDR_MASK;

        // Ensure PDPT -> PD
        let pdpte_addr = pdpt_base + pdpt_idx * 8;
        let mut pdpte = self.mem.read_u64(pdpte_addr);
        if pdpte & flags::PRESENT == 0 {
            let pd_page = self.alloc_page();
            pdpte = pd_page | flags::PRESENT | flags::WRITABLE;
            self.mem.write_u64(pdpte_addr, pdpte);
        }
        let pd_base = pdpte & Self::ADDR_MASK;

        // Ensure PD -> PT
        let pde_addr = pd_base + pd_idx * 8;
        let mut pde = self.mem.read_u64(pde_addr);
        if pde & flags::PRESENT == 0 {
            let pt_page = self.alloc_page();
            pde = pt_page | flags::PRESENT | flags::WRITABLE;
            self.mem.write_u64(pde_addr, pde);
        }

        // PT entry is left as 0 (demand-zero) — already zero from page allocation
        self
    }

    /// Set up a transition PTE: bit 0 clear, bit 11 set, PFN in bits 12-51.
    pub fn map_transition(mut self, vaddr: u64, pfn: u64) -> Self {
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pd_idx = (vaddr >> 21) & 0x1FF;
        let pt_idx = (vaddr >> 12) & 0x1FF;

        // Ensure upper levels
        let pml4e_addr = self.cr3 + pml4_idx * 8;
        let mut pml4e = self.mem.read_u64(pml4e_addr);
        if pml4e & flags::PRESENT == 0 {
            let pdpt_page = self.alloc_page();
            pml4e = pdpt_page | flags::PRESENT | flags::WRITABLE;
            self.mem.write_u64(pml4e_addr, pml4e);
        }
        let pdpt_base = pml4e & Self::ADDR_MASK;

        let pdpte_addr = pdpt_base + pdpt_idx * 8;
        let mut pdpte = self.mem.read_u64(pdpte_addr);
        if pdpte & flags::PRESENT == 0 {
            let pd_page = self.alloc_page();
            pdpte = pd_page | flags::PRESENT | flags::WRITABLE;
            self.mem.write_u64(pdpte_addr, pdpte);
        }
        let pd_base = pdpte & Self::ADDR_MASK;

        let pde_addr = pd_base + pd_idx * 8;
        let mut pde = self.mem.read_u64(pde_addr);
        if pde & flags::PRESENT == 0 {
            let pt_page = self.alloc_page();
            pde = pt_page | flags::PRESENT | flags::WRITABLE;
            self.mem.write_u64(pde_addr, pde);
        }
        let pt_base = pde & Self::ADDR_MASK;

        // Transition PTE: bit 0 = 0, bit 11 = 1, PFN in bits 12-51
        let pte = (pfn << 12) | (1 << 11);
        self.mem.write_u64(pt_base + pt_idx * 8, pte);
        self
    }

    /// Set up a pagefile PTE: bit 0 clear, bits 1-4 = pagefile_num, bits 12-51 = page_offset.
    pub fn map_pagefile(mut self, vaddr: u64, pagefile_num: u8, page_offset: u64) -> Self {
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pd_idx = (vaddr >> 21) & 0x1FF;
        let pt_idx = (vaddr >> 12) & 0x1FF;

        // Ensure upper levels
        let pml4e_addr = self.cr3 + pml4_idx * 8;
        let mut pml4e = self.mem.read_u64(pml4e_addr);
        if pml4e & flags::PRESENT == 0 {
            let pdpt_page = self.alloc_page();
            pml4e = pdpt_page | flags::PRESENT | flags::WRITABLE;
            self.mem.write_u64(pml4e_addr, pml4e);
        }
        let pdpt_base = pml4e & Self::ADDR_MASK;

        let pdpte_addr = pdpt_base + pdpt_idx * 8;
        let mut pdpte = self.mem.read_u64(pdpte_addr);
        if pdpte & flags::PRESENT == 0 {
            let pd_page = self.alloc_page();
            pdpte = pd_page | flags::PRESENT | flags::WRITABLE;
            self.mem.write_u64(pdpte_addr, pdpte);
        }
        let pd_base = pdpte & Self::ADDR_MASK;

        let pde_addr = pd_base + pd_idx * 8;
        let mut pde = self.mem.read_u64(pde_addr);
        if pde & flags::PRESENT == 0 {
            let pt_page = self.alloc_page();
            pde = pt_page | flags::PRESENT | flags::WRITABLE;
            self.mem.write_u64(pde_addr, pde);
        }
        let pt_base = pde & Self::ADDR_MASK;

        // Pagefile PTE: bit 0 = 0, bits 1-4 = pagefile_num, bit 10 = 0, bit 11 = 0, bits 12-51 = page_offset
        let pte = ((pagefile_num as u64 & 0xF) << 1) | (page_offset << 12);
        self.mem.write_u64(pt_base + pt_idx * 8, pte);
        self
    }

    /// Set up a prototype PTE: bit 0 clear, bit 10 set.
    pub fn map_prototype(mut self, vaddr: u64) -> Self {
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pd_idx = (vaddr >> 21) & 0x1FF;
        let pt_idx = (vaddr >> 12) & 0x1FF;

        // Ensure upper levels
        let pml4e_addr = self.cr3 + pml4_idx * 8;
        let mut pml4e = self.mem.read_u64(pml4e_addr);
        if pml4e & flags::PRESENT == 0 {
            let pdpt_page = self.alloc_page();
            pml4e = pdpt_page | flags::PRESENT | flags::WRITABLE;
            self.mem.write_u64(pml4e_addr, pml4e);
        }
        let pdpt_base = pml4e & Self::ADDR_MASK;

        let pdpte_addr = pdpt_base + pdpt_idx * 8;
        let mut pdpte = self.mem.read_u64(pdpte_addr);
        if pdpte & flags::PRESENT == 0 {
            let pd_page = self.alloc_page();
            pdpte = pd_page | flags::PRESENT | flags::WRITABLE;
            self.mem.write_u64(pdpte_addr, pdpte);
        }
        let pd_base = pdpte & Self::ADDR_MASK;

        let pde_addr = pd_base + pd_idx * 8;
        let mut pde = self.mem.read_u64(pde_addr);
        if pde & flags::PRESENT == 0 {
            let pt_page = self.alloc_page();
            pde = pt_page | flags::PRESENT | flags::WRITABLE;
            self.mem.write_u64(pde_addr, pde);
        }
        let pt_base = pde & Self::ADDR_MASK;

        // Prototype PTE: bit 0 = 0, bit 10 = 1
        let pte: u64 = 1 << 10;
        self.mem.write_u64(pt_base + pt_idx * 8, pte);
        self
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-core --lib -- page_table_builder_map_ 2>&1`
Expected: All 4 new tests + 2 mock tests + existing tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/memf-core/src/test_builders.rs
git commit --no-gpg-sign -m "feat(core): add PageTableBuilder helpers for non-present PTE types

map_demand_zero, map_transition, map_pagefile, map_prototype for testing
pagefile overlay resolution."
```

---

### Task 4: PTE Decoder and TranslationResult Enum

**Files:**
- Modify: `crates/memf-core/src/vas.rs`

This is the core PTE decoding logic. The `walk_x86_64_4level` method gains an internal `TranslationResult` enum and classifies non-present PTEs at the PT level. `virt_to_phys()` maps results to existing error types.

- [ ] **Step 1: Write failing tests for PTE decoding**

Add to the `#[cfg(test)] mod tests` block in `crates/memf-core/src/vas.rs`:

```rust
    #[test]
    fn demand_zero_pte_returns_page_not_present() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_demand_zero(vaddr)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let result = vas.virt_to_phys(vaddr);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::PageNotPresent(addr) => assert_eq!(addr, vaddr),
            other => panic!("expected PageNotPresent, got: {other}"),
        }
    }

    #[test]
    fn transition_pte_resolves_to_physical() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let pfn: u64 = 0x800; // physical addr = 0x80_0000
        let (cr3, mem) = PageTableBuilder::new()
            .map_transition(vaddr, pfn)
            .write_phys(pfn * 0x1000, &[0xDE, 0xAD, 0xBE, 0xEF])
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let paddr = vas.virt_to_phys(vaddr).unwrap();
        assert_eq!(paddr, pfn * 0x1000);
    }

    #[test]
    fn transition_pte_with_offset() {
        let vaddr_base: u64 = 0xFFFF_8000_0010_0000;
        let vaddr: u64 = vaddr_base + 0x42;
        let pfn: u64 = 0x800;
        let (cr3, mem) = PageTableBuilder::new()
            .map_transition(vaddr_base, pfn)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let paddr = vas.virt_to_phys(vaddr).unwrap();
        assert_eq!(paddr, pfn * 0x1000 + 0x42);
    }

    #[test]
    fn prototype_pte_returns_error() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_prototype(vaddr)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let result = vas.virt_to_phys(vaddr);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::PrototypePte(addr) => assert_eq!(addr, vaddr),
            other => panic!("expected PrototypePte, got: {other}"),
        }
    }

    #[test]
    fn pagefile_pte_returns_paged_out() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_pagefile(vaddr, 0, 0x1234)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let result = vas.virt_to_phys(vaddr);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::PagedOut { vaddr: v, pagefile_num, page_offset } => {
                assert_eq!(v, vaddr);
                assert_eq!(pagefile_num, 0);
                assert_eq!(page_offset, 0x1234);
            }
            other => panic!("expected PagedOut, got: {other}"),
        }
    }

    #[test]
    fn pagefile_pte_number_routing() {
        // pagefile_num = 2, page_offset = 0xABCD
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_pagefile(vaddr, 2, 0xABCD)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let result = vas.virt_to_phys(vaddr);
        match result.unwrap_err() {
            Error::PagedOut { pagefile_num, page_offset, .. } => {
                assert_eq!(pagefile_num, 2);
                assert_eq!(page_offset, 0xABCD);
            }
            other => panic!("expected PagedOut, got: {other}"),
        }
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-core --lib -- demand_zero_pte transition_pte prototype_pte pagefile_pte 2>&1`
Expected: FAIL — the walker currently returns `PageNotPresent` for all non-present PTEs.

- [ ] **Step 3: Implement TranslationResult and PTE decoder**

Replace the `walk_x86_64_4level` method in `crates/memf-core/src/vas.rs` with:

```rust
    fn walk_x86_64_4level(&self, vaddr: u64) -> Result<u64> {
        let result = self.walk_x86_64_4level_internal(vaddr)?;
        match result {
            TranslationResult::Physical(addr) | TranslationResult::Transition(addr) => Ok(addr),
            TranslationResult::DemandZero => Err(Error::PageNotPresent(vaddr)),
            TranslationResult::PagefileEntry { pagefile_num, page_offset } => {
                Err(Error::PagedOut { vaddr, pagefile_num, page_offset })
            }
            TranslationResult::Prototype => Err(Error::PrototypePte(vaddr)),
        }
    }

    fn walk_x86_64_4level_internal(&self, vaddr: u64) -> Result<TranslationResult> {
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pd_idx = (vaddr >> 21) & 0x1FF;
        let pt_idx = (vaddr >> 12) & 0x1FF;
        let page_offset = vaddr & 0xFFF;

        // PML4
        let pml4e = self.read_pte(self.page_table_root + pml4_idx * 8)?;
        if pml4e & PRESENT == 0 {
            return Err(Error::PageNotPresent(vaddr));
        }

        // PDPT
        let pdpt_base = pml4e & ADDR_MASK;
        let pdpte = self.read_pte(pdpt_base + pdpt_idx * 8)?;
        if pdpte & PRESENT == 0 {
            return Err(Error::PageNotPresent(vaddr));
        }

        // 1GB huge page check
        if pdpte & PS != 0 {
            let phys_base = pdpte & 0x000F_FFFF_C000_0000;
            let offset_1g = vaddr & 0x3FFF_FFFF;
            return Ok(TranslationResult::Physical(phys_base | offset_1g));
        }

        // PD
        let pd_base = pdpte & ADDR_MASK;
        let pde = self.read_pte(pd_base + pd_idx * 8)?;
        if pde & PRESENT == 0 {
            return Err(Error::PageNotPresent(vaddr));
        }

        // 2MB large page check
        if pde & PS != 0 {
            let phys_base = pde & 0x000F_FFFF_FFE0_0000;
            let offset_2m = vaddr & 0x1F_FFFF;
            return Ok(TranslationResult::Physical(phys_base | offset_2m));
        }

        // PT (4K page)
        let pt_base = pde & ADDR_MASK;
        let pte = self.read_pte(pt_base + pt_idx * 8)?;

        if pte & PRESENT != 0 {
            let phys_base = pte & ADDR_MASK;
            return Ok(TranslationResult::Physical(phys_base | page_offset));
        }

        // Non-present PTE decoding (PT level only)
        Ok(Self::decode_non_present_pte(pte, page_offset))
    }

    /// Decode a non-present PTE at the PT level.
    fn decode_non_present_pte(pte: u64, page_offset: u64) -> TranslationResult {
        // 1. Demand-zero: all bits are zero
        if pte == 0 {
            return TranslationResult::DemandZero;
        }
        // 2. Transition: bit 11 set → page still in physical RAM
        if pte & (1 << 11) != 0 {
            let pfn = (pte >> 12) & 0xF_FFFF_FFFF;
            return TranslationResult::Transition(pfn * 0x1000 + page_offset);
        }
        // 3. Prototype: bit 10 set → shared section (Phase 3F-B)
        if pte & (1 << 10) != 0 {
            return TranslationResult::Prototype;
        }
        // 4. Pagefile: bits 1-4 = pagefile number, bits 12-51 = page offset
        let pagefile_num = ((pte >> 1) & 0xF) as u8;
        let pf_page_offset = (pte >> 12) & 0xF_FFFF_FFFF;
        TranslationResult::PagefileEntry {
            pagefile_num,
            page_offset: pf_page_offset,
        }
    }
```

Also add the `TranslationResult` enum at the top of `vas.rs`, after the constants:

```rust
/// Internal result of page table walk — not exposed publicly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TranslationResult {
    /// Page is in physical memory at this address.
    Physical(u64),
    /// Page is demand-zero (all zeroes).
    DemandZero,
    /// Page is in a pagefile.
    PagefileEntry { pagefile_num: u8, page_offset: u64 },
    /// Page is a transition page (still in physical memory at this PFN-derived address).
    Transition(u64),
    /// Page uses a prototype PTE (Phase 3F-B).
    Prototype,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-core --lib 2>&1`
Expected: All tests pass — both old and new. The existing `non_present_page_returns_error` test still passes because PML4-level non-present entries still return `PageNotPresent`.

- [ ] **Step 5: Commit**

```bash
git add crates/memf-core/src/vas.rs
git commit --no-gpg-sign -m "feat(core): PTE decoder for demand-zero, transition, prototype, pagefile

TranslationResult enum classifies non-present PTEs at PT level.
virt_to_phys() maps results to PageNotPresent/PagedOut/PrototypePte errors."
```

---

### Task 5: VAS Pagefile Integration — `with_pagefile()` Builder + `read_virt()` Fallback

**Files:**
- Modify: `crates/memf-core/src/vas.rs`

This is the key integration task. The `VirtualAddressSpace` struct gains a `pagefiles` field and `with_pagefile()` builder. `read_virt()` is rewritten to use `TranslationResult` internally, routing demand-zero pages to zero-fill and pagefile pages to the attached providers.

- [ ] **Step 1: Write failing tests for pagefile-aware read_virt**

Add to the `#[cfg(test)] mod tests` block in `crates/memf-core/src/vas.rs`:

```rust
    use crate::test_builders::MockPagefileSource;

    #[test]
    fn read_virt_demand_zero_returns_zeroes() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_demand_zero(vaddr)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let mut buf = [0xFFu8; 4096];
        vas.read_virt(vaddr, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0), "demand-zero page must be all zeroes");
    }

    #[test]
    fn read_virt_transition_reads_physical() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let pfn: u64 = 0x800;
        let (cr3, mem) = PageTableBuilder::new()
            .map_transition(vaddr, pfn)
            .write_phys(pfn * 0x1000, &[0xCA, 0xFE, 0xBA, 0xBE])
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let mut buf = [0u8; 4];
        vas.read_virt(vaddr, &mut buf).unwrap();
        assert_eq!(buf, [0xCA, 0xFE, 0xBA, 0xBE]);
    }

    #[test]
    fn read_virt_pagefile_with_provider() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_offset: u64 = 0x10;
        let mut page_data = [0u8; 4096];
        page_data[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let (cr3, mem) = PageTableBuilder::new()
            .map_pagefile(vaddr, 0, page_offset)
            .build();

        let mock = MockPagefileSource::new(0, vec![(page_offset, page_data)]);
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel)
            .with_pagefile(Box::new(mock));

        let mut buf = [0u8; 4];
        vas.read_virt(vaddr, &mut buf).unwrap();
        assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn read_virt_pagefile_without_provider_errors() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_pagefile(vaddr, 0, 0x10)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let mut buf = [0u8; 4];
        let result = vas.read_virt(vaddr, &mut buf);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::PagedOut { pagefile_num: 0, page_offset: 0x10, .. } => {}
            other => panic!("expected PagedOut, got: {other}"),
        }
    }

    #[test]
    fn read_virt_prototype_pte_errors() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_prototype(vaddr)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let mut buf = [0u8; 4];
        let result = vas.read_virt(vaddr, &mut buf);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::PrototypePte(addr) => assert_eq!(addr, vaddr),
            other => panic!("expected PrototypePte, got: {other}"),
        }
    }

    #[test]
    fn read_virt_pagefile_number_routing() {
        let vaddr1: u64 = 0xFFFF_8000_0010_0000;
        let vaddr2: u64 = 0xFFFF_8000_0010_1000;

        let mut page0_data = [0u8; 4096];
        page0_data[0..4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let mut page1_data = [0u8; 4096];
        page1_data[0..4].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        let (cr3, mem) = PageTableBuilder::new()
            .map_pagefile(vaddr1, 0, 0x10)
            .map_pagefile(vaddr2, 1, 0x20)
            .build();

        let mock0 = MockPagefileSource::new(0, vec![(0x10, page0_data)]);
        let mock1 = MockPagefileSource::new(1, vec![(0x20, page1_data)]);

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel)
            .with_pagefile(Box::new(mock0))
            .with_pagefile(Box::new(mock1));

        let mut buf1 = [0u8; 4];
        vas.read_virt(vaddr1, &mut buf1).unwrap();
        assert_eq!(buf1, [0x11, 0x22, 0x33, 0x44]);

        let mut buf2 = [0u8; 4];
        vas.read_virt(vaddr2, &mut buf2).unwrap();
        assert_eq!(buf2, [0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn read_virt_pagefile_out_of_range() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_pagefile(vaddr, 0, 0x9999)
            .build();
        let mock = MockPagefileSource::new(0, vec![]); // no pages loaded
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel)
            .with_pagefile(Box::new(mock));
        let mut buf = [0u8; 4];
        let result = vas.read_virt(vaddr, &mut buf);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::PagedOut { page_offset: 0x9999, .. } => {}
            other => panic!("expected PagedOut, got: {other}"),
        }
    }

    #[test]
    fn read_virt_mixed_pages_cross_boundary() {
        // Page 1: physical (normal present PTE)
        // Page 2: pagefile PTE
        // Page 3: demand-zero
        let vaddr1: u64 = 0xFFFF_8000_0010_0000;
        let vaddr2: u64 = 0xFFFF_8000_0010_1000;
        let vaddr3: u64 = 0xFFFF_8000_0010_2000;
        let paddr1: u64 = 0x0080_0000;

        let mut pf_page = [0u8; 4096];
        pf_page[0..4].copy_from_slice(&[0xBB; 4]);

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr1, paddr1, flags::WRITABLE)
            .write_phys(paddr1 + 0xFFC, &[0xAA; 4]) // last 4 bytes of page 1
            .map_pagefile(vaddr2, 0, 0x10)
            .map_demand_zero(vaddr3)
            .build();

        let mock = MockPagefileSource::new(0, vec![(0x10, pf_page)]);
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel)
            .with_pagefile(Box::new(mock));

        // Read spanning: last 4 bytes of phys page + first 4 bytes of pagefile page
        let mut buf = [0u8; 8];
        vas.read_virt(vaddr1 + 0xFFC, &mut buf).unwrap();
        assert_eq!(buf, [0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB]);

        // Read spanning: last 4 bytes of pagefile page + first 4 bytes of demand-zero page
        let mut buf2 = [0u8; 8];
        vas.read_virt(vaddr2 + 0xFFC, &mut buf2).unwrap();
        // pf_page[0xFFC..0x1000] = [0, 0, 0, 0] (unset tail), demand-zero = [0, 0, 0, 0]
        assert_eq!(buf2, [0u8; 8]);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-core --lib -- read_virt_demand_zero read_virt_transition read_virt_pagefile read_virt_prototype read_virt_mixed 2>&1`
Expected: FAIL — `with_pagefile` doesn't exist, `read_virt` still uses `virt_to_phys`.

- [ ] **Step 3: Add pagefiles field, with_pagefile builder, and rewrite read_virt**

In `crates/memf-core/src/vas.rs`:

1. Add import at the top:

```rust
use crate::pagefile::PagefileSource;
```

2. Modify the `VirtualAddressSpace` struct:

```rust
pub struct VirtualAddressSpace<P: PhysicalMemoryProvider> {
    physical: P,
    page_table_root: u64,
    mode: TranslationMode,
    pagefiles: Vec<Box<dyn PagefileSource>>,
}
```

3. Update `new()`:

```rust
    pub fn new(physical: P, page_table_root: u64, mode: TranslationMode) -> Self {
        Self {
            physical,
            page_table_root,
            mode,
            pagefiles: Vec::new(),
        }
    }
```

4. Add builder method:

```rust
    /// Attach a pagefile source for resolving paged-out memory.
    /// Multiple sources can be attached (one per pagefile number).
    pub fn with_pagefile(mut self, source: Box<dyn PagefileSource>) -> Self {
        self.pagefiles.push(source);
        self
    }
```

5. Rewrite `read_virt()`:

```rust
    pub fn read_virt(&self, vaddr: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        let mut offset = 0usize;
        let mut current_vaddr = vaddr;

        while offset < buf.len() {
            let page_off = (current_vaddr & 0xFFF) as usize;
            let remaining_in_page = 0x1000 - page_off;
            let remaining_to_read = buf.len() - offset;
            let chunk = remaining_to_read.min(remaining_in_page);

            let result = match self.mode {
                TranslationMode::X86_64FourLevel => {
                    self.walk_x86_64_4level_internal(current_vaddr)?
                }
            };

            match result {
                TranslationResult::Physical(paddr) | TranslationResult::Transition(paddr) => {
                    let n = self
                        .physical
                        .read_phys(paddr, &mut buf[offset..offset + chunk])?;
                    if n == 0 {
                        return Err(Error::PartialRead {
                            addr: vaddr,
                            requested: buf.len(),
                            got: offset,
                        });
                    }
                    offset += n;
                    current_vaddr = current_vaddr.wrapping_add(n as u64);
                }
                TranslationResult::DemandZero => {
                    buf[offset..offset + chunk].fill(0);
                    offset += chunk;
                    current_vaddr = current_vaddr.wrapping_add(chunk as u64);
                }
                TranslationResult::PagefileEntry { pagefile_num, page_offset } => {
                    let page = self.read_pagefile_page(current_vaddr, pagefile_num, page_offset)?;
                    buf[offset..offset + chunk].copy_from_slice(&page[page_off..page_off + chunk]);
                    offset += chunk;
                    current_vaddr = current_vaddr.wrapping_add(chunk as u64);
                }
                TranslationResult::Prototype => {
                    return Err(Error::PrototypePte(current_vaddr));
                }
            }
        }

        Ok(())
    }
```

6. Add the pagefile lookup helper:

```rust
    fn read_pagefile_page(
        &self,
        vaddr: u64,
        pagefile_num: u8,
        page_offset: u64,
    ) -> Result<[u8; 4096]> {
        for source in &self.pagefiles {
            if source.pagefile_number() == pagefile_num {
                if let Some(page) = source.read_page(page_offset)? {
                    return Ok(page);
                }
                // Page offset out of range for this provider
                break;
            }
        }
        Err(Error::PagedOut {
            vaddr,
            pagefile_num,
            page_offset,
        })
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-core --lib 2>&1`
Expected: ALL tests pass — both old and new. Existing tests are unaffected because `pagefiles` defaults to empty and present PTEs still resolve as before.

- [ ] **Step 5: Run full workspace tests**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | grep "^test result:"`
Expected: Same count as baseline (391+) — no regressions in other crates.

- [ ] **Step 6: Commit**

```bash
git add crates/memf-core/src/vas.rs
git commit --no-gpg-sign -m "feat(core): pagefile-aware read_virt with transparent multi-source resolution

with_pagefile() builder attaches PagefileSource providers. read_virt() uses
TranslationResult to route each 4K chunk to physical RAM, pagefile, or
demand-zero fill. Cross-page reads span all source types seamlessly."
```

---

### Task 6: PagefileProvider (pagefile.sys)

**Files:**
- Modify: `crates/memf-core/src/pagefile.rs`

This task implements `PagefileProvider` — a memory-mapped reader for flat `pagefile.sys` files.

- [ ] **Step 1: Write failing tests**

Add to `crates/memf-core/src/pagefile.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn create_temp_pagefile(num_pages: usize) -> (tempfile::NamedTempFile, Vec<[u8; 4096]>) {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let mut pages = Vec::new();
        for i in 0..num_pages {
            let mut page = [0u8; 4096];
            // Fill with pattern: page index in first 4 bytes
            page[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            page[4] = 0xFF;
            file.write_all(&page).unwrap();
            pages.push(page);
        }
        file.flush().unwrap();
        (file, pages)
    }

    #[test]
    fn pagefile_provider_open_and_read() {
        let (file, pages) = create_temp_pagefile(4);
        let provider = PagefileProvider::open(file.path(), 0).unwrap();
        assert_eq!(provider.pagefile_number(), 0);

        let page = provider.read_page(0).unwrap().unwrap();
        assert_eq!(page, pages[0]);

        let page2 = provider.read_page(2).unwrap().unwrap();
        assert_eq!(page2, pages[2]);
    }

    #[test]
    fn pagefile_provider_out_of_range() {
        let (file, _pages) = create_temp_pagefile(4);
        let provider = PagefileProvider::open(file.path(), 0).unwrap();
        assert!(provider.read_page(4).unwrap().is_none());
        assert!(provider.read_page(9999).unwrap().is_none());
    }

    #[test]
    fn pagefile_provider_number() {
        let (file, _) = create_temp_pagefile(1);
        let provider = PagefileProvider::open(file.path(), 3).unwrap();
        assert_eq!(provider.pagefile_number(), 3);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-core --lib -- pagefile_provider 2>&1`
Expected: FAIL — `PagefileProvider` doesn't exist yet.

- [ ] **Step 3: Add tempfile dev-dependency**

In `crates/memf-core/Cargo.toml`, add:

```toml
[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 4: Implement PagefileProvider**

Add to `crates/memf-core/src/pagefile.rs`, after the `PagefileSource` trait:

```rust
use std::path::Path;

/// Provider for Windows pagefile.sys — a flat file of 4KB pages.
///
/// pagefile.sys has no headers and no compression. Each page occupies
/// exactly 4096 bytes at offset `page_index * 0x1000`.
pub struct PagefileProvider {
    mmap: memmap2::Mmap,
    pagefile_num: u8,
    page_count: u64,
}

impl PagefileProvider {
    /// Open a pagefile and memory-map it.
    pub fn open(path: &Path, pagefile_num: u8) -> Result<Self> {
        let file = std::fs::File::open(path).map_err(|e| {
            crate::Error::Physical(memf_format::Error::Io(e))
        })?;
        // SAFETY: We only read from the mmap, never write. The file is opened read-only.
        let mmap = unsafe { memmap2::MmapOptions::new().map(&file) }.map_err(|e| {
            crate::Error::Physical(memf_format::Error::Io(e))
        })?;
        let page_count = mmap.len() as u64 / 0x1000;
        Ok(Self {
            mmap,
            pagefile_num,
            page_count,
        })
    }
}

impl PagefileSource for PagefileProvider {
    fn pagefile_number(&self) -> u8 {
        self.pagefile_num
    }

    fn read_page(&self, page_offset: u64) -> Result<Option<[u8; 4096]>> {
        if page_offset >= self.page_count {
            return Ok(None);
        }
        let byte_offset = page_offset as usize * 0x1000;
        let mut page = [0u8; 4096];
        page.copy_from_slice(&self.mmap[byte_offset..byte_offset + 4096]);
        Ok(Some(page))
    }
}
```

Also update the `#![deny(unsafe_code)]` in `lib.rs` — since `PagefileProvider` uses `unsafe` for mmap, change it to `#![warn(unsafe_code)]` in `lib.rs`, OR move the unsafe block annotation. The simplest approach: add `#[allow(unsafe_code)]` on the `open` method:

Actually, the `#![deny(unsafe_code)]` is in `lib.rs`. The mmap needs `unsafe`. Add an allow on just the PagefileProvider `open` function:

```rust
    /// Open a pagefile and memory-map it.
    #[allow(unsafe_code)]
    pub fn open(path: &Path, pagefile_num: u8) -> Result<Self> {
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-core --lib -- pagefile_provider 2>&1`
Expected: All 3 tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/memf-core/src/pagefile.rs crates/memf-core/Cargo.toml
git commit --no-gpg-sign -m "feat(core): add PagefileProvider for flat pagefile.sys mmap reading"
```

---

### Task 7: SwapfileProvider (swapfile.sys)

**Files:**
- Modify: `crates/memf-core/src/pagefile.rs`

This task implements `SwapfileProvider` — a reader for Windows swapfile.sys with SM header parsing and Xpress decompression.

- [ ] **Step 1: Write failing tests**

Add to the `#[cfg(test)] mod tests` block in `crates/memf-core/src/pagefile.rs`:

```rust
    #[test]
    fn swapfile_provider_invalid_magic() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&[0x00; 4096]).unwrap(); // Not SM magic
        file.flush().unwrap();
        let result = SwapfileProvider::open(file.path());
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("SM") || msg.contains("magic"), "error should mention SM magic: {msg}");
    }

    #[test]
    fn swapfile_provider_too_small() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&[0x53, 0x4D]).unwrap(); // "SM" but too short
        file.flush().unwrap();
        let result = SwapfileProvider::open(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn swapfile_provider_valid_sm_header() {
        // Build a synthetic SM swapfile with one uncompressed page
        let mut data = vec![0u8; 0x2000]; // 2 pages worth

        // SM header at offset 0
        data[0] = 0x53; // 'S'
        data[1] = 0x4D; // 'M'
        data[2..4].copy_from_slice(&1u16.to_le_bytes()); // version = 1
        data[4..8].copy_from_slice(&0x1000u32.to_le_bytes()); // page_size
        data[8..16].copy_from_slice(&0x1000u64.to_le_bytes()); // region_table_offset
        data[16..20].copy_from_slice(&1u32.to_le_bytes()); // region_count

        // Region entry at offset 0x1000:
        // page_offset(u64) + file_offset(u64) + page_count(u32) + compressed_size_per_page(u32)
        // We store one uncompressed page (compressed_size = 0x1000) at file offset 0x1800
        let region_off = 0x1000usize;
        // page_offset = 5 (the virtual page offset this region covers)
        data.resize(0x3000, 0); // Ensure enough space
        data[region_off..region_off + 8].copy_from_slice(&5u64.to_le_bytes());
        // file_offset = 0x1800
        data[region_off + 8..region_off + 16].copy_from_slice(&0x1800u64.to_le_bytes());
        // page_count = 1
        data[region_off + 16..region_off + 20].copy_from_slice(&1u32.to_le_bytes());
        // compressed_size = 0x1000 (uncompressed)
        data[region_off + 20..region_off + 24].copy_from_slice(&0x1000u32.to_le_bytes());

        // Page data at file offset 0x1800
        data[0x1800] = 0x42;
        data[0x1801] = 0x43;
        for i in 2..4096 {
            data[0x1800 + i] = 0xAB;
        }

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        let provider = SwapfileProvider::open(file.path()).unwrap();
        assert_eq!(provider.pagefile_number(), 2);

        let page = provider.read_page(5).unwrap().unwrap();
        assert_eq!(page[0], 0x42);
        assert_eq!(page[1], 0x43);
        assert_eq!(page[2], 0xAB);

        // Page not in index
        assert!(provider.read_page(99).unwrap().is_none());
    }

    #[test]
    fn swapfile_provider_compressed_page() {
        // Build a synthetic SM swapfile with one Xpress-compressed page
        let mut original_page = [0u8; 4096];
        original_page[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        // Fill rest with repeating pattern (compresses well)
        for i in (4..4096).step_by(4) {
            original_page[i..i + 4].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        }

        let compressed = lzxpress::data::compress(&original_page).unwrap();
        assert!(compressed.len() < 4096, "compressed should be smaller");

        let mut data = vec![0u8; 0x3000 + compressed.len()];

        // SM header
        data[0] = 0x53;
        data[1] = 0x4D;
        data[2..4].copy_from_slice(&1u16.to_le_bytes());
        data[4..8].copy_from_slice(&0x1000u32.to_le_bytes());
        data[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        data[16..20].copy_from_slice(&1u32.to_le_bytes());

        // Region entry at 0x1000
        let region_off = 0x1000usize;
        data[region_off..region_off + 8].copy_from_slice(&7u64.to_le_bytes()); // page_offset = 7
        data[region_off + 8..region_off + 16].copy_from_slice(&0x1800u64.to_le_bytes()); // file_offset
        data[region_off + 16..region_off + 20].copy_from_slice(&1u32.to_le_bytes()); // page_count
        data[region_off + 20..region_off + 24]
            .copy_from_slice(&(compressed.len() as u32).to_le_bytes()); // compressed_size

        // Compressed page data at 0x1800
        data[0x1800..0x1800 + compressed.len()].copy_from_slice(&compressed);

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        let provider = SwapfileProvider::open(file.path()).unwrap();
        let page = provider.read_page(7).unwrap().unwrap();
        assert_eq!(page, original_page);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-core --lib -- swapfile_provider 2>&1`
Expected: FAIL — `SwapfileProvider` doesn't exist yet.

- [ ] **Step 3: Implement SwapfileProvider**

Add to `crates/memf-core/src/pagefile.rs`:

```rust
use std::collections::HashMap;

/// SM header magic for swapfile.sys: "SM" (0x534D little-endian).
const SM_MAGIC: u16 = 0x534D;

/// Minimum size for a valid SM header.
const SM_HEADER_SIZE: usize = 20;

/// Region entry size: page_offset(8) + file_offset(8) + page_count(4) + compressed_size(4).
const REGION_ENTRY_SIZE: usize = 24;

/// Provider for Windows swapfile.sys — SM header format with optional Xpress compression.
pub struct SwapfileProvider {
    mmap: memmap2::Mmap,
    /// Maps page offset -> (file_offset, compressed_size).
    /// Pages with compressed_size == 0x1000 are stored uncompressed.
    index: HashMap<u64, (u64, u32)>,
}

impl SwapfileProvider {
    /// Open a swapfile.sys and parse its SM header to build the page index.
    #[allow(unsafe_code)]
    pub fn open(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path).map_err(|e| {
            crate::Error::Physical(memf_format::Error::Io(e))
        })?;
        let mmap = unsafe { memmap2::MmapOptions::new().map(&file) }.map_err(|e| {
            crate::Error::Physical(memf_format::Error::Io(e))
        })?;

        if mmap.len() < SM_HEADER_SIZE {
            return Err(crate::Error::Physical(memf_format::Error::InvalidFormat(
                "swapfile too small for SM header".into(),
            )));
        }

        let magic = u16::from_le_bytes([mmap[0], mmap[1]]);
        if magic != SM_MAGIC {
            return Err(crate::Error::Physical(memf_format::Error::InvalidFormat(
                format!("invalid SM magic: expected 0x534D, got {magic:#06X}"),
            )));
        }

        let region_table_offset = u64::from_le_bytes(mmap[8..16].try_into().unwrap()) as usize;
        let region_count = u32::from_le_bytes(mmap[16..20].try_into().unwrap()) as usize;

        let mut index = HashMap::new();

        for i in 0..region_count {
            let entry_offset = region_table_offset + i * REGION_ENTRY_SIZE;
            if entry_offset + REGION_ENTRY_SIZE > mmap.len() {
                return Err(crate::Error::Physical(memf_format::Error::InvalidFormat(
                    format!("SM region entry {i} at offset {entry_offset:#x} truncated"),
                )));
            }

            let page_offset =
                u64::from_le_bytes(mmap[entry_offset..entry_offset + 8].try_into().unwrap());
            let file_offset = u64::from_le_bytes(
                mmap[entry_offset + 8..entry_offset + 16]
                    .try_into()
                    .unwrap(),
            );
            let page_count = u32::from_le_bytes(
                mmap[entry_offset + 16..entry_offset + 20]
                    .try_into()
                    .unwrap(),
            );
            let compressed_size = u32::from_le_bytes(
                mmap[entry_offset + 20..entry_offset + 24]
                    .try_into()
                    .unwrap(),
            );

            // Each region has `page_count` pages. For single-page regions, the
            // compressed_size applies to the one page. For multi-page regions,
            // each page has the same compressed_size and is stored sequentially.
            for p in 0..page_count as u64 {
                let fo = file_offset + p * compressed_size as u64;
                index.insert(page_offset + p, (fo, compressed_size));
            }
        }

        Ok(Self { mmap, index })
    }
}

impl PagefileSource for SwapfileProvider {
    fn pagefile_number(&self) -> u8 {
        2 // Windows convention for swapfile virtual store
    }

    fn read_page(&self, page_offset: u64) -> Result<Option<[u8; 4096]>> {
        let (file_offset, compressed_size) = match self.index.get(&page_offset) {
            Some(&entry) => entry,
            None => return Ok(None),
        };

        let fo = file_offset as usize;
        let cs = compressed_size as usize;

        if fo + cs > self.mmap.len() {
            return Err(crate::Error::Physical(memf_format::Error::InvalidFormat(
                format!(
                    "swapfile page at offset {page_offset:#x}: data at {fo:#x}+{cs:#x} beyond file"
                ),
            )));
        }

        if compressed_size == 0x1000 {
            // Uncompressed page
            let mut page = [0u8; 4096];
            page.copy_from_slice(&self.mmap[fo..fo + 4096]);
            Ok(Some(page))
        } else {
            // Xpress-compressed page
            let compressed_data = &self.mmap[fo..fo + cs];
            let decompressed = lzxpress::data::decompress(compressed_data).map_err(|e| {
                crate::Error::Physical(memf_format::Error::Decompression(format!(
                    "swapfile xpress decompress at page {page_offset:#x}: {e:?}"
                )))
            })?;
            if decompressed.len() < 4096 {
                return Err(crate::Error::Physical(memf_format::Error::InvalidFormat(
                    format!(
                        "swapfile decompressed page {page_offset:#x}: {} bytes (expected 4096)",
                        decompressed.len()
                    ),
                )));
            }
            let mut page = [0u8; 4096];
            page.copy_from_slice(&decompressed[..4096]);
            Ok(Some(page))
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p memf-core --lib -- swapfile_provider pagefile_provider 2>&1`
Expected: All swapfile and pagefile tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/memf-core/src/pagefile.rs
git commit --no-gpg-sign -m "feat(core): add SwapfileProvider with SM header parsing and Xpress decompression

Parses region table from SM header, builds page index, supports both
uncompressed and Xpress-compressed pages via lzxpress crate."
```

---

### Task 8: Final Verification and Cleanup

**Files:**
- All modified files from previous tasks

This task runs the full workspace test suite, clippy, and fmt to ensure no regressions and clean code.

- [ ] **Step 1: Run cargo fmt**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo fmt --all 2>&1`
Expected: No output (already formatted) or auto-formats.

- [ ] **Step 2: Run cargo clippy**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo clippy --workspace --all-targets 2>&1`
Expected: No warnings. Fix any clippy issues.

- [ ] **Step 3: Run full workspace tests**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | grep "^test result:"`
Expected: All pass. Count should be baseline (391) + new tests:
- lib.rs: +2 (error display)
- test_builders.rs: +6 (4 PTE builder + 2 mock)
- vas.rs: +14 (6 PTE decode + 8 read_virt)
- pagefile.rs: +7 (3 pagefile provider + 4 swapfile provider)
Total: ~29 new tests → 420+ total

- [ ] **Step 4: Verify test count**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | grep "^test result:" | awk '{sum += $4} END {print "Total:", sum}'`
Expected: 420 or more (391 baseline + 29 new)

- [ ] **Step 5: Commit any fmt/clippy fixes**

```bash
git add -A
git commit --no-gpg-sign -m "chore(core): fmt + clippy cleanup for Phase 3F-A"
```

(Only if there are changes. Skip if working tree is clean.)

- [ ] **Step 6: Run full test output to confirm zero failures**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1`
Expected: `0 failed` on every line. Zero regressions.
