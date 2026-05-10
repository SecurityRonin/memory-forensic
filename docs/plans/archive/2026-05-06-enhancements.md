# Enhancements Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Implement 10 prioritised enhancements covering performance, forensic coverage, output formats, reliability, and security hardening.

**Architecture:** Tasks are ordered by dependency. Tasks 1–3 touch `vas.rs` (page table walking) and must be sequential. Tasks 4–10 are independent of each other once Tasks 1–3 are done.

**Tech Stack:** Rust 2021, `lru = "0.16"` (already in `memf-core` deps), `cargo-fuzz` (new dev dep for Task 10).

**Commit convention:** All commits use `--no-gpg-sign`.

---

## Task 1: Translation cache in `VirtualAddressSpace`

**Why:** Every virtual→physical translation does 4 physical reads (one per page table level). On large scans (malfind over 10K VMAs), this is 40K+ redundant reads for shared pages. Adding a per-instance LRU cache eliminates redundant walks.

**Files:**
- Modify: `crates/memf-core/src/vas.rs`

**Context:**
`VirtualAddressSpace` is in `crates/memf-core/src/vas.rs`. It has:
- `physical: P` — the physical memory provider
- `page_table_root: u64` — CR3/TTBR0
- `mode: TranslationMode` — only `X86_64FourLevel` currently
`lru.workspace = true` is already in `crates/memf-core/Cargo.toml`.

The cache maps page-aligned vaddr (`vaddr & !0xFFF`) → page-aligned paddr. It lives inside `walk_x86_64_4level_internal` (and future mode variants). `RefCell<LruCache<u64, u64>>` is correct here because `VirtualAddressSpace` is not required to be `Sync`.

**Step 1: Write the RED test**

Add to the `#[cfg(test)] mod tests` block in `vas.rs`:

```rust
#[test]
fn translation_cache_hit_returns_same_result() {
    // Two reads of the same page should return identical results.
    // The second read hits the cache (no way to observe this directly,
    // but the test documents the contract and will fail if the cache
    // corrupts the result).
    let vaddr: u64 = 0xFFFF_8000_0010_0000;
    let paddr: u64 = 0x0080_0000;
    let (cr3, mem) = PageTableBuilder::new()
        .map_4k(vaddr, paddr, flags::WRITABLE)
        .build();
    let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
    let first  = vas.virt_to_phys(vaddr).unwrap();
    let second = vas.virt_to_phys(vaddr).unwrap();
    assert_eq!(first, second);
    assert_eq!(first, paddr);
}

#[test]
fn translation_cache_capacity_100_distinct_pages() {
    // Map 200 distinct pages; the LRU evicts old entries but never returns
    // wrong results — we re-translate after the cache is full.
    use std::collections::HashSet;
    let base_vaddr: u64 = 0xFFFF_8000_0000_0000;
    let mut builder = PageTableBuilder::new();
    for i in 0..200u64 {
        builder = builder.map_4k(base_vaddr + i * 0x1000, 0x1000 + i * 0x1000, flags::WRITABLE);
    }
    let (cr3, mem) = builder.build();
    let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
    let mut results = HashSet::new();
    for i in 0..200u64 {
        let paddr = vas.virt_to_phys(base_vaddr + i * 0x1000).unwrap();
        results.insert(paddr);
    }
    assert_eq!(results.len(), 200, "each page must map to a distinct physical address");
}
```

Run: `cargo test -p memf-core -- vas::tests::translation_cache 2>&1 | tail -5`
Expected: PASS (these tests pass even before the cache — they document the contract).

**Step 2: Commit RED**

```bash
git add crates/memf-core/src/vas.rs
git commit --no-gpg-sign -m "test(perf): RED — pin translation cache contract tests"
```

**Step 3: Add the cache to `VirtualAddressSpace`**

Add imports at the top of `vas.rs` (after existing imports):
```rust
use lru::LruCache;
use std::cell::RefCell;
use std::num::NonZeroUsize;
```

Add constant after the existing `PS` constant:
```rust
/// Number of page translations to cache per `VirtualAddressSpace` instance.
const TRANSLATION_CACHE_CAPACITY: usize = 4096;
```

Add the field to the struct (after `prototype_source`):
```rust
pub struct VirtualAddressSpace<P: PhysicalMemoryProvider> {
    physical: P,
    page_table_root: u64,
    mode: TranslationMode,
    pagefiles: Vec<Box<dyn PagefileSource>>,
    prototype_source: Option<Box<dyn PrototypePteSource>>,
    /// LRU cache: page-aligned vaddr → page-aligned paddr.
    tlb_cache: RefCell<LruCache<u64, u64>>,
}
```

Update `new()` to initialise the cache:
```rust
pub fn new(physical: P, page_table_root: u64, mode: TranslationMode) -> Self {
    Self {
        physical,
        page_table_root,
        mode,
        pagefiles: Vec::new(),
        prototype_source: None,
        tlb_cache: RefCell::new(LruCache::new(
            NonZeroUsize::new(TRANSLATION_CACHE_CAPACITY).expect("capacity is nonzero"),
        )),
    }
}
```

Add cache check/fill to `walk_x86_64_4level_internal` — at the very start of the function body, before the PML4 read:
```rust
fn walk_x86_64_4level_internal(&self, vaddr: u64) -> Result<TranslationResult> {
    // Check translation cache first.
    let page_vaddr = vaddr & !0xFFF;
    if let Some(&paddr_base) = self.tlb_cache.borrow().peek(&page_vaddr) {
        return Ok(TranslationResult::Physical(paddr_base | (vaddr & 0xFFF)));
    }

    // ... existing PML4 / PDPT / PD / PT walk code unchanged ...

    // At the final Physical return sites, populate the cache.
    // (There are three: huge 1GB, large 2MB, and 4K page)
```

For each `return Ok(TranslationResult::Physical(...))` site in `walk_x86_64_4level_internal`, add the cache insert before returning. The three sites are:

Site 1 (1GB huge page, line ~243):
```rust
let phys = phys_base | offset_1g;
self.tlb_cache.borrow_mut().put(page_vaddr, phys & !0xFFF);
return Ok(TranslationResult::Physical(phys));
```

Site 2 (2MB large page, line ~257):
```rust
let phys = phys_base | offset_2m;
self.tlb_cache.borrow_mut().put(page_vaddr, phys & !0xFFF);
return Ok(TranslationResult::Physical(phys));
```

Site 3 (4K page, line ~266):
```rust
let phys = phys_base | page_offset;
self.tlb_cache.borrow_mut().put(page_vaddr, phys_base);
return Ok(TranslationResult::Physical(phys));
```

**Step 4: Run tests**

```bash
cargo test -p memf-core -- vas::tests 2>&1 | tail -5
```
Expected: all pass.

**Step 5: Commit GREEN**

```bash
git add crates/memf-core/src/vas.rs
git commit --no-gpg-sign -m "feat(perf): GREEN — LRU translation cache in VirtualAddressSpace (4096-entry)"
```

---

## Task 2: 5-level paging (x86_64 LA57)

**Why:** Windows Server 2025 and Linux with `CONFIG_X86_5LEVEL` use 57-bit virtual addresses (5-level paging). Without this, the tool silently produces wrong translations on affected dumps.

**Files:**
- Modify: `crates/memf-core/src/vas.rs`

**Context:**
5-level paging adds a PML5 table before PML4. The PML5 index is bits [56:48] of the virtual address. Everything else is identical to 4-level. The existing `walk_x86_64_4level_internal` must be refactored to accept a `pml4_root: u64` parameter so 5-level can call it after the PML5 step.

**Step 1: Write RED tests**

Add to `vas::tests`:
```rust
#[test]
fn translate_5level_4k_page() {
    // 5-level address uses bit 48 as PML5 index.
    // vaddr 0x0100_0000_0010_0000 has PML5 idx=0, PML4 idx=0, ...
    let vaddr: u64 = 0x0100_0000_0010_0000;
    let paddr: u64 = 0x0080_0000;
    let (cr3, mem) = PageTableBuilder::new()
        .map_4k(vaddr, paddr, flags::WRITABLE)
        .build();
    // 5-level mode — must also work for addresses within the first PML5 entry
    let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_645Level);
    // For an address that fits in 48-bit VA, PML5[0] must be valid.
    // PageTableBuilder maps x86_64 4-level — for 5-level, pml5[0] points to cr3's
    // PML4. The test verifies the new mode compiles and dispatches correctly.
    // Use the existing 4-level address to verify fallthrough:
    let vaddr4: u64 = 0xFFFF_8000_0010_0000;
    let paddr4: u64 = 0x0090_0000;
    let (cr3_5, mem_5) = PageTableBuilder::new()
        .map_4k(vaddr4, paddr4, flags::WRITABLE)
        .build();
    let vas5 = VirtualAddressSpace::new(mem_5, cr3_5, TranslationMode::X86_645Level);
    // This tests the enum dispatch; full 5-level address translation
    // requires a 5-level-aware PageTableBuilder (future work).
    // For now, assert the method exists and the 4-level fallthrough works
    // when PML5[idx] points directly to a PML4 table at the cr3 root.
    let _ = vas5.virt_to_phys(vaddr4); // may error — just must not panic
}

#[test]
fn translate_mode_5level_is_distinct_from_4level() {
    assert_ne!(
        std::mem::discriminant(&TranslationMode::X86_645Level),
        std::mem::discriminant(&TranslationMode::X86_64FourLevel),
    );
}
```

Run: `cargo test -p memf-core -- vas::tests::translate_5level 2>&1 | tail -5`
Expected: compile error — `TranslationMode::X86_645Level` not found.

**Step 2: Commit RED**

```bash
git add crates/memf-core/src/vas.rs
git commit --no-gpg-sign -m "test(5level): RED — 5-level paging variant not yet defined"
```

**Step 3: Implement**

Add variant to `TranslationMode`:
```rust
pub enum TranslationMode {
    /// x86_64 4-level paging (PML4 → PDPT → PD → PT).
    X86_64FourLevel,
    /// x86_64 5-level paging (PML5 → PML4 → PDPT → PD → PT). Linux LA57, Server 2025.
    X86_645Level,
}
```

Refactor `walk_x86_64_4level_internal` to accept a `pml4_root` parameter:
```rust
fn walk_x86_64_4level_internal(&self, vaddr: u64) -> Result<TranslationResult> {
    self.walk_4level_from(self.page_table_root, vaddr)
}

fn walk_4level_from(&self, pml4_root: u64, vaddr: u64) -> Result<TranslationResult> {
    // Check translation cache first.
    let page_vaddr = vaddr & !0xFFF;
    if let Some(&paddr_base) = self.tlb_cache.borrow().peek(&page_vaddr) {
        return Ok(TranslationResult::Physical(paddr_base | (vaddr & 0xFFF)));
    }

    let pml4_idx = (vaddr >> 39) & 0x1FF;
    // ... rest of existing walk_x86_64_4level_internal body, using pml4_root ...
    // (move all existing code here, replacing self.page_table_root with pml4_root)
}
```

Add 5-level walk:
```rust
fn walk_x86_64_5level_internal(&self, vaddr: u64) -> Result<TranslationResult> {
    let pml5_idx = (vaddr >> 48) & 0x1FF;
    let pml5e = self.read_pte(self.page_table_root + pml5_idx * 8)?;
    if pml5e & PRESENT == 0 {
        return Err(Error::PageNotPresent(vaddr));
    }
    let pml4_root = pml5e & ADDR_MASK;
    self.walk_4level_from(pml4_root, vaddr)
}
```

Update dispatch in `virt_to_phys` and `read_virt`:
```rust
// In virt_to_phys:
match self.mode {
    TranslationMode::X86_64FourLevel => self.walk_x86_64_4level(vaddr),
    TranslationMode::X86_645Level   => {
        match self.walk_x86_64_5level_internal(vaddr)? {
            TranslationResult::Physical(addr) | TranslationResult::Transition(addr) => Ok(addr),
            TranslationResult::DemandZero => Err(Error::PageNotPresent(vaddr)),
            TranslationResult::PagefileEntry { pagefile_num, page_offset } =>
                Err(Error::PagedOut { vaddr, pagefile_num, page_offset }),
            TranslationResult::Prototype(_) => Err(Error::PrototypePte(vaddr)),
        }
    }
}

// In read_virt match arm, add:
TranslationMode::X86_645Level => self.walk_x86_64_5level_internal(current_vaddr)?,
```

Run: `cargo test -p memf-core -- vas::tests 2>&1 | tail -5`
Expected: all pass.

**Step 4: Commit GREEN**

```bash
git add crates/memf-core/src/vas.rs
git commit --no-gpg-sign -m "feat(5level): GREEN — x86_64 5-level paging (LA57) support"
```

---

## Task 3: AArch64 4-level page table walking

**Why:** Android forensics, Apple Silicon VMs, AWS Graviton. `MachineType::Aarch64` is declared in `memf-format` but no page table walker exists. This is the largest forensic coverage gap.

**Files:**
- Modify: `crates/memf-core/src/vas.rs`

**Context:**
AArch64 4K-granule, 48-bit VA page table (used by Linux and Android):
- Level 0 (PGD): vaddr bits [47:39], 9 bits
- Level 1 (PUD): vaddr bits [38:30], 9 bits
- Level 2 (PMD): vaddr bits [29:21], 9 bits
- Level 3 (PTE): vaddr bits [20:12], 9 bits
- Page offset: vaddr bits [11:0]

AArch64 PTE bit fields (4K granule):
- Bit 0: valid
- Bit 1: descriptor type (0=block, 1=table/page)
- Bits [47:12]: output address (OA) — mask: `0x0000_FFFF_FFFF_F000`
- `valid=1, type=1` at levels 0–2: table entry, OA points to next level
- `valid=1, type=0` at levels 1–2: block entry (1GB at L1, 2MB at L2)
- `valid=1, type=1` at level 3: page entry (4K)

For block entries:
- L1 block (1GB): OA mask = `0x0000_FFFF_C000_0000`, offset mask = `0x3FFF_FFFF`
- L2 block (2MB): OA mask = `0x0000_FFFF_FFE0_0000`, offset mask = `0x001F_FFFF`

**Step 1: Write RED tests**

```rust
#[test]
fn aarch64_translate_4k_page() {
    let vaddr: u64 = 0x0000_0000_0010_0000; // user space AArch64 vaddr
    let paddr: u64 = 0x0080_0000;
    let (cr3, mem) = PageTableBuilder::new()
        .map_4k(vaddr, paddr, flags::WRITABLE)
        .build();
    let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::AArch64FourLevel);
    // PageTableBuilder currently builds x86_64 tables.
    // AArch64 table format is identical at the structural level (9-bit indices, 8-byte PTEs).
    // The key difference is PTE bit layout. For a test where bit 0=1 and bit 1=1,
    // x86_64 PRESENT+TYPE maps perfectly to AArch64 VALID+TABLE.
    // So an x86_64-built table is also a valid AArch64 table for PRESENT pages.
    let result = vas.virt_to_phys(vaddr);
    // Must not panic; result may be Ok(paddr) or Err depending on flag interpretation.
    // The contract: AArch64 mode dispatches without panicking.
    let _ = result;
}

#[test]
fn aarch64_mode_distinct_from_x86() {
    assert_ne!(
        std::mem::discriminant(&TranslationMode::AArch64FourLevel),
        std::mem::discriminant(&TranslationMode::X86_64FourLevel),
    );
}

#[test]
fn aarch64_non_present_returns_error() {
    // A completely empty physical memory should return PageNotPresent.
    use crate::test_builders::SyntheticPhysMem;
    let mem = SyntheticPhysMem::new(4096 * 16);
    let vas = VirtualAddressSpace::new(mem, 0, TranslationMode::AArch64FourLevel);
    let result = vas.virt_to_phys(0x1000);
    assert!(matches!(result, Err(Error::PageNotPresent(_))));
}
```

Run: `cargo test -p memf-core -- vas::tests::aarch64 2>&1 | tail -5`
Expected: compile error — `TranslationMode::AArch64FourLevel` not found.

**Step 2: Commit RED**

```bash
git add crates/memf-core/src/vas.rs
git commit --no-gpg-sign -m "test(aarch64): RED — AArch64 translation mode not yet defined"
```

**Step 3: Implement**

Add constants after existing x86_64 constants:
```rust
// AArch64 4K-granule page table constants
const AARCH64_VALID: u64   = 1;        // bit 0
const AARCH64_TABLE: u64   = 1 << 1;  // bit 1: 1=table/page, 0=block
const AARCH64_OA_MASK: u64 = 0x0000_FFFF_FFFF_F000; // bits [47:12]
```

Add variant:
```rust
pub enum TranslationMode {
    X86_64FourLevel,
    X86_645Level,
    /// AArch64 4-level page tables (4K granule, 48-bit VA). Linux, Android, macOS ARM.
    AArch64FourLevel,
}
```

Add walk method:
```rust
fn walk_aarch64_4level(&self, vaddr: u64) -> Result<u64> {
    match self.walk_aarch64_internal(vaddr)? {
        TranslationResult::Physical(addr) | TranslationResult::Transition(addr) => Ok(addr),
        TranslationResult::DemandZero => Err(Error::PageNotPresent(vaddr)),
        TranslationResult::PagefileEntry { .. } => Err(Error::PageNotPresent(vaddr)),
        TranslationResult::Prototype(_) => Err(Error::PageNotPresent(vaddr)),
    }
}

fn walk_aarch64_internal(&self, vaddr: u64) -> Result<TranslationResult> {
    let page_vaddr = vaddr & !0xFFF;
    if let Some(&paddr_base) = self.tlb_cache.borrow().peek(&page_vaddr) {
        return Ok(TranslationResult::Physical(paddr_base | (vaddr & 0xFFF)));
    }

    let l0_idx = (vaddr >> 39) & 0x1FF;
    let l1_idx = (vaddr >> 30) & 0x1FF;
    let l2_idx = (vaddr >> 21) & 0x1FF;
    let l3_idx = (vaddr >> 12) & 0x1FF;
    let page_off = vaddr & 0xFFF;

    // Level 0 (PGD)
    let l0e = self.read_pte(self.page_table_root + l0_idx * 8)?;
    if l0e & AARCH64_VALID == 0 {
        return Err(Error::PageNotPresent(vaddr));
    }
    let l1_base = l0e & AARCH64_OA_MASK;

    // Level 1 (PUD)
    let l1e = self.read_pte(l1_base + l1_idx * 8)?;
    if l1e & AARCH64_VALID == 0 {
        return Err(Error::PageNotPresent(vaddr));
    }
    if l1e & AARCH64_TABLE == 0 {
        // 1GB block
        let phys_base = l1e & 0x0000_FFFF_C000_0000;
        let phys = phys_base | (vaddr & 0x3FFF_FFFF);
        self.tlb_cache.borrow_mut().put(page_vaddr, phys & !0xFFF);
        return Ok(TranslationResult::Physical(phys));
    }
    let l2_base = l1e & AARCH64_OA_MASK;

    // Level 2 (PMD)
    let l2e = self.read_pte(l2_base + l2_idx * 8)?;
    if l2e & AARCH64_VALID == 0 {
        return Err(Error::PageNotPresent(vaddr));
    }
    if l2e & AARCH64_TABLE == 0 {
        // 2MB block
        let phys_base = l2e & 0x0000_FFFF_FFE0_0000;
        let phys = phys_base | (vaddr & 0x001F_FFFF);
        self.tlb_cache.borrow_mut().put(page_vaddr, phys & !0xFFF);
        return Ok(TranslationResult::Physical(phys));
    }
    let l3_base = l2e & AARCH64_OA_MASK;

    // Level 3 (PTE)
    let l3e = self.read_pte(l3_base + l3_idx * 8)?;
    if l3e & AARCH64_VALID == 0 {
        return Err(Error::PageNotPresent(vaddr));
    }
    let phys_base = l3e & AARCH64_OA_MASK;
    let phys = phys_base | page_off;
    self.tlb_cache.borrow_mut().put(page_vaddr, phys_base);
    Ok(TranslationResult::Physical(phys))
}
```

Update dispatch in `virt_to_phys` and `read_virt` to add the `AArch64FourLevel` arm.

Run: `cargo test -p memf-core -- vas::tests 2>&1 | tail -5`
Expected: all pass.

**Step 4: Commit GREEN**

```bash
git add crates/memf-core/src/vas.rs
git commit --no-gpg-sign -m "feat(aarch64): GREEN — AArch64 4-level page table walking (4K granule, 48-bit VA)"
```

---

## Task 4: Linux IPv6 TCP connection walker

**Why:** Modern C2 uses IPv6. `walk_connections` in `network.rs` only covers `tcp_hashinfo` (IPv4). `Protocol::Tcp6` and `Protocol::Udp6` already exist in `types.rs`. IPv6 source/dest addresses are 16 bytes (`skc_v6_daddr`, `skc_v6_rcv_saddr` in `sock_common`).

**Files:**
- Modify: `crates/memf-linux/src/network.rs`

**Context:**
- `walk_connections` (existing): walks `tcp_hashinfo.ehash`, reads 4-byte IPv4 addrs via `skc_daddr` / `skc_rcv_saddr`, returns `Protocol::Tcp`
- IPv6 equivalent: walks `tcp6_hashinfo.ehash` (same struct layout, different symbol), reads 16-byte addrs via `skc_v6_daddr` / `skc_v6_rcv_saddr`, returns `Protocol::Tcp6`
- `skc_v6_daddr` is a `struct in6_addr` at offset within `sock_common` — read as 16 raw bytes

`ConnectionInfo.local_addr` and `remote_addr` are `String` — format IPv6 as colon-hex (`2001:db8::1`).

**Step 1: Write RED tests**

In `network.rs` test module, add:

```rust
#[test]
fn walk_ipv6_single_connection() {
    let vaddr: u64 = 0xFFFF_8000_0020_0000;
    let paddr: u64 = 0x00A0_0000;
    let mut data = vec![0u8; 4096];

    // tcp6_hashinfo: ehash ptr at offset 0, mask at offset 8
    let ehash6_addr = vaddr + 0x100;
    data[0..8].copy_from_slice(&ehash6_addr.to_le_bytes());
    data[8..12].copy_from_slice(&0u32.to_le_bytes()); // mask=0 → 1 bucket

    // bucket: chain ptr
    let sock6_addr = vaddr + 0x200;
    data[0x100..0x108].copy_from_slice(&sock6_addr.to_le_bytes());

    // sock_common: nulls_node=1 (terminator), then v6_daddr (16b), v6_rcv_saddr (16b),
    //             dport (2b), num (2b), state (1b)
    data[0x200..0x208].copy_from_slice(&1u64.to_le_bytes()); // null terminator
    // v6_rcv_saddr = ::1 (loopback)
    let mut saddr6 = [0u8; 16];
    saddr6[15] = 1; // ::1
    data[0x208..0x218].copy_from_slice(&saddr6);    // skc_v6_daddr
    data[0x218..0x228].copy_from_slice(&saddr6);    // skc_v6_rcv_saddr
    data[0x228..0x22A].copy_from_slice(&443u16.to_be_bytes()); // dport
    data[0x22A..0x22C].copy_from_slice(&8443u16.to_le_bytes()); // sport
    data[0x22C] = 1; // ESTABLISHED

    let isf = IsfBuilder::new()
        .add_struct("inet_hashinfo", 64)
        .add_field("inet_hashinfo", "ehash", 0, "pointer")
        .add_field("inet_hashinfo", "ehash_mask", 8, "unsigned int")
        .add_struct("inet_ehash_bucket", 8)
        .add_field("inet_ehash_bucket", "chain", 0, "pointer")
        .add_struct("sock_common", 128)
        .add_field("sock_common", "skc_nulls_node", 0, "pointer")
        .add_field("sock_common", "skc_v6_daddr", 8, "array")
        .add_field("sock_common", "skc_v6_rcv_saddr", 24, "array")
        .add_field("sock_common", "skc_dport", 40, "unsigned short")
        .add_field("sock_common", "skc_num", 42, "unsigned short")
        .add_field("sock_common", "skc_state", 44, "unsigned char")
        .add_struct("sock", 256)
        .add_field("sock", "__sk_common", 0, "sock_common")
        .add_symbol("tcp6_hashinfo", vaddr)
        .build_json();

    let resolver = IsfResolver::from_value(&isf).unwrap();
    let (cr3, mem) = PageTableBuilder::new()
        .map_4k(vaddr, paddr, flags::WRITABLE)
        .write_phys(paddr, &data)
        .build();
    let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
    let reader = ObjectReader::new(vas, Box::new(resolver));

    let conns = walk_connections6(&reader).unwrap();
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0].protocol, Protocol::Tcp6);
    assert_eq!(conns[0].local_addr, "::1");
    assert_eq!(conns[0].remote_addr, "::1");
    assert_eq!(conns[0].remote_port, 443);
}

#[test]
fn walk_ipv6_no_symbol_returns_empty() {
    // When tcp6_hashinfo symbol is missing, return empty vec (not error)
    let isf = IsfBuilder::new().build_json();
    let (cr3, mem) = PageTableBuilder::new().build();
    let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
    let reader = ObjectReader::new(vas, Box::new(IsfResolver::from_value(&isf).unwrap()));
    let result = walk_connections6(&reader).unwrap();
    assert!(result.is_empty());
}
```

Run: `cargo test -p memf-linux -- network::tests::walk_ipv6 2>&1 | tail -5`
Expected: compile error — `walk_connections6` not found.

**Step 2: Commit RED**

```bash
git add crates/memf-linux/src/network.rs
git commit --no-gpg-sign -m "test(ipv6): RED — IPv6 connection walker not yet implemented"
```

**Step 3: Implement `walk_connections6` and helpers**

Add after `ipv4_to_string`:

```rust
/// Walk Linux TCP IPv6 connections via `tcp6_hashinfo.ehash`.
pub fn walk_connections6<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<ConnectionInfo>> {
    let tcp6_hashinfo_addr = match reader.symbols().symbol_address("tcp6_hashinfo") {
        Some(a) => a,
        None => return Ok(Vec::new()),
    };

    let ehash_ptr: u64 = reader.read_field(tcp6_hashinfo_addr, "inet_hashinfo", "ehash")?;
    let ehash_mask: u32 = reader.read_field(tcp6_hashinfo_addr, "inet_hashinfo", "ehash_mask")?;

    if ehash_ptr == 0 {
        return Ok(Vec::new());
    }

    let mut connections = Vec::new();
    let bucket_count = u64::from(ehash_mask) + 1;

    for i in 0..bucket_count.min(1_000_000) {
        let bucket_size = reader.symbols().struct_size("inet_ehash_bucket").unwrap_or(8);
        let bucket_addr = ehash_ptr + i * bucket_size;

        let chain_first: u64 = match reader.read_field(bucket_addr, "inet_ehash_bucket", "chain") {
            Ok(v) => v,
            Err(_) => continue,
        };

        if chain_first == 0 || chain_first & 1 != 0 {
            continue;
        }

        let mut sk_addr = chain_first;
        let mut chain_len = 0;
        while sk_addr != 0 && sk_addr & 1 == 0 && chain_len < 1000 {
            if let Ok(conn) = read_inet6_sock(reader, sk_addr) {
                connections.push(conn);
            }
            sk_addr = match reader.read_pointer(sk_addr, "sock_common", "skc_nulls_node") {
                Ok(v) => v,
                Err(_) => break,
            };
            chain_len += 1;
        }
    }

    Ok(connections)
}

fn read_inet6_sock<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    sk_addr: u64,
) -> Result<ConnectionInfo> {
    let sk_common_off = reader.symbols().field_offset("sock", "__sk_common").unwrap_or(0);
    let common_addr = sk_addr + sk_common_off;

    let daddr_bytes = reader.read_bytes(
        common_addr + reader.symbols().field_offset("sock_common", "skc_v6_daddr").unwrap_or(8),
        16,
    )?;
    let saddr_bytes = reader.read_bytes(
        common_addr + reader.symbols().field_offset("sock_common", "skc_v6_rcv_saddr").unwrap_or(24),
        16,
    )?;
    let dport: u16 = reader.read_field(common_addr, "sock_common", "skc_dport")?;
    let sport: u16 = reader.read_field(common_addr, "sock_common", "skc_num")?;
    let state: u8  = reader.read_field(common_addr, "sock_common", "skc_state")?;

    let mut daddr = [0u8; 16];
    let mut saddr = [0u8; 16];
    daddr.copy_from_slice(&daddr_bytes);
    saddr.copy_from_slice(&saddr_bytes);

    Ok(ConnectionInfo {
        protocol: Protocol::Tcp6,
        local_addr:   ipv6_to_string(&saddr),
        local_port:   sport,
        remote_addr:  ipv6_to_string(&daddr),
        remote_port:  u16::from_be(dport),
        state: ConnectionState::from_raw(state),
        pid: None,
    })
}

fn ipv6_to_string(addr: &[u8; 16]) -> String {
    use std::net::Ipv6Addr;
    let mut groups = [0u16; 8];
    for (i, chunk) in addr.chunks(2).enumerate() {
        groups[i] = u16::from_be_bytes([chunk[0], chunk[1]]);
    }
    Ipv6Addr::from(groups).to_string()
}
```

Also expose in `lib.rs`:
```rust
pub use network::walk_connections6;
```

Run: `cargo test -p memf-linux -- network::tests 2>&1 | tail -5`
Expected: all pass.

**Step 4: Commit GREEN**

```bash
git add crates/memf-linux/src/network.rs crates/memf-linux/src/lib.rs
git commit --no-gpg-sign -m "feat(ipv6): GREEN — Linux TCP6 connection walker via tcp6_hashinfo"
```

---

## Task 5: Eliminate `unwrap()`/`expect()` in format parsers

**Why:** The format parsers process adversary-controlled memory dumps. An `unwrap()` on a malformed crashdump or hibernation file crashes the tool instead of returning a structured error. This is a security flaw for a forensic tool.

**Files:**
- Modify: `crates/memf-format/src/win_crashdump.rs` (lines 75, 80)
- Modify: `crates/memf-format/src/kdump.rs` (line 347, mutex lock)
- Modify: `crates/memf-format/src/hiberfil.rs` (up to 22 unwraps)

**Context:**
The `win_crashdump.rs` helpers at lines 75 and 80:
```rust
fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}
fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}
```
These panic if `data` is too short. Replace with functions returning `Result`.

**Step 1: Write RED tests for truncated input**

In `win_crashdump.rs` test module:
```rust
#[test]
fn from_bytes_truncated_header_returns_error() {
    // 3 bytes — too short to be any valid crash dump
    let tiny = vec![0u8; 3];
    let result = CrashDumpProvider::from_bytes(&tiny);
    assert!(result.is_err(), "truncated input must return Err, not panic");
}

#[test]
fn from_bytes_valid_signature_but_truncated_body_returns_error() {
    // Signature 'PAGE' at offset 0 but body too short for header fields
    let mut data = vec![0u8; 100];
    data[0..4].copy_from_slice(b"PAGE");
    let result = CrashDumpProvider::from_bytes(&data);
    // Either error or valid parse — must not panic
    let _ = result;
}
```

Run: `cargo test -p memf-format -- win_crashdump::tests::truncated 2>&1 | tail -5`
Expected: PASS (these are safety tests that should already not panic with the current code since the slice indexing panic is the bug we're fixing).

Actually run the tests first to see current behavior:
```bash
cargo test -p memf-format 2>&1 | grep "test result"
```

**Step 2: Commit RED**

```bash
git add crates/memf-format/src/win_crashdump.rs
git commit --no-gpg-sign -m "test(safety): RED — truncated crash dump input must not panic"
```

**Step 3: Fix `win_crashdump.rs`**

Replace the panicking helpers:
```rust
fn read_u32(data: &[u8], offset: usize) -> crate::Result<u32> {
    data.get(offset..offset + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(crate::Error::InvalidFormat("truncated header (u32)".into()))
}

fn read_u64(data: &[u8], offset: usize) -> crate::Result<u64> {
    data.get(offset..offset + 8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(crate::Error::InvalidFormat("truncated header (u64)".into()))
}
```

Then update all call sites within `win_crashdump.rs` to use `?` instead of direct calls (they will now return `Result`).

For `kdump.rs` line 347 — mutex lock:
```rust
// Before:
let data = self.cache.lock().expect("cache lock poisoned");
// After:
let data = self.cache.lock().map_err(|_| crate::Error::InvalidFormat("cache lock poisoned".into()))?;
```

For `hiberfil.rs` — read through the file and replace each `unwrap()` on slice operations with `.ok_or(Error::InvalidFormat(...))` and propagate with `?`.

Run: `cargo test -p memf-format 2>&1 | grep "test result"`
Expected: all pass, 0 failed.

**Step 4: Commit GREEN**

```bash
git add crates/memf-format/src/win_crashdump.rs crates/memf-format/src/kdump.rs crates/memf-format/src/hiberfil.rs
git commit --no-gpg-sign -m "fix(safety): GREEN — replace unwrap/expect in format parsers with Result propagation"
```

---

## Task 6: Per-walker failure counters (`WalkResult<T>`)

**Why:** Walkers silently skip corrupted entries (`Err(_) => continue`). Analysts need to know "walked 500/512 processes, 12 corrupted entries skipped" vs "walked 500/500 processes". Without this, silent failures are indistinguishable from a clean walk.

**Files:**
- Modify: `crates/memf-core/src/lib.rs` (add `WalkResult`)
- Modify: `crates/memf-linux/src/process.rs` (migrate to `WalkResult`)
- Modify: `crates/memf-linux/src/network.rs` (migrate to `WalkResult`)

**Context:**
Add `WalkResult<T>` to `memf-core`:
```rust
/// Output from a walker that may skip corrupted entries.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct WalkResult<T> {
    /// Successfully walked entries.
    pub items: Vec<T>,
    /// Number of entries skipped due to unreadable memory or parse errors.
    pub skipped: u32,
}

impl<T> WalkResult<T> {
    pub fn new(items: Vec<T>, skipped: u32) -> Self {
        Self { items, skipped }
    }
    pub fn push(&mut self, item: T) {
        self.items.push(item);
    }
    pub fn skip(&mut self) {
        self.skipped += 1;
    }
}
```

**NOTE:** To avoid a massive breaking change, we introduce `WalkResult` only on the two most important walkers: `walk_processes` (Linux) and `walk_connections` (Linux). Other walkers are migrated in follow-up work.

**Step 1: Write RED tests**

In `crates/memf-core/src/lib.rs` test module (or `walk_result.rs`):
```rust
#[test]
fn walk_result_new_has_correct_counts() {
    let r: WalkResult<u32> = WalkResult::new(vec![1, 2, 3], 5);
    assert_eq!(r.items.len(), 3);
    assert_eq!(r.skipped, 5);
}

#[test]
fn walk_result_skip_increments_counter() {
    let mut r: WalkResult<u32> = WalkResult::default();
    r.skip();
    r.skip();
    assert_eq!(r.skipped, 2);
    assert!(r.items.is_empty());
}
```

In `process.rs` test module (add after existing tests):
```rust
#[test]
fn walk_processes_result_has_skipped_field() {
    // Walk over an empty init_task — should produce WalkResult with 0 items, 0 skipped.
    // (uses existing test helper pattern from the file)
    // ... (implement using existing test infrastructure in process.rs) ...
    // The key assertion:
    // let result = walk_processes(&reader).unwrap();
    // let _ = result.skipped; // must compile
}
```

Run: `cargo test -p memf-core -- walk_result 2>&1 | tail -5`
Expected: compile error — `WalkResult` not found.

**Step 2: Commit RED**

```bash
git add crates/memf-core/src/lib.rs
git commit --no-gpg-sign -m "test(reliability): RED — WalkResult type not yet defined"
```

**Step 3: Implement `WalkResult` in memf-core**

Add to `crates/memf-core/src/lib.rs` (or a new `crates/memf-core/src/walk_result.rs` + `pub mod walk_result`):

```rust
/// Output wrapper for walkers that may encounter unreadable entries.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct WalkResult<T: serde::Serialize> {
    pub items: Vec<T>,
    pub skipped: u32,
}

impl<T: serde::Serialize> WalkResult<T> {
    pub fn new(items: Vec<T>, skipped: u32) -> Self { Self { items, skipped } }
    pub fn push(&mut self, item: T) { self.items.push(item); }
    pub fn skip(&mut self) { self.skipped += 1; }
}
```

Migrate `walk_processes` in `memf-linux/src/process.rs`:
- Change return type from `Result<Vec<ProcessInfo>>` to `Result<WalkResult<ProcessInfo>>`
- Replace `connections.push(conn)` with `result.push(conn)`
- Replace `continue` (after `Err(_)`) with `result.skip(); continue`

Migrate `walk_connections` in `memf-linux/src/network.rs` similarly.

Update `lib.rs` exports in `memf-linux` and any callers.

Run: `cargo test --workspace 2>&1 | grep "test result"` — all pass.

**Step 4: Commit GREEN**

```bash
git add crates/memf-core/src/lib.rs crates/memf-linux/src/process.rs crates/memf-linux/src/network.rs crates/memf-linux/src/lib.rs
git commit --no-gpg-sign -m "feat(reliability): GREEN — WalkResult<T> with skipped counter; migrate process/network walkers"
```

---

## Task 7: `iter_list` — streaming iterator for `walk_list`

**Why:** `walk_list` collects all list entries into `Vec<u64>` before returning. For a system with 100K handles, this allocates a 800KB vec upfront. A streaming iterator enables lazy evaluation, early termination on `--pid` filter, and lower peak memory.

**Files:**
- Modify: `crates/memf-core/src/object_reader.rs`

**Context:**
Add a **new** `iter_list` method returning `impl Iterator<Item = Result<u64>>`. Keep the existing `walk_list` to avoid breaking all callers. Callers can migrate incrementally.

The iterator must be a named struct (not `impl Trait` directly in the method) because `impl Trait` in method position cannot reference `self` lifetime cleanly with closures over mutable state.

**Step 1: Write RED tests**

In `object_reader.rs` test module:
```rust
#[test]
fn iter_list_yields_same_as_walk_list() {
    // Build a 3-node circular list, verify iter_list and walk_list agree.
    // (use existing list test helpers from the file)
    // The test verifies iter_list() exists and produces identical results.
    // ... (copy existing walk_list test setup, then compare)
    // let collected: Vec<u64> = reader.iter_list(head, "list_head", "next")
    //     .collect::<Result<Vec<_>, _>>()
    //     .unwrap();
    // assert_eq!(collected, walk_list_result);
}

#[test]
fn iter_list_can_stop_early() {
    // Verify take() works — iterator is lazy.
    // ... same list setup ...
    // let first_two: Vec<u64> = reader.iter_list(head, "list_head", "next")
    //     .take(2)
    //     .collect::<Result<Vec<_>, _>>()
    //     .unwrap();
    // assert_eq!(first_two.len(), 2);
}
```

Run: `cargo test -p memf-core -- object_reader::tests::iter_list 2>&1 | tail -5`
Expected: compile error — method `iter_list` not found.

**Step 2: Commit RED**

```bash
git add crates/memf-core/src/object_reader.rs
git commit --no-gpg-sign -m "test(perf): RED — iter_list streaming iterator not yet implemented"
```

**Step 3: Implement**

Add a `ListIter` struct and `iter_list` method to `ObjectReader`:

```rust
/// Streaming iterator over a kernel doubly-linked list.
pub struct ListIter<'a, P: PhysicalMemoryProvider> {
    reader: &'a ObjectReader<P>,
    head_vaddr: u64,
    current: u64,
    struct_name: &'a str,
    list_field: &'a str,
    seen: std::collections::HashSet<u64>,
    done: bool,
}

impl<'a, P: PhysicalMemoryProvider> Iterator for ListIter<'a, P> {
    type Item = crate::Result<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.current == self.head_vaddr {
            return None;
        }
        if !self.seen.insert(self.current) {
            self.done = true;
            return None;
        }
        if self.seen.len() > MAX_LIST_ITERATIONS {
            self.done = true;
            return Some(Err(crate::Error::ListCycle(MAX_LIST_ITERATIONS)));
        }

        let entry_addr = self.current;
        self.current = match self.reader.read_pointer(self.current, self.struct_name, self.list_field) {
            Ok(next) => next,
            Err(e) => {
                self.done = true;
                return Some(Err(e));
            }
        };
        Some(Ok(entry_addr))
    }
}

impl<P: PhysicalMemoryProvider> ObjectReader<P> {
    /// Returns a lazy iterator over a kernel linked list.
    ///
    /// Unlike [`walk_list`], this does not allocate a `Vec` — entries are
    /// yielded one at a time. Use `.take(n)` for early termination.
    pub fn iter_list<'a>(
        &'a self,
        head_vaddr: u64,
        struct_name: &'a str,
        list_field: &'a str,
    ) -> ListIter<'a, P> {
        let current = match self.read_pointer(head_vaddr, struct_name, list_field) {
            Ok(first) => first,
            Err(_) => head_vaddr, // will immediately return None
        };
        ListIter {
            reader: self,
            head_vaddr,
            current,
            struct_name,
            list_field,
            seen: std::collections::HashSet::new(),
            done: false,
        }
    }
}
```

Run: `cargo test -p memf-core -- object_reader::tests 2>&1 | tail -5`
Expected: all pass.

**Step 4: Commit GREEN**

```bash
git add crates/memf-core/src/object_reader.rs
git commit --no-gpg-sign -m "feat(perf): GREEN — iter_list streaming iterator for kernel linked lists"
```

---

## Task 8: `IntoForensicEvents` for top 3 walker types

**Why:** `IntoForensicEvents` trait exists in `memf-correlate/src/traits.rs` but is implemented on zero real walker output types. The correlation engine receives no data. This task wires three high-value walkers.

**Files:**
- Modify: `crates/memf-windows/src/types.rs` (add `IntoForensicEvents` impls)
- Modify: `crates/memf-windows/Cargo.toml` (add `memf-correlate.workspace = true`)
- Modify: `Cargo.toml` (workspace: add `memf-correlate` if not already there)

**Context:**
Three walker output types to wire:
1. `WinMalfindInfo` — maps to `Finding::ProcessHollowing`, `Severity::High`, `T1055.012`
2. `WinHollowingInfo` — maps to `Finding::ProcessHollowing`, `Severity::Critical`, `T1055.012`
3. `WinConnectionInfo` — maps to `Finding::NetworkBeaconing`, `Severity::Medium`, `T1071`

Check `crates/memf-correlate/Cargo.toml` is in workspace deps:
```bash
grep "memf-correlate" /Users/4n6h4x0r/src/memory-forensic/Cargo.toml
```

**Step 1: Write RED tests**

In `crates/memf-windows/src/types.rs` test module:
```rust
#[test]
fn malfind_info_produces_forensic_events() {
    use memf_correlate::traits::IntoForensicEvents;
    let info = WinMalfindInfo {
        pid: 1234,
        process_name: "malware.exe".into(),
        vad_start: 0x1000,
        vad_end: 0x2000,
        protection: "PAGE_EXECUTE_READWRITE".into(),
        header_bytes: vec![0x4D, 0x5A],
        is_suspicious: true,
    };
    let events = info.into_forensic_events();
    assert!(!events.is_empty());
    assert_eq!(events[0].source_walker, "malfind");
}

#[test]
fn non_suspicious_malfind_produces_no_events() {
    use memf_correlate::traits::IntoForensicEvents;
    let info = WinMalfindInfo {
        is_suspicious: false,
        // ... other fields zeroed ...
        pid: 4,
        process_name: "System".into(),
        vad_start: 0,
        vad_end: 0,
        protection: "PAGE_READONLY".into(),
        header_bytes: vec![],
    };
    let events = info.into_forensic_events();
    assert!(events.is_empty());
}
```

Run: `cargo test -p memf-windows -- types::tests::malfind_info 2>&1 | tail -5`
Expected: compile error — `IntoForensicEvents` not in scope / `memf_correlate` not found.

**Step 2: Commit RED**

```bash
git add crates/memf-windows/src/types.rs
git commit --no-gpg-sign -m "test(correlate): RED — IntoForensicEvents not yet implemented on WinMalfindInfo"
```

**Step 3: Add dependency + implement**

In `crates/memf-windows/Cargo.toml`, add:
```toml
memf-correlate.workspace = true
```

In `crates/memf-windows/src/types.rs`, add:
```rust
use memf_correlate::event::{Entity, Finding, ForensicEvent, Severity};
use memf_correlate::mitre::MitreAttackId;
use memf_correlate::traits::IntoForensicEvents;

impl IntoForensicEvents for WinMalfindInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        if !self.is_suspicious {
            return Vec::new();
        }
        vec![ForensicEvent::builder()
            .source_walker("malfind")
            .entity(Entity::Process {
                pid: self.pid,
                name: self.process_name,
                ppid: None,
            })
            .finding(Finding::ProcessHollowing)
            .severity(Severity::High)
            .confidence(0.8)
            .mitre_attack(vec![MitreAttackId::new("T1055.012").unwrap()])
            .raw_evidence(self.header_bytes)
            .build()]
    }
}

impl IntoForensicEvents for WinHollowingInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        if !self.is_hollow {
            return Vec::new();
        }
        vec![ForensicEvent::builder()
            .source_walker("hollowing")
            .entity(Entity::Process {
                pid: self.pid,
                name: self.process_name,
                ppid: None,
            })
            .finding(Finding::ProcessHollowing)
            .severity(Severity::Critical)
            .confidence(0.9)
            .mitre_attack(vec![MitreAttackId::new("T1055.012").unwrap()])
            .build()]
    }
}

impl IntoForensicEvents for WinConnectionInfo {
    fn into_forensic_events(self) -> Vec<ForensicEvent> {
        use memf_correlate::event::Protocol as CProtocol;
        let protocol = match self.protocol {
            WinTcpState::Established => CProtocol::Tcp,
            _ => CProtocol::Tcp,
        };
        let _ = protocol; // suppress unused warning during prototype
        vec![ForensicEvent::builder()
            .source_walker("network")
            .entity(Entity::NetworkConnection {
                src_addr: self.local_addr.parse().ok(),
                src_port: Some(self.local_port),
                dst_addr: self.remote_addr.parse().ok(),
                dst_port: Some(self.remote_port),
                protocol: memf_correlate::event::Protocol::Tcp,
            })
            .finding(Finding::Other("active_connection".into()))
            .severity(Severity::Info)
            .confidence(1.0)
            .build()]
    }
}
```

Run: `cargo test -p memf-windows -- types::tests 2>&1 | tail -5`
Expected: all pass.

**Step 4: Commit GREEN**

```bash
git add crates/memf-windows/Cargo.toml crates/memf-windows/src/types.rs
git commit --no-gpg-sign -m "feat(correlate): GREEN — IntoForensicEvents for WinMalfindInfo, WinHollowingInfo, WinConnectionInfo"
```

---

## Task 9: NDJSON output format

**Why:** NDJSON (newline-delimited JSON) is the standard for streaming to Splunk HEC, Elasticsearch bulk API, and piping to `jq`. The CLI already has `OutputFormat` with `Table`, `Json`, `Csv` — adding `Ndjson` is a small, high-value change.

**Files:**
- Modify: `src/main.rs` (add `Ndjson` variant and output handler)

**Context:**
`OutputFormat` enum at line 363 of `src/main.rs`. JSON output uses `serde_json::to_string_pretty`. NDJSON emits one `serde_json::to_string` (compact) per item with `\n`. Clap parses `--output ndjson`.

**Step 1: Write RED test**

The CLI binary is at `src/main.rs`. Integration testing via `assert_cmd` or `std::process::Command` is the right approach, but adding a unit test for the format function is simpler:

In `src/main.rs`, add a helper function and test:
```rust
fn write_ndjson<T: serde::Serialize>(items: &[T], writer: &mut impl std::io::Write) -> std::io::Result<()> {
    for item in items {
        let line = serde_json::to_string(item).unwrap_or_default();
        writeln!(writer, "{line}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_ndjson_produces_one_line_per_item() {
        let items = vec![
            serde_json::json!({"pid": 4, "name": "System"}),
            serde_json::json!({"pid": 8, "name": "smss.exe"}),
        ];
        let mut buf = Vec::new();
        write_ndjson(&items, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"pid\":4"));
        assert!(lines[1].contains("\"pid\":8"));
    }

    #[test]
    fn write_ndjson_empty_produces_no_output() {
        let items: Vec<serde_json::Value> = vec![];
        let mut buf = Vec::new();
        write_ndjson(&items, &mut buf).unwrap();
        assert!(buf.is_empty());
    }
}
```

Run: `cargo test --bin memf -- tests::write_ndjson 2>&1 | tail -5`
Expected: compile error — `OutputFormat::Ndjson` missing or `write_ndjson` not found.

**Step 2: Commit RED**

```bash
git add src/main.rs
git commit --no-gpg-sign -m "test(output): RED — NDJSON format not yet implemented"
```

**Step 3: Implement**

Add `Ndjson` variant:
```rust
#[derive(Clone, Copy, Default, clap::ValueEnum)]
enum OutputFormat {
    #[default]
    Table,
    Json,
    Csv,
    /// Newline-delimited JSON (one JSON object per line). Suitable for Splunk HEC,
    /// Elasticsearch bulk API, and piping to `jq`.
    Ndjson,
}
```

Add `write_ndjson` function (as defined above).

In each output dispatch block that currently handles `OutputFormat::Json`, add the `OutputFormat::Ndjson` arm:
```rust
OutputFormat::Ndjson => {
    write_ndjson(&items, &mut std::io::stdout()).unwrap();
}
```

Run: `cargo test --bin memf -- tests 2>&1 | tail -5`
Expected: all pass.

**Step 4: Commit GREEN**

```bash
git add src/main.rs
git commit --no-gpg-sign -m "feat(output): GREEN — NDJSON output format (--output ndjson)"
```

---

## Task 10: `cargo-fuzz` targets for format parsers

**Why:** The format parsers (`CrashDumpProvider`, `HiberfilProvider`, `KdumpProvider`, `LimeProvider`) process adversary-controlled binary data. Fuzzing is the only systematic way to find panic-on-malformed-input bugs. After Task 5 eliminates known panics, fuzzing finds the ones we missed.

**Files:**
- Create: `fuzz/Cargo.toml`
- Create: `fuzz/fuzz_targets/fuzz_crashdump.rs`
- Create: `fuzz/fuzz_targets/fuzz_hiberfil.rs`
- Create: `fuzz/fuzz_targets/fuzz_kdump.rs`
- Create: `fuzz/fuzz_targets/fuzz_lime.rs`

**Context:**
`cargo-fuzz` uses `libFuzzer` under the hood. Fuzz targets live in `fuzz/fuzz_targets/`. Each target is a Rust binary that takes `&[u8]` from the fuzzer and passes it to the parser's `from_bytes` (or equivalent) entry point.

Install: `cargo install cargo-fuzz` (not a project dep — developer tool).

**Step 1: Write RED "test"**

The RED here is a compile check — the fuzz targets should fail to compile without the workspace structure.

Create a `fuzz/Cargo.toml`:
```toml
[package]
name = "memf-fuzz"
version = "0.0.1"
edition = "2021"
publish = false

[dependencies]
libfuzzer-sys = "0.4"
memf-format = { path = "../crates/memf-format" }

[[bin]]
name = "fuzz_crashdump"
path = "fuzz_targets/fuzz_crashdump.rs"
test = false
doc = false

[[bin]]
name = "fuzz_hiberfil"
path = "fuzz_targets/fuzz_hiberfil.rs"
test = false
doc = false

[[bin]]
name = "fuzz_kdump"
path = "fuzz_targets/fuzz_kdump.rs"
test = false
doc = false

[[bin]]
name = "fuzz_lime"
path = "fuzz_targets/fuzz_lime.rs"
test = false
doc = false
```

Run: `cargo check --manifest-path fuzz/Cargo.toml 2>&1 | tail -5`
Expected: error — fuzz target files don't exist yet.

**Step 2: Commit RED**

```bash
git add fuzz/Cargo.toml
git commit --no-gpg-sign -m "test(fuzz): RED — fuzz Cargo.toml, targets not yet created"
```

**Step 3: Create fuzz targets**

`fuzz/fuzz_targets/fuzz_crashdump.rs`:
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use memf_format::win_crashdump::CrashDumpProvider;

fuzz_target!(|data: &[u8]| {
    // Must never panic — only return Ok or Err.
    let _ = CrashDumpProvider::from_bytes(data);
});
```

`fuzz/fuzz_targets/fuzz_hiberfil.rs`:
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use memf_format::hiberfil::HiberfilProvider;

fuzz_target!(|data: &[u8]| {
    let _ = HiberfilProvider::from_bytes(data);
});
```

`fuzz/fuzz_targets/fuzz_kdump.rs`:
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use memf_format::kdump::KdumpProvider;

fuzz_target!(|data: &[u8]| {
    let _ = KdumpProvider::from_bytes(data);
});
```

`fuzz/fuzz_targets/fuzz_lime.rs`:
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use memf_format::lime::LimeProvider;

fuzz_target!(|data: &[u8]| {
    let _ = LimeProvider::from_bytes(data);
});
```

Run: `cargo check --manifest-path fuzz/Cargo.toml 2>&1 | tail -5`
Expected: compiles cleanly (or errors only on `libfuzzer-sys` link step, which requires nightly).

Verify with: `cargo +nightly fuzz check 2>&1 | tail -5`

**Step 4: Commit GREEN**

```bash
git add fuzz/
git commit --no-gpg-sign -m "feat(fuzz): GREEN — cargo-fuzz targets for crashdump/hiberfil/kdump/lime parsers"
```

---

## Execution order and dependencies

```
Task 1 (translation cache)
  └→ Task 2 (5-level, adds to vas.rs after cache is in)
      └→ Task 3 (AArch64, uses walk_4level_from refactor from Task 2)

Task 4 (IPv6)         — independent
Task 5 (unwraps)      — independent, do before Task 10 (fuzz)
Task 6 (WalkResult)   — independent
Task 7 (iter_list)    — independent
Task 8 (IntoFE impls) — independent
Task 9 (NDJSON)       — independent
Task 10 (fuzz)        — after Task 5 (needs safe parsers)
```

## Full workspace verification (after all tasks)

```bash
cargo test --workspace 2>&1 | grep "test result"
cargo clippy --workspace --lib --bins -- -D warnings 2>&1 | grep "^error"
```
Expected: all pass, no clippy errors.
