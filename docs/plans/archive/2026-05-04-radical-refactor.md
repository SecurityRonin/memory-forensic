# Radical Refactor: Maintainability + Debuggability Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Eliminate the four largest DRY violations and replace stringly-typed errors with structured variants, making every walker shorter, every failure actionable, and every test helper non-duplicated.

**Architecture:** Four sequential passes — (1) shared test infrastructure, (2) `ObjectReader` convenience methods, (3) structured error types, (4) classify/heuristics consolidation. Each pass is independently testable and releasable. No public API surface changes; all changes are within the workspace.

**Tech Stack:** Rust 2021, `thiserror`, existing `memf-core`/`memf-linux`/`memf-windows` crates

---

## Background: What's Wrong

### Problem 1 — Duplicated test helpers (~160 files)
Every walker file contains its own `make_win_reader` / `make_linux_reader` / `make_module_reader` helper that:
- Builds an `IsfBuilder` with ISF fields
- Constructs a `PageTableBuilder`
- Calls `ObjectReader::new(VirtualAddressSpace::new(...), ...)`

These are 90% identical across every test module. Adding a new walker means copy-pasting 30 lines of test setup.

### Problem 2 — Symbol resolution boilerplate
The most common pattern in every walker (appears hundreds of times):
```rust
let foo = reader.symbols().symbol_address("foo")
    .ok_or_else(|| Error::Walker("symbol 'foo' not found".into()))?;
let off = reader.symbols().field_offset("task_struct", "field")
    .ok_or_else(|| Error::Walker("task_struct.field not found".into()))?;
```
Two `ObjectReader` methods (`required_symbol`, `required_field`) collapse each to one line.

### Problem 3 — `Error::Walker(String)` is opaque
`memf-linux::Error::Walker` and `memf-windows::Error::Walker` are catch-alls that swallow context. When a walker fails in production you see:
```
walker failed: task_struct.mm not found
```
You don't know which walker called it, whether it was a symbol or a field lookup, or whether the ISF is simply missing that struct. Structured variants fix this.

### Problem 4 — 60+ `classify_*` functions scattered one-per-file
Each Linux walker file ends with a public `classify_*` function. They are pure heuristics with no dependency on `ObjectReader`. They're impossible to discover, can't be unit-tested in one place, and add ~20 lines to every walker file. Consolidating them into `heuristics.rs` makes them findable and testable.

---

## Task 1: Shared test infrastructure — `testing.rs` per crate

**Files:**
- Create: `crates/memf-windows/src/testing.rs`
- Create: `crates/memf-linux/src/testing.rs`
- Modify: `crates/memf-windows/src/lib.rs` (add `#[cfg(test)] pub mod testing;`)
- Modify: `crates/memf-linux/src/lib.rs` (add `#[cfg(test)] pub mod testing;`)

**What to put in `memf-windows/src/testing.rs`:**

```rust
//! Shared test infrastructure for memf-windows walker tests.
//!
//! Import with: `use crate::testing::*;`

use memf_core::object_reader::ObjectReader;
use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
use memf_core::vas::{TranslationMode, VirtualAddressSpace};
use memf_symbols::isf::IsfResolver;
use memf_symbols::test_builders::IsfBuilder;

/// Build an `ObjectReader` from a pre-populated `IsfBuilder` and `PageTableBuilder`.
///
/// Standard Windows test setup: x64 4-level paging, CR3 from `ptb`.
pub fn make_reader(
    isf: &IsfBuilder,
    ptb: PageTableBuilder,
) -> ObjectReader<SyntheticPhysMem> {
    let json = isf.build_json();
    let resolver = IsfResolver::from_str(&json).expect("valid ISF");
    let (cr3, mem) = ptb.build();
    let vas = VirtualAddressSpace::new(mem, TranslationMode::X64, cr3);
    ObjectReader::new(vas, Box::new(resolver))
}

/// Standard Windows ISF with `_EPROCESS` and `_LIST_ENTRY`.
///
/// Offsets match the synthetic layout used across all Windows walker tests:
/// - `UniqueProcessId`  @ 0x2e8
/// - `ActiveProcessLinks` @ 0x2f0 (_LIST_ENTRY: Flink@0, Blink@8)
/// - `ImageFileName`   @ 0x450 (15-char inline string)
/// - `CreateTime`      @ 0x458 (FILETIME u64)
/// - `ExitTime`        @ 0x460 (FILETIME u64)
/// - `Peb`             @ 0x3f8
/// - `InheritedFromUniqueProcessId` @ 0x3e0
/// - `ActiveThreads`   @ 0x5f0 (u32)
/// - `WoW64Process`    @ 0x438
pub fn eprocess_isf() -> IsfBuilder {
    IsfBuilder::new()
        .add_struct("_EPROCESS", 0x700)
        .add_field("_EPROCESS", "UniqueProcessId", 0x2e8, "pointer")
        .add_field("_EPROCESS", "ActiveProcessLinks", 0x2f0, "_LIST_ENTRY")
        .add_field("_EPROCESS", "ImageFileName", 0x450, "char")
        .add_field("_EPROCESS", "CreateTime", 0x458, "unsigned long long")
        .add_field("_EPROCESS", "ExitTime", 0x460, "unsigned long long")
        .add_field("_EPROCESS", "Peb", 0x3f8, "pointer")
        .add_field("_EPROCESS", "InheritedFromUniqueProcessId", 0x3e0, "pointer")
        .add_field("_EPROCESS", "ActiveThreads", 0x5f0, "unsigned long")
        .add_field("_EPROCESS", "WoW64Process", 0x438, "pointer")
        .add_struct("_LIST_ENTRY", 16)
        .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
        .add_field("_LIST_ENTRY", "Blink", 8, "pointer")
}
```

**What to put in `memf-linux/src/testing.rs`:**

```rust
//! Shared test infrastructure for memf-linux walker tests.
//!
//! Import with: `use crate::testing::*;`

use memf_core::object_reader::ObjectReader;
use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
use memf_core::vas::{TranslationMode, VirtualAddressSpace};
use memf_symbols::isf::IsfResolver;
use memf_symbols::test_builders::IsfBuilder;

/// Build an `ObjectReader` from `IsfBuilder` + `PageTableBuilder`.
pub fn make_reader(
    isf: &IsfBuilder,
    ptb: PageTableBuilder,
) -> ObjectReader<SyntheticPhysMem> {
    let json = isf.build_json();
    let resolver = IsfResolver::from_str(&json).expect("valid ISF");
    let (cr3, mem) = ptb.build();
    let vas = VirtualAddressSpace::new(mem, TranslationMode::X64, cr3);
    ObjectReader::new(vas, Box::new(resolver))
}

/// Standard `task_struct` ISF layout used across Linux walker tests.
///
/// Offsets:
/// - `pid`          @ 0   (int, 4 bytes)
/// - `state`        @ 4   (long, 8 bytes)
/// - `tasks`        @ 16  (list_head, 16 bytes)
/// - `comm`         @ 32  (char, 16 bytes)
/// - `mm`           @ 48  (pointer, 8 bytes)
/// - `real_parent`  @ 56  (pointer, 8 bytes)
/// - `tgid`         @ 64  (int, 4 bytes)
/// - `thread_group` @ 72  (list_head, 16 bytes)
/// - `start_time`   @ 88  (unsigned long, 8 bytes)
pub fn task_struct_isf() -> IsfBuilder {
    IsfBuilder::new()
        .add_struct("task_struct", 128)
        .add_field("task_struct", "pid", 0, "int")
        .add_field("task_struct", "state", 4, "long")
        .add_field("task_struct", "tasks", 16, "list_head")
        .add_field("task_struct", "comm", 32, "char")
        .add_field("task_struct", "mm", 48, "pointer")
        .add_field("task_struct", "real_parent", 56, "pointer")
        .add_field("task_struct", "tgid", 64, "int")
        .add_field("task_struct", "thread_group", 72, "list_head")
        .add_field("task_struct", "start_time", 88, "unsigned long")
        .add_struct("list_head", 16)
        .add_field("list_head", "next", 0, "pointer")
        .add_field("list_head", "prev", 8, "pointer")
}
```

**Step 1: RED — write failing tests for the new helpers**

In `crates/memf-windows/src/testing.rs`, after the helpers, add:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_reader_builds_valid_reader() {
        let isf = eprocess_isf();
        let paddr: u64 = 0x0080_0000;
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let ptb = PageTableBuilder::new().map_4k(vaddr, paddr, flags::WRITABLE);
        let reader = make_reader(&isf, ptb);
        // Should resolve _EPROCESS.UniqueProcessId
        assert_eq!(
            reader.symbols().field_offset("_EPROCESS", "UniqueProcessId"),
            Some(0x2e8)
        );
    }
}
```

Run: `cargo test -p memf-windows -- testing:: 2>&1 | tail -5`
Expected: compile error (module not yet declared in lib.rs)

**Step 2: Declare the modules in lib.rs**

In `crates/memf-windows/src/lib.rs`, add near the top:
```rust
#[cfg(test)]
pub mod testing;
```

In `crates/memf-linux/src/lib.rs`, add:
```rust
#[cfg(test)]
pub mod testing;
```

**Step 3: GREEN — confirm tests pass**

Run: `cargo test -p memf-windows -- testing:: 2>&1 | tail -5`
Expected: `test result: ok. 1 passed; 0 failed`

Run: `cargo test -p memf-linux -- testing:: 2>&1 | tail -5`
Expected: `test result: ok. 1 passed; 0 failed`

**Step 4: Migrate process.rs to use shared helpers**

In `crates/memf-windows/src/process.rs`, replace the test module's local `make_win_reader` and inline `IsfBuilder` setup with:
```rust
use crate::testing::{eprocess_isf, make_reader};
```
Remove the local `make_win_reader` function and use the shared one.

Run: `cargo test -p memf-windows -- process:: 2>&1 | tail -5`
Expected: all process tests still pass.

**Step 5: Migrate thread.rs, modules.rs (linux), network.rs (linux)**

Same substitution in `thread.rs`, `memf-linux/src/modules.rs`, `memf-linux/src/network.rs`.

Each file: replace local helper → `use crate::testing::make_reader;`

Run: `cargo test -p memf-windows -p memf-linux 2>&1 | grep "test result"` 
Expected: all pass.

**Step 6: Commit RED + GREEN**

```bash
git add crates/memf-windows/src/testing.rs crates/memf-linux/src/testing.rs \
        crates/memf-windows/src/lib.rs crates/memf-linux/src/lib.rs \
        crates/memf-windows/src/process.rs crates/memf-windows/src/thread.rs \
        crates/memf-linux/src/modules.rs
git commit -m "refactor: shared test helpers in testing.rs — eliminate make_reader duplication"
```

---

## Task 2: `ObjectReader` convenience methods

**Files:**
- Modify: `crates/memf-core/src/object_reader.rs`

**What to add to `ObjectReader<P>`:**

```rust
/// Resolve a global kernel symbol, returning a structured error if absent.
///
/// Replaces the pattern:
/// ```
/// reader.symbols().symbol_address("foo")
///     .ok_or_else(|| Error::Walker("symbol 'foo' not found".into()))?
/// ```
pub fn required_symbol(&self, name: &str) -> Result<u64> {
    self.symbols()
        .symbol_address(name)
        .ok_or_else(|| Error::MissingSymbol(name.to_owned()))
}

/// Resolve a struct field offset, returning a structured error if absent.
///
/// Replaces the pattern:
/// ```
/// reader.symbols().field_offset("S", "f")
///     .ok_or_else(|| Error::Walker("S.f not found".into()))?
/// ```
pub fn required_field_offset(&self, struct_name: &str, field_name: &str) -> Result<usize> {
    self.symbols()
        .field_offset(struct_name, field_name)
        .ok_or_else(|| Error::MissingSymbol(format!("{struct_name}.{field_name}")))
}
```

**Step 1: RED — add tests**

In `crates/memf-core/src/object_reader.rs` test module:
```rust
#[test]
fn required_symbol_ok() {
    let isf = IsfBuilder::new().add_symbol("init_task", 0xFFFF_8000_CAFE_0000);
    let ptb = PageTableBuilder::new();
    let reader = make_reader(&isf, ptb);
    assert_eq!(reader.required_symbol("init_task").unwrap(), 0xFFFF_8000_CAFE_0000);
}

#[test]
fn required_symbol_missing_returns_error() {
    let isf = IsfBuilder::new();
    let ptb = PageTableBuilder::new();
    let reader = make_reader(&isf, ptb);
    let err = reader.required_symbol("nonexistent").unwrap_err();
    assert!(matches!(err, Error::MissingSymbol(_)));
}

#[test]
fn required_field_offset_ok() {
    let isf = IsfBuilder::new()
        .add_struct("task_struct", 128)
        .add_field("task_struct", "pid", 4, "int");
    let ptb = PageTableBuilder::new();
    let reader = make_reader(&isf, ptb);
    assert_eq!(reader.required_field_offset("task_struct", "pid").unwrap(), 4);
}

#[test]
fn required_field_offset_missing_returns_error() {
    let isf = IsfBuilder::new().add_struct("task_struct", 128);
    let ptb = PageTableBuilder::new();
    let reader = make_reader(&isf, ptb);
    let err = reader.required_field_offset("task_struct", "nonexistent").unwrap_err();
    assert!(matches!(err, Error::MissingSymbol(_)));
}
```

Run: `cargo test -p memf-core -- object_reader::tests::required 2>&1 | tail -5`
Expected: FAIL (methods don't exist yet)

**Step 2: GREEN — add the methods**

Add `required_symbol` and `required_field_offset` to `impl<P: PhysicalMemoryProvider> ObjectReader<P>` as shown above.

Run: `cargo test -p memf-core -- object_reader::tests::required 2>&1 | tail -5`
Expected: 4 passed

**Step 3: Migrate walkers to use new methods**

In `crates/memf-linux/src/process.rs`, replace:
```rust
// Before
let init_task_addr = reader
    .symbols()
    .symbol_address("init_task")
    .ok_or_else(|| Error::Walker("symbol 'init_task' not found".into()))?;
let tasks_offset = reader
    .symbols()
    .field_offset("task_struct", "tasks")
    .ok_or_else(|| Error::Walker("task_struct.tasks field not found".into()))?;

// After
let init_task_addr = reader.required_symbol("init_task")?;
let tasks_offset = reader.required_field_offset("task_struct", "tasks")?;
```

Do the same in `crates/memf-linux/src/modules.rs` and `crates/memf-windows/src/process.rs`.

Note: `required_symbol` and `required_field_offset` return `memf_core::Result`, while walkers use `memf_linux::Result`. The `?` operator works because `memf_linux::Error` implements `From<memf_core::Error>`. Verify this is true — if not, add:
```rust
// in memf-linux/src/lib.rs Error enum:
#[error(transparent)]
Core(#[from] memf_core::Error),
```

Run: `cargo test -p memf-linux -- process:: modules:: 2>&1 | tail -5`
Expected: all pass, no change in behaviour.

**Step 4: Commit**

```bash
git add crates/memf-core/src/object_reader.rs \
        crates/memf-linux/src/process.rs \
        crates/memf-linux/src/modules.rs \
        crates/memf-windows/src/process.rs
git commit -m "refactor: add required_symbol/required_field_offset to ObjectReader — eliminate ok_or_else boilerplate"
```

---

## Task 3: Structured error types

**Files:**
- Modify: `crates/memf-linux/src/lib.rs`
- Modify: `crates/memf-windows/src/lib.rs`

**Current (bad):**
```rust
pub enum Error {
    #[error("walker failed: {0}")]
    Walker(String),
    // ...
}
```

**Target:**
```rust
pub enum Error {
    /// A required kernel symbol was not found in the ISF.
    #[error("kernel symbol not found: {name}")]
    MissingKernelSymbol { name: String },

    /// A required struct field was not found in the ISF.
    #[error("ISF missing field: {struct_name}.{field_name}")]
    MissingField { struct_name: String, field_name: String },

    /// A walker-specific failure with the walker name for context.
    #[error("walker '{walker}' failed: {reason}")]
    WalkFailed { walker: &'static str, reason: String },

    /// A list walk failed (cycle, truncation, or corruption).
    #[error("list walk failed in walker '{walker}': {reason}")]
    ListWalkFailed { walker: &'static str, reason: String },

    /// Transparent pass-through from memf-core.
    #[error(transparent)]
    Core(#[from] memf_core::Error),

    /// Transparent pass-through from memf-format.
    #[error(transparent)]
    Format(#[from] memf_format::Error),
}
```

**Step 1: RED — add tests that assert on structured variants**

In `crates/memf-linux/src/lib.rs` test module:
```rust
#[test]
fn error_missing_kernel_symbol_contains_name() {
    let e = Error::MissingKernelSymbol { name: "init_task".to_owned() };
    assert!(e.to_string().contains("init_task"));
}

#[test]
fn error_missing_field_contains_struct_and_field() {
    let e = Error::MissingField {
        struct_name: "task_struct".to_owned(),
        field_name: "mm".to_owned(),
    };
    assert!(e.to_string().contains("task_struct"));
    assert!(e.to_string().contains("mm"));
}

#[test]
fn error_walk_failed_contains_walker_name() {
    let e = Error::WalkFailed {
        walker: "walk_processes",
        reason: "list corrupted".to_owned(),
    };
    assert!(e.to_string().contains("walk_processes"));
}
```

Run: `cargo test -p memf-linux -- lib::tests 2>&1 | tail -5`
Expected: FAIL (variants don't exist yet)

Do the same for `memf-windows/src/lib.rs`.

**Step 2: GREEN — replace the Error enum**

Replace `Error::Walker(String)` with the new variants in both `lib.rs` files.

Update existing `Error::Walker(...)` usages:
- `Error::Walker("symbol '...' not found".into())` → `Error::MissingKernelSymbol { name: "...".to_owned() }`
- `Error::Walker("struct.field not found".into())` → `Error::MissingField { struct_name: "...".to_owned(), field_name: "...".to_owned() }`
- `Error::Walker("some runtime message".into())` → `Error::WalkFailed { walker: "function_name", reason: "...".to_owned() }`

This will produce compile errors at every `Error::Walker(...)` callsite — that's intentional. Fix each one.

Run: `cargo build -p memf-linux -p memf-windows 2>&1 | grep "^error" | wc -l`
(count the errors, fix them one by one)

Run: `cargo test -p memf-linux -p memf-windows 2>&1 | grep "test result"`
Expected: all pass

**Step 3: Commit**

```bash
git add crates/memf-linux/src/lib.rs crates/memf-windows/src/lib.rs \
        crates/memf-linux/src/*.rs crates/memf-windows/src/*.rs
git commit -m "refactor: structured error variants — replace Walker(String) with typed MissingKernelSymbol/MissingField/WalkFailed"
```

---

## Task 4: Classify functions → `heuristics.rs`

**Files:**
- Create: `crates/memf-linux/src/heuristics.rs`
- Modify: `crates/memf-linux/src/lib.rs` (add `pub mod heuristics;`)
- Modify: each Linux walker file that has a `classify_*` function

**What `heuristics.rs` should contain:**

All 35+ `classify_*` functions currently in individual walker files, moved here verbatim. Each walker file keeps a re-export or just removes the function and callers use `heuristics::classify_bpf_program(...)`.

Since these are `pub fn`, moving them to a new module is a public API change. To maintain backward compatibility within the workspace, re-export from the original module:

```rust
// In bpf.rs — keep this one-liner where the function used to live:
pub use crate::heuristics::classify_bpf_program;
```

**Step 1: Create `heuristics.rs` with all classify functions**

Content of `crates/memf-linux/src/heuristics.rs`:
```rust
//! Pure heuristic classifiers for Linux forensic artifacts.
//!
//! All functions are stateless — they take primitive values extracted by
//! the walkers and return a `bool` (suspicious/not) or a `(bool, String)`
//! (suspicious, reason). No `ObjectReader` dependency.

/// Returns `true` if a BPF program type and name pattern indicates
/// a suspicious use (e.g. rootkit hooking syscalls via BPF trampolines).
pub fn classify_bpf_program(prog_type: &str, name: &str) -> bool {
    // ... (move body from bpf.rs)
}

// ... all other classify_* functions
```

**Step 2: RED — add unified heuristics tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bpf_syscall_hook_is_suspicious() {
        assert!(classify_bpf_program("tracepoint", "sys_enter_kill"));
    }

    #[test]
    fn normal_bpf_is_not_suspicious() {
        assert!(!classify_bpf_program("socket_filter", "tcpdump"));
    }

    // ... one test per classify function
}
```

Run: `cargo test -p memf-linux -- heuristics:: 2>&1 | tail -5`
Expected: FAIL (module doesn't exist yet)

**Step 3: GREEN — create heuristics.rs, add module declaration, add re-exports**

1. Create `heuristics.rs` with all classify functions moved from their original files
2. Add `pub mod heuristics;` to `lib.rs`
3. In each original walker file, replace the function body with a re-export: `pub use crate::heuristics::classify_foo;`

Run: `cargo test -p memf-linux 2>&1 | grep "test result"`
Expected: all tests pass (behaviour unchanged)

**Step 4: Commit**

```bash
git add crates/memf-linux/src/heuristics.rs crates/memf-linux/src/lib.rs \
        crates/memf-linux/src/*.rs
git commit -m "refactor: consolidate 35 classify_* functions into heuristics.rs — single discoverable location"
```

---

## Task 5: Full suite verification

**Step 1: Run full workspace**
```bash
cargo test --workspace 2>&1 | grep "test result"
```
Expected: all crates pass, zero failures.

**Step 2: Clippy clean**
```bash
cargo clippy --workspace -- -D warnings 2>&1 | grep "^error" | head -10
```
Expected: no errors.

**Step 3: Check test count didn't decrease**
```bash
cargo test --workspace 2>&1 | grep "test result" | grep -v "0 passed"
```
The test count should be ≥ what it was before (Task 4 adds heuristics tests).

**Step 4: Final commit**
```bash
git commit --allow-empty -m "chore(refactor): radical DRY/debuggability pass complete"
git push
```

---

## Summary of Impact

| Change | Files affected | Lines eliminated |
|---|---|---|
| Shared test helpers | ~160 walker files | ~4,800 (30/file) |
| `required_symbol` / `required_field_offset` | ~100 walker files | ~600 (3×200) |
| Structured errors | 2 lib.rs + all callers | +50 (more expressive) |
| Heuristics consolidation | 35 walker files | ~700 (20/file) |

Total: ~6,100 lines removed, 50 added — net **−6,050 lines** with zero behaviour change.
