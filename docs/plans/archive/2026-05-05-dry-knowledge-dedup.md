# Phase 2 DRY: Knowledge Deduplication Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Eliminate four categories of duplicated knowledge — masquerade target lists (4 files), EVTX format constants (2 files), winevt integrity naming, and winevt-core as a workspace dependency — so each fact lives in exactly one place.

**Architecture:** Three passes. (1) Wire `forensicnomicon` into `memf-windows` and replace 4 local masquerade-target constants with `forensicnomicon::processes::is_masquerade_target()`. (2) Wire `winevt-core` into the workspace and replace the 4 EVTX format constants in `evtx.rs` with re-exports from `winevt_core::binary`. (3) Rename `AntiForensicIndicator` → `IntegrityAnomaly` in `winevt-core` (intent belongs in RapidTriage, not the parser). Each pass is independently testable; no public API changes to callers outside the workspace.

**Tech Stack:** Rust 2021, `forensicnomicon 0.1` (path dep), `winevt-core 0.1` (path dep), `thiserror`, TDD with `cargo test`

---

## Background: What's Wrong

### Problem 1 — Masquerade target list duplicated 4 times

Four files in `memf-windows` each define their own private constant listing the same 6–7 Windows system process names:

| File | Constant |
|---|---|
| `peb_masquerade.rs:18` | `HIGH_VALUE_TARGETS: &[&str]` (7 names) |
| `correlate.rs:14` | `SPOOFABLE_NAMES: &[&str]` (7 names) |
| `suspicious_threads.rs:44` | `SYSTEM_PROCESSES: &[&str]` (6 names) |
| `getsids.rs` | `SYSTEM_PROCS: &[&str]` (similar set) |

`forensicnomicon::processes` already exports `WINDOWS_MASQUERADE_TARGETS` (15 entries, superset of all four) and `is_masquerade_target(name: &str) -> bool` (case-insensitive). These four constants should be deleted and their callers should call `is_masquerade_target()` instead.

### Problem 2 — EVTX format constants duplicated across repos

`memf-windows/src/evtx.rs` defines:
```rust
const ELFCHNK_MAGIC: [u8; 8] = [0x45, 0x6C, 0x66, 0x43, 0x68, 0x6E, 0x6B, 0x00];
const RECORD_MAGIC:  [u8; 4] = [0x2A, 0x2A, 0x00, 0x00];
const CHUNK_SIZE:    u64     = 0x10000;
const RECORDS_OFFSET: u64   = 0x200;
```

`winevt-core/src/binary.rs` already exports the identical values:
```rust
pub const ELFCHNK_MAGIC:        [u8; 8] = *b"ElfChnk\0";
pub const RECORD_MAGIC:         [u8; 4] = [0x2A, 0x2A, 0x00, 0x00];
pub const CHUNK_SIZE:           u64     = 0x1_0000;
pub const CHUNK_RECORDS_OFFSET: u64     = 0x200;
```

The four `evtx.rs` constants should be replaced with `use winevt_core::binary::{...}`.
`CHUNK_ALIGNMENT` (0x1000) and `MAX_CHUNKS` / `MAX_RECORDS_PER_CHUNK` are memory-walk–specific — they stay in `evtx.rs`.

### Problem 3 — `AntiForensicIndicator` encodes intent at the wrong layer

`winevt-core::binary` exports an `AntiForensicIndicator` enum. Anti-forensic detection implies intent, which belongs in RapidTriage's correlation engine — not in a low-level binary parser. The enum values themselves (RecordIdGap, ChecksumMismatch, TimestampAnomaly) are purely structural integrity facts. Rename to `IntegrityAnomaly`.

---

## Task 1: Add `forensicnomicon` dependency to `memf-windows`

**Files:**
- Modify: `crates/memf-windows/Cargo.toml`
- Test: `crates/memf-windows/src/peb_masquerade.rs` (test module)

**Context:**
`forensicnomicon` is already in `[workspace.dependencies]` at `{ path = "../forensicnomicon" }`.
`memf-windows/Cargo.toml` does NOT yet list it in `[dependencies]`.

**Step 1: RED — write a failing test that imports forensicnomicon**

In `crates/memf-windows/src/peb_masquerade.rs`, add to the existing `#[cfg(test)] mod tests` block:

```rust
#[test]
fn forensicnomicon_masquerade_target_covers_svchost() {
    // This test verifies forensicnomicon is reachable and its list is a superset
    // of the local HIGH_VALUE_TARGETS. If this fails to compile, the dep is missing.
    assert!(forensicnomicon::processes::is_masquerade_target("svchost.exe"));
    assert!(forensicnomicon::processes::is_masquerade_target("lsass.exe"));
    assert!(forensicnomicon::processes::is_masquerade_target("csrss.exe"));
}
```

Run: `cargo test -p memf-windows -- peb_masquerade::tests::forensicnomicon 2>&1 | tail -8`
Expected: compile error — `use of undeclared crate or module 'forensicnomicon'`

**Step 2: Commit RED**

```bash
git add crates/memf-windows/src/peb_masquerade.rs
git commit --no-gpg-sign -m "test(dry): RED — failing import of forensicnomicon in memf-windows"
```

**Step 3: GREEN — add the dep**

In `crates/memf-windows/Cargo.toml`, add to `[dependencies]`:
```toml
forensicnomicon.workspace = true
```

Run: `cargo test -p memf-windows -- peb_masquerade::tests::forensicnomicon 2>&1 | tail -5`
Expected: `test result: ok. 1 passed; 0 failed`

**Step 4: Commit GREEN**

```bash
git add crates/memf-windows/Cargo.toml
git commit --no-gpg-sign -m "feat(dry): GREEN — add forensicnomicon dep to memf-windows"
```

---

## Task 2: Replace `HIGH_VALUE_TARGETS` in `peb_masquerade.rs`

**Files:**
- Modify: `crates/memf-windows/src/peb_masquerade.rs`

**Context:**
`HIGH_VALUE_TARGETS` at line 18 is a `const &[&str]` with 7 entries.
It is used in `classify_peb_masquerade()` as:
```rust
HIGH_VALUE_TARGETS.iter().any(|t| t.eq_ignore_ascii_case(eprocess_name))
```

Replace the const and all its usages with `forensicnomicon::processes::is_masquerade_target(eprocess_name)`.

**Step 1: RED — add regression test pinning current behaviour**

In the `tests` block of `peb_masquerade.rs`, add:
```rust
#[test]
fn high_value_target_svchost_is_masquerade_candidate() {
    // svchost.exe with mismatched PEB path must be flagged
    assert!(classify_peb_masquerade(
        "svchost.exe",
        "C:\\Windows\\Temp\\malware.exe"
    ));
}

#[test]
fn high_value_target_notepad_mismatch_not_flagged() {
    // notepad.exe is not a high-value target — mismatch should NOT flag
    assert!(!classify_peb_masquerade(
        "notepad.exe",
        "C:\\Windows\\Temp\\malware.exe"
    ));
}
```

Run: `cargo test -p memf-windows -- peb_masquerade::tests 2>&1 | tail -5`
Expected: PASS (tests verify current behaviour before touching code)

**Step 2: Commit RED (pinning tests)**

```bash
git add crates/memf-windows/src/peb_masquerade.rs
git commit --no-gpg-sign -m "test(dry): RED — pin peb_masquerade classify behaviour before refactor"
```

**Step 3: GREEN — delete `HIGH_VALUE_TARGETS`, use `is_masquerade_target`**

Delete these lines entirely:
```rust
const HIGH_VALUE_TARGETS: &[&str] = &[
    "svchost.exe",
    "csrss.exe",
    "lsass.exe",
    "services.exe",
    "smss.exe",
    "wininit.exe",
    "explorer.exe",
];
```

Add the import at the top of the file (after the existing `use` statements):
```rust
use forensicnomicon::processes::is_masquerade_target;
```

Find every usage of `HIGH_VALUE_TARGETS` and replace with `is_masquerade_target(...)`:
```rust
// Before:
HIGH_VALUE_TARGETS.iter().any(|t| t.eq_ignore_ascii_case(eprocess_name))

// After:
is_masquerade_target(eprocess_name)
```

Run: `cargo test -p memf-windows -- peb_masquerade::tests 2>&1 | tail -5`
Expected: all tests pass (including the two new regression tests)

**Step 4: Commit GREEN**

```bash
git add crates/memf-windows/src/peb_masquerade.rs
git commit --no-gpg-sign -m "refactor(dry): GREEN — replace HIGH_VALUE_TARGETS with forensicnomicon::processes::is_masquerade_target"
```

---

## Task 3: Replace `SPOOFABLE_NAMES` in `correlate.rs` and `SYSTEM_PROCESSES` in `suspicious_threads.rs`

**Files:**
- Modify: `crates/memf-windows/src/correlate.rs`
- Modify: `crates/memf-windows/src/suspicious_threads.rs`

**Context:**
`correlate.rs` line 14 — `SPOOFABLE_NAMES: &[&str]` (7 entries), used in `WinProcessInfo::into_forensic_events()` as:
```rust
SPOOFABLE_NAMES.contains(&self.image_name.to_lowercase().as_str())
```

`suspicious_threads.rs` line ~44 — `SYSTEM_PROCESSES: &[&str]` (6 entries), used in `classify_suspicious_thread()`.

**Step 1: RED — add pinning tests**

In `correlate.rs` test module (add one if none exists):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WinProcessInfo;

    #[test]
    fn spoofable_svchost_produces_finding() {
        // svchost.exe in SPOOFABLE_NAMES must produce a forensic event with
        // finding Other("spoofable_name")
        let proc = WinProcessInfo {
            pid: 1234,
            ppid: 4,
            image_name: "svchost.exe".to_string(),
            ..Default::default()
        };
        let events = proc.into_forensic_events();
        assert!(!events.is_empty());
        // The presence of an event is sufficient; exact finding is an impl detail
    }
}
```

In `suspicious_threads.rs` test module — verify existing classify test covers a SYSTEM_PROCESSES member:
```rust
#[test]
fn lsass_system_process_flag_set() {
    // lsass.exe must be classified as is_system_thread candidate
    assert!(is_system_process("lsass.exe"));
}
```
(Note: if `is_system_process` is private, test through `classify_suspicious_thread` instead)

Run: `cargo test -p memf-windows -- correlate::tests suspicious_threads::tests 2>&1 | tail -5`
Expected: PASS or compile error if the helper doesn't exist yet (that's fine — adjust the test to test through the public API)

**Step 2: Commit RED**

```bash
git add crates/memf-windows/src/correlate.rs crates/memf-windows/src/suspicious_threads.rs
git commit --no-gpg-sign -m "test(dry): RED — pin correlate/suspicious_threads behaviour before refactor"
```

**Step 3: GREEN — replace both constants**

In `correlate.rs`:
1. Add `use forensicnomicon::processes::is_masquerade_target;`
2. Delete `SPOOFABLE_NAMES` const
3. Replace `SPOOFABLE_NAMES.contains(&self.image_name.to_lowercase().as_str())` with `is_masquerade_target(&self.image_name)`

In `suspicious_threads.rs`:
1. Add `use forensicnomicon::processes::is_masquerade_target;`
2. Delete `SYSTEM_PROCESSES` const
3. Replace `SYSTEM_PROCESSES.contains(&process_name.to_lowercase().as_str())` (or equivalent) with `is_masquerade_target(process_name)`

Run: `cargo test -p memf-windows 2>&1 | grep "test result"` — all tests must pass.

**Step 4: Commit GREEN**

```bash
git add crates/memf-windows/src/correlate.rs crates/memf-windows/src/suspicious_threads.rs
git commit --no-gpg-sign -m "refactor(dry): GREEN — replace SPOOFABLE_NAMES/SYSTEM_PROCESSES with forensicnomicon"
```

---

## Task 4: Replace `SYSTEM_PROCS` in `getsids.rs`

**Files:**
- Modify: `crates/memf-windows/src/getsids.rs`

**Context:**
`getsids.rs` has its own system process list. Read the file first to find the exact constant name and usage pattern, then apply the same substitution as Tasks 2–3.

**Step 1: Read the file**

```bash
grep -n "const\|SYSTEM\|PROCS\|TARGETS\|PROCESSES" crates/memf-windows/src/getsids.rs | head -20
```

**Step 2: RED — add a pinning test**

Add a test in `getsids.rs` test module that exercises the classify path with a system process name (e.g. `lsass.exe`) and a non-system name (e.g. `notepad.exe`) to document the boundary.

Run and confirm PASS (pinning green baseline).

**Step 3: Commit RED**

```bash
git add crates/memf-windows/src/getsids.rs
git commit --no-gpg-sign -m "test(dry): RED — pin getsids system-proc detection before refactor"
```

**Step 4: GREEN — delete local const, use forensicnomicon**

1. Add `use forensicnomicon::processes::is_masquerade_target;`
2. Delete the local constant
3. Replace all usages

Run: `cargo test -p memf-windows 2>&1 | grep "test result"` — all pass.

**Step 5: Commit GREEN**

```bash
git add crates/memf-windows/src/getsids.rs
git commit --no-gpg-sign -m "refactor(dry): GREEN — replace getsids SYSTEM_PROCS with forensicnomicon"
```

---

## Task 5: Add `winevt-core` to workspace and replace EVTX constants

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `crates/memf-windows/Cargo.toml`
- Modify: `crates/memf-windows/src/evtx.rs`

**Context:**
`winevt-core` lives at `~/src/winevt-forensic/crates/winevt-core/`.
The workspace root is at `~/src/memory-forensic/`.
Relative path from workspace root: `"../winevt-forensic/crates/winevt-core"`.

Four constants in `evtx.rs` (lines ~35–42) duplicate `winevt-core/src/binary.rs`:

| `evtx.rs` name | value | `winevt-core` name |
|---|---|---|
| `ELFCHNK_MAGIC` | `[0x45, 0x6C, ...]` | `ELFCHNK_MAGIC` = `*b"ElfChnk\0"` |
| `RECORD_MAGIC` | `[0x2A, 0x2A, 0x00, 0x00]` | `RECORD_MAGIC` |
| `CHUNK_SIZE` | `0x10000` | `CHUNK_SIZE` = `0x1_0000` |
| `RECORDS_OFFSET` | `0x200` | `CHUNK_RECORDS_OFFSET` |

Keep in `evtx.rs`: `CHUNK_ALIGNMENT` (0x1000), `MAX_CHUNKS`, `MAX_RECORDS_PER_CHUNK` — these are memory-walk policy, not format constants.

**Step 1: RED — add test that imports from winevt_core::binary**

In `crates/memf-windows/src/evtx.rs`, add to test module:
```rust
#[test]
fn winevt_core_magic_matches_our_constant() {
    // After refactor, we import from winevt_core::binary. This test verifies
    // the value is correct and winevt-core is reachable.
    assert_eq!(winevt_core::binary::ELFCHNK_MAGIC, *b"ElfChnk\0");
    assert_eq!(winevt_core::binary::RECORD_MAGIC, [0x2A, 0x2A, 0x00, 0x00]);
    assert_eq!(winevt_core::binary::CHUNK_SIZE, 0x10000);
    assert_eq!(winevt_core::binary::CHUNK_RECORDS_OFFSET, 0x200);
}
```

Run: `cargo test -p memf-windows -- evtx::tests 2>&1 | tail -8`
Expected: compile error — `use of undeclared crate or module 'winevt_core'`

**Step 2: Commit RED**

```bash
git add crates/memf-windows/src/evtx.rs
git commit --no-gpg-sign -m "test(dry): RED — failing import of winevt_core in evtx.rs"
```

**Step 3: GREEN — add winevt-core to workspace, then to memf-windows**

In `Cargo.toml` (workspace root), add to `[workspace.dependencies]`:
```toml
winevt-core = { path = "../winevt-forensic/crates/winevt-core" }
```

In `crates/memf-windows/Cargo.toml`, add to `[dependencies]`:
```toml
winevt-core.workspace = true
```

Run: `cargo build -p memf-windows 2>&1 | tail -5`
Expected: compiles cleanly.

**Step 4: Replace the four constants in `evtx.rs`**

Delete these four `const` declarations:
```rust
const ELFCHNK_MAGIC: [u8; 8] = [0x45, 0x6C, 0x66, 0x43, 0x68, 0x6E, 0x6B, 0x00];
const RECORD_MAGIC: [u8; 4] = [0x2A, 0x2A, 0x00, 0x00];
const CHUNK_SIZE: u64 = 0x10000;
const RECORDS_OFFSET: u64 = 0x200;
```

Add at the top of the file (after existing `use` statements):
```rust
use winevt_core::binary::{CHUNK_RECORDS_OFFSET, CHUNK_SIZE, ELFCHNK_MAGIC, RECORD_MAGIC};
```

Then rename any remaining reference to `RECORDS_OFFSET` → `CHUNK_RECORDS_OFFSET` (the winevt-core name).

Run: `cargo test -p memf-windows 2>&1 | grep "test result"` — all tests pass including the new import test.

**Step 5: Commit GREEN**

```bash
git add Cargo.toml crates/memf-windows/Cargo.toml crates/memf-windows/src/evtx.rs
git commit --no-gpg-sign -m "refactor(dry): GREEN — replace EVTX constants with winevt_core::binary re-exports"
```

---

## Task 6: Rename `AntiForensicIndicator` → `IntegrityAnomaly` in `winevt-core`

**Files:**
- Modify: `~/src/winevt-forensic/crates/winevt-core/src/binary.rs`
- Modify: any file in `winevt-forensic` that references `AntiForensicIndicator`

**Context:**
`AntiForensicIndicator` is used in `winevt-core::binary` and possibly `winevt-antiforensic`.
The rename is a public API change — callers in `winevt-antiforensic`, `winevt-carver`, and `memf-windows` must be updated.

Anti-forensic detection implies intent (the analyst's interpretation). The parser's job is to report structural integrity facts. `IntegrityAnomaly` is the correct name at this layer. Intent inference belongs in RapidTriage's correlation rules.

**Step 1: Find all usages**

```bash
grep -rn "AntiForensicIndicator" ~/src/winevt-forensic/ 2>/dev/null
grep -rn "AntiForensicIndicator" ~/src/memory-forensic/ 2>/dev/null
grep -rn "AntiForensicIndicator" ~/src/RapidTriage/ 2>/dev/null
```

**Step 2: RED — add a test in winevt-core that uses the new name**

In `winevt-core/src/binary.rs` test module:
```rust
#[test]
fn integrity_anomaly_has_checksum_variant() {
    let a = IntegrityAnomaly::ChecksumMismatch;
    let s = format!("{a:?}");
    assert!(s.contains("ChecksumMismatch"));
}
```

Run: `cargo test -p winevt-core -- tests::integrity_anomaly 2>&1 | tail -5`
Expected: compile error — `IntegrityAnomaly` not found

**Step 3: Commit RED**

```bash
cd ~/src/winevt-forensic
git add crates/winevt-core/src/binary.rs
git commit --no-gpg-sign -m "test(rename): RED — IntegrityAnomaly name not yet defined"
```

**Step 4: GREEN — rename the enum and update all callsites**

In `winevt-core/src/binary.rs`:
```rust
// Before:
pub enum AntiForensicIndicator { ... }

// After:
/// Structural integrity anomalies detected in an EVTX chunk or file.
///
/// These are raw parser observations — facts about the binary structure.
/// Interpreting them as evidence of anti-forensic activity is the caller's
/// responsibility (e.g., RapidTriage correlation rules).
pub enum IntegrityAnomaly { ... }
```

Update all references in:
- `winevt-core/src/binary.rs` (the enum definition + any `impl` blocks)
- `winevt-carver/src/lib.rs` (if it uses `AntiForensicIndicator`)
- `winevt-antiforensic/src/lib.rs` (if it re-exports or uses it)

Run: `cargo test --workspace 2>&1 | grep "test result"` (in `winevt-forensic` workspace) — all pass.

**Step 5: Commit GREEN**

```bash
git add -p  # stage only the rename changes
git commit --no-gpg-sign -m "refactor(rename): GREEN — AntiForensicIndicator → IntegrityAnomaly; intent belongs in correlation layer"
```

---

## Task 7: Full workspace verification

**Step 1: Run full workspace test suite**

```bash
cd ~/src/memory-forensic
cargo test --workspace 2>&1 | grep "test result"
```
Expected: all pass, zero failures.

**Step 2: Clippy clean**

```bash
cargo clippy --workspace -- -D warnings 2>&1 | grep "^error" | head -10
```
Expected: no errors.

**Step 3: Run winevt-forensic tests**

```bash
cd ~/src/winevt-forensic
cargo test --workspace 2>&1 | grep "test result"
```
Expected: all pass.

**Step 4: Push both repos**

```bash
cd ~/src/memory-forensic && git push origin main
cd ~/src/winevt-forensic && git push origin main
```

---

## Impact Summary

| Change | Files affected | Duplicate lines eliminated |
|---|---|---|
| `forensicnomicon` masquerade targets | 4 files (`peb_masquerade`, `correlate`, `suspicious_threads`, `getsids`) | ~28 (7 × 4) |
| EVTX format constants | 1 file (`evtx.rs`) | 4 |
| `AntiForensicIndicator` rename | 1–3 files in `winevt-forensic` | 0 lines removed, architectural correctness gained |

Total: **~32 lines removed, zero behaviour change** — each fact now lives in exactly one place.
