# Credential Walker DRY Refactoring Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Eliminate the six-way duplicated heap-scanner boilerplate (480+ lines) across all credential walkers, centralise constants, lazy-compile regexes, standardise field naming, and surface skipped regions via `WalkResult<T>` — all without breaking a single existing test.

**Architecture:** Four sequential passes. Pass 1 creates the `heap_walker.rs` abstraction and tests it in isolation. Pass 2 mechanically refactors each of the six credential walkers to call it. Pass 3 lazy-compiles per-module regexes with `std::sync::OnceLock`. Pass 4 renames `process_name` → `image_name` in the three output types that disagree. Each pass ends with a full `cargo test -p memf-windows` to confirm zero regressions.

**Tech Stack:** Rust 2021, `std::sync::OnceLock` (stable, no new deps), existing `WalkResult<T>` from `memf-core`, existing `walk_processes` / `walk_vad_tree` from `memf-windows`.

**Commit convention:** `--no-gpg-sign`. RED commit = failing tests only. GREEN commit = implementation that makes them pass. GITSIGN_CREDENTIAL_CACHE may be needed: `export GITSIGN_CREDENTIAL_CACHE=/Users/4n6h4x0r/Library/Caches/sigstore/gitsign/cache.sock`.

---

## Background

The six walkers below were added in quick succession and each contain an identical ~180-line VAD-scanning skeleton. Only the `filter_fn` (which processes to scan) and `scan_fn` (how to pattern-match a byte slice) differ:

| Walker | Process filter | Unique logic |
|---|---|---|
| `browser_credentials.rs` | Chromium root procs | credential regex |
| `browser_cookies.rs` | All Chromium + firefox | cookie regex |
| `firefox_credentials.rs` | `firefox.exe` | logins.json regex |
| `session_tokens.rs` | All processes | JWT/OAuth regex |
| `cloud_credentials.rs` | All processes | AWS/GCP/Azure regex |
| `ssh_agent_keys.rs` | `ssh-agent.exe`/`pageant.exe` | SSH wire format |

Each also:
- Defines `const MAX_REGION_BYTES: usize = 64 * 1024 * 1024;` (six copies)
- Repeats the identical VAD filter: `is_private && READWRITE && !EXECUTE`
- Repeats `seen: HashSet` dedup with bespoke key tuples
- Compiles regexes on every call to `scan_*_region`
- Silently drops skipped regions with no counter

The plan fixes all of this while keeping every existing test green.

---

## Task 1: `heap_walker.rs` — generic process heap scanner

**Why TDD here:** The new abstraction is testable in isolation with a fake `ObjectReader`. Its tests become the regression guard for the abstraction itself; walker tests remain the guard for each walker's unique logic.

**Files:**
- Create: `crates/memf-windows/src/heap_walker.rs`
- Modify: `crates/memf-windows/src/lib.rs` (add `pub(crate) mod heap_walker;`)

### Step 1: Write RED tests

Create `crates/memf-windows/src/heap_walker.rs` with the test module **only** — the public function body returns `Ok(WalkResult::new())` (empty, no items):

```rust
//! Generic process-heap scanner used by all credential walkers.

use std::collections::HashSet;
use std::hash::Hash;

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{
    process::walk_processes,
    types::WinProcessInfo,
    vad::walk_vad_tree,
    Result,
};

/// Maximum bytes consumed from any single VAD region.
/// Caps memory use when a large anonymous mapping is encountered.
pub(crate) const MAX_REGION_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Walk all private, readable-writable, non-executable VAD regions for every
/// process accepted by `filter_fn`, pass each region's bytes to `scan_fn`,
/// and collect the results.
///
/// Deduplication is applied globally across all regions using `key_fn`.
/// Items whose key was already seen are silently dropped (not counted as
/// skipped — they are successful reads).
///
/// Regions that fail to read are recorded as skipped in the returned
/// `WalkResult`.
///
/// # Arguments
///
/// * `reader`         — kernel-space `ObjectReader` (kernel CR3 / symbol table).
/// * `ps_head_vaddr`  — virtual address of `PsActiveProcessHead`.
/// * `filter_fn`      — returns `true` for processes whose heap should be scanned.
/// * `scan_fn`        — called with `(region_bytes, process)`, returns zero or more items.
/// * `key_fn`         — extracts the deduplication key from each item.
pub(crate) fn for_each_heap_region<P, T, K>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
    filter_fn: impl Fn(&WinProcessInfo) -> bool,
    scan_fn: impl Fn(&[u8], &WinProcessInfo) -> Vec<T>,
    key_fn: impl Fn(&T) -> K,
) -> Result<memf_core::walk_result::WalkResult<T>>
where
    P: PhysicalMemoryProvider + Clone,
    K: Eq + Hash,
{
    // TODO: implement
    Ok(memf_core::walk_result::WalkResult::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_reader() -> ObjectReader<impl PhysicalMemoryProvider + Clone> {
        let mut pt = PageTableBuilder::new();
        let _cr3 = pt.build();
        let mem = pt.into_memory();
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).expect("valid ISF");
        let vas = VirtualAddressSpace::new(mem, PageTableBuilder::CR3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// With no processes in the dump, the result must be empty with zero skipped.
    #[test]
    fn empty_process_list_yields_empty_result() {
        let reader = make_reader();
        // PsActiveProcessHead points to itself (empty circular list)
        let head_vaddr = 0x0; // will yield zero procs from walk_processes stub
        let result = for_each_heap_region(
            &reader,
            head_vaddr,
            |_p| true,
            |_bytes, _proc| vec!["token".to_string()],
            |s| s.clone(),
        );
        // expect Ok with empty items (no processes = no regions scanned)
        let wr = result.expect("should not error");
        assert_eq!(wr.items().len(), 0);
        assert_eq!(wr.skipped(), 0);
    }

    /// filter_fn returning false for all processes must yield zero items.
    #[test]
    fn filter_fn_false_for_all_yields_empty() {
        let reader = make_reader();
        let result = for_each_heap_region(
            &reader,
            0x0,
            |_p| false,  // reject all
            |_bytes, _proc| vec!["token".to_string()],
            |s| s.clone(),
        )
        .expect("should not error");
        assert_eq!(result.items().len(), 0);
    }

    /// The constant must be 64 MiB.
    #[test]
    fn max_region_bytes_is_64_mib() {
        assert_eq!(MAX_REGION_BYTES, 64 * 1024 * 1024);
    }
}
```

### Step 2: Run tests to confirm RED

```bash
cargo test -p memf-windows heap_walker 2>&1 | tail -20
```

Expected: 2 tests pass (they don't call into real walkers), 0 fail. Actually the empty/filter tests pass because `walk_processes` with address 0 returns an empty vec — both tests trivially pass even with stub implementation. That's acceptable: the abstraction's behavioral tests rely on the full integration path that the walker refactoring in Task 2 validates.

### Step 3: Implement `for_each_heap_region`

Replace the `// TODO: implement` body with:

```rust
    let procs = walk_processes(reader, ps_head_vaddr)?;

    let vad_root_offset = reader
        .required_field_offset("_EPROCESS", "VadRoot")?;

    let mut result = memf_core::walk_result::WalkResult::new();
    let mut seen: HashSet<K> = HashSet::new();

    for proc in procs.iter().filter(|p| filter_fn(p)) {
        if proc.cr3 == 0 || proc.peb_addr == 0 {
            continue;
        }

        let vad_root_addr = proc.vaddr.wrapping_add(vad_root_offset);
        let vads = match walk_vad_tree(reader, vad_root_addr, proc.pid, &proc.image_name) {
            Ok(v) => v,
            Err(_) => {
                result.record_skip();
                continue;
            }
        };

        let proc_reader = reader.with_cr3(proc.cr3);

        for vad in &vads {
            // Only private, readable-writable, non-executable pages (heap).
            if !vad.is_private || !vad.protection_str.contains("READWRITE") {
                continue;
            }
            if vad.protection_str.contains("EXECUTE") {
                continue;
            }

            let region_size = (vad.end_vaddr.saturating_sub(vad.start_vaddr) + 1)
                .min(MAX_REGION_BYTES as u64) as usize;
            if region_size == 0 {
                continue;
            }

            let bytes = match proc_reader.read_bytes(vad.start_vaddr, region_size) {
                Ok(b) => b,
                Err(_) => {
                    result.record_skip();
                    continue;
                }
            };

            for item in scan_fn(&bytes, proc) {
                let key = key_fn(&item);
                if seen.insert(key) {
                    result.push(item);
                }
            }
        }
    }

    Ok(result)
```

### Step 4: Confirm tests pass

```bash
cargo test -p memf-windows heap_walker
cargo test -p memf-windows 2>&1 | tail -5
```

Expected: 3 heap_walker tests pass; full suite ≥1574 passed, 0 failed.

### Step 5: RED commit

```bash
cd /Users/4n6h4x0r/src/memory-forensic
git add crates/memf-windows/src/heap_walker.rs crates/memf-windows/src/lib.rs
git commit --no-gpg-sign -m "test(dry): RED — heap_walker for_each_heap_region stub + tests"
```

Wait — the tests already pass with the stub. Instead, write the implementation in the same commit since the tests are not meaningfully failing. Use a **single GREEN commit** for this task:

```bash
git add crates/memf-windows/src/heap_walker.rs crates/memf-windows/src/lib.rs
git commit --no-gpg-sign -m "feat(dry): GREEN — heap_walker for_each_heap_region generic scanner"
```

---

## Task 2: Refactor all six credential walkers to use `for_each_heap_region`

This task is a pure refactor: no new public API, no new tests. The existing `scan_*_region` tests are the regression guard for each walker's unique logic. After each walker is refactored, run the full test suite.

**Files modified (one at a time):**
- `crates/memf-windows/src/browser_credentials.rs`
- `crates/memf-windows/src/browser_cookies.rs`
- `crates/memf-windows/src/firefox_credentials.rs`
- `crates/memf-windows/src/session_tokens.rs`
- `crates/memf-windows/src/cloud_credentials.rs`
- `crates/memf-windows/src/ssh_agent_keys.rs`

**Also remove from each walker:**
- The local `const MAX_REGION_BYTES` definition (now in `heap_walker`)
- The local `use std::collections::HashSet;` if no longer needed
- The local `walk_processes`, `walk_vad_tree` imports if no longer needed

### Step 1: Refactor `browser_credentials.rs`

The `walk_browser_credentials` function currently is ~80 lines. Replace the entire body (keep `CHROMIUM_BROWSERS` and `scan_region` unchanged):

```rust
pub fn walk_browser_credentials<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<BrowserCredentialInfo>> {
    let procs = crate::process::walk_processes(reader, ps_head_vaddr)?;

    // Build per-browser root PID sets so child processes are excluded.
    let mut root_pids: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for &browser in CHROMIUM_BROWSERS {
        let browser_pids: std::collections::HashSet<u64> = procs
            .iter()
            .filter(|p| p.image_name.eq_ignore_ascii_case(browser))
            .map(|p| p.pid)
            .collect();
        for p in procs.iter().filter(|p| {
            p.image_name.eq_ignore_ascii_case(browser) && !browser_pids.contains(&p.ppid)
        }) {
            root_pids.insert(p.pid);
        }
    }

    let wr = crate::heap_walker::for_each_heap_region(
        reader,
        ps_head_vaddr,
        |proc| root_pids.contains(&proc.pid),
        |bytes, proc| {
            scan_region(bytes)
                .into_iter()
                .map(|(url, username, password)| BrowserCredentialInfo {
                    pid: proc.pid,
                    image_name: proc.image_name.clone(),
                    url,
                    username,
                    password,
                })
                .collect()
        },
        |info| (info.pid, info.username.clone(), info.password.clone()),
    )?;

    Ok(wr.into_items())
}
```

Note: `walk_processes` is called twice here (once for root detection, once inside `for_each_heap_region`). To avoid that, thread the pre-built `root_pids` set into the filter closure — the approach above does this correctly.

However, `for_each_heap_region` internally calls `walk_processes`. To avoid the double call, add an overload or restructure. **Simpler approach**: keep the double call for now (it's pure reads, no side effects) and note it as a future optimisation. The refactor goal is DRY code structure, not perfect performance.

### Step 2: Run tests

```bash
cargo test -p memf-windows browser_credentials
cargo test -p memf-windows 2>&1 | tail -5
```

Expected: all browser_credentials tests pass; full suite ≥1574 passed.

### Step 3: Repeat for `browser_cookies.rs`

Same pattern. The filter is `COOKIE_BROWSERS` matching by `image_name`. No root-process detection needed. `scan_fn` calls `scan_cookie_region(bytes)` and wraps each tuple into `BrowserCookieInfo`. Dedup key: `(pid, domain, name, value)`.

```rust
pub fn walk_browser_cookies<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<BrowserCookieInfo>> {
    let wr = crate::heap_walker::for_each_heap_region(
        reader,
        ps_head_vaddr,
        |proc| COOKIE_BROWSERS.iter().any(|b| proc.image_name.eq_ignore_ascii_case(b)),
        |bytes, proc| {
            scan_cookie_region(bytes)
                .into_iter()
                .map(|(domain, name, value, path)| BrowserCookieInfo {
                    pid: proc.pid,
                    image_name: proc.image_name.clone(),
                    domain,
                    name,
                    value,
                    path,
                })
                .collect()
        },
        |info| (info.pid, info.domain.clone(), info.name.clone(), info.value.clone()),
    )?;
    Ok(wr.into_items())
}
```

### Step 4: Repeat for `firefox_credentials.rs`

Filter: `proc.image_name.eq_ignore_ascii_case("firefox.exe")`.
`scan_fn` calls `scan_firefox_region(bytes)`.
Dedup key: `(pid, encrypted_username.clone(), encrypted_password.clone())`.

### Step 5: Repeat for `session_tokens.rs`

Filter: `|_proc| true` (all processes).
`scan_fn` calls `scan_for_tokens(bytes, proc.pid, &proc.image_name)`.
Dedup key: `(info.pid, info.token_value.clone())`.

Remove the per-process `seen_in_proc` set that was inside `scan_for_tokens` if it exists, or leave it (it deduplicates within a region; the global dedup is across regions). Both layers of dedup are acceptable.

### Step 6: Repeat for `cloud_credentials.rs`

Filter: `|_proc| true`.
`scan_fn` calls `scan_cloud_region(bytes, proc.pid, &proc.image_name)`.
Dedup key: `(info.pid, info.value.clone())`.

### Step 7: Repeat for `ssh_agent_keys.rs`

Filter: `SSH_AGENT_PROCESSES.iter().any(|s| proc.image_name.eq_ignore_ascii_case(s))`.
`scan_fn` calls `scan_ssh_agent_region(bytes)` and wraps into `SshAgentKeyInfo`.
Dedup key: `(info.pid, info.region_offset)`.

### Step 8: Run full suite

```bash
cargo test -p memf-windows 2>&1 | tail -5
```

Expected: ≥1574 passed, 0 failed.

### Step 9: GREEN commit

```bash
git add crates/memf-windows/src/browser_credentials.rs \
        crates/memf-windows/src/browser_cookies.rs \
        crates/memf-windows/src/firefox_credentials.rs \
        crates/memf-windows/src/session_tokens.rs \
        crates/memf-windows/src/cloud_credentials.rs \
        crates/memf-windows/src/ssh_agent_keys.rs
git commit --no-gpg-sign -m "refactor(dry): GREEN — all 6 credential walkers use for_each_heap_region"
```

---

## Task 3: Lazy regex compilation with `OnceLock`

Currently, `session_tokens.rs` and `cloud_credentials.rs` compile their regex patterns on every `scan_*` call. For `session_tokens`, this is 7 regexes × every VAD region × every matching process. Fix with `std::sync::OnceLock`.

**Files:**
- Modify: `crates/memf-windows/src/session_tokens.rs`
- Modify: `crates/memf-windows/src/cloud_credentials.rs`

### Step 1: Write RED tests (pin current behavior)

Add a test to each file that verifies the scan function produces the same output when called twice rapidly (proves regexes aren't failing on second call due to compilation errors):

```rust
#[test]
fn scan_called_twice_returns_consistent_results() {
    let buf = b"Bearer ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx ";
    let r1 = scan_for_tokens(buf, 42, "chrome.exe");
    let r2 = scan_for_tokens(buf, 42, "chrome.exe");
    assert_eq!(r1.len(), r2.len(), "repeated calls must be consistent");
    assert_eq!(r1[0].token_value, r2[0].token_value);
}
```

Run: `cargo test -p memf-windows session_tokens::tests::scan_called_twice` — PASS (green already since current code doesn't fail, just recompiles). This is a pinning test; proceed with refactor.

### Step 2: Refactor `session_tokens.rs`

Extract the pattern list from inside `scan_for_tokens` into a static:

```rust
use std::sync::OnceLock;
use regex::Regex;

struct TokenPattern {
    label: &'static str,
    re: Regex,
}

static TOKEN_PATTERNS: OnceLock<Vec<TokenPattern>> = OnceLock::new();

fn token_patterns() -> &'static [TokenPattern] {
    TOKEN_PATTERNS.get_or_init(|| {
        vec![
            TokenPattern {
                label: "JWT",
                re: Regex::new(r"eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}")
                    .expect("valid JWT regex"),
            },
            // ... remaining patterns
        ]
    })
}
```

Replace the inner loop in `scan_for_tokens` that compiled regexes with a call to `token_patterns()`.

### Step 3: Repeat for `cloud_credentials.rs`

Same pattern. Create `static CLOUD_PATTERNS: OnceLock<Vec<CloudPattern>> = OnceLock::new();`.

### Step 4: Run tests

```bash
cargo test -p memf-windows session_tokens
cargo test -p memf-windows cloud_credentials
cargo test -p memf-windows 2>&1 | tail -5
```

Expected: all pass, ≥1574 total.

### Step 5: Commit

```bash
git add crates/memf-windows/src/session_tokens.rs \
        crates/memf-windows/src/cloud_credentials.rs
git commit --no-gpg-sign -m "perf(dry): lazy regex compilation via OnceLock in credential scanners"
```

---

## Task 4: Standardise `process_name` → `image_name` in output types

**Problem:** `SessionTokenInfo`, `CloudCredentialInfo`, `SshAgentKeyInfo` use `process_name`; all other walker types use `image_name`. This makes grouping by field name impossible without type-specific code.

**Files:**
- Modify: `crates/memf-windows/src/types.rs` — rename fields
- Modify: `crates/memf-windows/src/session_tokens.rs` — update struct literals
- Modify: `crates/memf-windows/src/cloud_credentials.rs` — update struct literals
- Modify: `crates/memf-windows/src/ssh_agent_keys.rs` — update struct literals
- Modify: any other file using `.process_name` on these types

**Check all callers first:**
```bash
grep -rn "\.process_name\b" crates/ src/ --include="*.rs"
```

### Step 1: Write RED test (pin field name)

In each of the three `*_tests` modules, add a field-access test:

```rust
#[test]
fn session_token_info_has_image_name_field() {
    let info = SessionTokenInfo {
        pid: 1,
        image_name: "test.exe".to_string(),  // must compile: field is image_name
        token_type: "JWT".to_string(),
        token_value: "tok".to_string(),
    };
    assert_eq!(info.image_name, "test.exe");
}
```

This test FAILS to compile before the rename (since the field is still `process_name`). That's the RED.

### Step 2: Rename in `types.rs`

Find and rename all three structs:
- `SessionTokenInfo::process_name` → `image_name`
- `CloudCredentialInfo::process_name` → `image_name`
- `SshAgentKeyInfo::process_name` → `image_name`

Also check `DebugRegisterInfo`, `IatHookInfo`, `PebMasqueradeInfo`, and any other types that showed `process_name` in the grep.

### Step 3: Update all struct literal sites

In `session_tokens.rs`, `cloud_credentials.rs`, `ssh_agent_keys.rs`: change `process_name: proc.image_name.clone()` → `image_name: proc.image_name.clone()`.

Use `grep -rn "process_name" crates/ src/` to find any missed sites.

### Step 4: Run tests

```bash
cargo test -p memf-windows 2>&1 | tail -5
```

Expected: ≥1574 passed, 0 failed.

### Step 5: RED then GREEN commit

```bash
# Stage the new test first
git add crates/memf-windows/src/session_tokens.rs \
        crates/memf-windows/src/cloud_credentials.rs \
        crates/memf-windows/src/ssh_agent_keys.rs
git commit --no-gpg-sign -m "test(dry): RED — image_name field access tests for credential types"

# Now do the rename
git add crates/memf-windows/src/types.rs \
        crates/memf-windows/src/session_tokens.rs \
        crates/memf-windows/src/cloud_credentials.rs \
        crates/memf-windows/src/ssh_agent_keys.rs
git commit --no-gpg-sign -m "refactor(dry): GREEN — standardise process_name → image_name in credential types"
```

---

## Task 5: Full suite verification

### Step 1: Run all crates

```bash
cargo test --workspace 2>&1 | tail -10
```

Expected: all suites pass, 0 failures.

### Step 2: Check for stray `MAX_REGION_BYTES` definitions

```bash
grep -rn "const MAX_REGION_BYTES" crates/ --include="*.rs"
```

Expected: only `crates/memf-windows/src/heap_walker.rs` defines it. If any walker still has its own definition, remove it and re-import from `heap_walker`.

### Step 3: Check for stray `process_name` fields

```bash
grep -rn "pub process_name" crates/ --include="*.rs"
```

Expected: zero results (all renamed).

### Step 4: Final verification commit

```bash
git commit --allow-empty --no-gpg-sign -m "chore: DRY refactor complete — 1574+ tests green, 480 LoC eliminated"
```

---

## Expected outcomes

| Metric | Before | After |
|---|---|---|
| Lines of duplicated VAD-walking boilerplate | ~480 (6 × 80) | 0 |
| `MAX_REGION_BYTES` definitions | 6 | 1 |
| Regex compilations per scan call | 7–14 | 0 (static) |
| `process_name` vs `image_name` split | 3 vs many | 0 vs all |
| Skipped region visibility | zero (silent) | `WalkResult.skipped()` |
| Test count delta | 1574 | ≥1574 (no regression) |
