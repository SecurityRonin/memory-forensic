# memory-forensic — Linux ELF Analysis Plan

New capability in `memf-linux`: scan loaded ELF objects per process, classify
imported symbols against the rootkit hook table, and detect non-packaged preloaded
libraries from raw memory or from artifact bytes on disk.

This plan closes **Gap 5 Layer B** from `issen/PLAN_LINUX_GAPS.md` — the ELF
capability-based detection that replaces name-pattern rootkit matching.

`goblin = "0.9"` is already in the workspace's `Cargo.toml`, so ELF parsing requires
no new dependencies.

---

## Background

LD_PRELOAD rootkits are detected today by:
- Name substring matching (Father/Jynx/Azazel) — brittle, name-agnostic variants evade it
- Path provenance (library not from package manager) — catches unknown libs but not *what* they do

The missing layer: **what does the shared library actually do?** ELF dynamic symbol
analysis answers this objectively, without knowing the library name in advance:
- `readdir64` / `getdents64` imported AND exported → process-hiding rootkit
- `pam_get_item` imported → PAM credential intercept
- `write` imported alongside `pam_*` → I/O logging credential theft
- Library exports a function with the same name as a libc symbol → classic hook pattern

This is behavioral fingerprinting at the binary level.

---

## 1. `memf-linux/src/elf_analysis.rs` — New Module

### 1.1 Core Types

The report surfaces signal IDs from `forensicnomicon::threat_intel::signals` so that
`issen-cli` can pass them directly to `score_all_profiles()` without translation.

```rust
use goblin::elf::Elf;
use forensicnomicon::heuristics::linux_rootkit::ROOTKIT_HOOK_SYMBOLS;
use forensicnomicon::threat_intel::signals as S;

#[derive(Debug, Clone)]
pub struct ElfCapabilityReport {
    /// Path or identifier of the ELF binary analysed.
    pub source: String,
    /// Imported/exported hook symbols matched against the hook table.
    pub matched_hooks: Vec<HookMatch>,
    /// Symbols this library exports that shadow libc functions (by name).
    pub libc_shadow_exports: Vec<String>,
    /// Deduplicated signal IDs emitted by this ELF.
    /// These are passed verbatim to `forensicnomicon::threat_intel::engine::score_all_profiles`.
    pub signals: Vec<&'static str>,
    /// Deduplicated MITRE technique IDs implied by `signals`.
    pub mitre_techniques: Vec<&'static str>,
}

#[derive(Debug, Clone)]
pub struct HookMatch {
    pub symbol_name: String,
    /// Signal ID this match contributes (from `forensicnomicon::threat_intel::signals`).
    pub signal_id: &'static str,
    pub mitre_technique: &'static str,
}
```

### 1.2 Primary Analysis Function

```rust
/// Analyse ELF bytes and return a capability report.
/// Returns `None` if bytes are not a valid ELF (not an error — callers may pass
/// arbitrary bytes from a carve pass).
/// Returns `Some(report)` with an empty `signals` vec if valid ELF but no hook matches.
pub fn analyse_elf_capabilities(bytes: &[u8], source: impl Into<String>) -> Option<ElfCapabilityReport> {
    let elf = Elf::parse(bytes).ok()?;

    let mut matched_hooks = Vec::new();
    let mut libc_shadow_exports = Vec::new();

    // Build a set of all hook-table symbol names for the export check
    let hook_names: std::collections::HashSet<&str> = ROOTKIT_HOOK_SYMBOLS
        .iter().map(|s| s.name).collect();

    for sym in &elf.dynsyms {
        if sym.st_name == 0 { continue }
        let name = match elf.dynstrtab.get_at(sym.st_name) {
            Some(n) => n,
            None => continue,
        };

        // Imports: library is wrapping this libc/kernel function
        if let Some(hook) = ROOTKIT_HOOK_SYMBOLS.iter().find(|s| s.name == name) {
            matched_hooks.push(HookMatch {
                symbol_name: name.to_string(),
                signal_id: hook.emits_signal,
                mitre_technique: hook.mitre_technique,
            });
        }

        // Exports that shadow libc: a .so exporting "readdir64" intercepts all callers
        if !sym.is_import() && hook_names.contains(name) {
            libc_shadow_exports.push(name.to_string());
        }
    }

    // Deduplicate signal IDs (multiple symbols may emit the same signal)
    let mut seen = std::collections::HashSet::new();
    let signals: Vec<&'static str> = matched_hooks.iter()
        .filter_map(|h| if seen.insert(h.signal_id) { Some(h.signal_id) } else { None })
        .chain(if !libc_shadow_exports.is_empty() {
            seen.insert(S::ELF_LIBC_SHADOW_EXPORTS)
                .then_some(S::ELF_LIBC_SHADOW_EXPORTS)
        } else { None })
        .collect();

    let mut seen_tt = std::collections::HashSet::new();
    let mitre_techniques: Vec<&'static str> = matched_hooks.iter()
        .filter_map(|h| seen_tt.insert(h.mitre_technique).then_some(h.mitre_technique))
        .collect();

    Some(ElfCapabilityReport {
        source: source.into(),
        matched_hooks,
        libc_shadow_exports,
        signals,
        mitre_techniques,
    })
}
```

### 1.3 ELF String Artifact Scanner

Extracts printable strings from ELF `.rodata` and symbol name sections, then matches
them against the Father-class pattern table from `forensicnomicon`. This catches
Father variants that have been recompiled with different flags or had their library
name changed — the format string template baked into the PAM hook source code remains
in `.rodata` regardless.

```rust
use forensicnomicon::heuristics::linux_rootkit::FATHER_CLASS_ELF_PATTERNS;

#[derive(Debug, Clone)]
pub struct ElfStringArtifact {
    pub matched_pattern: &'static str,
    pub description: &'static str,
    pub weight: u32,
    pub context: String, // up to 80 chars around the match
}

/// Extract printable-string artifact matches from ELF bytes.
/// Returns `None` if bytes are not a valid ELF object.
/// Returns `Some(vec![])` if valid ELF but no Father-class patterns found.
pub fn scan_elf_string_artifacts(bytes: &[u8]) -> Option<Vec<ElfStringArtifact>> {
    let elf = Elf::parse(bytes).ok()?;
    let mut results = Vec::new();

    // Walk section headers looking for .rodata and related string sections
    for section in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");
        let is_string_section = matches!(name,
            ".rodata" | ".rodata.str1.1" | ".rodata.str1.8" | ".data.rel.ro"
        ) || section.sh_type == goblin::elf::section_header::SHT_PROGBITS;

        if !is_string_section { continue }
        let start = section.sh_offset as usize;
        let end = start.saturating_add(section.sh_size as usize);
        let section_bytes = bytes.get(start..end).unwrap_or(&[]);

        let section_str = String::from_utf8_lossy(section_bytes);
        for pattern_def in FATHER_CLASS_ELF_PATTERNS {
            if let Some(pos) = section_str.find(pattern_def.pattern) {
                let ctx_start = pos.saturating_sub(20);
                let ctx_end = (pos + pattern_def.pattern.len() + 20).min(section_str.len());
                let context = section_str[ctx_start..ctx_end]
                    .chars()
                    .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '.' })
                    .collect();
                results.push(ElfStringArtifact {
                    matched_pattern: pattern_def.pattern,
                    description: pattern_def.description,
                    weight: pattern_def.weight,
                    context,
                });
            }
        }
    }
    Some(results)
}
```

### 1.4 Module Registration

Add to `memf-linux/src/lib.rs`:

```rust
pub mod elf_analysis;
```

---

## 2. `memf-linux/src/preload_scanner.rs` — Library Loading Analysis

### 2.1 All-Process Library Cross-Reference

A library that appears in every running process's mapped memory (via `/proc/<pid>/maps`)
is almost certainly an LD_PRELOAD injection — a non-malicious library rarely loads in
*every* process simultaneously.

```rust
#[derive(Debug)]
pub struct GloballyLoadedLibrary {
    pub path: String,
    pub present_in_pid_count: usize,
    pub total_pids_checked: usize,
    /// Fraction of processes that loaded this library.
    pub prevalence: f64,
    pub elf_report: Option<ElfCapabilityReport>,
}

/// Identify libraries loaded in nearly every process.
/// `proc_maps` is a list of (pid, mapped_paths) tuples from /proc/*/maps parsing.
/// Returns libraries where `prevalence >= threshold` (e.g. 0.9 for 90% of processes).
pub fn find_globally_loaded_libraries(
    proc_maps: &[(u32, Vec<String>)],
    threshold: f64,
) -> Vec<GloballyLoadedLibrary> {
    use std::collections::HashMap;
    let total = proc_maps.len();
    if total == 0 { return vec![]; }

    let mut counts: HashMap<String, usize> = HashMap::new();
    for (_, paths) in proc_maps {
        let unique_paths: std::collections::HashSet<&str> = paths.iter().map(|s| s.as_str()).collect();
        for p in unique_paths {
            *counts.entry(p.to_string()).or_default() += 1;
        }
    }

    counts.into_iter()
        .filter(|(path, count)| {
            // Only .so files
            path.ends_with(".so") || path.contains(".so.")
            && (*count as f64 / total as f64) >= threshold
        })
        .map(|(path, count)| {
            let prevalence = count as f64 / total as f64;
            GloballyLoadedLibrary {
                path,
                present_in_pid_count: count,
                total_pids_checked: total,
                prevalence,
                elf_report: None, // caller fills in after loading bytes
            }
        })
        .collect()
}
```

### 2.2 Volatility `linux.elfs` Output Parser

Volatility 3 `linux.elfs` plugin lists all ELF objects mapped in every process.
This is the primary source of process-level library loading information from a
memory dump, replacing manual `/proc/*/maps` reconstruction:

```rust
#[derive(Debug, Clone)]
pub struct VolatilityElfEntry {
    pub pid: u32,
    pub process_name: String,
    pub start: u64,
    pub end: u64,
    pub path: String,
}

/// Parse TSV output of `vol.py -f dump.raw linux.elfs`.
/// Expected columns: PID, Process, Start, End, File
pub fn parse_linux_elfs_tsv(content: &str) -> Vec<VolatilityElfEntry> {
    content.lines()
        .skip(1) // header
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|line| {
            let cols: Vec<&str> = line.splitn(5, '\t').collect();
            if cols.len() < 5 { return None; }
            Some(VolatilityElfEntry {
                pid: cols[0].trim().parse().ok()?,
                process_name: cols[1].trim().to_string(),
                start: u64::from_str_radix(cols[2].trim().trim_start_matches("0x"), 16).ok()?,
                end: u64::from_str_radix(cols[3].trim().trim_start_matches("0x"), 16).ok()?,
                path: cols[4].trim().to_string(),
            })
        })
        .collect()
}

/// From linux.elfs output, find libraries loaded in >= `threshold` fraction of PIDs.
pub fn find_globally_loaded_from_elfs(
    entries: &[VolatilityElfEntry],
    threshold: f64,
) -> Vec<(String, f64)> {
    use std::collections::HashMap;
    let mut pid_count: HashMap<&str, std::collections::HashSet<u32>> = HashMap::new();
    for e in entries {
        pid_count.entry(&e.path).or_default().insert(e.pid);
    }
    let total_pids: std::collections::HashSet<u32> = entries.iter().map(|e| e.pid).collect();
    let n = total_pids.len() as f64;
    if n == 0.0 { return vec![]; }

    let mut result: Vec<(String, f64)> = pid_count.into_iter()
        .filter_map(|(path, pids)| {
            let prevalence = pids.len() as f64 / n;
            if prevalence >= threshold { Some((path.to_string(), prevalence)) } else { None }
        })
        .collect();
    result.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    result
}
```

---

## 3. Signal Flow to the Scoring Engine

`memf-linux` produces `ElfCapabilityReport { signals: Vec<&'static str> }` where each
entry is a signal ID from `forensicnomicon::threat_intel::signals`. The signal IDs flow
upward through `issen-cli` into `score_all_profiles()` without any translation layer:

```
memf-linux::elf_analysis::analyse_elf_capabilities(bytes)
    → ElfCapabilityReport { signals: ["elf.hooks.process_hiding", "elf.hooks.pam_credential_theft"] }
              ↓ (issen-cli collects and wraps into DetectedSignal)
forensicnomicon::threat_intel::engine::score_all_profiles(signals)
    → [ProfileMatch { profile: &FATHER, score: 92, classification: Confirmed, ... }, ...]
```

`issen-parser-uac` (PARSER layer) and `memf-linux` (OS STRUCTURE layer) never import
each other — both emit `&'static str` signal IDs that are defined in `forensicnomicon`
(which both already depend on). Only `issen-cli` (ORCHESTRATION) knows both and
assembles the unified signal set before scoring.

---

## TDD Tests

### `elf_analysis.rs`

```rust
fn analyse_empty_bytes_returns_none()
fn analyse_non_elf_bytes_returns_none()
fn analyse_elf_without_hook_symbols_returns_empty_signals()
fn analyse_elf_with_readdir64_import_emits_process_hiding_signal()
fn analyse_elf_with_pam_get_item_import_emits_pam_credential_signal()
fn analyse_elf_with_readdir64_export_emits_libc_shadow_signal()
fn analyse_elf_multiple_hooks_deduplicates_signals()
fn analyse_elf_multiple_hooks_deduplicates_mitre_techniques()
fn analyse_elf_process_hiding_and_pam_both_in_signals()
fn analyse_elf_signals_are_valid_forensicnomicon_signal_ids()

// String artifact scanner
fn scan_elf_strings_non_elf_returns_none()
fn scan_elf_strings_elf_without_patterns_returns_empty_vec()
fn scan_elf_strings_detects_password_format_fragment()
fn scan_elf_strings_detects_silly_txt_reference()
fn scan_elf_strings_context_window_is_bounded()
fn scan_elf_strings_multiple_patterns_all_returned()
fn scan_elf_strings_stripped_binary_still_matches_rodata()
```

### `preload_scanner.rs`

```rust
fn find_globally_loaded_empty_input_returns_empty()
fn find_globally_loaded_library_in_all_pids_found()
fn find_globally_loaded_library_in_half_pids_below_threshold()
fn find_globally_loaded_respects_threshold_parameter()
fn parse_linux_elfs_tsv_empty_returns_empty()
fn parse_linux_elfs_tsv_parses_pid_and_path()
fn parse_linux_elfs_tsv_skips_header_line()
fn parse_linux_elfs_tsv_handles_hex_addresses()
fn find_globally_loaded_from_elfs_library_in_all_pids()
fn find_globally_loaded_from_elfs_sorted_by_prevalence()
```

---

## Implementation Order

| Priority | Item | Effort | Dependency |
|----------|------|--------|------------|
| 1 | `ElfCapabilityReport` types + `analyse_elf_capabilities()` | S | forensicnomicon hook symbol table (§1.1 in forensicnomicon plan) |
| 2 | `scan_elf_string_artifacts()` | S | forensicnomicon `FATHER_CLASS_ELF_PATTERNS` (§1.6b in forensicnomicon plan) |
| 3 | `find_globally_loaded_libraries()` | S | None |
| 4 | `parse_linux_elfs_tsv()` + `find_globally_loaded_from_elfs()` | S | None |
| 5 | Wire into `issen-cli/commands/analyse.rs` | M | Items 1+2 above + issen Gaps 5+7 |

Items 3 and 4 are independent of forensicnomicon and can be written immediately.
Items 1 and 2 require the forensicnomicon constants to exist first.

---

## TDD Commit Protocol

Two commits per item:
```
RED:   test(memf-linux): <item name> — failing tests
GREEN: feat(memf-linux): <item name> — implementation
```

Run after each GREEN:
```bash
cargo test -p memf-linux -p forensicnomicon
```
