# String Sanitization Design — `memf` CLI Output

Status: design / spec. Date: 2026-05-21.

## 0. Ground-truth correction (codebase reality vs. brief)

The brief assumes a `tsv_safe` function and a `Tsv` output format. **Neither exists.**
Verified state of `src/main.rs` (2026-05-21):

- `OutputFormat` variants: `Table`, `Json`, `Ndjson`, `Csv`. **No `Tsv`.**
- The "TSV / Volatility3-compatible" output the brief describes is actually the
  `Csv` arm. It is comma-delimited, not tab-delimited.
- **`Csv` arm is already broken.** Representative code (`print_windows_drivers`):

  ```rust
  OutputFormat::Csv => {
      println!("name,base_addr,size,path");
      for d in drivers {
          let escaped = d.full_path.replace('"', "\"\"");
          println!("{},{:#x},{},\"{}\"", d.name, d.base_addr, d.size, escaped);
      }
  }
  ```

  Defects: `d.name` is interpolated raw — a comma in the name shifts columns; a
  quote in the name is unescaped; a newline in either field splits the row;
  `path` is wrapped in `"` but `name` is not. The `replace('"', "\"\"")` is
  half of RFC 4180 and is applied to only one of two free-text fields.
- JSON arm correctly routes every field through `serde_json::json!`.
- Table arm uses `comfy-table`, does no escaping.
- All raw-byte → `String` conversions in the worker crates use
  `String::from_utf8_lossy` (15+ call sites confirmed). Windows registry/env
  paths use `String::from_utf16_lossy`. No `encoding_rs`, no Big5 decoder.

So this design covers: (a) Csv hardening, (b) optional real `Tsv` for
Volatility3 parity, (c) JSON upstream concerns, (d) Table display safety,
(e) the byte-decode helper.

Available deps (no new heavy deps needed): `aho-corasick`, `regex` in
workspace; `unicode-width` + `unicode-segmentation` already present as
transitive deps (promote to direct). `unicode-normalization` is **not**
present — design avoids needing it.

---

## 1. Threat model recap, mapped to output channels

| # | Input hazard | TSV | CSV | JSON | Table |
|---|---|---|---|---|---|
| 1 | `\t` | row corruption | benign | escaped by serde | display only |
| 2 | delimiter (`,`) in value | n/a | column shift | escaped | benign |
| 3/4/5 | `'` `"` unbalanced | benign | RFC4180 quoting | escaped | benign |
| 6 | `\` | benign | benign | escaped | benign |
| 7 | Unicode | benign | benign | benign | width |
| 8 | DBCS 0x5C collision | **decode-time, not output-time** | same | same | same |
| 9 | `\n \r \r\n` | row corruption | row corruption | escaped | display |
| 10 | NUL | parser truncation | parser truncation | escaped by serde | terminal |
| 11 | C0/C1 controls | parser/terminal | parser/terminal | escaped | terminal |
| 12 | JSON injection | n/a | n/a | **neutralized by serde** | n/a |
| 13 | very long | line-length | line-length | benign | wrap |
| 14 | RTL override | benign | benign | passes through | **terminal attack** |
| 15 | homoglyph | benign | benign | passes through | **visual deception** |

Key facts that simplify everything:

1. **Hazard 8 (DBCS) and the non-UTF-8 question are decode-time problems, not
   output-time problems.** Once a Rust `String` exists it is, by language
   invariant, valid UTF-8. There is no backslash-collision risk inside a
   `String`. The risk lives entirely in the byte→`String` boundary — see §6.
2. **Hazard 12 (JSON injection) is already fully neutralized.** It is only a
   threat against naive string-concatenation JSON. `serde_json::json!` is not
   that. No work needed for JSON injection beyond "never hand-roll JSON."
3. The genuinely unsolved channels are **CSV/TSV column integrity** and
   **terminal-facing Unicode (RTL/homoglyph/controls) in the Table arm**.

---

## 2. `tsv_safe` — specification

TSV has no escaping mechanism. A literal tab in a field *cannot* be
represented. The only correct strategy is **lossy substitution**: guarantee
constant field count per row by destroying every byte that could be a
record/field boundary, while preserving human identifiability.

```rust
/// Make `s` safe to emit as one TSV field (Volatility3-compatible: no quoting).
/// Guarantees the result contains no `\t`, `\n`, `\r`, NUL, or other C0/C1
/// control characters, so field and record boundaries stay intact.
/// Borrows when already clean (the common case).
pub fn tsv_safe(s: &str) -> Cow<'_, str>
```

Signature verdict: **`Cow<'_, str>`**. The overwhelming majority of process
names and paths are already clean; `Cow` makes the clean path allocation-free.
This matters — the brief specifies thousands of entries.

Replacement table (apply in a single pass):

| Input | Output | Rationale |
|---|---|---|
| `\t` U+0009 | space U+0020 | field-boundary char |
| `\n` U+000A | space | record-boundary char |
| `\r` U+000D | space | record-boundary char |
| NUL U+0000 | `\u{FFFD}` ` ` removed → use U+2400 `␀`? **No** — remove | C-string truncation |
| other C0 (U+0001–U+001F) | removed | terminal/parser confusion |
| DEL U+007F | removed | control |
| C1 controls (U+0080–U+009F) | removed | some terminals act on them |
| U+202A–U+202E, U+2066–U+2069, U+200E/200F (bidi) | removed | see §4 |
| everything else | unchanged | preserve identity |

Decisions:

- **Replace boundary chars (`\t \n \r`) with a space, not with deletion.**
  Deleting them can silently merge two tokens (`"foo\tbar"` → `"foobar"`),
  changing meaning. A space preserves the token boundary a human would expect.
- **Delete other control chars rather than space-substitute.** They were never
  meaningful whitespace; spacing them out invents structure.
- **Do not truncate length in `tsv_safe`.** Length capping is a separate
  concern (§7) and must be opt-in so analysts can request full paths.
- **Non-UTF-8 input cannot reach this function** — its argument is `&str`.
  Non-UTF-8 is handled strictly upstream in `bytes_to_utf8_lossy_safe` (§6).

Implementation sketch (single pass, O(n), no regex):

```rust
pub fn tsv_safe(s: &str) -> Cow<'_, str> {
    fn needs_fix(c: char) -> bool {
        matches!(c,
            '\t' | '\n' | '\r' | '\u{0}'..='\u{1F}' | '\u{7F}'
            | '\u{80}'..='\u{9F}'
            | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
            | '\u{200E}' | '\u{200F}')
    }
    if !s.chars().any(needs_fix) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\t' | '\n' | '\r' => out.push(' '),
            c if needs_fix(c) => {} // drop
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}
```

This same function is the correct field sanitizer for a real `Tsv` variant if
one is ever added. For Volatility3 parity, also emit a fixed column count and
never a trailing tab.

---

## 3. CSV — `csv_field` specification (fixes the live bug)

CSV (RFC 4180) *can* represent any text, unlike TSV — but only with correct
quoting. The current code quotes one field and forgets the other.

```rust
/// Format one field for an RFC 4180 CSV row.
/// Wraps in double quotes and doubles internal quotes IFF the field contains
/// `,`  `"`  `\n`  or `\r`; otherwise returns it bare. Also strips NUL and
/// other C0/C1 controls first (RFC 4180 says nothing about them but real
/// parsers and spreadsheets choke).
pub fn csv_field(s: &str) -> Cow<'_, str>
```

Rules:

1. First strip NUL + C0/C1 controls *except* `\n`/`\r` (those are legal inside
   a quoted field and we keep them so multi-line paths survive a round-trip).
   Strip bidi overrides (§4).
2. If the cleaned string contains any of `, " \n \r`, wrap in `"` and replace
   each internal `"` with `""`. Otherwise return as-is.
3. **Apply to every free-text field, not just `path`.** `name` must go through
   this too.

Additional CSV correctness fix — formula injection (a hazard the brief did
**not** list, see §8): if the cleaned field starts with `= + - @` or a leading
tab/CR, prefix a single `'` (or wrap and the `'` becomes literal). This stops
a process named `=cmd|'/c calc'!A1` from executing when the CSV is opened in
Excel/LibreOffice. This is a real, documented forensic-evidence-handling risk
(CSV/formula injection, OWASP).

Rewrite of the broken arm:

```rust
OutputFormat::Csv => {
    println!("name,base_addr,size,path");
    for d in drivers {
        println!("{},{:#x},{},{}",
            csv_field(&d.name), d.base_addr, d.size, csv_field(&d.full_path));
    }
}
```

Numeric fields (`base_addr`, `size`) are machine-formatted and need no
sanitizing.

---

## 4. JSON — what to do *upstream* of `serde_json`

`serde_json` already does the hard part correctly:
- escapes `"` `\` `\n` `\r` `\t`, all C0 controls as `\u00XX`, NUL as ` `;
- only emits valid UTF-8;
- makes hazard 12 (JSON injection) structurally impossible.

So the JSON arm needs **no escaping work**. The only open questions are
semantic, and the answer to both is: handle them at the *source*, not in the
JSON serializer.

- **Non-UTF-8 bytes**: cannot occur — every field is already a Rust `String`.
  The decode happened earlier (§6). If you want to *signal* that lossy
  decoding happened, that is a data-model change (add a `name_lossy: bool`
  field), not a serialization change. Recommended: yes, see §6.
- **RTL / bidi overrides (hazard 14) and homoglyphs (15)**: `serde_json` will
  faithfully pass U+202E into the JSON string. Whether that is a problem
  depends on the consumer. A downstream tool that renders the JSON in a
  terminal/HTML inherits the attack. **Recommendation: strip bidi control
  characters at decode time** (in `bytes_to_utf8_lossy_safe` / `from_utf16`
  wrappers) so *every* output format — JSON included — is clean by
  construction. Do **not** strip them only in the Table arm; that leaves JSON
  consumers exposed.
- **Homoglyphs**: do **not** attempt to "fix" them. Folding Cyrillic `а`
  U+0430 to Latin `a` would *destroy forensic accuracy* — the analyst needs to
  know the real codepoint. Homoglyphs are handled by *flagging*, not
  rewriting — see §7.

Net: there is no `json_safe_str` *escaping* function. The "json safe" concern
is fully covered by (a) keeping `serde_json::json!`, never hand-rolling, and
(b) bidi stripping at decode time.

---

## 5. Table — `display_safe` specification

Goes to a terminal, not a parser, so there is no column-injection risk. The
risks are terminal-control attacks and unreadable rows.

```rust
/// Make `s` safe and readable as a comfy-table cell on an interactive
/// terminal. Strips control chars, neutralizes bidi/terminal-control attacks,
/// flags or escapes deceptive codepoints, and optionally length-caps.
pub fn display_safe(s: &str) -> Cow<'_, str>
```

Rules:

1. **NUL + C0/C1 controls except `\n`**: remove. (comfy-table handles `\n` as
   an in-cell line break; keeping it is fine and sometimes desirable. If you
   want strictly single-line rows, replace `\n` with space too — make it a
   flag.) **`\r` must be removed** — a bare CR rewinds the cursor and lets a
   crafted name overwrite earlier table content.
2. **Bidi overrides** U+202A–202E, U+2066–2069, U+200E/200F: remove. This is
   the U+202E "RTL override" terminal-reversal attack — a file named
   `cod\u{202E}txt.exe` displays as `codexe.txt`. Removal, not escaping,
   because there is no legitimate use of an *override* in a process name or
   path.
3. **ANSI/OSC nuance**: the actual ANSI escape introducer is ESC (U+001B),
   already a C0 control caught by rule 1. Good — stripping C0 kills ANSI
   injection. Explicitly call this out so nobody "optimizes" the C0 strip away.
4. **Length cap**: cap displayed width (not byte length, not char count —
   *display columns* via `unicode-width`) at e.g. 120 cols, appending `…`.
   comfy-table can also wrap; capping is for the case where a 4 KB
   single-token "name" would otherwise dominate the table. Make the cap a
   parameter; default on for Table, off for JSON/CSV/TSV.
5. **Zero-width / invisible chars** (U+200B ZWSP, U+FEFF BOM, U+2060 word
   joiner): these are not bidi but are deceptive in a terminal (a name can
   carry hidden chars that make two visually identical rows distinct).
   Recommendation: **render them visibly** rather than strip — replace with a
   placeholder like `<U+200B>` so the analyst *sees* the anomaly. Stripping
   would hide evidence; this is a forensic tool.

`display_safe` is the one place where "make the anomaly visible" beats "make
it disappear," because the human is the consumer.

---

## 6. `bytes_to_utf8_lossy_safe` — the real DBCS frontier

This is where hazard 8 actually lives. Spec:

```rust
/// Decode raw bytes pulled from a memory dump into a Rust String for display.
/// `bytes` may be: valid UTF-8, valid UTF-16LE, a legacy DBCS encoding
/// (Big5/GBK/Shift-JIS), or garbage. Returns the decoded string plus a flag
/// indicating whether any byte could not be decoded losslessly.
pub struct DecodedStr { pub text: String, pub lossy: bool }
pub fn bytes_to_utf8_lossy_safe(bytes: &[u8]) -> DecodedStr
```

### Is the Big5 backslash-collision a real threat here? — Verdict: **No, not
as an output-time threat. Yes, as a decode-time *interpretation* hazard.**

Reasoning:

- A Rust `String` is UTF-8 by invariant. There is **no code path** where a
  `0x5C` byte that is "really" the trail byte of Big5 許 (`0xB3 0x5C`) ends up
  inside a `String` *as a standalone backslash* — because that byte pair never
  passed through a Big5 decoder in this codebase. The codebase calls
  `String::from_utf8_lossy`.
- Run `0xB3 0x5C` through `String::from_utf8_lossy`: `0xB3` is an invalid
  UTF-8 lead byte → becomes U+FFFD; `0x5C` is valid ASCII → becomes `\`. So
  the *current* code turns 許 into `"\u{FFFD}\\"` — i.e. **a replacement char
  followed by a real backslash.** That backslash is then a genuine,
  legitimate ASCII backslash in a valid `String`. It will be correctly escaped
  by `serde_json` and is harmless to TSV/CSV column integrity. So the
  backslash *collision* does not corrupt output.
- **But the data is silently wrong.** The analyst sees `\` where the process
  name was 許功蓋. That is an *accuracy* failure, not an injection failure —
  and for a forensic tool, accuracy failure is the more serious one. The brief
  frames Big5 as an escaping/injection problem; it is really a
  **decoding-correctness** problem.

Where it remains a risk — concretely, these code paths:
- `crates/memf-windows/src/com_hijacking.rs:193`
  `String::from_utf8_lossy(&data[NK_NAME_DATA..end])` — registry key names. Old
  registry hives on CJK-locale Windows can hold ANSI-codepage (`NK` without the
  comp-name flag) key names. Big5/GBK bytes here.
- `crates/memf-windows/src/browser_sessions.rs:81` — browser session blobs.
- Any Windows registry `VK` value whose type is `REG_SZ` but stored as the
  legacy ANSI codepage rather than UTF-16LE.
- Linux side (`envvars.rs`, `cgroups.rs`, etc.) — usually UTF-8 on modern
  systems; legacy `latin1`/`GBK` locales are the edge case.

### Decoding strategy (no `encoding_rs` — keep deps light)

`encoding_rs` is the correct full solution but is a non-trivial dependency.
Tiered approach:

1. **Try `std::str::from_utf8`.** Success → `lossy: false`. This is ~all
   modern data.
2. **If the byte stream is UTF-16LE** (caller knows from the registry value
   type / source), decode with `from_utf16` family — already done in
   `com_hijacking.rs` and `envvars.rs`. Keep that; do **not** route UTF-16
   through this function.
3. **On UTF-8 failure of an ANSI-codepage field**: this is the honest hard
   case. Options, in order of preference for *this* codebase:
   - **(a) Default: `String::from_utf8_lossy` + set `lossy: true`.** Accept
     the U+FFFD substitution but *record that it happened* so the analyst is
     never misled into thinking `\u{FFFD}\` was the real name. This is the
     minimal correct fix and needs zero new deps.
   - **(b) Better, opt-in: add `encoding_rs` behind a `legacy-codepages`
     Cargo feature.** When a dump's source OS locale is known (or the user
     passes `--ansi-codepage big5`), decode ANSI-codepage registry strings
     with the right decoder. This actually recovers 許功蓋. Recommended as a
     follow-up, not blocking.
   - Do **not** hand-roll a Big5 table. It is large, error-prone, and exactly
     the kind of thing `encoding_rs` exists for.
4. Always run the decoded `String` through bidi-strip (§4) before returning,
   so JSON/CSV/TSV/Table all inherit a clean string.

### `from_utf8_lossy` vs explicit — guidance

- Use `String::from_utf8_lossy` **only** when (a) you also propagate a `lossy`
  flag, and (b) the field is genuinely expected to be UTF-8. Bare
  `from_utf8_lossy` that discards the failure signal is the current
  anti-pattern — it converts "this name is in an encoding we didn't handle"
  into "this name contains a replacement character," indistinguishable from a
  name that legitimately contained U+FFFD.
- Use explicit `from_utf8` + matched error handling when you can do something
  smarter than U+FFFD (i.e. when the codepage is known).
- Never use `from_utf8_unchecked` on dump-derived bytes — untrusted input,
  `#![deny(unsafe_code)]` is set at the crate root anyway.

---

## 7. Length capping & homoglyph flagging (separate, opt-in)

- **Length**: `cap_display(s, max_cols) -> Cow` using `unicode-width` for
  column count. Default-on for Table, default-off elsewhere. Never silently
  cap in JSON/CSV/TSV — an analyst grepping for a full DLL path must get the
  full path.
- **Homoglyph / mixed-script detection**: do not rewrite. Provide an *audit*
  helper `suspicious_script_mix(s) -> bool` (true if a single token mixes,
  e.g., Latin + Cyrillic + Greek confusable ranges). Surface as a separate
  column/flag (`"suspicious": true` in JSON) so the analyst is alerted without
  the underlying string being altered. This keeps forensic fidelity.

---

## 8. `SanitizedStr` newtype — verdict: **not worth it here.**

A `SanitizedStr` newtype that "enforces sanitization at construction" is the
wrong shape for this problem, because **sanitization is not a property of the
string — it is a property of the output channel.** The same name needs:
- TSV: controls→space, no length cap;
- CSV: RFC 4180 quoting + formula-injection guard;
- JSON: nothing (serde does it);
- Table: bidi strip + length cap + visible zero-width markers.

A newtype that sanitizes at construction must either (a) pick one canonical
form — which is then wrong for at least two of the four channels — or (b)
store the original and expose `.as_tsv()`, `.as_csv()`, `.as_json()`,
`.as_display()`, at which point it is just a namespace for four free
functions, with added churn: every `WinProcessInfo.name: String` field, every
constructor across `memf-windows`/`memf-linux`/`memf-strings` would have to
change type, and `serde` derive interplay gets fiddly.

Recommendation:

- **Ship four free functions** in a new `memf-core::sanitize` (or
  `memf-format`) module: `tsv_safe`, `csv_field`, `display_safe`,
  `bytes_to_utf8_lossy_safe`, plus `cap_display` / `suspicious_script_mix`.
- The discipline "raw string in struct, sanitize at the print boundary" is
  enforced by **putting all printing in the existing
  `print_windows_*` / `print_linux_*` formatters** and code-reviewing that
  free-text fields are wrapped. A `clippy`-style grep test
  (`tests/` integration test that scans `src/main.rs` for `println!` with an
  interpolated `.name`/`.path` not wrapped) gives 80% of the newtype's safety
  for ~20 lines.
- If you *do* want a type, the lower-cost variant is a `DecodedStr`/`Decoded`
  carrying the `lossy` flag (§6) — that flag genuinely *is* an intrinsic
  property of the string and is worth modeling. The sanitization-per-channel
  is not.

---

## 9. Additional attack vectors the brief did not list

1. **CSV/TSV formula injection** (§3) — a process or file name beginning
   `= + - @` executes as a formula when the evidence CSV is opened in Excel /
   LibreOffice / Google Sheets. This is a documented, exploited class
   (OWASP "CSV Injection"). Forensic CSVs are *routinely* opened in
   spreadsheets. **Must** be handled. Mitigation: prefix `'` on offending
   fields.
2. **Bare `\r` cursor-rewind in the Table arm** — distinct from `\n`. A `\r`
   without `\n` moves the terminal cursor to column 0; a crafted name can
   overwrite a previously printed row. C0 stripping handles it, but only if
   `\r` is *not* exempted the way `\n` is. Called out in §5 rule 1.
3. **ANSI escape (ESC, U+001B) injection** — process names containing raw ANSI
   sequences can recolor the terminal, hide text, or (with some terminals)
   trigger clipboard/title OSC sequences. Covered by C0 stripping in §5; flag
   so it is never removed as an "optimization."
4. **U+FFFD ambiguity** — a name may *legitimately* contain U+FFFD (the dump
   really had a bad byte in the original process name), or U+FFFD may be an
   artifact of our own lossy decode. Without the `lossy` flag (§6) these are
   indistinguishable, and an analyst could mis-attribute. The `lossy` flag
   resolves it.
5. **NTFS Alternate Data Stream / device-namespace paths** — Windows paths
   like `\\?\C:\…`, `\Device\HarddiskVolume3\…`, or `file.exe:evil.dll`
   (ADS colon) are *legitimate* and must **not** be sanitized away. None of
   the functions here touch `:` `\` `?` — confirm this stays true; mangling
   them would corrupt evidence.
6. **Length as a DoS vector** — a multi-megabyte "name" recovered from
   corrupted memory will not break correctness but can blow up terminal
   rendering and log files. `cap_display` for Table; for JSON/CSV consider a
   sanity hard-cap (e.g. 64 KB) with a `truncated: true` flag rather than
   unbounded output.
7. **Trailing/leading whitespace** — a name `" svchost.exe "` or
   `"svchost.exe\u{00A0}"` (NBSP) is a classic masquerade. Do **not** trim
   automatically (changes identity) — instead `suspicious_script_mix` / a
   companion check should flag names with leading/trailing or non-ASCII
   whitespace.
8. **Combining-character / Zalgo overflow** — long runs of combining marks
   (U+0300+) can break terminal layout and some parsers. `unicode-width`
   counts them as zero-width so `cap_display` will not catch a Zalgo string by
   width. Add a combining-mark run-length cap in `display_safe` if Zalgo is in
   scope (low priority — annoyance, not a security breach).

---

## 10. Implementation order (TDD — RED then GREEN, separate commits)

Per project TDD policy, each step is two commits.

1. `memf-core::sanitize` module skeleton + `tsv_safe` — RED (tests:
   tab/newline/NUL/control/bidi cases, `Cow::Borrowed` on clean input), GREEN.
2. `csv_field` incl. RFC 4180 + formula-injection guard — RED, GREEN. Then
   wire it into every `OutputFormat::Csv` arm in `src/main.rs`, replacing the
   raw interpolation and the half-done `replace('"', ...)`.
3. `display_safe` + `cap_display` — RED, GREEN. Wire into every
   `OutputFormat::Table` arm.
4. `bytes_to_utf8_lossy_safe` + `DecodedStr{lossy}` — RED, GREEN. Migrate the
   `from_utf8_lossy` call sites that decode *display* strings (registry key
   names, env values) to carry the flag.
5. (Follow-up, separate plan) `encoding_rs` behind `legacy-codepages` feature
   for true Big5/GBK/Shift-JIS recovery + `--ansi-codepage` CLI flag.
6. (Follow-up) `suspicious_script_mix` + `"suspicious"` JSON column.

Validate against **real** data (per global doer-checker rule): build dumps /
registry hives from CJK-locale Windows VMs, not only synthetic byte fixtures —
synthetic Big5 fixtures will miss real `NK`/`VK` cell layout quirks.

---

## 11. One-paragraph summary

The brief's premise is partly out of date: there is no `tsv_safe` and no
`Tsv` format; the comma-delimited `Csv` arm exists and is **already buggy**
(unquoted `name`, half-applied quote-doubling). Fix that first — it is a live
correctness bug, not a hypothetical. JSON is genuinely fine; `serde_json`
neutralizes injection by construction, so there is no `json_safe_str` to
write. The DBCS/Big5 "backslash collision" is **not** an output-escaping
threat — a Rust `String` is always valid UTF-8 — it is a *decoding-accuracy*
threat at the `from_utf8_lossy` boundary, fixed by carrying a `lossy` flag and
(later) an opt-in `encoding_rs` decoder. RTL/bidi stripping **is** worth doing
and must be done **at decode time** so JSON consumers are protected, not only
the terminal. Homoglyphs should be **flagged, never rewritten** — rewriting
destroys forensic fidelity. A `SanitizedStr` newtype is **not** worth it
because sanitization is per-output-channel, not per-string; ship four free
functions plus a `DecodedStr{lossy}` type instead. Newly flagged hazards:
spreadsheet formula injection in evidence CSVs (real, must fix), bare-`\r`
cursor-rewind, ANSI/ESC injection, and U+FFFD provenance ambiguity.
