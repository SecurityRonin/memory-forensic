# TDD Audit Report: memory-forensic

**Date**: 2026-03-31
**Scope**: Phase 1 (memf-format, memf-strings) + Phase 2 (memf-symbols, memf-core)
**Excluded**: memf-linux (process.rs, modules.rs, network.rs, kaslr.rs) and src/main.rs (already TDD redo'd)

---

## PHASE 1: memf-format

### crates/memf-format/src/lib.rs -- NEEDS_REDO

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `pub enum Error` (5 variants) | UNTESTED | No Error::Display tests |
| `pub struct PhysicalRange` | TESTED | physical_range_len/empty/contains |
| `pub fn PhysicalRange::len()` | TESTED | physical_range_len |
| `pub fn PhysicalRange::is_empty()` | TESTED | physical_range_empty |
| `pub fn PhysicalRange::contains_addr()` | TESTED | physical_range_contains |
| `pub trait PhysicalMemoryProvider` | indirect | via format impls |
| `pub trait FormatPlugin` | indirect | via format impls |
| `pub fn open_dump(path)` | TESTED | open_dump_lime, open_dump_avml |

**Tests (6):** physical_range_len, physical_range_empty, physical_range_contains, open_dump_lime, open_dump_avml, open_dump_unknown

**Gaps:**
- No Error::Display tests for any of 5 variants
- No test for `PhysicalRange` with `start > end` (saturating_sub edge case)
- No test for `open_dump` producing `AmbiguousFormat`
- No test for `total_size()` default trait implementation
- No test for open_dump with ELF core or raw format files

---

### crates/memf-format/src/lime.rs -- STRICT_TDD

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `pub struct LimeProvider` | TESTED | single_range, two_ranges |
| `pub fn LimeProvider::from_bytes()` | TESTED | all tests via parse() helper |
| `pub fn LimeProvider::from_path()` | indirect | via open_dump in lib.rs |
| `impl PhysicalMemoryProvider` | TESTED | read, ranges, format_name |
| `impl FormatPlugin for LimePlugin` | TESTED | probe_lime_magic, probe_non_lime |

**Tests (7):** probe_lime_magic, probe_non_lime, single_range, two_ranges, read_gap_returns_zero, corrupt_magic_errors, truncated_header_errors

**Gaps:**
- Minor: No direct from_path() test

---

### crates/memf-format/src/avml.rs -- STRICT_TDD (with gaps)

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `pub struct AvmlProvider` | TESTED | single_range_roundtrip |
| `pub fn AvmlProvider::from_bytes()` | TESTED | roundtrip tests |
| `pub fn AvmlProvider::from_path()` | indirect | via open_dump |
| `impl PhysicalMemoryProvider` | TESTED | read, ranges |
| `impl FormatPlugin for AvmlPlugin` | TESTED | probe_avml_magic |

**Tests (5):** probe_avml_magic, probe_non_avml, single_range_roundtrip, two_ranges_roundtrip, gap_returns_zero

**Gaps:**
- NO error-case tests (corrupt header, truncated data)
- NO Snappy decompression tests (compressed block path entirely untested)
- NO AVML version mismatch test

---

### crates/memf-format/src/raw.rs -- STRICT_TDD

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `pub struct RawProvider` | TESTED | all tests |
| `pub fn RawProvider::from_bytes()` | TESTED | read_from_start |
| `pub fn RawProvider::from_path()` | indirect | via open_dump |
| `impl PhysicalMemoryProvider` | TESTED | read, ranges, total_size |
| `impl FormatPlugin for RawPlugin` | TESTED | probe_confidence |

**Tests (5):** probe_confidence, read_from_start, read_past_end, read_partial, empty_dump

**Gaps:**
- Minor: No from_path() error case test

---

### crates/memf-format/src/elf_core.rs -- STRICT_TDD

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `pub struct ElfCoreProvider` | TESTED | single_segment |
| `pub fn ElfCoreProvider::from_bytes()` | TESTED | single/two segments |
| `impl PhysicalMemoryProvider` | TESTED | read, ranges |
| `impl FormatPlugin for ElfCorePlugin` | TESTED | probe tests |

**Tests (6):** probe_elf_core, probe_non_core_elf, probe_non_elf, single_segment, two_segments, read_gap_returns_zero

**Gaps:**
- No corrupt/truncated ELF error test
- No empty data test

---

### crates/memf-format/src/test_builders.rs -- NEEDS_REDO

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `pub struct LimeBuilder` | UNTESTED | (used by other tests, never tested itself) |
| `pub fn LimeBuilder::new()` | UNTESTED | - |
| `pub fn LimeBuilder::add_range()` | UNTESTED | - |
| `pub fn LimeBuilder::build()` | UNTESTED | - |
| `pub struct AvmlBuilder` | UNTESTED | - |
| `pub fn AvmlBuilder::new()` | UNTESTED | - |
| `pub fn AvmlBuilder::add_range()` | UNTESTED | - |
| `pub fn AvmlBuilder::build()` | UNTESTED | - |
| `pub struct ElfCoreBuilder` | UNTESTED | - |
| `pub fn ElfCoreBuilder::new()` | UNTESTED | - |
| `pub fn ElfCoreBuilder::add_segment()` | UNTESTED | - |
| `pub fn ElfCoreBuilder::build()` | UNTESTED | - |

**Tests: ZERO**

**Gaps:**
- CRITICAL: Test infrastructure has no self-tests
- A builder bug could silently corrupt all dependent tests

---

## PHASE 1: memf-strings

### crates/memf-strings/src/lib.rs -- STRICT_TDD (thin)

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `pub struct ClassifiedString` | TESTED | classified_string_basic |
| `pub enum StringEncoding` | indirect | via extract tests |
| `pub enum StringCategory` | indirect | via classifier tests |
| `pub enum Error` (3 variants) | UNTESTED | No Display tests |

**Tests (1):** classified_string_basic

**Gaps:**
- No Error::Display tests
- Thin coverage for a type-definition module

---

### crates/memf-strings/src/extract.rs -- NEEDS_REDO

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `pub struct ExtractConfig` | TESTED | cfg_ascii_only, cfg_utf16_only |
| `pub fn extract_strings()` | TESTED | 4 tests |
| `fn is_printable_ascii()` (priv) | indirect | via extract_ascii_basic |
| `fn is_printable_utf16()` (priv) | indirect | via extract_utf16le |
| `fn emit_ascii()` (priv) | indirect | - |
| `fn emit_utf16()` (priv) | indirect | - |
| `fn build_utf16_pairs()` (priv) | indirect | - |

**Tests (4):** extract_ascii_basic, min_length_filters_short_strings, extract_utf16le, empty_dump

**Gaps:**
- NO test for mixed ASCII + UTF-16 in same dump
- NO test for strings spanning CHUNK_SIZE (64KB) boundaries
- NO test for ExtractConfig::default() values
- NO test for physical_offset correctness across multiple ranges
- NO test for UTF-16 with surrogate pairs

---

### crates/memf-strings/src/classify.rs -- NEEDS_REDO

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `pub trait StringClassifier` | UNTESTED | No object-safety test |
| `pub fn classify_strings()` | UNTESTED | ZERO tests |

**Tests: ZERO**

**Gaps:**
- CRITICAL: Core orchestration function has zero coverage
- No test for empty input
- No test for multiple classifier accumulation
- No test for classify_strings() populating categories

---

### crates/memf-strings/src/regex_classifier.rs -- STRICT_TDD

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `struct RegexClassifier` | TESTED | all classify tests |
| `impl StringClassifier` | TESTED | via classify helper |

**Tests (10):** classifies_url, classifies_ipv4, classifies_email, classifies_unix_path, classifies_windows_path, classifies_registry_key, classifies_ethereum_address, classifies_pem_private_key, classifies_shell_command, no_match_for_garbage

**Gaps:**
- No IPv6 classification test
- No Base64Blob classification test
- No confidence score value assertions
- No false positive edge case tests

---

### crates/memf-strings/src/yara_classifier.rs -- STRICT_TDD (with gaps)

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `pub struct YaraClassifier` | TESTED | match_simple_rule |
| `pub fn from_source()` | TESTED | match_simple_rule, invalid_rule |
| `pub fn from_rules_dir()` | UNTESTED | Entire dir-loading path |
| `pub fn scan_string()` | TESTED | match/no_match/multiple |
| `impl StringClassifier` | indirect | - |

**Tests (4):** match_simple_rule, no_match, multiple_rules, invalid_rule_source_errors

**Gaps:**
- from_rules_dir() entirely untested (empty dir, no .yar files, mixed files)

---

### crates/memf-strings/src/from_file.rs -- STRICT_TDD

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `pub fn from_strings_file()` | TESTED | 5 tests |

**Tests (5):** raw_format, offset_prefixed_decimal, offset_prefixed_hex, skips_empty_lines, string_with_colon_but_no_offset

**Gaps:**
- No I/O error test (nonexistent file)

---

## PHASE 2: memf-symbols

### crates/memf-symbols/src/lib.rs -- STRICT_TDD

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `pub enum Error` (4 variants) | PARTIAL | error_display (NotFound only) |
| `pub struct FieldInfo` | TESTED | field_info_clone |
| `pub struct StructInfo` | indirect | - |
| `pub trait SymbolResolver` | TESTED | trait_is_object_safe |

**Tests (3):** trait_is_object_safe, error_display, field_info_clone

**Gaps:**
- Only 1 of 4 Error variants tested for Display

---

### crates/memf-symbols/src/isf.rs -- STRICT_TDD

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `pub struct IsfResolver` | TESTED | many tests |
| `pub fn from_bytes()` | TESTED | from_bytes_roundtrip |
| `pub fn from_path()` | indirect | - |
| `pub fn from_value()` | TESTED | most tests use this |
| `pub fn struct_count()` | indirect | - |
| `pub fn symbol_count()` | UNTESTED | - |
| `pub fn discover_isf_files()` | TESTED | 3 discovery tests |
| `impl SymbolResolver` | TESTED | all trait methods |

**Tests (11):** resolve_field_offset, resolve_struct_size, resolve_symbol_address, struct_info_returns_all_fields, backend_name, from_bytes_roundtrip, empty_document_ok, invalid_json_is_error, dyn_dispatch_works, discover_explicit_file, discover_explicit_dir, discover_nonexistent_returns_empty

**Gaps:**
- symbol_count() not explicitly tested
- No malformed ISF structure test

---

### crates/memf-symbols/src/btf.rs -- STRICT_TDD (with gaps)

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `pub struct BtfResolver` | TESTED | multiple tests |
| `pub fn from_bytes()` | TESTED | parse_btf_header |
| `pub fn from_path()` | UNTESTED | ELF .BTF extraction untested |
| `pub fn struct_count()` | indirect | - |
| `impl SymbolResolver` | TESTED | all trait methods |

**Private (non-trivial):**
| Item | Status |
|------|--------|
| `fn parse_type_section()` | indirect |
| `fn read_btf_string()` | indirect |
| `fn resolve_type_name()` | indirect |
| `fn extract_btf_from_elf()` | UNTESTED |
| `fn extract_btf_from_elf64()` | UNTESTED |

**Tests (8):** parse_btf_header, resolve_struct_from_btf, btf_has_no_symbol_addresses, btf_backend_name, btf_bad_magic, btf_too_short, btf_struct_info, btf_dyn_dispatch

**Gaps:**
- from_path() entirely untested
- ELF .BTF section extraction untested (significant code path)
- No test for nested/complex BTF types

---

### crates/memf-symbols/src/test_builders.rs -- STRICT_TDD

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `pub struct IsfBuilder` | TESTED | builder_produces_valid_json |
| `pub fn new()` | TESTED | - |
| `pub fn add_struct()` | TESTED | - |
| `pub fn add_field()` | TESTED | - |
| `pub fn add_symbol()` | TESTED | - |
| `pub fn build_json()` | TESTED | - |
| `pub fn build_bytes()` | indirect | - |
| `pub fn linux_process_preset()` | TESTED | linux_preset_has_required_fields |

**Tests (3):** builder_produces_valid_json, linux_preset_has_required_fields, + 1 more

---

## PHASE 2: memf-core

### crates/memf-core/src/lib.rs -- STRICT_TDD (thin)

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `pub enum Error` (5 variants) | PARTIAL | error_display_page_not_present (1/5) |

**Tests (1):** error_display_page_not_present

**Gaps:**
- 4 of 5 error variants untested for Display

---

### crates/memf-core/src/vas.rs -- STRICT_TDD

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `pub enum TranslationMode` | indirect | - |
| `pub struct VirtualAddressSpace<P>` | TESTED | many tests |
| `pub fn new()` | TESTED | all tests |
| `pub fn virt_to_phys()` | TESTED | translate_4k/2m/1g |
| `pub fn read_virt()` | TESTED | read_virt_4k, cross_page |
| `pub fn physical()` | UNTESTED | - |

**Tests (9):** translate_4k_page, translate_4k_with_offset, read_virt_4k, translate_2mb_page, translate_1gb_page, non_present_page_returns_error, read_virt_cross_page_boundary, read_virt_empty_buffer, multiple_mappings_same_pml4

**Gaps:**
- physical() accessor untested
- No PartialRead error test

---

### crates/memf-core/src/object_reader.rs -- STRICT_TDD (with gaps)

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `pub struct ObjectReader<P>` | TESTED | read_field_u32 |
| `pub fn new()` | TESTED | make_reader helper |
| `pub fn symbols()` | UNTESTED | - |
| `pub fn read_field<T>()` | TESTED | u32, u64, missing_symbol |
| `pub fn read_pointer()` | UNTESTED | - |
| `pub fn read_string()` | TESTED | read_string_with_null |
| `pub fn read_field_string()` | TESTED | read_field_string_test |
| `pub fn walk_list()` | TESTED | walk_list_simple |

**Tests (6):** read_field_u32, read_field_u64, read_field_missing_symbol, read_field_string_test, read_string_with_null, walk_list_simple

**Gaps:**
- read_pointer() completely untested
- symbols() accessor untested
- No walk_list cycle detection test (ListCycle error)
- No walk_list empty list test (head.next == head)
- No walk_list single element test

---

### crates/memf-core/src/test_builders.rs -- STRICT_TDD

**Public API:**
| Item | Status | Tested By |
|------|--------|-----------|
| `pub struct SyntheticPhysMem` | TESTED | read_write, u64 |
| `pub struct PageTableBuilder` | TESTED | creates_pml4, map_4k, map_2m |
| All builder methods | TESTED or indirect | - |

**Tests (5):** synthetic_mem_read_write, synthetic_mem_u64, page_table_builder_creates_pml4, page_table_builder_map_4k, page_table_builder_map_2m

**Gaps:**
- data() accessor untested
- map_1g() only tested via vas.rs (not directly)

---

## PRIORITY REDO LIST (ordered by severity)

### CRITICAL (zero coverage on non-trivial logic):
1. **memf-strings/classify.rs** -- classify_strings() has ZERO tests
2. **memf-format/test_builders.rs** -- Test infrastructure has ZERO self-tests

### HIGH (significant untested code paths):
3. **memf-strings/extract.rs** -- Missing chunk boundary, mixed encoding, offset tracking tests
4. **memf-format/lib.rs** -- Missing Error display, AmbiguousFormat, edge case tests
5. **memf-symbols/btf.rs** -- from_path() and ELF .BTF extraction untested
6. **memf-core/object_reader.rs** -- read_pointer() untested, walk_list cycle/empty untested
7. **memf-strings/yara_classifier.rs** -- from_rules_dir() entirely untested

### MEDIUM (missing error path coverage):
8. **memf-format/avml.rs** -- No error/compressed block tests
9. **memf-format/elf_core.rs** -- No corrupt ELF test
10. **memf-core/lib.rs** -- 4/5 error variants untested
11. **memf-symbols/lib.rs** -- 3/4 error variants untested
12. **memf-strings/lib.rs** -- Error types untested

### LOW (minor gaps, accessor methods):
13. **memf-core/vas.rs** -- physical() untested
14. **memf-strings/regex_classifier.rs** -- IPv6, Base64Blob categories untested
15. **memf-strings/from_file.rs** -- I/O error path untested

### CONFIRMED: No todo!() or unimplemented!() stubs found in any audited file.
