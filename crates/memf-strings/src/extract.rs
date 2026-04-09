//! String extraction from physical memory.

use memf_format::PhysicalMemoryProvider;

use crate::{ClassifiedString, StringEncoding};

const CHUNK_SIZE: usize = 64 * 1024; // 64 KB

/// Configuration for string extraction.
pub struct ExtractConfig {
    /// Minimum number of characters for a string to be emitted. Default: 4.
    pub min_length: usize,
    /// Extract ASCII strings (printable bytes 0x20–0x7E plus \t \n \r). Default: true.
    pub ascii: bool,
    /// Extract UTF-16LE strings. Default: true.
    pub utf16le: bool,
}

impl Default for ExtractConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            ascii: true,
            utf16le: true,
        }
    }
}

/// Returns `true` if the byte is a printable ASCII character or a common
/// whitespace character (\t, \n, \r).
#[inline]
fn is_printable_ascii(b: u8) -> bool {
    matches!(b, 0x20..=0x7E | b'\t' | b'\n' | b'\r')
}

/// Returns `true` if the UTF-16 code unit represents a printable ASCII
/// character (same range, mapped to u16).
#[inline]
fn is_printable_utf16(cp: u16) -> bool {
    matches!(cp, 0x0020..=0x007E | 0x0009 | 0x000A | 0x000D)
}

/// Extract strings from a physical memory provider.
///
/// Reads 64 KB chunks from each physical range, scanning for ASCII and/or
/// UTF-16LE printable sequences of at least `config.min_length` characters.
/// The returned `ClassifiedString` values have empty `categories` — callers
/// should run a classifier pass afterwards.
pub fn extract_strings(
    provider: &dyn PhysicalMemoryProvider,
    config: &ExtractConfig,
) -> Vec<ClassifiedString> {
    let mut results: Vec<ClassifiedString> = Vec::new();

    for range in provider.ranges() {
        let mut addr = range.start;

        // carry-over buffer for ASCII across chunk boundaries
        let mut ascii_carry: Vec<u8> = Vec::new();
        let mut ascii_carry_offset: u64 = range.start;

        // carry-over for UTF-16LE (we may have an odd byte left from previous chunk)
        let mut utf16_odd_byte: Option<(u8, u64)> = None;

        while addr < range.end {
            let chunk_len = CHUNK_SIZE.min((range.end - addr) as usize);
            let mut buf = vec![0u8; chunk_len];
            let n = provider.read_phys(addr, &mut buf).unwrap_or(0);
            if n == 0 {
                if ascii_carry.len() >= config.min_length && config.ascii {
                    emit_ascii(&ascii_carry, ascii_carry_offset, &mut results);
                }
                ascii_carry.clear();
                utf16_odd_byte = None;
                addr += chunk_len as u64;
                continue;
            }
            let chunk = &buf[..n];

            // ── ASCII pass ────────────────────────────────────────────────
            if config.ascii {
                for (i, &b) in chunk.iter().enumerate() {
                    let phys = addr + i as u64;
                    if is_printable_ascii(b) {
                        if ascii_carry.is_empty() {
                            ascii_carry_offset = phys;
                        }
                        ascii_carry.push(b);
                    } else {
                        if ascii_carry.len() >= config.min_length {
                            emit_ascii(&ascii_carry, ascii_carry_offset, &mut results);
                        }
                        ascii_carry.clear();
                    }
                }
            }

            // ── UTF-16LE pass ─────────────────────────────────────────────
            if config.utf16le {
                let (pairs, new_odd) = build_utf16_pairs(chunk, addr, utf16_odd_byte.take());

                let mut run: Vec<char> = Vec::new();
                let mut run_offset: u64 = 0;

                for (cp, phys) in pairs {
                    if is_printable_utf16(cp) {
                        if run.is_empty() {
                            run_offset = phys;
                        }
                        run.push(cp as u8 as char);
                    } else {
                        if run.len() >= config.min_length {
                            emit_utf16(&run, run_offset, &mut results);
                        }
                        run.clear();
                    }
                }
                if run.len() >= config.min_length {
                    emit_utf16(&run, run_offset, &mut results);
                }
                utf16_odd_byte = new_odd;
            }

            addr += n as u64;
        }

        // ── End-of-range flushes ──────────────────────────────────────────
        if config.ascii && ascii_carry.len() >= config.min_length {
            emit_ascii(&ascii_carry, ascii_carry_offset, &mut results);
        }
    }

    results
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn emit_ascii(run: &[u8], offset: u64, out: &mut Vec<ClassifiedString>) {
    let value = String::from_utf8_lossy(run).into_owned();
    out.push(ClassifiedString {
        value,
        physical_offset: offset,
        encoding: StringEncoding::Ascii,
        categories: vec![],
    });
}

fn emit_utf16(run: &[char], offset: u64, out: &mut Vec<ClassifiedString>) {
    let value: String = run.iter().collect();
    out.push(ClassifiedString {
        value,
        physical_offset: offset,
        encoding: StringEncoding::Utf16Le,
        categories: vec![],
    });
}

/// Pair up bytes into (u16 code-unit, physical_address) tuples, handling an
/// optional leftover byte from the previous chunk.
fn build_utf16_pairs(
    chunk: &[u8],
    chunk_base: u64,
    odd: Option<(u8, u64)>,
) -> (Vec<(u16, u64)>, Option<(u8, u64)>) {
    let mut pairs = Vec::new();

    let mut i = if let Some((lo, addr)) = odd {
        if chunk.is_empty() {
            return (pairs, Some((lo, addr)));
        }
        let hi = chunk[0];
        let cp = u16::from_le_bytes([lo, hi]);
        pairs.push((cp, addr));
        1usize
    } else {
        0usize
    };

    while i + 1 < chunk.len() {
        let addr = chunk_base + i as u64;
        let cp = u16::from_le_bytes([chunk[i], chunk[i + 1]]);
        pairs.push((cp, addr));
        i += 2;
    }

    let new_odd = if i < chunk.len() {
        Some((chunk[i], chunk_base + i as u64))
    } else {
        None
    };

    (pairs, new_odd)
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use memf_format::raw::RawProvider;

    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn cfg_ascii_only(min: usize) -> ExtractConfig {
        ExtractConfig {
            min_length: min,
            ascii: true,
            utf16le: false,
        }
    }

    fn cfg_utf16_only(min: usize) -> ExtractConfig {
        ExtractConfig {
            min_length: min,
            ascii: false,
            utf16le: true,
        }
    }

    // ── Test 1: basic ASCII extraction ────────────────────────────────────────

    #[test]
    fn extract_ascii_basic() {
        // Build a 64-byte buffer: zeros everywhere except two embedded strings.
        //   offset 0x08: "Hello" (5 bytes)
        //   offset 0x20: "World" (5 bytes)
        let mut data = vec![0u8; 64];
        data[0x08..0x0D].copy_from_slice(b"Hello");
        data[0x20..0x25].copy_from_slice(b"World");

        let provider = RawProvider::from_bytes(&data);
        let cfg = cfg_ascii_only(4);
        let strings = extract_strings(&provider, &cfg);

        assert_eq!(
            strings.len(),
            2,
            "expected exactly 2 strings, got {strings:?}"
        );

        let hello = strings
            .iter()
            .find(|s| s.value == "Hello")
            .expect("Hello not found");
        assert_eq!(hello.physical_offset, 0x08);
        assert_eq!(hello.encoding, StringEncoding::Ascii);

        let world = strings
            .iter()
            .find(|s| s.value == "World")
            .expect("World not found");
        assert_eq!(world.physical_offset, 0x20);
        assert_eq!(world.encoding, StringEncoding::Ascii);
    }

    // ── Test 2: min_length filter ─────────────────────────────────────────────

    #[test]
    fn min_length_filters_short_strings() {
        // "Hi" is 2 chars -> filtered; "Longer" is 6 chars -> kept.
        let mut data = vec![0u8; 32];
        data[0x00..0x02].copy_from_slice(b"Hi");
        data[0x10..0x16].copy_from_slice(b"Longer");

        let provider = RawProvider::from_bytes(&data);
        let cfg = cfg_ascii_only(4);
        let strings = extract_strings(&provider, &cfg);

        assert!(
            strings.iter().all(|s| s.value != "Hi"),
            "\"Hi\" should be filtered out (len < min_length)"
        );
        assert!(
            strings.iter().any(|s| s.value == "Longer"),
            "\"Longer\" should be kept"
        );
    }

    // ── Test 3: UTF-16LE extraction ───────────────────────────────────────────

    #[test]
    fn extract_utf16le() {
        // Encode "Test" as UTF-16LE: T\0 e\0 s\0 t\0 = 8 bytes
        let mut data = vec![0u8; 32];
        let utf16_bytes: &[u8] = &[b'T', 0x00, b'e', 0x00, b's', 0x00, b't', 0x00];
        let offset = 0x08usize;
        data[offset..offset + utf16_bytes.len()].copy_from_slice(utf16_bytes);

        let provider = RawProvider::from_bytes(&data);
        let cfg = cfg_utf16_only(4);
        let strings = extract_strings(&provider, &cfg);

        let found = strings.iter().find(|s| s.value == "Test");
        assert!(
            found.is_some(),
            "expected UTF-16LE \"Test\", got {strings:?}"
        );
        assert_eq!(found.unwrap().encoding, StringEncoding::Utf16Le);
        assert_eq!(found.unwrap().physical_offset, offset as u64);
    }

    // ── Test 4: empty provider produces no strings ────────────────────────────

    #[test]
    fn empty_dump() {
        let provider = RawProvider::from_bytes(&[]);
        let cfg = ExtractConfig::default();
        let strings = extract_strings(&provider, &cfg);
        assert!(strings.is_empty(), "empty dump should yield no strings");
    }

    #[test]
    fn extract_config_default_values() {
        let cfg = ExtractConfig::default();
        assert_eq!(cfg.min_length, 4);
        assert!(cfg.ascii);
        assert!(cfg.utf16le);
    }

    #[test]
    fn cross_boundary_ascii_detection() {
        // Build a buffer where a string spans the 64KB chunk boundary.
        // CHUNK_SIZE is 64 * 1024 = 65536.
        let total_size = 65536 + 128;
        let mut data = vec![0u8; total_size];
        // Place "ABCDEFGHIJ" (10 chars) starting 5 bytes before the 64K boundary
        let start = 65536 - 5;
        data[start..start + 10].copy_from_slice(b"ABCDEFGHIJ");

        let provider = RawProvider::from_bytes(&data);
        let cfg = cfg_ascii_only(4);
        let strings = extract_strings(&provider, &cfg);

        // The carry mechanism should produce "ABCDEFGHIJ" as a single string
        let found = strings.iter().find(|s| s.value.contains("ABCDE"));
        assert!(
            found.is_some(),
            "expected cross-boundary string, got {:?}",
            strings.iter().map(|s| &s.value).collect::<Vec<_>>()
        );
        let s = found.unwrap();
        assert_eq!(s.value, "ABCDEFGHIJ");
        assert_eq!(s.physical_offset, start as u64);
    }

    #[test]
    fn ascii_only_mode_skips_utf16() {
        // Build UTF-16LE "Test" but only enable ASCII mode
        let mut data = vec![0u8; 32];
        data[0..8].copy_from_slice(&[b'T', 0x00, b'e', 0x00, b's', 0x00, b't', 0x00]);

        let provider = RawProvider::from_bytes(&data);
        let cfg = cfg_ascii_only(4);
        let strings = extract_strings(&provider, &cfg);

        // Should NOT find "Test" as a UTF-16 string
        assert!(
            !strings
                .iter()
                .any(|s| s.value == "Test" && s.encoding == StringEncoding::Utf16Le),
            "UTF-16 strings should not be extracted in ASCII-only mode"
        );
    }

    #[test]
    fn utf16_only_mode_skips_ascii() {
        let mut data = vec![0u8; 32];
        data[0..5].copy_from_slice(b"Hello");

        let provider = RawProvider::from_bytes(&data);
        let cfg = cfg_utf16_only(4);
        let strings = extract_strings(&provider, &cfg);

        // Should NOT find "Hello" as an ASCII string
        assert!(
            !strings
                .iter()
                .any(|s| s.value == "Hello" && s.encoding == StringEncoding::Ascii),
            "ASCII strings should not be extracted in UTF-16-only mode"
        );
    }
}
