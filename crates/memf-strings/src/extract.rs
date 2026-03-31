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
    todo!()
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn emit_ascii(run: &[u8], offset: u64, out: &mut Vec<ClassifiedString>) {
    todo!()
}

fn emit_utf16(run: &[char], offset: u64, out: &mut Vec<ClassifiedString>) {
    todo!()
}

/// Pair up bytes into (u16 code-unit, physical_address) tuples, handling an
/// optional leftover byte from the previous chunk.
fn build_utf16_pairs(
    chunk: &[u8],
    chunk_base: u64,
    odd: Option<(u8, u64)>,
) -> (Vec<(u16, u64)>, Option<(u8, u64)>) {
    todo!()
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
            "expected exactly 2 strings, got {:?}",
            strings
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
            "expected UTF-16LE \"Test\", got {:?}",
            strings
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
}
