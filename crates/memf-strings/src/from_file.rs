//! Parser for pre-extracted string files (one string per line).
//!
//! Supports two formats:
//! 1. Raw: one string per line (no offset info)
//! 2. Offset-prefixed: `<offset>: <string>` (decimal or hex offset)

use crate::{ClassifiedString, Result, StringEncoding};
use std::io::BufRead;
use std::path::Path;

/// Parse a pre-extracted strings file into `ClassifiedString` values.
///
/// Each line becomes one `ClassifiedString` with empty categories
/// (to be classified later by the pipeline).
pub fn from_strings_file(path: &Path) -> Result<Vec<ClassifiedString>> {
    todo!()
}

/// Parse a single line, detecting offset-prefixed format.
fn parse_line(line: &str, line_num: u64) -> (u64, String) {
    todo!()
}

fn parse_offset(s: &str) -> Option<u64> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp_file(content: &str) -> std::path::PathBuf {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        std::thread::current().name().hash(&mut h);
        content.len().hash(&mut h);
        let unique = h.finish();
        let path = std::env::temp_dir().join(format!(
            "memf_test_strings_{}_{}",
            std::process::id(),
            unique
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn raw_format() {
        let path = write_temp_file("Hello World\n/etc/passwd\nhttps://evil.com\n");
        let strings = from_strings_file(&path).unwrap();
        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0].value, "Hello World");
        assert_eq!(strings[1].value, "/etc/passwd");
        assert_eq!(strings[2].value, "https://evil.com");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn offset_prefixed_decimal() {
        let path = write_temp_file("1000: Hello\n2000: World\n");
        let strings = from_strings_file(&path).unwrap();
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].physical_offset, 1000);
        assert_eq!(strings[0].value, "Hello");
        assert_eq!(strings[1].physical_offset, 2000);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn offset_prefixed_hex() {
        let path = write_temp_file("0x1A2B: hex string\n");
        let strings = from_strings_file(&path).unwrap();
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].physical_offset, 0x1A2B);
        assert_eq!(strings[0].value, "hex string");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn skips_empty_lines() {
        let path = write_temp_file("line1\n\n\nline2\n");
        let strings = from_strings_file(&path).unwrap();
        assert_eq!(strings.len(), 2);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn string_with_colon_but_no_offset() {
        let path = write_temp_file("http://example.com:8080/path\n");
        let strings = from_strings_file(&path).unwrap();
        assert_eq!(strings.len(), 1);
        // "http" is not a valid offset, so the whole line is the value
        assert_eq!(strings[0].value, "http://example.com:8080/path");
        std::fs::remove_file(&path).ok();
    }
}
