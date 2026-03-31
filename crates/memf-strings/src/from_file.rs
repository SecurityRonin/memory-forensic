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
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut results = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }

        let (offset, value) = parse_line(trimmed, line_num as u64);
        results.push(ClassifiedString {
            value,
            physical_offset: offset,
            encoding: StringEncoding::Ascii,
            categories: Vec::new(),
        });
    }

    Ok(results)
}

/// Parse a single line, detecting offset-prefixed format.
fn parse_line(line: &str, line_num: u64) -> (u64, String) {
    // Try offset-prefixed format: "1234: some string" or "0x1234: some string"
    if let Some(colon_pos) = line.find(": ") {
        let prefix = &line[..colon_pos];
        let prefix = prefix.trim();
        if let Some(offset) = parse_offset(prefix) {
            let value = line[colon_pos + 2..].to_string();
            return (offset, value);
        }
    }
    // Raw format: use line number as pseudo-offset
    (line_num, line.to_string())
}

fn parse_offset(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
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

    #[test]
    fn malformed_offset_line() {
        // "notanumber: some text" — the prefix "notanumber" is not a valid offset,
        // so the whole line should be treated as raw format.
        let path = write_temp_file("notanumber: some text\n");
        let strings = from_strings_file(&path).unwrap();
        assert_eq!(strings.len(), 1);
        // Since "notanumber" can't be parsed as u64, the entire line is the value
        assert_eq!(strings[0].value, "notanumber: some text");
        assert_eq!(strings[0].physical_offset, 0); // line_num 0
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn offset_prefixed_hex_uppercase() {
        let path = write_temp_file("0XFF00: uppercase hex\n");
        let strings = from_strings_file(&path).unwrap();
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].physical_offset, 0xFF00);
        assert_eq!(strings[0].value, "uppercase hex");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn parse_offset_helper() {
        assert_eq!(parse_offset("0x1234"), Some(0x1234));
        assert_eq!(parse_offset("0X1234"), Some(0x1234));
        assert_eq!(parse_offset("42"), Some(42));
        assert_eq!(parse_offset("abc"), None);
        assert_eq!(parse_offset(""), None);
    }
}
