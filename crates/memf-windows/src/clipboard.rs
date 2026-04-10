//! Windows clipboard content recovery from kernel memory.
//!
//! The Windows clipboard stores data in `win32k`'s `_CLIP` structure array
//! on `_WINSTATION_OBJECT`. Recovering clipboard contents from memory
//! captures passwords, URLs, or commands that were copied before the dump.
//!
//! Each clipboard entry has a format (e.g., `CF_TEXT`, `CF_UNICODETEXT`,
//! `CF_HDROP`) and an associated data handle. Text formats are decoded
//! and a preview is extracted for forensic analysis.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// Maximum number of clipboard entries to enumerate (safety limit).
const MAX_CLIP_ENTRIES: usize = 256;

/// Information about a clipboard entry recovered from kernel memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClipboardEntry {
    /// Clipboard format code (CF_TEXT=1, CF_UNICODETEXT=13, CF_HDROP=15, etc.).
    pub format: u32,
    /// Human-readable format name.
    pub format_name: String,
    /// Size of clipboard data in bytes.
    pub data_size: usize,
    /// First 256 chars of text content (if text format).
    pub preview: String,
    /// Process that last set clipboard.
    pub owner_pid: u32,
    /// Heuristic flag indicating suspicious content.
    pub is_suspicious: bool,
}

/// Map a clipboard format code to a human-readable name.
pub fn format_name(format: u32) -> &'static str {
    match format {
        1 => "CF_TEXT",
        2 => "CF_BITMAP",
        3 => "CF_METAFILEPICT",
        4 => "CF_SYLK",
        5 => "CF_DIF",
        6 => "CF_TIFF",
        7 => "CF_OEMTEXT",
        8 => "CF_DIB",
        9 => "CF_PALETTE",
        10 => "CF_PENDATA",
        11 => "CF_RIFF",
        12 => "CF_WAVE",
        13 => "CF_UNICODETEXT",
        14 => "CF_ENHMETAFILE",
        15 => "CF_HDROP",
        16 => "CF_LOCALE",
        17 => "CF_DIBV5",
        _ => "Unknown",
    }
}

/// Classify clipboard text content as suspicious.
///
/// Returns `true` for content that may indicate credential theft,
/// encoded commands, or other malicious activity.
pub fn classify_clipboard(preview: &str) -> bool {
    if preview.is_empty() {
        return false;
    }

    let lower = preview.to_ascii_lowercase();

    // Contains "password" or "passwd" (case-insensitive)
    if lower.contains("password") || lower.contains("passwd") {
        return true;
    }

    // Contains PowerShell encoded commands (-enc, -encodedcommand)
    if lower.contains("-enc ") || lower.contains("-encodedcommand ") {
        return true;
    }

    // Contains URLs with raw IP addresses (http(s)://digits.digits.digits.digits)
    if contains_ip_url(&lower) {
        return true;
    }

    // Very long base64-like strings (>100 chars, no spaces)
    if preview.len() > 100 && !preview.contains(' ') {
        return true;
    }

    false
}

/// Check whether text contains an HTTP(S) URL with a raw IP address.
fn contains_ip_url(text: &str) -> bool {
    for prefix in &["http://", "https://"] {
        if let Some(start) = text.find(prefix) {
            let after = &text[start + prefix.len()..];
            // Check if the host portion starts with a digit (simple IP heuristic)
            if let Some(first) = after.chars().next() {
                if first.is_ascii_digit() {
                    // Verify it looks like an IP: digits and dots before the next / or :
                    let host_end = after
                        .find(|c: char| c == '/' || c == ':')
                        .unwrap_or(after.len());
                    let host = &after[..host_end];
                    if host.chars().all(|c| c.is_ascii_digit() || c == '.') && host.contains('.') {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Recover clipboard entries from Windows kernel memory.
///
/// Walks `grpWinStaList` to find `_WINSTATION_OBJECT` structures, then
/// reads the `pClipBase` pointer to the `_CLIP` structure array.
/// Returns an empty `Vec` if the required symbols are not present.
pub fn walk_clipboard<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<ClipboardEntry>> {
    // Look up grpWinStaList -> _WINSTATION_OBJECT list head.
    let winsta_head = match reader.symbols().symbol_address("grpWinStaList") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    let clip_base_off = reader
        .symbols()
        .field_offset("_WINSTATION_OBJECT", "pClipBase")
        .unwrap_or(0x58);

    let num_formats_off = reader
        .symbols()
        .field_offset("_WINSTATION_OBJECT", "cNumClipFormats")
        .unwrap_or(0x60);

    let clip_fmt_off = reader
        .symbols()
        .field_offset("_CLIP", "fmt")
        .unwrap_or(0x00);

    let clip_hdata_off = reader
        .symbols()
        .field_offset("_CLIP", "hData")
        .unwrap_or(0x08);

    let clip_struct_size = reader.symbols().struct_size("_CLIP").unwrap_or(0x10);

    // Read the _WINSTATION_OBJECT pointer from grpWinStaList.
    let winsta_ptr = match reader.read_bytes(winsta_head, 8) {
        Ok(bytes) if bytes.len() == 8 => {
            let ptr = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            if ptr == 0 {
                return Ok(Vec::new());
            }
            ptr
        }
        _ => return Ok(Vec::new()),
    };

    // Read cNumClipFormats to know how many _CLIP entries exist.
    let num_formats = match reader.read_bytes(winsta_ptr + num_formats_off, 4) {
        Ok(bytes) if bytes.len() == 4 => {
            u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize
        }
        _ => return Ok(Vec::new()),
    };

    if num_formats == 0 || num_formats > MAX_CLIP_ENTRIES {
        return Ok(Vec::new());
    }

    // Read pClipBase pointer -> array of _CLIP structures.
    let clip_base = match reader.read_bytes(winsta_ptr + clip_base_off, 8) {
        Ok(bytes) if bytes.len() == 8 => {
            let ptr = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            if ptr == 0 {
                return Ok(Vec::new());
            }
            ptr
        }
        _ => return Ok(Vec::new()),
    };

    let mut entries = Vec::new();

    for i in 0..num_formats {
        let clip_addr = clip_base + (i as u64) * clip_struct_size;

        // Read format code.
        let fmt = match reader.read_bytes(clip_addr + clip_fmt_off, 4) {
            Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            _ => continue,
        };

        // Read data handle.
        let h_data = match reader.read_bytes(clip_addr + clip_hdata_off, 8) {
            Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            _ => continue,
        };

        // Try to read text content for text formats.
        let (data_size, preview) = if fmt == 1 || fmt == 7 {
            // CF_TEXT / CF_OEMTEXT: ANSI string
            read_ansi_preview(reader, h_data)
        } else if fmt == 13 {
            // CF_UNICODETEXT: UTF-16LE string
            read_unicode_preview(reader, h_data)
        } else {
            (0, String::new())
        };

        let name = format_name(fmt).to_string();
        let is_suspicious = classify_clipboard(&preview);

        entries.push(ClipboardEntry {
            format: fmt,
            format_name: name,
            data_size,
            preview,
            owner_pid: 0, // Owner PID requires walking the clipboard owner chain
            is_suspicious,
        });
    }

    Ok(entries)
}

/// Read an ANSI (single-byte) string from a memory address for preview.
fn read_ansi_preview<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    addr: u64,
) -> (usize, String) {
    if addr == 0 {
        return (0, String::new());
    }

    let max_read = 512;
    match reader.read_bytes(addr, max_read) {
        Ok(buf) => {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            let text = String::from_utf8_lossy(&buf[..end]);
            let preview: String = text.chars().take(256).collect();
            (end, preview)
        }
        Err(_) => (0, String::new()),
    }
}

/// Read a UTF-16LE string from a memory address for preview.
fn read_unicode_preview<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    addr: u64,
) -> (usize, String) {
    if addr == 0 {
        return (0, String::new());
    }

    let max_read = 1024;
    match reader.read_bytes(addr, max_read) {
        Ok(buf) => {
            // Find null terminator (two zero bytes on u16 boundary)
            let mut end = buf.len();
            for i in (0..buf.len()).step_by(2) {
                if i + 1 < buf.len() && buf[i] == 0 && buf[i + 1] == 0 {
                    end = i;
                    break;
                }
            }

            let u16s: Vec<u16> = buf[..end]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();

            let text = String::from_utf16_lossy(&u16s);
            let preview: String = text.chars().take(256).collect();
            (end, preview)
        }
        Err(_) => (0, String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ── classify_clipboard tests ──────────────────────────────────────

    /// Contains "password" (case-insensitive) → suspicious.
    #[test]
    fn classify_clipboard_password_suspicious() {
        assert!(classify_clipboard("my Password is hunter2"));
        assert!(classify_clipboard("PASSWORD: secret123"));
        assert!(classify_clipboard("old passwd: abc"));
    }

    /// Contains PowerShell encoded command → suspicious.
    #[test]
    fn classify_clipboard_powershell_encoded_suspicious() {
        assert!(classify_clipboard(
            "powershell.exe -enc ZQBjAGgAbwAgACIASABlAGwAbABvACIA"
        ));
        assert!(classify_clipboard(
            "powershell -EncodedCommand ZQBjAGgAbwAgACIASABlAGwAbABvACIA"
        ));
    }

    /// Normal text → benign.
    #[test]
    fn classify_clipboard_normal_text_benign() {
        assert!(!classify_clipboard("Hello, world!"));
        assert!(!classify_clipboard("Meeting at 3pm tomorrow"));
        assert!(!classify_clipboard(
            "The quick brown fox jumps over the lazy dog"
        ));
    }

    /// Long base64-like string (>100 chars, no spaces) → suspicious.
    #[test]
    fn classify_clipboard_long_base64_suspicious() {
        let long_b64 = "a".repeat(101);
        assert!(classify_clipboard(&long_b64));
        // Short strings without spaces are NOT suspicious
        assert!(!classify_clipboard("aGVsbG8="));
    }

    /// Empty → not suspicious.
    #[test]
    fn classify_clipboard_empty_benign() {
        assert!(!classify_clipboard(""));
    }

    /// URL with raw IP address → suspicious.
    #[test]
    fn classify_clipboard_url_with_ip_suspicious() {
        assert!(classify_clipboard("http://192.168.1.1/payload.exe"));
        assert!(classify_clipboard("https://10.0.0.5:8080/cmd"));
    }

    /// URL with hostname (not raw IP) → benign.
    #[test]
    fn classify_clipboard_url_with_hostname_benign() {
        assert!(!classify_clipboard("https://example.com/page"));
        assert!(!classify_clipboard("http://www.google.com/search?q=test"));
    }

    /// Exactly 100 chars, no spaces — not long enough to be suspicious.
    #[test]
    fn classify_clipboard_exactly_100_chars_no_spaces_benign() {
        let s = "a".repeat(100);
        // Must be > 100, so exactly 100 is benign.
        assert!(!classify_clipboard(&s));
    }

    /// 101 chars with a space — not suspicious (space breaks the no-space rule).
    #[test]
    fn classify_clipboard_101_chars_with_space_benign() {
        let s = format!("{} {}", "a".repeat(50), "b".repeat(49));
        assert_eq!(s.len(), 101);
        assert!(!classify_clipboard(&s));
    }

    /// passwd variant triggers suspicious flag.
    #[test]
    fn classify_clipboard_passwd_variant_suspicious() {
        assert!(classify_clipboard("my passwd is secret"));
        assert!(classify_clipboard("enter PASSWD:"));
    }

    /// -encodedcommand (without trailing space) does not trigger false positive.
    #[test]
    fn classify_clipboard_encodedcommand_no_trailing_space_benign() {
        // The check is for "-encodedcommand " (with trailing space) — without space is benign.
        assert!(!classify_clipboard("info about -encodedcommandline option"));
    }

    /// https URL with IP but no slash or colon after IP → still suspicious.
    #[test]
    fn classify_clipboard_https_ip_no_path_suspicious() {
        assert!(classify_clipboard("https://172.16.0.1"));
    }

    // ── ClipboardEntry serialization ──────────────────────────────────

    #[test]
    fn clipboard_entry_serializes() {
        let entry = ClipboardEntry {
            format: 1,
            format_name: "CF_TEXT".to_string(),
            data_size: 42,
            preview: "hello world".to_string(),
            owner_pid: 1234,
            is_suspicious: false,
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"format\":1"));
        assert!(json.contains("\"format_name\":\"CF_TEXT\""));
        assert!(json.contains("\"data_size\":42"));
        assert!(json.contains("\"preview\":\"hello world\""));
        assert!(json.contains("\"owner_pid\":1234"));
        assert!(json.contains("\"is_suspicious\":false"));
    }

    #[test]
    fn clipboard_entry_suspicious_serializes() {
        let entry = ClipboardEntry {
            format: 13,
            format_name: "CF_UNICODETEXT".to_string(),
            data_size: 256,
            preview: "password: hunter2".to_string(),
            owner_pid: 0,
            is_suspicious: true,
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"is_suspicious\":true"));
        assert!(json.contains("\"format_name\":\"CF_UNICODETEXT\""));
    }

    // ── contains_ip_url edge cases ────────────────────────────────────

    #[test]
    fn contains_ip_url_with_port_only_suspicious() {
        // https://10.0.0.1:443 — has colon after IP (port), still recognized as IP.
        assert!(contains_ip_url("https://10.0.0.1:443"));
    }

    #[test]
    fn contains_ip_url_hostname_not_ip() {
        assert!(!contains_ip_url("http://malware-c2.ru/cmd"));
    }

    #[test]
    fn contains_ip_url_ip_without_dot_not_recognized() {
        // "1234" with no dot — not a valid IP pattern.
        assert!(!contains_ip_url("http://12345/path"));
    }

    #[test]
    fn contains_ip_url_empty_string() {
        assert!(!contains_ip_url(""));
    }

    // ── format_name tests ─────────────────────────────────────────────

    /// Known clipboard formats map to correct names.
    #[test]
    fn format_name_known_formats() {
        assert_eq!(format_name(1), "CF_TEXT");
        assert_eq!(format_name(2), "CF_BITMAP");
        assert_eq!(format_name(3), "CF_METAFILEPICT");
        assert_eq!(format_name(4), "CF_SYLK");
        assert_eq!(format_name(5), "CF_DIF");
        assert_eq!(format_name(6), "CF_TIFF");
        assert_eq!(format_name(7), "CF_OEMTEXT");
        assert_eq!(format_name(8), "CF_DIB");
        assert_eq!(format_name(9), "CF_PALETTE");
        assert_eq!(format_name(10), "CF_PENDATA");
        assert_eq!(format_name(11), "CF_RIFF");
        assert_eq!(format_name(12), "CF_WAVE");
        assert_eq!(format_name(13), "CF_UNICODETEXT");
        assert_eq!(format_name(14), "CF_ENHMETAFILE");
        assert_eq!(format_name(15), "CF_HDROP");
        assert_eq!(format_name(16), "CF_LOCALE");
        assert_eq!(format_name(17), "CF_DIBV5");
        assert_eq!(format_name(9999), "Unknown");
    }

    // ── walk_clipboard tests ──────────────────────────────────────────

    /// No grpWinStaList symbol → empty Vec.
    #[test]
    fn walk_clipboard_no_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 0x100)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_clipboard(&reader).unwrap();
        assert!(result.is_empty());
    }
}
