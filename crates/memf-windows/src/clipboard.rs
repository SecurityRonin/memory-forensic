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
        _ => "CF_UNKNOWN",
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

    let lower = preview.to_lowercase();

    // Credential-related keywords
    if lower.contains("password") || lower.contains("passwd") {
        return true;
    }

    // Encoded PowerShell commands (must have trailing space after flag)
    if lower.contains("-encodedcommand ") || lower.contains("-enc ") {
        return true;
    }

    // IP-based URLs (C2 beacons)
    if contains_ip_url(&lower) {
        return true;
    }

    // Long base64-like token: >100 chars, no spaces
    for token in preview.split_whitespace() {
        if token.len() > 100
            && token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            return true;
        }
    }

    false
}

/// Check whether text contains an HTTP(S) URL with a raw IP address.
fn contains_ip_url(text: &str) -> bool {
    // Look for http:// or https:// followed by digits
    for prefix in &["http://", "https://"] {
        let mut search = text;
        while let Some(pos) = search.find(prefix) {
            let after = &search[pos + prefix.len()..];
            // Check if next char is a digit (start of IP octets)
            if after
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
            {
                // Verify it looks like an IP: at least two dots in the host part
                let host_end = after
                    .find(|c: char| c == '/' || c == ':' || c == ' ' || c == '\n')
                    .unwrap_or(after.len());
                let host = &after[..host_end];
                if host.chars().filter(|&c| c == '.').count() >= 1
                    && host
                        .split('.')
                        .all(|part| part.is_empty() || part.chars().all(|c| c.is_ascii_digit()))
                {
                    return true;
                }
                // Even without all-digit parts, if host starts with digit and has a dot, flag it
                if host.contains('.')
                    && host
                        .chars()
                        .next()
                        .map(|c| c.is_ascii_digit())
                        .unwrap_or(false)
                {
                    return true;
                }
            }
            search = &search[pos + prefix.len()..];
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
    let list_sym = reader.symbols().symbol_address("grpWinStaList");
    let Some(list_sym) = list_sym else {
        return Ok(Vec::new());
    };

    let first_ws: u64 = match reader.read_bytes(list_sym, 8) {
        Ok(b) => u64::from_le_bytes(b[..8].try_into().unwrap()),
        Err(_) => return Ok(Vec::new()),
    };
    if first_ws == 0 {
        return Ok(Vec::new());
    }

    // Field offsets for _WINSTATION_OBJECT
    let ws_next_off = reader
        .symbols()
        .field_offset("_WINSTATION_OBJECT", "rpwinstaNext")
        .unwrap_or(0x28) as u64;
    let ws_num_formats_off = reader
        .symbols()
        .field_offset("_WINSTATION_OBJECT", "cNumClipFormats")
        .unwrap_or(0x40) as u64;
    let ws_clip_base_off = reader
        .symbols()
        .field_offset("_WINSTATION_OBJECT", "pClipBase")
        .unwrap_or(0x48) as u64;
    let ws_owner_pid_off = reader
        .symbols()
        .field_offset("_WINSTATION_OBJECT", "dwClipOwnerPid")
        .unwrap_or(0x50) as u64;

    // Field offsets for _CLIP entry
    // _CLIP { fmt: u32, hData: u64, size: u64 }
    let clip_fmt_off = reader.symbols().field_offset("_CLIP", "fmt").unwrap_or(0) as u64;
    let clip_hdata_off = reader.symbols().field_offset("_CLIP", "hData").unwrap_or(8) as u64;
    let clip_size_off = reader.symbols().field_offset("_CLIP", "size").unwrap_or(16) as u64;
    let clip_entry_size = reader.symbols().struct_size("_CLIP").unwrap_or(24) as u64;

    let mut results = Vec::new();

    let mut ws_addr = first_ws;
    while ws_addr != 0 {
        let num_formats: u32 = reader
            .read_bytes(ws_addr + ws_num_formats_off, 4)
            .map(|b| u32::from_le_bytes(b[..4].try_into().unwrap()))
            .unwrap_or(0);

        if num_formats == 0 || num_formats as usize > MAX_CLIP_ENTRIES {
            ws_addr = reader
                .read_bytes(ws_addr + ws_next_off, 8)
                .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap()))
                .unwrap_or(0);
            continue;
        }

        let clip_base: u64 = reader
            .read_bytes(ws_addr + ws_clip_base_off, 8)
            .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap()))
            .unwrap_or(0);

        if clip_base == 0 {
            ws_addr = reader
                .read_bytes(ws_addr + ws_next_off, 8)
                .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap()))
                .unwrap_or(0);
            continue;
        }

        let owner_pid: u32 = reader
            .read_bytes(ws_addr + ws_owner_pid_off, 4)
            .map(|b| u32::from_le_bytes(b[..4].try_into().unwrap()))
            .unwrap_or(0);

        for i in 0..num_formats as u64 {
            let entry_addr = clip_base + i * clip_entry_size;

            let fmt: u32 = reader
                .read_bytes(entry_addr + clip_fmt_off, 4)
                .map(|b| u32::from_le_bytes(b[..4].try_into().unwrap()))
                .unwrap_or(0);

            let hdata: u64 = reader
                .read_bytes(entry_addr + clip_hdata_off, 8)
                .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap()))
                .unwrap_or(0);

            let stored_size: u64 = reader
                .read_bytes(entry_addr + clip_size_off, 8)
                .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap()))
                .unwrap_or(0);

            let (data_size, preview) = match fmt {
                1 | 7 => read_ansi_preview(reader, hdata), // CF_TEXT, CF_OEMTEXT
                13 => read_unicode_preview(reader, hdata), // CF_UNICODETEXT
                _ => (stored_size as usize, String::new()),
            };

            let is_suspicious = classify_clipboard(&preview);
            results.push(ClipboardEntry {
                format: fmt,
                format_name: format_name(fmt).to_string(),
                data_size,
                preview,
                owner_pid,
                is_suspicious,
            });
        }

        ws_addr = reader
            .read_bytes(ws_addr + ws_next_off, 8)
            .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap()))
            .unwrap_or(0);
    }

    Ok(results)
}

/// Read an ANSI (single-byte) string from a memory address for preview.
fn read_ansi_preview<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    addr: u64,
) -> (usize, String) {
    if addr == 0 {
        return (0, String::new());
    }
    // Read up to 4096 bytes and find null terminator
    let chunk = match reader.read_bytes(addr, 4096) {
        Ok(b) => b,
        Err(_) => return (0, String::new()),
    };
    let null_pos = chunk.iter().position(|&b| b == 0).unwrap_or(chunk.len());
    let text = String::from_utf8_lossy(&chunk[..null_pos]).to_string();
    let size = null_pos + 1; // include null
    let preview = if text.len() > 256 {
        text[..256].to_string()
    } else {
        text
    };
    (size, preview)
}

/// Read a UTF-16LE string from a memory address for preview.
fn read_unicode_preview<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    addr: u64,
) -> (usize, String) {
    if addr == 0 {
        return (0, String::new());
    }
    // Read up to 4096 bytes (2048 UTF-16 code units) and find null terminator
    let chunk = match reader.read_bytes(addr, 4096) {
        Ok(b) => b,
        Err(_) => return (0, String::new()),
    };
    let units: Vec<u16> = chunk
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let null_pos = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    let text = String::from_utf16_lossy(&units[..null_pos]).to_string();
    let size = (null_pos + 1) * 2; // bytes including null
    let preview = if text.len() > 256 {
        text[..256].to_string()
    } else {
        text
    };
    (size, preview)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    use memf_core::test_builders::flags;
    use memf_core::test_builders::SyntheticPhysMem;

    // ── classify_clipboard tests ──────────────────────────────────────

    /// Contains "password" (case-insensitive) → suspicious.
    #[test]
    fn classify_clipboard_password_suspicious() {
        assert!(classify_clipboard("my password is abc123"));
        assert!(classify_clipboard("PASSWORD: secret"));
    }

    /// Contains PowerShell encoded command → suspicious.
    #[test]
    fn classify_clipboard_powershell_encoded_suspicious() {
        assert!(classify_clipboard("powershell -encodedcommand AAABBBCCC"));
        assert!(classify_clipboard("powershell -enc AAABBB"));
    }

    /// Normal text → benign.
    #[test]
    fn classify_clipboard_normal_text_benign() {
        assert!(!classify_clipboard("Hello, World!"));
        assert!(!classify_clipboard("https://example.com/page"));
    }

    /// Long base64-like string (>100 chars, no spaces) → suspicious.
    #[test]
    fn classify_clipboard_long_base64_suspicious() {
        let b64 = "A".repeat(101);
        assert!(classify_clipboard(&b64));
    }

    /// Empty → not suspicious.
    #[test]
    fn classify_clipboard_empty_benign() {
        assert!(!classify_clipboard(""));
    }

    /// URL with raw IP address → suspicious.
    #[test]
    fn classify_clipboard_url_with_ip_suspicious() {
        assert!(classify_clipboard("http://192.168.1.1/payload"));
        assert!(classify_clipboard("https://10.0.0.1/c2"));
    }

    /// URL with hostname (not raw IP) → benign.
    #[test]
    fn classify_clipboard_url_with_hostname_benign() {
        assert!(!classify_clipboard("https://example.com/page"));
    }

    /// Exactly 100 chars, no spaces — not long enough to be suspicious.
    #[test]
    fn classify_clipboard_exactly_100_chars_no_spaces_benign() {
        let s = "A".repeat(100);
        assert!(!classify_clipboard(&s));
    }

    /// 101 chars with a space — not suspicious (space breaks the no-space rule).
    #[test]
    fn classify_clipboard_101_chars_with_space_benign() {
        let s = format!("{} {}", "A".repeat(50), "A".repeat(50));
        assert!(!classify_clipboard(&s)); // 50+50+1=101 chars total but space splits tokens
    }

    /// passwd variant triggers suspicious flag.
    #[test]
    fn classify_clipboard_passwd_variant_suspicious() {
        assert!(classify_clipboard("root:passwd123"));
    }

    /// -encodedcommand (without trailing space) does not trigger false positive.
    #[test]
    fn classify_clipboard_encodedcommand_no_trailing_space_benign() {
        // "-encodedcommand" without trailing space should NOT trigger
        assert!(!classify_clipboard("-encodedcommandXYZ"));
    }

    /// https URL with IP but no slash or colon after IP → still suspicious.
    #[test]
    fn classify_clipboard_https_ip_no_path_suspicious() {
        assert!(classify_clipboard("https://1.2.3.4"));
    }

    // ── ClipboardEntry serialization ──────────────────────────────────

    #[test]
    fn clipboard_entry_serializes() {
        let entry = ClipboardEntry {
            format: 1,
            format_name: "CF_TEXT".to_string(),
            data_size: 42,
            preview: "hello".to_string(),
            owner_pid: 1234,
            is_suspicious: false,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("CF_TEXT"));
        assert!(json.contains("hello"));
    }

    #[test]
    fn clipboard_entry_suspicious_serializes() {
        let entry = ClipboardEntry {
            format: 13,
            format_name: "CF_UNICODETEXT".to_string(),
            data_size: 200,
            preview: "password: abc".to_string(),
            owner_pid: 5678,
            is_suspicious: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"is_suspicious\":true"));
    }

    // ── contains_ip_url edge cases ────────────────────────────────────

    #[test]
    fn contains_ip_url_with_port_only_suspicious() {
        assert!(contains_ip_url("http://10.0.0.1:8080/"));
    }

    #[test]
    fn contains_ip_url_hostname_not_ip() {
        assert!(!contains_ip_url("http://example.com/path"));
    }

    #[test]
    fn contains_ip_url_ip_without_dot_not_recognized() {
        // No dot → not an IP URL
        assert!(!contains_ip_url("http://localhost/path"));
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
        assert_eq!(format_name(13), "CF_UNICODETEXT");
        assert_eq!(format_name(15), "CF_HDROP");
        assert_eq!(format_name(999), "CF_UNKNOWN");
    }

    // ── read_ansi_preview and read_unicode_preview coverage ──────────

    fn make_clip_reader_with_page(
        vaddr: u64,
        paddr: u64,
        page: &[u8],
    ) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// read_ansi_preview from a mapped page returns text correctly.
    #[test]
    fn read_ansi_preview_mapped_text() {
        const VADDR: u64 = 0xFFFF_8000_0060_0000;
        const PADDR: u64 = 0x0060_0000;
        let mut page = vec![0u8; 4096];
        let text = b"hello world";
        page[..text.len()].copy_from_slice(text);
        // null terminator at text.len() (already 0)
        let reader = make_clip_reader_with_page(VADDR, PADDR, &page);
        let (size, preview) = read_ansi_preview(&reader, VADDR);
        assert_eq!(preview, "hello world");
        assert_eq!(size, text.len() + 1);
    }

    /// read_ansi_preview with addr=0 returns empty.
    #[test]
    fn read_ansi_preview_zero_addr_empty() {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let (size, preview) = read_ansi_preview(&reader, 0);
        assert_eq!(size, 0);
        assert_eq!(preview, "");
    }

    /// read_ansi_preview from unmapped address returns empty.
    #[test]
    fn read_ansi_preview_unmapped_addr_empty() {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let (size, preview) = read_ansi_preview(&reader, 0xFFFF_8000_1234_5678);
        assert_eq!(size, 0);
        assert_eq!(preview, "");
    }

    /// read_unicode_preview with addr=0 returns empty.
    #[test]
    fn read_unicode_preview_zero_addr_empty() {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let (size, preview) = read_unicode_preview(&reader, 0);
        assert_eq!(size, 0);
        assert_eq!(preview, "");
    }

    /// read_unicode_preview from unmapped address returns empty.
    #[test]
    fn read_unicode_preview_unmapped_empty() {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let (size, preview) = read_unicode_preview(&reader, 0xDEAD_BEEF_1234_5678);
        assert_eq!(size, 0);
        assert_eq!(preview, "");
    }

    /// read_unicode_preview decodes a UTF-16LE string from mapped memory.
    #[test]
    fn read_unicode_preview_mapped_text() {
        const VADDR: u64 = 0xFFFF_8000_0062_0000;
        const PADDR: u64 = 0x0062_0000;
        let text = "Hi";
        let utf16: Vec<u8> = text.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let mut page = vec![0u8; 4096];
        page[..utf16.len()].copy_from_slice(&utf16);
        // null terminator at utf16.len() (2 bytes of 0) already there
        let reader = make_clip_reader_with_page(VADDR, PADDR, &page);
        let (size, preview) = read_unicode_preview(&reader, VADDR);
        assert_eq!(preview, "Hi");
        assert_eq!(size, (text.len() + 1) * 2);
    }

    /// MAX_CLIP_ENTRIES constant is reasonable.
    #[test]
    fn max_clip_entries_constant_sensible() {
        assert!(MAX_CLIP_ENTRIES >= 64);
        assert!(MAX_CLIP_ENTRIES <= 4096);
    }

    // ── walk_clipboard tests — walker body coverage ──────────────────

    fn make_empty_clip_reader() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 64)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// walk_clipboard: grpWinStaList symbol present but memory read fails → empty.
    #[test]
    fn walk_clipboard_symbol_but_unreadable_memory() {
        let isf = IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 64)
            .add_symbol("grpWinStaList", 0xFFFF_8000_9999_0000)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_clipboard(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// walk_clipboard: grpWinStaList points to a 0 winsta ptr → empty.
    #[test]
    fn walk_clipboard_zero_winsta_ptr_empty() {
        const SYM_VADDR: u64 = 0xFFFF_8000_0058_0000;
        const SYM_PADDR: u64 = 0x0058_0000;
        let isf = IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 64)
            .add_symbol("grpWinStaList", SYM_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let sym_page = vec![0u8; 4096]; // first_ws = 0
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_clipboard(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// walk_clipboard: grpWinStaList → valid winsta but cNumClipFormats=0 → empty.
    #[test]
    fn walk_clipboard_zero_num_formats_empty() {
        const SYM_VADDR: u64 = 0xFFFF_8000_0057_0000;
        const SYM_PADDR: u64 = 0x0057_0000;
        const WS_VADDR: u64 = 0xFFFF_8000_0056_0000;
        const WS_PADDR: u64 = 0x0056_0000;
        let isf = IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 64)
            .add_field("_WINSTATION_OBJECT", "rpwinstaNext", 0x28, "pointer")
            .add_field(
                "_WINSTATION_OBJECT",
                "cNumClipFormats",
                0x40,
                "unsigned long",
            )
            .add_field("_WINSTATION_OBJECT", "pClipBase", 0x48, "pointer")
            .add_field(
                "_WINSTATION_OBJECT",
                "dwClipOwnerPid",
                0x50,
                "unsigned long",
            )
            .add_symbol("grpWinStaList", SYM_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&WS_VADDR.to_le_bytes());
        let ws_page = vec![0u8; 4096]; // cNumClipFormats = 0 at 0x40
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .map_4k(WS_VADDR, WS_PADDR, flags::WRITABLE)
            .write_phys(WS_PADDR, &ws_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_clipboard(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// walk_clipboard: num_formats > MAX_CLIP_ENTRIES → empty (safety guard).
    #[test]
    fn walk_clipboard_too_many_formats_empty() {
        const SYM_VADDR: u64 = 0xFFFF_8000_0055_0000;
        const SYM_PADDR: u64 = 0x0055_0000;
        const WS_VADDR: u64 = 0xFFFF_8000_0054_0000;
        const WS_PADDR: u64 = 0x0054_0000;
        let isf = IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 64)
            .add_field("_WINSTATION_OBJECT", "rpwinstaNext", 0x28, "pointer")
            .add_field(
                "_WINSTATION_OBJECT",
                "cNumClipFormats",
                0x40,
                "unsigned long",
            )
            .add_field("_WINSTATION_OBJECT", "pClipBase", 0x48, "pointer")
            .add_field(
                "_WINSTATION_OBJECT",
                "dwClipOwnerPid",
                0x50,
                "unsigned long",
            )
            .add_symbol("grpWinStaList", SYM_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&WS_VADDR.to_le_bytes());
        let mut ws_page = vec![0u8; 4096];
        // cNumClipFormats = MAX_CLIP_ENTRIES + 1 (triggers safety guard)
        let too_many = (MAX_CLIP_ENTRIES as u32) + 1;
        ws_page[0x40..0x44].copy_from_slice(&too_many.to_le_bytes());
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .map_4k(WS_VADDR, WS_PADDR, flags::WRITABLE)
            .write_phys(WS_PADDR, &ws_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_clipboard(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// walk_clipboard: pClipBase pointer is zero → empty.
    #[test]
    fn walk_clipboard_zero_clip_base_empty() {
        const SYM_VADDR: u64 = 0xFFFF_8000_0053_0000;
        const SYM_PADDR: u64 = 0x0053_0000;
        const WS_VADDR: u64 = 0xFFFF_8000_0052_0000;
        const WS_PADDR: u64 = 0x0052_0000;
        let isf = IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 64)
            .add_field("_WINSTATION_OBJECT", "rpwinstaNext", 0x28, "pointer")
            .add_field(
                "_WINSTATION_OBJECT",
                "cNumClipFormats",
                0x40,
                "unsigned long",
            )
            .add_field("_WINSTATION_OBJECT", "pClipBase", 0x48, "pointer")
            .add_field(
                "_WINSTATION_OBJECT",
                "dwClipOwnerPid",
                0x50,
                "unsigned long",
            )
            .add_symbol("grpWinStaList", SYM_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&WS_VADDR.to_le_bytes());
        let mut ws_page = vec![0u8; 4096];
        ws_page[0x40..0x44].copy_from_slice(&1u32.to_le_bytes()); // 1 format
        ws_page[0x48..0x50].copy_from_slice(&0u64.to_le_bytes()); // pClipBase = 0
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .map_4k(WS_VADDR, WS_PADDR, flags::WRITABLE)
            .write_phys(WS_PADDR, &ws_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_clipboard(&reader).unwrap();
        assert!(result.is_empty());
    }

    fn make_isf_with_clip_structs(sym_vaddr: u64) -> serde_json::Value {
        IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 128)
            .add_field("_WINSTATION_OBJECT", "rpwinstaNext", 0x28, "pointer")
            .add_field(
                "_WINSTATION_OBJECT",
                "cNumClipFormats",
                0x40,
                "unsigned long",
            )
            .add_field("_WINSTATION_OBJECT", "pClipBase", 0x48, "pointer")
            .add_field(
                "_WINSTATION_OBJECT",
                "dwClipOwnerPid",
                0x50,
                "unsigned long",
            )
            .add_struct("_CLIP", 24)
            .add_field("_CLIP", "fmt", 0, "unsigned long")
            .add_field("_CLIP", "hData", 8, "pointer")
            .add_field("_CLIP", "size", 16, "unsigned long")
            .add_symbol("grpWinStaList", sym_vaddr)
            .build_json()
    }

    /// walk_clipboard: full path with one CF_TEXT entry (suspicious password content).
    #[test]
    fn walk_clipboard_cf_text_entry_suspicious() {
        const SYM_VADDR: u64 = 0xFFFF_8000_0050_0000;
        const SYM_PADDR: u64 = 0x0050_0000;
        const WS_VADDR: u64 = 0xFFFF_8000_004F_0000;
        const WS_PADDR: u64 = 0x004F_0000;
        const CLIP_VADDR: u64 = 0xFFFF_8000_004E_0000;
        const CLIP_PADDR: u64 = 0x004E_0000;
        const DATA_VADDR: u64 = 0xFFFF_8000_004D_0000;
        const DATA_PADDR: u64 = 0x004D_0000;

        let isf = make_isf_with_clip_structs(SYM_VADDR);
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&WS_VADDR.to_le_bytes());

        let mut ws_page = vec![0u8; 4096];
        ws_page[0x40..0x44].copy_from_slice(&1u32.to_le_bytes()); // 1 format
        ws_page[0x48..0x50].copy_from_slice(&CLIP_VADDR.to_le_bytes()); // pClipBase
        ws_page[0x50..0x54].copy_from_slice(&1234u32.to_le_bytes()); // owner_pid

        // _CLIP entry: fmt=1 (CF_TEXT), hData=DATA_VADDR, size=20
        let mut clip_page = vec![0u8; 4096];
        clip_page[0..4].copy_from_slice(&1u32.to_le_bytes()); // fmt = CF_TEXT
        clip_page[8..16].copy_from_slice(&DATA_VADDR.to_le_bytes()); // hData
        clip_page[16..24].copy_from_slice(&20u64.to_le_bytes()); // size

        // Data: "password: abc\0"
        let mut data_page = vec![0u8; 4096];
        let text = b"password: abc";
        data_page[..text.len()].copy_from_slice(text);

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .map_4k(WS_VADDR, WS_PADDR, flags::WRITABLE)
            .write_phys(WS_PADDR, &ws_page)
            .map_4k(CLIP_VADDR, CLIP_PADDR, flags::WRITABLE)
            .write_phys(CLIP_PADDR, &clip_page)
            .map_4k(DATA_VADDR, DATA_PADDR, flags::WRITABLE)
            .write_phys(DATA_PADDR, &data_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_clipboard(&reader).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].format, 1);
        assert_eq!(result[0].format_name, "CF_TEXT");
        assert!(result[0].preview.contains("password"));
        assert!(result[0].is_suspicious);
        assert_eq!(result[0].owner_pid, 1234);
    }

    /// walk_clipboard: CF_UNICODETEXT entry with benign content.
    #[test]
    fn walk_clipboard_cf_unicodetext_entry_benign() {
        const SYM_VADDR: u64 = 0xFFFF_8000_004C_0000;
        const SYM_PADDR: u64 = 0x004C_0000;
        const WS_VADDR: u64 = 0xFFFF_8000_004B_0000;
        const WS_PADDR: u64 = 0x004B_0000;
        const CLIP_VADDR: u64 = 0xFFFF_8000_004A_0000;
        const CLIP_PADDR: u64 = 0x004A_0000;
        const DATA_VADDR: u64 = 0xFFFF_8000_0049_0000;
        const DATA_PADDR: u64 = 0x0049_0000;

        let isf = make_isf_with_clip_structs(SYM_VADDR);
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&WS_VADDR.to_le_bytes());

        let mut ws_page = vec![0u8; 4096];
        ws_page[0x40..0x44].copy_from_slice(&1u32.to_le_bytes());
        ws_page[0x48..0x50].copy_from_slice(&CLIP_VADDR.to_le_bytes());

        let mut clip_page = vec![0u8; 4096];
        clip_page[0..4].copy_from_slice(&13u32.to_le_bytes()); // CF_UNICODETEXT
        clip_page[8..16].copy_from_slice(&DATA_VADDR.to_le_bytes());

        // "Hello" as UTF-16LE
        let text = "Hello";
        let utf16: Vec<u8> = text.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let mut data_page = vec![0u8; 4096];
        data_page[..utf16.len()].copy_from_slice(&utf16);

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .map_4k(WS_VADDR, WS_PADDR, flags::WRITABLE)
            .write_phys(WS_PADDR, &ws_page)
            .map_4k(CLIP_VADDR, CLIP_PADDR, flags::WRITABLE)
            .write_phys(CLIP_PADDR, &clip_page)
            .map_4k(DATA_VADDR, DATA_PADDR, flags::WRITABLE)
            .write_phys(DATA_PADDR, &data_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_clipboard(&reader).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].format, 13);
        assert_eq!(result[0].preview, "Hello");
        assert!(!result[0].is_suspicious);
    }

    /// walk_clipboard: unknown (non-text) format produces an entry with empty preview.
    #[test]
    fn walk_clipboard_unknown_format_no_preview() {
        const SYM_VADDR: u64 = 0xFFFF_8000_0048_0000;
        const SYM_PADDR: u64 = 0x0048_0000;
        const WS_VADDR: u64 = 0xFFFF_8000_0047_0000;
        const WS_PADDR: u64 = 0x0047_0000;
        const CLIP_VADDR: u64 = 0xFFFF_8000_0046_0000;
        const CLIP_PADDR: u64 = 0x0046_0000;

        let isf = make_isf_with_clip_structs(SYM_VADDR);
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&WS_VADDR.to_le_bytes());

        let mut ws_page = vec![0u8; 4096];
        ws_page[0x40..0x44].copy_from_slice(&1u32.to_le_bytes());
        ws_page[0x48..0x50].copy_from_slice(&CLIP_VADDR.to_le_bytes());

        let mut clip_page = vec![0u8; 4096];
        clip_page[0..4].copy_from_slice(&2u32.to_le_bytes()); // CF_BITMAP
        clip_page[8..16].copy_from_slice(&0u64.to_le_bytes()); // hData = 0
        clip_page[16..24].copy_from_slice(&1024u64.to_le_bytes()); // size = 1024

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .map_4k(WS_VADDR, WS_PADDR, flags::WRITABLE)
            .write_phys(WS_PADDR, &ws_page)
            .map_4k(CLIP_VADDR, CLIP_PADDR, flags::WRITABLE)
            .write_phys(CLIP_PADDR, &clip_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_clipboard(&reader).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].format, 2);
        assert_eq!(result[0].format_name, "CF_BITMAP");
        assert_eq!(result[0].preview, "");
        assert_eq!(result[0].data_size, 1024);
    }

    // ── walk_clipboard tests ──────────────────────────────────────────

    /// No grpWinStaList symbol → empty Vec.
    #[test]
    fn walk_clipboard_no_symbol() {
        let reader = make_empty_clip_reader();
        let result = walk_clipboard(&reader).unwrap();
        assert!(result.is_empty());
    }
}
