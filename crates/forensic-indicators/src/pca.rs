/// Program Compatibility Assistant (PCA) forensic artifact support.
///
/// The PCA records Explorer-initiated application launches on Windows 11 22H2+.
/// Files are UTF-16 LE encoded, pipe-delimited: `<exe_path>|<timestamp>`.
///
/// **Critical limitation**: only Explorer shell launches are captured.
/// CMD, PowerShell, WMI, PsExec, scheduled tasks, and services are NOT recorded.
/// Absence of a record does NOT imply non-execution.
///
/// Source: research/registry-forensic-artifacts-complete-catalog.md §10.0
///
/// Reference: <https://andreafortuna.org/2026/03/19/windows11-pca-artifact/>

// ── Path constants ────────────────────────────────────────────────────────────

/// Directory containing PCA artifact files.
pub const PCA_DIR: &str = r"C:\Windows\appcompat\pca";

/// Primary PCA execution log — one `<exe_path>|<UTC timestamp>` record per line.
pub const PCA_APPLAUNCH_DIC_PATH: &str = r"C:\Windows\appcompat\pca\PcaAppLaunchDic.txt";

/// PCA general compatibility database (slot 0).
pub const PCA_GENERAL_DB0_PATH: &str = r"C:\Windows\appcompat\pca\PcaGeneralDb0.txt";

/// PCA general compatibility database (slot 1).
pub const PCA_GENERAL_DB1_PATH: &str = r"C:\Windows\appcompat\pca\PcaGeneralDb1.txt";

/// All known PCA file paths (for bulk scanning).
pub const PCA_ALL_PATHS: &[&str] = &[
    PCA_APPLAUNCH_DIC_PATH,
    PCA_GENERAL_DB0_PATH,
    PCA_GENERAL_DB1_PATH,
];

// ── Classification ────────────────────────────────────────────────────────────

/// Returns `true` if `path` (case-insensitive) matches a known PCA artifact file.
///
/// ```
/// use forensic_indicators::pca::is_pca_file;
/// assert!(is_pca_file(r"C:\Windows\appcompat\pca\PcaAppLaunchDic.txt"));
/// assert!(!is_pca_file(r"C:\Windows\System32\notepad.exe"));
/// ```
pub fn is_pca_file(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    PCA_ALL_PATHS
        .iter()
        .any(|p| lower == p.to_ascii_lowercase())
}

// ── Parsing ───────────────────────────────────────────────────────────────────

/// Parses a single pipe-delimited PCA line into `(exe_path, timestamp)`.
///
/// Returns `None` for empty lines or lines that contain no `|` separator.
///
/// ```
/// use forensic_indicators::pca::parse_pca_line;
/// let (path, ts) = parse_pca_line(r"C:\Windows\notepad.exe|2024-01-15 10:30:00").unwrap();
/// assert_eq!(path, r"C:\Windows\notepad.exe");
/// assert_eq!(ts, "2024-01-15 10:30:00");
/// ```
pub fn parse_pca_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let mut parts = line.splitn(2, '|');
    let exe = parts.next()?.to_string();
    let ts = parts.next().unwrap_or("").to_string();
    if exe.is_empty() {
        return None;
    }
    Some((exe, ts))
}

/// Decodes raw UTF-16 LE bytes from a PCA file and parses every non-empty line.
///
/// Returns a `Vec` of `(exe_path, timestamp)` pairs.  Lines that cannot be
/// parsed (no `|` separator, empty after trim) are silently skipped.
///
/// The optional BOM (`FF FE`) is stripped automatically.
pub fn decode_pca_utf16le(bytes: &[u8]) -> Vec<(String, String)> {
    if bytes.len() < 2 {
        return vec![];
    }

    // Strip BOM if present.
    let bytes = if bytes.starts_with(&[0xFF, 0xFE]) {
        &bytes[2..]
    } else {
        bytes
    };

    if bytes.len() % 2 != 0 {
        return vec![];
    }

    // Decode UTF-16 LE pairs.
    let utf16: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();

    let decoded = String::from_utf16_lossy(&utf16);

    decoded
        .lines()
        .filter_map(parse_pca_line)
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_pca_file ──────────────────────────────────────────────────────

    #[test]
    fn is_pca_file_applaunch_dic() {
        assert!(is_pca_file(r"C:\Windows\appcompat\pca\PcaAppLaunchDic.txt"));
    }

    #[test]
    fn is_pca_file_general_db0() {
        assert!(is_pca_file(r"C:\Windows\appcompat\pca\PcaGeneralDb0.txt"));
    }

    #[test]
    fn is_pca_file_general_db1() {
        assert!(is_pca_file(r"C:\Windows\appcompat\pca\PcaGeneralDb1.txt"));
    }

    #[test]
    fn is_pca_file_case_insensitive() {
        assert!(is_pca_file(
            r"c:\windows\appcompat\pca\pcaapplaunchdic.txt"
        ));
    }

    #[test]
    fn is_pca_file_rejects_unrelated() {
        assert!(!is_pca_file(r"C:\Windows\System32\notepad.exe"));
        assert!(!is_pca_file(""));
        assert!(!is_pca_file(r"C:\Windows\appcompat\pca\"));
    }

    // ── parse_pca_line ───────────────────────────────────────────────────

    #[test]
    fn parse_pca_line_valid() {
        let (path, ts) =
            parse_pca_line(r"C:\Windows\notepad.exe|2024-01-15 10:30:00").unwrap();
        assert_eq!(path, r"C:\Windows\notepad.exe");
        assert_eq!(ts, "2024-01-15 10:30:00");
    }

    #[test]
    fn parse_pca_line_no_timestamp() {
        let (path, ts) = parse_pca_line(r"C:\tool.exe|").unwrap();
        assert_eq!(path, r"C:\tool.exe");
        assert_eq!(ts, "");
    }

    #[test]
    fn parse_pca_line_no_pipe_returns_some_with_empty_ts() {
        // A line with no pipe still yields the whole string as exe_path.
        let (path, ts) = parse_pca_line(r"C:\removable\tool.exe").unwrap();
        assert_eq!(path, r"C:\removable\tool.exe");
        assert_eq!(ts, "");
    }

    #[test]
    fn parse_pca_line_empty_returns_none() {
        assert!(parse_pca_line("").is_none());
        assert!(parse_pca_line("   ").is_none());
    }

    #[test]
    fn parse_pca_line_trims_whitespace() {
        // trim() strips both leading and trailing whitespace from the full line
        // before splitting, so the timestamp carries no trailing spaces.
        let (path, ts) =
            parse_pca_line("  C:\\app.exe|2024-06-01 09:00:00  ").unwrap();
        assert_eq!(path, r"C:\app.exe");
        assert_eq!(ts, "2024-06-01 09:00:00");
    }

    #[test]
    fn parse_pca_line_path_with_pipe_uses_first_split() {
        // If the exe path somehow contained a pipe, only split on the first.
        let (path, ts) =
            parse_pca_line(r"C:\app.exe|2024-01-01 00:00:00|extra").unwrap();
        assert_eq!(path, r"C:\app.exe");
        assert_eq!(ts, "2024-01-01 00:00:00|extra");
    }

    // ── decode_pca_utf16le ───────────────────────────────────────────────

    fn encode_utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect()
    }

    #[test]
    fn decode_utf16le_single_entry() {
        let raw = encode_utf16le("C:\\Windows\\notepad.exe|2024-01-15 10:30:00\r\n");
        let entries = decode_pca_utf16le(&raw);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, r"C:\Windows\notepad.exe");
        assert_eq!(entries[0].1, "2024-01-15 10:30:00");
    }

    #[test]
    fn decode_utf16le_multiple_entries() {
        let content = "C:\\a.exe|2024-01-01 00:00:00\r\nC:\\b.exe|2024-01-02 00:00:00\r\n";
        let raw = encode_utf16le(content);
        let entries = decode_pca_utf16le(&raw);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, r"C:\a.exe");
        assert_eq!(entries[1].0, r"C:\b.exe");
    }

    #[test]
    fn decode_utf16le_strips_bom() {
        let mut raw = vec![0xFF_u8, 0xFE]; // BOM
        raw.extend(encode_utf16le("C:\\tool.exe|2024-06-01 08:00:00\n"));
        let entries = decode_pca_utf16le(&raw);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, r"C:\tool.exe");
    }

    #[test]
    fn decode_utf16le_skips_blank_lines() {
        let raw = encode_utf16le("C:\\a.exe|2024-01-01\r\n\r\nC:\\b.exe|2024-01-02\r\n");
        let entries = decode_pca_utf16le(&raw);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn decode_utf16le_empty_bytes_returns_empty() {
        assert!(decode_pca_utf16le(&[]).is_empty());
    }

    #[test]
    fn decode_utf16le_odd_byte_count_returns_empty() {
        // Odd length is malformed UTF-16LE.
        assert!(decode_pca_utf16le(&[0x41, 0x00, 0x42]).is_empty());
    }

    // ── Path constants ───────────────────────────────────────────────────

    #[test]
    fn pca_all_paths_contains_three_entries() {
        assert_eq!(PCA_ALL_PATHS.len(), 3);
    }

    #[test]
    fn pca_dir_is_prefix_of_all_paths() {
        let dir_lower = PCA_DIR.to_ascii_lowercase();
        for p in PCA_ALL_PATHS {
            assert!(
                p.to_ascii_lowercase().starts_with(&dir_lower),
                "{p} should be under {PCA_DIR}"
            );
        }
    }
}
