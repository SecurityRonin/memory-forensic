//! Kernel message ring buffer extraction.
//!
//! Reads the kernel log (printk) ring buffer from `__log_buf` and
//! `log_buf_len`.  Each record uses the kernel 3.x+ `printk_log` format.
//! Suspicious messages (rootkit indicators, kernel oops) are flagged.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Maximum number of kmsg records to extract (runaway protection).
const MAX_ENTRIES: usize = 8192;

/// A single kernel log record.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KmsgEntry {
    /// Sequence number.
    pub sequence: u64,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Log level (low 3 bits of `flags_level`).
    pub level: u8,
    /// Text content of the log record.
    pub text: String,
    /// True when the text contains known suspicious patterns.
    pub is_suspicious: bool,
}

/// Suspicious patterns in kernel log messages.
const SUSPICIOUS_PATTERNS: &[&str] = &[
    "rootkit",
    "hide",
    "call trace",
    "kernel bug",
    "general protection",
];

/// Classify whether a kernel log message is suspicious.
pub fn classify_kmsg(text: &str) -> bool {
    let lower = text.to_lowercase();
    SUSPICIOUS_PATTERNS.iter().any(|p| lower.contains(p))
}

/// Walk the kernel log ring buffer and return parsed entries.
///
/// Returns `Ok(Vec::new())` when `__log_buf` symbol is absent.
pub fn walk_kmsg<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>) -> Result<Vec<KmsgEntry>> {
    let Some(buf_addr) = reader.symbols().symbol_address("__log_buf") else {
        return Ok(Vec::new());
    };

    // Read log_buf_len (u32) from its symbol if present; default to 4096.
    let buf_len: usize = if let Some(len_addr) = reader.symbols().symbol_address("log_buf_len") {
        match reader.read_bytes(len_addr, 4) {
            Ok(b) if b.len() == 4 => {
                let v = u32::from_le_bytes(b.try_into().unwrap()) as usize;
                if v == 0 {
                    4096
                } else {
                    v.min(1024 * 1024)
                }
            }
            _ => 4096,
        }
    } else {
        4096
    };

    let data = match reader.read_bytes(buf_addr, buf_len) {
        Ok(d) => d,
        Err(_) => return Ok(Vec::new()),
    };

    let mut entries = Vec::new();
    let mut offset = 0usize;

    for _ in 0..MAX_ENTRIES {
        match parse_printk_record(&data, offset) {
            Some((entry, consumed)) => {
                entries.push(entry);
                offset += consumed;
            }
            None => break,
        }
        if offset >= data.len() {
            break;
        }
    }

    Ok(entries)
}

/// Parse raw `printk_log` record bytes into a `KmsgEntry`.
///
/// `printk_log` header layout (kernel 3.x+):
///   +0:  len (u16)       — total record length including header
///   +2:  text_len (u16)  — byte length of the text
///   +4:  dict_len (u16)  — byte length of the dict
///   +6:  facility (u8)
///   +7:  flags_level (u8) — log level in low 3 bits
///   +8:  ts_nsec (u64)
///   +16: seq (u64)
///
/// Text immediately follows the 24-byte header.
pub fn parse_printk_record(data: &[u8], offset: usize) -> Option<(KmsgEntry, usize)> {
    const HDR_LEN: usize = 24;
    if offset + HDR_LEN > data.len() {
        return None;
    }
    let hdr = &data[offset..];
    let len = u16::from_le_bytes([hdr[0], hdr[1]]) as usize;
    if len == 0 || offset + len > data.len() {
        return None;
    }
    let text_len = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;
    let flags_level = hdr[7];
    let level = flags_level & 0x07;
    let ts_nsec = u64::from_le_bytes(hdr[8..16].try_into().ok()?);
    let seq = u64::from_le_bytes(hdr[16..24].try_into().ok()?);

    let text_start = offset + HDR_LEN;
    let text_end = (text_start + text_len).min(offset + len);
    let text = String::from_utf8_lossy(&data[text_start..text_end])
        .trim_end_matches('\0')
        .to_string();

    let is_suspicious = classify_kmsg(&text);

    Some((
        KmsgEntry {
            sequence: seq,
            timestamp_ns: ts_nsec,
            level,
            text,
            is_suspicious,
        },
        len,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_no_symbol_reader() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn no_symbol_returns_empty() {
        let reader = make_no_symbol_reader();
        let result = walk_kmsg(&reader).unwrap();
        assert!(result.is_empty(), "no __log_buf symbol → empty vec");
    }

    #[test]
    fn classify_suspicious_rootkit_message() {
        assert!(
            classify_kmsg("rootkit detected in module list"),
            "message containing 'rootkit' should be suspicious"
        );
        assert!(
            classify_kmsg("Call Trace:"),
            "kernel oops call trace should be suspicious"
        );
    }

    #[test]
    fn classify_benign_message_not_flagged() {
        assert!(
            !classify_kmsg("usb 1-1: new full-speed USB device number 2"),
            "normal USB message should not be suspicious"
        );
        assert!(
            !classify_kmsg("EXT4-fs (sda1): mounted filesystem"),
            "normal mount message should not be suspicious"
        );
    }

    // RED test: parse_printk_record parses a synthetic record correctly.
    #[test]
    fn parse_printk_record_extracts_text() {
        let text = b"Linux version 5.15.0";
        let text_len = text.len() as u16;
        let total_len: u16 = 24 + text_len; // header + text
        let ts_nsec: u64 = 123_456_789;
        let seq: u64 = 42;

        let mut record = vec![0u8; total_len as usize];
        record[0..2].copy_from_slice(&total_len.to_le_bytes());
        record[2..4].copy_from_slice(&text_len.to_le_bytes());
        record[4..6].copy_from_slice(&0u16.to_le_bytes()); // dict_len = 0
        record[6] = 0; // facility
        record[7] = 6; // flags_level: level 6 (INFO)
        record[8..16].copy_from_slice(&ts_nsec.to_le_bytes());
        record[16..24].copy_from_slice(&seq.to_le_bytes());
        record[24..24 + text.len()].copy_from_slice(text);

        let (entry, consumed) = parse_printk_record(&record, 0).unwrap();
        assert_eq!(entry.sequence, seq);
        assert_eq!(entry.timestamp_ns, ts_nsec);
        assert_eq!(entry.level, 6);
        assert_eq!(entry.text, "Linux version 5.15.0");
        assert!(!entry.is_suspicious);
        assert_eq!(consumed, total_len as usize);
    }

    // RED test: walk_kmsg with symbol and mapped buffer returns entries.
    #[test]
    fn walk_kmsg_with_symbol_returns_entries() {
        use memf_core::test_builders::flags;

        // Build a minimal ring buffer with one record.
        let msg = b"rootkit module loaded";
        let text_len = msg.len() as u16;
        let total_len: u16 = 24 + text_len;
        let buf_len: u32 = 4096;

        let mut ring_buf = vec![0u8; buf_len as usize];
        ring_buf[0..2].copy_from_slice(&total_len.to_le_bytes());
        ring_buf[2..4].copy_from_slice(&text_len.to_le_bytes());
        ring_buf[4..6].copy_from_slice(&0u16.to_le_bytes());
        ring_buf[6] = 0;
        ring_buf[7] = 4; // KERN_WARNING
        ring_buf[8..16].copy_from_slice(&1_000_000u64.to_le_bytes());
        ring_buf[16..24].copy_from_slice(&1u64.to_le_bytes()); // seq = 1
        ring_buf[24..24 + msg.len()].copy_from_slice(msg);

        let buf_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let buf_paddr: u64 = 0x0082_0000;
        let len_vaddr: u64 = 0xFFFF_8000_0020_1000;
        let len_paddr: u64 = 0x0083_0000;

        let isf = IsfBuilder::new()
            .add_symbol("__log_buf", buf_vaddr)
            .add_symbol("log_buf_len", len_vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mut mem) = PageTableBuilder::new()
            .map_4k(buf_vaddr, buf_paddr, flags::PRESENT | flags::WRITABLE)
            .map_4k(len_vaddr, len_paddr, flags::PRESENT | flags::WRITABLE)
            .build();
        mem.write_bytes(buf_paddr, &ring_buf);
        mem.write_bytes(len_paddr, &buf_len.to_le_bytes());

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let entries = walk_kmsg(&reader).unwrap();
        assert!(!entries.is_empty(), "should return at least one kmsg entry");
        assert!(
            entries[0].is_suspicious,
            "rootkit message should be flagged"
        );
    }
}
