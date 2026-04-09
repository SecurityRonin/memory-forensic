//! Linux kernel dmesg ring buffer extraction.
//!
//! Extracts the kernel log ring buffer (`log_buf`) from memory. The kernel
//! stores dmesg messages in a circular buffer pointed to by the `log_buf`
//! symbol with length `log_buf_len`.
//!
//! Each log record (`struct printk_log` / `log`) has:
//! - `len` (u16) — total record length including text+dict
//! - `text_len` (u16) — length of the text message
//! - `dict_len` (u16) — length of the dict (key=value facility info)
//! - `facility` (u8) — syslog facility
//! - `level` (u8) — log level (0=EMERG..7=DEBUG)
//! - `ts_nsec` (u64) — timestamp in nanoseconds since boot
//! - Text immediately follows the 16-byte header

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use serde::Serialize;

/// A single parsed dmesg log entry from the kernel ring buffer.
#[derive(Debug, Clone, Serialize)]
pub struct DmesgEntry {
    /// Timestamp in nanoseconds since boot.
    pub timestamp_ns: u64,
    /// Log level (0=EMERG, 1=ALERT, 2=CRIT, 3=ERR, 4=WARNING, 5=NOTICE, 6=INFO, 7=DEBUG).
    pub level: u8,
    /// Syslog facility code.
    pub facility: u8,
    /// The log message text.
    pub message: String,
}

/// Extract dmesg entries from the kernel ring buffer.
///
/// Looks up the `log_buf` symbol, dereferences the pointer to obtain the
/// buffer address, reads `log_buf_len` to determine buffer size, then
/// iterates `printk_log` records until `len == 0` or the buffer is exhausted.
///
/// Returns an empty `Vec` if the `log_buf` symbol is not found (e.g., wrong
/// profile or non-Linux image).
///
/// # Safety limit
/// Caps extraction at 65,536 entries to prevent runaway iteration on corrupt data.
pub fn extract_dmesg<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<DmesgEntry>> {
    todo!("implement dmesg extraction")
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Helper: build an ObjectReader from ISF and page table builders.
    fn make_reader(
        isf: &IsfBuilder,
        ptb: PageTableBuilder,
    ) -> ObjectReader<SyntheticPhysMem> {
        let json = isf.build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// No `log_buf` symbol present -> returns empty Vec (not an error).
    #[test]
    fn extract_dmesg_no_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("printk_log", 16);
        let ptb = PageTableBuilder::new();
        let reader = make_reader(&isf, ptb);

        let entries = extract_dmesg(&reader).unwrap();
        assert!(entries.is_empty(), "expected empty Vec when log_buf symbol is missing");
    }

    /// `log_buf` symbol exists and points to a zero-filled buffer -> empty Vec.
    #[test]
    fn extract_dmesg_empty_buffer() {
        // Layout:
        //   log_buf symbol (vaddr) -> pointer to buffer vaddr
        //   log_buf_len symbol (vaddr) -> u32 buffer length
        //   buffer: all zeros (no records)
        let log_buf_sym_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let log_buf_len_sym_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let buf_vaddr: u64 = 0xFFFF_8000_0020_0000;

        let log_buf_sym_paddr: u64 = 0x0010_0000; // 1 MB
        let log_buf_len_sym_paddr: u64 = 0x0010_1000;
        let buf_paddr: u64 = 0x0020_0000; // 2 MB

        let buf_len: u32 = 4096;

        let isf = IsfBuilder::new()
            .add_symbol("log_buf", log_buf_sym_vaddr)
            .add_symbol("log_buf_len", log_buf_len_sym_vaddr);

        let ptb = PageTableBuilder::new()
            // Map the symbol locations
            .map_4k(log_buf_sym_vaddr, log_buf_sym_paddr, flags::WRITABLE)
            .map_4k(log_buf_len_sym_vaddr, log_buf_len_sym_paddr, flags::WRITABLE)
            // Map the buffer itself (one 4k page, zero-filled by default)
            .map_4k(buf_vaddr, buf_paddr, flags::WRITABLE)
            // Write the pointer value at log_buf symbol location
            .write_phys_u64(log_buf_sym_paddr, buf_vaddr)
            // Write the buffer length at log_buf_len symbol location
            .write_phys(log_buf_len_sym_paddr, &buf_len.to_le_bytes());

        let reader = make_reader(&isf, ptb);
        let entries = extract_dmesg(&reader).unwrap();
        assert!(entries.is_empty(), "expected empty Vec for zero-filled buffer");
    }

    /// Single valid printk_log record in the buffer -> one DmesgEntry.
    #[test]
    fn extract_dmesg_single_entry() {
        // printk_log header layout (16 bytes):
        //   offset 0: ts_nsec  (u64) — timestamp nanoseconds
        //   offset 8: len      (u16) — total record length
        //   offset 10: text_len (u16)
        //   offset 12: dict_len (u16)
        //   offset 14: facility (u8)
        //   offset 15: level    (u8)
        //   offset 16: text data (text_len bytes)
        //   (padding to align to len)
        let log_buf_sym_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let log_buf_len_sym_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let buf_vaddr: u64 = 0xFFFF_8000_0020_0000;

        let log_buf_sym_paddr: u64 = 0x0010_0000;
        let log_buf_len_sym_paddr: u64 = 0x0010_1000;
        let buf_paddr: u64 = 0x0020_0000;

        let message = b"Hello from kernel";
        let text_len = message.len() as u16; // 17
        let dict_len: u16 = 0;
        // Total record length: header(16) + text(17) + dict(0) = 33, aligned to 4 -> 36
        let record_len: u16 = ((16 + text_len + dict_len + 3) / 4 * 4) as u16;
        let ts_nsec: u64 = 1_000_000_000; // 1 second
        let facility: u8 = 0; // kern
        let level: u8 = 6; // info

        let buf_len: u32 = 4096;

        let isf = IsfBuilder::new()
            .add_symbol("log_buf", log_buf_sym_vaddr)
            .add_symbol("log_buf_len", log_buf_len_sym_vaddr);

        // Build the printk_log record in a local buffer
        let mut record = vec![0u8; record_len as usize];
        record[0..8].copy_from_slice(&ts_nsec.to_le_bytes());
        record[8..10].copy_from_slice(&record_len.to_le_bytes());
        record[10..12].copy_from_slice(&text_len.to_le_bytes());
        record[12..14].copy_from_slice(&dict_len.to_le_bytes());
        record[14] = facility;
        record[15] = level;
        record[16..16 + message.len()].copy_from_slice(message);

        let ptb = PageTableBuilder::new()
            .map_4k(log_buf_sym_vaddr, log_buf_sym_paddr, flags::WRITABLE)
            .map_4k(log_buf_len_sym_vaddr, log_buf_len_sym_paddr, flags::WRITABLE)
            .map_4k(buf_vaddr, buf_paddr, flags::WRITABLE)
            // log_buf pointer
            .write_phys_u64(log_buf_sym_paddr, buf_vaddr)
            // log_buf_len
            .write_phys(log_buf_len_sym_paddr, &buf_len.to_le_bytes())
            // The actual record data
            .write_phys(buf_paddr, &record);

        let reader = make_reader(&isf, ptb);
        let entries = extract_dmesg(&reader).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].timestamp_ns, 1_000_000_000);
        assert_eq!(entries[0].level, 6);
        assert_eq!(entries[0].facility, 0);
        assert_eq!(entries[0].message, "Hello from kernel");
    }
}
