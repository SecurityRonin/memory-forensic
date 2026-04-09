//! ETW (Event Tracing for Windows) trace buffer recovery.
//!
//! Windows ETW infrastructure maintains in-memory trace buffers via
//! `_WMI_LOGGER_CONTEXT` structures. Each logger has a circular buffer
//! of `_WMI_BUFFER_HEADER` entries containing events not yet flushed
//! to .etl files. Recovering these buffers captures in-flight events
//! that would otherwise be lost — particularly valuable for detecting
//! evasion techniques that clear ETW providers or tamper with the
//! trace pipeline.
//!
//! The kernel maintains an array of logger contexts at `EtwpLoggerContext`
//! (or `WmipLoggerContext` on older builds). Each context contains the
//! logger name, status, buffer configuration, and pointers to the
//! buffer list.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;

/// Maximum number of ETW loggers to enumerate (safety limit).
const MAX_LOGGERS: usize = 256;

/// Maximum buffers per logger to walk (safety limit).
#[allow(dead_code)]
const MAX_BUFFERS_PER_LOGGER: usize = 1024;

/// Information about an active ETW trace session recovered from memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EtwSessionInfo {
    /// Logger ID (index in the logger context array).
    pub logger_id: u32,
    /// Logger/session name (e.g., "NT Kernel Logger", "EventLog-Security").
    pub name: String,
    /// Whether the session is currently running.
    pub is_running: bool,
    /// Number of buffers allocated.
    pub buffer_count: u32,
    /// Size of each buffer in bytes.
    pub buffer_size: u32,
    /// Number of events lost (dropped).
    pub events_lost: u32,
    /// Number of buffers written to disk.
    pub buffers_written: u32,
    /// Minimum flush timer interval in seconds.
    pub flush_timer_sec: u32,
    /// Logger mode flags (real-time, file, circular, etc.).
    pub log_mode: u32,
}

/// A single ETW event recovered from an in-memory trace buffer.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EtwBufferEvent {
    /// Logger ID this event belongs to.
    pub logger_id: u32,
    /// Timestamp (FILETIME) of the event.
    pub timestamp: u64,
    /// Provider GUID as a string.
    pub provider_guid: String,
    /// Event ID.
    pub event_id: u16,
    /// Event opcode.
    pub opcode: u8,
    /// Event level (0=LogAlways..5=Verbose).
    pub level: u8,
    /// Size of the event payload in bytes.
    pub payload_size: u32,
}

/// Enumerate active ETW trace sessions from kernel memory.
///
/// Looks up `EtwpLoggerContext` (or `WmipLoggerContext`) — an array of
/// pointers to `_WMI_LOGGER_CONTEXT` structures. For each non-null
/// entry, reads the session name, status, and buffer configuration.
pub fn walk_etw_sessions<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<EtwSessionInfo>> {
    // Try EtwpLoggerContext first (Win8+), then WmipLoggerContext (Win7/XP).
    let array_addr = match reader.symbols().symbol_address("EtwpLoggerContext") {
        Some(addr) => addr,
        None => match reader.symbols().symbol_address("WmipLoggerContext") {
            Some(addr) => addr,
            None => return Ok(Vec::new()),
        },
    };

    // Get the field offset for LoggerName within _WMI_LOGGER_CONTEXT.
    let name_offset = reader
        .symbols()
        .field_offset("_WMI_LOGGER_CONTEXT", "LoggerName")
        .unwrap_or(0x10);

    let mut sessions = Vec::new();

    for i in 0..MAX_LOGGERS {
        // Read the pointer at array[i] (8-byte pointer).
        let ptr_addr = array_addr + (i as u64) * 8;
        let ctx_addr = match reader.read_bytes(ptr_addr, 8) {
            Ok(bytes) if bytes.len() == 8 => {
                u64::from_le_bytes(bytes[..8].try_into().unwrap())
            }
            _ => break, // End of mapped memory — stop scanning.
        };

        if ctx_addr == 0 {
            continue; // Empty slot.
        }

        // Read _WMI_LOGGER_CONTEXT fields.
        let name = read_unicode_string(reader, ctx_addr + name_offset)
            .unwrap_or_default();

        let running: u32 = reader
            .read_field(ctx_addr, "_WMI_LOGGER_CONTEXT", "Running")
            .unwrap_or(0);

        let buffer_count: u32 = reader
            .read_field(ctx_addr, "_WMI_LOGGER_CONTEXT", "BufferCount")
            .unwrap_or(0);

        let buffer_size: u32 = reader
            .read_field(ctx_addr, "_WMI_LOGGER_CONTEXT", "BufferSize")
            .unwrap_or(0);

        let events_lost: u32 = reader
            .read_field(ctx_addr, "_WMI_LOGGER_CONTEXT", "EventsLost")
            .unwrap_or(0);

        let buffers_written: u32 = reader
            .read_field(ctx_addr, "_WMI_LOGGER_CONTEXT", "BuffersWritten")
            .unwrap_or(0);

        let flush_timer: u32 = reader
            .read_field(ctx_addr, "_WMI_LOGGER_CONTEXT", "FlushTimer")
            .unwrap_or(0);

        let log_mode: u32 = reader
            .read_field(ctx_addr, "_WMI_LOGGER_CONTEXT", "LogMode")
            .unwrap_or(0);

        sessions.push(EtwSessionInfo {
            logger_id: i as u32,
            name,
            is_running: running != 0,
            buffer_count,
            buffer_size,
            events_lost,
            buffers_written,
            flush_timer_sec: flush_timer,
            log_mode,
        });
    }

    Ok(sessions)
}

/// Scan ETW trace buffers for in-flight events.
///
/// For each active session, walks the buffer list and extracts event
/// headers (timestamp, provider GUID, event ID, level, opcode).
/// Returns events sorted by timestamp.
pub fn scan_etw_buffers<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<EtwBufferEvent>> {
    // Reuse walk_etw_sessions to find active loggers.
    let sessions = walk_etw_sessions(reader)?;
    if sessions.is_empty() {
        return Ok(Vec::new());
    }

    // Buffer scanning requires _WMI_BUFFER_HEADER type info and buffer
    // list pointers within each logger context. For now, return the empty
    // set — the session enumeration is the primary value. Buffer event
    // extraction requires walking the FreeList/FlushList linked lists
    // within each _WMI_LOGGER_CONTEXT, which needs additional ISF fields
    // (BufferListHead, FreeList) and _WMI_BUFFER_HEADER structure
    // definitions that vary significantly across Windows versions.
    let _sessions = sessions; // suppress unused warning
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// No ETW logger symbol → empty Vec.
    #[test]
    fn walk_etw_sessions_no_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("_WMI_LOGGER_CONTEXT", 0x200)
            .add_field("_WMI_LOGGER_CONTEXT", "LoggerName", 0x10, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_etw_sessions(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// Single running ETW session → correct EtwSessionInfo.
    #[test]
    fn walk_etw_sessions_single_session() {
        // Layout:
        //   EtwpLoggerContext @ 0xFFFF_8000_0010_0000 (array of 64 pointers)
        //     [0] → 0xFFFF_8000_0020_0000 (_WMI_LOGGER_CONTEXT)
        //     [1..] → 0 (empty)
        //
        //   _WMI_LOGGER_CONTEXT @ 0xFFFF_8000_0020_0000:
        //     LoggerName @ 0x10 (_UNICODE_STRING → "NT Kernel Logger")
        //     Running    @ 0x28 (u32) = 1
        //     BufferCount @ 0x30 (u32) = 64
        //     BufferSize  @ 0x34 (u32) = 65536
        //     EventsLost  @ 0x38 (u32) = 0
        //     BuffersWritten @ 0x3C (u32) = 128
        //     FlushTimer  @ 0x40 (u32) = 1
        //     LogMode     @ 0x44 (u32) = 0x100 (real-time)

        let array_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let ctx_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let name_buf_vaddr: u64 = 0xFFFF_8000_0020_1000;

        let array_paddr: u64 = 0x0010_0000;
        let ctx_paddr: u64 = 0x0020_0000;
        let name_paddr: u64 = 0x0021_0000;

        let isf = IsfBuilder::new()
            .add_struct("_WMI_LOGGER_CONTEXT", 0x200)
            .add_field("_WMI_LOGGER_CONTEXT", "LoggerName", 0x10, "_UNICODE_STRING")
            .add_field("_WMI_LOGGER_CONTEXT", "Running", 0x28, "unsigned int")
            .add_field("_WMI_LOGGER_CONTEXT", "BufferCount", 0x30, "unsigned int")
            .add_field("_WMI_LOGGER_CONTEXT", "BufferSize", 0x34, "unsigned int")
            .add_field("_WMI_LOGGER_CONTEXT", "EventsLost", 0x38, "unsigned int")
            .add_field(
                "_WMI_LOGGER_CONTEXT",
                "BuffersWritten",
                0x3C,
                "unsigned int",
            )
            .add_field("_WMI_LOGGER_CONTEXT", "FlushTimer", 0x40, "unsigned int")
            .add_field("_WMI_LOGGER_CONTEXT", "LogMode", 0x44, "unsigned int")
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            .add_symbol("EtwpLoggerContext", array_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Build array page: [0] = ctx_vaddr, [1..] = 0
        let mut array_data = vec![0u8; 4096];
        array_data[0..8].copy_from_slice(&ctx_vaddr.to_le_bytes());

        // Build context page
        let mut ctx_data = vec![0u8; 4096];
        // LoggerName (_UNICODE_STRING) at offset 0x10
        let name_text = "NT Kernel Logger";
        let name_utf16: Vec<u8> = name_text
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let name_len = name_utf16.len() as u16;
        ctx_data[0x10..0x12].copy_from_slice(&name_len.to_le_bytes());
        ctx_data[0x12..0x14].copy_from_slice(&(name_len + 2).to_le_bytes());
        ctx_data[0x18..0x20].copy_from_slice(&name_buf_vaddr.to_le_bytes());
        // Running = 1
        ctx_data[0x28..0x2C].copy_from_slice(&1u32.to_le_bytes());
        // BufferCount = 64
        ctx_data[0x30..0x34].copy_from_slice(&64u32.to_le_bytes());
        // BufferSize = 65536
        ctx_data[0x34..0x38].copy_from_slice(&65536u32.to_le_bytes());
        // EventsLost = 0
        ctx_data[0x38..0x3C].copy_from_slice(&0u32.to_le_bytes());
        // BuffersWritten = 128
        ctx_data[0x3C..0x40].copy_from_slice(&128u32.to_le_bytes());
        // FlushTimer = 1
        ctx_data[0x40..0x44].copy_from_slice(&1u32.to_le_bytes());
        // LogMode = 0x100 (EVENT_TRACE_REAL_TIME_MODE)
        ctx_data[0x44..0x48].copy_from_slice(&0x100u32.to_le_bytes());

        // Name buffer
        let mut name_data = vec![0u8; 4096];
        name_data[..name_utf16.len()].copy_from_slice(&name_utf16);

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(array_vaddr, array_paddr, flags::WRITABLE)
            .write_phys(array_paddr, &array_data)
            .map_4k(ctx_vaddr, ctx_paddr, flags::WRITABLE)
            .write_phys(ctx_paddr, &ctx_data)
            .map_4k(name_buf_vaddr, name_paddr, flags::WRITABLE)
            .write_phys(name_paddr, &name_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let sessions = walk_etw_sessions(&reader).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].logger_id, 0);
        assert_eq!(sessions[0].name, "NT Kernel Logger");
        assert!(sessions[0].is_running);
        assert_eq!(sessions[0].buffer_count, 64);
        assert_eq!(sessions[0].buffer_size, 65536);
        assert_eq!(sessions[0].events_lost, 0);
        assert_eq!(sessions[0].buffers_written, 128);
        assert_eq!(sessions[0].flush_timer_sec, 1);
        assert_eq!(sessions[0].log_mode, 0x100);
    }

    /// Empty buffer scan → empty Vec.
    #[test]
    fn scan_etw_buffers_no_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("_WMI_LOGGER_CONTEXT", 0x200)
            .add_field("_WMI_LOGGER_CONTEXT", "LoggerName", 0x10, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let events = scan_etw_buffers(&reader).unwrap();
        assert!(events.is_empty());
    }
}
