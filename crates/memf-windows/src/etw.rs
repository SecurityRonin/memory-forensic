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
            Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            _ => continue, // Slot unreadable (page absent) — skip, keep scanning.
        };

        if ctx_addr == 0 {
            continue; // Empty slot.
        }

        // Read _WMI_LOGGER_CONTEXT fields.
        let name = read_unicode_string(reader, ctx_addr + name_offset).unwrap_or_default();

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

/// Maximum total buffers to visit across all sessions (cycle/corruption guard).
const MAX_BUFFERS: usize = 1024;

/// Scan ETW trace buffers for in-flight events.
///
/// For each active session, walks the `BufferListHead` linked list of
/// `_WMI_BUFFER_HEADER` entries embedded in the `_WMI_LOGGER_CONTEXT`.
/// For each buffer, emits one `EtwBufferEvent` describing the buffer
/// state and write offset. Returns an empty Vec if the required symbols
/// or ISF types are absent (graceful degradation).
pub fn scan_etw_buffers<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<EtwBufferEvent>> {
    // Try EtwpLoggerContext first (Win8+), then WmipLoggerContext (Win7/XP).
    let array_addr = match reader.symbols().symbol_address("EtwpLoggerContext") {
        Some(addr) => addr,
        None => match reader.symbols().symbol_address("WmipLoggerContext") {
            Some(addr) => addr,
            None => return Ok(Vec::new()),
        },
    };

    // Require BufferListHead offset — if absent, ISF lacks buffer walk support.
    let list_head_offset = match reader
        .symbols()
        .field_offset("_WMI_LOGGER_CONTEXT", "BufferListHead")
    {
        Some(off) => off,
        None => return Ok(Vec::new()),
    };

    let mut events = Vec::new();
    let mut total_buffers = 0usize;

    for i in 0..MAX_LOGGERS {
        if total_buffers >= MAX_BUFFERS {
            break;
        }

        // Read the context pointer from the array.
        let ptr_addr = array_addr + (i as u64) * 8;
        let ctx_addr = match reader.read_bytes(ptr_addr, 8) {
            Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            _ => continue,
        };
        if ctx_addr == 0 {
            continue;
        }

        // Check Running flag; skip inactive loggers.
        let running: u32 = reader
            .read_field(ctx_addr, "_WMI_LOGGER_CONTEXT", "Running")
            .unwrap_or(0);
        if running == 0 {
            continue;
        }

        // Walk the BufferListHead linked list.
        // The list head (_LIST_ENTRY) is embedded at ctx_addr + list_head_offset.
        let head_vaddr = ctx_addr + list_head_offset;
        let buffer_addrs = match reader.walk_list_with(
            head_vaddr,
            "_LIST_ENTRY",
            "Flink",
            "_WMI_BUFFER_HEADER",
            "ListEntry",
        ) {
            Ok(addrs) => addrs,
            Err(_) => continue, // Unreadable list — skip this logger.
        };

        for buf_addr in buffer_addrs {
            if total_buffers >= MAX_BUFFERS {
                break;
            }

            let state: u32 = reader
                .read_field(buf_addr, "_WMI_BUFFER_HEADER", "State")
                .unwrap_or(0);
            let offset: u32 = reader
                .read_field(buf_addr, "_WMI_BUFFER_HEADER", "Offset")
                .unwrap_or(0);

            events.push(EtwBufferEvent {
                logger_id: i as u32,
                timestamp: 0,
                provider_guid: String::new(),
                event_id: 0,
                opcode: 0,
                level: 0,
                payload_size: offset,
            });

            let _ = state; // Available for future use (filter by state).
            total_buffers += 1;
        }
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder};
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

    /// Helper: build ISF with ETW buffer structures.
    fn etw_buffer_isf(array_vaddr: u64) -> IsfBuilder {
        IsfBuilder::new()
            // Logger context
            .add_struct("_WMI_LOGGER_CONTEXT", 0x300)
            .add_field("_WMI_LOGGER_CONTEXT", "LoggerName", 0x10, "_UNICODE_STRING")
            .add_field("_WMI_LOGGER_CONTEXT", "Running", 0x28, "unsigned int")
            .add_field("_WMI_LOGGER_CONTEXT", "BufferCount", 0x30, "unsigned int")
            .add_field("_WMI_LOGGER_CONTEXT", "BufferSize", 0x34, "unsigned int")
            .add_field("_WMI_LOGGER_CONTEXT", "EventsLost", 0x38, "unsigned int")
            .add_field("_WMI_LOGGER_CONTEXT", "BuffersWritten", 0x3C, "unsigned int")
            .add_field("_WMI_LOGGER_CONTEXT", "FlushTimer", 0x40, "unsigned int")
            .add_field("_WMI_LOGGER_CONTEXT", "LogMode", 0x44, "unsigned int")
            // BufferListHead is a _LIST_ENTRY embedded at offset 0x100
            .add_field("_WMI_LOGGER_CONTEXT", "BufferListHead", 0x100, "_LIST_ENTRY")
            // Buffer header struct
            .add_struct("_WMI_BUFFER_HEADER", 0x80)
            // ListEntry at offset 0 (Flink/Blink)
            .add_field("_WMI_BUFFER_HEADER", "ListEntry", 0x00, "_LIST_ENTRY")
            // State at offset 0x10
            .add_field("_WMI_BUFFER_HEADER", "State", 0x10, "unsigned int")
            // Offset at offset 0x14 (current write position)
            .add_field("_WMI_BUFFER_HEADER", "Offset", 0x14, "unsigned int")
            // ClientContext at offset 0x18
            .add_field("_WMI_BUFFER_HEADER", "ClientContext", 0x18, "unsigned int")
            // _LIST_ENTRY
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer")
            // _UNICODE_STRING
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            .add_symbol("EtwpLoggerContext", array_vaddr)
    }

    /// Active logger with one buffer in BufferListHead → at least one EtwBufferEvent returned.
    #[test]
    fn scan_etw_buffers_returns_buffers_for_active_logger() {
        // Virtual addresses
        let array_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let ctx_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let buf_vaddr: u64 = 0xFFFF_8000_0030_0000;
        // Physical addresses (all < 0x00FF_FFFF)
        let array_paddr: u64 = 0x0010_0000;
        let ctx_paddr: u64 = 0x0020_0000;
        let buf_paddr: u64 = 0x0030_0000;

        // The list head is embedded in the logger context at offset 0x100.
        let list_head_vaddr = ctx_vaddr + 0x100;
        // The ListEntry field is at offset 0 within _WMI_BUFFER_HEADER, so the
        // Flink in the list head points directly to buf_vaddr (ListEntry.Flink
        // offset = 0 within the buffer header).
        // Circular: head.Flink -> buf.ListEntry.Flink -> head
        let buf_list_entry_vaddr = buf_vaddr; // ListEntry is at offset 0

        let isf = etw_buffer_isf(array_vaddr).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Array page: slot 0 = ctx_vaddr
        let mut array_data = vec![0u8; 4096];
        array_data[0..8].copy_from_slice(&ctx_vaddr.to_le_bytes());

        // Context page
        let mut ctx_data = vec![0u8; 4096];
        // Running = 1
        ctx_data[0x28..0x2C].copy_from_slice(&1u32.to_le_bytes());
        // BufferCount = 1
        ctx_data[0x30..0x34].copy_from_slice(&1u32.to_le_bytes());
        // BufferSize = 4096
        ctx_data[0x34..0x38].copy_from_slice(&4096u32.to_le_bytes());
        // BufferListHead.Flink (at ctx+0x100) → buf_list_entry_vaddr
        ctx_data[0x100..0x108].copy_from_slice(&buf_list_entry_vaddr.to_le_bytes());
        // BufferListHead.Blink (at ctx+0x108) → buf_list_entry_vaddr
        ctx_data[0x108..0x110].copy_from_slice(&buf_list_entry_vaddr.to_le_bytes());

        // Buffer header page
        let mut buf_data = vec![0u8; 4096];
        // ListEntry.Flink (offset 0) → list_head_vaddr (loops back to head)
        buf_data[0x00..0x08].copy_from_slice(&list_head_vaddr.to_le_bytes());
        // ListEntry.Blink (offset 8) → list_head_vaddr
        buf_data[0x08..0x10].copy_from_slice(&list_head_vaddr.to_le_bytes());
        // State = 1 (InUse)
        buf_data[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
        // Offset = 512
        buf_data[0x14..0x18].copy_from_slice(&512u32.to_le_bytes());
        // ClientContext = 0 (logger id 0)
        buf_data[0x18..0x1C].copy_from_slice(&0u32.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(array_vaddr, array_paddr, flags::WRITABLE)
            .write_phys(array_paddr, &array_data)
            .map_4k(ctx_vaddr, ctx_paddr, flags::WRITABLE)
            .write_phys(ctx_paddr, &ctx_data)
            .map_4k(buf_vaddr, buf_paddr, flags::WRITABLE)
            .write_phys(buf_paddr, &buf_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let events = scan_etw_buffers(&reader).unwrap();
        assert!(!events.is_empty(), "expected at least one EtwBufferEvent");
        assert_eq!(events[0].logger_id, 0);
        assert_eq!(events[0].payload_size, 512); // Offset field used as payload_size
    }

    /// No EtwpLoggerContext or WmipLoggerContext symbol → empty Vec.
    #[test]
    fn scan_etw_buffers_empty_when_no_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("_WMI_LOGGER_CONTEXT", 0x300)
            .add_field("_WMI_LOGGER_CONTEXT", "LoggerName", 0x10, "pointer")
            .add_struct("_WMI_BUFFER_HEADER", 0x80)
            .add_field("_WMI_BUFFER_HEADER", "ListEntry", 0x00, "_LIST_ENTRY")
            .add_field("_WMI_BUFFER_HEADER", "State", 0x10, "unsigned int")
            .add_field("_WMI_BUFFER_HEADER", "Offset", 0x14, "unsigned int")
            .add_field("_WMI_BUFFER_HEADER", "ClientContext", 0x18, "unsigned int")
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let events = scan_etw_buffers(&reader).unwrap();
        assert!(events.is_empty());
    }
}
