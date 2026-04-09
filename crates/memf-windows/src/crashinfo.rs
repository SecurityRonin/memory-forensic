//! Windows crash dump header and bug check analysis.
//!
//! Extracts crash dump header information, bug check code, and crash parameters
//! from kernel memory. Useful for BSOD analysis and detecting forced crash dumps
//! used as an anti-forensic technique. Equivalent to Volatility's `crashinfo`
//! plugin.
//!
//! Resolves `KiBugCheckData` or `KdDebuggerDataBlock` symbols to locate the
//! bug check code and four associated parameters. The `is_suspicious` flag is
//! set when the bug check code indicates a manually triggered crash (e.g.
//! `0xDEADDEAD` from `NotMyFault` or `0xC000021A` forced BSOD).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use serde::Serialize;

/// Crash dump information extracted from kernel memory.
#[derive(Debug, Clone, Serialize)]
pub struct CrashInfo {
    /// The bug check (stop) code that caused the crash.
    pub bugcheck_code: u32,
    /// First bug check parameter (meaning varies by code).
    pub param1: u64,
    /// Second bug check parameter.
    pub param2: u64,
    /// Third bug check parameter.
    pub param3: u64,
    /// Fourth bug check parameter.
    pub param4: u64,
    /// Dump type description (e.g. "Full", "Kernel", "Small/Minidump").
    pub dump_type: String,
    /// System time at crash (Windows FILETIME, 100-ns intervals since 1601).
    pub system_time: u64,
    /// Human-readable comment describing the bug check code.
    pub comment: String,
    /// Whether this crash is suspicious (manual crash / anti-forensic).
    pub is_suspicious: bool,
}

/// Map a bug check code to a human-readable name.
///
/// Common Windows bug check codes:
/// - `0x0A` = `IRQL_NOT_LESS_OR_EQUAL`
/// - `0x1A` = `MEMORY_MANAGEMENT`
/// - `0x3B` = `SYSTEM_SERVICE_EXCEPTION`
/// - `0x50` = `PAGE_FAULT_IN_NONPAGED_AREA`
/// - `0x7E` = `SYSTEM_THREAD_EXCEPTION_NOT_HANDLED`
/// - `0xD1` = `DRIVER_IRQL_NOT_LESS_OR_EQUAL`
pub fn bugcheck_name(code: u32) -> &'static str {
    match code {
        0x0A => "IRQL_NOT_LESS_OR_EQUAL",
        0x1A => "MEMORY_MANAGEMENT",
        0x3B => "SYSTEM_SERVICE_EXCEPTION",
        0x50 => "PAGE_FAULT_IN_NONPAGED_AREA",
        0x7E => "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        0xD1 => "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        _ => "UNKNOWN",
    }
}

/// Classify whether a bug check code indicates a suspicious (manually
/// triggered or anti-forensic) crash.
///
/// Returns `true` for:
/// - `0xDEADDEAD` — manual crash via `NotMyFault.exe` or similar tool
/// - `0xC000021A` — `STATUS_SYSTEM_PROCESS_TERMINATED`, often forced
pub fn classify_crashinfo(code: u32) -> bool {
    matches!(code, 0xDEAD_DEAD | 0xC000_021A)
}

/// Extract crash dump header and bug check information from kernel memory.
///
/// Looks up `KiBugCheckData` or `KdDebuggerDataBlock` to locate the bug check
/// code and four associated parameters. Returns `Ok(None)` if the essential
/// symbols are not found (e.g. non-Windows image or no crash data present).
///
/// Optional fields degrade gracefully: if a symbol is missing, a default
/// value is used (0 for integers, empty string for strings).
///
/// # Symbols read
///
/// | Symbol                | Type | Description                        |
/// |-----------------------|------|------------------------------------|
/// | `KiBugCheckData`      | u32  | Bug check code                     |
/// | `KdDebuggerDataBlock` | -    | Fallback for crash parameters      |
pub fn walk_crashinfo<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Option<CrashInfo>> {
    // Look up KiBugCheckData symbol — if absent, return None gracefully.
    let bugcheck_addr = match reader.symbols().symbol_address("KiBugCheckData") {
        Some(addr) => addr,
        None => return Ok(None),
    };

    // Layout at KiBugCheckData:
    //   offset 0: bug check code (u32)
    //   offset 8: param1 (u64)
    //   offset 16: param2 (u64)
    //   offset 24: param3 (u64)
    //   offset 32: param4 (u64)
    let bytes = match reader.read_bytes(bugcheck_addr, 40) {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };
    let bugcheck_code = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let param1 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let param2 = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let param3 = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let param4 = u64::from_le_bytes(bytes[32..40].try_into().unwrap());

    // Try to read system_time from KdDebuggerDataBlock at offset +0x14.
    let system_time = if let Some(kd_addr) = reader.symbols().symbol_address("KdDebuggerDataBlock") {
        reader
            .read_bytes(kd_addr.wrapping_add(0x14), 8)
            .ok()
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0)
    } else {
        0
    };

    let comment = bugcheck_name(bugcheck_code).to_string();
    let is_suspicious = classify_crashinfo(bugcheck_code);

    Ok(Some(CrashInfo {
        bugcheck_code,
        param1,
        param2,
        param3,
        param4,
        dump_type: String::new(),
        system_time,
        comment,
        is_suspicious,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── bugcheck_name classifier tests ──

    #[test]
    fn bugcheck_name_irql_not_less_or_equal() {
        assert_eq!(bugcheck_name(0x0A), "IRQL_NOT_LESS_OR_EQUAL");
    }

    #[test]
    fn bugcheck_name_memory_management() {
        assert_eq!(bugcheck_name(0x1A), "MEMORY_MANAGEMENT");
    }

    #[test]
    fn bugcheck_name_system_service_exception() {
        assert_eq!(bugcheck_name(0x3B), "SYSTEM_SERVICE_EXCEPTION");
    }

    #[test]
    fn bugcheck_name_page_fault() {
        assert_eq!(bugcheck_name(0x50), "PAGE_FAULT_IN_NONPAGED_AREA");
    }

    #[test]
    fn bugcheck_name_system_thread_exception() {
        assert_eq!(bugcheck_name(0x7E), "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED");
    }

    #[test]
    fn bugcheck_name_driver_irql() {
        assert_eq!(bugcheck_name(0xD1), "DRIVER_IRQL_NOT_LESS_OR_EQUAL");
    }

    #[test]
    fn bugcheck_name_unknown() {
        assert_eq!(bugcheck_name(0x00), "UNKNOWN");
        assert_eq!(bugcheck_name(0xFF), "UNKNOWN");
        assert_eq!(bugcheck_name(0xDEAD_DEAD), "UNKNOWN");
    }

    // ── classify_crashinfo tests ──

    #[test]
    fn classify_manual_crash() {
        assert!(classify_crashinfo(0xDEAD_DEAD));
    }

    #[test]
    fn classify_forced_bsod() {
        assert!(classify_crashinfo(0xC000_021A));
    }

    #[test]
    fn classify_normal_bugcheck_not_suspicious() {
        assert!(!classify_crashinfo(0x0A));
        assert!(!classify_crashinfo(0x1A));
        assert!(!classify_crashinfo(0x3B));
        assert!(!classify_crashinfo(0x50));
        assert!(!classify_crashinfo(0x7E));
        assert!(!classify_crashinfo(0xD1));
        assert!(!classify_crashinfo(0x00));
    }

    // ── serialization test ──

    #[test]
    fn crash_info_serializes() {
        let info = CrashInfo {
            bugcheck_code: 0x7E,
            param1: 0xC0000005,
            param2: 0xFFFFF800_01234567,
            param3: 0xFFFFF680_00001000,
            param4: 0xFFFFF680_00000100,
            dump_type: "Full".into(),
            system_time: 132_500_000_000_000_000,
            comment: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED".into(),
            is_suspicious: false,
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["bugcheck_code"], 0x7E);
        assert_eq!(json["param1"], 0xC000_0005u64);
        assert_eq!(json["dump_type"], "Full");
        assert_eq!(json["is_suspicious"], false);
        assert_eq!(json["comment"], "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED");
    }

    // ── walker tests ──

    #[test]
    fn walker_no_symbol_returns_none() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Build a reader with NO KiBugCheckData or KdDebuggerDataBlock symbol
        let isf = IsfBuilder::new()
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer");

        let json = isf.build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();

        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new().map_4k(vaddr, paddr, flags::WRITABLE);
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_crashinfo(&reader).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn walker_with_bugcheck_data_returns_info() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // KiBugCheckData: bug check code (u32) at symbol address
        // followed by 4x u64 parameters
        let bugcheck_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let bugcheck_paddr: u64 = 0x0090_0000;

        // KdDebuggerDataBlock for system_time
        let kd_vaddr: u64 = 0xFFFF_8000_0020_1000;
        let kd_paddr: u64 = 0x0091_0000;

        let isf = IsfBuilder::new()
            .add_symbol("KiBugCheckData", bugcheck_vaddr)
            .add_symbol("KdDebuggerDataBlock", kd_vaddr);

        let json = isf.build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();

        let code: u32 = 0x7E; // SYSTEM_THREAD_EXCEPTION_NOT_HANDLED
        let p1: u64 = 0xC000_0005;
        let p2: u64 = 0xFFFFF800_01234567;
        let p3: u64 = 0xFFFFF680_00001000;
        let p4: u64 = 0xFFFFF680_00000100;
        let sys_time: u64 = 132_500_000_000_000_000;

        // Layout: KiBugCheckData points to: code(u32) + pad(4) + p1(u64) + p2 + p3 + p4
        // Offset 0: code (u32), offset 8: param1, 16: param2, 24: param3, 32: param4
        let mut bugcheck_data = vec![0u8; 4096];
        bugcheck_data[0..4].copy_from_slice(&code.to_le_bytes());
        bugcheck_data[8..16].copy_from_slice(&p1.to_le_bytes());
        bugcheck_data[16..24].copy_from_slice(&p2.to_le_bytes());
        bugcheck_data[24..32].copy_from_slice(&p3.to_le_bytes());
        bugcheck_data[32..40].copy_from_slice(&p4.to_le_bytes());

        // KdDebuggerDataBlock: SystemTime at offset +0x14
        let mut kd_data = vec![0u8; 4096];
        kd_data[0x14..0x1C].copy_from_slice(&sys_time.to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(bugcheck_vaddr, bugcheck_paddr, flags::WRITABLE)
            .write_phys(bugcheck_paddr, &bugcheck_data)
            .map_4k(kd_vaddr, kd_paddr, flags::WRITABLE)
            .write_phys(kd_paddr, &kd_data);

        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_crashinfo(&reader).unwrap();
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.bugcheck_code, 0x7E);
        assert_eq!(info.param1, 0xC000_0005);
        assert_eq!(info.param2, 0xFFFFF800_01234567);
        assert_eq!(info.param3, 0xFFFFF680_00001000);
        assert_eq!(info.param4, 0xFFFFF680_00000100);
        assert_eq!(info.comment, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED");
        assert_eq!(info.system_time, 132_500_000_000_000_000);
        assert!(!info.is_suspicious);
    }

    #[test]
    fn walker_detects_suspicious_manual_crash() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let bugcheck_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let bugcheck_paddr: u64 = 0x0090_0000;

        let isf = IsfBuilder::new()
            .add_symbol("KiBugCheckData", bugcheck_vaddr);

        let json = isf.build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();

        // 0xDEADDEAD = manual crash (NotMyFault)
        let code: u32 = 0xDEAD_DEAD;
        let mut bugcheck_data = vec![0u8; 4096];
        bugcheck_data[0..4].copy_from_slice(&code.to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(bugcheck_vaddr, bugcheck_paddr, flags::WRITABLE)
            .write_phys(bugcheck_paddr, &bugcheck_data);

        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_crashinfo(&reader).unwrap();
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.bugcheck_code, 0xDEAD_DEAD);
        assert!(info.is_suspicious);
    }

    #[test]
    fn walker_detects_suspicious_forced_bsod() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let bugcheck_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let bugcheck_paddr: u64 = 0x0090_0000;

        let isf = IsfBuilder::new()
            .add_symbol("KiBugCheckData", bugcheck_vaddr);

        let json = isf.build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();

        // 0xC000021A = forced BSOD
        let code: u32 = 0xC000_021A;
        let mut bugcheck_data = vec![0u8; 4096];
        bugcheck_data[0..4].copy_from_slice(&code.to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(bugcheck_vaddr, bugcheck_paddr, flags::WRITABLE)
            .write_phys(bugcheck_paddr, &bugcheck_data);

        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_crashinfo(&reader).unwrap();
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.bugcheck_code, 0xC000_021A);
        assert!(info.is_suspicious);
    }
}
