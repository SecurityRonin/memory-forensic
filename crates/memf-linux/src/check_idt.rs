//! Linux IDT (Interrupt Descriptor Table) hook detector.
//!
//! Rootkits can hook the IDT to intercept system calls and hardware
//! interrupts (MITRE ATT&CK T1014). This module reads the IDT entries
//! from memory and checks if handler addresses point outside the kernel
//! text segment (`_stext`..`_etext`), which indicates potential hooking.
//!
//! On x86_64, the IDT has 256 entries, each a 16-byte `gate_descriptor`:
//!   - offset_low:  u16 at +0
//!   - segment:     u16 at +2
//!   - ist:         u8  at +4
//!   - type_attr:   u8  at +5
//!   - offset_mid:  u16 at +6
//!   - offset_high: u32 at +8
//!   - reserved:    u32 at +12
//!
//! The handler address is reconstructed as:
//!   `(offset_high << 32) | (offset_mid << 16) | offset_low`

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Maximum number of IDT entries on x86_64.
const MAX_IDT_ENTRIES: usize = 256;

/// Size of each IDT gate descriptor in bytes.
const GATE_DESC_SIZE: usize = 16;

/// Information about a single IDT entry with hook classification.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IdtEntryInfo {
    /// Interrupt vector number (0-255).
    pub vector: u8,
    /// Reconstructed handler virtual address.
    pub handler_addr: u64,
    /// Code segment selector from the gate descriptor.
    pub segment: u16,
    /// Human-readable gate type name.
    pub gate_type: String,
    /// Whether the handler points outside the kernel text section.
    pub is_hooked: bool,
}

/// Classify whether an IDT handler address is hooked.
///
/// - Address of `0` is not considered hooked (null/unused entry).
/// - Address within `[kernel_start, kernel_end]` is benign (kernel text).
/// - Address outside that range is suspicious (hooked).
pub fn classify_idt_entry(handler_addr: u64, kernel_start: u64, kernel_end: u64) -> bool {
    if handler_addr == 0 {
        return false;
    }
    !(kernel_start <= handler_addr && handler_addr <= kernel_end)
}

/// Map a gate type nibble to a human-readable name.
///
/// The lower 4 bits of the `type_attr` byte encode the gate type:
/// - `0xE` → Interrupt Gate (interrupts disabled on entry)
/// - `0xF` → Trap Gate (interrupts remain enabled)
/// - Other values are uncommon/reserved.
pub fn gate_type_name(type_attr: u8) -> String {
    let gate_nibble = type_attr & 0x0F;
    match gate_nibble {
        0xE => "Interrupt Gate".to_string(),
        0xF => "Trap Gate".to_string(),
        other => format!("Unknown(0x{other:02X})"),
    }
}

/// Walk the IDT and classify each entry against the kernel text range.
///
/// Looks up `_stext`, `_etext`, and `idt_table` symbols. If any are
/// missing, returns `Ok(Vec::new())` for graceful degradation. For each
/// of the 256 IDT entries, reconstructs the handler address and checks
/// whether it falls within the kernel text section.
pub fn walk_check_idt<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<IdtEntryInfo>> {
    let symbols = reader.symbols();

    // Resolve kernel text boundaries; if missing, we cannot classify.
    let Some(kernel_start) = symbols.symbol_address("_stext") else {
        return Ok(Vec::new());
    };
    let Some(kernel_end) = symbols.symbol_address("_etext") else {
        return Ok(Vec::new());
    };

    // Resolve the IDT base address.
    let Some(idt_base) = symbols.symbol_address("idt_table") else {
        return Ok(Vec::new());
    };

    let mut results = Vec::new();

    for vector in 0..MAX_IDT_ENTRIES {
        let entry_addr = idt_base + (vector as u64) * (GATE_DESC_SIZE as u64);

        // Read the full 16-byte gate descriptor.
        let raw = match reader.read_bytes(entry_addr, GATE_DESC_SIZE) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };

        // Parse fields from the gate descriptor:
        //   offset_low:  u16 at +0
        //   segment:     u16 at +2
        //   _ist:        u8  at +4
        //   type_attr:   u8  at +5
        //   offset_mid:  u16 at +6
        //   offset_high: u32 at +8
        //   _reserved:   u32 at +12
        let offset_low = u16::from_le_bytes([raw[0], raw[1]]);
        let segment = u16::from_le_bytes([raw[2], raw[3]]);
        let type_attr = raw[5];
        let offset_mid = u16::from_le_bytes([raw[6], raw[7]]);
        let offset_high = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);

        let handler_addr = (offset_high as u64) << 32
            | (offset_mid as u64) << 16
            | offset_low as u64;

        // Skip unused entries (handler == 0).
        if handler_addr == 0 {
            continue;
        }

        let is_hooked = classify_idt_entry(handler_addr, kernel_start, kernel_end);
        let gate_type = gate_type_name(type_attr);

        results.push(IdtEntryInfo {
            vector: vector as u8,
            handler_addr,
            segment,
            gate_type,
            is_hooked,
        });
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // -----------------------------------------------------------------------
    // classify_idt_entry unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn classify_hooked_outside_kernel() {
        let kernel_start = 0xFFFF_8000_0000_0000u64;
        let kernel_end = 0xFFFF_8000_00FF_FFFFu64;

        // Address in module space, well outside kernel text
        assert!(classify_idt_entry(0xFFFF_C900_DEAD_BEEF, kernel_start, kernel_end));
        // Address just below kernel start
        assert!(classify_idt_entry(kernel_start - 1, kernel_start, kernel_end));
        // Address just above kernel end
        assert!(classify_idt_entry(kernel_end + 1, kernel_start, kernel_end));
    }

    #[test]
    fn classify_benign_inside_kernel() {
        let kernel_start = 0xFFFF_8000_0000_0000u64;
        let kernel_end = 0xFFFF_8000_00FF_FFFFu64;

        // Exactly at start
        assert!(!classify_idt_entry(kernel_start, kernel_start, kernel_end));
        // In the middle
        assert!(!classify_idt_entry(kernel_start + 0x1000, kernel_start, kernel_end));
        // Exactly at end
        assert!(!classify_idt_entry(kernel_end, kernel_start, kernel_end));
    }

    #[test]
    fn classify_null_benign() {
        let kernel_start = 0xFFFF_8000_0000_0000u64;
        let kernel_end = 0xFFFF_8000_00FF_FFFFu64;

        // Null pointer is never considered hooked
        assert!(!classify_idt_entry(0, kernel_start, kernel_end));
    }

    #[test]
    fn gate_type_interrupt() {
        assert_eq!(gate_type_name(0x8E), "Interrupt Gate");
        // Also works with just the nibble
        assert_eq!(gate_type_name(0x0E), "Interrupt Gate");
    }

    #[test]
    fn gate_type_trap() {
        assert_eq!(gate_type_name(0x8F), "Trap Gate");
        assert_eq!(gate_type_name(0x0F), "Trap Gate");
    }

    #[test]
    fn gate_type_unknown() {
        assert_eq!(gate_type_name(0x00), "Unknown(0x00)");
        assert_eq!(gate_type_name(0x85), "Unknown(0x05)");
        assert_eq!(gate_type_name(0xAC), "Unknown(0x0C)");
    }

    #[test]
    fn walk_no_symbol_returns_empty() {
        // Build a reader with no idt_table symbol — walker should gracefully
        // return an empty vector instead of erroring.
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            .add_symbol("_stext", 0xFFFF_8000_0000_0000)
            .add_symbol("_etext", 0xFFFF_8000_00FF_FFFF)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_check_idt(&reader).unwrap();
        assert!(results.is_empty(), "expected empty results when idt_table symbol is missing");
    }
}
