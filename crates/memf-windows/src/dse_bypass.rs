//! Driver Signature Enforcement (DSE) bypass detection.
//!
//! Reads `g_CiOptions` from `ci.dll` to detect whether code integrity
//! checking has been disabled. Normal operation has `g_CiOptions = 0x6`.
//! Attackers clear this to zero (`0x0`) to allow loading unsigned drivers,
//! which is a key step in many kernel rootkit installs.
//!
//! Also checks `nt!g_CiEnabled` when present (older Windows versions).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about the Driver Signature Enforcement state.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DseBypassInfo {
    /// Virtual address of the `g_CiOptions` variable.
    pub ci_options_address: u64,
    /// Current value of `g_CiOptions`.
    pub ci_options_value: u32,
    /// Expected value on a healthy system (6 = integrity checking enabled).
    pub expected_value: u32,
    /// True if DSE appears to be disabled.
    pub is_disabled: bool,
    /// Technique description.
    pub technique: String,
}

/// Returns `true` if the `g_CiOptions` value indicates DSE is disabled.
///
/// Known values:
/// - `0` — DSE disabled (bypassed)
/// - `6` — DSE enabled (normal production)
/// - `8` — Test signing mode (unsigned drivers allowed, but legitimate)
pub fn classify_ci_options(value: u32) -> bool {
    value == 0
}

/// Check the `g_CiOptions` symbol for evidence of DSE bypass.
///
/// Returns `Ok(None)` if the `g_CiOptions` symbol is absent from the
/// symbol table (graceful degradation). Returns `Ok(Some(...))` with
/// findings when the symbol is present.
pub fn walk_dse_bypass<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Option<DseBypassInfo>> {
    // Graceful degradation: require g_CiOptions symbol
    let Some(ci_opts_sym_addr) = reader.symbols().symbol_address("g_CiOptions") else {
        return Ok(None);
    };

    // Read the 32-bit value at the symbol address
    let value: u32 = match reader.read_field(ci_opts_sym_addr, "_ULONG", "value") {
        Ok(v) => v,
        Err(_) => {
            // Try raw bytes fallback
            match reader.read_bytes(ci_opts_sym_addr, 4) {
                Ok(b) if b.len() == 4 => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
                _ => return Ok(None),
            }
        }
    };

    let is_disabled = classify_ci_options(value);
    let technique = if is_disabled {
        "g_CiOptions_cleared".to_string()
    } else {
        "none".to_string()
    };

    Ok(Some(DseBypassInfo {
        ci_options_address: ci_opts_sym_addr,
        ci_options_value: value,
        expected_value: 6,
        is_disabled,
        technique,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `g_CiOptions = 0` means DSE is disabled — must be flagged.
    #[test]
    fn classify_ci_options_zero_is_bypass() {
        assert!(classify_ci_options(0));
    }

    /// `g_CiOptions = 6` is the normal production value — must not be flagged.
    #[test]
    fn classify_ci_options_normal_not_bypass() {
        assert!(!classify_ci_options(6));
        // Test signing (8) is also not a cleared bypass
        assert!(!classify_ci_options(8));
    }

    /// Without `g_CiOptions` symbol, walker returns None.
    #[test]
    fn walk_dse_bypass_no_symbol_returns_none() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &[0u8; 16]);
        let (cr3, mem) = ptb.build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_dse_bypass(&reader).unwrap();
        assert!(result.is_none());
    }
}
