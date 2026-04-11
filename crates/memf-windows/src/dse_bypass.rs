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

    /// With `g_CiOptions` symbol mapped to memory with value=6, walker
    /// returns `Some` with `is_disabled=false` (raw bytes fallback path,
    /// since `_ULONG` struct is not in the ISF).
    #[test]
    fn walk_dse_bypass_symbol_present_value_6_not_disabled() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let ci_opts_vaddr: u64 = 0xFFFF_8001_0010_0000;
        let ci_opts_paddr: u64 = 0x0085_0000;

        // Write value 6 at the symbol address (little-endian u32)
        let mut page = vec![0u8; 4096];
        page[0..4].copy_from_slice(&6u32.to_le_bytes());

        // ISF with g_CiOptions symbol but NO _ULONG struct → field read will
        // fail → walker uses read_bytes fallback
        let isf = IsfBuilder::new()
            .add_symbol("g_CiOptions", ci_opts_vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(ci_opts_vaddr, ci_opts_paddr, flags::WRITABLE)
            .write_phys(ci_opts_paddr, &page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_dse_bypass(&reader).unwrap();
        let info = result.expect("should return Some when symbol is present and mapped");
        assert_eq!(info.ci_options_value, 6, "value should be 6");
        assert!(!info.is_disabled, "value=6 means DSE is enabled");
        assert_eq!(info.technique, "none");
        assert_eq!(info.expected_value, 6);
    }

    /// With `g_CiOptions` mapped to value=0, walker reports DSE as disabled.
    #[test]
    fn walk_dse_bypass_symbol_present_value_0_is_disabled() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let ci_opts_vaddr: u64 = 0xFFFF_8001_0020_0000;
        let ci_opts_paddr: u64 = 0x0086_0000;

        // Page stays zeroed → value=0
        let page = vec![0u8; 4096];

        let isf = IsfBuilder::new()
            .add_symbol("g_CiOptions", ci_opts_vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(ci_opts_vaddr, ci_opts_paddr, flags::WRITABLE)
            .write_phys(ci_opts_paddr, &page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_dse_bypass(&reader).unwrap();
        let info = result.expect("should return Some when symbol is present");
        assert_eq!(info.ci_options_value, 0);
        assert!(info.is_disabled, "value=0 means DSE is disabled (bypassed)");
        assert_eq!(info.technique, "g_CiOptions_cleared");
    }

    /// classify_ci_options does not flag test-signing mode (8).
    #[test]
    fn classify_ci_options_test_signing_not_bypass() {
        // Test signing is a legitimate mode
        assert!(!classify_ci_options(8));
    }

    /// classify_ci_options does not flag any non-zero value.
    #[test]
    fn classify_ci_options_nonzero_values_not_bypass() {
        for v in [1u32, 2, 3, 4, 5, 6, 7, 8, 16, 0xFF] {
            assert!(!classify_ci_options(v), "value {v} should not be a bypass");
        }
    }
}
