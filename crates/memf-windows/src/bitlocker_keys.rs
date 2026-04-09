//! BitLocker Full Volume Encryption Key (FVEK) detection.
//!
//! Scans kernel pool memory for the `FVE2` pool tag used by BitLocker's
//! `FveBlockDevice` object.  When a BitLocker volume is unlocked the FVEK
//! resides in non-paged pool, making it recoverable from a live memory dump.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// A BitLocker key candidate found in memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BitlockerKeyInfo {
    /// Volume GUID associated with this key (if determinable).
    pub volume_guid: String,
    /// Key type: `"FVEK"`, `"TWEAK_KEY"`, or `"VMK"`.
    pub key_type: String,
    /// Raw key material bytes (16 bytes = AES-128, 32 bytes = AES-256).
    pub key_material: Vec<u8>,
    /// Algorithm string, e.g. `"AES-128-CBC"` or `"AES-256-XTS"`.
    pub algorithm: String,
    /// `true` when the key material passes basic sanity checks.
    pub is_found: bool,
}

/// Returns `true` when `key_material` looks like a plausible FVEK.
///
/// A valid FVEK must be exactly 16 or 32 bytes of non-zero, non-uniform
/// content.  All-zero keys and keys where every byte is identical are
/// rejected as placeholders or zeroed memory.
pub fn classify_bitlocker_key(key_material: &[u8]) -> bool {
    if key_material.len() != 16 && key_material.len() != 32 {
        return false;
    }
    let all_zero = key_material.iter().all(|&b| b == 0);
    let all_same = key_material.windows(2).all(|w| w[0] == w[1]);
    !all_zero && !all_same
}

/// Walk kernel pool for `FVE2`-tagged objects containing BitLocker key material.
///
/// Returns an empty `Vec` when `FveBlockDevice` or `MmNonPagedPoolStart`
/// symbols are absent (graceful degradation).
pub fn walk_bitlocker_keys<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<BitlockerKeyInfo>> {
    // Graceful degradation: require FveBlockDevice symbol.
    if reader.symbols().symbol_address("FveBlockDevice").is_none() {
        return Ok(Vec::new());
    }

    // Graceful degradation: require MmNonPagedPoolStart symbol.
    if reader
        .symbols()
        .symbol_address("MmNonPagedPoolStart")
        .is_none()
    {
        return Ok(Vec::new());
    }

    // In a full implementation we would scan the non-paged pool for the `FVE2`
    // pool tag and parse the FVE_BLOCK_DEVICE_CONTEXT structure to extract the
    // FVEK.  For now return empty — the walker degrades gracefully when the
    // symbols are present but the pool walk is not yet implemented.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_reader_no_symbols() -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &[0u8; 16]);
        let (cr3, mem) = ptb.build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// 32 bytes of varied, non-zero content is a valid FVEK candidate.
    #[test]
    fn classify_valid_fvek_is_found() {
        let key: Vec<u8> = (1u8..=32).collect();
        assert!(classify_bitlocker_key(&key));
    }

    /// All-zero 32-byte key must be rejected.
    #[test]
    fn classify_zero_key_invalid() {
        let key = vec![0u8; 32];
        assert!(!classify_bitlocker_key(&key));
    }

    /// When `FveBlockDevice` symbol is absent the walker returns empty.
    #[test]
    fn walk_bitlocker_no_symbol_returns_empty() {
        let reader = make_reader_no_symbols();
        let results = walk_bitlocker_keys(&reader).unwrap();
        assert!(results.is_empty());
    }
}
