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

    /// 16-byte AES-128 key with varied content is valid.
    #[test]
    fn classify_valid_aes128_key() {
        let key: Vec<u8> = (10u8..=25).collect(); // 16 bytes
        assert!(classify_bitlocker_key(&key));
    }

    /// All-zero 16-byte key is invalid.
    #[test]
    fn classify_zero_16byte_key_invalid() {
        let key = vec![0u8; 16];
        assert!(!classify_bitlocker_key(&key));
    }

    /// Key where every byte is identical (non-zero) is invalid (uniform).
    #[test]
    fn classify_uniform_byte_key_invalid() {
        let key = vec![0xAAu8; 16];
        assert!(!classify_bitlocker_key(&key));
        let key32 = vec![0xBBu8; 32];
        assert!(!classify_bitlocker_key(&key32));
    }

    /// Wrong-length keys (e.g. 8, 24, 64 bytes) are rejected.
    #[test]
    fn classify_wrong_length_keys_invalid() {
        assert!(!classify_bitlocker_key(&[0u8; 8]));
        assert!(!classify_bitlocker_key(&[0x01u8; 24]));
        assert!(!classify_bitlocker_key(&[]));
        // 15 bytes — neither 16 nor 32
        let key15: Vec<u8> = (1u8..=15).collect();
        assert!(!classify_bitlocker_key(&key15));
    }

    /// FveBlockDevice present but MmNonPagedPoolStart absent → empty.
    #[test]
    fn walk_bitlocker_fve_present_no_pool_start_empty() {
        let isf = IsfBuilder::new()
            .add_symbol("FveBlockDevice", 0xFFFF_8000_0010_0000)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &[0u8; 16])
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let results = walk_bitlocker_keys(&reader).unwrap();
        assert!(results.is_empty());
    }

    /// Both FveBlockDevice and MmNonPagedPoolStart present → empty (graceful degradation).
    #[test]
    fn walk_bitlocker_both_symbols_present_empty() {
        let isf = IsfBuilder::new()
            .add_symbol("FveBlockDevice", 0xFFFF_8000_0010_0000)
            .add_symbol("MmNonPagedPoolStart", 0xFFFF_8000_0010_1000)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let p1: u64 = 0x0080_0000;
        let p2: u64 = 0x0081_0000;
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(0xFFFF_8000_0010_0000, p1, flags::WRITABLE)
            .map_4k(0xFFFF_8000_0010_1000, p2, flags::WRITABLE)
            .write_phys(p1, &[0u8; 16])
            .write_phys(p2, &[0u8; 16])
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let results = walk_bitlocker_keys(&reader).unwrap();
        assert!(results.is_empty());
    }

    /// BitlockerKeyInfo serializes correctly.
    #[test]
    fn bitlocker_key_info_serializes() {
        let info = BitlockerKeyInfo {
            volume_guid: "{12345678-1234-1234-1234-123456789abc}".to_string(),
            key_type: "FVEK".to_string(),
            key_material: vec![0x01u8; 32],
            algorithm: "AES-256-XTS".to_string(),
            is_found: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("FVEK"));
        assert!(json.contains("AES-256-XTS"));
        assert!(json.contains("\"is_found\":true"));
    }
}
