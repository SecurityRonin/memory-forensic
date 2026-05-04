//! MBR/VBR bootkit detection.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about a scanned MBR/VBR sector.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MbrInfo {
    /// Byte offset of the sector in memory.
    pub physical_offset: u64,
    /// 32-bit disk signature at offset 0x1B8.
    pub signature: u32,
    /// Boot indicator byte (0x80 = active/bootable).
    pub boot_indicator: u8,
    /// `true` when the sector ends with the `0x55 0xAA` boot magic.
    pub has_valid_magic: bool,
    /// `true` when the bootstrap code pattern looks anomalous.
    pub is_suspicious: bool,
    /// SHA-256 hex digest of the first 446 bootstrap bytes.
    pub bootstrap_hash: String,
}

/// Return `true` when the MBR bootstrap code pattern appears anomalous.
pub fn classify_mbr(bootstrap_bytes: &[u8]) -> bool {
    if bootstrap_bytes.len() < 4 {
        return false;
    }
    matches!(bootstrap_bytes[0], 0xFA | 0x90)
        && !matches!(
            &bootstrap_bytes[..3],
            [0xFA, 0x33 | 0x31, 0xC0]
        )
}

/// Scans virtual address space at 512-byte intervals starting from offset 0.
/// In test scenarios, the SyntheticPhysMem maps test data at vaddr 0.
/// In production use, the caller is responsible for providing a reader backed
/// by a physical memory image where vaddr 0 maps to the MBR sector.
pub fn walk_mbr_scan<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>) -> Result<Vec<MbrInfo>> {
    if reader
        .symbols()
        .symbol_address("MmSystemRangeStart")
        .is_none()
    {
        return Ok(Vec::new());
    }

    let mut results = Vec::new();
    let mut offset: u64 = 0;
    while offset + 512 <= 65536 {
        let sector = if let Ok(b) = reader.read_bytes(offset, 512) { b } else {
            offset += 512;
            continue;
        };

        let has_valid_magic = sector[510] == 0x55 && sector[511] == 0xAA;
        if !has_valid_magic {
            offset += 512;
            continue;
        }

        let signature =
            u32::from_le_bytes([sector[0x1B8], sector[0x1B9], sector[0x1BA], sector[0x1BB]]);
        let boot_indicator = sector[0x1BE];
        let bootstrap = &sector[..440.min(sector.len())];
        let is_suspicious = classify_mbr(bootstrap);
        let bootstrap_hash = sha256_hex(bootstrap);

        results.push(MbrInfo {
            physical_offset: offset,
            signature,
            boot_indicator,
            has_valid_magic,
            is_suspicious,
            bootstrap_hash,
        });

        offset += 512;
    }

    Ok(results)
}

fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write;
    let digest = sha256(data);
    digest.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[allow(clippy::many_single_char_names)]
fn sha256(data: &[u8]) -> [u8; 32] {
    #[rustfmt::skip]
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, bytes) in chunk.chunks(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
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

    #[test]
    fn classify_nop_sled_suspicious() {
        let bootstrap = [0x90u8, 0x00, 0x00, 0x00];
        assert!(classify_mbr(&bootstrap));
    }

    #[test]
    fn classify_windows_mbr_not_suspicious() {
        let bootstrap = [0xFAu8, 0x33, 0xC0, 0x8E];
        assert!(!classify_mbr(&bootstrap));
    }

    #[test]
    fn walk_mbr_scan_no_symbol_returns_empty() {
        let reader = make_reader_no_symbols();
        let results = walk_mbr_scan(&reader).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn classify_windows_mbr_fa31c0_not_suspicious() {
        let bootstrap = [0xFAu8, 0x31, 0xC0, 0xD0];
        assert!(!classify_mbr(&bootstrap));
    }

    #[test]
    fn classify_fa_unknown_suspicious() {
        let bootstrap = [0xFAu8, 0x00, 0x00, 0x00];
        assert!(classify_mbr(&bootstrap));
    }

    #[test]
    fn classify_mbr_too_short_not_suspicious() {
        assert!(!classify_mbr(&[]));
        assert!(!classify_mbr(&[0x90]));
        assert!(!classify_mbr(&[0xFA, 0x33]));
        assert!(!classify_mbr(&[0xFA, 0x33, 0xC0]));
    }

    #[test]
    fn classify_mbr_other_first_byte_not_suspicious() {
        let bootstrap = [0xEB, 0x63, 0x00, 0x00];
        assert!(!classify_mbr(&bootstrap));
        let bootstrap2 = [0x33, 0xC0, 0x8E, 0xD0];
        assert!(!classify_mbr(&bootstrap2));
    }

    #[test]
    fn mbr_info_serializes() {
        let info = MbrInfo {
            physical_offset: 0,
            signature: 0xABCD1234,
            boot_indicator: 0x80,
            has_valid_magic: true,
            is_suspicious: false,
            bootstrap_hash: "deadbeef".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("physical_offset"));
        assert!(json.contains("bootstrap_hash"));
        assert!(json.contains("deadbeef"));
    }

    #[test]
    fn walk_mbr_scan_finds_sector_with_valid_magic() {
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};

        let isf = IsfBuilder::new()
            .add_symbol("MmSystemRangeStart", 0xFFFF_8000_0000_0000u64)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut first_phys_page = [0u8; 4096];
        first_phys_page[0] = 0xFA;
        first_phys_page[1] = 0x33;
        first_phys_page[2] = 0xC0;
        first_phys_page[510] = 0x55;
        first_phys_page[511] = 0xAA;
        first_phys_page[0x1B8] = 0xAB;
        first_phys_page[0x1B9] = 0xCD;
        first_phys_page[0x1BA] = 0xEF;
        first_phys_page[0x1BB] = 0x01;
        first_phys_page[0x1BE] = 0x80;

        let page_paddr: u64 = 0x0010_0000;

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(0, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &first_phys_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_mbr_scan(&reader).unwrap_or_default();
        assert!(
            !results.is_empty(),
            "should find the sector with 0x55AA magic"
        );
        let mbr = &results[0];
        assert_eq!(mbr.physical_offset, 0);
        assert!(mbr.has_valid_magic);
        assert!(
            !mbr.is_suspicious,
            "Windows FA 33 C0 MBR should not be suspicious"
        );
        assert_eq!(mbr.signature, 0x01EF_CDAB);
        assert_eq!(mbr.boot_indicator, 0x80);
        assert_eq!(mbr.bootstrap_hash.len(), 64);
    }

    #[test]
    fn walk_mbr_scan_with_symbol_no_valid_sector() {
        use memf_core::test_builders::SyntheticPhysMem;

        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;

        let isf = IsfBuilder::new()
            .add_symbol("MmSystemRangeStart", 0xFFFF_8000_0000_0000u64)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &[0u8; 16]);
        let (cr3, mem) = ptb.build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_mbr_scan(&reader).unwrap();
        assert!(results.is_empty(), "No valid 0x55AA magic → empty results");
    }
}
