//! PE debug info extraction.
//!
//! Parses CodeView RSDS records from PE debug directories to extract
//! PDB identification (GUID, age, PDB filename) needed for symbol
//! server downloads.

/// PDB identification extracted from a PE debug directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbId {
    /// GUID as uppercase hex with dashes (e.g., "1B72224D-37B8-1792-2820-0ED8994498B2").
    pub guid: String,
    /// PDB age counter.
    pub age: u32,
    /// PDB filename (e.g., "ntkrnlmp.pdb").
    pub pdb_name: String,
}

/// Format a 16-byte mixed-endian GUID as uppercase hex with dashes.
///
/// The GUID is stored in mixed-endian format:
/// - Bytes 0-3: `Data1` (little-endian u32)
/// - Bytes 4-5: `Data2` (little-endian u16)
/// - Bytes 6-7: `Data3` (little-endian u16)
/// - Bytes 8-15: `Data4` (big-endian, raw bytes)
fn format_guid(bytes: &[u8; 16]) -> String {
    todo!()
}

/// Extract PDB identification from a PE binary.
///
/// Parses the PE debug directory to find a CodeView RSDS record containing
/// the GUID, age, and PDB filename needed to download the matching PDB
/// from a symbol server.
pub fn extract_pdb_id(pe_bytes: &[u8]) -> crate::Result<PdbId> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal PE (PE32+/AMD64) with an embedded CodeView RSDS debug record.
    ///
    /// The resulting buffer is a valid PE that goblin can parse, containing:
    /// - DOS header with e_lfanew at 0x80
    /// - PE signature + COFF header (AMD64, 1 section)
    /// - PE32+ optional header with debug data directory
    /// - One .rdata section mapping RVA 0x200 to file offset 0x200
    /// - IMAGE_DEBUG_DIRECTORY pointing to CodeView data
    /// - CodeView RSDS record with the given GUID, age, and PDB filename
    fn build_pe_with_debug(guid_bytes: [u8; 16], age: u32, pdb_name: &str) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];

        // DOS header
        buf[0] = b'M';
        buf[1] = b'Z';
        let pe_offset: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());

        let mut pos = pe_offset as usize;

        // PE signature
        buf[pos..pos + 4].copy_from_slice(b"PE\0\0");
        pos += 4;

        // COFF header (20 bytes)
        buf[pos..pos + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine: AMD64
        buf[pos + 2..pos + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections: 1
        let optional_header_size: u16 = 240; // PE32+ optional header size (112 + 16*8)
        buf[pos + 16..pos + 18].copy_from_slice(&optional_header_size.to_le_bytes());
        buf[pos + 18..pos + 20].copy_from_slice(&0x0022u16.to_le_bytes()); // Characteristics
        pos += 20;

        // Optional header (PE32+)
        let opt_start = pos;
        buf[pos..pos + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+ magic

        // SizeOfHeaders at offset 60 from opt_start
        buf[opt_start + 60..opt_start + 64].copy_from_slice(&0x400u32.to_le_bytes());

        // NumberOfRvaAndSizes at offset 108 from opt_start
        buf[opt_start + 108..opt_start + 112].copy_from_slice(&16u32.to_le_bytes());

        // Data directories start at offset 112 from opt_start.
        // Debug directory is index 6 -> offset 112 + 6*8 = 160 from opt_start.
        let debug_dir_rva: u32 = 0x200;
        let debug_dir_size: u32 = 28; // One IMAGE_DEBUG_DIRECTORY entry
        buf[opt_start + 160..opt_start + 164].copy_from_slice(&debug_dir_rva.to_le_bytes());
        buf[opt_start + 164..opt_start + 168].copy_from_slice(&debug_dir_size.to_le_bytes());

        pos = opt_start + optional_header_size as usize;

        // Section header (40 bytes) — .rdata covering our debug data area
        buf[pos..pos + 8].copy_from_slice(b".rdata\0\0");
        buf[pos + 8..pos + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        buf[pos + 12..pos + 16].copy_from_slice(&0x200u32.to_le_bytes()); // VirtualAddress
        buf[pos + 16..pos + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        buf[pos + 20..pos + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData

        // IMAGE_DEBUG_DIRECTORY at file offset 0x200
        let debug_dir_offset = 0x200usize;
        let cv_rva: u32 = 0x220;
        let pdb_name_bytes = pdb_name.as_bytes();
        let cv_size: u32 = (24 + pdb_name_bytes.len() + 1) as u32;

        // Type field is at offset +12 in IMAGE_DEBUG_DIRECTORY
        buf[debug_dir_offset + 12..debug_dir_offset + 16]
            .copy_from_slice(&2u32.to_le_bytes()); // IMAGE_DEBUG_TYPE_CODEVIEW
        buf[debug_dir_offset + 16..debug_dir_offset + 20]
            .copy_from_slice(&cv_size.to_le_bytes()); // SizeOfData
        buf[debug_dir_offset + 20..debug_dir_offset + 24]
            .copy_from_slice(&cv_rva.to_le_bytes()); // AddressOfRawData
        buf[debug_dir_offset + 24..debug_dir_offset + 28]
            .copy_from_slice(&cv_rva.to_le_bytes()); // PointerToRawData (= RVA, 1:1 mapping)

        // CodeView RSDS record at file offset 0x220
        let cv_offset = 0x220usize;
        buf[cv_offset..cv_offset + 4].copy_from_slice(b"RSDS");
        buf[cv_offset + 4..cv_offset + 20].copy_from_slice(&guid_bytes);
        buf[cv_offset + 20..cv_offset + 24].copy_from_slice(&age.to_le_bytes());
        let name_start = cv_offset + 24;
        buf[name_start..name_start + pdb_name_bytes.len()].copy_from_slice(pdb_name_bytes);
        buf[name_start + pdb_name_bytes.len()] = 0; // null terminator

        buf
    }

    /// Build a minimal valid PE (PE32+/AMD64) with no debug directory.
    fn build_pe_no_debug() -> Vec<u8> {
        let mut buf = vec![0u8; 4096];

        // DOS header
        buf[0] = b'M';
        buf[1] = b'Z';
        let pe_offset: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());

        let mut pos = pe_offset as usize;

        // PE signature
        buf[pos..pos + 4].copy_from_slice(b"PE\0\0");
        pos += 4;

        // COFF header (20 bytes)
        buf[pos..pos + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine: AMD64
        buf[pos + 2..pos + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections: 1
        let optional_header_size: u16 = 240;
        buf[pos + 16..pos + 18].copy_from_slice(&optional_header_size.to_le_bytes());
        buf[pos + 18..pos + 20].copy_from_slice(&0x0022u16.to_le_bytes());
        pos += 20;

        // Optional header (PE32+)
        let opt_start = pos;
        buf[pos..pos + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        buf[opt_start + 60..opt_start + 64].copy_from_slice(&0x400u32.to_le_bytes());

        // NumberOfRvaAndSizes = 0 => no data directories at all
        buf[opt_start + 108..opt_start + 112].copy_from_slice(&0u32.to_le_bytes());

        pos = opt_start + optional_header_size as usize;

        // Section header
        buf[pos..pos + 8].copy_from_slice(b".text\0\0\0");
        buf[pos + 8..pos + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[pos + 12..pos + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[pos + 16..pos + 20].copy_from_slice(&0x200u32.to_le_bytes());
        buf[pos + 20..pos + 24].copy_from_slice(&0x200u32.to_le_bytes());

        buf
    }

    // Known GUID bytes for testing:
    // Stored as mixed-endian: Data1(LE) Data2(LE) Data3(LE) Data4(BE)
    // Target: "1B72224D-37B8-1792-2820-0ED8994498B2"
    //   Data1 = 0x1B72224D -> LE bytes: [0x4D, 0x22, 0x72, 0x1B]
    //   Data2 = 0x37B8     -> LE bytes: [0xB8, 0x37]
    //   Data3 = 0x1792     -> LE bytes: [0x92, 0x17]
    //   Data4 = [0x28, 0x20, 0x0E, 0xD8, 0x99, 0x44, 0x98, 0xB2]
    const TEST_GUID_BYTES: [u8; 16] = [
        0x4D, 0x22, 0x72, 0x1B, // Data1 LE
        0xB8, 0x37, // Data2 LE
        0x92, 0x17, // Data3 LE
        0x28, 0x20, 0x0E, 0xD8, 0x99, 0x44, 0x98, 0xB2, // Data4 BE
    ];
    const TEST_GUID_STR: &str = "1B72224D-37B8-1792-2820-0ED8994498B2";

    #[test]
    fn extract_pdb_id_basic() {
        let pe = build_pe_with_debug(TEST_GUID_BYTES, 1, "ntkrnlmp.pdb");
        let id = extract_pdb_id(&pe).expect("should parse");
        assert_eq!(id.guid, TEST_GUID_STR);
        assert_eq!(id.age, 1);
        assert_eq!(id.pdb_name, "ntkrnlmp.pdb");
    }

    #[test]
    fn extract_pdb_id_guid_format() {
        // Verify GUID has correct dash positions and uppercase hex.
        let pe = build_pe_with_debug(TEST_GUID_BYTES, 1, "test.pdb");
        let id = extract_pdb_id(&pe).expect("should parse");

        let parts: Vec<&str> = id.guid.split('-').collect();
        assert_eq!(parts.len(), 5, "GUID should have 5 dash-separated parts");
        assert_eq!(parts[0].len(), 8, "Data1 should be 8 hex chars");
        assert_eq!(parts[1].len(), 4, "Data2 should be 4 hex chars");
        assert_eq!(parts[2].len(), 4, "Data3 should be 4 hex chars");
        assert_eq!(parts[3].len(), 4, "Data4a should be 4 hex chars");
        assert_eq!(parts[4].len(), 12, "Data4b should be 12 hex chars");

        // Verify all uppercase hex
        assert_eq!(id.guid, id.guid.to_uppercase());
    }

    #[test]
    fn extract_pdb_id_different_ages() {
        for age in [1u32, 10, 255] {
            let pe = build_pe_with_debug(TEST_GUID_BYTES, age, "kernel.pdb");
            let id = extract_pdb_id(&pe).expect("should parse");
            assert_eq!(id.age, age, "age mismatch for input {age}");
        }
    }

    #[test]
    fn extract_pdb_id_not_pe() {
        let garbage = b"this is definitely not a PE file";
        let err = extract_pdb_id(garbage).unwrap_err();
        assert!(
            matches!(err, crate::Error::Malformed(_)),
            "expected Malformed, got: {err:?}"
        );
    }

    #[test]
    fn extract_pdb_id_empty() {
        let err = extract_pdb_id(&[]).unwrap_err();
        assert!(
            matches!(err, crate::Error::Malformed(_)),
            "expected Malformed for empty input, got: {err:?}"
        );
    }

    #[test]
    fn extract_pdb_id_pe_no_debug() {
        let pe = build_pe_no_debug();
        let err = extract_pdb_id(&pe).unwrap_err();
        assert!(
            matches!(err, crate::Error::Malformed(_)),
            "expected Malformed for PE without debug dir, got: {err:?}"
        );
    }

    #[test]
    fn pdb_id_clone_and_eq() {
        let id = PdbId {
            guid: TEST_GUID_STR.to_string(),
            age: 1,
            pdb_name: "test.pdb".to_string(),
        };
        let id2 = id.clone();
        assert_eq!(id, id2);

        let id3 = PdbId {
            guid: TEST_GUID_STR.to_string(),
            age: 2,
            pdb_name: "test.pdb".to_string(),
        };
        assert_ne!(id, id3);
    }

    #[test]
    fn format_guid_mixed_endian() {
        let result = format_guid(&TEST_GUID_BYTES);
        assert_eq!(result, TEST_GUID_STR);
    }
}
