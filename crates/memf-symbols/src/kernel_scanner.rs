//! Kernel PE scanner for Windows physical memory dumps.
//!
//! Scans physical pages for the ntoskrnl.exe MZ header and extracts
//! the PDB identification (GUID + age + filename) from its CodeView
//! debug directory.

use memf_format::PhysicalMemoryProvider;

use crate::pe_debug::PdbId;

/// Physical address range to scan for the kernel (1 MiB – 128 MiB).
/// The Windows kernel always loads within this window on x64 systems.
const SCAN_START: u64 = 0x0010_0000;
const SCAN_END: u64 = 0x0800_0000;
const PAGE_SIZE: usize = 0x1000;

/// Scan physical memory for ntoskrnl.exe and extract its PDB identification.
///
/// Searches page-aligned addresses from 1 MiB to 128 MiB for a valid
/// AMD64 PE image whose CodeView record identifies it as an ntoskrnl variant.
/// Returns `Error::NotFound` if no kernel PE is found in the scan window.
pub fn scan_for_kernel<P: PhysicalMemoryProvider>(mem: &P) -> crate::Result<PdbId> {
    let _ = mem;
    Err(crate::Error::NotFound("not implemented".into()))
}

/// Check whether a PDB filename looks like an ntoskrnl variant.
pub(crate) fn is_kernel_pdb_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("ntkrnl") || lower.contains("ntoskrnl")
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_format::{PhysicalRange, Result as FmtResult};

    /// Minimal in-memory PhysicalMemoryProvider for tests.
    struct FakeMem {
        data: Vec<u8>,
        base: u64,
    }

    impl FakeMem {
        fn new(base: u64, data: Vec<u8>) -> Self {
            Self { data, base }
        }
    }

    impl PhysicalMemoryProvider for FakeMem {
        fn read_phys(&self, addr: u64, buf: &mut [u8]) -> FmtResult<usize> {
            if addr < self.base {
                return Ok(0);
            }
            let off = (addr - self.base) as usize;
            if off >= self.data.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.data.len() - off);
            buf[..n].copy_from_slice(&self.data[off..off + n]);
            Ok(n)
        }

        fn ranges(&self) -> &[PhysicalRange] {
            &[]
        }

        fn format_name(&self) -> &str {
            "fake"
        }
    }

    /// Build a minimal AMD64 PE with a CodeView RSDS debug directory.
    fn build_kernel_pe(pdb_name: &str, guid: [u8; 16], age: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];

        // DOS header: MZ signature + e_lfanew = 0x40
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());

        // PE signature at 0x40
        buf[0x40..0x44].copy_from_slice(b"PE\0\0");

        // COFF header: Machine = 0x8664 (AMD64), SizeOfOptionalHeader = 0xf0
        buf[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
        buf[0x46..0x48].copy_from_slice(&0u16.to_le_bytes()); // NumberOfSections
        buf[0x4c..0x4e].copy_from_slice(&0xf0u16.to_le_bytes()); // SizeOfOptionalHeader

        // Optional header: Magic = 0x20b (PE32+)
        buf[0x58..0x5a].copy_from_slice(&0x020bu16.to_le_bytes());

        // DataDirectory[6] = Debug directory (RVA=0x200, size=28)
        let dd_offset = 0x58 + 0x60 + 6 * 8;
        buf[dd_offset..dd_offset + 4].copy_from_slice(&0x200u32.to_le_bytes()); // RVA
        buf[dd_offset + 4..dd_offset + 8].copy_from_slice(&28u32.to_le_bytes()); // size

        // IMAGE_DEBUG_DIRECTORY at RVA 0x200
        // Type = 2 (IMAGE_DEBUG_TYPE_CODEVIEW)
        buf[0x200 + 12..0x200 + 16].copy_from_slice(&2u32.to_le_bytes());
        let rsds_size = (4 + 16 + 4 + pdb_name.len() + 1) as u32;
        buf[0x200 + 16..0x200 + 20].copy_from_slice(&rsds_size.to_le_bytes());
        buf[0x200 + 20..0x200 + 24].copy_from_slice(&0x240u32.to_le_bytes());
        buf[0x200 + 24..0x200 + 28].copy_from_slice(&0x240u32.to_le_bytes());

        // CodeView RSDS record at 0x240
        buf[0x240..0x244].copy_from_slice(b"RSDS");
        buf[0x244..0x254].copy_from_slice(&guid);
        buf[0x254..0x258].copy_from_slice(&age.to_le_bytes());
        let name_bytes = pdb_name.as_bytes();
        buf[0x258..0x258 + name_bytes.len()].copy_from_slice(name_bytes);

        buf
    }

    #[test]
    fn is_kernel_pdb_name_accepts_variants() {
        assert!(is_kernel_pdb_name("ntoskrnl.pdb"));
        assert!(is_kernel_pdb_name("ntkrnlmp.pdb"));
        assert!(is_kernel_pdb_name("ntkrnlpa.pdb"));
        assert!(is_kernel_pdb_name("NTOSKRNL.PDB"));
    }

    #[test]
    fn is_kernel_pdb_name_rejects_others() {
        assert!(!is_kernel_pdb_name("notepad.pdb"));
        assert!(!is_kernel_pdb_name("hal.pdb"));
        assert!(!is_kernel_pdb_name(""));
    }

    #[test]
    fn scan_returns_not_found_on_empty_memory() {
        let mem = FakeMem::new(0, vec![0u8; 0x100]);
        let result = scan_for_kernel(&mem);
        assert!(matches!(result, Err(crate::Error::NotFound(_))));
    }

    #[test]
    fn scan_finds_kernel_pe_at_scan_start() {
        let guid = [
            0x1B, 0x72, 0x22, 0x4D, 0x37, 0xB8, 0x17, 0x92,
            0x28, 0x20, 0x0E, 0xD8, 0x99, 0x44, 0x98, 0xB2,
        ];
        let pe = build_kernel_pe("ntkrnlmp.pdb", guid, 1);
        let mem = FakeMem::new(SCAN_START, pe);
        let pdb_id = scan_for_kernel(&mem).expect("should find kernel PE");
        assert_eq!(pdb_id.pdb_name, "ntkrnlmp.pdb");
        assert_eq!(pdb_id.age, 1);
        assert!(pdb_id.guid.contains("1B72224D"));
    }

    #[test]
    fn scan_skips_pages_before_valid_pe() {
        let guid = [0xAA; 16];
        let pe = build_kernel_pe("ntoskrnl.pdb", guid, 2);
        let offset = 0x2000usize;
        let mut data = vec![0xCC_u8; offset];
        data.extend_from_slice(&pe);
        let mem = FakeMem::new(SCAN_START, data);
        let pdb_id = scan_for_kernel(&mem).expect("should find kernel PE after garbage");
        assert_eq!(pdb_id.pdb_name, "ntoskrnl.pdb");
    }

    #[test]
    fn scan_rejects_non_amd64_pe() {
        let guid = [0xBB; 16];
        let mut pe = build_kernel_pe("ntoskrnl.pdb", guid, 1);
        // Patch Machine to x86 (0x014c)
        pe[0x44..0x46].copy_from_slice(&0x014cu16.to_le_bytes());
        let mem = FakeMem::new(SCAN_START, pe);
        let result = scan_for_kernel(&mem);
        assert!(matches!(result, Err(crate::Error::NotFound(_))));
    }

    #[test]
    fn scan_rejects_non_kernel_pdb_name() {
        let guid = [0xCC; 16];
        let pe = build_kernel_pe("notepad.pdb", guid, 1);
        let mem = FakeMem::new(SCAN_START, pe);
        let result = scan_for_kernel(&mem);
        assert!(matches!(result, Err(crate::Error::NotFound(_))));
    }
}
