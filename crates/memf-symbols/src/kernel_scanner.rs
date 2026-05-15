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
    let mut addr = SCAN_START;
    while addr < SCAN_END {
        let mut mz = [0u8; 2];
        // treat read errors as absent pages — providers return Ok(0) for unmapped ranges
        if mem.read_phys(addr, &mut mz).unwrap_or(0) < 2 || mz != [b'M', b'Z'] {
            addr += PAGE_SIZE as u64;
            continue;
        }
        let mut page = [0u8; PAGE_SIZE];
        // treat read errors as absent pages — providers return Ok(0) for unmapped ranges
        if mem.read_phys(addr, &mut page).unwrap_or(0) < PAGE_SIZE {
            addr += PAGE_SIZE as u64;
            continue;
        }
        let e_lfanew = u32::from_le_bytes([page[0x3C], page[0x3D], page[0x3E], page[0x3F]]) as usize;
        if e_lfanew + 6 > PAGE_SIZE || &page[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            addr += PAGE_SIZE as u64;
            continue;
        }
        let machine = u16::from_le_bytes([page[e_lfanew + 4], page[e_lfanew + 5]]);
        if machine != 0x8664 {
            addr += PAGE_SIZE as u64;
            continue;
        }
        if let Ok(pdb_id) = crate::pe_debug::extract_pdb_id(&page) {
            if is_kernel_pdb_name(&pdb_id.pdb_name) {
                return Ok(pdb_id);
            }
        }
        addr += PAGE_SIZE as u64;
    }
    Err(crate::Error::NotFound("kernel PE not found in physical memory".into()))
}

/// Check whether a PDB filename looks like an ntoskrnl variant.
fn is_kernel_pdb_name(name: &str) -> bool {
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

    /// Build a valid AMD64 PE parseable by goblin, with a CodeView RSDS debug directory.
    ///
    /// Layout mirrors `pe_debug::build_pe_with_debug`: e_lfanew=0x80, one .rdata
    /// section mapping RVA 0x200 → file 0x200, NumberOfRvaAndSizes=16.
    ///
    /// GUID bytes must be in mixed-endian format (Data1/2/3 LE, Data4 BE).
    /// For "1B72224D-37B8-1792-…" use `[0x4D,0x22,0x72,0x1B, 0xB8,0x37, 0x92,0x17, …]`.
    fn build_kernel_pe(pdb_name: &str, guid: [u8; 16], age: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];

        // DOS header
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew

        let mut pos = 0x80usize;

        // PE signature
        buf[pos..pos + 4].copy_from_slice(b"PE\0\0");
        pos += 4;

        // COFF header (20 bytes)
        buf[pos..pos + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine: AMD64
        buf[pos + 2..pos + 4].copy_from_slice(&1u16.to_le_bytes());  // NumberOfSections: 1
        let opt_size: u16 = 240;
        buf[pos + 16..pos + 18].copy_from_slice(&opt_size.to_le_bytes());
        buf[pos + 18..pos + 20].copy_from_slice(&0x0022u16.to_le_bytes()); // Characteristics
        pos += 20;

        // PE32+ optional header
        let opt_start = pos;
        buf[opt_start..opt_start + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // Magic
        buf[opt_start + 32..opt_start + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        buf[opt_start + 36..opt_start + 40].copy_from_slice(&0x200u32.to_le_bytes());  // FileAlignment
        buf[opt_start + 56..opt_start + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // SizeOfImage
        buf[opt_start + 60..opt_start + 64].copy_from_slice(&0x200u32.to_le_bytes());  // SizeOfHeaders
        buf[opt_start + 108..opt_start + 112].copy_from_slice(&16u32.to_le_bytes());   // NumberOfRvaAndSizes
        // Debug directory: data dir index 6 → offset 112 + 6*8 = 160 from opt_start
        buf[opt_start + 160..opt_start + 164].copy_from_slice(&0x200u32.to_le_bytes()); // RVA
        buf[opt_start + 164..opt_start + 168].copy_from_slice(&28u32.to_le_bytes());    // size

        pos = opt_start + opt_size as usize;

        // Section header: .rdata, RVA 0x200 → file offset 0x200
        buf[pos..pos + 8].copy_from_slice(b".rdata\0\0");
        buf[pos + 8..pos + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        buf[pos + 12..pos + 16].copy_from_slice(&0x200u32.to_le_bytes()); // VirtualAddress
        buf[pos + 16..pos + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        buf[pos + 20..pos + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData

        // IMAGE_DEBUG_DIRECTORY at file offset 0x200
        buf[0x200 + 12..0x200 + 16].copy_from_slice(&2u32.to_le_bytes()); // Type=CODEVIEW
        let pdb_bytes = pdb_name.as_bytes();
        let cv_size = (24 + pdb_bytes.len() + 1) as u32;
        buf[0x200 + 16..0x200 + 20].copy_from_slice(&cv_size.to_le_bytes());
        buf[0x200 + 20..0x200 + 24].copy_from_slice(&0x220u32.to_le_bytes()); // AddressOfRawData
        buf[0x200 + 24..0x200 + 28].copy_from_slice(&0x220u32.to_le_bytes()); // PointerToRawData

        // CodeView RSDS record at file offset 0x220
        buf[0x220..0x224].copy_from_slice(b"RSDS");
        buf[0x224..0x234].copy_from_slice(&guid);
        buf[0x234..0x238].copy_from_slice(&age.to_le_bytes());
        buf[0x238..0x238 + pdb_bytes.len()].copy_from_slice(pdb_bytes);
        // null terminator already zero from vec initialisation

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
            0x4D, 0x22, 0x72, 0x1B, // Data1 LE → "1B72224D"
            0xB8, 0x37,             // Data2 LE → "37B8"
            0x92, 0x17,             // Data3 LE → "1792"
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
        pe[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes());
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
