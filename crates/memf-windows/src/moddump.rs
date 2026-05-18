//! Windows process/module memory extraction.
//!
//! Provides raw-byte extraction of PE images from live or snapshot memory,
//! reconstruction of on-disk PE layout from in-memory layout, and enumeration
//! of memory-mapped (non-private) VAD regions.

use memf_format::PhysicalMemoryProvider;
use memf_core::object_reader::ObjectReader;
use crate::types::{WinDllInfo, WinDriverInfo, WinProcessInfo, WinVadInfo};

/// A dumped module or process image extracted from memory.
#[derive(Debug, Clone)]
pub struct ModuleDump {
    /// Base name of the module (e.g. `"ntdll.dll"`).
    pub name: String,
    /// Virtual base address where the image is loaded.
    pub base_addr: u64,
    /// Raw bytes read directly from virtual memory (in-memory layout).
    pub raw_bytes: Vec<u8>,
    /// Reconstructed on-disk PE layout, if reconstruction succeeded.
    pub reconstructed: Option<Vec<u8>>,
}

/// A memory-mapped file region extracted from VAD information.
#[derive(Debug, Clone)]
pub struct MappedFileRegion {
    /// Start virtual address of the mapped region.
    pub start_vaddr: u64,
    /// End virtual address of the mapped region (inclusive last byte).
    pub end_vaddr: u64,
    /// File path backing this mapping (empty if unavailable).
    pub file_path: String,
    /// Page protection value.
    pub protection: u32,
}

/// Abstraction over a memory source for testability.
pub(crate) trait MemReader {
    /// Read `len` bytes starting at virtual address `vaddr`.
    fn read_region(&self, vaddr: u64, len: usize) -> crate::Result<Vec<u8>>;
}

impl<P: PhysicalMemoryProvider> MemReader for ObjectReader<P> {
    fn read_region(&self, vaddr: u64, len: usize) -> crate::Result<Vec<u8>> {
        Ok(self.read_bytes(vaddr, len)?)
    }
}

/// Read `size` bytes from virtual address `vaddr` using the given reader.
pub fn dump_memory_region<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    vaddr: u64,
    size: usize,
) -> crate::Result<Vec<u8>> {
    dump_region_inner(reader, vaddr, size)
}

/// Inner implementation of region dumping, testable via `MemReader`.
pub(crate) fn dump_region_inner(
    reader: &impl MemReader,
    vaddr: u64,
    size: usize,
) -> crate::Result<Vec<u8>> {
    reader.read_region(vaddr, size)
}

/// Dump a loaded DLL from process virtual memory.
pub fn moddump<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    dll: &WinDllInfo,
) -> crate::Result<ModuleDump> {
    moddump_inner(reader, &dll.name, dll.base_addr, dll.size as usize)
}

/// Dump a loaded kernel driver from kernel virtual memory.
pub fn moddump_driver<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    drv: &WinDriverInfo,
) -> crate::Result<ModuleDump> {
    moddump_inner(reader, &drv.name, drv.base_addr, drv.size as usize)
}

/// Inner implementation of module dumping — STUB.
pub(crate) fn moddump_inner(
    _reader: &impl MemReader,
    _name: &str,
    _base_addr: u64,
    _size: usize,
) -> crate::Result<ModuleDump> {
    Err(crate::Error::WalkFailed {
        walker: "moddump",
        reason: "not implemented".into(),
    })
}

/// Dump all memory regions belonging to a process (minidump-style).
pub fn procdump<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    process: &WinProcessInfo,
    dlls: &[WinDllInfo],
) -> crate::Result<ModuleDump> {
    procdump_inner(reader, process, dlls)
}

/// Inner implementation of process dumping — STUB.
pub(crate) fn procdump_inner(
    _reader: &impl MemReader,
    _process: &WinProcessInfo,
    _dlls: &[WinDllInfo],
) -> crate::Result<ModuleDump> {
    Err(crate::Error::WalkFailed {
        walker: "procdump",
        reason: "not implemented".into(),
    })
}

/// Enumerate all memory-mapped (non-private) VAD regions.
///
/// Private VADs (anonymous allocations) are excluded; only file-backed
/// mappings are returned. The `file_path` field is left empty because
/// path resolution requires additional kernel symbol walking.
pub fn list_mapped_files(vads: &[WinVadInfo]) -> Vec<MappedFileRegion> {
    vads.iter()
        .filter(|v| !v.is_private)
        .map(|v| MappedFileRegion {
            start_vaddr: v.start_vaddr,
            end_vaddr: v.end_vaddr,
            file_path: String::new(),
            protection: v.protection,
        })
        .collect()
}

/// Reconstruct an on-disk PE layout from an in-memory PE image.
///
/// In-memory PEs have sections mapped to their `VirtualAddress` offsets;
/// on-disk PEs place sections at their `PointerToRawData` offsets.
/// This function copies headers verbatim and remaps each section.
///
/// # Errors
///
/// Returns `WalkFailed` until implemented.
pub fn reconstruct_pe(_in_memory: &[u8]) -> crate::Result<Vec<u8>> {
    Err(crate::Error::WalkFailed {
        walker: "reconstruct_pe",
        reason: "not implemented".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{WinProcessInfo, WinVadInfo};

    // ── FakeReader ────────────────────────────────────────────────────────────

    struct FakeReader {
        base: u64,
        data: Vec<u8>,
    }

    impl FakeReader {
        fn new(base: u64, data: Vec<u8>) -> Self {
            Self { base, data }
        }
    }

    impl MemReader for FakeReader {
        fn read_region(&self, vaddr: u64, len: usize) -> crate::Result<Vec<u8>> {
            if vaddr < self.base {
                return Ok(vec![0u8; len]);
            }
            let off = (vaddr - self.base) as usize;
            if off >= self.data.len() {
                return Ok(vec![0u8; len]);
            }
            let n = len.min(self.data.len() - off);
            let mut out = vec![0u8; len];
            out[..n].copy_from_slice(&self.data[off..off + n]);
            Ok(out)
        }
    }

    // ── build_memory_pe ───────────────────────────────────────────────────────

    /// Build a valid AMD64 PE in memory layout (sections at VirtualAddress offsets).
    fn build_memory_pe() -> Vec<u8> {
        let mut buf = vec![0u8; 0x3000];

        // DOS header
        buf[0] = b'M';
        buf[1] = b'Z';
        // e_lfanew at 0x3C
        let e_lfanew: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

        // PE signature at 0x80
        let pe_sig_offset = e_lfanew as usize;
        buf[pe_sig_offset..pe_sig_offset + 4].copy_from_slice(b"PE\0\0");

        // COFF header at pe_sig_offset + 4
        let coff = pe_sig_offset + 4;
        // Machine: AMD64 = 0x8664
        buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        // NumberOfSections = 2
        buf[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
        // SizeOfOptionalHeader = 240 (0xF0)
        buf[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        // Characteristics
        buf[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());

        // Optional header at coff + 20
        let opt = coff + 20;
        // Magic: PE32+ = 0x20B
        buf[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        // SectionAlignment at opt+56
        buf[opt + 56..opt + 60].copy_from_slice(&0x1000u32.to_le_bytes());
        // FileAlignment at opt+60
        buf[opt + 60..opt + 64].copy_from_slice(&0x0200u32.to_le_bytes());
        // SizeOfImage at opt+56+0x38 = opt+112 ... actually layout:
        // opt+56: SectionAlignment, opt+60: FileAlignment
        // SizeOfImage at opt+56 (PE32+ optional header layout):
        //   +0:  Magic(2), MajorLinkerVersion(1), MinorLinkerVersion(1)
        //   +4:  SizeOfCode(4)
        //   +8:  SizeOfInitializedData(4)
        //   +12: SizeOfUninitializedData(4)
        //   +16: AddressOfEntryPoint(4)
        //   +20: BaseOfCode(4)
        //   +24: ImageBase(8)
        //   +32: SectionAlignment(4)
        //   +36: FileAlignment(4)
        //   ...
        //   +56: SizeOfImage(4)
        //   +60: SizeOfHeaders(4)
        //   +64: CheckSum(4)
        //   ...
        //   +92: NumberOfRvaAndSizes(4)
        //   +96: DataDirectory[16]

        // Fix: reset and use correct PE32+ optional header field offsets
        // Magic at opt+0
        buf[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        // ImageBase at opt+24
        buf[opt + 24..opt + 32].copy_from_slice(&0x0000000140000000u64.to_le_bytes());
        // SectionAlignment at opt+32
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        // FileAlignment at opt+36
        buf[opt + 36..opt + 40].copy_from_slice(&0x0200u32.to_le_bytes());
        // SizeOfImage at opt+56
        buf[opt + 56..opt + 60].copy_from_slice(&0x4000u32.to_le_bytes());
        // SizeOfHeaders at opt+60
        buf[opt + 60..opt + 64].copy_from_slice(&0x0400u32.to_le_bytes());
        // NumberOfRvaAndSizes at opt+92
        buf[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());

        // Section headers start at opt + 240 = pe_sig_offset+4+20+240
        let sect = opt + 240; // = 0x80 + 4 + 20 + 240 = 0x80 + 264 = 0x188

        // Section 0: .text
        // Name (8 bytes)
        buf[sect..sect + 8].copy_from_slice(b".text\0\0\0");
        // VirtualSize at sect+8
        buf[sect + 8..sect + 12].copy_from_slice(&0x0200u32.to_le_bytes());
        // VirtualAddress at sect+12
        buf[sect + 12..sect + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        // SizeOfRawData at sect+16
        buf[sect + 16..sect + 20].copy_from_slice(&0x0200u32.to_le_bytes());
        // PointerToRawData at sect+20
        buf[sect + 20..sect + 24].copy_from_slice(&0x0400u32.to_le_bytes());

        // Section 1: .data (40 bytes per section header)
        let sect1 = sect + 40;
        buf[sect1..sect1 + 8].copy_from_slice(b".data\0\0\0");
        // VirtualSize
        buf[sect1 + 8..sect1 + 12].copy_from_slice(&0x0100u32.to_le_bytes());
        // VirtualAddress
        buf[sect1 + 12..sect1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        // SizeOfRawData
        buf[sect1 + 16..sect1 + 20].copy_from_slice(&0x0200u32.to_le_bytes());
        // PointerToRawData
        buf[sect1 + 20..sect1 + 24].copy_from_slice(&0x0600u32.to_le_bytes());

        // Section data in memory layout
        // .text at VirtualAddress 0x1000
        for b in buf[0x1000..0x1200].iter_mut() {
            *b = 0xCC;
        }
        // .data at VirtualAddress 0x2000
        for b in buf[0x2000..0x2100].iter_mut() {
            *b = 0xDD;
        }

        buf
    }

    // ── reconstruct_pe tests (RED — stub returns WalkFailed) ─────────────────

    #[test]
    fn reconstruct_pe_fails_on_empty_input() {
        assert!(reconstruct_pe(b"").is_err());
    }

    #[test]
    fn reconstruct_pe_fails_on_garbage() {
        assert!(reconstruct_pe(b"GARBAGE").is_err());
    }

    #[test]
    fn reconstruct_pe_remaps_text_section_to_disk_offset() {
        let mem_pe = build_memory_pe();
        let disk = reconstruct_pe(&mem_pe).expect("should succeed on valid PE");
        assert!(!disk.is_empty());
        assert!(disk.len() > 0x600);
        assert_eq!(disk[0x400], 0xCC, ".text not at disk offset 0x400");
    }

    #[test]
    fn reconstruct_pe_remaps_data_section_to_disk_offset() {
        let mem_pe = build_memory_pe();
        let disk = reconstruct_pe(&mem_pe).expect("should succeed");
        assert_eq!(disk[0x600], 0xDD, ".data not at disk offset 0x600");
    }

    #[test]
    fn reconstruct_pe_preserves_dos_header() {
        let mem_pe = build_memory_pe();
        let disk = reconstruct_pe(&mem_pe).expect("should succeed");
        assert_eq!(&disk[0..2], b"MZ");
        let e_lfanew = u32::from_le_bytes([disk[0x3C], disk[0x3D], disk[0x3E], disk[0x3F]]);
        assert_eq!(e_lfanew, 0x80);
    }

    // ── dump_region_inner tests (PASS in RED) ─────────────────────────────────

    #[test]
    fn dump_region_inner_reads_correct_bytes() {
        let data: Vec<u8> = (0u8..=255).collect();
        let reader = FakeReader::new(0x1000, data.clone());
        let result = dump_region_inner(&reader, 0x1000, 16).unwrap();
        assert_eq!(result, &data[..16]);
    }

    #[test]
    fn dump_region_inner_returns_zeros_for_unmapped() {
        let reader = FakeReader::new(0x5000, vec![0xAB; 0x100]);
        let result = dump_region_inner(&reader, 0x1000, 8).unwrap();
        assert_eq!(result, vec![0u8; 8]);
    }

    // ── moddump_inner stub test (PASS in RED) ─────────────────────────────────

    #[test]
    fn moddump_inner_stub_returns_error() {
        let reader = FakeReader::new(0x1000, vec![0u8; 0x100]);
        assert!(moddump_inner(&reader, "test.dll", 0x1000, 0x100).is_err());
    }

    // ── procdump_inner stub test (PASS in RED) ────────────────────────────────

    #[test]
    fn procdump_inner_stub_returns_error() {
        let reader = FakeReader::new(0x1000, vec![0u8; 0x100]);
        let process = WinProcessInfo {
            pid: 4,
            ppid: 0,
            image_name: "System".into(),
            create_time: 0,
            exit_time: 0,
            cr3: 0,
            peb_addr: 0,
            vaddr: 0,
            thread_count: 1,
            is_wow64: false,
        };
        assert!(procdump_inner(&reader, &process, &[]).is_err());
    }

    // ── list_mapped_files tests (PASS in RED) ─────────────────────────────────

    #[test]
    fn list_mapped_files_excludes_private_vads() {
        let vads = vec![
            WinVadInfo {
                pid: 1,
                image_name: "t".into(),
                start_vaddr: 0x1000,
                end_vaddr: 0x1FFF,
                protection: 4,
                protection_str: "RW".into(),
                is_private: true,
            },
            WinVadInfo {
                pid: 1,
                image_name: "t".into(),
                start_vaddr: 0x2000,
                end_vaddr: 0x2FFF,
                protection: 2,
                protection_str: "RO".into(),
                is_private: false,
            },
        ];
        let mapped = list_mapped_files(&vads);
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].start_vaddr, 0x2000);
    }

    #[test]
    fn list_mapped_files_empty_on_all_private() {
        let vads = vec![WinVadInfo {
            pid: 1,
            image_name: "p".into(),
            start_vaddr: 0,
            end_vaddr: 0xFFF,
            protection: 4,
            protection_str: "RW".into(),
            is_private: true,
        }];
        assert!(list_mapped_files(&vads).is_empty());
    }
}
