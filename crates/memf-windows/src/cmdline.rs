//! Windows process command line extraction.
//!
//! Reads command lines from `_EPROCESS` -> `_PEB` ->
//! `_RTL_USER_PROCESS_PARAMETERS.CommandLine` for each process.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;
use crate::{Error, Result, WinCmdlineInfo};

/// Walk all processes and extract their command lines.
///
/// For each process with a non-null PEB, reads
/// `PEB.ProcessParameters.CommandLine`. Kernel processes (PEB = 0)
/// are skipped.
pub fn walk_cmdlines<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<WinCmdlineInfo>> {
    let eproc_addrs = reader.walk_list_with(
        ps_head_vaddr,
        "_LIST_ENTRY",
        "Flink",
        "_EPROCESS",
        "ActiveProcessLinks",
    )?;

    let mut results = Vec::new();

    for eproc_addr in eproc_addrs {
        let pid: u64 = reader.read_field(eproc_addr, "_EPROCESS", "UniqueProcessId")?;
        let peb_addr: u64 = reader.read_field(eproc_addr, "_EPROCESS", "Peb")?;
        let image_name = reader.read_field_string(eproc_addr, "_EPROCESS", "ImageFileName", 15)?;

        // Skip kernel processes (no PEB)
        if peb_addr == 0 {
            continue;
        }

        // PEB.ProcessParameters
        let params_ptr: u64 = reader.read_field(peb_addr, "_PEB", "ProcessParameters")?;
        if params_ptr == 0 {
            continue;
        }

        // ProcessParameters.CommandLine is a _UNICODE_STRING
        let cmdline_offset = reader
            .symbols()
            .field_offset("_RTL_USER_PROCESS_PARAMETERS", "CommandLine")
            .ok_or_else(|| {
                Error::Walker("missing _RTL_USER_PROCESS_PARAMETERS.CommandLine offset".into())
            })?;
        let cmdline_ustr_addr = params_ptr.wrapping_add(cmdline_offset);
        let cmdline = read_unicode_string(reader, cmdline_ustr_addr)?;

        results.push(WinCmdlineInfo {
            pid,
            image_name,
            cmdline,
        });
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Encode a Rust &str as UTF-16LE bytes.
    fn utf16le_bytes(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
    }

    /// Build a _UNICODE_STRING in a byte buffer.
    fn build_unicode_string_at(buf: &mut [u8], offset: usize, length: u16, buffer_ptr: u64) {
        buf[offset..offset + 2].copy_from_slice(&length.to_le_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&length.to_le_bytes());
        buf[offset + 8..offset + 16].copy_from_slice(&buffer_ptr.to_le_bytes());
    }

    fn make_win_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    // Offsets from windows_kernel_preset:
    const EPROCESS_PID: u64 = 0x440;
    const EPROCESS_LINKS: u64 = 0x448;
    const EPROCESS_PPID: u64 = 0x540;
    const EPROCESS_PEB: u64 = 0x550;
    const EPROCESS_IMAGE_NAME: u64 = 0x5A8;
    const EPROCESS_CREATE_TIME: u64 = 0x430;
    const EPROCESS_EXIT_TIME: u64 = 0x438;
    const KPROCESS_DTB: u64 = 0x28;
    // PEB offsets
    const PEB_PROCESS_PARAMETERS: u64 = 0x20;
    // _RTL_USER_PROCESS_PARAMETERS offsets
    const PARAMS_COMMAND_LINE: u64 = 0x70;

    #[test]
    fn extracts_cmdline_from_process() {
        // Layout:
        //   Page 1: PsActiveProcessHead sentinel + _EPROCESS
        //   Page 2: PEB + _RTL_USER_PROCESS_PARAMETERS + string data

        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let peb_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0080_1000;
        let peb_paddr: u64 = 0x0080_2000;

        // Sentinel: head → eproc → head (single process)
        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(peb_vaddr, peb_paddr, flags::WRITABLE)
            // Sentinel
            .write_phys_u64(head_paddr, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(head_paddr + 8, eproc_vaddr + EPROCESS_LINKS)
            // _EPROCESS
            .write_phys_u64(eproc_paddr + KPROCESS_DTB, 0x1AB000)
            .write_phys_u64(eproc_paddr + EPROCESS_CREATE_TIME, 132800000000000000)
            .write_phys_u64(eproc_paddr + EPROCESS_EXIT_TIME, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PID, 1234)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS, head_vaddr) // Flink → head
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS + 8, head_vaddr) // Blink → head
            .write_phys_u64(eproc_paddr + EPROCESS_PPID, 4)
            .write_phys_u64(eproc_paddr + EPROCESS_PEB, peb_vaddr)
            .write_phys(eproc_paddr + EPROCESS_IMAGE_NAME, b"notepad.exe\0");

        // PEB: ProcessParameters → params_vaddr
        let params_vaddr = peb_vaddr + 0x200;
        let mut peb_data = vec![0u8; 4096];
        peb_data[PEB_PROCESS_PARAMETERS as usize..PEB_PROCESS_PARAMETERS as usize + 8]
            .copy_from_slice(&params_vaddr.to_le_bytes());

        // _RTL_USER_PROCESS_PARAMETERS.CommandLine at offset 0x70
        let cmdline_text = "notepad.exe C:\\Users\\test\\doc.txt";
        let cmdline_utf16 = utf16le_bytes(cmdline_text);
        let cmdline_len = cmdline_utf16.len() as u16;
        let cmdline_buf_vaddr = peb_vaddr + 0x400;
        let params_offset = 0x200usize;
        build_unicode_string_at(
            &mut peb_data,
            params_offset + PARAMS_COMMAND_LINE as usize,
            cmdline_len,
            cmdline_buf_vaddr,
        );

        // String data
        let str_offset = 0x400usize;
        peb_data[str_offset..str_offset + cmdline_utf16.len()].copy_from_slice(&cmdline_utf16);

        let ptb = ptb.write_phys(peb_paddr, &peb_data);

        let reader = make_win_reader(ptb);
        let results = walk_cmdlines(&reader, head_vaddr).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pid, 1234);
        assert_eq!(results[0].image_name, "notepad.exe");
        assert_eq!(results[0].cmdline, cmdline_text);
    }

    #[test]
    fn skips_kernel_processes_no_peb() {
        // System process (PEB = 0) should be skipped.
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0080_1000;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys_u64(head_paddr, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(head_paddr + 8, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(eproc_paddr + KPROCESS_DTB, 0x1AB000)
            .write_phys_u64(eproc_paddr + EPROCESS_CREATE_TIME, 132800000000000000)
            .write_phys_u64(eproc_paddr + EPROCESS_EXIT_TIME, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PID, 4)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS + 8, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_PPID, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PEB, 0) // No PEB
            .write_phys(eproc_paddr + EPROCESS_IMAGE_NAME, b"System\0");

        let reader = make_win_reader(ptb);
        let results = walk_cmdlines(&reader, head_vaddr).unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn handles_empty_cmdline() {
        // Process with PEB but empty CommandLine.
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let peb_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0080_1000;
        let peb_paddr: u64 = 0x0080_2000;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(peb_vaddr, peb_paddr, flags::WRITABLE)
            .write_phys_u64(head_paddr, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(head_paddr + 8, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(eproc_paddr + KPROCESS_DTB, 0x1AB000)
            .write_phys_u64(eproc_paddr + EPROCESS_CREATE_TIME, 132800000000000000)
            .write_phys_u64(eproc_paddr + EPROCESS_EXIT_TIME, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PID, 500)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS + 8, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_PPID, 4)
            .write_phys_u64(eproc_paddr + EPROCESS_PEB, peb_vaddr)
            .write_phys(eproc_paddr + EPROCESS_IMAGE_NAME, b"idle.exe\0");

        // PEB with ProcessParameters pointing to params, but CommandLine Length=0
        let params_vaddr = peb_vaddr + 0x200;
        let mut peb_data = vec![0u8; 4096];
        peb_data[PEB_PROCESS_PARAMETERS as usize..PEB_PROCESS_PARAMETERS as usize + 8]
            .copy_from_slice(&params_vaddr.to_le_bytes());
        // CommandLine: Length=0, Buffer=0 (already zero)
        let ptb = ptb.write_phys(peb_paddr, &peb_data);

        let reader = make_win_reader(ptb);
        let results = walk_cmdlines(&reader, head_vaddr).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pid, 500);
        assert!(results[0].cmdline.is_empty());
    }
}
