//! Windows process environment variable extraction.
//!
//! Reads environment blocks from `_EPROCESS` -> `_PEB` ->
//! `_RTL_USER_PROCESS_PARAMETERS.Environment`. The environment block
//! is a UTF-16LE encoded sequence of `KEY=VALUE\0` pairs terminated
//! by a double null.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, WinEnvVarInfo};

/// Maximum bytes to read from an environment block.
const MAX_ENV_SIZE: usize = 32768;

/// Walk all processes and extract their environment variables.
///
/// For each process with a non-null PEB, reads the environment
/// block from `PEB.ProcessParameters.Environment`. Kernel processes
/// (PEB = 0) are skipped.
pub fn walk_envvars<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<WinEnvVarInfo>> {
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

        // ProcessParameters.Environment
        let env_ptr: u64 =
            reader.read_field(params_ptr, "_RTL_USER_PROCESS_PARAMETERS", "Environment")?;

        if env_ptr == 0 {
            continue;
        }

        // Read the environment block (up to MAX_ENV_SIZE bytes)
        let Ok(raw) = reader.read_bytes(env_ptr, MAX_ENV_SIZE) else {
            continue;
        };

        let pairs = parse_env_block(&raw);
        for (variable, value) in pairs {
            results.push(WinEnvVarInfo {
                pid,
                image_name: image_name.clone(),
                variable,
                value,
            });
        }
    }

    Ok(results)
}

/// Parse a UTF-16LE environment block into key-value pairs.
///
/// The block is a sequence of `KEY=VALUE\0` strings terminated by
/// a double null (`\0\0`).
fn parse_env_block(raw: &[u8]) -> Vec<(String, String)> {
    let mut pairs = Vec::new();

    // Convert raw bytes to u16 code units
    let u16s: Vec<u16> = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();

    let mut start = 0;
    for (i, &ch) in u16s.iter().enumerate() {
        if ch == 0 {
            if i == start {
                // Double null — end of block
                break;
            }
            let entry = String::from_utf16_lossy(&u16s[start..i]);
            if let Some(eq_pos) = entry.find('=') {
                let key = entry[..eq_pos].to_string();
                let val = entry[eq_pos + 1..].to_string();
                pairs.push((key, val));
            }
            start = i + 1;
        }
    }

    pairs
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn utf16le_bytes(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
    }

    fn make_win_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// Build a UTF-16LE environment block from key-value pairs.
    fn build_env_block(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut block = Vec::new();
        for (key, val) in pairs {
            let entry = format!("{key}={val}");
            block.extend(utf16le_bytes(&entry));
            block.extend([0u8; 2]); // null terminator (one UTF-16 null)
        }
        block.extend([0u8; 2]); // double null terminator
        block
    }

    const EPROCESS_PID: u64 = 0x440;
    const EPROCESS_LINKS: u64 = 0x448;
    const EPROCESS_PPID: u64 = 0x540;
    const EPROCESS_PEB: u64 = 0x550;
    const EPROCESS_IMAGE_NAME: u64 = 0x5A8;
    const EPROCESS_CREATE_TIME: u64 = 0x430;
    const EPROCESS_EXIT_TIME: u64 = 0x438;
    const KPROCESS_DTB: u64 = 0x28;
    const PEB_PROCESS_PARAMETERS: u64 = 0x20;
    const PARAMS_ENVIRONMENT: u64 = 0x80;

    #[test]
    fn parse_env_block_basic() {
        let block = build_env_block(&[("PATH", "C:\\Windows"), ("HOME", "C:\\Users\\test")]);
        let pairs = parse_env_block(&block);

        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], ("PATH".to_string(), "C:\\Windows".to_string()));
        assert_eq!(
            pairs[1],
            ("HOME".to_string(), "C:\\Users\\test".to_string())
        );
    }

    #[test]
    fn parse_env_block_empty() {
        // Just a double null
        let block = vec![0u8; 4];
        let pairs = parse_env_block(&block);
        assert!(pairs.is_empty());
    }

    #[test]
    fn extracts_envvars_from_process() {
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let peb_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let env_vaddr: u64 = 0xFFFF_8000_0010_3000;
        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0080_1000;
        let peb_paddr: u64 = 0x0080_2000;
        let env_paddr: u64 = 0x0080_3000;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(peb_vaddr, peb_paddr, flags::WRITABLE)
            .map_4k(env_vaddr, env_paddr, flags::WRITABLE)
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
            .write_phys(eproc_paddr + EPROCESS_IMAGE_NAME, b"cmd.exe\0");

        // PEB → ProcessParameters
        let params_vaddr = peb_vaddr + 0x200;
        let mut peb_data = vec![0u8; 4096];
        peb_data[PEB_PROCESS_PARAMETERS as usize..PEB_PROCESS_PARAMETERS as usize + 8]
            .copy_from_slice(&params_vaddr.to_le_bytes());
        // ProcessParameters.Environment → env_vaddr
        let params_off = 0x200usize;
        peb_data[params_off + PARAMS_ENVIRONMENT as usize
            ..params_off + PARAMS_ENVIRONMENT as usize + 8]
            .copy_from_slice(&env_vaddr.to_le_bytes());
        let ptb = ptb.write_phys(peb_paddr, &peb_data);

        // Environment block
        let env_block =
            build_env_block(&[("USERPROFILE", "C:\\Users\\test"), ("LANG", "en_US.UTF-8")]);
        let ptb = ptb.write_phys(env_paddr, &env_block);

        let reader = make_win_reader(ptb);
        let results = walk_envvars(&reader, head_vaddr).unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].pid, 500);
        assert_eq!(results[0].image_name, "cmd.exe");
        assert_eq!(results[0].variable, "USERPROFILE");
        assert_eq!(results[0].value, "C:\\Users\\test");
        assert_eq!(results[1].variable, "LANG");
        assert_eq!(results[1].value, "en_US.UTF-8");
    }

    #[test]
    fn skips_kernel_processes_no_peb() {
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
            .write_phys_u64(eproc_paddr + EPROCESS_PEB, 0)
            .write_phys(eproc_paddr + EPROCESS_IMAGE_NAME, b"System\0");

        let reader = make_win_reader(ptb);
        let results = walk_envvars(&reader, head_vaddr).unwrap();

        assert!(results.is_empty());
    }
}
