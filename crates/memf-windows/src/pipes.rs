//! Windows kernel named pipe enumeration for C2/lateral-movement detection.
//!
//! Walks the kernel Object Manager namespace tree starting from
//! `ObpRootDirectoryObject`, navigates to `\Device\NamedPipe`, and
//! enumerates all pipe objects within that directory.  Each pipe name
//! is checked against known-suspicious patterns (Cobalt Strike beacon
//! pipes, PsExec service pipes, Meterpreter post-exploitation pipes,
//! GUID-like random pipe names, etc.).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::object_directory::walk_directory;

/// Maximum recursion depth when walking nested object directories to
/// reach `\Device\NamedPipe`.
const MAX_DIR_DEPTH: usize = 8;

/// Information about a single named pipe found in kernel memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NamedPipeInfo {
    /// The name of the pipe.
    pub name: String,
    /// Whether this pipe name matches a known-suspicious pattern.
    pub is_suspicious: bool,
    /// Human-readable reason for flagging, if suspicious.
    pub suspicion_reason: Option<String>,
}

/// Enumerate named pipes from the object directory.
///
/// Resolves `ObpRootDirectoryObject`, walks through `\Device\NamedPipe`,
/// and returns information about each pipe found.  Returns an empty `Vec`
/// if the root directory symbol is missing or the path cannot be resolved.
pub fn walk_named_pipes<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<NamedPipeInfo>> {
    let root_dir_sym_addr = match reader.symbols().symbol_address("ObpRootDirectoryObject") {
        Some(v) => v,
        None => return Ok(Vec::new()),
    };

    // Read the pointer stored at the symbol address
    let root_dir_addr: u64 = match reader.read_bytes(root_dir_sym_addr, 8) {
        Ok(bytes) => u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")),
        Err(_) => return Ok(Vec::new()),
    };

    if root_dir_addr == 0 {
        return Ok(Vec::new());
    }

    let named_pipe_dir = match find_subdir_by_path(reader, root_dir_addr, &["Device", "NamedPipe"]) {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    let entries = walk_directory(reader, named_pipe_dir).unwrap_or_default();

    let mut results = Vec::new();
    for (name, _body_addr) in entries {
        let (is_suspicious, suspicion_reason) = match classify_pipe(&name) {
            Some(reason) => (true, Some(reason)),
            None => (false, None),
        };
        results.push(NamedPipeInfo {
            name,
            is_suspicious,
            suspicion_reason,
        });
    }

    Ok(results)
}

/// Walk a path of subdirectory names from a starting directory address.
///
/// Returns the object body address of the final directory in the path,
/// or `None` if any segment is not found.
fn find_subdir_by_path<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    mut dir_addr: u64,
    segments: &[&str],
) -> Option<u64> {
    for (_depth, segment) in segments.iter().enumerate().take(MAX_DIR_DEPTH) {
        let entries = walk_directory(reader, dir_addr).unwrap_or_default();
        let found = entries.into_iter().find(|(name, _)| name.eq_ignore_ascii_case(segment));
        match found {
            Some((_name, body_addr)) => dir_addr = body_addr,
            None => return None,
        }
    }
    Some(dir_addr)
}

/// Check if a pipe name matches known C2/lateral-movement patterns.
///
/// Returns `Some(reason)` if the name is suspicious, `None` otherwise.
/// Patterns are checked in order of specificity to avoid false positives.
pub fn classify_pipe(name: &str) -> Option<String> {
    let lower = name.to_lowercase();

    // Cobalt Strike: MSSE-*-server
    if lower.starts_with("msse-") && lower.ends_with("-server") {
        return Some("Cobalt Strike beacon pipe (MSSE-*-server)".to_string());
    }
    // msagent_* — Cobalt Strike post-ex
    if lower.starts_with("msagent_") {
        return Some("Cobalt Strike msagent post-ex pipe".to_string());
    }
    // postex_ssh_ takes priority over postex_
    if lower.starts_with("postex_ssh_") {
        return Some("Cobalt Strike postex_ssh pipe".to_string());
    }
    // postex_ — Cobalt Strike post-ex
    if lower.starts_with("postex_") {
        return Some("Cobalt Strike postex pipe".to_string());
    }
    // PsExec pipes
    if lower.starts_with("psexesvc") || lower.starts_with("psexec") {
        return Some("PsExec service pipe".to_string());
    }
    // RemCom
    if lower.starts_with("remcom_") {
        return Some("RemCom lateral movement pipe".to_string());
    }
    // CSExec
    if lower.starts_with("csexec") {
        return Some("CSExec lateral movement pipe".to_string());
    }
    // GUID-like pipe names (random C2 named pipes)
    if is_guid_like(&lower) {
        return Some("GUID-like pipe name (likely random C2 pipe)".to_string());
    }
    None
}

/// Check whether a string matches the GUID format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
/// where each `x` is a hex digit.
fn is_guid_like(s: &str) -> bool {
    // GUID: 8-4-4-4-12 hex digits with hyphens = 36 chars total
    if s.len() != 36 {
        return false;
    }
    let bytes = s.as_bytes();
    // Hyphen positions: 8, 13, 18, 23
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return false;
    }
    // All other positions must be hex digits
    for (i, &b) in bytes.iter().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            continue;
        }
        if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ISF preset symbol addresses (same as mutant.rs tests)
    const OBP_ROOT_DIR_OBJ_VADDR: u64 = 0xFFFFF805_5A4A0000;

    fn make_isf_with_obp_root(root_sym_vaddr: u64) -> serde_json::Value {
        IsfBuilder::new()
            // _OBJECT_DIRECTORY: 37 bucket pointers (u64 each) at offset 0
            .add_struct("_OBJECT_DIRECTORY", 37 * 8 + 16)
            .add_field("_OBJECT_DIRECTORY", "HashBuckets", 0, "pointer")
            // _OBJECT_DIRECTORY_ENTRY
            .add_struct("_OBJECT_DIRECTORY_ENTRY", 24)
            .add_field("_OBJECT_DIRECTORY_ENTRY", "ChainLink", 0, "pointer")
            .add_field("_OBJECT_DIRECTORY_ENTRY", "Object", 8, "pointer")
            .add_field("_OBJECT_DIRECTORY_ENTRY", "HashValue", 0x10, "unsigned int")
            // _OBJECT_HEADER_NAME_INFO (size=0x20, Name at 0x10)
            .add_struct("_OBJECT_HEADER_NAME_INFO", 0x20)
            .add_field("_OBJECT_HEADER_NAME_INFO", "Name", 0x10, "pointer")
            // _UNICODE_STRING
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            // _OBJECT_HEADER (size=0x30): Body at 0x30, InfoMask at 0x1a
            .add_struct("_OBJECT_HEADER", 0x30)
            .add_field("_OBJECT_HEADER", "Body", 0x30, "pointer")
            .add_field("_OBJECT_HEADER", "InfoMask", 0x1a, "unsigned char")
            .add_symbol("ObpRootDirectoryObject", root_sym_vaddr)
            .build_json()
    }

    fn make_test_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = make_isf_with_obp_root(OBP_ROOT_DIR_OBJ_VADDR);
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    // ─────────────────────────────────────────────────────────────────────
    // classify_pipe tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn classify_pipe_cobalt_strike() {
        assert!(classify_pipe("MSSE-1234-server").is_some());
        assert!(classify_pipe("msagent_test").is_some());
        assert!(classify_pipe("postex_1234").is_some());
    }

    #[test]
    fn classify_pipe_psexec_variants() {
        assert!(classify_pipe("psexesvc").is_some());
        assert!(classify_pipe("PSEXEC_svc").is_some());
        assert!(classify_pipe("remcom_12345").is_some());
        assert!(classify_pipe("csexec_svc").is_some());
    }

    #[test]
    fn classify_pipe_meterpreter() {
        // meterpreter uses GUID-like names
        assert!(classify_pipe("12345678-1234-1234-1234-123456789abc").is_some());
    }

    #[test]
    fn classify_pipe_guid_like() {
        assert!(classify_pipe("aabbccdd-eeff-0011-2233-445566778899").is_some());
    }

    #[test]
    fn classify_pipe_benign() {
        assert!(classify_pipe("lsass").is_none());
        assert!(classify_pipe("wkssvc").is_none());
        assert!(classify_pipe("ntsvcs").is_none());
    }

    // ─────────────────────────────────────────────────────────────────────
    // is_guid_like tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn is_guid_like_valid_guid() {
        assert!(is_guid_like("12345678-1234-1234-1234-123456789abc"));
    }

    #[test]
    fn is_guid_like_wrong_length() {
        assert!(!is_guid_like("12345678-1234-1234-1234-12345678abc"));
        assert!(!is_guid_like("12345678-1234-1234-1234-1234567890abc"));
    }

    #[test]
    fn is_guid_like_wrong_hyphen_positions() {
        assert!(!is_guid_like("1234567-81234-1234-1234-123456789abc"));
    }

    #[test]
    fn is_guid_like_non_hex_chars() {
        assert!(!is_guid_like("1234567g-1234-1234-1234-123456789abc"));
    }

    #[test]
    fn is_guid_like_missing_hyphens() {
        assert!(!is_guid_like("123456781234123412341234567890ab"));
    }

    #[test]
    fn classify_pipe_guid_like_uppercase_roundtrip() {
        // classify_pipe lowercases before checking
        let guid = "AABBCCDD-EEFF-0011-2233-445566778899";
        assert!(classify_pipe(guid).is_some());
    }

    #[test]
    fn classify_pipe_non_guid_36_chars() {
        // 36 chars but not hex in right places
        assert!(classify_pipe("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz").is_none());
    }

    #[test]
    fn walk_named_pipes_no_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("_OBJECT_DIRECTORY", 37 * 8 + 16)
            .add_field("_OBJECT_DIRECTORY", "HashBuckets", 0, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_named_pipes(&reader).unwrap();
        assert!(result.is_empty());
    }

    // ── find_subdir_by_path / walk_named_pipes with non-null root dir ─

    /// walk_named_pipes: root_dir_addr is non-null but points to an empty
    /// _OBJECT_DIRECTORY (all 37 bucket pointers zero). find_subdir_by_path
    /// will not find "Device" → returns None → walk returns empty Vec.
    #[test]
    fn walk_named_pipes_non_null_root_empty_directory_returns_empty() {
        // Symbol addr holds a pointer to root_dir_addr (mapped page)
        const SYM_VADDR:  u64 = OBP_ROOT_DIR_OBJ_VADDR;
        const SYM_PADDR:  u64 = 0x00A0_0000;
        const ROOT_VADDR: u64 = 0xFFFF_8000_0030_0000;
        const ROOT_PADDR: u64 = 0x0030_0000;

        let isf = make_isf_with_obp_root(SYM_VADDR);
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&ROOT_VADDR.to_le_bytes());

        let root_page = vec![0u8; 4096]; // all zeros → empty directory

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .map_4k(ROOT_VADDR, ROOT_PADDR, flags::WRITABLE)
            .write_phys(ROOT_PADDR, &root_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_named_pipes(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// find_subdir_by_path: Device not found after exhausting directory → None.
    #[test]
    fn find_subdir_by_path_device_not_found_returns_none() {
        const SYM_VADDR:  u64 = OBP_ROOT_DIR_OBJ_VADDR;
        const SYM_PADDR:  u64 = 0x00A1_0000;
        const ROOT_VADDR: u64 = 0xFFFF_8000_0031_0000;
        const ROOT_PADDR: u64 = 0x0031_0000;

        let isf = make_isf_with_obp_root(SYM_VADDR);
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&ROOT_VADDR.to_le_bytes());
        let root_page = vec![0u8; 4096];

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .map_4k(ROOT_VADDR, ROOT_PADDR, flags::WRITABLE)
            .write_phys(ROOT_PADDR, &root_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        // Directly test find_subdir_by_path returns None
        let result = find_subdir_by_path(&reader, ROOT_VADDR, &["Device"]);
        assert!(result.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────
    // walk_named_pipes: full path through Device → NamedPipe → pipe objects
    // ─────────────────────────────────────────────────────────────────────

    /// Helper: encode a Rust &str as UTF-16LE bytes.
    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
    }

    /// Write a minimal named-object block into `buf` at `obj_page_offset`.
    /// String data is placed at `str_offset` (must be within same buf/page).
    /// Returns the virtual address of the object body (+0x50 from obj start).
    fn write_obj(
        buf: &mut Vec<u8>,
        obj_page_offset: usize,
        page_vaddr: u64,
        name: &str,
        str_offset: usize,
    ) -> u64 {
        let name_bytes = utf16le(name);
        let name_len = name_bytes.len() as u16;
        // str_offset is within the same page — compute its vaddr accordingly
        let str_vaddr = page_vaddr + str_offset as u64;
        // _OBJECT_HEADER_NAME_INFO.Name (_UNICODE_STRING) at obj_page_offset + 0x10
        buf[obj_page_offset + 0x10..obj_page_offset + 0x12].copy_from_slice(&name_len.to_le_bytes());
        buf[obj_page_offset + 0x12..obj_page_offset + 0x14].copy_from_slice(&name_len.to_le_bytes());
        buf[obj_page_offset + 0x18..obj_page_offset + 0x20].copy_from_slice(&str_vaddr.to_le_bytes());
        // _OBJECT_HEADER at +0x20: InfoMask at +0x1a = 0x02 (has NAME_INFO)
        buf[obj_page_offset + 0x20 + 0x1a] = 0x02;
        // Write the name string at str_offset within buf
        buf[str_offset..str_offset + name_bytes.len()].copy_from_slice(&name_bytes);
        // Body is at obj_page_offset + 0x50
        page_vaddr + obj_page_offset as u64 + 0x50
    }

    /// Write an `_OBJECT_DIRECTORY_ENTRY` at `entry_offset` in `buf`.
    fn write_entry(buf: &mut Vec<u8>, entry_offset: usize, chain_link: u64, object_body: u64) {
        buf[entry_offset..entry_offset + 8].copy_from_slice(&chain_link.to_le_bytes());
        buf[entry_offset + 8..entry_offset + 16].copy_from_slice(&object_body.to_le_bytes());
    }

    /// Set bucket `bucket_idx` of a directory page at `dir_page_offset` in `buf`.
    fn set_bucket_ptr(buf: &mut Vec<u8>, dir_page_offset: usize, bucket_idx: usize, entry_vaddr: u64) {
        let off = dir_page_offset + bucket_idx * 8;
        buf[off..off + 8].copy_from_slice(&entry_vaddr.to_le_bytes());
    }

    /// walk_named_pipes: full two-level directory traversal.
    ///
    /// Layout uses page-aligned body addresses: each object's body sits at offset 0
    /// of its own 4K-aligned page, so it can be used directly as a directory page.
    /// Object header (name_info + _OBJECT_HEADER) lives in a separate page before it.
    ///
    ///   HDR page (vaddr H):  name_info(+0x00) + _OBJECT_HEADER(+0x20)
    ///                        string inline at +0x100
    ///                        body_vaddr = H + 0x50 → must be page-aligned
    ///
    /// We achieve this by placing object headers at page_base + 0xFB0 so that
    /// body = page_base + 0xFB0 + 0x50 = page_base + 0x1000 = next_page_base.
    /// That means the body IS the start of the next 4K-aligned page.
    ///
    ///   Layout per object (two consecutive 4K pages A, B):
    ///     A + 0xFB0: _OBJECT_HEADER_NAME_INFO (0x20 bytes) + _OBJECT_HEADER (0x30 bytes)
    ///                → body = A + 0xFB0 + 0x50 = A + 0x1000 = B
    ///     A + 0xE00: inline string for the name
    ///     B + 0x000...: used as directory (37 bucket pointers)
    #[test]
    fn walk_named_pipes_full_path_finds_suspicious_pipe() {
        // Each object takes two consecutive 4K pages (header page + body/dir page).
        // Naming: DEV_H = Device header page, DEV_B = Device body/dir page, etc.

        const SYM_VADDR:   u64 = OBP_ROOT_DIR_OBJ_VADDR;
        const SYM_PADDR:   u64 = 0x00A2_0000;
        // Root directory page
        const ROOT_VADDR:  u64 = 0xFFFF_8000_0040_0000;
        const ROOT_PADDR:  u64 = 0x0040_0000;
        // Root entry (points to Device object body)
        const ROOT_E_VADDR: u64 = 0xFFFF_8000_0041_0000;
        const ROOT_E_PADDR: u64 = 0x0041_0000;
        // Device object: header at DEV_H, body at DEV_B (= DEV_H + 0x1000)
        // Header page base addresses. Body = hdr_vaddr + 0x1000 (next 4K page).
        // HDR_OFF=0xFB0, body = hdr_vaddr + 0xFB0 + 0x50 = hdr_vaddr + 0x1000.
        const DEV_H_VADDR:  u64 = 0xFFFF_8000_0042_0000;
        const DEV_H_PADDR:  u64 = 0x0042_0000;
        const DEV_B_VADDR:  u64 = 0xFFFF_8000_0042_1000; // = DEV_H_VADDR + 0x1000 ✓
        const DEV_B_PADDR:  u64 = 0x0042_1000;
        const DEV_E_VADDR:  u64 = 0xFFFF_8000_0043_0000;
        const DEV_E_PADDR:  u64 = 0x0043_0000;
        const PIPE_H_VADDR: u64 = 0xFFFF_8000_0044_0000;
        const PIPE_H_PADDR: u64 = 0x0044_0000;
        const PIPE_B_VADDR: u64 = 0xFFFF_8000_0044_1000; // = PIPE_H_VADDR + 0x1000 ✓
        const PIPE_B_PADDR: u64 = 0x0044_1000;
        const PIPE_E_VADDR: u64 = 0xFFFF_8000_0045_0000;
        const PIPE_E_PADDR: u64 = 0x0045_0000;
        const MS_H_VADDR:   u64 = 0xFFFF_8000_0046_0000;
        const MS_H_PADDR:   u64 = 0x0046_0000;
        const MS_B_VADDR:   u64 = 0xFFFF_8000_0046_1000; // = MS_H_VADDR + 0x1000 ✓
        const MS_B_PADDR:   u64 = 0x0046_1000;
        // Entry inside NamedPipe dir pointing to msagent is stored at PIPE_E_VADDR.

        let isf = make_isf_with_obp_root(SYM_VADDR);
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Header offset within header page: 0xFB0
        // body_vaddr = hdr_page_vaddr + 0xFB0 + 0x50 = hdr_page_vaddr + 0x1000 = body_page_vaddr
        const HDR_OFF: usize = 0xFB0;

        // Build a header page for a named object.
        // name_info at HDR_OFF, string at HDR_OFF - 0x200 (so no overlap).
        let make_hdr_page = |hdr_page_vaddr: u64, body_page_vaddr: u64, name: &str| -> Vec<u8> {
            let encoded = utf16le(name);
            let len = encoded.len() as u16;
            // Place string at 0x800 within the header page
            let str_vaddr = hdr_page_vaddr + 0x800;
            let mut page = vec![0u8; 4096];
            // name_info at HDR_OFF: _UNICODE_STRING for the name
            page[HDR_OFF + 0x10..HDR_OFF + 0x12].copy_from_slice(&len.to_le_bytes());
            page[HDR_OFF + 0x12..HDR_OFF + 0x14].copy_from_slice(&len.to_le_bytes());
            page[HDR_OFF + 0x18..HDR_OFF + 0x20].copy_from_slice(&str_vaddr.to_le_bytes());
            // _OBJECT_HEADER at HDR_OFF + 0x20: InfoMask = 0x02
            page[HDR_OFF + 0x20 + 0x1a] = 0x02;
            // Inline string at 0x800
            page[0x800..0x800 + encoded.len()].copy_from_slice(&encoded);
            // Verify body vaddr = hdr_page_vaddr + HDR_OFF + 0x50 = hdr_page_vaddr + 0x1000
            assert_eq!(hdr_page_vaddr + HDR_OFF as u64 + 0x50, body_page_vaddr,
                "body must be at start of next page");
            page
        };

        // Body of each intermediate object doubles as a directory page (bucket[0] = entry_vaddr).
        let make_dir_page = |entry_vaddr: u64| -> Vec<u8> {
            let mut page = vec![0u8; 4096];
            page[0..8].copy_from_slice(&entry_vaddr.to_le_bytes());
            page
        };

        // Entry page: { ChainLink=0, Object=obj_body_vaddr }
        let make_entry_page = |obj_body: u64| -> Vec<u8> {
            let mut page = vec![0u8; 4096];
            page[8..16].copy_from_slice(&obj_body.to_le_bytes());
            page
        };

        // Object body vaddrs (= start of body page)
        let dev_body  = DEV_B_VADDR;
        let pipe_body = PIPE_B_VADDR;
        let ms_body   = MS_B_VADDR;

        // Build pages
        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&ROOT_VADDR.to_le_bytes());

        let root_page      = make_dir_page(ROOT_E_VADDR);
        let root_e_page    = make_entry_page(dev_body);
        let dev_hdr_page   = make_hdr_page(DEV_H_VADDR, DEV_B_VADDR, "Device");
        let dev_dir_page   = make_dir_page(DEV_E_VADDR);
        let dev_e_page     = make_entry_page(pipe_body);
        let pipe_hdr_page  = make_hdr_page(PIPE_H_VADDR, PIPE_B_VADDR, "NamedPipe");
        let pipe_dir_page  = make_dir_page(PIPE_E_VADDR);
        let pipe_e_page    = make_entry_page(ms_body);
        let ms_hdr_page    = make_hdr_page(MS_H_VADDR, MS_B_VADDR, "msagent_test");
        let ms_body_page   = vec![0u8; 4096]; // leaf — not used as directory

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(SYM_VADDR,   SYM_PADDR,   flags::WRITABLE).write_phys(SYM_PADDR,   &sym_page)
            .map_4k(ROOT_VADDR,  ROOT_PADDR,  flags::WRITABLE).write_phys(ROOT_PADDR,  &root_page)
            .map_4k(ROOT_E_VADDR,ROOT_E_PADDR,flags::WRITABLE).write_phys(ROOT_E_PADDR,&root_e_page)
            .map_4k(DEV_H_VADDR, DEV_H_PADDR, flags::WRITABLE).write_phys(DEV_H_PADDR, &dev_hdr_page)
            .map_4k(DEV_B_VADDR, DEV_B_PADDR, flags::WRITABLE).write_phys(DEV_B_PADDR, &dev_dir_page)
            .map_4k(DEV_E_VADDR, DEV_E_PADDR, flags::WRITABLE).write_phys(DEV_E_PADDR, &dev_e_page)
            .map_4k(PIPE_H_VADDR,PIPE_H_PADDR,flags::WRITABLE).write_phys(PIPE_H_PADDR,&pipe_hdr_page)
            .map_4k(PIPE_B_VADDR,PIPE_B_PADDR,flags::WRITABLE).write_phys(PIPE_B_PADDR,&pipe_dir_page)
            .map_4k(PIPE_E_VADDR,PIPE_E_PADDR,flags::WRITABLE).write_phys(PIPE_E_PADDR,&pipe_e_page)
            .map_4k(MS_H_VADDR,  MS_H_PADDR,  flags::WRITABLE).write_phys(MS_H_PADDR,  &ms_hdr_page)
            .map_4k(MS_B_VADDR,  MS_B_PADDR,  flags::WRITABLE).write_phys(MS_B_PADDR,  &ms_body_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let pipes = walk_named_pipes(&reader).unwrap();
        assert_eq!(pipes.len(), 1);
        assert_eq!(pipes[0].name, "msagent_test");
        assert!(pipes[0].is_suspicious);
    }

    /// find_subdir_by_path: called with empty segments slice → returns initial dir_addr.
    #[test]
    fn find_subdir_by_path_empty_segments_returns_start() {
        let reader = make_test_reader(PageTableBuilder::new());
        let result = find_subdir_by_path(&reader, 0xFFFF_8000_DEAD_0000, &[]);
        assert_eq!(result, Some(0xFFFF_8000_DEAD_0000));
    }

    /// NamedPipeInfo serializes correctly.
    #[test]
    fn named_pipe_info_serializes() {
        let info = NamedPipeInfo {
            name: "msagent_test".to_string(),
            is_suspicious: true,
            suspicion_reason: Some("Cobalt Strike msagent post-ex pipe".to_string()),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("msagent_test"));
        assert!(json.contains("Cobalt Strike"));
    }

    /// NamedPipeInfo serializes correctly for benign pipes (suspicion_reason = None).
    #[test]
    fn named_pipe_info_benign_serializes() {
        let info = NamedPipeInfo {
            name: "lsass".to_string(),
            is_suspicious: false,
            suspicion_reason: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("lsass"));
        assert!(json.contains("false"));
    }

    /// classify_pipe: MSSE prefix but missing "-server" suffix → not suspicious.
    #[test]
    fn classify_pipe_msse_no_server_suffix_benign() {
        assert!(classify_pipe("MSSE-1234-client").is_none());
        assert!(classify_pipe("MSSE-1234").is_none());
    }

    /// classify_pipe: postex_ssh_ takes priority over postex_.
    #[test]
    fn classify_pipe_postex_ssh_beats_postex() {
        let reason = classify_pipe("postex_ssh_abc").unwrap();
        assert!(reason.contains("postex_ssh"), "expected ssh-specific reason, got: {reason}");
    }

    /// is_guid_like: string of correct length but hyphen in wrong position.
    #[test]
    fn is_guid_like_hyphen_wrong_position_not_guid() {
        // Hyphen at position 7 instead of 8
        assert!(!is_guid_like("1234567-81234-1234-1234-123456789abc"));
    }

    /// walk_named_pipes: symbol present but ObpRootDirectoryObject read returns null ptr → empty.
    #[test]
    fn walk_named_pipes_root_dir_zero_returns_empty() {
        const SYM_VADDR: u64 = OBP_ROOT_DIR_OBJ_VADDR;
        const SYM_PADDR: u64 = 0x00A3_0000;

        let isf = make_isf_with_obp_root(SYM_VADDR);
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&0u64.to_le_bytes()); // null ptr

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_named_pipes(&reader).unwrap();
        assert!(result.is_empty());
    }
}
