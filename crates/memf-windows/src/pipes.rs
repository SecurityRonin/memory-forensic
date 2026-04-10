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
    // Resolve ObpRootDirectoryObject → root _OBJECT_DIRECTORY pointer.
    let root_ptr_addr = match reader.symbols().symbol_address("ObpRootDirectoryObject") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    let root_dir_addr = {
        let bytes = match reader.read_bytes(root_ptr_addr, 8) {
            Ok(b) => b,
            Err(_) => return Ok(Vec::new()),
        };
        u64::from_le_bytes(bytes.try_into().expect("8 bytes"))
    };

    if root_dir_addr == 0 {
        return Ok(Vec::new());
    }

    // Walk the path: root → "Device" → "NamedPipe".
    let named_pipe_dir = match find_subdir_by_path(reader, root_dir_addr, &["Device", "NamedPipe"])
    {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // Enumerate all objects in the NamedPipe directory.
    let entries = walk_directory(reader, named_pipe_dir)?;

    let pipes = entries
        .into_iter()
        .map(|(name, _body_addr)| {
            let classification = classify_pipe(&name);
            NamedPipeInfo {
                name,
                is_suspicious: classification.is_some(),
                suspicion_reason: classification,
            }
        })
        .collect();

    Ok(pipes)
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
    for (depth, segment) in segments.iter().enumerate() {
        if depth >= MAX_DIR_DEPTH {
            return None;
        }
        let entries = walk_directory(reader, dir_addr).ok()?;
        let found = entries.into_iter().find(|(name, _)| name == segment);
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
    let lower = name.to_ascii_lowercase();

    // ── Cobalt Strike beacon / SSH / post-exploitation pipes ──
    if lower.starts_with("msagent_") {
        return Some("Cobalt Strike beacon pipe (msagent_*)".into());
    }
    if lower.starts_with("msse-") && lower.ends_with("-server") {
        return Some("Cobalt Strike beacon pipe (MSSE-*-server)".into());
    }
    // postex_ssh_* is Cobalt Strike SSH, must match BEFORE generic postex_*
    if lower.starts_with("postex_ssh_") {
        return Some("Cobalt Strike SSH pipe (postex_ssh_*)".into());
    }

    // ── PsExec / lateral-movement variants ──
    if lower.starts_with("psexec") {
        return Some("PsExec lateral movement pipe".into());
    }
    if lower.starts_with("remcom") {
        return Some("PsExec variant (RemCom) lateral movement pipe".into());
    }
    if lower.starts_with("csexec") {
        return Some("PsExec variant (CsExec) lateral movement pipe".into());
    }

    // ── Meterpreter post-exploitation ──
    // Generic postex_* (without ssh_) is Meterpreter
    if lower.starts_with("postex_") {
        return Some("Meterpreter post-exploitation pipe (postex_*)".into());
    }

    // ── GUID-like random pipe names (8-4-4-4-12 hex) ──
    if is_guid_like(&lower) {
        return Some("GUID-like random pipe name (possible C2 channel)".into());
    }

    None
}

/// Check whether a string matches the GUID format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
/// where each `x` is a hex digit.
fn is_guid_like(s: &str) -> bool {
    // GUID = 8-4-4-4-12 = 36 characters total with hyphens
    if s.len() != 36 {
        return false;
    }

    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if b != b'-' {
                    return false;
                }
            }
            _ => {
                if !b.is_ascii_hexdigit() {
                    return false;
                }
            }
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

    fn make_test_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
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
        // msagent_* pattern
        let reason = classify_pipe("msagent_dc01").unwrap();
        assert!(
            reason.contains("Cobalt Strike"),
            "expected 'Cobalt Strike' in reason, got: {reason}"
        );

        // MSSE-*-server pattern
        let reason = classify_pipe("MSSE-1234-server").unwrap();
        assert!(
            reason.contains("Cobalt Strike"),
            "expected 'Cobalt Strike' in reason, got: {reason}"
        );

        // postex_ssh_* pattern
        let reason = classify_pipe("postex_ssh_1234").unwrap();
        assert!(
            reason.contains("Cobalt Strike"),
            "expected 'Cobalt Strike' in reason, got: {reason}"
        );
    }

    #[test]
    fn classify_pipe_psexec_variants() {
        // psexec
        let reason = classify_pipe("psexecsvc").unwrap();
        assert!(
            reason.contains("PsExec"),
            "expected 'PsExec' in reason, got: {reason}"
        );

        // remcom
        let reason = classify_pipe("remcomsvc").unwrap();
        assert!(
            reason.contains("PsExec"),
            "expected 'PsExec' in reason, got: {reason}"
        );

        // csexec
        let reason = classify_pipe("csexecsvc").unwrap();
        assert!(
            reason.contains("PsExec"),
            "expected 'PsExec' in reason, got: {reason}"
        );
    }

    #[test]
    fn classify_pipe_meterpreter() {
        let reason = classify_pipe("postex_1234").unwrap();
        assert!(
            reason.contains("Meterpreter"),
            "expected 'Meterpreter' in reason, got: {reason}"
        );
    }

    #[test]
    fn classify_pipe_guid_like() {
        // Standard GUID: 8-4-4-4-12 hex chars
        let reason = classify_pipe("deadbeef-1234-5678-abcd-0123456789ab").unwrap();
        assert!(
            reason.contains("GUID"),
            "expected 'GUID' in reason, got: {reason}"
        );
    }

    #[test]
    fn classify_pipe_benign() {
        // Normal Windows pipes should NOT be flagged
        assert!(classify_pipe("lsass").is_none());
        assert!(classify_pipe("wkssvc").is_none());
        assert!(classify_pipe("srvsvc").is_none());
        assert!(classify_pipe("spoolss").is_none());
        assert!(classify_pipe("ntsvcs").is_none());
    }

    // ─────────────────────────────────────────────────────────────────────
    // walk_named_pipes tests
    // ─────────────────────────────────────────────────────────────────────

    // ─────────────────────────────────────────────────────────────────────
    // is_guid_like tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn is_guid_like_valid_guid() {
        // Standard GUID format
        assert!(is_guid_like("deadbeef-1234-5678-abcd-0123456789ab"));
        // All uppercase hex digits are also valid (lowercased before call in classify_pipe,
        // but is_guid_like itself checks the string as given)
        assert!(is_guid_like("DEADBEEF-1234-5678-ABCD-0123456789AB"));
    }

    #[test]
    fn is_guid_like_wrong_length() {
        // Too short (35 chars)
        assert!(!is_guid_like("deadbeef-1234-5678-abcd-0123456789a"));
        // Too long (37 chars)
        assert!(!is_guid_like("deadbeef-1234-5678-abcd-0123456789abc"));
        // Empty string
        assert!(!is_guid_like(""));
    }

    #[test]
    fn is_guid_like_wrong_hyphen_positions() {
        // Hyphen at wrong position (position 7 instead of 8)
        assert!(!is_guid_like("deadbee-f1234-5678-abcd-0123456789ab"));
    }

    #[test]
    fn is_guid_like_non_hex_chars() {
        // 'z' is not a hex digit
        assert!(!is_guid_like("deadbeef-1234-5678-abcd-0123456789az"));
    }

    #[test]
    fn is_guid_like_missing_hyphens() {
        // All hex digits, correct length but no hyphens
        assert!(!is_guid_like("deadbeef12345678abcd0123456789ab__"));
    }

    #[test]
    fn classify_pipe_guid_like_uppercase_roundtrip() {
        // classify_pipe lowercases before calling is_guid_like
        let reason = classify_pipe("DEADBEEF-1234-5678-ABCD-0123456789AB").unwrap();
        assert!(reason.contains("GUID"), "uppercase GUID should be flagged: {reason}");
    }

    #[test]
    fn classify_pipe_non_guid_36_chars() {
        // 36 chars but with non-hex / wrong hyphen placement → not GUID → not suspicious
        let name = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"; // x is not hex
        assert!(
            classify_pipe(name).is_none(),
            "non-hex GUID-length string should not be suspicious"
        );
    }

    #[test]
    fn walk_named_pipes_no_symbol() {
        // Build a reader with NO symbols at all — the ISF preset does
        // include ObpRootDirectoryObject, so we test with a reader whose
        // root directory pointer is zero (null) to simulate "no pipes found".
        let root_dir_ptr_paddr: u64 = 0x0010_0000;
        let ptb = PageTableBuilder::new()
            .map_4k(OBP_ROOT_DIR_OBJ_VADDR, root_dir_ptr_paddr, flags::WRITABLE)
            // Write zero as the root directory address (null pointer)
            .write_phys_u64(root_dir_ptr_paddr, 0);

        let reader = make_test_reader(ptb);
        let pipes = walk_named_pipes(&reader).unwrap();
        assert!(pipes.is_empty(), "expected empty Vec for null root dir");
    }

    // ── find_subdir_by_path / walk_named_pipes with non-null root dir ─

    /// walk_named_pipes: root_dir_addr is non-null but points to an empty
    /// _OBJECT_DIRECTORY (all 37 bucket pointers zero). find_subdir_by_path
    /// will not find "Device" → returns None → walk returns empty Vec.
    /// Covers the find_subdir_by_path body and the non-null root_dir branch.
    #[test]
    fn walk_named_pipes_non_null_root_empty_directory_returns_empty() {
        let root_dir_addr: u64 = 0xFFFF_8000_0200_0000;
        let root_dir_paddr: u64 = 0x00F0_0000; // within 16MB synthetic mem

        // ObpRootDirectoryObject points to root_dir_addr
        let root_dir_ptr_paddr: u64 = 0x00F1_0000;

        // Root dir page: 37 buckets × 8 bytes = 296 bytes — all zeros (empty dir).
        let root_dir_page = vec![0u8; 0x1000];

        let ptb = PageTableBuilder::new()
            .map_4k(OBP_ROOT_DIR_OBJ_VADDR, root_dir_ptr_paddr, flags::WRITABLE)
            .write_phys_u64(root_dir_ptr_paddr, root_dir_addr)
            .map_4k(root_dir_addr, root_dir_paddr, flags::WRITABLE)
            .write_phys(root_dir_paddr, &root_dir_page);

        let reader = make_test_reader(ptb);
        let pipes = walk_named_pipes(&reader).unwrap();
        assert!(
            pipes.is_empty(),
            "empty root directory (no Device subdir) should return empty Vec"
        );
    }

    /// find_subdir_by_path: depth limit (MAX_DIR_DEPTH) guard is never exceeded
    /// in normal usage, but we can test that the loop iterates and returns None
    /// when Device is not found after exhausting the directory.
    /// This exercises find_subdir_by_path's for loop body with depth=0 (first segment).
    #[test]
    fn find_subdir_by_path_device_not_found_returns_none() {
        // An unmapped directory address (walk_directory returns Err → ok()? = None).
        let reader = {
            let isf = IsfBuilder::windows_kernel_preset().build_json();
            let resolver = IsfResolver::from_value(&isf).unwrap();
            let (cr3, mem) = PageTableBuilder::new().build();
            let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
            ObjectReader::new(vas, Box::new(resolver))
        };

        let result = find_subdir_by_path(&reader, 0xDEAD_BEEF_0000, &["Device", "NamedPipe"]);
        assert!(result.is_none(), "unmapped dir_addr should return None from find_subdir_by_path");
    }

    // ─────────────────────────────────────────────────────────────────────
    // walk_named_pipes: full path through Device → NamedPipe → pipe objects
    // ─────────────────────────────────────────────────────────────────────

    /// Helper: encode a Rust &str as UTF-16LE bytes.
    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// Write a minimal named-object block at `obj_page_offset` within `buf`.
    ///
    /// Layout (matching `object_directory.rs` preset offsets):
    ///   +0x00  _OBJECT_HEADER_NAME_INFO (0x20 bytes)
    ///     .Name (_UNICODE_STRING) at +0x10:
    ///       Length/MaxLength at +0x10/+0x12 (u16)
    ///       Buffer pointer   at +0x18 (u64)
    ///   +0x20  _OBJECT_HEADER (0x30 bytes to Body)
    ///     InfoMask at +0x1a = 0x02 (NAME_INFO bit)
    ///   +0x50  Body (returned as the object body address)
    ///
    /// The UTF-16LE name data is written at `str_offset` in `buf`.
    /// Returns the *virtual* address of the object body.
    fn write_obj(
        buf: &mut Vec<u8>,
        obj_page_offset: usize,
        page_vaddr: u64,
        name: &str,
        str_offset: usize,
    ) -> u64 {
        let utf16 = utf16le(name);
        let len = utf16.len() as u16;
        buf[str_offset..str_offset + utf16.len()].copy_from_slice(&utf16);

        // _OBJECT_HEADER_NAME_INFO at obj_page_offset
        let ni = obj_page_offset;
        // Name._UNICODE_STRING: Length at +0x10, MaxLength at +0x12, Buffer at +0x18
        buf[ni + 0x10..ni + 0x12].copy_from_slice(&len.to_le_bytes());
        buf[ni + 0x12..ni + 0x14].copy_from_slice(&len.to_le_bytes());
        let str_vaddr = page_vaddr + str_offset as u64;
        buf[ni + 0x18..ni + 0x20].copy_from_slice(&str_vaddr.to_le_bytes());

        // _OBJECT_HEADER at obj_page_offset + 0x20: InfoMask at +0x1a = 0x02
        buf[obj_page_offset + 0x20 + 0x1a] = 0x02;

        // Body at obj_page_offset + 0x50
        page_vaddr + (obj_page_offset + 0x50) as u64
    }

    /// Write an `_OBJECT_DIRECTORY_ENTRY` at `entry_offset` in `buf`.
    /// Layout from ISF preset: ChainLink at 0, Object at 8, HashValue at 0x10.
    fn write_entry(buf: &mut Vec<u8>, entry_offset: usize, chain_link: u64, object_body: u64) {
        buf[entry_offset..entry_offset + 8].copy_from_slice(&chain_link.to_le_bytes());
        buf[entry_offset + 8..entry_offset + 16].copy_from_slice(&object_body.to_le_bytes());
    }

    /// Set bucket `bucket_idx` of a directory page starting at `dir_page_offset` in `buf`.
    fn set_bucket_ptr(buf: &mut Vec<u8>, dir_page_offset: usize, bucket_idx: usize, entry_vaddr: u64) {
        let off = dir_page_offset + bucket_idx * 8;
        buf[off..off + 8].copy_from_slice(&entry_vaddr.to_le_bytes());
    }

    /// walk_named_pipes: full two-level directory traversal.
    ///
    /// Sets up:
    ///   root directory → "Device" subdir body → "NamedPipe" subdir body → pipe object "msagent_test"
    ///
    /// Exercises lines 44–78: root_dir_addr != 0, find_subdir_by_path finds Device and NamedPipe,
    /// walk_directory on NamedPipe returns the pipe entry, classify_pipe classifies it.
    ///
    /// All physical addresses are within the 16 MB SyntheticPhysMem limit.
    #[test]
    fn walk_named_pipes_full_path_finds_suspicious_pipe() {
        // Virtual addresses (kernel space, high canonical).
        let root_dir_ptr_paddr: u64   = 0x0001_0000; // holds the pointer read from ObpRootDirectoryObject
        let root_dir_vaddr: u64       = 0xFFFF_8000_0011_0000;
        let root_dir_paddr: u64       = 0x0011_0000;

        let device_dir_vaddr: u64     = 0xFFFF_8000_0012_0000;
        let device_dir_paddr: u64     = 0x0012_0000;

        let named_pipe_dir_vaddr: u64 = 0xFFFF_8000_0013_0000;
        let named_pipe_dir_paddr: u64 = 0x0013_0000;

        let pipe_obj_vaddr: u64       = 0xFFFF_8000_0014_0000;
        let pipe_obj_paddr: u64       = 0x0014_0000;

        // ── Page 1: root directory ────────────────────────────────────────────
        // _OBJECT_DIRECTORY: 37 × 8-byte bucket pointers starting at offset 0.
        // We place "Device" dir entry at offset 0x300 and its named-object at 0x400.
        let mut root_page = vec![0u8; 0x1000];

        // "Device" named object at root_page offset 0x400, string at 0x800.
        // Body of "Device" object == device_dir_vaddr (the actual _OBJECT_DIRECTORY).
        // But write_obj returns page_vaddr + (obj_offset + 0x50).
        // We need the body to *be* device_dir_vaddr so find_subdir_by_path navigates there.
        // To do this: place the object such that obj_offset + 0x50 maps to device_dir_vaddr.
        // Simpler: just write the object at root_page[0x400] (body = root_dir_vaddr + 0x450)
        // and then store device_dir_vaddr at entry.Object instead.
        //
        // Actually, the _OBJECT_DIRECTORY_ENTRY.Object field IS the body address.
        // The name is read FROM that body via read_object_name (walks backward to header).
        // So we need the name info to be BEHIND the body address, on the same or an
        // accessible page.
        //
        // Easiest: put the "Device" name-info/header/body block on the root_dir_page
        // so body addr = root_dir_vaddr + obj_body_offset, then the ENTRY.Object = that addr.
        // After find_subdir_by_path finds "Device", dir_addr = body_addr = root_dir_vaddr+offset.
        // Then walk_directory(reader, dir_addr) tries to read 37*8 bytes from that addr.
        // That addr is still on root_dir_page (it points into it) — so we need the second-level
        // "Device" directory buckets to live at that offset within root_dir_page too.
        // This becomes layout-complex; instead use a separate page for the Device directory.
        //
        // Strategy:
        //   - root_dir_page: bucket[0] → root_entry at root_dir_vaddr+0x300
        //     root_entry.Object = device_body_addr (on device_dir_page)
        //     root_entry object name "Device" is read from device_body_addr - 0x50 - 0x20 = device_dir_vaddr + 0x190
        //     so name_info must be at device_dir_vaddr + 0x190, header at device_dir_vaddr + 0x1b0, body at device_dir_vaddr + 0x1e0
        //   - device_dir_page: bucket[0] at offset 0 → device_entry at device_dir_vaddr+0x300
        //     device_entry.Object = named_pipe_body on named_pipe_dir_page
        //     etc.

        // ── Simpler layout: all name-info/header/body on same page as the directory ──
        //
        // root_dir_page (vaddr=root_dir_vaddr, paddr=root_dir_paddr):
        //   [0x000] = _OBJECT_DIRECTORY hash buckets (37 × 8 = 296 bytes)
        //   [0x200] = _OBJECT_DIRECTORY_ENTRY for "Device" dir
        //   [0x300] = _OBJECT_HEADER_NAME_INFO for "Device" (0x20 bytes)
        //   [0x320] = _OBJECT_HEADER for "Device" (InfoMask=0x02)
        //   [0x350] = Body of "Device" = root_dir_vaddr + 0x350
        //             BUT we need walk_directory(reader, body) to find "NamedPipe"
        //             which means body should == device_dir_vaddr.
        //
        // The cleanest solution: use the body address as a pointer to device_dir_vaddr.
        // Entry.Object = device_dir_vaddr + 0x350 where the header lives on device_dir_page.

        // Root page: name-info/header for "Device" at offset 0x300, body at 0x350.
        // The entry at 0x200 points to body @ root_dir_vaddr+0x350.
        // But find_subdir_by_path sets dir_addr = body_addr = root_dir_vaddr + 0x350
        // and then calls walk_directory(reader, root_dir_vaddr + 0x350).
        // walk_directory reads 37*8=296 bytes from root_dir_vaddr+0x350 — still on root_dir_page.
        // So the "Device" subdir's buckets live at root_dir_vaddr+0x350.
        // We place "NamedPipe" entry at 0x600, its name-info/header/body at 0x700.

        // ── Root dir page layout ─────────────────────────────────────────────
        // [0x000] Root _OBJECT_DIRECTORY (37 buckets × 8). Bucket[0] → 0x200.
        // [0x200] Entry for "Device": ChainLink=0, Object=root_dir_vaddr+0x350.
        // [0x300] _OBJECT_HEADER_NAME_INFO for "Device": Name at +0x10.
        // [0x320] _OBJECT_HEADER for "Device": InfoMask=0x02 at +0x1a.
        // [0x350] Body of "Device" = used as dir addr for second walk_directory call.
        // [0x350] also = start of Device's _OBJECT_DIRECTORY (37 buckets × 8).
        //         Bucket[0] → 0x600.
        // [0x600] Entry for "NamedPipe": ChainLink=0, Object=device_dir_vaddr+0x150.
        //         We put NamedPipe's name-info/header/body on device_dir_page.
        // String data for "Device" at [0x900].
        //
        // device_dir_page (vaddr=device_dir_vaddr, paddr=device_dir_paddr):
        // [0x100] _OBJECT_HEADER_NAME_INFO for "NamedPipe": Name at +0x10.
        // [0x120] _OBJECT_HEADER for "NamedPipe": InfoMask=0x02.
        // [0x150] Body of "NamedPipe" = used as dir addr for pipe enumeration.
        // [0x150] also = start of NamedPipe's _OBJECT_DIRECTORY (37 buckets × 8).
        //         Bucket[0] → device_dir_vaddr+0x500.
        // [0x500] Entry for pipe object "msagent_test": ChainLink=0, Object=pipe_obj_vaddr+0x050.
        // String data for "NamedPipe" at [0x800].
        //
        // pipe_obj_page (vaddr=pipe_obj_vaddr, paddr=pipe_obj_paddr):
        // [0x000] _OBJECT_HEADER_NAME_INFO for "msagent_test": Name at +0x10.
        // [0x020] _OBJECT_HEADER for "msagent_test": InfoMask=0x02.
        // [0x050] Body of "msagent_test".
        // String data at [0x200].

        // Write "Device" name-info/header: name_info at root_page[0x300], header at [0x320].
        {
            let dev_utf16 = utf16le("Device");
            let dev_len = dev_utf16.len() as u16;
            let str_vaddr = root_dir_vaddr + 0x900;
            root_page[0x900..0x900 + dev_utf16.len()].copy_from_slice(&dev_utf16);
            // name_info.Name at +0x10 (offset 0x310)
            root_page[0x310..0x312].copy_from_slice(&dev_len.to_le_bytes()); // Length
            root_page[0x312..0x314].copy_from_slice(&dev_len.to_le_bytes()); // MaxLength
            root_page[0x318..0x320].copy_from_slice(&str_vaddr.to_le_bytes()); // Buffer
            // header InfoMask at 0x320 + 0x1a = 0x33a
            root_page[0x33a] = 0x02;
        }
        // Device body = root_dir_vaddr + 0x350. Entry at 0x200.
        let device_body_in_root = root_dir_vaddr + 0x350;
        write_entry(&mut root_page, 0x200, 0, device_body_in_root);
        // Root bucket[0] → entry at root_dir_vaddr+0x200
        set_bucket_ptr(&mut root_page, 0, 0, root_dir_vaddr + 0x200);

        // Device's _OBJECT_DIRECTORY starts at offset 0x350; bucket[0] → 0x600
        set_bucket_ptr(&mut root_page, 0x350, 0, root_dir_vaddr + 0x600);

        // Write "NamedPipe" entry at root_page[0x600]: Object = device_dir_vaddr+0x150
        let named_pipe_body = device_dir_vaddr + 0x150;
        write_entry(&mut root_page, 0x600, 0, named_pipe_body);

        // ── device_dir_page: NamedPipe name-info/header, NamedPipe dir, pipe entry ────
        let mut device_page = vec![0u8; 0x1000];

        // "NamedPipe" name-info at 0x100, header at 0x120, body at 0x150.
        {
            let np_utf16 = utf16le("NamedPipe");
            let np_len = np_utf16.len() as u16;
            let str_vaddr = device_dir_vaddr + 0x800;
            device_page[0x800..0x800 + np_utf16.len()].copy_from_slice(&np_utf16);
            device_page[0x110..0x112].copy_from_slice(&np_len.to_le_bytes()); // Length
            device_page[0x112..0x114].copy_from_slice(&np_len.to_le_bytes()); // MaxLength
            device_page[0x118..0x120].copy_from_slice(&str_vaddr.to_le_bytes()); // Buffer
            // header InfoMask at 0x120 + 0x1a = 0x13a
            device_page[0x13a] = 0x02;
        }
        // NamedPipe _OBJECT_DIRECTORY at 0x150; bucket[0] → device_dir_vaddr+0x500
        set_bucket_ptr(&mut device_page, 0x150, 0, device_dir_vaddr + 0x500);

        // Write pipe "msagent_test" entry at device_page[0x500]: Object = pipe_obj_vaddr+0x050
        let pipe_body = pipe_obj_vaddr + 0x050;
        write_entry(&mut device_page, 0x500, 0, pipe_body);

        // ── pipe_obj_page: "msagent_test" name-info/header/body ─────────────────
        let mut pipe_page = vec![0u8; 0x1000];
        {
            let pipe_utf16 = utf16le("msagent_test");
            let pipe_len = pipe_utf16.len() as u16;
            let str_vaddr = pipe_obj_vaddr + 0x200;
            pipe_page[0x200..0x200 + pipe_utf16.len()].copy_from_slice(&pipe_utf16);
            pipe_page[0x010..0x012].copy_from_slice(&pipe_len.to_le_bytes());
            pipe_page[0x012..0x014].copy_from_slice(&pipe_len.to_le_bytes());
            pipe_page[0x018..0x020].copy_from_slice(&str_vaddr.to_le_bytes());
            // header at 0x020, InfoMask at 0x020 + 0x1a = 0x03a
            pipe_page[0x03a] = 0x02;
        }

        // Build the page table.
        // ObpRootDirectoryObject (symbol vaddr 0xFFFFF805_5A4A0000) → root_dir_ptr_paddr
        // root_dir_ptr_paddr holds: root_dir_vaddr
        let ptb = PageTableBuilder::new()
            .map_4k(OBP_ROOT_DIR_OBJ_VADDR, root_dir_ptr_paddr, flags::WRITABLE)
            .write_phys_u64(root_dir_ptr_paddr, root_dir_vaddr)
            .map_4k(root_dir_vaddr, root_dir_paddr, flags::WRITABLE)
            .write_phys(root_dir_paddr, &root_page)
            .map_4k(device_dir_vaddr, device_dir_paddr, flags::WRITABLE)
            .write_phys(device_dir_paddr, &device_page)
            .map_4k(pipe_obj_vaddr, pipe_obj_paddr, flags::WRITABLE)
            .write_phys(pipe_obj_paddr, &pipe_page);

        let reader = make_test_reader(ptb);
        let pipes = walk_named_pipes(&reader).unwrap();

        // Must find at least one pipe (msagent_test) flagged as suspicious.
        assert!(!pipes.is_empty(), "should enumerate at least one named pipe");
        let pipe = &pipes[0];
        assert_eq!(pipe.name, "msagent_test");
        assert!(pipe.is_suspicious, "msagent_test should be flagged as suspicious");
        assert!(
            pipe.suspicion_reason
                .as_deref()
                .unwrap_or("")
                .contains("Cobalt Strike"),
            "should identify as Cobalt Strike pipe"
        );
    }

    /// find_subdir_by_path: called with empty segments slice → returns initial dir_addr.
    #[test]
    fn find_subdir_by_path_empty_segments_returns_start() {
        let (cr3, mem) = PageTableBuilder::new().build();
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let start_addr = 0xFFFF_8000_DEAD_0000;
        let result = find_subdir_by_path(&reader, start_addr, &[]);
        assert_eq!(result, Some(start_addr), "empty segments should return the start addr");
    }

    /// NamedPipeInfo serializes correctly.
    #[test]
    fn named_pipe_info_serializes() {
        let info = NamedPipeInfo {
            name: "msagent_dc01".to_string(),
            is_suspicious: true,
            suspicion_reason: Some("Cobalt Strike beacon pipe (msagent_*)".to_string()),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("msagent_dc01"));
        assert!(json.contains("\"is_suspicious\":true"));
        assert!(json.contains("Cobalt Strike"));
    }
}
