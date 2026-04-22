//! Tmpfs/ramfs inode enumeration for ephemeral file recovery.
//!
//! Walks the kernel `super_blocks` list to find all tmpfs/ramfs superblocks,
//! then enumerates their in-memory inodes via `s_inodes` (`i_sb_list`).
//! Executable or hidden files are flagged as suspicious.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about a file found in an in-memory tmpfs/ramfs filesystem.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TmpfsFileInfo {
    /// Inode number.
    pub inode_number: u64,
    /// Filename recovered from dentry cache (empty if not cached).
    pub filename: String,
    /// File size in bytes.
    pub file_size: u64,
    /// User ID of the file owner.
    pub uid: u32,
    /// Group ID of the file owner.
    pub gid: u32,
    /// File mode (permissions + type bits).
    pub mode: u32,
    /// Last access time (seconds since epoch).
    pub atime_sec: u64,
    /// Last modification time (seconds since epoch).
    pub mtime_sec: u64,
    /// Last status-change time (seconds since epoch).
    pub ctime_sec: u64,
    /// True when the file has the executable bit set or starts with `.` (hidden).
    pub is_suspicious: bool,
}

/// Classify whether a tmpfs file is suspicious.
///
/// A file is suspicious when:
/// - It is a regular file (`S_ISREG`: mode type bits == 0o100000) with any
///   executable bit set (`mode & 0o111 != 0`), or
/// - Its name starts with `.` and has more than one character (hidden file).
///
/// Directories (type bits 0o040000) with execute bits are normal and not flagged.
pub fn classify_tmpfs_file(filename: &str, mode: u32) -> bool {
    // S_IFREG = 0o100000; S_IFMT = 0o170000
    let is_regular_file = (mode & 0o170_000) == 0o100_000;
    let is_exec = is_regular_file && (mode & 0o111) != 0;
    let is_hidden = filename.starts_with('.') && filename.len() > 1;
    is_exec || is_hidden
}

/// Walk all tmpfs/ramfs inodes across all superblocks in memory.
///
/// Returns `Ok(Vec::new())` when the `super_blocks` symbol or required ISF
/// offsets are absent (graceful degradation).
pub fn walk_tmpfs_files<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<TmpfsFileInfo>> {
    // Graceful degradation: require super_blocks symbol.
    let sb_list_addr = match reader.symbols().symbol_address("super_blocks") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // Require super_block.s_list offset to walk the superblock list.
    let sb_list_offset = match reader.symbols().field_offset("super_block", "s_list") {
        Some(off) => off,
        None => return Ok(Vec::new()),
    };

    let mut results = Vec::new();

    // Walk super_blocks list (list_head embedded in super_block at s_list).
    let first_sb_list: u64 = match reader.read_bytes(sb_list_addr, 8) {
        Ok(b) => u64::from_le_bytes(b.try_into().unwrap_or([0u8; 8])),
        Err(_) => return Ok(Vec::new()),
    };

    let mut sb_cursor = first_sb_list;
    let mut sb_guard = 0usize;
    loop {
        if sb_cursor == 0 || sb_cursor == sb_list_addr || sb_guard > 1024 {
            break;
        }
        // Recover super_block base from s_list offset.
        let sb_addr = sb_cursor.saturating_sub(sb_list_offset as u64);

        // Read s_type pointer → file_system_type → name string.
        let s_type_ptr: u64 = match reader.read_field(sb_addr, "super_block", "s_type") {
            Ok(v) => v,
            Err(_) => {
                sb_cursor = match reader.read_bytes(sb_cursor, 8) {
                    Ok(b) => u64::from_le_bytes(b.try_into().unwrap_or([0u8; 8])),
                    Err(_) => break,
                };
                sb_guard += 1;
                continue;
            }
        };

        let is_tmpfs = if s_type_ptr != 0 {
            // file_system_type.name is a `const char *` pointer at offset 0.
            let name_ptr: u64 = reader
                .read_bytes(s_type_ptr, 8)
                .ok()
                .and_then(|b| b.try_into().ok())
                .map(u64::from_le_bytes)
                .unwrap_or(0);
            if name_ptr != 0 {
                let name_bytes: Vec<u8> = reader.read_bytes(name_ptr, 8).unwrap_or_default();
                let fs_name = std::str::from_utf8(&name_bytes)
                    .unwrap_or("")
                    .split('\0')
                    .next()
                    .unwrap_or("");
                fs_name == "tmpfs" || fs_name == "ramfs"
            } else {
                false
            }
        } else {
            false
        };

        if is_tmpfs {
            // Walk s_inodes list: inode.i_sb_list list_head.
            let s_inodes_offset = match reader.symbols().field_offset("super_block", "s_inodes") {
                Some(off) => off,
                None => {
                    sb_cursor = match reader.read_bytes(sb_cursor, 8) {
                        Ok(b) => u64::from_le_bytes(b.try_into().unwrap_or([0u8; 8])),
                        Err(_) => break,
                    };
                    sb_guard += 1;
                    continue;
                }
            };

            let inode_sb_list_offset = match reader.symbols().field_offset("inode", "i_sb_list") {
                Some(off) => off,
                None => {
                    sb_cursor = match reader.read_bytes(sb_cursor, 8) {
                        Ok(b) => u64::from_le_bytes(b.try_into().unwrap_or([0u8; 8])),
                        Err(_) => break,
                    };
                    sb_guard += 1;
                    continue;
                }
            };

            let inode_list_head = sb_addr + s_inodes_offset as u64;
            let first_inode_list: u64 = reader
                .read_bytes(inode_list_head, 8)
                .ok()
                .and_then(|b| b.try_into().ok())
                .map(u64::from_le_bytes)
                .unwrap_or(0);

            let mut inode_cursor = first_inode_list;
            let mut inode_guard = 0usize;
            loop {
                if inode_cursor == 0 || inode_cursor == inode_list_head || inode_guard > 65536 {
                    break;
                }
                let inode_addr = inode_cursor.saturating_sub(inode_sb_list_offset as u64);

                let i_ino: u64 = reader.read_field(inode_addr, "inode", "i_ino").unwrap_or(0);
                let i_size: u64 = reader
                    .read_field(inode_addr, "inode", "i_size")
                    .unwrap_or(0);
                let i_uid: u32 = reader.read_field(inode_addr, "inode", "i_uid").unwrap_or(0);
                let i_gid: u32 = reader.read_field(inode_addr, "inode", "i_gid").unwrap_or(0);
                let i_mode: u32 = reader
                    .read_field(inode_addr, "inode", "i_mode")
                    .unwrap_or(0);
                let atime_sec: u64 = reader
                    .read_field(inode_addr, "inode", "i_atime")
                    .unwrap_or(0);
                let mtime_sec: u64 = reader
                    .read_field(inode_addr, "inode", "i_mtime")
                    .unwrap_or(0);
                let ctime_sec: u64 = reader
                    .read_field(inode_addr, "inode", "i_ctime")
                    .unwrap_or(0);

                // Resolve the filename by walking the inode's i_dentry hlist.
                // i_dentry is an hlist_head whose `first` pointer (if non-null) points
                // at the hlist_node embedded inside the first dentry at offset d_alias.
                // To get the dentry base: dentry_addr = first - d_alias_offset.
                // Then read dentry.d_name_name (the char* pointer) and read the
                // null-terminated string. Falls back to "" on any failure or null pointer.
                let filename: String = (|| -> String {
                    // Read i_dentry.first — the hlist_head first pointer.
                    let first: u64 = reader
                        .read_field(inode_addr, "inode", "i_dentry")
                        .unwrap_or(0);
                    if first == 0 {
                        return String::new();
                    }
                    // d_alias offset tells us how far into dentry the hlist_node sits.
                    let d_alias_offset = reader
                        .symbols()
                        .field_offset("dentry", "d_alias")
                        .unwrap_or(0);
                    let dentry_addr = first.saturating_sub(d_alias_offset);
                    if dentry_addr == 0 {
                        return String::new();
                    }
                    // Read d_name.name pointer (stored as "d_name_name" field on dentry).
                    let name_ptr: u64 = reader
                        .read_field(dentry_addr, "dentry", "d_name_name")
                        .unwrap_or(0);
                    if name_ptr == 0 {
                        return String::new();
                    }
                    // Read up to 256 bytes and split on the first null byte.
                    let bytes = reader.read_bytes(name_ptr, 256).unwrap_or_default();
                    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                    String::from_utf8_lossy(&bytes[..end]).into_owned()
                })();
                let is_suspicious = classify_tmpfs_file(&filename, i_mode);

                results.push(TmpfsFileInfo {
                    inode_number: i_ino,
                    filename,
                    file_size: i_size,
                    uid: i_uid,
                    gid: i_gid,
                    mode: i_mode,
                    atime_sec,
                    mtime_sec,
                    ctime_sec,
                    is_suspicious,
                });

                inode_cursor = match reader.read_bytes(inode_cursor, 8) {
                    Ok(b) => u64::from_le_bytes(b.try_into().unwrap_or([0u8; 8])),
                    Err(_) => break,
                };
                inode_guard += 1;
            }
        }

        sb_cursor = match reader.read_bytes(sb_cursor, 8) {
            Ok(b) => u64::from_le_bytes(b.try_into().unwrap_or([0u8; 8])),
            Err(_) => break,
        };
        sb_guard += 1;
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_no_symbol_reader() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn classify_executable_tmpfs_file_suspicious() {
        assert!(
            classify_tmpfs_file("script.sh", 0o100_755),
            "executable file must be suspicious"
        );
    }

    #[test]
    fn classify_hidden_file_suspicious() {
        assert!(
            classify_tmpfs_file(".hidden_file", 0o100_644),
            "hidden file must be suspicious"
        );
    }

    #[test]
    fn classify_dot_alone_not_suspicious() {
        assert!(
            !classify_tmpfs_file(".", 0o040_755),
            "bare '.' directory must not be suspicious"
        );
    }

    #[test]
    fn classify_normal_tmpfs_file_benign() {
        assert!(
            !classify_tmpfs_file("data.bin", 0o100_644),
            "non-executable non-hidden file must not be suspicious"
        );
    }

    #[test]
    fn classify_executable_and_hidden_suspicious() {
        assert!(
            classify_tmpfs_file(".runme", 0o100_755),
            "executable hidden file must be suspicious"
        );
    }

    #[test]
    fn walk_tmpfs_no_symbol_returns_empty() {
        let reader = make_no_symbol_reader();
        let result = walk_tmpfs_files(&reader).unwrap();
        assert!(
            result.is_empty(),
            "no super_blocks symbol → empty vec expected"
        );
    }

    // --- additional classify_tmpfs_file coverage ---

    #[test]
    fn classify_empty_filename_not_suspicious() {
        // Empty filename: does not start with '.', not executable
        assert!(
            !classify_tmpfs_file("", 0o100_644),
            "empty filename non-executable must not be suspicious"
        );
    }

    #[test]
    fn classify_dot_with_exec_bit_not_suspicious_because_len_1() {
        // "." starts with '.' but len == 1, so hidden check fails.
        // Also a directory (0o040_755) so exec check also fails.
        assert!(
            !classify_tmpfs_file(".", 0o040_755),
            "bare '.' must not be suspicious"
        );
    }

    #[test]
    fn classify_directory_with_exec_bits_not_suspicious() {
        // S_IFDIR = 0o040000; exec bits set but it's not S_IFREG
        assert!(
            !classify_tmpfs_file("mydir", 0o040_755),
            "directory with exec bits must not be suspicious"
        );
    }

    #[test]
    fn classify_regular_file_no_exec_not_suspicious() {
        // S_IFREG = 0o100000, mode 0o600 — no exec bit
        assert!(
            !classify_tmpfs_file("secret.dat", 0o100_600),
            "regular non-executable non-hidden file must not be suspicious"
        );
    }

    #[test]
    fn classify_regular_file_group_exec_suspicious() {
        // Group execute bit (0o010) set on regular file
        assert!(
            classify_tmpfs_file("grpexec", 0o100_610),
            "regular file with group exec bit must be suspicious"
        );
    }

    #[test]
    fn classify_regular_file_other_exec_suspicious() {
        // Other execute bit (0o001) set on regular file
        assert!(
            classify_tmpfs_file("otherexec", 0o100_601),
            "regular file with other exec bit must be suspicious"
        );
    }

    #[test]
    fn classify_dotdot_not_suspicious() {
        // ".." starts with '.' but len == 2; the hidden check passes
        // however ".." is a valid directory reference — verify behaviour is consistent
        // The function does NOT special-case ".."; len > 1 makes it suspicious
        assert!(
            classify_tmpfs_file("..", 0o040_755),
            "'..' is two chars starting with '.'; hidden-check flags it"
        );
    }

    #[test]
    fn classify_non_regular_non_exec_file_benign() {
        // S_IFLNK = 0o120000 — symlink, with rwx bits; not S_IFREG so exec check fails
        assert!(
            !classify_tmpfs_file("mylink", 0o120_777),
            "symlink with rwx bits must not be suspicious (not S_IFREG)"
        );
    }

    // --- walk_tmpfs_files: symbol present but s_list field missing ---

    #[test]
    fn walk_tmpfs_missing_s_list_offset_returns_empty() {
        // Build a reader that HAS the super_blocks symbol but NO s_list field
        let isf = IsfBuilder::new()
            .add_symbol("super_blocks", 0xFFFF_8000_1234_0000)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_tmpfs_files(&reader).unwrap();
        assert!(
            result.is_empty(),
            "missing s_list field_offset → empty vec expected"
        );
    }

    // --- walk_tmpfs_files: symbol + s_list present but read fails (sb_list_addr unreadable) ---

    #[test]
    fn walk_tmpfs_unreadable_first_sb_returns_empty() {
        // super_blocks symbol points to an unmapped address; read_bytes will fail
        let isf = IsfBuilder::new()
            .add_symbol("super_blocks", 0xDEAD_BEEF_0000_0000)
            .add_struct("super_block", 512)
            .add_field("super_block", "s_list", 0, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_tmpfs_files(&reader).unwrap();
        assert!(
            result.is_empty(),
            "unreadable super_blocks address → empty vec expected"
        );
    }

    // --- walk_tmpfs_files: symbol + s_list present, self-pointing list → empty ---
    // Exercises the superblock scanning loop body with an empty (self-pointing) list.
    #[test]
    fn walk_tmpfs_symbol_present_self_pointing_list_returns_empty() {
        use memf_core::test_builders::flags as ptf;

        // super_blocks points to a mapped page; the first 8 bytes (s_list.next)
        // point back to super_blocks itself → loop exits immediately (cursor == sb_list_addr).
        let sym_vaddr: u64 = 0xFFFF_8800_0010_0000;
        let sym_paddr: u64 = 0x0030_0000; // unique paddr, < 16 MB

        let isf = IsfBuilder::new()
            .add_symbol("super_blocks", sym_vaddr)
            .add_struct("super_block", 0x200)
            .add_field("super_block", "s_list", 0x00, "pointer")
            .add_field("super_block", "s_type", 0x08, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Write a page where offset 0 (s_list.next) == sym_vaddr (self-pointer).
        let mut page = [0u8; 4096];
        page[0..8].copy_from_slice(&sym_vaddr.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_tmpfs_files(&reader).unwrap();
        assert!(
            result.is_empty(),
            "self-pointing superblock list → no entries"
        );
    }

    // --- walk_tmpfs_files: first_sb_list != 0 && != sb_list_addr, exercises loop body ---
    // The sb_cursor enters the loop; s_type read fails (unreadable sb_addr), so it
    // advances via read_bytes(sb_cursor) which also fails → breaks out → empty result.
    // This gets the loop-body code path covered without needing tmpfs name matching.
    #[test]
    fn walk_tmpfs_first_sb_nonzero_but_unreadable_sb_body() {
        use memf_core::test_builders::flags as ptf;

        // super_blocks page at sym_vaddr.
        // s_list is at offset 0x10 (sb_list_offset = 0x10).
        // The first 8 bytes at sym_vaddr = some_sb_list_addr pointing INTO a mapped page
        // so that sb_cursor != 0 and != sym_vaddr, and sb_cursor is readable.
        // But s_type (offset 0x08 inside super_block) at sb_addr = sb_cursor - 0x10
        // is NOT mapped → read_field fails → we fall into the advance-cursor branch,
        // which reads sb_cursor's first 8 bytes → they point back to sym_vaddr → loop ends.

        let sym_vaddr: u64 = 0xFFFF_8800_0040_0000; // super_blocks list head
        let sym_paddr: u64 = 0x0040_0000;

        // sb_cursor will be the value stored at sym_vaddr + 0 (first pointer).
        // We want it to be a distinct mapped address so the loop body runs.
        let sb_list_vaddr: u64 = 0xFFFF_8800_0041_0000; // points into the same page region
        let sb_list_paddr: u64 = 0x0041_0000;

        // s_list offset = 0x10 in super_block; s_type at 0x08.
        // sb_addr = sb_cursor - 0x10 → sb_cursor - 0x10 is unmapped → s_type read fails.
        // Then advance: read_bytes(sb_cursor, 8) returns sym_vaddr → loop exits (== sb_list_addr).

        // Page for super_blocks list head: first 8 bytes = sb_list_vaddr.
        let mut sym_page = [0u8; 4096];
        sym_page[0..8].copy_from_slice(&sb_list_vaddr.to_le_bytes());

        // Page for the single fake superblock entry:
        // offset 0 = next pointer = sym_vaddr (so cursor wraps back to list head, ending the loop).
        let mut sb_page = [0u8; 4096];
        sb_page[0..8].copy_from_slice(&sym_vaddr.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_symbol("super_blocks", sym_vaddr)
            .add_struct("super_block", 0x200)
            .add_field("super_block", "s_list", 0x10, "pointer")
            .add_field("super_block", "s_type", 0x08, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &sym_page)
            .map_4k(sb_list_vaddr, sb_list_paddr, ptf::WRITABLE)
            .write_phys(sb_list_paddr, &sb_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // sb_cursor = sb_list_vaddr ≠ 0 and ≠ sym_vaddr → enters loop body.
        // s_type read on sb_addr (sb_list_vaddr - 0x10 = unmapped) fails → advance cursor.
        // read_bytes(sb_list_vaddr, 8) = sym_vaddr → sb_cursor == sb_list_addr → break.
        let result = walk_tmpfs_files(&reader).unwrap();
        assert!(
            result.is_empty(),
            "loop body ran but s_type unreadable → no results"
        );
    }

    // --- walk_tmpfs_files: exercises s_inodes / inode walk when s_type is not tmpfs ---
    // Provides a super_block with s_type pointing to a page that has a name pointer
    // that leads to a non-tmpfs fs name → is_tmpfs = false → inode walk skipped.
    // Cursor advances back to sym_vaddr (self-loop) → exits.
    #[test]
    fn walk_tmpfs_non_tmpfs_superblock_skipped() {
        use memf_core::test_builders::flags as ptf;

        let sym_vaddr: u64 = 0xFFFF_8800_0042_0000; // super_blocks list head
        let sym_paddr: u64 = 0x0042_0000;

        let sb_entry_vaddr: u64 = 0xFFFF_8800_0043_0000;
        let sb_entry_paddr: u64 = 0x0043_0000;

        let fs_type_vaddr: u64 = 0xFFFF_8800_0044_0000; // file_system_type struct
        let fs_type_paddr: u64 = 0x0044_0000;

        let name_str_vaddr: u64 = 0xFFFF_8800_0045_0000; // name string "ext4\0"
        let name_str_paddr: u64 = 0x0045_0000;

        // s_list at offset 0, s_type at offset 8 within super_block.
        // super_blocks page: first 8 bytes = sb_entry_vaddr (the superblock entry's s_list).
        let mut sym_page = [0u8; 4096];
        sym_page[0..8].copy_from_slice(&sb_entry_vaddr.to_le_bytes());

        // sb_entry page:
        //   offset 0x00 (s_list.next) = sym_vaddr  (wraps back → loop ends after this entry)
        //   offset 0x08 (s_type ptr)  = fs_type_vaddr
        let mut sb_page = [0u8; 4096];
        sb_page[0x00..0x08].copy_from_slice(&sym_vaddr.to_le_bytes()); // s_list.next = head
        sb_page[0x08..0x10].copy_from_slice(&fs_type_vaddr.to_le_bytes()); // s_type

        // fs_type page: first 8 bytes = name_str_vaddr (the const char *name pointer).
        let mut fs_type_page = [0u8; 4096];
        fs_type_page[0..8].copy_from_slice(&name_str_vaddr.to_le_bytes());

        // name_str page: "ext4\0..." — not "tmpfs" or "ramfs".
        let mut name_page = [0u8; 4096];
        name_page[..5].copy_from_slice(b"ext4\0");

        let isf = IsfBuilder::new()
            .add_symbol("super_blocks", sym_vaddr)
            .add_struct("super_block", 0x200)
            .add_field("super_block", "s_list", 0x00, "pointer")
            .add_field("super_block", "s_type", 0x08, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &sym_page)
            .map_4k(sb_entry_vaddr, sb_entry_paddr, ptf::WRITABLE)
            .write_phys(sb_entry_paddr, &sb_page)
            .map_4k(fs_type_vaddr, fs_type_paddr, ptf::WRITABLE)
            .write_phys(fs_type_paddr, &fs_type_page)
            .map_4k(name_str_vaddr, name_str_paddr, ptf::WRITABLE)
            .write_phys(name_str_paddr, &name_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_tmpfs_files(&reader).unwrap();
        assert!(
            result.is_empty(),
            "non-tmpfs superblock must not produce entries"
        );
    }

    // --- walk_tmpfs_files: s_type ptr == 0 → is_tmpfs = false ---
    // Exercises the s_type_ptr == 0 branch in the is_tmpfs block.
    #[test]
    fn walk_tmpfs_null_s_type_ptr_skipped() {
        use memf_core::test_builders::flags as ptf;

        let sym_vaddr: u64 = 0xFFFF_8800_0046_0000;
        let sym_paddr: u64 = 0x0046_0000;

        let sb_entry_vaddr: u64 = 0xFFFF_8800_0047_0000;
        let sb_entry_paddr: u64 = 0x0047_0000;

        let mut sym_page = [0u8; 4096];
        sym_page[0..8].copy_from_slice(&sb_entry_vaddr.to_le_bytes());

        let mut sb_page = [0u8; 4096];
        // s_list.next = sym_vaddr (loop ends after one entry)
        sb_page[0x00..0x08].copy_from_slice(&sym_vaddr.to_le_bytes());
        // s_type = 0 (null pointer → is_tmpfs = false)
        sb_page[0x08..0x10].copy_from_slice(&0u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_symbol("super_blocks", sym_vaddr)
            .add_struct("super_block", 0x200)
            .add_field("super_block", "s_list", 0x00, "pointer")
            .add_field("super_block", "s_type", 0x08, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &sym_page)
            .map_4k(sb_entry_vaddr, sb_entry_paddr, ptf::WRITABLE)
            .write_phys(sb_entry_paddr, &sb_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_tmpfs_files(&reader).unwrap();
        assert!(
            result.is_empty(),
            "null s_type ptr → is_tmpfs false → no entries"
        );
    }

    // --- walk_tmpfs_files: tmpfs superblock found, s_inodes missing → skips inode walk ---
    // Exercises the is_tmpfs == true branch and the missing-s_inodes graceful path.
    #[test]
    fn walk_tmpfs_tmpfs_sb_no_s_inodes_field_skips() {
        use memf_core::test_builders::flags as ptf;

        let sym_vaddr: u64 = 0xFFFF_8800_0048_0000;
        let sym_paddr: u64 = 0x0048_0000;

        let sb_entry_vaddr: u64 = 0xFFFF_8800_0049_0000;
        let sb_entry_paddr: u64 = 0x0049_0000;

        let fs_type_vaddr: u64 = 0xFFFF_8800_004A_0000;
        let fs_type_paddr: u64 = 0x004A_0000;

        let name_str_vaddr: u64 = 0xFFFF_8800_004B_0000;
        let name_str_paddr: u64 = 0x004B_0000;

        let mut sym_page = [0u8; 4096];
        sym_page[0..8].copy_from_slice(&sb_entry_vaddr.to_le_bytes());

        let mut sb_page = [0u8; 4096];
        sb_page[0x00..0x08].copy_from_slice(&sym_vaddr.to_le_bytes()); // s_list.next = head
        sb_page[0x08..0x10].copy_from_slice(&fs_type_vaddr.to_le_bytes()); // s_type

        let mut fs_type_page = [0u8; 4096];
        fs_type_page[0..8].copy_from_slice(&name_str_vaddr.to_le_bytes());

        let mut name_page = [0u8; 4096];
        name_page[..6].copy_from_slice(b"tmpfs\0");

        // ISF: has super_block with s_list and s_type but NO s_inodes field.
        let isf = IsfBuilder::new()
            .add_symbol("super_blocks", sym_vaddr)
            .add_struct("super_block", 0x200)
            .add_field("super_block", "s_list", 0x00, "pointer")
            .add_field("super_block", "s_type", 0x08, "pointer")
            // deliberately omit "s_inodes"
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &sym_page)
            .map_4k(sb_entry_vaddr, sb_entry_paddr, ptf::WRITABLE)
            .write_phys(sb_entry_paddr, &sb_page)
            .map_4k(fs_type_vaddr, fs_type_paddr, ptf::WRITABLE)
            .write_phys(fs_type_paddr, &fs_type_page)
            .map_4k(name_str_vaddr, name_str_paddr, ptf::WRITABLE)
            .write_phys(name_str_paddr, &name_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // is_tmpfs == true but s_inodes field missing → skips inode walk → empty
        let result = walk_tmpfs_files(&reader).unwrap();
        assert!(
            result.is_empty(),
            "tmpfs sb without s_inodes offset → empty (graceful)"
        );
    }

    // --- walk_tmpfs_files: tmpfs sb found, s_inodes present, missing i_sb_list → skips ---
    #[test]
    fn walk_tmpfs_tmpfs_sb_no_i_sb_list_field_skips() {
        use memf_core::test_builders::flags as ptf;

        let sym_vaddr: u64 = 0xFFFF_8800_004C_0000;
        let sym_paddr: u64 = 0x004C_0000;

        let sb_entry_vaddr: u64 = 0xFFFF_8800_004D_0000;
        let sb_entry_paddr: u64 = 0x004D_0000;

        let fs_type_vaddr: u64 = 0xFFFF_8800_004E_0000;
        let fs_type_paddr: u64 = 0x004E_0000;

        let name_str_vaddr: u64 = 0xFFFF_8800_004F_0000;
        let name_str_paddr: u64 = 0x004F_0000;

        let mut sym_page = [0u8; 4096];
        sym_page[0..8].copy_from_slice(&sb_entry_vaddr.to_le_bytes());

        let mut sb_page = [0u8; 4096];
        sb_page[0x00..0x08].copy_from_slice(&sym_vaddr.to_le_bytes()); // s_list.next = head
        sb_page[0x08..0x10].copy_from_slice(&fs_type_vaddr.to_le_bytes()); // s_type

        let mut fs_type_page = [0u8; 4096];
        fs_type_page[0..8].copy_from_slice(&name_str_vaddr.to_le_bytes());

        let mut name_page = [0u8; 4096];
        name_page[..6].copy_from_slice(b"tmpfs\0");

        // ISF: has s_inodes but NO inode.i_sb_list
        let isf = IsfBuilder::new()
            .add_symbol("super_blocks", sym_vaddr)
            .add_struct("super_block", 0x400)
            .add_field("super_block", "s_list", 0x00, "pointer")
            .add_field("super_block", "s_type", 0x08, "pointer")
            .add_field("super_block", "s_inodes", 0x20, "pointer")
            // deliberately omit "inode" struct / "i_sb_list" field
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &sym_page)
            .map_4k(sb_entry_vaddr, sb_entry_paddr, ptf::WRITABLE)
            .write_phys(sb_entry_paddr, &sb_page)
            .map_4k(fs_type_vaddr, fs_type_paddr, ptf::WRITABLE)
            .write_phys(fs_type_paddr, &fs_type_page)
            .map_4k(name_str_vaddr, name_str_paddr, ptf::WRITABLE)
            .write_phys(name_str_paddr, &name_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_tmpfs_files(&reader).unwrap();
        assert!(
            result.is_empty(),
            "tmpfs sb with s_inodes but no i_sb_list → empty (graceful)"
        );
    }

    // --- walk_tmpfs_files: s_type ptr readable, name_ptr == 0 → is_tmpfs = false ---
    // Exercises the `name_ptr != 0` guard inside the is_tmpfs block: name_ptr = 0 → false.
    #[test]
    fn walk_tmpfs_null_name_ptr_is_not_tmpfs() {
        use memf_core::test_builders::flags as ptf;

        let sym_vaddr: u64 = 0xFFFF_8800_0054_0000;
        let sym_paddr: u64 = 0x0054_0000;
        let sb_entry_vaddr: u64 = 0xFFFF_8800_0055_0000;
        let sb_entry_paddr: u64 = 0x0055_0000;
        let fs_type_vaddr: u64 = 0xFFFF_8800_0056_0000;
        let fs_type_paddr: u64 = 0x0056_0000;

        let mut sym_page = [0u8; 4096];
        sym_page[0..8].copy_from_slice(&sb_entry_vaddr.to_le_bytes());

        let mut sb_page = [0u8; 4096];
        sb_page[0x00..0x08].copy_from_slice(&sym_vaddr.to_le_bytes()); // s_list.next = head
        sb_page[0x08..0x10].copy_from_slice(&fs_type_vaddr.to_le_bytes()); // s_type

        // fs_type page: name pointer at offset 0 = 0 (null) → name_ptr == 0 → is_tmpfs = false
        let fs_type_page = [0u8; 4096];

        let isf = IsfBuilder::new()
            .add_symbol("super_blocks", sym_vaddr)
            .add_struct("super_block", 0x200)
            .add_field("super_block", "s_list", 0x00, "pointer")
            .add_field("super_block", "s_type", 0x08, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &sym_page)
            .map_4k(sb_entry_vaddr, sb_entry_paddr, ptf::WRITABLE)
            .write_phys(sb_entry_paddr, &sb_page)
            .map_4k(fs_type_vaddr, fs_type_paddr, ptf::WRITABLE)
            .write_phys(fs_type_paddr, &fs_type_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_tmpfs_files(&reader).unwrap();
        assert!(
            result.is_empty(),
            "null name_ptr → is_tmpfs false → no entries"
        );
    }

    // --- walk_tmpfs_files: full path — tmpfs sb with one real inode in the list ---
    // Exercises the inode walk body (lines 165-207): reads i_ino, i_size, i_uid,
    // i_gid, i_mode, timestamps, classifies the file, and pushes a TmpfsFileInfo.
    #[test]
    fn walk_tmpfs_tmpfs_sb_with_one_inode_produces_result() {
        use memf_core::test_builders::flags as ptf;

        // Memory layout (all physical addresses < 16 MB):
        //   sym_vaddr         — super_blocks list head
        //   sb_entry_vaddr    — the super_block
        //   fs_type_vaddr     — file_system_type struct
        //   name_str_vaddr    — "tmpfs\0"
        //   inode_head_vaddr  — s_inodes list head (embedded in super_block at s_inodes_offset)
        //   inode_vaddr       — the inode struct
        //
        // Note: s_inodes is embedded inside sb_entry_vaddr (same page), so inode_head_vaddr
        // is actually sb_entry_vaddr + s_inodes_offset.
        //
        // The inode list is singly traversed via i_sb_list embedded in the inode:
        //   inode_head (= sb_entry_vaddr + s_inodes_offset):
        //     first 8 bytes (next ptr) = inode_vaddr + i_sb_list_offset
        //   inode.i_sb_list (= inode_vaddr + i_sb_list_offset):
        //     first 8 bytes (next ptr) = inode_head (wraps back → loop ends)

        let sym_vaddr: u64 = 0xFFFF_8800_0057_0000;
        let sym_paddr: u64 = 0x0057_0000;
        let sb_vaddr: u64 = 0xFFFF_8800_0058_0000;
        let sb_paddr: u64 = 0x0058_0000;
        let fstype_vaddr: u64 = 0xFFFF_8800_0059_0000;
        let fstype_paddr: u64 = 0x0059_0000;
        let name_vaddr: u64 = 0xFFFF_8800_005A_0000;
        let name_paddr: u64 = 0x005A_0000;
        let inode_vaddr: u64 = 0xFFFF_8800_005B_0000;
        let inode_paddr: u64 = 0x005B_0000;

        // super_block field offsets:
        let s_list_offset: u64 = 0x00;
        let s_type_offset: u64 = 0x08;
        let s_inodes_offset: u64 = 0x20;

        // inode field offsets:
        let i_sb_list_offset: u64 = 0x08;
        let i_ino_offset: u64 = 0x10;
        let i_size_offset: u64 = 0x18;
        let i_uid_offset: u64 = 0x20;
        let i_gid_offset: u64 = 0x24;
        let i_mode_offset: u64 = 0x28;
        let i_atime_offset: u64 = 0x30;
        let i_mtime_offset: u64 = 0x38;
        let i_ctime_offset: u64 = 0x40;

        // The inode list head is embedded in the super_block at s_inodes_offset.
        let inode_list_head = sb_vaddr + s_inodes_offset;
        // The inode's i_sb_list node is at inode_vaddr + i_sb_list_offset.
        let inode_list_node = inode_vaddr + i_sb_list_offset;

        // super_blocks list head page: first 8 bytes = sb_entry's s_list
        let mut sym_page = [0u8; 4096];
        sym_page[0..8].copy_from_slice(&sb_vaddr.to_le_bytes());

        // super_block page:
        //   s_list.next    @ 0x00 = sym_vaddr  (wraps back → outer loop ends after this sb)
        //   s_type         @ 0x08 = fstype_vaddr
        //   s_inodes.next  @ 0x20 = inode_list_node  (points into inode)
        let mut sb_page = [0u8; 4096];
        sb_page[s_list_offset as usize..s_list_offset as usize + 8]
            .copy_from_slice(&sym_vaddr.to_le_bytes());
        sb_page[s_type_offset as usize..s_type_offset as usize + 8]
            .copy_from_slice(&fstype_vaddr.to_le_bytes());
        sb_page[s_inodes_offset as usize..s_inodes_offset as usize + 8]
            .copy_from_slice(&inode_list_node.to_le_bytes());

        // file_system_type page: first 8 bytes = name_vaddr
        let mut fstype_page = [0u8; 4096];
        fstype_page[0..8].copy_from_slice(&name_vaddr.to_le_bytes());

        // name string page: "tmpfs\0"
        let mut name_page = [0u8; 4096];
        name_page[..6].copy_from_slice(b"tmpfs\0");

        // inode page:
        //   i_sb_list.next @ i_sb_list_offset = inode_list_head  (wraps back → loop ends)
        //   i_ino          @ i_ino_offset    = 1234
        //   i_size         @ i_size_offset   = 4096
        //   i_uid          @ i_uid_offset    = 500
        //   i_gid          @ i_gid_offset    = 501
        //   i_mode         @ i_mode_offset   = 0o100755  (S_IFREG | rwxr-xr-x → executable → suspicious)
        //   i_atime        @ i_atime_offset  = 1000
        //   i_mtime        @ i_mtime_offset  = 2000
        //   i_ctime        @ i_ctime_offset  = 3000
        let mut inode_page = [0u8; 4096];
        inode_page[i_sb_list_offset as usize..i_sb_list_offset as usize + 8]
            .copy_from_slice(&inode_list_head.to_le_bytes());
        inode_page[i_ino_offset as usize..i_ino_offset as usize + 8]
            .copy_from_slice(&1234u64.to_le_bytes());
        inode_page[i_size_offset as usize..i_size_offset as usize + 8]
            .copy_from_slice(&4096u64.to_le_bytes());
        inode_page[i_uid_offset as usize..i_uid_offset as usize + 4]
            .copy_from_slice(&500u32.to_le_bytes());
        inode_page[i_gid_offset as usize..i_gid_offset as usize + 4]
            .copy_from_slice(&501u32.to_le_bytes());
        inode_page[i_mode_offset as usize..i_mode_offset as usize + 4]
            .copy_from_slice(&0o100_755u32.to_le_bytes());
        inode_page[i_atime_offset as usize..i_atime_offset as usize + 8]
            .copy_from_slice(&1000u64.to_le_bytes());
        inode_page[i_mtime_offset as usize..i_mtime_offset as usize + 8]
            .copy_from_slice(&2000u64.to_le_bytes());
        inode_page[i_ctime_offset as usize..i_ctime_offset as usize + 8]
            .copy_from_slice(&3000u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_symbol("super_blocks", sym_vaddr)
            .add_struct("super_block", 0x400)
            .add_field("super_block", "s_list", s_list_offset, "pointer")
            .add_field("super_block", "s_type", s_type_offset, "pointer")
            .add_field("super_block", "s_inodes", s_inodes_offset, "pointer")
            .add_struct("inode", 0x200)
            .add_field("inode", "i_sb_list", i_sb_list_offset, "pointer")
            .add_field("inode", "i_ino", i_ino_offset, "unsigned long")
            .add_field("inode", "i_size", i_size_offset, "long long")
            .add_field("inode", "i_uid", i_uid_offset, "unsigned int")
            .add_field("inode", "i_gid", i_gid_offset, "unsigned int")
            .add_field("inode", "i_mode", i_mode_offset, "unsigned int")
            .add_field("inode", "i_atime", i_atime_offset, "long long")
            .add_field("inode", "i_mtime", i_mtime_offset, "long long")
            .add_field("inode", "i_ctime", i_ctime_offset, "long long")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &sym_page)
            .map_4k(sb_vaddr, sb_paddr, ptf::WRITABLE)
            .write_phys(sb_paddr, &sb_page)
            .map_4k(fstype_vaddr, fstype_paddr, ptf::WRITABLE)
            .write_phys(fstype_paddr, &fstype_page)
            .map_4k(name_vaddr, name_paddr, ptf::WRITABLE)
            .write_phys(name_paddr, &name_page)
            .map_4k(inode_vaddr, inode_paddr, ptf::WRITABLE)
            .write_phys(inode_paddr, &inode_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_tmpfs_files(&reader).unwrap();
        assert_eq!(result.len(), 1, "should find exactly one inode");
        let fi = &result[0];
        assert_eq!(fi.inode_number, 1234);
        assert_eq!(fi.file_size, 4096);
        assert_eq!(fi.uid, 500);
        assert_eq!(fi.gid, 501);
        assert_eq!(fi.mode, 0o100_755);
        assert_eq!(fi.atime_sec, 1000);
        assert_eq!(fi.mtime_sec, 2000);
        assert_eq!(fi.ctime_sec, 3000);
        assert!(
            fi.is_suspicious,
            "executable regular file must be suspicious"
        );
    }

    // --- dentry-based filename resolution ---

    /// Full path: inode has `i_dentry.first` pointing into a mapped dentry.
    /// `dentry.d_name.name` points to a mapped string "secret.txt\0".
    /// Asserts that `TmpfsFileInfo.filename == "secret.txt"`.
    #[test]
    fn inode_with_dentry_returns_filename() {
        use memf_core::test_builders::flags as ptf;

        // Virtual address layout (all physical addrs < 16 MB):
        //   sym_vaddr         — super_blocks list head
        //   sb_vaddr          — the single super_block
        //   fstype_vaddr      — file_system_type
        //   name_vaddr        — "tmpfs\0"
        //   inode_vaddr       — the inode
        //   dentry_vaddr      — the dentry
        //   dname_str_vaddr   — "secret.txt\0"

        let sym_vaddr: u64 = 0xFFFF_8800_0060_0000;
        let sym_paddr: u64 = 0x0060_0000;
        let sb_vaddr: u64 = 0xFFFF_8800_0061_0000;
        let sb_paddr: u64 = 0x0061_0000;
        let fstype_vaddr: u64 = 0xFFFF_8800_0062_0000;
        let fstype_paddr: u64 = 0x0062_0000;
        let fsname_vaddr: u64 = 0xFFFF_8800_0063_0000;
        let fsname_paddr: u64 = 0x0063_0000;
        let inode_vaddr: u64 = 0xFFFF_8800_0064_0000;
        let inode_paddr: u64 = 0x0064_0000;
        let dentry_vaddr: u64 = 0xFFFF_8800_0065_0000;
        let dentry_paddr: u64 = 0x0065_0000;
        let dname_str_vaddr: u64 = 0xFFFF_8800_0066_0000;
        let dname_str_paddr: u64 = 0x0066_0000;

        // super_block field offsets
        let s_list_off: u64 = 0x00;
        let s_type_off: u64 = 0x08;
        let s_inodes_off: u64 = 0x20;

        // inode field offsets
        let i_sb_list_off: u64 = 0x08;
        let i_ino_off: u64 = 0x10;
        let i_size_off: u64 = 0x18;
        let i_uid_off: u64 = 0x20;
        let i_gid_off: u64 = 0x24;
        let i_mode_off: u64 = 0x28;
        let i_atime_off: u64 = 0x30;
        let i_mtime_off: u64 = 0x38;
        let i_ctime_off: u64 = 0x40;
        let i_dentry_off: u64 = 0x48; // hlist_head.first pointer

        // dentry field offsets
        let d_alias_off: u64 = 0x00; // hlist_node embedded at start of dentry
        let d_name_off: u64 = 0x20; // qstr struct
        let d_name_name_off: u64 = d_name_off + 0x08; // name pointer within qstr (after hash+len)

        // The hlist_node pointer stored in inode.i_dentry.first points at
        // dentry.d_alias (which is at dentry_vaddr + d_alias_off).
        let hlist_node_ptr = dentry_vaddr + d_alias_off;

        // inode list pointers
        let inode_list_head = sb_vaddr + s_inodes_off;
        let inode_list_node = inode_vaddr + i_sb_list_off;

        // super_blocks list-head page: first 8 bytes = sb.s_list
        let mut sym_page = [0u8; 4096];
        sym_page[0..8].copy_from_slice(&sb_vaddr.to_le_bytes());

        // super_block page
        let mut sb_page = [0u8; 4096];
        sb_page[s_list_off as usize..s_list_off as usize + 8]
            .copy_from_slice(&sym_vaddr.to_le_bytes()); // s_list.next = head (loop ends)
        sb_page[s_type_off as usize..s_type_off as usize + 8]
            .copy_from_slice(&fstype_vaddr.to_le_bytes());
        sb_page[s_inodes_off as usize..s_inodes_off as usize + 8]
            .copy_from_slice(&inode_list_node.to_le_bytes());

        // file_system_type page: first 8 bytes = fsname_vaddr
        let mut fstype_page = [0u8; 4096];
        fstype_page[0..8].copy_from_slice(&fsname_vaddr.to_le_bytes());

        // fs name page: "tmpfs\0"
        let mut fsname_page = [0u8; 4096];
        fsname_page[..6].copy_from_slice(b"tmpfs\0");

        // inode page
        let mut inode_page = [0u8; 4096];
        inode_page[i_sb_list_off as usize..i_sb_list_off as usize + 8]
            .copy_from_slice(&inode_list_head.to_le_bytes()); // wrap back → inner loop ends
        inode_page[i_ino_off as usize..i_ino_off as usize + 8]
            .copy_from_slice(&42u64.to_le_bytes());
        inode_page[i_size_off as usize..i_size_off as usize + 8]
            .copy_from_slice(&512u64.to_le_bytes());
        inode_page[i_uid_off as usize..i_uid_off as usize + 4]
            .copy_from_slice(&1000u32.to_le_bytes());
        inode_page[i_gid_off as usize..i_gid_off as usize + 4]
            .copy_from_slice(&1000u32.to_le_bytes());
        inode_page[i_mode_off as usize..i_mode_off as usize + 4]
            .copy_from_slice(&0o100_644u32.to_le_bytes());
        inode_page[i_atime_off as usize..i_atime_off as usize + 8]
            .copy_from_slice(&100u64.to_le_bytes());
        inode_page[i_mtime_off as usize..i_mtime_off as usize + 8]
            .copy_from_slice(&200u64.to_le_bytes());
        inode_page[i_ctime_off as usize..i_ctime_off as usize + 8]
            .copy_from_slice(&300u64.to_le_bytes());
        // i_dentry.first = hlist_node_ptr (points at dentry.d_alias)
        inode_page[i_dentry_off as usize..i_dentry_off as usize + 8]
            .copy_from_slice(&hlist_node_ptr.to_le_bytes());

        // dentry page
        let mut dentry_page = [0u8; 4096];
        // d_name.name pointer at d_name_name_off within dentry page
        dentry_page[d_name_name_off as usize..d_name_name_off as usize + 8]
            .copy_from_slice(&dname_str_vaddr.to_le_bytes());

        // filename string page: "secret.txt\0"
        let mut dname_str_page = [0u8; 4096];
        dname_str_page[..11].copy_from_slice(b"secret.txt\0");

        let isf = IsfBuilder::new()
            .add_symbol("super_blocks", sym_vaddr)
            .add_struct("super_block", 0x400)
            .add_field("super_block", "s_list", s_list_off, "pointer")
            .add_field("super_block", "s_type", s_type_off, "pointer")
            .add_field("super_block", "s_inodes", s_inodes_off, "pointer")
            .add_struct("inode", 0x200)
            .add_field("inode", "i_sb_list", i_sb_list_off, "pointer")
            .add_field("inode", "i_ino", i_ino_off, "unsigned long")
            .add_field("inode", "i_size", i_size_off, "long long")
            .add_field("inode", "i_uid", i_uid_off, "unsigned int")
            .add_field("inode", "i_gid", i_gid_off, "unsigned int")
            .add_field("inode", "i_mode", i_mode_off, "unsigned int")
            .add_field("inode", "i_atime", i_atime_off, "long long")
            .add_field("inode", "i_mtime", i_mtime_off, "long long")
            .add_field("inode", "i_ctime", i_ctime_off, "long long")
            .add_field("inode", "i_dentry", i_dentry_off, "pointer")
            .add_struct("dentry", 0x200)
            .add_field("dentry", "d_alias", d_alias_off, "pointer")
            .add_field("dentry", "d_name_name", d_name_name_off, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &sym_page)
            .map_4k(sb_vaddr, sb_paddr, ptf::WRITABLE)
            .write_phys(sb_paddr, &sb_page)
            .map_4k(fstype_vaddr, fstype_paddr, ptf::WRITABLE)
            .write_phys(fstype_paddr, &fstype_page)
            .map_4k(fsname_vaddr, fsname_paddr, ptf::WRITABLE)
            .write_phys(fsname_paddr, &fsname_page)
            .map_4k(inode_vaddr, inode_paddr, ptf::WRITABLE)
            .write_phys(inode_paddr, &inode_page)
            .map_4k(dentry_vaddr, dentry_paddr, ptf::WRITABLE)
            .write_phys(dentry_paddr, &dentry_page)
            .map_4k(dname_str_vaddr, dname_str_paddr, ptf::WRITABLE)
            .write_phys(dname_str_paddr, &dname_str_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_tmpfs_files(&reader).unwrap();
        assert_eq!(result.len(), 1, "should find exactly one inode");
        assert_eq!(
            result[0].filename, "secret.txt",
            "filename must be resolved from dentry d_name.name"
        );
    }

    /// Inode with `i_dentry.first == 0` (null hlist) — filename must be empty.
    #[test]
    fn inode_without_dentry_returns_empty_filename() {
        use memf_core::test_builders::flags as ptf;

        let sym_vaddr: u64 = 0xFFFF_8800_0067_0000;
        let sym_paddr: u64 = 0x0067_0000;
        let sb_vaddr: u64 = 0xFFFF_8800_0068_0000;
        let sb_paddr: u64 = 0x0068_0000;
        let fstype_vaddr: u64 = 0xFFFF_8800_0069_0000;
        let fstype_paddr: u64 = 0x0069_0000;
        let fsname_vaddr: u64 = 0xFFFF_8800_006A_0000;
        let fsname_paddr: u64 = 0x006A_0000;
        let inode_vaddr: u64 = 0xFFFF_8800_006B_0000;
        let inode_paddr: u64 = 0x006B_0000;

        let s_list_off: u64 = 0x00;
        let s_type_off: u64 = 0x08;
        let s_inodes_off: u64 = 0x20;
        let i_sb_list_off: u64 = 0x08;
        let i_ino_off: u64 = 0x10;
        let i_size_off: u64 = 0x18;
        let i_uid_off: u64 = 0x20;
        let i_gid_off: u64 = 0x24;
        let i_mode_off: u64 = 0x28;
        let i_atime_off: u64 = 0x30;
        let i_mtime_off: u64 = 0x38;
        let i_ctime_off: u64 = 0x40;
        let i_dentry_off: u64 = 0x48;

        let inode_list_head = sb_vaddr + s_inodes_off;
        let inode_list_node = inode_vaddr + i_sb_list_off;

        let mut sym_page = [0u8; 4096];
        sym_page[0..8].copy_from_slice(&sb_vaddr.to_le_bytes());

        let mut sb_page = [0u8; 4096];
        sb_page[s_list_off as usize..s_list_off as usize + 8]
            .copy_from_slice(&sym_vaddr.to_le_bytes());
        sb_page[s_type_off as usize..s_type_off as usize + 8]
            .copy_from_slice(&fstype_vaddr.to_le_bytes());
        sb_page[s_inodes_off as usize..s_inodes_off as usize + 8]
            .copy_from_slice(&inode_list_node.to_le_bytes());

        let mut fstype_page = [0u8; 4096];
        fstype_page[0..8].copy_from_slice(&fsname_vaddr.to_le_bytes());

        let mut fsname_page = [0u8; 4096];
        fsname_page[..6].copy_from_slice(b"tmpfs\0");

        let mut inode_page = [0u8; 4096];
        inode_page[i_sb_list_off as usize..i_sb_list_off as usize + 8]
            .copy_from_slice(&inode_list_head.to_le_bytes());
        inode_page[i_ino_off as usize..i_ino_off as usize + 8]
            .copy_from_slice(&99u64.to_le_bytes());
        inode_page[i_size_off as usize..i_size_off as usize + 8]
            .copy_from_slice(&0u64.to_le_bytes());
        inode_page[i_uid_off as usize..i_uid_off as usize + 4].copy_from_slice(&0u32.to_le_bytes());
        inode_page[i_gid_off as usize..i_gid_off as usize + 4].copy_from_slice(&0u32.to_le_bytes());
        inode_page[i_mode_off as usize..i_mode_off as usize + 4]
            .copy_from_slice(&0o100_644u32.to_le_bytes());
        inode_page[i_atime_off as usize..i_atime_off as usize + 8]
            .copy_from_slice(&0u64.to_le_bytes());
        inode_page[i_mtime_off as usize..i_mtime_off as usize + 8]
            .copy_from_slice(&0u64.to_le_bytes());
        inode_page[i_ctime_off as usize..i_ctime_off as usize + 8]
            .copy_from_slice(&0u64.to_le_bytes());
        // i_dentry.first = 0 (null — no dentry)
        inode_page[i_dentry_off as usize..i_dentry_off as usize + 8]
            .copy_from_slice(&0u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_symbol("super_blocks", sym_vaddr)
            .add_struct("super_block", 0x400)
            .add_field("super_block", "s_list", s_list_off, "pointer")
            .add_field("super_block", "s_type", s_type_off, "pointer")
            .add_field("super_block", "s_inodes", s_inodes_off, "pointer")
            .add_struct("inode", 0x200)
            .add_field("inode", "i_sb_list", i_sb_list_off, "pointer")
            .add_field("inode", "i_ino", i_ino_off, "unsigned long")
            .add_field("inode", "i_size", i_size_off, "long long")
            .add_field("inode", "i_uid", i_uid_off, "unsigned int")
            .add_field("inode", "i_gid", i_gid_off, "unsigned int")
            .add_field("inode", "i_mode", i_mode_off, "unsigned int")
            .add_field("inode", "i_atime", i_atime_off, "long long")
            .add_field("inode", "i_mtime", i_mtime_off, "long long")
            .add_field("inode", "i_ctime", i_ctime_off, "long long")
            .add_field("inode", "i_dentry", i_dentry_off, "pointer")
            .add_struct("dentry", 0x200)
            .add_field("dentry", "d_alias", 0x00, "pointer")
            .add_field("dentry", "d_name_name", 0x28, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &sym_page)
            .map_4k(sb_vaddr, sb_paddr, ptf::WRITABLE)
            .write_phys(sb_paddr, &sb_page)
            .map_4k(fstype_vaddr, fstype_paddr, ptf::WRITABLE)
            .write_phys(fstype_paddr, &fstype_page)
            .map_4k(fsname_vaddr, fsname_paddr, ptf::WRITABLE)
            .write_phys(fsname_paddr, &fsname_page)
            .map_4k(inode_vaddr, inode_paddr, ptf::WRITABLE)
            .write_phys(inode_paddr, &inode_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_tmpfs_files(&reader).unwrap();
        assert_eq!(result.len(), 1, "should find exactly one inode");
        assert_eq!(
            result[0].filename, "",
            "null i_dentry.first → filename must be empty string"
        );
    }

    // --- classify_tmpfs_file: TmpfsFileInfo struct coverage ---
    #[test]
    fn tmpfs_file_info_clone_debug_serialize() {
        let info = TmpfsFileInfo {
            inode_number: 42,
            filename: ".evil".to_string(),
            file_size: 1024,
            uid: 0,
            gid: 0,
            mode: 0o100_755,
            atime_sec: 1000,
            mtime_sec: 2000,
            ctime_sec: 3000,
            is_suspicious: true,
        };
        let cloned = info.clone();
        assert_eq!(cloned.inode_number, 42);
        let dbg = format!("{:?}", cloned);
        assert!(dbg.contains("evil"));
        let json = serde_json::to_string(&cloned).unwrap();
        assert!(json.contains("\"inode_number\":42"));
        assert!(json.contains("\"is_suspicious\":true"));
    }

    // --- walk_tmpfs_files: full path — tmpfs sb with self-pointing inode list → empty inodes ---
    // Exercises: is_tmpfs=true, s_inodes_offset found, i_sb_list_offset found,
    // inode list is self-pointing → inner loop terminates immediately → no TmpfsFileInfo pushed.
    #[test]
    fn walk_tmpfs_tmpfs_sb_self_pointing_inode_list_returns_empty() {
        use memf_core::test_builders::flags as ptf;

        // Layout (all physical addrs < 16 MB):
        //   sym_vaddr      = super_blocks list head
        //   sb_entry_vaddr = the single super_block (s_list.next = sym_vaddr so loop ends)
        //   fs_type_vaddr  = file_system_type
        //   name_str_vaddr = "tmpfs\0"
        let sym_vaddr: u64 = 0xFFFF_8800_0050_0000;
        let sym_paddr: u64 = 0x0050_0000;
        let sb_entry_vaddr: u64 = 0xFFFF_8800_0051_0000;
        let sb_entry_paddr: u64 = 0x0051_0000;
        let fs_type_vaddr: u64 = 0xFFFF_8800_0052_0000;
        let fs_type_paddr: u64 = 0x0052_0000;
        let name_str_vaddr: u64 = 0xFFFF_8800_0053_0000;
        let name_str_paddr: u64 = 0x0053_0000;

        // Offsets inside super_block:
        //   s_list   @ 0x00
        //   s_type   @ 0x08
        //   s_inodes @ 0x20  (list_head; first 8 bytes = next pointer)
        let s_inodes_offset: u64 = 0x20;

        // The inode list head lives at sb_entry_vaddr + s_inodes_offset.
        // A self-pointing list → next == inode_list_head → inner loop exits immediately.
        let inode_list_head = sb_entry_vaddr + s_inodes_offset;

        // Build the super_blocks list-head page: first 8 bytes = sb_entry_vaddr.
        let mut sym_page = [0u8; 4096];
        sym_page[0..8].copy_from_slice(&sb_entry_vaddr.to_le_bytes());

        // Build the super_block page.
        let mut sb_page = [0u8; 4096];
        sb_page[0x00..0x08].copy_from_slice(&sym_vaddr.to_le_bytes()); // s_list.next = head → ends loop
        sb_page[0x08..0x10].copy_from_slice(&fs_type_vaddr.to_le_bytes()); // s_type
                                                                           // s_inodes.next = inode_list_head (self-pointer → inner loop exits immediately)
        sb_page[s_inodes_offset as usize..s_inodes_offset as usize + 8]
            .copy_from_slice(&inode_list_head.to_le_bytes());

        let mut fs_type_page = [0u8; 4096];
        fs_type_page[0..8].copy_from_slice(&name_str_vaddr.to_le_bytes());

        let mut name_page = [0u8; 4096];
        name_page[..6].copy_from_slice(b"tmpfs\0");

        // i_sb_list offset inside inode = 0x08 (arbitrary; just needs to resolve).
        let isf = IsfBuilder::new()
            .add_symbol("super_blocks", sym_vaddr)
            .add_struct("super_block", 0x400)
            .add_field("super_block", "s_list", 0x00, "pointer")
            .add_field("super_block", "s_type", 0x08, "pointer")
            .add_field("super_block", "s_inodes", s_inodes_offset, "pointer")
            .add_struct("inode", 0x400)
            .add_field("inode", "i_sb_list", 0x08, "pointer")
            .add_field("inode", "i_ino", 0x10, "unsigned long")
            .add_field("inode", "i_size", 0x18, "long long")
            .add_field("inode", "i_uid", 0x20, "unsigned int")
            .add_field("inode", "i_gid", 0x24, "unsigned int")
            .add_field("inode", "i_mode", 0x28, "unsigned int")
            .add_field("inode", "i_atime", 0x30, "long long")
            .add_field("inode", "i_mtime", 0x38, "long long")
            .add_field("inode", "i_ctime", 0x40, "long long")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &sym_page)
            .map_4k(sb_entry_vaddr, sb_entry_paddr, ptf::WRITABLE)
            .write_phys(sb_entry_paddr, &sb_page)
            .map_4k(fs_type_vaddr, fs_type_paddr, ptf::WRITABLE)
            .write_phys(fs_type_paddr, &fs_type_page)
            .map_4k(name_str_vaddr, name_str_paddr, ptf::WRITABLE)
            .write_phys(name_str_paddr, &name_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_tmpfs_files(&reader).unwrap();
        assert!(
            result.is_empty(),
            "tmpfs sb with self-pointing inode list → 0 inodes"
        );
    }
}
