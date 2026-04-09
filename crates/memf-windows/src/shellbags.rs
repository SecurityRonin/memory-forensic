//! Shellbags folder-access evidence walker.
//!
//! Windows stores folder browsing history in NTUSER.DAT and UsrClass.dat
//! registry hives under `Software\Microsoft\Windows\Shell\BagMRU` and
//! `Shell\Bags`. Each entry contains a folder path and access timestamps.
//! Shellbags persist even after folder deletion — valuable for proving
//! lateral movement during incident response.
//!
//! The BagMRU tree uses `_CM_KEY_NODE` structures. Each numbered subkey
//! (0, 1, 2...) contains a default value holding a SHITEMID blob that
//! encodes the folder name and optional extension blocks with timestamps.
//! Walking the tree recursively builds the full folder path.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// Maximum number of BagMRU subkeys to walk per level (safety limit).
const MAX_SUBKEYS_PER_LEVEL: usize = 256;

/// Maximum recursion depth for the BagMRU tree.
const MAX_DEPTH: usize = 32;

/// Information about a single shellbag entry recovered from memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShellbagEntry {
    /// Reconstructed folder path from the BagMRU tree.
    pub path: String,
    /// Registry key last-write time (Windows FILETIME, 100ns ticks since 1601-01-01).
    pub slot_modified_time: u64,
    /// Access time extracted from the SHITEMID extension block.
    pub access_time: u64,
    /// Creation time extracted from the SHITEMID extension block.
    pub creation_time: u64,
    /// Whether this path is suspicious (admin shares, temp dirs, UNC paths).
    pub is_suspicious: bool,
}

/// Classify a shellbag folder path as suspicious.
///
/// Returns `true` if the path matches patterns commonly associated with
/// lateral movement or attacker activity:
/// - Admin shares (`\\C$`, `\\ADMIN$`, `\\IPC$`)
/// - UNC paths (`\\\\server\\share`) indicating remote folder access
/// - Temp/staging directories commonly used for tool drops
/// - Uncommon system paths rarely browsed by legitimate users
pub fn classify_shellbag(path: &str) -> bool {
    todo!()
}

/// Walk the BagMRU tree in a registry hive to recover shellbag entries.
///
/// Looks up the `_CM_KEY_NODE` symbol and walks the BagMRU tree starting
/// from `hive_addr`. Each numbered subkey's default value is parsed as a
/// SHITEMID blob to extract the folder name. Extension blocks (signature
/// `0xBEEF0004`) provide access and creation timestamps.
///
/// Returns `Ok(Vec::new())` if required symbols are not available in the
/// profile (graceful degradation).
pub fn walk_shellbags<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
) -> crate::Result<Vec<ShellbagEntry>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// No BagMRU symbol → empty Vec (graceful degradation).
    #[test]
    fn walk_shellbags_no_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("_CM_KEY_NODE", 0x50)
            .add_field("_CM_KEY_NODE", "Signature", 0x00, "unsigned short")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_shellbags(&reader, 0).unwrap();
        assert!(result.is_empty());
    }

    /// Normal folder paths like "Desktop" and "Documents" are not suspicious.
    #[test]
    fn classify_shellbag_benign() {
        assert!(!classify_shellbag("Desktop"));
        assert!(!classify_shellbag("Documents"));
        assert!(!classify_shellbag("Downloads"));
        assert!(!classify_shellbag("C:\\Users\\alice\\Pictures"));
        assert!(!classify_shellbag("D:\\Projects\\src"));
    }

    /// Admin share paths (\\C$, \\ADMIN$, \\IPC$) are suspicious — lateral movement indicator.
    #[test]
    fn classify_shellbag_suspicious_admin_share() {
        assert!(classify_shellbag("\\\\fileserver\\C$"));
        assert!(classify_shellbag("\\\\10.0.0.5\\ADMIN$"));
        assert!(classify_shellbag("\\\\dc01\\IPC$"));
        assert!(classify_shellbag("\\\\dc01\\C$\\Windows\\Temp"));
    }

    /// UNC paths (\\\\server\\share) indicate remote folder access — lateral movement.
    #[test]
    fn classify_shellbag_suspicious_remote() {
        assert!(classify_shellbag("\\\\192.168.1.100\\share"));
        assert!(classify_shellbag("\\\\fileserver\\data"));
        assert!(classify_shellbag("\\\\corp-dc\\SYSVOL"));
    }

    /// Temp/staging directories are suspicious.
    #[test]
    fn classify_shellbag_suspicious_temp() {
        assert!(classify_shellbag("C:\\Windows\\Temp"));
        assert!(classify_shellbag("C:\\Users\\Public\\Downloads"));
        assert!(classify_shellbag("C:\\PerfLogs"));
    }

    /// Empty path is not suspicious.
    #[test]
    fn classify_shellbag_empty() {
        assert!(!classify_shellbag(""));
    }
}
