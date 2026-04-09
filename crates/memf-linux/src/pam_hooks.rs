//! PAM library hook detection.
//!
//! Detects processes that have loaded a PAM-related shared library
//! (`libpam*.so`) from non-standard system paths, which is a strong
//! indicator of credential theft (MITRE ATT&CK T1556.003).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, Result};

/// Information about a suspicious PAM library loaded by a process.
#[derive(Debug, Clone)]
pub struct PamHookInfo {
    /// Process ID.
    pub pid: u32,
    /// Process command name.
    pub comm: String,
    /// Full path of the loaded PAM library (dentry name component).
    pub library_path: String,
    /// True if the library originates from a standard system lib directory.
    pub is_system_path: bool,
    /// True if the library is considered suspicious.
    pub is_suspicious: bool,
}

/// Classify whether a PAM library path is suspicious.
pub fn classify_pam_hook(_path: &str) -> bool {
    todo!("implement classify_pam_hook")
}

/// Walk all process VMAs and report PAM libraries loaded from non-system paths.
pub fn walk_pam_hooks<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
) -> Result<Vec<PamHookInfo>> {
    todo!("implement walk_pam_hooks")
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    #[test]
    #[should_panic(expected = "implement classify_pam_hook")]
    fn classify_pam_hook_tmp_path_suspicious() {
        assert!(classify_pam_hook("/tmp/libpam_evil.so"));
    }

    #[test]
    #[should_panic(expected = "implement classify_pam_hook")]
    fn classify_pam_hook_home_path_suspicious() {
        assert!(classify_pam_hook(
            "/home/attacker/.local/libpam_backdoor.so"
        ));
    }

    #[test]
    #[should_panic(expected = "implement classify_pam_hook")]
    fn classify_pam_hook_system_lib_not_suspicious() {
        assert!(!classify_pam_hook("/lib/x86_64-linux-gnu/libpam.so.0"));
    }

    #[test]
    #[should_panic(expected = "implement classify_pam_hook")]
    fn classify_pam_hook_empty_path_not_suspicious() {
        assert!(!classify_pam_hook(""));
    }

    #[test]
    #[should_panic(expected = "implement classify_pam_hook")]
    fn classify_pam_hook_devshm_suspicious() {
        assert!(classify_pam_hook("/dev/shm/libpam_hook.so"));
    }

    #[test]
    #[should_panic(expected = "implement walk_pam_hooks")]
    fn walk_pam_hooks_missing_init_task_returns_empty() {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 8, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_pam_hooks(&reader).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    #[should_panic(expected = "implement walk_pam_hooks")]
    fn walk_pam_hooks_kernel_thread_returns_empty() {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 8, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("init_task", 0xFFFF_8000_0010_0000u64)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_pam_hooks(&reader).unwrap();
        assert!(result.is_empty());
    }
}
