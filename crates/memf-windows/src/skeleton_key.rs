//! Skeleton Key backdoor detection (MITRE ATT&CK T1556.001).
//!
//! The Skeleton Key attack patches LSASS process memory to install a master
//! password that works alongside every user's real password. Detection
//! involves scanning for known byte patterns in authentication DLLs
//! (`msv1_0.dll`, `kdcsvc.dll`, `cryptdll.dll`, `lsasrv.dll`) loaded by
//! `lsass.exe`.
//!
//! Key indicators:
//! - NOP sleds (0x90 repeated) in `msv1_0.dll` near `MsvpPasswordValidate`
//! - Patched conditional jumps (0xEB replacing 0x75) in `kdcsvc.dll`
//! - Modified RC4 init routines in `cryptdll.dll`
//! - Authentication bypass patches in `lsasrv.dll`

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// A single Skeleton Key attack indicator found in LSASS process memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SkeletonKeyIndicator {
    /// Type of indicator (e.g., "auth_patch", "kdc_patch", "rc4_patch").
    pub indicator_type: String,
    /// Virtual address where the indicator was found.
    pub address: u64,
    /// DLL module where the indicator was found (e.g., "msv1_0.dll").
    pub module: String,
    /// Human-readable description of the indicator.
    pub description: String,
    /// Confidence score (0-100) for this indicator.
    pub confidence: u8,
    /// Whether a Skeleton Key indicator was positively detected.
    pub is_detected: bool,
}

/// Classify a Skeleton Key byte pattern based on the module and pattern type.
///
/// Returns a `(description, confidence)` tuple for known attack signatures.
/// Unknown combinations receive a generic description with lower confidence.
pub fn classify_skeleton_key_pattern(module: &str, pattern_type: &str) -> (String, u8) {
    match (module, pattern_type) {
        ("msv1_0.dll", "auth_patch") => {
            ("MSV1_0 authentication bypass patch".into(), 90)
        }
        ("kdcsvc.dll", "kdc_patch") => {
            ("KDC service Kerberos validation bypass".into(), 90)
        }
        ("cryptdll.dll", "rc4_patch") => {
            ("RC4 HMAC encryption downgrade patch".into(), 80)
        }
        ("lsasrv.dll", "auth_patch") => {
            ("LSA Server authentication bypass".into(), 85)
        }
        _ => ("Unknown modification".into(), 50),
    }
}

/// Scan lsass.exe process memory for Skeleton Key backdoor indicators.
///
/// Walks the process list to find `lsass.exe`, switches to its address space,
/// enumerates loaded DLLs, and scans authentication-critical modules for
/// known Skeleton Key byte patterns.
///
/// Returns an empty `Vec` if lsass.exe is not found or if the
/// `PsActiveProcessHead` symbol cannot be resolved.
pub fn walk_skeleton_key<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<SkeletonKeyIndicator>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_msv_patch() {
        let (desc, conf) = classify_skeleton_key_pattern("msv1_0.dll", "auth_patch");
        assert_eq!(desc, "MSV1_0 authentication bypass patch");
        assert_eq!(conf, 90);
    }

    #[test]
    fn classify_kdc_patch() {
        let (desc, conf) = classify_skeleton_key_pattern("kdcsvc.dll", "kdc_patch");
        assert_eq!(desc, "KDC service Kerberos validation bypass");
        assert_eq!(conf, 90);
    }

    #[test]
    fn classify_rc4_patch() {
        let (desc, conf) = classify_skeleton_key_pattern("cryptdll.dll", "rc4_patch");
        assert_eq!(desc, "RC4 HMAC encryption downgrade patch");
        assert_eq!(conf, 80);
    }

    #[test]
    fn classify_lsasrv_patch() {
        let (desc, conf) = classify_skeleton_key_pattern("lsasrv.dll", "auth_patch");
        assert_eq!(desc, "LSA Server authentication bypass");
        assert_eq!(conf, 85);
    }

    #[test]
    fn classify_unknown_pattern() {
        let (desc, conf) = classify_skeleton_key_pattern("foo.dll", "bar");
        assert_eq!(desc, "Unknown modification");
        assert_eq!(conf, 50);
    }

    #[test]
    fn walk_no_symbol_returns_empty() {
        // When PsActiveProcessHead is not in symbols, walker should return empty.
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Build an ISF with no PsActiveProcessHead symbol
        let isf = IsfBuilder::new()
            .add_struct("_EPROCESS", 2048)
            .add_field("_EPROCESS", "UniqueProcessId", 0x440, "pointer")
            .add_field("_EPROCESS", "ActiveProcessLinks", 0x448, "_LIST_ENTRY")
            .add_field("_EPROCESS", "ImageFileName", 0x5A8, "char")
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_skeleton_key(&reader).unwrap();
        assert!(results.is_empty(), "no PsActiveProcessHead should yield empty results");
    }

    #[test]
    fn indicator_serializes() {
        let indicator = SkeletonKeyIndicator {
            indicator_type: "auth_patch".into(),
            address: 0x7FFE_0001_0000,
            module: "msv1_0.dll".into(),
            description: "MSV1_0 authentication bypass patch".into(),
            confidence: 90,
            is_detected: true,
        };

        let json = serde_json::to_string(&indicator).unwrap();
        assert!(json.contains("auth_patch"));
        assert!(json.contains("msv1_0.dll"));
        assert!(json.contains("90"));
        assert!(json.contains("true"));
        assert!(json.contains("MSV1_0 authentication bypass patch"));
    }
}
