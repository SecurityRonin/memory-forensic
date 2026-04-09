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
}
