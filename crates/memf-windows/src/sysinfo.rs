//! Windows system information extraction.
//!
//! Reads OS version, build number, service pack, and system metadata from
//! kernel memory structures. Equivalent to Volatility's `windows.info` plugin.
//! Resolves global symbols: `NtBuildNumber`, `NtBuildLab`, `CmNtCSDVersion`,
//! `NtMajorVersion`, `NtMinorVersion`, `KeNumberProcessors`, and
//! `KdDebuggerDataBlock`.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use serde::Serialize;

/// Windows system information extracted from kernel memory.
#[derive(Debug, Clone, Serialize)]
pub struct SystemInfo {
    /// NT major version (e.g. 10 for Windows 10/11).
    pub major_version: u32,
    /// NT minor version (e.g. 0 for Windows 10).
    pub minor_version: u32,
    /// Build number from `NtBuildNumber` (high bit masked off).
    pub build_number: u32,
    /// Build lab string from `NtBuildLab` (null-terminated ASCII).
    pub build_lab: String,
    /// Service pack string derived from `CmNtCSDVersion`.
    pub service_pack: String,
    /// Number of logical processors from `KeNumberProcessors`.
    pub num_processors: u32,
    /// System time from `KdDebuggerDataBlock` (Windows FILETIME).
    pub system_time: u64,
    /// Product type string: "Workstation", "Domain Controller", "Server", or "Unknown".
    pub product_type: String,
}

/// Map an NT product type code to a human-readable name.
///
/// NT product type values:
/// - 1 = VER_NT_WORKSTATION
/// - 2 = VER_NT_DOMAIN_CONTROLLER
/// - 3 = VER_NT_SERVER
pub fn product_type_name(product_type: u32) -> String {
        todo!()
    }

/// Extract Windows system information from kernel memory.
///
/// Looks up global kernel symbols (`NtBuildNumber`, `NtMajorVersion`, etc.)
/// to reconstruct the OS version and build metadata. Returns `Ok(None)` if
/// the essential `NtBuildNumber` symbol is not found (e.g. non-Windows image).
///
/// Optional fields degrade gracefully: if a symbol is missing, a default
/// value is used (0 for integers, empty string for strings).
///
/// # Symbols read
///
/// | Symbol               | Type | Description                          |
/// |----------------------|------|--------------------------------------|
/// | `NtBuildNumber`      | u32  | Build number (high bit = checked)    |
/// | `NtMajorVersion`     | u32  | NT major version                     |
/// | `NtMinorVersion`     | u32  | NT minor version                     |
/// | `NtBuildLab`         | str  | Build lab string (128 bytes max)     |
/// | `CmNtCSDVersion`     | u32  | Service pack encoded value           |
/// | `KeNumberProcessors` | u32  | Logical processor count              |
pub fn walk_sysinfo<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Option<SystemInfo>> {
        todo!()
    }

/// Helper: read a u32 from a global symbol address.
fn read_u32_symbol<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    symbols: &dyn memf_symbols::SymbolResolver,
    name: &str,
) -> Option<u32> {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;

    // ── product_type_name classifier tests ──

    #[test]
    fn product_type_workstation() {
        todo!()
    }

    #[test]
    fn product_type_domain_controller() {
        todo!()
    }

    #[test]
    fn product_type_server() {
        todo!()
    }

    #[test]
    fn product_type_unknown() {
        todo!()
    }

    // ── serialization test ──

    #[test]
    fn system_info_serializes() {
        todo!()
    }

    // ── walker test ──

    #[test]
    fn walker_no_symbol_returns_none() {
        todo!()
    }

    /// walk_sysinfo: KdDebuggerDataBlock present — exercises product_type_name branches
    /// and the system_time read path.
    #[test]
    fn walker_with_kd_debugger_data_block() {
        todo!()
    }

    /// walk_sysinfo: KdDebuggerDataBlock present but product_type = 2 → Domain Controller.
    #[test]
    fn walker_kd_debugger_domain_controller() {
        todo!()
    }

    /// walk_sysinfo: KdDebuggerDataBlock present but product_type = 1 → Workstation.
    #[test]
    fn walker_kd_debugger_workstation() {
        todo!()
    }

    #[test]
    fn walker_with_build_number_returns_info() {
        todo!()
    }
}
