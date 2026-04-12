//! Windows service record enumeration (svcscan).
//!
//! Enumerates Windows services by walking the doubly-linked list of
//! `_SERVICE_RECORD` structures maintained by the Service Control
//! Manager (`services.exe`). The list head is identified via the
//! `ServiceRecordListHead` symbol inside `services.exe` memory.
//!
//! Each `_SERVICE_RECORD` contains the service name, display name,
//! current state, start type, service type, image path, and the
//! account under which it runs.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;
use crate::{Result, ServiceInfo, ServiceStartType, ServiceState};

/// Maximum service records to walk before stopping (prevents infinite loops).
const MAX_SERVICE_RECORDS: usize = 10_000;

/// Walk the SCM service record list and return service information.
///
/// `list_head_vaddr` is the virtual address of the `ServiceRecordListHead`
/// symbol (a `_LIST_ENTRY` that is the head of the doubly-linked service
/// record list inside `services.exe`).
///
/// For each `_SERVICE_RECORD`, reads the service name, display name,
/// state, start type, service type, image path, object name, and PID.
pub fn walk_services<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    list_head_vaddr: u64,
) -> Result<Vec<ServiceInfo>> {
        todo!()
    }

/// Read a single `_SERVICE_RECORD` and extract all fields.
fn read_service_record<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    record_addr: u64,
) -> Result<ServiceInfo> {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServiceStartType, ServiceState};
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ── _SERVICE_RECORD field offsets (synthetic layout) ──────────────

    /// ServiceList (_LIST_ENTRY) at offset 0x00.
    const SR_SERVICE_LIST: usize = 0x00;
    /// ServiceName (pointer to _UNICODE_STRING) at offset 0x10.
    const SR_SERVICE_NAME: usize = 0x10;
    /// DisplayName (pointer to _UNICODE_STRING) at offset 0x18.
    const SR_DISPLAY_NAME: usize = 0x18;
    /// CurrentState (u32) at offset 0x20.
    const SR_CURRENT_STATE: usize = 0x20;
    /// ServiceType (u32) at offset 0x24.
    const SR_SERVICE_TYPE: usize = 0x24;
    /// StartType (u32) at offset 0x28.
    const SR_START_TYPE: usize = 0x28;
    /// ImagePath (pointer to _UNICODE_STRING) at offset 0x30.
    const SR_IMAGE_PATH: usize = 0x30;
    /// ObjectName (pointer to _UNICODE_STRING) at offset 0x38.
    const SR_OBJECT_NAME: usize = 0x38;
    /// ProcessId (u32) at offset 0x40.
    const SR_PROCESS_ID: usize = 0x40;

    fn make_svc_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        todo!()
    }

    /// Encode a Rust string as UTF-16LE bytes.
    fn utf16le(s: &str) -> Vec<u8> {
        todo!()
    }

    /// Write a _UNICODE_STRING header + buffer data into a page.
    ///
    /// `ustr_off` is the offset within `buf` for the _UNICODE_STRING struct.
    /// `data_vaddr` is the virtual address the Buffer pointer should point to.
    /// `data_off` is the offset within `buf` for the actual UTF-16LE data.
    fn write_unicode_string(
        buf: &mut [u8],
        ustr_off: usize,
        data_vaddr: u64,
        data_off: usize,
        text: &str,
    ) {
        todo!()
    }

    #[test]
    fn service_state_from_raw() {
        todo!()
    }

    #[test]
    fn service_state_display() {
        todo!()
    }

    #[test]
    fn service_start_type_from_raw() {
        todo!()
    }

    #[test]
    fn service_start_type_display() {
        todo!()
    }

    #[test]
    fn walk_services_empty() {
        todo!()
    }

    #[test]
    fn walk_single_service() {
        todo!()
    }

    #[test]
    fn walk_two_services() {
        todo!()
    }
}
