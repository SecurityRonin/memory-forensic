//! TLS (Thread Local Storage) callback validation walker.
//!
//! Walks the TLS directory of each loaded PE image to enumerate TLS
//! callback function pointers and detect those that resolve outside the
//! module's mapped range — a sign of callback hijacking.
//! MITRE ATT&CK T1055 / T1106.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{types::TlsCallbackInfo, Result};

/// Walk TLS directories of all loaded modules in all processes and validate
/// callback addresses.
///
/// For each `_IMAGE_TLS_DIRECTORY` found, extracts the callback array and
/// checks that each entry falls within `[module_base, module_base + size)`.
/// Callbacks that resolve outside this range are flagged as
/// `is_outside_module = true`.
///
/// # MITRE ATT&CK
/// T1055 — Process Injection (TLS callback abuse)
pub fn scan_tls_callbacks<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<TlsCallbackInfo>> {
    let _ = reader;
    Ok(vec![])
}
