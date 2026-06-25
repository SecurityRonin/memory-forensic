//! Analysis bootstrap (OS detection, CR3/DTB recovery, kernel list-head
//! resolution). The implementation now lives in the `memf-session` library
//! crate so non-CLI consumers (e.g. 4n6mount's memory mount) can reuse it; this
//! module is a thin re-export to keep the binary's existing `os_detect::…` call
//! sites unchanged.

pub use memf_session::*;
