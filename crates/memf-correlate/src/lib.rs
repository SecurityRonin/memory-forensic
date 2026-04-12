//! Forensic event correlation model for the memf forensics framework.
//!
//! Provides the [`ForensicEvent`] data model, severity classification,
//! MITRE ATT&CK mapping, and the [`IntoForensicEvents`] conversion trait.

#![warn(missing_docs)]
#![deny(unsafe_code)]

pub mod event;
pub mod mitre;
pub mod process_tree;
pub mod scoring;
pub mod timeline;
pub mod traits;
