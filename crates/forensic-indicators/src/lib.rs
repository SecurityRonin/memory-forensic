//! forensic-indicators — static indicator tables for memory-forensic analysis.
//!
//! Provides zero-dependency, `std`-only lookup functions and constants covering:
//! suspicious network ports, trusted/suspicious filesystem paths, persistence
//! registry keys and paths, Living-Off-the-Land binaries (LOLBins), process
//! masquerading targets, malicious command patterns, and anti-forensics indicators.

pub mod antiforensics;
pub mod catalog;
pub mod commands;
pub mod encryption;
pub mod lolbins;
pub mod paths;
pub mod pca;
pub mod persistence;
pub mod ports;
pub mod processes;
pub mod remote_access;
pub mod third_party;
