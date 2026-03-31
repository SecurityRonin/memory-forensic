#![deny(unsafe_code)]
#![warn(missing_docs)]
//! String extraction and IoC classification for memory forensics.
//!
//! Extracts ASCII/UTF-8/UTF-16LE strings from physical memory dumps,
//! classifies them via regex and YARA-X rules, and supports loading
//! pre-extracted string files.
