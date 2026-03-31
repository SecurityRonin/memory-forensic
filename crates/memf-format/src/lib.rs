#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Physical memory dump format parsers.
//!
//! Provides the [`PhysicalMemoryProvider`] trait for reading physical memory
//! from various dump formats (LiME, AVML, raw), plus confidence-based format
//! probing via [`FormatPlugin`] and the [`inventory`] crate.
