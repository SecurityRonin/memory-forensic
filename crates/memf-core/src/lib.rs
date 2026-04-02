#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Virtual address translation and kernel object reading.
//!
//! This crate provides:
//! - [`VirtualAddressSpace`] — page table walking for x86_64 (4-level, 5-level),
//!   AArch64, and x86 PAE/non-PAE modes
//! - [`ObjectReader`] — high-level kernel struct traversal using symbol information

pub mod object_reader;
pub mod pagefile;
pub mod test_builders;
pub mod vas;

/// Error type for memf-core operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Physical memory read error.
    #[error("physical memory error: {0}")]
    Physical(#[from] memf_format::Error),

    /// Symbol resolution error.
    #[error("symbol error: {0}")]
    Symbol(#[from] memf_symbols::Error),

    /// Page table entry not present (page fault).
    #[error("page not present at virtual address {0:#018x}")]
    PageNotPresent(u64),

    /// Read crossed a page boundary and the next page is not mapped.
    #[error("partial read: got {got} of {requested} bytes at {addr:#018x}")]
    PartialRead {
        /// Virtual address of the read.
        addr: u64,
        /// Bytes requested.
        requested: usize,
        /// Bytes actually read.
        got: usize,
    },

    /// A required symbol or field was not found.
    #[error("missing symbol or field: {0}")]
    MissingSymbol(String),

    /// Type size mismatch during Pod cast.
    #[error("type size mismatch: expected {expected}, got {got}")]
    SizeMismatch {
        /// Expected size in bytes.
        expected: usize,
        /// Actual size available.
        got: usize,
    },

    /// The list walk exceeded the maximum iteration count (cycle protection).
    #[error("list walk exceeded {0} iterations (possible cycle)")]
    ListCycle(usize),

    /// Page is in a pagefile that was not provided.
    #[error("page at {vaddr:#018x} paged out to pagefile {pagefile_num} offset {page_offset:#x}")]
    PagedOut {
        /// Virtual address of the faulting page.
        vaddr: u64,
        /// Pagefile number (0 = pagefile.sys, 1-15 = secondary).
        pagefile_num: u8,
        /// Page offset within the pagefile.
        page_offset: u64,
    },

    /// Page uses a prototype PTE (shared section, not yet supported).
    #[error("prototype PTE at {0:#018x} (not yet supported)")]
    PrototypePte(u64),
}

/// A Result alias for memf-core.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_page_not_present() {
        let e = Error::PageNotPresent(0xFFFF_8000_0000_1000);
        assert!(e.to_string().contains("0xffff800000001000"));
    }

    #[test]
    fn error_display_partial_read() {
        let e = Error::PartialRead {
            addr: 0x1000,
            requested: 8,
            got: 4,
        };
        assert!(e.to_string().contains("4 of 8"));
    }

    #[test]
    fn error_display_list_cycle() {
        let e = Error::ListCycle(10000);
        assert!(e.to_string().contains("10000"));
    }

    #[test]
    fn error_display_missing_symbol() {
        let e = Error::MissingSymbol("task_struct.pid".into());
        assert!(e.to_string().contains("task_struct.pid"));
    }

    #[test]
    fn error_display_size_mismatch() {
        let e = Error::SizeMismatch {
            expected: 8,
            got: 4,
        };
        let msg = e.to_string();
        assert!(msg.contains('8'));
        assert!(msg.contains('4'));
    }

    #[test]
    fn error_from_physical() {
        let phys_err = memf_format::Error::UnknownFormat;
        let e: Error = Error::from(phys_err);
        assert!(matches!(e, Error::Physical(_)));
        assert!(e.to_string().contains("unknown dump format"));
    }

    #[test]
    fn error_from_symbol() {
        let sym_err = memf_symbols::Error::NotFound("init_task".into());
        let e: Error = Error::from(sym_err);
        assert!(matches!(e, Error::Symbol(_)));
        assert!(e.to_string().contains("init_task"));
    }

    #[test]
    fn error_from_io_via_physical() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
        let phys_err = memf_format::Error::from(io_err);
        let e: Error = Error::from(phys_err);
        assert!(matches!(e, Error::Physical(_)));
    }

    #[test]
    fn error_display_paged_out() {
        let e = Error::PagedOut {
            vaddr: 0xFFFF_8000_0000_2000,
            pagefile_num: 0,
            page_offset: 0x1234,
        };
        let msg = e.to_string();
        assert!(msg.contains("0xffff800000002000"));
        assert!(msg.contains("pagefile 0"));
        assert!(msg.contains("0x1234"));
    }

    #[test]
    fn error_display_prototype_pte() {
        let e = Error::PrototypePte(0xFFFF_8000_DEAD_0000);
        let msg = e.to_string();
        assert!(msg.contains("0xffff8000dead0000"));
        assert!(msg.contains("prototype PTE"));
    }
}
