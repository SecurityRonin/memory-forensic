#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Physical memory dump format parsers.

use std::path::Path;

/// Error type for memf-format operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error reading the dump file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The dump format could not be identified.
    #[error("unknown dump format")]
    UnknownFormat,

    /// Multiple formats matched with similar confidence.
    #[error("ambiguous format: multiple plugins scored >= 50")]
    AmbiguousFormat,

    /// The dump file is corrupt or truncated.
    #[error("corrupt dump: {0}")]
    Corrupt(String),

    /// Snappy decompression error.
    #[error("decompression error: {0}")]
    Decompression(String),
}

/// A Result alias for memf-format.
pub type Result<T> = std::result::Result<T, Error>;

/// A contiguous range of physical memory present in the dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalRange {
    /// Start physical address (inclusive).
    pub start: u64,
    /// End physical address (exclusive).
    pub end: u64,
}

impl PhysicalRange {
    /// Number of bytes in this range.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Whether this range is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the given address falls within this range.
    #[must_use]
    pub fn contains_addr(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

/// Machine architecture identified from a dump header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineType {
    /// x86_64 / AMD64 (machine image type 0x8664).
    Amd64,
    /// x86 / i386 (machine image type 0x014C).
    I386,
    /// AArch64 / ARM64 (machine image type 0xAA64).
    Aarch64,
}

/// Optional metadata extracted from dump file headers.
///
/// Windows crash dumps embed analysis-critical fields directly in the header:
/// CR3 (page table root), `PsActiveProcessHead` (EPROCESS list), and
/// `PsLoadedModuleList` (driver list). These let downstream crates bootstrap
/// kernel walking without symbol resolution.
#[derive(Debug, Clone, Default)]
pub struct DumpMetadata {
    /// Page table root physical address (CR3 / DirectoryTableBase).
    pub cr3: Option<u64>,
    /// Machine architecture.
    pub machine_type: Option<MachineType>,
    /// OS major and minor version from the dump header.
    pub os_version: Option<(u32, u32)>,
    /// Number of processors.
    pub num_processors: Option<u32>,
    /// Virtual address of `PsActiveProcessHead` (EPROCESS linked list head).
    pub ps_active_process_head: Option<u64>,
    /// Virtual address of `PsLoadedModuleList` (loaded driver list head).
    pub ps_loaded_module_list: Option<u64>,
    /// Virtual address of `KdDebuggerDataBlock`.
    pub kd_debugger_data_block: Option<u64>,
    /// System time at dump creation (Windows FILETIME, 100ns intervals since 1601-01-01).
    pub system_time: Option<u64>,
    /// Human-readable dump sub-type (e.g., "Full", "Kernel", "Bitmap").
    pub dump_type: Option<String>,
}

/// A provider of physical memory from a dump file.
pub trait PhysicalMemoryProvider: Send + Sync {
    /// Read up to `buf.len()` bytes starting at physical address `addr`.
    /// Returns the number of bytes actually read (may be less if crossing a gap).
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize>;

    /// Return all valid physical address ranges in the dump.
    fn ranges(&self) -> &[PhysicalRange];

    /// Total physical memory size (sum of all range lengths).
    fn total_size(&self) -> u64 {
        self.ranges().iter().map(PhysicalRange::len).sum()
    }

    /// Human-readable format name (e.g., "LiME", "AVML v2").
    fn format_name(&self) -> &str;

    /// Optional metadata extracted from the dump header.
    /// Returns `None` for formats that carry no metadata (Raw, LiME, AVML).
    fn metadata(&self) -> Option<DumpMetadata> {
        None
    }
}

/// A plugin that can detect and open a specific dump format.
pub trait FormatPlugin: Send + Sync {
    /// Human-readable name for this format.
    fn name(&self) -> &str;

    /// Probe the first `header` bytes of a file. Return confidence 0-100.
    fn probe(&self, header: &[u8]) -> u8;

    /// Open the file and return a `PhysicalMemoryProvider`.
    fn open(&self, path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>>;
}

inventory::collect!(&'static dyn FormatPlugin);

/// Open a dump file by probing all registered format plugins.
///
/// Reads the first 4096 bytes and asks each plugin for a confidence score.
/// Returns the provider from the highest-confidence plugin (>=80 returns
/// immediately; otherwise the best score >=50 wins).
pub fn open_dump(path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut header = [0u8; 4096];
    let n = file.read(&mut header)?;
    let header = &header[..n];

    let mut best: Option<(&dyn FormatPlugin, u8)> = None;
    let mut ambiguous = false;

    for plugin in inventory::iter::<&dyn FormatPlugin> {
        let score = plugin.probe(header);
        if score >= 80 {
            return plugin.open(path);
        }
        if score >= 50 {
            if let Some((_, prev_score)) = best {
                if score >= prev_score {
                    if score == prev_score {
                        ambiguous = true;
                    } else {
                        ambiguous = false;
                        best = Some((*plugin, score));
                    }
                }
            } else {
                best = Some((*plugin, score));
            }
        } else if score >= 20 && best.is_none() {
            best = Some((*plugin, score));
        }
    }

    if ambiguous {
        return Err(Error::AmbiguousFormat);
    }

    match best {
        Some((plugin, _)) => plugin.open(path),
        None => Err(Error::UnknownFormat),
    }
}

pub mod avml;
pub mod elf_core;
pub mod hiberfil;
pub mod kdump;
pub mod lime;
pub mod raw;
pub mod test_builders;
pub mod vmware;
pub mod win_crashdump;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_range_len() {
        let r = PhysicalRange {
            start: 0x1000,
            end: 0x2000,
        };
        assert_eq!(r.len(), 0x1000);
    }

    #[test]
    fn physical_range_empty() {
        let r = PhysicalRange {
            start: 0x1000,
            end: 0x1000,
        };
        assert!(r.is_empty());
    }

    #[test]
    fn physical_range_contains() {
        let r = PhysicalRange {
            start: 0x1000,
            end: 0x2000,
        };
        assert!(r.contains_addr(0x1000));
        assert!(r.contains_addr(0x1FFF));
        assert!(!r.contains_addr(0x2000));
        assert!(!r.contains_addr(0x0FFF));
    }

    #[test]
    fn open_dump_lime() {
        use crate::test_builders::LimeBuilder;
        let dump = LimeBuilder::new().add_range(0, &[0xAA; 128]).build();
        let dir = std::env::temp_dir().join("memf_test_lime");
        std::fs::write(&dir, &dump).unwrap();
        let provider = open_dump(&dir).unwrap();
        assert_eq!(provider.format_name(), "LiME");
        assert_eq!(provider.total_size(), 128);
        std::fs::remove_file(&dir).ok();
    }

    #[test]
    fn open_dump_avml() {
        use crate::test_builders::AvmlBuilder;
        let dump = AvmlBuilder::new().add_range(0, &[0xBB; 128]).build();
        let dir = std::env::temp_dir().join("memf_test_avml");
        std::fs::write(&dir, &dump).unwrap();
        let provider = open_dump(&dir).unwrap();
        assert_eq!(provider.format_name(), "AVML v2");
        assert_eq!(provider.total_size(), 128);
        std::fs::remove_file(&dir).ok();
    }

    #[test]
    fn open_dump_unknown_is_error() {
        let data = vec![0x00; 1024];
        let dir = std::env::temp_dir().join("memf_test_raw");
        std::fs::write(&dir, &data).unwrap();
        // Raw plugin scores 5 which is < 20, so open_dump returns UnknownFormat
        let result = open_dump(&dir);
        assert!(result.is_err());
        std::fs::remove_file(&dir).ok();
    }

    #[test]
    fn physical_range_zero_length() {
        let r = PhysicalRange {
            start: 0x5000,
            end: 0x5000,
        };
        assert_eq!(r.len(), 0);
        assert!(r.is_empty());
        assert!(!r.contains_addr(0x5000));
    }

    #[test]
    fn physical_range_saturating_sub() {
        // Test the saturating_sub path: start > end should yield 0
        let r = PhysicalRange {
            start: 0x2000,
            end: 0x1000,
        };
        assert_eq!(r.len(), 0);
        assert!(r.is_empty());
    }

    #[test]
    fn error_io_from_impl() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: Error = Error::from(io_err);
        assert!(matches!(err, Error::Io(_)));
        assert!(err.to_string().contains("file not found"));
    }

    #[test]
    fn error_unknown_format_display() {
        let err = Error::UnknownFormat;
        assert_eq!(err.to_string(), "unknown dump format");
    }

    #[test]
    fn error_ambiguous_format_display() {
        let err = Error::AmbiguousFormat;
        assert_eq!(
            err.to_string(),
            "ambiguous format: multiple plugins scored >= 50"
        );
    }

    #[test]
    fn error_corrupt_display() {
        let err = Error::Corrupt("truncated header".into());
        assert!(err.to_string().contains("truncated header"));
    }

    #[test]
    fn error_decompression_display() {
        let err = Error::Decompression("snappy failure".into());
        assert!(err.to_string().contains("snappy failure"));
    }

    #[test]
    fn open_dump_nonexistent_file() {
        let result = open_dump(Path::new("/nonexistent/path/to/dump.lime"));
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn dump_metadata_default_is_all_none() {
        let m = DumpMetadata::default();
        assert!(m.cr3.is_none());
        assert!(m.machine_type.is_none());
        assert!(m.os_version.is_none());
        assert!(m.num_processors.is_none());
        assert!(m.ps_active_process_head.is_none());
        assert!(m.ps_loaded_module_list.is_none());
        assert!(m.kd_debugger_data_block.is_none());
        assert!(m.system_time.is_none());
        assert!(m.dump_type.is_none());
    }

    #[test]
    fn machine_type_variants() {
        assert_ne!(MachineType::Amd64, MachineType::I386);
        assert_ne!(MachineType::Amd64, MachineType::Aarch64);
        assert_ne!(MachineType::I386, MachineType::Aarch64);
        let a = MachineType::Amd64;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn metadata_default_method_returns_none() {
        use crate::test_builders::LimeBuilder;
        let dump = LimeBuilder::new().add_range(0, &[0xAA; 64]).build();
        let provider = crate::lime::LimeProvider::from_bytes(&dump).unwrap();
        assert!(provider.metadata().is_none());
    }

    #[test]
    fn open_dump_crashdump() {
        use crate::test_builders::CrashDumpBuilder;
        let page = vec![0xAA; 4096];
        let dump = CrashDumpBuilder::new().add_run(0, &page).build();
        let path = std::env::temp_dir().join("memf_test_open_crashdump.dmp");
        std::fs::write(&path, &dump).unwrap();
        let provider = open_dump(&path).unwrap();
        assert_eq!(provider.format_name(), "Windows Crash Dump");
        assert_eq!(provider.total_size(), 4096);
        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xAA, 0xAA]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn open_dump_hiberfil() {
        use crate::test_builders::HiberfilBuilder;
        let page = [0xBB; 4096];
        let dump = HiberfilBuilder::new().add_page(0, &page).build();
        let path = std::env::temp_dir().join("memf_test_open_hiberfil.sys");
        std::fs::write(&path, &dump).unwrap();
        let provider = open_dump(&path).unwrap();
        assert_eq!(provider.format_name(), "Hiberfil.sys");
        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xBB, 0xBB]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn open_dump_vmware() {
        use crate::test_builders::VmwareStateBuilder;
        let dump = VmwareStateBuilder::new()
            .add_region(0, &[0xCC; 128])
            .build();
        let path = std::env::temp_dir().join("memf_test_open_vmware.vmss");
        std::fs::write(&path, &dump).unwrap();
        let provider = open_dump(&path).unwrap();
        assert_eq!(provider.format_name(), "VMware State");
        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xCC, 0xCC]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn open_dump_kdump() {
        use crate::test_builders::KdumpBuilder;
        let page = vec![0xDD; 4096];
        let dump = KdumpBuilder::new()
            .compression(0x04)
            .add_page(0, &page)
            .build();
        let path = std::env::temp_dir().join("memf_test_open_kdump.dump");
        std::fs::write(&path, &dump).unwrap();
        let provider = open_dump(&path).unwrap();
        assert_eq!(provider.format_name(), "kdump");
        let mut buf = [0u8; 2];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xDD, 0xDD]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn metadata_returns_none_for_legacy_formats() {
        use crate::test_builders::LimeBuilder;
        let dump = LimeBuilder::new().add_range(0, &[0xAA; 64]).build();
        let path = std::env::temp_dir().join("memf_test_meta_lime.lime");
        std::fs::write(&path, &dump).unwrap();
        let provider = open_dump(&path).unwrap();
        assert!(provider.metadata().is_none());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn metadata_returns_some_for_crashdump() {
        use crate::test_builders::CrashDumpBuilder;
        let page = vec![0u8; 4096];
        let dump = CrashDumpBuilder::new().cr3(0x1ab000).add_run(0, &page).build();
        let path = std::env::temp_dir().join("memf_test_meta_crash.dmp");
        std::fs::write(&path, &dump).unwrap();
        let provider = open_dump(&path).unwrap();
        let meta = provider.metadata().expect("crash dump should have metadata");
        assert_eq!(meta.cr3, Some(0x1ab000));
        std::fs::remove_file(&path).ok();
    }
}
