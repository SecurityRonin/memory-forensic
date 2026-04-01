#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Symbol resolution backends for memory forensics.
//!
//! Provides the [`SymbolResolver`] trait and concrete backends:
//! - ISF JSON (Volatility 3-compatible symbol tables)
//! - BTF (Linux BPF Type Format, kernel 5.2+)

pub mod btf;
pub mod isf;
pub mod pdb_resolver;
pub mod pe_debug;
pub mod symserver;
pub mod test_builders;

use std::collections::HashMap;

/// Error type for memf-symbols operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error reading symbol files.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Symbol file is malformed or unsupported.
    #[error("malformed symbol data: {0}")]
    Malformed(String),

    /// Requested symbol or type not found.
    #[error("symbol not found: {0}")]
    NotFound(String),

    /// PDB parsing error.
    #[error("PDB error: {0}")]
    Pdb(String),

    /// Network/download error.
    #[error("network error: {0}")]
    Network(String),

    /// Cache I/O error.
    #[error("cache error: {0}")]
    Cache(String),
}

impl From<pdb::Error> for Error {
    fn from(e: pdb::Error) -> Self {
        Self::Pdb(e.to_string())
    }
}

/// A Result alias for memf-symbols.
pub type Result<T> = std::result::Result<T, Error>;

/// Information about a struct field from the symbol table.
#[derive(Debug, Clone)]
pub struct FieldInfo {
    /// Byte offset of this field within the struct.
    pub offset: u64,
    /// Name of the field's type (e.g., "unsigned int", "list_head").
    pub type_name: String,
}

/// Information about a struct type from the symbol table.
#[derive(Debug, Clone)]
pub struct StructInfo {
    /// Total size of the struct in bytes.
    pub size: u64,
    /// Fields keyed by field name.
    pub fields: HashMap<String, FieldInfo>,
}

/// A provider of symbol/type information for kernel analysis.
///
/// Backends implement this trait to resolve struct layouts, field offsets,
/// and symbol addresses from various sources (ISF JSON, BTF, DWARF, etc.).
pub trait SymbolResolver: Send + Sync {
    /// Return the byte offset of `field_name` within `struct_name`.
    fn field_offset(&self, struct_name: &str, field_name: &str) -> Option<u64>;

    /// Return the total size in bytes of `struct_name`.
    fn struct_size(&self, struct_name: &str) -> Option<u64>;

    /// Return the virtual address of a kernel symbol by name.
    fn symbol_address(&self, symbol_name: &str) -> Option<u64>;

    /// Return full struct information including all fields.
    fn struct_info(&self, struct_name: &str) -> Option<StructInfo>;

    /// Human-readable name for this backend (e.g., "ISF JSON", "BTF").
    fn backend_name(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verify the trait is object-safe (can be used as dyn SymbolResolver)
    #[test]
    fn trait_is_object_safe() {
        fn _assert_object_safe(_: &dyn SymbolResolver) {}
    }

    #[test]
    fn error_display() {
        let e = Error::NotFound("init_task".into());
        assert_eq!(e.to_string(), "symbol not found: init_task");
    }

    #[test]
    fn field_info_clone() {
        let f = FieldInfo {
            offset: 8,
            type_name: "int".into(),
        };
        let f2 = f.clone();
        assert_eq!(f2.offset, 8);
    }

    #[test]
    fn error_io_from_impl() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let err: Error = Error::from(io_err);
        assert!(matches!(err, Error::Io(_)));
        assert!(err.to_string().contains("gone"));
    }

    #[test]
    fn error_json_from_impl() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err: Error = Error::from(json_err);
        assert!(matches!(err, Error::Json(_)));
    }

    #[test]
    fn error_malformed_display() {
        let err = Error::Malformed("bad data".into());
        assert!(err.to_string().contains("bad data"));
    }

    #[test]
    fn error_pdb_display() {
        let err = Error::Pdb("invalid type index".into());
        assert_eq!(err.to_string(), "PDB error: invalid type index");
        // Verify Debug impl
        let debug = format!("{err:?}");
        assert!(debug.contains("Pdb"));
    }

    #[test]
    fn error_network_display() {
        let err = Error::Network("connection refused".into());
        assert_eq!(err.to_string(), "network error: connection refused");
        let debug = format!("{err:?}");
        assert!(debug.contains("Network"));
    }

    #[test]
    fn error_cache_display() {
        let err = Error::Cache("disk full".into());
        assert_eq!(err.to_string(), "cache error: disk full");
        let debug = format!("{err:?}");
        assert!(debug.contains("Cache"));
    }

    #[test]
    fn struct_info_clone() {
        let mut fields = HashMap::new();
        fields.insert(
            "pid".into(),
            FieldInfo {
                offset: 0,
                type_name: "int".into(),
            },
        );
        let info = StructInfo { size: 128, fields };
        let info2 = info.clone();
        assert_eq!(info2.size, 128);
        assert!(info2.fields.contains_key("pid"));
    }

    #[test]
    fn isf_and_pdb_resolvers_agree_on_windows_kernel() {
        use crate::isf::IsfResolver;
        use crate::pdb_resolver::{PdbField, PdbParsedData, PdbResolver, PdbStruct};
        use crate::test_builders::IsfBuilder;

        let isf =
            IsfResolver::from_value(&IsfBuilder::windows_kernel_preset().build_json()).unwrap();
        let pdb = PdbResolver::from_parsed(PdbParsedData {
            structs: vec![PdbStruct {
                name: "_EPROCESS".into(),
                size: 2048,
                fields: vec![
                    PdbField {
                        name: "UniqueProcessId".into(),
                        offset: 0x440,
                        type_name: "pointer".into(),
                    },
                    PdbField {
                        name: "ActiveProcessLinks".into(),
                        offset: 0x448,
                        type_name: "_LIST_ENTRY".into(),
                    },
                    PdbField {
                        name: "ImageFileName".into(),
                        offset: 0x5A8,
                        type_name: "char".into(),
                    },
                ],
            }],
            symbols: vec![],
        });

        // Both resolvers agree on _EPROCESS layout
        assert_eq!(isf.struct_size("_EPROCESS"), pdb.struct_size("_EPROCESS"));
        assert_eq!(
            isf.field_offset("_EPROCESS", "UniqueProcessId"),
            pdb.field_offset("_EPROCESS", "UniqueProcessId")
        );
        assert_eq!(
            isf.field_offset("_EPROCESS", "ActiveProcessLinks"),
            pdb.field_offset("_EPROCESS", "ActiveProcessLinks")
        );
        assert_eq!(
            isf.field_offset("_EPROCESS", "ImageFileName"),
            pdb.field_offset("_EPROCESS", "ImageFileName")
        );
    }

    #[test]
    fn all_three_backends_through_dyn_trait() {
        use crate::pdb_resolver::{PdbField, PdbParsedData, PdbResolver, PdbStruct};

        let resolvers: Vec<Box<dyn SymbolResolver>> = vec![
            Box::new(
                crate::isf::IsfResolver::from_value(
                    &crate::test_builders::IsfBuilder::new()
                        .add_struct("task_struct", 9024)
                        .add_field("task_struct", "pid", 1128, "int")
                        .add_symbol("init_task", 0xFFFF_0000)
                        .build_json(),
                )
                .unwrap(),
            ),
            Box::new(PdbResolver::from_parsed(PdbParsedData {
                structs: vec![PdbStruct {
                    name: "_EPROCESS".into(),
                    size: 2048,
                    fields: vec![PdbField {
                        name: "UniqueProcessId".into(),
                        offset: 0x440,
                        type_name: "pointer".into(),
                    }],
                }],
                symbols: vec![],
            })),
        ];

        assert_eq!(resolvers[0].backend_name(), "ISF JSON");
        assert_eq!(resolvers[0].struct_size("task_struct"), Some(9024));
        assert_eq!(resolvers[1].backend_name(), "PDB");
        assert_eq!(resolvers[1].struct_size("_EPROCESS"), Some(2048));
    }

    #[test]
    fn pdb_id_to_symserver_url_workflow() {
        use crate::pe_debug::PdbId;
        use crate::symserver;

        // Simulate extracted PDB identity (PE parsing tested in pe_debug module)
        let pdb_id = PdbId {
            guid: "1B72224D-37B8-1792-2820-0ED8994498B2".into(),
            age: 1,
            pdb_name: "ntkrnlmp.pdb".into(),
        };

        // Use extracted info to construct download URL
        let url = symserver::download_url(
            symserver::default_server_url(),
            &pdb_id.pdb_name,
            &pdb_id.guid,
            pdb_id.age,
        );
        assert!(url.starts_with("https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/"));
        assert!(url.contains("1B72224D37B8179228200ED8994498B2"));
        assert!(url.ends_with("/ntkrnlmp.pdb"));

        // Verify cache path construction
        let cache = symserver::cache_path(
            std::path::Path::new("/tmp/symbols"),
            &pdb_id.pdb_name,
            &pdb_id.guid,
            pdb_id.age,
        );
        assert!(cache.ends_with("ntkrnlmp.pdb"));
        assert!(cache
            .to_string_lossy()
            .contains("1B72224D37B8179228200ED8994498B2"));
    }
}
